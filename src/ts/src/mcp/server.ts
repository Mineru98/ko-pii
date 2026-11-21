/**
 * MCP (Model Context Protocol) 서버 — LLM 이 ko-pii 를 *도구* 로 호출.
 * Python `ko_pii/integrations/mcp_server.py` 1:1 포트.
 *
 * MCP 는 Anthropic 이 표준화한 LLM 도구 인터페이스 프로토콜.
 * Claude·OpenAI·기타 호환 클라이언트가 stdio 로 본 서버에 연결하여
 * ko-pii 의 기능을 *함수* 처럼 호출할 수 있다.
 *
 * 실행 (stdio 모드, LLM 클라이언트 통합용)::
 *
 *     ko-pii-mcp-server
 *
 * 제공 도구 (LLM 이 호출 가능):
 * - `detect_pii(text)` — PII 검출만 (가명화 X)
 * - `anonymize(text, mode?, strategy?, vault_id?)` — 가명화 + 결과 본문 반환
 * - `reveal(token, vault_id)` — 토큰에서 원본 복원 (호스트의 별도 승인/권한 검사 필요)
 * - `combined_risk(text)` — 결합 위험도 평가
 *
 * 서버 자체는 로컬 stdio 를 사용한다. 호스트가 모델에 보내는 입력/도구 응답은 통제하지 않는다.
 * detect_pii 와 reveal 은 원문을 반환하며 전송 전 필터가 아니다.
 *
 * 잘못된 호출(알 수 없는 도구, 스키마 위반 인자, 처리 실패)은 거부된 값을 되비추지 않는
 * `isError` 결과로 돌려준다 (Python 1.27 과 같은 고정 메시지). SDK 의 고수준 McpServer 는
 * 검증 오류에 입력값을 담을 수 있어 저수준 `Server` 와 자체 JSON Schema 검사를 쓴다.
 *
 * NOTE: `@modelcontextprotocol/sdk` import 는 이 디렉터리(mcp/)에만 허용된다
 * (코어 의존성 분리 유지 — 다른 src 모듈은 Node 표준만 import).
 */

import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { riskLevelName, score_combined_risk } from "../analytics/index.js";
import { Anonymizer } from "../anonymizer.js";
import type { ProcessingMode } from "../core/modes.js";
import { pyFloatRepr } from "../core/pyFormat.js";
import { detectAll } from "../detect.js";
import { pyJsonDumps, ReversibleVault } from "../vault/reversible.js";
import { VERSION } from "../version.js";

/**
 * 세션별 vault 관리 (in-memory) — Python 모듈 전역 `_VAULTS: dict[str, ReversibleVault]`
 * 대응. 프로세스 재시작 시 소실 (영구 저장은 ReversibleVault.save() 권장).
 */
const _VAULTS = new Map<string, ReversibleVault>();

/** Python `[types.TextContent(type="text", text=json.dumps(payload, ...))]` 대응.
 * `indent=2` 는 Python `json.dumps(ensure_ascii=False, indent=2)` 와 바이트 동일,
 * `indent=null` 은 compact (기본 구분자 `", "` / `": "`) 와 바이트 동일하다. */
type TextContent = { type: "text"; text: string };

function textResult(payload: unknown, indent: number | null = 2): { content: TextContent[] } {
  return { content: [{ type: "text", text: pyJsonDumps(payload, indent) }] };
}

/**
 * detect_pii 전용 — Python 의 confidence 는 float 이라 `1.0` 으로 직렬화된다
 * (JS 는 `1`). confidence 값만 호출별 임의 토큰으로 표시한 뒤 Python repr 로 치환한다
 * (본문 text 와 충돌하지 않도록 토큰은 매번 새로 만든다).
 */
function detectTextResult(payload: unknown): { content: { type: "text"; text: string }[] } {
  const mark = randomUUID();
  const json = JSON.stringify(
    payload,
    (key, value) =>
      key === "confidence" && typeof value === "number" ? `${mark}${pyFloatRepr(value)}` : value,
    2,
  );
  return {
    content: [{ type: "text", text: json.replaceAll(new RegExp(`"${mark}([^"]*)"`, "g"), "$1") }],
  };
}

interface PropertySchema {
  type: "string";
  description?: string;
  enum?: string[];
  default?: string;
}

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, PropertySchema>;
    required: string[];
  };
}

/** Python ``list_tools`` 와 같은 도구 정의 (설명·스키마 문자열까지 동일). */
const TOOLS: readonly ToolDefinition[] = [
  {
    name: "detect_pii",
    description:
      "한국 공공 PII 검출. text 를 분석해 검출된 PII 의 라벨·위치·신뢰도·법적 근거를 JSON 으로 반환. 가명화는 하지 않음.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string", description: "분석할 텍스트" } },
      required: ["text"],
    },
  },
  {
    name: "anonymize",
    description:
      "한국 공공 PII 검출 + 가명화. vault_id 가 있으면 같은 세션의 기존 vault 재사용 (같은 사람 → 같은 토큰).",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string" },
        mode: {
          type: "string",
          enum: ["PARANOID", "STRICT", "BALANCED", "PERMISSIVE", "AUDIT"],
          default: "STRICT",
        },
        strategy: {
          type: "string",
          enum: ["tokenize", "redact", "asterisk", "hashed", "partial", "fpe"],
          default: "tokenize",
        },
        vault_id: { type: "string", description: "세션 vault ID (옵션)" },
      },
      required: ["text"],
    },
  },
  {
    name: "reveal",
    description:
      "토큰에서 원본 PII 복원. vault_id 와 token 필요. 경고: 감사 로그가 활성화되지 않은 환경에서 호출 시 추적 불가.",
    inputSchema: {
      type: "object",
      properties: {
        token: { type: "string", description: "예: <RRN_1>" },
        vault_id: { type: "string" },
      },
      required: ["token", "vault_id"],
    },
  },
  {
    name: "combined_risk",
    description:
      "텍스트의 결합 위험도 평가 — 「개인정보 비식별 조치 가이드라인」 기준 식별자/준식별자/민감속성 분류 후 종합 위험도 산출.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"],
    },
  },
];

/** Python ``Draft202012Validator(schema).is_valid(arguments)`` — 이 서버 스키마에 필요한 부분. */
function isValidArguments(schema: ToolDefinition["inputSchema"], args: unknown): boolean {
  if (typeof args !== "object" || args === null || Array.isArray(args)) return false;
  const record = args as Record<string, unknown>;
  if (schema.required.some((key) => !Object.hasOwn(record, key))) return false;
  for (const [key, prop] of Object.entries(schema.properties)) {
    if (!Object.hasOwn(record, key)) continue;
    const value = record[key];
    if (typeof value !== "string") return false;
    if (prop.enum !== undefined && !prop.enum.includes(value)) return false;
  }
  return true;
}

/** Python ``error_result`` — ``json.dumps({"error": message})`` 고정 메시지. */
function errorResult(message: string): { isError: true; content: TextContent[] } {
  return {
    isError: true,
    content: [{ type: "text", text: pyJsonDumps({ error: message }, null) }],
  };
}

async function dispatch(
  name: string,
  args: Record<string, string>,
): Promise<{ content: TextContent[] }> {
  if (name === "detect_pii") {
    const detections = detectAll(args.text as string);
    return detectTextResult({
      count: detections.length,
      detections: detections.map((d) => ({
        label: d.label,
        text: d.text,
        start: d.start,
        end: d.end,
        risk_level: riskLevelName(d.riskLevel),
        confidence: d.confidence,
        legal_basis: d.legal_basis,
        evidence: [...d.evidence],
      })),
    });
  }

  if (name === "anonymize") {
    const text = args.text as string;
    const mode = (args.mode ?? "STRICT") as ProcessingMode;
    const strategy = args.strategy ?? "tokenize";
    const given = args.vault_id;
    const vault = (given ? _VAULTS.get(given) : undefined) ?? new ReversibleVault();
    const vid = given || randomUUID();
    const anon = new Anonymizer(mode, strategy, vault);
    const result = anon.process(text);
    // 처리에 성공한 뒤에만 세션 vault 를 등록한다 (Python 1.27).
    _VAULTS.set(vid, vault);

    // process() 는 항상 combined_risk 를 채움 (Python assert 대응).
    const combined = result.combined_risk;
    if (combined === null) {
      throw new Error("unreachable: Anonymizer.process() always sets combined_risk");
    }
    return textResult({
      text: result.text,
      vault_id: vid,
      combined_risk: riskLevelName(combined.combined_risk),
      summary: result.summary,
    });
  }

  if (name === "reveal") {
    const token = args.token as string;
    const vault = _VAULTS.get(args.vault_id as string);
    if (vault === undefined) throw new Error("Unknown vault");
    const original = vault.reveal(token, "MCP reveal");
    return textResult({ token, original, found: original !== null });
  }

  if (name === "combined_risk") {
    const cr = score_combined_risk(detectAll(args.text as string));
    return textResult({
      risk_level: riskLevelName(cr.combined_risk),
      rationale: [...cr.rationale],
      identifiers: [...cr.distinct_identifiers],
      quasi_identifiers: [...cr.distinct_quasi],
      sensitive_attributes: [...cr.sensitive_present],
    });
  }

  throw new Error("Unknown tool");
}

/** Python ``call_tool`` — 도구 조회 → 스키마 검증 → 실행. 실패는 값 없는 isError 결과. */
export async function callTool(
  name: string,
  args: unknown,
): Promise<{ content: TextContent[]; isError: boolean }> {
  const tool = TOOLS.find((t) => t.name === name);
  if (tool === undefined) return errorResult("Unknown tool");
  if (!isValidArguments(tool.inputSchema, args)) return errorResult("Invalid tool arguments");
  try {
    // Python ``CallToolResult(content=...)`` 는 성공에도 ``"isError": false`` 를 직렬화한다.
    const { content } = await dispatch(name, args as Record<string, string>);
    return { content, isError: false };
  } catch {
    return errorResult("Tool execution failed");
  }
}

/**
 * ko-pii MCP 서버 인스턴스 생성 + 도구 4개 등록.
 * stdio 대신 InMemoryTransport 로 연결해 테스트할 수 있다 (tests/unit/mcp-server.test.ts).
 */
export function buildMcpServer(): Server {
  const server = new Server({ name: "ko-pii", version: VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map((tool) => structuredClone(tool)),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) =>
    callTool(request.params.name, request.params.arguments ?? {}),
  );
  return server;
}

/** ko-pii-mcp-server CLI entry point — stdio 전송으로 서버를 구동한다. */
export async function main(): Promise<void> {
  const server = buildMcpServer();
  await server.connect(new StdioServerTransport());
}
