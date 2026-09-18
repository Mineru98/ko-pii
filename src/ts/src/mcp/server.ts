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
 * - `reveal(token, vault_id)` — 토큰에서 원본 복원
 * - `combined_risk(text)` — 결합 위험도 평가
 *
 * 본 서버는 *로컬 stdio* 만 사용 — 외부 네트워크 X. PII 데이터 외부 유출 없음.
 *
 * NOTE: `@modelcontextprotocol/sdk` / `zod` import 는 이 파일(mcp/)에만 허용된다
 * (코어 의존성 분리 유지 — 다른 src 모듈은 Node 표준만 import).
 */

import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { riskLevelName, score_combined_risk } from "../analytics/index.js";
import { Anonymizer } from "../anonymizer.js";
import { ProcessingMode } from "../core/modes.js";
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
function textResult(
  payload: unknown,
  indent: number | null = 2,
): {
  content: { type: "text"; text: string }[];
} {
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

/**
 * ko-pii MCP 서버 인스턴스 생성 + 도구 4개 등록.
 * stdio 대신 InMemoryTransport 로 연결해 테스트할 수 있다 (tests/unit/mcp-server.test.ts).
 */
export function buildMcpServer(): McpServer {
  const server = new McpServer({ name: "ko-pii", version: VERSION });

  server.registerTool(
    "detect_pii",
    {
      description:
        "한국 공공 PII 검출. text 를 분석해 검출된 PII 의 라벨·위치·신뢰도·법적 근거를 JSON 으로 반환. 가명화는 하지 않음.",
      inputSchema: {
        text: z.string().describe("분석할 텍스트"),
      },
    },
    async ({ text }) => {
      const detections = detectAll(text);
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
    },
  );

  server.registerTool(
    "anonymize",
    {
      description:
        "한국 공공 PII 검출 + 가명화. vault_id 가 있으면 같은 세션의 기존 vault 재사용 (같은 사람 → 같은 토큰).",
      inputSchema: {
        text: z.string(),
        mode: z.enum(["PARANOID", "STRICT", "BALANCED", "PERMISSIVE", "AUDIT"]).default("STRICT"),
        strategy: z
          .enum(["tokenize", "redact", "asterisk", "hashed", "partial", "fpe"])
          .default("tokenize"),
        vault_id: z.string().optional().describe("세션 vault ID (옵션)"),
      },
    },
    async ({ text, mode, strategy, vault_id }) => {
      let vid = vault_id;
      let vault: ReversibleVault;
      const existing = vid === undefined ? undefined : _VAULTS.get(vid);
      if (vid && existing !== undefined) {
        vault = existing;
      } else {
        vault = new ReversibleVault();
        if (!vid) {
          vid = randomUUID();
        }
        _VAULTS.set(vid, vault);
      }

      const anon = new Anonymizer(ProcessingMode[mode], strategy, vault);
      const result = anon.process(text);

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
    },
  );

  server.registerTool(
    "reveal",
    {
      description:
        "토큰에서 원본 PII 복원. vault_id 와 token 필요. 경고: 감사 로그가 활성화되지 않은 환경에서 호출 시 추적 불가.",
      inputSchema: {
        token: z.string().describe("예: <RRN_1>"),
        vault_id: z.string(),
      },
    },
    async ({ token, vault_id }) => {
      const vault = _VAULTS.get(vault_id);
      if (vault === undefined) {
        return textResult({ error: `unknown vault_id: ${vault_id}` }, null);
      }
      const original = vault.reveal(token, "MCP reveal");
      return textResult({
        token,
        original,
        found: original !== null,
      });
    },
  );

  server.registerTool(
    "combined_risk",
    {
      description:
        "텍스트의 결합 위험도 평가 — 「개인정보 비식별 조치 가이드라인」 기준 식별자/준식별자/민감속성 분류 후 종합 위험도 산출.",
      inputSchema: {
        text: z.string(),
      },
    },
    async ({ text }) => {
      const cr = score_combined_risk(detectAll(text));
      return textResult({
        risk_level: riskLevelName(cr.combined_risk),
        rationale: [...cr.rationale],
        identifiers: [...cr.distinct_identifiers],
        quasi_identifiers: [...cr.distinct_quasi],
        sensitive_attributes: [...cr.sensitive_present],
      });
    },
  );

  return server;
}

/** ko-pii-mcp-server CLI entry point — stdio 전송으로 서버를 구동한다. */
export async function main(): Promise<void> {
  const server = buildMcpServer();
  await server.connect(new StdioServerTransport());
}
