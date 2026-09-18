/**
 * MCP 서버 프로토콜 테스트 — Python `ko_pii/integrations/mcp_server.py` 실측(gold) 대조.
 *
 * Python 실측 환경: venv + mcp 1.29.1, `create_connected_server_and_client_session`
 * 으로 InMemory 구동 후 도구별 출력/에러를 수집했다 (2026-08).
 * TS 측은 동일한 SDK 개념(`InMemoryTransport.createLinkedPair()` + `Client`)으로
 * 같은 프로세스에서 클라이언트↔서버를 연결해 검증한다.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { riskLevelName } from "../../src/analytics/index.js";
import { detectAll } from "../../src/detect.js";
import { buildMcpServer } from "../../src/mcp/server.js";

const DETECT_TEXT = "신청인 홍길동 (880101-1234568)";
const COMBINED_TEXT = "홍길동이 880101-1234568, 서울특별시 중구 세종대로 110 거주";

/** 도구 JSON 응답의 snake_case 필드 (Python payload 구조 대응). */
interface DetectionPayload {
  label: string;
  text: string;
  start: number;
  end: number;
  risk_level: string;
  confidence: number;
  legal_basis: string | null;
  evidence: string[];
}

interface JsonSchemaProp {
  type?: string;
  description?: string;
  enum?: string[];
  default?: string;
}

interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: {
    properties?: Record<string, JsonSchemaProp>;
    required?: string[];
  };
}

const openers: Array<() => Promise<void>> = [];

async function connectClient(): Promise<Client> {
  const server = buildMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "ko-pii-test-client", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  openers.push(async () => {
    await client.close();
    await server.close();
  });
  return client;
}

afterEach(async () => {
  while (openers.length > 0) {
    const close = openers.pop();
    if (close) await close();
  }
});

/** CallToolResult 의 첫 번째 text 블록 추출 (Python types.TextContent 대응). */
function textOf(res: { content: Array<{ type: string; text?: string }> }): string {
  const block = res.content[0];
  if (block === undefined || block.type !== "text" || typeof block.text !== "string") {
    throw new Error(`expected a text content block, got: ${JSON.stringify(res.content)}`);
  }
  return block.text;
}

async function callJson(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const res = await client.callTool({ name, arguments: args });
  return JSON.parse(textOf(res)) as Record<string, unknown>;
}

describe("ko-pii MCP server", () => {
  it("tools/list: 4개 도구가 Python 과 동일한 이름·설명·inputSchema 로 노출된다", async () => {
    const client = await connectClient();
    const { tools } = await client.listTools();

    expect(tools.map((t) => t.name)).toEqual([
      "detect_pii",
      "anonymize",
      "reveal",
      "combined_risk",
    ]);

    const byName = new Map<string, ToolInfo>(tools.map((t) => [t.name, t as ToolInfo]));

    // 설명문 — Python mcp_server.py 와 문자열까지 동일
    expect(byName.get("detect_pii")?.description).toBe(
      "한국 공공 PII 검출. text 를 분석해 검출된 PII 의 라벨·위치·신뢰도·법적 근거를 JSON 으로 반환. 가명화는 하지 않음.",
    );
    expect(byName.get("anonymize")?.description).toBe(
      "한국 공공 PII 검출 + 가명화. vault_id 가 있으면 같은 세션의 기존 vault 재사용 (같은 사람 → 같은 토큰).",
    );
    expect(byName.get("reveal")?.description).toBe(
      "토큰에서 원본 PII 복원. vault_id 와 token 필요. 경고: 감사 로그가 활성화되지 않은 환경에서 호출 시 추적 불가.",
    );
    expect(byName.get("combined_risk")?.description).toBe(
      "텍스트의 결합 위험도 평가 — 「개인정보 비식별 조치 가이드라인」 기준 식별자/준식별자/민감속성 분류 후 종합 위험도 산출.",
    );

    // detect_pii: { text } 필수
    const detect = byName.get("detect_pii")?.inputSchema;
    expect(detect?.properties?.text).toEqual({
      type: "string",
      description: "분석할 텍스트",
    });
    expect(detect?.required).toEqual(["text"]);

    // anonymize: { text 필수, mode/strategy enum+기본값, vault_id 옵션 }
    const anon = byName.get("anonymize")?.inputSchema;
    expect(anon?.properties?.text).toEqual({ type: "string" });
    expect(anon?.properties?.mode?.enum).toEqual([
      "PARANOID",
      "STRICT",
      "BALANCED",
      "PERMISSIVE",
      "AUDIT",
    ]);
    expect(anon?.properties?.mode?.default).toBe("STRICT");
    expect(anon?.properties?.strategy?.enum).toEqual([
      "tokenize",
      "redact",
      "asterisk",
      "hashed",
      "partial",
      "fpe",
    ]);
    expect(anon?.properties?.strategy?.default).toBe("tokenize");
    expect(anon?.properties?.vault_id).toEqual({
      type: "string",
      description: "세션 vault ID (옵션)",
    });
    expect(anon?.required).toEqual(["text"]);

    // reveal: { token, vault_id } 둘 다 필수
    const reveal = byName.get("reveal")?.inputSchema;
    expect(reveal?.properties?.token).toEqual({ type: "string", description: "예: <RRN_1>" });
    expect(reveal?.properties?.vault_id).toEqual({ type: "string" });
    expect(reveal?.required).toEqual(["token", "vault_id"]);

    // combined_risk: { text } 필수
    const combined = byName.get("combined_risk")?.inputSchema;
    expect(combined?.properties?.text).toEqual({ type: "string" });
    expect(combined?.required).toEqual(["text"]);
  });

  it("detect_pii: 검출 JSON 이 detectAll 직접 호출과 교차 검증된다 (RRN/PERSON)", async () => {
    const client = await connectClient();
    const payload = (await callJson(client, "detect_pii", { text: DETECT_TEXT })) as {
      count: number;
      detections: DetectionPayload[];
    };
    const direct = detectAll(DETECT_TEXT);

    expect(payload.count).toBe(direct.length);
    expect(payload.detections).toHaveLength(direct.length);
    for (const [i, d] of direct.entries()) {
      const p = payload.detections[i];
      if (!p) throw new Error(`detection ${i} missing`);
      expect(p.label).toBe(d.label);
      expect(p.text).toBe(d.text);
      expect(p.start).toBe(d.start);
      expect(p.end).toBe(d.end);
      expect(p.risk_level).toBe(riskLevelName(d.riskLevel));
      expect(p.confidence).toBe(d.confidence);
      expect(p.legal_basis).toBe(d.legal_basis);
      expect(p.evidence).toEqual([...d.evidence]);
    }

    // Python 실측값 — RRN/PERSON 이 라벨·위치·법적 근거까지 동일하게 검출된다
    const rrn = payload.detections.find((d) => d.label === "RRN");
    expect(rrn).toMatchObject({
      text: "880101-1234568",
      start: 9,
      end: 23,
      risk_level: "CRITICAL",
      confidence: 1.0,
      legal_basis: "개인정보보호법 제24조의2",
      evidence: ["pattern:rrn", "date_valid:1988-01-01", "checksum:valid"],
    });
    const person = payload.detections.find((d) => d.label === "PERSON");
    expect(person).toMatchObject({
      text: "홍길동",
      start: 4,
      end: 7,
      risk_level: "HIGH",
      legal_basis: "개인정보보호법 제2조",
    });
  });

  it("anonymize: 토큰 획득, 같은 vault_id 재호출 시 동일 토큰 (세션 vault 일관성)", async () => {
    const client = await connectClient();

    // 1) vault_id 미지정 → 새 vault 생성 + uuid 반환
    const p1 = (await callJson(client, "anonymize", { text: DETECT_TEXT })) as {
      text: string;
      vault_id: string;
      combined_risk: string;
      summary: Record<string, unknown>;
    };
    expect(p1.text).toBe("신청인 <PERSON_1> (<RRN_1>)"); // Python 실측과 동일
    expect(typeof p1.vault_id).toBe("string");
    expect(p1.vault_id.length).toBeGreaterThan(0);
    expect(p1.combined_risk).toBe("CRITICAL");
    expect(p1.summary.by_label).toEqual({ PERSON: 1, RRN: 1 });
    expect(p1.summary.mode).toBe("STRICT");
    expect(p1.summary.strategy).toBe("tokenize");

    // 2) 같은 vault_id 재호출 → 같은 사람/값은 같은 토큰 (카운터 재시작 X)
    const p2 = (await callJson(client, "anonymize", {
      text: DETECT_TEXT,
      vault_id: p1.vault_id,
    })) as { text: string; vault_id: string };
    expect(p2.text).toBe(p1.text);
    expect(p2.vault_id).toBe(p1.vault_id);

    // 3) 다른 vault_id 지정 → 별도 세션 vault 로 등록 (카운터 초기화)
    const p3 = (await callJson(client, "anonymize", {
      text: DETECT_TEXT,
      vault_id: "mcp-test-vault-a",
    })) as { text: string; vault_id: string };
    expect(p3.vault_id).toBe("mcp-test-vault-a");
    expect(p3.text).toBe("신청인 <PERSON_1> (<RRN_1>)");
  });

  it("reveal: 토큰 복원, 존재하지 않는 토큰/vault_id 는 Python 실측 동작", async () => {
    const client = await connectClient();
    const anon = (await callJson(client, "anonymize", { text: DETECT_TEXT })) as {
      vault_id: string;
    };
    const vid = anon.vault_id;

    // 복원 성공 — Python 실측: { token, original, found: true }
    const good = await callJson(client, "reveal", { token: "<RRN_1>", vault_id: vid });
    expect(good).toEqual({ token: "<RRN_1>", original: "880101-1234568", found: true });

    // 존재하지 않는 토큰 — Python 실측: found=false + original=null (MCP 에러 아님)
    const miss = await callJson(client, "reveal", { token: "<RRN_999>", vault_id: vid });
    expect(miss).toEqual({ token: "<RRN_999>", original: null, found: false });

    // 존재하지 않는 vault_id — Python 실측: compact JSON 에러 본문
    const badVault = await client.callTool({
      name: "reveal",
      arguments: { token: "<RRN_1>", vault_id: "no-such-vault" },
    });
    expect(textOf(badVault)).toBe('{"error": "unknown vault_id: no-such-vault"}');
  });

  it("combined_risk: 이름+RRN+주소 → CRITICAL (Python 실측 분류와 동일)", async () => {
    const client = await connectClient();
    const payload = await callJson(client, "combined_risk", { text: COMBINED_TEXT });

    expect(payload.risk_level).toBe("CRITICAL");
    expect(payload.identifiers).toEqual(["RRN"]);
    expect(payload.quasi_identifiers).toEqual(["ADDRESS", "PERSON"]);
    expect(payload.sensitive_attributes).toEqual([]);
    const rationale = payload.rationale;
    expect(Array.isArray(rationale)).toBe(true);
    expect((rationale as string[]).length).toBeGreaterThan(0);
  });
});
