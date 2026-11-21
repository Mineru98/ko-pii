/**
 * MCP 서버 1.27 — Python tests/unit/integrations/test_mcp_server.py 포트.
 * 실제 stdio 전송(tsx 로 bin 실행)과 InMemory 전송 둘 다로 검증한다.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { buildMcpServer, callTool } from "../../src/mcp/server.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
});

type Result = { isError?: boolean; content: Array<{ type: string; text?: string }> };

async function inMemory(): Promise<Client> {
  const server = buildMcpServer();
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([server.connect(b), client.connect(a)]);
  closers.push(async () => {
    await client.close();
    await server.close();
  });
  return client;
}

async function stdio(): Promise<{ client: Client; stderr: () => string }> {
  const transport = new StdioClientTransport({
    command: join(ROOT, "node_modules", ".bin", "tsx"),
    args: [join(ROOT, "src", "mcp", "bin.ts")],
    stderr: "pipe",
  });
  const chunks: string[] = [];
  transport.stderr?.on("data", (c: Buffer) => chunks.push(c.toString("utf8")));
  const client = new Client({ name: "t", version: "0" });
  await client.connect(transport);
  closers.push(() => client.close());
  return { client, stderr: () => chunks.join("") };
}

function payload(result: unknown): Record<string, unknown> {
  const r = result as Result;
  expect(r.isError ?? false).toBe(false);
  return JSON.parse(r.content[0]?.text as string) as Record<string, unknown>;
}

async function call(client: Client, name: string, args: Record<string, unknown>) {
  return client.callTool({ name, arguments: args });
}

describe("test_real_stdio_all_tools_and_vault_reuse", () => {
  it("실제 stdio 로 4개 도구·vault 재사용·빈 텍스트", async () => {
    const { client, stderr } = await stdio();
    expect(client.getServerVersion()?.name).toBe("ko-pii");
    const tools = new Map((await client.listTools()).tools.map((t) => [t.name, t]));
    expect([...tools.keys()].sort()).toEqual([
      "anonymize",
      "combined_risk",
      "detect_pii",
      "reveal",
    ]);
    expect(tools.get("anonymize")?.inputSchema.required).toEqual(["text"]);
    const props = tools.get("anonymize")?.inputSchema.properties as
      | Record<string, { default?: string }>
      | undefined;
    expect(props?.mode?.default).toBe("STRICT");

    const masked = payload(await call(client, "anonymize", { text: "메일 demo@example.com" }));
    expect(masked.text).toBe("메일 <EMAIL_1>");
    const reused = payload(
      await call(client, "anonymize", {
        text: "demo@example.com next@example.com",
        vault_id: masked.vault_id,
      }),
    );
    expect(reused.text).toBe("<EMAIL_1> <EMAIL_2>");
    expect(
      payload(await call(client, "reveal", { vault_id: masked.vault_id, token: "<EMAIL_1>" })),
    ).toEqual({ token: "<EMAIL_1>", original: "demo@example.com", found: true });
    const missing = payload(
      await call(client, "reveal", { vault_id: masked.vault_id, token: "<EMAIL_999>" }),
    );
    expect(missing.original).toBeNull();
    expect(missing.found).toBe(false);
    const detected = payload(await call(client, "detect_pii", { text: "demo@example.com" }));
    expect(detected.count).toBe(1);
    const risk = payload(await call(client, "combined_risk", { text: "demo@example.com" }));
    expect(Object.keys(risk).sort()).toEqual([
      "identifiers",
      "quasi_identifiers",
      "rationale",
      "risk_level",
      "sensitive_attributes",
    ]);
    expect(payload(await call(client, "anonymize", { text: "" })).text).toBe("");
    expect(stderr()).not.toContain("demo@example.com");
  }, 30_000);
});

describe("복원 경로 (Python 실측)", () => {
  it("test_real_stdio_korean_declaration_and_nested_address_restore_every_piece", async () => {
    const client = await inMemory();
    const source = "담당자는 김다은입니다. 주소: 서울특별시 강남구 테헤란로 152 (010-1234-5678)";
    const masked = payload(await call(client, "anonymize", { text: source }));
    expect(masked.text).toBe("담당자는 <PERSON_1>입니다. 주소: <ADDRESS_1><PHONE_1><ADDRESS_2>");
    let restored = masked.text as string;
    for (const token of ["<PERSON_1>", "<ADDRESS_1>", "<PHONE_1>", "<ADDRESS_2>"]) {
      const value = payload(await call(client, "reveal", { vault_id: masked.vault_id, token }));
      expect(value.found).toBe(true);
      restored = restored.replace(token, value.original as string);
    }
    expect(restored).toBe(source);
  });

  it("test_real_stdio_financial_quotes_keep_the_numeric_vault_value", async () => {
    const client = await inMemory();
    const source = "계좌번호=“110-123-456789”\n카드: 4111-1111-1111-1111";
    const masked = payload(await call(client, "anonymize", { text: source }));
    expect(masked.text).toBe("계좌번호=“<ACCOUNT_1>”\n카드: <CARD_1>");
    const value = payload(
      await call(client, "reveal", { vault_id: masked.vault_id, token: "<ACCOUNT_1>" }),
    );
    expect(value.original).toBe("110-123-456789");
  });
});

describe("test_stdio_rejects_bad_calls_without_echoing_pii", () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ["anonymize", {}, "Invalid tool arguments"],
    ["anonymize", { text: 42 }, "Invalid tool arguments"],
    ["anonymize", { text: ["secret@example.com"] }, "Invalid tool arguments"],
    ["anonymize", { text: null }, "Invalid tool arguments"],
    [
      "anonymize",
      { text: "secret@example.com", mode: "secret@example.com" },
      "Invalid tool arguments",
    ],
    [
      "anonymize",
      { text: "secret@example.com", strategy: "secret@example.com" },
      "Invalid tool arguments",
    ],
    ["anonymize", { text: "secret@example.com", vault_id: 42 }, "Invalid tool arguments"],
    ["detect_pii", { text: { "secret@example.com": 1 } }, "Invalid tool arguments"],
    ["combined_risk", {}, "Invalid tool arguments"],
    ["reveal", { token: "secret@example.com" }, "Invalid tool arguments"],
    ["reveal", { token: "<EMAIL_1>", vault_id: "secret@example.com" }, "Tool execution failed"],
    ["secret@example.com", { text: "secret@example.com" }, "Unknown tool"],
  ];
  for (const [name, args, message] of cases) {
    it(`${name} ${JSON.stringify(args)}`, async () => {
      const client = await inMemory();
      const result = (await call(client, name, args)) as Result;
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result)).not.toContain("secret@example.com");
      expect(result.content[0]?.text).toBe(`{"error": "${message}"}`);
      // 잘못된 호출이 다음 호출을 오염시키지 않는다
      expect(payload(await call(client, "anonymize", { text: "ok@example.com" })).text).toBe(
        "<EMAIL_1>",
      );
    });
  }

  it("거부된 anonymize 는 vault_id 를 등록하지 않는다", async () => {
    const client = await inMemory();
    const bad = (await call(client, "anonymize", {
      text: "x",
      vault_id: "fresh-id",
      mode: "NOPE",
    })) as Result;
    expect(bad.isError).toBe(true);
    const reveal = (await call(client, "reveal", {
      token: "<EMAIL_1>",
      vault_id: "fresh-id",
    })) as Result;
    expect(reveal.content[0]?.text).toBe('{"error": "Tool execution failed"}');
  });
});

describe("성공 응답의 isError: false 명시 (Python CallToolResult 직렬화)", () => {
  it("callTool 결과 키는 content, isError 순서이며 isError 는 false", async () => {
    const result = await callTool("detect_pii", { text: "010-1234-5678" });
    expect(Object.keys(result)).toEqual(["content", "isError"]);
    expect(result.isError).toBe(false);
  });

  it("전송 계층을 거친 4개 도구 성공 응답 모두 isError 필드를 싣는다", async () => {
    const client = await inMemory();
    const anonymized = (await call(client, "anonymize", {
      text: "메일 demo@example.com",
    })) as Result;
    const vaultId = payload(anonymized).vault_id as string;
    const results = [
      anonymized,
      (await call(client, "detect_pii", { text: "010-1234-5678" })) as Result,
      (await call(client, "combined_risk", { text: "010-1234-5678" })) as Result,
      (await call(client, "reveal", { token: "<EMAIL_1>", vault_id: vaultId })) as Result,
    ];
    for (const result of results) {
      expect(Object.hasOwn(result, "isError")).toBe(true);
      expect(result.isError).toBe(false);
    }
  });
});
