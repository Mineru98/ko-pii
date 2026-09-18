/**
 * CLI 단위 테스트 — Python tests/unit/test_cli.py 1:1 포트 (+argparse 동작 보강).
 *
 * 원본 5개 테스트:
 *   test_cli_tokenize_writes_output_and_vault / test_cli_redact_strategy /
 *   test_cli_json_summary / test_cli_certificate_report / test_cli_include_filter
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../../src/cli/main.js";
import { ReversibleVault } from "../../src/vault/index.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ko-pii-cli-"));
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function write(p: string, text: string): void {
  writeFileSync(p, text, "utf8");
}

function read(p: string): string {
  return readFileSync(p, "utf8");
}

/** capsys 대응 — process.stderr.write 를 가로챈다. */
async function captureStderr(run: () => Promise<number>): Promise<{ rc: number; err: string }> {
  const chunks: string[] = [];
  const orig = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  try {
    const rc = await run();
    return { rc, err: chunks.join("") };
  } finally {
    process.stderr.write = orig;
  }
}

// ───────────────────────────────────────────── Python test_cli.py 포트

describe("test_cli.py 포트", () => {
  it("test_cli_tokenize_writes_output_and_vault", async () => {
    const src = join(dir, "in.txt");
    const out = join(dir, "out.txt");
    const vault = join(dir, "vault.json");
    write(src, "신청인 880101-1234568");

    const rc = await main([src, "-m", "STRICT", "-s", "tokenize", "-o", out, "--vault", vault]);
    expect(rc).toBe(0);
    const body = read(out);
    expect(body).toContain("<RRN_1>");
    expect(body).not.toContain("880101-1234568");
    // Vault saved
    expect(existsSync(vault)).toBe(true);
    const v = ReversibleVault.load(vault);
    expect(v.reveal("<RRN_1>")).toBe("880101-1234568");
  });

  it("test_cli_redact_strategy", async () => {
    const src = join(dir, "in.txt");
    const out = join(dir, "out.txt");
    write(src, "연락처 010-1234-5678");
    const rc = await main([src, "-s", "redact", "-o", out]);
    expect(rc).toBe(0);
    expect(read(out)).toContain("[전화번호]");
  });

  it("test_cli_json_summary", async () => {
    const src = join(dir, "in.txt");
    write(src, "신청인 880101-1234568");
    const { err } = await captureStderr(() =>
      main([src, "-o", join(dir, "out.txt"), "--json-summary"]),
    );
    const payload = JSON.parse(err) as Record<string, unknown>;
    expect(payload.total).toBeGreaterThanOrEqual(1);
    expect(payload.mode).toBe("STRICT");
  });

  it("test_cli_certificate_report", async () => {
    const src = join(dir, "in.txt");
    const out = join(dir, "out.txt");
    const report = join(dir, "report.txt");
    write(src, "신청인 880101-1234568");
    await main([src, "-o", out, "--report", report]);
    expect(existsSync(report)).toBe(true);
    const content = read(report);
    expect(content).toContain("처리 증명서");
  });

  it("test_cli_include_filter", async () => {
    const src = join(dir, "in.txt");
    const out = join(dir, "out.txt");
    write(src, "주민번호 880101-1234568 연락처 010-1234-5678");
    await main([src, "-s", "redact", "-o", out, "--include", "RRN"]);
    const body = read(out);
    expect(body).toContain("[주민등록번호]");
    expect(body).toContain("010-1234-5678"); // not filtered
  });
});

// ───────────────────────────────────────────── 보강 (argparse / 옵션 동작)

describe("CLI 보강 (argparse 동작)", () => {
  it("--labels 는 33개 카테고리 표를 stdout 으로 출력하고 0 으로 끝난다", async () => {
    const chunks: string[] = [];
    const orig = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
      return true;
    }) as typeof process.stdout.write;
    try {
      const rc = await main(["--labels"]);
      expect(rc).toBe(0);
      const text = chunks.join("");
      expect(text).toContain("ko-pii PII 카테고리 33종");
      expect(text).toContain("RRN");
      expect(text).toContain("[결정적 검증] (8)");
    } finally {
      process.stdout.write = orig;
    }
  });

  it("input 누락 시 usage + error 로 코드 2", async () => {
    const { rc, err } = await captureStderr(() => main([]));
    expect(rc).toBe(2);
    expect(err).toContain("usage: ko-pii");
    expect(err).toContain("ko-pii: error: input is required (or use --labels to list categories)");
  });

  it("잘못된 --mode choices 는 코드 2 + invalid choice 메시지", async () => {
    const { rc, err } = await captureStderr(() => main(["-m", "FOO", "x.txt"]));
    expect(rc).toBe(2);
    expect(err).toContain(
      "ko-pii: error: argument -m/--mode: invalid choice: 'FOO' " +
        "(choose from PARANOID, STRICT, BALANCED, PERMISSIVE, AUDIT)",
    );
  });

  it("--workers 정수 아님 → invalid int value, 코드 2", async () => {
    const { rc, err } = await captureStderr(() => main(["--workers", "abc", "x.txt"]));
    expect(rc).toBe(2);
    expect(err).toContain("invalid int value: 'abc'");
  });

  it("존재하지 않는 파일 → 코드 1 + FileNotFoundError", async () => {
    const { rc, err } = await captureStderr(() => main(["no_such_file_cli_test.txt"]));
    expect(rc).toBe(1);
    expect(err).toContain(
      "FileNotFoundError: [Errno 2] No such file or directory: 'no_such_file_cli_test.txt'",
    );
  });

  it("--vault-password 값 직접 지정 시 경고 + 암호화 vault 저장/재복호화", async () => {
    const src = join(dir, "in.txt");
    const out = join(dir, "out.txt");
    const kvault = join(dir, "v.kvault");
    write(src, "신청인 880101-1234568");

    const { rc, err } = await captureStderr(() =>
      main([src, "-o", out, "--vault", kvault, "--vault-password", "test1234"]),
    );
    expect(rc).toBe(0);
    expect(err).toContain("경고: --vault-password 값은 프로세스 목록/셸 히스토리에 노출됩니다.");
    expect(existsSync(kvault)).toBe(true);
    expect(read(out)).toContain("<RRN_1>");

    // 암호화 vault 재로딩 — env var 경로
    process.env.KPII_VAULT_PASSWORD = "test1234";
    try {
      const out2 = join(dir, "out2.txt");
      const rc2 = await captureStderr(() => main([src, "-o", out2, "--vault", kvault]));
      expect(rc2.rc).toBe(0);
      expect(read(out2)).toContain("<RRN_1>");
    } finally {
      delete process.env.KPII_VAULT_PASSWORD;
    }

    // 비밀번호 없이 암호화 vault 읽기 → 코드 1 + 안내 메시지
    const { rc: rc3, err: err3 } = await captureStderr(() =>
      main([src, "-o", join(dir, "out3.txt"), "--vault", kvault]),
    );
    expect(rc3).toBe(1);
    expect(err3).toContain(
      "암호화 vault: --vault-password 또는 환경변수 $KPII_VAULT_PASSWORD 필요.",
    );
  });
});
