/**
 * CLI 1.27 — Python tests/unit/test_cli.py (감사 fail-closed) + test_safe_processing.py 의 CLI 케이스.
 * Python monkeypatch 대상은 `cliHooks` 로 교체한다. 기대값은 Python v1.27.0 실측.
 */
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import JSZip from "jszip";
import { afterEach, describe, expect, it } from "vitest";
import { cliHooks, main } from "../../src/cli/main.js";
import { AuditLog } from "../../src/vault/audit.js";
import { loadEncrypted, saveEncrypted } from "../../src/vault/encrypted.js";
import { ReversibleVault } from "../../src/vault/reversible.js";

const original = { ...cliHooks };
afterEach(() => {
  Object.assign(cliHooks, original);
  delete process.env.KPII_VAULT_PASSWORD;
});

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "ko-pii-cli127-"));
}

async function capture(
  run: () => Promise<number>,
): Promise<{ rc: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const o = process.stdout.write;
  const e = process.stderr.write;
  const sink = (into: string[]) =>
    ((chunk: string | Uint8Array) => {
      into.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
      return true;
    }) as typeof process.stdout.write;
  process.stdout.write = sink(out);
  process.stderr.write = sink(err);
  try {
    const rc = await run();
    return { rc, out: out.join(""), err: err.join("") };
  } finally {
    process.stdout.write = o;
    process.stderr.write = e;
  }
}

function source(dir: string, text = "주민번호 880101-1234568"): string {
  const path = join(dir, "in.txt");
  writeFileSync(path, text, "utf-8");
  return path;
}

describe("감사 로그 fail-closed (test_cli.py)", () => {
  it("test_cli_audit_is_fail_closed_by_default_and_closes_log", async () => {
    const dir = tmp();
    const out = join(dir, "out.txt");
    let closed = false;
    cliHooks.createAudit = (path) =>
      new (class extends AuditLog {
        override recordStore(): void {
          throw Object.assign(new Error("audit unavailable"), { code: "EIO", errno: -5 });
        }
        override close(): void {
          closed = true;
        }
      })(path);
    const { rc } = await capture(() =>
      main([source(dir), "-o", out, "--audit-log", join(dir, "audit")]),
    );
    expect(rc).toBe(1);
    expect(existsSync(out)).toBe(false);
    expect(closed).toBe(true);
  });

  it("test_cli_can_opt_into_best_effort_audit", async () => {
    const dir = tmp();
    const out = join(dir, "out.txt");
    const ioError = () => Object.assign(new Error("audit unavailable"), { code: "EIO", errno: -5 });
    cliHooks.createAudit = (path) =>
      new (class extends AuditLog {
        override record(): void {
          throw ioError();
        }
        override close(): void {
          throw ioError();
        }
      })(path);
    const { rc, err } = await capture(() =>
      main([
        source(dir),
        "-o",
        out,
        "--audit-log",
        join(dir, "audit"),
        "--audit-failure-policy",
        "best_effort",
        "--json-summary",
      ]),
    );
    expect(rc).toBe(0);
    expect(readFileSync(out, "utf-8")).toContain("<RRN_1>");
    const warnings = (JSON.parse(err) as { warnings: string[] }).warnings;
    expect(warnings.some((w) => w.includes("감사 레코드를 기록하지 못했습니다"))).toBe(true);
    expect(warnings.some((w) => w.includes("감사 로그를 정상적으로 종료하지 못했"))).toBe(true);
  });

  it("test_cli_best_effort_continues_when_audit_log_cannot_open", async () => {
    const dir = tmp();
    const out = join(dir, "out.txt");
    const { rc, err } = await capture(() =>
      main([
        source(dir),
        "-o",
        out,
        "--audit-log",
        join(dir, "missing", "audit.jsonl"),
        "--audit-failure-policy",
        "best_effort",
        "--json-summary",
      ]),
    );
    expect(rc).toBe(0);
    expect(readFileSync(out, "utf-8")).toContain("<RRN_1>");
    expect((JSON.parse(err) as { warnings: string[] }).warnings).toEqual([
      "경고: 감사 로그를 열지 못해 감사 기록 없이 계속합니다 (FileNotFoundError).",
    ]);
  });

  it("test_cli_audit_open_failure_is_fail_closed_by_default", async () => {
    const dir = tmp();
    const out = join(dir, "out.txt");
    const { rc, err } = await capture(() =>
      main([source(dir), "-o", out, "--audit-log", join(dir, "missing", "audit.jsonl")]),
    );
    expect(rc).toBe(1);
    expect(err).toBe("ko-pii: audit_open_failed: audit_open could not be completed\n");
    expect(existsSync(out)).toBe(false);
  });

  it("test_cli_strict_audit_close_failure_prevents_output", async () => {
    const dir = tmp();
    const out = join(dir, "out.txt");
    cliHooks.createAudit = (path) =>
      new (class extends AuditLog {
        override close(): void {
          throw Object.assign(new Error("close"), { code: "EIO", errno: -5 });
        }
      })(path);
    const { rc, err } = await capture(() =>
      main([source(dir), "-o", out, "--audit-log", join(dir, "audit.jsonl")]),
    );
    expect(rc).toBe(1);
    expect(err).toBe("ko-pii: audit_finalize_failed: audit_finalize could not be completed\n");
    expect(existsSync(out)).toBe(false);
  });

  it("test_cli_audit_marks_prepared_not_persisted_before_output", async () => {
    const dir = tmp();
    const src = source(dir);
    const events: unknown[] = [];
    cliHooks.createAudit = (path) =>
      new (class extends AuditLog {
        override recordStore(): void {}
        override recordAnonymize(count: number, mode: string, opts: object = {}): void {
          events.push({ count, mode, ...opts });
        }
      })(path);
    cliHooks.writeOutput = () => {
      throw Object.assign(new Error("output unavailable"), { code: "EIO", errno: -5 });
    };
    const { rc, err } = await capture(() =>
      main([src, "-o", join(dir, "out.txt"), "--audit-log", join(dir, "audit.jsonl")]),
    );
    expect(rc).toBe(1);
    expect(err).toBe("ko-pii: output_write_failed: output_write could not be completed\n");
    expect(events).toEqual([{ count: 1, mode: "STRICT", status: "prepared", context: src }]);
  });

  it("test_cli_summary_audit_failure_prevents_output_in_strict_mode", async () => {
    const dir = tmp();
    const out = join(dir, "out.txt");
    cliHooks.createAudit = (path) =>
      new (class extends AuditLog {
        override recordAnonymize(): void {
          throw Object.assign(new Error("summary"), { code: "EIO", errno: -5 });
        }
      })(path);
    const { rc } = await capture(() =>
      main([source(dir), "-s", "redact", "-o", out, "--audit-log", join(dir, "audit")]),
    );
    expect(rc).toBe(1);
    expect(existsSync(out)).toBe(false);
  });

  it("실제 감사 파일에 prepared 레코드가 남는다", async () => {
    const dir = tmp();
    const audit = join(dir, "audit.jsonl");
    const { rc } = await capture(() =>
      main([source(dir), "-o", join(dir, "o.txt"), "--audit-log", audit]),
    );
    expect(rc).toBe(0);
    const last = JSON.parse(readFileSync(audit, "utf-8").trim().split("\n").at(-1) as string);
    expect(last.extra).toEqual({ count: 1, mode: "STRICT", status: "prepared" });
  });
});

describe("batch 미지원 옵션 (test_cli.py)", () => {
  for (const [option, value] of [
    ["--audit-log", "state"],
    ["--audit-log", ""],
    ["--vault", "state"],
    ["--vault", ""],
    ["--vault-password", "state"],
    ["--vault-password", ""],
  ] as const) {
    it(`test_cli_batch_rejects_unsupported_security_state_options[${option}=${value}]`, async () => {
      const dir = tmp();
      mkdirSync(join(dir, "in"));
      writeFileSync(join(dir, "in", "one.txt"), "연락처 010-1234-5678");
      const { rc, err } = await capture(() => main([join(dir, "in"), "--batch", option, value]));
      expect(rc).toBe(2);
      expect(err).toContain(option);
      expect(existsSync(join(dir, "anon"))).toBe(false);
    });
  }

  it("test_cli_json_summary_rejects_interactive_password_prompt", async () => {
    const dir = tmp();
    cliHooks.promptPassword = () => {
      throw new Error("unexpected password prompt");
    };
    const { rc, err } = await capture(() =>
      main([source(dir), "--vault", join(dir, "v.kvault"), "--vault-password", "--json-summary"]),
    );
    expect(rc).toBe(2);
    expect(err).toContain("KPII_VAULT_PASSWORD");
  });
});

describe("안전 처리 (test_safe_processing.py)", () => {
  it("test_cli_does_not_publish_when_vault_storage_fails", async () => {
    const dir = tmp();
    cliHooks.saveVault = () => {
      throw Object.assign(new Error("vault unavailable"), { code: "EIO", errno: -5 });
    };
    const { rc, out, err } = await capture(() =>
      main([source(dir, "연락처 010-1234-5678"), "--vault", join(dir, "vault")]),
    );
    expect(rc).toBe(1);
    expect(out).toBe("");
    expect(err).toBe("ko-pii: vault_save_failed: vault_save could not be completed\n");
  });

  it("test_cli_password_is_requested_once_for_load_and_save", async () => {
    const dir = tmp();
    const vault = join(dir, "vault");
    saveEncrypted(new ReversibleVault(), vault, "test-password");
    const prompts: string[] = [];
    cliHooks.promptPassword = (prompt) => {
      prompts.push(prompt);
      return "test-password";
    };
    const { rc } = await capture(() =>
      main([source(dir, "연락처 010-1234-5678"), "--vault", vault, "--vault-password"]),
    );
    expect(rc).toBe(0);
    expect(prompts).toEqual(["Vault password: "]);
    expect(loadEncrypted(vault, "test-password").reveal("<PHONE_1>")).toBe("010-1234-5678");
  });

  it("빈 프롬프트 비밀번호는 vault_load 실패", async () => {
    const dir = tmp();
    const vault = join(dir, "vault");
    saveEncrypted(new ReversibleVault(), vault, "test-password");
    cliHooks.promptPassword = () => "";
    const { rc, err } = await capture(() =>
      main([source(dir), "--vault", vault, "--vault-password"]),
    );
    expect(rc).toBe(1);
    expect(err).toBe("ko-pii: vault_load_failed: vault_load could not be completed\n");
  });

  for (const option of ["--vault", "--output", "--report", "--audit-log"]) {
    it(`test_cli_rejects_paths_aliasing_input[${option}]`, async () => {
      const dir = tmp();
      const src = source(dir, "original");
      const { rc, err } = await capture(() => main([src, option, src]));
      expect(rc).toBe(2);
      expect(err).toMatch(/ko-pii: error: \w+ and input must use different files\n$/);
      expect(readFileSync(src, "utf-8")).toBe("original");
    });
  }

  it("test_cli_rejects_hardlinked_outputs", async () => {
    const dir = tmp();
    const vault = join(dir, "vault");
    writeFileSync(vault, "state");
    const output = join(dir, "out.txt");
    linkSync(vault, output);
    const { rc, err } = await capture(() =>
      main([source(dir, "original"), "--vault", vault, "-o", output]),
    );
    expect(rc).toBe(2);
    expect(err).toContain("ko-pii: error: vault and output must use different files");
  });

  it("test_cli_limits_report_json_without_publishing", async () => {
    const dir = tmp();
    const output = join(dir, "out.txt");
    const { rc, err } = await capture(() =>
      main([source(dir, "oversized"), "--max-file-bytes", "2", "-o", output, "--json-summary"]),
    );
    expect(rc).toBe(1);
    expect(JSON.parse(err)).toMatchObject({
      status: "failed",
      error: "file_too_large",
      stage: "extraction",
      vault_saved: false,
      output_state: "not_written",
    });
    expect(existsSync(output)).toBe(false);
  });

  it("test_cli_stdin_is_bounded", async () => {
    cliHooks.readStdin = () => Buffer.from("가나다라", "utf-8");
    const { rc, out, err } = await capture(() =>
      main(["-", "--max-file-bytes", "3", "--json-summary"]),
    );
    expect(rc).toBe(1);
    expect(out).toBe("");
    expect((JSON.parse(err) as { error: string }).error).toBe("stdin_too_large");
  });

  it("stdin 줄바꿈은 바꾸지 않는다 (Python 실측)", async () => {
    cliHooks.readStdin = () => Buffer.from("연락처 010-1234-5678\r\n끝\r", "utf-8");
    const { rc, out } = await capture(() => main(["-", "-s", "redact"]));
    expect(rc).toBe(0);
    expect(out).toBe("연락처 [전화번호]\r\n끝\r\n");
  });

  it("test_batch_rejects_zip_expansion_without_output", async () => {
    const dir = tmp();
    const zip = new JSZip();
    zip.file("Contents/section0.xml", "A".repeat(20_000));
    const src = join(dir, "input.hwpx");
    writeFileSync(src, await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" }));
    const output = join(dir, "out");
    const { rc, err } = await capture(() =>
      main([src, "--batch", "--output-dir", output, "--json-summary"]),
    );
    expect(rc).toBe(1);
    const result = (JSON.parse(err) as { results: Array<Record<string, unknown>> }).results[0];
    expect(result?.error_code).toBe("compression_ratio_exceeded");
    expect(Object.keys(result ?? {})).toEqual([
      "input_path",
      "output_path",
      "detections",
      "combined_risk",
      "blocked",
      "review",
      "error",
      "elapsed_s",
      "error_code",
      "coverage",
    ]);
    expect(existsSync(output)).toBe(false);
  });

  it("test_cli_batch_output_ancestor_returns_failure_json", async () => {
    const dir = tmp();
    mkdirSync(join(dir, "in"));
    writeFileSync(join(dir, "in", "doc.txt"), "original");
    const { rc, err } = await capture(() =>
      main([join(dir, "in"), "--batch", "--output-dir", dir, "--json-summary"]),
    );
    expect(rc).toBe(1);
    expect(JSON.parse(err)).toEqual({
      status: "failed",
      error: "batch_configuration",
      stage: "batch",
      message: "batch could not be completed",
      vault_saved: false,
      output_state: "not_written",
    });
  });
});

describe("설정 검증 (Python 실측 메시지·종료 코드)", () => {
  it("잘못된 라벨 필터는 invalid_label_filter, 종료 2", async () => {
    const dir = tmp();
    const { rc, err } = await capture(() => main([source(dir), "--include", "RRN,"]));
    expect(rc).toBe(2);
    expect(err).toBe("ko-pii: invalid_label_filter: configuration could not be completed\n");
  });

  it("--strategy-for 오류는 invalid_processing_policy", async () => {
    const dir = tmp();
    const { rc, err } = await capture(() => main([source(dir), "--strategy-for", "PHONE"]));
    expect(rc).toBe(2);
    expect(err).toBe("ko-pii: invalid_processing_policy: configuration could not be completed\n");
  });

  it("--strategy-for 는 반복 가능하고 요약에 종류별 전략이 나온다", async () => {
    const dir = tmp();
    const { rc, out, err } = await capture(() =>
      main([
        source(dir, "연락처 010-1234-5678 주민 880101-1234568"),
        "-s",
        "redact",
        "--strategy-for",
        "PHONE=asterisk",
        "--strategy-for",
        "RRN=tokenize",
      ]),
    );
    expect(rc).toBe(0);
    expect(out).toBe("연락처 ************* 주민 <RRN_1>\n");
    expect(err).toContain("종류별 전략: {'PHONE': 'asterisk', 'RRN': 'tokenize'}");
  });

  it("한도·시간 옵션 검증은 argparse 오류 (종료 2)", async () => {
    const dir = tmp();
    const zero = await capture(() => main([source(dir), "--max-file-bytes", "0"]));
    expect(zero.rc).toBe(2);
    expect(zero.err).toContain("ko-pii: error: all bounded-read limits must be positive integers");
    const nan = await capture(() => main([source(dir), "--extraction-timeout", "nan"]));
    expect(nan.err).toContain("ko-pii: error: extraction timeout must be finite and positive");
    const bad = await capture(() => main([source(dir), "--extraction-timeout", "abc"]));
    expect(bad.err).toContain("argument --extraction-timeout: invalid float value: 'abc'");
  });

  it("--trace-limit 은 --explain 이 필요하다", async () => {
    const dir = tmp();
    const { rc, err } = await capture(() => main([source(dir), "--trace-limit", "3"]));
    expect(rc).toBe(2);
    expect(err).toContain("--trace-limit requires --explain and must be between 0 and 1000");
  });

  it("--policy 는 처리 정책 플래그와 함께 쓸 수 없다", async () => {
    const dir = tmp();
    const policy = join(dir, "p.json");
    writeFileSync(policy, JSON.stringify({ schema_version: 1, name: "p", settings: {} }));
    const { rc, err } = await capture(() =>
      main([source(dir), "--policy", policy, "-m", "STRICT"]),
    );
    expect(rc).toBe(2);
    expect(err).toContain("--policy cannot be combined with processing-policy or model flags");
  });

  it("--policy 프로파일의 모드·전략을 쓴다", async () => {
    const dir = tmp();
    const policy = join(dir, "p.json");
    writeFileSync(
      policy,
      JSON.stringify({
        schema_version: 1,
        name: "p",
        settings: { mode: "STRICT", strategy: "redact" },
      }),
    );
    const { rc, out } = await capture(() =>
      main([source(dir, "연락처 010-1234-5678"), "--policy", policy]),
    );
    expect(rc).toBe(0);
    expect(out).toBe("연락처 [전화번호]\n");
  });
});

describe("JSON 모드와 explain", () => {
  it("--format json 은 키를 보존하고 Python float 표기를 지킨다", async () => {
    const dir = tmp();
    const src = join(dir, "doc.json");
    writeFileSync(src, '{"phone": "010-1234-5678", "score": 1.0, "n": 12345678901234567890}');
    const { rc, out, err } = await capture(() => main([src, "--format", "json"]));
    expect(rc).toBe(0);
    expect(out).toBe(
      '{\n  "phone": "<PHONE_1>",\n  "score": 1.0,\n  "n": 12345678901234567890\n}\n',
    );
    expect(err).toBe("Processed 1 document(s); 1 detection(s). Keys not screened.\n");
  });

  it("--format jsonl 은 문서마다 한 줄", async () => {
    const dir = tmp();
    const src = join(dir, "doc.jsonl");
    writeFileSync(src, '{"a": "010-1234-5678", "x": 2.50}\n\n{"b": "hong@example.com"}\n');
    const { rc, out } = await capture(() => main([src, "--format", "jsonl", "-s", "redact"]));
    expect(rc).toBe(0);
    expect(out).toBe('{"a": "[전화번호]", "x": 2.5}\n{"b": "[이메일]"}\n');
  });

  it("text 모드 필드 옵션은 argparse 오류", async () => {
    const dir = tmp();
    const { rc, err } = await capture(() => main([source(dir), "--field-label", "/a=PHONE"]));
    expect(rc).toBe(2);
    expect(err).toContain("field options require --format json or jsonl");
  });

  it("--explain 은 값 없는 JSON (confidence 는 float 표기)", async () => {
    const dir = tmp();
    const explain = join(dir, "e.json");
    const { rc } = await capture(() =>
      main([source(dir), "-o", join(dir, "o.txt"), "--explain", explain, "--trace-limit", "2"]),
    );
    expect(rc).toBe(0);
    const text = readFileSync(explain, "utf-8");
    expect(text).toContain('"confidence": 1.0');
    expect(text).not.toContain("880101-1234568");
    const report = JSON.parse(text) as Record<string, unknown>;
    expect(report.contract).toBe("ko-pii-explanation-v1");
    expect(report.overlap_trace).toMatchObject({ limit: 2 });
  });

  it("--report 는 기본적으로 값과 문서 식별자를 싣지 않는다", async () => {
    const dir = tmp();
    const src = source(dir);
    const report = join(dir, "r.txt");
    const { rc } = await capture(() => main([src, "-o", join(dir, "o.txt"), "--report", report]));
    expect(rc).toBe(0);
    const text = readFileSync(report, "utf-8");
    expect(text).toContain("  - RRN @[5, 19] strategy=tokenize status=substituted");
    expect(text).not.toContain(src);
    expect(text).not.toContain("<RRN_1>");
  });
});

describe("--format json/jsonl 키 순서 (Python 실측 바이트)", () => {
  it("정수형 키·'__proto__'·중첩 객체가 원본 순서로 나온다", async () => {
    const dir = tmp();
    const src = join(dir, "in.json");
    writeFileSync(
      src,
      '{"b":"x","2023":"010-1234-5678","1":{"z":"a@b.co","0":1.5},"__proto__":2.0}',
      "utf-8",
    );
    const { rc, out, err } = await capture(() => main([src, "--format", "json", "-s", "redact"]));
    expect(rc).toBe(0);
    expect(err).toBe("Processed 1 document(s); 2 detection(s). Keys not screened.\n");
    expect(out).toBe(
      '{\n  "b": "x",\n  "2023": "[전화번호]",\n  "1": {\n    "z": "[이메일]",\n    "0": 1.5\n  },\n  "__proto__": 2.0\n}\n',
    );
  });

  it("jsonl", async () => {
    const dir = tmp();
    const src = join(dir, "in.jsonl");
    writeFileSync(
      src,
      '{"b":"x","1":"010-1234-5678"}\n{"__proto__":{"9":"a@b.co","0":1e2}}\n',
      "utf-8",
    );
    const { rc, out } = await capture(() => main([src, "--format", "jsonl", "-s", "redact"]));
    expect(rc).toBe(0);
    expect(out).toBe(
      '{"b": "x", "1": "[전화번호]"}\n{"__proto__": {"9": "[이메일]", "0": 100.0}}\n',
    );
  });
});

describe("JSON 모드 — 2^53 밖 정수 정밀도 (Python json.loads int 실측)", () => {
  const vaultOriginals = (path: string): string[] =>
    Object.values(
      (JSON.parse(readFileSync(path, "utf-8")) as { entries: Record<string, { original: string }> })
        .entries,
    ).map((entry) => entry.original);

  it("--field-label 단언 정수는 vault 에 원본 숫자열 그대로 저장된다", async () => {
    const dir = tmp();
    const src = join(dir, "in.json");
    writeFileSync(src, '{"acct": 98765432109876543210}', "utf-8");
    const vault = join(dir, "v.json");
    const out = join(dir, "out.json");
    const { rc } = await capture(() =>
      main([
        src,
        "--format",
        "json",
        "--field-label",
        "/acct=ACCOUNT",
        "--vault",
        vault,
        "-o",
        out,
      ]),
    );
    expect(rc).toBe(0);
    expect(readFileSync(out, "utf-8")).toBe('{\n  "acct": "<ACCOUNT_1>"\n}\n');
    expect(vaultOriginals(vault)).toEqual(["98765432109876543210"]);
  });

  it("비단언 큰 정수·음수·-0·배열 원소는 원본 값 그대로 출력된다", async () => {
    const dir = tmp();
    const src = join(dir, "in.json");
    writeFileSync(
      src,
      '{"acct": 98765432109876543210, "n": 12345678901234567890123, "neg": -98765432109876543210, "z": -0, "f": 1e300, "a": [18446744073709551616]}',
      "utf-8",
    );
    const out = join(dir, "out.json");
    const { rc } = await capture(() =>
      main([src, "--format", "json", "--field-label", "/acct=ACCOUNT", "-o", out]),
    );
    expect(rc).toBe(0);
    expect(readFileSync(out, "utf-8")).toBe(
      '{\n  "acct": "<ACCOUNT_1>",\n  "n": 12345678901234567890123,\n  "neg": -98765432109876543210,\n  "z": 0,\n  "f": 1e+300,\n  "a": [\n    18446744073709551616\n  ]\n}\n',
    );
  });

  it("JSONL 도 문서별로 큰 정수를 보존한다", async () => {
    const dir = tmp();
    const src = join(dir, "in.jsonl");
    writeFileSync(
      src,
      '{"acct": 98765432109876543210}\n{"acct": 9007199254740993, "b": [1, 9007199254740993]}\n',
      "utf-8",
    );
    const vault = join(dir, "v.json");
    const out = join(dir, "out.jsonl");
    const { rc } = await capture(() =>
      main([
        src,
        "--format",
        "jsonl",
        "--field-label",
        "/acct=ACCOUNT",
        "--vault",
        vault,
        "-o",
        out,
      ]),
    );
    expect(rc).toBe(0);
    expect(readFileSync(out, "utf-8")).toBe(
      '{"acct": "<ACCOUNT_1>"}\n{"acct": "<ACCOUNT_2>", "b": [1, 9007199254740993]}\n',
    );
    expect(vaultOriginals(vault).sort()).toEqual(["9007199254740993", "98765432109876543210"]);
  });

  it("정수 자릿수 상한 4300 (Python int_max_str_digits) — 초과는 processing_failed", async () => {
    const dir = tmp();
    const ok = join(dir, "ok.json");
    writeFileSync(ok, `{"a": -${"9".repeat(4300)}}`, "utf-8");
    const okOut = join(dir, "ok.out.json");
    expect((await capture(() => main([ok, "--format", "json", "-o", okOut]))).rc).toBe(0);
    expect(readFileSync(okOut, "utf-8")).toBe(`{\n  "a": -${"9".repeat(4300)}\n}\n`);

    const bad = join(dir, "bad.json");
    writeFileSync(bad, `{"a": ${"9".repeat(4301)}}`, "utf-8");
    const { rc, err } = await capture(() =>
      main([bad, "--format", "json", "-o", join(dir, "bad.out.json")]),
    );
    expect(rc).toBe(1);
    expect(err).toBe("ko-pii: processing_failed: processing could not be completed\n");
  });
});
