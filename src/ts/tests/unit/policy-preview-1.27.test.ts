/**
 * policy_preview 1.27 — Python tests/unit/test_policy_preview.py, test_structured_policy_preview.py
 * 대응 + Python 실측 보고서와의 바이트 대조 (policy-preview-1.27.fixture.json,
 * .venv/bin/python ko_pii 1.27.0 으로 ``json.dumps(report, ensure_ascii=False, indent=2) + "\n"``).
 */
import { existsSync, linkSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { compareJsonPolicies, comparePolicies, main } from "../../src/policyPreview.js";
import { pyJsonDumps } from "../../src/vault/reversible.js";

type Settings = Record<string, unknown>;
interface Fixture {
  text: { text: string; before: Settings; after: Settings; report: string }[];
  json: {
    data: unknown;
    before: Settings;
    after: Settings;
    include_paths: boolean;
    report: string;
  }[];
}

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(
  readFileSync(join(here, "policy-preview-1.27.fixture.json"), "utf8"),
) as Fixture;

const dump = (report: unknown) => `${pyJsonDumps(report, 2)}\n`;

describe("Python 1.27 실측 보고서와 바이트 대조", () => {
  FIXTURE.text.forEach((c, i) => {
    it(`compare_policies #${i}`, () => {
      expect(dump(comparePolicies(c.text, { before: c.before, after: c.after }))).toBe(c.report);
    });
  });
  FIXTURE.json.forEach((c, i) => {
    it(`compare_json_policies #${i}`, () => {
      const report = compareJsonPolicies(c.data, {
        before: c.before,
        after: c.after,
        includePaths: c.include_paths,
      });
      expect(dump(report)).toBe(c.report);
    });
  });
});

describe("compare_policies (test_policy_preview.py)", () => {
  it("실제 유지 상태를 값 없이 보고", () => {
    const before = {
      include: ["PHONE", "EMAIL"],
      strategy: "tokenize",
      strategies: { PHONE: "partial" },
    };
    const original = structuredClone(before);
    const after = { ...before, strategies: { PHONE: "redact" } };
    const report = comparePolicies("018-2345-6789 user@example.com", { before, after });
    expect(report.changed_by_label).toEqual({ PHONE: 1 });
    const changes = report.changes as { before: Settings; after: Settings }[];
    expect(changes[0]?.before.output_state).toBe("partial_strategy");
    expect(changes[0]?.after.output_state).toBe("replaced");
    const serialized = JSON.stringify(report);
    for (const v of ["018-2345-6789", "user@example.com", "<EMAIL_1>", "018-****-6789"]) {
      expect(serialized).not.toContain(v);
    }
    expect(before).toEqual(original);
    expect(report.whole_text_safety_assessed).toBe(false);
  });

  for (const strategy of ["tokenize", "hashed", "fpe", "partial", "redact", "asterisk"]) {
    it(`동일 정책은 무작위 토큰을 무시 — ${strategy}`, () => {
      const policy = { include: ["EMAIL", "PHONE"], strategy };
      const r = comparePolicies("user@example.com 010-2345-6789", {
        before: policy,
        after: policy,
      });
      expect(r.changed_span_count).toBe(0);
      expect(r.before_policy_sha256).toBe(r.after_policy_sha256);
    });
  }

  it("제외어·AUDIT 은 정확도로 가장하지 않는다", () => {
    const r = comparePolicies("성명: 홍길동", {
      before: { include: ["PERSON"] },
      after: { include: ["PERSON"], person_exclusions: ["홍길동"] },
    });
    expect((r.changes as { after: Settings }[])[0]?.after.output_state).toBe("not_detected");
    expect(JSON.stringify(r)).not.toContain("홍길동");
    const audit = comparePolicies("010-2345-6789", {
      before: { mode: "AUDIT" },
      after: { mode: "STRICT" },
    });
    const change = (audit.changes as { before: Settings; after: Settings }[])[0];
    expect(change?.before.output_state).toBe("retained_by_policy");
    expect(change?.before.applied_strategy).toBeNull();
    expect(change?.after.applied_strategy).toBe("tokenize");
    expect(comparePolicies("", { before: {}, after: {} }).input_empty).toBe(true);
  });

  for (const config of [
    { vault: "secret" },
    { secondary_detector: {} },
    { mode: "bad" },
    { strategies: { PERSON: "bad" } },
  ]) {
    it(`외부 상태·어댑터 거부 ${JSON.stringify(config)}`, () => {
      expect(() => comparePolicies("test", { before: config, after: {} })).toThrow();
    });
  }

  it("상한과 미검출은 안전 통과가 아니다", () => {
    expect(() => comparePolicies("x".repeat(100_001), { before: {}, after: {} })).toThrow(/100000/);
    const r = comparePolicies("undetected personal details", {
      before: { include: ["RRN"] },
      after: { include: ["RRN"] },
    });
    expect(r.observed_span_count).toBe(0);
    expect(r.scope).toBe("union_of_observed_spans_not_gold");
    expect(r.whole_text_safety_assessed).toBe(false);
  });
});

describe("compare_json_policies (test_structured_policy_preview.py)", () => {
  it("필드 제외어는 지역적이며 단언이 이긴다 — 값 유출 없음", () => {
    const data = { "product-private": "성명: 홍길동", "customer-private": "홍길동" };
    const before = { include: ["PERSON"], field_labels: { "/customer-private": "PERSON" } };
    const after = {
      ...before,
      field_person_exclusions: { "/product-private": ["홍길동"], "/customer-private": ["홍길동"] },
    };
    const originals = structuredClone([data, before, after]);
    const r = compareJsonPolicies(data, { before, after });
    expect([data, before, after]).toEqual(originals);
    expect([r.observed_span_count, r.changed_span_count]).toEqual([2, 1]);
    const change = (r.changes as Settings[])[0] as Settings & { before: Settings; after: Settings };
    expect(change.field_index).toBe(0);
    expect(change.before.output_state).toBe("replaced");
    expect(change.after.output_state).toBe("not_detected");
    expect((r.fields as Settings[])[1]?.after_output_counts).toEqual({ replaced: 1 });
    expect(r.before_policy_sha256).not.toBe(r.after_policy_sha256);
    const serialized = JSON.stringify(r);
    for (const p of ["홍길동", "product-private", "customer-private", "<PERSON_1>"]) {
      expect(serialized).not.toContain(p);
    }
    expect([r.paths_included, r.keys_screened, r.whole_text_safety_assessed]).toEqual([
      false,
      false,
      false,
    ]);
  });

  it("한쪽만 단언한 정수 필드도 같은 필드로 정렬", () => {
    const data = {
      skip: 42,
      account: 12345,
      email: "user@example.com",
      boolean: true,
      null: null,
      float: 1.5,
    };
    const plain = { include: ["EMAIL", "ACCOUNT"] };
    const asserted = { ...plain, field_labels: { "/account": "ACCOUNT" } };
    const r = compareJsonPolicies(data, { before: plain, after: asserted, includePaths: true });
    const fields = r.fields as Settings[];
    expect(fields.map((f) => f.field_index)).toEqual([1, 2]);
    expect(fields.map((f) => f.path)).toEqual(["/account", "/email"]);
    expect([
      fields[0]?.before_screened,
      fields[0]?.after_screened,
      fields[1]?.before_screened,
    ]).toEqual([false, true, true]);
    const change = (r.changes as (Settings & { before: Settings; after: Settings })[])[0];
    expect(change?.source_span).toEqual([0, 5]);
    expect(change?.before.output_state).toBe("not_detected");
    const reverse = compareJsonPolicies(data, { before: asserted, after: plain });
    const rc = (reverse.changes as Settings[])[0];
    expect(rc?.before).toEqual(change?.after);
    expect(rc?.after).toEqual(change?.before);
  });

  for (const config of [
    { vault: {} },
    { secondary_detector: {} },
    { trace_limit: 1 },
    { field_labels: { "/name": "PESRON" } },
    { field_labels: { name: "PERSON" } },
    { field_labels: { "/~2": "PERSON" } },
    { field_labels: { "/name": "PERSON" }, exclude: ["PERSON"] },
    { field_rules: [{ path: ["name"], label: "PERSON" }], include: ["EMAIL"] },
    { field_rules: [{ path: [true], label: "PERSON" }] },
    { field_rules: null },
    { field_person_exclusions: { "/name": "private" } },
    { field_person_exclusions: { name: ["private"] } },
    { field_labels: { "/missing-secret": "PERSON" } },
    { field_person_exclusions: { "/missing-secret": ["private-value"] } },
    { field_rules: [{ path: ["missing-secret"], label: "PERSON" }] },
    { field_labels: { "/name": "EMAIL" }, field_rules: [{ path: ["name"], label: "PERSON" }] },
  ]) {
    it(`잘못된 설정은 값·경로 반사 없이 거부 ${JSON.stringify(config)}`, () => {
      let message = "";
      expect(() => {
        try {
          compareJsonPolicies({ name: "private-value" }, { before: {}, after: config });
        } catch (e) {
          message = (e as Error).message;
          throw e;
        }
      }).toThrow();
      expect(message).not.toContain("private-value");
      expect(message).not.toContain("missing-secret");
    });
  }

  const cyclic: unknown[] = [];
  cyclic.push(cyclic);
  for (const [name, data, pattern] of [
    ["long-text", "x".repeat(100_001), /character/],
    ["many-fields", Array(1001).fill(""), /1000/],
    ["surrogate-value", "\ud800", /surrogate/],
    ["surrogate-key", { "\ud800": "" }, /surrogate/],
    ["nonfinite", Number.NaN, /finite/],
    ["cycle", cyclic, /cycle/],
  ] as const) {
    it(`상한·잘못된 JSON 값 — ${name}`, () => {
      expect(() => compareJsonPolicies(data, { before: {}, after: {} })).toThrow(pattern);
    });
  }

  it("관측 span 상한 2000", () => {
    expect(() =>
      compareJsonPolicies(Array(2).fill("user@example.com ".repeat(1001)), {
        before: { include: ["EMAIL"] },
        after: { include: ["EMAIL"] },
      }),
    ).toThrow(/2000/);
  });

  it("includePaths 는 명시적 boolean", () => {
    expect(() =>
      compareJsonPolicies(
        {},
        { before: {}, after: {}, includePaths: "false" as unknown as boolean },
      ),
    ).toThrow(/boolean/);
  });
});

describe("ko-pii-compare-policies CLI", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
  });
  const tmp = (): string => {
    const root = mkdtempSync(join(tmpdir(), "ko-pii-preview-"));
    roots.push(root);
    return root;
  };
  const run = (argv: string[], stdin = "") => {
    let stdout = "";
    let stderr = "";
    const code = main(argv, {
      stdout: (t) => {
        stdout += t;
      },
      stderr: (t) => {
        stderr += t;
      },
      readStdin: () => Buffer.from(stdin, "utf8"),
    });
    return { code, stdout, stderr };
  };

  it("입력 불변·덮어쓰기 거부 (text)", () => {
    const root = tmp();
    const [source, before, after, output] = ["text.txt", "a.json", "b.json", "report.json"].map(
      (n) => join(root, n),
    ) as [string, string, string, string];
    writeFileSync(source, "user@example.com");
    writeFileSync(before, '{"mode":"AUDIT"}');
    writeFileSync(after, '{"mode":"STRICT"}');
    const originals = [source, before, after].map((p) => readFileSync(p, "utf8"));
    const args = [source, "--before", before, "--after", after];
    expect(run([...args, "--output", output]).code).toBe(0);
    const written = readFileSync(output, "utf8");
    expect(written).not.toContain("user@example.com");
    expect(written).toBe(
      `${pyJsonDumps(comparePolicies("user@example.com", { before: { mode: "AUDIT" }, after: { mode: "STRICT" } }), 2)}\n`,
    );
    const failed = run([...args, "--output", before]);
    expect(failed.code).toBe(1);
    expect(failed.stderr).toBe(
      "policy preview failed: check bounded UTF-8 input, core settings and distinct output path\n",
    );
    expect([source, before, after].map((p) => readFileSync(p, "utf8"))).toEqual(originals);
  });

  it("설정 stdin 은 읽기 전에 거부", () => {
    let read = false;
    const code = main(["-", "--before", "-", "--after", "other.json"], {
      stderr: () => {},
      readStdin: () => {
        read = true;
        return Buffer.from("");
      },
    });
    expect(code).toBe(1);
    expect(read).toBe(false);
  });

  it("JSON 출력과 원본 보호 (하드링크 포함), stdin 입력", () => {
    const root = tmp();
    const [source, before, after, output] = [
      "source.json",
      "before.json",
      "after.json",
      "report.json",
    ].map((n) => join(root, n)) as [string, string, string, string];
    writeFileSync(source, '{"private-field": "user@example.com"}');
    writeFileSync(before, '{"mode":"AUDIT"}');
    writeFileSync(after, "{}");
    const originals = [source, before, after].map((p) => readFileSync(p, "utf8"));
    const args = [source, "--format", "json", "--before", before, "--after", after];
    expect(run([...args, "--output", output]).code).toBe(0);
    const text = readFileSync(output, "utf8");
    expect(JSON.parse(text).changed_span_count).toBe(1);
    expect(text).not.toContain("private-field");
    expect(text).not.toContain("user@example.com");
    const withPaths = run([...args, "--include-paths"]);
    expect(withPaths.code).toBe(0);
    expect(JSON.parse(withPaths.stdout).changes[0].path).toBe("/private-field");
    for (const p of [source, before, after]) expect(run([...args, "--output", p]).code).toBe(1);
    const alias = join(root, "alias.json");
    linkSync(source, alias);
    expect(run([...args, "--output", alias]).code).toBe(1);
    expect([source, before, after].map((p) => readFileSync(p, "utf8"))).toEqual(originals);
    const fromStdin = run(["-", ...args.slice(1)], originals[0]);
    expect(fromStdin.code).toBe(0);
    expect(JSON.parse(fromStdin.stdout).changed_span_count).toBe(1);
  });

  for (const contents of ['{"x":1,"x":2}', '{"x":', '{"x":"\\ud800"}', '{"x": NaN}']) {
    it(`잘못된 JSON 입력 ${contents} — 정리된 오류, 출력 없음`, () => {
      const root = tmp();
      const [source, settings, output] = ["source.json", "settings.json", "output.json"].map((n) =>
        join(root, n),
      ) as [string, string, string];
      writeFileSync(source, contents);
      writeFileSync(settings, "{}");
      const r = run([
        source,
        "--format",
        "json",
        "--before",
        settings,
        "--after",
        settings,
        "--output",
        output,
      ]);
      expect(r.code).toBe(1);
      expect(existsSync(output)).toBe(false);
      expect(r.stderr).not.toContain(contents);
    });
  }

  it("--include-paths 는 JSON 전용 (argparse 오류 코드 2)", () => {
    const r = run(["input.txt", "--before", "a.json", "--after", "b.json", "--include-paths"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(
      /^usage: ko-pii-compare-policies .*\n.*error: --include-paths requires --format json\n$/s,
    );
  });

  it("필수 인자 누락은 코드 2", () => {
    const r = run(["input.txt"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("the following arguments are required: --before, --after");
  });
});
