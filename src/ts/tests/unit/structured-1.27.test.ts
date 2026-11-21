/**
 * 구조화 JSON (anonymizeJson / anonymizeJsonl / loadsJson) — Python tests/unit/test_structured.py,
 * test_field_exclusions.py 대응 (CLI 케이스 제외 — cli 는 다음 웨이브).
 *
 * 기대값은 Python 테스트 단언 또는 .venv/bin/python (ko_pii 1.27.0) 실측값이다.
 */
import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ValueError } from "../../src/core/errors.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { EACH, FieldRule } from "../../src/fieldRules.js";
import { RegexDetector } from "../../src/integrations/custom.js";
import { recordKeys } from "../../src/io/recordOrder.js";
import { PolicyProfile } from "../../src/profile.js";
import {
  anonymizeJson,
  anonymizeJsonl,
  loadsJson,
  StructuredLimits,
} from "../../src/structured.js";
import { anonymizeRecords, anonymizeValue } from "../../src/tabular.js";
import { pyJsonDumps, ReversibleVault } from "../../src/vault/reversible.js";

const anonymizer = (
  strategy = "tokenize",
  opts: {
    mode?: ProcessingMode;
    include?: string[] | null;
    exclude?: string[] | null;
    secondary?: RegexDetector | null;
    personExclusions?: string[] | null;
    strategies?: Record<string, string>;
  } = {},
) =>
  new Anonymizer(
    opts.mode ?? ProcessingMode.STRICT,
    strategy,
    null,
    opts.include ?? null,
    opts.exclude ?? null,
    opts.secondary ?? null,
    "union",
    null,
    opts.personExclusions ?? null,
    { strategies: opts.strategies ?? null },
  );

function errorOf(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected an error");
}

describe("anonymizeJson (test_structured.py)", () => {
  it("중첩 구조·원본 보존 (Python 실측)", () => {
    const data = {
      users: [{ email: "user@example.com", phone: "010-2345-6789", n: 3 }],
      yes: true,
      none: null,
    };
    const original = structuredClone(data);
    const result = anonymizeJson(data, {
      anonymizer: anonymizer("redact", { strategies: { PHONE: "partial" } }),
    });
    expect(data).toEqual(original);
    expect(result.data).toEqual({
      users: [{ email: "[이메일]", phone: "010-****-6789", n: 3 }],
      yes: true,
      none: null,
    });
    expect(result.fields.map((f) => f.path)).toEqual(["/users/0/email", "/users/0/phone"]);
    const out = result.data as { users: unknown };
    expect(out).not.toBe(data);
    expect(out.users).not.toBe(data.users);
    const report = result.report();
    expect(report.keys_screened).toBe(false);
    expect((report.fields as { findings: unknown[] }[])[1]?.findings).toEqual([
      {
        label: "PHONE",
        rule_id: "ko-pii.phone.v1",
        subrule_id: null,
        source_span: [0, 13],
        output_span: [0, 13],
        normalized: false,
        checks: [],
        confidence: 1.0,
        action: "BLOCK",
        requested_strategy: "partial",
        applied_strategy: "partial",
        reason: "partial_masking",
      },
    ]);
  });

  it("포인터 이스케이프·단언·반복 토큰 (Python 실측 report)", () => {
    const data = { "a/b": { "~name": "이상" }, again: "이상", id: 12345 };
    const result = anonymizeJson(data, {
      fieldLabels: { "/a~1b/~0name": "PERSON", "/again": "PERSON", "/id": "ACCOUNT" },
    });
    expect(result.data).toEqual({
      "a/b": { "~name": "<PERSON_1>" },
      again: "<PERSON_1>",
      id: "<ACCOUNT_1>",
    });
    const report = result.report({ includePaths: true, includeTrace: true });
    const fields = report.fields as Record<string, unknown>[];
    expect(fields.map((f) => f.path)).toEqual(["/a~1b/~0name", "/again", "/id"]);
    expect(fields[2]).toEqual({
      field_index: 2,
      schema_version: 1,
      contract: "ko-pii-explanation-v1",
      scope: "selected_detections_only",
      overlap_resolution: "risk_confidence_length_start; discarded_candidates_not_included",
      offset_unit: "python_code_points",
      mode: "STRICT",
      detection_count: 1,
      substitution_count: 1,
      findings: [
        {
          label: "ACCOUNT",
          rule_id: "field.asserted.v1",
          subrule_id: null,
          source_span: [0, 5],
          output_span: [0, 11],
          normalized: false,
          checks: ["field:asserted"],
          confidence: 1.0,
          action: "BLOCK",
          requested_strategy: "tokenize",
          applied_strategy: "tokenize",
          reason: "substituted",
        },
      ],
      overlap_trace: null,
      path: "/id",
    });
  });

  it("AUDIT 은 정수 타입을 보존한다", () => {
    const result = anonymizeJson(
      { id: 1234 },
      {
        fieldLabels: { "/id": "ACCOUNT" },
        anonymizer: anonymizer("tokenize", { mode: ProcessingMode.AUDIT }),
      },
    );
    expect(result.data).toEqual({ id: 1234 });
  });

  it("키와 경로는 명시적으로 검사하지 않는다", () => {
    const key = "user@example.com";
    const result = anonymizeJson({ [key]: "010-2345-6789" }, { anonymizer: anonymizer("redact") });
    expect(Object.keys(result.data as object)).toContain(key);
    expect(JSON.stringify(result.report())).not.toContain(key);
    expect(result.report().keys_screened).toBe(false);
    expect((result.report({ includePaths: true }).fields as { path: string }[])[0]?.path).toBe(
      `/${key}`,
    );
  });

  it.each([
    [{ a: 1.2 }, { "/a": "ACCOUNT" }],
    [{ a: true }, { "/a": "ACCOUNT" }],
    [{ a: {} }, { "/a": "PERSON" }],
    [{}, { "/missing": "PHONE" }],
    [{ a: "x" }, { a: "PERSON" }],
    [{ a: "x" }, { "/~2": "PERSON" }],
    [{ a: "x" }, { "/a": "TYPO" }],
  ])("잘못된 필드 정책은 vault 쓰기 전에 실패: %o %o", (data, labels) => {
    const anon = anonymizer();
    expect(() => anonymizeJson(data, { anonymizer: anon, fieldLabels: labels })).toThrow(
      ValueError,
    );
    expect(anon.vault.entries()).toEqual([]);
  });

  it("include/exclude 와 충돌하는 필드 라벨은 거부", () => {
    expect(() =>
      anonymizeJson(
        { a: "name" },
        {
          anonymizer: anonymizer("tokenize", { exclude: ["PERSON"] }),
          fieldLabels: { "/a": "PERSON" },
        },
      ),
    ).toThrow(/conflicts/);
  });

  it("상한과 순환", () => {
    const cyclic: unknown[] = [];
    cyclic.push(cyclic);
    expect(() => anonymizeJson(cyclic)).toThrow(/cycle/);
    expect(() =>
      anonymizeJson([[["a"]]], { limits: new StructuredLimits({ maxDepth: 2 }) }),
    ).toThrow(/depth/);
    expect(() =>
      anonymizeJson([1, 2, 3], { limits: new StructuredLimits({ maxNodes: 3 }) }),
    ).toThrow(/node/);
    expect(() =>
      anonymizeJson("abcd", { limits: new StructuredLimits({ maxStringChars: 3 }) }),
    ).toThrow(/character/);
    // Python ``{1: "x"}`` (비문자열 키) 대응 — JS 에서는 Map 등 비 JSON 값이 거부된다.
    expect(() => anonymizeJson(new Map([[1, "x"]]))).toThrow(/non-JSON/);
    expect(() => anonymizeJson({ a: undefined })).toThrow(/non-JSON/);
  });

  it("StructuredLimits 검증", () => {
    expect(() => new StructuredLimits({ maxDepth: 0 })).toThrow(/positive integers/);
    expect(() => new StructuredLimits({ maxNodes: 1.5 })).toThrow(/positive integers/);
    expect(() => new StructuredLimits({ maxDepth: 129 })).toThrow(/128/);
  });

  it("아스트랄 문자는 코드 포인트 하나로 세고 짝 없는 서로게이트는 거부", () => {
    expect(() =>
      anonymizeJson("😀😀😀", { limits: new StructuredLimits({ maxStringChars: 3 }) }),
    ).not.toThrow();
    expect(() => anonymizeJson("\ud800")).toThrow(/surrogate/);
  });

  it("'__proto__' 키도 own property 로 보존된다", () => {
    const data = loadsJson('{"__proto__": "user@example.com"}');
    const result = anonymizeJson(data, { anonymizer: anonymizer("redact") });
    expect(Object.hasOwn(result.data as object, "__proto__")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(result.data, "__proto__")?.value).toBe("[이메일]");
    expect(Object.getPrototypeOf(result.data)).toBe(Object.prototype);
  });
});

describe("loadsJson (strict)", () => {
  it.each(['{"a":1,"a":2}', '{"secret": NaN}', '{"secret": 1e999}', '"\\ud800"', "{bad"])(
    "잘못된 JSON 은 값 없이 거부: %s",
    (text) => {
      const err = errorOf(() => loadsJson(text));
      expect(err).toBeInstanceOf(ValueError);
      expect(err.message).not.toContain("secret");
    },
  );
});

describe("anonymizeJsonl", () => {
  it("처리 전에 전체 검증하고 줄 번호를 보존한다", () => {
    const anon = anonymizer();
    expect(() => anonymizeJsonl('{"a":"user@example.com"}\n\n{bad', { anonymizer: anon })).toThrow(
      "invalid JSONL document at line 3",
    );
    expect(anon.vault.entries()).toEqual([]);
    const rows = anonymizeJsonl('{"a":"user@example.com"}\n\n{"a":"user@example.com"}', {
      anonymizer: anon,
    });
    expect(rows.map((r) => r.sourceLine)).toEqual([1, 3]);
    expect(rows[0]?.data).toEqual({ a: "<EMAIL_1>" });
    expect(rows[1]?.data).toEqual({ a: "<EMAIL_1>" });
  });

  it("JSON 문자열 안의 U+2028 은 레코드 경계가 아니다", () => {
    const text = JSON.stringify({ message: "앞 user@example.com 뒤" });
    const result = anonymizeJsonl(text, {
      anonymizer: anonymizer("redact", { include: ["EMAIL"] }),
    });
    expect(result).toHaveLength(1);
    expect((result[0]?.data as { message: string } | undefined)?.message).toBe("앞 [이메일] 뒤");
  });

  it("빈 입력·문서 수 상한", () => {
    expect(() => anonymizeJsonl("\n  \n")).toThrow(/at least one document/);
    expect(() =>
      anonymizeJsonl("1\n2\n3", { limits: new StructuredLimits({ maxDocuments: 2 }) }),
    ).toThrow(/document limits/);
  });
});

describe("field person exclusions (test_field_exclusions.py)", () => {
  it("제외는 필드 범위이며 공유 설정을 바꾸지 않는다", () => {
    const anon = anonymizer("redact", {
      include: ["PERSON"],
      secondary: new RegexDetector("홍길동", { label: "PERSON" }),
    });
    const data = { product: "홍길동", customer: "홍길동", other: ["홍길동"] };
    const result = anonymizeJson(data, {
      anonymizer: anon,
      fieldPersonExclusions: { "/product": ["홍길동"] },
    });
    expect(result.data).toEqual({ product: "홍길동", customer: "[성명]", other: ["[성명]"] });
    expect(data.customer).toBe("홍길동");
    expect(anon.personExclusions.size).toBe(0);
    expect(anon.process("홍길동").text).toBe("[성명]");
    expect(JSON.stringify(result.report())).not.toContain("홍길동");
  });

  it.each(
    (["pointer", "rule"] as const).flatMap((assertion) =>
      [ProcessingMode.STRICT, ProcessingMode.AUDIT].map((mode) => [assertion, mode] as const),
    ),
  )("단언 필드는 전역·로컬 제외보다 우선: %s %s", (assertion, mode) => {
    const kw =
      assertion === "pointer"
        ? { fieldLabels: { "/names/0": "PERSON" } }
        : { fieldRules: [new FieldRule(["names", EACH], "PERSON")] };
    const result = anonymizeJson(
      { names: ["홍길동"] },
      {
        anonymizer: anonymizer("tokenize", { mode, personExclusions: ["홍길동"] }),
        fieldPersonExclusions: { "/names/0": ["홍길동"] },
        ...kw,
      },
    );
    expect((result.data as { names: string[] }).names).toEqual(
      mode === ProcessingMode.AUDIT ? ["홍길동"] : ["<PERSON_1>"],
    );
  });

  it("PERSON 과 정확히 정규화된 값만 억제한다", () => {
    const anon = anonymizer("redact", {
      include: ["EMAIL", "PERSON"],
      secondary: new RegexDetector("홍길동", { label: "PERSON" }),
    });
    let result = anonymizeJson(
      { field: "홍길동 user@example.com" },
      { anonymizer: anon, fieldPersonExclusions: { "/field": ["홍​길동", "user@example.com"] } },
    );
    expect(result.data).toEqual({ field: "홍길동 [이메일]" });
    result = anonymizeJson(
      { field: "홍길동" },
      { anonymizer: anon, fieldPersonExclusions: { "/field": ["홍길"] } },
    );
    expect((result.data as { field: string }).field).toBe("[성명]");
  });

  it("이스케이프 키·루트·null·배열 인덱스", () => {
    const data = { "a/b": { "~": ["홍길동", null] } };
    const result = anonymizeJson(data, {
      fieldPersonExclusions: { "/a~1b/~0/0": ["홍길동"], "/a~1b/~0/1": [] },
    });
    expect(result.data).toEqual(data);
    expect(anonymizeJson("홍길동", { fieldPersonExclusions: { "": ["홍길동"] } }).data).toBe(
      "홍길동",
    );
  });

  it.each([
    [[]],
    [{ bad: [] }],
    [{ "/a~2b": [] }],
    [{ "/missing": [] }],
    [{ "/arr/01": [] }],
    [{ "/arr/0": "홍길동" }],
    [{ "/arr/0": [1] }],
    [{ "/arr/0": null }],
    [{ "/arr/0": [""] }],
    [{ "/arr": [] }],
    [{ "/number": [] }],
    [{ "/arr/0": Array(257).fill("x") }],
    [{ "/arr/0": ["x".repeat(257)] }],
    [{ "/arr/999999999999999999999999": [] }],
    [{ "/arr/0": ["​"] }],
    [{ "/arr/0": ["ﷺ".repeat(100)] }],
  ])("잘못된 설정은 vault 변경 전에 실패: %o", (config) => {
    const anon = anonymizer();
    expect(() =>
      anonymizeJson(
        { first: "user@example.com", arr: ["홍길동"], number: 123 },
        { anonymizer: anon, fieldPersonExclusions: config as never },
      ),
    ).toThrow(ValueError);
    expect(anon.vault.size).toBe(0);
  });

  it("JSONL 은 모든 경로를 사전 검증하고 용어 생성기를 한 번만 소비한다", () => {
    const anon = anonymizer();
    function* terms() {
      yield "홍길동";
    }
    expect(() =>
      anonymizeJsonl('{"name":"홍길동"}\n{"missing":"user@example.com"}', {
        anonymizer: anon,
        fieldPersonExclusions: { "/name": terms() },
      }),
    ).toThrow("invalid JSONL document at line 2");
    expect(anon.vault.size).toBe(0);
    const results = anonymizeJsonl('{"name":"홍길동"}\n{"name":"홍길동"}', {
      fieldPersonExclusions: { "/name": terms() },
    });
    expect(results.map((r) => r.data)).toEqual([{ name: "홍길동" }, { name: "홍길동" }]);
  });
});

describe("typed values across entry points (test_typed_values.py)", () => {
  const transform = (label: string, value: string, strategy: string, entry: string): unknown => {
    const vault = new ReversibleVault({
      salt: "test",
      secretKey: "test",
      fingerprintIterations: 1,
    });
    const anon = new Anonymizer(ProcessingMode.STRICT, strategy, vault);
    if (entry === "value") return anonymizeValue(value, label, { strategy, vault })[0];
    if (entry === "records") {
      return anonymizeRecords([{ field: value }], {
        columnMap: { field: label },
        strategy,
        vault,
      })[0][0]?.field;
    }
    if (entry === "profile") {
      const profile = new PolicyProfile({ strategy, field_labels: { "/field": label } });
      return (profile.processJson({ field: value }).data as { field: unknown }).field;
    }
    const options =
      entry === "json"
        ? { fieldLabels: { "/field": label } }
        : { fieldRules: [new FieldRule(["field"], label)] };
    const result = anonymizeJson({ field: value }, { anonymizer: anon, ...options });
    expect(result.fields[0]?.result.substitutions[0]?.end).toBe(value.length);
    return (result.data as { field: unknown }).field;
  };

  it.each(
    ["value", "records", "json", "rules", "profile"].flatMap((entry) =>
      (
        [
          ["PHONE", "010-1234-5678 (홍길동)", "fpe"],
          ["FAX", "02-1234-5678 / secret@example.com", "fpe"],
          ["CARD", "4111-1111-1111-1111 (홍길동)", "fpe"],
          ["DT_BIRTH", "홍길동 / 010-1234-5678 / 1988년생", "partial"],
          ["PERSON", "홍", "partial"],
          ["PERSON", "남궁", "partial"],
          ["PASSPORT", "M12", "partial"],
        ] as const
      ).map(([label, value, strategy]) => [entry, label, value, strategy] as const),
    ),
  )("복합·짧은 값은 전부 마스킹: %s %s %s", (entry, label, value, strategy) => {
    expect(transform(label, value, strategy, entry)).toBe("*".repeat(value.length));
  });

  it("AUDIT 은 원문 단언 필드를 보존한다", () => {
    const value = "010-1234-5678 (Private Person)";
    const result = anonymizeJson(
      { phone: value },
      {
        fieldLabels: { "/phone": "PHONE" },
        anonymizer: new Anonymizer(ProcessingMode.AUDIT, "fpe"),
      },
    );
    expect((result.data as { phone: string }).phone).toBe(value);
    expect(result.fields[0]?.result.substitutions).toEqual([]);
  });
});

describe("키 순서 — Python dict 삽입 순서 (.venv/bin/python 실측)", () => {
  const dumps = (value: unknown) => pyJsonDumps(value, null);
  const redact = () => anonymizer("redact");

  it("정수형 키는 원본 자리를 지킨다", () => {
    const data = loadsJson('{"b":1,"1":2,"0":"x"}');
    expect(recordKeys(data as Record<string, unknown>)).toEqual(["b", "1", "0"]);
    const result = anonymizeJson(data, { anonymizer: redact() });
    expect(dumps(result.data)).toBe('{"b": 1, "1": 2, "0": "x"}');
    expect(result.fields.map((f) => f.path)).toEqual(["/0"]);
  });

  it("'__proto__' 키와 배열 속 객체", () => {
    const data = loadsJson(
      '{"__proto__":{"2":"user@example.com","a":"010-1234-5678"},"10":[{"5":"b","4":"a"}]}',
    );
    expect(recordKeys(data as Record<string, unknown>)).toEqual(["__proto__", "10"]);
    const result = anonymizeJson(data, { anonymizer: redact() });
    expect(dumps(result.data)).toBe(
      '{"__proto__": {"2": "[이메일]", "a": "[전화번호]"}, "10": [{"5": "b", "4": "a"}]}',
    );
    expect(result.fields.map((f) => f.path)).toEqual([
      "/__proto__/2",
      "/__proto__/a",
      "/10/0/5",
      "/10/0/4",
    ]);
  });

  it("중첩 객체", () => {
    const data = loadsJson('{"z":{"y":{"3":"010-1234-5678","x":{"20":"a@b.co","1":"t"}}},"2":0}');
    const result = anonymizeJson(data, { anonymizer: redact() });
    expect(dumps(result.data)).toBe(
      '{"z": {"y": {"3": "[전화번호]", "x": {"20": "[이메일]", "1": "t"}}}, "2": 0}',
    );
    expect(result.fields.map((f) => f.path)).toEqual(["/z/y/3", "/z/y/x/20", "/z/y/x/1"]);
  });

  it("JSONL", () => {
    const results = anonymizeJsonl(
      '{"b":"x","1":"010-1234-5678"}\n\n{"__proto__":{"9":"a@b.co","0":1}}\n',
      { anonymizer: redact() },
    );
    expect(results.map((r) => [r.sourceLine, dumps(r.data), r.fields.map((f) => f.path)])).toEqual([
      [1, '{"b": "x", "1": "[전화번호]"}', ["/b", "/1"]],
      [3, '{"__proto__": {"9": "[이메일]", "0": 1}}', ["/__proto__/9"]],
    ]);
  });
});

describe("loadsJson — 2^53 밖 정수 정밀도 (Python json.loads int 실측)", () => {
  it("안전 범위 밖 정수는 bigint 로 정확히 보존된다", () => {
    expect(loadsJson("123456789012345678901234567890")).toBe(123456789012345678901234567890n);
    expect(loadsJson("9007199254740993")).toBe(9007199254740993n);
    expect(loadsJson("9007199254740991")).toBe(9007199254740991);
    expect(Object.is(loadsJson("-0"), 0)).toBe(true);
    expect(loadsJson('{"a": [-98765432109876543210, 1.5, 1e300]}')).toEqual({
      a: [-98765432109876543210n, 1.5, 1e300],
    });
  });

  it("정수 자릿수 상한 4300 (부호 제외) — 초과는 일반 오류 메시지", () => {
    expect(String(loadsJson("1".repeat(4300))).length).toBe(4300);
    expect(String(loadsJson(`-${"1".repeat(4300)}`)).length).toBe(4301);
    const message = "invalid JSON, duplicate key, non-finite number or excessive nesting";
    expect(() => loadsJson("1".repeat(4301))).toThrow(new ValueError(message));
    expect(() => loadsJson(`{"a": -${"1".repeat(4301)}}`)).toThrow(new ValueError(message));
    // 소수 어휘는 Python float — 오버플로는 비유한 수 오류 (int 자릿수 상한과 무관)
    expect(() => loadsJson(`${"1".repeat(4300)}.5`)).toThrow(
      new ValueError("structured input must contain finite JSON numbers"),
    );
  });

  it("단언 필드의 큰 정수는 원본 숫자열로 가명화되고 비단언 정수는 그대로 남는다", () => {
    const vault = new ReversibleVault();
    const anon = new Anonymizer(ProcessingMode.STRICT, "tokenize", vault);
    const result = anonymizeJson(
      loadsJson(
        '{"acct": 98765432109876543210, "id": 9007199254740993, "n": 12345678901234567890123, "neg": -98765432109876543210}',
      ),
      { anonymizer: anon, fieldLabels: { "/acct": "ACCOUNT", "/id": "ACCOUNT" } },
    );
    expect(result.data).toEqual({
      acct: "<ACCOUNT_1>",
      id: "<ACCOUNT_2>",
      n: 12345678901234567890123n,
      neg: -98765432109876543210n,
    });
    expect(Object.values(vault.toDict().entries).map((e) => e.original)).toEqual([
      "98765432109876543210",
      "9007199254740993",
    ]);
    expect(pyJsonDumps(result.data, null)).toBe(
      '{"acct": "<ACCOUNT_1>", "id": "<ACCOUNT_2>", "n": 12345678901234567890123, "neg": -98765432109876543210}',
    );
  });

  it("Vault JSON 도 큰 정수를 보존하고 4300 자리 초과는 Python 원문 메시지로 거부한다", () => {
    const base = JSON.stringify(
      new ReversibleVault({ salt: "00".repeat(16), fingerprintIterations: 10 }).toDict(),
    );
    const loaded = ReversibleVault.loads(
      base.replace('"fingerprint_iterations":10', '"fingerprint_iterations":98765432109876543210'),
    );
    expect(loaded.toDict().fingerprint_iterations).toBe(98765432109876543210n);
    expect(loaded.dumps()).toContain('"fingerprint_iterations": 98765432109876543210');
    expect(() =>
      ReversibleVault.loads(
        base.replace('"fingerprint_iterations":10', `"fingerprint_iterations":${"1".repeat(4301)}`),
      ),
    ).toThrow(
      new ValueError(
        "Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use sys.set_int_max_str_digits() to increase the limit",
      ),
    );
  });
});
