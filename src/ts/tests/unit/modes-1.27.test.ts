/**
 * 1.27.0 modes 변경 (prepare_detections 원문 결속 검증, AppliedSpan trace, FPE 정규화·fail-closed,
 * 부분 마스킹 경계) — Python 실측값 대조.
 *
 * Python 원본: tests/unit/modes/test_source_boundary.py, test_typed_values.py, test_typed_email.py,
 * test_output_normalization.py. 기대값은 `.venv/bin/python` 으로 생성한 실측값이다
 * (vault: salt="regression", secret_key="test-key", fingerprint_iterations=1).
 */
import { describe, expect, it } from "vitest";
import { ValueError } from "../../src/core/errors.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../../src/core/types.js";
import {
  type AppliedSpan,
  applySubstitutions,
  FPE_BY_LABEL,
  fpe,
  hashed,
  maskValue,
  partial,
  prepareDetections,
  pseudonymizeValue,
  redact,
  tokenize,
} from "../../src/modes/index.js";
import { splitLiteralEmail } from "../../src/modes/literalShapes.js";
import { ReversibleVault } from "../../src/vault/reversible.js";

const fastVault = (salt = "regression", secretKey = "test-key"): ReversibleVault =>
  new ReversibleVault({ salt, secretKey, fingerprintIterations: 1 });

// [label, value, Python mask_value(label, value)]
const PY_MASK: [string, string, string][] = [
  ["PERSON", "홍길동", "홍OO"],
  ["PERSON", "남궁민수", "남궁OO"],
  ["PERSON", "홍", "*"],
  ["PERSON", "남궁", "**"],
  ["PERSON", "X", "*"],
  ["PASSPORT", "M12345678", "M******78"],
  ["PASSPORT", "M123A4567", "M******67"],
  ["PASSPORT", "M1", "**"],
  ["PASSPORT", "M12", "***"],
  ["PASSPORT", "M12\n", "****"],
  ["PASSPORT", "PP12", "****"],
  ["PASSPORT", "M123", "M*23"],
  ["PASSPORT", "Ｍ１２３４５６７８", "*********"],
  ["DT_BIRTH", "88년생", "88년생"],
  ["DT_BIRTH", "1988년생", "1988년생"],
  ["DT_BIRTH", "88 년생", "88 년생"],
  ["DT_BIRTH", "988년생", "*****"],
  ["DT_BIRTH", "88년생\n", "*****"],
  ["DT_BIRTH", "홍길동 / 010-1234-5678 / 1988년생", "****************************"],
  ["DT_BIRTH", "1988-01-01", "1988-**-**"],
  ["DT_BIRTH", "1988년 1월 1일", "1988년 **월 **일"],
  ["POSITION", "사무관", "사무관"],
  ["ACCOUNT", "1234567", "*******"],
  ["ACCOUNT", "12345678", "********"],
  ["ACCOUNT", "1234-5678", "*********"],
  ["ACCOUNT", "123456789", "1234*6789"],
  ["ACCOUNT", "1234567890", "1234**7890"],
  ["CARD", "1234567", "*******"],
  ["CARD", "12345678", "********"],
  ["CARD", "1234-5678", "*********"],
  ["CARD", "123456789", "1234*6789"],
  ["CARD", "1234567890123456", "1234********3456"],
  ["CARD", "4111-1111-1111-111¹", "4111-****-****-1111"],
  ["PHONE", "010-1234-567⁸", "010-****-5678"],
  ["PHONE", "０１０-１２Ｏ４-５６７８", "010-****-5678"],
  ["PHONE", "010-1234-5678", "010-****-5678"],
  ["EMAIL", "user@example.com", "u***@example.com"],
  ["EMAIL", "a@b.c", "a***@b.c"],
  ["EMAIL", "user@한국.com", "u***@한국.com"],
  ["EMAIL", "@example.com", "************"],
  ["EMAIL", ".user@example.com", "*****************"],
  ["EMAIL", "user..name@example.com", "**********************"],
  ["EMAIL", "user@example..com", "*****************"],
  ["EMAIL", "user@-example.com", "*****************"],
  ["EMAIL", "user@example.com\n", "*****************"],
  ["EMAIL", "first@example.com;second@example.com", "************************************"],
  ["EMAIL", "Name <first@example.com>", "************************"],
  ["EMAIL", "first@@example.com", "******************"],
  ["RRN", "880101-1234568", "880101-1******"],
  ["RRN", "８８０１０１-１２３４５６８", "880101-1******"],
];

// [label, value, Python _pseudonymize_value(label, value, vault.fingerprint(label, value))]
const PY_PSEUDO: [string, string, string][] = [
  ["PHONE", "010-1234-5678", "010-6579-1284"],
  ["PHONE", "(02) 1234-5678", "(02) 5811-2924"],
  ["FAX", "031)123-4567", "031)727-5034"],
  ["PHONE", "+82 (0)10-1234-5678", "+82 (8)89-8667-0455"],
  ["PHONE", "1588-1234", "68086423"],
  ["PHONE", "0504-1234-5678", "0533-8913-8263"],
  ["PHONE", "010-1234-567⁸", "010-3316-5301"],
  ["PHONE", "⁰¹⁰-¹²³⁴-⁵⁶⁷⁸", "010-5584-2827"],
  ["PHONE", "０１０-１２Ｏ４-５６７８", "010-5778-2935"],
  ["PHONE", "010-1234-5678 (Private Person)", "******************************"],
  ["PHONE", "010-1234-5678🔒", "**************"],
  ["PHONE", "010-1234-5678 010-2345-6789", "***************************"],
  ["PHONE", "123456", "******"],
  ["FAX", "02-1234-5678 / secret@example.com", "*********************************"],
  ["CARD", "4111.1111.1111.1111", "4111.1110.0188.7838"],
  ["CARD", "4111 /1111 /1111 /1111", "4111 /1101 /1512 /8915"],
  ["CARD", "3782 822463 10005", "3782 823949 94576"],
  ["CARD", "4111-1111-1111-111¹", "4111-1132-0910-0626"],
  ["CARD", "4111111111111111/4242424242424242", "*********************************"],
  ["CARD", "12345678", "********"],
  ["CARD", "4111-1111-1111-1111 ext: 1234", "*****************************"],
  ["RRN", "880101-1234568", "048629-1812281"],
  ["RRN", "8801011234568", "9697831699269"],
  ["RRN", "880101-123456", "380378316135"],
  ["FRN", "900101-5234567", "985862-5403028"],
  ["FRN", "9001015234567", "4272465450333"],
  ["EMAIL", "user@example.com", "hhqf@example.com"],
  ["EMAIL", "user+tag@example.com", "hjlczdsd@example.com"],
  ["EMAIL", "user@xn--3e0b707e.com", "rfee@xn--3e0b707e.com"],
  ["EMAIL", "user@한국.com", "hynv@한국.com"],
  ["EMAIL", "a@b.c", "h@b.c"],
  ["EMAIL", "user＠BOB12.example", "thrx@BOB12.example"],
  ["EMAIL", "hong [at] example [dot] com", "***************************"],
  ["EMAIL", "not-an-email", "************"],
  ["EMAIL", "first@example.com, second@example.com", "*************************************"],
  ["PASSPORT", "M12345678", "M43805233"],
  ["PASSPORT", "M123A4567", "M241A8908"],
  ["PASSPORT", "Ｍ１２３４５６７８", "M03976176"],
  ["PASSPORT", "not-a-passport", "**************"],
  ["PASSPORT", "PP1234567", "PP2355848"],
  ["PERSON", "張三", "**"],
  ["PERSON", "홍길동", "펙뉝쨧"],
  ["INTERNAL_ID", "abc123", "pdy738"],
  ["ACCOUNT", "110-123-456789", "139-707-951470"],
  ["ADDRESS", "서울 Ab-12 é ß", "늗쟩 Bt-97 * *"],
  ["DT_BIRTH", "1988년 1월 1일", "2940딸 1횙 1뽆"],
];

const E2E_SRC = "연락처 010-1234-5678, 메일 alice@example.com, 주민 880101-1234568 끝";
const PY_E2E = {
  tokenize: [
    "연락처 <PHONE_1>, 메일 <EMAIL_1>, 주민 <RRN_1> 끝",
    '{"schema_version": 1, "created_at": "2026-11-19T15:02:15.677984+00:00", "salt": "e2e", "fingerprint_scheme": "pbkdf2-sha256-v2", "fingerprint_iterations": 1, "entries": {"<PHONE_1>": {"label": "PHONE", "original": "010-1234-5678", "risk_level": 4, "legal_basis": null, "first_seen_offset": 4, "occurrences": [4], "extra": {}}, "<EMAIL_1>": {"label": "EMAIL", "original": "alice@example.com", "risk_level": 3, "legal_basis": null, "first_seen_offset": 22, "occurrences": [22], "extra": {}}, "<RRN_1>": {"label": "RRN", "original": "880101-1234568", "risk_level": 5, "legal_basis": null, "first_seen_offset": 44, "occurrences": [44], "extra": {}}}}',
  ],
  fpe: [
    "연락처 010-4769-4873, 메일 wkhmm@example.com, 주민 290668-1149595 끝",
    {
      "<PHONE_1>": {
        label: "PHONE",
        original: "010-1234-5678",
        risk_level: 4,
        legal_basis: null,
        first_seen_offset: 4,
        occurrences: [4],
        extra: {
          fpe_value: "010-4769-4873",
        },
      },
      "<EMAIL_1>": {
        label: "EMAIL",
        original: "alice@example.com",
        risk_level: 3,
        legal_basis: null,
        first_seen_offset: 22,
        occurrences: [22],
        extra: {
          fpe_value: "wkhmm@example.com",
        },
      },
      "<RRN_1>": {
        label: "RRN",
        original: "880101-1234568",
        risk_level: 5,
        legal_basis: null,
        first_seen_offset: 44,
        occurrences: [44],
        extra: {
          fpe_value: "290668-1149595",
        },
      },
    },
  ],
  hashed: ["연락처 <PHONE:de48baba>, 메일 <EMAIL:b371150d>, 주민 <RRN:2e00c228> 끝", 0],
  partial: "연락처 010-****-5678, 메일 a****@example.com, 주민 880101-1****** 끝",
  redact: "연락처 [전화번호], 메일 [이메일], 주민 [주민등록번호] 끝",
  trace: [
    "연락처 <PHONE>, 메일 <EMAIL>, 주민 <RRN> 끝",
    [
      [4, 17, 4, 11],
      [22, 39, 16, 23],
      [44, 58, 28, 33],
    ],
  ],
} as const;

function e2eDetections(): DetectionResult[] {
  const at = (label: string, value: string, riskLevel: RiskLevel): DetectionResult => {
    const start = E2E_SRC.indexOf(value);
    return makeDetection({ label, text: value, start, end: start + value.length, riskLevel });
  };
  return [
    at("PHONE", "010-1234-5678", RiskLevel.HIGH),
    at("EMAIL", "alice@example.com", RiskLevel.MEDIUM),
    at("RRN", "880101-1234568", RiskLevel.CRITICAL),
  ];
}

describe("maskValue — Python 실측 대조 (1.27 경계: 짧은 값·복합 값·정규화)", () => {
  it.each(PY_MASK)("%s %j → %j", (label, value, expected) => {
    expect(maskValue(label, value)).toBe(expected);
  });
});

describe("pseudonymizeValue — Python 실측 대조 (정규화 + fail-closed 마스킹)", () => {
  it.each(PY_PSEUDO)("%s %j → %j", (label, value, expected) => {
    const v = fastVault();
    expect(pseudonymizeValue(label, value, v.fingerprint(label, value))).toBe(expected);
  });

  it("정규화만으로는 가명화로 치지 않는다", () => {
    const original = FPE_BY_LABEL.get("PHONE");
    FPE_BY_LABEL.set("PHONE", (value) => value);
    try {
      const text = "０１０-１２３４-５６７８";
      expect(pseudonymizeValue("PHONE", text, "1".repeat(64))).toBe("*".repeat(text.length));
    } finally {
      if (original) FPE_BY_LABEL.set("PHONE", original);
    }
  });

  it.each([
    ["PHONE", "010-1234-5678"],
    ["RRN", "880101-1234568"],
    ["CARD", "4111-1111-1111-1111"],
    ["EMAIL", "user@example.com"],
    ["PASSPORT", "M12345678"],
  ])("표준 형식 %s 은 라벨 변환 함수 결과 그대로", (label, text) => {
    const fp = fastVault().fingerprint(label, text);
    expect(pseudonymizeValue(label, text, fp)).toBe(FPE_BY_LABEL.get(label)?.(text, fp));
  });

  it("fpe 는 원문을 Vault 에 두고 fpe_value 로 마스킹 결과를 기록", () => {
    const value = "010-1234-5678 (Private Person)";
    const vault = fastVault("test", "test");
    const det = makeDetection({
      label: "PHONE",
      text: value,
      start: 0,
      end: value.length,
      riskLevel: RiskLevel.HIGH,
    });
    const [out, returned] = fpe(value, [det], vault);
    expect(returned).toBe(vault);
    expect(out).toBe("*".repeat(value.length));
    expect(vault.entries()[0]?.original).toBe(value);
    expect(vault.entries()[0]?.extra.fpe_value).toBe(out);
  });
});

describe("모드 end-to-end — Python 실측 대조", () => {
  it("tokenize", () => {
    const [out, vault] = tokenize(E2E_SRC, e2eDetections(), fastVault("e2e", "k"));
    expect(out).toBe(PY_E2E.tokenize[0]);
    expect(vault.toDict().entries).toEqual(JSON.parse(PY_E2E.tokenize[1]).entries);
  });

  it("fpe", () => {
    const [out, vault] = fpe(E2E_SRC, e2eDetections(), fastVault("e2e", "k"));
    expect(out).toBe(PY_E2E.fpe[0]);
    expect(vault.toDict().entries).toEqual(PY_E2E.fpe[1]);
  });

  it("hashed (Vault 항목 없음)", () => {
    const [out, vault] = hashed(E2E_SRC, e2eDetections(), fastVault("e2e", "k"), 8);
    expect(out).toBe(PY_E2E.hashed[0]);
    expect(vault.size).toBe(PY_E2E.hashed[1]);
  });

  it("partial / redact", () => {
    expect(partial(E2E_SRC, e2eDetections())).toBe(PY_E2E.partial);
    expect(redact(E2E_SRC, e2eDetections())).toBe(PY_E2E.redact);
  });

  it("applySubstitutions trace — 원문/출력 좌표", () => {
    const trace: AppliedSpan[] = [];
    const out = applySubstitutions(E2E_SRC, e2eDetections(), (d) => `<${d.label}>`, { trace });
    expect(out).toBe(PY_E2E.trace[0]);
    expect(trace.map((s) => [s.start, s.end, s.outputStart, s.outputEnd])).toEqual(PY_E2E.trace[1]);
    for (const s of trace) expect(out.slice(s.outputStart, s.outputEnd)).toMatch(/^<[A-Z]+>$/);
  });
});

// --------------------------------------------------------------------------
// tests/unit/modes/test_source_boundary.py
// --------------------------------------------------------------------------

const SOURCE = "alice@example.com bob@example.com";
const VALUE = "alice@example.com";
type Mode = "tokenize" | "redact" | "hashed" | "partial" | "fpe";
const MODES: Mode[] = ["tokenize", "redact", "hashed", "partial", "fpe"];
const VAULT_MODES: Mode[] = ["tokenize", "hashed", "fpe"];

function record(): DetectionResult {
  return makeDetection({
    label: "EMAIL",
    text: VALUE,
    start: 0,
    end: VALUE.length,
    riskLevel: RiskLevel.MEDIUM,
  });
}

function invoke(mode: Mode, text: unknown, detections: Iterable<unknown>, vault?: ReversibleVault) {
  const t = text as string;
  const ds = detections as Iterable<DetectionResult>;
  switch (mode) {
    case "tokenize":
      return tokenize(t, ds, vault ?? null)[0];
    case "hashed":
      return hashed(t, ds, vault ?? null)[0];
    case "fpe":
      return fpe(t, ds, vault ?? null)[0];
    case "partial":
      return partial(t, ds);
    default:
      return redact(t, ds);
  }
}

const INVALID_CHANGES: Record<string, unknown>[] = [
  { end: 0, text: "" },
  { start: -1 },
  { end: SOURCE.length + 1 },
  { start: 20, end: 19 },
  { start: false },
  { end: 17.5 },
  { text: "other@example.com" },
  { text: null },
  { riskLevel: 7 },
  { confidence: Number.NaN },
  { confidence: 2 },
  { label: "" },
  { label: "<EMAIL>" },
  { extra: [] },
];

describe("prepareDetections — 원문 결속 검증 (모든 모드)", () => {
  for (const mode of MODES) {
    it.each(INVALID_CHANGES)(`${mode}: 잘못된 결과 %j 는 Vault 기록 전에 거부`, (changes) => {
      const vault = new ReversibleVault({ salt: "synthetic-boundary-test" });
      const invalid = { ...record(), ...changes };
      let caught: unknown;
      try {
        invoke(mode, SOURCE, [record(), invalid], vault);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ValueError);
      const msg = (caught as Error).message;
      expect(msg).not.toContain(VALUE);
      expect(msg).not.toContain("other@example.com");
      expect(vault.size).toBe(0);
    });

    it.each([null, Buffer.from("private"), 0])(
      `${mode}: 문자열이 아닌 원문 %j 는 빈 검출에도 거부`,
      (value) => {
        expect(() => invoke(mode, value, [])).toThrow(ValueError);
      },
    );

    it.each([null, {}, "alice@example.com"])(`${mode}: 검출 레코드가 아닌 %j 거부`, (invalid) => {
      expect(() => invoke(mode, SOURCE, [invalid])).toThrow(ValueError);
    });

    it(`${mode}: 생성기가 재사용하는 레코드는 yield 마다 스냅샷`, () => {
      function* detections(): Generator<DetectionResult> {
        const item = record();
        yield item;
        item.start = 18;
        item.end = SOURCE.length;
        item.text = "bob@example.com";
        yield item;
        item.start = 0;
        item.end = 0;
        item.text = "";
      }
      const vault = new ReversibleVault({
        salt: "synthetic-snapshot-test",
        fingerprintIterations: 1,
      });
      const output = invoke(mode, SOURCE, detections(), vault);
      expect(output).not.toContain(VALUE);
      expect(output).not.toContain("bob@example.com");
      if (mode === "tokenize") expect(output).toBe("<EMAIL_1> <EMAIL_2>");
      if (mode === "tokenize" || mode === "fpe") {
        expect(vault.reveal("<EMAIL_1>")).toBe(VALUE);
        expect(vault.reveal("<EMAIL_2>")).toBe("bob@example.com");
      }
    });

    it(`${mode}: 늦은 이터레이터 실패는 입력을 노출하지 않고 Vault 를 쓰지 않는다`, () => {
      function* detections(): Generator<DetectionResult> {
        yield record();
        throw new Error(`private input ${SOURCE}`);
      }
      const vault = new ReversibleVault({ salt: "synthetic-iterator-test" });
      let caught: unknown;
      try {
        invoke(mode, SOURCE, detections(), vault);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ValueError);
      expect((caught as Error).message).not.toContain(VALUE);
      expect((caught as Error).cause).toBeUndefined();
      expect(vault.size).toBe(0);
    });

    it(`${mode}: 사용자 정의 라벨과 빈 입력 호환`, () => {
      const item = makeDetection({
        label: "INTERNAL_ID",
        text: "abc123",
        start: 0,
        end: 6,
        riskLevel: RiskLevel.HIGH,
      });
      expect(invoke(mode, "abc123", [item])).not.toBe("abc123");
      expect(invoke(mode, "", [])).toBe("");
      expect(invoke(mode, "public", [])).toBe("public");
    });

    it(`${mode}: 유효한 겹침·순서는 분리된 리스트와 같은 결과`, () => {
      const first = record();
      const second = makeDetection({
        label: "EMAIL",
        text: "bob@example.com",
        start: 18,
        end: SOURCE.length,
        riskLevel: RiskLevel.MEDIUM,
      });
      const low = makeDetection({
        label: "URL",
        text: SOURCE,
        start: 0,
        end: SOURCE.length,
        riskLevel: RiskLevel.LOW,
      });
      const left = invoke(mode, SOURCE, [second, low, first, { ...first }], fastVault("stable"));
      const right = invoke(mode, SOURCE, [first, second][Symbol.iterator](), fastVault("stable"));
      expect(left).toBe(right);
    });
  }

  for (const mode of VAULT_MODES) {
    it(`${mode}: 사전 검증이 store/fingerprint 보다 먼저`, () => {
      const vault = new ReversibleVault({ salt: "synthetic-no-side-effects" });
      const forbidden = (): never => {
        throw new Error("Vault operation must not precede input validation");
      };
      vault.store = forbidden;
      vault.fingerprint = forbidden;
      expect(() => invoke(mode, SOURCE, [record(), { ...record(), text: "wrong" }], vault)).toThrow(
        ValueError,
      );
    });
  }

  it("prepareDetections 는 메타데이터를 복사한 분리 레코드를 반환", () => {
    const item = record();
    item.extra = { k: 1 };
    const [copy] = prepareDetections(SOURCE, [item]);
    expect(copy).not.toBe(item);
    expect(copy?.extra).toEqual({ k: 1 });
    expect(copy?.extra).not.toBe(item.extra);
  });
});

describe("hashed digestLen 검증", () => {
  it.each([0, -1, 65, true, 1.5, "12", null])("digestLen=%j 거부 (빈 입력 포함)", (length) => {
    const n = length as unknown as number;
    expect(() => hashed(SOURCE, [record()], null, n)).toThrow(
      new ValueError("digest_len must be an integer from 1 to 64"),
    );
    expect(() => hashed("", [], null, n)).toThrow(ValueError);
  });

  it.each([1, 8, 12, 64])("digestLen=%i 는 요청한 길이의 hex", (length) => {
    const [output] = hashed(VALUE, [record()], fastVault("stable"), length);
    const digest = output.replace(/^<EMAIL:/, "").replace(/>$/, "");
    expect(digest).toHaveLength(length);
    expect(digest).toMatch(/^[0-9a-f]+$/);
  });
});

describe("splitLiteralEmail — Python _split_literal_email 실측 대조 (IDNA 길이 경계)", () => {
  const a = (n: number) => "a".repeat(n);
  const ga = (n: number) => "가".repeat(n);
  it.each([
    [`u@${a(63)}.com`, true],
    [`u@${a(64)}.com`, false],
    [`u@${ga(30)}.com`, true],
    [`u@${ga(40)}.com`, true],
    [`u@${ga(60)}.com`, false],
    [`u@${[a(61), a(61), a(61), a(61)].join(".")}.com`, true],
    [`u@${[a(62), a(62), a(62), a(62)].join(".")}.com`, false],
    ["u@xn--한.com", false],
    ["u@한국.한국.kr", true],
    ["u@ABC한.com", true],
    ["a.b@x.co", true],
  ])("%s → 지원=%s", (value, supported) => {
    const parts = splitLiteralEmail(value);
    if (supported)
      expect(parts).toEqual([
        value.slice(0, value.indexOf("@")),
        value.slice(value.indexOf("@") + 1),
      ]);
    else expect(parts).toBeNull();
  });
});
