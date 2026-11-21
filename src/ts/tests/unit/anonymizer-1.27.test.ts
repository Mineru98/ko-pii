/**
 * Anonymizer 1.27 동작 — Python tests/unit/test_processing_policy.py, test_overlap_protection.py,
 * test_primary_policy_overlap.py, test_explanation_trace.py (anonymizer 부분) 대응.
 *
 * 기대값은 Python 테스트 단언 또는 .venv/bin/python (ko_pii 1.27.0) 실측값이다.
 * Python 의 ``monkeypatch.setattr("ko_pii.anonymizer._detect_candidates", ...)`` 는 vi.mock 으로
 * detectCandidates 를 교체해 재현한다.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ValueError } from "../../src/core/errors.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../../src/core/types.js";
import { detectAll } from "../../src/detect.js";
import { CallableDetector } from "../../src/integrations/custom.js";
import { explain } from "../../src/reporting/explanation.js";
import { ReversibleVault } from "../../src/vault/reversible.js";

const hoisted = vi.hoisted(() => ({
  override: null as null | ((text: string) => DetectionResult[]),
}));

vi.mock("../../src/detect.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/detect.js")>();
  return {
    ...actual,
    detectCandidates: (...args: Parameters<typeof actual.detectCandidates>) =>
      hoisted.override !== null ? hoisted.override(args[0]) : actual.detectCandidates(...args),
  };
});

afterEach(() => {
  hoisted.override = null;
});

function candidates(list: DetectionResult[]): void {
  hoisted.override = () => list;
}

function detection(
  source: string,
  label: string,
  begin: number,
  end: number,
  risk: RiskLevel,
  confidence = 1.0,
): DetectionResult {
  return makeDetection({
    label,
    text: source.slice(begin, end),
    start: begin,
    end,
    riskLevel: risk,
    confidence,
  });
}

const spans = (r: { substitutions: { start: number; end: number }[] }) =>
  r.substitutions.map((s) => [s.start, s.end]);

describe("per-label strategies (test_processing_policy.py)", () => {
  it("혼합 전략 한 번에 적용 + 요약/설명 (Python 실측)", () => {
    const text = "주민번호 880101-1234568 전화 010-2345-6789 메일 user@example.com";
    const overrides: Record<string, string> = { RRN: "redact", PHONE: "partial" };
    const anon = new Anonymizer(
      ProcessingMode.STRICT,
      "tokenize",
      null,
      ["RRN", "PHONE", "EMAIL"],
      null,
      null,
      "union",
      null,
      null,
      { strategies: overrides, traceLimit: 5 },
    );
    overrides.RRN = "partial"; // 생성 후 변경은 반영되지 않는다
    const result = anon.process(text);
    expect(result.text).toBe("주민번호 [주민등록번호] 전화 010-****-6789 메일 <EMAIL_1>");
    expect(result.vault?.reveal("<EMAIL_1>")).toBe("user@example.com");
    expect(result.substitutions).toEqual([
      { start: 5, end: 19, outputStart: 5, outputEnd: 13 },
      { start: 23, end: 36, outputStart: 17, outputEnd: 30 },
      { start: 40, end: 56, outputStart: 34, outputEnd: 43 },
    ]);
    expect(result.detections.map((r) => r.strategy)).toEqual(["redact", "partial", "tokenize"]);
    expect(result.summary.strategies).toEqual({ RRN: "redact", PHONE: "partial" });
    expect(result.summary.transformation_policy_sha256).toBe(
      "c3086e8aa1be14990a7a0b35b65020408efe383b7a1f57828a47e8d42d05170d",
    );
    expect(result.summary.detection_scope).toEqual({
      input_empty: false,
      asserted_field: false,
      include: ["EMAIL", "PHONE", "RRN"],
      exclude: [],
      combined_risk_basis: "observed_labels_heuristic_not_anonymity_assessment",
    });
    const report = explain(result, { includeTrace: true });
    expect(report.findings).toEqual([
      {
        label: "RRN",
        rule_id: "ko-pii.rrn.v1",
        subrule_id: null,
        source_span: [5, 19],
        output_span: [5, 13],
        normalized: false,
        checks: ["checksum:valid"],
        confidence: 1.0,
        action: "BLOCK",
        requested_strategy: "redact",
        applied_strategy: "redact",
        reason: "substituted",
      },
      {
        label: "PHONE",
        rule_id: "ko-pii.phone.v1",
        subrule_id: null,
        source_span: [23, 36],
        output_span: [17, 30],
        normalized: false,
        checks: [],
        confidence: 1.0,
        action: "BLOCK",
        requested_strategy: "partial",
        applied_strategy: "partial",
        reason: "partial_masking",
      },
      {
        label: "EMAIL",
        rule_id: "ko-pii.email.v1",
        subrule_id: "email.ascii.v1",
        source_span: [40, 56],
        output_span: [34, 43],
        normalized: false,
        checks: [],
        confidence: 1.0,
        action: "BLOCK",
        requested_strategy: "tokenize",
        applied_strategy: "tokenize",
        reason: "substituted",
      },
    ]);
    expect(report.overlap_trace).toEqual({
      schema_version: 1,
      contract: "ko-pii-overlap-trace-v1",
      scope: "common_overlap_only; excludes_detector_internal_and_merge_policy_rejections",
      limit: 5,
      truncated: false,
      omitted_events: 0,
      stages: { primary: { candidates: 3, kept: 3, discarded: 0 } },
      discarded: [],
    });
  });

  it.each([[{ NO_LABEL: "redact" }], [{ PHONE: "typo" }], [{ PHONE: [] }], ["redact"]])(
    "잘못된 정책은 거부: %o",
    (overrides) => {
      expect(
        () =>
          new Anonymizer(undefined, undefined, null, null, null, null, "union", null, null, {
            strategies: overrides as never,
          }),
      ).toThrow(ValueError);
    },
  );

  it("재정의는 AUDIT 모드를 우회하지 않는다", () => {
    const text = "메일 user@example.com";
    const result = new Anonymizer(
      ProcessingMode.AUDIT,
      "tokenize",
      null,
      null,
      null,
      null,
      "union",
      null,
      null,
      { strategies: { EMAIL: "asterisk" } },
    ).process(text);
    expect(result.text).toBe(text);
    expect(result.substitutions).toEqual([]);
    expect((explain(result).findings as { reason: string }[])[0]?.reason).toBe(
      "retained_by_policy",
    );
  });

  it("빈 입력 요약과 include 중복 제거·정렬 (Python 실측)", () => {
    const result = new Anonymizer(
      ProcessingMode.STRICT,
      "redact",
      null,
      ["PHONE", "EMAIL", "PHONE"],
      ["RRN"],
    ).process("");
    expect(result.summary).toEqual({
      combined_risk: "INFO",
      combined_rationale: [
        "선택된 탐지 결과에서 식별자/준식별자 라벨을 찾지 못함; 원문에 없다는 보장은 아님",
      ],
      distinct_identifiers: [],
      distinct_quasi_identifiers: [],
      sensitive_attributes: [],
      total: 0,
      mode: "STRICT",
      strategy: "redact",
      strategies: {},
      transformation_policy_sha256:
        "85613033b68132d6c6bcf2fb526b0d31f4335304873273fa26a940e5a063da1d",
      by_action: {},
      by_risk: {},
      by_label: {},
      by_legal_basis: {},
      detection_scope: {
        input_empty: true,
        asserted_field: false,
        include: ["EMAIL", "PHONE"],
        exclude: ["RRN"],
        combined_risk_basis: "observed_labels_heuristic_not_anonymity_assessment",
      },
      overlap_resolution: "block_risk_confidence_length_start",
    });
    expect(result.vault).toBeNull();
  });
});

describe("constructor validation", () => {
  it("빈 include·미지 라벨·문자열 단독 필터는 ValueError", () => {
    expect(() => new Anonymizer(undefined, undefined, null, [])).toThrow(ValueError);
    expect(() => new Anonymizer(undefined, undefined, null, ["NOPE"])).toThrow(ValueError);
    expect(() => new Anonymizer(undefined, undefined, null, "PHONE" as never)).toThrow(ValueError);
    expect(new Anonymizer(undefined, undefined, null, null, []).exclude).toEqual([]);
  });

  it("trace_limit 범위·merge 설정·secondary detect 검증", () => {
    const opts = (traceLimit: number) =>
      new Anonymizer(undefined, undefined, null, null, null, null, "union", null, null, {
        traceLimit,
      });
    expect(() => opts(-1)).toThrow(ValueError);
    expect(() => opts(1001)).toThrow(ValueError);
    expect(() => opts(1.5)).toThrow(ValueError);
    expect(opts(1000).traceLimit).toBe(1000);
    expect(
      () => new Anonymizer(undefined, undefined, null, null, null, null, "union", ["TYPO"]),
    ).toThrow("invalid merge_mode or role_split_labels; use registered modes and labels");
    expect(
      () => new Anonymizer(undefined, undefined, null, null, null, { name: "x" } as never),
    ).toThrow("secondary_detector must provide a callable detect method");
  });

  it("strategy 오타는 Python 과 같은 메시지", () => {
    expect(() => new Anonymizer(undefined, "nope")).toThrow("Unknown strategy");
  });

  it("빈 명시 vault 를 유지한다", () => {
    const vault = new ReversibleVault();
    expect(new Anonymizer(undefined, "tokenize", vault).vault).toBe(vault);
  });

  it("secondary 결과가 원문에 결속되지 않으면 값 없이 거부하고 vault 에 쓰지 않는다", () => {
    const vault = new ReversibleVault();
    const bad = makeDetection({
      label: "PERSON",
      text: "secret-value",
      start: 0,
      end: 3,
      riskLevel: RiskLevel.HIGH,
    });
    const anon = new Anonymizer(undefined, "tokenize", vault, null, null, {
      name: "bad",
      detect: () => [bad],
    });
    let message = "";
    try {
      anon.process("홍길동 010-1234-5678");
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toBe("secondary detector failed or returned invalid source-bound results");
    expect(vault.size).toBe(0);
  });
});

describe("person_exclusions (인스턴스 범위)", () => {
  it("제외어는 PERSON 만 억제한다 (Python 실측)", () => {
    const anon = new Anonymizer(
      ProcessingMode.STRICT,
      "redact",
      null,
      null,
      null,
      null,
      "union",
      null,
      ["홍길동"],
    );
    expect(anon.process("담당자 홍길동 김철수 010-1234-5678").text).toBe(
      "담당자 홍길동 [성명] [전화번호]",
    );
    expect([...anon.personExclusions]).toEqual(["홍길동"]);
  });
});

describe("overlap protection (test_overlap_protection.py)", () => {
  it.each(["redact", "tokenize", "asterisk", "hashed"])(
    "중첩 완전 마스크는 내부 검출을 유지하고 양쪽을 보호한다: %s",
    (strategy) => {
      const source = "ABCDEFGHIJ";
      const parent = detection(source, "ADDRESS", 0, 10, RiskLevel.MEDIUM);
      const child = detection(source, "PHONE", 3, 7, RiskLevel.HIGH);
      candidates([parent, child]);
      const vault = new ReversibleVault({
        salt: "coverage",
        secretKey: "test",
        fingerprintIterations: 1,
      });
      const result = new Anonymizer(ProcessingMode.STRICT, strategy, vault).process(source);
      expect(spans(result)).toEqual([
        [0, 3],
        [3, 7],
        [7, 10],
      ]);
      expect(result.detections.map((r) => r.detection.label)).toEqual([
        "ADDRESS",
        "PHONE",
        "ADDRESS",
      ]);
      expect(result.detections[1]?.detection).toBe(child);
      expect(result.summary.overlap_protection).toEqual({ fragments: 2 });
      for (const record of [result.detections[0], result.detections[2]]) {
        const d = record?.detection as DetectionResult;
        expect(d.text).toBe(source.slice(d.start, d.end));
        expect(d.subruleId).toBe("protection.overlap-remainder.v1");
        expect(d.extra.overlap_parent).toEqual({ label: "ADDRESS", source_span: [0, 10] });
      }
      if (strategy === "tokenize") {
        let restored = result.text;
        for (const entry of vault.entries()) {
          restored = restored.replace(entry.token, vault.reveal(entry.token) as string);
        }
        expect(restored).toBe(source);
      }
    },
  );

  it("교차하는 버려진 후보들은 서로의 나머지를 버리지 않는다", () => {
    const source = "ABCDEFGHIJKLMNO";
    candidates([
      detection(source, "ADDRESS", 0, 9, RiskLevel.MEDIUM),
      detection(source, "ACCOUNT", 5, 15, RiskLevel.HIGH, 0.95),
      detection(source, "PHONE", 7, 10, RiskLevel.HIGH),
    ]);
    const result = new Anonymizer(ProcessingMode.STRICT, "redact").process(source);
    expect(result.text).toBe("[주소][계좌번호][전화번호][계좌번호]");
    expect(spans(result)).toEqual([
      [0, 5],
      [5, 7],
      [7, 10],
      [10, 15],
    ]);
  });

  it.each([
    [
      " (010-1234-5678)",
      [
        ["ADDRESS", 4, 24],
        ["PHONE", 24, 37],
        ["ADDRESS", 37, 38],
      ],
    ],
    [
      " (101동 1202호, 010-1234-5678)",
      [
        ["ADDRESS", 4, 36],
        ["PHONE", 36, 49],
        ["ADDRESS", 49, 50],
      ],
    ],
  ])("전화번호가 박힌 실제 주소도 노출되지 않는다 (Python 실측): %s", (tail, expected) => {
    const address = "서울특별시 강남구 테헤란로 152";
    const result = new Anonymizer(
      ProcessingMode.STRICT,
      "redact",
      null,
      null,
      null,
      null,
      "union",
      null,
      null,
      { traceLimit: 10 },
    ).process(`주소: ${address}${tail}`);
    expect(result.text).toBe("주소: [주소][전화번호][주소]");
    expect(
      result.detections.map((r) => [r.detection.label, r.detection.start, r.detection.end]),
    ).toEqual(expected);
    expect(result.summary.overlap_resolution).toBe(
      "block_risk_confidence_length_start;complete_replacement_remainders",
    );
    const trace = result.overlap_trace?.report();
    expect(trace?.stages).toEqual({
      primary: { candidates: 2, kept: 1, discarded: 1 },
      protection: { candidates: 3, kept: 3, discarded: 0 },
    });
    expect(trace?.discarded[0]?.reason).toBe("lower_risk_priority");
  });

  it("주소 안의 확정 PERSON 이 도로명·층을 노출하지 않는다 (Python 실측)", () => {
    const source = "성명: 김다은\n주소: 서울특별시 강남구 테헤란로 152 김다은 12층";
    const result = new Anonymizer(ProcessingMode.STRICT, "redact").process(source);
    expect(result.text).toBe("성명: [성명]\n주소: [주소][성명][주소]");
    for (const value of ["김다은", "테헤란로", "152", "12층"]) {
      expect(result.text).not.toContain(value);
    }
  });

  it.each(["union", "role_split"])("나머지는 자격 있는 병합 후보에서 나온다: %s", (mode) => {
    const source = "ABCDEFGHIJ";
    const child = detection(source, "PHONE", 3, 7, RiskLevel.HIGH);
    const parent = detection(source, "ADDRESS", 0, 10, RiskLevel.MEDIUM);
    candidates([child]);
    const extra = new CallableDetector(() => [parent]);
    const result = new Anonymizer(ProcessingMode.STRICT, "redact", null, null, null, extra, mode, [
      "ADDRESS",
    ]).process(source);
    expect(result.text).toBe("[주소][전화번호][주소]");
  });

  it.each([
    ["intersection", "ABCDEFGHIJ"],
    ["fallback_secondary", "[주소][전화번호][주소]"],
    ["role_split", "ABC[전화번호]HIJ"],
  ])("병합에서 거부된 후보는 되살아나지 않는다: %s", (mode, expected) => {
    const source = "ABCDEFGHIJ";
    candidates([
      detection(source, "ADDRESS", 0, 10, RiskLevel.MEDIUM),
      detection(source, "PHONE", 3, 7, RiskLevel.HIGH),
    ]);
    const extra = new CallableDetector(() => []);
    const result = new Anonymizer(ProcessingMode.STRICT, "redact", null, null, null, extra, mode, [
      "ADDRESS",
    ]).process(source);
    expect(result.text).toBe(expected);
  });

  it("enrich_primary 는 primary 와 겹치는 secondary 피복을 되살리지 않는다", () => {
    const source = "ABCDEFGHIJ";
    const parent = detection(source, "ADDRESS", 0, 10, RiskLevel.MEDIUM);
    candidates([detection(source, "PHONE", 3, 7, RiskLevel.HIGH)]);
    const result = new Anonymizer(
      ProcessingMode.STRICT,
      "redact",
      null,
      null,
      null,
      new CallableDetector(() => [parent]),
      "enrich_primary",
    ).process(source);
    expect(result.text).toBe("ABC[전화번호]HIJ");
  });

  it.each(["partial", "fpe"])("partial/fpe 부모는 완전 치환으로 보지 않는다: %s", (strategy) => {
    const source = "ABCDEFGHIJ";
    candidates([
      detection(source, "ADDRESS", 0, 10, RiskLevel.MEDIUM),
      detection(source, "PHONE", 3, 7, RiskLevel.HIGH),
    ]);
    const result = new Anonymizer(
      ProcessingMode.STRICT,
      "redact",
      null,
      null,
      null,
      null,
      "union",
      null,
      null,
      { strategies: { ADDRESS: strategy } },
    ).process(source);
    expect(result.text).toBe("ABC[전화번호]HIJ");
    expect(result.summary).not.toHaveProperty("overlap_protection");
  });

  it("채택된 partial 전략은 부모가 덮어쓰지 않는다", () => {
    const source = "before 01012345678 after";
    candidates([
      detection(source, "ADDRESS", 0, source.length, RiskLevel.MEDIUM),
      detection(source, "PHONE", 7, 18, RiskLevel.HIGH),
    ]);
    const result = new Anonymizer(
      ProcessingMode.STRICT,
      "redact",
      null,
      null,
      null,
      null,
      "union",
      null,
      null,
      { strategies: { PHONE: "partial" } },
    ).process(source);
    expect(result.text).not.toContain("before");
    expect(result.text).not.toContain("after");
    expect(result.text).toContain("5678");
    expect(result.detections[1]?.strategy).toBe("partial");
  });

  it("AUDIT·필터·저수준 검출은 각자의 계약을 유지한다", () => {
    const source = "주소: 서울특별시 강남구 테헤란로 152 (010-1234-5678)";
    const audit = new Anonymizer(ProcessingMode.AUDIT);
    const result = audit.process(source);
    expect(result.text).toBe(source);
    expect(result.substitutions).toEqual([]);
    expect(audit.vault.entries()).toEqual([]);
    const filtered = new Anonymizer(ProcessingMode.STRICT, "redact", null, ["PHONE"]).process(
      source,
    );
    expect(filtered.text).toContain("테헤란로 152");
    expect(filtered.text).not.toContain("010-1234-5678");
    expect(detectAll(source).map((d) => [d.label, d.text])).toEqual([["PHONE", "010-1234-5678"]]);
  });

  it("조각 보고는 값을 노출하지 않고 파생 span 을 설명한다", () => {
    const source = "ABCDEFGHIJ";
    candidates([
      detection(source, "ADDRESS", 0, 10, RiskLevel.MEDIUM),
      detection(source, "PHONE", 3, 7, RiskLevel.HIGH),
    ]);
    const result = new Anonymizer(
      ProcessingMode.STRICT,
      "redact",
      null,
      null,
      null,
      null,
      "union",
      null,
      null,
      { traceLimit: 10 },
    ).process(source);
    const report = explain(result, { includeTrace: true });
    const trace = report.overlap_trace as { stages: Record<string, unknown> };
    expect(trace.stages.protection).toEqual({ candidates: 3, kept: 3, discarded: 0 });
    expect((report.findings as { subrule_id: string }[])[0]?.subrule_id).toBe(
      "protection.overlap-remainder.v1",
    );
    expect(
      String(report.overlap_resolution).startsWith("block_risk_confidence_length_start;"),
    ).toBe(true);
    const dumped = JSON.stringify(report);
    for (const value of [source, "ABC", "DEFG", "HIJ"]) expect(dumped).not.toContain(value);
  });
});

describe("primary policy overlap (test_primary_policy_overlap.py)", () => {
  it.each(["9001011234567", "900101-1234567", "９００１０１１２３４５６７"])(
    "REVIEW 인 RRN 후보만 있어도 ACCOUNT 는 마스킹된다: %s",
    (value) => {
      const result = new Anonymizer(ProcessingMode.BALANCED, "redact").process(
        `계좌번호: ${value}`,
      );
      expect(result.text).toBe("계좌번호: [계좌번호]");
    },
  );

  it("REVIEW 후보를 추가해도 기존 BLOCK 이 되돌아가지 않는다", () => {
    const text = "계좌번호: 9001011234567";
    const narrow = new Anonymizer(ProcessingMode.BALANCED, "redact", null, ["ACCOUNT"]);
    const broader = new Anonymizer(ProcessingMode.BALANCED, "redact", null, ["ACCOUNT", "RRN"]);
    expect(broader.process(text).text).toBe(narrow.process(text).text);
  });
});
