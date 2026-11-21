/**
 * Analytics 1.27 — Python tests/unit/analytics/test_k_anonymity.py, test_combined_risk.py 대응.
 * 문구 기대값은 .venv/bin/python (ko_pii 1.27.0) 실측.
 */
import { describe, expect, it } from "vitest";
import {
  evaluate_dataset,
  is_re_identifiable,
  k_anonymity,
  score_combined_risk,
} from "../../src/analytics/index.js";
import { makeDetection, RiskLevel } from "../../src/core/types.js";

describe("k_anonymity 1.27 — 미평가와 입력 검증", () => {
  it("준식별자가 없으면 통과가 아니라 미평가 (k=0)", () => {
    const rpt = k_anonymity([{ RRN: "880101-1" }, { RRN: "950101-2" }]);
    expect(rpt).toEqual({
      k: 0,
      group_count: 0,
      smallest_group_size: 0,
      smallest_group_values: [],
      quasi_identifier_keys: [],
      record_count: 2,
      satisfies_threshold: false,
      threshold: 5,
      rationale: ["준식별자가 없어 평가하지 않음; k=0은 미평가 표시"],
    });
  });

  for (const threshold of [0, -1, true, 1.5, "5", null, Number.NaN]) {
    it(`잘못된 threshold ${String(threshold)} 는 빈 데이터에서도 거부`, () => {
      expect(() => k_anonymity([], null, threshold as unknown as number)).toThrow(/threshold/);
    });
  }

  for (const keys of ["AGE", [""], [null], [["AGE"]], ["AGE", "AGE"]]) {
    it(`잘못된 quasi_keys ${JSON.stringify(keys)}`, () => {
      expect(() => k_anonymity([], keys as unknown as string[])).toThrow(/quasi_keys/);
    });
  }

  const missingCases: [Record<string, unknown>[], string[] | null][] = [
    [[0, 1, 2, 3, 4].map((age) => ({ AGE: age })), ["age"]],
    [[{ AGE: 20 }, {}], ["AGE"]],
    [[{ AGE: 20 }, {}], null],
  ];
  for (const [records, keys] of missingCases) {
    it(`누락 열은 공유 null 그룹이 되지 않는다 ${JSON.stringify(keys)}`, () => {
      expect(() => k_anonymity(records, keys)).toThrow(/present in every record/);
    });
  }

  it("명시적 null 값과 고유 값은 구별", () => {
    expect(k_anonymity(Array(5).fill({ AGE: null }), ["AGE"]).k).toBe(5);
    const report = k_anonymity(
      [0, 1, 2, 3, 4].map((age) => ({ AGE: age })),
      ["AGE"],
    );
    expect(report.k).toBe(1);
    expect(report.satisfies_threshold).toBe(false);
  });

  it("빈 명시 키는 threshold 통과를 주장하지 않는다", () => {
    const report = k_anonymity(Array(10).fill({ AGE: 20 }), [], 5);
    expect(report.k).toBe(0);
    expect(report.satisfies_threshold).toBe(false);
  });

  it("해시 불가 값 오류는 데이터를 반사하지 않는다", () => {
    let message = "";
    try {
      k_anonymity([{ AGE: ["private-value"] }]);
    } catch (e) {
      message = (e as Error).message;
      expect((e as Error).name).toBe("ValueError");
    }
    expect(message).toMatch(/hashable/);
    expect(message).not.toContain("private-value");
  });

  it("기본 동작 (자동 준식별자 선택·rationale 문구)", () => {
    const rpt = k_anonymity(Array(3).fill({ PERSON: "P1", ADDRESS: "서울" }));
    expect([rpt.k, rpt.group_count, rpt.satisfies_threshold]).toEqual([3, 1, false]);
    expect(rpt.rationale).toEqual([
      "준식별자 ['ADDRESS', 'PERSON'] 기준 1개 그룹",
      "최소 그룹 크기 k = 3",
      "k=3 < threshold 5 → 일반화 필요 (권장: 연령 구간화, 주소 시·도 단위 등)",
    ]);
    const auto = evaluate_dataset([
      { RRN: "880101-1", PERSON: "P1", ADDRESS: "서울", URL: "x" },
      { RRN: "950101-2", PERSON: "P1", ADDRESS: "서울", URL: "y" },
    ]);
    expect(auto.k).toBe(2);
    expect(auto.quasi_identifier_keys).toEqual(["ADDRESS", "PERSON"]);
  });
});

describe("combined_risk 1.27 — 휴리스틱 문구", () => {
  const d = (label: string) =>
    makeDetection({ label, text: "x", start: 0, end: 1, riskLevel: RiskLevel.HIGH });
  const cases: [string[], RiskLevel, string[]][] = [
    [
      ["RRN", "PERSON"],
      RiskLevel.CRITICAL,
      ["선택된 탐지에서 식별자 1종 관측: RRN → 규칙상 CRITICAL"],
    ],
    [
      ["PERSON", "PHONE", "EMAIL", "ADDRESS"],
      RiskLevel.HIGH,
      ["준식별자 4종 관측 → 규칙상 HIGH (ADDRESS, EMAIL, PERSON, PHONE)"],
    ],
    [["PERSON", "PHONE"], RiskLevel.MEDIUM, ["준식별자 2종 결합 → 재식별 가능성 있음"]],
    [["PERSON"], RiskLevel.LOW, ["준식별자 1종 관측 → 규칙상 LOW; 단독 식별 불가를 뜻하지 않음"]],
    [
      [],
      RiskLevel.INFO,
      ["선택된 탐지 결과에서 식별자/준식별자 라벨을 찾지 못함; 원문에 없다는 보장은 아님"],
    ],
    [
      ["PERSON", "PHONE", "MEDICAL_INSURANCE"],
      RiskLevel.HIGH,
      [
        "준식별자 2종 결합 → 재식별 가능성 있음",
        "민감속성 1종 등장 (MEDICAL_INSURANCE) → 위험도 MEDIUM → HIGH",
      ],
    ],
  ];
  for (const [labels, risk, rationale] of cases) {
    it(JSON.stringify(labels), () => {
      const rpt = score_combined_risk(labels.map(d));
      expect(rpt.combined_risk).toBe(risk);
      expect(rpt.rationale).toEqual(rationale);
    });
  }
  it("is_re_identifiable 는 HIGH/CRITICAL 휴리스틱", () => {
    expect(is_re_identifiable(score_combined_risk([d("RRN")]))).toBe(true);
    expect(is_re_identifiable(score_combined_risk([d("PERSON")]))).toBe(false);
  });
});
