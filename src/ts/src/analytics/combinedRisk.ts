/** 결합 위험도 평가 — 검출 결과의 조합이 *함께* 식별 가능한지 평가.
 *
 * Python ko_pii.analytics.combined_risk 대응.
 * 「개인정보 비식별 조치 가이드라인」(개인정보보호위원회) 분류:
 * - 식별자 (identifier): 단독으로 개인 식별 가능. 무조건 차단.
 * - 준식별자 (quasi-identifier): 단독은 식별 불가하나, 결합 시 식별 가능.
 * - 민감속성 (sensitive attribute): 식별과는 별개로 보호 대상 정보.
 * - 일반속성 (general attribute): 위 셋에 해당하지 않음.
 *
 * 결합 위험도는 서로 다른 준식별자 종류 수에 따라 증가:
 * - 0~1 종류: LOW / 2~3 종류: MEDIUM / 4 이상: HIGH.
 * 식별자가 1개라도 있으면 자동 CRITICAL. 민감속성 등장 시 한 단계 가산 (CRITICAL 캡).
 */

import { type DetectionResult, RiskLevel } from "../core/types.js";

/** 속성 분류 (값은 Python Enum의 문자열 값 그대로 — JSON 직렬화 호환). */
export enum AttributeClass {
  IDENTIFIER = "identifier",
  QUASI_IDENTIFIER = "quasi_identifier",
  SENSITIVE = "sensitive",
  GENERAL = "general",
}

/** 라벨 → 속성 분류 매핑 (가이드라인 + 본 라이브러리 카테고리).
 * Python 원본과 키 집합/순서 동일. 미등록 라벨(예: EDI_DRUG, NATIONALITY, 알 수 없는 라벨)은
 * classify_attribute에서 GENERAL로 분류된다.
 */
const _LABEL_TO_CLASS: Readonly<Record<string, AttributeClass>> = {
  // 식별자 (단독 식별)
  RRN: AttributeClass.IDENTIFIER,
  FRN: AttributeClass.IDENTIFIER,
  PASSPORT: AttributeClass.IDENTIFIER,
  DRIVER_LICENSE: AttributeClass.IDENTIFIER,
  CARD: AttributeClass.IDENTIFIER,
  // 준식별자 (결합 식별)
  PERSON: AttributeClass.QUASI_IDENTIFIER,
  PHONE: AttributeClass.QUASI_IDENTIFIER,
  EMAIL: AttributeClass.QUASI_IDENTIFIER,
  ADDRESS: AttributeClass.QUASI_IDENTIFIER,
  POSTAL_CODE: AttributeClass.QUASI_IDENTIFIER,
  ACCOUNT: AttributeClass.QUASI_IDENTIFIER,
  BUSINESS_REG: AttributeClass.QUASI_IDENTIFIER,
  CORP_REG: AttributeClass.QUASI_IDENTIFIER,
  VEHICLE: AttributeClass.QUASI_IDENTIFIER,
  EMPLOYEE_ID: AttributeClass.QUASI_IDENTIFIER,
  IP: AttributeClass.QUASI_IDENTIFIER,
  // 인적 속성 (KDPII 준식별자)
  DT_BIRTH: AttributeClass.QUASI_IDENTIFIER,
  EDUCATION: AttributeClass.QUASI_IDENTIFIER,
  MAJOR: AttributeClass.QUASI_IDENTIFIER,
  POSITION: AttributeClass.QUASI_IDENTIFIER,
  AGE: AttributeClass.QUASI_IDENTIFIER,
  HEIGHT: AttributeClass.QUASI_IDENTIFIER,
  WEIGHT: AttributeClass.QUASI_IDENTIFIER,
  // 민감속성 (보호 대상)
  MEDICAL_INSURANCE: AttributeClass.SENSITIVE,
  PRESCRIPTION_ID: AttributeClass.SENSITIVE,
  COURT_CASE: AttributeClass.SENSITIVE,
  // 일반·참조
  URL: AttributeClass.GENERAL,
  FAX: AttributeClass.GENERAL,
  DOC_ID: AttributeClass.GENERAL,
  PETITION_ID: AttributeClass.GENERAL,
  PNU: AttributeClass.GENERAL,
};

/** 단일 식별 항목 (Python Identifier dataclass 대응). */
export interface Identifier {
  label: string;
  text: string;
  attribute_class: AttributeClass;
}

/** 결합 위험도 보고서 (Python CombinedRiskReport dataclass 대응).
 * 필드명은 anonymizer `_build_summary` 및 JSON 직렬화 호환을 위해 스네이크케이스 유지.
 */
export interface CombinedRiskReport {
  distinct_identifiers: string[];
  distinct_quasi: string[];
  sensitive_present: string[];
  combined_risk: RiskLevel;
  rationale: string[];
}

/** Python `RiskLevel(...).name` 동등물 — 숫자 enum의 역방향 매핑. */
export function riskLevelName(level: RiskLevel): string {
  return RiskLevel[level];
}

/** Python `CombinedRiskReport.is_re_identifiable()` 동등물.
 * True 이면 재식별 가능성이 충분히 높음 (CRITICAL/HIGH).
 */
export function is_re_identifiable(rpt: CombinedRiskReport): boolean {
  return rpt.combined_risk >= RiskLevel.HIGH;
}

/** 라벨을 속성 클래스로 분류. 매핑에 없는 라벨은 GENERAL. */
export function classify_attribute(label: string): AttributeClass {
  const cls = _LABEL_TO_CLASS[label];
  return cls ?? AttributeClass.GENERAL;
}

/** Python sorted() 동등물 — 라벨은 ASCII라 JS 기본 정렬(UTF-16 코드 유닛)과 동치. */
function sortedLabels(labels: ReadonlySet<string>): string[] {
  return [...labels].sort();
}

/** 주어진 검출 결과 집합의 *조합* 위험도를 산출. */
export function score_combined_risk(detections: Iterable<DetectionResult>): CombinedRiskReport {
  const ids = new Set<string>();
  const quasi = new Set<string>();
  const sensitive = new Set<string>();

  for (const d of detections) {
    const cls = classify_attribute(d.label);
    if (cls === AttributeClass.IDENTIFIER) {
      ids.add(d.label);
    } else if (cls === AttributeClass.QUASI_IDENTIFIER) {
      quasi.add(d.label);
    } else if (cls === AttributeClass.SENSITIVE) {
      sensitive.add(d.label);
    }
  }

  const distinct_identifiers = sortedLabels(ids);
  const distinct_quasi = sortedLabels(quasi);
  const sensitive_present = sortedLabels(sensitive);

  const rationale: string[] = [];
  let combined_risk: RiskLevel;

  // 위험도 결정
  if (ids.size > 0) {
    combined_risk = RiskLevel.CRITICAL;
    rationale.push(
      `식별자 ${ids.size}종 등장: ${distinct_identifiers.join(", ")} → 즉시 식별 가능`,
    );
  } else if (quasi.size >= 4) {
    combined_risk = RiskLevel.HIGH;
    rationale.push(
      `준식별자 ${quasi.size}종 결합 → 재식별 가능성 매우 높음 (${distinct_quasi.join(", ")})`,
    );
  } else if (quasi.size >= 2) {
    combined_risk = RiskLevel.MEDIUM;
    rationale.push(`준식별자 ${quasi.size}종 결합 → 재식별 가능성 있음`);
  } else if (quasi.size === 1) {
    combined_risk = RiskLevel.LOW;
    rationale.push("준식별자 1종 → 단독 식별 어려움");
  } else {
    combined_risk = RiskLevel.INFO;
    rationale.push("식별 정보 없음");
  }

  // 민감속성 등장 시 한 단계 가산 (CRITICAL 캡)
  if (sensitive.size > 0 && combined_risk < RiskLevel.CRITICAL) {
    const prev = combined_risk;
    combined_risk = Math.min(prev + 1, RiskLevel.CRITICAL) as RiskLevel;
    rationale.push(
      `민감속성 ${sensitive.size}종 등장 (${sensitive_present.join(", ")}) → 위험도 ${riskLevelName(prev)} → ${riskLevelName(combined_risk)}`,
    );
  }

  return {
    distinct_identifiers,
    distinct_quasi,
    sensitive_present,
    combined_risk,
    rationale,
  };
}
