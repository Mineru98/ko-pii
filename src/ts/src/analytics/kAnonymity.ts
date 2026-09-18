/** k-익명성 (k-Anonymity) — 「비식별 조치 가이드라인」의 핵심 정량 지표.
 *
 * Python ko_pii.analytics.k_anonymity 대응.
 *
 * 정의:
 * - 데이터셋의 각 레코드가 *준식별자 조합* 이 동일한 다른 (k-1)개 레코드와
 *   구분되지 않을 때 k-익명성을 만족한다고 한다.
 * - 통상 k ≥ 5 권장. 민감속성이 포함된 데이터는 k ≥ 10.
 *
 * 가명화된 레코드 집합 (각 레코드 = Record[label, value]) 을 받아
 * - 준식별자 조합별 그룹 크기 계산
 * - 최소 그룹 크기 = k
 * - k < threshold 면 일반화 (generalization) 제안
 *
 * 원본 PII 가 아닌 *가명화 후* 레코드를 대상으로 평가하는 것이 표준 사용법.
 */

import { AttributeClass, classify_attribute } from "./combinedRisk.js";

/** k-익명성 평가 보고서 (Python KAnonymityReport dataclass 대응).
 * 필드명은 JSON 직렬화 골드 대조를 위해 스네이크케이스 유지.
 */
export interface KAnonymityReport {
  /** 최소 그룹 크기 (= k). */
  k: number;
  group_count: number;
  smallest_group_size: number;
  /** 최소 그룹의 준식별자 값 튜플 (Python tuple → 배열). */
  smallest_group_values: unknown[];
  quasi_identifier_keys: string[];
  record_count: number;
  satisfies_threshold: boolean;
  threshold: number;
  rationale: string[];
}

/** Python `repr(str)` 동등물 — rationale에 리스트 표현이 그대로 들어가므로 표현 일치 필요. */
function pyReprString(s: string): string {
  return `'${s.replaceAll("\\", "\\\\").replaceAll("'", "\\'")}'`;
}

/** Python `repr(list[str])` 동등물 — `['A', 'B']` 형태 (작은따옴표, `, ` 구분). */
function pyListRepr(items: readonly string[]): string {
  return `[${items.map(pyReprString).join(", ")}]`;
}

/** 그룹 키 해시 — Python tuple 해시/동등성 대응.
 * 누락 키(undefined)와 null은 Python `rec.get(k)`의 None과 마찬가지로 동일 그룹으로 취급된다.
 */
function groupKey(values: readonly unknown[]): string {
  return JSON.stringify(values);
}

/** Python sorted() 동등물 — 키는 ASCII 라벨이라 JS 기본 정렬과 동치. */
function sortedStrings(values: ReadonlySet<string>): string[] {
  return [...values].sort();
}

/** `records` 의 k-익명성을 평가.
 *
 * @param records
 *   각 레코드는 `{label: value}` 형태의 매핑. label 은 AttributeClass 분류와
 *   일치하는 PII 카테고리.
 * @param quasi_keys
 *   준식별자로 간주할 키 목록. `null`/`undefined` 이면 `classify_attribute` 로
 *   QUASI_IDENTIFIER 인 것만 자동 선택 (사전순 정렬).
 * @param threshold
 *   만족 기준 k 값 (기본 5, 가이드라인 권장).
 */
export function k_anonymity(
  records: Iterable<Record<string, unknown>>,
  quasi_keys?: string[] | null,
  threshold = 5,
): KAnonymityReport {
  const record_list: Record<string, unknown>[] = Array.from(records, (r) => ({
    ...r,
  }));
  if (record_list.length === 0) {
    return {
      k: 0,
      group_count: 0,
      smallest_group_size: 0,
      smallest_group_values: [],
      quasi_identifier_keys: [],
      record_count: 0,
      satisfies_threshold: false,
      threshold,
      rationale: ["빈 레코드"],
    };
  }

  let keys: string[] | null = quasi_keys ?? null;
  if (keys === null) {
    const found = new Set<string>();
    for (const rec of record_list) {
      for (const k of Object.keys(rec)) {
        if (classify_attribute(k) === AttributeClass.QUASI_IDENTIFIER) {
          found.add(k);
        }
      }
    }
    keys = sortedStrings(found);
  }

  if (keys.length === 0) {
    const n = record_list.length;
    return {
      k: n,
      group_count: 1,
      smallest_group_size: n,
      smallest_group_values: [],
      quasi_identifier_keys: [],
      record_count: n,
      satisfies_threshold: true,
      threshold,
      rationale: ["준식별자가 없어 k-익명성은 무한대"],
    };
  }

  const quasiKeys = keys;
  const groups = new Map<string, { values: unknown[]; count: number }>();
  for (const rec of record_list) {
    // Python rec.get(k): 누락 키는 undefined (직렬화 시 null — Python None과 동치)
    const values = quasiKeys.map((k) => rec[k]);
    const hash = groupKey(values);
    const g = groups.get(hash);
    if (g !== undefined) {
      g.count += 1;
    } else {
      groups.set(hash, { values, count: 1 });
    }
  }

  // Python min(groups.items(), key=size): 삽입 순서에서 처음 등장한 최소 그룹 선택
  let smallest_values: unknown[] = [];
  let smallest_size = Number.POSITIVE_INFINITY;
  let seen = false;
  for (const g of groups.values()) {
    if (!seen || g.count < smallest_size) {
      smallest_values = g.values;
      smallest_size = g.count;
      seen = true;
    }
  }

  const rationale = [
    `준식별자 ${pyListRepr(quasiKeys)} 기준 ${groups.size}개 그룹`,
    `최소 그룹 크기 k = ${smallest_size}`,
  ];
  if (smallest_size < threshold) {
    rationale.push(
      `k=${smallest_size} < threshold ${threshold} → 일반화 필요 (권장: 연령 구간화, 주소 시·도 단위 등)`,
    );
  } else {
    rationale.push(`k=${smallest_size} ≥ ${threshold} → 만족`);
  }

  return {
    k: smallest_size,
    group_count: groups.size,
    smallest_group_size: smallest_size,
    smallest_group_values: smallest_values,
    quasi_identifier_keys: quasiKeys,
    record_count: record_list.length,
    satisfies_threshold: smallest_size >= threshold,
    threshold,
    rationale,
  };
}

/** Convenience wrapper — auto-detects quasi-identifier keys. */
export function evaluate_dataset(
  records: Iterable<Record<string, unknown>>,
  threshold = 5,
): KAnonymityReport {
  return k_anonymity(records, null, threshold);
}
