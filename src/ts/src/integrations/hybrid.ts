/**
 * 두 검출기 (primary + secondary) 결과 병합 로직.
 * Python ko_pii.integrations.hybrid 대응.
 *
 * 병합 모드:
 * - ``UNION``: 양쪽 검출 결과 *합산* (overlap 해소) — 가장 일반적 (Method A)
 * - ``INTERSECTION``: 양쪽 모두 찾은 것만 인정 (높은 신뢰도, Method B 일부)
 * - ``CROSS_VALIDATION``: 일치=BLOCK / 불일치=REVIEW (Method B 완전)
 * - ``ENRICH_PRIMARY``: primary 우선, secondary 가 *놓친 영역* 만 보강 (Method C)
 * - ``FALLBACK_SECONDARY``: primary 의 REVIEW 만 secondary 에 위임 (Method D)
 * - ``ROLE_SPLIT``: **역할 분담** — 퍼지 카테고리(이름·주소·직책 등)는 secondary(ML)가
 *   *교체* 담당, 나머지(결정적 ID 등)는 primary(룰)만 담당 (Method E).
 *
 * Overlap 해소: ``core/overlap.resolveOverlaps`` 단일 구현 사용
 * (위험도 → 확신도 → 길이 순, ``detectAll`` 과 동일 — 늦게 시작하는 고위험 PII 누출 차단).
 */

import { ValueError } from "../core/errors.js";
import { resolveOverlaps } from "../core/overlap.js";
import { type DetectionResult, makeDetection } from "../core/types.js";

export enum MergeMode {
  UNION = "union",
  INTERSECTION = "intersection",
  CROSS_VALIDATION = "cross_validation",
  ENRICH_PRIMARY = "enrich_primary",
  FALLBACK_SECONDARY = "fallback_secondary",
  ROLE_SPLIT = "role_split",
}

/** Python ``MergeMode(value)`` 대응 — 잘못된 값은 같은 메시지의 ValueError. */
export function toMergeMode(value: string): MergeMode {
  if ((Object.values(MergeMode) as string[]).includes(value)) return value as MergeMode;
  throw new ValueError(`'${value}' is not a valid MergeMode`);
}

/**
 * ROLE_SPLIT 기본 위임 라벨 — secondary(ML)가 교체 담당하는 퍼지 카테고리.
 * 룰이 체크섬·패턴으로 강한 결정적 ID(RRN/CARD/PHONE/EMAIL 등)는 primary 유지.
 * (HYBRID_NER.md 의 하이브리드 정의와 동일한 10종.)
 */
export const DEFAULT_ROLE_SPLIT_LABELS: ReadonlySet<string> = new Set([
  "PERSON",
  "ADDRESS",
  "POSITION",
  "EDUCATION",
  "MAJOR",
  "NATIONALITY",
  "AGE",
  "DT_BIRTH",
  "HEIGHT",
  "WEIGHT",
]);

function spansOverlap(a: DetectionResult, b: DetectionResult): boolean {
  return a.start < b.end && b.start < a.end;
}

function sameLabel(a: DetectionResult, b: DetectionResult): boolean {
  // ko-pii 의 카테고리 호환 — 동일 라벨이면 일치
  return a.label === b.label;
}

/** primary 에 secondary 의 신뢰도·증거 추가. */
function enrichWithSecondaryInfo(
  primary: DetectionResult,
  secondary: DetectionResult,
): DetectionResult {
  return makeDetection({
    label: primary.label,
    text: primary.text,
    start: primary.start,
    end: primary.end,
    riskLevel: primary.riskLevel,
    confidence: Math.min(1.0, primary.confidence + 0.05), // 약간 부스트
    evidence: [...primary.evidence, `corroborated_by:secondary(${secondary.label})`],
    legal_basis: primary.legal_basis,
    extra: {
      ...primary.extra,
      secondary_confirmed_by: secondary.evidence,
      secondary_label: secondary.label,
    },
  });
}

/**
 * primary + secondary 검출 결과를 ``mode`` 에 따라 병합.
 *
 * @param roleSplitLabels ``ROLE_SPLIT`` 모드에서 secondary 가 담당할 라벨 집합.
 *   미지정(null) 시 {@link DEFAULT_ROLE_SPLIT_LABELS} (퍼지 10종).
 * @returns overlap 해소되고 정렬된 결과.
 */
export function mergeDetections(
  primary: Iterable<DetectionResult>,
  secondary: Iterable<DetectionResult>,
  mode: MergeMode = MergeMode.UNION,
  roleSplitLabels: Iterable<string> | null = null,
): DetectionResult[] {
  const primaryList = [...primary];
  const secondaryList = [...secondary];

  if (mode === MergeMode.ROLE_SPLIT) {
    // 역할 분담 — 위임 라벨은 secondary 로 *교체*(primary 의 해당 라벨 폐기),
    // 나머지 라벨은 primary 만. 합산(union)이 아니라 교체라는 점이 핵심:
    // 약한 쪽의 FP 가 강한 쪽의 검출을 오염시키지 않는다.
    const delegated: ReadonlySet<string> =
      roleSplitLabels !== null ? new Set(roleSplitLabels) : DEFAULT_ROLE_SPLIT_LABELS;
    const out = primaryList.filter((p) => !delegated.has(p.label));
    out.push(...secondaryList.filter((s) => delegated.has(s.label)));
    return resolveOverlaps(out);
  }

  if (mode === MergeMode.INTERSECTION) {
    // 양쪽 모두 찾은 것만 인정
    const out: DetectionResult[] = [];
    for (const p of primaryList) {
      for (const s of secondaryList) {
        if (spansOverlap(p, s) && sameLabel(p, s)) {
          out.push(enrichWithSecondaryInfo(p, s));
          break;
        }
      }
    }
    return resolveOverlaps(out);
  }

  if (mode === MergeMode.ENRICH_PRIMARY) {
    // primary 우선, secondary 는 primary 가 *놓친* 영역만 추가
    const out = [...primaryList];
    for (const s of secondaryList) {
      const overlapsPrimary = primaryList.some((p) => spansOverlap(s, p));
      if (!overlapsPrimary) {
        out.push(s);
      } else {
        // primary 가 잡은 같은 spans 에 secondary corroboration 추가
        for (let i = 0; i < out.length; i++) {
          const p = out[i] as DetectionResult;
          if (spansOverlap(p, s) && sameLabel(p, s)) {
            out[i] = enrichWithSecondaryInfo(p, s);
            break;
          }
        }
      }
    }
    return resolveOverlaps(out);
  }

  if (mode === MergeMode.CROSS_VALIDATION) {
    // 일치 = high confidence / 불일치 = secondary 결과는 REVIEW 카테고리로
    // (이 모드는 정책 결정을 Anonymizer 에서 함 — 여기서는 결과만 합산)
    const out = [...primaryList];
    for (const s of secondaryList) {
      let corroborated = false;
      for (let i = 0; i < out.length; i++) {
        const p = out[i] as DetectionResult;
        if (spansOverlap(p, s) && sameLabel(p, s)) {
          out[i] = enrichWithSecondaryInfo(p, s);
          corroborated = true;
          break;
        }
      }
      if (!corroborated) {
        // secondary 단독 검출 — 신뢰도 낮춤 (cross-val 미통과)
        out.push(
          makeDetection({
            label: s.label,
            text: s.text,
            start: s.start,
            end: s.end,
            riskLevel: s.riskLevel,
            confidence: s.confidence * 0.7, // cross-val 미통과 페널티
            evidence: [...s.evidence, "uncorroborated:primary_missed"],
            legal_basis: s.legal_basis,
            extra: { ...s.extra, cross_val: "secondary_only" },
          }),
        );
      }
    }
    return resolveOverlaps(out);
  }

  if (mode === MergeMode.FALLBACK_SECONDARY) {
    // primary 결과만 반환 — secondary 는 *호출 시점에서* REVIEW 만
    // 다시 평가하도록 사용 (Anonymizer 가 처리)
    return resolveOverlaps(primaryList);
  }

  // UNION (기본)
  return resolveOverlaps([...primaryList, ...secondaryList]);
}
