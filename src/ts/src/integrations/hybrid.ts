/**
 * 두 검출기 (primary + secondary) 결과 병합 로직.
 * Python ko_pii.integrations.hybrid 대응.
 *
 * 병합 모드:
 * - ``UNION``: 양쪽 검출 결과 *합산* (overlap 해소) — 가장 일반적 (Method A)
 * - ``INTERSECTION``: 양쪽 모두 찾은 것만 인정 (높은 신뢰도, Method B 일부)
 * - ``CROSS_VALIDATION``: 일치 시 보강, secondary 단독 결과는 신뢰도 감점 후 모드 정책 적용
 * - ``ENRICH_PRIMARY``: primary 우선, secondary 가 *놓친 영역* 만 보강 (Method C)
 * - ``FALLBACK_SECONDARY``: primary 의 REVIEW 만 secondary 에 위임 (Method D)
 * - ``ROLE_SPLIT``: **역할 분담** — 퍼지 카테고리(이름·주소·직책 등)는 secondary(ML)가
 *   *교체* 담당, 나머지(결정적 ID 등)는 primary(룰)만 담당 (Method E).
 *
 * Overlap 해소: ``core/overlap.resolveOverlaps`` 단일 구현 사용
 * (위험도 → 확신도 → 길이 순; policy 가 있으면 그 전에 BLOCK 후보를 우선).
 */

import { ValueError } from "../core/errors.js";
import { Action, type ModePolicy, ProcessingMode, policyFor } from "../core/modes.js";
import { resolveOverlaps } from "../core/overlap.js";
import { pySpanLength } from "../core/strUtils.js";
import type { OverlapTrace } from "../core/trace.js";
import { type DetectionResult, makeDetection } from "../core/types.js";
import { validateLabelFilter } from "../labels.js";

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
  if (typeof value === "string" && (Object.values(MergeMode) as string[]).includes(value)) {
    return value as MergeMode;
  }
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

/**
 * Python ``validate_merge_config`` 대응 — 잘못된 모드·라벨은 단일 메시지 ValueError.
 * @returns ``[mode, 검증된 라벨 집합 | null]``.
 */
export function validateMergeConfig(
  mode: string,
  labels: Iterable<string> | null | undefined,
): [MergeMode, ReadonlySet<string> | null] {
  let selected: MergeMode;
  let validated: string[] | null;
  try {
    selected = toMergeMode(mode);
    validated = validateLabelFilter(labels, "role_split_labels");
  } catch (e) {
    if (e instanceof ValueError || e instanceof TypeError) {
      throw new ValueError(
        "invalid merge_mode or role_split_labels; use registered modes and labels",
      );
    }
    throw e;
  }
  return [selected, validated !== null ? new Set(validated) : null];
}

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
    ruleId: primary.ruleId,
    normalized: primary.normalized,
    subruleId: primary.subruleId,
  });
}

/** Python 정렬 키 비교 — 문자열은 코드 포인트 순 (라벨은 ASCII). */
function cmpStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Python ``max(iterable, key=...)`` — 동률이면 첫 원소. */
function maxBy<T>(items: readonly T[], key: (t: T) => number): T | null {
  let best: T | null = null;
  for (const it of items) if (best === null || key(it) > key(best)) best = it;
  return best;
}

/** Python ``_merge_candidates`` 의 keyword 인자. */
export interface MergeCandidatesOptions {
  /**
   * 차단 우선 overlap 해소용 변환 정책. FALLBACK_SECONDARY 는 생략 시 STRICT 를 쓰며,
   * 같은 라벨 secondary 가 span 을 완전히 덮는 REVIEW primary 의 확신도만 올린다.
   */
  policy?: ModePolicy | null;
}

/**
 * 병합 자격·확신도 변경을 overlap 선택 *전에* 적용 (Python ``_merge_candidates``).
 *
 * @param roleSplitLabels ``ROLE_SPLIT`` 모드에서 secondary 가 담당할 라벨 집합.
 *   미지정(null) 시 {@link DEFAULT_ROLE_SPLIT_LABELS} (퍼지 10종).
 * @returns 자격 있는 후보 — overlap 은 남아 있다.
 */
export function mergeCandidates(
  primary: Iterable<DetectionResult>,
  secondary: Iterable<DetectionResult>,
  mode: MergeMode | string = MergeMode.UNION,
  roleSplitLabels: Iterable<string> | null = null,
  options: MergeCandidatesOptions = {},
): DetectionResult[] {
  const [selected, validatedLabels] = validateMergeConfig(mode, roleSplitLabels);
  const primaryList = [...primary];
  const secondaryList = [...secondary];

  if (selected === MergeMode.ROLE_SPLIT) {
    // 역할 분담 — 위임 라벨은 secondary 로 *교체*(primary 의 해당 라벨 폐기),
    // 나머지 라벨은 primary 만. 합산(union)이 아니라 교체라는 점이 핵심:
    // 약한 쪽의 FP 가 강한 쪽의 검출을 오염시키지 않는다.
    const delegated = validatedLabels ?? DEFAULT_ROLE_SPLIT_LABELS;
    const out = primaryList.filter((p) => !delegated.has(p.label));
    out.push(...secondaryList.filter((s) => delegated.has(s.label)));
    return out;
  }

  if (selected === MergeMode.INTERSECTION) {
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
    return out;
  }

  if (selected === MergeMode.ENRICH_PRIMARY) {
    // 원래 primary 를 한 번씩만 보강 — 이미 보강된 사본을 다시 보강하지 않는다.
    const ordered = [...secondaryList].sort(
      (a, b) =>
        b.confidence - a.confidence ||
        b.riskLevel - a.riskLevel ||
        pySpanLength(b) - pySpanLength(a) ||
        a.start - b.start ||
        a.end - b.end ||
        cmpStr(a.label, b.label),
    );
    const out: DetectionResult[] = [];
    for (const p of primaryList) {
      const best = ordered.find((s) => spansOverlap(p, s) && sameLabel(p, s));
      out.push(best !== undefined ? enrichWithSecondaryInfo(p, best) : p);
    }
    out.push(...ordered.filter((s) => !primaryList.some((p) => spansOverlap(s, p))));
    return out;
  }

  if (selected === MergeMode.CROSS_VALIDATION) {
    // 감점은 action override 가 아니다: STRICT 는 1.0 * 0.7 도 여전히 차단할 수 있다.
    // secondary 하나는 각 primary 를 한 번만 확인하며, 추가된 secondary 후보가
    // primary 증거로 가장해서는 안 된다.
    const orderedSecondary = [...secondaryList].sort(
      (a, b) =>
        b.riskLevel - a.riskLevel ||
        b.confidence - a.confidence ||
        pySpanLength(b) - pySpanLength(a) ||
        a.start - b.start ||
        a.end - b.end ||
        cmpStr(a.label, b.label),
    );
    const out: DetectionResult[] = [];
    for (const p of primaryList) {
      const best = maxBy(
        orderedSecondary.filter((s) => spansOverlap(p, s) && sameLabel(p, s)),
        (s) => s.confidence,
      );
      out.push(best !== null ? enrichWithSecondaryInfo(p, best) : p);
    }
    for (const s of orderedSecondary) {
      if (!primaryList.some((p) => spansOverlap(p, s) && sameLabel(p, s))) {
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
            ruleId: s.ruleId,
            normalized: s.normalized,
            subruleId: s.subruleId,
          }),
        );
      }
    }
    return out;
  }

  if (selected === MergeMode.FALLBACK_SECONDARY) {
    const selectedPolicy = options.policy ?? policyFor(ProcessingMode.STRICT);
    const out: DetectionResult[] = [];
    for (let p of primaryList) {
      if (selectedPolicy.decide(p.riskLevel, p.confidence) === Action.REVIEW) {
        const primaryRef = p;
        const confirmations = secondaryList.filter(
          (s) =>
            s.label === primaryRef.label &&
            s.start <= primaryRef.start &&
            s.end >= primaryRef.end &&
            s.confidence > primaryRef.confidence,
        );
        const best = maxBy(confirmations, (s) => s.confidence);
        if (best !== null) {
          // primary span 유지 — 부분 일치는 값 전체를 보증할 수 없고
          // secondary 단독 추정은 무시한다.
          p = { ...enrichWithSecondaryInfo(p, best), confidence: best.confidence };
        }
      }
      out.push(p);
    }
    return out;
  }

  // UNION (기본)
  return [...primaryList, ...secondaryList];
}

/** {@link mergeDetections} 의 keyword 인자. */
export interface MergeDetectionsOptions extends MergeCandidatesOptions {
  trace?: OverlapTrace | null;
}

/**
 * 모드별 자격 적용 후 정렬된 서로소 span 반환 (Python ``merge_detections``).
 *
 * @param roleSplitLabels ``ROLE_SPLIT`` 모드에서 secondary 가 담당할 라벨 집합.
 *   미지정(null) 시 {@link DEFAULT_ROLE_SPLIT_LABELS} (퍼지 10종).
 */
export function mergeDetections(
  primary: Iterable<DetectionResult>,
  secondary: Iterable<DetectionResult>,
  mode: MergeMode | string = MergeMode.UNION,
  roleSplitLabels: Iterable<string> | null = null,
  options: MergeDetectionsOptions = {},
): DetectionResult[] {
  return resolveOverlaps(
    mergeCandidates(primary, secondary, mode, roleSplitLabels, { policy: options.policy ?? null }),
    { trace: options.trace ?? null, stage: "hybrid", policy: options.policy ?? null },
  );
}
