/**
 * 확장(보조 검출기 등) 결과를 치환에 쓰기 전에 원문 결속을 검증 — Python ko_pii.core.validation 대응.
 */
import { ALL_LABELS } from "../labels.js";
import { ValueError } from "./errors.js";
import { type DetectionResult, makeDetection, RiskLevel } from "./types.js";

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);
const RISK_VALUES: ReadonlySet<unknown> = new Set(
  Object.values(RiskLevel).filter((v) => typeof v === "number"),
);

export interface ValidatedDetectionOptions {
  /** false 면 label/text/span/risk/confidence 만 남긴 새 레코드를 만든다. 기본 true. */
  preserveMetadata?: boolean;
  /** true 면 레지스트리 밖 라벨도 허용(빈 값·`<>\r\n` 포함 라벨은 거부). 기본 false. */
  allowCustomLabels?: boolean;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** 분리된 레코드를 반환하거나 값 없는 오류를 던진다 — 잘못된 span 을 고쳐 주지 않는다.
 *
 * 오프셋은 UTF-16 코드 유닛 기준 (TS 포트 정책).
 */
export function validatedDetection(
  result: unknown,
  text: string,
  options: ValidatedDetectionOptions = {},
): DetectionResult {
  const preserveMetadata = options.preserveMetadata ?? true;
  const allowCustomLabels = options.allowCustomLabels ?? false;
  if (!isPlainRecord(result)) {
    throw new ValueError("detector must return DetectionResult objects");
  }
  const r = result as Partial<DetectionResult> & Record<string, unknown>;
  if (allowCustomLabels) {
    if (typeof r.label !== "string" || !r.label || /[<>\r\n]/.test(r.label)) {
      throw new ValueError("detector returned an invalid label");
    }
  } else if (typeof r.label !== "string" || !LABEL_SET.has(r.label)) {
    throw new ValueError("detector must use an existing ko-pii label");
  }
  const { start, end } = r;
  if (
    typeof start !== "number" ||
    typeof end !== "number" ||
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    !(start >= 0 && start < end && end <= text.length)
  ) {
    throw new ValueError("detector returned an invalid source span");
  }
  if (typeof r.text !== "string" || r.text !== text.slice(start, end)) {
    throw new ValueError("detector text must equal the source slice");
  }
  if (!RISK_VALUES.has(r.riskLevel)) {
    throw new ValueError("detector risk_level must be RiskLevel");
  }
  const confidence = r.confidence;
  if (
    typeof confidence !== "number" ||
    !Number.isFinite(confidence) ||
    !(confidence >= 0 && confidence <= 1)
  ) {
    throw new ValueError("detector confidence must be finite and between 0 and 1");
  }
  const riskLevel = r.riskLevel as RiskLevel;
  if (!preserveMetadata) {
    return makeDetection({ label: r.label, text: r.text, start, end, riskLevel, confidence });
  }
  const optionalString = (v: unknown): boolean =>
    v === undefined || v === null || typeof v === "string";
  if (
    !Array.isArray(r.evidence) ||
    r.evidence.some((s) => typeof s !== "string") ||
    !isPlainRecord(r.extra) ||
    (r.normalized !== undefined && typeof r.normalized !== "boolean") ||
    !optionalString(r.legal_basis) ||
    !optionalString(r.ruleId) ||
    !optionalString(r.subruleId)
  ) {
    throw new ValueError("detector returned invalid metadata");
  }
  // 생성기가 같은 레코드를 재사용·변경할 수 있으므로 매번 스냅샷한다.
  return {
    ...(r as DetectionResult),
    confidence,
    evidence: [...r.evidence],
    extra: { ...r.extra },
  };
}
