/**
 * Irreversible redaction (masking) mode.
 *
 * 원본 정보는 복원 불가하며, 카테고리 라벨 ``[성명]`` 또는 ``***`` 류 마스크로
 * 치환된다. 정보 분석/저장 대상이 *아닌* 표시·공유 용도 사용.
 *
 * Legal basis: 개인정보보호법 비식별 조치 가이드라인 — 가명처리(가역) 와 비식별
 * (비가역) 구분.
 */
import type { DetectionResult } from "../core/types.js";
import { applySubstitutions } from "./apply.js";

const LABEL_TO_HANGUL = new Map<string, string>([
  ["RRN", "주민등록번호"],
  ["FRN", "외국인등록번호"],
  ["BUSINESS_REG", "사업자등록번호"],
  ["CORP_REG", "법인등록번호"],
  ["DRIVER_LICENSE", "운전면허번호"],
  ["PASSPORT", "여권번호"],
  ["CARD", "카드번호"],
  ["MEDICAL_INSURANCE", "건강보험증번호"],
  ["PHONE", "전화번호"],
  ["FAX", "팩스번호"],
  ["EMAIL", "이메일"],
  ["POSTAL_CODE", "우편번호"],
  ["IP", "IP"],
  ["VEHICLE", "차량번호"],
  ["URL", "URL"],
  ["ADDRESS", "주소"],
  ["NATIONALITY", "국적"],
  ["ACCOUNT", "계좌번호"],
  ["PERSON", "성명"],
  ["DOC_ID", "문서번호"],
  ["PETITION_ID", "민원번호"],
  ["EMPLOYEE_ID", "사번"],
  ["PNU", "토지번호"],
  ["PRESCRIPTION_ID", "처방번호"],
  ["EDI_DRUG", "약품코드"],
  ["DT_BIRTH", "생년월일"],
  ["EDUCATION", "학력"],
  ["MAJOR", "전공"],
  ["POSITION", "직책"],
  ["AGE", "나이"],
  ["HEIGHT", "신장"],
  ["WEIGHT", "체중"],
  ["COURT_CASE", "사건번호"],
]);

/** 라벨을 한국어 카테고리명으로 바꾼다. 알 수 없는 라벨은 그대로 반환. */
export function labelToHangul(label: string): string {
  return LABEL_TO_HANGUL.get(label) ?? label;
}

/**
 * Replace each detection span with an irreversible mask.
 *
 * ``style``:
 *   - ``"label"``  — ``[성명]``, ``[주민등록번호]`` (default)
 *   - ``"asterisk"`` — repeat ``maskChar`` * len(match)
 *   - ``"fixed"``  — fixed ``***`` regardless of length
 */
export function redact(
  text: string,
  detections: Iterable<DetectionResult>,
  style = "label",
  maskChar = "*",
): string {
  if (style !== "label" && style !== "asterisk" && style !== "fixed") {
    throw new Error(`Unknown redact style: ${style}`);
  }

  const replace = (d: DetectionResult): string => {
    if (style === "label") return `[${labelToHangul(d.label)}]`;
    if (style === "asterisk") return maskChar.repeat(Math.max(1, d.end - d.start));
    return "***";
  };

  return applySubstitutions(text, detections, replace);
}
