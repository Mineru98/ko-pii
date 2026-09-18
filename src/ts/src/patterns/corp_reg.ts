/**
 * 법인등록번호 (Corporation Registration Number) detection.
 *
 * 13-digit format visually identical to RRN (NNNNNN-NNNNNNN), but the first 6
 * digits are a registry-office + registration code, not a date.
 *
 * Disambiguation from RRN/FRN:
 *   - This module requires the 법인 checksum to pass (Luhn-like, weights 1-2).
 *   - If the candidate ALSO passes the RRN/FRN checksum AND its first 6 digits
 *     form a valid calendar date, we treat it as an RRN/FRN and yield nothing
 *     here. The RRN/FRN modules will claim it.
 *   - Otherwise (e.g., 한전 191211-0006637: RRN checksum fails) we emit as
 *     CORP_REG.
 *
 * Risk level: MEDIUM. 법인등록번호 자체는 일반적으로 개인정보로 분류되지 않지만,
 * 공공기관·법인의 식별 정보로서 일정 수준의 처리 통제가 권고됨.
 */

import { isValidChecksum } from "../checksum/corpRegChecksum.js";
import { isValidChecksum as isValidRrnChecksum } from "../checksum/rrnChecksum.js";
import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "CORP_REG";
const LEGAL_BASIS = "상법 제40조; 법인등기규칙";
const CATEGORY = "법인식별정보";

const PATTERN = /(?<![0-9])([0-9]{6})(?:\s?[-./]\s?|[-./\s]{0,2})([0-9]{7})(?![0-9])/g;

/** Return True if YYMMDD could form a real calendar date in any century. */
function isValidDatePrefix(yymmdd: string): boolean {
  const mm = Number(yymmdd.slice(2, 4));
  const dd = Number(yymmdd.slice(4, 6));
  if (!(mm >= 1 && mm <= 12)) {
    return false;
  }
  if (!(dd >= 1 && dd <= 31)) {
    return false;
  }
  // date(2000, mm, dd) — 2000 is a leap year, so Feb 29 is valid
  let daysInMonth = 31;
  if (mm === 4 || mm === 6 || mm === 9 || mm === 11) {
    daysInMonth = 30;
  } else if (mm === 2) {
    daysInMonth = 29;
  }
  return dd <= daysInMonth;
}

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    const full = m[0] as string;
    const front = m[1] as string;
    const back = m[2] as string;
    const digits = front + back;
    // GS1 Bookland(ISBN/ISSN, 978/979 시작)의 무구분자 13자리는 도서 바코드이지
    // 법인등록번호가 아니다 → 제외(법인번호는 978/979 로 시작하지 않아 recall 무해).
    if ((front.slice(0, 3) === "978" || front.slice(0, 3) === "979") && full === digits) {
      continue;
    }
    if (!isValidChecksum(digits)) {
      continue;
    }
    if (isValidRrnChecksum(digits) && isValidDatePrefix(front)) {
      // An actual RRN/FRN coincidentally passes the 법인 checksum;
      // let the RRN/FRN detector claim it.
      continue;
    }
    results.push(
      makeDetection({
        label: LABEL,
        text: full,
        start: m.index,
        end: m.index + full.length,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:corp_reg", "checksum:valid"],
        legal_basis: LEGAL_BASIS,
        extra: {
          front,
          back,
          digits,
          category: CATEGORY,
        },
      }),
    );
  }
  return results;
}
