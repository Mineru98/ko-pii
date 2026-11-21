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
import { isValidChecksum as isValidFrnChecksum } from "../checksum/frnChecksum.js";
import { isValidChecksum as isValidRrnChecksum } from "../checksum/rrnChecksum.js";
import { PY_S, PY_S_CHARS } from "../core/strUtils.js";
import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "CORP_REG";
const LEGAL_BASIS = "상법 제40조; 법인등기규칙";
const CATEGORY = "법인식별정보";

const PATTERN = new RegExp(
  `(?<![0-9])([0-9]{6})(?:${PY_S}?[-./]${PY_S}?|[-./${PY_S_CHARS}]{0,2})([0-9]{7})(?![0-9])`,
  "gu",
);

/** Python datetime.date(y, m, d) 유효성 (proleptic Gregorian, 1..9999년). */
function isValidDate(year: number, month: number, day: number): boolean {
  if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1) return false;
  let daysInMonth = 31;
  if (month === 4 || month === 6 || month === 9 || month === 11) {
    daysInMonth = 30;
  } else if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    daysInMonth = leap ? 29 : 28;
  }
  return day <= daysInMonth;
}

/** 개인 식별번호로 양보하려면 그럴듯한 완전 생년월일(미래 아님)이어야 한다. */
function isValidDatePrefix(yymmdd: string, genderDigit: string): boolean {
  const century = "90".includes(genderDigit) ? 1800 : "1256".includes(genderDigit) ? 1900 : 2000;
  const year = century + Number(yymmdd.slice(0, 2));
  const month = Number(yymmdd.slice(2, 4));
  const day = Number(yymmdd.slice(4, 6));
  if (!isValidDate(year, month, day)) return false;
  const now = new Date();
  const today = now.getFullYear() * 10000 + (now.getMonth() + 1) * 100 + now.getDate();
  return year * 10000 + month * 100 + day <= today;
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
    const gender = back.charAt(0);
    const personalChecksum = "5678".includes(gender) ? isValidFrnChecksum : isValidRrnChecksum;
    if (personalChecksum(digits) && isValidDatePrefix(front, gender)) {
      // An RRN/FRN-shaped candidate also passes the corporate checksum;
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
