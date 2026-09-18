/**
 * 외국인등록번호 (Foreign Registration Number) detection.
 *
 * Format is identical to RRN (13 digits, YYMMDD-SXXXXXC, optional hyphen between
 * 6th and 7th digit). The differentiator is the 7th (century/gender) digit,
 * which for FRN is restricted to:
 *   5, 6 → 1900s foreigner (male, female)
 *   7, 8 → 2000s foreigner
 *
 * Checksum: same weighted-sum algorithm as RRN; post-2020 randomization applies.
 *
 * Legal basis: 개인정보보호법 시행령 제19조 (고유식별정보의 범위 — 외국인등록번호),
 * 출입국관리법 제31조.
 */
import { isValidChecksum } from "../checksum/rrnChecksum.js";
import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "FRN";
const LEGAL_BASIS = "개인정보보호법 시행령 제19조; 출입국관리법 제31조";
const CATEGORY = "고유식별정보";

const PATTERN = /(?<![0-9])([0-9]{6})(?:\s?[-./]\s?|[-./\s]{0,2})([0-9]{7})(?![0-9])/g;

const CENTURY_BY_GENDER_DIGIT = new Map<number, number>([
  [5, 1900],
  [6, 1900],
  [7, 2000],
  [8, 2000],
]);

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

interface BirthDate {
  iso: string;
}

/** Python _decode_birth_date 대응 — 유효 날짜 아니면 null. */
function decodeBirthDate(yymmdd: string, genderDigit: number): BirthDate | null {
  const centuryBase = CENTURY_BY_GENDER_DIGIT.get(genderDigit);
  if (centuryBase === undefined) return null;
  const year = centuryBase + Number(yymmdd.slice(0, 2));
  const month = Number(yymmdd.slice(2, 4));
  const day = Number(yymmdd.slice(4, 6));
  if (!isValidDate(year, month, day)) return null;
  const iso =
    `${String(year).padStart(4, "0")}-` +
    `${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
  return { iso };
}

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    const full = m[0] as string;
    const front = m[1] as string;
    const back = m[2] as string;
    const genderDigit = Number(back.charAt(0));
    const birth = decodeBirthDate(front, genderDigit);
    if (birth === null) continue;

    const digitsOnly = front + back;
    const checksumOk = isValidChecksum(digitsOnly);

    const evidence = ["pattern:frn", `date_valid:${birth.iso}`];
    let confidence: number;
    if (checksumOk) {
      evidence.push("checksum:valid");
      confidence = 1.0;
    } else {
      evidence.push("checksum:invalid_or_post_2020");
      confidence = 0.7;
    }

    results.push(
      makeDetection({
        label: LABEL,
        text: full,
        start: m.index,
        end: m.index + full.length,
        riskLevel: RiskLevel.CRITICAL,
        confidence,
        evidence,
        legal_basis: LEGAL_BASIS,
        extra: {
          front,
          back,
          birth_date: birth.iso,
          gender_digit: genderDigit,
          checksum_valid: checksumOk,
          category: CATEGORY,
        },
      }),
    );
  }
  return results;
}
