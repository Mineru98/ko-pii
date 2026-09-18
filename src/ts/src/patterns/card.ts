/** 신용카드 / 체크카드 번호 (Card Number) detection.
 *
 * Python 원본: src/ko_pii/patterns/card.py — 1:1 포팅 (골드 마스터 기준).
 *
 * Luhn (mod-10) 체크섬 통과 + IIN/BIN 첫 자리 화이트리스트 (ISO/IEC 7812).
 * 거부: 0, 1, 7, 8 — 현행 카드 브랜드에 할당되지 않음.
 */

import { isValid as isValidLuhn } from "../checksum/luhn.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "CARD";
const LEGAL_BASIS = "개인정보보호법 제2조; 여신전문금융업법";
const CATEGORY = "일반개인정보";

const VALID_BIN_FIRST_DIGITS: ReadonlySet<string> = new Set(["2", "3", "4", "5", "6", "9"]);

const PATTERN =
  /(?<![0-9])(?:[0-9]{4}[-. /]\s?[0-9]{4}[-. /]\s?[0-9]{4}[-. /]\s?[0-9]{1,7}|[0-9]{13,19})(?![0-9])/g;

const BRAND_BY_FIRST_DIGIT: Record<string, string> = {
  "3": "amex_or_jcb_or_diners",
  "4": "visa",
  "5": "mastercard",
  "6": "discover_or_unionpay",
  "9": "korea_domestic",
  "2": "mastercard_new_or_misc",
};

function brandFor(firstDigit: string): string {
  return BRAND_BY_FIRST_DIGIT[firstDigit] ?? "unknown";
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    if (m.index === undefined) continue;
    const raw = m[0];
    const digits = raw.replace(/\D/g, "");
    if (!(digits.length >= 13 && digits.length <= 19)) continue;
    const first = digits[0];
    if (first === undefined || !VALID_BIN_FIRST_DIGITS.has(first)) continue;
    // 길이-브랜드 일관성: 13자리는 구형 Visa(4), 15자리는 Amex(34/37)만 허용 —
    // EAN-13 바코드/15자리 IMEI 의 Luhn-우연 통과 FP 를 막는다.
    if (digits.length === 13 && first !== "4") continue;
    if (digits.length === 15 && !["34", "37"].includes(digits.slice(0, 2))) continue;
    if (!isValidLuhn(digits)) continue;
    out.push(
      makeDetection({
        label: LABEL,
        text: raw,
        start: m.index,
        end: m.index + raw.length,
        riskLevel: RiskLevel.HIGH,
        confidence: 1.0,
        evidence: ["pattern:card", "checksum:luhn_valid", `brand_hint:${brandFor(first)}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          digits,
          length: digits.length,
          brand_hint: brandFor(first),
          category: CATEGORY,
        },
      }),
    );
  }
  return out;
}
