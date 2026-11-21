/**
 * 여권번호 (Korean Passport Number) detection.
 *
 * Nine characters: prefix + eight digits, or prefix + three digits + a letter
 * and four digits (MOFA example: M123A4567). PP/PM/PS are document type codes,
 * not two-letter passport-number prefixes. This is format detection, not a
 * checksum, issuance or identity check. Historical G/T numeric candidates are
 * retained for compatibility; their presence does not prove a valid document.
 *
 * Sources:
 * https://passport.go.kr/home/kor/contents.do?menuPos=60
 * https://learn.microsoft.com/en-us/purview/sit-defn-south-korea-passport-number
 *
 * Legal basis: 개인정보보호법 시행령 제19조 (고유식별정보 — 여권번호).
 */

import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "PASSPORT";
const LEGAL_BASIS = "개인정보보호법 시행령 제19조";
const CATEGORY = "고유식별정보";

const MODERN_FORMAT = "[MSROD][0-9]{3}[A-Z][0-9]{4}";
const PATTERN = new RegExp(
  `(?<![A-Za-z0-9])(?:[MSGODRT][0-9]{8}|${MODERN_FORMAT})(?![A-Za-z0-9])`,
  "g",
);

const PASSPORT_KIND: Readonly<Record<string, string>> = {
  M: "general_multiple",
  S: "general_single",
  O: "official",
  D: "diplomatic",
  R: "resident",
  T: "travel_cert",
};

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    const full = m[0] as string;
    const prefix = full.slice(0, 1);
    const number = full.slice(1);
    // Reject all-zero serial (placeholder)
    if (number === "00000000") {
      continue;
    }
    const kind = PASSPORT_KIND[prefix] ?? "unknown";
    results.push(
      makeDetection({
        label: LABEL,
        text: full,
        start: m.index,
        end: m.index + full.length,
        riskLevel: RiskLevel.CRITICAL,
        confidence: 0.9,
        evidence: ["pattern:passport", `prefix:${prefix}`, `kind:${kind}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          prefix,
          number,
          kind,
          category: CATEGORY,
        },
      }),
    );
  }
  return results;
}
