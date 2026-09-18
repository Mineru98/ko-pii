/**
 * 여권번호 (Korean Passport Number) detection.
 *
 * Format: 1-2 uppercase letter prefix + 8 digits.
 *
 * Prefix codes (외교부 「여권법」 + 2024.12.16 국제표준 개정):
 *
 * 단일 알파벳 (구 체계 + 일부 현행):
 *   M  - 일반 복수 여권 (Multiple)
 *   S  - 일반 단수 여권 (Single)
 *   G  - 일반 여권 (general, 신형)
 *   O  - 관용 여권 (Official)
 *   D  - 외교관 여권 (Diplomatic)
 *   R  - 거주 여권 (Resident)
 *   T  - 여행증명서 (Travel certificate, 임시)
 *
 * 두 글자 (외교부 신형):
 *   PP - 일반 여권 (2024.12.16~ 통일, 단복수 통합)
 *   PM - 일반 복수 여권 (구 PM 표기)
 *   PS - 일반 단수 여권 (구 PS 표기)
 *   PO - 관용 여권
 *   PD - 외교관 여권
 *   PR - 거주 여권
 *   PT - 여행증명서
 *
 * 체크섬은 공개되지 않아 패턴 + prefix 화이트리스트 + 8자리 검증.
 *
 * Legal basis: 개인정보보호법 시행령 제19조 (고유식별정보 — 여권번호).
 */

import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "PASSPORT";
const LEGAL_BASIS = "개인정보보호법 시행령 제19조";
const CATEGORY = "고유식별정보";

// 정확한 우선순위: 2자 prefix 먼저 매칭 → 1자 prefix
const PATTERN = /(?<![A-Za-z0-9])(PP|PM|PS|PO|PD|PR|PT|M|S|G|O|D|R|T)([0-9]{8})(?![A-Za-z0-9])/g;

const PASSPORT_KIND: Readonly<Record<string, string>> = {
  M: "general_multiple",
  PM: "general_multiple",
  PP: "general",
  S: "general_single",
  PS: "general_single",
  G: "general",
  O: "official",
  PO: "official",
  D: "diplomatic",
  PD: "diplomatic",
  R: "resident",
  PR: "resident",
  T: "travel_cert",
  PT: "travel_cert",
};

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    const full = m[0] as string;
    const prefix = m[1] as string;
    const number = m[2] as string;
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
