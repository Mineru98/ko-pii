/** EDI 약품코드 (식약처 의약품 표준코드) detection — 식의약 도메인.
 *
 * Python 원본: src/ko_pii/patterns/edi_drug.py — 1:1 포팅 (골드 마스터 기준).
 *
 * 표준 (식약처 / 의약품관리종합센터 KPIS):
 * - **EDI 코드**: 9자리 숫자 = 업체식별코드(4) + 품목코드(5)
 * - **KD 코드**: 13자리 숫자 = 국가식별(3) + 업체(4) + 품목(5) + 검증(1)
 *
 * 검출 정책:
 * - 9자리/13자리 단독 숫자는 FP 위험 큼 → **키워드 anchor 필수**
 *
 * 법적 근거: 약사법 제31조 (의약품 표준코드 관리), 개인정보보호법 제2조.
 *
 * 위험도: LOW (코드 자체는 PII 아니지만 처방·환자정보와 결합 시 가산).
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "EDI_DRUG";
const LEGAL_BASIS = "약사법 제31조; 개인정보보호법 제2조";
const CATEGORY = "참조정보";

// 13자리 KD 코드 우선 (longer-first), 그 다음 9자리 EDI
const PATTERN_13 = /(?<![0-9])([0-9]{13})(?![0-9])/g;

const PATTERN_9 = /(?<![0-9])([0-9]{9})(?![0-9])/g;

// FP 위험으로 제거된 키워드:
//   - "표준코드" : 일반 산업·제품 표준 코드와 충돌 (의약품 한정 단서 부족)
const KEYWORDS: readonly string[] = [
  "EDI",
  "edi",
  "약품코드",
  "의약품코드",
  "주성분코드",
  "KD코드",
  "KD 코드",
  "약가코드",
];

function hasKeywordBefore(text: string, start: number, window = 18): string | null {
  const head = text.slice(Math.max(0, start - window), start);
  for (const kw of KEYWORDS) {
    if (head.includes(kw)) return kw;
  }
  return null;
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Array<[number, number]> = [];

  for (const m of text.matchAll(PATTERN_13)) {
    if (m.index === undefined) continue;
    const kw = hasKeywordBefore(text, m.index);
    if (kw === null) continue;
    const digits = m[1];
    if (digits === undefined) continue;
    // 첫 3자리 국가식별코드는 한국이 880~881 (대한상의 유통물류진흥원)
    if (!digits.startsWith("880") && !digits.startsWith("881") && !digits.startsWith("888")) {
      continue;
    }
    const start = m.index;
    const end = start + digits.length;
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: digits,
        start,
        end,
        riskLevel: RiskLevel.LOW,
        confidence: 0.9,
        evidence: ["pattern:edi_drug", "format:kd_code_13", `keyword:${kw}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          category: CATEGORY,
          format: "kd_code_13",
          country_id: digits.slice(0, 3),
          company_id: digits.slice(3, 7),
          item_id: digits.slice(7, 12),
          check_digit: digits[12],
        },
      }),
    );
  }

  for (const m of text.matchAll(PATTERN_9)) {
    if (m.index === undefined) continue;
    const digits = m[1];
    if (digits === undefined) continue;
    const start = m.index;
    const end = start + digits.length;
    if (seen.some(([s, e]) => start < e && s < end)) continue;
    const kw = hasKeywordBefore(text, start);
    if (kw === null) continue;
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: digits,
        start,
        end,
        riskLevel: RiskLevel.LOW,
        confidence: 0.85,
        evidence: ["pattern:edi_drug", "format:edi_9", `keyword:${kw}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          category: CATEGORY,
          format: "edi_9",
          company_id: digits.slice(0, 4),
          item_id: digits.slice(4, 9),
        },
      }),
    );
  }

  return out;
}
