/** 팩스번호 (FAX) 검출 — 전화번호와 분리.
 *
 * Python 원본: src/ko_pii/patterns/fax.py — 1:1 포팅 (골드 마스터 기준).
 *
 * 포맷 자체는 일반전화 (서울/지역/070) 와 동일하지만, "팩스", "FAX", "fax" 등의
 * 키워드가 12자 이내 앞에 있을 때만 FAX 로 분류한다.
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "FAX";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

const PATTERN = /(?<![0-9+])(0[0-9]{1,2})[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{4})(?![0-9])/g;

// FP 위험으로 제거된 키워드:
//   - "F."   : 알파벳 약자 "Grade F." 등과 충돌
//   - "전송" : "데이터 전송" 같은 일반 동사 충돌 (FAX 키워드는 "팩스/FAX"
//             명시 표기가 표준 양식이므로 일반 동사는 굳이 필요 없음)
const KEYWORDS: readonly string[] = ["팩스", "FAX", "fax", "Fax"];

function hasKeywordBefore(text: string, start: number, window = 12): string | null {
  const head = text.slice(Math.max(0, start - window), start);
  for (const kw of KEYWORDS) {
    if (head.includes(kw)) return kw;
  }
  return null;
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    if (m.index === undefined) continue;
    const kw = hasKeywordBefore(text, m.index);
    if (kw === null) continue;
    const raw = m[0];
    const prefix = m[1];
    if (prefix === undefined) continue;
    out.push(
      makeDetection({
        label: LABEL,
        text: raw,
        start: m.index,
        end: m.index + raw.length,
        riskLevel: RiskLevel.LOW,
        confidence: 0.85,
        evidence: ["pattern:fax", `keyword:${kw}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          prefix,
          digits_only: raw.replace(/\D/g, ""),
          category: CATEGORY,
        },
      }),
    );
  }
  return out;
}
