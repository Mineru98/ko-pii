/** 건강보험증 번호 (National Health Insurance Card Number) detection.
 *
 * Python 원본: src/ko_pii/patterns/medical_insurance.py — 1:1 포팅 (골드 마스터 기준).
 *
 * 11-digit identifier issued by 국민건강보험공단. Because plain 11-digit numeric
 * runs collide heavily with mobile phone numbers and other identifiers, this
 * detector requires a context keyword (건강보험 / 의료보험 / 보험증) within ~25
 * characters before the candidate — tight enough to exclude paragraph-level
 * mentions, wide enough to allow ":" / linebreak / brief noun between them.
 *
 * Risk: HIGH. While the number itself is not classified as 민감정보, it is a
 * direct entry point to medical-claim history and should be treated as a
 * high-sensitivity personal identifier.
 *
 * Legal basis: 개인정보보호법 제2조; 국민건강보험법 제96조 (자료의 보호).
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "MEDICAL_INSURANCE";
const LEGAL_BASIS = "개인정보보호법 제2조; 국민건강보험법 제96조";
const CATEGORY = "일반개인정보";

const CONTEXT_WINDOW = 25;
const KEYWORD_RE = /건강\s*보험|의료\s*보험|보험증/;
// 건강보험증번호 형식 2종: 순수 11자리, 또는 '증번호' 표기형 N-NNNNNNNNNN
// (1자리 종별 코드 + 하이픈 + 10자리). 키워드 anchor 가 있어 FP 위험은 낮다.
const NUMBER_RE = /(?<![0-9-])((?:[0-9]-[0-9]{10})|(?:[0-9]{11}))(?![0-9-])/g;

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  for (const m of text.matchAll(NUMBER_RE)) {
    if (m.index === undefined) continue;
    const windowStart = Math.max(0, m.index - CONTEXT_WINDOW);
    const prefixWindow = text.slice(windowStart, m.index);
    if (!KEYWORD_RE.test(prefixWindow)) continue;
    // group 1 이 매치 전체를 감싸므로 m.start(1) === m.start(), m.end(1) === m.end()
    const digits = m[1];
    if (digits === undefined) continue;
    out.push(
      makeDetection({
        label: LABEL,
        text: digits,
        start: m.index,
        end: m.index + digits.length,
        riskLevel: RiskLevel.HIGH,
        confidence: 0.9,
        evidence: ["pattern:medical_insurance", "context:keyword_found"],
        legal_basis: LEGAL_BASIS,
        extra: {
          digits,
          category: CATEGORY,
        },
      }),
    );
  }
  return out;
}
