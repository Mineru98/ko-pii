/** URL detection (http/https).
 *
 * Python 원본: src/ko_pii/patterns/url.py — 1:1 포팅 (골드 마스터 기준).
 *
 * URL 자체는 대개 PII 가 아니지만 INFO/LOW 로 내보내 후속 규칙이 path/query 의
 * 매식 식별자(이메일, ID)를 훑을 수 있게 한다.
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "URL";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

// Python \b 는 유니코드 단어 경계 — '한https://' 는 '한'이 단어 문자라 매칭
// 되지 않는다. JS \b 는 ASCII 전용이므로 동등한 유니코드 lookbehind 로 대체.
const PATTERN = /(?<![\p{L}\p{N}_])https?:\/\/[^\s<>"'`)\]}]+/giu;

function rstripPunct(s: string): string {
  // Python s.rstrip(".,;:!?") 대응
  return s.replace(/[.,;:!?]+$/, "");
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    if (m.index === undefined) continue;
    const url = rstripPunct(m[0]);
    out.push(
      makeDetection({
        label: LABEL,
        text: url,
        start: m.index,
        end: m.index + url.length,
        riskLevel: RiskLevel.INFO,
        confidence: 0.9,
        evidence: ["pattern:url"],
        legal_basis: LEGAL_BASIS,
        extra: {
          url,
          scheme: url.split("://", 1)[0]?.toLowerCase() ?? "",
          category: CATEGORY,
        },
      }),
    );
  }
  return out;
}
