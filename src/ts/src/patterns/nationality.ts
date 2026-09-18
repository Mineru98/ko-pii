/** 국적/국가명 (Nationality) detection — Python ko_pii.patterns.nationality 대응.
 *
 * "거주지국 대한민국", "국적 미국", "한국인" 등 국가명은 주소가 아니라 국적 정보.
 * ADDRESS 카테고리와 혼동 방지를 위해 별도 검출기로 분리.
 *
 * Legal basis: 개인정보보호법 제2조 (국적은 준식별자로 분류 가능).
 */
import { stripTrailingParticle } from "../context/particles.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";
import { isCountry } from "../dictionaries/index.js";

const LABEL = "NATIONALITY";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "준식별자";

// 단독 토큰 매칭 — 앞뒤 한글/영숫자 거부
const _PATTERN_TOKEN = /(?<![가-힣A-Za-z0-9])([가-힣]{2,8})(?![가-힣A-Za-z0-9])/g;

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];

  for (const m of text.matchAll(_PATTERN_TOKEN)) {
    // biome-ignore lint/style/noNonNullAssertion: 정규식 그룹 보장 접근
    const mStart = m.index!;
    // biome-ignore lint/style/noNonNullAssertion: 정규식 그룹 보장 접근
    const mEnd = mStart + m[0]!.length;
    // biome-ignore lint/style/noNonNullAssertion: 정규식 그룹 보장 접근
    const rawToken = m[1]!;
    const [token0, particle] = stripTrailingParticle(rawToken);
    if (token0.length < 2) {
      continue;
    }

    let token = token0;
    // "한국인/미국인" → "한국/미국"
    let peopleSuffix: string | null = null;
    if (token.length >= 3 && token.endsWith("인") && isCountry(token.slice(0, -1))) {
      token = token.slice(0, -1);
      peopleSuffix = "인";
    }

    if (!isCountry(token)) {
      continue;
    }

    const actualEnd =
      mEnd - (particle !== null ? particle.length : 0) - (peopleSuffix !== null ? 1 : 0);

    results.push(
      makeDetection({
        label: LABEL,
        text: token,
        start: mStart,
        end: actualEnd,
        riskLevel: RiskLevel.LOW,
        confidence: 0.7,
        evidence: ["pattern:nationality", "dict:country"],
        legal_basis: LEGAL_BASIS,
        extra: {
          country: token,
          category: CATEGORY,
        },
      }),
    );
  }

  return results;
}
