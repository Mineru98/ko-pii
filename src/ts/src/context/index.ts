/** 컨텍스트 분석 — 점수 기반 이름 탐지 + 누적 사전 + 표기 변형 매칭.
 * Python ko_pii.context.__init__ 의 공개 표면(__all__) 대응 재수출.
 */

export type { NameCandidate, Score } from "./contextRules.js";
export { makeNameCandidate, makeScore, scoreCandidate } from "./contextRules.js";
export { hanjaToHangul, hasHanja } from "./hanja.js";
export type { NameRecord } from "./nameDictionary.js";
export { NameDictionary } from "./nameDictionary.js";
export {
  PARTICLES,
  startsWithParticle,
  stripTrailingParticle,
} from "./particles.js";
export { alternativeRomanizations, romanizeName } from "./romanization.js";
