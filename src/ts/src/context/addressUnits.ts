/**
 * 유형 주소 단위(동·호·층) 뒤의 공통 연속 문법 — 꼬리는 소비하지 않는다.
 * Python ko_pii.context.address_units 대응.
 *
 * Python ``[\W_]`` (유니코드 \w 의 여집합 + 밑줄) 은 JS ``u`` 플래그의
 * ``[^\p{L}\p{N}]`` 로 옮긴다 — 이 모듈의 패턴은 ``u`` 플래그로 컴파일해야 한다.
 */

const LONG_PARTICLE = "(?:으로부터|에서부터|으로|에서|부터|까지)";
const NON_WORD_OR_UNDERSCORE = "[^\\p{L}\\p{N}]";
const SHORT_PARTICLE = `(?:에|로|은|는|이|가|을|를|도|만|의)(?:은|는|도|만|의)?(?=${NON_WORD_OR_UNDERSCORE}|$)`;
const COPULA = "(?:입니다|이에요|이었|이다|이고|이며|이라|이어서|예요)";
const BOUNDARY_OR_PARTICLE = `(?:${NON_WORD_OR_UNDERSCORE}|$|${LONG_PARTICLE}|${SHORT_PARTICLE}|${COPULA})`;
const LOCATION_NOUN =
  "(?:근처|인근|주변|내부|외부|출입구|입구|출구|로비|사무실|상가|" +
  "안쪽|바깥쪽|바깥|앞쪽|뒤쪽|옆쪽|맞은편|건너편|동쪽|서쪽|남쪽|북쪽)" +
  `(?=${BOUNDARY_OR_PARTICLE})`;
const SHORT_LOCATION = `(?:앞|뒤|옆|안|내)(?=${BOUNDARY_OR_PARTICLE}|${LOCATION_NOUN})`;

/** 단위 뒤 꼬리 문법 (정규식 소스 — ``u`` 플래그 필요). */
export const UNIT_TAIL = `(?:${BOUNDARY_OR_PARTICLE}|${LOCATION_NOUN}|${SHORT_LOCATION})`;
const TAIL_PATTERN = new RegExp(UNIT_TAIL, "uy");

export function hasUnitTail(text: string, position: number): boolean {
  TAIL_PATTERN.lastIndex = position;
  return TAIL_PATTERN.test(text);
}
