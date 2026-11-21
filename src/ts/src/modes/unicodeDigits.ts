/**
 * Python 유니코드 숫자·문자열 의미론 대응 — modes 계층 전용 헬퍼.
 *
 * modes 는 *검출된 원문* 을 직접 받는다. PORTING.md 의 "``\d`` → ``[0-9]``"
 * 관례는 업스트림 정규화로 전각이 폴딩된다는 전제인데, modes 에는 폴딩되지 않은
 * 텍스트(예: 전각 RRN)가 그대로 들어온다 (anonymize goldmaster 의
 * ``fullwidth_digits`` 케이스가 실증). 따라서 Python ``re`` 의 ``\d`` (= 유니코드
 * Nd) 와 ``int()``/``float()`` 의 Nd 파싱 의미론을 그대로 재현한다.
 * Nd 판정은 core/strUtils 의 pyIsDigit (의도적 Nd 근사) 를 재사용한다.
 *
 * 또한 Python ``len()``/슬라이스는 *코드 포인트* 단위다. 마스킹 결과의 길이와 잘린
 * 위치는 관찰 가능한 출력이므로(오프셋 단위 관용과 별개), 아스트랄 문자(이모지·수학
 * 숫자)가 섞인 값은 코드 포인트 배열로 다뤄야 서로게이트가 깨지지 않는다.
 */
import { PY_S, pyIsDigit } from "../core/strUtils.js";
import { DIGIT_FOLD } from "../core/unicode-tables.gen.js";

/**
 * Python ``re`` 의 유니코드 ``\s`` 집합 (= ``str.isspace()``) 문자 클래스 소스. JS ``\s`` 와 달리
 * U+001C~U+001F·U+0085 를 포함하고 U+FEFF 는 제외한다.
 */
export const PY_WS = PY_S;

/** Python ``list(s)`` 대응 — 코드 포인트 단위 분해 (서로게이트 쌍은 한 원소). */
export function codePoints(s: string): string[] {
  return [...s];
}

/** Python ``len(s)`` 대응 — 코드 포인트 수. */
export function cpLength(s: string): number {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

/** Python ``re.sub(r"\D", "", text)`` 대응 — Nd(십진 숫자) 코드 포인트만 남긴다. */
export function keepDigits(text: string): string {
  return [...text].filter((ch) => pyIsDigit(ch)).join("");
}

/**
 * Python ``str.isdigit()`` 이 True 인 비ASCII 문자 집합 — Nd 와 Numeric_Type=Digit
 * (위첨자 ``²``, 원문자 ``①`` 등 No). 생성 테이블 DIGIT_FOLD 의 키 집합이 정확히 이
 * 집합이다 (Python ``unicodedata`` 와 전 범위 대조: 808자 일치).
 */
const NON_ASCII_ISDIGIT = new Set<number>(DIGIT_FOLD.map(([cp]) => cp));

/**
 * Python ``ch.isdigit()`` 대응 (단일 문자). ``\d``/``pyIsDigit`` (Nd 한정) 보다 넓다 —
 * fpe 의 문자 분류 루프는 Python 이 ``isdigit()`` 을 쓰므로 이쪽을 써야 한다.
 */
export function pyStrIsDigit(ch: string): boolean {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return false;
  if (cp < 0x80) return cp >= 0x30 && cp <= 0x39;
  return NON_ASCII_ISDIGIT.has(cp) || pyIsDigit(ch);
}

export { cpSlice, foldNdDigits, ndToNumber } from "../core/strUtils.js";
