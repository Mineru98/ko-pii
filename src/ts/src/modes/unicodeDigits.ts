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
import { pyIsDigit } from "../core/strUtils.js";
import { DIGIT_FOLD } from "../core/unicode-tables.gen.js";

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

/** Python ``s[start:end]`` 대응 — 코드 포인트 단위 슬라이스 (음수 인덱스 포함). */
export function cpSlice(s: string, start?: number, end?: number): string {
  return [...s].slice(start, end).join("");
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

const ND_CHAR = /\p{Nd}/u;

function ndDigitValue(cp: number): number {
  // Nd 는 10개(값 0..9) 단위로 정의되며 모든 묶음의 시작 코드 포인트는 연속 실행의
  // 시작에서 10의 배수만큼 떨어져 있다. 수학 숫자(U+1D7CE..U+1D7FF)처럼 묶음 5개가
  // 붙어 있는 블록이 있으므로 실행 시작점까지의 거리를 10 으로 나눈 나머지가 자릿값.
  let start = cp;
  while (start > 0 && ND_CHAR.test(String.fromCodePoint(start - 1))) start -= 1;
  return (cp - start) % 10;
}

/** Nd 숫자를 ASCII 숫자로 접은 문자열 (Python ``int()``/``float()`` 파싱 전처리). */
export function foldNdDigits(s: string): string {
  let folded = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    folded += cp !== undefined && pyIsDigit(ch) ? String(ndDigitValue(cp)) : ch;
  }
  return folded;
}

/** Python ``int(s)``/``float(s)`` 의 Nd 숫자열 파싱 대응 — 전각 등을 값으로 접는다. */
export function ndToNumber(s: string): number {
  return Number(foldNdDigits(s));
}
