/**
 * Python 유니코드 숫자 의미론 대응 — modes 계층 전용 헬퍼.
 *
 * modes 는 *검출된 원문* 을 직접 받는다. PORTING.md 의 "``\d`` → ``[0-9]``"
 * 관례는 업스트림 정규화로 전각이 폴딩된다는 전제인데, modes 에는 폴딩되지 않은
 * 텍스트(예: 전각 RRN)가 그대로 들어온다 (anonymize goldmaster 의
 * ``fullwidth_digits`` 케이스가 실증). 따라서 Python ``re`` 의 ``\d`` (= 유니코드
 * Nd) 와 ``int()``/``float()`` 의 Nd 파싱 의미론을 그대로 재현한다.
 * Nd 판정은 core/strUtils 의 pyIsDigit (의도적 Nd 근사) 를 재사용한다.
 */
import { pyIsDigit } from "../core/strUtils.js";

/** Python ``re.sub(r"\D", "", text)`` 대응 — Nd(십진 숫자) 코드 포인트만 남긴다. */
export function keepDigits(text: string): string {
  return [...text].filter((ch) => pyIsDigit(ch)).join("");
}

const ND_CHAR = /\p{Nd}/u;

function ndDigitValue(cp: number): number {
  // Nd 는 연속 10개(값 0..9) 실행 단위로 정의된다 — 실행 시작점까지 내려가면
  // (cp - 시작) 이 그 문자의 십진 값.
  let start = cp;
  while (start > 0 && ND_CHAR.test(String.fromCodePoint(start - 1))) start -= 1;
  return cp - start;
}

/** Python ``int(s)``/``float(s)`` 의 Nd 숫자열 파싱 대응 — 전각 등을 값으로 접는다. */
export function ndToNumber(s: string): number {
  let folded = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    folded += cp !== undefined && pyIsDigit(ch) ? String(ndDigitValue(cp)) : ch;
  }
  return Number(folded);
}
