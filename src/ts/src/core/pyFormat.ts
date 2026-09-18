/**
 * Python 숫자 → 문자열 규칙의 TS 대응 (출력 문자열의 바이트 동등성용).
 */

/**
 * Python ``f"{x:.{digits}f}"`` 대응.
 *
 * 둘 다 double 의 *정확한* 십진 값을 반올림하므로 차이는 정확한 중간값(tie)뿐이다:
 * Python 은 half-even, ``toFixed`` 는 큰 쪽. tie 는 x = 홀수 / 2^(digits+1) 일 때만
 * 생기며(예: 6.25, 0.125), 2의 거듭제곱 곱은 부동소수에서 정확하므로 오판이 없다.
 * (``x * 10**digits`` 로 판정하면 8.345 같은 비-tie 가 곱셈 반올림으로 tie 처럼 보인다.)
 */
export function pyFormatFixed(x: number, digits: number): string {
  const fixed = x.toFixed(digits);
  if (!Number.isFinite(x) || digits < 1) return fixed;
  const dyadic = x * 2 ** (digits + 1);
  if (!Number.isInteger(dyadic) || dyadic % 2 === 0) return fixed;
  // tie: toFixed 는 절댓값이 큰 쪽을 골랐다. 마지막 자릿수가 홀수면 한 단계 내린 쪽이
  // 짝수다 — 홀수에서 1 을 빼므로 자리내림이 없어 문자열 조작만으로 정확하다
  // (큰 수에서 x*10^n 산술은 정밀도를 잃는다).
  const last = fixed.charCodeAt(fixed.length - 1) - 48;
  return last % 2 === 0 ? fixed : `${fixed.slice(0, -1)}${last - 1}`;
}

/**
 * Python ``repr(float)`` / ``json.dumps(float)`` 대응.
 * 정숫값은 ``1.0``, 지수 표기는 exp < -4 또는 exp >= 16 에서 두 자리 지수(``1e-07``, ``1e+16``).
 */
export function pyFloatRepr(v: number): string {
  if (Number.isNaN(v)) return "NaN";
  if (v === Number.POSITIVE_INFINITY) return "Infinity";
  if (v === Number.NEGATIVE_INFINITY) return "-Infinity";
  if (v === 0) return Object.is(v, -0) ? "-0.0" : "0.0";
  const [mantissa, expStr] = v.toExponential().split("e") as [string, string];
  const exp = Number(expStr);
  if (exp >= -4 && exp < 16) {
    const fixed = String(v); // 이 범위에서 JS 도 고정 표기
    return fixed.includes(".") ? fixed : `${fixed}.0`;
  }
  const sign = exp < 0 ? "-" : "+";
  return `${mantissa}e${sign}${String(Math.abs(exp)).padStart(2, "0")}`;
}
