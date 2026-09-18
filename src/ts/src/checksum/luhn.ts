/** Luhn algorithm (ISO/IEC 7812 mod-10 check) — 카드번호 검증용. */

import { ValueError } from "../core/errors.js";

/** 숫자 문자열이 Luhn 검사를 통과하는지. */
export function isValid(digits: string): boolean {
  if (!/^[0-9]+$/.test(digits) || digits.length < 2) return false;
  let total = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d >= 10) d -= 9; // 자릿수 합과 동일
    }
    total += d;
  }
  return total % 10 === 0;
}

/** *payload* + check_digit 이 유효해지는 check digit 반환. */
export function computeCheckDigit(payload: string): number {
  if (!/^[0-9]+$/.test(payload)) throw new ValueError("expected numeric string");
  let total = 0;
  for (let i = 0; i < payload.length; i++) {
    let d = Number(payload[payload.length - 1 - i]);
    // payload 는 prefix 이므로 reversed(payload) 의 위치 i 는 전체 번호 기준
    // 오른쪽에서 i+1 번째 → 짝수(i%2==0) 위치가 2배.
    if (i % 2 === 0) {
      d *= 2;
      if (d >= 10) d -= 9;
    }
    total += d;
  }
  return (10 - (total % 10)) % 10;
}
