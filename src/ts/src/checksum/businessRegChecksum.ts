/**
 * 사업자등록번호 (Business Registration Number) checksum validation.
 *
 * 10자리 XXX-YY-NNNNN, 10번째 자리가 check digit.
 * 국세청 방식: weights (1,3,7,1,3,7,1,3,5) 를 1..9자리에 적용,
 * 추가로 (digit[8] * 5) // 10 을 가중합에 가산. check = (10 - sum % 10) % 10.
 */

import { ValueError } from "../core/errors.js";

const WEIGHTS = [1, 3, 7, 1, 3, 7, 1, 3, 5] as const;

export function computeCheckDigit(nineDigits: string): number {
  if (nineDigits.length !== 9 || !/^[0-9]+$/.test(nineDigits)) {
    throw new ValueError("expected a 9-digit numeric string");
  }
  let total = 0;
  for (let i = 0; i < 9; i++) {
    // biome-ignore lint/style/noNonNullAssertion: 길이·숫자 사전 검증 후 인덱싱
    total += Number(nineDigits[i]) * WEIGHTS[i]!;
  }
  total += Math.trunc((Number(nineDigits[8]) * 5) / 10);
  return (10 - (total % 10)) % 10;
}

export function isValidChecksum(tenDigits: string): boolean {
  if (tenDigits.length !== 10 || !/^[0-9]+$/.test(tenDigits)) return false;
  return computeCheckDigit(tenDigits.slice(0, 9)) === Number(tenDigits[9]);
}
