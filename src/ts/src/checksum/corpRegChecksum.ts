/**
 * 법인등록번호 (Corporation Registration Number) checksum validation.
 *
 * 13자리 NNNNNN-NNNNNNN, 13번째 자리가 check digit.
 * weights (1,2) 교대 가중합(자릿수 축약 없음), check = (10 - sum % 10) % 10.
 * 예: 삼성전자 130111-0006246 → check digit 6.
 */

import { ValueError } from "../core/errors.js";

const WEIGHTS = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2] as const;

export function computeCheckDigit(twelveDigits: string): number {
  if (twelveDigits.length !== 12 || !/^[0-9]+$/.test(twelveDigits)) {
    throw new ValueError("expected a 12-digit numeric string");
  }
  let total = 0;
  for (let i = 0; i < 12; i++) {
    // biome-ignore lint/style/noNonNullAssertion: 길이·숫자 사전 검증 후 인덱싱
    total += Number(twelveDigits[i]) * WEIGHTS[i]!;
  }
  return (10 - (total % 10)) % 10;
}

export function isValidChecksum(thirteenDigits: string): boolean {
  if (thirteenDigits.length !== 13 || !/^[0-9]+$/.test(thirteenDigits)) return false;
  return computeCheckDigit(thirteenDigits.slice(0, 12)) === Number(thirteenDigits[12]);
}
