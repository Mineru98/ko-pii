/**
 * 주민등록번호 (RRN) checksum validation.
 *
 * 가중치 (2,3,4,5,6,7,8,9,2,3,4,5) 가중합 → check = (11 - sum % 11) % 10.
 * 2020-10 이후 신규 RRN 은 뒷자리가 무작위라 체크섬 실패를 "RRN 아님"이 아닌
 * 신뢰도 감쇠 신호로 취급할 것 (patterns/rrn 참조).
 */
const WEIGHTS = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5] as const;

/** 첫 12자리에 대한 기대 check digit 반환. */
export function computeCheckDigit(twelveDigits: string): number {
  if (twelveDigits.length !== 12 || !/^[0-9]+$/.test(twelveDigits)) {
    throw new Error("expected a 12-digit numeric string");
  }
  let total = 0;
  for (let i = 0; i < 12; i++) {
    // biome-ignore lint/style/noNonNullAssertion: 길이·숫자 사전 검증 후 인덱싱
    total += Number(twelveDigits[i]) * WEIGHTS[i]!;
  }
  return (11 - (total % 11)) % 10;
}

/** 13자리 RRN 이 check digit 과 일치하는지. */
export function isValidChecksum(thirteenDigits: string): boolean {
  if (thirteenDigits.length !== 13 || !/^[0-9]+$/.test(thirteenDigits)) return false;
  return computeCheckDigit(thirteenDigits.slice(0, 12)) === Number(thirteenDigits[12]);
}
