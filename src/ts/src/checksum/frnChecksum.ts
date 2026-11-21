/**
 * 외국인등록번호 레거시 체크섬 산술 — 신원 검증이 아니다 (Python ko_pii.checksum.frn_checksum 대응).
 *
 * 외국인 check digit = (주민등록번호 가중합 check digit + 2) mod 10.
 * 날짜·세기·검출 정책은 의도적으로 이 헬퍼 밖에 둔다.
 */

import { ValueError } from "../core/errors.js";
import { computeCheckDigit as residentCheckDigit } from "./rrnChecksum.js";

/** 정확히 12자리 ASCII 숫자에 대한 레거시 외국인 check digit. */
export function computeCheckDigit(twelveDigits: string): number {
  if (typeof twelveDigits !== "string" || !/^[0-9]{12}$/.test(twelveDigits)) {
    throw new ValueError("expected a 12-digit ASCII string");
  }
  return (residentCheckDigit(twelveDigits) + 2) % 10;
}

/** 산술만 확인한다 — 불일치가 비-PII 를 증명하지 않는다. */
export function isValidChecksum(thirteenDigits: string): boolean {
  if (typeof thirteenDigits !== "string" || !/^[0-9]{13}$/.test(thirteenDigits)) return false;
  return computeCheckDigit(thirteenDigits.slice(0, 12)) === Number(thirteenDigits[12]);
}
