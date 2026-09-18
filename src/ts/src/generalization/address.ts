/**
 * 주소 일반화 — 상세 주소 → 상위 행정구역.
 *
 * 입력은 검출 결과 또는 임의 한국 주소 문자열. 시·도까지만 남기거나, 시·군·구
 * 까지 남기는 두 모드를 지원.
 */

import { ValueError } from "../core/errors.js";

const CITY_PATTERN = /([가-힣]+(?:특별시|광역시|특별자치도|특별자치시|도))/;
const DISTRICT_PATTERN = /([가-힣]+(?:시|군|구))/;

/**
 * Trim ``addr`` to the first 시·도 (``"city"``) or 시·군·구 (``"district"``).
 *
 * Falls back to the input on no match.
 */
export function generalizeAddress(addr: string, level = "city"): string {
  if (level !== "city" && level !== "district") {
    throw new ValueError(`Unknown level: ${level}`);
  }
  const city = CITY_PATTERN.exec(addr);
  const cityText = city?.[1];
  if (level === "city") return cityText !== undefined ? cityText : addr;
  // Search for 시·군·구 strictly after the 시·도 to avoid matching
  // the same token ("서울특별시" also ends with 시).
  const searchFrom = city ? city.index + city[0].length : 0;
  const district = DISTRICT_PATTERN.exec(addr.slice(searchFrom));
  const districtText = district?.[1];
  if (cityText !== undefined && districtText !== undefined) {
    return `${cityText} ${districtText}`;
  }
  if (cityText !== undefined) return cityText;
  if (districtText !== undefined) return districtText;
  return addr;
}
