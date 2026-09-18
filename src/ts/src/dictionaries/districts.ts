/** 행정구역 사전 게이트 — Python dictionaries/districts.py 함수층 대응. */
import {
  ALL_DISTRICTS,
  COMMON_DONGS,
  COUNTRIES,
  EXTRA_CITY_ABBREV,
  PROVINCE_ABBREV,
  PROVINCE_DISTRICTS,
  PROVINCES,
} from "./generated/districts.js";

// 런타임 조회 성능을 위해 배열 데이터를 Set 으로 승격 (모듈 초기화 1회).
const EXTRA_CITY = new Set(EXTRA_CITY_ABBREV);
const PROVINCE_DISTRICT_SETS = new Map(
  Object.entries(PROVINCE_DISTRICTS).map(([k, v]) => [k, new Set(v)]),
);

/** 국가명 토큰. */
export const isCountry = (token: string): boolean => COUNTRIES.has(token);
/** 빈출 동 사전 매칭. */
export const isCommonDong = (token: string): boolean => COMMON_DONGS.has(token);
/** 광역 외 빈출 시 약칭. */
export const isExtraCity = (token: string): boolean => EXTRA_CITY.has(token);

/** (광역, 기초) 조합이 실제 한국 행정구역인지 검증. */
export function isValidProvinceDistrict(province: string, district: string): boolean {
  if (!province || !district) return false;
  const districts = PROVINCE_DISTRICT_SETS.get(province);
  if (districts === undefined) return false;
  return districts.has(district);
}

/** 주어진 광역의 자치구·군 집합. */
export function districtsOf(province: string): ReadonlySet<string> {
  return PROVINCE_DISTRICT_SETS.get(province) ?? new Set();
}

export const isProvince = (token: string): boolean =>
  PROVINCES.has(token) || PROVINCE_ABBREV[token] !== undefined;

/** 자치구·군·시 (기초자치단체) 여부. */
export const isDistrict = (token: string): boolean => ALL_DISTRICTS.has(token);

/** 광역·기초·읍·면·동 등 모든 행정구역 토큰. */
export const isAdminUnit = (token: string): boolean => isProvince(token) || isDistrict(token);

/** 약칭을 정식 광역명으로. */
export const normalizeProvince = (token: string): string => PROVINCE_ABBREV[token] ?? token;
