/** 기관 사전 게이트 — Python dictionaries/agencies.py 함수층 대응. */
import {
  AGENCIES_CHEONG,
  COMMISSIONS,
  JUDICIAL,
  LOCAL_GOV,
  MINISTRIES,
  PUBLIC_CORPS,
} from "./generated/agencies.js";

const AGENCIES = new Set([
  ...MINISTRIES,
  ...AGENCIES_CHEONG,
  ...COMMISSIONS,
  ...JUDICIAL,
  ...LOCAL_GOV,
  ...PUBLIC_CORPS,
]);

export const isAgency = (token: string): boolean => AGENCIES.has(token);
export const isMinistry = (token: string): boolean => MINISTRIES.has(token);
export const isCheong = (token: string): boolean => AGENCIES_CHEONG.has(token);
export const isCommission = (token: string): boolean => COMMISSIONS.has(token);
export const isLocalGov = (token: string): boolean => LOCAL_GOV.has(token);
