/** 직함 사전 게이트 — Python dictionaries/titles.py 함수층 대응. */
import {
  ALL_GOV_TITLES,
  TITLES,
  TITLES_DIPLOMAT,
  TITLES_FIRE,
  TITLES_GOV,
  TITLES_JUDGE,
  TITLES_MILITARY,
  TITLES_OTHER_SPECIAL,
  TITLES_POLICE,
  TITLES_PROSECUTOR,
} from "./generated/titles.js";

export const isTitle = (token: string): boolean => TITLES.has(token) || ALL_GOV_TITLES.has(token);
export const isGovTitle = (token: string): boolean => ALL_GOV_TITLES.has(token);
export const isPoliceTitle = (token: string): boolean => TITLES_POLICE.has(token);
export const isFireTitle = (token: string): boolean => TITLES_FIRE.has(token);
export const isMilitaryTitle = (token: string): boolean => TITLES_MILITARY.has(token);
export const isDiplomatTitle = (token: string): boolean => TITLES_DIPLOMAT.has(token);
export const isProsecutorTitle = (token: string): boolean => TITLES_PROSECUTOR.has(token);
export const isJudgeTitle = (token: string): boolean => TITLES_JUDGE.has(token);

/** 'general'/'gov'/'police'/'fire'/'military'/'diplomat'/'prosecutor'/'judge' 또는 null. */
export function titleDomain(token: string): string | null {
  if (TITLES_POLICE.has(token)) return "police";
  if (TITLES_FIRE.has(token)) return "fire";
  if (TITLES_MILITARY.has(token)) return "military";
  if (TITLES_DIPLOMAT.has(token)) return "diplomat";
  if (TITLES_PROSECUTOR.has(token)) return "prosecutor";
  if (TITLES_JUDGE.has(token)) return "judge";
  if (TITLES_GOV.has(token) || TITLES_OTHER_SPECIAL.has(token)) return "gov";
  if (TITLES.has(token)) return "general";
  return null;
}
