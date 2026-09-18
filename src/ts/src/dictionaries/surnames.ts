/** 성씨 사전 게이트 — Python dictionaries/surnames.py 함수층 대응. */
import { COMPOUND_SURNAMES, SINGLE_CHAR_SURNAMES } from "./generated/surnames.js";

export const isSurname = (token: string): boolean =>
  COMPOUND_SURNAMES.has(token) || SINGLE_CHAR_SURNAMES.has(token);

/** 이름의 선행 성씨 길이 — 1 / 2 / 없으면 0. */
export function surnamePrefixLen(name: string): number {
  if (name.length >= 2 && COMPOUND_SURNAMES.has(name.slice(0, 2))) return 2;
  if (name.length >= 1 && SINGLE_CHAR_SURNAMES.has(name.slice(0, 1))) return 1;
  return 0;
}
