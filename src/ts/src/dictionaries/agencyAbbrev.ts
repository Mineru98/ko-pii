/** 기관 약칭 사전 게이트 — Python dictionaries/agency_abbrev.py 함수층 대응. */
import {
  DOC_ID_PREFIXES,
  ENG_ABBREV_TO_KOR,
  KOR_ABBREV_TO_FULL,
} from "./generated/agency_abbrev.js";

/** 약칭(한글/영문)을 정식 명칭으로 정규화. 매핑 없으면 null. */
export function normalizeAgency(token: string): string | null {
  const kor = KOR_ABBREV_TO_FULL[token];
  if (kor !== undefined) return kor;
  const eng = ENG_ABBREV_TO_KOR[token];
  if (eng !== undefined) return eng;
  return null;
}

export function isDocIdPrefix(token: string): boolean {
  return DOC_ID_PREFIXES.has(token);
}
