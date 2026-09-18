/** 전공 사전 게이트 — Python dictionaries/majors.py 함수층 대응. */
import { ALL_MAJORS, MAJOR_ABBREV } from "./generated/majors.js";

const SUFFIX_VARIANTS = ["학과", "학부", "전공", "과"] as const;

/** 접미사 제거 + 표준 명칭으로 정규화 ("컴퓨터공학과"→"컴퓨터공학", "컴공과"→약칭 매핑). */
export function normalizeMajor(token: string): string {
  if (ALL_MAJORS.has(token)) return token;
  const abbrev = MAJOR_ABBREV[token];
  if (abbrev !== undefined) return abbrev;
  for (const suf of SUFFIX_VARIANTS) {
    if (token.endsWith(suf) && token.length > suf.length) {
      const stem = token.slice(0, -suf.length);
      if (ALL_MAJORS.has(stem)) return stem;
      // "학" 안 붙은 경우 "학" 추가 시도 ("경영과" → "경영학")
      if (ALL_MAJORS.has(`${stem}학`)) return `${stem}학`;
    }
  }
  return token;
}

/** 전공명 인식 (접미사 변형 + 약칭 포함). */
export function isMajor(token: string): boolean {
  if (MAJOR_ABBREV[token] !== undefined) return true;
  return ALL_MAJORS.has(normalizeMajor(token));
}
