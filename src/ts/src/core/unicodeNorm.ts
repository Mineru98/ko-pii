/**
 * 유니코드 정규화 — 전각/호환문자 폴딩 + 보이지 않는 문자 제거 (offset 보존).
 * Python ko_pii.core.unicode_norm 대응.
 *
 * PII 검출 우회 차단: 전각 숫자/영문(０１０→010), 호환 형태(①→1), 제로폭/방향
 * 문자 제거, 자릿수 분할 공백 붕괴, 라틴 호몰로그 숫자(l→1) 폴딩.
 *
 * TS 판 차이 (PORTING.md): 오프셋은 코드 포인트가 아닌 **UTF-16 코드 유닛** 기준.
 * 아스트랄 문자(이모지 등)는 서로게이트 단위로 처리되지만 결과 문자열은 Python 과
 * 동일하다. 골드 마스터 회귀가 문자열 등가성을 검증한다.
 */

import { pyIsAlpha, pyIsAscii, pyIsDigit, regexEscape } from "./strUtils.js";
import type { DetectionResult } from "./types.js";
import { COMBINING_RANGES, DIGIT_FOLD } from "./unicode-tables.gen.js";

// 보이지 않는/제로폭/방향 문자 + C0/C1 제어 + U+2A74('::=' 확장, PII 숫자열 재결합 차단)
const INVISIBLE =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: 제어문자·제로폭 제거가 이 모듈의 기능 본질
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2A74\uFEFF]/;

// 결합표시(nonspacing marks) — 숫자 사이에 끼면 PII 를 쪼개는 우회. fast-path 별도 검사.
const COMBINING_FAST =
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: NFD 분해형 한글 자모 범위 — 조합용 자모 우회 차단용
  /[\u0300-\u036F\u0483-\u0489\u0591-\u05BD\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06DC\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]/;

// 비ASCII 숫자 → ASCII 폴딩 테이블 (Python unicodedata 에서 생성 — 위 테이블 참조).
const DIGIT_FOLD_MAP = new Map<string, string>(
  DIGIT_FOLD.map(([cp, ch]) => [String.fromCodePoint(cp), ch]),
);

const DASH_CHARS =
  "\u2010\u2011\u2012\u2013\u2014\u2015\u2043\u2212\uFE58\uFE63\uFF0D\u00B7\u2022\u2027\u2219\u22C5\u30FB\uFF65\u318D";
const SLASH_CHARS = "\u2044\u2215\u29F8\u2571";

const CHAR_FOLD = new Map<string, string>(DIGIT_FOLD_MAP);
for (const c of DASH_CHARS) CHAR_FOLD.set(c, "-");
for (const c of SLASH_CHARS) CHAR_FOLD.set(c, "/");

// fast-path 검사용: 모든 폴딩 대상 문자 하나의 클래스
const FOLD_DIGIT = new RegExp(`[${[...CHAR_FOLD.keys()].map(regexEscape).join("")}]`);

// 조합용 한글 자모(NFD 분해형). 단독 자모는 NFKC 가 안 바꾸므로 fast-path 에서 별도 검사.
const CONJOINING_JAMO = /[\u1100-\u11FF\uA960-\uA97F\uD7B0-\uD7FF]/;

/** 결합 클래스 코드포인트 여부 (생성 테이블 이분 탐색 — Python unicodedata 데이터). */
function hasCombiningClass(ch: string): boolean {
  if (ch.length !== 1) return false;
  const cp = ch.codePointAt(0);
  if (cp === undefined) return false;
  let lo = 0;
  let hi = COMBINING_RANGES.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const range = COMBINING_RANGES[mid];
    if (range === undefined) return false;
    const [s, e] = range;
    if (cp < s) hi = mid - 1;
    else if (cp > e) lo = mid + 1;
    else return true;
  }
  return false;
}

function isConjoiningJamo(ch: string): boolean {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return false;
  return (
    (cp >= 0x1100 && cp <= 0x11ff) ||
    (cp >= 0xa960 && cp <= 0xa97f) ||
    (cp >= 0xd7b0 && cp <= 0xd7ff)
  );
}

// 자릿수 사이 ASCII 공백 주입 우회('8 8 0 1 0 1-1234568') — recall-safe 붕괴 대상 판정.
const SPACED_NUM_REGION = /(?<![0-9A-Za-z])[0-9](?:[ .-]{0,3}[0-9]){8,}(?![0-9A-Za-z])/g;
const SINGLE_SPACED_DIGIT = /(?<= )[0-9](?= )/g;

/** 자릿수 분할 우회 구간 안의 '제거 대상 ASCII 공백' 원본 위치 집합. */
function spacedCollapsePositions(text: string): Set<number> {
  const drop = new Set<number>();
  SPACED_NUM_REGION.lastIndex = 0;
  for (const m of text.matchAll(SPACED_NUM_REGION)) {
    const region = m[0];
    let digits = 0;
    for (const c of region) if (pyIsDigit(c)) digits += 1;
    if (digits < 10 || digits > 16) continue;
    // 단일공백에 둘러싸인 한 자리 숫자가 4회 이상 — 자릿수 분할 시그니처.
    const padded = ` ${region} `;
    const paddedCount = [...padded.matchAll(SINGLE_SPACED_DIGIT)].length;
    if (paddedCount < 4) continue;
    const base = m.index;
    for (let i = 0; i < region.length; i++) {
      if (region[i] === " ") drop.add(base + i);
    }
  }
  return drop;
}

// 라틴 글리프 숫자 위장(O→0, l→1 …) — 숫자 토큰 안에서만 폴딩.
const DIGIT_HOMOGLYPH: Record<string, string> = {
  O: "0",
  o: "0",
  Q: "0",
  l: "1",
  I: "1",
  "|": "1",
  S: "5",
  B: "8",
  Z: "2",
  G: "6",
};
const DIGIT_HG_TOKEN = /[0-9OoQlI|SBZG][0-9OoQlI|SBZG\-\u2010-\u2015]*/g;

/** 숫자열 토큰 안의 라틴 호몰로그를 숫자로 폴딩(1:1, 길이 불변). */
function foldDigitHomoglyphs(text: string): string {
  return text.replace(DIGIT_HG_TOKEN, (s) => {
    let digits = 0;
    let hg = 0;
    for (const c of s) {
      if (pyIsDigit(c)) digits += 1;
      if (c in DIGIT_HOMOGLYPH) hg += 1;
    }
    if (digits >= 2 && hg >= 1) {
      let out = "";
      for (const c of s) out += DIGIT_HOMOGLYPH[c] ?? c;
      return out;
    }
    return s;
  });
}

/** 정규화(우회 차단)가 필요한가 — detect_all 진입 가드용. */
export function needsNormalization(text: string): boolean {
  return !pyIsAscii(text) || INVISIBLE.test(text) || spacedCollapsePositions(text).size > 0;
}

/**
 * NFKC 폴딩 + 보이지 않는 문자 제거.
 * Returns `[normalized, offsetMap]`. offsetMap[i] 는 normalized[i] (UTF-16 유닛)에
 * 대응하는 원본 UTF-16 위치. 변화가 없으면 normalized === text (offsetMap 은 빈 배열).
 */
export function normalizeUnicode(text: string): [string, number[]] {
  text = foldDigitHomoglyphs(text);
  const dropSpaces = spacedCollapsePositions(text);
  // 빠른 경로: 이미 NFKC 이고 보이지 않는/결합/폴딩/조합 자모 문자가 없으면 no-op.
  if (
    dropSpaces.size === 0 &&
    !INVISIBLE.test(text) &&
    !COMBINING_FAST.test(text) &&
    !FOLD_DIGIT.test(text) &&
    !CONJOINING_JAMO.test(text) &&
    text.normalize("NFKC") === text
  ) {
    return [text, []];
  }

  const out: string[] = [];
  const omap: number[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const ch = text.charAt(i);
    if (INVISIBLE.test(ch)) {
      i += 1;
      continue;
    }
    // 자릿수 분할 우회 구간 안의 ASCII 공백 — invisible 처럼 스킵하되 위치는 다음
    // 글자의 원본 매핑이 덮어 redact span 이 원본 공백까지 포함한다.
    if (ch === " " && dropSpaces.has(i)) {
      i += 1;
      continue;
    }
    // 기본 문자 + 뒤따르는 결합표시/한글 자모를 한 클러스터로 묶어 NFKC.
    let j = i + 1;
    while (j < n && (hasCombiningClass(text.charAt(j)) || isConjoiningJamo(text.charAt(j)))) {
      j += 1;
    }
    const baseIsAlpha = pyIsAlpha(text.charAt(i));
    for (const fc of text.slice(i, j).normalize("NFKC")) {
      // 숫자/기호 베이스에 남는 결합표시·조합용 자모('9001ᄀ01' 우회)는 제거.
      // 문자 베이스(é, NFD 한글 등 정상 결합)는 보존.
      if (!baseIsAlpha && (hasCombiningClass(fc) || isConjoiningJamo(fc))) {
        continue;
      }
      out.push(CHAR_FOLD.get(fc) ?? fc);
      omap.push(i);
    }
    i = j;
  }
  return [out.join(""), omap];
}

/** 정규화 텍스트 기준 offset 을 원본 기준으로 역매핑 + .text 원본 복원. */
export function remapToSource(
  detections: DetectionResult[],
  offsetMap: number[],
  source: string,
): DetectionResult[] {
  const n = offsetMap.length;
  return detections.map((det) => {
    // 인덱스 경계 검사를 통과했으므로 매핑값은 항상 존재한다 (offsetMap 에 구멍 없음).
    const start = det.start < n ? (offsetMap[det.start] ?? det.start) : det.start;
    // 검출 끝 = 다음 정규화 글자의 원본 시작 위치(마지막 클러스터의 원본 끝).
    let end: number;
    if (det.end < n) end = offsetMap[det.end] ?? det.end;
    else if (det.end === n) end = source.length;
    else end = det.end;
    return { ...det, start, end, text: source.slice(start, end) };
  });
}
