/**
 * 유니코드 정규화 — 전각/호환문자 폴딩 + 보이지 않는 문자 제거 (offset 보존).
 * Python ko_pii.core.unicode_norm 대응.
 *
 * PII 검출 우회 차단: 전각 숫자/영문(０１０→010), 호환 형태(①→1), 제로폭/방향
 * 문자 제거, 자릿수 분할 공백 붕괴, 라틴 호몰로그 숫자(l→1) 폴딩.
 *
 * TS 판 차이 (PORTING.md): 오프셋은 코드 포인트가 아닌 **UTF-16 코드 유닛** 기준.
 * 순회·판정은 Python 과 같이 코드 포인트 단위다 (아스트랄 숫자·결합표시 포함) — 결과
 * 문자열은 Python 과 동일하고, 골드 마스터 회귀가 문자열 등가성을 검증한다.
 */

import { pyIsAlpha, pyIsAscii, pyIsDigit, regexEscape } from "./strUtils.js";
import type { DetectionResult } from "./types.js";
import { COMBINING_RANGES, DIGIT_FOLD } from "./unicode-tables.gen.js";

// 보이지 않는/제로폭/방향 문자 + C0/C1 제어 + U+2A74('::=' 확장, PII 숫자열 재결합 차단)
const INVISIBLE =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: 제어문자·제로폭 제거가 이 모듈의 기능 본질
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2A74\uFEFF]/;

// 결합표시 — fast-path 판정 전용. Python `_COMBINING` 과 같은 손 나열 BMP 범위다
// (느린 경로의 결합 판정은 unicodedata.combining 전체 테이블 = COMBINING_RANGES).
const COMBINING_FAST =
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: 결합표시 범위 판정이 목적 (Python _COMBINING 과 동일)
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
// u 플래그: 아스트랄 키(수학 숫자 등)를 서로게이트 반쪽이 아닌 코드 포인트로 매칭한다.
const FOLD_DIGIT = new RegExp(`[${[...CHAR_FOLD.keys()].map(regexEscape).join("")}]`, "u");

// 조합용 한글 자모(NFD 분해형). 단독 자모는 NFKC 가 안 바꾸므로 fast-path 에서 별도 검사.
const CONJOINING_JAMO = /[\u1100-\u11FF\uA960-\uA97F\uD7B0-\uD7FF]/;

/** 결합 클래스 코드포인트 여부 (생성 테이블 이분 탐색 — Python unicodedata 데이터). */
function hasCombiningClass(ch: string): boolean {
  // ch 는 코드 포인트 1개(BMP 1유닛 또는 아스트랄 2유닛) — 아스트랄 결합표시도 판정한다.
  const cp = ch.codePointAt(0);
  if (cp === undefined) return false;
  if (ch.length !== (cp > 0xffff ? 2 : 1)) return false;
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
const DIGIT_HG_TOKEN = /[A-Za-z0-9_|][A-Za-z0-9_|\-\u2010-\u2015]*/g;
const DIGIT_HG_PRESENT = /[OoQlI|SBZG]/;
const DIGIT_HG_ALLOWED: ReadonlySet<string> = new Set([
  ..."0123456789-\u2010\u2011\u2012\u2013\u2014\u2015",
  ...Object.keys(DIGIT_HOMOGLYPH),
]);

/** ASCII 식별자 토큰 전체를 본다 — 토큰 안의 숫자처럼 보이는 꼬리만 보지 않는다. */
function isDigitHomoglyphToken(token: string): boolean {
  if (!DIGIT_HG_PRESENT.test(token)) return false;
  let digits = 0;
  for (const c of token) {
    if (!DIGIT_HG_ALLOWED.has(c)) return false;
    if (c >= "0" && c <= "9") digits += 1;
  }
  return digits >= 2;
}

/** 숫자열 토큰 안의 라틴 호몰로그를 숫자로 폴딩(1:1, 길이 불변). */
function foldDigitHomoglyphs(text: string): string {
  return text.replace(DIGIT_HG_TOKEN, (s) => {
    if (!isDigitHomoglyphToken(s)) return s;
    let out = "";
    for (const c of s) out += DIGIT_HOMOGLYPH[c] ?? c;
    return out;
  });
}

function hasDigitHomoglyphToken(text: string): boolean {
  if (!DIGIT_HG_PRESENT.test(text)) return false;
  for (const m of text.matchAll(DIGIT_HG_TOKEN)) {
    if (isDigitHomoglyphToken(m[0])) return true;
  }
  return false;
}

/** 정규화(우회 차단)가 필요한가 — detect_all 진입 가드용. */
export function needsNormalization(text: string): boolean {
  return (
    !pyIsAscii(text) ||
    INVISIBLE.test(text) ||
    spacedCollapsePositions(text).size > 0 ||
    hasDigitHomoglyphToken(text)
  );
}

/** 코드 포인트 1개(아스트랄은 2유닛)를 pos 에서 읽는다. lone surrogate 는 폭 1. */
function cpAt(text: string, pos: number): string {
  const cp = text.codePointAt(pos);
  return cp !== undefined && cp > 0xffff ? text.slice(pos, pos + 2) : text.charAt(pos);
}

/** 결합표시 + 합성 가능한 한글 음절 하나를 묶는다 — 단어 전체가 아니다.
 * Python `_normalization_cluster_end` 대응 (인덱스는 UTF-16, 이동은 코드 포인트 단위).
 */
function normalizationClusterEnd(text: string, start: number): number {
  const n = text.length;
  const firstCh = cpAt(text, start);
  let end = start + firstCh.length;
  const first = firstCh.normalize("NFKC");
  const firstCode = first.length === 1 ? first.charCodeAt(0) : -1;
  let canTakeTail = firstCode >= 0xac00 && firstCode <= 0xd7a3 && (firstCode - 0xac00) % 28 === 0;
  if (firstCode >= 0x1100 && firstCode <= 0x1112 && end < n) {
    const vowelCh = cpAt(text, end);
    const vowel = vowelCh.normalize("NFKC");
    const v = vowel.length === 1 ? vowel.charCodeAt(0) : -1;
    if (v >= 0x1161 && v <= 0x1175) {
      end += vowelCh.length;
      canTakeTail = true;
    }
  }
  if (canTakeTail && end < n) {
    const tailCh = cpAt(text, end);
    const tail = tailCh.normalize("NFKC");
    const t = tail.length === 1 ? tail.charCodeAt(0) : -1;
    if (t >= 0x11a8 && t <= 0x11c2) end += tailCh.length;
  }
  while (end < n) {
    const next = cpAt(text, end);
    if (!hasCombiningClass(next)) break;
    end += next.length;
  }
  return end;
}

/** 유니코드 폴딩 뒤 ASCII 숫자 폴딩을 적용하고 원본 offset 을 합성한다. */
function foldNumericText(text: string, offsets: number[]): [string, number[]] {
  const folded = foldDigitHomoglyphs(text);
  const drop = spacedCollapsePositions(folded);
  if (drop.size === 0) return [folded, offsets];
  let out = "";
  const omap: number[] = [];
  for (let i = 0; i < folded.length; i++) {
    if (drop.has(i)) continue;
    out += folded[i];
    omap.push(offsets.length > 0 ? (offsets[i] as number) : i);
  }
  return [out, omap];
}

export interface NormalizeOptions {
  /** false 면 여권 S/O/G 같은 문자 그대로 둔다 (유니코드 호환 폴딩·offset 은 유지). 기본 true. */
  foldNumeric?: boolean;
}

/**
 * NFKC 폴딩 + 보이지 않는 문자 제거.
 * Returns `[normalized, offsetMap]`. offsetMap[i] 는 normalized[i] (UTF-16 유닛)에
 * 대응하는 원본 UTF-16 위치. 길이·위치가 유지되는 빠른 경로에서는 빈 배열 — 이때도 숫자
 * 닮은꼴 폴딩으로 내용은 달라질 수 있다.
 */
export function normalizeUnicode(text: string, options: NormalizeOptions = {}): [string, number[]] {
  const foldNumeric = options.foldNumeric ?? true;
  // 빠른 경로: 이미 NFKC 이고 보이지 않는/결합/폴딩/조합 자모 문자가 없으면 no-op.
  if (
    !INVISIBLE.test(text) &&
    !COMBINING_FAST.test(text) &&
    !FOLD_DIGIT.test(text) &&
    !CONJOINING_JAMO.test(text) &&
    text.normalize("NFKC") === text
  ) {
    return foldNumeric ? foldNumericText(text, []) : [text, []];
  }

  const out: string[] = [];
  const omap: number[] = [];
  const n = text.length;
  let i = 0;
  let previousBaseAlpha: boolean | null = null;
  // Python 은 코드 포인트 단위로 순회한다 — 아스트랄 숫자(𝟗 등)도 폴딩되도록 코드 포인트로 돈다.
  while (i < n) {
    const ch = cpAt(text, i);
    if (INVISIBLE.test(ch)) {
      i += ch.length;
      continue;
    }
    // L+V(+T) 또는 LV+T 를 한 음절로 합성 (Unicode 3.12). 자모 단어 전체를 한 offset 으로
    // 매핑하면 접미 경계가 0길이 검출이 되어 원본 이름이 남을 수 있다.
    const j = normalizationClusterEnd(text, i);
    const cluster = text.slice(i, j).normalize("NFKC");
    if (previousBaseAlpha === false) {
      let allNoise = true;
      for (const c of cluster) {
        if (!isConjoiningJamo(c) && !hasCombiningClass(c)) {
          allNoise = false;
          break;
        }
      }
      if (allNoise) {
        // 숫자 잡음 처리는 유지하되 실제 음절은 버리지 않는다.
        i = j;
        continue;
      }
    }
    const baseIsAlpha = pyIsAlpha(ch);
    for (const fc of cluster) {
      // 숫자/기호 베이스에 남는 결합표시·조합용 자모('9001ᄀ01' 우회)는 제거.
      if (!baseIsAlpha && (hasCombiningClass(fc) || isConjoiningJamo(fc))) {
        continue;
      }
      const folded = CHAR_FOLD.get(fc) ?? fc;
      out.push(folded);
      // offsetMap 은 출력 UTF-16 유닛마다 한 칸 (아스트랄 출력은 2유닛).
      for (let k = 0; k < folded.length; k++) omap.push(i);
    }
    previousBaseAlpha = baseIsAlpha;
    i = j;
  }
  const normalized = out.join("");
  return foldNumeric ? foldNumericText(normalized, omap) : [normalized, omap];
}

/** Python ``bisect_right``. */
function bisectRight(arr: readonly number[], x: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (x < (arr[mid] as number)) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

/** 정규화 텍스트 기준 offset 을 원본 기준으로 역매핑 + .text 원본 복원 (normalized=true). */
export function remapToSource(
  detections: DetectionResult[],
  offsetMap: number[],
  source: string,
): DetectionResult[] {
  const n = offsetMap.length;
  return detections.map((det) => {
    const start = det.start < n ? (offsetMap[det.start] as number) : det.start;
    let end: number;
    // 호환 확장(ﬁ→fi 등) 안에서 끝나는 매치는 원본 글자를 통째로 덮어야 한다.
    if (det.start < det.end && det.end > 0 && det.end <= n) {
      const following = bisectRight(offsetMap, offsetMap[det.end - 1] as number);
      end = following < n ? (offsetMap[following] as number) : source.length;
    } else if (det.end < n) end = offsetMap[det.end] as number;
    else if (det.end === n) end = source.length;
    else end = det.end;
    return { ...det, start, end, text: source.slice(start, end), normalized: true };
  });
}
