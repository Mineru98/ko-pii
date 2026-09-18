/** 한국어 이름 ↔ 로마자 (Revised Romanization) — Python ko_pii.context.romanization 대응.
 *
 * 표준: 「국어의 로마자 표기법」 (문화체육관광부 고시 제2014-42호).
 *
 * 본 모듈은 *이름 검출 보조* 가 목적이라 풀-스펙 RR 변환은 아님 — 한국어 이름의
 * *초성·중성·종성 매핑* 만 정확하면 됨.
 *
 * 용도:
 * - 가명화 vault 에서 "홍길동" 과 "Hong Gildong" 을 *같은 사람* 으로 묶기
 * - 외국어 보고서의 한국 인명 검출
 *
 * API:
 * - `romanizeName(hangul)` — "홍길동" → "Hong Gildong"
 * - `alternativeRomanizations(hangul)` — 변형 표기 후보 ["Hong Gildong",
 *   "Hong Gil-dong", "Hong Gil Dong", "HONG Gildong", ...]
 */
import { surnamePrefixLen } from "../dictionaries/index.js";

// 초성 (19)
const INITIAL: readonly string[] = [
  "g",
  "kk",
  "n",
  "d",
  "tt",
  "r",
  "m",
  "b",
  "pp",
  "s",
  "ss",
  "",
  "j",
  "jj",
  "ch",
  "k",
  "t",
  "p",
  "h",
];
// 중성 (21)
const MEDIAL: readonly string[] = [
  "a",
  "ae",
  "ya",
  "yae",
  "eo",
  "e",
  "yeo",
  "ye",
  "o",
  "wa",
  "wae",
  "oe",
  "yo",
  "u",
  "wo",
  "we",
  "wi",
  "yu",
  "eu",
  "ui",
  "i",
];
// 종성 (28) — Unicode Hangul Jamo 순서 (RR 간이 매핑, 단어 끝 기준)
//  0:없음   1:ㄱ    2:ㄲ    3:ㄳ    4:ㄴ    5:ㄵ    6:ㄶ
//  7:ㄷ     8:ㄹ    9:ㄺ   10:ㄻ   11:ㄼ   12:ㄽ   13:ㄾ
// 14:ㄿ    15:ㅀ   16:ㅁ   17:ㅂ   18:ㅄ   19:ㅅ   20:ㅆ
// 21:ㅇ    22:ㅈ   23:ㅊ   24:ㅋ   25:ㅌ   26:ㅍ   27:ㅎ
const FINAL: readonly string[] = [
  "",
  "k",
  "kk",
  "ks",
  "n",
  "nj",
  "nh",
  "t",
  "l",
  "lk",
  "lm",
  "lp",
  "ls",
  "lt",
  "lp",
  "lh",
  "m",
  "p",
  "ps",
  "t",
  "tt",
  "ng",
  "j",
  "ch",
  "k",
  "t",
  "p",
  "h",
];

function romanizeSyllable(ch: string): string {
  // Decompose a single Hangul syllable into 초성+중성+종성 → roman.
  const code0 = ch.charCodeAt(0);
  if (code0 === undefined || code0 < 0xac00 || code0 > 0xd7a3) {
    return ch;
  }
  const code = code0 - 0xac00;
  const initialIdx = Math.floor(code / (21 * 28));
  const medialIdx = Math.floor((code % (21 * 28)) / 28);
  const finalIdx = code % 28;
  return (INITIAL[initialIdx] ?? "") + (MEDIAL[medialIdx] ?? "") + (FINAL[finalIdx] ?? "");
}

function capitalize(s: string): string {
  return s ? s.slice(0, 1).toUpperCase() + s.slice(1) : s;
}

/** Python `"a b".split()` 동등 — 연속 공백을 하나로 묶고 앞뒤 공백을 버린다. */
function pySplitWords(s: string): string[] {
  const trimmed = s.trim();
  if (!trimmed) {
    return [];
  }
  return trimmed.split(/\s+/);
}

/** 한글 이름을 로마자 표기로 변환 (성 한 글자 + 이름).
 *
 *     romanizeName("홍길동")   // "Hong Gildong"
 *     romanizeName("남궁민수") // "Namgung Minsu"
 */
export function romanizeName(hangul: string): string {
  const sp = surnamePrefixLen(hangul);
  if (sp === 0) {
    // surname 미상 — 단순 음절 단위 변환
    return Array.from(hangul, (c) => capitalize(romanizeSyllable(c))).join(" ");
  }
  const surname = hangul.slice(0, sp);
  const given = hangul.slice(sp);
  const surnameRoman = Array.from(surname, (c) => romanizeSyllable(c)).join("");
  const givenRoman = Array.from(given, (c) => romanizeSyllable(c)).join("");
  return `${capitalize(surnameRoman)} ${capitalize(givenRoman)}`;
}

/** 같은 이름의 다양한 로마자 표기 변형들을 반환.
 *
 * 실무에서 "Hong Gildong" / "Hong Gil-dong" / "Hong Gil Dong" / "GILDONG HONG"
 * 같이 표기 차이가 흔함 → 모두 같은 사람으로 묶기 위한 후보 리스트.
 */
export function alternativeRomanizations(hangul: string): string[] {
  const base = romanizeName(hangul);
  const parts = pySplitWords(base);
  if (parts.length !== 2) {
    return [base];
  }
  const surname = parts[0] as string;
  const given = parts[1] as string;
  // given 을 음절 단위로 분리
  const sp = surnamePrefixLen(hangul);
  const givenSyllables = Array.from(hangul.slice(sp), (c) => capitalize(romanizeSyllable(c)));
  const givenHyphen = givenSyllables.join("-"); // Gil-dong
  const givenSpace = givenSyllables.join(" "); // Gil dong
  const alts: string[] = [];
  const seen: Set<string> = new Set();
  const add = (s: string): void => {
    if (!seen.has(s)) {
      seen.add(s);
      alts.push(s);
    }
  };
  add(base); // Hong Gildong
  add(`${surname} ${givenHyphen}`); // Hong Gil-dong
  add(`${surname} ${givenSpace}`); // Hong Gil dong
  add(`${surname.toUpperCase()} ${given}`); // HONG Gildong (성 대문자)
  add(`${given} ${surname}`); // Gildong Hong (Western order)
  add(`${surname},${given}`); // Hong,Gildong (CSV form)
  add(base.toLowerCase());
  add(base.toUpperCase());
  return alts;
}
