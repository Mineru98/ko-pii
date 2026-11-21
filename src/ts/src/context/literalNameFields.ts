/**
 * 사람 전용 필드의 이름 형태 값 — 범용 다국어 NER 이 아니다.
 * Python ko_pii.context.literal_name_fields 대응.
 *
 * 위치는 UTF-16 인덱스지만 순회·길이 판정은 Python 과 같이 코드 포인트 단위다
 * (아스트랄 한자 이름 등에서도 MAX_NAME_CHARS·조각 길이가 Python 과 일치).
 */
import { ValueError } from "../core/errors.js";
import { isSurname } from "../dictionaries/surnames.js";
import { nextFieldAfterName, strongNameFieldStarts } from "./nameFields.js";
import { PARTICLES, stripTrailingParticle } from "./particles.js";

export const MAX_NAME_CHARS = 128;
export const COPULA_ENDINGS: readonly string[] = [
  "이라고",
  "이라는",
  "입니다",
  "이며",
  "이고",
  "이라",
];
const ENDING = new RegExp(
  [...new Set([...PARTICLES, ...COPULA_ENDINGS])]
    .sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0))
    .join("|"),
  "y",
);
const EMPTY = /(?:n\/a|n\.a\.|na|null|none)/iy;
const WRAPPERS: ReadonlyArray<readonly [string, string]> = [
  ["**", "**"],
  ["__", "__"],
  ["`", "`"],
  ['"', '"'],
  ["'", "'"],
  ["“", "”"],
  ["‘", "’"],
  ["「", "」"],
  ["『", "』"],
];
const SEPARATORS: ReadonlySet<string> = new Set([...",/&·-"]);
const VALUE_END: ReadonlySet<string> = new Set([
  ..."\r\n\v\f\x1c\x1d\x1e\x85  \t,;|/&·-().[]{}!?“”‘’「」『』\"'",
]);

// unicodedata.name(ch) 가 "HANGUL" 또는 "CJK " 로 시작하는 코드 포인트 (Python 3.12 / Unicode 15.0 생성).
const EAST_ASIAN_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x1100, 0x11ff],
  [0x2e80, 0x2e99],
  [0x2e9b, 0x2ef3],
  [0x302e, 0x302f],
  [0x3131, 0x318e],
  [0x31c0, 0x31e3],
  [0x3400, 0x4dbf],
  [0x4e00, 0x9fff],
  [0xa960, 0xa97c],
  [0xac00, 0xd7a3],
  [0xd7b0, 0xd7c6],
  [0xd7cb, 0xd7fb],
  [0xf900, 0xfa6d],
  [0xfa70, 0xfad9],
  [0x20000, 0x2a6df],
  [0x2a700, 0x2b739],
  [0x2b740, 0x2b81d],
  [0x2b820, 0x2cea1],
  [0x2ceb0, 0x2ebe0],
  [0x2f800, 0x2fa1d],
  [0x30000, 0x3134a],
  [0x31350, 0x323af],
];

export interface LiteralName {
  name: string;
  start: number;
  end: number;
  label: string;
  parenthetical: boolean;
  ending: string | null;
  legacy: boolean;
}

/** pos 의 코드 포인트 (아스트랄은 2유닛, 범위 밖은 ""). */
function cpAt(text: string, pos: number): string {
  if (pos < 0 || pos >= text.length) return "";
  const cp = text.codePointAt(pos) as number;
  return cp > 0xffff ? text.slice(pos, pos + 2) : text.charAt(pos);
}

/** pos 바로 앞 코드 포인트. */
function cpBefore(text: string, pos: number): string {
  if (pos <= 0) return "";
  const lo = text.charCodeAt(pos - 1);
  if (lo >= 0xdc00 && lo <= 0xdfff && pos >= 2) {
    const hi = text.charCodeAt(pos - 2);
    if (hi >= 0xd800 && hi <= 0xdbff) return text.slice(pos - 2, pos);
  }
  return text.charAt(pos - 1);
}

function cpCount(s: string): number {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

const isLetter = (ch: string): boolean => /^\p{L}$/u.test(ch);
const isNameChar = (ch: string): boolean => /^[\p{L}\p{M}]$/u.test(ch);
/** Python ``ch == "_" or ch.isalnum() or _name_char(ch)``. */
const isWordChar = (ch: string): boolean => /^[\p{L}\p{M}\p{N}_]$/u.test(ch);

function isHangul(value: string): boolean {
  if (!value) return false;
  for (const ch of value.normalize("NFC")) {
    if (ch < "가" || ch > "힣") return false;
  }
  return true;
}

function isEastAsian(ch: string): boolean {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return false;
  return EAST_ASIAN_RANGES.some(([a, b]) => cp >= a && cp <= b);
}

function horizontal(text: string, position: number): number {
  let p = position;
  while (p < text.length && text[p] === " ") p += 1;
  return p;
}

/** start 에서 n 코드 포인트 전진한 UTF-16 위치 (문자열 끝을 넘으면 남은 수만큼 가상 연장). */
function advance(text: string, start: number, n: number): number {
  let p = start;
  let k = 0;
  while (k < n && p < text.length) {
    p += cpAt(text, p).length;
    k += 1;
  }
  return p + (n - k);
}

function atEnd(text: string, position: number, close: string | null): boolean {
  const tail = horizontal(text, position);
  return (
    tail === text.length ||
    (close !== null && text.startsWith(close, tail)) ||
    (tail < text.length && VALUE_END.has(text[tail] as string)) ||
    nextFieldAfterName(text, position)
  );
}

function wordEnd(text: string, start: number, limit: number): number {
  if (start >= text.length || !isLetter(cpAt(text, start))) return start;
  let position = start;
  let pieceStart = start;
  const bound = Math.min(text.length, limit);
  while (position < bound) {
    const ch = cpAt(text, position);
    const next = cpAt(text, position + ch.length);
    if (isNameChar(ch)) {
      position += ch.length;
    } else if ("-'’·".includes(ch) && next !== "" && isLetter(next)) {
      if (isEastAsian(cpBefore(text, position)) || isEastAsian(next)) break;
      pieceStart = position + 1;
      position += 1;
    } else if (
      ch === "." &&
      (cpCount(text.slice(pieceStart, position)) === 1 ||
        ["jr", "sr"].includes(text.slice(pieceStart, position).toLowerCase()))
    ) {
      position += 1;
      pieceStart = position;
    } else {
      break;
    }
  }
  return position;
}

type Component = [LiteralName | null, number] | null;

function component(
  text: string,
  position: number,
  label: string,
  parenthetical = false,
): Component {
  const wrapper = WRAPPERS.find(([open]) => text.startsWith(open, position));
  const close = wrapper ? wrapper[1] : null;
  let start = position + (wrapper ? wrapper[0].length : 0);
  if (wrapper) start = horizontal(text, start);
  const limit = advance(text, start, MAX_NAME_CHARS);
  EMPTY.lastIndex = start;
  const empty = EMPTY.exec(text);
  if (empty !== null && atEnd(text, start + empty[0].length, close)) {
    let end = start + empty[0].length;
    if (close !== null) {
      const closing = horizontal(text, end);
      if (!text.startsWith(close, closing)) return null;
      end = closing + close.length;
    }
    return [null, end];
  }
  const words: string[] = [];
  let cursor = start;
  let end: number;
  for (;;) {
    end = wordEnd(text, cursor, limit);
    if (end === cursor) return null;
    words.push(text.slice(cursor, end));
    if (end === limit && end < text.length && !atEnd(text, end, close)) {
      const ch = cpAt(text, end);
      if (isNameChar(ch) || " -'’·".includes(ch)) return null;
    }
    if (atEnd(text, end, close)) break;
    const following = horizontal(text, end);
    if (following === end || following >= limit) return null;
    cursor = following;
  }
  let consumed = end;
  const closing = horizontal(text, end);
  const quoted = close !== null && text.startsWith(close, closing);
  if (close !== null) {
    if (!quoted) return null;
    consumed = closing + close.length;
  }
  if (words.every(isHangul) && words.length > 1 && !quoted) {
    if (words.length !== 2 || !isSurname((words[0] as string).normalize("NFC"))) return null;
  }
  let value = text.slice(start, end);
  let ending: string | null = null;
  if (isHangul(value) && value.length > 4) {
    ending =
      COPULA_ENDINGS.find(
        (suffix) => value.endsWith(suffix) && value.length - suffix.length >= 2,
      ) ?? null;
    if (ending !== null) {
      end -= ending.length;
      value = text.slice(start, end);
    } else {
      const [stem, particle] = stripTrailingParticle(value);
      if (particle !== null && particle.length > 1 && stem.length >= 2 && stem.length <= 4) {
        return [
          {
            name: stem,
            start,
            end: start + stem.length,
            label,
            parenthetical,
            ending: particle,
            legacy: true,
          },
          consumed,
        ];
      }
    }
  }
  const legacy = isHangul(value) && value.length >= 2 && value.length <= 4 && !parenthetical;
  return [{ name: value, start, end, label, parenthetical, ending, legacy }, consumed];
}

export function literalNameFields(text: string): LiteralName[] {
  const out: LiteralName[] = [];
  for (const [fieldStart, label] of strongNameFieldStarts(text)) {
    let position = fieldStart;
    const fieldValues: LiteralName[] = [];
    while (position < text.length) {
      const parsed = component(text, position, label);
      if (parsed === null) break;
      const [candidate, next] = parsed;
      position = next;
      if (candidate !== null) fieldValues.push(candidate);
      let after = horizontal(text, position);
      if (after < text.length && text[after] === "(") {
        const child = component(text, after + 1, label, true);
        if (child !== null) {
          const [alternative, childEnd] = child;
          const end = horizontal(text, childEnd);
          if (end < text.length && text[end] === ")") {
            if (alternative !== null) fieldValues.push(alternative);
            after = horizontal(text, end + 1);
          }
        }
      }
      if (after >= text.length || !SEPARATORS.has(text[after] as string)) break;
      position = horizontal(text, after + 1);
    }
    if (fieldValues.some((candidate) => !candidate.legacy)) out.push(...fieldValues);
  }
  return out;
}

interface TrieNode {
  children: Map<string, TrieNode>;
  terminal: boolean;
}

/** 확인된 값의 같은 문서 내 반복 표기 — ``[start, end, ending]`` (단어 경계 검사). */
export function literalNameMentions(
  text: string,
  names: Iterable<string>,
): Array<[number, number, string | null]> {
  const values = new Set(names);
  const out: Array<[number, number, string | null]> = [];
  if (values.size === 0) return out;
  const root: TrieNode = { children: new Map(), terminal: false };
  for (const name of values) {
    if (!name || cpCount(name) > MAX_NAME_CHARS) {
      throw new ValueError("literal name is outside the supported field bound");
    }
    let node = root;
    for (const ch of name) {
      let child = node.children.get(ch);
      if (child === undefined) {
        child = { children: new Map(), terminal: false };
        node.children.set(ch, child);
      }
      node = child;
    }
    node.terminal = true;
  }
  for (let start = 0; start < text.length; ) {
    const first = cpAt(text, start);
    const step = first.length;
    if (!root.children.has(first) || (start > 0 && isWordChar(cpBefore(text, start)))) {
      start += step;
      continue;
    }
    let node = root;
    let best: [number, number, string | null] | null = null;
    let position = start;
    for (let k = 0; k < MAX_NAME_CHARS && position < text.length; k++) {
      const ch = cpAt(text, position);
      const child = node.children.get(ch);
      if (child === undefined) break;
      node = child;
      const end = position + ch.length;
      position = end;
      if (!node.terminal) continue;
      if (end === text.length || !isWordChar(cpAt(text, end))) {
        best = [start, end, null];
      } else {
        ENDING.lastIndex = end;
        const ending = ENDING.exec(text);
        if (ending !== null) {
          const endingEnd = end + ending[0].length;
          if (endingEnd === text.length || !isWordChar(cpAt(text, endingEnd))) {
            best = [start, end, ending[0]];
          }
        }
      }
    }
    if (best !== null) out.push(best);
    start += step;
  }
  return out;
}
