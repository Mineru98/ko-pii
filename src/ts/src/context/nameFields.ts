/**
 * 경계가 분명한 이름 필드 문법 — 후보 선택과 채점이 공유한다.
 * Python ko_pii.context.name_fields 대응.
 *
 * 포팅 메모:
 * - Python 조건부 그룹 ``(?(square)\])`` 은 JS 에 없어 래퍼별 대안으로 펼친다. 같은
 *   언어를 받아들이며 대안 순서(래퍼 → 무래퍼)도 Python 의 greedy optional 과 같다.
 * - Python 유니코드 ``\w`` 는 ``[\p{L}\p{N}_]`` (u 플래그) 로 근사한다.
 * - ``search(text, begin, end)`` 의 endpos 는 ``text.slice(0, end)`` + ``$`` 로 재현한다
 *   (lookbehind 는 begin 앞도 본다 — Python 과 동일).
 */
import { cpIndexBefore, regexEscape } from "../core/strUtils.js";
import {
  FIELD_BOUNDARY_LABELS,
  FIELD_LABELS_NAME,
} from "../dictionaries/generated/field_labels.js";
import { ENGLISH_SUBJECTS, KOREAN_SUBJECTS } from "../dictionaries/generated/table_headers.js";

export const PERSON_NAME_LABELS: ReadonlySet<string> = new Set(["성명", "성함"]);
const LINE_BREAK_CHARS = "\r\n\v\f\x1c\x1d\x1e\x85  ";
const OPENING_QUOTES = "\"'“‘「『";
const CLOSING_QUOTES = "\"'”’」』";

/** 문자 클래스 본문용 이스케이프 (u 플래그 안전). */
function classEscape(chars: string): string {
  let out = "";
  for (const ch of chars) {
    const cp = ch.codePointAt(0) as number;
    if (/[\\\][^-]/.test(ch)) out += `\\${ch}`;
    else if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || cp === 0x2028 || cp === 0x2029) {
      out += `\\u${cp.toString(16).padStart(4, "0")}`;
    } else out += ch;
  }
  return out;
}

const GAP = `[${classEscape(` \t${LINE_BREAK_CHARS}`)}]`;
const PY_WORD = "[\\p{L}\\p{N}_]";

/** Python sorted(key=(-len, value)) — 길이(코드 포인트) 내림차순, 동률은 코드 포인트 순. */
function byLengthThenValue(values: Iterable<string>): string[] {
  return [...values].sort((a, b) => {
    const d = [...b].length - [...a].length;
    if (d !== 0) return d;
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function labelsPattern(labels: Iterable<string>): string {
  const canonical = new Set([...labels].map((label) => label.replaceAll(" ", "")));
  return byLengthThenValue(canonical)
    .map((label) => [...label].map((ch) => regexEscape(ch)).join("[ \\t]*"))
    .join("|");
}

const WRAPPERS: ReadonlyArray<readonly [string, string]> = [
  ["\\[", "\\]"],
  ["【", "】"],
  ["\\*\\*", "\\*\\*"],
  ["__", "__"],
  ["`", "`"],
];

/** 래퍼별로 펼친 라벨 접두 (라벨은 그룹 l0..l5 중 하나). */
function labelPrefix(labels: Iterable<string>): string {
  const body = `(?:${labelsPattern(labels)})`;
  const annotation = "(?:[ \\t]*\\((?:한글|국문|실명|영문|영어|한자)\\))?";
  const alts = WRAPPERS.map(([open, close], i) => `${open}(?<l${i}>${body})${annotation}${close}`);
  alts.push(`(?<l5>${body})${annotation}`);
  return `(?<!${PY_WORD})(?:${alts.join("|")})(?:[ \\t]*[:：=|]${GAP}*|${GAP}+)`;
}

function labelOf(groups: Record<string, string | undefined> | undefined): string {
  for (let i = 0; i <= 5; i++) {
    const v = groups?.[`l${i}`];
    if (v !== undefined) return v.replaceAll(" ", "").replaceAll("\t", "");
  }
  return "";
}

const LABEL_BEFORE = new RegExp(
  `${labelPrefix(FIELD_LABELS_NAME)}(?:\\*\\*|__|\`|[${classEscape(OPENING_QUOTES)}])?$`,
  "gu",
);
const STRONG_FIELD = new RegExp(labelPrefix(PERSON_NAME_LABELS), "gu");
const VALUE_END = new RegExp(
  ` *$| *(?=[${classEscape(`${LINE_BREAK_CHARS}\t,;|/&().[]{}-·*_\`${CLOSING_QUOTES}`)}])`,
  "uy",
);
const ANNOTATION = ` *\\([^${classEscape(`()\t${LINE_BREAK_CHARS}`)}]{0,32}\\)`;
const SUBJECT =
  `(?:(?:${KOREAN_SUBJECTS.map(regexEscape).join("|")})[ _-]*` +
  `|(?:${ENGLISH_SUBJECTS.map(regexEscape).join("|")})[ _-]+)`;
const BOUNDARY = `(?:${labelsPattern(FIELD_BOUNDARY_LABELS)})`;
// Python 의 조건부 그룹: 주체(subject)는 여는 래퍼 앞 또는 뒤 중 한 곳에만, 설명(annotation)은
// 닫는 래퍼 앞 또는 뒤 중 한 곳에만 올 수 있다. 불리언 판정만 쓰므로 같은 언어로 펼친다.
const NEXT_FIELD = new RegExp(
  ` +(?:${[
    `(?:${SUBJECT})?${BOUNDARY}(?:${ANNOTATION})?`,
    ...WRAPPERS.map(
      ([open, close]) =>
        `(?:${SUBJECT}${open}|${open}(?:${SUBJECT})?)${BOUNDARY}` +
        `(?:${ANNOTATION}${close}|${close}(?:${ANNOTATION})?)`,
    ),
  ].join("|")})[ \\t]*[:：=]`,
  "iuy",
);
const LABEL_ENDINGS: ReadonlySet<string> = new Set([
  ...[...FIELD_LABELS_NAME].map((label) => [...label].at(-1) as string),
  ")",
  "]",
  "】",
  "*",
  "_",
  "`",
]);
const LIST_SEPARATOR = new RegExp(
  `^[ \\t]*(?:(?:\\*\\*|__|\`|[${classEscape(CLOSING_QUOTES)}])[ \\t]*)?` +
    `[,/&·-][ \\t]*(?:(?:\\*\\*|__|\`|[${classEscape(OPENING_QUOTES)}])[ \\t]*)?$`,
  "u",
);
const ROLE_LABELS = [...FIELD_LABELS_NAME].filter((label) => label !== "참조");
const ROLE_BEFORE = new RegExp(
  `(?<![가-힣A-Za-z0-9_])(?<label>(?:${labelsPattern(ROLE_LABELS)}))(?:은|는|이|가|인)[ \\t]+$`,
  "gu",
);

const RSTRIP_CHARS: ReadonlySet<string> = new Set([
  ..." \t:：=|*_`",
  ...OPENING_QUOTES,
  ...LINE_BREAK_CHARS,
]);

/** 결합표시(M)는 Python ``\w`` 밖이지만 앞 단어에 속한다 — 그 뒤는 라벨 경계가 아니다. */
function labelBoundary(text: string, start: number): boolean {
  if (start === 0) return true;
  let prev = text.slice(start - 1, start);
  const lo = prev.charCodeAt(0);
  if (lo >= 0xdc00 && lo <= 0xdfff && start >= 2) {
    const hi = text.charCodeAt(start - 2);
    if (hi >= 0xd800 && hi <= 0xdbff) prev = text.slice(start - 2, start);
  }
  return !/^\p{M}$/u.test(prev);
}

/** Python ``pattern.search(text, pos, endpos)``. */
function searchBounded(pattern: RegExp, text: string, pos: number, endpos: number) {
  pattern.lastIndex = pos;
  return pattern.exec(text.slice(0, endpos));
}

export function nameFieldBefore(text: string, start: number, window = 6): string | null {
  const begin = cpIndexBefore(text, start, Math.max(window + 4, 32));
  let headEnd = start;
  while (headEnd > begin && RSTRIP_CHARS.has(text[headEnd - 1] as string)) headEnd -= 1;
  if (headEnd === begin || !LABEL_ENDINGS.has(text[headEnd - 1] as string)) return null;
  const match = searchBounded(LABEL_BEFORE, text, begin, start);
  if (match === null || !labelBoundary(text, match.index)) return null;
  return labelOf(match.groups);
}

export function boundedNameValueEnd(text: string, end: number): boolean {
  VALUE_END.lastIndex = end;
  if (VALUE_END.test(text)) return true;
  return nextFieldAfterName(text, end);
}

/** ``(값 시작 위치, 라벨)`` 목록 — 사람 전용 강한 필드(성명/성함). */
export function strongNameFieldStarts(text: string): Array<[number, string]> {
  const out: Array<[number, string]> = [];
  for (const match of text.matchAll(STRONG_FIELD)) {
    if (labelBoundary(text, match.index)) {
      out.push([match.index + match[0].length, labelOf(match.groups)]);
    }
  }
  return out;
}

export function nextFieldAfterName(text: string, end: number): boolean {
  NEXT_FIELD.lastIndex = end;
  return NEXT_FIELD.test(text);
}

/** 목록 문맥은 한 셀/줄 안에만 머문다 — 임의 산문을 넘지 않는다. */
export function nameListSeparator(text: string, start: number, end: number): boolean {
  return LIST_SEPARATOR.test(text.slice(start, end));
}

/** 산문의 사람 역할 표현 — 리터럴 필드로 취급하지 않는다. */
export function nameRoleBefore(text: string, start: number): string | null {
  const begin = cpIndexBefore(text, start, 32);
  let headEnd = start;
  while (headEnd > begin && (text[headEnd - 1] === " " || text[headEnd - 1] === "\t")) headEnd -= 1;
  const last = headEnd > begin ? (text[headEnd - 1] as string) : "";
  if (!["은", "는", "이", "가", "인"].includes(last)) return null;
  const match = searchBounded(ROLE_BEFORE, text, begin, start);
  if (match === null) return null;
  return (match.groups?.label ?? "").replaceAll(" ", "").replaceAll("\t", "");
}
