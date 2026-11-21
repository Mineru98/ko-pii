/**
 * Python 문자열 판정 함수의 TS 근사 — PORTING.md 컨벤션의 일부.
 *
 * 의도적 단순화: ko-pii 코드베이스에서 이 판정들은 정규화 이후 ASCII
 * (숫자/영문) 또는 단일 BMP 문자에만 적용되므로, 유니코드 전체 Python 의미론
 * 대신 아래 정의로 충분하다. 골드 마스터 회귀가 차이를 잡는다.
 */

/*
 * Python ``re`` (str 패턴) 의 유니코드 문자 클래스 — 반드시 ``u`` 플래그와 함께 쓴다.
 *
 * 원문 재검사 패스(detect.ts)는 정규화로 숫자가 접히지 않은 텍스트를 본다. 그래서 원본이
 * ``\d``/``\s``/``\w`` 를 쓴 자리는 ASCII 근사가 아니라 이 의미를 그대로 옮겨야 한다.
 * ``*_CHARS`` 는 문자 클래스 안에 끼워 넣는 용도 (예: ``[-.${PY_S_CHARS}]``).
 */
/** ``\d`` — 유니코드 Nd. */
export const PY_D = String.raw`\p{Nd}`;
/** ``\D``. */
export const PY_ND = String.raw`\P{Nd}`;
/** ``\s`` 의 문자 집합 (= ``str.isspace()``). JS ``\s`` 와 달리 U+001C~U+001F·U+0085 포함, U+FEFF 제외. */
export const PY_S_CHARS = String.raw`\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000`;
/** ``\s``. */
export const PY_S = `[${PY_S_CHARS}]`;
/** ``\S``. */
export const PY_NS = `[^${PY_S_CHARS}]`;
/** ``\w`` 의 문자 집합 (= ``str.isalnum()`` + ``_``, Unicode 15 전 범위 대조로 일치). */
export const PY_W_CHARS = String.raw`\p{L}\p{N}_`;
/** ``\w``. */
export const PY_W = `[${PY_W_CHARS}]`;
/** ``\W``. */
export const PY_NW = `[^${PY_W_CHARS}]`;

const PY_STRIP_RE = new RegExp(`^${PY_S}+|${PY_S}+$`, "gu");
const PY_WS_RUN = new RegExp(`${PY_S}+`, "u");

/** Python ``str.strip()`` (인자 없음) — 공백 집합은 ``\s`` 와 같다 (JS ``trim()`` 과 다름). */
export function pyStrip(s: string): string {
  return s.replace(PY_STRIP_RE, "");
}

/** Python ``str.split()`` (인자 없음) — 공백 런으로 나누고 빈 조각은 버린다. */
export function pySplitWs(s: string): string[] {
  return s.split(PY_WS_RUN).filter((part) => part !== "");
}

const ND_CHAR = /^\p{Nd}$/u;

/** Nd 한 글자의 자릿값 (Python ``unicodedata.decimal``). Nd 가 아니면 -1. */
export function ndDigitValue(ch: string): number {
  const cp = ch.codePointAt(0);
  if (cp === undefined || !ND_CHAR.test(ch)) return -1;
  if (cp < 0x80) return cp - 0x30;
  // Nd 는 값 0..9 묶음으로 정의되고 묶음 시작은 연속 실행 시작에서 10 의 배수만큼 떨어져
  // 있다 (수학 숫자 U+1D7CE..U+1D7FF 처럼 묶음 5개가 붙은 블록 포함).
  let start = cp;
  while (start > 0 && ND_CHAR.test(String.fromCodePoint(start - 1))) start -= 1;
  return (cp - start) % 10;
}

/** Nd 숫자를 ASCII 숫자로 접은 문자열 (Python ``int()``/``float()`` 파싱 전처리). */
export function foldNdDigits(s: string): string {
  if (pyIsAscii(s)) return s;
  let folded = "";
  for (const ch of s) {
    const v = ndDigitValue(ch);
    folded += v >= 0 ? String(v) : ch;
  }
  return folded;
}

/** Python ``int(s)``/``float(s)`` 의 Nd 숫자열 파싱 대응 — 비ASCII 십진 숫자도 값으로 읽는다. */
export function ndToNumber(s: string): number {
  return Number(foldNdDigits(s));
}

/** Python str.isdigit() 근사 — Nd (십진 숫자) 클래스. 전각 포함, 위첨자(No) 제외. */
export function pyIsDigit(ch: string): boolean {
  return /^[\p{Nd}]$/u.test(ch);
}

/** 문자열 전체가 (근사) digit 인지. */
export function pyIsAllDigits(s: string): boolean {
  return s.length > 0 && /^[\p{Nd}]+$/u.test(s);
}

/** Python str.isalpha() 근사 — 단일 문자 기준. */
export function pyIsAlpha(ch: string): boolean {
  return /^\p{L}$/u.test(ch);
}

/** Python str.isascii() 근사. */
export function pyIsAscii(s: string): boolean {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: ASCII 범위 검사가 목적
  return /^[\x00-\x7F]*$/.test(s);
}

/** Python re.escape() 대응 — 정규식 메타문자 이스케이프. */
export function regexEscape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Python `len(str)` — 코드 포인트 수 (서로게이트 쌍은 1로 센다). */
export function codePointLength(text: string): number {
  let n = text.length;
  for (let i = 0; i < text.length - 1; i++) {
    const hi = text.charCodeAt(i);
    if (hi >= 0xd800 && hi <= 0xdbff) {
      const lo = text.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        n -= 1;
        i += 1;
      }
    }
  }
  return n;
}

/** Python ``s[start:end]`` 대응 — 코드 포인트 단위 슬라이스 (음수 인덱스 포함). */
export function cpSlice(s: string, start?: number, end?: number): string {
  return [...s].slice(start, end).join("");
}

/**
 * Python ``d.end - d.start`` — 코드 포인트 span 길이. 겹침 해소의 "긴 span 우선" 동률 깨기가
 * 아스트랄 문자(수학 숫자·이모지)가 든 span 에서 Python 과 같은 순서를 내도록 쓴다.
 */
export function pySpanLength(d: {
  readonly start: number;
  readonly end: number;
  readonly text: string;
}): number {
  const units = d.end - d.start;
  return d.text.length === units && /[\uD800-\uDBFF]/.test(d.text)
    ? codePointLength(d.text)
    : units;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

/** UTF-16 인덱스 ``pos`` 에서 코드 포인트 ``n`` 개 앞의 UTF-16 인덱스 (0 에서 멈춤). */
export function cpIndexBefore(text: string, pos: number, n: number): number {
  let i = pos;
  for (let k = 0; k < n && i > 0; k++) {
    i -=
      i >= 2 && isLowSurrogate(text.charCodeAt(i - 1)) && isHighSurrogate(text.charCodeAt(i - 2))
        ? 2
        : 1;
  }
  return i;
}

/** UTF-16 인덱스 ``pos`` 에서 코드 포인트 ``n`` 개 뒤의 UTF-16 인덱스 (끝에서 멈춤). */
export function cpIndexAfter(text: string, pos: number, n: number): number {
  let i = pos;
  for (let k = 0; k < n && i < text.length; k++) {
    i +=
      i + 1 < text.length &&
      isHighSurrogate(text.charCodeAt(i)) &&
      isLowSurrogate(text.charCodeAt(i + 1))
        ? 2
        : 1;
  }
  return i;
}

/**
 * Python ``text[max(0, start - n):start]`` — 창 너비는 코드 포인트 (``start`` 는 UTF-16 인덱스).
 * 원문 재검사 패스는 아스트랄 Nd(수학 숫자 등)를 숫자로 매칭하므로 키워드 창도 Python 처럼
 * 코드 포인트로 재야 같은 범위를 본다.
 */
export function cpWindowBefore(text: string, start: number, n: number): string {
  return text.slice(cpIndexBefore(text, start, n), start);
}

/** Python ``text[end:end + n]`` — 창 너비는 코드 포인트. */
export function cpWindowAfter(text: string, end: number, n: number): string {
  return text.slice(end, cpIndexAfter(text, end, n));
}

/** Python `type(value).__name__` 대응 (에러 메시지 호환). */
export function pyTypeName(value: unknown): string {
  if (value === null) return "NoneType";
  if (Array.isArray(value)) return "list";
  if (value instanceof Uint8Array) return "bytes";
  switch (typeof value) {
    case "string":
      return "str";
    case "boolean":
      return "bool";
    case "number":
      return Number.isInteger(value) ? "int" : "float";
    case "bigint":
      return "int";
    case "object":
      return "dict";
    default:
      return typeof value;
  }
}
