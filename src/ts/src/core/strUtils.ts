/**
 * Python 문자열 판정 함수의 TS 근사 — PORTING.md 컨벤션의 일부.
 *
 * 의도적 단순화: ko-pii 코드베이스에서 이 판정들은 정규화 이후 ASCII
 * (숫자/영문) 또는 단일 BMP 문자에만 적용되므로, 유니코드 전체 Python 의미론
 * 대신 아래 정의로 충분하다. 골드 마스터 회귀가 차이를 잡는다.
 */

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
