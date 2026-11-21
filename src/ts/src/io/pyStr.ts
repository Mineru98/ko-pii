/** io 공용 Python 문자열 헬퍼. */

/** Python `str.isspace` 집합 (JS `\s` 와 달리 U+FEFF 는 공백이 아니다). */
const PY_SPACE_CLASS =
  "[\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]";
const PY_STRIP = new RegExp(`^${PY_SPACE_CLASS}+|${PY_SPACE_CLASS}+$`, "g");
const PY_NON_SPACE = new RegExp(`[^${PY_SPACE_CLASS.slice(1, -1)}]`);

/** Python `str.strip()`. */
export function pyStrip(s: string): string {
  return s.replace(PY_STRIP, "");
}

/** Python `bool(s.strip())` 의 부정 — 비었거나 공백뿐이면 true. */
export function pyIsBlank(s: string): boolean {
  return !PY_NON_SPACE.test(s);
}

/** Python 튜플 키 비교 ``(prefix, len(digits), digits, name)``. */
type SortKey = [string, number, string, string];

function sortKey(name: string, stem: string): SortKey {
  const m = new RegExp(`^(.*${stem})([0-9]+)\\.xml$`).exec(name);
  if (m === null) return [name, 0, "", name];
  const digits = m[2]!.replace(/^0+/, "");
  return [m[1]!, digits.length, digits, name];
}

function compareStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** 숫자 접미사를 자릿값으로 비교하는 정렬 (Python ``sorted(key=...)``, 안정 정렬). */
export function numericSorted(names: readonly string[], stem: string): string[] {
  const keyed = names.map((name) => [sortKey(name, stem), name] as const);
  keyed.sort(([a], [b]) => {
    return (
      compareStr(a[0], b[0]) || a[1] - b[1] || compareStr(a[2], b[2]) || compareStr(a[3], b[3])
    );
  });
  return keyed.map(([, name]) => name);
}
