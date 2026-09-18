/**
 * eval 포트 전용 Python 문자열 규칙 보조 — 출력 바이트 동등성용.
 * (Python 은 코드 포인트 단위로 len/슬라이스/정렬 폭을 센다.)
 */
import { readFileSync } from "node:fs";

/** Python ``str.isspace()`` / ``re`` 의 ``\s`` (str 패턴) 문자 집합. JS ``\s`` 와 다르다
 * (Python 만: U+001C–001F, U+0085 / JS 만: U+FEFF). */
const PY_WS =
  "\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_WS_RUN = new RegExp(`[${PY_WS}]+`, "g");
const PY_STRIP = new RegExp(`^[${PY_WS}]+|[${PY_WS}]+$`, "g");
const PY_LSTRIP = new RegExp(`^[${PY_WS}]+`);

/** ``re.sub(r"\s+", repl, s)`` */
export function pySubWhitespace(s: string, repl: string): string {
  return s.replace(PY_WS_RUN, repl);
}

/** ``s.strip()`` */
export function pyStrip(s: string): string {
  return s.replace(PY_STRIP, "");
}

/** ``s.lstrip()`` */
export function pyLstrip(s: string): string {
  return s.replace(PY_LSTRIP, "");
}

/** ``len(s)`` — 코드 포인트 수. */
export function cpLen(s: string): number {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

/** ``s[:n]`` (n >= 0) — 코드 포인트 단위 앞부분. */
export function cpHead(s: string, n: number): string {
  if (s.length <= n) return s;
  let out = "";
  let i = 0;
  for (const ch of s) {
    if (i >= n) break;
    out += ch;
    i += 1;
  }
  return out;
}

/** ``f"{s:<w}"`` — 코드 포인트 폭 기준 왼쪽 정렬. */
export function padRight(s: string, width: number): string {
  const n = cpLen(s);
  return n >= width ? s : s + " ".repeat(width - n);
}

/** ``f"{s:>w}"`` — 코드 포인트 폭 기준 오른쪽 정렬 (정수는 ``String(n)`` 으로 넘긴다). */
export function padLeft(s: string, width: number): string {
  const n = cpLen(s);
  return n >= width ? s : " ".repeat(width - n) + s;
}

/** Python ``str.splitlines()`` 의 줄 경계. (제어 문자를 정규식 리터럴에 쓰지 않으려고 문자열로 조립.) */
const PY_LINE_BREAK_CHARS = "\\n\\r\\v\\f\\x1c-\\x1e\\x85\\u2028\\u2029";
const PY_LINE_BREAK = new RegExp(`\\r\\n|[${PY_LINE_BREAK_CHARS}]`);

/** ``str.splitlines()`` — Python 의 줄 경계 전체 (\n \r \r\n \v \f \x1c-\x1e \x85 U+2028 U+2029). */
export function pySplitlines(s: string): string[] {
  const parts = s.split(PY_LINE_BREAK);
  if (parts[parts.length - 1] === "") parts.pop();
  return parts;
}

/** 텍스트 모드 파일 순회 (``for line in fh``) — universal newlines, 줄 끝 개행 제거본. */
export function pyFileLines(s: string): string[] {
  const parts = s.split(/\r\n|\n|\r/);
  if (parts[parts.length - 1] === "") parts.pop();
  return parts;
}

/** ``open(path, encoding="utf-8").read()`` — 잘못된 UTF-8 은 예외 (Python UnicodeDecodeError 대응),
 * BOM 은 Python 처럼 보존. */
export function readUtf8(path: string): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(path));
}

const D = "[0-9](?:_?[0-9])*";
const PY_FLOAT = new RegExp(
  `^[+-]?(?:(?:${D}\\.?(?:${D})?|\\.${D})(?:[eE][+-]?${D})?|inf|infinity|nan)$`,
  "i",
);

/** Python ``float("...")`` — 실패 시 null. (ASCII 숫자만 — Python 은 유니코드 숫자도 받는다.) */
export function pyFloat(s: string): number | null {
  const t = pyStrip(s);
  if (!PY_FLOAT.test(t)) return null;
  const low = t.toLowerCase().replace(/^[+-]/, "");
  const sign = t.startsWith("-") ? -1 : 1;
  if (low === "inf" || low === "infinity") return sign * Number.POSITIVE_INFINITY;
  if (low === "nan") return Number.NaN;
  return Number(t.replaceAll("_", ""));
}

/** ``str(pathlib.PurePosixPath(p))`` — 중복 슬래시·"." 성분·후행 슬래시 제거 (".." 은 유지). */
export function pyPathStr(p: string): string {
  const root = p.startsWith("//") && !p.startsWith("///") ? "//" : p.startsWith("/") ? "/" : "";
  const parts = p.split("/").filter((c) => c !== "" && c !== ".");
  const joined = root + parts.join("/");
  return joined === "" ? "." : joined;
}
