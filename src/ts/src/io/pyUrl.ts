/** io 패키지 경로 해석용 Python `urllib.parse` 최소 대응 (unquote / urlsplit). */
import { ValueError } from "../core/errors.js";

const utf8Strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Python `unquote(s, errors="strict")` — 연속된 `%XX` 를 바이트로 모아 UTF-8 로 엄격 디코드한다.
 * 16진수가 아닌 `%` 는 그대로 남는다. 디코드 실패는 ValueError (Python UnicodeDecodeError).
 */
export function pyUnquoteStrict(s: string): string {
  if (!s.includes("%")) return s;
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    }
    try {
      return utf8Strict.decode(bytes);
    } catch {
      const error = new ValueError("'utf-8' codec can't decode bytes");
      error.name = "UnicodeDecodeError";
      throw error;
    }
  });
}

export interface SplitUrl {
  scheme: string;
  netloc: string;
  path: string;
  query: string;
  fragment: string;
}

const SCHEME_CHARS = /^[A-Za-z0-9+\-.]+$/;

/** Python `urlsplit(url)` (allow_fragments=True) — 판정에 쓰는 다섯 성분만. */
export function pyUrlsplit(input: string): SplitUrl {
  // Python: 선행 C0 제어문자·공백 strip, 탭/개행 제거
  // biome-ignore lint/suspicious/noControlCharactersInRegex: Python _WHATWG_C0_CONTROL_OR_SPACE
  let url = input.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
  let scheme = "";
  let netloc = "";
  let query = "";
  let fragment = "";
  const colon = url.indexOf(":");
  if (colon > 0 && /^[A-Za-z]/.test(url) && SCHEME_CHARS.test(url.slice(0, colon))) {
    scheme = url.slice(0, colon).toLowerCase();
    url = url.slice(colon + 1);
  }
  if (url.startsWith("//")) {
    let end = url.length;
    for (const ch of "/?#") {
      const at = url.indexOf(ch, 2);
      if (at >= 0) end = Math.min(end, at);
    }
    netloc = url.slice(2, end);
    url = url.slice(end);
    if (netloc.includes("[") !== netloc.includes("]")) throw new ValueError("Invalid IPv6 URL");
  }
  const hash = url.indexOf("#");
  if (hash >= 0) {
    fragment = url.slice(hash + 1);
    url = url.slice(0, hash);
  }
  const q = url.indexOf("?");
  if (q >= 0) {
    query = url.slice(q + 1);
    url = url.slice(0, q);
  }
  return { scheme, netloc, path: url, query, fragment };
}

/** Python `str(PurePosixPath(p))` 의 조각 — 빈 조각·"." 제거 (선행 "/" 는 별도 처리). */
export function posixParts(p: string): string[] {
  return p.split("/").filter((part) => part !== "" && part !== ".");
}
