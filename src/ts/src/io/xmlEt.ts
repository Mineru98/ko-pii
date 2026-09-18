/** Python xml.etree.ElementTree 의사동작 헬퍼 — io_ 문서 파서 공용.
 *
 * Python 원본은 stdlib ElementTree 를 쓰며 다음 의미론에 의존한다:
 * - ``elem.tag`` 가 ``{namespace-uri}local`` 형태 (접두어는 URI 로 해석됨).
 *   미선언 접두어는 ParseError.
 * - ``root.iter()`` 는 루트 포함 pre-order (문서 순서) 순회.
 * - ``elem.text`` 는 첫 자식 요소 앞의 텍스트 (없으면 None, 공백은 보존).
 * - 정의된 5개 엔티티(lt gt amp quot apos)와 숫자 문자 참조를 디코딩하고,
 *   미정의 엔티티/유효하지 않은 문자 참조는 ParseError.
 * - malformed XML 은 ParseError.
 *
 * fast-xml-parser 로 파싱하되 위 의미론이 1:1 재현되도록 변환한다. 엔티티 디코딩은
 * fxp(processEntities=false, 숫자 참조 미지원) 대신 자체 구현으로 ET 와 동일하게
 * 처리한다. ET 의 ParseError 는 {@link XmlParseError} 로 대응한다.
 */
import { XMLParser, XMLValidator } from "fast-xml-parser";
import { encodingExists, decode as iconvDecode } from "iconv-lite";
import { ValueError } from "../core/errors.js";

/** Python LookupError 대응 — 선언된 인코딩을 codecs 가 모를 때 (pyexpat 실측). */
export class LookupError extends Error {
  override name = "LookupError";
}

/** Python xml.etree.ElementTree.ParseError 대응. */
export class XmlParseError extends Error {
  override name = "XmlParseError";
}

/** Python elem.tag / elem.attrib / elem.text 의 TS 대응 구조. */
export interface XmlElement {
  /** 태그 local-name — Python ``elem.tag.split("}", 1)[-1]`` 결과. */
  local: string;
  /** 네임스페이스 URI. 기본 네임스페이스 미선언이면 null. */
  nsUri: string | null;
  /** Python ``elem.attrib`` — 네임스페이스 속성은 ``{uri}name`` 키. xmlns 선언 제외. */
  attrs: Record<string, string>;
  /** Python ``elem.text`` — 첫 자식 요소 앞 텍스트. 없으면 null. 엔티티 디코딩 완료. */
  text: string | null;
  children: XmlElement[];
}

// XML 1.0 유효 문자 참조 범위 (expat 이 거절하는 범위와 동일).
function isValidCharRef(cp: number): boolean {
  return (
    cp === 0x09 ||
    cp === 0x0a ||
    cp === 0x0d ||
    (cp >= 0x20 && cp <= 0xd7ff) ||
    (cp >= 0xe000 && cp <= 0xfffd) ||
    (cp >= 0x10000 && cp <= 0x10ffff)
  );
}

const NAMED_ENTITIES: Record<string, string> = {
  lt: "<",
  gt: ">",
  amp: "&",
  quot: '"',
  apos: "'",
};

/** 엔티티/문자 참조 디코딩 — ET 의미론 (미정의 엔티티·무효 참조는 ParseError). */
function decodeXmlChars(raw: string): string {
  if (!raw.includes("&")) return raw;
  let out = "";
  let i = 0;
  while (i < raw.length) {
    const ch = raw[i];
    if (ch !== "&") {
      out += ch;
      i++;
      continue;
    }
    const semi = raw.indexOf(";", i + 1);
    if (semi < 0) throw new XmlParseError("not well-formed (invalid token)");
    const body = raw.slice(i + 1, semi);
    if (body.startsWith("#")) {
      const hex = body.length > 1 && body[1] === "x";
      const digits = hex ? body.slice(2) : body.slice(1);
      const ok =
        digits.length > 0 && (hex ? /^[0-9a-fA-F]+$/.test(digits) : /^[0-9]+$/.test(digits));
      if (!ok) throw new XmlParseError("not well-formed (invalid token)");
      const cp = Number.parseInt(digits, hex ? 16 : 10);
      if (!isValidCharRef(cp)) {
        throw new XmlParseError("reference to invalid character number");
      }
      out += String.fromCodePoint(cp);
    } else {
      const named = NAMED_ENTITIES[body];
      if (named === undefined) throw new XmlParseError(`undefined entity: ${body}`);
      out += named;
    }
    i = semi + 1;
  }
  return out;
}

type FxpItem = Record<string, unknown>;

const CDATA_KEY = "#cdata";
/** expat 이 모든 문서에 사전 바인딩하는 ``xml`` 접두어 (xml:space, xml:lang). */
const XML_NS = "http://www.w3.org/XML/1998/namespace";

const parser = new XMLParser({
  preserveOrder: true,
  // Python ET 는 공백 텍스트를 그대로 유지하므로 trim 금지.
  trimValues: false,
  ignoreAttributes: false,
  // ET 는 모든 값을 문자열로 유지 — fxp(strnum) 의 숫자/불리언 자동 변환 억제.
  parseTagValue: false,
  parseAttributeValue: false,
  // ET 의 엔티티 의미론(숫자 참조 디코딩, 미정의 엔티티 ParseError)을 자체 구현으로
  // 재현하기 위해 fxp 엔티티 처리를 끈다.
  processEntities: false,
  ignoreDeclaration: true,
  // CDATA 는 엔티티 디코딩 없이 원문 그대로 text 에 이어붙여야 한다 (ET 의미론).
  cdataPropName: CDATA_KEY,
});

function elementItemsOf(rec: FxpItem): unknown[] {
  const v = rec[Object.keys(rec).find((k) => k !== ":@") ?? ""];
  return Array.isArray(v) ? v : [];
}

function attrsOf(rec: FxpItem): Record<string, string> {
  const raw: Record<string, string> = {};
  const block = rec[":@"];
  if (typeof block !== "object" || block === null) return raw;
  for (const [k, v] of Object.entries(block as Record<string, unknown>)) {
    const name = k.startsWith("@_") ? k.slice(2) : k;
    raw[name] = typeof v === "string" ? decodeXmlChars(v) : String(v);
  }
  return raw;
}

/** fxp preserveOrder 항목 배열 → 요소들 + 첫 자식 앞 텍스트. */
function convertChildren(
  items: unknown[],
  parentNs: ReadonlyMap<string, string>,
): { elements: XmlElement[]; text: string | null } {
  const elements: XmlElement[] = [];
  let text: string | null = null;
  for (const item of items) {
    if (typeof item !== "object" || item === null) continue;
    const rec = item as FxpItem;
    if ("#text" in rec) {
      // Python elem.text — 첫 자식 요소 앞의 텍스트만 의미가 있다. CDATA 로 끊긴
      // 조각들은 ET 처럼 하나로 이어붙인다.
      const v = rec["#text"];
      if (elements.length === 0 && typeof v === "string") {
        text = (text ?? "") + decodeXmlChars(v);
      }
      continue;
    }
    if (CDATA_KEY in rec) {
      if (elements.length === 0) {
        let raw = "";
        for (const piece of elementItemsOf(rec)) {
          const v = (piece as FxpItem)["#text"];
          if (typeof v === "string") raw += v; // CDATA 내부는 디코딩하지 않는다
        }
        text = (text ?? "") + raw;
      }
      continue;
    }
    const tagKey = Object.keys(rec).find((k) => k !== ":@");
    if (tagKey === undefined) continue;
    if (tagKey.startsWith("?")) continue; // 처리 명령(processing instruction) — ET 도 무시
    elements.push(convertElement(tagKey, rec, parentNs));
  }
  return { elements, text };
}

function convertElement(
  tagKey: string,
  rec: FxpItem,
  parentNs: ReadonlyMap<string, string>,
): XmlElement {
  const rawAttrs = attrsOf(rec);

  // 네임스페이스 선언 스택 (기본 + 접두어).
  const ns = new Map(parentNs);
  for (const [name, value] of Object.entries(rawAttrs)) {
    if (name === "xmlns") ns.set("", value);
    else if (name.startsWith("xmlns:")) ns.set(name.slice("xmlns:".length), value);
  }

  const colon = tagKey.indexOf(":");
  const prefix = colon < 0 ? null : tagKey.slice(0, colon);
  const local = colon < 0 ? tagKey : tagKey.slice(colon + 1);
  let nsUri: string | null;
  if (prefix === null) {
    nsUri = ns.get("") ?? null;
  } else {
    const uri = ns.get(prefix);
    if (uri === undefined) throw new XmlParseError(`unbound prefix: ${prefix}`);
    nsUri = uri;
  }

  // Python elem.attrib — xmlns 선언은 제외, 네임스페이스 속성은 "{uri}name" 키.
  const attrs: Record<string, string> = {};
  for (const [name, value] of Object.entries(rawAttrs)) {
    if (name === "xmlns" || name.startsWith("xmlns:")) continue;
    const c = name.indexOf(":");
    if (c < 0) {
      attrs[name] = value;
    } else {
      const uri = ns.get(name.slice(0, c));
      if (uri === undefined) throw new XmlParseError(`unbound prefix: ${name.slice(0, c)}`);
      attrs[`{${uri}}${name.slice(c + 1)}`] = value;
    }
  }

  const { elements, text } = convertChildren(elementItemsOf(rec), ns);
  return { local, nsUri, attrs, text, children: elements };
}

// XML 1.0 에서 허용되지 않는 문자 — expat "not well-formed (invalid token)".
// biome-ignore lint/suspicious/noControlCharactersInRegex: XML 1.0 금지 문자 범위 그 자체
const INVALID_XML_CHAR = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/;

/**
 * fxp XMLValidator 가 통과시키지만 expat 은 거부하는 두 가지를 선행 검사한다:
 * 문서 어디든 XML 1.0 금지 제어문자, 그리고 속성값 안의 ``<``.
 */
function assertExpatWellFormed(xml: string): void {
  if (INVALID_XML_CHAR.test(xml)) {
    throw new XmlParseError("not well-formed (invalid token)");
  }
  const n = xml.length;
  let i = 0;
  while (i < n) {
    const lt = xml.indexOf("<", i);
    if (lt < 0) return;
    const skipTo = (open: string, close: string): boolean => {
      if (!xml.startsWith(open, lt)) return false;
      const end = xml.indexOf(close, lt + open.length);
      i = end < 0 ? n : end + close.length;
      return true;
    };
    // 문서 맨 앞이 아닌 XML 선언 — expat "XML or text declaration not at start of entity".
    if (lt > 0 && /^<\?xml[\s?]/i.test(xml.slice(lt, lt + 6))) {
      throw new XmlParseError("XML or text declaration not at start of entity");
    }
    if (skipTo("<!--", "-->") || skipTo("<![CDATA[", "]]>") || skipTo("<?", "?>")) continue;
    // 태그 또는 <!DOCTYPE …> — 따옴표/내부 서브셋([ ]) 을 추적하며 닫는 '>' 까지.
    const isDecl = xml.startsWith("<!", lt);
    let quote = "";
    let depth = 0;
    let j = lt + 1;
    for (; j < n; j++) {
      const ch = xml[j];
      if (quote) {
        if (ch === quote) quote = "";
        else if (ch === "<" && !isDecl) throw new XmlParseError("not well-formed (invalid token)");
      } else if (ch === '"' || ch === "'") quote = ch;
      else if (isDecl && ch === "[") depth += 1;
      else if (isDecl && ch === "]") depth -= 1;
      else if (ch === ">" && depth <= 0) break;
    }
    i = j + 1;
  }
}

/** XML 문자열 파싱 — ET.fromstring 대응. 실패 시 XmlParseError. */
export function parseXmlFromString(source: string): XmlElement {
  const xml = expandInternalEntities(source);
  assertExpatWellFormed(xml);
  const verdict = XMLValidator.validate(xml);
  if (verdict !== true) {
    const err = verdict as { err?: { msg?: string } };
    throw new XmlParseError(err?.err?.msg ?? "not well-formed (invalid token)");
  }
  const tree: unknown = parser.parse(xml);
  if (!Array.isArray(tree)) throw new XmlParseError("no element found");
  // 루트 앞뒤 공백 텍스트는 ET 도 허용한다.
  for (const item of tree) {
    if (typeof item === "object" && item !== null && "#text" in item) {
      const v = (item as FxpItem)["#text"];
      if (typeof v === "string" && v.trim() !== "") {
        throw new XmlParseError("junk before document element");
      }
    }
  }
  const { elements } = convertChildren(tree, new Map([["xml", XML_NS]]));
  if (elements.length !== 1) throw new XmlParseError("junk after document element");
  return elements[0]!;
}

/** expat 의 UTF-16 자동 감지 — BOM, 또는 BOM 없는 ``<?`` 의 2바이트 패턴. */
function sniffUtf16(b: Uint8Array): "utf-16le" | "utf-16be" | null {
  if (b.length < 2) return null;
  if (b[0] === 0xff && b[1] === 0xfe) return "utf-16le";
  if (b[0] === 0xfe && b[1] === 0xff) return "utf-16be";
  if (b.length >= 4 && b[0] === 0x3c && b[1] === 0 && b[2] === 0x3f && b[3] === 0)
    return "utf-16le";
  if (b.length >= 4 && b[0] === 0 && b[1] === 0x3c && b[2] === 0 && b[3] === 0x3f)
    return "utf-16be";
  return null;
}

// ---------------------------------------------------------------------------
// 내부 일반 엔티티 (<!DOCTYPE d [<!ENTITY e "…">]>) — ET(expat) 는 확장한다
// ---------------------------------------------------------------------------

/** 확장 결과 상한 — expat 의 billion-laughs 방어(증폭 한도)에 대응하는 안전장치. */
const MAX_ENTITY_EXPANSION_CHARS = 8 * 1024 * 1024;

/** 엔티티 값 리터럴의 숫자 문자 참조는 선언 시점에 풀린다 (XML 4.5). 일반 참조는 그대로 둔다. */
function normalizeEntityValue(value: string): string {
  return value.replace(/&#(x[0-9a-fA-F]+|[0-9]+);/g, (_m, body: string) => {
    const cp = body.startsWith("x")
      ? Number.parseInt(body.slice(1), 16)
      : Number.parseInt(body, 10);
    if (!isValidCharRef(cp)) throw new XmlParseError("reference to invalid character number");
    return String.fromCodePoint(cp);
  });
}

/**
 * DOCTYPE 내부 서브셋의 내부 일반 엔티티를 본문에 텍스트로 치환한 XML 을 돌려준다
 * (DOCTYPE 선언 자체는 제거). 치환 후 다시 파싱되므로 엔티티 값 안의 마크업도 ET 처럼
 * 요소가 된다. 외부(SYSTEM/PUBLIC)·매개변수 엔티티는 등록하지 않는다 — 참조하면 뒤의
 * decodeXmlChars 가 "undefined entity" ParseError 를 낸다 (ET 실측과 같은 결과).
 */
function expandInternalEntities(xml: string): string {
  const start = xml.indexOf("<!DOCTYPE");
  if (start < 0) return xml;
  const n = xml.length;
  let subsetStart = -1;
  let subsetEnd = -1;
  let quote = "";
  let end = -1;
  for (let i = start + 9; i < n; i++) {
    const ch = xml[i];
    if (quote) {
      if (ch === quote) quote = "";
    } else if (subsetStart >= 0 && subsetEnd < 0 && xml.startsWith("<!--", i)) {
      const close = xml.indexOf("-->", i + 4);
      if (close < 0) break;
      i = close + 2;
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "[" && subsetStart < 0) subsetStart = i + 1;
    else if (ch === "]" && subsetStart >= 0 && subsetEnd < 0) subsetEnd = i;
    else if (ch === ">" && (subsetStart < 0 || subsetEnd >= 0)) {
      end = i;
      break;
    }
  }
  if (end < 0) throw new XmlParseError("unclosed token");

  const entities = new Map<string, string>();
  if (subsetStart >= 0) {
    const subset = xml.slice(subsetStart, subsetEnd).replace(/<!--[\s\S]*?-->/g, "");
    const decl = /<!ENTITY\s+(%\s+)?(\S+)\s+(?:(?:SYSTEM|PUBLIC)\b[^>]*|"([^"]*)"|'([^']*)')\s*>/g;
    for (const m of subset.matchAll(decl)) {
      const value = m[3] ?? m[4];
      const name = m[2] ?? "";
      // 매개변수·외부 엔티티 제외, 같은 이름은 첫 선언이 유효 (XML 4.2)
      if (m[1] !== undefined || value === undefined || entities.has(name)) continue;
      entities.set(name, normalizeEntityValue(value));
    }
  }

  const body = xml.slice(0, start) + xml.slice(end + 1);
  if (entities.size === 0) return body;
  let budget = MAX_ENTITY_EXPANSION_CHARS;
  const expand = (text: string, stack: readonly string[]): string => {
    let out = "";
    let i = 0;
    while (i < text.length) {
      // 주석·CDATA·PI 안의 '&' 는 참조가 아니다
      let skipped = false;
      for (const [open, close] of [
        ["<!--", "-->"],
        ["<![CDATA[", "]]>"],
        ["<?", "?>"],
      ] as const) {
        if (text.startsWith(open, i)) {
          const closeAt = text.indexOf(close, i + open.length);
          const stop = closeAt < 0 ? text.length : closeAt + close.length;
          out += text.slice(i, stop);
          i = stop;
          skipped = true;
          break;
        }
      }
      if (skipped) continue;
      const m = text[i] === "&" ? /^&([^#;&\s<]+);/.exec(text.slice(i, i + 256)) : null;
      const name = m?.[1];
      const value =
        name !== undefined && !(name in NAMED_ENTITIES) ? entities.get(name) : undefined;
      if (m === null || name === undefined || value === undefined) {
        out += text[i];
        i += 1;
        continue;
      }
      if (stack.includes(name)) throw new XmlParseError("recursive entity reference");
      const expanded = expand(value, [...stack, name]);
      budget -= expanded.length;
      if (budget < 0) throw new XmlParseError("limit on input amplification factor breached");
      out += expanded;
      i += m[0].length;
    }
    return out;
  };
  return expand(body, []);
}

// ---------------------------------------------------------------------------
// 바이트 디코드 — expat 의 인코딩 판정 + pyexpat UnknownEncodingHandler
// ---------------------------------------------------------------------------

const XML_DECL_ENCODING =
  /^<\?xml\s+version\s*=\s*(?:"[^"]*"|'[^']*')(?:\s+encoding\s*=\s*(?:"([^"]*)"|'([^']*)'))?/;

function declaredEncoding(prolog: string): string | null {
  const m = XML_DECL_ENCODING.exec(prolog);
  return m === null ? null : (m[1] ?? m[2] ?? null);
}

const ALL_BYTES = Buffer.from(Array.from({ length: 256 }, (_, i) => i));

/**
 * 선언 인코딩에 따라 바이트를 문자열로 — Python ET.fromstring(bytes) 실측 의미론:
 * - UTF-16 은 BOM/`<?` 패턴으로 자동 감지. 선언과 실제 바이트가 어긋나면 ParseError.
 * - expat 내장: UTF-8, ISO-8859-1, US-ASCII.
 * - 그 밖의 이름은 pyexpat 이 Python codecs 로 256바이트 표를 만든다: 모르는 이름은
 *   LookupError("unknown encoding: X"), 멀티바이트 코덱(euc-kr, cp949, shift_jis …)은
 *   ValueError("multi-byte encodings are not supported") — 둘 다 ParseError 가 *아니라서*
 *   추출기의 `except ParseError` 를 지나 호출자에게 전파된다 (빈 텍스트 성공 금지).
 */
function decodeXmlBytes(bytes: Uint8Array): string {
  const invalid = (): XmlParseError => new XmlParseError("not well-formed (invalid token)");
  const utf16 = sniffUtf16(bytes);
  if (utf16 !== null) {
    let text: string;
    try {
      text = new TextDecoder(utf16, { fatal: true }).decode(bytes);
    } catch {
      throw invalid();
    }
    const enc = declaredEncoding(text)?.toLowerCase() ?? null;
    if (enc !== null && !enc.startsWith("utf-16")) throw new XmlParseError("encoding mismatch");
    return text;
  }

  const hasBom = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
  const prolog = Buffer.from(bytes.subarray(hasBom ? 3 : 0, 1024)).toString("latin1");
  const name = declaredEncoding(prolog);
  const enc = name?.toLowerCase() ?? "utf-8";
  if (enc === "utf-8") {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw invalid();
    }
  }
  // 바이트는 8비트 계열인데 선언은 UTF-16 — expat "encoding specified in XML declaration is incorrect"
  if (enc.startsWith("utf-16")) throw new XmlParseError("encoding mismatch");
  const buf = Buffer.from(bytes);
  if (enc === "iso-8859-1") return buf.toString("latin1");
  if (enc === "us-ascii") {
    if (buf.some((b) => b >= 0x80)) throw invalid();
    return buf.toString("latin1");
  }
  // pyexpat UnknownEncodingHandler
  if (!encodingExists(enc)) throw new LookupError(`unknown encoding: ${name}`);
  if (iconvDecode(ALL_BYTES, enc).length !== 256) {
    throw new ValueError("multi-byte encodings are not supported");
  }
  const text = iconvDecode(buf, enc);
  if (text.includes("\uFFFD")) throw invalid(); // 코덱에 없는 바이트 — expat 에게는 무효 문자
  return text;
}

/** 바이트 → 문자열 → 파싱 (ET.fromstring(bytes) 대응; malformed 는 XmlParseError). */
export function parseXmlBytes(xmlBytes: Uint8Array): XmlElement {
  return parseXmlFromString(decodeXmlBytes(xmlBytes));
}

/** Python ``root.iter()`` 대응 — 루트 포함 pre-order (문서 순서) 순회. */
export function* iterElements(root: XmlElement): Generator<XmlElement> {
  yield root;
  for (const child of root.children) {
    yield* iterElements(child);
  }
}
