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
      // Python elem.text — 첫 자식 요소 앞의 텍스트만 의미가 있다.
      if (text === null && elements.length === 0) {
        const v = rec["#text"];
        text = typeof v === "string" ? decodeXmlChars(v) : null;
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

/** XML 문자열 파싱 — ET.fromstring 대응. 실패 시 XmlParseError. */
export function parseXmlFromString(xml: string): XmlElement {
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
  const { elements } = convertChildren(tree, new Map());
  if (elements.length !== 1) throw new XmlParseError("junk after document element");
  return elements[0]!;
}

/** 바이트 → UTF-8 문자열 → 파싱 (ET.fromstring(bytes) 대응; 실패 시 XmlParseError). */
export function parseXmlBytes(xmlBytes: Uint8Array): XmlElement {
  let xml: string;
  try {
    xml = new TextDecoder("utf-8", { fatal: true }).decode(xmlBytes);
  } catch {
    throw new XmlParseError("not well-formed (invalid bytes)");
  }
  return parseXmlFromString(xml);
}

/** Python ``root.iter()`` 대응 — 루트 포함 pre-order (문서 순서) 순회. */
export function* iterElements(root: XmlElement): Generator<XmlElement> {
  yield root;
  for (const child of root.children) {
    yield* iterElements(child);
  }
}
