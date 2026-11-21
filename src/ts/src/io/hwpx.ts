/** HWPX (한컴오피스, KS X 6101) 텍스트 추출 — Python ko_pii/io_/hwpx.py 대응.
 *
 * HWPX 는 ZIP + XML 구조:
 *   META-INF/manifest.xml
 *   Contents/content.hpf — OPF 매니페스트 + spine (본문 순서)
 *   Contents/section0.xml, section1.xml ...
 *   Contents/header.xml
 *
 * 각 ``section*.xml`` 의 ``<hp:p>`` (문단) 아래 ``<hp:run><hp:t>...</hp:t></hp:run>``
 * 요소에 본문 텍스트가 들어 있다. 표·머리말·꼬리말도 같은 구조라 ``<hp:t>`` 만
 * 재귀적으로 모으면 본문 + 표 + 머리말 다 추출 가능. ``<hp:t>`` 안의 인라인 컨트롤
 * (tab/lineBreak/...) 뒤 텍스트(tail)도 보존한다.
 *
 * content.hpf 가 있으면 spine 순서가 본문 순서이고, 파일명 추측으로 폴백하지 않는다.
 *
 * References:
 * - https://tech.hancom.com/hwpxformat/
 * - KS X 6101 (OWPML)
 */
import { ValueError } from "../core/errors.js";
import { inspectParts, isPartFailure, TextExtraction } from "./coverage.js";
import { numericSorted, pyIsBlank } from "./pyStr.js";
import { posixParts, pyUnquoteStrict, pyUrlsplit } from "./pyUrl.js";
import type { XmlElement } from "./xmlEt.js";
import { iterElements, itertext, parseXmlBytes } from "./xmlEt.js";
import type { ZipFile } from "./zipFile.js";
import { openZip, zipNames, zipRead } from "./zipFile.js";

const INLINE_CHARACTERS: Readonly<Record<string, string>> = {
  tab: "\t",
  lineBreak: "\n",
  nbSpace: " ",
  fwSpace: "　",
  hyphen: "­",
};
const CONTENT = "Contents/content.hpf";
const OPF_NAMESPACES: ReadonlySet<string> = new Set([
  "http://www.idpf.org/2007/opf/",
  "http://www.idpf.org/2007/opf",
]);
const SECTION = "{http://www.hancom.co.kr/hwpml/2011/section}sec";
const HEAD = "{http://www.hancom.co.kr/hwpml/2011/head}head";
const DC_PREFIX = "{http://purl.org/dc/elements/1.1/}";

/** Python ``elem.tag`` — ``{uri}local`` 또는 ``local``. */
function tagOf(elem: XmlElement): string {
  return elem.nsUri === null ? elem.local : `{${elem.nsUri}}${elem.local}`;
}

/** 섹션 XML → 텍스트 조각 (Python ``_extract_text_from_section``). */
export function extractTextFromSection(xmlBytes: Uint8Array): string[] {
  return sectionParts(parseXmlBytes(xmlBytes));
}

function sectionParts(root: XmlElement): string[] {
  const parts: string[] = [];
  const stack: Array<[XmlElement, boolean]> = [[root, false]];
  let textDepth = 0;
  while (stack.length > 0) {
    const [elem, closing] = stack.pop()!;
    const local = elem.local;
    if (closing) {
      if (local === "t") textDepth -= 1;
      // Only mixed-content tails belong to text, not XML indentation.
      if (textDepth && elem.tail) parts.push(elem.tail);
      continue;
    }
    if (local === "t") textDepth += 1;
    const inline = Object.hasOwn(INLINE_CHARACTERS, local) ? INLINE_CHARACTERS[local] : undefined;
    if (inline !== undefined) {
      parts.push(inline);
    } else if (local === "p" || local === "linesegarray") {
      parts.push("\n");
    }
    if (textDepth && elem.text) parts.push(elem.text);
    // End visits retain tails in order without recursing through deep XML.
    stack.push([elem, true]);
    for (let i = elem.children.length - 1; i >= 0; i--) stack.push([elem.children[i]!, false]);
  }
  return parts;
}

/** HWPX core 메타: 작성자·제목·키워드 추출. */
function extractMetadata(xmlBytes: Uint8Array): Map<string, string> {
  const meta = new Map<string, string>();
  const root = parseXmlBytes(xmlBytes);
  const LOCAL_KEYS = new Set([
    "creator",
    "lastModifiedBy",
    "title",
    "subject",
    "Author",
    "LastSavedBy",
    "Title",
  ]);
  for (const elem of iterElements(root)) {
    if (LOCAL_KEYS.has(elem.local) && elem.text) meta.set(elem.local, elem.text);
  }
  return meta;
}

function discoveredSections(names: readonly string[]): string[] {
  let sections = names.filter((n) => n.startsWith("Contents/section") && n.endsWith(".xml"));
  if (sections.length === 0) {
    sections = names.filter((n) => n.endsWith(".xml") && n.toLowerCase().includes("section"));
  }
  return numericSorted(sections, "section");
}

function countOf(names: readonly string[], value: string): number {
  let n = 0;
  for (const name of names) if (name === value) n += 1;
  return n;
}

function localManifestPath(href: string, names: readonly string[]): string {
  const path = pyUnquoteStrict(href);
  const parsed = pyUrlsplit(path);
  if (
    !path ||
    path.startsWith("/") ||
    path.endsWith("/") ||
    path.includes("\\") ||
    [...path].some((ch) => ch.codePointAt(0)! < 32) ||
    parsed.scheme ||
    parsed.netloc ||
    parsed.query ||
    parsed.fragment ||
    posixParts(path).includes("..")
  ) {
    throw new ValueError("unsupported package path");
  }
  const name = posixParts(path).join("/") || ".";
  const relative = `Contents/${name}`;
  if (names.includes(name) && names.includes(relative) && name !== relative) {
    throw new ValueError("ambiguous package path");
  }
  // Hancom writes archive-root paths; accept unambiguous package-relative paths too.
  const result = name.startsWith("Contents/") || names.includes(name) ? name : relative;
  if (countOf(names, result) > 1) throw new ValueError("duplicate package member");
  return result;
}

function childrenWithTag(elem: XmlElement, tag: string): XmlElement[] {
  return elem.children.filter((child) => tagOf(child) === tag);
}

async function contentPlan(
  archive: ZipFile,
  names: readonly string[],
): Promise<[string, string[]]> {
  if (countOf(names, CONTENT) !== 1) throw new ValueError("duplicate content manifest");
  const root = parseXmlBytes(await zipRead(archive, CONTENT));
  const rootTag = tagOf(root);
  let namespace = rootTag.endsWith("}package") ? rootTag.slice(0, -"}package".length) : rootTag;
  if (namespace.startsWith("{")) namespace = namespace.slice(1);
  if (!OPF_NAMESPACES.has(namespace) || rootTag !== `{${namespace}}package`) {
    throw new ValueError("unsupported content manifest");
  }
  const ns = `{${namespace}}`;
  const manifests = childrenWithTag(root, `${ns}manifest`);
  const spines = childrenWithTag(root, `${ns}spine`);
  if (manifests.length !== 1 || spines.length !== 1) {
    throw new ValueError("missing or duplicate package structure");
  }
  const manifest = manifests[0]!;
  const spine = spines[0]!;
  if (
    manifest.children.some((item) => tagOf(item) !== `${ns}item`) ||
    spine.children.some((item) => tagOf(item) !== `${ns}itemref`)
  ) {
    throw new ValueError("unsupported manifest or spine entry");
  }
  const items = new Map<string, XmlElement>();
  for (const item of childrenWithTag(manifest, `${ns}item`)) {
    const identity = item.attrs.id ?? "";
    if (!identity || items.has(identity)) throw new ValueError("missing or duplicate manifest ID");
    items.set(identity, item);
  }
  const paths: string[] = [];
  for (const reference of childrenWithTag(spine, `${ns}itemref`)) {
    const item = items.get(reference.attrs.idref ?? "");
    if (item === undefined) {
      const error = new Error(reference.attrs.idref ?? "");
      error.name = "KeyError";
      throw error;
    }
    const mediaType = item.attrs["media-type"] ?? "application/xml";
    if (mediaType !== "application/xml" && mediaType !== "text/xml") {
      throw new ValueError("unsupported spine content type");
    }
    const path = localManifestPath(item.attrs.href ?? "", names);
    if (path === CONTENT || paths.includes(path)) throw new ValueError("duplicate spine part");
    paths.push(path);
  }
  if (paths.length === 0 || discoveredSections(names).some((name) => !paths.includes(name))) {
    throw new ValueError("missing or unreferenced body sections");
  }

  const fields = new Set(["title", "creator", "subject", "description", "lastsaveby", "keyword"]);
  const metadata: string[] = [];
  for (const container of childrenWithTag(root, `${ns}metadata`)) {
    for (const element of container.children) {
      const tag = tagOf(element);
      const local = element.local;
      const key =
        tag === `${ns}meta` ? (element.attrs.name ?? "").toLowerCase() : local.toLowerCase();
      if (fields.has(key) && (tag.startsWith(ns) || tag.startsWith(DC_PREFIX))) {
        const value = itertext(element);
        if (!pyIsBlank(value)) metadata.push(`[메타:${key}] ${value}`);
      }
    }
  }
  return [metadata.join("\n"), paths];
}

/** Inspect supported text parts; partial text is for manual review only. */
export async function inspectText(path: string): Promise<TextExtraction> {
  const zf = await openZip(path);
  const names = zipNames(zf);
  // 메타데이터 (META-INF/core.xml 또는 docInfo.xml)
  const metaCandidates = ["META-INF/core.xml", "Contents/core.xml", "docProps/core.xml"];
  const metadata = metaCandidates.filter((name) => names.includes(name));
  const hasManifest = names.includes(CONTENT);
  let manifestText = "";
  let sectionNames: string[];
  if (hasManifest) {
    try {
      [manifestText, sectionNames] = await contentPlan(zf, names);
      if (sectionNames.some((name) => metadata.includes(name))) {
        throw new ValueError("metadata cannot be a body part");
      }
    } catch (error) {
      if (!isPartFailure(error)) throw error;
      return new TextExtraction("", [
        { part: CONTENT, status: "failed", reason: "invalid_content_manifest" },
      ]);
    }
    metadata.unshift(CONTENT);
  } else {
    const discovered = discoveredSections(names);
    sectionNames = discovered.length > 0 ? discovered : ["Contents/section0.xml"];
  }
  let bodySeen = false;

  const result = await inspectParts(zf, [...metadata, ...sectionNames], async (archive, name) => {
    if (name === CONTENT) return manifestText;
    if (metadata.includes(name)) {
      const meta = extractMetadata(await zipRead(archive, name));
      return [...meta].map(([key, value]) => `[메타:${key}] ${value}`).join("\n");
    }
    const root = parseXmlBytes(await zipRead(archive, name));
    if (hasManifest) {
      if (tagOf(root) === HEAD) return "";
      if (tagOf(root) !== SECTION) throw new ValueError("unsupported spine part root");
    }
    bodySeen = true;
    return sectionParts(root).join("");
  });
  if (hasManifest && !bodySeen) {
    return new TextExtraction(result.text, [
      ...result.parts,
      { part: "(body)", status: "failed", reason: "missing_body_sections" },
    ]);
  }
  return result;
}

export async function readText(path: string): Promise<string> {
  return (await inspectText(path)).requireComplete();
}
