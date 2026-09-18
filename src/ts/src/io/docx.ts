/** DOCX (Microsoft Word OOXML) 텍스트 추출 — Python ko_pii/io_/docx.py 대응.
 *
 * DOCX 는 ZIP + XML 구조:
 *   word/document.xml — 본문
 *   word/header*.xml — 머리말
 *   word/footer*.xml — 꼬리말
 *
 * ``<w:t>`` 요소에 텍스트가 들어 있고 ``<w:p>`` 가 문단 경계.
 */
import type { XmlElement } from "./xmlEt.js";
import { iterElements, parseXmlBytes, XmlParseError } from "./xmlEt.js";
import { openZip, zipNames, zipRead } from "./zipFile.js";

/** ET ``root.iter()`` pre-order 의미 그대로 — 부모(p) 가 자식(t) 보다 먼저 방문된다. */
function extractFromXml(xmlBytes: Uint8Array): string[] {
  const parts: string[] = [];
  let root: XmlElement;
  try {
    root = parseXmlBytes(xmlBytes);
  } catch (e) {
    if (e instanceof XmlParseError) return parts;
    throw e;
  }
  for (const elem of iterElements(root)) {
    const local = elem.local;
    if (local === "t" && elem.text) {
      parts.push(elem.text);
    } else if (local === "tab") {
      parts.push("\t");
    } else if (local === "br" || local === "p") {
      parts.push("\n");
    }
  }
  return parts;
}

/** docProps/core.xml 의 작성자·수정자·제목 추출. */
function extractMetadata(xmlBytes: Uint8Array): Record<string, string> {
  const meta: Record<string, string> = {};
  let root: XmlElement;
  try {
    root = parseXmlBytes(xmlBytes);
  } catch (e) {
    if (e instanceof XmlParseError) return meta;
    throw e;
  }
  const LOCAL_KEYS = new Set(["creator", "lastModifiedBy", "title", "subject", "keywords"]);
  for (const elem of iterElements(root)) {
    const local = elem.local;
    if (LOCAL_KEYS.has(local) && elem.text) {
      meta[local] = elem.text;
    }
  }
  return meta;
}

export async function readText(path: string): Promise<string> {
  const out: string[] = [];
  const zf = await openZip(path);
  const names = new Set(zipNames(zf));
  // 메타데이터 — 작성자·수정자가 PII 인 경우가 잦음
  if (names.has("docProps/core.xml")) {
    const meta = extractMetadata(await zipRead(zf, "docProps/core.xml"));
    for (const key of ["creator", "lastModifiedBy", "title", "subject"]) {
      if (key in meta) {
        out.push(`[메타:${key}] ${meta[key]}\n`);
      }
    }
  }
  // Main body
  const candidates = ["word/document.xml"];
  // Headers / footers
  candidates.push(
    ...zipNames(zf)
      .filter((n) => n.startsWith("word/header") || n.startsWith("word/footer"))
      .sort(),
  );
  for (const name of candidates) {
    if (names.has(name)) {
      out.push(...extractFromXml(await zipRead(zf, name)));
      out.push("\n");
    }
  }
  return out.join("");
}
