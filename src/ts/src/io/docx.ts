/** DOCX (Microsoft Word OOXML) 텍스트 추출 — Python ko_pii/io_/docx.py 대응.
 *
 * DOCX 는 ZIP + XML 구조:
 *   word/document.xml — 본문
 *   word/header*.xml — 머리말
 *   word/footer*.xml — 꼬리말
 *
 * ``<w:t>`` 요소에 텍스트가 들어 있고 ``<w:p>`` 가 문단 경계.
 * 파트 파싱 실패는 빈 텍스트로 삼키지 않고 coverage 에 failed 로 남긴다.
 */
import { inspectParts, type TextExtraction } from "./coverage.js";
import { iterElements, parseXmlBytes } from "./xmlEt.js";
import { openZip, zipNames, zipRead } from "./zipFile.js";

/** ET ``root.iter()`` pre-order 의미 그대로 — 부모(p) 가 자식(t) 보다 먼저 방문된다. */
function extractFromXml(xmlBytes: Uint8Array): string[] {
  const parts: string[] = [];
  const root = parseXmlBytes(xmlBytes);
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

/** docProps/core.xml 의 작성자·수정자·제목 추출 (문서 순서, 같은 키는 첫 위치에 마지막 값). */
function extractMetadata(xmlBytes: Uint8Array): Map<string, string> {
  const meta = new Map<string, string>();
  const root = parseXmlBytes(xmlBytes);
  const LOCAL_KEYS = new Set(["creator", "lastModifiedBy", "title", "subject", "keywords"]);
  for (const elem of iterElements(root)) {
    const local = elem.local;
    if (LOCAL_KEYS.has(local) && elem.text) {
      meta.set(local, elem.text);
    }
  }
  return meta;
}

/** Python `str.casefold().endswith(".xml")` — 확장자 비교용 (ASCII 범위면 동일). */
function endsWithXml(name: string): boolean {
  return name.toLowerCase().endsWith(".xml");
}

/** Inspect supported text parts; partial text is for manual review only. */
export async function inspectText(path: string): Promise<TextExtraction> {
  const zf = await openZip(path);
  const names = zipNames(zf);
  const candidates = ["word/document.xml"];
  if (names.includes("docProps/core.xml")) candidates.unshift("docProps/core.xml");
  candidates.push(
    ...names
      .filter((n) => (n.startsWith("word/header") || n.startsWith("word/footer")) && endsWithXml(n))
      .sort(),
  );
  return inspectParts(zf, candidates, async (archive, name) => {
    if (name === "docProps/core.xml") {
      const meta = extractMetadata(await zipRead(archive, name));
      return [...meta].map(([key, value]) => `[메타:${key}] ${value}`).join("\n");
    }
    return extractFromXml(await zipRead(archive, name)).join("");
  });
}

export async function readText(path: string): Promise<string> {
  return (await inspectText(path)).requireComplete();
}
