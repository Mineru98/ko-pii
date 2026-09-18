/** HWPX (한컴오피스, KS X 6101) 텍스트 추출 — Python ko_pii/io_/hwpx.py 대응.
 *
 * HWPX 는 ZIP + XML 구조:
 *   META-INF/manifest.xml
 *   Contents/section0.xml, section1.xml ...
 *   Contents/header.xml
 *
 * 각 ``section*.xml`` 의 ``<hp:p>`` (문단) 아래 ``<hp:run><hp:t>...</hp:t></hp:run>``
 * 요소에 본문 텍스트가 들어 있다. 표·머리말·꼬리말도 같은 구조라 ``<hp:t>`` 만
 * 재귀적으로 모으면 본문 + 표 + 머리말 다 추출 가능.
 *
 * References:
 * - https://tech.hancom.com/hwpxformat/
 * - KS X 6101 (OWPML)
 */
import type { XmlElement } from "./xmlEt.js";
import { iterElements, parseXmlBytes, XmlParseError } from "./xmlEt.js";
import { openZip, zipNames, zipRead } from "./zipFile.js";

function extractTextFromSection(xmlBytes: Uint8Array): string[] {
  const parts: string[] = [];
  let root: XmlElement;
  try {
    root = parseXmlBytes(xmlBytes);
  } catch (e) {
    if (e instanceof XmlParseError) return parts;
    throw e;
  }
  // Iterate every element with local-name 't' (텍스트 노드)
  for (const elem of iterElements(root)) {
    const local = elem.local;
    if (local === "t" && elem.text) {
      parts.push(elem.text);
    }
    // 문단 경계 — <hp:p> 마다 줄바꿈 삽입(문단 융합 방지). lineBreak/linesegarray 도 보존.
    // ("p" 누락으로 linesegarray 없는 문단이 다음 문단과 분리자 없이 붙던 문제 수정.)
    if (local === "p" || local === "lineBreak" || local === "linesegarray") {
      parts.push("\n");
    }
  }
  return parts;
}

/** HWPX core 메타: 작성자·제목·키워드 추출. */
function extractMetadata(xmlBytes: Uint8Array): Record<string, string> {
  const meta: Record<string, string> = {};
  let root: XmlElement;
  try {
    root = parseXmlBytes(xmlBytes);
  } catch (e) {
    if (e instanceof XmlParseError) return meta;
    throw e;
  }
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
  // 메타데이터 (META-INF/core.xml 또는 docInfo.xml)
  const metaCandidates = ["META-INF/core.xml", "Contents/core.xml", "docProps/core.xml"];
  for (const mc of metaCandidates) {
    if (names.has(mc)) {
      const meta = extractMetadata(await zipRead(zf, mc));
      for (const key of [
        "creator",
        "lastModifiedBy",
        "title",
        "subject",
        "Author",
        "LastSavedBy",
        "Title",
      ]) {
        if (key in meta) {
          out.push(`[메타:${key}] ${meta[key]}\n`);
        }
      }
      break;
    }
  }
  let sectionNames = zipNames(zf)
    .filter((n) => n.startsWith("Contents/section") && n.endsWith(".xml"))
    .sort();
  if (sectionNames.length === 0) {
    // Some HWPX variants put sections elsewhere
    sectionNames = zipNames(zf)
      .filter((n) => n.endsWith(".xml") && n.toLowerCase().includes("section"))
      .sort();
  }
  for (const name of sectionNames) {
    const data = await zipRead(zf, name);
    out.push(...extractTextFromSection(data));
    out.push("\n"); // section separator
  }
  return out.join("");
}
