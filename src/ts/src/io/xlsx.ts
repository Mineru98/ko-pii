/** XLSX (Microsoft Excel OOXML) 텍스트 추출 — Python ko_pii/io_/xlsx.py 대응.
 *
 * XLSX 구조:
 *   xl/sharedStrings.xml — 모든 inline strings (lookup)
 *   xl/worksheets/sheet1.xml ... — 셀 좌표 + 값/참조
 *
 * 각 ``<c>`` 셀의 ``t`` 속성:
 *   - ``s`` : sharedStrings 인덱스
 *   - ``str`` / ``inlineStr`` : 직접 문자열
 *   - 그 외 (숫자) : ``<v>`` 텍스트
 *
 * 테이블 분석을 위한 정형 추출 (`readRecords`) + 단순 텍스트 추출 (`readText`)
 * 둘 다 제공.
 */
import { pyIsAlpha } from "../core/strUtils.js";
import type { XmlElement } from "./xmlEt.js";
import { iterElements, parseXmlBytes, XmlParseError } from "./xmlEt.js";
import type { ZipFile } from "./zipFile.js";
import { openZip, zipNames, zipRead } from "./zipFile.js";

const MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

/** Python ``root.findall("main:si", NS)`` — 직계 자식 중 main 네임스페이스 si. */
function findMainChildren(elem: XmlElement, local: string): XmlElement[] {
  return elem.children.filter((c) => c.nsUri === MAIN_NS && c.local === local);
}

/** Python ``c.find("main:v", NS)`` — 직계 자식 첫 번째. */
function findMainChild(elem: XmlElement, local: string): XmlElement | null {
  return elem.children.find((c) => c.nsUri === MAIN_NS && c.local === local) ?? null;
}

async function sharedStrings(zf: ZipFile): Promise<string[]> {
  if (!zipNames(zf).includes("xl/sharedStrings.xml")) return [];
  const root = parseXmlBytes(await zipRead(zf, "xl/sharedStrings.xml"));
  const strings: string[] = [];
  for (const si of findMainChildren(root, "si")) {
    // 각 <si> 안의 <t> 텍스트 (rich text 면 여러 개)
    const parts: string[] = [];
    for (const t of iterElements(si)) {
      if (t.nsUri === MAIN_NS && t.local === "t" && t.text) {
        parts.push(t.text);
      }
    }
    strings.push(parts.join(""));
  }
  return strings;
}

function cellValue(c: XmlElement, sst: string[]): string {
  const tAttr = c.attrs.t;
  if (tAttr === "s") {
    const v = findMainChild(c, "v");
    if (v === null || v.text === null) return "";
    // Python int(v.text) — 공백 strip + 부호 허용, 실패 시 ""
    const raw = v.text.trim();
    if (!/^[+-]?[0-9]+$/.test(raw)) return "";
    const idx = Number.parseInt(raw, 10);
    // Python list 인덱싱 — 음수는 뒤에서부터, 범위 밖은 ""
    const resolved = idx < 0 ? sst.length + idx : idx;
    return resolved >= 0 && resolved < sst.length ? (sst[resolved] ?? "") : "";
  }
  if (tAttr === "inlineStr") {
    const isElem = findMainChild(c, "is");
    if (isElem === null) return "";
    let out = "";
    for (const t of iterElements(isElem)) {
      if (t.nsUri === MAIN_NS && t.local === "t") {
        out += t.text ?? "";
      }
    }
    return out;
  }
  const v = findMainChild(c, "v");
  return v !== null && v.text !== null ? v.text : "";
}

/** 셀 참조('C5')의 0-based 열 인덱스. 참조 없으면 -1.
 *
 * 빈 셀은 XML 에서 ``<c>`` 가 생략되므로, 좌표를 무시하고 순서대로 이으면
 * 열이 왼쪽으로 밀려 정렬이 깨진다. r 속성으로 정확한 열에 배치한다.
 */
function colIndex(ref: string): number {
  let letters = "";
  for (const ch of ref) {
    if (pyIsAlpha(ch)) {
      letters += ch;
    } else if (letters) {
      break;
    }
  }
  if (!letters) return -1;
  let idx = 0;
  for (const ch of letters.toUpperCase()) {
    idx = idx * 26 + ((ch.codePointAt(0) ?? 0) - 64);
  }
  return idx - 1;
}

/** 탭/줄바꿈 구분된 텍스트로 모든 시트 + 셀 반환. */
export async function readText(path: string): Promise<string> {
  const parts: string[] = [];
  const zf = await openZip(path);
  const sst = await sharedStrings(zf);
  const sheetNames = zipNames(zf)
    .filter((n) => n.startsWith("xl/worksheets/sheet") && n.endsWith(".xml"))
    .sort();
  for (const name of sheetNames) {
    let root: XmlElement;
    try {
      root = parseXmlBytes(await zipRead(zf, name));
    } catch (e) {
      if (e instanceof XmlParseError) continue;
      throw e;
    }
    for (const row of iterElements(root)) {
      if (row.nsUri !== MAIN_NS || row.local !== "row") continue;
      const cells = new Map<number, string>();
      let seq = -1;
      for (const c of findMainChildren(row, "c")) {
        let ci = colIndex(c.attrs.r ?? "");
        if (ci < 0) ci = seq + 1;
        seq = Math.max(seq, ci);
        cells.set(ci, cellValue(c, sst));
      }
      const rowVals: string[] = [];
      for (let i = 0; i < seq + 1; i++) {
        rowVals.push(cells.get(i) ?? "");
      }
      parts.push(rowVals.join("\t"));
      parts.push("\n");
    }
    parts.push("\n"); // sheet separator
  }
  return parts.join("");
}

/** 첫 행을 헤더로, 이후 행을 ``{header: value}`` dict 리스트로 반환. */
export async function readRecords(path: string): Promise<Record<string, string>[]> {
  const text = await readText(path);
  const lines = text.split("\n").filter((ln) => ln.trim().length > 0);
  if (lines.length === 0) return [];
  const headers = lines[0]!.split("\t");
  const records: Record<string, string>[] = [];
  for (const ln of lines.slice(1)) {
    let cells = ln.split("\t");
    if (cells.length < headers.length) {
      cells = cells.concat(new Array(headers.length - cells.length).fill(""));
    }
    const record: Record<string, string> = {};
    // Python dict(zip(headers, cells[:len(headers)])) — 마지막 값이 이전 값을 덮음
    for (let i = 0; i < Math.min(headers.length, cells.length); i++) {
      record[headers[i]!] = cells[i]!;
    }
    records.push(record);
  }
  return records;
}
