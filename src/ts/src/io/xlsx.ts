/** XLSX (Microsoft Excel OOXML) 텍스트 추출 — Python ko_pii/io_/xlsx.py 대응.
 *
 * XLSX 구조:
 *   xl/sharedStrings.xml — 공유 문자열 표 (lookup)
 *   xl/worksheets/sheet1.xml ... — 셀 좌표 + 값/참조
 *
 * 각 ``<c>`` 셀의 ``t`` 속성:
 *   - ``s`` : sharedStrings 인덱스
 *   - ``str`` / ``inlineStr`` : 직접 문자열
 *   - 그 외 (숫자) : ``<v>`` 텍스트
 *
 * workbook.xml의 시트 순서와 workbook.xml.rels의 시트/공유 문자열 참조를 사용한다.
 * 테이블 분석을 위한 정형 추출 (`readRecords`) + 단순 텍스트 추출 (`readText`)을 제공한다.
 */

import { ValueError } from "../core/errors.js";
import { pyIsAlpha } from "../core/strUtils.js";
import { foldNdDigits } from "../modes/unicodeDigits.js";
import { inspectParts, isPartFailure, TextExtraction } from "./coverage.js";
import { numericSorted, pyIsBlank, pyStrip } from "./pyStr.js";
import { pyUnquoteStrict, pyUrlsplit } from "./pyUrl.js";
import { setField } from "./recordOrder.js";
import type { XmlElement } from "./xmlEt.js";
import { iterElements, parseXmlBytes } from "./xmlEt.js";
import type { ZipFile } from "./zipFile.js";
import { openZip, zipNames, zipRead } from "./zipFile.js";

const NAMESPACES = [
  "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
  "http://purl.oclc.org/ooxml/spreadsheetml/main",
] as const;
const REL_NAMESPACES = [
  "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
  "http://purl.oclc.org/ooxml/officeDocument/relationships",
] as const;
const PACKAGE_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}";
const WORKBOOK = "xl/workbook.xml";
const RELS = "xl/_rels/workbook.xml.rels";

/** Python ``elem.tag`` — ``{uri}local`` 또는 ``local``. */
function tagOf(elem: XmlElement): string {
  return elem.nsUri === null ? elem.local : `{${elem.nsUri}}${elem.local}`;
}

/** Python ``str.casefold()`` 근사 — 대문자화 후 소문자화로 ß→ss 같은 특수 폴딩을 반영한다. */
function casefold(s: string): string {
  return s.toUpperCase().toLowerCase();
}

function namespaceOf(root: XmlElement, localName: string): string {
  for (const namespace of NAMESPACES) {
    if (tagOf(root) === `{${namespace}}${localName}`) return namespace;
  }
  throw new ValueError("unsupported spreadsheet part root or namespace");
}

/** Python ``elem.findall(tag)`` — 직계 자식 중 태그 일치. */
function findAll(elem: XmlElement, tag: string): XmlElement[] {
  return elem.children.filter((c) => tagOf(c) === tag);
}

/** Python ``elem.find(tag)`` — 직계 자식 첫 번째. */
function findFirst(elem: XmlElement, tag: string): XmlElement | null {
  return elem.children.find((c) => tagOf(c) === tag) ?? null;
}

function countOf(names: readonly string[], value: string): number {
  let n = 0;
  for (const name of names) if (name === value) n += 1;
  return n;
}

async function sharedStrings(
  zf: ZipFile,
  name: string | null = "xl/sharedStrings.xml",
): Promise<string[]> {
  if (name === null || !zipNames(zf).includes(name)) return [];
  const root = parseXmlBytes(await zipRead(zf, name));
  const namespace = namespaceOf(root, "sst");
  const strings: string[] = [];
  for (const si of findAll(root, `{${namespace}}si`)) {
    // 각 <si> 안의 <t> 텍스트 (rich text 면 여러 개)
    const parts: string[] = [];
    for (const t of iterElements(si)) {
      if (tagOf(t) === `{${namespace}}t` && t.text) parts.push(t.text);
    }
    strings.push(parts.join(""));
  }
  return strings;
}

/** Python `int(text)` (10진) — 공백 strip, 부호, 유니코드 십진 숫자, 숫자 사이 밑줄. 실패 시 ValueError. */
function pyInt(text: string): number {
  const m = /^([+-]?)(\p{Nd}+(?:_\p{Nd}+)*)$/u.exec(pyStrip(text));
  if (m === null) throw new ValueError(`invalid literal for int() with base 10: '${text}'`);
  // Nd 자릿값은 공용 구현(modes/unicodeDigits)을 쓴다 — 수학 숫자(U+1D7CE~)처럼 10개 묶음이
  // 연달아 붙은 블록을 직접 세면 값이 틀어진다.
  const value = Number(foldNdDigits((m[2] ?? "").replaceAll("_", "")));
  return m[1] === "-" ? -value : value;
}

function cellValue(c: XmlElement, sst: readonly string[], namespace: string): string {
  const tAttr = c.attrs.t;
  if (tAttr === "s") {
    const v = findFirst(c, `{${namespace}}v`);
    if (v === null || v.text === null) return "";
    const index = pyInt(v.text);
    if (!(index >= 0 && index < sst.length)) {
      throw new ValueError("invalid shared string reference");
    }
    return sst[index]!;
  }
  if (tAttr === "inlineStr") {
    const isElem = findFirst(c, `{${namespace}}is`);
    if (isElem === null) return "";
    let out = "";
    for (const t of iterElements(isElem)) {
      if (tagOf(t) === `{${namespace}}t`) out += t.text ?? "";
    }
    return out;
  }
  const v = findFirst(c, `{${namespace}}v`);
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

function sheetNames(names: readonly string[]): string[] {
  return numericSorted(
    names.filter((n) => n.startsWith("xl/worksheets/sheet") && n.endsWith(".xml")),
    "sheet",
  );
}

function relationshipTarget(item: XmlElement, names: readonly string[]): string {
  const target = item.attrs.Target ?? "";
  if (/%(?![0-9a-fA-F]{2})/.test(target)) {
    throw new ValueError("invalid relationship target encoding");
  }
  const path = pyUnquoteStrict(target);
  const uri = pyUrlsplit(path);
  if (
    (item.attrs.TargetMode ?? "Internal") !== "Internal" ||
    !path ||
    path.endsWith("/") ||
    path.includes("\\") ||
    [...path].some((ch) => ch.codePointAt(0)! < 32) ||
    uri.scheme ||
    uri.netloc ||
    uri.query ||
    uri.fragment
  ) {
    throw new ValueError("unsupported relationship target");
  }
  // Resolve only ZIP member names. A leading slash is package-root relative,
  // not a host filesystem path; parent segments may not escape the package.
  const pieces: string[] = path.startsWith("/") ? [] : ["xl"];
  for (const piece of path.split("/")) {
    if (piece === "" || piece === ".") continue;
    if (piece === "..") {
      if (pieces.length === 0) throw new ValueError("relationship escapes package root");
      pieces.pop();
    } else {
      pieces.push(piece);
    }
  }
  const name = pieces.join("/");
  if (!casefold(name).endsWith(".xml") || countOf(names, name) !== 1) {
    throw new ValueError("missing, duplicate or unsupported relationship part");
  }
  return name;
}

async function workbookPlan(archive: ZipFile): Promise<[string[], string | null]> {
  const names = zipNames(archive);
  if (names.length !== new Set(names).size) {
    throw new ValueError("duplicate spreadsheet package member");
  }
  if (!names.includes(WORKBOOK) && !names.includes(RELS)) {
    return [
      sheetNames(names),
      names.includes("xl/sharedStrings.xml") ? "xl/sharedStrings.xml" : null,
    ];
  }
  if (countOf(names, WORKBOOK) !== 1 || countOf(names, RELS) !== 1) {
    throw new ValueError("missing or duplicate workbook structure");
  }
  const workbook = parseXmlBytes(await zipRead(archive, WORKBOOK));
  const namespace = namespaceOf(workbook, "workbook");
  const relationship =
    REL_NAMESPACES[NAMESPACES.indexOf(namespace as (typeof NAMESPACES)[number])]!;
  const root = parseXmlBytes(await zipRead(archive, RELS));
  if (tagOf(root) !== `${PACKAGE_REL}Relationships`) {
    throw new ValueError("unsupported workbook relationships");
  }
  const links = new Map<string, XmlElement>();
  for (const link of root.children) {
    const identity = link.attrs.Id ?? "";
    if (tagOf(link) !== `${PACKAGE_REL}Relationship` || !identity || links.has(identity)) {
      throw new ValueError("invalid or duplicate relationship ID");
    }
    links.set(identity, link);
  }
  const containers = findAll(workbook, `{${namespace}}sheets`);
  if (containers.length !== 1 || containers[0]!.children.length === 0) {
    throw new ValueError("missing or duplicate worksheet list");
  }
  const paths: string[] = [];
  const ids = new Set<number>();
  const labels = new Set<string>();
  const used = new Set<string>();
  for (const entry of containers[0]!.children) {
    const identity = entry.attrs[`{${relationship}}id`] ?? "";
    const item = links.get(identity);
    const number = pyInt(entry.attrs.sheetId ?? "");
    const label = casefold(entry.attrs.name ?? "");
    if (
      tagOf(entry) !== `{${namespace}}sheet` ||
      item === undefined ||
      item.attrs.Type !== `${relationship}/worksheet` ||
      number < 1 ||
      number > 4_294_967_295 ||
      ids.has(number) ||
      !label ||
      labels.has(label) ||
      used.has(identity)
    ) {
      throw new ValueError("invalid, duplicate or unsupported worksheet reference");
    }
    const path = relationshipTarget(item, names);
    if (paths.includes(path) || path === WORKBOOK) {
      throw new ValueError("duplicate or invalid worksheet target");
    }
    paths.push(path);
    ids.add(number);
    labels.add(label);
    used.add(identity);
  }
  const worksheetIds = new Set(
    [...links]
      .filter(([, item]) => item.attrs.Type === `${relationship}/worksheet`)
      .map(([k]) => k),
  );
  const sameIds = used.size === worksheetIds.size && [...used].every((k) => worksheetIds.has(k));
  if (!sameIds || sheetNames(names).some((name) => !paths.includes(name))) {
    throw new ValueError("unlisted worksheet part");
  }
  const strings = [...links.values()].filter(
    (item) => item.attrs.Type === `${relationship}/sharedStrings`,
  );
  if (strings.length > 1) throw new ValueError("duplicate shared string relationships");
  const shared = strings.length > 0 ? relationshipTarget(strings[0]!, names) : null;
  if (
    (shared !== null && paths.includes(shared)) ||
    shared === WORKBOOK ||
    (names.includes("xl/sharedStrings.xml") && shared !== "xl/sharedStrings.xml")
  ) {
    throw new ValueError("invalid or unlisted shared string table");
  }
  return [paths, shared];
}

/** 시트 행 — Python 제너레이터처럼 행 단위로 지연 평가한다 (오류 순서 보존). */
async function sheetRows(
  archive: ZipFile,
  name: string,
  sst: readonly string[],
): Promise<Generator<string[]>> {
  const root = parseXmlBytes(await zipRead(archive, name));
  const namespace = namespaceOf(root, "worksheet");
  return (function* (): Generator<string[]> {
    for (const row of iterElements(root)) {
      if (tagOf(row) !== `{${namespace}}row`) continue;
      const cells = new Map<number, string>();
      let seq = -1;
      for (const cell of findAll(row, `{${namespace}}c`)) {
        let column = colIndex(cell.attrs.r ?? "");
        if (column < 0) column = seq + 1;
        if (column >= 16_384) throw new ValueError("column reference exceeds spreadsheet limits");
        if (cells.has(column)) throw new ValueError("duplicate cell reference");
        seq = Math.max(seq, column);
        cells.set(column, cellValue(cell, sst, namespace));
      }
      const values: string[] = [];
      for (let index = 0; index < seq + 1; index++) values.push(cells.get(index) ?? "");
      yield values;
    }
  })();
}

/** Inspect each sheet without silently dropping parse failures. */
export async function inspectText(path: string): Promise<TextExtraction> {
  const zf = await openZip(path);
  let sst: string[] | null = null;
  let plan: [string[], string | null];
  try {
    plan = await workbookPlan(zf);
  } catch (error) {
    if (!isPartFailure(error)) throw error;
    return new TextExtraction("", [
      { part: WORKBOOK, status: "failed", reason: "invalid_workbook_relationships" },
    ]);
  }
  const [names, stringsName] = plan;
  return inspectParts(zf, names, async (archive, name) => {
    if (sst === null) sst = await sharedStrings(archive, stringsName);
    let out = "";
    for (const row of await sheetRows(archive, name, sst)) out += `${row.join("\t")}\n`;
    return out;
  });
}

/** 탭/줄바꿈 구분된 텍스트로 모든 시트 + 셀 반환. */
export async function readText(path: string): Promise<string> {
  return (await inspectText(path)).requireComplete();
}

/** Read each sheet using its own first nonempty row as headers.
 *
 * Cell strings are preserved, including tabs/newlines. Duplicate/blank headers
 * and nonempty cells beyond the headers are rejected, never silently dropped.
 * Empty rows and trailing empty formatting cells are ignored. This low-level
 * reader does not provide process isolation or validate all package relationships.
 */
export async function readRecords(path: string): Promise<Record<string, string>[]> {
  const records: Record<string, string>[] = [];
  const archive = await openZip(path);
  let plan: [string[], string | null];
  try {
    plan = await workbookPlan(archive);
  } catch (error) {
    if (!isPartFailure(error)) throw error;
    throw new ValueError("invalid workbook relationships");
  }
  const [names, stringsName] = plan;
  if (names.length === 0) throw new ValueError("spreadsheet has no supported worksheets");
  const sst = await sharedStrings(archive, stringsName);
  for (const name of names) {
    let headers: string[] | null = null;
    for (const cells of await sheetRows(archive, name, sst)) {
      if (cells.every((value) => pyIsBlank(value))) continue;
      if (headers === null) {
        // OOXML may include trailing cells solely for formatting.
        while (cells.length > 0 && cells[cells.length - 1] === "") cells.pop();
        if (cells.some((key) => pyIsBlank(key)) || new Set(cells).size !== cells.length) {
          throw new ValueError("spreadsheet headers must be nonempty and unique");
        }
        headers = cells;
        continue;
      }
      if (cells.slice(headers.length).some((value) => value !== "")) {
        throw new ValueError("spreadsheet row has values beyond its headers");
      }
      const record: Record<string, string> = {};
      for (let i = 0; i < headers.length; i++) setField(record, headers[i]!, cells[i] ?? "");
      records.push(record);
    }
  }
  return records;
}
