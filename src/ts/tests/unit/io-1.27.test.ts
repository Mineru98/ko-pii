/**
 * io 1.27 동기화 단위 테스트 — Python v1.27.0 의 새 거부 규칙·한계값 케이스 포트.
 *
 * 근거 Python 테스트: tests/unit/io_/{test_hwpx_mixed_text, test_hwpx_package,
 * test_xlsx_namespaces, test_xlsx_package, test_record_boundaries, test_text_ingestion,
 * test_numeric_boundaries}.py, tests/unit/{test_bounded_io, test_safe_processing,
 * test_failure_boundaries}.py. 기대값은 해당 Python 테스트의 단언(또는 Python 실측)이다.
 *
 * 픽스처 zip 은 Python `zipfile.writestr` 기본값(ZIP_STORED)과 같은 무압축 아카이브를
 * 아래 storedZip 으로 만든다 — 중복 멤버처럼 jszip 이 만들 수 없는 패키지도 필요하다.
 */
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 } from "node:zlib";
import { describe, expect, it } from "vitest";
import { ValueError } from "../../src/core/errors.js";
import { writeBytesAtomic, writeTextAtomic } from "../../src/io/atomic.js";
import type { BoundedDocument } from "../../src/io/bounded.js";
import { BoundedReadError, FileReadPolicy, readTextBounded } from "../../src/io/bounded.js";
import { DocumentExtractionError, TextExtraction } from "../../src/io/coverage.js";
import { readRecords, readText } from "../../src/io/dispatcher.js";
import { inspectText as inspectDocx } from "../../src/io/docx.js";
import { extractTextFromSection, inspectText as inspectHwpx } from "../../src/io/hwpx.js";
import { defaultReadPolicy, readTextIsolated } from "../../src/io/isolated.js";
import {
  inspectText as inspectPdf,
  PdfExtractionError,
  readText as readPdf,
} from "../../src/io/pdf.js";
import { readText as readPlain, TextDecodingError } from "../../src/io/plain.js";
import { normalizeForDetection } from "../../src/io/textNormalizer.js";
import { inspectText as inspectXlsx } from "../../src/io/xlsx.js";

// ---------------------------------------------------------------------------
// 픽스처 헬퍼
// ---------------------------------------------------------------------------

const DIR = mkdtempSync(join(tmpdir(), "ko-pii-io-127-"));
let serial = 0;

function tmpPath(name: string): string {
  serial += 1;
  return join(DIR, `${serial}-${name}`);
}

type Entry = [name: string, content: string | Uint8Array];

/** Python `zipfile.ZipFile(path, "w").writestr(...)` 와 같은 무압축 zip (중복 이름 허용). */
function storedZip(entries: readonly Entry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const nameBytes = Buffer.from(name, "utf-8");
    const data = typeof content === "string" ? Buffer.from(content, "utf-8") : Buffer.from(content);
    const crc = crc32(data) >>> 0;
    const flags = nameBytes.length !== name.length ? 0x800 : 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, data);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

function writeZip(name: string, entries: readonly Entry[] | Record<string, string | Uint8Array>) {
  const path = tmpPath(name);
  writeFileSync(path, storedZip(Array.isArray(entries) ? entries : Object.entries(entries)));
  return path;
}

function writeBytes(name: string, data: string | Uint8Array): string {
  const path = tmpPath(name);
  writeFileSync(path, data);
  return path;
}

/** Python `str.encode("utf-16")` — BOM(LE) + UTF-16LE. */
function utf16(text: string): Buffer {
  return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);
}

async function boundedCode(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (error) {
    if (error instanceof BoundedReadError) return error.code;
    throw error;
  }
  return "OK";
}

async function textOf(result: Promise<string | BoundedDocument>): Promise<string> {
  const value = await result;
  return typeof value === "string" ? value : value.text;
}

const TEXT_READERS = {
  readText: (path: string) => readText(path),
  readTextBounded: (path: string) => readTextBounded(path),
} as const;

// ---------------------------------------------------------------------------
// atomic.py
// ---------------------------------------------------------------------------

describe("atomic — 임시 파일 + rename (test_safe_processing.py)", () => {
  it("새 파일은 소유자 전용 권한, 심볼릭 링크는 따라가지 않는다", () => {
    const target = tmpPath("vault");
    writeBytesAtomic(target, Buffer.from("state"));
    if (process.platform !== "win32") expect(statSync(target).mode & 0o777).toBe(0o600);
    const link = tmpPath("link");
    symlinkSync(target, link);
    expect(() => writeBytesAtomic(link, Buffer.from("changed"))).toThrow(/symbolic/);
    expect(readFileSync(target, "utf-8")).toBe("state");
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
  });

  it("기존 파일을 교체하고 임시 파일을 남기지 않는다", () => {
    const dir = mkdtempSync(join(tmpdir(), "ko-pii-atomic-"));
    const target = join(dir, "out.txt");
    writeFileSync(target, "previous");
    writeTextAtomic(target, "새 내용");
    expect(readFileSync(target, "utf-8")).toBe("새 내용");
    expect(readdirSync(dir)).toEqual(["out.txt"]);
  });

  it("rename 실패 시 이전 대상과 디렉터리 상태를 보존한다", () => {
    const dir = mkdtempSync(join(tmpdir(), "ko-pii-atomic-"));
    const target = join(dir, "busy");
    // 비어 있지 않은 디렉터리로의 rename 은 실패한다 (EISDIR/ENOTEMPTY) — 교체 실패 재현
    const sub = join(target, "child");
    writeFileSync(join(dir, "keep"), "x");
    mkdirSync(target);
    writeFileSync(sub, "previous");
    expect(() => writeTextAtomic(target, "changed")).toThrow();
    expect(readFileSync(sub, "utf-8")).toBe("previous");
    expect(readdirSync(dir).sort()).toEqual(["busy", "keep"]);
  });
});

// ---------------------------------------------------------------------------
// coverage.py
// ---------------------------------------------------------------------------

describe("coverage — TextExtraction / DocumentExtractionError", () => {
  it("실패 파트가 있으면 텍스트 유무로 partial/failed, 없으면 complete", () => {
    const failed = { part: "b", status: "failed", reason: "part_parse_failed" } as const;
    expect(new TextExtraction("x", [{ part: "a", status: "read" }]).coverage.status).toBe(
      "complete",
    );
    expect(new TextExtraction("x", [{ part: "a", status: "read" }, failed]).coverage.status).toBe(
      "partial",
    );
    expect(new TextExtraction(" \n", [failed]).coverage.status).toBe("failed");
    const error = (() => {
      try {
        new TextExtraction("x", [failed]).requireComplete();
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect(error).toBeInstanceOf(DocumentExtractionError);
    expect(error).toBeInstanceOf(ValueError);
    expect((error as DocumentExtractionError).code).toBe("document_extraction_incomplete");
    expect((error as DocumentExtractionError).message).toBe(
      "document text extraction incomplete; review failed parts",
    );
    expect(() => new TextExtraction("x", []).requireComplete()).toThrow(DocumentExtractionError);
  });

  it("부분 파싱 실패 docx 는 내용 없는 coverage 를 남긴다 (Python 실측)", async () => {
    const path = writeZip("partial.docx", {
      "word/document.xml": "<document><t>normal</t></document>",
      "word/header1.xml": "<header><t>010-1234-5678",
    });
    const result = await inspectDocx(path);
    expect(result.text).toBe("normal");
    expect(result.coverage).toEqual({
      status: "partial",
      scope: "discovered_supported_text_parts",
      parts: [
        { part: "word/document.xml", status: "read" },
        { part: "word/header1.xml", status: "failed", reason: "part_parse_failed" },
      ],
      limitations: [
        "embedded_images_not_ocr_checked",
        "unsupported_parts_not_inspected",
        "package_relationships_not_validated",
      ],
    });
    expect(JSON.stringify(result.coverage)).not.toContain("010-1234-5678");
  });

  it.each(["word/header1.XML", "word/footer1.Xml"])(
    "대소문자가 다른 docx 텍스트 파트도 coverage 에 남는다: %s",
    async (part) => {
      const path = writeZip("case.docx", {
        "word/document.xml": "<document><t>normal</t></document>",
        [part]: "<header><t>010-1234-5678</t></header>",
      });
      const document = await readTextBounded(path);
      expect(document.text).toContain("010-1234-5678");
      expect(document.coverage?.parts).toContainEqual({ part, status: "read" });
    },
  );

  it("알 수 없는 XML 인코딩은 실패 파트로 기록된다", async () => {
    const path = writeZip("enc.docx", {
      "word/document.xml": "<document><t>normal</t></document>",
      "word/header1.xml": '<?xml version="1.0" encoding="NOT-AN-ENCODING"?><header/>',
    });
    expect((await inspectDocx(path)).coverage.status).toBe("partial");
    try {
      await readTextBounded(path);
      expect.fail("expected rejection");
    } catch (e) {
      expect((e as BoundedReadError).code).toBe("document_extraction_incomplete");
      expect((e as BoundedReadError).coverage?.parts[1]?.status).toBe("failed");
    }
  });
});

// ---------------------------------------------------------------------------
// hwpx.py — 인라인 컨트롤 tail 보존 (test_hwpx_mixed_text.py)
// ---------------------------------------------------------------------------

const PARAGRAPH_NS = "http://www.hancom.co.kr/hwpml/2011/paragraph";
const SECTION_NS = "http://www.hancom.co.kr/hwpml/2011/section";
const CONTROLS: Array<[string, string]> = [
  ["tab", "\t"],
  ["lineBreak", "\n"],
  ["nbSpace", "\u00a0"],
  ["fwSpace", "\u3000"],
  ["hyphen", "\u00ad"],
];
const MARKS = [
  "markpenBegin",
  "markpenEnd",
  "titleMark",
  "insertBegin",
  "insertEnd",
  "deleteBegin",
  "deleteEnd",
];
const EMAILS = ["first@example.com", "second@example.com"];

function section(body: string): Buffer {
  return Buffer.from(
    `<hs:sec xmlns:hs="${SECTION_NS}" xmlns:hp="${PARAGRAPH_NS}">${body}</hs:sec>`,
    "utf-8",
  );
}

function paragraph(text: string): string {
  return `<hp:p id="0"><hp:run charPrIDRef="0"><hp:t>${text}</hp:t></hp:run></hp:p>`;
}

function sectionText(body: string): string {
  return extractTextFromSection(section(body)).join("");
}

function mixedPackage(body: string, later?: string): string {
  const entries: Entry[] = [
    ["mimetype", "application/hwp+zip"],
    ["Contents/section0.xml", section(body)],
  ];
  if (later !== undefined) entries.push(["Contents/section1.xml", later]);
  return writeZip("contacts.hwpx", entries);
}

describe("hwpx — 인라인 컨트롤 뒤 텍스트 (test_hwpx_mixed_text.py)", () => {
  for (const [control, character] of CONTROLS) {
    for (const prefix of ["", "label:"]) {
      it(`<hp:${control}/> 뒤 텍스트 보존 (prefix=${JSON.stringify(prefix)})`, () => {
        expect(sectionText(paragraph(`${prefix}<hp:${control}/>${EMAILS[0]}`))).toBe(
          `\n${prefix}${character}${EMAILS[0]}`,
        );
      });
    }
  }

  for (const mark of MARKS) {
    for (const prefix of ["", "first"]) {
      it(`비출력 표식 <hp:${mark}/> 은 텍스트를 떨어뜨리거나 가르지 않는다 (${prefix})`, () => {
        expect(sectionText(paragraph(`${prefix}<hp:${mark} id="1"/>@example.com`))).toBe(
          `\n${prefix}@example.com`,
        );
      });
    }
  }

  it("혼합 컨트롤은 순서대로 정확히 한 번", () => {
    const body = paragraph(
      'A<hp:tab/>B<hp:lineBreak/>C<hp:markpenBegin color="#000000"/>' +
        "D<hp:markpenEnd/>E<hp:nbSpace/>F<hp:fwSpace/>G<hp:hyphen/>H",
    );
    expect(sectionText(body)).toBe("\nA\tB\nCDE\u00a0F\u3000G\u00adH");
  });

  it("일반 run 과 문단 구분자는 호환된다", () => {
    const body =
      "<hp:p><hp:run><hp:t>one</hp:t></hp:run><hp:run><hp:t>two</hp:t></hp:run>" +
      `<hp:linesegarray/></hp:p>${paragraph("three")}`;
    expect(sectionText(body)).toBe("\nonetwo\n\nthree");
  });

  it("텍스트 범위는 XML 들여쓰기·속성을 담지 않는다", () => {
    const body =
      '<hp:p attr="attribute-secret">\n  <hp:run>outside-before<hp:t>A<hp:tab/>' +
      "B</hp:t>outside-after</hp:run>\n</hp:p>";
    expect(sectionText(body)).toBe("\nA\tB");
  });

  it("빈 텍스트·중첩 텍스트는 값을 중복하지 않는다", () => {
    expect(sectionText(`${paragraph("<hp:t>A<hp:tab/>B</hp:t>C")}${paragraph("")}`)).toBe(
      "\nA\tBC\n",
    );
  });

  it("깊은 구조(1500단)도 재귀 한도 없이 추출된다", () => {
    const depth = 1500;
    const body =
      "<hp:subList>".repeat(depth) +
      paragraph(`<hp:tab/>${EMAILS[0]}`) +
      "</hp:subList>".repeat(depth);
    expect(sectionText(body)).toBe(`\n\t${EMAILS[0]}`);
  });

  for (const [name, reader] of Object.entries(TEXT_READERS)) {
    it(`모든 텍스트 리더가 인라인 내용을 보존한다: ${name}`, async () => {
      const path = mixedPackage(
        paragraph(`email:<hp:tab/>${EMAILS[0]}<hp:lineBreak/>${EMAILS[1]}`),
      );
      const [expected] = normalizeForDetection(`\nemail:\t${EMAILS[0]}\n${EMAILS[1]}`);
      expect(await textOf(reader(path))).toBe(expected);
    });
  }

  it("중첩 표·머리말 텍스트도 한 번씩 검사된다", async () => {
    const body =
      "<hp:p><hp:run><hp:ctrl><hp:header><hp:subList>" +
      paragraph(`<hp:tab/>${EMAILS[0]}`) +
      "</hp:subList></hp:header></hp:ctrl><hp:tbl><hp:tr><hp:tc><hp:subList>" +
      paragraph(`<hp:lineBreak/>${EMAILS[1]}`) +
      "</hp:subList></hp:tc></hp:tr></hp:tbl></hp:run></hp:p>";
    const result = await inspectHwpx(mixedPackage(body));
    expect(result.coverage.status).toBe("complete");
    expect(result.parts[0]?.status).toBe("read");
    for (const value of EMAILS) expect(result.text.split(value).length - 1).toBe(1);
  });

  it("뒤 섹션 파싱 실패는 부분 텍스트 게시를 막는다", async () => {
    const path = mixedPackage(paragraph(`email:<hp:tab/>${EMAILS[0]}`), "<broken>");
    expect(await boundedCode(() => readTextBounded(path))).toBe("document_extraction_incomplete");
    await expect(readText(path)).rejects.toBeInstanceOf(DocumentExtractionError);
    expect((await inspectHwpx(path)).coverage.status).toBe("partial");
  });

  it("복원된 tail 도 텍스트 한도에 포함된다", async () => {
    const path = mixedPackage(paragraph(`email:<hp:tab/>${EMAILS[0]}`));
    expect(
      await boundedCode(() => readTextBounded(path, new FileReadPolicy({ maxTextChars: 12 }))),
    ).toBe("extracted_text_too_large");
  });
});

// ---------------------------------------------------------------------------
// hwpx.py — content.hpf 매니페스트/spine (test_hwpx_package.py)
// ---------------------------------------------------------------------------

const OPF = "http://www.idpf.org/2007/opf/";
const HEAD = "http://www.hancom.co.kr/hwpml/2011/head";
const MANIFEST = "Contents/content.hpf";

function xmlAttr(value: string): string {
  return `"${value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll('"', "&quot;")}"`;
}

function body(text: string): string {
  return `<sec xmlns="${SECTION_NS}"><p xmlns="${PARAGRAPH_NS}"><run><t>${text}</t></run></p></sec>`;
}

function content(
  items: Array<[string, string]>,
  spine: string[],
  options: { metadata?: string; namespace?: string } = {},
): string {
  const itemXml = items
    .map(
      ([key, path]) =>
        `<item id=${xmlAttr(key)} href=${xmlAttr(path)} media-type="application/xml"/>`,
    )
    .join("");
  const refs = spine.map((key) => `<itemref idref=${xmlAttr(key)}/>`).join("");
  return (
    `<package xmlns="${options.namespace ?? OPF}"><metadata>${options.metadata ?? ""}</metadata>` +
    `<manifest>${itemXml}</manifest><spine>${refs}</spine></package>`
  );
}

function hwpxPackage(xml: string | Uint8Array | null, parts: Record<string, string>): string {
  const entries: Entry[] = [["mimetype", "application/hwp+zip"]];
  if (xml !== null) entries.push([MANIFEST, xml]);
  for (const [name, text] of Object.entries(parts)) entries.push([name, text]);
  return writeZip("package.hwpx", entries);
}

async function expectHwpxFailed(path: string): Promise<void> {
  const result = await inspectHwpx(path);
  expect(["partial", "failed"]).toContain(result.coverage.status);
  expect(() => result.requireComplete()).toThrow(DocumentExtractionError);
}

describe("hwpx — 패키지 순서와 선언된 본문 (test_hwpx_package.py)", () => {
  for (const [name, reader] of Object.entries(TEXT_READERS)) {
    it(`파일명·zip 순서가 아니라 spine 이 순서를 정한다: ${name}`, async () => {
      const xml = content(
        [
          ["a", "Contents/section0.xml"],
          ["b", "Contents/section1.xml"],
        ],
        ["b", "a"],
      );
      const path = hwpxPackage(xml, {
        "Contents/section0.xml": body("first@example.com"),
        "Contents/section1.xml": body("second@example.com"),
      });
      const text = await textOf(reader(path));
      expect(text.indexOf("second@example.com")).toBeLessThan(text.indexOf("first@example.com"));
    });
  }

  it("spine 순서 텍스트와 파트 목록 (Python 실측)", async () => {
    const xml = content(
      [
        ["a", "Contents/section0.xml"],
        ["b", "Contents/section1.xml"],
      ],
      ["b", "a"],
      { metadata: "<title>T</title>" },
    );
    const path = hwpxPackage(xml, {
      "Contents/section0.xml": body("first"),
      "Contents/section1.xml": body("second"),
    });
    const result = await inspectHwpx(path);
    expect(result.text).toBe("[메타:title] T\n\nsecond\n\nfirst");
    expect(result.parts).toEqual([
      { part: MANIFEST, status: "read" },
      { part: "Contents/section1.xml", status: "read" },
      { part: "Contents/section0.xml", status: "read" },
    ]);
    expect((await readTextBounded(path)).text).toBe("[메타:title] T\n\nsecond\n\nfirst");
  });

  for (const href of ["Contents/body.xml", "body.xml", "./body.xml", "body%20one.xml"]) {
    it(`매니페스트가 section 이름이 아닌 본문을 가리킬 수 있다: ${href}`, async () => {
      const part = href.includes("%20") ? "Contents/body one.xml" : "Contents/body.xml";
      const path = hwpxPackage(content([["body", href]], ["body"]), {
        [part]: body("first@example.com"),
      });
      expect(await readText(path)).toContain("first@example.com");
      expect((await readTextBounded(path)).text).toContain("first@example.com");
    });
  }

  for (const namespace of [OPF, OPF.replace(/\/$/, "")]) {
    it(`메타데이터·헤더를 읽되 본문 순서는 그대로 (${namespace})`, async () => {
      const xml = content(
        [
          ["head", "Contents/header.xml"],
          ["a", "Contents/section0.xml"],
        ],
        ["head", "a"],
        {
          metadata:
            '<title>title@example.com</title><meta name="creator" content="text">' +
            'author@example.com</meta><meta name="creator" content="text">' +
            'other@example.com</meta><meta name="keyword" content="text">' +
            "keyword@example.com</meta>",
          namespace,
        },
      );
      const path = hwpxPackage(xml, {
        "Contents/header.xml": `<head xmlns="${HEAD}"/>`,
        "Contents/section0.xml": body("body@example.com"),
      });
      const result = await inspectHwpx(path);
      expect(result.coverage.status).toBe("complete");
      for (const value of ["title", "author", "other", "keyword", "body"]) {
        expect(result.text.split(`${value}@example.com`).length - 1).toBe(1);
      }
      expect(result.parts.map((part) => part.part)).toEqual([
        MANIFEST,
        "Contents/header.xml",
        "Contents/section0.xml",
      ]);
    });
  }

  it("접두어·non-linear spine 도 본문을 숨기지 않는다", async () => {
    const xml =
      `<o:package xmlns:o="${OPF}"><o:manifest>` +
      '<o:item id="a" href="Contents/section0.xml" media-type="application/xml"/>' +
      '</o:manifest><o:spine><o:itemref idref="a" linear="no"/></o:spine></o:package>';
    const path = hwpxPackage(xml, { "Contents/section0.xml": body("first@example.com") });
    expect(await readText(path)).toContain("first@example.com");
  });

  const broken: Array<[string, string]> = [
    ["broken", "<broken>"],
    ["empty-package", "<package/>"],
    ["missing-idref", content([["a", "Contents/section0.xml"]], ["missing"])],
    [
      "duplicate-id",
      content(
        [
          ["a", "Contents/section0.xml"],
          ["a", "Contents/section1.xml"],
        ],
        ["a"],
      ),
    ],
    ["duplicate-ref", content([["a", "Contents/section0.xml"]], ["a", "a"])],
    [
      "duplicate-target",
      content(
        [
          ["a", "Contents/section0.xml"],
          ["b", "Contents/section0.xml"],
        ],
        ["a", "b"],
      ),
    ],
    ["empty-spine", content([["a", "Contents/section0.xml"]], [])],
    [
      "wrong-spine",
      content([["a", "Contents/section0.xml"]], ["a"])
        .replace("<spine>", "<wrong>")
        .replace("</spine>", "</wrong>"),
    ],
    [
      "unknown-namespace",
      content([["a", "Contents/section0.xml"]], ["a"], { namespace: "urn:unknown" }),
    ],
  ];
  for (const [label, xml] of broken) {
    it(`깨진 패키지는 발견된 본문으로 폴백하지 않는다: ${label}`, async () => {
      const path = hwpxPackage(xml, { "Contents/section0.xml": body("first@example.com") });
      await expectHwpxFailed(path);
      const result = await inspectHwpx(path);
      expect(result.parts).toEqual([
        { part: MANIFEST, status: "failed", reason: "invalid_content_manifest" },
      ]);
    });
  }

  for (const href of [
    "https://example.com/body.xml",
    "//example.com/body.xml",
    "/Contents/section0.xml",
    "../outside.xml",
    "Contents/section0.xml?query",
    "Contents/section0.xml#fragment",
    "Contents\\section0.xml",
    "C:/section0.xml",
    "%2e%2e/outside.xml",
    "%68ttps://example.com/body.xml",
    "",
  ]) {
    it(`안전하지 않거나 원격인 spine 경로는 따라가지 않는다: ${JSON.stringify(href)}`, async () => {
      const path = hwpxPackage(content([["a", href]], ["a"]), {
        "Contents/section0.xml": body("first@example.com"),
      });
      await expectHwpxFailed(path);
    });
  }

  it("선언된 본문이 없으면 있는 본문 뒤에 실패한다", async () => {
    const xml = content(
      [
        ["a", "Contents/section0.xml"],
        ["b", "Contents/section1.xml"],
      ],
      ["a", "b"],
    );
    const path = hwpxPackage(xml, { "Contents/section0.xml": body("first@example.com") });
    await expectHwpxFailed(path);
    expect(await boundedCode(() => readTextBounded(path))).toBe("document_extraction_incomplete");
  });

  it("참조되지 않은 section 은 조용히 빠지지 않는다", async () => {
    const path = hwpxPackage(content([["a", "Contents/section0.xml"]], ["a"]), {
      "Contents/section0.xml": body("first@example.com"),
      "Contents/section1.xml": body("second@example.com"),
    });
    await expectHwpxFailed(path);
  });

  for (const invalid of ["<wrong/>", '<sec xmlns="urn:unknown"/>', "<broken>"]) {
    it(`알 수 없는 spine XML 은 빈 본문으로 취급되지 않는다: ${invalid}`, async () => {
      const xml = content(
        [
          ["a", "Contents/section0.xml"],
          ["b", "Contents/section1.xml"],
        ],
        ["a", "b"],
      );
      const path = hwpxPackage(xml, {
        "Contents/section0.xml": body("first@example.com"),
        "Contents/section1.xml": invalid,
      });
      await expectHwpxFailed(path);
    });
  }

  it("본문 없는 매니페스트는 성공이 아니다", async () => {
    const path = hwpxPackage(content([["header", "Contents/header.xml"]], ["header"]), {
      "Contents/header.xml": `<head xmlns="${HEAD}"/>`,
    });
    await expectHwpxFailed(path);
    expect((await inspectHwpx(path)).parts.at(-1)).toEqual({
      part: "(body)",
      status: "failed",
      reason: "missing_body_sections",
    });
  });

  it("매니페스트 없는 레거시 section 은 숫자 순서", async () => {
    const parts: Record<string, string> = {};
    for (let i = 11; i >= 0; i--) {
      parts[`Contents/section${i}.xml`] = body(`row-${String(i).padStart(2, "0")}`);
    }
    const text = await readText(hwpxPackage(null, parts));
    const positions = Array.from({ length: 12 }, (_, i) =>
      text.indexOf(`row-${String(i).padStart(2, "0")}`),
    );
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  for (const encoding of ["utf-8", "utf-16"] as const) {
    it(`content.hpf 의 DTD 는 새 메타데이터 파서보다 먼저 검사된다 (${encoding})`, async () => {
      let xml = `<?xml version="1.0" encoding="${encoding}"?><!DOCTYPE package [<!ENTITY x "first@example.com">]>`;
      xml += content([["a", "Contents/section0.xml"]], ["a"], { metadata: "<title>&x;</title>" });
      const path = hwpxPackage(encoding === "utf-8" ? Buffer.from(xml, "utf-8") : utf16(xml), {
        "Contents/section0.xml": body("body text"),
      });
      expect(await boundedCode(() => readTextBounded(path))).toBe("xml_dtd_rejected");
    });
  }

  for (const target of [MANIFEST, "META-INF/core.xml", "Contents/core.xml", "docProps/core.xml"]) {
    it(`메타데이터 파트를 본문으로 재해석하지 않는다: ${target}`, async () => {
      const parts: Record<string, string> = { "Contents/section0.xml": body("first@example.com") };
      if (target !== MANIFEST) parts[target] = "<core><creator>author@example.com</creator></core>";
      const xml = content(
        [
          ["a", "Contents/section0.xml"],
          ["b", target],
        ],
        ["a", "b"],
      );
      await expectHwpxFailed(hwpxPackage(xml, parts));
    });
  }

  it("루트 경로와 상대 경로가 모호하면 거부한다", async () => {
    const path = hwpxPackage(content([["a", "body.xml"]], ["a"]), {
      "body.xml": body("first@example.com"),
      "Contents/body.xml": body("second@example.com"),
    });
    await expectHwpxFailed(path);
  });

  it("매니페스트 메타데이터도 텍스트 한도에 포함된다", async () => {
    const path = hwpxPackage(
      content([["a", "Contents/section0.xml"]], ["a"], {
        metadata: '<meta name="creator" content="text">author@example.com</meta>',
      }),
      { "Contents/section0.xml": body("x") },
    );
    expect(
      await boundedCode(() => readTextBounded(path, new FileReadPolicy({ maxTextChars: 10 }))),
    ).toBe("extracted_text_too_large");
  });

  for (const extra of [
    '<itemref xmlns="urn:unknown" idref="missing"/>',
    '<unknown idref="missing"/>',
  ]) {
    it(`알 수 없는 spine 항목이 누락 참조를 숨기지 않는다: ${extra}`, async () => {
      const xml = content([["a", "Contents/section0.xml"]], ["a"]).replace(
        "</spine>",
        `${extra}</spine>`,
      );
      await expectHwpxFailed(
        hwpxPackage(xml, { "Contents/section0.xml": body("first@example.com") }),
      );
    });
  }

  it("저수준 검사도 중복 매니페스트 멤버를 거부한다", async () => {
    const xml = content([["a", "Contents/section0.xml"]], ["a"]);
    const path = writeZip("duplicate.hwpx", [
      ["mimetype", "application/hwp+zip"],
      [MANIFEST, xml],
      ["Contents/section0.xml", body("first@example.com")],
      [MANIFEST, xml],
    ]);
    await expectHwpxFailed(path);
  });
});

// ---------------------------------------------------------------------------
// xlsx.py — 네임스페이스 (test_xlsx_namespaces.py)
// ---------------------------------------------------------------------------

const TRANSITIONAL = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const STRICT = "http://purl.oclc.org/ooxml/spreadsheetml/main";
const REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const SREL = "http://purl.oclc.org/ooxml/officeDocument/relationships";
const PKG = "http://schemas.openxmlformats.org/package/2006/relationships";
const WORKBOOK = "xl/workbook.xml";
const RELS = "xl/_rels/workbook.xml.rels";
const VALUE = "first@example.com";

function element(name: string, inner = "", attrs = "", prefix = ""): string {
  return `<${prefix}${name}${attrs}>${inner}</${prefix}${name}>`;
}

interface NsPackageOptions {
  shared?: boolean;
  prefix?: string;
  extraSheet?: string;
  sheetRoot?: string;
  sharedRoot?: string;
  sharedNamespace?: string;
}

function nsPackage(namespace: string, options: NsPackageOptions = {}): string {
  const { shared = false, prefix = "", extraSheet, sheetRoot = "worksheet" } = options;
  const xml = (name: string, inner: string, ns = namespace): string => {
    const declaration = ns ? ` xmlns${prefix ? `:${prefix.slice(0, -1)}` : ""}="${ns}"` : "";
    return element(name, inner, declaration, prefix);
  };
  const tag = (name: string, inner = "", attrs = ""): string => element(name, inner, attrs, prefix);
  const values = ["email", "memo", VALUE, "public"];
  const rows: string[] = [];
  for (let index = 0; index < 2; index++) {
    const cells: string[] = [];
    for (let column = 0; column < 2; column++) {
      const position = index * 2 + column;
      const attrs = ` r="${String.fromCharCode(65 + column)}${index + 1}"`;
      const value = values[position] ?? "";
      if (shared) {
        cells.push(tag("c", tag("v", String(position)), `${attrs} t="s"`));
      } else {
        const runs = tag("r", tag("t", value.slice(0, 3))) + tag("r", tag("t", value.slice(3)));
        cells.push(tag("c", tag("is", runs), `${attrs} t="inlineStr"`));
      }
    }
    rows.push(tag("row", cells.join(""), ` r="${index + 1}"`));
  }
  const sheet = xml(sheetRoot, tag("sheetData", rows.join("")));
  const relationshipNs = namespace === STRICT ? SREL : REL;
  const entries: Entry[] = [
    [
      "_rels/.rels",
      `<Relationships xmlns="${PKG}"><Relationship Id="rId1" Type="${relationshipNs}/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
    ],
    [
      WORKBOOK,
      `<workbook xmlns="${namespace}" xmlns:r="${relationshipNs}"><sheets><sheet name="Contacts" sheetId="1" r:id="rId1"/>` +
        (extraSheet !== undefined ? '<sheet name="Other" sheetId="2" r:id="rId3"/>' : "") +
        "</sheets></workbook>",
    ],
    [
      RELS,
      `<Relationships xmlns="${PKG}"><Relationship Id="rId1" Type="${relationshipNs}/worksheet" Target="worksheets/sheet1.xml"/>` +
        (shared
          ? `<Relationship Id="rId2" Type="${relationshipNs}/sharedStrings" Target="sharedStrings.xml"/>`
          : "") +
        (extraSheet !== undefined
          ? `<Relationship Id="rId3" Type="${relationshipNs}/worksheet" Target="worksheets/sheet2.xml"/>`
          : "") +
        "</Relationships>",
    ],
    ["xl/worksheets/sheet1.xml", sheet],
  ];
  if (shared) {
    const strings = values
      .map((value) =>
        tag("si", tag("r", tag("t", value.slice(0, 3))) + tag("r", tag("t", value.slice(3)))),
      )
      .join("");
    entries.push([
      "xl/sharedStrings.xml",
      xml(options.sharedRoot ?? "sst", strings, options.sharedNamespace ?? namespace),
    ]);
  }
  if (extraSheet !== undefined) entries.push(["xl/worksheets/sheet2.xml", extraSheet]);
  return writeZip("contacts.xlsx", entries);
}

const UNSUPPORTED_SHEET = '<worksheet xmlns="urn:unsupported"><sheetData/></worksheet>';

describe("xlsx — 방언이 빈 시트로 취급되지 않는다 (test_xlsx_namespaces.py)", () => {
  for (const namespace of [TRANSITIONAL, STRICT]) {
    for (const shared of [false, true]) {
      for (const prefix of ["", "s:"]) {
        it(`네임스페이스가 셀을 보존한다 (${namespace === STRICT ? "strict" : "transitional"}, shared=${shared}, prefix=${JSON.stringify(prefix)})`, async () => {
          const path = nsPackage(namespace, { shared, prefix });
          expect(await readRecords(path)).toEqual([{ email: VALUE, memo: "public" }]);
          const inspection = await inspectXlsx(path);
          expect(inspection.coverage.status).toBe("complete");
          expect(inspection.parts[0]?.status).toBe("read");
          expect(inspection.text).toBe(`email\tmemo\n${VALUE}\tpublic\n`);
          expect((await readTextBounded(path)).text).toContain(VALUE);
        });
      }
    }
  }

  for (const [namespace, root] of [
    ["", "worksheet"],
    ["urn:unsupported", "worksheet"],
    [TRANSITIONAL, "notWorksheet"],
    [STRICT, "notWorksheet"],
  ] as const) {
    it(`알 수 없는 워크시트는 빈 시트가 아니라 실패 (${namespace || "no-ns"}, ${root})`, async () => {
      const path = nsPackage(namespace, { sheetRoot: root });
      await expect(readRecords(path)).rejects.toBeInstanceOf(ValueError);
      const inspection = await inspectXlsx(path);
      expect(inspection.coverage.status).toBe("failed");
      expect(JSON.stringify(inspection.coverage)).not.toContain(VALUE);
      expect(() => inspection.requireComplete()).toThrow(DocumentExtractionError);
    });
  }

  for (const [namespace, root] of [
    ["", "sst"],
    ["urn:unsupported", "sst"],
    [STRICT, "notSst"],
  ] as const) {
    it(`알 수 없는 공유 문자열 표는 거부된다 (${namespace || "no-ns"}, ${root})`, async () => {
      const path = nsPackage(STRICT, {
        shared: true,
        sharedNamespace: namespace,
        sharedRoot: root,
      });
      await expect(readRecords(path)).rejects.toBeInstanceOf(ValueError);
      expect((await inspectXlsx(path)).coverage.status).toBe("failed");
    });
  }

  it("알 수 없는 뒤 시트가 완전한 결과에서 사라지지 않는다", async () => {
    const path = nsPackage(TRANSITIONAL, { extraSheet: UNSUPPORTED_SHEET });
    const inspection = await inspectXlsx(path);
    expect(inspection.text).toContain(VALUE);
    expect(inspection.coverage.status).toBe("partial");
    expect(() => inspection.requireComplete()).toThrow(DocumentExtractionError);
    await expect(readRecords(path)).rejects.toBeInstanceOf(ValueError);
    await expect(readText(path)).rejects.toBeInstanceOf(ValueError);
    expect(await boundedCode(() => readTextBounded(path))).toBe("document_extraction_incomplete");
  });

  for (const namespace of [TRANSITIONAL, STRICT]) {
    it(`유효한 빈 워크시트는 여전히 비어 있다 (${namespace})`, async () => {
      const path = writeZip("empty.xlsx", {
        "xl/worksheets/sheet1.xml": `<worksheet xmlns="${namespace}"><sheetData/></worksheet>`,
      });
      expect(await readRecords(path)).toEqual([]);
      expect((await inspectXlsx(path)).parts[0]?.status).toBe("empty");
    });

    for (const [cellType, value] of [
      ["str", VALUE],
      ["n", "123.5"],
      ["b", "1"],
      ["d", "2020-01-01"],
    ] as const) {
      it(`캐시된 스칼라 값도 시트 네임스페이스를 쓴다 (${cellType}, ${namespace})`, async () => {
        const path = writeZip("scalar.xlsx", {
          "xl/worksheets/sheet1.xml":
            `<worksheet xmlns="${namespace}"><sheetData>` +
            '<row><c t="inlineStr"><is><t>memo</t></is></c></row>' +
            `<row><c t="${cellType}"><v>${value}</v></c></row></sheetData></worksheet>`,
        });
        expect(await readRecords(path)).toEqual([{ memo: value }]);
      });
    }
  }

  for (const [first, second] of [
    [TRANSITIONAL, STRICT],
    [STRICT, TRANSITIONAL],
  ] as const) {
    it("네임스페이스 선택은 통합 문서가 아니라 파트 단위", async () => {
      const other =
        `<worksheet xmlns="${second}"><sheetData>` +
        '<row><c t="inlineStr"><is><t>email</t></is></c></row>' +
        '<row><c t="inlineStr"><is><t>second@example.com</t></is></c></row></sheetData></worksheet>';
      const path = nsPackage(first, { extraSheet: other });
      expect(await readRecords(path)).toEqual([
        { email: VALUE, memo: "public" },
        { email: "second@example.com" },
      ]);
      expect((await readTextBounded(path)).text).toContain("second@example.com");
    });
  }
});

// ---------------------------------------------------------------------------
// xlsx.py — 통합 문서 관계 (test_xlsx_package.py)
// ---------------------------------------------------------------------------

function sheetXml(value: string, namespace = TRANSITIONAL, shared = false): string {
  const cells = shared
    ? ['<c t="s"><v>0</v></c>', '<c t="s"><v>1</v></c>']
    : ["email", value].map((text) => `<c t="inlineStr"><is><t>${text}</t></is></c>`);
  return (
    `<worksheet xmlns="${namespace}"><sheetData>` +
    cells.map((cell, i) => `<row r="${i + 1}">${cell}</row>`).join("") +
    "</sheetData></worksheet>"
  );
}

function workbookParts(namespace = TRANSITIONAL, shared = false): Record<string, string> {
  const relationship = namespace === STRICT ? SREL : REL;
  const entries: Array<[string, string, string]> = [
    ["2", "worksheets/sheet2.xml", "second@example.com"],
    ["1", "worksheets/sheet1.xml", "first@example.com"],
  ];
  const parts: Record<string, string> = {
    [WORKBOOK]:
      `<workbook xmlns="${namespace}" xmlns:r="${relationship}"><sheets>` +
      entries
        .map(([i]) => `<sheet name="Contacts${i}" sheetId="${i}" r:id="r${i}" state="hidden"/>`)
        .join("") +
      "</sheets></workbook>",
    [RELS]:
      `<Relationships xmlns="${PKG}">` +
      entries
        .map(
          ([i, path]) =>
            `<Relationship Id="r${i}" Type="${relationship}/worksheet" Target="${path}"/>`,
        )
        .join("") +
      (shared
        ? `<Relationship Id="strings" Type="${relationship}/sharedStrings" Target="text/values.xml"/>`
        : "") +
      "</Relationships>",
  };
  for (const [, path, value] of entries) parts[`xl/${path}`] = sheetXml(value, namespace, shared);
  if (shared) {
    parts["xl/text/values.xml"] =
      `<sst xmlns="${namespace}"><si><t>email</t></si>` +
      "<si><t>shared@example.com</t></si></sst>";
  }
  return parts;
}

describe("xlsx — 워크시트 발견은 통합 문서를 따른다 (test_xlsx_package.py)", () => {
  for (const namespace of [TRANSITIONAL, STRICT]) {
    it(`파일명이 아니라 통합 문서 순서 (${namespace})`, async () => {
      const path = writeZip("order.xlsx", workbookParts(namespace));
      expect(await readRecords(path)).toEqual([
        { email: "second@example.com" },
        { email: "first@example.com" },
      ]);
      for (const text of [await readText(path), (await readTextBounded(path)).text]) {
        expect(text.indexOf("second@example.com")).toBeLessThan(text.indexOf("first@example.com"));
      }
    });

    it(`공유 문자열은 관계에서 로드한다 (${namespace})`, async () => {
      const path = writeZip("strings.xlsx", workbookParts(namespace, true));
      expect(await readText(path)).toContain("shared@example.com");
      expect(JSON.stringify(await readRecords(path))).toContain("shared@example.com");
    });
  }

  for (const [target, name] of [
    ["worksheets/contacts.xml", "xl/worksheets/contacts.xml"],
    ["/xl/custom/contacts.xml", "xl/custom/contacts.xml"],
    ["../custom/contacts.xml", "custom/contacts.xml"],
    ["custom/contact%20list.xml", "xl/custom/contact list.xml"],
  ] as const) {
    it(`관계 대상은 비정규 이름일 수 있다: ${target}`, async () => {
      const parts = workbookParts();
      parts[RELS] = (parts[RELS] ?? "").replace("worksheets/sheet2.xml", target);
      parts[name] = parts["xl/worksheets/sheet2.xml"] ?? "";
      delete parts["xl/worksheets/sheet2.xml"];
      const path = writeZip("names.xlsx", parts);
      expect(JSON.stringify(await readRecords(path))).toContain("second@example.com");
      expect((await readTextBounded(path)).text).toContain("second@example.com");
    });
  }

  const faults: Record<string, (parts: Record<string, string>) => void> = {
    missing_sheet: (p) => delete p["xl/worksheets/sheet2.xml"],
    missing_relationship: (p) => delete p[RELS],
    missing_workbook: (p) => delete p[WORKBOOK],
    bad_workbook: (p) => (p[WORKBOOK] = "<workbook"),
    bad_rels: (p) => (p[RELS] = "<Relationships"),
    bad_namespace: (p) => (p[WORKBOOK] = (p[WORKBOOK] ?? "").replace(TRANSITIONAL, "urn:unknown")),
    unknown_id: (p) => (p[WORKBOOK] = (p[WORKBOOK] ?? "").replace('r:id="r2"', 'r:id="absent"')),
    duplicate_id: (p) => (p[RELS] = (p[RELS] ?? "").replace('Id="r1"', 'Id="r2"')),
    duplicate_target: (p) => (p[RELS] = (p[RELS] ?? "").replace("sheet2.xml", "sheet1.xml")),
    duplicate_sheet_id: (p) =>
      (p[WORKBOOK] = (p[WORKBOOK] ?? "").replace('sheetId="2"', 'sheetId="1"')),
    duplicate_sheet_name: (p) =>
      (p[WORKBOOK] = (p[WORKBOOK] ?? "").replace("Contacts2", "Contacts1")),
    external: (p) =>
      (p[RELS] = (p[RELS] ?? "").replace('Id="r2"', 'Id="r2" TargetMode="External"')),
    remote: (p) =>
      (p[RELS] = (p[RELS] ?? "").replace(
        "worksheets/sheet2.xml",
        "https://example.com/private.xml",
      )),
    escape_root: (p) =>
      (p[RELS] = (p[RELS] ?? "").replace("worksheets/sheet2.xml", "../../escape.xml")),
    fragment: (p) =>
      (p[RELS] = (p[RELS] ?? "").replace("worksheets/sheet2.xml", "worksheets/sheet2.xml#part")),
    backslash: (p) =>
      (p[RELS] = (p[RELS] ?? "").replace("worksheets/sheet2.xml", "worksheets\\sheet2.xml")),
    unknown_type: (p) => (p[RELS] = (p[RELS] ?? "").replaceAll("/worksheet", "/chartsheet")),
    unlisted_sheet: (p) => (p["xl/worksheets/sheet3.xml"] = sheetXml("third@example.com")),
    unlisted_relationship: (p) =>
      (p[RELS] = (p[RELS] ?? "").replace(
        "</Relationships>",
        `<Relationship Id="unused" Type="${REL}/worksheet" Target="custom.xml"/></Relationships>`,
      )),
    missing_strings: (p) => delete p["xl/text/values.xml"],
    duplicate_strings: (p) =>
      (p[RELS] = (p[RELS] ?? "").replace(
        "</Relationships>",
        `<Relationship Id="other" Type="${REL}/sharedStrings" Target="other.xml"/></Relationships>`,
      )),
    conflicting_strings: (p) => (p["xl/sharedStrings.xml"] = p["xl/text/values.xml"] ?? ""),
    missing_sheets: (p) => (p[WORKBOOK] = `<workbook xmlns="${TRANSITIONAL}"/>`),
  };
  for (const [fault, apply] of Object.entries(faults)) {
    it(`깨진 패키지는 부분 성공을 돌려주지 않는다: ${fault}`, async () => {
      const parts = workbookParts(TRANSITIONAL, fault.endsWith("strings"));
      apply(parts);
      const path = writeZip("broken.xlsx", parts);
      await expect(readRecords(path)).rejects.toBeInstanceOf(ValueError);
      const inspection = await inspectXlsx(path);
      expect(["partial", "failed"]).toContain(inspection.coverage.status);
      expect(JSON.stringify(inspection.coverage)).not.toContain("@example.com");
      expect(() => inspection.requireComplete()).toThrow(DocumentExtractionError);
    });
  }

  it("통합 문서 없는 레거시는 숫자 시트 순서", async () => {
    const parts: Record<string, string> = {};
    for (let i = 1; i <= 12; i++)
      parts[`xl/worksheets/sheet${i}.xml`] = sheetXml(`p${i}@example.com`);
    const records = await readRecords(writeZip("legacy.xlsx", parts));
    expect(records.map((row) => row.email)).toEqual(
      Array.from({ length: 12 }, (_, i) => `p${i + 1}@example.com`),
    );
  });

  for (const name of [WORKBOOK, RELS, "xl/worksheets/sheet2.xml", "xl/text/values.xml"]) {
    it(`저수준 리더는 중복 멤버를 거부한다: ${name}`, async () => {
      const parts = workbookParts(TRANSITIONAL, true);
      const path = writeZip("duplicate.xlsx", [
        ...Object.entries(parts),
        [name, parts[name] ?? ""],
      ]);
      await expect(readRecords(path)).rejects.toThrow("invalid workbook relationships");
      expect((await inspectXlsx(path)).coverage.status).toBe("failed");
    });
  }

  for (const name of [WORKBOOK, RELS, "xl/text/values.xml"]) {
    for (const encoding of ["utf-8", "utf-16"] as const) {
      it(`관계 XML 도 DTD 사전 검사를 받는다 (${name}, ${encoding})`, async () => {
        const parts: Record<string, string | Uint8Array> = workbookParts(TRANSITIONAL, true);
        const xml =
          `<?xml version="1.0" encoding="${encoding}"?>` +
          '<!DOCTYPE item [<!ENTITY secret "private@example.com">]><item>&secret;</item>';
        parts[name] = encoding === "utf-8" ? Buffer.from(xml, "utf-8") : utf16(xml);
        const path = writeZip("dtd.xlsx", parts);
        expect(await boundedCode(() => readTextBounded(path))).toBe("xml_dtd_rejected");
      });
    }
  }

  it("이름을 바꾼 시트도 텍스트 한도를 받는다", async () => {
    const parts = workbookParts();
    parts[RELS] = (parts[RELS] ?? "").replace("worksheets/sheet2.xml", "worksheets/contacts.xml");
    parts["xl/worksheets/contacts.xml"] = parts["xl/worksheets/sheet2.xml"] ?? "";
    delete parts["xl/worksheets/sheet2.xml"];
    const path = writeZip("limit.xlsx", parts);
    expect(
      await boundedCode(() => readTextBounded(path, new FileReadPolicy({ maxTextChars: 10 }))),
    ).toBe("extracted_text_too_large");
  });

  for (const target of [
    "https://example.com/values.xml",
    "../../values.xml",
    "text/values.xml#part",
    "text/%invalid.xml",
  ]) {
    it(`잘못된 공유 문자열 대상은 따라가지 않는다: ${target}`, async () => {
      const parts = workbookParts(TRANSITIONAL, true);
      parts[RELS] = (parts[RELS] ?? "").replace("text/values.xml", target);
      await expect(readText(writeZip("strings.xlsx", parts))).rejects.toBeInstanceOf(
        DocumentExtractionError,
      );
    });
  }

  it("관련 없는 관계는 가져오지 않는다", async () => {
    const parts = workbookParts();
    parts[RELS] = (parts[RELS] ?? "").replace(
      "</Relationships>",
      `<Relationship Id="unused" Type="${REL}/externalLink" TargetMode="External" ` +
        'Target="https://example.com/not-fetched"/></Relationships>',
    );
    expect(await readRecords(writeZip("external.xlsx", parts))).toHaveLength(2);
  });

  it("범위 밖 공유 문자열 인덱스는 빈 셀이 아니다", async () => {
    const path = writeZip("bad.xlsx", {
      [WORKBOOK]: `<workbook xmlns="${TRANSITIONAL}" xmlns:r="${REL}"><sheets><sheet name="Sheet1" sheetId="1" r:id="r1"/></sheets></workbook>`,
      [RELS]:
        `<Relationships xmlns="${PKG}"><Relationship Id="r1" Type="${REL}/worksheet" Target="worksheets/sheet1.xml"/>` +
        `<Relationship Id="sst" Type="${REL}/sharedStrings" Target="sharedStrings.xml"/></Relationships>`,
      "xl/sharedStrings.xml": `<sst xmlns="${TRANSITIONAL}"><si><t>normal</t></si></sst>`,
      "xl/worksheets/sheet1.xml": `<worksheet xmlns="${TRANSITIONAL}"><row><c t="s"><v>-1</v></c></row></worksheet>`,
    });
    expect(await boundedCode(() => readTextBounded(path))).toBe("document_extraction_incomplete");
  });

  // Python int() 의미론 — 유효 인덱스는 값, 그 밖(음수·소수·선행 밑줄)은 파트 실패 (Python 실측)
  for (const [raw, expected] of [
    ["１", "s1\n"],
    ["1_0", "s10\n"],
    [" +1 ", "s1\n"],
    ["٣", "s3\n"],
    ["-1", null],
    ["1.0", null],
    ["_1", null],
  ] as const) {
    it(`공유 문자열 인덱스 ${JSON.stringify(raw)} → ${JSON.stringify(expected)}`, async () => {
      const strings = Array.from({ length: 12 }, (_, i) => `<si><t>s${i}</t></si>`).join("");
      const path = writeZip("index.xlsx", {
        "xl/sharedStrings.xml": `<sst xmlns="${TRANSITIONAL}">${strings}</sst>`,
        "xl/worksheets/sheet1.xml": `<worksheet xmlns="${TRANSITIONAL}"><sheetData><row><c t="s"><v>${raw}</v></c></row></sheetData></worksheet>`,
      });
      const inspection = await inspectXlsx(path);
      if (expected === null) {
        expect(inspection.text).toBe("");
        expect(inspection.coverage.status).toBe("failed");
      } else {
        expect(inspection.text).toBe(expected);
        expect(inspection.coverage.status).toBe("complete");
      }
    });
  }
});

// ---------------------------------------------------------------------------
// 표 리더 경계 (test_record_boundaries.py)
// ---------------------------------------------------------------------------

function escapeXml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function spreadsheet(sheets: string[][][]): string {
  const parts: Record<string, string> = {};
  sheets.forEach((rows, sheetIndex) => {
    const content = rows.map((row, r) => {
      const cells = row.map((value, column) => {
        const text = escapeXml(value).replaceAll('"', "&quot;").replaceAll("\r", "&#13;");
        return (
          `<c r="${String.fromCharCode(65 + column)}${r + 1}" t="inlineStr">` +
          `<is><t xml:space="preserve">${text}</t></is></c>`
        );
      });
      return `<row r="${r + 1}">${cells.join("")}</row>`;
    });
    parts[`xl/worksheets/sheet${sheetIndex + 1}.xml`] =
      `<worksheet xmlns="${TRANSITIONAL}"><sheetData>${content.join("")}</sheetData></worksheet>`;
  });
  return writeZip("sheets.xlsx", parts);
}

describe("표 리더는 셀을 재해석하거나 버리지 않는다 (test_record_boundaries.py)", () => {
  it("시트마다 헤더가 독립적이다", async () => {
    const path = spreadsheet([
      [
        ["email", "memo"],
        ["first@example.com", "public"],
      ],
      [
        ["memo", "email"],
        ["public", "second@example.com"],
      ],
    ]);
    const records = await readRecords(path);
    expect(records).toEqual([
      { email: "first@example.com", memo: "public" },
      { memo: "public", email: "second@example.com" },
    ]);
    expect(Object.keys(records[1] ?? {})).toEqual(["memo", "email"]);
  });

  for (const separator of ["\t", "\n", "\r\n"]) {
    it(`셀 안 구분자·공백 보존 (${JSON.stringify(separator)})`, async () => {
      const value = ` first@example.com${separator}second@example.com `;
      const path = spreadsheet([
        [
          ["email", "memo"],
          [value, "public"],
        ],
      ]);
      expect(await readRecords(path)).toEqual([{ email: value, memo: "public" }]);
    });
  }

  for (const headers of [
    ["email", "email"],
    ["", "email"],
    ["email", "   "],
  ]) {
    it(`모호한 xlsx 헤더는 내용 없이 실패 (${JSON.stringify(headers)})`, async () => {
      const path = spreadsheet([[headers, ["first@example.com", "second@example.com"]]]);
      await expect(readRecords(path)).rejects.toThrow(
        "spreadsheet headers must be nonempty and unique",
      );
    });

    it(`모호한 csv 헤더는 내용 없이 실패 (${JSON.stringify(headers)})`, async () => {
      const path = writeBytes(
        "ambiguous.csv",
        `${headers.join(",")}\nfirst@example.com,second@example.com\n`,
      );
      await expect(readRecords(path)).rejects.toThrow("CSV headers must be nonempty and unique");
    });
  }

  for (const extra of ["second@example.com", " "]) {
    it(`xlsx 헤더 밖 비어 있지 않은 셀은 거부 (${JSON.stringify(extra)})`, async () => {
      const path = spreadsheet([[["email"], ["first@example.com", extra]]]);
      await expect(readRecords(path)).rejects.toThrow(
        "spreadsheet row has values beyond its headers",
      );
    });
  }

  it("빈 행·누락 셀·서식용 빈 셀", async () => {
    const path = spreadsheet([
      [],
      [[], ["email", "memo", ""], [], ["first@example.com"], ["second@example.com", "public", ""]],
    ]);
    expect(await readRecords(path)).toEqual([
      { email: "first@example.com", memo: "" },
      { email: "second@example.com", memo: "public" },
    ]);
  });

  it("뒤 시트가 나쁘면 부분 레코드 대신 예외", async () => {
    const path = spreadsheet([[["email"], ["first@example.com"]], [["email", "email"]]]);
    await expect(readRecords(path)).rejects.toThrow("headers");
  });

  it("중복 셀 참조는 조용히 덮어쓰지 않는다", async () => {
    const path = writeZip("duplicate-cell.xlsx", {
      "xl/worksheets/sheet1.xml":
        `<worksheet xmlns="${TRANSITIONAL}"><sheetData>` +
        '<row><c r="A1" t="inlineStr"><is><t>email</t></is></c></row>' +
        '<row><c r="A2" t="inlineStr"><is><t>first@example.com</t></is></c>' +
        '<c r="A2" t="inlineStr"><is><t>public</t></is></c></row>' +
        "</sheetData></worksheet>",
    });
    await expect(readRecords(path)).rejects.toThrow("duplicate cell reference");
  });

  it("빈 셀이 있는 헤더는 거부된다 (Python 실측: 'email\\t\\tmemo')", async () => {
    const path = writeZip("gap.xlsx", {
      "xl/worksheets/sheet1.xml":
        `<worksheet xmlns="${TRANSITIONAL}"><sheetData><row><c r="A1" t="inlineStr"><is><t>email</t></is></c>` +
        '<c r="C1" t="inlineStr"><is><t>memo</t></is></c></row><row><c t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>',
    });
    expect((await inspectXlsx(path)).text).toBe("email\t\tmemo\nx\n");
    await expect(readRecords(path)).rejects.toThrow(
      "spreadsheet headers must be nonempty and unique",
    );
  });

  it("csv 초과 셀은 레거시 restkey 로 남는다", async () => {
    const path = writeBytes(
      "overflow.csv",
      "email,memo\nfirst@example.com,public,second@example.com\n",
    );
    const records = (await readRecords(path)) as unknown as Array<Record<string, unknown>>;
    expect(records[0]?.[""]).toEqual(["second@example.com"]);
  });

  for (const separator of ["\n", "\r\n", "\r"]) {
    it(`csv 따옴표 안 줄바꿈은 한 셀에 남는다 (${JSON.stringify(separator)})`, async () => {
      const value = `first@example.com${separator}second@example.com`;
      const path = writeBytes("quoted.csv", `email,memo\r\n"${value}",public\r\n`);
      expect(await readRecords(path)).toEqual([{ email: value, memo: "public" }]);
    });
  }
});

// ---------------------------------------------------------------------------
// 평문·CSV 입력 (test_text_ingestion.py)
// ---------------------------------------------------------------------------

const EMAIL = "synthetic@example.com";
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);

describe("평문 내보내기는 스키마를 바꾸거나 우회하지 않는다 (test_text_ingestion.py)", () => {
  for (const header of ["email", '"email"', "성명"]) {
    for (const delimiter of [",", "\t", ";", "|"]) {
      it(`UTF-8 BOM 이 첫 열을 숨기지 않는다 (${header}, ${JSON.stringify(delimiter)})`, async () => {
        const source = `${header}${delimiter}memo\r\n${EMAIL}${delimiter}public\r\n`;
        const path = writeBytes("export.csv", Buffer.concat([UTF8_BOM, Buffer.from(source)]));
        expect(await readRecords(path)).toEqual([
          { [header.replaceAll('"', "")]: EMAIL, memo: "public" },
        ]);
      });
    }
  }

  it("지원 한국어 인코딩은 스키마와 셀을 유지한다 (utf-8 / utf-8-sig)", async () => {
    const source = "성명\t메모\r\n홍길동\t일반 문서\r\n";
    for (const bytes of [Buffer.from(source), Buffer.concat([UTF8_BOM, Buffer.from(source)])]) {
      const path = writeBytes("export.tsv", bytes);
      expect(readPlain(path)).toBe(source);
      expect(await readRecords(path)).toEqual([{ 성명: "홍길동", 메모: "일반 문서" }]);
    }
  });

  it("cp949 / euc-kr 도 손실 없이 읽는다", async () => {
    // "성명\t메모\r\n홍길동\t일반 문서\r\n" 의 cp949(= euc-kr 범위) 인코딩
    const bytes = Buffer.from("bcbab8ed09b8deb8f00d0ac8abb1e6b5bf09c0cfb9dd20b9aebcad0d0a", "hex");
    const path = writeBytes("export.tsv", bytes);
    expect(readPlain(path)).toBe("성명\t메모\r\n홍길동\t일반 문서\r\n");
    expect(await readRecords(path)).toEqual([{ 성명: "홍길동", 메모: "일반 문서" }]);
  });

  it("파일 선두 BOM 만 제거하고 본문 U+FEFF 는 보존한다", () => {
    const source = `left\ufeffright\n${EMAIL}`;
    const path = writeBytes("export.txt", Buffer.concat([UTF8_BOM, Buffer.from(source)]));
    expect(readPlain(path)).toBe(source);
  });

  it("원본의 U+FFFD 는 디코드 실패가 아니다", () => {
    const source = "literal \ufffd character";
    expect(readPlain(writeBytes("text.txt", source))).toBe(source);
  });

  it("cp949 확장 문자도 디코드된다", () => {
    // "똠방각하" cp949
    const path = writeBytes("text.txt", Buffer.from("8c63b9e6b0a2c7cf", "hex"));
    expect(readPlain(path)).toBe("똠방각하");
  });

  it("UTF-8 을 선언(BOM)한 파일은 다른 인코딩으로 폴백하지 않는다", () => {
    // BOM + "홍길동" cp949 바이트
    const path = writeBytes(
      "text.txt",
      Buffer.concat([UTF8_BOM, Buffer.from("c8abb1e6b5bf", "hex")]),
    );
    expect(() => readPlain(path)).toThrow(TextDecodingError);
    expect(() => readPlain(path)).toThrow(ValueError);
  });

  for (const separator of ["\r", "\n", "\r\n"]) {
    it(`유효한 따옴표 CSV 는 구분자·이중 따옴표를 보존한다 (${JSON.stringify(separator)})`, async () => {
      const source = `"email","memo"${separator}"${EMAIL}","a,b; c | d\t""quoted"""${separator}`;
      const path = writeBytes("valid.csv", Buffer.concat([UTF8_BOM, Buffer.from(source)]));
      expect(await readRecords(path)).toEqual([{ email: EMAIL, memo: 'a,b; c | d\t"quoted"' }]);
    });
  }

  for (const suffix of [`public,"unterminated\n${EMAIL},memo\n`, 'public,"quoted"unexpected\n']) {
    for (const prefix of ["", `${EMAIL},safe\n`]) {
      it(`잘못된 CSV 는 레코드 전체를 거부한다 (${JSON.stringify(suffix.slice(0, 20))}, prefix=${prefix !== ""})`, async () => {
        const path = writeBytes("invalid.csv", `email,memo\n${prefix}${suffix}`);
        await expect(readRecords(path)).rejects.toThrow("invalid CSV record syntax");
        await expect(readRecords(path)).rejects.toBeInstanceOf(ValueError);
      });
    }
  }

  for (const payload of [[0xff], [0xf8], [0xef, 0xbb, 0xbf, 0xff]]) {
    it(`디코드 불가 파일은 치환 문자를 돌려주지 않는다 (${Buffer.from(payload).toString("hex")})`, async () => {
      const path = writeBytes(
        "invalid.csv",
        Buffer.concat([Buffer.from(`email\n${EMAIL}\n`), Buffer.from(payload)]),
      );
      expect(() => readPlain(path)).toThrow(ValueError);
      await expect(readRecords(path)).rejects.toBeInstanceOf(ValueError);
      try {
        readPlain(path);
      } catch (e) {
        expect((e as Error).message).not.toContain(EMAIL);
      }
    });
  }

  it("디코드 실패는 안전한 기계 판독 코드 text_decode_failed", async () => {
    const path = writeBytes(
      "invalid.txt",
      Buffer.concat([Buffer.from(`${EMAIL}\n`), Buffer.from([0xff])]),
    );
    try {
      await readTextBounded(path);
      expect.fail("expected rejection");
    } catch (e) {
      expect((e as BoundedReadError).code).toBe("text_decode_failed");
      expect((e as Error).message).not.toContain(EMAIL);
    }
  });
});

// ---------------------------------------------------------------------------
// 숫자 경계 (test_numeric_boundaries.py)
// ---------------------------------------------------------------------------

describe("전처리가 금융 검출 경계를 되돌리지 않는다 (test_numeric_boundaries.py)", () => {
  for (const text of [
    "Account: 110-123-456789 100000",
    "Account: 110-123-456789\n100000",
    "Account: 110-123-456789\t100000",
    "Business: 123\n45\n67891",
    "Business: 123\r\n45\r\n67891",
    "Card: 3782-\n822463-\n10005",
  ]) {
    it(`기본 정규화는 숫자 필드 경계를 유지한다: ${JSON.stringify(text)}`, () => {
      expect(normalizeForDetection(text)).toEqual([
        text,
        Array.from({ length: text.length }, (_, i) => i),
      ]);
    });
  }

  for (const [name, reader] of Object.entries(TEXT_READERS)) {
    it(`파일 리더는 계좌·금액·사업자 행을 합치지 않는다: ${name}`, async () => {
      const source = "계좌번호: 110-123-456789 100000\n사업자등록번호: 123\n45\n67891";
      expect(await textOf(reader(writeBytes("input.txt", source)))).toBe(source);
    });
  }

  it("줄 합치기는 명시적 aggressive 에서만", () => {
    expect(normalizeForDetection("123\n45\n67891")[0]).toBe("123\n45\n67891");
    expect(normalizeForDetection("123\n45\n67891", { aggressive: true })[0]).toBe("123 45 67891");
    const source = "성명: 김다은\n성명: 김태성";
    expect(normalizeForDetection(source)).toEqual([
      source,
      Array.from({ length: source.length }, (_, i) => i),
    ]);
    expect(normalizeForDetection(source, { aggressive: true })[0]).toBe(source.replace("\n", ""));
  });

  it("지원되는 칸별 RRN 공백은 여전히 축소된다", () => {
    expect(normalizeForDetection("8 8 0 1 0 1 - 1 2 3 4 5 6 8")[0]).toBe("880101-1234568");
    expect(normalizeForDetection("88 0 1 0 1 - 1 2 3 4 5 6 8")[0]).toBe("880101-1234568");
  });
});

// ---------------------------------------------------------------------------
// bounded.py — 정책 검증·XML 사전 검사 (test_bounded_io.py)
// ---------------------------------------------------------------------------

describe("FileReadPolicy 런타임 검증 (test_bounded_io.py)", () => {
  const integerFields = [
    "maxFileBytes",
    "maxArchiveMembers",
    "maxArchiveMemberBytes",
    "maxDecompressedBytes",
    "maxTextChars",
  ] as const;
  const badIntegers: unknown[] = [
    0,
    -1,
    true,
    "10",
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    null,
  ];
  for (const name of integerFields) {
    it(`${name}: 양의 정수가 아니면 거부`, () => {
      for (const value of badIntegers) {
        expect(() => new FileReadPolicy({ [name]: value } as never)).toThrow(
          "all bounded-read limits must be positive integers",
        );
      }
    });
  }

  it("maxCompressionRatio 는 유한하고 1.0 이상", () => {
    for (const value of [
      true,
      "10",
      null,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      0.5,
    ]) {
      expect(() => new FileReadPolicy({ maxCompressionRatio: value } as never)).toThrow(
        "max_compression_ratio must be finite and at least 1.0",
      );
    }
    expect(new FileReadPolicy({ maxCompressionRatio: 1 }).maxCompressionRatio).toBe(1);
  });

  it("allowedExtensions 는 '.' 으로 시작하는 문자열 배열", () => {
    for (const value of [".txt", 1, [null], ["txt"]]) {
      expect(() => new FileReadPolicy({ allowedExtensions: value } as never)).toThrow(
        /allowed_extensions/,
      );
    }
    expect(() => new FileReadPolicy({ allowedExtensions: [] })).toThrow(
      "allowed_extensions must not be empty",
    );
  });

  it("rejectSymlinks 는 boolean", () => {
    expect(() => new FileReadPolicy({ rejectSymlinks: "false" } as never)).toThrow(
      "reject_symlinks must be a boolean",
    );
  });

  it("격리 기본 정책은 지원 확장자 전체(pdf/hwp 포함)를 허용한다", () => {
    expect(defaultReadPolicy().allowedExtensions).toContain(".pdf");
    expect(defaultReadPolicy().allowedExtensions).toContain(".hwp");
  });
});

describe("bounded — XML 인코딩이 DTD 를 숨길 수 없다 (test_bounded_io.py)", () => {
  const encode = (text: string, encoding: string): Buffer => {
    if (encoding === "utf-8") return Buffer.from(text, "utf-8");
    if (encoding === "utf-16") return utf16(text);
    const le = Buffer.from(text, "utf16le");
    if (encoding === "utf-16-le") return Buffer.concat([Buffer.from([0xff, 0xfe]), le]);
    // utf-16-be + BOM
    const be = Buffer.from(le);
    be.swap16();
    return Buffer.concat([Buffer.from([0xfe, 0xff]), be]);
  };
  for (const encoding of ["utf-8", "utf-16", "utf-16-le", "utf-16-be"]) {
    for (const dtd of [true, false]) {
      it(`${encoding}, dtd=${dtd}`, async () => {
        const declaration = encoding.startsWith("utf-16") ? "UTF-16" : "UTF-8";
        const text =
          `<?xml version="1.0" encoding="${declaration}"?>` +
          (dtd ? '<!DOCTYPE p [<!ENTITY contact "first@example.com">]>' : "") +
          `<p><t>${dtd ? "&contact;" : "first@example.com"}</t></p>`;
        const path = writeZip("input.hwpx", [["Contents/section0.xml", encode(text, encoding)]]);
        if (dtd) {
          expect(await boundedCode(() => readTextBounded(path))).toBe("xml_dtd_rejected");
        } else {
          expect((await readTextBounded(path)).text).toBe("\nfirst@example.com");
        }
      });
    }
  }

  it("청크 경계 뒤 DTD 도 잡고, CDATA 안 표식은 통과시킨다", async () => {
    const prefix = `<!--${"x".repeat(65525)}-->`;
    const rejected = writeZip("input.hwpx", [
      ["Contents/section0.xml", `${prefix}<!DOCTYPE p><p><t>safe</t></p>`],
    ]);
    expect(await boundedCode(() => readTextBounded(rejected))).toBe("xml_dtd_rejected");
    const accepted = writeZip("input.hwpx", [
      ["Contents/section0.xml", "<p><t><![CDATA[<!DOCTYPE sample>]]></t></p>"],
    ]);
    expect((await readTextBounded(accepted)).text).toBe("\n<!DOCTYPE sample>");
  });

  it("잘못된 XML 오류는 원문 내용을 노출하지 않는다", async () => {
    const path = writeZip("input.hwpx", [["Contents/section0.xml", "<p><private-value></p>"]]);
    try {
      await readTextBounded(path);
      expect.fail("expected rejection");
    } catch (e) {
      expect((e as BoundedReadError).code).toBe("document_extraction_incomplete");
      expect((e as BoundedReadError).coverage?.status).toBe("failed");
      expect((e as Error).message).not.toContain("private-value");
    }
  });

  it("content.hpf 만 있는 hwpx 도 형식 검사를 통과한다 (section 이름 불필요)", async () => {
    const path = hwpxPackage(content([["body", "Contents/body.xml"]], ["body"]), {
      "Contents/body.xml": body("본문"),
    });
    expect((await readTextBounded(path)).text).toContain("본문");
  });

  it("바이너리 포맷의 빈 추출은 no_extractable_text", async () => {
    const path = writeZip("blank.docx", { "word/document.xml": "<document> </document>" });
    expect(await boundedCode(() => readTextBounded(path))).toBe("no_extractable_text");
  });
});

// ---------------------------------------------------------------------------
// pdf.py — 빈/실패 페이지는 조용한 성공이 아니다 (test_optional_formats.py, test_safe_processing.py)
// ---------------------------------------------------------------------------

/** pypdf `PdfWriter().add_blank_page(200, 200)` 출력 (Python 실측 픽스처). */
const BLANK_PDF =
  "JVBERi0xLjMKJeLjz9MKMSAwIG9iago8PAovUHJvZHVjZXIgKHB5cGRmKQo+PgplbmRvYmoKMiAwIG9iago8PAovVHlwZSAvUGFnZXMKL0NvdW50IDEKL0tpZHMgWyA0IDAgUiBdCj4+CmVuZG9iagozIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAyIDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovVHlwZSAvUGFnZQovUmVzb3VyY2VzIDw8Cj4+Ci9NZWRpYUJveCBbIDAuMCAwLjAgMjAwIDIwMCBdCi9QYXJlbnQgMiAwIFIKPj4KZW5kb2JqCnhyZWYKMCA1CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwMDU0IDAwMDAwIG4gCjAwMDAwMDAxMTMgMDAwMDAgbiAKMDAwMDAwMDE2MiAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDUKL1Jvb3QgMyAwIFIKL0luZm8gMSAwIFIKPj4Kc3RhcnR4cmVmCjI1NgolJUVPRgo=";

describe("pdf — 빈 페이지 보고", () => {
  it("빈 페이지는 coverage 로 보고되고 readText 는 PdfExtractionError", async () => {
    const path = writeBytes("scan.pdf", Buffer.from(BLANK_PDF, "base64"));
    const result = await inspectPdf(path);
    expect(result).toMatchObject({ pageCount: 1, failedPages: [], emptyPages: [1] });
    await expect(readPdf(path)).rejects.toBeInstanceOf(PdfExtractionError);
    await expect(readPdf(path)).rejects.toBeInstanceOf(ValueError);
    await expect(readText(path)).rejects.toMatchObject({ code: "pdf_extraction_incomplete" });
  });

  it("bounded(명시 opt-in)·격리 경로는 같은 코드와 내용 없는 메시지로 거부한다", async () => {
    const path = writeBytes("scan.pdf", Buffer.from(BLANK_PDF, "base64"));
    const message =
      "PDF text extraction incomplete: pages=1, failed_pages=[], empty_pages=[1]; review the source or apply OCR";
    for (const read of [
      () => readTextBounded(path, defaultReadPolicy()),
      () => readTextIsolated(path),
    ]) {
      await expect(read()).rejects.toMatchObject({ code: "pdf_extraction_incomplete", message });
    }
  });
});

// ---------------------------------------------------------------------------
// isolated.py / _worker.py (test_safe_processing.py, test_failure_boundaries.py)
// ---------------------------------------------------------------------------

describe("readTextIsolated — 워커 격리 + 시간 제한", () => {
  it("왕복과 크기 한도", async () => {
    const source = writeBytes("in.txt", "문서 내용");
    expect((await readTextIsolated(source)).text).toBe("문서 내용");
    expect(
      await boundedCode(() =>
        readTextIsolated(source, { policy: new FileReadPolicy({ maxFileBytes: 2 }) }),
      ),
    ).toBe("file_too_large");
  });

  it("시간 초과는 워커를 끊고 extract_timeout", async () => {
    const source = writeBytes("in.txt", "문서 내용");
    expect(await boundedCode(() => readTextIsolated(source, { timeout: 0.001 }))).toBe(
      "extract_timeout",
    );
  });

  it("시간 제한은 유한한 양수", async () => {
    for (const timeout of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      await expect(readTextIsolated("unused", { timeout })).rejects.toThrow(
        "extraction timeout must be finite and positive",
      );
    }
  });

  it("부분 파싱 실패 문서는 거부되고 coverage 가 전달된다 (docx/hwpx/xlsx)", async () => {
    const xlsxStructure = workbookParts();
    const cases: Record<string, Record<string, string>> = {
      "partial.docx": {
        "word/document.xml": "<document><p><t>ordinary body</t></p></document>",
        "word/header1.xml": "<header><p><t>010-1234-5678",
      },
      "partial.hwpx": {
        "Contents/section0.xml": "<section><p><t>ordinary body</t></p></section>",
        "Contents/section1.xml": "<section><p><t>010-1234-5678",
      },
      "partial.xlsx": {
        ...xlsxStructure,
        "xl/worksheets/sheet1.xml": `<worksheet xmlns="${TRANSITIONAL}"><sheetData><row><c r="A1" t="inlineStr"><is><t>ordinary body</t></is></c></row></sheetData></worksheet>`,
        "xl/worksheets/sheet2.xml": "<worksheet><row><c>010-1234-5678",
      },
    };
    for (const [name, parts] of Object.entries(cases)) {
      const path = writeZip(name, parts);
      try {
        await readTextIsolated(path);
        expect.fail(`accepted ${name}`);
      } catch (e) {
        expect(e).toBeInstanceOf(BoundedReadError);
        expect((e as BoundedReadError).code).toBe("document_extraction_incomplete");
        expect((e as BoundedReadError).coverage?.status).toBe("partial");
        expect(JSON.stringify((e as BoundedReadError).coverage)).not.toContain("010-1234-5678");
      }
    }
  });

  it("DTD 사전 검사는 격리 경로에서도 같다", async () => {
    let xml =
      '<?xml version="1.0" encoding="utf-16"?><!DOCTYPE package [<!ENTITY x "first@example.com">]>';
    xml += content([["a", "Contents/section0.xml"]], ["a"], { metadata: "<title>&x;</title>" });
    const path = hwpxPackage(utf16(xml), { "Contents/section0.xml": body("body text") });
    expect(await boundedCode(() => readTextIsolated(path))).toBe("xml_dtd_rejected");
  });

  it("유효한 문서는 추출되고 coverage 를 돌려준다", async () => {
    const path = writeZip("valid.docx", {
      "word/document.xml": "<document><p><t>ordinary body</t></p></document>",
      "word/header1.xml": "<header><p><t>010-1234-5678</t></p></header>",
    });
    const document = await readTextIsolated(path);
    expect(document.text).toContain("ordinary body");
    expect(document.text).toContain("010-1234-5678");
    expect(document.coverage?.status).toBe("complete");
    expect(document.extension).toBe(".docx");
  });
});
