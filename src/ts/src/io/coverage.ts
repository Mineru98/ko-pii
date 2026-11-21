/**
 * Content-free coverage of supported archive text parts, not OCR coverage.
 * Python 대응: ko_pii/io_/coverage.py.
 */
import { ValueError } from "../core/errors.js";
import { pyIsBlank } from "./pyStr.js";
import { LookupError, XmlParseError } from "./xmlEt.js";
import type { ZipFile } from "./zipFile.js";
import { BadZipFile } from "./zipFile.js";

/** 파트 하나의 추출 상태 — 내용은 담지 않는다. */
export interface PartCoverage {
  part: string;
  status: "read" | "empty" | "failed";
  reason?: string;
}

/** Python `TextExtraction.coverage` 사전. */
export interface ExtractionCoverage {
  status: "complete" | "partial" | "failed";
  scope: "discovered_supported_text_parts";
  parts: PartCoverage[];
  limitations: string[];
}

export class DocumentExtractionError extends ValueError {
  readonly code = "document_extraction_incomplete";
  readonly coverage: ExtractionCoverage;

  constructor(coverage: ExtractionCoverage) {
    super("document text extraction incomplete; review failed parts");
    this.name = "DocumentExtractionError";
    this.coverage = coverage;
  }
}

export class TextExtraction {
  readonly text: string;
  readonly parts: readonly PartCoverage[];

  constructor(text: string, parts: readonly PartCoverage[]) {
    this.text = text;
    this.parts = parts;
  }

  get coverage(): ExtractionCoverage {
    const failed = this.parts.filter((part) => part.status === "failed").length;
    return {
      status: failed && !pyIsBlank(this.text) ? "partial" : failed ? "failed" : "complete",
      scope: "discovered_supported_text_parts",
      parts: this.parts.map((part) => ({ ...part })),
      limitations: [
        "embedded_images_not_ocr_checked",
        "unsupported_parts_not_inspected",
        "package_relationships_not_validated",
      ],
    };
  }

  requireComplete(): string {
    if (this.parts.length === 0 || this.parts.some((part) => part.status === "failed")) {
      throw new DocumentExtractionError(this.coverage);
    }
    return this.text;
  }
}

/** Python 예외 이름 — ValueError/LookupError/OSError 계열 (inspect_parts 가 잡는 범위). */
const CAUGHT_NAMES: ReadonlySet<string> = new Set([
  "ValueError",
  "UnicodeDecodeError",
  "LookupError",
  "KeyError",
  "IndexError",
  "OSError",
]);

/**
 * Python `except (ET.ParseError, ValueError, LookupError, OSError, zipfile.BadZipFile)`.
 * Node 파일 시스템 오류(errno 코드 보유)는 OSError 로 본다.
 */
export function isPartFailure(error: unknown): boolean {
  if (
    error instanceof XmlParseError ||
    error instanceof ValueError ||
    error instanceof LookupError ||
    error instanceof BadZipFile
  ) {
    return true;
  }
  if (!(error instanceof Error)) return false;
  if (CAUGHT_NAMES.has(error.name)) return true;
  return typeof (error as NodeJS.ErrnoException).errno === "number";
}

export type PartReader = (archive: ZipFile, name: string) => Promise<string> | string;

export async function inspectParts(
  archive: ZipFile,
  names: readonly string[],
  reader: PartReader,
): Promise<TextExtraction> {
  const chunks: string[] = [];
  const parts: PartCoverage[] = [];
  for (const name of names) {
    let text: string;
    try {
      text = await reader(archive, name);
    } catch (error) {
      if (!isPartFailure(error)) throw error;
      parts.push({ part: name, status: "failed", reason: "part_parse_failed" });
      continue;
    }
    chunks.push(text);
    parts.push({ part: name, status: pyIsBlank(text) ? "empty" : "read" });
  }
  if (names.length === 0) {
    parts.push({ part: "(document)", status: "failed", reason: "missing_text_parts" });
  }
  return new TextExtraction(chunks.join("\n"), parts);
}
