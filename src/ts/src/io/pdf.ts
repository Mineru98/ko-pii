/** PDF 텍스트 레이어 추출 — Python ko_pii/io_/pdf.py 대응 (unpdf 단일 경로).
 *
 * Python 원본은 pdfplumber > pypdf 폴백 체인을 쓰지만, TS 포트는 unpdf(pdf.js)
 * 단일 경로로 대체한다. 페이지 텍스트 조립은 unpdf 의 방식(item.str + hasEOL 개행)
 * 을 그대로 따른다. 페이지별 예외·빈 페이지는 조용히 넘기지 않고 coverage
 * (failedPages/emptyPages) 로 보고하며, readText 는 PdfExtractionError 로 거부한다.
 *
 * 이미지/스캔 PDF 는 OCR 필요 — 본 모듈은 *텍스트 레이어* 만 추출
 * (한국 공공 결재 PDF 는 대부분 텍스트 레이어 있음).
 */
import { readFile } from "node:fs/promises";
import { getDocumentProxy } from "unpdf";
import { ValueError } from "../core/errors.js";
import { pyIsBlank } from "./pyStr.js";
import { normalizeForDetection } from "./textNormalizer.js";

/** Text-layer coverage only; embedded images are not inspected with OCR. */
export interface PdfTextResult {
  text: string;
  pageCount: number;
  failedPages: readonly number[];
  emptyPages: readonly number[];
}

/** Python `PdfExtractionError` — 추출 텍스트·파서 예외 내용은 메시지에 담지 않는다. */
export class PdfExtractionError extends ValueError {
  readonly code = "pdf_extraction_incomplete";
  readonly pageCount: number;
  readonly failedPages: readonly number[];
  readonly emptyPages: readonly number[];

  constructor(result: PdfTextResult) {
    // Keep extracted text and parser exceptions out of error messages.
    super(
      `PDF text extraction incomplete: pages=${result.pageCount}, ` +
        `failed_pages=[${result.failedPages.join(", ")}], ` +
        `empty_pages=[${result.emptyPages.join(", ")}]; review the source or apply OCR`,
    );
    this.name = "PdfExtractionError";
    this.pageCount = result.pageCount;
    this.failedPages = result.failedPages;
    this.emptyPages = result.emptyPages;
  }
}

/** Return partial text and coverage for an explicit manual-review workflow. */
export async function inspectText(path: string): Promise<PdfTextResult> {
  const data = await readFile(path);
  const pdf = await getDocumentProxy(new Uint8Array(data));
  const parts: string[] = [];
  const failed: number[] = [];
  const empty: number[] = [];
  for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
    let text = "";
    try {
      const page = await pdf.getPage(pageNum);
      const { items } = await page.getTextContent();
      // unpdf 의 페이지 텍스트 조립과 동일: str 없는 item 제외, hasEOL 에서 개행.
      for (const item of items) {
        if (!("str" in item) || item.str == null) continue;
        text += item.str + (item.hasEOL ? "\n" : "");
      }
    } catch {
      failed.push(pageNum);
      parts.push("");
      continue;
    }
    if (pyIsBlank(text)) empty.push(pageNum);
    parts.push(text);
  }
  return {
    text: parts.join("\n\n"),
    pageCount: parts.length,
    failedPages: failed,
    emptyPages: empty,
  };
}

/** PDF → 원본 텍스트 (페이지별 "\n\n" 결합). 실패·빈 페이지가 있으면 PdfExtractionError. */
async function extractRaw(path: string): Promise<string> {
  const result = await inspectText(path);
  if (!result.pageCount || result.failedPages.length > 0 || result.emptyPages.length > 0) {
    throw new PdfExtractionError(result);
  }
  return result.text;
}

/** PDF 텍스트 레이어 추출.
 *
 * @param options.normalize
 *   true(기본)이면 PII 패턴 중간의 불필요 줄바꿈/공백을 정규화.
 *   PDF 특성상 단어/숫자 중간에 줄바꿈·칸별 공백이 삽입되어
 *   PII 검출이 실패하는 경우가 많으므로 기본 활성화.
 */
export async function readText(path: string, options?: { normalize?: boolean }): Promise<string> {
  const normalize = options?.normalize ?? true;
  const raw = await extractRaw(path);
  if (normalize) {
    return normalizeForDetection(raw)[0];
  }
  return raw;
}

/** PDF 텍스트 추출 + offset 역매핑 정보.
 *
 * Returns [raw, normalized, offsetMap]
 *   raw : 원본 PDF 추출 텍스트
 *   normalized : 정규화된 텍스트 (PII 검출용)
 *   offsetMap : normalized[i] → raw[offsetMap[i]]
 */
export async function readTextWithMap(path: string): Promise<[string, string, number[]]> {
  const raw = await extractRaw(path);
  const [normalized, offsetMap] = normalizeForDetection(raw);
  return [raw, normalized, offsetMap];
}
