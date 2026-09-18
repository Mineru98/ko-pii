/** PDF 텍스트 레이어 추출 — Python ko_pii/io_/pdf.py 대응 (unpdf 단일 경로).
 *
 * Python 원본은 pdfplumber > pypdf 폴백 체인을 쓰지만, TS 포트는 unpdf(pdf.js)
 * 단일 경로로 대체한다. 페이지 텍스트 조립은 unpdf 의 방식(item.str + hasEOL 개행)
 * 을 그대로 따르며 페이지별 예외는 빈 문자열로 격리한다 — Python 의 페이지별
 * try/except 와 동일.
 *
 * 이미지/스캔 PDF 는 OCR 필요 — 본 모듈은 *텍스트 레이어* 만 추출
 * (한국 공공 결재 PDF 는 대부분 텍스트 레이어 있음).
 */
import { readFile } from "node:fs/promises";
import { getDocumentProxy } from "unpdf";
import { normalizeForDetection } from "./textNormalizer.js";

/** PDF → 원본 텍스트 추출 (페이지별 "\n\n" 결합 — Python ``_extract_raw`` 대응). */
async function extractRaw(path: string): Promise<string> {
  const data = await readFile(path);
  const pdf = await getDocumentProxy(new Uint8Array(data));
  const parts: string[] = [];
  for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
    let text = "";
    try {
      const page = await pdf.getPage(pageNum);
      const { items } = await page.getTextContent();
      // unpdf 의 페이지 텍스트 조립과 동일: str 없는 item 제외, hasEOL 에서 개행.
      let pageText = "";
      for (const item of items) {
        if (!("str" in item) || item.str == null) continue;
        pageText += item.str + (item.hasEOL ? "\n" : "");
      }
      text = pageText;
    } catch {
      text = "";
    }
    parts.push(text);
  }
  return parts.join("\n\n");
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
