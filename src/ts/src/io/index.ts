/** 파일 입력 (Document I/O) — Python ko_pii.io_ 대응 통합 진입점.
 *
 * 지원 포맷: txt/md/log(UTF-8/cp949 자동), hwpx/docx/xlsx(OOXML), csv/tsv,
 * hwp 5.x(OLE+레코드), pdf. 모든 포맷에 text_normalizer 가 적용된다.
 *
 * 참고: jszip/fast-xml-parser/cfb/iconv-lite/unpdf 는 이 서브패스 전용 의존성 —
 * 코어(ko-pii 루트 import)는 의존성 0을 유지한다.
 */

export type { BoundedDocument } from "./bounded.js";
export {
  BoundedReadError,
  DEFAULT_BOUNDED_EXTENSIONS,
  FileReadPolicy,
  readTextBounded,
} from "./bounded.js";
export { readText as readCsvText } from "./csvReader.js";
export { readRecords, readText, SUPPORTED_EXTENSIONS } from "./dispatcher.js";
export { readText as readDocxText } from "./docx.js";
export { readText as readHwpText } from "./hwp.js";
export { readText as readHwpxText } from "./hwpx.js";
export { readText as readPdfText, readTextWithMap as readPdfTextWithMap } from "./pdf.js";
export { readText as readPlainText } from "./plain.js";
export { normalizeForDetection } from "./textNormalizer.js";
export { readRecords as readXlsxRecords, readText as readXlsxText } from "./xlsx.js";
