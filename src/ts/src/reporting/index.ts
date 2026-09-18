/** Reporting — 처리 결과의 사람·기계용 요약. Python `ko_pii.reporting.__init__` 대응.
 *
 * Python `__all__` = ["summarize", "format_summary_text", "generate_certificate"].
 * `generate_html_report` (html_report 서브모듈) 과 `review_queue` (summary 서브모듈) 는
 * Python 에서 `ko_pii.reporting.html_report` / `ko_pii.reporting.summary` 경로로
 * 접근하므로, 여기서는 편의상 문서화된 재수출로만 제공한다.
 */
export { generateCertificate } from "./certificate.js";
export { generateHtmlReport, type HtmlReportOptions } from "./htmlReport.js";
export {
  formatSummaryText,
  type ReviewQueueEntry,
  reviewQueue,
  summarize,
} from "./summary.js";
