/** HTML 검토 리포트 — 단일 정적 HTML 파일 (외부 의존성 0).
 *
 * Python `ko_pii.reporting.html_report` 1:1 포트. 출력 HTML 문자열은 Python 과
 * 바이트 동일하다 — 단 마킹 메타데이터의 ``report_id`` (uuid4 hex) 는 호출마다 무작위다.
 * ``data-start``/``data-end``/``source_characters`` 는 Python 계약(``python_code_points``)대로
 * 코드 포인트로 내보낸다 (TS 내부 오프셋은 UTF-16 — 아스트랄 문자에서만 수치가 다르다).
 *
 * 특징:
 * - 원본 / 가명본 사이드 바이 사이드
 * - 카테고리별 색상 오버레이
 * - 검출 항목 hover → 신뢰도·근거·법조항 툴팁
 * - 결합 위험도·요약 통계 상단 표시
 * - 검토 큐 항목별 OK/FP 클릭 마킹 (JS 로컬 다운로드)
 *
 * 핵심 원칙: **단일 파일**, 외부 CSS·JS 없음, 어디서나 열림.
 */

import { randomUUID } from "node:crypto";
import { riskLevelName } from "../analytics/index.js";
import type { AnonymizationResult, DetectionRecord } from "../anonymizer.js";
import { ValueError } from "../core/errors.js";
import { Action } from "../core/modes.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { codePointLength } from "../core/strUtils.js";
import { validatedDetection } from "../core/validation.js";
import { ALL_LABELS } from "../labels.js";
import { compareCodePoints } from "./summary.js";

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);
const ACTIONS: ReadonlySet<unknown> = new Set(Object.values(Action));

const CATEGORY_COLORS: Readonly<Record<string, string>> = {
  RRN: "#d32f2f",
  FRN: "#d32f2f",
  PASSPORT: "#c62828",
  DRIVER_LICENSE: "#c62828",
  CARD: "#b71c1c",
  BUSINESS_REG: "#f57c00",
  CORP_REG: "#f57c00",
  ACCOUNT: "#e64a19",
  MEDICAL_INSURANCE: "#ad1457",
  PRESCRIPTION_ID: "#ad1457",
  PHONE: "#1976d2",
  FAX: "#1976d2",
  EMAIL: "#1565c0",
  IP: "#0277bd",
  VEHICLE: "#00838f",
  POSTAL_CODE: "#00695c",
  URL: "#9e9e9e",
  ADDRESS: "#388e3c",
  PERSON: "#7b1fa2",
  DOC_ID: "#5d4037",
  PETITION_ID: "#5d4037",
  EMPLOYEE_ID: "#6d4c41",
  PNU: "#558b2f",
  EDI_DRUG: "#ad1457",
  COURT_CASE: "#3949ab",
};

function colorFor(label: string): string {
  return CATEGORY_COLORS[label] ?? "#616161";
}

/** Python `html.escape` (quote=True 기본) 동등물 — 치환 순서와 결과가 동일하다. */
function htmlEscape(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

/** Python ``str(v)`` — None 은 "None". */
function pyStr(v: unknown): string {
  return v === null || v === undefined ? "None" : String(v);
}

function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v);
}

/** 불일치 문서를 거부한다 — 검출 span 밖의 차이도 포함 (Python ``_validate_source_result``). */
function validateSourceResult(original: unknown, result: AnonymizationResult): void {
  try {
    if (
      typeof original !== "string" ||
      result === null ||
      typeof result !== "object" ||
      typeof result.text !== "string" ||
      !Array.isArray(result.detections) ||
      !Array.isArray(result.substitutions)
    ) {
      throw new ValueError();
    }
    const blocked = new Set<string>();
    for (const record of result.detections) {
      if (record === null || typeof record !== "object" || !ACTIONS.has(record.action)) {
        throw new ValueError();
      }
      const detection = validatedDetection(record.detection, original, {
        allowCustomLabels: true,
      });
      if (record.action === Action.BLOCK) blocked.add(`${detection.start}:${detection.end}`);
    }
    let sourceCursor = 0;
    let outputCursor = 0;
    for (const span of result.substitutions) {
      if (
        span === null ||
        typeof span !== "object" ||
        !isInt(span.start) ||
        !isInt(span.end) ||
        !isInt(span.outputStart) ||
        !isInt(span.outputEnd) ||
        !(sourceCursor <= span.start && span.start < span.end && span.end <= original.length) ||
        !(
          outputCursor <= span.outputStart &&
          span.outputStart <= span.outputEnd &&
          span.outputEnd <= result.text.length
        ) ||
        !blocked.has(`${span.start}:${span.end}`) ||
        original.slice(sourceCursor, span.start) !==
          result.text.slice(outputCursor, span.outputStart)
      ) {
        throw new ValueError();
      }
      sourceCursor = span.end;
      outputCursor = span.outputEnd;
    }
    if (original.slice(sourceCursor) !== result.text.slice(outputCursor)) throw new ValueError();
  } catch (e) {
    if (e instanceof ValueError || e instanceof TypeError) {
      throw new ValueError(
        "HTML report requires matching source text, detections and substitution coordinates",
      );
    }
    throw e;
  }
}

/** 텍스트에 검출 span 을 <span class="pii"> 로 감싸 HTML 생성. */
function annotateHtml(text: string, detections: DetectionRecord[], withMarking = false): string {
  // Python sorted key (start, -end) — start 오름차순, end 내림차순
  const sortedD = [...detections].sort(
    (a, b) => a.detection.start - b.detection.start || b.detection.end - a.detection.end,
  );
  const out: string[] = [];
  let cursor = 0;
  for (const [findingIndex, r] of sortedD.entries()) {
    const d = r.detection;
    if (d.start < cursor) continue; // overlap (이미 포함됨)
    out.push(htmlEscape(text.slice(cursor, d.start)));
    const risk = riskLevelName(d.riskLevel);
    const action = `${r.action}`;
    const tokenAttr = r.token ? ` data-token="${htmlEscape(r.token)}"` : "";
    const markBtns =
      withMarking && r.action === Action.REVIEW
        ? ' <span class="mark-buttons">' +
          '<button class="ok" aria-label="탐지 맞음" aria-pressed="false" onclick="mark(this,\'OK\')">✓</button>' +
          '<button class="fp" aria-label="오탐" aria-pressed="false" onclick="mark(this,\'FP\')">✗</button>' +
          "</span>"
        : "";
    out.push(
      `<span class="pii pii-${htmlEscape(d.label)}" ` +
        `style="background:${colorFor(d.label)}22;border-bottom:2px solid ${colorFor(d.label)};" ` +
        `data-label="${htmlEscape(d.label)}" ` +
        `data-review-label="${LABEL_SET.has(d.label) ? d.label : "UNKNOWN"}" ` +
        `data-finding-id="finding-${findingIndex}" ` +
        `data-start="${codePointLength(text.slice(0, d.start))}" ` +
        `data-end="${codePointLength(text.slice(0, d.end))}" ` +
        `data-action="${action}" ` +
        `data-risk="${risk}" ` +
        `data-conf="${pyFormatFixed(d.confidence, 2)}"` +
        `${tokenAttr} ` +
        `title="${htmlEscape(d.label)} | risk=${risk} | conf=${pyFormatFixed(d.confidence, 2)} | ` +
        `action=${action} | ${htmlEscape(d.legal_basis ?? "")}">` +
        `${htmlEscape(d.text)}` +
        `</span>${markBtns}`,
    );
    cursor = d.end;
  }
  out.push(htmlEscape(text.slice(cursor)));
  return out.join("").replaceAll("\n", "<br>");
}

const CSS = `
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
       "Noto Sans KR", sans-serif; margin: 0; background: #f5f5f5; color: #212121; }
.header { background: #263238; color: #fff; padding: 16px 24px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 10; }
.header h1 { margin: 0; font-size: 18px; }
.header .meta { font-size: 12px; opacity: 0.7; margin-top: 4px; }
.privacy-notice { padding: 12px 24px; background: #fff3cd; color: #5a4300; line-height: 1.6; }
.risk-badge { display:inline-block; padding: 2px 10px; border-radius: 12px;
              font-weight: 600; font-size: 11px; margin-left: 8px; }
.risk-CRITICAL { background:#d32f2f; color:#fff; }
.risk-HIGH { background:#f57c00; color:#fff; }
.risk-MEDIUM { background:#fbc02d; color:#000; }
.risk-LOW { background:#388e3c; color:#fff; }
.risk-INFO { background:#90a4ae; color:#fff; }
.container { display: grid; grid-template-columns: 1fr 1fr;
             gap: 16px; padding: 16px 24px; }
.panel { background: #fff; padding: 16px 20px; border-radius: 6px;
         box-shadow: 0 1px 2px rgba(0,0,0,0.08); }
.panel h2 { margin: 0 0 12px 0; font-size: 14px; color: #555;
            border-bottom: 1px solid #eee; padding-bottom: 8px; }
.text-body { font-family: "Noto Sans Mono", "Consolas", monospace;
             font-size: 13px; line-height: 1.7; white-space: pre-wrap;
             word-break: break-all; }
.pii { padding: 1px 3px; border-radius: 3px; cursor: help; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 12px; padding: 16px 24px; }
.summary-card { background: #fff; padding: 12px; border-radius: 6px;
                box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
.summary-card .label { font-size: 11px; color: #757575; text-transform: uppercase; }
.summary-card .value { font-size: 22px; font-weight: 600; margin-top: 4px; }
.category-list { padding: 16px 24px; }
.cat-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 13px; }
.cat-dot { width: 12px; height: 12px; border-radius: 2px; flex-shrink: 0; }
.cat-name { font-weight: 500; min-width: 140px; }
.cat-count { color: #555; }
.cat-bar { flex: 1; height: 8px; background: #eee; border-radius: 4px; overflow: hidden; }
.cat-bar-inner { height: 100%; }
.mark-buttons { display: inline-flex; gap: 2px; margin-left: 4px; }
.mark-buttons button { border: 1px solid #ddd; background: #fafafa;
                       padding: 0 6px; cursor: pointer; font-size: 11px; }
.mark-buttons button.ok:hover { background: #c8e6c9; }
.mark-buttons button.fp:hover { background: #ffcdd2; }
.rationale { padding: 16px 24px; }
.rationale ul { margin: 4px 0 0 0; padding-left: 18px; }
.rationale li { font-size: 13px; color: #555; line-height: 1.5; }
@media (max-width: 720px) {
  .container { grid-template-columns: 1fr; }
  .mark-buttons button { min-width: 36px; min-height: 36px; }
}
`;

const JS = `
const marks = new Map();
const reviewMetadata = JSON.parse(document.getElementById('reviewMetadata').textContent);
function mark(btn, verdict) {
  const span = btn.parentElement.previousElementSibling;
  if (!span || !['OK', 'FP'].includes(verdict)) return;
  const id = span.dataset.findingId;
  const start = Number(span.dataset.start);
  const end = Number(span.dataset.end);
  if (!id || !span.dataset.reviewLabel || !Number.isInteger(start) || !Number.isInteger(end)
      || start < 0 || end <= start || end > reviewMetadata.source_characters) return;
  marks.set(id, {finding_id: id, label: span.dataset.reviewLabel, source_span: [start, end], verdict});
  span.style.outline = verdict === 'OK' ? '2px solid #4caf50' : '2px solid #f44336';
  for (const button of btn.parentElement.children) {
    button.setAttribute('aria-pressed', button === btn ? 'true' : 'false');
  }
  document.getElementById('markCount').textContent = String(marks.size);
}
function exportMarks() {
  const items = [...marks.values()].sort((a, b) => a.source_span[0] - b.source_span[0]
    || a.source_span[1] - b.source_span[1] || a.finding_id.localeCompare(b.finding_id));
  const payload = {...reviewMetadata, items};
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  const url = URL.createObjectURL(blob);
  a.href = url;
  a.download = 'review_marks.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
`;

export interface HtmlReportOptions {
  /** 문서 식별자 — 제목과 헤더에 표시. */
  documentId?: string;
  /** REVIEW 항목에 OK/FP 마킹 버튼 + 마킹 다운로드 블록 포함 여부. */
  enableMarking?: boolean;
}

/** 일치하는 원문/결과 한 쌍에 대한 민감한 로컬 검토 페이지를 만든다.
 *
 * 다운로드되는 v1 마킹은 공유 값이 아니라 선택한 위치(occurrence)를 식별한다. 원문·토큰·
 * 사용자 지정 문서 식별자는 내보내지 않는다. 원문/결과가 어긋나면 원문 없는 ``ValueError``.
 */
export function generateHtmlReport(
  originalText: string,
  result: AnonymizationResult,
  options: HtmlReportOptions = {},
): string {
  const documentId = options.documentId ?? "(unspecified)";
  const enableMarking = options.enableMarking ?? true;

  validateSourceResult(originalText, result);
  const s = result.summary;
  const combinedRisk = htmlEscape(
    pyStr(Object.hasOwn(s, "combined_risk") ? s.combined_risk : "INFO"),
  );
  const byLabel = (s.by_label as Record<string, number> | undefined) ?? {};
  const counts = Object.values(byLabel);
  const maxCount = counts.length > 0 ? Math.max(...counts) : 1;
  const mode = (s.mode as string | undefined) ?? "-";
  const strategy = (s.strategy as string | undefined) ?? "-";
  const total = htmlEscape(pyStr(Object.hasOwn(s, "total") ? s.total : 0));
  const rationale = (s.combined_rationale as string[] | undefined) ?? [];
  const byAction = (s.by_action as Record<string, number> | undefined) ?? {};

  // Category bars
  const catRows: string[] = [];
  const labelEntries = Object.entries(byLabel).sort(
    (x, y) => y[1] - x[1] || compareCodePoints(x[0], y[0]),
  );
  for (const [lbl, n] of labelEntries) {
    const color = colorFor(lbl);
    const pct = (100 * n) / maxCount;
    catRows.push(
      '<div class="cat-row">' +
        `<div class="cat-dot" style="background:${color}"></div>` +
        `<div class="cat-name">${htmlEscape(lbl)}</div>` +
        `<div class="cat-count">${n} 건</div>` +
        '<div class="cat-bar"><div class="cat-bar-inner" ' +
        `style="background:${color};width:${pyFormatFixed(pct, 1)}%"></div></div>` +
        "</div>",
    );
  }

  const rationaleLis = rationale.map((r) => `<li>${htmlEscape(r)}</li>`).join("");

  const annotatedOriginal = annotateHtml(originalText, result.detections, enableMarking);
  // Anonymized text: show as-is (no annotation needed, it has tokens already)
  const annotatedAnon = htmlEscape(result.text).replaceAll("\n", "<br>");

  let byRiskHtml = "";
  for (const [k, v] of Object.entries(byAction)) {
    byRiskHtml +=
      '<div class="summary-card"><div class="label">' +
      `${htmlEscape(k)}</div>` +
      `<div class="value">${htmlEscape(pyStr(v))}</div></div>`;
  }

  // Python json.dumps 기본 구분자 (", " / ": ").
  const reviewMetadata =
    `{"schema_version": 1, "contract": "ko-pii-html-review-marks-v1", ` +
    `"report_id": "${randomUUID().replaceAll("-", "")}", "scope": "selected_occurrences_only", ` +
    `"offset_unit": "python_code_points", "source_characters": ${codePointLength(originalText)}}`;

  const markingBlock = enableMarking
    ? '<div style="padding:16px 24px;">검토 표시 <strong id="markCount" aria-live="polite">0</strong>건 · ' +
      '<button onclick="exportMarks()">' +
      "검토 마킹 다운로드 (review_marks.json)</button></div>"
    : "";
  const scriptBlock = enableMarking
    ? `<script id="reviewMetadata" type="application/json">${reviewMetadata}</script><script>${JS}</script>`
    : "";

  const catRowsHtml = catRows.join("");

  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ko-pii 검토 리포트: ${htmlEscape(documentId)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="header">
  <h1>ko-pii 처리 리포트
    <span class="risk-badge risk-${combinedRisk}">${combinedRisk}</span>
  </h1>
  <div class="meta">문서: ${htmlEscape(documentId)} · 모드: ${htmlEscape(mode)}
    · 전략: ${htmlEscape(strategy)} · 총 검출 ${total} 건</div>
</div>

<div class="privacy-notice" role="note">
  이 HTML에는 원문 개인정보가 포함됩니다. 외부에 공개하지 말고 접근을 제한하세요.
  표시된 위험도는 탐지된 항목의 보조 지표이며, 미탐지 개인정보의 부재를 뜻하지 않습니다.
  검토 표시는 선택한 위치에만 적용되며 사전이나 처리 정책을 자동 변경하지 않습니다.
</div>

<div class="summary-grid">
  <div class="summary-card"><div class="label">결합 위험도</div>
    <div class="value">${combinedRisk}</div></div>
  ${byRiskHtml}
</div>

<div class="rationale">
  <strong>판단 근거:</strong>
  <ul>${rationaleLis}</ul>
</div>

<div class="category-list">
  <strong>카테고리별 분포:</strong>
  ${catRowsHtml}
</div>

<div class="container">
  <div class="panel">
    <h2>원본 (PII 표시)</h2>
    <div class="text-body">${annotatedOriginal}</div>
  </div>
  <div class="panel">
    <h2>가명화 결과</h2>
    <div class="text-body">${annotatedAnon}</div>
  </div>
</div>

${markingBlock}

${scriptBlock}
</body>
</html>
`;
}
