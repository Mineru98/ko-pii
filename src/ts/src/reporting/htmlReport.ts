/** HTML 검토 리포트 — 단일 정적 HTML 파일 (외부 의존성 0).
 *
 * Python `ko_pii.reporting.html_report` 1:1 포트. 출력 HTML 문자열은 Python 과
 * 바이트 동일하다 (비결정 요소 없음 — 타임스탬프를 넣지 않는다).
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

import { riskLevelName } from "../analytics/index.js";
import type { AnonymizationResult, DetectionRecord } from "../anonymizer.js";
import { Action } from "../core/modes.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { compareCodePoints } from "./summary.js";

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

/** 텍스트에 검출 span 을 <span class="pii"> 로 감싸 HTML 생성. */
function annotateHtml(text: string, detections: DetectionRecord[], withMarking = false): string {
  // Python sorted key (start, -end) — start 오름차순, end 내림차순
  const sortedD = [...detections].sort(
    (a, b) => a.detection.start - b.detection.start || b.detection.end - a.detection.end,
  );
  const out: string[] = [];
  let cursor = 0;
  for (const r of sortedD) {
    const d = r.detection;
    if (d.start < cursor) continue; // overlap (이미 포함됨)
    out.push(htmlEscape(text.slice(cursor, d.start)));
    const risk = riskLevelName(d.riskLevel);
    const action = `${r.action}`;
    const tokenAttr = r.token ? ` data-token="${htmlEscape(r.token)}"` : "";
    const markBtns =
      withMarking && r.action === Action.REVIEW
        ? ' <span class="mark-buttons">' +
          '<button class="ok" onclick="mark(this,\'OK\')">✓</button>' +
          '<button class="fp" onclick="mark(this,\'FP\')">✗</button>' +
          "</span>"
        : "";
    out.push(
      `<span class="pii pii-${htmlEscape(d.label)}" ` +
        `style="background:${colorFor(d.label)}22;border-bottom:2px solid ${colorFor(d.label)};" ` +
        `data-label="${htmlEscape(d.label)}" ` +
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
`;

const JS = `
let marks = {};
function mark(btn, verdict) {
  const span = btn.parentElement.previousElementSibling;
  const token = span.dataset.token || (span.dataset.label + ':' + span.innerText);
  marks[token] = verdict;
  span.style.outline = verdict === 'OK' ? '2px solid #4caf50' : '2px solid #f44336';
}
function exportMarks() {
  const blob = new Blob([JSON.stringify(marks, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'review_marks.json';
  a.click();
}
`;

export interface HtmlReportOptions {
  /** 문서 식별자 — 제목과 헤더에 표시. */
  documentId?: string;
  /** REVIEW 항목에 OK/FP 마킹 버튼 + 마킹 다운로드 블록 포함 여부. */
  enableMarking?: boolean;
}

export function generateHtmlReport(
  originalText: string,
  result: AnonymizationResult,
  options: HtmlReportOptions = {},
): string {
  const documentId = options.documentId ?? "(unspecified)";
  const enableMarking = options.enableMarking ?? true;

  const s = result.summary;
  const combinedRisk = (s.combined_risk as string | undefined) ?? "INFO";
  const byLabel = (s.by_label as Record<string, number> | undefined) ?? {};
  const counts = Object.values(byLabel);
  const maxCount = counts.length > 0 ? Math.max(...counts) : 1;
  const mode = (s.mode as string | undefined) ?? "-";
  const strategy = (s.strategy as string | undefined) ?? "-";
  const total = (s.total as number | undefined) ?? 0;
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
      `<div class="value">${v}</div></div>`;
  }

  const markingBlock = enableMarking
    ? '<div style="padding:16px 24px;"><button onclick="exportMarks()">' +
      "검토 마킹 다운로드 (review_marks.json)</button></div>"
    : "";

  const catRowsHtml = catRows.join("");

  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
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

<script>${JS}</script>
</body>
</html>
`;
}
