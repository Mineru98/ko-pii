/** 처리 결과 요약 — by_risk / by_action / by_legal_basis.
 *
 * Python `ko_pii.reporting.summary` 1:1 포트.
 */

import { riskLevelName } from "../analytics/index.js";
import type { AnonymizationResult, DetectionRecord } from "../anonymizer.js";
import { Action } from "../core/modes.js";

type SummaryDict = Record<string, unknown>;

/** Python str 정렬(코드 포인트 순) 대응 비교자. BMP 문자에서는 기본 정렬과 동일. */
export function compareCodePoints(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i) as number;
    const cb = b.codePointAt(j) as number;
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  if (i < a.length) return 1; // b 가 접두사 → b < a
  if (j < b.length) return -1; // a 가 접두사 → a < b
  return 0;
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? (v as string[]) : [];
}

function numDict(v: unknown): Record<string, number> {
  return v !== null && typeof v === "object" ? (v as Record<string, number>) : {};
}

/** Python f-string 이 `None` 을 "None" 으로 보간하는 것에 대응. */
function fmt(v: unknown): string {
  return v === null || v === undefined ? "None" : String(v);
}

/** ``AnonymizationResult`` 에 붙은 구조화 요약의 사본을 반환.
 *
 * Python 과 동일하게 요약은 ``Anonymizer`` 가 만들며, 이 함수는 import 경로
 * 안정화를 위한 얇은 접근자다.
 */
export function summarize(result: AnonymizationResult): SummaryDict {
  return { ...result.summary };
}

export function formatSummaryText(result: AnonymizationResult): string {
  const s = result.summary;
  const lines: string[] = [];
  lines.push(`처리 모드: ${fmt(s.mode)}`);
  lines.push(`치환 전략: ${fmt(s.strategy)}`);
  lines.push(`총 검출: ${fmt(s.total)} 건`);
  lines.push("");
  lines.push(`[결합 위험도] ${(s.combined_risk as string | undefined) ?? "—"}`);
  for (const r of strArray(s.combined_rationale)) {
    lines.push(`  · ${r}`);
  }
  const ids = strArray(s.distinct_identifiers);
  if (ids.length > 0) lines.push(`  식별자: ${ids.join(", ")}`);
  const quasi = strArray(s.distinct_quasi_identifiers);
  if (quasi.length > 0) lines.push(`  준식별자: ${quasi.join(", ")}`);
  const sensitive = strArray(s.sensitive_attributes);
  if (sensitive.length > 0) lines.push(`  민감속성: ${sensitive.join(", ")}`);
  lines.push("");
  lines.push("[조치별 분포]");
  const byAction = numDict(s.by_action);
  for (const action of Object.keys(byAction).sort(compareCodePoints)) {
    lines.push(`  - ${action}: ${byAction[action]}`);
  }
  lines.push("");
  lines.push("[위험도별 분포]");
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const byRisk = numDict(s.by_risk);
  for (const name of order) {
    if (name in byRisk) lines.push(`  - ${name}: ${byRisk[name]}`);
  }
  lines.push("");
  lines.push("[카테고리별 분포]");
  const byLabel = numDict(s.by_label);
  const labelEntries = Object.entries(byLabel).sort(
    (x, y) => y[1] - x[1] || compareCodePoints(x[0], y[0]),
  );
  for (const [lbl, n] of labelEntries) {
    lines.push(`  - ${lbl}: ${n}`);
  }
  lines.push("");
  lines.push("[법적 근거별 분포]");
  const byLegal = numDict(s.by_legal_basis);
  for (const lb of Object.keys(byLegal).sort(compareCodePoints)) {
    lines.push(`  - ${lb}: ${byLegal[lb]}`);
  }
  return lines.join("\n");
}

/** 검토(REVIEW) 표시된 항목의 사전형 레코드 — 사람 검수용. */
export interface ReviewQueueEntry {
  label: string;
  text: string;
  span: [number, number];
  risk_level: string;
  confidence: number;
  evidence: string[];
  legal_basis: string | null;
}

/** 정책이 REVIEW 로 표시한 항목들 — 사람 검수용. */
export function reviewQueue(records: Iterable<DetectionRecord>): ReviewQueueEntry[] {
  const out: ReviewQueueEntry[] = [];
  for (const r of records) {
    if (r.action !== Action.REVIEW) continue;
    const d = r.detection;
    out.push({
      label: d.label,
      text: d.text,
      span: [d.start, d.end],
      risk_level: riskLevelName(d.riskLevel),
      confidence: d.confidence,
      evidence: [...d.evidence],
      legal_basis: d.legal_basis,
    });
  }
  return out;
}
