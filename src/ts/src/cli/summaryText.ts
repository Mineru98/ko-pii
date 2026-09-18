/**
 * 처리 결과 요약 텍스트 — Python ko_pii.reporting.summary.format_summary_text
 * 1:1 포트. (ts/src/reporting 은 다른 에이전트 소유 — 포팅 완료 후 이 파일을
 * reporting 쪽 구현으로 교체/재수출하면 된다.)
 *
 * stderr 요약 관례: "stdout = 처리 결과 본문, stderr = 한국어 요약".
 */
import type { AnonymizationResult } from "../anonymizer.js";
import { pyStrCompare } from "./argparse.js";

type Dict = Record<string, unknown>;

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function asDict(v: unknown): Dict {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Dict) : {};
}

/** Python `sorted(items)` — 코드 포인트 순. */
function sortedKeys(d: Dict): string[] {
  return Object.keys(d).sort(pyStrCompare);
}

/** Python `sorted(items, key=lambda x: (-x[1], x[0]))` 대응. */
function sortedByCountDesc(d: Dict): string[] {
  return Object.keys(d).sort((a, b) => {
    const ca = Number(d[a]);
    const cb = Number(d[b]);
    if (ca !== cb) return cb - ca;
    return pyStrCompare(a, b);
  });
}

export function formatSummaryText(result: AnonymizationResult): string {
  const s = result.summary as Dict;
  const lines: string[] = [];
  lines.push(`처리 모드: ${String(s.mode)}`);
  lines.push(`치환 전략: ${String(s.strategy)}`);
  lines.push(`총 검출: ${String(s.total)} 건`);
  lines.push("");
  lines.push(`[결합 위험도] ${s.combined_risk !== undefined ? String(s.combined_risk) : "—"}`);
  for (const r of asArray(s.combined_rationale)) {
    lines.push(`  · ${String(r)}`);
  }
  const identifiers = asArray(s.distinct_identifiers).map(String);
  if (identifiers.length > 0) {
    lines.push(`  식별자: ${identifiers.join(", ")}`);
  }
  const quasi = asArray(s.distinct_quasi_identifiers).map(String);
  if (quasi.length > 0) {
    lines.push(`  준식별자: ${quasi.join(", ")}`);
  }
  const sensitive = asArray(s.sensitive_attributes).map(String);
  if (sensitive.length > 0) {
    lines.push(`  민감속성: ${sensitive.join(", ")}`);
  }
  lines.push("");
  lines.push("[조치별 분포]");
  const byAction = asDict(s.by_action);
  for (const action of sortedKeys(byAction)) {
    lines.push(`  - ${action}: ${String(byAction[action])}`);
  }
  lines.push("");
  lines.push("[위험도별 분포]");
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const byRisk = asDict(s.by_risk);
  for (const name of order) {
    if (name in byRisk) {
      lines.push(`  - ${name}: ${String(byRisk[name])}`);
    }
  }
  lines.push("");
  lines.push("[카테고리별 분포]");
  const byLabel = asDict(s.by_label);
  for (const lbl of sortedByCountDesc(byLabel)) {
    lines.push(`  - ${lbl}: ${String(byLabel[lbl])}`);
  }
  lines.push("");
  lines.push("[법적 근거별 분포]");
  const byLegal = asDict(s.by_legal_basis);
  for (const lb of sortedKeys(byLegal)) {
    lines.push(`  - ${lb}: ${String(byLegal[lb])}`);
  }
  return lines.join("\n");
}
