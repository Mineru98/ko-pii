/**
 * 관측된 결정의 버전 관리되는 값 없는(value-free) 보고 — 익명성 주장이 아니다.
 * Python ko_pii.reporting.explanation 대응.
 *
 * TS 포트 메모: ``source_span``/``output_span`` 은 TS 오프셋 정책대로 UTF-16 코드 유닛이다.
 * ``offset_unit`` 문자열은 Python 계약과의 바이트 호환을 위해 원본 값을 유지한다 — 아스트랄
 * 문자가 없으면 수치가 동일하다 (PORTING.md).
 */
import type { AnonymizationResult } from "../anonymizer.js";
import { Action, ProcessingMode } from "../core/modes.js";
import { RULE_IDS, SUBRULE_IDS } from "../core/trace.js";
import { ALL_LABELS } from "../labels.js";
import { STRATEGIES } from "../policy.js";

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);
const MODES: ReadonlySet<string> = new Set(Object.values(ProcessingMode));
const CHECKS: ReadonlySet<string> = new Set([
  "checksum:valid",
  "checksum:invalid_or_post_2020",
  "checksum:luhn_valid",
  "obfuscated:deobfuscated",
  "field:asserted",
]);

export interface ExplanationFinding {
  label: string;
  rule_id: string | null;
  subrule_id: string | null;
  source_span: [number, number];
  output_span: [number, number] | null;
  normalized: boolean;
  checks: string[];
  confidence: number | null;
  action: string;
  requested_strategy: string | null;
  applied_strategy: string | null;
  reason: string;
}

/** 허용 목록 메타데이터만 내보낸다 — 텍스트·토큰·evidence·extra 는 로컬에 남는다.
 *
 * Rule ID 는 규칙 계열을, subrule 은 파생 보호 구간도 구분한다. 선택적 trace 는 공통 겹침
 * 해소만 다루며 모든 거부·누락을 다루지 않는다.
 */
export function explain(
  result: AnonymizationResult,
  options: { includeTrace?: boolean } = {},
): Record<string, unknown> {
  const spans = new Map<string, { outputStart: number; outputEnd: number }>();
  for (const s of result.substitutions) spans.set(`${s.start}:${s.end}`, s);
  const rows: ExplanationFinding[] = [];
  for (const record of result.detections) {
    const d = record.detection;
    const span = record.action === Action.BLOCK ? (spans.get(`${d.start}:${d.end}`) ?? null) : null;
    const selected = record.strategy || result.summary.strategy;
    const strategy = typeof selected === "string" && STRATEGIES.has(selected) ? selected : null;
    let reason: string;
    if (span === null) {
      reason =
        record.action === Action.BLOCK ? "not_selected_for_substitution" : "retained_by_policy";
    } else if (strategy === "partial") {
      reason = "partial_masking";
    } else {
      reason = "substituted";
    }
    const ruleId = d.ruleId ?? null;
    const subruleId = d.subruleId ?? null;
    rows.push({
      label: LABEL_SET.has(d.label) ? d.label : "UNKNOWN",
      rule_id: ruleId !== null && RULE_IDS.has(ruleId) ? ruleId : null,
      subrule_id: subruleId !== null && SUBRULE_IDS.has(subruleId) ? subruleId : null,
      source_span: [d.start, d.end],
      output_span: span ? [span.outputStart, span.outputEnd] : null,
      normalized: Boolean(d.normalized),
      checks: [...new Set(d.evidence.filter((item) => CHECKS.has(item)))].sort(),
      confidence: Number.isFinite(d.confidence) ? d.confidence : null,
      action: record.action,
      requested_strategy: strategy,
      applied_strategy: span ? strategy : null,
      reason,
    });
  }
  const mode = result.summary.mode;
  const resolution = result.summary.overlap_resolution ?? "";
  const priority =
    typeof resolution === "string" &&
    resolution.split(";", 1)[0] === "block_risk_confidence_length_start"
      ? "block_risk_confidence_length_start"
      : "risk_confidence_length_start";
  const report: Record<string, unknown> = {
    schema_version: 1,
    contract: "ko-pii-explanation-v1",
    scope: "selected_detections_only",
    overlap_resolution: `${priority}; discarded_candidates_not_included`,
    offset_unit: "python_code_points",
    mode: typeof mode === "string" && MODES.has(mode) ? mode : null,
    detection_count: rows.length,
    substitution_count: rows.filter((row) => row.output_span !== null).length,
    findings: rows,
  };
  if (options.includeTrace) {
    report.overlap_trace = result.overlap_trace !== null ? result.overlap_trace.report() : null;
  }
  return report;
}
