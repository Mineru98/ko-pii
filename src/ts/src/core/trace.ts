/**
 * 공통 겹침 해소의 값 없는(value-free) 메타데이터 수집 — Python ko_pii.core.trace 대응.
 *
 * 원문 값은 담지 않는다: 라벨·규칙 ID·원문 좌표만 기록한다.
 */

import { ALL_LABELS } from "../labels.js";
import { ValueError } from "./errors.js";
import { Action, type ModePolicy } from "./modes.js";
import { pySpanLength } from "./strUtils.js";
import type { DetectionResult } from "./types.js";

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);

export const RULE_IDS: ReadonlySet<string> = new Set([
  ...ALL_LABELS.map((label) => `ko-pii.${label.toLowerCase()}.v1`),
  "field.asserted.v1",
]);

export const SUBRULE_IDS: ReadonlySet<string> = new Set([
  "email.ascii.v1",
  "email.korean_domain.v1",
  "email.obfuscated.v1",
  "protection.overlap-remainder.v1",
]);

export type OverlapStage = "primary" | "hybrid" | "protection";
const STAGES: ReadonlySet<string> = new Set(["primary", "hybrid", "protection"]);

export function validateTraceLimit(limit: unknown): void {
  if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 0 || limit > 1000) {
    throw new ValueError("trace_limit must be an integer between 0 and 1000");
  }
}

export interface TraceMetadata {
  label: string;
  rule_id: string | null;
  subrule_id: string | null;
  source_span: [number, number];
}

export interface TraceEvent {
  stage: string;
  reason: string;
  candidate: TraceMetadata;
  blocker: TraceMetadata;
}

export interface StageCounts {
  candidates: number;
  kept: number;
  discarded: number;
}

export interface OverlapTraceReport {
  schema_version: 1;
  contract: "ko-pii-overlap-trace-v1";
  scope: string;
  limit: number;
  truncated: boolean;
  omitted_events: number;
  stages: Record<string, StageCounts>;
  discarded: TraceEvent[];
}

function metadata(d: DetectionResult): TraceMetadata {
  const ruleId = d.ruleId ?? null;
  const subruleId = d.subruleId ?? null;
  return {
    label: LABEL_SET.has(d.label) ? d.label : "UNKNOWN",
    rule_id: ruleId !== null && RULE_IDS.has(ruleId) ? ruleId : null,
    subrule_id: subruleId !== null && SUBRULE_IDS.has(subruleId) ? subruleId : null,
    source_span: [d.start, d.end],
  };
}

/** 후보 수는 전부 세고, 상한은 버려진 후보 메타데이터에만 적용된다.
 *
 * blocker 는 해당 단계에서 채택된 겹치는 후보 하나이며, 유일한 blocker 이거나 최종 출력
 * 검출임을 뜻하지 않는다.
 */
export class OverlapTrace {
  private readonly limit: number;
  private readonly events: TraceEvent[] = [];
  private discardedCount = 0;
  private readonly stages: Record<string, StageCounts> = {};

  constructor(limit = 100) {
    validateTraceLimit(limit);
    this.limit = limit;
  }

  record(
    candidate: DetectionResult,
    blocker: DetectionResult | null,
    stage: string,
    policy?: ModePolicy | null,
  ): void {
    if (!STAGES.has(stage)) {
      throw new ValueError("unknown overlap stage");
    }
    let counts = this.stages[stage];
    if (counts === undefined) {
      counts = { candidates: 0, kept: 0, discarded: 0 };
      this.stages[stage] = counts;
    }
    counts.candidates += 1;
    if (blocker === null) {
      counts.kept += 1;
      return;
    }
    counts.discarded += 1;
    this.discardedCount += 1;
    if (this.events.length >= this.limit) return;
    let reason: string;
    if (
      policy != null &&
      policy.decide(candidate.riskLevel, candidate.confidence) !== Action.BLOCK &&
      policy.decide(blocker.riskLevel, blocker.confidence) === Action.BLOCK
    ) {
      reason = "non_blocking_policy_priority";
    } else if (candidate.riskLevel !== blocker.riskLevel) {
      reason = "lower_risk_priority";
    } else if (candidate.confidence !== blocker.confidence) {
      reason = "lower_confidence_priority";
    } else if (pySpanLength(candidate) !== pySpanLength(blocker)) {
      reason = "shorter_span_priority";
    } else if (candidate.start !== blocker.start) {
      reason = "later_start_priority";
    } else {
      reason = "stable_input_order_tie";
    }
    this.events.push({
      stage,
      reason,
      candidate: metadata(candidate),
      blocker: metadata(blocker),
    });
  }

  report(): OverlapTraceReport {
    const stages: Record<string, StageCounts> = {};
    for (const [key, value] of Object.entries(this.stages)) stages[key] = { ...value };
    return {
      schema_version: 1,
      contract: "ko-pii-overlap-trace-v1",
      scope: "common_overlap_only; excludes_detector_internal_and_merge_policy_rejections",
      limit: this.limit,
      truncated: this.discardedCount > this.events.length,
      omitted_events: this.discardedCount - this.events.length,
      stages,
      discarded: this.events.map((e) => ({
        stage: e.stage,
        reason: e.reason,
        candidate: { ...e.candidate, source_span: [...e.candidate.source_span] },
        blocker: { ...e.blocker, source_span: [...e.blocker.source_span] },
      })),
    };
  }
}
