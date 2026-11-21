/**
 * 라벨된 원문 span 을 실제 치환과 대조 — 재검출하지 않는다. Python ``ko_pii.eval.output`` 대응.
 *
 * 오프셋은 TS 판 정책대로 UTF-16 코드 유닛 (PORTING.md).
 */
import type { AnonymizationResult } from "../anonymizer.js";
import { ValueError } from "../core/errors.js";
import { ProcessingMode } from "../core/modes.js";
import { codePointCompare, validateStrategies } from "../policy.js";
import { pyEqual } from "./pyEqual.js";
import type { GoldDocument } from "./types.js";

export const OUTPUT_STATES = [
  "replaced",
  "missed",
  "retained_by_policy",
  "partially_replaced",
  "partial_strategy",
  "literal_retained",
] as const;

export type OutputState = (typeof OUTPUT_STATES)[number];

export interface OutputSpanRow {
  label: string;
  start: number;
  end: number;
  state: OutputState;
  covered_source_characters: number;
}

export interface OutputDocumentRow {
  id: string;
  spans: OutputSpanRow[];
}

const STATE_SET: ReadonlySet<string> = new Set(OUTPUT_STATES);

/** 치환된 span 은 익명성이나 미주석 PII 제거의 증거가 아니다. */
export function assessOutput(
  gold: GoldDocument,
  result: AnonymizationResult,
  strategy: string,
): OutputSpanRow[] {
  const rows: OutputSpanRow[] = [];
  for (const span of gold.spans) {
    const applied = result.substitutions.filter((s) => s.start < span.end && s.end > span.start);
    let covered = 0;
    for (const s of applied) covered += Math.min(span.end, s.end) - Math.max(span.start, s.start);
    let state: OutputState;
    if (applied.length === 0) {
      const detected = result.detections.some(
        (r) => r.detection.start < span.end && r.detection.end > span.start,
      );
      state = detected ? "retained_by_policy" : "missed";
    } else if (covered < span.end - span.start) {
      state = "partially_replaced";
    } else {
      const replacement = applied
        .map((s) => result.text.slice(s.outputStart, s.outputEnd))
        .join("");
      if (replacement.includes(gold.text.slice(span.start, span.end))) {
        state = "literal_retained";
      } else if (
        result.detections.some(
          (r) =>
            applied.some((s) => s.start === r.detection.start && s.end === r.detection.end) &&
            (r.strategy || strategy) === "partial",
        )
      ) {
        state = "partial_strategy";
      } else {
        state = "replaced";
      }
    }
    rows.push({
      label: span.label,
      start: span.start,
      end: span.end,
      state,
      covered_source_characters: covered,
    });
  }
  return rows;
}

function zeroCounts(): Record<OutputState, number> {
  const counts = {} as Record<OutputState, number>;
  for (const s of OUTPUT_STATES) counts[s] = 0;
  return counts;
}

export interface OutputSummary {
  contract: "source-span-substitution-v1";
  mode: string;
  strategy: string;
  counts: Record<OutputState, number>;
  per_label: Record<string, Record<OutputState, number>>;
  not_fully_replaced: number;
  documents?: OutputDocumentRow[];
  strategies?: Record<string, string>;
}

export function summarizeOutput(
  documents: OutputDocumentRow[],
  mode: string,
  strategy: string,
): OutputSummary {
  const counts = zeroCounts();
  const perLabel: Record<string, Record<OutputState, number>> = {};
  for (const document of documents) {
    for (const span of document.spans) {
      counts[span.state] += 1;
      if (!Object.hasOwn(perLabel, span.label)) perLabel[span.label] = zeroCounts();
      (perLabel[span.label] as Record<OutputState, number>)[span.state] += 1;
    }
  }
  let total = 0;
  for (const s of OUTPUT_STATES) total += counts[s];
  return {
    contract: "source-span-substitution-v1",
    mode,
    strategy,
    counts,
    per_label: perLabel,
    not_fully_replaced: total - counts.replaced,
    documents,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInt(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

export interface OutputChange {
  id: string;
  label: string;
  start: number;
  end: number;
  before: string;
  after: string;
}

export interface OutputComparison {
  changes: OutputChange[];
  new_not_fully_replaced: number;
  resolved_not_fully_replaced: number;
}

type SpanKey = [string, string, number, number];

function compareKeys(a: SpanKey, b: SpanKey): number {
  return codePointCompare(a[0], b[0]) || codePointCompare(a[1], b[1]) || a[2] - b[2] || a[3] - b[3];
}

/** 코퍼스·주석 동일성 확인 후 실제 보존 상태를 비교 (Python ``compare_output_reports``). */
export function compareOutputReports(
  current: Record<string, unknown>,
  baseline: Record<string, unknown>,
): OutputComparison {
  const next = current.output_evaluation;
  const old = baseline.output_evaluation;
  if (!isRecord(next) || !isRecord(old)) {
    throw new ValueError("both reports require output evaluation");
  }
  for (const key of ["contract", "mode", "strategy", "strategies"]) {
    const a = Object.hasOwn(next, key) ? next[key] : {};
    const b = Object.hasOwn(old, key) ? old[key] : {};
    if (!pyEqual(a, b)) {
      throw new ValueError("output policies differ; do not compare them as code regressions");
    }
  }
  if (
    next.contract !== "source-span-substitution-v1" ||
    !(Object.values(ProcessingMode) as unknown[]).includes(next.mode)
  ) {
    throw new ValueError("invalid output evaluation contract or mode");
  }
  const strategy = next.strategy;
  if (typeof strategy !== "string") {
    throw new ValueError("invalid output evaluation strategy");
  }
  validateStrategies(
    strategy,
    (Object.hasOwn(next, "strategies") ? next.strategies : {}) as Record<string, string>,
  );
  const sourceDocuments = new Map<string, Record<string, unknown>>();
  for (const row of current.documents as Record<string, unknown>[]) {
    sourceDocuments.set(row.id as string, row);
  }

  const index = (report: Record<string, unknown>): Map<string, [SpanKey, string]> => {
    const rows = report.documents;
    if (!Array.isArray(rows)) throw new ValueError("invalid output evaluation documents");
    const result = new Map<string, [SpanKey, string]>();
    const seen = new Set<string>();
    for (const row of rows as unknown[]) {
      if (
        !isRecord(row) ||
        typeof row.id !== "string" ||
        seen.has(row.id) ||
        !sourceDocuments.has(row.id)
      ) {
        throw new ValueError("invalid output evaluation document");
      }
      const id = row.id;
      seen.add(id);
      if (!Array.isArray(row.spans)) throw new ValueError("invalid output evaluation spans");
      const characters = (sourceDocuments.get(id) as Record<string, unknown>).characters as number;
      for (const span of row.spans as unknown[]) {
        const keys = isRecord(span) ? Object.keys(span) : [];
        if (
          !isRecord(span) ||
          keys.length !== 5 ||
          !["label", "start", "end", "state", "covered_source_characters"].every((k) =>
            Object.hasOwn(span, k),
          )
        ) {
          throw new ValueError("invalid output evaluation span");
        }
        const { label, start, end, state } = span;
        if (
          typeof label !== "string" ||
          !isInt(start) ||
          !isInt(end) ||
          !(start >= 0 && start < end && end <= characters) ||
          typeof state !== "string" ||
          !STATE_SET.has(state)
        ) {
          throw new ValueError("invalid output evaluation state");
        }
        const covered = span.covered_source_characters;
        const length = end - start;
        if (
          !isInt(covered) ||
          !(covered >= 0 && covered <= length) ||
          ((state === "missed" || state === "retained_by_policy") && covered !== 0) ||
          (state === "partially_replaced" && !(covered > 0 && covered < length)) ||
          ((state === "replaced" || state === "partial_strategy" || state === "literal_retained") &&
            covered !== length)
        ) {
          throw new ValueError("output evaluation state and covered characters disagree");
        }
        const key: SpanKey = [id, label, start, end];
        const k = JSON.stringify(key);
        if (result.has(k)) throw new ValueError("duplicate output evaluation span");
        result.set(k, [key, state]);
      }
    }
    if (seen.size !== sourceDocuments.size || [...seen].some((id) => !sourceDocuments.has(id))) {
      throw new ValueError("output evaluation document set differs");
    }
    return result;
  };

  const now = index(next);
  const previous = index(old);
  const expected = new Set<string>();
  for (const d of current.documents as {
    id: string;
    gold: { label: string; start: number; end: number }[];
  }[]) {
    for (const s of d.gold) expected.add(JSON.stringify([d.id, s.label, s.start, s.end]));
  }
  const sameKeys = (
    a: Iterable<string>,
    b: ReadonlySet<string> | ReadonlyMap<string, unknown>,
    n: number,
  ) => b.size === n && [...a].every((k) => b.has(k));
  if (!sameKeys(now.keys(), previous, now.size) || !sameKeys(now.keys(), expected, now.size)) {
    throw new ValueError("output evaluation annotations differ");
  }
  const changes: OutputChange[] = [];
  const ordered = [...now.entries()].sort((a, b) => compareKeys(a[1][0], b[1][0]));
  for (const [k, [key, state]] of ordered) {
    const before = (previous.get(k) as [SpanKey, string])[1];
    if (state !== before) {
      changes.push({ id: key[0], label: key[1], start: key[2], end: key[3], before, after: state });
    }
  }
  return {
    changes,
    new_not_fully_replaced: changes.filter((r) => r.before === "replaced" && r.after !== "replaced")
      .length,
    resolved_not_fully_replaced: changes.filter(
      (r) => r.before !== "replaced" && r.after === "replaced",
    ).length,
  };
}
