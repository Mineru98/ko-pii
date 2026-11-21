/**
 * Precision / Recall / F1 — span-level + label-level. Python ``ko_pii.eval.metrics`` 대응.
 *
 * 매칭 정책:
 * - **strict**: 라벨 + (start, end) 가 정확히 일치해야 TP.
 * - **partial**: 라벨이 같고 span 이 겹치면 TP. (오프셋 1~2 자 차이 허용)
 *
 * 각 구간은 최대 한 번만 대응하며, partial 은 순서와 무관한 최대 일대일 매칭을 쓴다.
 *
 * 기본 정책은 ``partial`` — 검출 모듈이 조사·구두점을 포함/배제하는 차이는
 * 일상적이라서 strict 만 보면 점수가 과소평가됨.
 *
 * 오프셋은 gold·예측 모두 UTF-16 코드 유닛이어야 한다 (Python 코드 포인트 골드를
 * 가져올 때는 호출자가 변환).
 */
import { pyStrCompare } from "../cli/argparse.js";
import { ValueError } from "../core/errors.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import type { DetectionResult } from "../core/types.js";
import { padLeft, padRight } from "./pyCompat.js";
import type { GoldDocument, GoldSpan } from "./types.js";

export class PerLabelMetrics {
  label: string;
  tp: number;
  fp: number;
  fn: number;

  constructor(label: string, tp = 0, fp = 0, fn = 0) {
    this.label = label;
    this.tp = tp;
    this.fp = fp;
    this.fn = fn;
  }

  get precision(): number {
    const denom = this.tp + this.fp;
    return denom ? this.tp / denom : 0.0;
  }

  get recall(): number {
    const denom = this.tp + this.fn;
    return denom ? this.tp / denom : 0.0;
  }

  get f1(): number {
    const p = this.precision;
    const r = this.recall;
    return p + r ? (2 * p * r) / (p + r) : 0.0;
  }
}

export class BenchmarkReport {
  /** 삽입 순서 유지 (Python dict). */
  perLabel: Map<string, PerLabelMetrics>;
  documentCount: number;
  matchMode: string;

  constructor(
    init: {
      perLabel?: Map<string, PerLabelMetrics>;
      documentCount?: number;
      matchMode?: string;
    } = {},
  ) {
    this.perLabel = init.perLabel ?? new Map();
    this.documentCount = init.documentCount ?? 0;
    this.matchMode = init.matchMode ?? "partial";
  }

  micro(): PerLabelMetrics {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    for (const m of this.perLabel.values()) {
      tp += m.tp;
      fp += m.fp;
      fn += m.fn;
    }
    return new PerLabelMetrics("(micro)", tp, fp, fn);
  }

  macroF1(): number {
    if (this.perLabel.size === 0) return 0.0;
    let sum = 0;
    for (const m of this.perLabel.values()) sum += m.f1;
    return sum / this.perLabel.size;
  }
}

function spansMatch(g: GoldSpan, p: DetectionResult, mode: string): boolean {
  if (g.label !== p.label) return false;
  if (mode === "strict") return g.start === p.start && g.end === p.end;
  // partial — non-empty overlap
  return g.start < p.end && p.start < g.end;
}

function setDefault(metrics: Map<string, PerLabelMetrics>, label: string): PerLabelMetrics {
  let m = metrics.get(label);
  if (m === undefined) {
    m = new PerLabelMetrics(label);
    metrics.set(label, m);
  }
  return m;
}

function validateMode(mode: string): void {
  if (mode !== "strict" && mode !== "partial") {
    throw new ValueError("match mode must be 'strict' or 'partial'");
  }
}

/** 반복 증가 경로(BFS)로 구한 최대 일대일 매칭 크기 (Python ``_matching_size``). */
export function matchingSize(edges: number[][], predictionCount: number): number {
  const owners = new Array<number>(predictionCount).fill(-1);
  const matches = new Array<number>(edges.length).fill(-1);
  let count = 0;
  for (let root = 0; root < edges.length; root++) {
    const queue: number[] = [root];
    let head = 0;
    const parents = new Map<number, number>();
    let free = -1;
    while (head < queue.length && free === -1) {
      const goldIndex = queue[head++] as number;
      for (const predictionIndex of edges[goldIndex] as number[]) {
        if (parents.has(predictionIndex)) continue;
        parents.set(predictionIndex, goldIndex);
        const owner = owners[predictionIndex] as number;
        if (owner === -1) {
          free = predictionIndex;
          break;
        }
        queue.push(owner);
      }
    }
    if (free === -1) continue;
    count += 1;
    while (free !== -1) {
      const goldIndex = parents.get(free) as number;
      const previous = matches[goldIndex] as number;
      matches[goldIndex] = free;
      owners[free] = goldIndex;
      free = previous;
    }
  }
  return count;
}

export function scoreDocument(
  gold: GoldDocument,
  predictions: Iterable<DetectionResult>,
  mode = "partial",
): Map<string, PerLabelMetrics> {
  validateMode(mode);
  const goldByLabel = new Map<string, GoldSpan[]>();
  const predByLabel = new Map<string, DetectionResult[]>();
  for (const g of gold.spans) {
    const list = goldByLabel.get(g.label);
    if (list) list.push(g);
    else goldByLabel.set(g.label, [g]);
  }
  for (const p of predictions) {
    const list = predByLabel.get(p.label);
    if (list) list.push(p);
    else predByLabel.set(p.label, [p]);
  }
  const metrics = new Map<string, PerLabelMetrics>();
  const labels = [...new Set([...goldByLabel.keys(), ...predByLabel.keys()])].sort(pyStrCompare);
  for (const label of labels) {
    const goldSpans = goldByLabel.get(label) ?? [];
    const preds = predByLabel.get(label) ?? [];
    let tp: number;
    if (mode === "strict") {
      // Counter 교집합 — (start, end) 별 min(gold 수, 예측 수) 합.
      const goldCounts = new Map<string, number>();
      for (const g of goldSpans) {
        const k = `${g.start},${g.end}`;
        goldCounts.set(k, (goldCounts.get(k) ?? 0) + 1);
      }
      const predCounts = new Map<string, number>();
      for (const p of preds) {
        const k = `${p.start},${p.end}`;
        predCounts.set(k, (predCounts.get(k) ?? 0) + 1);
      }
      tp = 0;
      for (const [k, n] of goldCounts) tp += Math.min(n, predCounts.get(k) ?? 0);
    } else {
      const edges = goldSpans.map((g) =>
        preds.flatMap((p, i) => (spansMatch(g, p, mode) ? [i] : [])),
      );
      tp = matchingSize(edges, preds.length);
    }
    metrics.set(label, new PerLabelMetrics(label, tp, preds.length - tp, goldSpans.length - tp));
  }
  return metrics;
}

/**
 * Score a list of gold docs.
 *
 * ``predictFn(text) -> DetectionResult[]`` — the detector to evaluate.
 */
export function scoreCorpus(
  goldDocs: Iterable<GoldDocument>,
  predictFn: (text: string) => Iterable<DetectionResult>,
  mode = "partial",
): BenchmarkReport {
  validateMode(mode);
  const report = new BenchmarkReport({ matchMode: mode });
  for (const doc of goldDocs) {
    report.documentCount += 1;
    const perDoc = scoreDocument(doc, predictFn(doc.text), mode);
    for (const [label, m] of perDoc) {
      const agg = setDefault(report.perLabel, label);
      agg.tp += m.tp;
      agg.fp += m.fp;
      agg.fn += m.fn;
    }
  }
  return report;
}

function row(label: string, m: PerLabelMetrics): string {
  return (
    `${padRight(label, 22)}${padLeft(String(m.tp), 5)}${padLeft(String(m.fp), 5)}` +
    `${padLeft(String(m.fn), 5)}${padLeft(pyFormatFixed(m.precision, 3), 10)} ` +
    `${padLeft(pyFormatFixed(m.recall, 3), 8)}${padLeft(pyFormatFixed(m.f1, 3), 8)}`
  );
}

export function formatReport(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push(`문서 수: ${report.documentCount}`);
  lines.push(`매칭 정책: ${report.matchMode}`);
  lines.push("");
  lines.push(
    `${padRight("라벨", 22)}${padLeft("정탐", 5)}${padLeft("오탐", 5)}${padLeft("미탐", 5)}` +
      `${padLeft("정확도", 11)}${padLeft("재현율", 9)}${padLeft("F1", 8)}`,
  );
  lines.push("-".repeat(65));
  for (const label of [...report.perLabel.keys()].sort(pyStrCompare)) {
    lines.push(row(label, report.perLabel.get(label)!));
  }
  lines.push("-".repeat(65));
  lines.push(row("(전체)", report.micro()));
  lines.push(
    `${padRight("(macro F1)", 22)}${" ".repeat(15 + 11 + 9)}${padLeft(pyFormatFixed(report.macroF1(), 3), 8)}`,
  );
  return lines.join("\n");
}
