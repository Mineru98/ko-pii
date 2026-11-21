/**
 * 라벨된 로컬 문서 평가 + strict span 회귀 비교. Python ``ko_pii.eval.domain`` 대응
 * (``ko-pii-evaluate`` CLI 엔트리 ``main`` 포함 — bin 은 ``domainBin.ts``).
 *
 * 오프셋 정책: TS 판은 span 오프셋과 ``characters`` 를 UTF-16 코드 유닛으로 센다 (PORTING.md).
 * 아스트랄 문자(이모지 등)가 없는 코퍼스에서는 Python 보고서와 수치가 같다.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { Anonymizer } from "../anonymizer.js";
import { ArgumentParser, ParseExit } from "../cli/argparse.js";
import { ValueError } from "../core/errors.js";
import { ProcessingMode } from "../core/modes.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import type { DetectionResult } from "../core/types.js";
import { detectAll } from "../detect.js";
import { writeTextAtomic } from "../io/atomic.js";
import { ALL_LABELS, validateLabelFilter } from "../labels.js";
import { normalizeExclusions } from "../patterns/person.js";
import { codePointCompare, validateStrategies } from "../policy.js";
import { loadsJson, StructuredLimits } from "../structured.js";
import { pyIsoUtcNow, pyJsonDumps } from "../vault/reversible.js";
import { VERSION } from "../version.js";
import { K_PII_LABELS, loadKPiiBenchText } from "./external.js";
import { BenchmarkReport, PerLabelMetrics, scoreDocument } from "./metrics.js";
import {
  assessOutput,
  compareOutputReports,
  type OutputComparison,
  type OutputDocumentRow,
  type OutputSummary,
  summarizeOutput,
} from "./output.js";
import { cpLen, padLeft, padRight, pySplitlines, pyStrip } from "./pyCompat.js";
import { pyEqual } from "./pyEqual.js";
import type { GoldDocument, GoldSpan } from "./types.js";

export const MAX_DATASET_BYTES = 16 * 1024 * 1024;
export const MAX_DOCUMENTS = 10_000;
export const MAX_DOCUMENT_CHARS = 100_000;
export const MAX_SPANS = 2_000;
export const REPORT_SCHEMA_VERSION = 1;
export const MAX_REPORT_BYTES = 64 * 1024 * 1024;

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);

/** Python frozen dataclass ``LabeledDocument``. */
export class LabeledDocument {
  readonly id: string;
  readonly gold: GoldDocument;
  readonly domain: string | null;
  readonly variant: string | null;

  constructor(
    id: string,
    gold: GoldDocument,
    domain: string | null = null,
    variant: string | null = null,
  ) {
    this.id = id;
    this.gold = gold;
    this.domain = domain;
    this.variant = variant;
    Object.freeze(this);
  }
}

/** ``(label, start, end)`` — Python span 튜플. */
export type SpanTuple = readonly [string, number, number];

export interface SpanRow {
  label: string;
  start: number;
  end: number;
}

/** 평가 슬라이스 값 — 짧은 범주 식별자만 (Python ``[\w.-]{1,64}``). */
const SLICE_VALUE = /^[\p{L}\p{N}_.-]{1,64}$/u;
const PROVENANCE_ID = /^[\p{L}\p{N}_./-]{1,128}$/u;

export function sliceValue(value: unknown): string | null {
  if (
    value !== null &&
    value !== undefined &&
    (typeof value !== "string" || !SLICE_VALUE.test(value))
  ) {
    throw new ValueError("evaluation slice must be a short category identifier, not free text");
  }
  return (value ?? null) as string | null;
}

/** Python OSError 대응 — 파일시스템 오류 (메시지에 경로를 싣지 않으려 구분). */
function isOsError(e: unknown): boolean {
  return e instanceof Error && typeof (e as NodeJS.ErrnoException).code === "string";
}

/** ``max_bytes`` 를 넘지 않는 UTF-8 파일을 읽는다 (BOM 보존 — Python ``bytes.decode``). */
export function readJsonFile(file: string, maxBytes: number): string {
  const fd = fs.openSync(file, "r");
  let raw: Buffer;
  try {
    const chunks: Buffer[] = [];
    let total = 0;
    const limit = maxBytes + 1;
    const buf = Buffer.alloc(Math.min(limit, 1 << 20));
    while (total < limit) {
      const n = fs.readSync(fd, buf, 0, Math.min(buf.length, limit - total), null);
      if (n === 0) break;
      chunks.push(Buffer.from(buf.subarray(0, n)));
      total += n;
    }
    raw = Buffer.concat(chunks);
  } finally {
    fs.closeSync(fd);
  }
  if (raw.length > maxBytes) throw new ValueError("evaluation file exceeds the size limit");
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  } catch {
    throw new ValueError("evaluation files must be UTF-8");
  }
}

function spanKey(label: string, start: number, end: number): string {
  return `${label}\u0000${start}\u0000${end}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInt(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

/** 키 → 튜플. Python ``set[tuple[str, int, int]]`` 대응. */
type SpanSet = Map<string, SpanTuple>;

function spans(
  value: unknown,
  length: number,
  labels: ReadonlySet<string>,
  maxSpans: number = MAX_SPANS,
): SpanSet {
  if (!Array.isArray(value) || value.length > maxSpans) {
    throw new ValueError("spans must be a bounded list");
  }
  const out: SpanSet = new Map();
  for (const span of value as unknown[]) {
    if (
      !isRecord(span) ||
      Object.keys(span).length !== 3 ||
      !Object.hasOwn(span, "label") ||
      !Object.hasOwn(span, "start") ||
      !Object.hasOwn(span, "end")
    ) {
      throw new ValueError("each span requires exactly label, start and end");
    }
    const { label, start, end } = span;
    if (typeof label !== "string" || !labels.has(label)) {
      throw new ValueError("span label is outside the evaluated labels");
    }
    if (!isInt(start) || !isInt(end) || !(start >= 0 && start < end && end <= length)) {
      throw new ValueError("span offsets must be valid Python character offsets");
    }
    const key = spanKey(label, start, end);
    if (out.has(key)) throw new ValueError("duplicate span");
    out.set(key, [label, start, end]);
  }
  return out;
}

function compareSpan(a: SpanTuple, b: SpanTuple): number {
  return codePointCompare(a[0], b[0]) || a[1] - b[1] || a[2] - b[2];
}

function minus(a: SpanSet, b: SpanSet): SpanSet {
  const out: SpanSet = new Map();
  for (const [k, v] of a) if (!b.has(k)) out.set(k, v);
  return out;
}

function intersect(a: SpanSet, b: SpanSet): SpanSet {
  const out: SpanSet = new Map();
  for (const [k, v] of a) if (b.has(k)) out.set(k, v);
  return out;
}

function toSpanSet(items: Iterable<SpanTuple>): SpanSet {
  const out: SpanSet = new Map();
  for (const t of items) out.set(spanKey(t[0], t[1], t[2]), t);
  return out;
}

function spanRows(items: Iterable<SpanTuple>): SpanRow[] {
  return [...items].sort(compareSpan).map(([label, start, end]) => ({ label, start, end }));
}

/** id, text, spans 를 담은 JSONL 을 읽는다. */
export function loadDataset(file: string): LabeledDocument[] {
  return loadDatasetText(readJsonFile(file, MAX_DATASET_BYTES));
}

/** @internal Python ``_load_dataset_text``. */
export function loadDatasetText(raw: string): LabeledDocument[] {
  const documents: LabeledDocument[] = [];
  const seen = new Set<string>();
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    const lineNumber = i + 1;
    if (!pyStrip(line)) continue;
    try {
      const item = loadsJson(line);
      const keys = isRecord(item) ? Object.keys(item) : [];
      if (
        !isRecord(item) ||
        !["id", "text", "spans"].every((k) => Object.hasOwn(item, k)) ||
        !keys.every((k) => k === "id" || k === "text" || k === "spans" || k === "metadata")
      ) {
        throw new ValueError("each document requires id, text, spans and optional metadata");
      }
      const metadata = Object.hasOwn(item, "metadata") ? item.metadata : {};
      if (
        !isRecord(metadata) ||
        !Object.keys(metadata).every((k) => k === "domain" || k === "variant")
      ) {
        throw new ValueError("metadata supports domain and variant only");
      }
      const docId = item.id;
      const text = item.text;
      if (typeof docId !== "string" || !pyStrip(docId) || cpLen(docId) > 128) {
        throw new ValueError("id must be a nonempty string of at most 128 characters");
      }
      if (seen.has(docId)) throw new ValueError("document ids must be unique");
      if (typeof text !== "string" || cpLen(text) > MAX_DOCUMENT_CHARS) {
        throw new ValueError("text exceeds the document character limit");
      }
      const parsed = spans(item.spans, text.length, LABEL_SET);
      const gold: GoldDocument = {
        text,
        spans: [...parsed.values()].sort(compareSpan).map(([label, start, end]) => ({
          label,
          start,
          end,
          text: text.slice(start, end),
        })),
      };
      documents.push(
        new LabeledDocument(docId, gold, sliceValue(metadata.domain), sliceValue(metadata.variant)),
      );
      seen.add(docId);
      if (documents.length > MAX_DOCUMENTS) {
        throw new ValueError("dataset exceeds the document count limit");
      }
    } catch (e) {
      // JSON 디코더 메시지는 원문을 담을 수 있다 — 줄을 되울리지 않는다.
      if (e instanceof ValueError || e instanceof TypeError) {
        throw new ValueError(`dataset line ${lineNumber}: ${e.message}`);
      }
      throw e;
    }
  }
  if (documents.length === 0) throw new ValueError("dataset must contain at least one document");
  return documents;
}

const LONE_SURROGATE = /\p{Cs}/u;

function isGoldSpan(value: unknown): value is GoldSpan {
  return (
    isRecord(value) &&
    typeof value.label === "string" &&
    typeof value.start === "number" &&
    typeof value.end === "number" &&
    typeof value.text === "string"
  );
}

/** 라벨 필터링·검출 전에 입력 전체를 검증 (Python ``_validate_documents``). */
function validateDocuments(documents: readonly LabeledDocument[]): void {
  if (!Array.isArray(documents) || documents.length === 0) {
    throw new ValueError("dataset must contain at least one document");
  }
  if (documents.length > MAX_DOCUMENTS) {
    throw new ValueError("dataset exceeds the document count limit");
  }
  const seen = new Set<string>();
  for (const doc of documents) {
    if (
      !(doc instanceof LabeledDocument) ||
      typeof doc.id !== "string" ||
      !pyStrip(doc.id) ||
      cpLen(doc.id) > 128 ||
      seen.has(doc.id)
    ) {
      throw new ValueError("evaluation requires bounded documents with unique short ids");
    }
    seen.add(doc.id);
    if (
      !isRecord(doc.gold) ||
      typeof doc.gold.text !== "string" ||
      cpLen(doc.gold.text) > MAX_DOCUMENT_CHARS
    ) {
      throw new ValueError("text exceeds the document character limit or is not a string");
    }
    if (LONE_SURROGATE.test(doc.gold.text)) {
      throw new ValueError("evaluation text contains an invalid Unicode surrogate");
    }
    if (
      !Array.isArray(doc.gold.spans) ||
      doc.gold.spans.length > MAX_SPANS ||
      doc.gold.spans.some((s) => !isGoldSpan(s))
    ) {
      throw new ValueError("spans must be a bounded list of GoldSpan values");
    }
    spans(
      doc.gold.spans.map((s) => ({ label: s.label, start: s.start, end: s.end })),
      doc.gold.text.length,
      LABEL_SET,
    );
    if (doc.gold.spans.some((s) => s.text !== doc.gold.text.slice(s.start, s.end))) {
      throw new ValueError("gold span text does not match its source offsets");
    }
    sliceValue(doc.domain);
    sliceValue(doc.variant);
  }
}

export interface CountsRow {
  tp: number;
  fp: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

function counts(metric: PerLabelMetrics): CountsRow {
  return {
    tp: metric.tp,
    fp: metric.fp,
    fn: metric.fn,
    precision: metric.tp + metric.fp ? metric.precision : null,
    recall: metric.tp + metric.fn ? metric.recall : null,
    f1: metric.tp + metric.fp + metric.fn ? metric.f1 : null,
  };
}

function perLabelCounts(metrics: BenchmarkReport): Record<string, CountsRow> {
  const out: Record<string, CountsRow> = {};
  for (const label of [...metrics.perLabel.keys()].sort(codePointCompare)) {
    out[label] = counts(metrics.perLabel.get(label) as PerLabelMetrics);
  }
  return out;
}

function setDefault(metrics: BenchmarkReport, label: string): PerLabelMetrics {
  let m = metrics.perLabel.get(label);
  if (m === undefined) {
    m = new PerLabelMetrics(label);
    metrics.perLabel.set(label, m);
  }
  return m;
}

export interface DocumentRow {
  id: string;
  characters: number;
  gold: SpanRow[];
  predictions: SpanRow[];
  false_negatives: SpanRow[];
  false_positives: SpanRow[];
}

export interface SliceSummary {
  value: string | null;
  document_count: number;
  micro: CountsRow;
  per_label: Record<string, CountsRow>;
  output_evaluation?: OutputSummary;
}

function rowSet(rows: readonly SpanRow[]): SpanSet {
  return toSpanSet(rows.map((s) => [s.label, s.start, s.end] as const));
}

/** 카운트 합산 — 문서별 F1 평균이나 재검출은 하지 않는다. */
function sliceReports(
  documents: readonly LabeledDocument[],
  rows: readonly DocumentRow[],
  outputRows: readonly OutputDocumentRow[],
  mode: ProcessingMode | null,
  strategy: string,
  overrides: Record<string, string>,
): Record<string, SliceSummary[]> {
  const result: Record<string, SliceSummary[]> = {};
  const byId = new Map(rows.map((row) => [row.id, row] as const));
  for (const dimension of ["domain", "variant"] as const) {
    const categories = new Set(documents.map((doc) => doc[dimension]));
    if (categories.size === 1 && categories.has(null)) continue;
    const summaries: SliceSummary[] = [];
    const ordered = [...categories].sort((a, b) =>
      a === null ? (b === null ? 0 : -1) : b === null ? 1 : codePointCompare(a, b),
    );
    for (const value of ordered) {
      const ids = new Set(documents.filter((doc) => doc[dimension] === value).map((d) => d.id));
      const metrics = new BenchmarkReport({ matchMode: "strict" });
      for (const docId of ids) {
        const row = byId.get(docId) as DocumentRow;
        const gold = rowSet(row.gold);
        const predicted = rowSet(row.predictions);
        for (const [label] of intersect(gold, predicted).values())
          setDefault(metrics, label).tp += 1;
        for (const [label] of minus(predicted, gold).values()) setDefault(metrics, label).fp += 1;
        for (const [label] of minus(gold, predicted).values()) setDefault(metrics, label).fn += 1;
      }
      const summary: SliceSummary = {
        value,
        document_count: ids.size,
        micro: counts(metrics.micro()),
        per_label: perLabelCounts(metrics),
      };
      if (mode !== null) {
        const output = summarizeOutput(
          outputRows.filter((row) => ids.has(row.id)),
          mode,
          strategy,
        );
        delete output.documents;
        output.strategies = overrides;
        summary.output_evaluation = output;
      }
      summaries.push(summary);
    }
    result[dimension] = summaries;
  }
  return result;
}

/** 선언된 revision/split 을 실제로 읽은 바이트에 결속 — 업스트림 신뢰가 아니다. */
export function validateProvenance(value: unknown, sourceText: string): Record<string, unknown> {
  const keys = isRecord(value) ? Object.keys(value) : [];
  if (
    !isRecord(value) ||
    keys.length !== 4 ||
    !["schema_version", "source_sha256", "revision", "split"].every((k) =>
      Object.hasOwn(value, k),
    ) ||
    !isInt(value.schema_version) ||
    value.schema_version !== 1
  ) {
    throw new ValueError("provenance requires schema_version=1, source_sha256, revision and split");
  }
  for (const key of ["revision", "split"]) {
    const v = value[key];
    if (typeof v !== "string" || !PROVENANCE_ID.test(v)) {
      throw new ValueError("provenance revision/split must be bounded identifiers");
    }
  }
  const digest = createHash("sha256").update(sourceText, "utf8").digest("hex");
  if (value.source_sha256 !== digest) {
    throw new ValueError("provenance source digest does not match the dataset");
  }
  return { ...value, upstream_revision_verified: false };
}

/** Python ``json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))``. */
function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort(codePointCompare);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/** Python 기본 ``json.dumps(list_of_str)`` (ensure_ascii=True, ``", "`` 구분자). */
function asciiJsonStringList(values: readonly string[]): string {
  const enc = (s: string) =>
    JSON.stringify(s).replace(
      /[\u0080-￿]/g,
      (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
  return `[${values.map(enc).join(", ")}]`;
}

function localIsoDate(): string {
  const d = new Date();
  const pad2 = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

export interface EvaluateOptions {
  labels?: Iterable<string> | null;
  personExclusions?: Iterable<string>;
  outputMode?: ProcessingMode | null;
  outputStrategy?: string;
  outputStrategies?: Readonly<Record<string, string>> | ReadonlyMap<string, string> | null;
}

export interface EvaluationReport {
  schema_version: number;
  package_version: string;
  generated_at: string;
  evaluation_date: string;
  dataset_sha256: string;
  match_mode: "strict";
  evaluated_labels: string[];
  person_exclusions_sha256: string;
  document_count: number;
  documents_with_misses: number;
  micro: CountsRow;
  per_label: Record<string, CountsRow>;
  documents: DocumentRow[];
  output_evaluation?: OutputSummary;
  slices?: Record<string, SliceSummary[]>;
  dataset_adapter?: Record<string, unknown>;
  provenance?: Record<string, unknown>;
  comparison?: ReportComparison;
  [key: string]: unknown;
}

/** 검출과 (선택) 주석 span 의 실제 치환을 평가. */
export function evaluate(
  documents: readonly LabeledDocument[],
  options: EvaluateOptions = {},
): EvaluationReport {
  validateDocuments(documents);
  const outputMode = options.outputMode ?? null;
  const outputStrategy = options.outputStrategy ?? "redact";
  if (outputMode !== null && !(Object.values(ProcessingMode) as unknown[]).includes(outputMode)) {
    throw new ValueError("output_mode must be a ProcessingMode or None");
  }
  const overrides = validateStrategies(outputStrategy, options.outputStrategies);
  const selected = validateLabelFilter(options.labels, "labels");
  const active = new Set(selected === null ? ALL_LABELS : selected);
  if (active.size === 0) {
    throw new ValueError("evaluated labels must be a nonempty subset of ko-pii labels");
  }
  const exclusions = [...normalizeExclusions(options.personExclusions ?? [])].sort(
    codePointCompare,
  );
  const sortedDocs = [...documents].sort((a, b) => codePointCompare(a.id, b.id));
  const canonical: Record<string, unknown>[] = sortedDocs.map((doc) => ({
    id: doc.id,
    text: doc.gold.text,
    spans: spanRows(doc.gold.spans.map((s) => [s.label, s.start, s.end] as const)),
  }));
  sortedDocs.forEach((doc, i) => {
    const domain = sliceValue(doc.domain);
    const variant = sliceValue(doc.variant);
    if (domain !== null || variant !== null) {
      (canonical[i] as Record<string, unknown>).metadata = { domain, variant };
    }
  });
  for (const dimension of ["domain", "variant"] as const) {
    if (new Set(documents.map((doc) => doc[dimension])).size > 128) {
      throw new ValueError("evaluation exceeds 128 categories per slice dimension");
    }
  }
  const datasetHash = createHash("sha256").update(canonicalJson(canonical), "utf8").digest("hex");
  const metrics = new BenchmarkReport({ matchMode: "strict" });
  const rows: DocumentRow[] = [];
  const outputRows: OutputDocumentRow[] = [];
  for (const doc of sortedDocs) {
    const gold: GoldDocument = {
      text: doc.gold.text,
      spans: doc.gold.spans.filter((s) => active.has(s.label)),
    };
    let predictions: DetectionResult[];
    if (outputMode !== null) {
      const result = new Anonymizer(
        outputMode,
        outputStrategy,
        null,
        active,
        null,
        null,
        "union",
        null,
        exclusions,
        { strategies: overrides },
      ).process(doc.gold.text);
      predictions = result.detections.map((record) => record.detection);
      outputRows.push({ id: doc.id, spans: assessOutput(gold, result, outputStrategy) });
    } else {
      predictions = detectAll(doc.gold.text, active, null, { personExclusions: exclusions });
    }
    const perLabel = scoreDocument(gold, predictions, "strict");
    for (const [label, score] of perLabel) {
      const total = setDefault(metrics, label);
      total.tp += score.tp;
      total.fp += score.fp;
      total.fn += score.fn;
    }
    const expected = toSpanSet(gold.spans.map((s) => [s.label, s.start, s.end] as const));
    const predicted = toSpanSet(predictions.map((p) => [p.label, p.start, p.end] as const));
    rows.push({
      id: doc.id,
      characters: doc.gold.text.length,
      gold: spanRows(expected.values()),
      predictions: spanRows(predicted.values()),
      false_negatives: spanRows(minus(expected, predicted).values()),
      false_positives: spanRows(minus(predicted, expected).values()),
    });
  }
  const report: EvaluationReport = {
    schema_version: REPORT_SCHEMA_VERSION,
    package_version: VERSION,
    generated_at: pyIsoUtcNow(),
    evaluation_date: localIsoDate(),
    dataset_sha256: datasetHash,
    match_mode: "strict",
    evaluated_labels: [...active].sort(codePointCompare),
    person_exclusions_sha256: createHash("sha256")
      .update(asciiJsonStringList(exclusions), "utf8")
      .digest("hex"),
    document_count: rows.length,
    documents_with_misses: rows.filter((row) => row.false_negatives.length > 0).length,
    micro: counts(metrics.micro()),
    per_label: perLabelCounts(metrics),
    documents: rows,
  };
  if (outputMode !== null) {
    const outputReport = summarizeOutput(outputRows, outputMode, outputStrategy);
    outputReport.strategies = overrides;
    report.output_evaluation = outputReport;
  }
  const slices = sliceReports(documents, rows, outputRows, outputMode, outputStrategy, overrides);
  if (Object.keys(slices).length > 0) report.slices = slices;
  return report;
}

export interface ReportComparison {
  baseline_version: unknown;
  scope: "detector_spans_only";
  counts: Record<string, number>;
  new_false_negatives: (SpanRow & { id: string })[];
  resolved_false_negatives: (SpanRow & { id: string })[];
  new_false_positives: (SpanRow & { id: string })[];
  resolved_false_positives: (SpanRow & { id: string })[];
  output?: OutputComparison;
}

/** 같은 코퍼스·라벨 범위·채점 계약에서 span 을 비교. */
export function compareReports(
  current: Record<string, unknown>,
  baseline: Record<string, unknown>,
): ReportComparison {
  for (const key of ["schema_version", "dataset_sha256", "match_mode", "evaluated_labels"]) {
    if (!Object.hasOwn(baseline, key) || !pyEqual(current[key], baseline[key])) {
      throw new ValueError(`baseline ${key} differs; compare the same corpus and label scope`);
    }
  }
  if (!pyEqual(current.dataset_adapter, baseline.dataset_adapter)) {
    throw new ValueError("baseline external dataset mapping or source differs");
  }
  if (!pyEqual(current.provenance, baseline.provenance)) {
    throw new ValueError("baseline dataset provenance differs");
  }
  const currentDocs = current.documents as DocumentRow[];
  const oldDocs = baseline.documents;
  if (!Array.isArray(oldDocs) || oldDocs.length !== currentDocs.length) {
    throw new ValueError("baseline document set differs");
  }
  if ((oldDocs as unknown[]).some((row) => !isRecord(row) || typeof row.id !== "string")) {
    throw new ValueError("invalid baseline document");
  }
  const byId = new Map<string, Record<string, unknown>>();
  for (const row of oldDocs as Record<string, unknown>[]) byId.set(row.id as string, row);
  if (byId.size !== oldDocs.length) throw new ValueError("duplicate baseline document id");
  const changes = {
    new_false_negatives: [] as (SpanRow & { id: string })[],
    resolved_false_negatives: [] as (SpanRow & { id: string })[],
    new_false_positives: [] as (SpanRow & { id: string })[],
    resolved_false_positives: [] as (SpanRow & { id: string })[],
  };
  const active = new Set(current.evaluated_labels as string[]);
  for (const row of currentDocs) {
    const old = byId.get(row.id);
    if (
      old === undefined ||
      !pyEqual(old.characters, row.characters) ||
      !pyEqual(old.gold, row.gold)
    ) {
      throw new ValueError("baseline annotations differ");
    }
    const length = row.characters;
    const gold = spans(row.gold, length, active);
    const previous = spans(old.predictions, length, active, MAX_DOCUMENT_CHARS);
    const predicted = spans(row.predictions, length, active, MAX_DOCUMENT_CHARS);
    const oldFn = minus(gold, previous);
    const newFn = minus(gold, predicted);
    const oldFp = minus(previous, gold);
    const newFp = minus(predicted, gold);
    const pairs: [keyof typeof changes, SpanSet][] = [
      ["new_false_negatives", minus(newFn, oldFn)],
      ["resolved_false_negatives", minus(oldFn, newFn)],
      ["new_false_positives", minus(newFp, oldFp)],
      ["resolved_false_positives", minus(oldFp, newFp)],
    ];
    for (const [key, set] of pairs) {
      changes[key].push(...spanRows(set.values()).map((span) => ({ id: row.id, ...span })));
    }
  }
  const countsOut: Record<string, number> = {};
  for (const [key, list] of Object.entries(changes)) countsOut[key] = list.length;
  const comparison: ReportComparison = {
    baseline_version: Object.hasOwn(baseline, "package_version") ? baseline.package_version : null,
    scope: "detector_spans_only",
    counts: countsOut,
    ...changes,
  };
  if (Object.hasOwn(current, "output_evaluation") && Object.hasOwn(baseline, "output_evaluation")) {
    comparison.output = compareOutputReports(current, baseline);
  }
  return comparison;
}

export function formatSummary(report: EvaluationReport): string {
  const lines = [
    `Documents: ${report.document_count} | matching: strict character spans`,
    "Label                 TP     FP     FN   Precision  Recall",
  ];
  for (const [label, values] of Object.entries(report.per_label)) {
    const p = values.precision === null ? "n/a" : pyFormatFixed(values.precision, 3);
    const r = values.recall === null ? "n/a" : pyFormatFixed(values.recall, 3);
    lines.push(
      `${padRight(label, 20)} ${padLeft(String(values.tp), 5)} ${padLeft(String(values.fp), 6)} ` +
        `${padLeft(String(values.fn), 6)} ${padLeft(p, 10)} ${padLeft(r, 7)}`,
    );
  }
  lines.push(`Documents with unmatched gold spans: ${report.documents_with_misses}`);
  if (report.output_evaluation !== undefined) {
    const output = report.output_evaluation;
    lines.push(`Output evaluation: ${output.mode} / ${output.strategy} (annotated spans only)`);
    for (const [state, count] of Object.entries(output.counts)) lines.push(`${state}: ${count}`);
  }
  if (report.comparison !== undefined) {
    lines.push(
      "Baseline comparison: detector spans; output retention compared separately when available",
    );
    for (const [key, count] of Object.entries(report.comparison.counts)) {
      lines.push(`${key}: ${count}`);
    }
    if (report.comparison.output !== undefined) {
      lines.push(
        `New not-fully-replaced spans: ${report.comparison.output.new_not_fully_replaced}`,
      );
    }
  }
  return lines.join("\n");
}

/** Python ``ko_pii.cli._assignments`` — ``KEY=VALUE`` (마지막 ``=`` 기준) 고유 쌍. */
function assignments(items: readonly string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of items) {
    const at = item.lastIndexOf("=");
    const key = at < 0 ? "" : item.slice(0, at);
    const value = at < 0 ? "" : item.slice(at + 1);
    if (at < 0 || !value || Object.hasOwn(result, key)) {
      throw new ValueError("assignments must be unique KEY=VALUE pairs");
    }
    result[key] = value;
  }
  return result;
}

/** Python ``Path(p).resolve()`` (strict=False) — 존재하는 가장 긴 접두를 realpath 로. */
function resolvePath(p: string): string {
  let current = path.resolve(p);
  const rest: string[] = [];
  for (;;) {
    try {
      return path.join(fs.realpathSync(current), ...rest);
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return path.join(current, ...rest);
      rest.unshift(path.basename(current));
      current = parent;
    }
  }
}

function sameFile(a: string, b: string): boolean {
  const x = fs.statSync(a);
  const y = fs.statSync(b);
  return x.dev === y.dev && x.ino === y.ino;
}

/** 보고서의 precision/recall/f1 (항상 Python float) 중 정숫값 줄. */
const RATIO_INT = /^(\s*"(?:precision|recall|f1)": )(-?\d+)(,?)$/gm;

/** ``ko-pii-evaluate`` CLI (Python ``ko_pii.eval.domain.main``). 반환값은 종료 코드. */
export function main(argv?: string[]): number {
  const p = new ArgumentParser(
    "ko-pii-evaluate",
    "Evaluate labeled local JSONL documents and compare detector regressions.",
  );
  p.addArgument({ dest: "dataset", help: "UTF-8 JSONL containing id, text and spans" });
  p.addArgument({
    dest: "dataset_format",
    optionStrings: ["--dataset-format"],
    choices: ["ko-pii", "k-pii-bench"],
    def: "ko-pii",
  });
  p.addArgument({
    dest: "provenance",
    optionStrings: ["--provenance"],
    help: "Local revision/split manifest with required source SHA-256",
  });
  p.addArgument({
    dest: "output",
    optionStrings: ["--output"],
    required: true,
    help: "JSON report (no source text or span values)",
  });
  p.addArgument({
    dest: "labels",
    optionStrings: ["--labels"],
    help: "Comma-separated labels; annotate all occurrences of these labels",
  });
  p.addArgument({ dest: "person_exclusions_file", optionStrings: ["--person-exclusions-file"] });
  p.addArgument({
    dest: "baseline",
    optionStrings: ["--baseline"],
    help: "Earlier report for the same corpus and label scope",
  });
  p.addArgument({
    dest: "fail_on_new_misses",
    optionStrings: ["--fail-on-new-misses"],
    isFlag: true,
    def: false,
  });
  p.addArgument({
    dest: "fail_on_new_false_positives",
    optionStrings: ["--fail-on-new-false-positives"],
    isFlag: true,
    def: false,
  });
  p.addArgument({
    dest: "output_mode",
    optionStrings: ["--output-mode"],
    choices: Object.values(ProcessingMode),
  });
  p.addArgument({
    dest: "output_strategy",
    optionStrings: ["--output-strategy"],
    choices: ["redact", "tokenize", "asterisk", "partial", "hashed", "fpe"],
  });
  p.addArgument({
    dest: "fail_on_retained",
    optionStrings: ["--fail-on-retained"],
    isFlag: true,
    def: false,
    help: "Fail if any gold span is not fully replaced, including intentional partial masking",
  });
  p.addArgument({
    dest: "fail_on_new_retained",
    optionStrings: ["--fail-on-new-retained"],
    isFlag: true,
    def: false,
    help: "Fail if a previously fully replaced gold span is no longer fully replaced",
  });
  p.addArgument({
    dest: "output_strategy_for",
    optionStrings: ["--output-strategy-for"],
    append: true,
    def: [],
    metavar: "LABEL=STRATEGY",
  });

  try {
    const args = p.parseArgs(argv ?? process.argv.slice(2));
    const dataset = args.dataset as string;
    const baselinePath = args.baseline as string | null;
    const provenancePath = args.provenance as string | null;
    const exclusionsPath = args.person_exclusions_file as string | null;
    const outputMode = args.output_mode as ProcessingMode | null;
    const outputStrategy = args.output_strategy as string | null;
    if ((args.fail_on_new_misses || args.fail_on_new_false_positives) && !baselinePath) {
      p.errorExit("regression exit-code options require --baseline");
    }
    if ((args.fail_on_retained || outputStrategy) && !outputMode) {
      p.errorExit("output evaluation options require --output-mode");
    }
    const strategyFor = args.output_strategy_for as string[];
    if (strategyFor.length > 0 && !outputMode) {
      p.errorExit("--output-strategy-for requires --output-mode");
    }
    if (args.fail_on_new_retained && (!baselinePath || !outputMode)) {
      p.errorExit("--fail-on-new-retained requires --baseline and --output-mode");
    }
    const output = resolvePath(args.output as string);
    for (const source of [dataset, baselinePath, exclusionsPath, provenancePath]) {
      if (
        source &&
        (output === resolvePath(source) ||
          (fs.existsSync(output) && fs.existsSync(source) && sameFile(output, source)))
      ) {
        p.errorExit("output must not overwrite the dataset, baseline or exclusions");
      }
    }
    let report: EvaluationReport;
    try {
      let exclusions: string[] = [];
      if (exclusionsPath) {
        exclusions = pySplitlines(readJsonFile(exclusionsPath, 1024 * 1024))
          .filter((line) => pyStrip(line) && !pyStrip(line).startsWith("#"))
          .map((line) => pyStrip(line));
      }
      let labels: string[] | null =
        args.labels === null ? null : (args.labels as string).split(",").map((s) => pyStrip(s));
      const sourceText = readJsonFile(dataset, MAX_DATASET_BYTES);
      const provenance = provenancePath
        ? validateProvenance(loadsJson(readJsonFile(provenancePath, 4096)), sourceText)
        : null;
      let metadata: Record<string, unknown> | null = null;
      let documents: LabeledDocument[];
      if (args.dataset_format === "k-pii-bench") {
        const loaded = loadKPiiBenchText(sourceText);
        documents = loaded[0];
        metadata = loaded[1];
        const supported = new Set(
          Object.values(K_PII_LABELS).filter((label): label is string => label !== null),
        );
        if (labels === null) {
          labels = [...supported].sort(codePointCompare);
        } else if (!labels.every((label) => supported.has(label))) {
          throw new ValueError(
            "selected labels are not covered by the external annotation mapping",
          );
        }
      } else {
        documents = loadDatasetText(sourceText);
      }
      report = evaluate(documents, {
        labels,
        personExclusions: exclusions,
        outputMode,
        outputStrategy: outputStrategy || "redact",
        outputStrategies: assignments(strategyFor),
      });
      if (metadata !== null) report.dataset_adapter = metadata;
      if (provenance !== null) report.provenance = provenance;
      if (baselinePath) {
        const baseline = loadsJson(readJsonFile(baselinePath, MAX_REPORT_BYTES), {
          limits: new StructuredLimits({
            maxChars: MAX_REPORT_BYTES,
            maxStringChars: MAX_REPORT_BYTES,
            maxNodes: MAX_REPORT_BYTES,
          }),
        });
        if (!isRecord(baseline)) throw new ValueError("baseline must be a JSON object");
        report.comparison = compareReports(report, baseline);
        if (args.fail_on_new_retained && report.comparison.output === undefined) {
          throw new ValueError("baseline requires output evaluation for retention comparison");
        }
      }
      // JS 는 float 1.0 과 int 1 을 구분하지 못한다 — 비율 필드만 Python float 표기로 복원.
      const serialized = `${pyJsonDumps(report, 2).replace(RATIO_INT, "$1$2.0$3")}\n`;
      if (Buffer.byteLength(serialized, "utf8") > MAX_REPORT_BYTES) {
        throw new ValueError("report exceeds 64 MiB; split the evaluation dataset");
      }
      writeTextAtomic(output, serialized);
    } catch (e) {
      // 경로가 식별자를 담을 수 있으므로 파일시스템 예외는 되울리지 않는다.
      if (isOsError(e) || e instanceof ValueError) {
        const message = isOsError(e) ? "file could not be read or written" : (e as Error).message;
        process.stderr.write(`ko-pii-evaluate: ${message}\n`);
        return 2;
      }
      throw e;
    }
    process.stdout.write(`${formatSummary(report)}\n`);
    const changeCounts = report.comparison?.counts ?? {};
    if (args.fail_on_new_retained && report.comparison?.output?.new_not_fully_replaced) return 1;
    if (args.fail_on_retained && report.output_evaluation?.not_fully_replaced) return 1;
    if (args.fail_on_new_misses && changeCounts.new_false_negatives) return 1;
    if (args.fail_on_new_false_positives && changeCounts.new_false_positives) return 1;
    return 0;
  } catch (e) {
    if (e instanceof ParseExit) {
      (e.stream === "stdout" ? process.stdout : process.stderr).write(e.text);
      return e.code;
    }
    throw e;
  }
}
