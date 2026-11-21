/**
 * 두 로컬 코어 정책의 값 없는 비교 — 양쪽 모두 새 메모리 Vault 를 쓴다.
 * Python ``ko_pii.policy_preview`` 대응 (``ko-pii-compare-policies`` = ``main``).
 *
 * TS 표현 차이: ``source_span`` 은 TS 오프셋 정책대로 UTF-16 코드 유닛이다. ``offset_unit``
 * 문자열은 Python 계약과의 호환을 위해 원본 값을 유지한다 — 아스트랄 문자가 없으면 수치가
 * 동일하다 (PORTING.md). 입력 문자 수 상한은 Python 처럼 코드 포인트로 센다.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { type AnonymizationResult, Anonymizer } from "./anonymizer.js";
import { ArgumentParser, ParseExit } from "./cli/argparse.js";
import { ValueError } from "./core/errors.js";
import type { ProcessingMode } from "./core/modes.js";
import { codePointLength } from "./core/strUtils.js";
import { assessOutput } from "./eval/output.js";
import type { GoldDocument } from "./eval/types.js";
import { rulesFromJson } from "./fieldRules.js";
import { writeTextAtomic } from "./io/atomic.js";
import { recordEntries } from "./io/recordOrder.js";
import { codePointCompare } from "./policy.js";
import { coreSettings, type PolicyProfile, structuredSettings } from "./profile.js";
import { type ExplanationFinding, explain } from "./reporting/explanation.js";
import { anonymizeJson, loadsJson, StructuredLimits, validateStructured } from "./structured.js";
import { pyJsonDumps } from "./vault/reversible.js";

type Settings = Record<string, unknown>;
export type PolicyInput = Settings | PolicyProfile;

const JSON_LIMITS = new StructuredLimits({
  maxNodes: 10_000,
  maxChars: 100_000,
  maxStringChars: 100_000,
});

/** Python ``json.dumps(ensure_ascii=False, sort_keys=True, separators=(",", ":"))``. */
function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort(codePointCompare);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

function digest(config: Settings): string {
  return createHash("sha256").update(canonicalJson(config), "utf8").digest("hex");
}

function coreAnonymizer(config: Settings): Anonymizer {
  return new Anonymizer(
    config.mode as ProcessingMode,
    config.strategy as string,
    null,
    config.include as string[] | null,
    config.exclude as string[] | null,
    null,
    "union",
    null,
    config.person_exclusions as string[],
    { strategies: config.strategies as Record<string, string> },
  );
}

/** Python ``dict(sorted(Counter(values).items()))``. */
function sortedCounts(values: Iterable<string>): Record<string, number> {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return sortedRecord(counts);
}

function sortedRecord(counts: ReadonlyMap<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const key of [...counts.keys()].sort(codePointCompare)) {
    Object.defineProperty(out, key, {
      value: counts.get(key),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

interface SpanState {
  detected: boolean;
  action: string | null;
  requested_strategy: string | null;
  applied_strategy: string | null;
  output_state: string;
}

function sameState(a: SpanState, b: SpanState): boolean {
  return (
    a.detected === b.detected &&
    a.action === b.action &&
    a.requested_strategy === b.requested_strategy &&
    a.applied_strategy === b.applied_strategy &&
    a.output_state === b.output_state
  );
}

interface Comparison {
  observed_span_count: number;
  changed_span_count: number;
  changed_by_label: Record<string, number>;
  before_output_counts: Record<string, number>;
  after_output_counts: Record<string, number>;
  changes: Record<string, unknown>[];
}

function compareResults(text: string, results: AnonymizationResult[]): Comparison {
  const unique = new Map<string, [string, number, number]>();
  for (const result of results) {
    for (const r of result.detections) {
      const d = r.detection;
      unique.set(JSON.stringify([d.label, d.start, d.end]), [d.label, d.start, d.end]);
    }
  }
  // Python sorted(tuple): 라벨(코드 포인트) → start → end
  const spans = [...unique.values()].sort(
    (a, b) => codePointCompare(a[0], b[0]) || a[1] - b[1] || a[2] - b[2],
  );
  if (spans.length > 2_000) throw new ValueError("policy preview exceeds 2000 observed spans");
  const observed: GoldDocument = {
    text,
    spans: spans.map(([label, start, end]) => ({
      label,
      start,
      end,
      text: text.slice(start, end),
    })),
  };
  const keyOf = (label: string, start: number, end: number): string =>
    JSON.stringify([label, start, end]);

  const states = (result: AnonymizationResult): Map<string, SpanState> => {
    const records = new Map<string, ExplanationFinding>();
    for (const row of explain(result).findings as ExplanationFinding[]) {
      records.set(keyOf(row.label, row.source_span[0], row.source_span[1]), row);
    }
    const indexed = new Map<string, SpanState>();
    for (const row of assessOutput(observed, result, result.summary.strategy as string)) {
      const key = keyOf(row.label, row.start, row.end);
      const record = records.get(key);
      indexed.set(key, {
        detected: record !== undefined,
        action: record ? record.action : null,
        requested_strategy: record ? record.requested_strategy : null,
        applied_strategy: record ? record.applied_strategy : null,
        output_state: row.state === "missed" ? "not_detected" : row.state,
      });
    }
    return indexed;
  };

  const [old, now] = results.map(states) as [Map<string, SpanState>, Map<string, SpanState>];
  const changes: Record<string, unknown>[] = [];
  for (const [label, start, end] of spans) {
    const key = keyOf(label, start, end);
    const before = old.get(key) as SpanState;
    const after = now.get(key) as SpanState;
    if (!sameState(before, after)) {
      changes.push({ label, source_span: [start, end], before, after });
    }
  }
  return {
    observed_span_count: spans.length,
    changed_span_count: changes.length,
    changed_by_label: sortedCounts(changes.map((row) => row.label as string)),
    before_output_counts: sortedCounts([...old.values()].map((row) => row.output_state)),
    after_output_counts: sortedCounts([...now.values()].map((row) => row.output_state)),
    changes,
  };
}

export interface ComparePoliciesOptions {
  before: PolicyInput;
  after: PolicyInput;
}

/** 관측 가능한 처리를 비교한다 — 골드 정확도나 전체 텍스트 안전성이 아니다.
 *
 * 호출자 지정 Anonymizer·Vault·보조 검출기는 받지 않는다. 로컬 코어 설정만 허용한다.
 * 원문·치환 값은 반환하지 않는다.
 */
export function comparePolicies(
  text: string,
  options: ComparePoliciesOptions,
): Record<string, unknown> {
  if (typeof text !== "string" || codePointLength(text) > 100_000) {
    throw new ValueError("policy preview requires text of at most 100000 characters");
  }
  const configs = [coreSettings(options.before), coreSettings(options.after)] as [
    Settings,
    Settings,
  ];
  const results = configs.map((config) => coreAnonymizer(config).process(text));
  return {
    schema_version: 1,
    contract: "ko-pii-policy-preview-v1",
    scope: "union_of_observed_spans_not_gold",
    input_empty: !text,
    offset_unit: "python_code_points",
    whole_text_safety_assessed: false,
    before_policy_sha256: digest(configs[0]),
    after_policy_sha256: digest(configs[1]),
    ...compareResults(text, results),
  };
}

export interface CompareJsonPoliciesOptions extends ComparePoliciesOptions {
  /** 잠재적으로 민감한 JSON 키 경로를 포함 — 공개 보고서에 부적합. */
  includePaths?: boolean;
}

function isPyInt(value: unknown): value is number | bigint {
  return typeof value === "bigint" || (typeof value === "number" && Number.isInteger(value));
}

function pyIntStr(value: number | bigint): string {
  if (typeof value === "bigint" || Number.isSafeInteger(value)) return value.toString();
  return BigInt(value).toString();
}

/** 상한이 있는 JSON 값을 독립된 로컬 코어 정책으로 비교한다.
 *
 * 필드 규칙은 JSON 설정 형태를 쓴다 (null 경로 세그먼트 = EACH). 원문 값·치환 값·키는 기본적으로
 * 반환하지 않는다. 명시적 ``includePaths`` 는 JSON 키를 노출하며 공개 보고서에 부적합하다.
 */
export function compareJsonPolicies(
  data: unknown,
  options: CompareJsonPoliciesOptions,
): Record<string, unknown> {
  const includePaths = options.includePaths ?? false;
  if (typeof includePaths !== "boolean") throw new ValueError("include_paths must be a boolean");
  validateStructured(data, {}, JSON_LIMITS);
  const configs = [structuredSettings(options.before), structuredSettings(options.after)] as [
    Settings,
    Settings,
  ];
  const sources: [string, string][] = [];

  const collect = (value: unknown, at: string): void => {
    if (typeof value === "string" || isPyInt(value)) {
      if (sources.length >= 1000) {
        throw new ValueError("structured policy preview exceeds 1000 string/integer fields");
      }
      sources.push([at, typeof value === "string" ? value : pyIntStr(value)]);
    } else if (Array.isArray(value)) {
      value.forEach((child: unknown, index) => {
        collect(child, `${at}/${index}`);
      });
    } else if (value !== null && typeof value === "object") {
      for (const [key, child] of recordEntries(value as Record<string, unknown>)) {
        collect(child, `${at}/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`);
      }
    }
  };

  collect(data, "");
  const processed = configs.map((config) => {
    const result = anonymizeJson(data, {
      anonymizer: coreAnonymizer(config),
      limits: JSON_LIMITS,
      fieldLabels: config.field_labels as Record<string, string>,
      fieldRules: rulesFromJson(config.field_rules),
      fieldPersonExclusions: config.field_person_exclusions as Record<string, string[]>,
    });
    return new Map(result.fields.map((field) => [field.path, field.result]));
  }) as [Map<string, AnonymizationResult>, Map<string, AnonymizationResult>];

  const fields: Record<string, unknown>[] = [];
  const changes: Record<string, unknown>[] = [];
  let observed = 0;
  const oldCounts = new Map<string, number>();
  const newCounts = new Map<string, number>();
  const addCounts = (target: Map<string, number>, counts: Record<string, number>): void => {
    for (const [k, n] of Object.entries(counts)) target.set(k, (target.get(k) ?? 0) + n);
  };
  for (const [index, [at, text]] of sources.entries()) {
    if (!processed.some((side) => side.has(at))) continue; // 단언 없는 일반 정수는 검사하지 않는다.
    const results = configs.map(
      (config, i) =>
        processed[i]?.get(at) ?? {
          text,
          detections: [],
          vault: null,
          summary: { strategy: config.strategy },
          combined_risk: null,
          substitutions: [],
          overlap_trace: null,
        },
    );
    const { changes: fieldChanges, ...comparison } = compareResults(text, results);
    observed += comparison.observed_span_count;
    if (observed > 2000) {
      throw new ValueError("structured policy preview exceeds 2000 observed spans");
    }
    const identity: Record<string, unknown> = { field_index: index };
    if (includePaths) identity.path = at;
    for (const change of fieldChanges) changes.push({ ...identity, ...change });
    fields.push({
      ...identity,
      before_screened: processed[0].has(at),
      after_screened: processed[1].has(at),
      ...comparison,
    });
    addCounts(oldCounts, comparison.before_output_counts);
    addCounts(newCounts, comparison.after_output_counts);
  }
  return {
    schema_version: 1,
    contract: "ko-pii-structured-policy-preview-v1",
    scope: "union_of_observed_spans_not_gold",
    whole_text_safety_assessed: false,
    keys_screened: false,
    unasserted_numbers_screened: false,
    paths_included: includePaths,
    offset_unit: "python_code_points_within_field",
    field_index_scope: "string_and_integer_leaves_in_input_order",
    before_policy_sha256: digest(configs[0]),
    after_policy_sha256: digest(configs[1]),
    compared_field_count: fields.length,
    observed_span_count: observed,
    changed_span_count: changes.length,
    changed_by_label: sortedCounts(changes.map((row) => row.label as string)),
    before_output_counts: sortedRecord(oldCounts),
    after_output_counts: sortedRecord(newCounts),
    fields,
    changes,
  };
}

// ───────────────────────────────────────────── CLI

const MAX_FILE_BYTES = 400_000;
const MAX_TEXT_CHARS = 100_000;

/** Python ``cli._read_structured_input`` (FileReadPolicy(max_file_bytes=400_000, max_text_chars=100_000)). */
function readStructuredInput(source: string, readStdin: () => Buffer): string {
  if (source === "-") {
    // Python sys.stdin.read(n): utf-8 디코딩 (BOM 은 벗기지 않는다).
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readStdin());
    if (
      codePointLength(text) > MAX_TEXT_CHARS ||
      Buffer.byteLength(text, "utf8") > MAX_FILE_BYTES
    ) {
      throw new ValueError("standard input exceeds configured limits");
    }
    return text;
  }
  const fd = fs.openSync(source, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  let raw: Buffer;
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size > MAX_FILE_BYTES) {
      throw new ValueError("JSON input must be a bounded regular file");
    }
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const n = fs.readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
    }
    raw = buffer.subarray(0, length);
  } finally {
    fs.closeSync(fd);
  }
  if (raw.length > MAX_FILE_BYTES) throw new ValueError("JSON input exceeds byte limits");
  let text: string;
  try {
    // utf-8-sig: 선행 BOM 하나를 벗긴다, 잘못된 바이트는 오류.
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    throw new ValueError("'utf-8' codec can't decode input bytes");
  }
  if (codePointLength(text) > MAX_TEXT_CHARS) {
    throw new ValueError("JSON input exceeds character limits");
  }
  return text;
}

/** Python ``Path(p).resolve()`` (strict=False) — 존재하는 가장 긴 접두어까지 symlink 를 푼다. */
function resolvePath(p: string): string {
  const absolute = path.resolve(p);
  const tail: string[] = [];
  let head = absolute;
  for (;;) {
    try {
      return path.join(fs.realpathSync(head), ...tail.reverse());
    } catch {
      const parent = path.dirname(head);
      if (parent === head) return absolute;
      tail.push(path.basename(head));
      head = parent;
    }
  }
}

function sameFile(a: string, b: string): boolean {
  const x = fs.statSync(a);
  const y = fs.statSync(b);
  return x.dev === y.dev && x.ino === y.ino;
}

function readAllStdin(): Buffer {
  const chunks: Buffer[] = [];
  const buffer = Buffer.alloc(65_536);
  let total = 0;
  for (;;) {
    let n: number;
    try {
      n = fs.readSync(0, buffer, 0, buffer.length, null);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EAGAIN") continue;
      if ((e as NodeJS.ErrnoException).code === "EOF") break;
      throw e;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buffer.subarray(0, n)));
    total += n;
    // 상한(문자 수 상한 × UTF-8 최대 4바이트)을 넘으면 더 읽지 않는다 — 어차피 거부된다.
    if (total > MAX_FILE_BYTES + 4) break;
  }
  return Buffer.concat(chunks);
}

export interface PolicyPreviewIo {
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  /** 표준 입력 전체 바이트 (테스트 주입용). */
  readStdin?: () => Buffer;
}

/** ``ko-pii-compare-policies`` — Python ``policy_preview.main`` 대응. 종료 코드를 반환한다. */
export function main(argv: string[] = process.argv.slice(2), io: PolicyPreviewIo = {}): number {
  const out = io.stdout ?? ((text: string) => process.stdout.write(text));
  const err = io.stderr ?? ((text: string) => process.stderr.write(text));
  const parser = new ArgumentParser(
    "ko-pii-compare-policies",
    "Preview two core policies on bounded UTF-8 text or JSON.",
  );
  parser.addArgument({ dest: "input" });
  parser.addArgument({
    dest: "before",
    optionStrings: ["--before"],
    required: true,
    help: "JSON policy settings",
  });
  parser.addArgument({
    dest: "after",
    optionStrings: ["--after"],
    required: true,
    help: "JSON policy settings",
  });
  parser.addArgument({
    dest: "output",
    optionStrings: ["--output"],
    help: "Value-free JSON report (default: stdout)",
  });
  parser.addArgument({
    dest: "format",
    optionStrings: ["--format"],
    choices: ["text", "json"],
    def: "text",
    help: "Input format; JSON enables field-specific policy settings.",
  });
  parser.addArgument({
    dest: "include_paths",
    optionStrings: ["--include-paths"],
    isFlag: true,
    help: "Include potentially sensitive JSON field paths (JSON mode only).",
  });
  let args: Record<string, unknown>;
  try {
    args = parser.parseArgs(argv);
    if (args.include_paths && args.format !== "json") {
      parser.errorExit("--include-paths requires --format json");
    }
  } catch (e) {
    if (e instanceof ParseExit) {
      (e.stream === "stdout" ? out : err)(e.text);
      return e.code;
    }
    throw e;
  }
  const input = args.input as string;
  const before = args.before as string;
  const after = args.after as string;
  const output = (args.output as string | null) ?? null;
  try {
    if (before === "-" || after === "-") {
      throw new ValueError("policy settings require distinct files, not stdin");
    }
    if (output) {
      for (const source of [input, before, after]) {
        if (
          resolvePath(source) === resolvePath(output) ||
          (fs.existsSync(source) && fs.existsSync(output) && sameFile(source, output))
        ) {
          throw new ValueError("output must not overwrite source or configuration");
        }
      }
    }
    const readStdin = io.readStdin ?? readAllStdin;
    const text = readStructuredInput(input, readStdin);
    const beforeSettings = loadsJson(readStructuredInput(before, readStdin)) as Settings;
    const afterSettings = loadsJson(readStructuredInput(after, readStdin)) as Settings;
    const report =
      args.format === "json"
        ? compareJsonPolicies(loadsJson(text, { limits: JSON_LIMITS }), {
            before: beforeSettings,
            after: afterSettings,
            includePaths: Boolean(args.include_paths),
          })
        : comparePolicies(text, { before: beforeSettings, after: afterSettings });
    const rendered = `${pyJsonDumps(report, 2)}\n`;
    if (output) writeTextAtomic(output, rendered);
    else out(rendered);
    return 0;
  } catch (e) {
    // Python: (ValueError, TypeError, OSError). TS 에서는 Node 시스템 오류·원자적 쓰기의
    // 일반 Error 도 같은 계열이라 원문 없는 고정 문구로 정리한다.
    if (e instanceof Error) {
      err(
        "policy preview failed: check bounded UTF-8 input, core settings and distinct output path\n",
      );
      return 1;
    }
    throw e;
  }
}
