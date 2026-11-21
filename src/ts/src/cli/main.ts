/**
 * CLI — ko-pii input.txt --mode strict --vault vault.json --strategy tokenize.
 *
 * 표준 입력으로 받으려면 input 자리에 ``-`` 사용. 결과는 stdout 으로 (치환된 본문),
 * 요약/검토는 stderr 로 출력한다. Vault 저장 경로가 지정되면 Vault JSON 도 함께 기록.
 *
 * Python ko_pii.cli (v1.27) 1:1 포트. argparse 는 서브셋 재구현(`./argparse.js`) — npm 의존성
 * 추가로 코어 "의존성 0" 약속이 깨지지 않도록. 종료 코드는 main() 이 반환하고 process.exit 는
 * bin 래퍼가 호출한다.
 *
 * 실패 경계: Python 이 잡는 (OSError, ValueError, ImportError) 는 `ko-pii: <code>: <stage> could
 * not be completed` 한 줄(또는 --json-summary 의 실패 JSON)로 보고하고 원문을 담을 수 있는 예외
 * 메시지는 내보내지 않는다. 설정 단계 실패는 2, 그 밖은 1.
 */

import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from "node:fs";
import { Anonymizer } from "../anonymizer.js";
import {
  isOsError,
  pathExists,
  processPaths,
  pyExceptionName,
  pyRealpath,
  sameFile,
} from "../batch.js";
import { ValueError } from "../core/errors.js";
import { ProcessingMode } from "../core/modes.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { type FieldRule, rulesFromJson } from "../fieldRules.js";
import { writeTextAtomic } from "../io/atomic.js";
import { BoundedReadError, FileReadPolicy } from "../io/bounded.js";
import type { ExtractionCoverage } from "../io/coverage.js";
import { defaultReadPolicy, readTextIsolated } from "../io/isolated.js";
import { validateLabelFilter } from "../labels.js";
import { validateStrategies } from "../policy.js";
import { PolicyProfile } from "../profile.js";
import { generateCertificate } from "../reporting/certificate.js";
import { explain } from "../reporting/explanation.js";
import { formatSummaryText } from "../reporting/summary.js";
import {
  anonymizeJson,
  anonymizeJsonl,
  fieldExclusions,
  loadsJson,
  StructuredLimits,
  type StructuredResult,
} from "../structured.js";
import { AuditLog } from "../vault/audit.js";
import { isEncryptedFile, loadEncrypted, saveEncrypted } from "../vault/encrypted.js";
import { pyStrip, ReversibleVault } from "../vault/reversible.js";
import { VERSION } from "../version.js";
import { type ArgSpec, ArgumentParser, ParseExit } from "./argparse.js";
import { formatLabelsTable } from "./labelsTable.js";
import { promptPassword } from "./prompt.js";
import { numberShadow, pyDumps } from "./pyJson.js";

/** Python ``ImportError`` 대응 (선택 의존성 부재). */
class ImportError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "ImportError";
  }
}

/** 테스트에서 교체할 수 있는 입출력 지점 (Python monkeypatch 대상 대응). */
export const cliHooks = {
  /** Python ``getpass.getpass``. */
  promptPassword: (prompt: string): string => promptPassword(prompt),
  /** 표준 입력 원시 바이트 — 최대 ``limit`` 바이트까지만 읽는다 (``null`` = 끝까지). */
  readStdin: (limit: number): Buffer => readStdinBytes(limit),
  /** Python ``_save_vault`` 의 저장 단계 (실패 주입용). */
  saveVault: (args: CliNamespace, vault: ReversibleVault): void => saveVault(args, vault),
  /** Python ``AuditLog(path)`` 생성 (실패 주입용). */
  createAudit: (path: string): AuditLog => new AuditLog(path),
  /** Python ``_write_output``. */
  writeOutput: (path: string | null, text: string): void => writeOutput(path, text),
};

export interface CliNamespace {
  input: string | null;
  labels: boolean;
  mode: string | null;
  strategy: string | null;
  vault: string | null;
  include: string | null;
  exclude: string | null;
  person_exclusions_file: string | null;
  output: string | null;
  report: string | null;
  format: "text" | "json" | "jsonl";
  policy: string | null;
  strategy_for: string[];
  field_label: string[];
  field_rules: string | null;
  field_person_exclusions: string | null;
  explain: string | null;
  trace_limit: number;
  report_include_sensitive: boolean;
  json_summary: boolean;
  batch: boolean;
  output_dir: string;
  recursive: boolean;
  workers: number;
  no_progress: boolean;
  allow_empty: boolean;
  vault_password: string | null;
  audit_log: string | null;
  audit_failure_policy: "raise" | "best_effort";
  with_privacy_filter: boolean;
  privacy_filter_device: string | null;
  merge_mode: string | null;
  extra_inputs: string[];
  max_file_bytes: number;
  max_text_chars: number;
  max_decompressed_bytes: number;
  extraction_timeout: number;
}

/** Python 이 ``args`` 에 덧붙이는 실행 상태 (``_stage``, ``_json_warnings`` 등). */
interface RunState {
  stage: string;
  jsonWarnings: string[];
  resolvedPassword?: string | null;
  vaultSaved: boolean;
  outputState: string;
  readPolicy: FileReadPolicy;
  profile: PolicyProfile | null;
  strategies: Record<string, string>;
  fieldLabels: Record<string, string>;
  fieldRules: FieldRule[];
  fieldPersonExclusions: Record<string, Iterable<string>> | null;
  coverage: ExtractionCoverage | null;
  /** JSON 입력 숫자 어휘 (int/float 구분 보존). */
  inputText?: string;
}

const PROCESSING_MODES = Object.values(ProcessingMode) as string[];
const STRATEGIES = ["tokenize", "redact", "asterisk", "hashed", "partial", "fpe"] as const;
const MERGE_MODES = ["union", "intersection", "cross_validation", "enrich_primary"] as const;
/** 값 없는 --vault-password → 프롬프트 트리거 (Python const 값 그대로). */
const VAULT_PASSWORD_PROMPT = "__PROMPT__";
/** JSON 출력에서 항상 Python float 인 키. */
const FLOAT_KEYS: ReadonlySet<string> = new Set(["confidence", "elapsed_s"]);

function buildParser(): ArgumentParser {
  const p = new ArgumentParser(
    "ko-pii",
    "Rule-based PII detection and reversible pseudonymization for Korean public-sector documents.",
  );
  const opt = (spec: ArgSpec): void => p.addArgument(spec);
  const limits = defaultReadPolicy();

  opt({ dest: "input", nargs: "opt", help: "Input file path (or '-' for stdin)." });
  opt({
    dest: "labels",
    optionStrings: ["--labels"],
    isFlag: true,
    def: false,
    help: "Print the 33 PII category labels (include/exclude keys) and exit.",
  });
  opt({
    dest: "mode",
    optionStrings: ["-m", "--mode"],
    choices: PROCESSING_MODES,
    help: "Processing mode (default: STRICT).",
  });
  opt({
    dest: "strategy",
    optionStrings: ["-s", "--strategy"],
    choices: STRATEGIES,
    help: "Substitution strategy (default: tokenize).",
  });
  opt({
    dest: "vault",
    optionStrings: ["--vault"],
    help: "Path to read/write the vault JSON (single-file mode only).",
  });
  opt({
    dest: "include",
    optionStrings: ["--include"],
    help: "Comma-separated category labels to include (others ignored).",
  });
  opt({
    dest: "exclude",
    optionStrings: ["--exclude"],
    help: "Comma-separated category labels to exclude.",
  });
  opt({
    dest: "person_exclusions_file",
    optionStrings: ["--person-exclusions-file"],
    help: "UTF-8 file with one domain term per line to exclude from PERSON detection.",
  });
  opt({
    dest: "output",
    optionStrings: ["-o", "--output"],
    help: "Output file path (default: stdout).",
  });
  opt({
    dest: "report",
    optionStrings: ["--report"],
    help: "Write a processing certificate to this path.",
  });
  opt({
    dest: "format",
    optionStrings: ["--format"],
    choices: ["text", "json", "jsonl"],
    def: "text",
    help: "Input/output format; JSON modes preserve keys and process values.",
  });
  opt({
    dest: "policy",
    optionStrings: ["--policy"],
    help: "Local versioned PolicyProfile JSON; cannot be combined with policy flags.",
  });
  opt({
    dest: "strategy_for",
    optionStrings: ["--strategy-for"],
    append: true,
    def: [],
    metavar: "LABEL=STRATEGY",
    help: "Override a label's transformation (repeatable, single-file mode).",
  });
  opt({
    dest: "field_label",
    optionStrings: ["--field-label"],
    append: true,
    def: [],
    metavar: "POINTER=LABEL",
    help: "Assert the label of an exact JSON Pointer (JSON modes only).",
  });
  opt({
    dest: "field_rules",
    optionStrings: ["--field-rules"],
    help: "JSON array of typed field rules; null path segments select array items.",
  });
  opt({
    dest: "field_person_exclusions",
    optionStrings: ["--field-person-exclusions"],
    help: "JSON object of exact field pointers to PERSON exclusion lists.",
  });
  opt({
    dest: "explain",
    optionStrings: ["--explain"],
    help: "Write value-free versioned JSON decision metadata.",
  });
  opt({
    dest: "trace_limit",
    optionStrings: ["--trace-limit"],
    isInt: true,
    def: 0,
    help: "Opt-in overlap trace events per text/string field (0-1000); requires --explain.",
  });
  opt({
    dest: "report_include_sensitive",
    optionStrings: ["--report-include-sensitive"],
    isFlag: true,
    def: false,
    help: "Include raw review values, replacements and input path in --report. Do not share.",
  });
  opt({
    dest: "json_summary",
    optionStrings: ["--json-summary"],
    isFlag: true,
    def: false,
    help: "Print the summary as JSON to stderr instead of text.",
  });
  opt({
    dest: "version",
    optionStrings: ["-V", "--version"],
    versionText: `ko-pii ${VERSION}`,
    help: "show program's version number and exit",
  });
  // 배치 모드
  opt({
    dest: "batch",
    optionStrings: ["--batch"],
    isFlag: true,
    def: false,
    help: "Treat input(s) as a directory or glob; process all matching files.",
  });
  opt({
    dest: "output_dir",
    optionStrings: ["--output-dir"],
    def: "anon",
    help: "Output directory for --batch mode (default: 'anon/').",
  });
  opt({
    dest: "recursive",
    optionStrings: ["--recursive"],
    isFlag: true,
    def: true,
    help: "Recurse into subdirectories in --batch mode (default: True).",
  });
  opt({
    dest: "workers",
    optionStrings: ["--workers"],
    isInt: true,
    def: 1,
    help: "Parallel workers for --batch mode (default: 1).",
  });
  opt({
    dest: "no_progress",
    optionStrings: ["--no-progress"],
    isFlag: true,
    def: false,
    help: "Disable batch progress indicator.",
  });
  opt({
    dest: "allow_empty",
    optionStrings: ["--allow-empty"],
    isFlag: true,
    def: false,
    help: "Allow empty batch directories or unmatched globs (not missing explicit files).",
  });
  // 암호화 vault
  opt({
    dest: "vault_password",
    optionStrings: ["--vault-password"],
    nargs: "opt",
    const: VAULT_PASSWORD_PROMPT,
    help:
      "Encrypted vault password. 값 없이 주면 프롬프트로 안전하게 입력. " +
      "값을 직접 주면 프로세스 목록/히스토리에 노출되니 비권장 — " +
      "env var $KPII_VAULT_PASSWORD 권장.",
  });
  opt({
    dest: "audit_log",
    optionStrings: ["--audit-log"],
    help: "Append audit log to this JSONL file (single-file mode only).",
  });
  opt({
    dest: "audit_failure_policy",
    optionStrings: ["--audit-failure-policy"],
    choices: ["raise", "best_effort"],
    def: "raise",
    help: "Behavior when audit logging fails (default: raise).",
  });
  // OpenAI Privacy Filter 통합 (옵션)
  opt({
    dest: "with_privacy_filter",
    optionStrings: ["--with-privacy-filter"],
    isFlag: true,
    def: false,
    help: "Combine ko-pii with OpenAI Privacy Filter (ML, requires [ml] extras).",
  });
  opt({
    dest: "privacy_filter_device",
    optionStrings: ["--privacy-filter-device"],
    help: "Device for Privacy Filter (cpu/cuda/mps). Default: cpu.",
  });
  opt({
    dest: "merge_mode",
    optionStrings: ["--merge-mode"],
    choices: MERGE_MODES,
    help: "How to combine ko-pii with secondary detector (default: union).",
  });
  // 추가 입력 인자
  opt({
    dest: "extra_inputs",
    nargs: "star",
    help: "Additional input paths/globs for --batch mode.",
  });
  opt({
    dest: "max_file_bytes",
    optionStrings: ["--max-file-bytes"],
    isInt: true,
    def: limits.maxFileBytes,
  });
  opt({
    dest: "max_text_chars",
    optionStrings: ["--max-text-chars"],
    isInt: true,
    def: limits.maxTextChars,
  });
  opt({
    dest: "max_decompressed_bytes",
    optionStrings: ["--max-decompressed-bytes"],
    isInt: true,
    def: limits.maxDecompressedBytes,
  });
  opt({
    dest: "extraction_timeout",
    optionStrings: ["--extraction-timeout"],
    isFloat: true,
    def: 30.0,
    help: "Seconds allowed per file extraction (default: 30).",
  });
  return p;
}

// ---------------------------------------------------------------- 입출력

/** 표준 입력을 최대 ``limit`` 바이트까지 동기로 읽는다 (EOF 또는 한도 초과 시 중단). */
function readStdinBytes(limit: number): Buffer {
  const chunks: Buffer[] = [];
  let total = 0;
  const buf = Buffer.alloc(65_536);
  for (;;) {
    let n: number;
    try {
      n = readSync(0, buf, 0, buf.length, null);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EAGAIN") continue;
      if ((err as NodeJS.ErrnoException).code === "EOF") break;
      throw err;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buf.subarray(0, n)));
    total += n;
    if (total > limit) break;
  }
  return Buffer.concat(chunks);
}

function codePointLength(text: string): number {
  let n = 0;
  for (const _ of text) n += 1;
  return n;
}

/** UTF-8 엄격 디코딩 — 잘못된 바이트는 Python UnicodeDecodeError(ValueError) 대응. */
function decodeUtf8(bytes: Uint8Array, stripBom: boolean): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: !stripBom }).decode(bytes);
  } catch {
    throw new ValueError("'utf-8' codec can't decode input");
  }
}

/** Python ``_read_input`` — stdin 은 한도까지만 읽고, 파일은 격리 추출한다. */
async function readInput(
  path: string,
  policy: FileReadPolicy,
  timeout: number,
): Promise<[string, ExtractionCoverage | null]> {
  if (path === "-") {
    // Python: sys.stdin.read(min(max_text_chars, max_file_bytes) + 1) — sys.stdin 은 줄바꿈을
    // 바꾸지 않는다 (실측: "\r\n" 그대로). 문자 수 ≤ 바이트 수이므로 바이트 한도까지만 읽어도
    // 같은 판정을 얻는다.
    const raw = cliHooks.readStdin(policy.maxFileBytes);
    const text = decodeUtf8(raw, false);
    if (
      codePointLength(text) > policy.maxTextChars ||
      Buffer.byteLength(text, "utf8") > policy.maxFileBytes
    ) {
      throw new BoundedReadError("stdin_too_large", "standard input exceeds configured limits");
    }
    return [text, null];
  }
  const document = await readTextIsolated(path, { policy, timeout });
  return [document.text, document.coverage];
}

function writeOutput(path: string | null, text: string): void {
  if (!path || path === "-") {
    process.stdout.write(text);
    if (!text.endsWith("\n")) process.stdout.write("\n");
    return;
  }
  writeTextAtomic(path, text);
}

/** Python ``_assignments`` — ``KEY=VALUE`` (마지막 ``=`` 기준) 의 유일한 사전. */
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

/** Python ``_read_structured_input`` — 상한이 있는 일반 파일만 읽는다 (utf-8-sig). */
function readStructuredInput(path: string, policy: FileReadPolicy): Promise<string> | string {
  if (path === "-") return readInput(path, policy, 30.0).then(([text]) => text);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  let raw: Buffer;
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > policy.maxFileBytes) {
      throw new ValueError("JSON input must be a bounded regular file");
    }
    const buf = Buffer.alloc(policy.maxFileBytes + 1);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
      if (total >= buf.length) break;
    }
    raw = buf.subarray(0, total);
  } finally {
    closeSync(fd);
  }
  if (raw.length > policy.maxFileBytes) throw new ValueError("JSON input exceeds byte limits");
  const text = decodeUtf8(raw, true);
  if (codePointLength(text) > policy.maxTextChars) {
    throw new ValueError("JSON input exceeds character limits");
  }
  return text;
}

/** Python ``_split_csv`` — 빈 항목도 그대로 남긴다 (라벨 검증이 거부한다). */
function splitCsv(value: string | null): string[] | null {
  if (value === null) return null;
  return value.split(",").map((t) => pyStrip(t));
}

/** Python ``_load_person_exclusions`` — 줄 단위, 빈 줄·``#`` 주석 제외. */
function loadPersonExclusions(path: string | null): string[] | null {
  if (!path) return null;
  const text = decodeUtf8(readFileSync(path), false);
  const out: string[] = [];
  // Python 텍스트 모드 줄 단위 반복 (universal newlines)
  for (const raw of text.split(/\r\n|\r|\n/)) {
    const line = pyStrip(raw);
    if (line && !line.startsWith("#")) out.push(line);
  }
  return out;
}

/** ``--json-summary`` 활성 시 stderr 를 기계 판독 가능하게 유지한다. */
function emitWarning(args: CliNamespace, state: RunState, message: string): void {
  if (args.json_summary) {
    if (!state.jsonWarnings.includes(message)) state.jsonWarnings.push(message);
    return;
  }
  process.stderr.write(`${message}\n`);
}

function writeJsonSummary(state: RunState, summary: Record<string, unknown>): void {
  const payload: Record<string, unknown> = { ...summary };
  if (state.jsonWarnings.length > 0) payload.warnings = [...state.jsonWarnings];
  process.stderr.write(`${pyDumps(payload, 2, { floatKeys: FLOAT_KEYS })}\n`);
}

function resolveVaultPassword(args: CliNamespace, state: RunState): string | null {
  if (state.resolvedPassword !== undefined) return state.resolvedPassword;
  let pw = args.vault_password;
  if (pw === VAULT_PASSWORD_PROMPT) {
    // 값 없는 --vault-password → 안전한 프롬프트 입력
    pw = cliHooks.promptPassword("Vault password: ");
    if (!pw) throw new ValueError("Vault password must not be empty");
  } else if (pw) {
    emitWarning(
      args,
      state,
      "경고: --vault-password 값은 프로세스 목록/셸 히스토리에 노출됩니다. " +
        "env var $KPII_VAULT_PASSWORD 또는 값 없는 --vault-password(프롬프트) 사용 권장.",
    );
  } else {
    pw = process.env.KPII_VAULT_PASSWORD ?? null;
  }
  state.resolvedPassword = pw;
  return pw;
}

/** Open the vault — auto-detect encrypted format. */
function loadVault(args: CliNamespace, state: RunState): ReversibleVault | null {
  if (!args.vault || !pathExists(args.vault)) return null;
  if (isEncryptedFile(args.vault)) {
    const pw = resolveVaultPassword(args, state);
    if (!pw) {
      throw new ValueError(
        "암호화 vault: --vault-password 또는 환경변수 $KPII_VAULT_PASSWORD 필요.",
      );
    }
    return loadEncrypted(args.vault, pw);
  }
  return ReversibleVault.load(args.vault);
}

let activeState: RunState | null = null;

function saveVault(args: CliNamespace, vault: ReversibleVault): void {
  const state = activeState as RunState;
  if (!args.vault) return;
  const pw = resolveVaultPassword(args, state);
  if (pw) {
    saveEncrypted(vault, args.vault, pw);
  } else {
    emitWarning(
      args,
      state,
      "경고: 암호 없이 저장한 Vault JSON에는 원본 개인정보가 평문으로 포함됩니다. " +
        "운영 환경에서는 --vault-password 또는 KPII_VAULT_PASSWORD를 사용하십시오.",
    );
    vault.save(args.vault);
  }
}

function validateBatchArgs(parser: ArgumentParser, args: CliNamespace): void {
  const unsupported: string[] = [];
  if (
    args.format !== "text" ||
    args.strategy_for.length > 0 ||
    args.field_label.length > 0 ||
    args.field_rules ||
    args.field_person_exclusions ||
    args.explain ||
    args.report_include_sensitive
  ) {
    unsupported.push("structured/policy/explanation options");
  }
  if (args.audit_log !== null) unsupported.push("--audit-log");
  if (args.vault !== null) unsupported.push("--vault");
  if (args.vault_password !== null) unsupported.push("--vault-password");
  if (args.with_privacy_filter) unsupported.push("--with-privacy-filter");
  if (args.report !== null) unsupported.push("--report");
  if (args.output !== null) unsupported.push("--output");
  if (unsupported.length > 0) {
    parser.errorExit(
      `--batch does not support ${unsupported.join(", ")}; use single-file mode for these options`,
    );
  }
}

const PATH_OPTIONS = [
  "output",
  "vault",
  "report",
  "audit_log",
  "explain",
  "person_exclusions_file",
  "field_rules",
  "field_person_exclusions",
  "policy",
] as const;

/** Python ``_validate_paths`` — 입력·출력·설정 파일이 같은 파일(심링크·하드링크 포함)이면 거부. */
function validatePaths(parser: ArgumentParser, args: CliNamespace): void {
  const paths: Array<[string, string]> =
    args.input !== "-" ? [["input", args.input as string]] : [];
  for (const name of PATH_OPTIONS) {
    const value = args[name];
    if (value !== null && !(name === "output" && value === "-")) {
      if (!value) parser.errorExit(`${name} path must not be empty`);
      paths.push([name, value]);
    }
  }
  for (let index = 0; index < paths.length; index++) {
    const [name, value] = paths[index]!;
    for (const [otherName, other] of paths.slice(0, index)) {
      let same = pyRealpath(value) === pyRealpath(other);
      if (!same && pathExists(value) && pathExists(other)) same = sameFile(value, other);
      if (same) parser.errorExit(`${name} and ${otherName} must use different files`);
    }
  }
}

/** Python ``AuditLog.__enter__`` — 추가 모드로 열 수 있는지 확인한다 (열기 실패는 OSError). */
function openAuditFile(path: string): void {
  closeSync(openSync(path, "a"));
}

function openAudit(args: CliNamespace, state: RunState): AuditLog | null {
  if (!args.audit_log) return null;
  try {
    const audit = cliHooks.createAudit(args.audit_log);
    openAuditFile(args.audit_log);
    return audit;
  } catch (exc) {
    if (args.audit_failure_policy === "raise") throw exc;
    emitWarning(
      args,
      state,
      `경고: 감사 로그를 열지 못해 감사 기록 없이 계속합니다 (${pyExceptionName(exc)}).`,
    );
    return null;
  }
}

function closeAudit(
  args: CliNamespace,
  state: RunState,
  audit: AuditLog | null,
  activeError = false,
): void {
  if (audit === null) return;
  try {
    audit.close();
  } catch (exc) {
    // 진행 중인 처리 오류를 2차 close 실패로 가리지 않는다.
    if (activeError) return;
    if (args.audit_failure_policy === "raise") throw exc;
    emitWarning(
      args,
      state,
      "경고: 감사 로그를 정상적으로 종료하지 못했지만 best_effort 정책으로 " +
        `계속합니다 (${pyExceptionName(exc)}).`,
    );
  }
}

/** Python 이 잡는 (OSError, ValueError, ImportError) 계열인지. JSON 구문 오류는 ValueError. */
function isHandledError(exc: unknown): boolean {
  return (
    exc instanceof ValueError ||
    exc instanceof SyntaxError ||
    exc instanceof ImportError ||
    isOsError(exc)
  );
}

// ---------------------------------------------------------------- 배치

async function runBatch(args: CliNamespace, state: RunState): Promise<number> {
  // Python: inputs = [args.input] + (args.extra_inputs or []) — input 은 None 이 아님
  const inputs = [args.input as string, ...args.extra_inputs];
  const summary = await processPaths(inputs, args.output_dir, {
    mode: args.mode as string,
    strategy: args.strategy as string,
    recursive: args.recursive,
    workers: args.workers,
    include: splitCsv(args.include),
    exclude: splitCsv(args.exclude),
    personExclusions: loadPersonExclusions(args.person_exclusions_file),
    progress: !args.no_progress && !args.json_summary,
    readPolicy: state.readPolicy,
    extractionTimeout: args.extraction_timeout,
    allowEmpty: args.allow_empty,
    protectedPaths: args.person_exclusions_file ? [args.person_exclusions_file] : [],
  });
  if (args.json_summary) {
    // Python dataclasses.asdict(FileResult) 필드 순서(snake_case) 유지
    writeJsonSummary(state, {
      total: summary.totalFiles,
      succeeded: summary.succeeded,
      failed: summary.failed,
      detections: summary.totalDetections,
      blocked: summary.totalBlocked,
      review: summary.totalReview,
      elapsed_s: summary.elapsedS,
      results: summary.results.map((r) => ({
        input_path: r.inputPath,
        output_path: r.outputPath,
        detections: r.detections,
        combined_risk: r.combinedRisk,
        blocked: r.blocked,
        review: r.review,
        error: r.error,
        elapsed_s: r.elapsedS,
        error_code: r.errorCode,
        coverage: r.coverage,
      })),
      skipped: summary.skipped,
    });
  } else {
    process.stderr.write(
      `\n[배치 완료] 총 ${summary.totalFiles}개 / 성공 ${summary.succeeded} / ` +
        `실패 ${summary.failed} / 검출 ${summary.totalDetections} / ` +
        `차단 ${summary.totalBlocked} / 검토 ${summary.totalReview} / ` +
        `${pyFormatFixed(summary.elapsedS, 2)}초\n`,
    );
  }
  return summary.failed === 0 ? 0 : 1;
}

// ---------------------------------------------------------------- 단일 파일

function runSingle(
  args: CliNamespace,
  state: RunState,
  text: string,
  vault: ReversibleVault | null,
  audit: AuditLog | null,
): number {
  state.stage = "processing";
  let outputText: string;
  let activeVault: ReversibleVault | null;
  let summary: Record<string, unknown>;
  let detectionCount: number;
  let explanation: Record<string, unknown> | null = null;
  let result: ReturnType<Anonymizer["process"]> | null = null;
  try {
    if (args.with_privacy_filter) {
      // Python get_privacy_filter_adapter 는 [ml] extras(transformers + torch) 가 필요하다.
      // TS 포트에는 ML 보조 검출기가 없으므로 미설치 환경과 같은 ImportError 로 끝난다.
      throw new ImportError("OpenAI Privacy Filter 어댑터는 transformers + torch 가 필요합니다.");
    }
    const anon =
      state.profile !== null
        ? state.profile.makeAnonymizer({ vault, traceLimit: args.trace_limit })
        : new Anonymizer(
            args.mode as ProcessingMode,
            args.strategy as string,
            vault,
            splitCsv(args.include),
            splitCsv(args.exclude),
            null,
            args.merge_mode as string,
            null,
            loadPersonExclusions(args.person_exclusions_file),
            { strategies: state.strategies, traceLimit: args.trace_limit },
          );
    if (audit !== null) {
      anon.vault.attachAudit(audit, { failurePolicy: args.audit_failure_policy });
    }

    if (args.format === "text") {
      result = anon.process(text);
      outputText = result.text;
      activeVault = result.vault;
      summary = { ...(result.summary as Record<string, unknown>) };
      detectionCount = result.detections.length;
      if (args.explain) explanation = explain(result, { includeTrace: Boolean(args.trace_limit) });
    } else {
      const limits = new StructuredLimits({ maxChars: args.max_text_chars });
      const options = {
        anonymizer: anon,
        fieldLabels: state.fieldLabels,
        limits,
        fieldRules: state.fieldRules,
        fieldPersonExclusions: state.fieldPersonExclusions,
      };
      let documents: StructuredResult[];
      if (args.format === "json") {
        documents = [anonymizeJson(loadsJson(text, { limits }), options)];
        outputText = `${pyDumps(documents[0]!.data, 2, { shadow: numberShadow(text) })}\n`;
      } else {
        documents = anonymizeJsonl(text, options);
        const lines = text.split("\n");
        outputText = documents
          .map((doc) => {
            const source = doc.sourceLine === null ? null : lines[doc.sourceLine - 1];
            const shadow = source === undefined || source === null ? null : numberShadow(source);
            return `${pyDumps(doc.data, null, { shadow })}\n`;
          })
          .join("");
      }
      detectionCount = documents.reduce(
        (n, doc) => n + doc.fields.reduce((m, f) => m + f.result.detections.length, 0),
        0,
      );
      const used = new Set([anon.strategy, ...Object.values(anon.strategies)]);
      activeVault = ["tokenize", "hashed", "fpe"].some((s) => used.has(s)) ? anon.vault : null;
      summary = {
        format: args.format,
        documents: documents.length,
        total: detectionCount,
        keys_screened: false,
        strategy: anon.strategy,
        strategies: { ...anon.strategies },
        field_rules: documents.map((doc) => ({
          source_line: doc.sourceLine,
          rules: doc.fieldRuleSummary,
        })),
      };
      if (args.explain) {
        explanation = {
          schema_version: 1,
          documents: documents.map((doc) =>
            doc.report({ includeTrace: Boolean(args.trace_limit) }),
          ),
        };
      }
    }
    if (audit !== null) {
      try {
        audit.recordAnonymize(detectionCount, args.mode as string, {
          status: "prepared",
          context: args.input,
        });
      } catch (exc) {
        if (args.audit_failure_policy === "raise") throw exc;
        emitWarning(args, state, "경고: 익명화 결과 준비 감사 레코드를 기록하지 못했습니다.");
      }
    }
  } catch (exc) {
    closeAudit(args, state, audit, true);
    throw exc;
  }

  // 감사 종료는 fail-closed 경계에 속한다. 위 이벤트는 "persisted" 가 아니라 "prepared" —
  // 이후 파일시스템/stdout 쓰기는 JSONL 감사 파일과 원자적으로 커밋할 수 없다.
  state.stage = "audit_finalize";
  closeAudit(args, state, audit);

  if (args.vault && activeVault !== null) {
    state.stage = "vault_save";
    cliHooks.saveVault(args, activeVault);
    state.vaultSaved = true;
  }

  state.stage = "output_write";
  state.outputState = "uncertain";
  cliHooks.writeOutput(args.output, outputText);
  state.outputState = "written";

  if (args.report && result !== null) {
    state.stage = "report_write";
    const sensitive = args.report_include_sensitive;
    const certificate = generateCertificate(result, args.input as string, sensitive, {
      includeDocumentId: sensitive,
      includeReplacements: sensitive,
    });
    writeTextAtomic(args.report, certificate);
  }
  if (args.explain && explanation !== null) {
    state.stage = "explanation_write";
    writeTextAtomic(args.explain, `${pyDumps(explanation, 2, { floatKeys: FLOAT_KEYS })}\n`);
  }

  state.stage = "summary_write";
  if (args.json_summary) {
    if (state.coverage !== null) summary.extraction_coverage = state.coverage;
    writeJsonSummary(state, summary);
  } else if (args.format === "text" && result !== null) {
    process.stderr.write(`${formatSummaryText(result)}\n`);
  } else {
    process.stderr.write(
      `Processed ${String(summary.documents)} document(s); ${detectionCount} detection(s). Keys not screened.\n`,
    );
  }
  return 0;
}

/** Python ``_report_failure`` — 원문 없는 실패 보고. 설정 단계면 2, 그 밖은 1. */
function reportFailure(
  args: CliNamespace,
  state: RunState,
  exc: unknown,
  code: string | null = null,
): number {
  const stage = state.stage;
  const bounded = exc instanceof BoundedReadError ? exc : null;
  const error = code ?? (bounded !== null ? bounded.code : `${stage}_failed`);
  const message = bounded !== null ? bounded.message : `${stage} could not be completed`;
  const payload: Record<string, unknown> = {
    status: "failed",
    error,
    stage,
    message,
    vault_saved: state.vaultSaved,
    output_state: state.outputState,
  };
  if (bounded !== null && bounded.coverage !== null) payload.extraction_coverage = bounded.coverage;
  if (args.json_summary) {
    writeJsonSummary(state, payload);
  } else {
    process.stderr.write(`ko-pii: ${error}: ${message}\n`);
  }
  return stage === "configuration" ? 2 : 1;
}

async function run(parser: ArgumentParser, args: CliNamespace): Promise<number> {
  if (args.labels) {
    process.stdout.write(`${formatLabelsTable()}\n`);
    return 0;
  }
  if (args.input === null) {
    parser.errorExit("input is required (or use --labels to list categories)");
  }

  if (args.policy !== null) {
    if (args.batch || args.policy === "-") {
      parser.errorExit("--policy requires a local settings file in single-file mode");
    }
    const flags = [
      args.mode,
      args.strategy,
      args.include,
      args.exclude,
      args.person_exclusions_file,
      args.field_rules,
      args.field_person_exclusions,
      args.merge_mode,
      args.privacy_filter_device,
    ];
    if (
      flags.some((v) => v !== null) ||
      args.strategy_for.length > 0 ||
      args.field_label.length > 0 ||
      args.with_privacy_filter
    ) {
      parser.errorExit("--policy cannot be combined with processing-policy or model flags");
    }
  }
  args.mode = args.mode ?? ProcessingMode.STRICT;
  args.strategy = args.strategy ?? "tokenize";
  args.merge_mode = args.merge_mode ?? "union";
  args.privacy_filter_device = args.privacy_filter_device ?? "cpu";
  const state: RunState = {
    stage: "configuration",
    jsonWarnings: [],
    vaultSaved: false,
    outputState: "not_written",
    readPolicy: defaultReadPolicy(),
    profile: null,
    strategies: {},
    fieldLabels: {},
    fieldRules: [],
    fieldPersonExclusions: null,
    coverage: null,
  };
  activeState = state;
  try {
    validateLabelFilter(splitCsv(args.include), "include");
    validateLabelFilter(splitCsv(args.exclude), "exclude");
    state.strategies = validateStrategies(args.strategy, assignments(args.strategy_for));
    state.fieldLabels = assignments(args.field_label);
  } catch (exc) {
    if (!(exc instanceof ValueError)) throw exc;
    return reportFailure(
      args,
      state,
      exc,
      args.strategy_for.length === 0 && args.field_label.length === 0
        ? "invalid_label_filter"
        : "invalid_processing_policy",
    );
  }
  if (
    args.format === "text" &&
    (args.field_label.length > 0 || args.field_rules || args.field_person_exclusions)
  ) {
    parser.errorExit("field options require --format json or jsonl");
  }
  if (!(args.trace_limit >= 0 && args.trace_limit <= 1000) || (args.trace_limit && !args.explain)) {
    parser.errorExit("--trace-limit requires --explain and must be between 0 and 1000");
  }
  if (args.format !== "text" && (args.report || args.report_include_sensitive)) {
    parser.errorExit("JSON modes use --explain instead of --report");
  }
  if (args.report_include_sensitive && !args.report) {
    parser.errorExit("--report-include-sensitive requires --report");
  }
  if (args.json_summary && args.vault_password === VAULT_PASSWORD_PROMPT) {
    parser.errorExit(
      "--json-summary cannot use the interactive --vault-password prompt; " +
        "set KPII_VAULT_PASSWORD instead",
    );
  }
  if (args.vault_password === "") parser.errorExit("--vault-password must not be empty");
  try {
    const base = defaultReadPolicy().toInit();
    state.readPolicy = new FileReadPolicy({
      ...base,
      maxFileBytes: args.max_file_bytes,
      maxTextChars: args.max_text_chars,
      maxDecompressedBytes: args.max_decompressed_bytes,
    });
    if (!Number.isFinite(args.extraction_timeout) || args.extraction_timeout <= 0) {
      throw new ValueError("extraction timeout must be finite and positive");
    }
  } catch (exc) {
    if (!(exc instanceof ValueError)) throw exc;
    parser.errorExit(exc.message);
  }

  if (args.batch) {
    validateBatchArgs(parser, args);
    state.stage = "batch";
    try {
      return await runBatch(args, state);
    } catch (exc) {
      if (!(exc instanceof ValueError || isOsError(exc))) throw exc;
      return reportFailure(args, state, exc, "batch_configuration");
    }
  }

  validatePaths(parser, args);
  try {
    state.fieldPersonExclusions = null;
    if (args.field_person_exclusions) {
      const config = loadsJson(
        await readStructuredInput(args.field_person_exclusions, state.readPolicy),
      );
      if (typeof config !== "object" || config === null || Array.isArray(config)) {
        throw new ValueError("field person exclusions configuration must be a JSON object");
      }
      fieldExclusions(config as Record<string, Iterable<string>>);
      state.fieldPersonExclusions = config as Record<string, Iterable<string>>;
    }
    state.fieldRules = [];
    if (args.field_rules) {
      state.fieldRules = rulesFromJson(
        loadsJson(await readStructuredInput(args.field_rules, state.readPolicy)),
      );
    }
    if (args.policy) {
      const profile = PolicyProfile.fromJson(
        await readStructuredInput(
          args.policy,
          new FileReadPolicy({ maxFileBytes: 400_000, maxTextChars: 100_000 }),
        ),
      );
      state.profile = profile;
      if (args.format === "text" && profile.structured) {
        throw new ValueError("profile field settings require --format json or jsonl");
      }
      const settings = profile.settings;
      args.mode = settings.mode as string;
      args.strategy = settings.strategy as string;
      const options = profile.structuredOptions();
      state.fieldLabels = options.fieldLabels;
      state.fieldRules = options.fieldRules;
      state.fieldPersonExclusions = options.fieldPersonExclusions;
    }
    state.stage = "extraction";
    let text: string;
    if (args.format === "text") {
      [text, state.coverage] = await readInput(
        args.input as string,
        state.readPolicy,
        args.extraction_timeout,
      );
    } else {
      text = await readStructuredInput(args.input as string, state.readPolicy);
      state.coverage = null;
    }
    state.stage = "vault_load";
    let vault: ReversibleVault | null;
    try {
      vault = loadVault(args, state);
    } catch (exc) {
      if (exc instanceof TypeError) throw new ValueError("invalid Vault structure");
      throw exc;
    }
    state.stage = "audit_open";
    const audit = openAudit(args, state);
    return runSingle(args, state, text, vault, audit);
  } catch (exc) {
    if (!isHandledError(exc)) throw exc;
    return reportFailure(args, state, exc);
  }
}

/**
 * CLI 진입점 — Python `ko_pii.cli.main(argv) -> int` 대응.
 * argv 미지정 시 process.argv.slice(2). process.exit 는 호출하지 않는다 —
 * bin 래퍼가 반환값으로 process.exitCode 를 설정한다.
 */
export async function main(argv?: string[]): Promise<number> {
  const parser = buildParser();
  try {
    const args = parser.parseArgs(argv) as unknown as CliNamespace;
    return await run(parser, args);
  } catch (e) {
    if (e instanceof ParseExit) {
      (e.stream === "stdout" ? process.stdout : process.stderr).write(e.text);
      return e.code;
    }
    // Python 은 잡지 않은 예외의 전체 트레이스백을 출력하지만 TS 포트는 마지막 줄만 재현한다
    const name = e instanceof Error ? e.name : "Exception";
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`${name}: ${msg}\n`);
    return 1;
  } finally {
    activeState = null;
  }
}
