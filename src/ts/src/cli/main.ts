/**
 * CLI — ko-pii input.txt --mode strict --vault vault.json --strategy tokenize.
 *
 * 표준 입력으로 받으려면 input 자리에 ``-`` 사용. 결과는 stdout 으로 (치환된 본문),
 * 요약/검토는 stderr 로 출력한다. Vault 저장 경로가 지정되면 Vault JSON 도 함께 기록.
 *
 * Python ko_pii.cli (argparse 기반 22 옵션) 1:1 포트. argparse 는 서브셋 재구현
 * (`./argparse.js`) — npm 의존성 추가로 코어 "의존성 0" 약속이 깨지지 않도록.
 * 종료 코드는 main() 이 반환하고 process.exit 는 bin 래퍼(통합 담당)가 호출한다.
 */

import { existsSync, writeFileSync } from "node:fs";
import { Anonymizer } from "../anonymizer.js";
import { processPaths } from "../batch.js";
import { ProcessingMode } from "../core/modes.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { readText } from "../io/dispatcher.js";
import { AuditLog } from "../vault/audit.js";
import { isEncryptedFile, loadEncrypted, saveEncrypted } from "../vault/encrypted.js";
import { ReversibleVault } from "../vault/reversible.js";
import { VERSION } from "../version.js";
import { type ArgSpec, ArgumentParser, ParseExit } from "./argparse.js";
import { generateCertificate } from "./certificate.js";
import { formatLabelsTable } from "./labelsTable.js";
import { promptPassword } from "./prompt.js";
import { formatSummaryText } from "./summaryText.js";

/** Python SystemExit("메시지") — 메시지를 stderr 에 출력하고 코드 1. */
class SystemExitMessage extends Error {
  readonly messageText: string;
  constructor(messageText: string) {
    super(messageText);
    this.messageText = messageText;
  }
}

export interface CliNamespace {
  input: string | null;
  labels: boolean;
  mode: string;
  strategy: string;
  vault: string | null;
  include: string | null;
  exclude: string | null;
  output: string | null;
  report: string | null;
  json_summary: boolean;
  batch: boolean;
  output_dir: string;
  recursive: boolean;
  workers: number;
  no_progress: boolean;
  vault_password: string | null;
  audit_log: string | null;
  with_privacy_filter: boolean;
  privacy_filter_device: string;
  merge_mode: string;
  extra_inputs: string[];
}

const PROCESSING_MODES = Object.values(ProcessingMode) as string[];
const STRATEGIES = ["tokenize", "redact", "asterisk", "hashed", "partial", "fpe"] as const;
const MERGE_MODES = ["union", "intersection", "cross_validation", "enrich_primary"] as const;
/** 값 없는 --vault-password → 프롬프트 트리거 (Python const 값 그대로). */
const VAULT_PASSWORD_PROMPT = "__PROMPT__";

function buildParser(): ArgumentParser {
  const p = new ArgumentParser(
    "ko-pii",
    "Rule-based PII detection and reversible pseudonymization for Korean public-sector documents.",
  );
  const opt = (spec: ArgSpec): void => p.addArgument(spec);

  opt({ dest: "input", nargs: "opt", help: "Input file path (or '-' for stdin)." });
  opt({
    dest: "labels",
    optionStrings: ["--labels"],
    isFlag: true,
    help: "Print the 33 PII category labels (include/exclude keys) and exit.",
  });
  opt({
    dest: "mode",
    optionStrings: ["-m", "--mode"],
    choices: PROCESSING_MODES,
    def: "STRICT",
    help: "Processing mode (default: STRICT).",
  });
  opt({
    dest: "strategy",
    optionStrings: ["-s", "--strategy"],
    choices: STRATEGIES,
    def: "tokenize",
    help: "Substitution strategy (default: tokenize).",
  });
  opt({
    dest: "vault",
    optionStrings: ["--vault"],
    help: "Path to read/write the vault JSON (used by tokenize/hashed).",
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
    dest: "json_summary",
    optionStrings: ["--json-summary"],
    isFlag: true,
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
    help: "Disable batch progress indicator.",
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
    help: "Append audit log to this JSONL file.",
  });
  // OpenAI Privacy Filter 통합 (옵션)
  opt({
    dest: "with_privacy_filter",
    optionStrings: ["--with-privacy-filter"],
    isFlag: true,
    help: "Combine ko-pii with OpenAI Privacy Filter (ML, requires [ml] extras).",
  });
  opt({
    dest: "privacy_filter_device",
    optionStrings: ["--privacy-filter-device"],
    def: "cpu",
    help: "Device for Privacy Filter (cpu/cuda/mps). Default: cpu.",
  });
  opt({
    dest: "merge_mode",
    optionStrings: ["--merge-mode"],
    choices: MERGE_MODES,
    def: "union",
    help: "How to combine ko-pii with secondary detector (default: union).",
  });
  // 추가 입력 인자
  opt({
    dest: "extra_inputs",
    nargs: "star",
    help: "Additional input paths/globs for --batch mode.",
  });
  return p;
}

// ---------------------------------------------------------------- 유틸

async function readInput(path: string): Promise<string> {
  if (path === "-") return readStdinAll();
  // 확장자 기반 자동 디스패처 (HWPX/DOCX/XLSX/CSV/TXT 등)
  try {
    return await readText(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    if (code === "ENOENT") {
      // Python FileNotFoundError 마지막 줄과 동일한 표현
      const e = new Error(`[Errno 2] No such file or directory: '${path}'`);
      e.name = "FileNotFoundError";
      throw e;
    }
    throw err;
  }
}

function readStdinAll(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

function writeOutput(path: string | null, text: string): void {
  if (!path || path === "-") {
    process.stdout.write(text);
    if (!text.endsWith("\n")) process.stdout.write("\n");
    return;
  }
  writeFileSync(path, text, "utf8");
}

function splitCsv(value: string | null): string[] | null {
  if (!value) return null;
  return value
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t !== "");
}

async function resolveVaultPassword(args: CliNamespace): Promise<string | null> {
  const pw = args.vault_password;
  if (pw === VAULT_PASSWORD_PROMPT) {
    // 값 없는 --vault-password → 안전한 프롬프트 입력
    return promptPassword("Vault password: ");
  }
  if (pw) {
    process.stderr.write(
      "경고: --vault-password 값은 프로세스 목록/셸 히스토리에 노출됩니다. " +
        "env var $KPII_VAULT_PASSWORD 또는 값 없는 --vault-password(프롬프트) 사용 권장.\n",
    );
    return pw;
  }
  return process.env.KPII_VAULT_PASSWORD ?? null;
}

/** Open the vault — auto-detect encrypted format. */
async function loadVault(args: CliNamespace): Promise<ReversibleVault | null> {
  if (!args.vault || !existsSync(args.vault)) return null;
  if (isEncryptedFile(args.vault)) {
    const pw = await resolveVaultPassword(args);
    if (!pw) {
      throw new SystemExitMessage(
        "암호화 vault: --vault-password 또는 환경변수 $KPII_VAULT_PASSWORD 필요.",
      );
    }
    return loadEncrypted(args.vault, pw);
  }
  return ReversibleVault.load(args.vault);
}

async function saveVault(args: CliNamespace, vault: ReversibleVault): Promise<void> {
  if (!args.vault) return;
  const pw = await resolveVaultPassword(args);
  if (pw) {
    saveEncrypted(vault, args.vault, pw);
  } else {
    vault.save(args.vault);
  }
}

// ---------------------------------------------------------------- 배치

async function runBatch(args: CliNamespace): Promise<number> {
  // Python: inputs = [args.input] + (args.extra_inputs or []) — input 은 None 이 아님
  const inputs = [args.input as string, ...args.extra_inputs];
  const summary = await processPaths(inputs, args.output_dir, {
    mode: args.mode,
    strategy: args.strategy,
    recursive: args.recursive,
    workers: args.workers,
    include: splitCsv(args.include),
    exclude: splitCsv(args.exclude),
    progress: !args.no_progress,
  });
  process.stderr.write(
    `\n[배치 완료] 총 ${summary.totalFiles}개 / 성공 ${summary.succeeded} / ` +
      `실패 ${summary.failed} / 검출 ${summary.totalDetections} / ` +
      `차단 ${summary.totalBlocked} / 검토 ${summary.totalReview} / ` +
      `${pyFormatFixed(summary.elapsedS, 2)}초\n`,
  );
  if (args.json_summary) {
    // Python dataclasses.asdict(FileResult) 필드 순서(snake_case) 유지
    const payload = {
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
      })),
    };
    process.stderr.write(`${JSON.stringify(payload, null, 2)}\n`);
  }
  return summary.failed === 0 ? 0 : 1;
}

// ---------------------------------------------------------------- 본체

async function run(args: CliNamespace): Promise<number> {
  if (args.batch) {
    return runBatch(args);
  }

  // main() 에서 input !== null 이 보장된다
  const text = await readInput(args.input as string);

  const vault = await loadVault(args);
  let audit: AuditLog | null = null;
  if (args.audit_log) {
    audit = new AuditLog(args.audit_log);
    if (vault !== null) vault.attachAudit(audit);
  }

  if (args.with_privacy_filter) {
    // Python ko_pii.integrations.get_privacy_filter_adapter 는 [ml] extras
    // (transformers + torch) 를 요구하며, 미설치 환경 실측 출력은 ImportError:
    //   OpenAI Privacy Filter 어댑터는 transformers + torch 가 필요합니다.
    //     pip install ko-pii[ml]
    //   (원인: No module named 'transformers')
    // TS 포트에는 ML 보조 검출기가 없으므로 동일한 오류 메시지로 종료한다 (코드 1).
    process.stderr.write(
      "ImportError: OpenAI Privacy Filter 어댑터는 transformers + torch 가 필요합니다.\n" +
        "  pip install ko-pii[ml]\n" +
        "(원인: No module named 'transformers')\n",
    );
    return 1;
  }

  const anon = new Anonymizer(
    args.mode as ProcessingMode,
    args.strategy,
    vault ?? undefined,
    splitCsv(args.include),
    splitCsv(args.exclude),
  );
  // Python cli.py: process 전에 anon.vault 에 감사 로그 부착 (store 이벤트 기록)
  if (audit !== null) {
    anon.vault.attachAudit(audit);
  }

  const result = anon.process(text);
  writeOutput(args.output, result.text);

  if (args.vault && result.vault !== null) {
    await saveVault(args, result.vault);
  }

  if (args.report) {
    writeFileSync(args.report, generateCertificate(result, args.input ?? "(unspecified)"), "utf8");
  }

  if (audit !== null) {
    audit.recordAnonymize(result.detections.length, args.mode, {
      context: args.input ?? null,
    });
    audit.close();
  }

  if (args.json_summary) {
    process.stderr.write(`${JSON.stringify(result.summary, null, 2)}\n`);
  } else {
    process.stderr.write(`${formatSummaryText(result)}\n`);
  }

  return 0;
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
    if (args.labels) {
      process.stdout.write(`${formatLabelsTable()}\n`);
      return 0;
    }
    if (args.input === null) {
      parser.errorExit("input is required (or use --labels to list categories)");
    }
    return await run(args);
  } catch (e) {
    if (e instanceof ParseExit) {
      (e.stream === "stdout" ? process.stdout : process.stderr).write(e.text);
      return e.code;
    }
    if (e instanceof SystemExitMessage) {
      process.stderr.write(`${e.messageText}\n`);
      return 1;
    }
    // Python 은 전체 스택 트레이스를 출력하지만 TS 포트는 마지막 예외 줄만 재현한다
    const name = e instanceof Error ? e.name : "Exception";
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`${name}: ${msg}\n`);
    return 1;
  }
}
