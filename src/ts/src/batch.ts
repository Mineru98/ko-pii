/**
 * 배치 / 병렬 처리 — 디렉토리·glob 패턴 일괄 가명화.
 * Python `ko_pii.batch` 1:1 포트.
 *
 * 특징:
 * - Python `multiprocessing.Pool` → Node **worker_threads** 풀 (표준 라이브러리)
 *   워커 스크립트는 ts/src/batchWorker.ts (path 기반 로드)
 * - 진행률 표시 (stderr 라인 갱신, 외부 deps 없이)
 * - 입력 파일별 결과를 *대응되는 출력 경로* 에 기록
 * - Vault: Python 코드는 파일별 신규 vault (요약에 vault 없음) — 기본 동작은
 *   동일하다. ``sharedVault`` 옵션(원본 docstring 의도 — "공유하면 문서 간 토큰
 *   일관성")은 TS 확장으로, workers=1 이면 하나의 vault 를 공유하고 workers>=2
 *   이면 워커별 vault 를 structured clone 으로 수집해 메인에서 병합한다.
 *   Python 과 같은 제약: 워커별 토큰은 워커 지역적이라 병합 vault 토큰이 출력
 *   본문과 어긋날 수 있다 — 토큰 일관성이 필요하면 workers=1 (docstring 권고).
 * - 실패한 파일은 건너뛰고 보고 (전체 작업 중단 X)
 *
 * Usage::
 *
 *     import { processPaths } from "./batch.js";
 *     const summary = await processPaths(["docs/"], "out/", {
 *         mode: ProcessingMode.STRICT, strategy: "tokenize",
 *         recursive: true, workers: 4,
 *     });
 */

import { createHash } from "node:crypto";
import { type Dirent, lstatSync, mkdirSync, readdirSync, readlinkSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, dirname, resolve as pathResolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";
import { riskLevelName } from "./analytics/index.js";
import { Anonymizer } from "./anonymizer.js";
import { ValueError } from "./core/errors.js";
import { Action, ProcessingMode } from "./core/modes.js";
import { pyFormatFixed } from "./core/pyFormat.js";
import { regexEscape } from "./core/strUtils.js";
import { writeTextAtomic } from "./io/atomic.js";
import { BoundedReadError, FileReadPolicy, type FileReadPolicyInit } from "./io/bounded.js";
import type { ExtractionCoverage } from "./io/coverage.js";
import { defaultReadPolicy, readTextIsolated } from "./io/isolated.js";
import { validateLabelFilter } from "./labels.js";
import { normalizeExclusions } from "./patterns/person.js";
import { ReversibleVault, type VaultDict, type VaultEntryDict } from "./vault/reversible.js";

// ─────────────────────────────────────────────────────────────────────
// 결과 구조
// ─────────────────────────────────────────────────────────────────────

/** Python ``batch.FileResult`` 대응. */
export interface FileResult {
  inputPath: string;
  outputPath: string | null;
  detections: number;
  combinedRisk: string;
  blocked: number;
  review: number;
  error: string | null;
  elapsedS: number;
  /** 기계 판독용 실패 코드 (Python ``error_code``). 성공 시 null. */
  errorCode: string | null;
  /** 문서 파트 coverage (Python ``coverage``) — 내용 없음. */
  coverage: ExtractionCoverage | null;
}

/** Python ``batch.BatchSummary`` 대응. ``vault`` 는 sharedVault 옵션일 때만 채워진다. */
export interface BatchSummary {
  totalFiles: number;
  succeeded: number;
  failed: number;
  totalDetections: number;
  totalBlocked: number;
  totalReview: number;
  elapsedS: number;
  results: FileResult[];
  /** 수집 단계에서 건너뛴 경로 (Python ``skipped``). */
  skipped: SkippedInput[];
  vault?: ReversibleVault | null;
}

// ─────────────────────────────────────────────────────────────────────
// 파일 수집
// ─────────────────────────────────────────────────────────────────────

/** Python ``batch.DEFAULT_EXTENSIONS`` 대응. */
export const DEFAULT_EXTENSIONS: ReadonlySet<string> = new Set([
  ".txt",
  ".md",
  ".log",
  ".csv",
  ".tsv",
  ".hwpx",
  ".hwp",
  ".docx",
  ".xlsx",
  ".pdf",
]);

/** Python ``os.path.isfile`` 대응 (symlink 따라감). */
function isFile(p: string): boolean {
  try {
    return statSync(p, { throwIfNoEntry: false })?.isFile() ?? false;
  } catch {
    return false; // Python 은 ENOENT 뿐 아니라 모든 OSError(ELOOP·ENOTDIR·EACCES)를 False 로 본다
  }
}

/** Python ``os.path.isdir`` 대응 (symlink 따라감). */
function isDir(p: string): boolean {
  try {
    return statSync(p, { throwIfNoEntry: false })?.isDirectory() ?? false;
  } catch {
    return false; // symlink 루프(ELOOP) 등 — glob/수집이 예외로 중단되지 않게
  }
}

/** Python ``os.path.splitext`` (posixpath) 1:1 포트. */
export function pySplitExt(p: string): [stem: string, ext: string] {
  const sepIndex = p.lastIndexOf("/");
  const dotIndex = p.lastIndexOf(".");
  if (dotIndex > sepIndex) {
    // 선행 점들은 모두 건너뛴다 (".bashrc" 는 확장자 없음)
    let filenameIndex = sepIndex + 1;
    while (filenameIndex < dotIndex) {
      if (p[filenameIndex] !== ".") {
        return [p.slice(0, dotIndex), p.slice(dotIndex)];
      }
      filenameIndex += 1;
    }
  }
  return [p, ""];
}

/** Python ``sorted(str)`` — 코드 포인트 순 비교 (JS 기본 정렬은 UTF-16 코드 유닛). */
function pyCompare(a: string, b: string): number {
  let i = 0;
  while (i < a.length && i < b.length) {
    const ca = a.codePointAt(i)!;
    const cb = b.codePointAt(i)!;
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
  }
  return a.length - b.length;
}

/** Python ``glob.has_magic`` 대응. */
function hasMagic(s: string): boolean {
  return /[*?[]/.test(s);
}

/**
 * Python ``fnmatch.translate`` (CPython 3.12) 1:1 포트 — STAR 압축, `[...]`
 * 문자 클래스(범위/`!` 부정/빈 클래스/빈 부정), 내부 STAR 는 원자적 최소 매칭
 * `(?>.*?fixed)` (V8 원자 그룹 지원) 까지 재현한다.
 */
export function fnmatchTranslate(pat: string): RegExp {
  const STAR = Symbol("*");
  type Piece = string | typeof STAR;
  const res: Piece[] = [];
  const add = (p: Piece): void => void res.push(p);
  let i = 0;
  const n = pat.length;
  while (i < n) {
    const c = pat[i]!;
    i += 1;
    if (c === "*") {
      // 연속 `*` 는 하나로 압축
      if (res.length === 0 || res[res.length - 1] !== STAR) add(STAR);
    } else if (c === "?") {
      add(".");
    } else if (c === "[") {
      let j = i;
      if (j < n && pat[j] === "!") j += 1;
      if (j < n && pat[j] === "]") j += 1;
      while (j < n && pat[j] !== "]") j += 1;
      if (j >= n) {
        add("\\[");
      } else {
        let stuff = pat.slice(i, j);
        if (!stuff.includes("-")) {
          stuff = stuff.replaceAll("\\", "\\\\");
        } else {
          const chunks: string[] = [];
          let k = pat[i] === "!" ? i + 2 : i + 1;
          let ii = i;
          for (;;) {
            // Python pat.find('-', k, j) — 구간 [k, j) 에서 탐색
            const local = pat.slice(k, j).indexOf("-");
            if (local < 0) break;
            k += local;
            chunks.push(pat.slice(ii, k));
            ii = k + 1;
            k = k + 3;
          }
          const chunk = pat.slice(ii, j);
          if (chunk) chunks.push(chunk);
          else chunks[chunks.length - 1] = `${chunks[chunks.length - 1]!}-`;
          // 빈 범위 제거 — RE 에서 유효하지 않음
          for (let x = chunks.length - 1; x > 0; x--) {
            const prev = chunks[x - 1]!;
            const cur = chunks[x]!;
            if (prev[prev.length - 1]! > cur[0]!) {
              chunks[x - 1] = prev.slice(0, -1) + cur.slice(1);
              chunks.splice(x, 1);
            }
          }
          // 백슬래시와 하이픸 이스케이프 (범위를 만드는 하이픸은 제외)
          stuff = chunks.map((s) => s.replaceAll("\\", "\\\\").replaceAll("-", "\\-")).join("-");
        }
        // 집합 연산 이스케이프 (&&, ~~, ||)
        stuff = stuff.replace(/[&~|]/g, (m) => `\\${m}`);
        i = j + 1;
        if (!stuff) {
          // 빈 클래스: 절대 매칭 없음
          add("(?!)");
        } else if (stuff === "!") {
          // 부정된 빈 클래스: 모든 문자 매칭
          add(".");
        } else {
          if (stuff[0] === "!") stuff = `^${stuff.slice(1)}`;
          else if (stuff[0] === "^" || stuff[0] === "[") stuff = `\\${stuff}`;
          add(`[${stuff}]`);
        }
      }
    } else {
      add(regexEscape(c));
    }
  }

  // STAR 처리 — 내부 `STAR fixed` 는 역추적 없는 최소 매칭
  const inp = res;
  const out: string[] = [];
  const add2 = (s: string): void => void out.push(s);
  let k = 0;
  const m = inp.length;
  while (k < m && inp[k] !== STAR) {
    add2(inp[k] as string);
    k += 1;
  }
  while (k < m) {
    // inp[k] === STAR
    k += 1;
    if (k === m) {
      add2(".*");
      break;
    }
    const fixed: string[] = [];
    while (k < m && inp[k] !== STAR) {
      fixed.push(inp[k] as string);
      k += 1;
    }
    const fixedStr = fixed.join("");
    if (k === m) {
      add2(".*");
      add2(fixedStr);
    } else {
      add2(`(?>.*?${fixedStr})`);
    }
  }
  // Python `(?s:...)\Z` 대응 — JS 는 s 플래그 + 명시적 앵커
  return new RegExp(`^(?:${out.join("")})$`, "s");
}

/**
 * Python ``os.path.join(a, b)`` (posix) — node ``path.join`` 과 달리 정규화하지 않는다
 * ("./in" + "a.txt" → "./in/a.txt", "in//" + "a.txt" → "in//a.txt").
 */
function pathJoin(a: string, b: string): string {
  if (b.startsWith("/")) return b;
  if (a === "" || a.endsWith("/")) return a + b;
  return `${a}/${b}`;
}

/** 숨김 파일 규칙 — Python glob: 패턴 세그먼트가 `.` 로 시작하지 않으면 숨김 제외. */
function isHidden(x: string): boolean {
  return x.startsWith(".");
}

/** 디렉터리 재귀 나열 — Python glob `_rlistdir` (symlink 디렉터리도 따라감). */
function rlistdir(path: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(path === "" ? "." : path);
  } catch {
    return; // OSError → 무시
  }
  for (const name of entries) {
    if (isHidden(name)) continue; // Python _rlistdir: include_hidden=False 면 숨김 제외
    const full = pathJoin(path, name);
    out.push(full);
    if (isDir(full)) rlistdir(full, out);
  }
}

/** 단일 세그먼트 매칭 — Python glob ``_glob1`` (숨김 규칙 + fnmatch filter). */
function globSegment1(dir: string, pattern: string): string[] {
  let names: string[];
  try {
    names = readdirSync(dir === "" ? "." : dir);
  } catch {
    return [];
  }
  if (!isHidden(pattern)) {
    names = names.filter((name) => !isHidden(name));
  }
  const re = fnmatchTranslate(pattern);
  return names.filter((name) => re.test(name)).map((name) => pathJoin(dir, name));
}

/**
 * Python ``glob.glob(pattern, recursive=recursive)`` 축소 1:1 포트.
 * (ko-pii 배치 입력용 — 파일/디렉터리 경로 문자열을 반환한다.)
 */
export function pyGlob(pattern: string, recursive: boolean): string[] {
  const parts = pattern.split("/");
  const isAbsolute = pattern.startsWith("/");
  // 상대 패턴의 base 는 "" — Python glob 처럼 "./" 접두를 원문 그대로 보존한다.
  let base = isAbsolute ? "/" : "";
  let idx = 0;
  // 선행 고정 세그먼트 소비
  for (; idx < parts.length; idx++) {
    const seg = parts[idx]!;
    if (seg === "" && !isAbsolute) continue; // "//" 등 빈 세그먼트 무시
    if (seg === "" && isAbsolute && idx === 0) continue;
    if (hasMagic(seg)) break;
    base = pathJoin(base, seg);
  }
  if (idx >= parts.length) {
    // 매직 없는 패턴 — 존재하면 그대로 (Python glob 계약)
    try {
      return statSync(pattern, { throwIfNoEntry: false }) !== undefined ? [pattern] : [];
    } catch {
      return [];
    }
  }
  if (!isDir(base === "" ? "." : base)) return [];

  let candidates: string[] = [base];
  for (; idx < parts.length; idx++) {
    const seg = parts[idx]!;
    if (seg === "**" && recursive) {
      const expanded: string[] = [];
      for (const dir of candidates) {
        expanded.push(dir);
        rlistdir(dir, expanded);
      }
      candidates = expanded;
      if (idx === parts.length - 1) {
        // `**` 가 마지막이면 모든 하위 항목(파일+디렉터리) 반환
        return [...new Set(candidates)].filter((c) => c !== "");
      }
      continue;
    }
    const matched: string[] = [];
    const seenSeg = new Set<string>();
    for (const dir of candidates) {
      for (const p of globSegment1(dir, seg)) {
        if (!seenSeg.has(p)) {
          seenSeg.add(p);
          matched.push(p);
        }
      }
    }
    if (idx === parts.length - 1) return matched;
    candidates = matched.filter((p) => isDir(p));
  }
  return [];
}

/**
 * Python ``os.walk(top, onerror=...)`` (topdown, followlinks=False) 대응.
 * ``visit(root, dirs, names)`` 가 ``dirs`` 를 제자리 수정하면 하위 탐색이 바뀐다 (Python 과 동일).
 * ``false`` 를 반환하면 탐색을 멈춘다 (``break``).
 */
function osWalk(
  top: string,
  onerror: (path: string) => void,
  visit: (root: string, dirs: string[], names: string[]) => boolean,
): void {
  const stack = [top];
  while (stack.length > 0) {
    const root = stack.pop() as string;
    let entries: Dirent[];
    try {
      entries = readdirSync(root === "" ? "." : root, { withFileTypes: true });
    } catch {
      onerror(root);
      continue;
    }
    const dirs: string[] = [];
    const names: string[] = [];
    for (const entry of entries) {
      // entry.is_dir() 는 symlink 를 따라간다
      const dir =
        entry.isDirectory() || (entry.isSymbolicLink() && isDir(pathJoin(root, entry.name)));
      (dir ? dirs : names).push(entry.name);
    }
    if (!visit(root, dirs, names)) return;
    for (let i = dirs.length - 1; i >= 0; i--) {
      const next = pathJoin(root, dirs[i] as string);
      if (!isLink(next)) stack.push(next);
    }
  }
}

/** Python ``os.path.islink`` 대응. */
function isLink(p: string): boolean {
  try {
    return lstatSync(p, { throwIfNoEntry: false })?.isSymbolicLink() ?? false;
  } catch {
    return false;
  }
}

/** Python ``posixpath.split`` 대응. */
function pySplit(p: string): [string, string] {
  const i = p.lastIndexOf("/") + 1;
  let head = p.slice(0, i);
  const tail = p.slice(i);
  if (head && head !== "/".repeat(head.length)) head = head.replace(/\/+$/, "");
  return [head, tail];
}

function joinRealpath(
  start: string,
  restIn: string,
  seen: Map<string, string | null>,
): [string, boolean] {
  let path = start;
  let rest = restIn;
  if (rest.startsWith("/")) {
    rest = rest.slice(1);
    path = "/";
  }
  while (rest) {
    const i = rest.indexOf("/");
    const name = i < 0 ? rest : rest.slice(0, i);
    rest = i < 0 ? "" : rest.slice(i + 1);
    if (!name || name === ".") continue;
    if (name === "..") {
      if (path) {
        const [head, tail] = pySplit(path);
        path = tail === ".." ? pathJoin(pathJoin(head, ".."), "..") : head;
      } else {
        path = "..";
      }
      continue;
    }
    const newpath = pathJoin(path, name);
    if (!isLink(newpath)) {
      path = newpath;
      continue;
    }
    if (seen.has(newpath)) {
      const known = seen.get(newpath);
      if (known !== null && known !== undefined) {
        path = known;
        continue;
      }
      return [pathJoin(newpath, rest), false]; // symlink 루프 — 비엄격 모드는 그대로 반환
    }
    seen.set(newpath, null);
    let target: string;
    try {
      target = readlinkSync(newpath);
    } catch {
      path = newpath;
      continue;
    }
    const [resolved, ok] = joinRealpath(path, target, seen);
    if (!ok) return [pathJoin(resolved, rest), false];
    path = resolved;
    seen.set(newpath, path);
  }
  return [path, true];
}

/**
 * Python ``os.path.realpath`` (posix, strict=False) 1:1 포트 — 존재하지 않는 꼬리도 허용하고
 * 대소문자를 바꾸지 않는다 (``fs.realpathSync`` 는 존재하지 않는 경로에서 실패한다).
 * @internal
 */
export function pyRealpath(p: string): string {
  const [path] = joinRealpath("", p, new Map());
  return pathResolve(path || ".");
}

/** Python ``PurePath.is_relative_to`` (realpath 결과끼리 비교). @internal */
export function isRelativeTo(path: string, root: string): boolean {
  if (path === root) return true;
  return path.startsWith(root.endsWith("/") ? root : `${root}/`);
}

/** Python ``os.path.samefile`` — 둘 다 존재할 때만 호출한다. @internal */
export function sameFile(a: string, b: string): boolean {
  try {
    const x = statSync(a);
    const y = statSync(b);
    return x.dev === y.dev && x.ino === y.ino;
  } catch {
    return false;
  }
}

/** Python ``os.path.exists`` (symlink 를 따라간다). @internal */
export function pathExists(p: string): boolean {
  try {
    return statSync(p, { throwIfNoEntry: false }) !== undefined;
  } catch {
    return false;
  }
}

/** 배치 입력 수집에서 건너뛴 경로 (Python ``BatchSummary.skipped`` 항목). */
export interface SkippedInput {
  input_path: string;
  reason: string;
}

function failedResult(path: string, code: string): FileResult {
  return {
    inputPath: path,
    outputPath: null,
    detections: 0,
    combinedRisk: "UNKNOWN",
    blocked: 0,
    review: 0,
    error: code,
    elapsedS: 0,
    errorCode: code,
    coverage: null,
  };
}

/**
 * 입력 경로(파일·디렉토리·glob) 를 모두 풀어 파일 목록을 반환.
 * Python ``batch.collect_files`` 1:1 포트.
 */
export function collectFiles(
  inputs: Iterable<string>,
  recursive = true,
  extensions?: ReadonlySet<string> | null,
): string[] {
  return collectInputs(inputs, recursive, extensions ?? null).files;
}

/** Python ``batch._collect_inputs`` 1:1 포트. */
function collectInputs(
  inputs: Iterable<string>,
  recursive: boolean,
  extensions: ReadonlySet<string> | null,
  options: { outputRoot?: string | null; allowEmpty?: boolean } = {},
): { files: string[]; errors: FileResult[]; skipped: SkippedInput[] } {
  const outputRoot = options.outputRoot ?? null;
  const allowEmpty = options.allowEmpty ?? false;
  // Python: `extensions if extensions is not None else DEFAULT_EXTENSIONS` — 빈 집합은 그대로.
  const exts = extensions ?? DEFAULT_EXTENSIONS;
  const seen = new Set<string>();
  const out: string[] = [];
  const errors: FileResult[] = [];
  const skipped: SkippedInput[] = [];

  const fail = (path: string, code: string): void => {
    errors.push(failedResult(path, code));
  };
  const excluded = (path: string): boolean =>
    outputRoot !== null && isRelativeTo(pyRealpath(path), outputRoot);

  const add = (path: string, explicit: boolean): number => {
    if (excluded(path)) {
      skipped.push({ input_path: path, reason: "output_directory" });
      return 0;
    }
    if (!isFile(path)) {
      fail(path, "file_unavailable");
      return 0;
    }
    if (!exts.has(pySplitExt(path)[1].toLowerCase())) {
      if (explicit) fail(path, "unsupported_extension");
      else skipped.push({ input_path: path, reason: "unsupported_extension" });
      return 0;
    }
    const key = pathResolve(path); // normcase(abspath) — posix normcase 는 항등
    if (!seen.has(key)) {
      seen.add(key);
      out.push(path);
    }
    return 1;
  };

  const visit = (path: string): void => {
    if (excluded(path)) {
      skipped.push({ input_path: path, reason: "output_directory" });
      return;
    }
    if (!isDir(path)) {
      add(path, true);
      return;
    }
    let count = 0;
    const beforeErrors = errors.length;
    osWalk(
      path,
      (failed) => fail(failed || path, "directory_unavailable"),
      (root, dirs, names) => {
        for (const directory of [...dirs]) {
          const candidate = pathJoin(root, directory);
          if (excluded(candidate) || isLink(candidate)) {
            dirs.splice(dirs.indexOf(directory), 1);
            skipped.push({ input_path: candidate, reason: "directory_not_traversed" });
          }
        }
        for (const name of names) count += add(pathJoin(root, name), false);
        return recursive;
      },
    );
    if (!count && errors.length === beforeErrors && !allowEmpty) fail(path, "no_input_files");
  };

  for (const item of inputs) {
    if (hasMagic(item)) {
      const matches = pyGlob(item, recursive);
      if (matches.length === 0 && !allowEmpty) fail(item, "glob_no_matches");
      for (const match of matches) visit(match);
    } else {
      visit(item);
    }
  }
  if (out.length === 0 && errors.length === 0 && !allowEmpty) fail("(batch)", "no_input_files");
  return { files: out.sort(pyCompare), errors, skipped };
}

// ─────────────────────────────────────────────────────────────────────
// 단일 파일 처리 (워커 진입점)
// ─────────────────────────────────────────────────────────────────────

/** Python ``_process_single`` 인자 튜플 대응 (worker_threads 메시지 페이로드). */
export interface WorkerTask {
  inputPath: string;
  outputPath: string;
  /** ProcessingMode 값 문자열 — 유효하지 않으면 파일별 에러 결과 (Python PM(mode) 동일). */
  mode: string;
  strategy: string;
  include: string[] | null;
  exclude: string[] | null;
  /** 정규화·정렬된 PERSON 제외어 (Python ``tuple(sorted(normalized_exclusions))``). */
  personExclusions: string[];
  /** 구조화 복제 가능한 읽기 정책 (Python ``FileReadPolicy``). */
  readPolicy: Required<FileReadPolicyInit>;
  /** 파일별 추출 시간 한도(초). */
  extractionTimeout: number;
  /** sharedVault + 멀티워커: 워커 vault 가 쓸 고정 salt (지문 일관성). */
  vaultSalt: string | null;
}

export interface SingleResult {
  result: FileResult;
  /** sharedVault + 멀티워커일 때만 수집 (structured clone 가능한 vault 사전). */
  vaultDict: VaultDict | null;
}

/** Python ``ValueError: '<v>' is not a valid ProcessingMode`` 대응. */
function toProcessingMode(value: string): ProcessingMode {
  if (!(Object.values(ProcessingMode) as string[]).includes(value)) {
    throw new ValueError(`'${value}' is not a valid ProcessingMode`);
  }
  return value as ProcessingMode;
}

const ERRNO_CLASSES: Readonly<Record<string, string>> = {
  ENOENT: "FileNotFoundError",
  EACCES: "PermissionError",
  EPERM: "PermissionError",
  EEXIST: "FileExistsError",
  EISDIR: "IsADirectoryError",
  ENOTDIR: "NotADirectoryError",
};

/** Node 시스템 오류(errno 코드 보유) 여부 — Python ``OSError`` 대응. @internal */
export function isOsError(error: unknown): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    typeof (error as NodeJS.ErrnoException).code === "string" &&
    typeof (error as NodeJS.ErrnoException).errno === "number"
  );
}

/** Python ``type(e).__name__`` 대응 — Node errno 오류는 OSError 하위 클래스명으로. @internal */
export function pyExceptionName(error: unknown): string {
  if (isOsError(error)) return ERRNO_CLASSES[error.code as string] ?? "OSError";
  if (error instanceof SyntaxError) return "JSONDecodeError";
  if (error instanceof Error) return error.name || "Exception";
  return "Exception";
}

/**
 * 단일 파일 처리 — Python ``batch._process_single`` 1:1 포트.
 * 추출은 격리 워커(``readTextIsolated``)에서 한도·시간 제한과 함께 수행한다.
 * 예외는 잡아 FileResult.error 로 보고한다 (전체 작업 중단 X). 원문을 담을 수 있는 예외
 * 메시지는 내보내지 않는다 — BoundedReadError 만 메시지를 그대로 쓴다.
 */
export async function processSingle(
  task: WorkerTask,
  sharedVault: ReversibleVault | null = null,
): Promise<SingleResult> {
  const t0 = performance.now();
  const { inputPath, outputPath } = task;
  try {
    const document = await readTextIsolated(inputPath, {
      policy: new FileReadPolicy(task.readPolicy),
      timeout: task.extractionTimeout,
    });
    const anon = new Anonymizer(
      toProcessingMode(task.mode),
      task.strategy,
      sharedVault ?? (task.vaultSalt ? new ReversibleVault({ salt: task.vaultSalt }) : undefined),
      task.include,
      task.exclude,
      null,
      "union",
      null,
      task.personExclusions,
    );
    const result = anon.process(document.text);

    if (outputPath) {
      mkdirSync(dirname(outputPath) || ".", { recursive: true });
      writeTextAtomic(outputPath, result.text);
    }

    const nBlock = result.detections.filter((r) => r.action === Action.BLOCK).length;
    const nReview = result.detections.filter((r) => r.action === Action.REVIEW).length;
    return {
      result: {
        inputPath,
        outputPath,
        detections: result.detections.length,
        combinedRisk: result.combined_risk
          ? riskLevelName(result.combined_risk.combined_risk)
          : "INFO",
        blocked: nBlock,
        review: nReview,
        error: null,
        elapsedS: (performance.now() - t0) / 1000,
        errorCode: null,
        coverage: document.coverage,
      },
      // 멀티워커 sharedVault 일 때만 워커 vault 를 사전으로 수집
      vaultDict: task.vaultSalt !== null ? (result.vault?.toDict() ?? null) : null,
    };
  } catch (error) {
    const bounded = error instanceof BoundedReadError;
    return {
      result: {
        inputPath,
        outputPath: null,
        detections: 0,
        combinedRisk: "UNKNOWN",
        blocked: 0,
        review: 0,
        error: bounded ? error.message : `${pyExceptionName(error)}: processing failed`,
        elapsedS: (performance.now() - t0) / 1000,
        errorCode: bounded ? error.code : "processing_failed",
        coverage: bounded ? error.coverage : null,
      },
      vaultDict: null,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────
// 진행률 표시
// ─────────────────────────────────────────────────────────────────────

function printProgress(done: number, total: number, r: FileResult): void {
  const pct = total ? (100 * done) / total : 100;
  const name = basename(r.inputPath).slice(0, 40);
  const status = r.error ? "ERR" : `${r.detections}d/${r.blocked}b/${r.review}r`;
  process.stderr.write(
    `\r[${done}/${total}] ${pyFormatFixed(pct, 1).padStart(5)}%  ${name.padEnd(40)}  ${status.padEnd(20)}`,
  );
}

// ─────────────────────────────────────────────────────────────────────
// 공개 진입점
// ─────────────────────────────────────────────────────────────────────

/** Python ``str.casefold`` 근사 — 특수 확장 문자(ß→ss 등)는 대문자 경유로 접는다. */
function caseFold(s: string): string {
  return s.toUpperCase().toLowerCase();
}

/** Python ``batch._output_path_for`` 1:1 포트. */
export function outputPathFor(inputPath: string, outputDir: string, suffix = ""): string {
  const name = basename(inputPath);
  const [stem] = pySplitExt(name);
  return pathJoin(outputDir, `${stem}${suffix}.txt`);
}

export interface ProcessPathsOptions {
  mode?: ProcessingMode | string;
  strategy?: string;
  recursive?: boolean;
  workers?: number;
  include?: Iterable<string> | null;
  exclude?: Iterable<string> | null;
  /** PERSON 검출에서 제외할 도메인 용어 (Python ``person_exclusions``). */
  personExclusions?: Iterable<string> | null;
  extensions?: ReadonlySet<string> | null;
  progress?: boolean;
  /** 파일·압축·텍스트 한도 (기본 ``defaultReadPolicy()``). */
  readPolicy?: FileReadPolicy | null;
  /** 파일별 추출 시간 한도(초, 기본 30). 유한한 양수. */
  extractionTimeout?: number;
  /** 빈 디렉터리·매칭 없는 glob 을 실패로 보지 않는다 (명시 파일 누락은 여전히 실패). */
  allowEmpty?: boolean;
  /** 예정 출력과 충돌하면 모든 쓰기 전에 거부할 설정 파일 경로. */
  protectedPaths?: Iterable<string>;
  /**
   * TS 확장 — 문서 간 토큰 일관성 (원본 모듈 docstring 의도).
   * - workers<=1: 하나의 vault 를 모든 파일이 공유 (토큰 일관).
   * - workers>=2: 워커별 vault (고정 salt) → 결과에서 vault 를 structured clone
   *   으로 수집해 메인에서 병합. Python 의 워커별 vault 제약과 동일하게 워커 지역
   *   토큰은 본문과 어긋날 수 있다 — 토큰 일관성이 필요하면 workers=1.
   * 기본 false (Python 코드 동작 — 파일별 신규 vault, 요약에 vault 없음).
   */
  sharedVault?: boolean;
}

interface PoolOutcome {
  results: FileResult[];
  vaultDicts: VaultDict[];
}

/**
 * worker_threads 풀 — Python ``Pool(imap_unordered)`` 대응.
 * 결과는 *완료 순서* 로 수집되고 각 완료마다 진행률을 출력한다.
 */
function runPool(
  tasks: WorkerTask[],
  size: number,
  progress: boolean,
  total: number,
): Promise<PoolOutcome> {
  // Python Pool 은 빈 iterable 에 즉시 끝난다 — 워커가 0개면 exit 이벤트도 없어 영원히 미해결.
  if (tasks.length === 0) return Promise.resolve({ results: [], vaultDicts: [] });
  return new Promise<PoolOutcome>((resolve, reject) => {
    // 소스 실행(.ts, tsx 로더 필요) 과 빌드 산출물(dist/batchWorker.mjs|cjs) 을 구분한다.
    const selfExt = /\.[cm]?[jt]s$/.exec(new URL(import.meta.url).pathname)?.[0] ?? ".ts";
    const fromSource = selfExt.endsWith("ts");
    const workerPath = new URL(`./batchWorker${selfExt}`, import.meta.url);
    const results: FileResult[] = [];
    const vaultDicts: VaultDict[] = [];
    const workers: Worker[] = [];
    let next = 0;
    let done = 0;
    let exited = 0;
    let settled = false;

    const tryResolve = (): void => {
      if (settled && exited === workers.length) {
        resolve({ results, vaultDicts });
      }
    };

    const spawnWorker = (): void => {
      const w = new Worker(workerPath, fromSource ? { execArgv: workerExecArgv() } : {});
      workers.push(w);
      w.on(
        "message",
        (msg: { kind: string; result?: FileResult; vaultDict?: VaultDict | null }) => {
          if (msg.kind !== "result" || !msg.result) return;
          results.push(msg.result);
          if (msg.vaultDict) vaultDicts.push(msg.vaultDict);
          done += 1;
          if (progress) printProgress(done, total, msg.result);
          if (done === tasks.length) {
            settled = true;
            for (const worker of workers) worker.postMessage({ kind: "end" });
          }
          if (next < tasks.length) {
            w.postMessage({ kind: "task", task: tasks[next++] });
          } else {
            w.postMessage({ kind: "end" });
          }
        },
      );
      w.on("error", (err) => {
        // 워커 프로세스 자체의 비정상 종료 — Python Pool 크래시에 해당
        settled = true;
        reject(err);
      });
      w.on("exit", () => {
        exited += 1;
        tryResolve();
      });
      if (next < tasks.length) {
        w.postMessage({ kind: "task", task: tasks[next++] });
      }
    };

    for (let i = 0; i < Math.min(size, tasks.length); i++) spawnWorker();
  });
}

let cachedExecArgv: string[] | null = null;
/**
 * 워커가 .ts 소스(및 .js→.ts 확장 매핑)를 로드하려면 tsx 로더가 필요하다
 * (Node 네이티브 타입 스트리핑은 확장 매핑이 없다). tsx 가 resolvable 하면
 * 절대 file URL 로 로더를 명시하고, 아니면 부모 execArgv 상속에 위임한다.
 */
function workerExecArgv(): string[] | undefined {
  if (cachedExecArgv === null) {
    try {
      const require = createRequire(import.meta.url);
      const loader = require.resolve("tsx");
      cachedExecArgv = ["--import", pathToFileURL(loader).href];
    } catch {
      cachedExecArgv = [];
    }
  }
  return cachedExecArgv.length > 0 ? cachedExecArgv : undefined;
}

/**
 * 워커 vault 사전 병합 — sharedVault + workers>=2 에서 메인이 수행한다.
 * - 같은 (label, original) 은 첫 토큰으로 통합 (중복 제거)
 * - 워커 지역 토큰(`<LABEL_N>`) 충돌은 카운터를 이어받아 새 토큰으로 재배정
 *   (출력 본문의 워커 지역 토큰과 어긋날 수 있음 — docstring 제약, workers=1 권장)
 */
function mergeVaultDicts(dicts: VaultDict[]): ReversibleVault | null {
  const nonEmpty = dicts.filter((d) => Object.keys(d.entries).length > 0);
  if (nonEmpty.length === 0) return null;

  // 전체 토큰 카운터 최댓값 선스캔 — 재배정이 기존 토큰을 피하도록
  const maxCounter = new Map<string, number>();
  for (const dict of nonEmpty) {
    for (const [token, entry] of Object.entries(dict.entries)) {
      const m = /_(\d+)>$/.exec(token);
      const n = m === null ? null : Number.parseInt(m[1]!, 10);
      if (n !== null && n > (maxCounter.get(entry.label) ?? 0)) maxCounter.set(entry.label, n);
    }
  }

  const entries: Record<string, VaultEntryDict> = {};
  const byOriginal = new Map<string, string>();
  const usedTokens = new Set<string>();
  for (const dict of nonEmpty) {
    for (const [token, entry] of Object.entries(dict.entries)) {
      const key = `${entry.label}\u0000${entry.original}`;
      if (byOriginal.has(key)) continue; // 같은 원본은 첫 토큰으로 통합
      let finalToken = token;
      while (usedTokens.has(finalToken)) {
        const next = (maxCounter.get(entry.label) ?? 0) + 1;
        maxCounter.set(entry.label, next);
        finalToken = `<${entry.label}_${next}>`;
      }
      entries[finalToken] = entry;
      byOriginal.set(key, finalToken);
      usedTokens.add(finalToken);
    }
  }

  const base = nonEmpty[0]!;
  return ReversibleVault.fromDict({ ...base, entries });
}

/**
 * 입력 파일·디렉토리·glob 들을 일괄 처리. Python ``batch.process_paths`` 1:1 포트
 * (multiprocessing → worker_threads, async).
 *
 * Notes:
 * -----
 * 워커 수와 관계없이 파일마다 별도 Anonymizer/Vault 를 사용한다 (sharedVault TS 확장 제외).
 * 문서 간 토큰 일관성이나 감사 가능한 가역 Vault 가 필요하면 단일 파일 API 를 사용한다.
 * protectedPaths 의 설정 파일과 예정 출력이 충돌하면 모든 쓰기 전에 거부한다.
 */
export async function processPaths(
  inputs: Iterable<string>,
  outputDir: string,
  options: ProcessPathsOptions = {},
): Promise<BatchSummary> {
  const {
    mode = ProcessingMode.STRICT,
    strategy = "tokenize",
    recursive = true,
    workers = 1,
    include = null,
    exclude = null,
    personExclusions = null,
    extensions = null,
    progress = true,
    readPolicy = null,
    extractionTimeout = 30.0,
    allowEmpty = false,
    protectedPaths = [],
    sharedVault = false,
  } = options;
  const modeValue = typeof mode === "string" ? mode : (mode as string);
  // Python 은 mode.value 접근에서 잘못된 모드에 즉시 실패한다 (파일별 에러가 아니라
  // 호출 수준 예외) — 진입 시 동일하게 검증한다.
  if (!(Object.values(ProcessingMode) as string[]).includes(modeValue)) {
    throw new ValueError(`'${modeValue}' is not a valid ProcessingMode`);
  }
  const normalizedExclusions = normalizeExclusions(personExclusions);
  const includeValues = validateLabelFilter(include, "include");
  const excludeValues = validateLabelFilter(exclude, "exclude");
  if (
    !Number.isInteger(workers) ||
    workers < 1 ||
    typeof extractionTimeout !== "number" ||
    !Number.isFinite(extractionTimeout) ||
    extractionTimeout <= 0
  ) {
    throw new ValueError("workers and extraction timeout must be positive");
  }
  const inputValues = [...inputs];
  const protectedReal = [...protectedPaths].map((p) => pyRealpath(p));
  const outputRoot = pyRealpath(outputDir);
  for (const value of inputValues) {
    if (isRelativeTo(pyRealpath(value), outputRoot)) {
      throw new ValueError("output directory must differ from and must not contain an input path");
    }
  }
  const collected = collectInputs(inputValues, recursive, extensions, { outputRoot, allowEmpty });
  const files = collected.files;
  const summary: BatchSummary = {
    totalFiles: files.length + collected.errors.length,
    succeeded: 0,
    failed: 0,
    totalDetections: 0,
    totalBlocked: 0,
    totalReview: 0,
    elapsedS: 0,
    results: [],
    skipped: collected.skipped,
    vault: null,
  };
  const t0 = performance.now();
  const policyInit = (readPolicy ?? defaultReadPolicy()).toInit();
  const exclusionList = [...normalizedExclusions].sort(pyCompare);

  // 출력 경로 유일성 보장 — 서로 다른 디렉토리의 동명 파일이 같은
  // out/<stem>.txt 로 충돌해 마지막 결과가 이전 결과를 덮어쓰던 데이터 손실
  // 방지 (#12). 첫 파일은 <stem>.txt 유지, 충돌 시에만 입력경로 해시 부여.
  // 대소문자 무시 파일시스템을 위해 casefold 로 비교한다.
  const seenOut = new Set<string>();
  const tasks: WorkerTask[] = [];
  const sharedSalt = sharedVault && workers > 1 ? new ReversibleVault().salt : null;
  for (const f of files) {
    let outPath = outputPathFor(f, outputDir);
    if (seenOut.has(caseFold(outPath))) {
      const [stem, ext] = pySplitExt(outPath);
      const h = createHash("sha1").update(pathResolve(f), "utf8").digest("hex").slice(0, 8);
      outPath = `${stem}_${h}${ext}`;
      let number = 2;
      while (seenOut.has(caseFold(outPath))) {
        outPath = `${stem}_${h}_${number}${ext}`;
        number += 1;
      }
    }
    seenOut.add(caseFold(outPath));
    for (const path of protectedReal) {
      if (
        pyRealpath(outPath) === path ||
        (pathExists(outPath) && pathExists(path) && sameFile(outPath, path))
      ) {
        throw new ValueError("batch output conflicts with a protected configuration file");
      }
    }
    tasks.push({
      inputPath: f,
      outputPath: outPath,
      mode: modeValue,
      strategy,
      include: includeValues,
      exclude: excludeValues,
      personExclusions: exclusionList,
      readPolicy: policyInit,
      extractionTimeout,
      vaultSalt: sharedVault && workers > 1 ? sharedSalt : null,
    });
  }

  let results: FileResult[];
  let vaultDicts: VaultDict[] = [];
  const sharedInstance = sharedVault && workers <= 1 ? new ReversibleVault() : null;
  if (workers <= 1) {
    results = [];
    for (let i = 0; i < tasks.length; i++) {
      const { result } = await processSingle(tasks[i]!, sharedInstance);
      results.push(result);
      if (progress) printProgress(i + 1, files.length, result);
    }
  } else {
    const outcome = await runPool(tasks, workers, progress, files.length);
    results = outcome.results;
    vaultDicts = outcome.vaultDicts;
  }

  for (const r of [...collected.errors, ...results]) {
    summary.results.push(r);
    if (r.error) {
      summary.failed += 1;
    } else {
      summary.succeeded += 1;
      summary.totalDetections += r.detections;
      summary.totalBlocked += r.blocked;
      summary.totalReview += r.review;
    }
  }

  summary.elapsedS = (performance.now() - t0) / 1000;
  if (progress) {
    process.stderr.write("\n");
  }
  if (sharedVault) {
    summary.vault = workers <= 1 ? sharedInstance : mergeVaultDicts(vaultDicts);
  }
  return summary;
}
