/**
 * Bounded document extraction for untrusted ingestion paths.
 * Python `ko_pii.io_.bounded` 1:1 포트.
 *
 * 악성 입력 방어 게이트 — 부정 사례(파일 크기/형식 불일치/zip bomb/DTD/심링크/
 * 경로 역주행/원본 변경)에서 Python 과 동일한 코드로 거부한다.
 *
 * zip 처리: Python zipfile 의 판정을 옮긴 파서(zipFile.ts)를 일반 추출 경로와 공유한다 —
 * 검증기와 추출기가 같은 바이트를 같은 규칙으로 본다. Python 실측 시맨틱:
 * - 시그니처 검사는 `zipfile.is_zipfile` 과 동일하게 EOCD 레코드 존재만 본다.
 *   CD 가 손상된 아카이브는 시그니처( format_mismatch) 가 아니라 아카이브 검증
 *   단계에서 invalid_archive 로 거부된다 (Python 실측).
 * - 멤버 읽기는 CRC-32 를 검증한다 (ZipFile.read → BadZipFile → invalid_archive).
 * - inflate 자체가 실패하는 손상 스트림은 Python 이 zlib.error 를 그대로 던지듯
 *   ZlibError 로 전파한다 (bounded except 절에 없어서 탈출하는 실측 동작).
 *
 * 텍스트 추출: docx/xlsx/hwpx 는 파트별 coverage 를 내는 inspectText 로 읽고 실패 파트가
 * 있으면 document_extraction_incomplete 로 거부한다. 그 밖의 포맷은 dispatcher.readText 로
 * 위임한다. 모든 포맷에 text_normalizer 정규화가 적용된다.
 */

import { createHash } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { lstatSync, readFileSync, statSync } from "node:fs";
import { extname } from "node:path";
import { ValueError } from "../core/errors.js";
import { codePointLength } from "../core/strUtils.js";
import type { ExtractionCoverage } from "./coverage.js";
import { DocumentExtractionError } from "./coverage.js";
import { readText as dispatcherReadText } from "./dispatcher.js";
import { inspectText as inspectDocx } from "./docx.js";
import { inspectText as inspectHwpx } from "./hwpx.js";
import { PdfExtractionError } from "./pdf.js";
import { TextDecodingError } from "./plain.js";
import { pyIsBlank } from "./pyStr.js";
import { normalizeForDetection } from "./textNormalizer.js";
import { inspectText as inspectXlsx } from "./xlsx.js";
import { hasDoctypeDeclaration } from "./xmlEt.js";
import type { ZipEntryInfo } from "./zipFile.js";
import { isZipfileEocd, parseCentralDirectory, readZipEntry, ZlibError } from "./zipFile.js";

// 기존 공개 API 유지 — zip 파서는 비-bounded 추출 경로와 공유하려고 zipFile.ts 로 옮겼다.
export { ZlibError };

export const DEFAULT_BOUNDED_EXTENSIONS: readonly string[] = [
  ".txt",
  ".md",
  ".log",
  ".csv",
  ".tsv",
  ".hwpx",
  ".docx",
  ".xlsx",
];
const ZIP_EXTENSIONS: ReadonlySet<string> = new Set([".hwpx", ".docx", ".xlsx"]);
const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([...ZIP_EXTENSIONS, ".pdf", ".hwp"]);
const OLE_SIGNATURE = Buffer.from("d0cf11e0a1b11ae1", "hex");

/** Machine-readable rejection raised before content reaches a guard. */
export class BoundedReadError extends ValueError {
  readonly code: string;
  /** 문서 파트 coverage (내용 없음) — 파트 추출 실패에서만 채워진다. */
  readonly coverage: ExtractionCoverage | null;

  constructor(
    code: string,
    message: string,
    options: { coverage?: ExtractionCoverage | null } = {},
  ) {
    super(message);
    this.name = "BoundedReadError";
    this.code = code;
    this.coverage = options.coverage ?? null;
  }
}

function reject(code: string, message: string): never {
  throw new BoundedReadError(code, message);
}

export interface FileReadPolicyInit {
  maxFileBytes?: number;
  maxArchiveMembers?: number;
  maxArchiveMemberBytes?: number;
  maxDecompressedBytes?: number;
  maxCompressionRatio?: number;
  maxTextChars?: number;
  allowedExtensions?: readonly string[];
  rejectSymlinks?: boolean;
}

/** Resource and format limits for one untrusted document. */
export class FileReadPolicy {
  readonly maxFileBytes: number;
  readonly maxArchiveMembers: number;
  readonly maxArchiveMemberBytes: number;
  readonly maxDecompressedBytes: number;
  readonly maxCompressionRatio: number;
  readonly maxTextChars: number;
  readonly allowedExtensions: readonly string[];
  readonly rejectSymlinks: boolean;

  constructor(init: FileReadPolicyInit = {}) {
    // `??` 가 아니라 undefined 만 기본값으로 — Python 은 None 을 명시하면 거부한다.
    const pick = <T>(value: T | undefined, fallback: T): T =>
      value === undefined ? fallback : value;
    this.maxFileBytes = pick(init.maxFileBytes, 16 * 1024 * 1024);
    this.maxArchiveMembers = pick(init.maxArchiveMembers, 2_048);
    this.maxArchiveMemberBytes = pick(init.maxArchiveMemberBytes, 16 * 1024 * 1024);
    this.maxDecompressedBytes = pick(init.maxDecompressedBytes, 64 * 1024 * 1024);
    this.maxCompressionRatio = pick(init.maxCompressionRatio, 200.0);
    this.maxTextChars = pick(init.maxTextChars, 2_000_000);
    this.allowedExtensions = pick(init.allowedExtensions, DEFAULT_BOUNDED_EXTENSIONS);
    this.rejectSymlinks = pick(init.rejectSymlinks, true);

    // 런타임 값은 타입 선언을 믿지 않는다 (JS 호출자·CLI·워커 경계) — Python __post_init__ 대응.
    const integerLimits: unknown[] = [
      this.maxFileBytes,
      this.maxArchiveMembers,
      this.maxArchiveMemberBytes,
      this.maxDecompressedBytes,
      this.maxTextChars,
    ];
    if (
      integerLimits.some(
        (value) => typeof value !== "number" || !Number.isInteger(value) || value < 1,
      )
    ) {
      throw new ValueError("all bounded-read limits must be positive integers");
    }
    const ratio: unknown = this.maxCompressionRatio;
    if (typeof ratio !== "number" || !Number.isFinite(ratio) || ratio < 1.0) {
      throw new ValueError("max_compression_ratio must be finite and at least 1.0");
    }
    const extensions: unknown = this.allowedExtensions;
    if (!extensions || (Array.isArray(extensions) && extensions.length === 0)) {
      throw new ValueError("allowed_extensions must not be empty");
    }
    if (
      !Array.isArray(extensions) ||
      extensions.some((value) => typeof value !== "string" || !value.startsWith("."))
    ) {
      throw new ValueError("allowed_extensions entries must start with '.'");
    }
    if (typeof (this.rejectSymlinks as unknown) !== "boolean") {
      throw new ValueError("reject_symlinks must be a boolean");
    }
  }

  /** 구조화 복제 가능한 초기값 — Python `asdict(policy)` 대응 (격리 워커 전달용). */
  toInit(): Required<FileReadPolicyInit> {
    return {
      maxFileBytes: this.maxFileBytes,
      maxArchiveMembers: this.maxArchiveMembers,
      maxArchiveMemberBytes: this.maxArchiveMemberBytes,
      maxDecompressedBytes: this.maxDecompressedBytes,
      maxCompressionRatio: this.maxCompressionRatio,
      maxTextChars: this.maxTextChars,
      allowedExtensions: [...this.allowedExtensions],
      rejectSymlinks: this.rejectSymlinks,
    };
  }
}

/** Extracted text plus provenance that contains no document content. */
export interface BoundedDocument {
  text: string;
  sha256: string;
  sizeBytes: number;
  extension: string;
  archiveMembers: number;
  declaredDecompressedBytes: number;
  /** docx/xlsx/hwpx 의 파트 coverage. 그 밖의 포맷은 null. */
  coverage: ExtractionCoverage | null;
}

// ---------------------------------------------------------------------------
// 검증 단계 (Python bounded.py 함수 대응)
// ---------------------------------------------------------------------------

interface PathValidation {
  stat: BigIntStats;
  extension: string;
}

/** Python `path.stat()` 을 `except OSError` 로 감싼 것과 같다 — 어떤 실패든 undefined. */
function statPath(path: string): BigIntStats | undefined {
  try {
    return statSync(path, { bigint: true, throwIfNoEntry: false }) as BigIntStats | undefined;
  } catch {
    return undefined; // ENOTDIR / EACCES / ELOOP …
  }
}

/** Python `Path.is_symlink()` — lstat 이 실패하면(OSError) False. */
function isSymlink(path: string): boolean {
  try {
    return lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink() === true;
  } catch {
    return false;
  }
}

function validatePath(path: string, policy: FileReadPolicy): PathValidation {
  if (policy.rejectSymlinks && isSymlink(path)) {
    reject("symlink_rejected", "symbolic links are not accepted");
  }
  const before = statPath(path);
  if (before === undefined) {
    reject("file_unavailable", "document is not an accessible file");
  }
  if (!before.isFile()) {
    reject("not_regular_file", "document must be a regular file");
  }
  if (before.size > BigInt(policy.maxFileBytes)) {
    reject("file_too_large", "document exceeds max_file_bytes");
  }
  let extension = extname(path).toLowerCase();
  if (extension === ".") extension = ""; // Python Path("a.").suffix == ""
  const allowed = new Set([...policy.allowedExtensions].map((value) => value.toLowerCase()));
  if (!allowed.has(extension)) {
    reject("unsupported_extension", "document extension is not allowed");
  }
  return { stat: before, extension };
}

function validateSignature(buf: Buffer, extension: string): void {
  const prefix = buf.subarray(0, 8);
  if (ZIP_EXTENSIONS.has(extension)) {
    // Python `zipfile.is_zipfile` — EOCD 존재만 본다. CD 손상은
    // validateArchive 단계에서 invalid_archive 로 거부된다 (Python 실측).
    if (!isZipfileEocd(buf)) {
      reject("format_mismatch", "archive extension does not match file content");
    }
  } else if (
    extension === ".pdf" &&
    !prefix.subarray(0, 5).toString("latin1").startsWith("%PDF-")
  ) {
    reject("format_mismatch", "PDF extension does not match file content");
  } else if (extension === ".hwp" && !prefix.equals(OLE_SIGNATURE)) {
    reject("format_mismatch", "HWP extension does not match file content");
  } else if (!BINARY_EXTENSIONS.has(extension) && prefix.includes(0)) {
    reject("format_mismatch", "text input contains a binary signature");
  }
}

function safeArchiveName(name: string): string {
  const normalized = name.replaceAll("\\", "/");
  // Python `PurePosixPath(name).parts` — 빈 조각과 "." 조각은 버려진다. 그래서 "./c:evil" 의
  // 첫 조각은 "." 이 아니라 "c:evil" 이다.
  const parts = normalized.split("/").filter((part) => part !== "" && part !== ".");
  const isAbsolute = normalized.startsWith("/");
  if (
    !normalized ||
    isAbsolute ||
    parts.includes("..") ||
    (parts.length > 0 && parts[0]!.includes(":"))
  ) {
    reject("unsafe_archive_path", "archive contains an unsafe member path");
  }
  return normalized;
}

interface ArchiveValidation {
  members: number;
  total: number;
}

function validateArchive(
  buf: Buffer,
  extension: string,
  policy: FileReadPolicy,
): ArchiveValidation {
  try {
    const parsed = parseCentralDirectory(buf);
    // Python: [info for info in archive.infolist() if not info.is_dir()]
    const infos = parsed.filter((info) => !info.name.endsWith("/"));
    if (infos.length > policy.maxArchiveMembers) {
      reject("too_many_archive_members", "archive member count exceeds policy");
    }

    const names = new Set<string>();
    const xmlInfos: ZipEntryInfo[] = [];
    let total = 0;
    for (const info of infos) {
      const name = safeArchiveName(info.name);
      if (names.has(name)) {
        reject("duplicate_archive_member", "archive contains duplicate members");
      }
      names.add(name);
      if ((info.flagBits & 0x1) !== 0) {
        reject("encrypted_archive", "encrypted archive members are not accepted");
      }
      const mode = info.externalAttr >>> 16;
      if ((mode & 0o170000) === 0o120000) {
        // stat.S_ISLNK
        reject("archive_symlink", "archive symlinks are not accepted");
      }
      if (info.fileSize > policy.maxArchiveMemberBytes) {
        reject("archive_member_too_large", "archive member exceeds policy");
      }
      total += info.fileSize;
      if (total > policy.maxDecompressedBytes) {
        reject("archive_too_large", "declared decompressed size exceeds policy");
      }
      if (info.fileSize > 1_024) {
        if (info.compressedSize === 0) {
          reject("compression_ratio_exceeded", "archive member has zero compressed size");
        }
        const ratio = info.fileSize / info.compressedSize;
        if (ratio > policy.maxCompressionRatio) {
          reject("compression_ratio_exceeded", "archive compression ratio exceeds policy");
        }
      }
      const casefolded = name.toLowerCase();
      if (
        casefolded.endsWith(".xml") ||
        casefolded.endsWith(".rels") ||
        (extension === ".hwpx" && name === "Contents/content.hpf")
      ) {
        xmlInfos.push(info);
      }
    }

    // OOXML and HWPX do not require DTDs. Let the parser handle encodings (a byte
    // search misses UTF-16 declarations); a DTD is rejected before any entity is
    // expanded by the extraction parser.
    for (const info of xmlInfos) {
      if (hasDoctypeDeclaration(readZipEntry(buf, info))) {
        reject("xml_dtd_rejected", "archive XML contains a DTD or entity declaration");
      }
    }

    if (extension === ".docx" && !names.has("word/document.xml")) {
      reject("format_mismatch", "DOCX archive is missing word/document.xml");
    }
    if (extension === ".xlsx" && !names.has("xl/workbook.xml")) {
      reject("format_mismatch", "XLSX archive is missing xl/workbook.xml");
    }
    if (
      extension === ".hwpx" &&
      !names.has("Contents/content.hpf") &&
      ![...names].some((name) => name.startsWith("Contents/section") && name.endsWith(".xml"))
    ) {
      reject("format_mismatch", "HWPX archive has no section XML");
    }
    return { members: infos.length, total };
  } catch (error) {
    if (error instanceof BoundedReadError) throw error;
    if (error instanceof ZlibError) throw error;
    // 멤버 이름의 utf-8 디코드 실패도 Python except 절 밖이라 그대로 탈출한다 (실측).
    if (error instanceof Error && error.name === "UnicodeDecodeError") throw error;
    // Python: (OSError, BadZipFile, RuntimeError, NotImplementedError, EOFError)
    // — zlib.error 는 여기 없이 탈출한다 (Python 실측).
    reject("invalid_archive", "document archive is invalid");
  }
}

function sha256WithNulCheck(buf: Buffer, rejectNul: boolean): string {
  const digest = createHash("sha256");
  for (let off = 0; off < buf.length; off += 1024 * 1024) {
    const block = buf.subarray(off, Math.min(buf.length, off + 1024 * 1024));
    if (rejectNul && block.includes(0)) {
      reject("format_mismatch", "text input contains a NUL byte");
    }
    digest.update(block);
  }
  return digest.digest("hex");
}

// ---------------------------------------------------------------------------
// 텍스트 추출
// ---------------------------------------------------------------------------

const ZIP_INSPECTORS = {
  ".docx": inspectDocx,
  ".hwpx": inspectHwpx,
  ".xlsx": inspectXlsx,
} as const;

/**
 * zip 포맷은 파트 coverage 를 남기는 inspectText + requireComplete, 그 밖은
 * dispatcher.readText (확장자 라우팅 + text_normalizer). Python 은 선택 의존성 미설치 시
 * ImportError → extractor_unavailable 이지만, TS 포트는 모든 추출기를 내장한다.
 */
async function extractText(
  path: string,
  extension: string,
): Promise<[string, ExtractionCoverage | null]> {
  if (extension === ".docx" || extension === ".hwpx" || extension === ".xlsx") {
    const result = await ZIP_INSPECTORS[extension](path);
    const [text] = normalizeForDetection(result.requireComplete());
    return [text, result.coverage];
  }
  return [await dispatcherReadText(path), null];
}

/**
 * Validate resource bounds, extract text, and return safe provenance.
 *
 * Legacy HWP and PDF are excluded from the default allowlist because their
 * optional parsers do not expose a deterministic decompression/page budget.
 * Deployments may opt in only when extraction runs in a separately constrained
 * worker or container.
 */
export async function readTextBounded(
  path: string,
  policy: FileReadPolicy | null = null,
): Promise<BoundedDocument> {
  const activePolicy = policy ?? new FileReadPolicy();
  const validated = validatePath(path, activePolicy);
  const before = validated.stat;
  const extension = validated.extension;
  const buf = readFileSync(path);
  validateSignature(buf, extension);
  let members = 0;
  let decompressed = 0;
  if (ZIP_EXTENSIONS.has(extension)) {
    const archive = validateArchive(buf, extension, activePolicy);
    members = archive.members;
    decompressed = archive.total;
  }
  const sourceDigest = sha256WithNulCheck(buf, !BINARY_EXTENSIONS.has(extension));
  let text: string;
  let coverage: ExtractionCoverage | null;
  try {
    [text, coverage] = await extractText(path, extension);
  } catch (error) {
    if (error instanceof BoundedReadError) throw error;
    if (error instanceof DocumentExtractionError) {
      throw new BoundedReadError(error.code, error.message, { coverage: error.coverage });
    }
    if (error instanceof TextDecodingError) throw new BoundedReadError(error.code, error.message);
    if (error instanceof PdfExtractionError) reject(error.code, error.message);
    // Python: ImportError → extractor_unavailable (TS 는 추출기 내장 — 해당 없음),
    // 그 외 모든 예외는 extract_failed 로 수렴한다 (csv.Error 포함 — 실측).
    reject("extract_failed", "document text extraction failed");
  }
  if (BINARY_EXTENSIONS.has(extension) && pyIsBlank(text)) {
    reject("no_extractable_text", "document has no extractable text; review or OCR is required");
  }
  if (codePointLength(text) > activePolicy.maxTextChars) {
    reject("extracted_text_too_large", "extracted text exceeds max_text_chars");
  }

  const after = statPath(path);
  if (after === undefined) {
    reject("source_changed", "document changed during extraction");
  }
  const identityChanged =
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs;
  const reread = readFileSync(path);
  if (identityChanged || sha256WithNulCheck(reread, false) !== sourceDigest) {
    reject("source_changed", "document changed during extraction");
  }

  return {
    text,
    sha256: sourceDigest,
    sizeBytes: Number(before.size),
    extension,
    archiveMembers: members,
    declaredDecompressedBytes: decompressed,
    coverage,
  };
}
