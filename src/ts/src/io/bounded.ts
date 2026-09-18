/**
 * Bounded document extraction for untrusted ingestion paths.
 * Python `ko_pii.io_.bounded` 1:1 포트.
 *
 * 악성 입력 방어 게이트 — 부정 사례(파일 크기/형식 불일치/zip bomb/DTD/심링크/
 * 경로 역주행/원본 변경)에서 Python 과 동일한 코드로 거부한다.
 *
 * zip 처리: JS 의 JSZip 은 flag_bits/external_attr/CRC 같은 중앙 디렉터리
 * 메타데이터를 노출하지 않으므로, 중앙 디렉터리를 직접 파싱한다 (순수 구현 +
 * Node zlib inflate). Python 실측 시맨틱:
 * - 시그니처 검사는 `zipfile.is_zipfile` 과 동일하게 EOCD 레코드 존재만 본다.
 *   CD 가 손상된 아카이브는 시그니처( format_mismatch) 가 아니라 아카이브 검증
 *   단계에서 invalid_archive 로 거부된다 (Python 실측).
 * - 멤버 읽기는 CRC-32 를 검증한다 (ZipFile.read → BadZipFile → invalid_archive).
 * - inflate 자체가 실패하는 손상 스트림은 Python 이 zlib.error 를 그대로 던지듯
 *   ZlibError 로 전파한다 (bounded except 절에 없어서 탈출하는 실측 동작).
 *
 * 텍스트 추출은 dispatcher.read_text 로 위인한다 — Python 과 동일하게 모든 포맷의
 * raw 텍스트에 text_normalizer 정규화가 적용되고, docx/xlsx/hwpx 도 라우팅된다.
 */
import { createHash } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { lstatSync, readFileSync, statSync } from "node:fs";
import { extname } from "node:path";
import { crc32, inflateRawSync } from "node:zlib";
import { readText as dispatcherReadText } from "./dispatcher.js";

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
export class BoundedReadError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "BoundedReadError";
    this.code = code;
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
    this.maxFileBytes = init.maxFileBytes ?? 16 * 1024 * 1024;
    this.maxArchiveMembers = init.maxArchiveMembers ?? 2_048;
    this.maxArchiveMemberBytes = init.maxArchiveMemberBytes ?? 16 * 1024 * 1024;
    this.maxDecompressedBytes = init.maxDecompressedBytes ?? 64 * 1024 * 1024;
    this.maxCompressionRatio = init.maxCompressionRatio ?? 200.0;
    this.maxTextChars = init.maxTextChars ?? 2_000_000;
    this.allowedExtensions = init.allowedExtensions ?? DEFAULT_BOUNDED_EXTENSIONS;
    this.rejectSymlinks = init.rejectSymlinks ?? true;

    const integerLimits = [
      this.maxFileBytes,
      this.maxArchiveMembers,
      this.maxArchiveMemberBytes,
      this.maxDecompressedBytes,
      this.maxTextChars,
    ];
    if (integerLimits.some((value) => value < 1)) {
      throw new Error("all bounded-read limits must be positive");
    }
    if (this.maxCompressionRatio < 1.0) {
      throw new Error("max_compression_ratio must be at least 1.0");
    }
    if (this.allowedExtensions.length === 0) {
      throw new Error("allowed_extensions must not be empty");
    }
    if (this.allowedExtensions.some((value) => !value.startsWith("."))) {
      throw new Error("allowed_extensions entries must start with '.'");
    }
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
}

// ---------------------------------------------------------------------------
// zip 중앙 디렉터리 파서 (Python zipfile 대응 메타데이터 추출)
// ---------------------------------------------------------------------------

/** 구조적 손상 — Python zipfile.BadZipFile 대응 (invalid_archive 로 수렴). */
class BadZipFile extends Error {}

/** Python zlib.error 대응 — bounded 의 except 절 밖으로 탈출하는 손상 스트림. */
export class ZlibError extends Error {}

interface ZipEntryInfo {
  name: string;
  flagBits: number;
  externalAttr: number;
  crc: number;
  compressedSize: number;
  fileSize: number;
  method: number;
  localHeaderOffset: number;
}

interface Eocd {
  cdOffset: number;
  entryCount: number;
}

/** EOCD 탐색 — Python `_EndRecData`: 마지막 PK\x05\x06 에서 comment 길이 일치 확인. */
function findEocd(buf: Buffer): Eocd {
  const minOffset = Math.max(0, buf.length - (22 + 65535));
  for (let i = buf.length - 22; i >= minOffset; i--) {
    if (buf.readUInt32LE(i) !== 0x06054b50) continue;
    const commentLen = buf.readUInt16LE(i + 20);
    if (i + 22 + commentLen !== buf.length) continue;
    let entryCount = buf.readUInt16LE(i + 10);
    let cdSize = buf.readUInt32LE(i + 12);
    let cdOffset = buf.readUInt32LE(i + 16);
    if (cdOffset === 0xffffffff || cdSize === 0xffffffff || entryCount === 0xffff) {
      // zip64: EOCD locator (PK\x06\x07) 바로 앞에 존재
      if (i < 20 || buf.readUInt32LE(i - 20) !== 0x07064b50) throw new BadZipFile("bad zip64");
      const z64Offset = buf.readBigUInt64LE(i - 20 + 8);
      const z64 = Number(z64Offset);
      if (z64 + 56 > buf.length || buf.readUInt32LE(z64) !== 0x06064b50) {
        throw new BadZipFile("bad zip64 eocd");
      }
      entryCount = Number(buf.readBigUInt64LE(z64 + 32));
      cdSize = Number(buf.readBigUInt64LE(z64 + 40));
      cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
    }
    return { cdOffset, entryCount };
  }
  throw new BadZipFile("end of central directory not found");
}

/** Python `zipfile.is_zipfile` — EOCD 레코드 존재만 확인 (`_check_zipfile`). */
function isZipfileEocd(buf: Buffer): boolean {
  try {
    findEocd(buf);
    return true;
  } catch {
    return false; // EOCD 부재 / 버퍼 과소 — Python _EndRecData falsy 대응
  }
}

function parseCentralDirectory(buf: Buffer): ZipEntryInfo[] {
  const eocd = findEocd(buf);
  const infos: ZipEntryInfo[] = [];
  let pos = eocd.cdOffset;
  for (let n = 0; n < eocd.entryCount; n++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== 0x02014b50) {
      throw new BadZipFile("bad magic number for central directory");
    }
    const flagBits = buf.readUInt16LE(pos + 8);
    const method = buf.readUInt16LE(pos + 10);
    const crc = buf.readUInt32LE(pos + 16);
    let compressedSize = buf.readUInt32LE(pos + 20);
    let fileSize = buf.readUInt32LE(pos + 24);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const externalAttr = buf.readUInt32LE(pos + 38);
    let localHeaderOffset = buf.readUInt32LE(pos + 42);
    const nameBytes = buf.subarray(pos + 46, pos + 46 + nameLen);
    // flag bit 0x800: utf-8 이름, 아니면 cp437 (ASCII 범위에서는 latin1과 동일)
    const name =
      (flagBits & 0x800) !== 0 ? nameBytes.toString("utf-8") : nameBytes.toString("latin1");
    let extra = pos + 46 + nameLen;
    const extraEnd = extra + extraLen;
    // zip64 extended information extra field (0x0001)
    while (extra + 4 <= extraEnd) {
      const headerId = buf.readUInt16LE(extra);
      const size = buf.readUInt16LE(extra + 2);
      if (headerId === 0x0001) {
        let field = extra + 4;
        if (fileSize === 0xffffffff) {
          fileSize = Number(buf.readBigUInt64LE(field));
          field += 8;
        }
        if (compressedSize === 0xffffffff) {
          compressedSize = Number(buf.readBigUInt64LE(field));
          field += 8;
        }
        if (localHeaderOffset === 0xffffffff) {
          localHeaderOffset = Number(buf.readBigUInt64LE(field));
        }
        break;
      }
      extra += 4 + size;
    }
    infos.push({
      name,
      flagBits,
      externalAttr,
      crc,
      compressedSize,
      fileSize,
      method,
      localHeaderOffset,
    });
    pos = pos + 46 + nameLen + extraLen + commentLen;
  }
  return infos;
}

/** 멤버 내용 읽기 (Python zipfile.ZipFile.read 대응) — stored/deflate만 지원. */
function readZipEntry(buf: Buffer, info: ZipEntryInfo): Buffer {
  const off = info.localHeaderOffset;
  if (off + 30 > buf.length || buf.readUInt32LE(off) !== 0x04034b50) {
    throw new BadZipFile("bad local header");
  }
  const nameLen = buf.readUInt16LE(off + 26);
  const extraLen = buf.readUInt16LE(off + 28);
  const dataStart = off + 30 + nameLen + extraLen;
  const compressed = buf.subarray(dataStart, dataStart + info.compressedSize);
  let data: Buffer;
  if (info.method === 0) {
    data = Buffer.from(compressed); // stored
  } else if (info.method === 8) {
    try {
      data = inflateRawSync(compressed);
    } catch (error) {
      // Python 은 zlib.error 를 그대로 던진다 (bounded except 절에 없음 — 실측).
      throw new ZlibError((error as Error).message);
    }
  } else {
    // Python: "compression type X not supported" (NotImplementedError) → invalid_archive
    throw new BadZipFile(`compression type ${info.method} not supported`);
  }
  // ZipFile.read 의 CRC-32 검증 (불일치 → BadZipFile → invalid_archive)
  if (info.crc >>> 0 !== crc32(data) >>> 0) {
    throw new BadZipFile(`Bad CRC-32 for file ${JSON.stringify(info.name)}`);
  }
  return data;
}

// ---------------------------------------------------------------------------
// 검증 단계 (Python bounded.py 함수 대응)
// ---------------------------------------------------------------------------

interface PathValidation {
  stat: BigIntStats;
  extension: string;
}

function statPath(path: string): BigIntStats | undefined {
  return statSync(path, { bigint: true, throwIfNoEntry: false }) as BigIntStats | undefined;
}

function validatePath(path: string, policy: FileReadPolicy): PathValidation {
  if (
    policy.rejectSymlinks &&
    lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink() === true
  ) {
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
  const parts = normalized.split("/");
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
      if (casefolded.endsWith(".xml") || casefolded.endsWith(".rels")) {
        xmlInfos.push(info);
      }
    }

    // OOXML and HWPX do not require DTDs. Reject them before the XML parser
    // sees the payload so internal entity expansion cannot amplify a small,
    // otherwise valid archive member in parser memory.
    for (const info of xmlInfos) {
      const content = asciiUpper(readZipEntry(buf, info));
      if (content.includes("<!DOCTYPE") || content.includes("<!ENTITY")) {
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
      ![...names].some((name) => name.startsWith("Contents/section") && name.endsWith(".xml"))
    ) {
      reject("format_mismatch", "HWPX archive has no section XML");
    }
    return { members: infos.length, total };
  } catch (error) {
    if (error instanceof BoundedReadError) throw error;
    if (error instanceof ZlibError) throw error;
    // Python: (OSError, BadZipFile, RuntimeError, NotImplementedError, EOFError)
    // — zlib.error 는 여기 없이 탈출한다 (Python 실측).
    reject("invalid_archive", "document archive is invalid");
  }
}

/** Python `bytes.upper()` 대응 — ASCII 만 대문자화. */
function asciiUpper(buf: Buffer): Buffer {
  const out = Buffer.from(buf); // copy — inflate 결과를 변형하지 않는다
  for (let i = 0; i < out.length; i++) {
    const b = out[i]!;
    if (b >= 0x61 && b <= 0x7a) out[i] = b - 0x20;
  }
  return out;
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
// 텍스트 추출 (dispatcher.read_text 대응)
// ---------------------------------------------------------------------------

/**
 * Python `dispatcher.read_text(str(source))` 대응 — 확장자 라우팅 + 모든 포맷
 * 공통 text_normalizer 정규화까지 dispatcher 가 수행한다. hwpx/docx/xlsx 추출기도
 * Python 처럼 동작한다 (Python 은 선택 의존성 미설치 시 ImportError →
 * extractor_unavailable 이지만, TS 포트는 모든 추출기를 내장한다).
 */
async function extractText(path: string): Promise<string> {
  return dispatcherReadText(path);
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
  try {
    text = await extractText(path);
  } catch (error) {
    if (error instanceof BoundedReadError) throw error;
    // Python: ImportError → extractor_unavailable (TS 는 추출기 내장 — 해당 없음),
    // 그 외 모든 예외는 extract_failed 로 수렴한다 (csv.Error 포함 — 실측).
    reject("extract_failed", "document text extraction failed");
  }
  if (text.length > activePolicy.maxTextChars) {
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
  };
}
