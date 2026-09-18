/**
 * ZIP 컨테이너 — Python `zipfile.ZipFile` 의 TS 대응 (순수 구현 + Node zlib).
 *
 * 예전에는 JSZip 에 위임했지만 JSZip 은 Python zipfile 보다 관대해서(로컬 헤더 이름
 * 불일치, 엔트리 겹침, extract_version>63, flag bit 5/6 을 그냥 읽는다) Python 이
 * BadZipFile / NotImplementedError 로 실패하는 아카이브에서 텍스트가 나왔다. 지금은
 * `_EndRecData` / `_RealGetContents` / `ZipFile.open` + `ZipExtFile` 의 판정을 그대로
 * 옮긴 파서 하나를 bounded 검증기와 일반 추출 경로(docx/hwpx/xlsx)가 함께 쓴다 —
 * 검증기와 추출기가 같은 바이트를 같은 규칙으로 본다.
 *
 * 예외는 Python 클래스명과 같은 `error.name`, Python 실측과 같은 메시지를 갖는다
 * (batch 의 `"{클래스명}: {메시지}"` 문자열이 일치하도록).
 * 알려진 차이: bzip2(12)/LZMA(14) 멤버는 Python 이 읽지만 여기서는 NotImplementedError.
 */
import { readFile } from "node:fs/promises";
import { crc32, inflateRawSync, constants as zlibConstants } from "node:zlib";
import { decode as iconvDecode } from "iconv-lite";

/** Python 내장 예외 대응 — `name` 이 Python 클래스명. */
class PyError extends Error {
  constructor(name: string, message: string) {
    super(message);
    this.name = name;
  }
}

/** 구조적 손상 — Python `zipfile.BadZipFile`. */
export class BadZipFile extends Error {
  override name = "BadZipFile";
}

/**
 * Python `zlib.error` — 손상된 deflate 스트림. bounded 의 except 절에 없어 그대로
 * 탈출한다(실측). Python 클래스의 `__name__` 은 "error" 다.
 */
export class ZlibError extends Error {
  override name = "error";
}

/** Python `repr(str)` — 아카이브 멤버 이름 메시지용. */
function pyReprStr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (ch === "\\" || ch === quote) out += `\\${ch}`;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (cp < 0x20 || cp === 0x7f) out += `\\x${cp.toString(16).padStart(2, "0")}`;
    else out += ch;
  }
  return quote + out + quote;
}

/** Python `repr(bytes)`. */
function pyReprBytes(bytes: Buffer): string {
  const hasSingle = bytes.includes(0x27);
  const quote = hasSingle && !bytes.includes(0x22) ? '"' : "'";
  let out = "";
  for (const b of bytes) {
    const ch = String.fromCharCode(b);
    if (ch === "\\" || ch === quote) out += `\\${ch}`;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (b < 0x20 || b >= 0x7f) out += `\\x${b.toString(16).padStart(2, "0")}`;
    else out += ch;
  }
  return `b${quote}${out}${quote}`;
}

// ---------------------------------------------------------------------------
// 중앙 디렉터리 파서 (Python zipfile 대응 메타데이터)
// ---------------------------------------------------------------------------

export interface ZipEntryInfo {
  /** Python ``ZipInfo.filename`` — NUL 절단 + unicode path extra 반영. */
  name: string;
  /** Python ``ZipInfo.orig_filename`` — 로컬 헤더 이름과의 대조용. */
  origName: string;
  flagBits: number;
  externalAttr: number;
  crc: number;
  compressedSize: number;
  fileSize: number;
  method: number;
  /** concat(선두 데이터) 보정이 끝난 로컬 헤더 절대 위치. */
  localHeaderOffset: number;
  /** Python ``ZipInfo._end_offset`` — 다음 엔트리(또는 CD) 시작. 겹침 검사용. */
  endOffset: number;
}

interface Eocd {
  cdOffset: number;
  cdSize: number;
  /** EOCD 레코드 위치 (zip64 면 zip64 EOCD 위치) — concat 계산의 기준. */
  location: number;
}

const SIZE_EOCD = 22;
const SIZE_EOCD64 = 56;
const SIZE_EOCD64_LOCATOR = 20;
const ZIP_MAX_COMMENT = 65535;
const MAX_EXTRACT_VERSION = 63;

/**
 * Python `_EndRecData` — (1) 파일 끝 22바이트가 주석 없는 EOCD 인지 보고, (2) 아니면
 * 마지막 64K+22 바이트에서 *마지막* 시그니처를 채택한다 (주석 길이는 검증하지 않는다).
 * EOCD 가 없으면 null.
 */
function findEocd(buf: Buffer): Eocd | null {
  const size = buf.length;
  if (size < SIZE_EOCD) return null;
  let location = -1;
  const tail = size - SIZE_EOCD;
  if (buf.readUInt32LE(tail) === 0x06054b50 && buf.readUInt16LE(tail + 20) === 0) {
    location = tail;
  } else {
    const maxCommentStart = Math.max(size - ZIP_MAX_COMMENT - SIZE_EOCD, 0);
    const start = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (start < maxCommentStart) return null; // -1 포함
    if (start + SIZE_EOCD > size) return null; // Zip file is corrupted.
    location = start;
  }
  const eocd: Eocd = {
    cdSize: buf.readUInt32LE(location + 12),
    cdOffset: buf.readUInt32LE(location + 16),
    location,
  };
  return applyZip64(buf, eocd);
}

/** Python `_EndRecData64` — locator 가 있으면 zip64 EOCD 값으로 갱신. */
function applyZip64(buf: Buffer, eocd: Eocd): Eocd {
  let offset = eocd.location - SIZE_EOCD64_LOCATOR;
  if (offset < 0) return eocd;
  if (buf.readUInt32LE(offset) !== 0x07064b50) return eocd;
  const diskno = buf.readUInt32LE(offset + 4);
  const reloff = Number(buf.readBigUInt64LE(offset + 8));
  const disks = buf.readUInt32LE(offset + 16);
  if (diskno !== 0 || disks > 1) {
    throw new BadZipFile("zipfiles that span multiple disks are not supported");
  }
  offset -= SIZE_EOCD64;
  if (reloff > offset) throw new BadZipFile("Corrupt zip64 end of central directory locator");
  // First, check the assumption that there is no prepended data.
  let at = reloff;
  let extrasz = offset - reloff;
  if (buf.readUInt32LE(at) !== 0x06064b50 && reloff !== offset) {
    at = offset;
    extrasz = 0;
  }
  if (buf.readUInt32LE(at) !== 0x06064b50) {
    throw new BadZipFile("Zip64 end of central directory record not found");
  }
  const sz = Number(buf.readBigUInt64LE(at + 4));
  const cdSize = Number(buf.readBigUInt64LE(at + 40));
  const cdOffset = Number(buf.readBigUInt64LE(at + 48));
  if (cdOffset + cdSize !== reloff || sz + 12 !== SIZE_EOCD64 + extrasz) {
    throw new BadZipFile("Corrupt zip64 end of central directory record");
  }
  return { cdSize, cdOffset, location: offset - extrasz };
}

/** Python `zipfile.is_zipfile` — EOCD 레코드 존재만 확인 (`_check_zipfile`). */
export function isZipfileEocd(buf: Buffer): boolean {
  return findEocd(buf) !== null;
}

function decodeZipName(bytes: Buffer, flagBits: number): string {
  // flag bit 0x800: utf-8 이름, 아니면 cp437 (Python `metadata_encoding or "cp437"`)
  if ((flagBits & 0x800) === 0) return iconvDecode(bytes, "cp437");
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    // Python: bytes.decode("utf-8") 의 UnicodeDecodeError 가 그대로 전파된다.
    throw new PyError("UnicodeDecodeError", utf8DecodeErrorMessage(bytes));
  }
}

/** CPython `bytes.decode("utf-8")` 의 UnicodeDecodeError 메시지 (첫 오류 위치·사유). */
function utf8DecodeErrorMessage(bytes: Buffer): string {
  const n = bytes.length;
  let i = 0;
  while (i < n) {
    const lead = bytes[i] ?? 0;
    if (lead < 0x80) {
      i += 1;
      continue;
    }
    const need =
      lead >= 0xc2 && lead <= 0xdf
        ? 2
        : lead >= 0xe0 && lead <= 0xef
          ? 3
          : lead >= 0xf0 && lead <= 0xf4
            ? 4
            : 0;
    let reason = "invalid start byte";
    let consumed = 1;
    if (need > 0) {
      reason = "";
      for (let k = 1; k < need; k++) {
        if (i + k >= n) {
          reason = "unexpected end of data";
          break;
        }
        const c = bytes[i + k] ?? 0;
        // 두 번째 바이트의 허용 범위는 선두 바이트에 따라 좁아진다 (overlong·서로게이트·>U+10FFFF 배제)
        let lo = 0x80;
        let hi = 0xbf;
        if (k === 1) {
          if (lead === 0xe0) lo = 0xa0;
          else if (lead === 0xed) hi = 0x9f;
          else if (lead === 0xf0) lo = 0x90;
          else if (lead === 0xf4) hi = 0x8f;
        }
        if (c < lo || c > hi) {
          reason = "invalid continuation byte";
          break;
        }
        consumed += 1;
      }
      if (reason === "") {
        i += need;
        continue;
      }
    }
    const where =
      consumed === 1
        ? `byte 0x${lead.toString(16).padStart(2, "0")} in position ${i}`
        : `bytes in position ${i}-${i + consumed - 1}`;
    return `'utf-8' codec can't decode ${where}: ${reason}`;
  }
  return "'utf-8' codec can't decode bytes";
}

/** Python `_sanitize_filename` (posix) — 첫 NUL 에서 절단. */
function sanitizeZipName(name: string): string {
  const nul = name.indexOf("\0");
  return nul >= 0 ? name.slice(0, nul) : name;
}

/**
 * Python `ZipFile._RealGetContents` — 중앙 디렉터리를 EOCD 의 *엔트리 수가 아니라*
 * cdSize 바이트를 다 소비할 때까지 파싱한다 (엔트리 수 조작으로 검증을 건너뛸 수 없다).
 */
export function parseCentralDirectory(buf: Buffer): ZipEntryInfo[] {
  const eocd = findEocd(buf);
  if (eocd === null) throw new BadZipFile("File is not a zip file");
  // "concat" is zero, unless zip was concatenated to another file
  const concat = eocd.location - eocd.cdSize - eocd.cdOffset;
  const startDir = eocd.cdOffset + concat;
  if (startDir < 0) throw new BadZipFile("Bad offset for central directory");
  const cd = buf.subarray(startDir, startDir + eocd.cdSize);

  const infos: ZipEntryInfo[] = [];
  let pos = 0;
  while (pos < eocd.cdSize) {
    if (pos + 46 > cd.length) throw new BadZipFile("Truncated central directory");
    if (cd.readUInt32LE(pos) !== 0x02014b50) {
      throw new BadZipFile("Bad magic number for central directory");
    }
    const extractVersion = cd.readUInt16LE(pos + 6);
    const flagBits = cd.readUInt16LE(pos + 8);
    const method = cd.readUInt16LE(pos + 10);
    const crc = cd.readUInt32LE(pos + 16);
    let compressedSize = cd.readUInt32LE(pos + 20);
    let fileSize = cd.readUInt32LE(pos + 24);
    const nameLen = cd.readUInt16LE(pos + 28);
    const extraLen = cd.readUInt16LE(pos + 30);
    const commentLen = cd.readUInt16LE(pos + 32);
    const externalAttr = cd.readUInt32LE(pos + 38);
    let localHeaderOffset = cd.readUInt32LE(pos + 42);
    const nameBytes = cd.subarray(pos + 46, pos + 46 + nameLen);
    const origName = decodeZipName(nameBytes, flagBits);
    let name = sanitizeZipName(origName);
    if (extractVersion > MAX_EXTRACT_VERSION) {
      throw new PyError(
        "NotImplementedError",
        `zip file version ${(extractVersion / 10).toFixed(1)}`,
      );
    }

    // Python `ZipInfo._decodeExtra`
    let extra = cd.subarray(pos + 46 + nameLen, pos + 46 + nameLen + extraLen);
    while (extra.length >= 4) {
      const tp = extra.readUInt16LE(0);
      const ln = extra.readUInt16LE(2);
      if (ln + 4 > extra.length) {
        throw new BadZipFile(
          `Corrupt extra field ${tp.toString(16).padStart(4, "0")} (size=${ln})`,
        );
      }
      let data = extra.subarray(4, ln + 4);
      if (tp === 0x0001) {
        const take = (field: string): number => {
          if (data.length < 8)
            throw new BadZipFile(`Corrupt zip64 extra field. ${field} not found.`);
          const value = Number(data.readBigUInt64LE(0));
          data = data.subarray(8);
          return value;
        };
        if (fileSize === 0xffffffff) fileSize = take("File size");
        if (compressedSize === 0xffffffff) compressedSize = take("Compress size");
        if (localHeaderOffset === 0xffffffff) localHeaderOffset = take("Header offset");
      } else if (tp === 0x7075) {
        // Unicode Path Extra Field — 버전 1 이고 원본 이름 CRC 가 맞으면 이름을 대체
        if (data.length < 5) throw new BadZipFile("Corrupt unicode path extra field (0x7075)");
        if (data[0] === 1 && data.readUInt32LE(1) === crc32(nameBytes) >>> 0) {
          let unicodeName: string;
          try {
            unicodeName = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
              data.subarray(5),
            );
          } catch {
            throw new BadZipFile("Corrupt unicode path extra field (0x7075): invalid utf-8 bytes");
          }
          if (unicodeName) name = sanitizeZipName(unicodeName);
        }
      }
      extra = extra.subarray(ln + 4);
    }

    infos.push({
      name,
      origName,
      flagBits,
      externalAttr,
      crc,
      compressedSize,
      fileSize,
      method,
      localHeaderOffset: localHeaderOffset + concat,
      endOffset: startDir,
    });
    pos += 46 + nameLen + extraLen + commentLen;
  }

  // Python: reversed(sorted(filelist, key=header_offset)) 로 _end_offset 부여 (안정 정렬).
  const order = infos
    .map((_, i) => i)
    .sort((a, b) => {
      return infos[a]!.localHeaderOffset - infos[b]!.localHeaderOffset || a - b;
    });
  let endOffset = startDir;
  for (let k = order.length - 1; k >= 0; k--) {
    const info = infos[order[k]!]!;
    info.endOffset = endOffset;
    endOffset = info.localHeaderOffset;
  }
  return infos;
}

/**
 * 멤버 내용 읽기 — Python `ZipFile.read` (`open` 의 헤더 검사 + `ZipExtFile` 의 읽기/CRC).
 *
 * 선언된 file_size 를 넘는 출력은 만들지 않는다 (`maxOutputLength`) — 크기를 속인
 * 멤버로 메모리를 쓰게 할 수 없다. Python 은 file_size 에서 잘라 CRC 를 보고, 잘린
 * 스트림은 풀린 데까지만으로 CRC 를 본다 — 둘 다 "Bad CRC-32" (실측). Z_SYNC_FLUSH 로
 * 잘린 스트림의 부분 출력을 받아 같은 판정을 낸다.
 */
export function readZipEntry(buf: Buffer, info: ZipEntryInfo): Buffer {
  const off = info.localHeaderOffset;
  if (off < 0 || off + 30 > buf.length) throw new BadZipFile("Truncated file header");
  if (buf.readUInt32LE(off) !== 0x04034b50) {
    throw new BadZipFile("Bad magic number for file header");
  }
  const localFlags = buf.readUInt16LE(off + 6);
  const nameLen = buf.readUInt16LE(off + 26);
  const extraLen = buf.readUInt16LE(off + 28);
  if ((info.flagBits & 0x20) !== 0) {
    throw new PyError("NotImplementedError", "compressed patched data (flag bit 5)");
  }
  if ((info.flagBits & 0x40) !== 0) {
    throw new PyError("NotImplementedError", "strong encryption (flag bit 6)");
  }
  const localNameBytes = buf.subarray(off + 30, off + 30 + nameLen);
  if (decodeZipName(localNameBytes, localFlags) !== info.origName) {
    throw new BadZipFile(
      `File name in directory ${pyReprStr(info.origName)} and header ${pyReprBytes(localNameBytes)} differ.`,
    );
  }
  const dataStart = off + 30 + nameLen + extraLen;
  // Python 3.12: 같은 로컬 헤더를 공유하는 엔트리(_end_offset == header_offset)는 경고만
  // 하고 읽는다. 그 밖의 겹침만 BadZipFile.
  if (dataStart + info.compressedSize > info.endOffset && info.endOffset !== off) {
    throw new BadZipFile(`Overlapped entries: ${pyReprStr(info.origName)} (possible zip bomb)`);
  }
  if ((info.flagBits & 0x1) !== 0) {
    throw new PyError(
      "RuntimeError",
      `File ${pyReprStr(info.name)} is encrypted, password required for extraction`,
    );
  }
  const compressed = buf.subarray(dataStart, dataStart + info.compressedSize);
  const badCrc = (): BadZipFile => new BadZipFile(`Bad CRC-32 for file ${pyReprStr(info.name)}`);
  let data: Buffer;
  if (info.method === 0) {
    // stored — min(compress_size, file_size) 만큼 읽고 CRC 만 본다 (짧아도 CRC 가 맞으면 통과).
    data = Buffer.from(compressed.subarray(0, info.fileSize));
  } else if (info.method === 8) {
    try {
      data = inflateRawSync(compressed, {
        finishFlush: zlibConstants.Z_SYNC_FLUSH,
        maxOutputLength: Math.max(info.fileSize, 1),
      });
    } catch (error) {
      const err = error as NodeJS.ErrnoException;
      // 선언 크기 초과 — Python 은 file_size 에서 자른 데이터의 CRC 불일치로 끝난다.
      if (err.code === "ERR_BUFFER_TOO_LARGE") throw badCrc();
      throw new ZlibError(`Error ${err.errno ?? -3} while decompressing data: ${err.message}`);
    }
    if (data.length > info.fileSize) throw badCrc();
  } else {
    // Python `_check_compression` — stored/deflate/bzip2/lzma 외 전부 (실측 메시지)
    throw new PyError("NotImplementedError", "That compression method is not supported");
  }
  if (info.crc >>> 0 !== crc32(data) >>> 0) throw badCrc();
  return data;
}

// ---------------------------------------------------------------------------
// ZipFile — docx/hwpx/xlsx 추출기가 쓰는 Python `zipfile.ZipFile` 최소 표면
// ---------------------------------------------------------------------------

export interface ZipFile {
  readonly buf: Buffer;
  /** Python `ZipFile.filelist` — 중앙 디렉터리 순서, 중복·폴더 엔트리 포함. */
  readonly infos: readonly ZipEntryInfo[];
  /** Python `ZipFile.NameToInfo` — 같은 이름은 마지막 엔트리가 이긴다. */
  readonly byName: ReadonlyMap<string, ZipEntryInfo>;
}

/** Python `zipfile.ZipFile(path)` — 중앙 디렉터리 구조 검증까지 수행한다. */
export async function openZip(path: string): Promise<ZipFile> {
  const buf = await readFile(path);
  const infos = parseCentralDirectory(buf);
  const byName = new Map<string, ZipEntryInfo>();
  for (const info of infos) byName.set(info.name, info);
  return { buf, infos, byName };
}

/** Python `zf.namelist()` — 엔트리 이름 목록 (폴더·중복 포함, 디렉터리 순서). */
export function zipNames(zf: ZipFile): string[] {
  return zf.infos.map((info) => info.name);
}

/** Python `zf.read(name)` — 헤더 검사 + CRC 검증을 거친 멤버 바이트. */
export async function zipRead(zf: ZipFile, name: string): Promise<Uint8Array> {
  const info = zf.byName.get(name);
  if (info === undefined) {
    throw new PyError("KeyError", `"There is no item named ${pyReprStr(name)} in the archive"`);
  }
  return readZipEntry(zf.buf, info);
}
