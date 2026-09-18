/**
 * HWP 5.x (구 한컴오피스, OLE 컴파운드) 텍스트 추출.
 *
 * HWP 5.x 는 Microsoft OLE Compound Document 포맷 + 압축된 레코드 스트림.
 * HWPX 와 달리 XML 이 아니라 *바이너리 레코드* 라서 별도 파서 필요.
 *
 * 구조 (한컴테크 명세):
 *   - FileHeader (256 bytes) — 압축·암호화 플래그
 *   - DocInfo — 문서 메타
 *   - BodyText/Section0, Section1, ... — 본문 (zlib raw deflate 압축)
 *   - ViewText/Section0, ... — 미리보기 (선택)
 *
 * 각 섹션 스트림은 레코드의 연속:
 *   - Record header (4 bytes, little-endian):
 *       bits  0~9  (10 bits): tag ID
 *       bits 10~19 (10 bits): level (계층)
 *       bits 20~31 (12 bits): size
 *       size == 0xFFF 이면 다음 4 bytes 가 실제 size
 *   - Body (size bytes)
 *
 * 본문 텍스트는 ``HWPTAG_PARA_TEXT`` (0x43, 67) 레코드에 UTF-16LE 로 들어 있다.
 * 일부 코드포인트 (0x00 ~ 0x1F) 는 inline control (각주·하이퍼링크·표 시작 등) 로
 * 별도 의미 — 본 모듈은 *텍스트만* 추출하므로 control 은 건너뜀.
 *
 * 외부 의존성: ``cfb`` (Apache-2.0, SheetJS). 원본 Python 은 OLE 컨테이너 열기를
 * ``olefile`` 에 위임하고 설치 지연(``_ensure_olefile`` 의 lazy ImportError)를
 * 뒀지만, TS 포트는 cfb 를 하드 의존성으로 설치하므로 그 가드가 불필요하다
 * (레코드 파싱은 어차피 자체 구현).
 */
import { readFileSync } from "node:fs";
import { inflateRawSync } from "node:zlib";
import type { CFB$Container } from "cfb";
import CFB from "cfb";

// HWP record tag IDs (한컴테크 명세 5.0 기준)
export const HWPTAG_BEGIN = 0x010;
export const HWPTAG_PARA_HEADER = HWPTAG_BEGIN + 50; // 0x42
export const HWPTAG_PARA_TEXT = HWPTAG_BEGIN + 51; // 0x43
export const HWPTAG_PARA_CHAR_SHAPE = HWPTAG_BEGIN + 52;
export const HWPTAG_PARA_LINE_SEG = HWPTAG_BEGIN + 53;

/** CFB 엔트리 타입 중 stream (cfb 타입의 CFB$EntryType.stream — 런타임 값 2). */
const CFB_TYPE_STREAM = 2;

/** ``(tag_id, level, body)`` 레코드 튜플. */
export type HwpRecord = [tagId: number, level: number, body: Buffer];

// HWP PARA_TEXT 제어문자 (UTF-16LE 코드포인트 0~31) — HWP 5.0 명세 + java-hwp 참조 구현 기준.
// inline ∪ extended controls 는 코드 1워드 + 14바이트(7워드) inline data → data 를 건너뛴다.
// (이전 구현은 5~8·12·14·15 등을 누락해 14바이트 payload 가 텍스트로 새어나왔고,
//  반대로 24~26 은 데이터 없는 char control 인데 14바이트를 더 소비해 정렬이 깨졌다.)
const CTRL_WITH_DATA: ReadonlySet<number> = new Set([
  1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
]);
// 추가 데이터 없는 char control (0x0D=문단구분·0x09=탭은 decodeParaText 에서 별도 처리)
const CTRL_NO_DATA: ReadonlySet<number> = new Set([0, 10, 24, 25, 26, 27, 28, 29, 30, 31]);

/** HWP 레코드 스트림을 순회하며 ``[tag_id, level, body]`` 를 yield 한다. */
export function* iterRecords(stream: Buffer): Generator<HwpRecord> {
  let i = 0;
  const n = stream.length;
  while (i + 4 <= n) {
    const header = stream.readUInt32LE(i);
    i += 4;
    const tagId = header & 0x3ff;
    const level = (header >>> 10) & 0x3ff;
    let size = (header >>> 20) & 0xfff;
    if (size === 0xfff) {
      if (i + 4 > n) {
        break;
      }
      size = stream.readUInt32LE(i);
      i += 4;
    }
    if (i + size > n) {
      break;
    }
    const body = stream.subarray(i, i + size);
    i += size;
    yield [tagId, level, body];
  }
}

/** PARA_TEXT 본문 디코드 — UTF-16LE 문자 + inline control 처리. */
export function decodeParaText(body: Buffer): string {
  const chars: string[] = [];
  let i = 0;
  const n = body.length;
  while (i + 2 <= n) {
    const cp = body.readUInt16LE(i);
    i += 2;
    if (cp === 0x0d) {
      // 문단 구분 (char control, 데이터 없음)
      chars.push("\n");
      continue;
    }
    if (cp === 0x09) {
      // 탭 — inline control: \t + 14바이트 데이터
      chars.push("\t");
      i += 14;
      continue;
    }
    if (CTRL_WITH_DATA.has(cp)) {
      // inline/extended control: 14바이트 데이터 건너뜀
      i += 14;
      continue;
    }
    if (CTRL_NO_DATA.has(cp)) {
      // 데이터 없는 char control (0x00 포함)
      continue;
    }
    // 원본의 chr(cp) try/except ValueError 는 cp ≤ 0xFFFF (uint16) 에서는
    // 발생 불가능하므로 생략 — String.fromCharCode 가 lone surrogate 까지
    // Python chr 과 동일하다.
    chars.push(String.fromCharCode(cp));
  }
  return chars.join("");
}

/** HWP FileHeader byte 36 의 bit 0 이 압축 플래그. */
export function isCompressed(headerBytes: Buffer): boolean {
  if (headerBytes.length < 37) {
    return true; // 안전한 기본값
  }
  return ((headerBytes[36] ?? 0) & 0x01) !== 0;
}

/**
 * 문자열끼리 코드포인트 순 비교 — Python ``str`` 비교 등가.
 * (JS 의 ``<`` 는 UTF-16 코드 유닛 순이라 보충 문자 vs U+E000~U+FFFF 에서
 *  순서가 뒤집힐 수 있다. 섹션명은 ASCII 가 일반적이지만 원본 정렬을 그대로 재현.)
 */
function compareCodePoints(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    // 루프 조건이 범위를 보장 — undefined 폴백은 도달 불가
    const ca = a.codePointAt(i) ?? 0;
    const cb = b.codePointAt(j) ?? 0;
    if (ca !== cb) {
      return ca < cb ? -1 : 1;
    }
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  // 한쪽이 다른 쪽의 접두어 — 짧은 쪽이 먼저 (Python 리스트 비교 등가)
  return i < a.length ? 1 : j < b.length ? -1 : 0;
}

/** 경로 컴포넌트 배열 비교 — Python ``sorted`` (요소별 비교, 짧은 접두어 먼저). */
function comparePaths(a: string[], b: string[]): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const cmp = compareCodePoints(a[i] ?? "", b[i] ?? "");
    if (cmp !== 0) {
      return cmp;
    }
  }
  return a.length - b.length;
}

/**
 * olefile.listdir() 등가 — stream 엔트리만 루트 기준 경로 컴포넌트 배열로.
 * cfb 의 FullPaths 는 루트 이름("Root Entry" 등)을 포함하고 저장소는 끝에
 * "/" 가 붙으므로, index 0 (루트) 의 경로를 접두어로 떼어낸다.
 */
function listSectionPaths(ole: CFB$Container): string[][] {
  const rootPrefix = ole.FullPaths[0] ?? "/"; // 예: "Root Entry/"
  const paths: string[][] = [];
  for (let i = 0; i < ole.FileIndex.length; i++) {
    const entry = ole.FileIndex[i];
    if (!entry || entry.type !== CFB_TYPE_STREAM) {
      continue; // 저장소·루트·더미 제외 (olefile listdir 기본값: stream 만)
    }
    const fullPath = ole.FullPaths[i] ?? "";
    const rel = fullPath.startsWith(rootPrefix) ? fullPath.slice(rootPrefix.length) : fullPath;
    const parts = rel
      .replace(/\/$/, "")
      .split("/")
      .filter((p) => p.length > 0);
    if (parts[0] === "BodyText") {
      paths.push(parts);
    }
  }
  paths.sort(comparePaths); // Python sorted() = 코드포인트 정렬
  return paths;
}

function toBuffer(content: number[] | Uint8Array): Buffer {
  return Buffer.isBuffer(content) ? content : Buffer.from(content);
}

/** olefile.openstream(parts).read() 등가 — 없거나 저장소면 null. */
function readStream(ole: CFB$Container, parts: string[]): Buffer | null {
  const entry = CFB.find(ole, `/${parts.join("/")}`);
  if (!entry || entry.type !== CFB_TYPE_STREAM) {
    return null;
  }
  return toBuffer(entry.content);
}

/** HWP 5.x 파일에서 본문 텍스트를 추출한다. */
export function readText(path: string): string {
  // 원본은 olefile.OleFileIO(path) 로 여닫지만 cfb 는 read 시 전부 메모리에
  // 올리므로 close 할 자원이 없다 (try/finally 불필요).
  const ole = CFB.read(readFileSync(path));
  // FileHeader 로 압축 여부 판단 — 원본은 openstream 실패 시 b"" 로 폴백하고,
  // cfb 의 find 는 누락·저장소 엔트리에서 null 을 반환하므로 같은 결과.
  const headerEntry = CFB.find(ole, "FileHeader");
  const headerBytes = headerEntry ? toBuffer(headerEntry.content) : Buffer.alloc(0);
  const compressed = isCompressed(headerBytes);

  const out: string[] = [];
  for (const parts of listSectionPaths(ole)) {
    let raw = readStream(ole, parts);
    if (raw === null) {
      continue;
    }
    if (compressed) {
      try {
        raw = inflateRawSync(raw); // raw deflate (Python zlib.decompress(raw, -15))
      } catch {
        continue; // zlib.error → 섹션 skip (구분자 \n 도 넣지 않음)
      }
    }
    for (const [tagId, , body] of iterRecords(raw)) {
      if (tagId === HWPTAG_PARA_TEXT) {
        out.push(decodeParaText(body));
        out.push("\n");
      }
    }
    out.push("\n"); // section separator
  }
  return out.join("");
}
