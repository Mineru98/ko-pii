/**
 * Plain text decoding: UTF-8 (including BOM), then lossless Korean fallbacks.
 * Python `ko_pii.io_.plain` 1:1 포트.
 *
 * JS Buffer 는 cp949/euc-kr 을 지원하지 않으므로 iconv-lite 를 사용한다.
 * - utf-8 / utf-8-sig 완전성 검사: `TextDecoder("utf-8", { fatal: true })` (직접 수행)
 *   - `ignoreBOM: true` — 디코더가 BOM 을 임의로 떼지 않게 하고, 파일 선두 BOM 하나만
 *     utf-8-sig 경로에서 수동으로 뗀다 (본문 중간의 U+FEFF 는 보존).
 * - cp949 / euc-kr: iconv-lite 디코드. iconv-lite 는 strict 모드가 없어 잘못된
 *   바이트를 U+FFFD 로 치환하므로, 결과에 U+FFFD 가 있으면 "디코드 실패"로 간주해
 *   다음 후보로 넘어간다 (Python UnicodeDecodeError 폴백 재현).
 */
import { readFileSync } from "node:fs";
import { decode as iconvDecode } from "iconv-lite";
import { ValueError } from "../core/errors.js";

/** Python "utf-8" 코덱 대응 — BOM 을 유지하고 잘못된 바이트에서 예외(fatal). */
const utf8Fatal = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** No supported codec can read the file without discarding source bytes. */
export class TextDecodingError extends ValueError {
  readonly code = "text_decode_failed";

  constructor(message: string) {
    super(message);
    this.name = "TextDecodingError";
  }
}

type DecodeCandidate = "utf-8" | "utf-8-sig" | "cp949" | "euc-kr";

/** 단일 인코딩 시도. 실패(Python UnicodeDecodeError) 시 null. */
function tryDecode(raw: Buffer, encoding: DecodeCandidate): string | null {
  try {
    if (encoding === "utf-8") {
      return utf8Fatal.decode(raw);
    }
    if (encoding === "utf-8-sig") {
      // utf-8 로 디코드된 뒤 선행 BOM 하나만 제거 (Python utf-8-sig 코덱 시맨틱)
      return utf8Fatal.decode(raw).replace(/^\uFEFF/, "");
    }
    const decoded = iconvDecode(raw, encoding, { stripBOM: false });
    // iconv-lite 는 예외 대신 U+FFFD 치환이므로, 원본에 없던 치환 문자가 생기면 실패로 본다.
    // (원본이 담은 U+FFFD 는 cp949/euc-kr 로 표현할 수 없으므로 여기서는 언제나 실패다.)
    if (decoded.includes("\uFFFD")) return null;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * 파일을 읽어 텍스트로 디코드한다.
 *
 * Consume a file-level UTF-8 signature before CSV interprets its first header.
 * A declared UTF-8 file must not be silently reinterpreted as a legacy codec.
 * BOM 이 있으면 utf-8-sig 만, 없으면 utf-8 → cp949 → euc-kr. 모두 실패하면 TextDecodingError.
 */
export function readText(path: string): string {
  const raw = readFileSync(path);
  const hasBom = raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf;
  const encodings: readonly DecodeCandidate[] = hasBom
    ? ["utf-8-sig"]
    : ["utf-8", "cp949", "euc-kr"];
  for (const encoding of encodings) {
    const decoded = tryDecode(raw, encoding);
    if (decoded !== null) return decoded;
  }
  throw new TextDecodingError(
    "text cannot be decoded as supported UTF-8/CP949/EUC-KR without data loss",
  );
}
