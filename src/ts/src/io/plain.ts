/**
 * 평문 텍스트 (.txt, .md, .log) — UTF-8 우선, cp949 fallback.
 * Python `ko_pii.io_.plain` 1:1 포트.
 *
 * JS Buffer 는 cp949/euc-kr 을 지원하지 않으므로 iconv-lite 를 사용한다.
 * - utf-8 / utf-8-sig 완전성 검사: `TextDecoder("utf-8", { fatal: true })` (직접 수행)
 *   - `ignoreBOM: true` 필수 — Python "utf-8" 코덱은 BOM(U+FEFF)을 제거하지 않고
 *     그대로 디코드하기 때문 (골드 sample_bom.txt 의 raw_text 가 BOM 을 유지한다).
 * - BOM 제거(utf-8-sig)는 수동으로 선행 U+FEFF 하나를 뗀다.
 * - cp949 / euc-kr: iconv-lite 디코드. iconv-lite 는 strict 모드가 없어 잘못된
 *   바이트를 U+FFFD 로 치환하므로, 결과에 U+FFFD 가 있으면 "디코드 실패"로 간주해
 *   다음 후보로 넘어간다 (Python UnicodeDecodeError 폴백 재현).
 */
import { readFileSync } from "node:fs";
import { decode as iconvDecode } from "iconv-lite";

/** Python "utf-8" 코덱 대응 — BOM 을 유지하고 잘못된 바이트에서 예외(fatal). */
const utf8Fatal = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
/** 최종 폴백 `raw.decode("utf-8", errors="replace")` 대응. */
const utf8Replace = new TextDecoder("utf-8", { ignoreBOM: true });

const DECODE_CANDIDATES = ["utf-8", "utf-8-sig", "cp949", "euc-kr"] as const;
type DecodeCandidate = (typeof DECODE_CANDIDATES)[number];

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
    // iconv-lite 는 예외 대신 U+FFFD 치환이므로, 치환 문자가 있으면 실패로 본다.
    if (decoded.includes("\uFFFD")) return null;
    return decoded;
  } catch {
    return null;
  }
}

/** 파일을 읽어 텍스트로 디코드한다 (utf-8 → utf-8-sig → cp949 → euc-kr → replace). */
export function readText(path: string): string {
  const raw = readFileSync(path);
  for (const encoding of DECODE_CANDIDATES) {
    const decoded = tryDecode(raw, encoding);
    if (decoded !== null) return decoded;
  }
  return utf8Replace.decode(raw);
}
