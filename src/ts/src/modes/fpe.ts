/**
 * 형식 보존 가명화 (Format-Preserving Pseudonymization).
 *
 * 원본 PII 와 *같은 구조* (자릿수·구분자 위치·하이픈) 를 유지하면서 값만 바꾼다.
 * 데이터 분석·통계 호환성이 필요할 때 사용 (예: RRN 컬럼 길이·체크섬 형태 유지).
 *
 * - 결정적: 같은 입력 + 같은 vault salt → 같은 출력
 * - 가역적이지는 않음 (rainbow table 공격 회피). 복원이 필요하면 ``tokenize`` 사용.
 *
 * 알고리즘:
 * 1. ``(label, original)`` 의 salted SHA-256 fingerprint 를 얻는다.
 * 2. fingerprint 를 카테고리별 길이·형식에 맞춰 변환:
 *    - 숫자 자릿: hex → digit (mod 10)
 *    - 알파벳: A-Z 범위 매핑
 *    - 구분자(하이픈/공백/점/@)는 원위치 유지
 * 3. RRN/카드처럼 체크섬이 있는 경우 마지막 자리는 체크섬 재계산.
 *
 * 본 모듈은 *진정한 FPE* (FF1/FF3) 가 아니라 **형식 보존 결정적 매핑** — 길이와
 * 구조만 보존. 강한 암호학적 가역성이 필요하면 별도 FF1 구현 필요.
 *
 * Legal basis: 「가명정보 처리 가이드라인」 (개인정보보호위원회) — 형식 보존
 * 가명화는 데이터 효용 보존을 위한 권장 기법.
 *
 * 구현 참고: 256비트 지문 hex 는 Number 범위를 초과하므로 Python ``int(fp, 16)``
 * 은 ``BigInt("0x" + fp)`` 로, ``val //= k`` 는 BigInt 나눗셈(절사)으로 옮긴다.
 */
import { computeCheckDigit, luhnComputeCheckDigit } from "../checksum/index.js";
import { pyIsAlpha, pyIsAscii, pyIsDigit } from "../core/strUtils.js";
import type { DetectionResult } from "../core/types.js";
import { applySubstitutions } from "./apply.js";
import { keepDigits, ndToNumber } from "./unicodeDigits.js";
import type { ModesVault } from "./vault.js";

/** Convert hex fingerprint into ``n`` decimal digits. */
function digitsFromHash(fp: string, n: number): string {
  // Use the integer value of the hash and mod each digit out
  const base = BigInt(`0x${fp}`);
  let val = base;
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    out.push((val % 10n).toString());
    val /= 10n;
    if (val === 0n) val = base; // cycle
  }
  return out.join("");
}

function alphaFromHash(fp: string, n: number): string {
  const base = BigInt(`0x${fp}`);
  let val = base;
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    out.push(String.fromCharCode(65 + Number(val % 26n)));
    val /= 26n;
    if (val === 0n) val = base;
  }
  return out.join("");
}

const ND_ONLY = /^\p{Nd}+$/u;

/**
 * Python ``rrn_checksum.compute_check_digit`` 은 ``isdigit()``/``int()`` 로 Nd
 * 자리(전각 포함)를 받아들인다. 재단 checksum 은 ASCII 전용이므로 Nd 를 값으로
 * 접어 동일 결과를 낸다.
 */
function rrnCheckDigitNd(twelve: string): number {
  if (twelve.length !== 12 || ![...twelve].every((ch) => ND_ONLY.test(ch))) {
    throw new Error("expected a 12-digit numeric string");
  }
  const folded = [...twelve].map((ch) => ndToNumber(ch).toString()).join("");
  return computeCheckDigit(folded);
}

/** Python ``luhn.compute_check_digit`` 동일 Nd 의미론 래퍼. */
function luhnCheckDigitNd(payload: string): number {
  if (!ND_ONLY.test(payload)) throw new Error("expected numeric string");
  const folded = [...payload].map((ch) => ndToNumber(ch).toString()).join("");
  return luhnComputeCheckDigit(folded);
}

/** Hangul syllable 블록 (U+AC00..U+D7A3) 크기 — 11172 자. */
const HANGUL_COUNT = 0xd7a3 - 0xac00 + 1;

/** Convert hex fingerprint into ``n`` Hangul syllables (U+AC00..U+D7A3). */
function hangulFromHash(fp: string, n: number): string {
  const base = BigInt(`0x${fp}`);
  const count = BigInt(HANGUL_COUNT);
  let val = base;
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    out.push(String.fromCharCode(0xac00 + Number(val % count)));
    val /= count;
    if (val === 0n) val = base;
  }
  return out.join("");
}

/** RRN: 13자리, 6-7 사이 하이픈, 7번째 자리(gender) 유지. */
function fpeRrn(original: string, fp: string): string {
  const digits = keepDigits(original);
  if (digits.length !== 13) return digitsFromHash(fp, digits.length);
  // RRN = 6 (date) + 1 (gender) + 5 (region) + 1 (check) = 13
  const frontNew = digitsFromHash(fp.slice(0, 16), 6);
  const gender = digits.charAt(6); // gender 자리 유지 (성별 분포 보존)
  const backPartial = digitsFromHash(fp.slice(16, 30), 5);
  // 체크섬 재계산 — 첫 12자리에서 산출
  const newFirst12 = `${frontNew}${gender}${backPartial}`;
  let check: number;
  try {
    check = rrnCheckDigitNd(newFirst12);
  } catch {
    check = 0;
  }
  const newFull = `${newFirst12}${check}`;
  const hasHyphen = original.includes("-");
  return hasHyphen ? `${newFull.slice(0, 6)}-${newFull.slice(6)}` : newFull;
}

/**
 * 숫자만 새 값으로 바꾸고 원본의 구분자(비숫자 문자)는 제자리에 유지한다.
 * Python ``_fpe_phone``/``_fpe_card`` 말미의 재조합 루프 공통.
 */
function rebuildPreservingSeparators(original: string, newDigits: string): string {
  const chars: string[] = [];
  let di = 0;
  for (const ch of original) {
    if (pyIsDigit(ch)) {
      chars.push(newDigits.charAt(di));
      di += 1;
    } else {
      chars.push(ch);
    }
  }
  return chars.join("");
}

/** 전화: 자릿수·구분자·prefix 유지. 010/02/031 등은 보존. */
function fpePhone(original: string, fp: string): string {
  const digits = keepDigits(original);
  if (digits.length < 9) return digitsFromHash(fp, digits.length);
  // 통신사·지역 prefix 보존 (식별과 무관한 *통계* 정보)
  let prefixLen: number;
  if (["010", "011", "016", "017", "018", "019", "070", "02"].some((p) => digits.startsWith(p))) {
    prefixLen = digits.startsWith("02") ? 2 : 3;
  } else if (
    [
      "031",
      "032",
      "033",
      "041",
      "042",
      "043",
      "044",
      "051",
      "052",
      "053",
      "054",
      "055",
      "061",
      "062",
      "063",
      "064",
    ].some((p) => digits.startsWith(p))
  ) {
    prefixLen = 3;
  } else {
    prefixLen = 2;
  }
  const prefix = digits.slice(0, prefixLen);
  const newTail = digitsFromHash(fp, digits.length - prefixLen);
  const newDigits = prefix + newTail;
  // 구분자 위치 보존
  return rebuildPreservingSeparators(original, newDigits);
}

/** 카드: BIN(첫 6자리) 보존 + 마지막 자리 Luhn 재계산. */
function fpeCard(original: string, fp: string): string {
  const digits = keepDigits(original);
  if (digits.length < 13) return digitsFromHash(fp, digits.length);
  const binPart = digits.slice(0, 6);
  const body = digitsFromHash(fp, digits.length - 6 - 1);
  const partial = binPart + body;
  let check: number;
  try {
    check = luhnCheckDigitNd(partial);
  } catch {
    check = 0;
  }
  const newDigits = partial + String(check);
  return rebuildPreservingSeparators(original, newDigits);
}

/** 이메일: 도메인은 그대로, 로컬 부분만 무작위 영숫자. */
function fpeEmail(original: string, fp: string): string {
  if (!original.includes("@")) return original;
  const at = original.indexOf("@");
  const local = original.slice(0, at);
  const domain = original.slice(at + 1);
  const newLocal = alphaFromHash(fp, Math.max(4, local.length))
    .toLowerCase()
    .slice(0, local.length);
  return `${newLocal}@${domain}`;
}

/** 여권: prefix(M/S/PP 등) 유지, 8자리 숫자만 변경. */
function fpePassport(original: string, fp: string): string {
  const m = /^([A-Z]{1,2})([0-9]+)$/.exec(original);
  if (!m) return original;
  const prefix = m[1] ?? "";
  const digits = m[2] ?? "";
  return prefix + digitsFromHash(fp, digits.length);
}

/** ``_FPE_BY_LABEL`` 에 없는 라벨의 기본 변환 (Python ``_fpe_default`` 대응). */
export function fpeDefault(original: string, fp: string): string {
  const chars: string[] = [];
  const digitPool = digitsFromHash(fp, original.length);
  const alphaPool = alphaFromHash(fp, original.length);
  const hangulPool = hangulFromHash(fp, original.length);
  let di = 0;
  let ai = 0;
  let hi = 0;
  for (const ch of original) {
    if (pyIsDigit(ch)) {
      chars.push(digitPool.charAt(di));
      di += 1;
    } else if (ch >= "가" && ch <= "힣") {
      // 한글 음절 → 한글로 치환 (형식 유지; isalpha 가 한글도 True 라 먼저 처리)
      chars.push(hangulPool.charAt(hi));
      hi += 1;
    } else if (pyIsAscii(ch) && pyIsAlpha(ch)) {
      const mapped = alphaPool.charAt(ai);
      chars.push(ch >= "A" && ch <= "Z" ? mapped : mapped.toLowerCase());
      ai += 1;
    } else {
      chars.push(ch); // 구분자 등은 그대로
    }
  }
  return chars.join("");
}

/** 라벨별 FPE 변환 함수 테이블 (Python ``_FPE_BY_LABEL`` 대응). */
export const FPE_BY_LABEL = new Map<string, (original: string, fp: string) => string>([
  ["RRN", fpeRrn],
  ["FRN", fpeRrn],
  ["PHONE", fpePhone],
  ["FAX", fpePhone],
  ["CARD", fpeCard],
  ["EMAIL", fpeEmail],
  ["PASSPORT", fpePassport],
]);

/**
 * Replace each detection with a format-preserving pseudo-value.
 *
 * Returns ``[replaced_text, vault]``. The vault stores the original-to-fake
 * mapping so reproducible regeneration is possible (not strictly reversible).
 */
export function fpe(
  text: string,
  detections: Iterable<DetectionResult>,
  vault: ModesVault,
): [string, ModesVault] {
  const v = vault;
  const list = [...detections];

  const replace = (d: DetectionResult): string => {
    const fp = v.fingerprint(d.label, d.text);
    const fn = FPE_BY_LABEL.get(d.label) ?? fpeDefault;
    const newValue = fn(d.text, fp);
    // Store the mapping for audit
    v.store({
      label: d.label,
      original: d.text,
      riskLevel: d.riskLevel,
      legal_basis: d.legal_basis,
      offset: d.start,
      extra: { ...d.extra, fpe_value: newValue },
    });
    return newValue;
  };

  const replaced = applySubstitutions(text, list, replace);
  return [replaced, v];
}
