/**
 * 형식 보존 가명화 (Format-Preserving Pseudonymization).
 *
 * 원본 PII 와 *같은 구조* (자릿수·구분자 위치·하이픈) 를 유지하면서 값만 바꾼다.
 * 데이터 분석·통계 호환성이 필요할 때 사용 (예: RRN 컬럼 길이·체크섬 형태 유지).
 *
 * - 결정적: 같은 입력 + 같은 Vault 지문 설정(키·salt·scheme·반복 횟수) → 같은 출력
 * - 원문은 Vault에 저장된다. 출력의 형식만으로 원문을 복원하는 암호 방식은 아니다.
 *
 * 알고리즘:
 * 1. ``(label, original)`` 의 Vault fingerprint 를 얻는다 (신규 기본값: PBKDF2).
 * 2. fingerprint 를 카테고리별 길이·형식에 맞춰 변환:
 *    - 숫자 자릿: hex → digit (mod 10)
 *    - 알파벳: A-Z 범위 매핑
 *    - 구분자(하이픈/공백/점/@)는 원위치 유지
 * 3. RRN/카드처럼 체크섬이 있는 경우 마지막 자리는 체크섬 재계산.
 *
 * 본 모듈은 *진정한 FPE* (FF1/FF3) 가 아니라 **형식 보존 결정적 매핑** — 길이와
 * 구조만 보존. 강한 암호학적 가역성이 필요하면 별도 FF1 구현 필요.
 *
 * 비표준 숫자 표기는 정규화되므로 길이·구분자가 바뀔 수 있다. 지원하지 않는 형식이나
 * 변환 후 값이 그대로인 경우에는 원문 길이의 별표로 전체 마스킹한다.
 *
 * Legal basis: 「가명정보 처리 가이드라인」 (개인정보보호위원회) — 형식 보존
 * 가명화는 데이터 효용 보존을 위한 권장 기법.
 *
 * 구현 참고: 256비트 지문 hex 는 Number 범위를 초과하므로 Python ``int(fp, 16)``
 * 은 ``BigInt("0x" + fp)`` 로, ``val //= k`` 는 BigInt 나눗셈(절사)으로 옮긴다.
 */

import {
  computeCheckDigit,
  computeFrnCheckDigit,
  luhnComputeCheckDigit,
} from "../checksum/index.js";
import { ValueError } from "../core/errors.js";
import { pyIsAlpha, pyIsAscii, pyIsDigit } from "../core/strUtils.js";
import type { DetectionResult } from "../core/types.js";
import { normalizeUnicode } from "../core/unicodeNorm.js";
import { ReversibleVault } from "../vault/reversible.js";
import { applySubstitutions, prepareDetections } from "./apply.js";
import { isModernPassportNumber, splitLiteralEmail } from "./literalShapes.js";
import {
  codePoints,
  cpLength,
  keepDigits,
  ndToNumber,
  PY_WS,
  pyStrIsDigit,
} from "./unicodeDigits.js";
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
  if (cpLength(twelve) !== 12 || ![...twelve].every((ch) => ND_ONLY.test(ch))) {
    throw new ValueError("expected a 12-digit numeric string");
  }
  const folded = [...twelve].map((ch) => ndToNumber(ch).toString()).join("");
  return computeCheckDigit(folded);
}

/** Python ``luhn.compute_check_digit`` 동일 Nd 의미론 래퍼. */
function luhnCheckDigitNd(payload: string): number {
  if (!ND_ONLY.test(payload)) throw new ValueError("expected numeric string");
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

/** Preserve the 13-digit shape and gender digit, not a valid birth date. */
function fpeRegistration(
  original: string,
  fp: string,
  checkDigit: (twelve: string) => number,
): string {
  // Python 은 코드 포인트 단위 — 아스트랄 Nd(수학 숫자 등)도 한 자리로 센다.
  const digits = codePoints(keepDigits(original));
  if (digits.length !== 13) return digitsFromHash(fp, digits.length);
  // RRN = 6 (date) + 1 (gender) + 5 (region) + 1 (check) = 13
  const frontNew = digitsFromHash(fp.slice(0, 16), 6);
  const gender = digits[6] ?? ""; // gender 자리 유지 (성별 분포 보존)
  const backPartial = digitsFromHash(fp.slice(16, 30), 5);
  // 체크섬 재계산 — 첫 12자리에서 산출
  const newFirst12 = `${frontNew}${gender}${backPartial}`;
  let check: number;
  try {
    check = checkDigit(newFirst12);
  } catch {
    check = 0;
  }
  const newFull = codePoints(`${newFirst12}${check}`);
  const hasHyphen = original.includes("-");
  return hasHyphen
    ? `${newFull.slice(0, 6).join("")}-${newFull.slice(6).join("")}`
    : newFull.join("");
}

function fpeRrn(original: string, fp: string): string {
  return fpeRegistration(original, fp, rrnCheckDigitNd);
}

function fpeFrn(original: string, fp: string): string {
  return fpeRegistration(original, fp, computeFrnCheckDigit);
}

/**
 * 숫자만 새 값으로 바꾸고 원본의 구분자(비숫자 문자)는 제자리에 유지한다.
 * Python ``_fpe_phone``/``_fpe_card`` 말미의 재조합 루프 공통 (``ch.isdecimal()`` = Nd).
 */
function rebuildPreservingSeparators(original: string, newDigits: readonly string[]): string {
  const chars: string[] = [];
  let di = 0;
  for (const ch of original) {
    if (pyIsDigit(ch)) {
      chars.push(newDigits[di] ?? "");
      di += 1;
    } else {
      chars.push(ch);
    }
  }
  return chars.join("");
}

// A typed field may contain prose. Only numeric formatting may survive.
// Python ``[0-9]`` 는 ASCII, ``\s`` 는 유니코드 공백.
const PHONE_SHAPE = new RegExp(`^\\+?(?:[0-9().\\[\\]-]|${PY_WS})+$`, "u");
const CARD_SHAPE = new RegExp(`^(?:[0-9. /-]|${PY_WS})+$`, "u");

/** 전화: 자릿수·구분자·prefix 유지. 010/02/031 등은 보존. */
function fpePhone(original: string, fp: string): string {
  const digits = keepDigits(original);
  const digitCps = codePoints(digits);
  if (!PHONE_SHAPE.test(original) || digitCps.length < 7 || digitCps.length > 15) return original;
  if (digitCps.length < 9) return digitsFromHash(fp, digitCps.length);
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
  const prefix = digitCps.slice(0, prefixLen);
  const newTail = digitsFromHash(fp, digitCps.length - prefixLen);
  const newDigits = [...prefix, ...newTail];
  // 구분자 위치 보존
  return rebuildPreservingSeparators(original, newDigits);
}

/** 카드: BIN(첫 6자리) 보존 + 마지막 자리 Luhn 재계산. */
function fpeCard(original: string, fp: string): string {
  const digits = codePoints(keepDigits(original));
  if (!CARD_SHAPE.test(original) || digits.length < 13 || digits.length > 19) return original;
  const binPart = digits.slice(0, 6).join("");
  const body = digitsFromHash(fp, digits.length - 6 - 1);
  const partial = binPart + body;
  let check: number;
  try {
    check = luhnCheckDigitNd(partial);
  } catch {
    check = 0;
  }
  const newDigits = codePoints(partial + String(check));
  return rebuildPreservingSeparators(original, newDigits);
}

/** 이메일: 도메인은 그대로, 로컬 부분만 무작위 영숫자. */
function fpeEmail(original: string, fp: string): string {
  const parts = splitLiteralEmail(original);
  // The shared caller replaces unsupported values with a full mask.
  if (parts === null) return original;
  const [local, domain] = parts;
  const localLen = cpLength(local); // Python len() — 코드 포인트 수
  const newLocal = alphaFromHash(fp, Math.max(4, localLen)).toLowerCase().slice(0, localLen);
  return `${newLocal}@${domain}`;
}

/** Preserve the prefix and supported numeric/alphanumeric serial shape. */
function fpePassport(original: string, fp: string): string {
  if (isModernPassportNumber(original)) {
    const digits = digitsFromHash(fp, 7);
    return `${original[0]}${digits.slice(0, 3)}${alphaFromHash(fp, 1)}${digits.slice(3)}`;
  }
  // Python ``re.fullmatch(r"([A-Z]{1,2})([0-9]+)")`` — ASCII 숫자, 끝 개행 불허.
  const m = /^([A-Z]{1,2})([0-9]+)$/.exec(original);
  if (!m) return original;
  const prefix = m[1] ?? "";
  const digits = m[2] ?? "";
  return prefix + digitsFromHash(fp, digits.length);
}

/** ``_FPE_BY_LABEL`` 에 없는 라벨의 기본 변환 (Python ``_fpe_default`` 대응). */
export function fpeDefault(original: string, fp: string): string {
  const chars: string[] = [];
  const n = cpLength(original);
  const digitPool = digitsFromHash(fp, n);
  const alphaPool = alphaFromHash(fp, n);
  const hangulPool = hangulFromHash(fp, n);
  let di = 0;
  let ai = 0;
  let hi = 0;
  for (const ch of original) {
    if (pyStrIsDigit(ch)) {
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
    } else if (pyIsAlpha(ch)) {
      chars.push("*");
    } else {
      chars.push(ch); // 구분자 등은 그대로
    }
  }
  return chars.join("");
}

/** 라벨별 FPE 변환 함수 테이블 (Python ``_FPE_BY_LABEL`` 대응). */
export const FPE_BY_LABEL = new Map<string, (original: string, fp: string) => string>([
  ["RRN", fpeRrn],
  ["FRN", fpeFrn],
  ["PHONE", fpePhone],
  ["FAX", fpePhone],
  ["CARD", fpeCard],
  ["EMAIL", fpeEmail],
  ["PASSPORT", fpePassport],
]);

/** 정규화(NFKC 대신 normalizeUnicode)를 공유하는 숫자형 라벨. */
const NORMALIZED_LABELS: ReadonlySet<string> = new Set([
  "RRN",
  "FRN",
  "PHONE",
  "FAX",
  "CARD",
  "ACCOUNT",
]);

/**
 * Share normalization and fail-closed fallback across every FPE entry point
 * (Python ``_pseudonymize_value``). 결과가 비었거나 원문/정규화 값과 같으면 원문
 * 길이(코드 포인트)의 별표로 전체 마스킹한다.
 */
export function pseudonymizeValue(label: string, original: string, fp: string): string {
  // Numeric homoglyph folding must not rewrite an email's domain letters.
  const normalized = NORMALIZED_LABELS.has(label)
    ? normalizeUnicode(original)[0]
    : original.normalize("NFKC");
  const fn = FPE_BY_LABEL.get(label) ?? fpeDefault;
  const result = fn(normalized, fp);
  if (!result || result === original || result === normalized) {
    return "*".repeat(cpLength(original));
  }
  return result;
}

/**
 * Replace each detection with a format-preserving pseudo-value.
 *
 * Returns ``[replaced_text, vault]``. The vault stores the original-to-fake
 * mapping so reproducible regeneration is possible (not strictly reversible).
 * vault 를 생략하면 새 ReversibleVault 를 만든다 (Python ``vault=None`` 대응).
 */
export function fpe(text: string, detections: Iterable<DetectionResult>): [string, ReversibleVault];
export function fpe<V extends ModesVault>(
  text: string,
  detections: Iterable<DetectionResult>,
  vault: V,
): [string, V];
export function fpe(
  text: string,
  detections: Iterable<DetectionResult>,
  vault?: ModesVault | null,
): [string, ModesVault];
export function fpe(
  text: string,
  detections: Iterable<DetectionResult>,
  vault?: ModesVault | null,
): [string, ModesVault] {
  // 원문 결속 검증을 지문·Vault 기록보다 먼저 — 실패 시 Vault 는 변경되지 않는다.
  const list = prepareDetections(text, detections);
  const v: ModesVault = vault ?? new ReversibleVault();

  const replace = (d: DetectionResult): string => {
    const fp = v.fingerprint(d.label, d.text);
    const newValue = pseudonymizeValue(d.label, d.text, fp);
    // Store the mapping for audit
    v.store(d.label, d.text, d.riskLevel, d.legal_basis, d.start, {
      ...d.extra,
      fpe_value: newValue,
    });
    return newValue;
  };

  const replaced = applySubstitutions(text, list, replace);
  return [replaced, v];
}
