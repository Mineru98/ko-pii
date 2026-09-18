/**
 * 부분 마스킹 (Partial Redaction) — 공문서 표준 양식 호환.
 *
 * 실제 한국 공문서는 PII 의 일부만 마스킹하는 경우가 많다:
 *   - 성명:    "홍길동" → "홍OO" (성만 노출)
 *   - 주민번호: "880101-1234568" → "880101-1******" (앞 6자리만 노출)
 *   - 전화:    "010-1234-5678" → "010-****-5678" (양 끝만 노출)
 *   - 이메일:  "user@example.com" → "u***@example.com"
 *   - 카드:    "1234-5678-9012-3456" → "1234-****-****-3456"
 *   - 주소:    "서울특별시 강남구 ..." → "서울특별시 강남구 ***"
 *
 * 각 카테고리별 표준 마스킹 룰을 ``partial`` 함수에 제공한다.
 *
 * Legal basis: 「개인정보 비식별 조치 가이드라인」 (개인정보보호위원회) —
 * "부분 마스킹은 비식별 조치의 *부분 일반화* 형태로 인정".
 */

import type { DetectionResult } from "../core/types.js";
import { surnamePrefixLen } from "../dictionaries/surnames.js";
import { generalizeAddress } from "../generalization/address.js";
import { applySubstitutions } from "./apply.js";
import { codePoints, cpLength, foldNdDigits, keepDigits, ndToNumber } from "./unicodeDigits.js";

export const MASK = "*";

// Python ``len()``/슬라이스는 코드 포인트 단위다. 마스킹 결과의 길이·절단 위치는 관찰
// 가능한 출력이므로 아스트랄 문자(이모지·수학 숫자)가 섞인 값은 코드 포인트 배열로 다룬다
// (UTF-16 ``.length``/``.slice`` 는 길이가 달라지고 서로게이트를 반으로 자른다).

/** Python ``MASK * len(text)`` 대응. */
function maskAll(text: string): string {
  return MASK.repeat(cpLength(text));
}

/** Python ``"*" * n`` 대응 — 음수 n 은 빈 문자열 (JS ``repeat`` 은 RangeError). */
function stars(n: number, ch: string = MASK): string {
  return ch.repeat(Math.max(0, n));
}

/**
 * Python ``re`` 의 유니코드 ``\s`` 집합 (= ``str.isspace()``). JS ``\s`` 와 달리
 * U+001C~U+001F·U+0085 를 포함하고 U+FEFF 는 제외한다.
 */
const PY_WS =
  "[\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";

/** Python ``float // 5`` 대응 (양수 피제수) — CPython float_floor_div 의 fmod 기반 절차. */
function pyFloorDiv5(x: number): number {
  const mod = x % 5;
  const div = (x - mod) / 5;
  let floordiv = Math.floor(div);
  if (div - floordiv > 0.5) floordiv += 1;
  return floordiv;
}

/** ``int(x // 5) * 5`` 구간 하한과 상한을 정수 그대로(지수 표기 없이) 문자열화. */
function bucket5(x: number, unit: string): string {
  const lo = BigInt(pyFloorDiv5(x)) * 5n; // inf/NaN 은 RangeError — Python OverflowError/ValueError 대응
  return `${lo}-${lo + 5n}${unit}`;
}

function maskRrn(text: string): string {
  // ``880101-1234568`` → ``880101-1******`` (생년 + gender 만 노출).
  const digits = codePoints(keepDigits(text));
  if (digits.length !== 13) return maskAll(text);
  const hasHyphen = text.includes("-");
  const front = digits.slice(0, 6).join("");
  const gender = digits[6] ?? "";
  const maskedBack = MASK.repeat(6);
  return hasHyphen ? `${front}-${gender}${maskedBack}` : `${front}${gender}${maskedBack}`;
}

function maskPhone(text: string): string {
  // 전화번호 마스킹 — 한국 번호 체계 보존.
  //   010-1234-5678   → 010-****-5678
  //   02-1234-5678    → 02-****-5678  (서울은 2자리 지역번호)
  //   02-123-4567     → 02-***-4567
  //   031-987-6543    → 031-***-6543
  //   +82-10-1234-5678 → +82-10-****-5678
  //   +82-2-1234-5678  → +82-2-****-5678
  //   1588-1234       → 1588-****
  //   0504-1234-5678  → 0504-****-5678 (안심번호)
  const digits = keepDigits(text);
  const dcp = codePoints(digits); // 자릿수·슬라이스는 코드 포인트 기준
  const nDigits = dcp.length;
  const head = (n: number): string => dcp.slice(0, n).join("");
  const last4 = dcp.slice(-4).join("");
  if (nDigits < 7) return maskAll(text);
  const hasPlus = text.startsWith("+");
  let sep = "";
  if (text.includes("-")) sep = "-";
  else if (text.includes(".")) sep = ".";
  else if (text.includes(" ")) sep = " ";

  // +82 국가 코드
  if (hasPlus && digits.startsWith("82")) {
    const rest = dcp.slice(2);
    if (rest[0] === "2") {
      // 서울: +82-2-XXXX-XXXX (앞자리 2 = 02 의 leading 0 제거)
      const sub = rest.slice(1);
      const mid = MASK.repeat(Math.max(3, sub.length - 4));
      return `+82${sep}2${sep}${mid}${sep}${sub.slice(-4).join("")}`;
    }
    if (rest.length >= 9) {
      // 모바일 (10/11/16-19) 및 3자리 지역번호 (31~64, 70)
      const area = rest.slice(0, 2).join("");
      const sub = rest.slice(2);
      const mid = MASK.repeat(Math.max(3, sub.length - 4));
      return `+82${sep}${area}${sep}${mid}${sep}${sub.slice(-4).join("")}`;
    }
  }

  // 050X 안심번호 (12자리: 050X + 4 + 4)
  if (digits.startsWith("050") && nDigits === 12) {
    return `${head(4)}${sep}${MASK.repeat(4)}${sep}${last4}`;
  }

  // 서울 02 (2자리 지역번호)
  if (digits.startsWith("02") && (nDigits === 9 || nDigits === 10)) {
    const subLen = nDigits - 2;
    return `02${sep}${MASK.repeat(subLen - 4)}${sep}${last4}`;
  }

  // 1588/1577/1644 형식 (8자리, 지역번호 없음)
  if (nDigits === 8 && ["15", "16", "18"].includes(head(2))) {
    return `${head(4)}${sep}${MASK.repeat(4)}`;
  }

  // 모바일 (010-019) 및 3자리 지역번호 (031-064, 070)
  if (nDigits >= 11) {
    return `${head(3)}${sep}${MASK.repeat(4)}${sep}${last4}`;
  }
  if (nDigits === 10) {
    return `${head(3)}${sep}${MASK.repeat(3)}${sep}${last4}`;
  }
  if (nDigits === 9) {
    return `${head(2)}${sep}${MASK.repeat(3)}${sep}${last4}`;
  }
  return maskAll(text);
}

function maskEmail(text: string): string {
  // ``user@example.com`` → ``u***@example.com`` (로컬 앞자만 노출).
  if (!text.includes("@")) return maskAll(text);
  const at = text.indexOf("@");
  const local = codePoints(text.slice(0, at));
  const domain = text.slice(at + 1);
  if (local.length === 0) return text;
  if (local.length <= 1) return `${local.join("")}${MASK.repeat(3)}@${domain}`;
  return `${local[0] ?? ""}${MASK.repeat(Math.max(3, local.length - 1))}@${domain}`;
}

function maskCard(text: string): string {
  // ``1234-5678-9012-3456`` → ``1234-****-****-3456`` (BIN + 마지막 4).
  const digits = codePoints(keepDigits(text));
  if (digits.length < 8) return maskAll(text);
  // 길이 보존하면서 중간만 가림
  const hasHyphen = text.includes("-");
  const hasSpace = text.includes(" ");
  const sep = hasHyphen ? "-" : hasSpace ? " " : "";
  const front = digits.slice(0, 4).join("");
  const back = digits.slice(-4).join("");
  const middleLen = digits.length - 8;
  if (sep) {
    // 4자리 그룹 형태로 재조합
    const groups: string[] = [front];
    let i = 4;
    while (i < digits.length - 4) {
      groups.push(MASK.repeat(Math.min(4, digits.length - 4 - i)));
      i += 4;
    }
    groups.push(back);
    return groups.join(sep);
  }
  return `${front}${MASK.repeat(middleLen)}${back}`;
}

function maskName(text: string): string {
  // ``홍길동`` → ``홍OO`` (성만 노출, 이름은 한국 표준 O 로 마스킹).
  let sp = surnamePrefixLen(text);
  if (sp === 0) sp = 1; // 폴백: 첫 글자만 노출
  const cps = codePoints(text);
  if (cps.length <= sp) return text;
  return cps.slice(0, sp).join("") + "O".repeat(cps.length - sp);
}

function maskAddress(text: string): string {
  // 주소: 시·도/시·군·구까지만 노출, 도로명 이하 마스킹.
  const g = generalizeAddress(text, "district");
  return g !== text ? `${g} ${MASK.repeat(3)}` : maskAll(text);
}

function maskAccount(text: string): string {
  // 계좌: 앞 4 + 끝 4 노출, 중간 마스킹.
  const digits = codePoints(keepDigits(text));
  if (digits.length < 8) return maskAll(text);
  return `${digits.slice(0, 4).join("")}${MASK.repeat(digits.length - 8)}${digits.slice(-4).join("")}`;
}

function maskPassport(text: string): string {
  // 여권: prefix + 마지막 2자리 노출.
  // Python ``$`` 는 문자열 끝의 개행 직전에도 매칭한다 → ``\n?$``.
  const m = /^([A-Z]{1,2})(\p{Nd}+)\n?$/u.exec(text);
  if (!m) return maskAll(text);
  const prefix = m[1] ?? "";
  const digits = codePoints(m[2] ?? "");
  // 숫자 1자리("M1")면 Python 은 ``"*" * -1 == ""`` — repeat 음수 가드.
  return `${prefix}${stars(digits.length - 2)}${digits.slice(-2).join("")}`;
}

function maskDefault(text: string): string {
  // 기본: 전체 마스킹 (가능하면 양 끝 2자리는 노출).
  const cps = codePoints(text);
  if (cps.length <= 4) return maskAll(text);
  return cps.slice(0, 2).join("") + MASK.repeat(cps.length - 4) + cps.slice(-2).join("");
}

// Python ``\s`` 집합 + ``$`` 의 끝 개행 허용(``\n?$``)을 그대로 재현.
const KOR_BIRTH = new RegExp(
  `^(\\p{Nd}{2,4})${PY_WS}*년${PY_WS}*\\p{Nd}{1,2}${PY_WS}*월${PY_WS}*\\p{Nd}{1,2}${PY_WS}*일\\n?$`,
  "u",
);

function maskBirth(text: string): string {
  // 생년월일: 연도만 노출, 월/일 마스킹.
  //   1988년 1월 1일 → 1988년 **월 **일
  //   1988-01-01     → 1988-**-**
  //   88.01.01       → 88.**.**
  //   88년생          → 그대로 (이미 연도만)
  // "년생" 형태는 이미 연도만 → 그대로 두거나 마스킹 강도 낮음
  if (text.endsWith("년생")) return text;
  // 한국어: 1988년 X월 X일
  const kor = KOR_BIRTH.exec(text);
  if (kor) return `${kor[1]}년 ${MASK.repeat(2)}월 ${MASK.repeat(2)}일`;
  // 숫자 형식: 1988.01.01 / 1988-01-01 / 1988/01/01 / 88.01.01
  const numeric = /^(\p{Nd}{2,4})([./-])\p{Nd}{1,2}\2\p{Nd}{1,2}\n?$/u.exec(text);
  if (numeric) {
    const sep = numeric[2] ?? "";
    return `${numeric[1]}${sep}${MASK.repeat(2)}${sep}${MASK.repeat(2)}`;
  }
  return maskAll(text);
}

function maskEducation(text: string): string {
  // 학력: 대학교명 → 'X대학교' (계열은 보존하지 않고 한글 X 로 치환).
  //   서울대학교 → ○대학교
  //   KAIST     → ○○○○○ (영문은 모두 가림)
  // 한국어 대학교명: 첫 글자만 ○ 로 + "대학교/대학" 유지
  for (const suf of ["대학원대학교", "전문대학", "대학교", "대학"]) {
    if (text.endsWith(suf)) return `○${suf}`;
  }
  // 영문 약칭 (KAIST 등) → 전체 마스킹
  return maskAll(text);
}

function maskMajor(text: string): string {
  // 전공: 계열까지만 노출.
  //   컴퓨터공학과 → ○○○○학과
  //   경영학       → ○○학
  // 접미사 유지
  for (const suf of ["학과", "학부", "전공", "학", "과"]) {
    if (text.endsWith(suf) && text.length > suf.length) {
      const stem = text.slice(0, -suf.length);
      return "○".repeat(cpLength(stem)) + suf;
    }
  }
  return maskAll(text);
}

function maskPosition(text: string): string {
  // 직책: 그대로 (이미 일반화된 직급).
  return text;
}

function maskAge(text: string): string {
  // 나이: 10세 단위 구간화. '32세' → '30대'.
  const m = /(\p{Nd}+)/u.exec(text);
  const raw = m?.[1];
  if (raw !== undefined) {
    const age = BigInt(foldNdDigits(raw)); // Python int() — 임의 정밀도
    if (age < 10n) return "10대 미만";
    const decade = (age / 10n) * 10n;
    return `${decade}대`;
  }
  return maskAll(text);
}

function maskHeight(text: string): string {
  // 신장: 5cm 구간화. '175cm' → '175-180cm'.
  const m = /(\p{Nd}+(?:\.\p{Nd}+)?)/u.exec(text);
  const raw = m?.[1];
  if (raw !== undefined) {
    let h = ndToNumber(raw);
    // m 단위면 cm 로 변환
    if (h < 3) h *= 100;
    return bucket5(h, "cm");
  }
  return maskAll(text);
}

function maskWeight(text: string): string {
  // 체중: 5kg 구간화. '70kg' → '70-75kg'.
  const m = /(\p{Nd}+(?:\.\p{Nd}+)?)/u.exec(text);
  const raw = m?.[1];
  if (raw !== undefined) {
    const w = ndToNumber(raw);
    return bucket5(w, "kg");
  }
  return maskAll(text);
}

type Masker = (text: string) => string;

const MASKERS = new Map<string, Masker>([
  ["RRN", maskRrn],
  ["FRN", maskRrn],
  ["PHONE", maskPhone],
  ["FAX", maskPhone],
  ["EMAIL", maskEmail],
  ["CARD", maskCard],
  ["PERSON", maskName],
  ["ADDRESS", maskAddress],
  ["ACCOUNT", maskAccount],
  ["PASSPORT", maskPassport],
  // KDPII 표준 준식별자
  ["DT_BIRTH", maskBirth],
  ["EDUCATION", maskEducation],
  ["MAJOR", maskMajor],
  ["POSITION", maskPosition],
  ["AGE", maskAge],
  ["HEIGHT", maskHeight],
  ["WEIGHT", maskWeight],
]);

/** Apply category-aware partial masking to each detection span. */
export function partial(text: string, detections: Iterable<DetectionResult>): string {
  const replace = (d: DetectionResult): string => (MASKERS.get(d.label) ?? maskDefault)(d.text);
  return applySubstitutions(text, detections, replace);
}

/** Stand-alone helper: ``mask_value("RRN", "880101-1234568")`` → ``880101-1******``. */
export function maskValue(label: string, value: string): string {
  const masker = MASKERS.get(label) ?? maskDefault;
  return masker(value);
}
