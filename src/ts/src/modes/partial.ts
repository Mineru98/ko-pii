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
import { keepDigits, ndToNumber } from "./unicodeDigits.js";

export const MASK = "*";

function maskRrn(text: string): string {
  // ``880101-1234568`` → ``880101-1******`` (생년 + gender 만 노출).
  const digits = keepDigits(text);
  if (digits.length !== 13) return MASK.repeat(text.length);
  const hasHyphen = text.includes("-");
  const front = digits.slice(0, 6);
  const gender = digits.charAt(6);
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
  if (digits.length < 7) return MASK.repeat(text.length);
  const hasPlus = text.startsWith("+");
  let sep = "";
  if (text.includes("-")) sep = "-";
  else if (text.includes(".")) sep = ".";
  else if (text.includes(" ")) sep = " ";

  // +82 국가 코드
  if (hasPlus && digits.startsWith("82")) {
    const rest = digits.slice(2);
    if (rest.startsWith("2")) {
      // 서울: +82-2-XXXX-XXXX (앞자리 2 = 02 의 leading 0 제거)
      const sub = rest.slice(1);
      const mid = MASK.repeat(Math.max(3, sub.length - 4));
      return `+82${sep}2${sep}${mid}${sep}${sub.slice(-4)}`;
    }
    if (rest.length >= 9) {
      // 모바일 (10/11/16-19) 및 3자리 지역번호 (31~64, 70)
      const area = rest.slice(0, 2);
      const sub = rest.slice(2);
      const mid = MASK.repeat(Math.max(3, sub.length - 4));
      return `+82${sep}${area}${sep}${mid}${sep}${sub.slice(-4)}`;
    }
  }

  // 050X 안심번호 (12자리: 050X + 4 + 4)
  if (digits.startsWith("050") && digits.length === 12) {
    return `${digits.slice(0, 4)}${sep}${MASK.repeat(4)}${sep}${digits.slice(-4)}`;
  }

  // 서울 02 (2자리 지역번호)
  if (digits.startsWith("02") && (digits.length === 9 || digits.length === 10)) {
    const subLen = digits.length - 2;
    return `02${sep}${MASK.repeat(subLen - 4)}${sep}${digits.slice(-4)}`;
  }

  // 1588/1577/1644 형식 (8자리, 지역번호 없음)
  if (digits.length === 8 && ["15", "16", "18"].includes(digits.slice(0, 2))) {
    return `${digits.slice(0, 4)}${sep}${MASK.repeat(4)}`;
  }

  // 모바일 (010-019) 및 3자리 지역번호 (031-064, 070)
  if (digits.length >= 11) {
    return `${digits.slice(0, 3)}${sep}${MASK.repeat(4)}${sep}${digits.slice(-4)}`;
  }
  if (digits.length === 10) {
    return `${digits.slice(0, 3)}${sep}${MASK.repeat(3)}${sep}${digits.slice(-4)}`;
  }
  if (digits.length === 9) {
    return `${digits.slice(0, 2)}${sep}${MASK.repeat(3)}${sep}${digits.slice(-4)}`;
  }
  return MASK.repeat(text.length);
}

function maskEmail(text: string): string {
  // ``user@example.com`` → ``u***@example.com`` (로컬 앞자만 노출).
  if (!text.includes("@")) return MASK.repeat(text.length);
  const at = text.indexOf("@");
  const local = text.slice(0, at);
  const domain = text.slice(at + 1);
  if (local.length === 0) return text;
  if (local.length <= 1) return `${local}${MASK.repeat(3)}@${domain}`;
  return `${local.charAt(0)}${MASK.repeat(Math.max(3, local.length - 1))}@${domain}`;
}

function maskCard(text: string): string {
  // ``1234-5678-9012-3456`` → ``1234-****-****-3456`` (BIN + 마지막 4).
  const digits = keepDigits(text);
  if (digits.length < 8) return MASK.repeat(text.length);
  // 길이 보존하면서 중간만 가림
  const hasHyphen = text.includes("-");
  const hasSpace = text.includes(" ");
  const sep = hasHyphen ? "-" : hasSpace ? " " : "";
  const front = digits.slice(0, 4);
  const back = digits.slice(-4);
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
  if (text.length <= sp) return text;
  return text.slice(0, sp) + "O".repeat(text.length - sp);
}

function maskAddress(text: string): string {
  // 주소: 시·도/시·군·구까지만 노출, 도로명 이하 마스킹.
  const g = generalizeAddress(text, "district");
  return g !== text ? `${g} ${MASK.repeat(3)}` : MASK.repeat(text.length);
}

function maskAccount(text: string): string {
  // 계좌: 앞 4 + 끝 4 노출, 중간 마스킹.
  const digits = keepDigits(text);
  if (digits.length < 8) return MASK.repeat(text.length);
  return `${digits.slice(0, 4)}${MASK.repeat(digits.length - 8)}${digits.slice(-4)}`;
}

function maskPassport(text: string): string {
  // 여권: prefix + 마지막 2자리 노출.
  const m = /^([A-Z]{1,2})(\p{Nd}+)$/u.exec(text);
  if (!m) return MASK.repeat(text.length);
  const prefix = m[1] ?? "";
  const digits = m[2] ?? "";
  return `${prefix}${MASK.repeat(digits.length - 2)}${digits.slice(-2)}`;
}

function maskDefault(text: string): string {
  // 기본: 전체 마스킹 (가능하면 양 끝 2자리는 노출).
  if (text.length <= 4) return MASK.repeat(text.length);
  return text.slice(0, 2) + MASK.repeat(text.length - 4) + text.slice(-2);
}

function maskBirth(text: string): string {
  // 생년월일: 연도만 노출, 월/일 마스킹.
  //   1988년 1월 1일 → 1988년 **월 **일
  //   1988-01-01     → 1988-**-**
  //   88.01.01       → 88.**.**
  //   88년생          → 그대로 (이미 연도만)
  // "년생" 형태는 이미 연도만 → 그대로 두거나 마스킹 강도 낮음
  if (text.endsWith("년생")) return text;
  // 한국어: 1988년 X월 X일
  const kor = /^(\p{Nd}{2,4})\s*년\s*\p{Nd}{1,2}\s*월\s*\p{Nd}{1,2}\s*일$/u.exec(text);
  if (kor) return `${kor[1]}년 ${MASK.repeat(2)}월 ${MASK.repeat(2)}일`;
  // 숫자 형식: 1988.01.01 / 1988-01-01 / 1988/01/01 / 88.01.01
  const numeric = /^(\p{Nd}{2,4})([./-])\p{Nd}{1,2}\2\p{Nd}{1,2}$/u.exec(text);
  if (numeric) {
    const sep = numeric[2] ?? "";
    return `${numeric[1]}${sep}${MASK.repeat(2)}${sep}${MASK.repeat(2)}`;
  }
  return MASK.repeat(text.length);
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
  return MASK.repeat(text.length);
}

function maskMajor(text: string): string {
  // 전공: 계열까지만 노출.
  //   컴퓨터공학과 → ○○○○학과
  //   경영학       → ○○학
  // 접미사 유지
  for (const suf of ["학과", "학부", "전공", "학", "과"]) {
    if (text.endsWith(suf) && text.length > suf.length) {
      const stem = text.slice(0, -suf.length);
      return "○".repeat(stem.length) + suf;
    }
  }
  return MASK.repeat(text.length);
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
    const age = ndToNumber(raw);
    if (age < 10) return "10대 미만";
    const decade = Math.floor(age / 10) * 10;
    return `${decade}대`;
  }
  return MASK.repeat(text.length);
}

function maskHeight(text: string): string {
  // 신장: 5cm 구간화. '175cm' → '175-180cm'.
  const m = /(\p{Nd}+(?:\.\p{Nd}+)?)/u.exec(text);
  const raw = m?.[1];
  if (raw !== undefined) {
    let h = ndToNumber(raw);
    // m 단위면 cm 로 변환
    if (h < 3) h *= 100;
    const lo = Math.floor(h / 5) * 5;
    return `${lo}-${lo + 5}cm`;
  }
  return MASK.repeat(text.length);
}

function maskWeight(text: string): string {
  // 체중: 5kg 구간화. '70kg' → '70-75kg'.
  const m = /(\p{Nd}+(?:\.\p{Nd}+)?)/u.exec(text);
  const raw = m?.[1];
  if (raw !== undefined) {
    const w = ndToNumber(raw);
    const lo = Math.floor(w / 5) * 5;
    return `${lo}-${lo + 5}kg`;
  }
  return MASK.repeat(text.length);
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
