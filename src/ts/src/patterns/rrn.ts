/**
 * 주민등록번호 (Resident Registration Number) detection.
 *
 * Detection criteria, in order:
 *   1. Pattern: 13 ASCII digits with an optional hyphen between the 6th and 7th
 *      digit, with no surrounding digits (prevents matches inside longer numeric
 *      runs such as credit cards).
 *   2. Gender/century digit (7th) must indicate a Korean national: {1, 2, 3, 4,
 *      9, 0}. Foreigner codes {5, 6, 7, 8} are handled by ko_pii.patterns.frn.
 *   3. Date validity: digits 1..6 must form a real calendar date once the
 *      century is decoded from the 7th digit.
 *   4. Checksum: if it passes the standard weighted-sum check, confidence = 1.0;
 *      otherwise the candidate is still emitted with reduced confidence (0.7),
 *      because post-2020 RRNs may not satisfy the checksum.
 *
 * Legal basis: 개인정보보호법 제24조의2 (고유식별정보, 주민등록번호 처리 제한).
 */
import { isValidChecksum as isValidCorpChecksum } from "../checksum/corpRegChecksum.js";
import { isValidChecksum } from "../checksum/rrnChecksum.js";
import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "RRN";
const LEGAL_BASIS = "개인정보보호법 제24조의2";
const CATEGORY = "고유식별정보";

const PATTERN = /(?<![0-9])([0-9]{6})(?:\s?[-./]\s?|[-./\s]{0,2})([0-9]{7})(?![0-9])/g;

// PDF 서식용: 앞에 1자리 숫자(관계코드 등)가 붙은 패턴
// "1951230-1850431" → 앞 1은 관계코드, 951230-1850431이 RRN
const PATTERN_PREFIXED =
  /(?<![0-9])[0-9]([0-9]{6})(?:\s?[-./]\s?|[-./\s]{0,2})([0-9]{7})(?![0-9])/g;

// 분할 재조합(GAP 2): 6자리 + 짧은 *단어* 필러 + 7자리.
// "앞자리 880101 뒷자리 1234567", "880101 다시 1234567" 처럼 한 문장 안에서 구분자
// 대신 한국어 필러(앞자리/뒷자리/다시/그리고)로 쪼갠 RRN 을 잡는다.
// 필러는 숫자·줄바꿈 없이 1~8자이되 *문자/단어 한 글자 이상*을 포함해야 한다
// (``(?=[^0-9\n]*[^\s\d])``). 순수 공백("880101   1234568" 표 칼럼)·순수 구분자
// (하이픈/점)는 기존 ``PATTERN`` 의 cap 규칙이 처리하므로 분할 패턴에서 제외 — 표
// 칼럼 나열 FP(test_three_pure_spaces_not_matched)를 깨지 않는다. 6자리는 유효 날짜,
// 7자리 첫 자리는 한국인 성별코드여야 하며, 체크섬 불일치 시 주민 맥락/재조합 필러가
// 있을 때만 방출(recall-safe: 무맥락 무작위 6자리 단독은 절대 미방출).
const PATTERN_SPLIT =
  /(?<![0-9])([0-9]{6})((?=[^0-9\n]*[^\s\d])[^0-9\n]{1,8}?)([0-9]{7})(?![0-9])/g;

// RRN 맥락 마커 — 분할 재조합의 체크섬 불일치 케이스를 방출할 근거.
const RRN_MARKERS: readonly string[] = [
  "주민등록번호",
  "주민번호",
  "주민 번호",
  "앞자리",
  "뒷자리",
  "주민",
];

// 재조합 연결 필러 — 두 숫자 조각을 잇는 한국어 표현. 필러 자체가 분할 시그니처라
// 전역 마커가 없어도 방출 근거가 된다('880101 다시 1234567'). 유효 날짜 + 성별코드
// 제약과 함께라 산문 FP 위험은 무시할 수준.
const SPLIT_FILLER_MARKERS: readonly string[] = [
  "뒷자리",
  "앞자리",
  "다시",
  "그리고",
  "이고",
  "하고",
  "뒤",
  "이어서",
];

const CENTURY_BY_GENDER_DIGIT = new Map<number, number>([
  [1, 1900],
  [2, 1900],
  [3, 2000],
  [4, 2000],
  [9, 1800],
  [0, 1800],
]);

/** Python datetime.date(y, m, d) 유효성 (proleptic Gregorian, 1..9999년). */
function isValidDate(year: number, month: number, day: number): boolean {
  if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1) return false;
  let daysInMonth = 31;
  if (month === 4 || month === 6 || month === 9 || month === 11) {
    daysInMonth = 30;
  } else if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    daysInMonth = leap ? 29 : 28;
  }
  return day <= daysInMonth;
}

/** Python date.today() 대응 — 로컬 시간 기준 YYYYMMDD 정수. */
function todayYmd(): number {
  const now = new Date();
  return now.getFullYear() * 10000 + (now.getMonth() + 1) * 100 + now.getDate();
}

interface BirthDate {
  /** yyyymmdd 정수 — 날짜 비교용. */
  ymd: number;
  /** Python date.isoformat() 동등 ("YYYY-MM-DD"). */
  iso: string;
}

/** Python _decode_birth_date 대응 — 유효 날짜 아니면 null. */
function decodeBirthDate(yymmdd: string, genderDigit: number): BirthDate | null {
  const centuryBase = CENTURY_BY_GENDER_DIGIT.get(genderDigit);
  if (centuryBase === undefined) return null;
  const year = centuryBase + Number(yymmdd.slice(0, 2));
  const month = Number(yymmdd.slice(2, 4));
  const day = Number(yymmdd.slice(4, 6));
  if (!isValidDate(year, month, day)) return null;
  const iso =
    `${String(year).padStart(4, "0")}-` +
    `${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
  return { ymd: year * 10000 + month * 100 + day, iso };
}

/** 공통 RRN 검출 로직. offset = 매치 내에서 front 시작 위치 보정. */
function emit(
  full: string,
  start: number,
  end: number,
  front: string,
  back: string,
  offset: number,
): DetectionResult | null {
  const genderDigit = Number(back.charAt(0));
  const birth = decodeBirthDate(front, genderDigit);
  if (birth === null) return null;

  // 미래 생년월일은 실존 인물의 RRN일 수 없음 → 미방출.
  // 880·881·888 로 시작하는 한국 GS1/EAN-13 바코드(예: 8801234567890)가
  // 7번째 자리=3/4 일 때 2000년대 century 로 디코딩되어 2088년 등
  // 미래 일자를 만드는 FP 차단. 실제 RRN(생년 ≤ 현재년)은 영향 없음.
  if (birth.ymd > todayYmd()) return null;

  const digitsOnly = front + back;
  const checksumOk = isValidChecksum(digitsOnly);

  // RRN 체크섬 실패 + 성별자리(7번째)=0 + 법인 체크섬 통과 → 법인등록번호로 판단해
  // RRN 미방출. (설계 D-003: 130111-0006246·191211-0006639 류 CORP_REG.)
  // 성별자리 0 은 법인번호 종류코드의 전형값이자 1800년대 RRN(실질 무의미)이라,
  // 실사용 RRN(성별 1~8)은 법인 체크섬을 우연히 통과해도 그대로 RRN 으로 보호.
  if (!checksumOk && back.charAt(0) === "0" && isValidCorpChecksum(digitsOnly)) {
    return null;
  }

  // GS1 한국 EAN-13 바코드(880~ 시작, 무구분자, 체크섬 불일치)는 RRN 이 아니다.
  // 진짜 88년생 RRN 은 체크섬을 통과(checksum_ok)하므로 영향 없음(recall-safe).
  const real = full.slice(offset);
  if (!checksumOk && digitsOnly.startsWith("880") && real === digitsOnly) {
    return null;
  }

  const evidence = ["pattern:rrn", `date_valid:${birth.iso}`];
  let confidence: number;
  if (checksumOk) {
    evidence.push("checksum:valid");
    confidence = 1.0;
  } else {
    evidence.push("checksum:invalid_or_post_2020");
    confidence = 0.7;
  }

  // span은 prefix를 제외한 실제 RRN 부분
  return makeDetection({
    label: LABEL,
    text: real,
    start: start + offset,
    end,
    riskLevel: RiskLevel.CRITICAL,
    confidence,
    evidence,
    legal_basis: LEGAL_BASIS,
    extra: {
      front,
      back,
      birth_date: birth.iso,
      gender_digit: genderDigit,
      checksum_valid: checksumOk,
      category: CATEGORY,
    },
  });
}

/** 분할 재조합 RRN 검출(6자리 + 필러 + 7자리).
 *
 * span 은 필러를 포함한 원본 전체(front 시작 ~ back 끝)를 덮어, 마스킹 시 두 조각이
 * 모두 제거된다. 체크섬 불일치면 주민 맥락 마커가 있을 때만 방출.
 */
function emitSplit(
  full: string,
  start: number,
  end: number,
  front: string,
  filler: string,
  back: string,
  markerPresent: boolean,
): DetectionResult | null {
  const genderDigit = Number(back.charAt(0));
  const birth = decodeBirthDate(front, genderDigit);
  if (birth === null) return null;
  if (birth.ymd > todayYmd()) return null;

  const digitsOnly = front + back;
  const checksumOk = isValidChecksum(digitsOnly);

  // 법인등록번호(성별자리 0 + 법인 체크섬 통과)는 RRN 으로 보지 않음 — 단일 패턴과 동일.
  if (!checksumOk && back.charAt(0) === "0" && isValidCorpChecksum(digitsOnly)) {
    return null;
  }

  // 필러 자체가 재조합 연결 표현이면 그것도 방출 근거(전역 마커 불필요).
  const hasContext = markerPresent || SPLIT_FILLER_MARKERS.some((fm) => filler.includes(fm));

  // recall-safe: 체크섬 불일치 + 무맥락 → 미방출(무작위 6+7 숫자쌍 FP 차단).
  if (!checksumOk && !hasContext) return null;

  const evidence = ["pattern:rrn_split", `date_valid:${birth.iso}`];
  let confidence: number;
  if (checksumOk) {
    evidence.push("checksum:valid");
    confidence = 1.0;
  } else {
    evidence.push("checksum:invalid_or_post_2020");
    evidence.push("context:rrn_marker");
    confidence = 0.7;
  }

  return makeDetection({
    label: LABEL,
    text: full,
    start,
    end,
    riskLevel: RiskLevel.CRITICAL,
    confidence,
    evidence,
    legal_basis: LEGAL_BASIS,
    extra: {
      front,
      back,
      birth_date: birth.iso,
      gender_digit: genderDigit,
      checksum_valid: checksumOk,
      category: CATEGORY,
      reassembled: true,
    },
  });
}

/** Yield a DetectionResult for each plausible RRN found in *text*. */
export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  const seen: Array<[number, number]> = [];
  const markerPresent = RRN_MARKERS.some((mk) => text.includes(mk));

  // 기본 패턴
  for (const m of text.matchAll(PATTERN)) {
    const full = m[0] as string;
    const start = m.index;
    const result = emit(full, start, start + full.length, m[1] as string, m[2] as string, 0);
    if (result !== null) {
      seen.push([result.start, result.end]);
      results.push(result);
    }
  }

  // PDF prefix 패턴 (관계코드 등 1자리 숫자 뒤 RRN)
  for (const m of text.matchAll(PATTERN_PREFIXED)) {
    const full = m[0] as string;
    const start = m.index;
    const result = emit(full, start, start + full.length, m[1] as string, m[2] as string, 1);
    if (result !== null && !seen.some(([s, e]) => s === result.start && e === result.end)) {
      seen.push([result.start, result.end]);
      results.push(result);
    }
  }

  // 분할 재조합 패턴 (GAP 2): 6자리 + 한국어 필러 + 7자리.
  // 이미 잡힌 RRN(단일/prefix)과 겹치는 매치는 건너뛴다.
  for (const m of text.matchAll(PATTERN_SPLIT)) {
    const full = m[0] as string;
    const start = m.index;
    const end = start + full.length;
    let overlapsSeen = false;
    for (const [s, e] of seen) {
      if (s < end && start < e) {
        overlapsSeen = true;
        break;
      }
    }
    if (overlapsSeen) continue;
    const result = emitSplit(
      full,
      start,
      end,
      m[1] as string,
      m[2] as string,
      m[3] as string,
      markerPresent,
    );
    if (result !== null) {
      seen.push([start, end]);
      results.push(result);
    }
  }

  return results;
}
