/** 처방전 발행번호 (Prescription Issuance Number) detection — 식의약 도메인.
 *
 * Python 원본: src/ko_pii/patterns/prescription.py — 1:1 포팅 (골드 마스터 기준).
 *
 * 표준 (HIRA / 건강보험심사평가원 EMR 표준프레임워크):
 * - **처방전 발행번호 (처방전교부번호)**: 12자리 = ``YYYYMMDD`` (8) + 일련번호 (4)
 *   - 예: ``201912010001`` (2019.12.01 발행 1번)
 * - **의료기관기호**: 8자리 — HIRA 표준 의료기관 식별번호
 *   (처방전 자체보다 *발급기관* 식별이라 별도 PII 처리)
 *
 * 검출 정책:
 * - 12자리 처방번호는 단독으로는 거대 FP 위험 → **키워드 anchor** 필수
 * - 발행 날짜 부분이 *유효 날짜* 여야 함 (1990-01-01 ~ 2099-12-31)
 * - 통상 의료기관기호 (8자리) 도 같은 anchor 로 emit
 *
 * 법적 근거:
 * - 의료법 제18조 (처방전 작성과 교부)
 * - 약사법 제22조 (조제내역 기록)
 * - 개인정보보호법 제23조 (민감정보 — 건강 정보)
 *
 * 위험도: HIGH (건강 정보 결합 → 민감속성).
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "PRESCRIPTION_ID";
const LEGAL_BASIS = "의료법 제18조; 약사법 제22조; 개인정보보호법 제23조";
const CATEGORY = "민감정보(건강)";

const KEYWORDS: readonly string[] = [
  "처방번호",
  "처방전번호",
  "처방전 번호",
  "처방전 발행번호",
  "처방전교부번호",
  "교부번호",
  "Rx 번호",
  "Rx번호",
  "Rx",
];

// 처방전 발행번호: 12자리 = 날짜 8 + 일련 4
const ISSUANCE_PATTERN = /(?<![0-9])([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{4})(?![0-9])/g;

// 의료기관기호: 8자리 (HIRA 표준) — anchor 필수
const INSTITUTION_PATTERN = /(?<![0-9])([0-9]{8})(?![0-9])/g;

const INSTITUTION_KEYWORDS: readonly string[] = [
  "의료기관기호",
  "기관기호",
  "요양기관기호",
  "요양기관번호",
  "병원코드",
];

// 영문 접두 처방번호 (EMR 시스템별 다양): RX-2026-008471, PRSC-2026-0053-77192,
// RX-260503-44120 등. 키워드 anchor 가 필수라 영문+하이픈 ID 를 넓게 캡처해도 FP 안전.
const LABELED_ID_PATTERN =
  /(?<![A-Za-z0-9])([A-Za-z]{2,6}-[0-9][0-9A-Za-z-]{3,22})(?![A-Za-z0-9])/g;

function hasKeywordBefore(
  text: string,
  start: number,
  window: number,
  keywords: readonly string[],
): string | null {
  const head = text.slice(Math.max(0, start - window), start);
  for (const kw of keywords) {
    if (head.includes(kw)) return kw;
  }
  return null;
}

/** Python datetime.date(y, m, d) 유효성 — 실제 달력 검증 (윤년 포함). */
function isValidIssuanceDate(yyyy: string, mm: string, dd: string): boolean {
  // 정규식이 순수 숫자임을 보장하므로 int() ValueError 분기는 발생 불가
  const y = Number(yyyy);
  const m = Number(mm);
  const d = Number(dd);
  if (y < 1990 || y > 2099) return false;
  if (m < 1 || m > 12) return false;
  const isLeap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const daysInMonth = [31, isLeap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const maxDay = daysInMonth[m - 1];
  return d >= 1 && maxDay !== undefined && d <= maxDay;
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Array<[number, number]> = [];

  // 처방전 발행번호 (12자리)
  for (const m of text.matchAll(ISSUANCE_PATTERN)) {
    if (m.index === undefined) continue;
    const yyyy = m[1];
    const mm = m[2];
    const dd = m[3];
    const serial = m[4];
    if (yyyy === undefined || mm === undefined || dd === undefined || serial === undefined) {
      continue;
    }
    if (!isValidIssuanceDate(yyyy, mm, dd)) continue;
    const kw = hasKeywordBefore(text, m.index, 20, KEYWORDS);
    if (kw === null) continue;
    const start = m.index;
    const end = start + m[0].length;
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: m[0],
        start,
        end,
        riskLevel: RiskLevel.HIGH,
        confidence: 0.9,
        evidence: [
          "pattern:prescription_issuance",
          `keyword:${kw}`,
          `date_valid:${yyyy}-${mm}-${dd}`,
        ],
        legal_basis: LEGAL_BASIS,
        extra: {
          category: CATEGORY,
          subtype: "issuance_id",
          issue_date: `${yyyy}-${mm}-${dd}`,
          serial,
        },
      }),
    );
  }

  // 영문 접두 처방번호 (RX-/PRSC- 등) — 키워드 anchor 필수
  for (const m of text.matchAll(LABELED_ID_PATTERN)) {
    if (m.index === undefined) continue;
    const id = m[1];
    if (id === undefined) continue;
    const start = m.index;
    const end = start + id.length;
    if (seen.some(([s, e]) => start < e && s < end)) continue;
    const kw = hasKeywordBefore(text, start, 18, KEYWORDS);
    if (kw === null) continue;
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: id,
        start,
        end,
        riskLevel: RiskLevel.HIGH,
        confidence: 0.88,
        evidence: ["pattern:prescription_labeled_id", `keyword:${kw}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: CATEGORY, subtype: "labeled_id", value: id },
      }),
    );
  }

  // 의료기관기호 (8자리, 별도 키워드)
  for (const m of text.matchAll(INSTITUTION_PATTERN)) {
    if (m.index === undefined) continue;
    const code = m[1];
    if (code === undefined) continue;
    const start = m.index;
    const end = start + code.length;
    if (seen.some(([s, e]) => start < e && s < end)) continue;
    const kw = hasKeywordBefore(text, start, 15, INSTITUTION_KEYWORDS);
    if (kw === null) continue;
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: code,
        start,
        end,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 0.85,
        evidence: ["pattern:prescription_institution", `keyword:${kw}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          category: CATEGORY,
          subtype: "institution_id",
          value: code,
        },
      }),
    );
  }

  return out;
}
