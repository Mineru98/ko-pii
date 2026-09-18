/** 법원 사건번호 (Court Case Number) detection — Python patterns/court_case 대응.
 *
 * 구조: ``YYYY`` + ``부호문자`` + ``일련번호`` (대법원 사건별 부호문자 예규 기준).
 * 위험도 MEDIUM — 사건번호 자체는 PII 가 아니지만 당사자 정보 추적 가능.
 */
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "COURT_CASE";
const LEGAL_BASIS = "개인정보보호법 제2조; 민사소송법 제65조";
const CATEGORY = "참조정보";

// 사건별 부호문자 화이트리스트 (대법원 예규 기준 빈출 코드)
const VALID_CASE_CODES: readonly string[] = [
  // 민사
  "가합",
  "가단",
  "가소",
  "나",
  "다",
  "카합",
  "카단",
  "차",
  "카기",
  "머",
  // 형사
  "고합",
  "고단",
  "고정",
  "노",
  "도",
  "초",
  "형보",
  "고약",
  "고전",
  // 행정
  "구합",
  "구단",
  "누",
  "두",
  "구약",
  // 가사
  "드합",
  "드단",
  "르",
  "므",
  "수단",
  "수합",
  "후단",
  "후합",
  // 등기·기타
  "호",
  "자",
  "보",
  "사",
  "허",
  "라",
  "마",
  "바",
  // 헌재
  "헌가",
  "헌나",
  "헌다",
  "헌라",
  "헌마",
  "헌바",
];

// 우선순위 정렬: 긴 코드부터 매칭되어야 "가합" 이 "가" 보다 먼저 잡힘
const SORTED_CODES = [...VALID_CASE_CODES].sort((a, b) => b.length - a.length);
const CODE_ALTS = SORTED_CODES.map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");

const PATTERN = new RegExp(
  "(?<![0-9가-힣])" +
    "((?:19|20)[0-9]{2})" + // 연도
    `(${CODE_ALTS})` + // 부호문자
    "([0-9]{1,6})" + // 일련번호
    "(?![0-9가-힣])",
  "g",
);

const INSTANCE_BY_CODE: Record<string, string> = {
  가단: "civil_1st_single",
  가합: "civil_1st_panel",
  가소: "civil_1st_small",
  나: "civil_2nd",
  다: "civil_3rd",
  고단: "criminal_1st_single",
  고합: "criminal_1st_panel",
  고정: "criminal_1st_summary",
  노: "criminal_2nd",
  도: "criminal_3rd",
  구단: "admin_1st_single",
  구합: "admin_1st_panel",
  누: "admin_2nd",
  두: "admin_3rd",
  드합: "family_1st_panel",
  드단: "family_1st_single",
  르: "family_2nd",
  므: "family_3rd",
  차: "payment_order",
  카기: "interim_misc",
  헌가: "constitutional_review",
  헌나: "constitutional_complaint",
  헌마: "constitutional_basic_rights",
};

export function* detect(text: string): Generator<DetectionResult> {
  PATTERN.lastIndex = 0;
  for (const m of text.matchAll(PATTERN)) {
    const year = m[1] as string;
    const code = m[2] as string;
    const serial = m[3] as string;
    // Serial must have at least 1 non-zero digit (일련번호 0 placeholder 거부)
    if (Number.parseInt(serial, 10) === 0) continue;
    yield makeDetection({
      label: LABEL,
      text: m[0],
      start: m.index,
      end: m.index + m[0].length,
      riskLevel: RiskLevel.MEDIUM,
      confidence: 0.9,
      evidence: ["pattern:court_case", `code:${code}`, `year:${year}`],
      legal_basis: LEGAL_BASIS,
      extra: {
        year,
        case_code: code,
        serial,
        instance: INSTANCE_BY_CODE[code] ?? "unknown",
        category: CATEGORY,
      },
    });
  }
}
