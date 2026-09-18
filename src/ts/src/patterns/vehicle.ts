/** 자동차 등록번호 (Vehicle License Plate) detection.
 *
 * Python 원본: src/ko_pii/patterns/vehicle.py — 1:1 포팅 (골드 마스터 기준).
 *
 * Korean plate format (post-2004): NN[가-힣]NNNN or NNN[가-힣]NNNN
 *   ─ 2~3자리 접두 (차종), 1 한글 용도 코드 (화이트리스트), 4자리 일련번호
 *
 * 총 약 50개 한글 문자만 유효 — 그 외 한글이 들어가면 FP 가 거의 확실.
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "VEHICLE";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

// 한글 용도 코드 화이트리스트
const VEHICLE_HANGUL: ReadonlySet<string> = new Set([
  // 자가용 (비사업용) 32자 — 자동차관리법 시행규칙 별표7
  "가",
  "나",
  "다",
  "라",
  "마",
  "거",
  "너",
  "더",
  "러",
  "머",
  "버",
  "서",
  "어",
  "저",
  "고",
  "노",
  "도",
  "로",
  "모",
  "보",
  "소",
  "오",
  "조",
  "구",
  "누",
  "두",
  "루",
  "무",
  "부",
  "수",
  "우",
  "주",
  // 영업용 (택시·버스·화물 등)
  "바",
  "사",
  "아",
  "자",
  // 배달·택배
  "배",
  // 렌터카 (2013~)
  "하",
  "허",
  "호",
  // 외교용
  "외",
  "영",
  "준",
  "협",
  "대",
  // 군용
  "국",
  "합",
  "육",
  "해",
  "공",
]);

/** Classify the 1-char purpose code. */
function vehiclePurpose(hangul: string): string {
  if (["바", "사", "아", "자"].includes(hangul)) return "commercial";
  if (hangul === "배") return "delivery";
  if (["하", "허", "호"].includes(hangul)) return "rental";
  if (["외", "영", "준", "협", "대"].includes(hangul)) return "diplomatic";
  if (["국", "합", "육", "해", "공"].includes(hangul)) return "military";
  return "private";
}

const PATTERN = /(?<![0-9가-힣])([0-9]{2,3})\s?([가-힣])\s?([0-9]{4})(?![0-9])/g;

// 차량번호 뒤에 따라오면 차량 X — 한국어 수량·통화 단위어
const FOLLOWING_UNIT_REJECT: readonly string[] = [
  "원",
  "달러",
  "엔",
  "위안",
  "유로",
  "파운드",
  "프랑",
  "억",
  "만",
  "천",
  "백",
  "조",
  "%",
  "퍼센트",
  "퍼센트포인트",
  "포인트",
  "포",
  "건",
  "건수",
  "명",
  "년",
  "월",
  "일",
  "시간",
  "분",
  "초",
  "톤",
  "kg",
  "g",
  "m",
  "km",
  "mm",
];

/** 차량번호 뒤에 한국어 수량/통화 단위가 따라오면 차량 아님. */
function hasUnitAfter(text: string, end: number): string | null {
  const tail = text.slice(end, end + 8).replace(/^\s+/, "");
  for (const unit of FOLLOWING_UNIT_REJECT) {
    if (tail.startsWith(unit)) return unit;
  }
  return null;
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    if (m.index === undefined) continue;
    const purposeChar = m[2];
    if (purposeChar === undefined) continue;
    // 용도 한글 화이트리스트 — 그 외 한글은 FP
    if (!VEHICLE_HANGUL.has(purposeChar)) continue;
    const suffix = m[3];
    if (suffix === undefined) continue;
    // 뒷 4자리 0000 은 placeholder/시범 번호 — 실제 차량 아님
    if (suffix === "0000") continue;
    const start = m.index;
    const end = start + m[0].length;
    // 뒤에 한국어 수량·통화 단위 → 차량 아님 ("291조9000억 원" 등)
    const unit = hasUnitAfter(text, end);
    if (unit !== null) continue;
    out.push(
      makeDetection({
        label: LABEL,
        text: m[0],
        start,
        end,
        riskLevel: RiskLevel.LOW,
        confidence: 0.85,
        evidence: ["pattern:vehicle", `purpose:${vehiclePurpose(purposeChar)}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          prefix: m[1],
          purpose_char: purposeChar,
          purpose: vehiclePurpose(purposeChar),
          suffix,
          category: CATEGORY,
        },
      }),
    );
  }
  return out;
}
