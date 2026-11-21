/** 한국 전화번호 detection (휴대전화 / 일반전화 / 인터넷전화 / 국제 형식).
 *
 * Python 원본: src/ko_pii/patterns/phone.py — 1:1 포팅 (골드 마스터 기준).
 */

import { selectNonOverlapping } from "../core/overlap.js";
import { PY_S_CHARS } from "../core/strUtils.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "PHONE";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

// International prefix: +82, 0082, or 82- (less common). The body strips the
// leading 0 of the area code per ITU-T E.123 conventions.
const SEP = `[-.${PY_S_CHARS}]`;
const AREA_SEP = `[-.${PY_S_CHARS})\\]]`;
const INTL_PREFIX = String.raw`(?:\+82|0082|82)${SEP}?(?:\(0\)${SEP}?)?`;
// 가입자 번호 본체 — 원본 ``\d`` 는 유니코드 Nd (원문 재검사 패스에서 의미가 있다).
const BODY = String.raw`${SEP}{0,3}(\p{Nd}{3,4})${SEP}{0,3}(\p{Nd}{4})(?![0-9])`;

// 정규식은 모듈 상수 + matchAll 사용 (matchAll 은 내부 복제본으로 순회하므로
// lastIndex 공유 문제 없음 — PORTING.md 참조).
const MOBILE = new RegExp(String.raw`(?<![0-9+])(01[016789])${BODY}`, "gu");

const MOBILE_INTL = new RegExp(String.raw`(?<![0-9])${INTL_PREFIX}(1[016789])${BODY}`, "gu");

// 국제표기 유선 — +82-2-... (서울) / +82-3x-... (지역). leading 0 생략.
const SEOUL_INTL = new RegExp(String.raw`(?<![0-9])${INTL_PREFIX}(2)${BODY}`, "gu");

const REGIONAL_INTL = new RegExp(
  String.raw`(?<![0-9])${INTL_PREFIX}(3[1-3]|4[1-4]|5[1-5]|6[1-4]|70)${BODY}`,
  "gu",
);

const AREA_BODY = String.raw`${AREA_SEP}{0,3}(\p{Nd}{3,4})${SEP}{0,3}(\p{Nd}{4})(?![0-9])`;

const SEOUL = new RegExp(String.raw`(?<![0-9+])(02)${AREA_BODY}`, "gu");

const REGIONAL = new RegExp(
  String.raw`(?<![0-9+])(03[1-3]|04[1-4]|05[1-5]|06[1-4]|070)${AREA_BODY}`,
  "gu",
);

// 괄호 지역번호 표기 — "(" 포함 전체 span 선점용. 유효 한국 prefix 만 허용해 '(2024) 발표'·
// '(주) 회사' 같은 괄호 텍스트 FP 를 차단한다.
const PAREN_AREA = new RegExp(
  String.raw`(?<![0-9A-Za-z])\((01[016789]|02|03[1-3]|04[1-4]|05[1-5]|06[1-4]|070)\)${BODY}`,
  "gu",
);

// 대표번호 (15xx/16xx/17xx/18xx) — 8자리, 사업장/콜센터 (1500~1899 대역).
// 4-4 형식과 동일해 단독 구분 불가 — recall 우선으로 채택 (문서화된 한계).
const REPRESENTATIVE = new RegExp(
  String.raw`(?<![0-9+])(1[5-8]\p{Nd}{2})${SEP}{0,3}(\p{Nd}{4})(?![0-9])`,
  "gu",
);

function emit(m: RegExpMatchArray, phoneType: string, international = false): DetectionResult {
  const start = m.index;
  if (start === undefined) throw new Error("matchAll 결과에 index 없음");
  const raw = m[0];
  const prefix = m[1];
  if (prefix === undefined) throw new Error("prefix 그룹 누락");
  const digits = raw.replace(/\P{Nd}/gu, "");
  const ev = ["pattern:phone", `type:${phoneType}`];
  if (international) ev.push("intl:+82");
  // 위험도 분기 — 휴대전화는 개인 직통 (HIGH), 유선/VoIP 는 가입자 추적
  // 가능하지만 사업장·대표번호 케이스 다수 (MEDIUM).
  const risk = phoneType === "mobile" ? RiskLevel.HIGH : RiskLevel.MEDIUM;
  return makeDetection({
    label: LABEL,
    text: raw,
    start,
    end: start + raw.length,
    riskLevel: risk,
    confidence: 1.0,
    evidence: ev,
    legal_basis: LEGAL_BASIS,
    extra: {
      type: phoneType,
      prefix,
      digits_only: digits,
      international,
      category: CATEGORY,
    },
  });
}

function phoneTypeForPrefix(prefix: string): string {
  if (prefix.startsWith("01")) return "mobile";
  if (prefix === "070") return "voip";
  return "landline";
}

export function detect(text: string): DetectionResult[] {
  // 패턴 우선순위·방출 순서를 보존한다 (위험도 우선 아님): 괄호/국제 표기가 국내형처럼 보이는
  // 핵심부를 소유해야 한다.
  const candidates: DetectionResult[] = [];
  const patterns: ReadonlyArray<readonly [RegExp, boolean]> = [
    [PAREN_AREA, false],
    [MOBILE_INTL, true],
    [SEOUL_INTL, true],
    [REGIONAL_INTL, true],
    [MOBILE, false],
    [REGIONAL, false],
    [SEOUL, false],
    [REPRESENTATIVE, false],
  ];
  for (const [pattern, international] of patterns) {
    for (const m of text.matchAll(pattern)) {
      const prefix = (international ? "0" : "") + (m[1] as string);
      const phoneType = pattern === REPRESENTATIVE ? "representative" : phoneTypeForPrefix(prefix);
      candidates.push(emit(m, phoneType, international));
    }
  }
  return selectNonOverlapping(candidates);
}
