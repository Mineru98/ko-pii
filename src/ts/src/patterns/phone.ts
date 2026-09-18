/** 한국 전화번호 detection (휴대전화 / 일반전화 / 인터넷전화 / 국제 형식).
 *
 * Python 원본: src/ko_pii/patterns/phone.py — 1:1 포팅 (골드 마스터 기준).
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "PHONE";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

// International prefix: +82, 0082, or 82- (less common). The body strips the
// leading 0 of the area code per ITU-T E.123 conventions.
const INTL_PREFIX = String.raw`(?:\+82|0082|82)[-.\s]?(?:\(0\)[-.\s]?)?`;

// 정규식은 모듈 상수 + matchAll 사용 (matchAll 은 내부 복제본으로 순회하므로
// lastIndex 공유 문제 없음 — PORTING.md 참조).
const MOBILE = /(?<![0-9+])(01[01679])[-.\s]{0,3}([0-9]{3,4})[-.\s]{0,3}([0-9]{4})(?![0-9])/g;

const MOBILE_INTL = new RegExp(
  String.raw`(?<![0-9])` +
    INTL_PREFIX +
    String.raw`(1[01679])[-.\s]{0,3}([0-9]{3,4})[-.\s]{0,3}([0-9]{4})(?![0-9])`,
  "g",
);

// 국제표기 유선 — +82-2-... (서울) / +82-3x-... (지역). leading 0 생략.
const SEOUL_INTL = new RegExp(
  String.raw`(?<![0-9])` +
    INTL_PREFIX +
    String.raw`(2)[-.\s]{0,3}([0-9]{3,4})[-.\s]{0,3}([0-9]{4})(?![0-9])`,
  "g",
);

const REGIONAL_INTL = new RegExp(
  String.raw`(?<![0-9])` +
    INTL_PREFIX +
    String.raw`(3[1-3]|4[1-4]|5[1-5]|6[1-4]|70)[-.\s]{0,3}([0-9]{3,4})[-.\s]{0,3}([0-9]{4})(?![0-9])`,
  "g",
);

const SEOUL = /(?<![0-9+])(02)[-.\s)\]]{0,3}([0-9]{3,4})[-.\s]{0,3}([0-9]{4})(?![0-9])/g;

const REGIONAL =
  /(?<![0-9+])(03[1-3]|04[1-4]|05[1-5]|06[1-4]|070)[-.\s)\]]{0,3}([0-9]{3,4})[-.\s]{0,3}([0-9]{4})(?![0-9])/g;

// 괄호 지역번호 표기 — "(" 포함 전체 span 선점용. 표준 괄호 표기는 대부분
// "(02)1234-5678" 형태이며, 국제 prefix("+(82)..." 등)는 뒤의 INTL 패턴이
// 담당하므로 여기서는 숫자 앞뒤 가드만 둔다.
const PAREN_AREA =
  /(?<![0-9A-Za-z])\((01[01679]|02|03[1-3]|04[1-4]|05[1-5]|06[1-4]|070)\)[-.\s]{0,3}([0-9]{3,4})[-.\s]{0,3}([0-9]{4})(?![0-9])/g;

// 대표번호 (15xx/16xx/17xx/18xx) — 8자리, 사업장/콜센터 (1500~1899 대역).
// 4-4 형식과 동일해 단독 구분 불가 — recall 우선으로 채택 (문서화된 한계).
const REPRESENTATIVE = /(?<![0-9+])(1[5-8][0-9]{2})[-.\s]{0,3}([0-9]{4})(?![0-9])/g;

function emit(m: RegExpMatchArray, phoneType: string, international = false): DetectionResult {
  const start = m.index;
  if (start === undefined) throw new Error("matchAll 결과에 index 없음");
  const raw = m[0];
  const prefix = m[1];
  if (prefix === undefined) throw new Error("prefix 그룹 누락");
  const digits = raw.replace(/\D/g, "");
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

type Span = readonly [number, number];

function overlaps(span: Span, seen: Span[]): boolean {
  const [s, e] = span;
  for (const [ss, ee] of seen) {
    if (s < ee && ss < e) return true;
  }
  return false;
}

function phoneTypeForPrefix(prefix: string): string {
  if (prefix.startsWith("01")) return "mobile";
  if (prefix === "070") return "voip";
  return "landline";
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Span[] = [];

  // 괄호 지역번호 표기 먼저 — 여는 괄호까지 포함한 전체 span 을 선점.
  for (const m of text.matchAll(PAREN_AREA)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    const prefix = m[1];
    if (prefix === undefined) continue;
    seen.push(span);
    out.push(emit(m, phoneTypeForPrefix(prefix)));
  }

  // International forms first — they cover their domestic-looking core.
  for (const m of text.matchAll(MOBILE_INTL)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    seen.push(span);
    out.push(emit(m, "mobile", true));
  }

  for (const m of text.matchAll(SEOUL_INTL)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    seen.push(span);
    out.push(emit(m, "landline", true));
  }

  for (const m of text.matchAll(REGIONAL_INTL)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    const g1 = m[1];
    if (g1 === undefined) continue;
    seen.push(span);
    out.push(emit(m, g1 === "70" ? "voip" : "landline", true));
  }

  for (const m of text.matchAll(MOBILE)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    seen.push(span);
    out.push(emit(m, "mobile"));
  }

  for (const m of text.matchAll(REGIONAL)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    const prefix = m[1];
    if (prefix === undefined) continue;
    seen.push(span);
    out.push(emit(m, prefix === "070" ? "voip" : "landline"));
  }

  for (const m of text.matchAll(SEOUL)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    seen.push(span);
    out.push(emit(m, "landline"));
  }

  for (const m of text.matchAll(REPRESENTATIVE)) {
    if (m.index === undefined) continue;
    const span: Span = [m.index, m.index + m[0].length];
    if (overlaps(span, seen)) continue;
    seen.push(span);
    out.push(emit(m, "representative"));
  }

  return out;
}
