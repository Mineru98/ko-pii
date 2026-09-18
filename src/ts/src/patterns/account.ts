/** 은행 계좌번호 (Bank Account Number) — keyword-anchored.
 *
 * Python 원본: src/ko_pii/patterns/account.py — 1:1 포팅 (골드 마스터 기준).
 *
 * 매칭 anchor (둘 중 하나라도 통과):
 * 1. "계좌" / "계좌번호" / "계좌번" 키워드 직전
 * 2. 한국 은행명 키워드 (농협/신한/국민/우리/하나/카뱅/토스 등) — 숫자 *앞 또는 뒤*
 */

import { regexEscape } from "../core/strUtils.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "ACCOUNT";
const LEGAL_BASIS = "개인정보보호법 제2조; 금융실명법";
const CATEGORY = "일반개인정보";

// 한국 은행·금융기관 키워드 — 정확한 명칭 + 약칭 모두 포함.
// 순서는 Python 원본 그대로 유지 — 긴 명칭("국민은행")이 짧은 약칭("국민")보다
// 먼저 매칭되어 bank 추출이 정식 명칭을 따른다.
const BANK_NAMES: readonly string[] = [
  // 시중은행 (정식·약칭)
  "국민은행",
  "신한은행",
  "우리은행",
  "하나은행",
  "기업은행",
  "IBK",
  "KEB하나은행",
  "KEB",
  "KB국민은행",
  "KB",
  "농협은행",
  "농협",
  "NH농협",
  "NH",
  "수협은행",
  "수협",
  "Sh수협",
  "SC제일은행",
  "제일은행",
  "씨티은행",
  "한국씨티",
  "외환은행",
  "스탠다드차타드",
  // 인터넷은행
  "카카오뱅크",
  "카뱅",
  "카카오페이",
  "토스뱅크",
  "토스뱅킹",
  "토스페이",
  "케이뱅크",
  "K뱅크",
  "네이버페이",
  // 지방은행
  "부산은행",
  "BNK부산",
  "대구은행",
  "DGB대구",
  "경남은행",
  "BNK경남",
  "광주은행",
  "전북은행",
  "제주은행",
  "JB제주",
  // 특수은행·기관
  "산업은행",
  "KDB산업",
  "수출입은행",
  "EXIM",
  "한국은행",
  "BOK",
  "우체국",
  "우정사업본부",
  "우정청",
  // 상호금융
  "새마을금고",
  "MG새마을",
  "MG",
  "신협",
  "신용협동조합",
  "수산업협동조합",
  "농업협동조합",
  // 일부 약칭/통칭 (한국어 약칭만, 영문 약칭은 단어 경계 충돌 위험으로 별도)
  "국민",
  "신한",
  "우리",
  "하나",
];

const BANK_ALT = `(?:${BANK_NAMES.map((n) => regexEscape(n)).join("|")})`;

// anchor 1: "계좌" 키워드가 *직전* 에 (콜론·번호 옵션 허용)
const KEYWORD_PATTERN = new RegExp(
  String.raw`(?:계좌\s*(?:번호|번)?\s*:?\s*)` + String.raw`([0-9][\s\-]*(?:[0-9][\s\-]*){9,19})`,
  "gd",
);

// anchor 2: 은행명이 *앞* 에 (선택적 콜론·공백)
const BANK_BEFORE_PATTERN = new RegExp(
  BANK_ALT + String.raw`\s*:?\s*` + String.raw`([0-9]+(?:[\s\-][0-9]+){1,4}|[0-9]{10,16})`,
  "gd",
);

// anchor 3: 은행명이 *뒤* 에 (숫자 + 공백/콤마 옵션 + 은행명)
const BANK_AFTER_PATTERN = new RegExp(
  // biome-ignore lint/complexity/noUselessStringRaw: 원본 Python 정규식 리터럴과의 대응 가독성 유지
  String.raw`(?<![0-9])` +
    String.raw`([0-9]+(?:[\s\-][0-9]+){1,4}|[0-9]{10,16})` +
    String.raw`\s*` +
    BANK_ALT,
  "gd",
);

/** 공백/하이픈 제거 후 10~16자리 숫자만 반환. */
function normalizeAndCheck(raw: string): string | null {
  const digits = raw.replace(/[\s-]/g, "");
  if (!/^[0-9]+$/.test(digits)) return null;
  if (!(digits.length >= 10 && digits.length <= 16)) return null;
  return digits;
}

/** Python str.rstrip() — 후행 공백 제거. */
function rstrip(s: string): string {
  return s.replace(/\s+$/, "");
}

/** Python s.strip(": ") — 양끝의 ':' 과 ' ' 제거. */
function stripColonSpace(s: string): string {
  return s.replace(/^[ :]+|[ :]+$/g, "");
}

type Span = readonly [number, number];

function spanSeenExact(span: Span, seen: Span[]): boolean {
  return seen.some(([s, e]) => s === span[0] && e === span[1]);
}

function spanOverlapsSeen(span: Span, seen: Span[]): boolean {
  return seen.some(([s, e]) => s < span[1] && span[0] < e);
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Span[] = [];

  // 1) "계좌" 키워드 anchor
  for (const m of text.matchAll(KEYWORD_PATTERN)) {
    const g = m.indices?.[1];
    if (g === undefined) continue;
    const raw = rstrip(m[1] ?? "");
    const digits = normalizeAndCheck(raw);
    if (digits === null) continue;
    const span: Span = [g[0], g[0] + raw.length];
    if (spanSeenExact(span, seen)) continue;
    seen.push(span);
    out.push(
      makeDetection({
        label: LABEL,
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.HIGH,
        confidence: 0.9,
        evidence: ["pattern:account", "keyword:계좌"],
        legal_basis: LEGAL_BASIS,
        extra: { digits, length: digits.length, category: CATEGORY },
      }),
    );
  }

  // 2) 은행명 anchor (앞)
  for (const m of text.matchAll(BANK_BEFORE_PATTERN)) {
    const g = m.indices?.[1];
    if (g === undefined) continue;
    const raw = rstrip(m[1] ?? "");
    const digits = normalizeAndCheck(raw);
    if (digits === null) continue;
    const span: Span = [g[0], g[0] + raw.length];
    if (spanSeenExact(span, seen) || spanOverlapsSeen(span, seen)) continue;
    seen.push(span);
    const bank = stripColonSpace((m[0] ?? "").split(raw)[0] ?? "");
    out.push(
      makeDetection({
        label: LABEL,
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.HIGH,
        confidence: 0.9,
        evidence: ["pattern:account", `keyword:bank(${bank})`, "position:before"],
        legal_basis: LEGAL_BASIS,
        extra: { digits, length: digits.length, bank, category: CATEGORY },
      }),
    );
  }

  // 3) 은행명 anchor (뒤)
  for (const m of text.matchAll(BANK_AFTER_PATTERN)) {
    const g = m.indices?.[1];
    if (g === undefined) continue;
    const raw = rstrip(m[1] ?? "");
    const digits = normalizeAndCheck(raw);
    if (digits === null) continue;
    const span: Span = [g[0], g[0] + raw.length];
    if (spanSeenExact(span, seen) || spanOverlapsSeen(span, seen)) continue;
    seen.push(span);
    const bank = stripColonSpace((m[0] ?? "").split(raw).at(-1) ?? "");
    out.push(
      makeDetection({
        label: LABEL,
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.HIGH,
        confidence: 0.9,
        evidence: ["pattern:account", `keyword:bank(${bank})`, "position:after"],
        legal_basis: LEGAL_BASIS,
        extra: { digits, length: digits.length, bank, category: CATEGORY },
      }),
    );
  }

  return out;
}
