/** 은행 계좌번호 (Bank Account Number) — keyword-anchored.
 *
 * Python 원본: src/ko_pii/patterns/account.py — 1:1 포팅 (골드 마스터 기준).
 *
 * 매칭 anchor (둘 중 하나라도 통과):
 * 1. "계좌" / "계좌번호" / "계좌번" 키워드 직전
 * 2. 한국 은행명 키워드 (농협/신한/국민/우리/하나/카뱅/토스 등) — 숫자 *앞 또는 뒤*
 */

import { PY_NW, PY_S, PY_W, regexEscape } from "../core/strUtils.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "ACCOUNT";
const LEGAL_BASIS = "개인정보보호법 제2조; 금융실명법";
const CATEGORY = "일반개인정보";

// 한국 은행·금융기관 키워드 — 정확한 명칭 + 기존 약칭 모두 포함.
const BANK_NAMES: readonly string[] = [
  // Qualified spellings previously recognized through their Korean suffix.
  "NH농협은행",
  "IBK기업은행",
  "KDB산업은행",
  "BNK부산은행",
  "BNK경남은행",
  "DGB대구은행",
  "Sh수협은행",
  "JB제주은행",
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

/** Python sorted(key=lambda n: (-len(n), n)) — 길이 내림차순, 동률은 코드 포인트 사전순. */
function byLengthThenName(names: readonly string[]): string[] {
  return [...names].sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));
}

// Python 유니코드 \w 근사 (u 플래그 필요).
const PY_WORD = PY_W;

// 하이픈은 숫자 블록을 묶고, 단일 공백은 계좌 그룹을 나눌 수 있다. 검증 전에 블록 전체를
// 소비해 과대 값이 잘려 나가지 않게 한다.
const BLOCK = "[0-9]+(?: ?- ?[0-9]+)*";
const BLOCK_PATTERN = new RegExp(BLOCK, "g");
const NUMBER = `${BLOCK}(?: ${BLOCK}){0,4}(?![0-9]| ?-)`;
const VALUE_PREFIX = `${PY_S}*(?:[:=]${PY_S}*)?(?:["'“‘「『(]${PY_S}*)?`;
const BANK_PATTERN = `(?:${byLengthThenName(BANK_NAMES).map(regexEscape).join("|")})`;
const COMPOUND_BANK_PATTERN = `(?:${byLengthThenName(BANK_NAMES.filter((n) => n.length >= 4))
  .map(regexEscape)
  .join("|")})`;
const BANK_PARTICLE =
  "(?:(?:으로부터|에서부터|으로|에게서|한테서|께서|에게|한테|에서|부터|까지|보다|처럼|같이|에|로|와|과|의)" +
  "(?:은|는|도|만|의)?|은|는|이|가|을|를|도|만|입니다|이며|이고)";
const BANK_END = `(?=${PY_NW}|$|${BANK_PARTICLE}(?!${PY_WORD}))`;

// anchor 1: "계좌" 키워드가 *직전* 에 (콜론·번호 옵션 허용)
const KEYWORD_PATTERN = new RegExp(
  `계좌(?:${PY_S}*(?:번호|번))?${VALUE_PREFIX}(?<value>${NUMBER})`,
  "gdu",
);

// anchor 2: 은행명이 *앞* 에 (선택적 구분자·인용부호)
const BANK_BEFORE_PATTERN = new RegExp(
  `(?:(?<!${PY_WORD})|(?<=[가-힣])(?=${COMPOUND_BANK_PATTERN}))` +
    `(?<bank>${BANK_PATTERN})` +
    VALUE_PREFIX +
    `(?<value>${NUMBER})`,
  "gdu",
);

// anchor 3: 은행명이 *뒤* 에 (숫자 + 공백/인용·콤마 옵션 + 은행명)
const BANK_AFTER_PATTERN = new RegExp(
  "(?<![0-9-])(?<!- )" +
    `(?<value>${NUMBER})` +
    `${PY_S}*(?:["'”’」』)]${PY_S}*)?(?:,${PY_S}*)?` +
    `(?<bank>${BANK_PATTERN})` +
    BANK_END,
  "gdu",
);

/** 이전 패스들의 span 은 서로 겹치지 않는다 — 마지막 후보 하나만 본다. */
function overlapsPrevious(span: Span, occupied: readonly Span[]): boolean {
  // bisect_left(occupied, (span[1],)) - 1 → start < span.end 인 마지막 항목
  let lo = 0;
  let hi = occupied.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((occupied[mid] as Span)[0] < span[1]) lo = mid + 1;
    else hi = mid;
  }
  const previous = lo - 1;
  return previous >= 0 && (occupied[previous] as Span)[1] > span[0];
}

/** 완전한 첫 값을 이후 숫자 필드와 분리한다 (Python ``_account_prefix``). */
function accountPrefix(raw: string): string | null {
  let total = 0;
  let end = 0;
  let index = 0;
  for (const block of raw.matchAll(BLOCK_PATTERN)) {
    for (const ch of block[0]) if (ch >= "0" && ch <= "9") total += 1;
    if (total > 16) break;
    if (total >= 10) {
      end = block.index + block[0].length;
      if (index === 0) break;
    }
    index += 1;
  }
  return end ? raw.slice(0, end) : null;
}

function sortedSpans(seen: readonly Span[]): Span[] {
  return [...seen].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
}

/** 공백/하이픈 제거 후 10~16자리 숫자만 반환. */
function normalizeAndCheck(raw: string): string | null {
  const digits = raw.replace(/[ -]/g, "");
  if (!/^[0-9]+$/.test(digits)) return null;
  if (!(digits.length >= 10 && digits.length <= 16)) return null;
  return digits;
}

const TRAILING_WS = new RegExp(`${PY_S}+$`, "u");

/** Python str.rstrip() — 후행 공백 제거. */
function rstrip(s: string): string {
  return s.replace(TRAILING_WS, "");
}

type Span = readonly [number, number];

function spanSeenExact(span: Span, seen: Span[]): boolean {
  return seen.some(([s, e]) => s === span[0] && e === span[1]);
}

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Span[] = [];

  // 1) "계좌" 키워드 anchor
  for (const m of text.matchAll(KEYWORD_PATTERN)) {
    const g = m.indices?.groups?.value;
    if (g === undefined) continue;
    const raw = accountPrefix(m.groups?.value ?? "");
    if (raw === null) continue;
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
  let occupied = sortedSpans(seen);
  for (const m of text.matchAll(BANK_BEFORE_PATTERN)) {
    const g = m.indices?.groups?.value;
    if (g === undefined) continue;
    const raw = accountPrefix(m.groups?.value ?? "");
    if (raw === null) continue;
    const digits = normalizeAndCheck(raw);
    if (digits === null) continue;
    const span: Span = [g[0], g[0] + raw.length];
    if (overlapsPrevious(span, occupied)) continue;
    seen.push(span);
    const bank = m.groups?.bank ?? "";
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
  occupied = sortedSpans(seen);
  for (const m of text.matchAll(BANK_AFTER_PATTERN)) {
    const g = m.indices?.groups?.value;
    if (g === undefined) continue;
    const raw = rstrip(m.groups?.value ?? "");
    const digits = normalizeAndCheck(raw);
    if (digits === null) continue;
    const span: Span = [g[0], g[0] + raw.length];
    if (overlapsPrevious(span, occupied)) continue;
    seen.push(span);
    const bank = m.groups?.bank ?? "";
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
