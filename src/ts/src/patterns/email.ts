/** Email address detection (simplified RFC 5322) — 한국어 IDN 도메인·난독화 이메일 포함.
 *
 * Python 원본: src/python/ko_pii/patterns/email.py — 1:1 포팅 (골드 마스터 기준).
 *
 * 전체 RFC 5322 문법(인용 로컬 파트, IP 도메인 리터럴, 주석)은 한국 공공 문서에 거의
 * 등장하지 않아 실용 부분집합만 쓴다.
 */

import { selectNonOverlapping } from "../core/overlap.js";
import { PY_S } from "../core/strUtils.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "EMAIL";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

const PATTERN_BODY =
  "(?<![A-Za-z0-9._%+-])" +
  "([A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)" +
  "(?![A-Za-z0-9])";
const PATTERN = new RegExp(PATTERN_BODY, "g");
const PATTERN_FULL = new RegExp(`^(?:${PATTERN_BODY})$`);

// ASCII 최종 라벨을 가진 한국어 IDN 라벨. 유니코드 로컬 파트·유니코드 TLD 는 범위 밖:
// 조사가 붙으면 경계가 모호하다.
const IDN_LABEL = "[A-Za-z0-9가-힣](?:[A-Za-z0-9가-힣-]*[A-Za-z0-9가-힣])?";
const IDN_PATTERN_BODY =
  "(?<![A-Za-z0-9._%+\\-가-힣])([A-Za-z0-9._%+-]+@" +
  IDN_LABEL +
  `(?:\\.${IDN_LABEL})*\\.[A-Za-z]{2,63})(?![A-Za-z0-9-])`;
const IDN_PATTERN = new RegExp(IDN_PATTERN_BODY, "g");
const IDN_PATTERN_FULL = new RegExp(`^(?:${IDN_PATTERN_BODY})$`);

// ---------------------------------------------------------------------------
// Python ``str.encode("idna")`` (IDNA 2003) 대응 — 이 모듈이 받는 도메인은 정규식상
// [A-Za-z0-9가-힣-] 라벨뿐이라 nameprep 은 NFKC + 소문자화로 충분하다.
// ---------------------------------------------------------------------------

const PUNY_BASE = 36;
const PUNY_TMIN = 1;
const PUNY_TMAX = 26;
const PUNY_SKEW = 38;
const PUNY_DAMP = 700;
const PUNY_INITIAL_BIAS = 72;
const PUNY_INITIAL_N = 128;

function punyAdapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / PUNY_DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) >> 1) {
    d = Math.floor(d / (PUNY_BASE - PUNY_TMIN));
    k += PUNY_BASE;
  }
  return k + Math.floor(((PUNY_BASE - PUNY_TMIN + 1) * d) / (d + PUNY_SKEW));
}

function punyDigit(d: number): string {
  return String.fromCharCode(d < 26 ? 97 + d : 22 + d);
}

/** RFC 3492 punycode 인코딩 (Python ``str.encode("punycode")``). */
function punycodeEncode(input: string): string {
  const cps = [...input].map((c) => c.codePointAt(0) as number);
  let out = cps
    .filter((c) => c < 0x80)
    .map((c) => String.fromCharCode(c))
    .join("");
  const basic = out.length;
  let handled = basic;
  if (basic > 0) out += "-";
  let n = PUNY_INITIAL_N;
  let delta = 0;
  let bias = PUNY_INITIAL_BIAS;
  while (handled < cps.length) {
    let m = Number.MAX_SAFE_INTEGER;
    for (const c of cps) if (c >= n && c < m) m = c;
    delta += (m - n) * (handled + 1);
    n = m;
    for (const c of cps) {
      if (c < n) delta += 1;
      if (c === n) {
        let q = delta;
        for (let k = PUNY_BASE; ; k += PUNY_BASE) {
          const t = k <= bias ? PUNY_TMIN : k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias;
          if (q < t) break;
          out += punyDigit(t + ((q - t) % (PUNY_BASE - t)));
          q = Math.floor((q - t) / (PUNY_BASE - t));
        }
        out += punyDigit(q);
        bias = punyAdapt(delta, handled + 1, handled === basic);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
  }
  return out;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: ASCII 판정
const ASCII_ONLY = /^[\x00-\x7f]*$/;

/** Python IDNA ``ToASCII`` (라벨 단위). 실패 시 null (Python UnicodeError). */
function labelToAscii(label: string): string | null {
  if (ASCII_ONLY.test(label)) {
    return label.length > 0 && label.length < 64 ? label : null;
  }
  const prepped = label.normalize("NFKC").toLowerCase();
  if (ASCII_ONLY.test(prepped)) {
    return prepped.length > 0 && prepped.length < 64 ? prepped : null;
  }
  if (prepped.startsWith("xn--")) return null;
  const ace = `xn--${punycodeEncode(prepped)}`;
  return ace.length > 0 && ace.length < 64 ? ace : null;
}

/** Python ``domain.encode("idna").decode("ascii")`` — 실패 시 null. */
function idnaEncode(domain: string): string | null {
  if (ASCII_ONLY.test(domain)) {
    const labels = domain.split(".");
    for (const label of labels.slice(0, -1)) {
      if (!(label.length > 0 && label.length < 64)) return null;
    }
    if ((labels[labels.length - 1] as string).length >= 64) return null;
    return domain;
  }
  const labels = domain.split(/[.。．｡]/);
  let trailingDot = "";
  if (labels.length > 0 && labels[labels.length - 1] === "") {
    trailingDot = ".";
    labels.pop();
  }
  const out: string[] = [];
  for (const label of labels) {
    const ascii = labelToAscii(label);
    if (ascii === null) return null;
    out.push(ascii);
  }
  return out.join(".") + trailingDot;
}

/** 지원 부분집합의 완전한 주소 하나일 때만 (local, domain) 을 반환 (Python ``_split_literal_email``).
 *
 * 필드 단언 값에는 목록·산문이 섞일 수 있다. 변환기가 첫 @ 뒤 전부를 무해한 도메인 하나로
 * 남기면 안 된다.
 */
export function splitLiteralEmail(value: string): [string, string] | null {
  if (!PATTERN_FULL.test(value) && !IDN_PATTERN_FULL.test(value)) return null;
  const at = value.indexOf("@");
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
  const asciiDomain = idnaEncode(domain);
  if (asciiDomain === null || asciiDomain.length > 253) return null;
  return [local, domain];
}

// 난독화 이메일(GAP 3): '[at]'/'(at)' · '[dot]'/'(dot)' 치환과 '@'/'.' 주변 공백 주입으로
// 마스킹을 회피하는 우회.
//   - "hong [at] gmail [dot] com"      → hong@gmail.com
//   - "hong gildong @ naver . com"     → 로컬 내부 공백은 명시적 opt-in
// recall-safe 설계:
//   - @ 등가물은 실제 '@' 또는 대괄호/소괄호로 감싼 at 만 허용(맨단어 ' at '는 산문 FP
//     위험이 커 제외 — "meet at noon" 등).
//   - dot 등가물도 실제 '.' 또는 괄호 감싼 dot 만. 도메인 라벨이 1개 이상 점으로 이어질
//     때만 매치 → 'admin@host'(점 없음)·'10 . 5'(라벨 아님)는 미해당.
//
// Python re.IGNORECASE 는 [A-Za-z] 에 İ ı ſ K(U+212A) 네 글자도 받아들인다 — JS i 플래그
// (u 없음)는 받지 않으므로 클래스에 명시적으로 추가한다.
const IC_EXTRA = "İıſK";
const OBF_AT = String.raw`(?:@|\[[ \t]*at[ \t]*\]|\([ \t]*at[ \t]*\))`;
const OBF_DOT = String.raw`(?:\.|\[[ \t]*dot[ \t]*\]|\([ \t]*dot[ \t]*\))`;
const OBF_LOCAL = `[A-Za-z0-9._%+\\-${IC_EXTRA}]+`;
const OBF_LABEL = `[A-Za-z0-9${IC_EXTRA}](?:[A-Za-z0-9\\-${IC_EXTRA}]*[A-Za-z0-9${IC_EXTRA}])?`;

function obfuscatedPattern(local: string): RegExp {
  return new RegExp(
    `(?<![A-Za-z0-9._%+\\-@${IC_EXTRA}])${local}` +
      `[ \\t]*${OBF_AT}[ \\t]*${OBF_LABEL}` +
      `(?:[ \\t]*${OBF_DOT}[ \\t]*${OBF_LABEL})+` +
      `(?![A-Za-z0-9${IC_EXTRA}])`,
    "iy",
  );
}

const OBFUSCATED = obfuscatedPattern(OBF_LOCAL);
const OBFUSCATED_SPACED = obfuscatedPattern(`${OBF_LOCAL}(?:[ \\t]+${OBF_LOCAL})*`);
const AT_MARKER = new RegExp(OBF_AT, "gi");
const DOMAIN_AFTER_AT = new RegExp(
  `[ \\t]*${OBF_LABEL}(?:[ \\t]*${OBF_DOT}[ \\t]*${OBF_LABEL})+(?![A-Za-z0-9${IC_EXTRA}])`,
  "iy",
);
const LOCAL_CHARS: ReadonlySet<string> = new Set([
  ..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-",
  ...IC_EXTRA,
]);
const LOCAL_OR_SPACE: ReadonlySet<string> = new Set([...LOCAL_CHARS, " ", "\t"]);
const LOCAL_OR_AT: ReadonlySet<string> = new Set([...LOCAL_CHARS, "@"]);

interface ObfMatch {
  text: string;
  start: number;
  end: number;
}

/** 로컬 단어마다 재시도하지 않고 유효한 at/도메인 쌍에 앵커한다. */
function obfuscatedMatches(text: string, allowSpacedLocal: boolean): ObfMatch[] {
  const out: ObfMatch[] = [];
  let cursor = 0;
  const isBlank = (ch: string | undefined): boolean => ch === " " || ch === "\t";
  for (const at of text.matchAll(AT_MARKER)) {
    const atStart = at.index;
    if (atStart < cursor) continue;
    DOMAIN_AFTER_AT.lastIndex = atStart + at[0].length;
    if (!DOMAIN_AFTER_AT.test(text)) continue;
    let start = atStart;
    while (start > cursor && isBlank(text[start - 1])) start -= 1;
    // 앞 산문 단어는 기본적으로 로컬 파트가 아니다.
    const allowed = allowSpacedLocal ? LOCAL_OR_SPACE : LOCAL_CHARS;
    while (start > cursor && allowed.has(text[start - 1] as string)) start -= 1;
    while (start < atStart && isBlank(text[start])) start += 1;
    // 원래 lookbehind 는 다른 @ 바로 뒤에서 시작하는 것을 금지한다.
    if (start > 0 && LOCAL_OR_AT.has(text[start - 1] as string)) {
      while (start < atStart && LOCAL_CHARS.has(text[start] as string)) start += 1;
      while (start < atStart && isBlank(text[start])) start += 1;
    }
    if (start < atStart) {
      const pattern = allowSpacedLocal ? OBFUSCATED_SPACED : OBFUSCATED;
      pattern.lastIndex = start;
      const match = pattern.exec(text);
      if (match !== null) {
        cursor = match.index + match[0].length;
        out.push({ text: match[0], start: match.index, end: cursor });
      }
    }
  }
  return out;
}

// 난독화 토큰([at]/[dot]/괄호/공백)을 표준형으로 환원.
const DEOBF_AT = new RegExp(
  `${PY_S}*(?:\\[${PY_S}*at${PY_S}*\\]|\\(${PY_S}*at${PY_S}*\\))${PY_S}*`,
  "giu",
);
const DEOBF_DOT = new RegExp(
  `${PY_S}*(?:\\[${PY_S}*dot${PY_S}*\\]|\\(${PY_S}*dot${PY_S}*\\))${PY_S}*`,
  "giu",
);

/** 난독화 이메일 원문 → 표준 'local@domain'. 비정상이면 null. */
function canonicalize(raw: string): string | null {
  let s = raw.replace(DEOBF_AT, "@");
  s = s.replace(DEOBF_DOT, ".");
  s = s.replaceAll(" ", "").replaceAll("\t", "");
  const at = s.lastIndexOf("@");
  const sep = at >= 0;
  const local = sep ? s.slice(0, at) : "";
  const domain = sep ? s.slice(at + 1) : "";
  if (!sep || !local || !domain) return null;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
  if (
    !domain.includes(".") ||
    domain.includes("..") ||
    domain.startsWith(".") ||
    domain.endsWith(".")
  ) {
    return null;
  }
  return s;
}

export interface EmailDetectOptions {
  /** true 면 같은 줄의 로컬 파트 단어들을 잇는다 — 고립된 이메일 필드에만 쓸 것. */
  allowSpacedLocal?: boolean;
}

/** 앞 산문을 삼키거나 줄을 넘지 않고 이메일을 검출한다.
 *
 * ``allowSpacedLocal: true`` 는 같은 줄의 로컬 파트 단어를 잇는다. 주변 영어 산문과 구분할
 * 수 없으므로 고립된 이메일 필드에만 쓴다. 기본은 가장 가까운 로컬 단어만 인식한다.
 */
export function detect(text: string, options: EmailDetectOptions = {}): DetectionResult[] {
  const allowSpacedLocal = options.allowSpacedLocal ?? false;
  const candidates: DetectionResult[] = [];

  for (const m of text.matchAll(PATTERN)) {
    const value = m[1] as string;
    const at = value.lastIndexOf("@");
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    // Reject obvious malformed cases the regex permits
    if (local.startsWith(".") || local.endsWith(".")) continue;
    if (local.includes("..") || domain.includes("..")) continue;
    candidates.push(
      makeDetection({
        label: LABEL,
        text: value,
        start: m.index,
        end: m.index + m[0].length,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:email"],
        subruleId: "email.ascii.v1",
        legal_basis: LEGAL_BASIS,
        extra: { value, local, domain, category: CATEGORY },
      }),
    );
  }

  for (const m of text.matchAll(IDN_PATTERN)) {
    const value = m[1] as string;
    const at = value.lastIndexOf("@");
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    if (
      ASCII_ONLY.test(domain) ||
      local.startsWith(".") ||
      local.endsWith(".") ||
      local.includes("..")
    ) {
      continue;
    }
    const asciiDomain = idnaEncode(domain);
    if (asciiDomain === null || asciiDomain.length > 253) continue;
    candidates.push(
      makeDetection({
        label: LABEL,
        text: value,
        start: m.index,
        end: m.index + m[0].length,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:email_idn"],
        legal_basis: LEGAL_BASIS,
        subruleId: "email.korean_domain.v1",
        extra: { value, local, domain, ascii_domain: asciiDomain, category: CATEGORY },
      }),
    );
  }

  // 난독화 이메일 — 표준 패턴에 안 잡힌 우회 형태. 표준 매치와 겹치면 선택 단계에서 빠진다.
  for (const m of obfuscatedMatches(text, allowSpacedLocal)) {
    const canon = canonicalize(m.text);
    if (canon === null) continue;
    const at = canon.lastIndexOf("@");
    const local = canon.slice(0, at);
    const domain = canon.slice(at + 1);
    candidates.push(
      makeDetection({
        label: LABEL,
        text: m.text,
        start: m.start,
        end: m.end,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:email", "obfuscated:deobfuscated"],
        subruleId: "email.obfuscated.v1",
        legal_basis: LEGAL_BASIS,
        extra: { value: canon, local, domain, category: CATEGORY, obfuscated: true },
      }),
    );
  }
  return selectNonOverlapping(candidates);
}
