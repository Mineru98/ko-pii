/** 컨텍스트 점수 시스템 — 이름 후보 평가. Python ko_pii.context.context_rules 대응.
 *
 * 각 후보는 0.0~1.0 사이 점수를 받고, 임계값 이상이면 PERSON 으로 emit.
 *
 * 점수 가산 신호:
 * + 0.50  필드 라벨 (성명: / 신청인) 가 직전(≤4자) 에 있음
 * + 0.35  공무원·민간 직책이 인접(≤3자) — 앞 또는 뒤
 * + 0.30  결정적 PII (RRN/PHONE/EMAIL) 가 동일 문장 내 인접
 * + 0.20  한국어 조사 (이/가/은/는/을/를) 가 직접 붙음
 * + 0.15  성씨 사전 매칭
 * + 0.10  기관(부처/기관) 토큰이 같은 문장 내
 * + 0.20  누적 사전에 이미 확정된 이름
 *
 * 감점 신호:
 * - 0.40  토큰이 일반 단어 사전에 있음
 * - 0.30  토큰 길이 1 (한 글자 이름은 시드 신호 없으면 거의 항상 FP)
 * - 0.20  토큰이 숫자/영문 포함
 */

import { FIELD_LABELS_NAME } from "../dictionaries/generated/field_labels.js";
import {
  isAgency,
  isCommonWord,
  isGovTitle,
  isTitle,
  surnamePrefixLen,
} from "../dictionaries/index.js";
import { PARTICLES, stripTrailingParticle } from "./particles.js";

/** Python NameCandidate dataclass 대응. */
export interface NameCandidate {
  name: string;
  start: number;
  end: number;
}

/** NameCandidate 팩토리 — Python dataclass 생성자 대응. */
export function makeNameCandidate(name: string, start: number, end: number): NameCandidate {
  return { name, start, end };
}

/** Python Score dataclass 대응. */
export interface Score {
  value: number;
  evidence: string[];
}

/** Score 팩토리 — evidence 기본값 [] (Python field(default_factory=list)) 대응. */
export function makeScore(value: number, evidence?: string[]): Score {
  return { value, evidence: evidence ?? [] };
}

/**
 * 같은 문장의 (left, right) 범위별 기관 매칭 결과 캐시 — Python
 * `dict[tuple[int, int], bool] | None` 대응. 키는 `"${left},${right}"`.
 */
export type AgencySentenceCache = Map<string, boolean>;

// ---------------------------------------------------------------------------
// Python str 유틸 근사 (이 모듈 전용)
// ---------------------------------------------------------------------------

/** Python str.isspace() 문자 클래스 — str.strip() 근사용. */
const PY_WS =
  "[\\t\\n\\u000b\\u000c\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const RE_PY_STRIP = new RegExp(`^${PY_WS}+|${PY_WS}+$`, "g");
const RE_PY_RSTRIP = new RegExp(`${PY_WS}+$`);

function pyStrip(s: string): string {
  return s.replace(RE_PY_STRIP, "");
}

function pyRstrip(s: string): string {
  return s.replace(RE_PY_RSTRIP, "");
}

function pyLstripColons(s: string): string {
  return s.replace(/^[:：]+/, "");
}

/** Python `" a b".split()` 동등 — `re.finditer(r"\S+", s)` 와 동일한 토큰열. */
function wordIter(text: string): string[] {
  const trimmed = text.trim();
  if (!trimmed) {
    return [];
  }
  return trimmed.split(/\s+/);
}

/** Python: all("가" <= ch <= "힣" for ch in name) — 빈 문자열은 all() 이 참. */
function looksKorean(name: string): boolean {
  for (const ch of name) {
    const code = ch.codePointAt(0) as number;
    if (code < 0xac00 || code > 0xd7a3) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// 개별 신호 판정 (Python 비공개 헬퍼 대응)
// ---------------------------------------------------------------------------

/** Look for a name-field label like "성명:" within `window` chars before.
 *
 * 반환값은 매칭된 라벨 (없으면 null).
 */
export function hasFieldLabelBefore(text: string, start: number, window = 6): string | null {
  const head = text.slice(Math.max(0, start - window - 4), start);
  // Python 의 FIELD_LABELS_NAME 은 frozenset — 순회 순서가 해시 시드마다 달라진다.
  // TS 에서는 generated Set 의 삽입 순서(결정적)로 순회하며, 모호한 접미 쌍
  // (고소인/피고소인, 평가자/피평가자, 면담자/피면담자, 추천인/피추천인) 은
  // 어느 순서에서도 짧은 라벨이 먼저 매칭되어 결과가 동일하다.
  for (const label of FIELD_LABELS_NAME) {
    // Allow "성명:", "성명 :", "성명 ", etc.
    const idx = head.lastIndexOf(label);
    if (idx === -1) {
      continue;
    }
    const between = head.slice(idx + label.length);
    const stripped = pyStrip(pyLstripColons(pyStrip(between)));
    if (stripped === "") {
      return label;
    }
  }
  return null;
}

/** `word` → title 정식형 (조사·연결어미 제거 후 dict 매칭). */
function resolveTitle(word: string): [string | null, boolean] {
  // 1차: 조사 strip 후 dict 매칭
  const [stem] = stripTrailingParticle(word);
  if (isTitle(stem)) {
    return [stem, isGovTitle(stem)];
  }
  // 2차: 직책 dict 의 prefix 매칭 (조사·연결어미 부착 형식)
  // "주임이며/주임이고/주임이라/사장님은" 같은 패턴 cover
  // 가장 긴 매칭 우선 (4자 → 2자)
  for (let plen = Math.min(stem.length, 5); plen >= 2; plen--) {
    const prefix = stem.slice(0, plen);
    if (isTitle(prefix)) {
      return [prefix, isGovTitle(prefix)];
    }
  }
  return [null, false];
}

/** Return `[matchedTitle, isGov]` if a title is within `window` chars.
 *
 * Checks both sides: "<title> <name>" and "<name> <title>". Korean
 * particles attached to the title (e.g. "과장이", "과장은") are stripped
 * before lookup. Connective endings (e.g. "주임이며/주임이고") are
 * also stripped by checking title prefix.
 */
export function hasTitleAdjacent(
  text: string,
  start: number,
  end: number,
  window = 5,
): [string | null, boolean] {
  // After the candidate (most common: "홍길동 과장") — only the first word
  // counts as "adjacent".
  const tail = text.slice(end, end + window + 6);
  const tailWords = wordIter(tail);
  const firstWord = tailWords[0];
  if (firstWord !== undefined) {
    const [title, gov] = resolveTitle(firstWord);
    if (title !== null) {
      return [title, gov];
    }
  }

  // Before the candidate (e.g., "과장 홍길동")
  const headStart = Math.max(0, start - window - 6);
  const head = text.slice(headStart, start);
  const rev = pyRstrip(head);
  if (rev) {
    const words = wordIter(rev);
    const last = words[words.length - 1];
    if (last !== undefined) {
      const [title, gov] = resolveTitle(last);
      if (title !== null) {
        return [title, gov];
      }
    }
  }
  return [null, false];
}

/** 후보가 속한 문장(좌우 경계) 내 기관 언급 여부. */
export function hasAgencyInSentence(
  text: string,
  start: number,
  end: number,
  cache?: AgencySentenceCache | null,
): boolean {
  // Extract sentence boundaries: . / 다. / 음. / line break
  const before = text.slice(0, start);
  const left = Math.max(before.lastIndexOf("."), before.lastIndexOf("\n")) + 1;
  const rightDot = text.indexOf(".", end);
  const rightNl = text.indexOf("\n", end);
  const candidates = [rightDot, rightNl].filter((r) => r !== -1);
  const right = candidates.length > 0 ? Math.min(...candidates) : text.length;
  // 같은 문장의 후보들은 동일한 (left, right) 범위를 공유 → 한 번만 단어 순회하도록
  // 캐시(없으면 O(후보×단어)=O(n²); 긴 문서·이름 다수에서 quadratic 폭주를 막는다).
  const key = `${left},${right}`;
  if (cache?.has(key)) {
    return cache.get(key) as boolean;
  }
  const result = wordIter(text.slice(left, right)).some((tok) => isAgency(tok));
  if (cache != null) {
    cache.set(key, result);
  }
  return result;
}

/** Check if right after the candidate there is a Korean particle. */
export function hasParticleAttached(text: string, end: number): string | null {
  const tail = text.slice(end, end + 3);
  for (const p of PARTICLES) {
    if (tail.startsWith(p)) {
      return p;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// 후보 채점
// ---------------------------------------------------------------------------

/** Compute a 0~1 score for `cand` based on surrounding signals. */
export function scoreCandidate(
  text: string,
  cand: NameCandidate,
  deterministicNearby = false,
  nameDictionaryBoost = 0.0,
  agencyCache?: AgencySentenceCache | null,
): Score {
  const ev: string[] = [];
  let score = 0.0;

  // Negative signal: common word.
  if (isCommonWord(cand.name)) {
    score -= 0.4;
    ev.push("neg:common_word");
  }

  // Negative signal: non-Korean characters.
  if (!looksKorean(cand.name)) {
    score -= 0.2;
    ev.push("neg:non_korean");
  }

  // Negative signal: length 1.
  if (Array.from(cand.name).length === 1) {
    score -= 0.3;
    ev.push("neg:length_1");
  }

  // Surname presence
  const sp = surnamePrefixLen(cand.name);
  if (sp > 0) {
    score += 0.15;
    ev.push(`pos:surname(${cand.name.slice(0, sp)})`);
  }

  // Field label immediately before
  const label = hasFieldLabelBefore(text, cand.start);
  if (label !== null) {
    score += 0.5;
    ev.push(`pos:field_label(${label})`);
  }

  // Title adjacency
  const [title, gov] = hasTitleAdjacent(text, cand.start, cand.end);
  if (title !== null) {
    score += 0.35;
    ev.push(`pos:title(${title}${gov ? ":gov" : ""})`);
  }

  // Particle attached — 한국어의 강한 PERSON 신호
  // 예: "장혁이 울었다" → surname + particle 만으로도 인명 인식 가능해야
  const p = hasParticleAttached(text, cand.end);
  if (p !== null) {
    score += 0.35;
    ev.push(`pos:particle(${p})`);
  }

  // Deterministic PII adjacent — strong cue: RRN/PHONE next to a Korean
  // 2~4 char surname-prefixed token is almost always a name.
  // 길이 차등 부스트 (KDPII 과탐 분석 결과):
  // - 3자+ 풀네임: +0.40 (확정적 PII 옆 풀네임 = 거의 확실한 인명)
  // - 2자 단명·약명: +0.20 (성+1자 이름은 일반 어휘 충돌 잦음)
  if (deterministicNearby) {
    const tokenLen = cand.end - cand.start;
    const boost = tokenLen >= 3 ? 0.4 : 0.2;
    score += boost;
    ev.push("pos:deterministic_pii_nearby");
  }

  // Agency mention in same sentence
  if (hasAgencyInSentence(text, cand.start, cand.end, agencyCache)) {
    score += 0.1;
    ev.push("pos:agency_in_sentence");
  }

  // Cumulative dictionary boost
  if (nameDictionaryBoost > 0) {
    score += nameDictionaryBoost;
    ev.push(`pos:name_dict_boost(${nameDictionaryBoost.toFixed(2)})`);
  }

  // Clamp to [0, 1]
  if (score < 0) {
    score = 0.0;
  }
  if (score > 1) {
    score = 1.0;
  }
  return makeScore(score, ev);
}
