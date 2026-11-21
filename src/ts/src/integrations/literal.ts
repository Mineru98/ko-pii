/**
 * 원문에 대한 한도 있는 정확값 매칭 — 한국어 조사는 opt-in.
 * Python ko_pii.integrations.literal 대응.
 */

import { PARTICLES } from "../context/particles.js";
import { ValueError } from "../core/errors.js";
import { codePointLength, regexEscape } from "../core/strUtils.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";
import { ALL_LABELS } from "../labels.js";
import { CallableDetector, type CustomDetectorLimits } from "./custom.js";

export type LiteralBoundary = "word" | "substring" | "korean";

/** {@link LiteralDetector} 옵션. */
export interface LiteralDetectorOptions extends CustomDetectorLimits {
  /** 기본 "word". */
  boundary?: LiteralBoundary;
}

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);
const BOUNDARIES: ReadonlySet<unknown> = new Set(["word", "substring", "korean"]);
/** Python ``\w`` (유니코드 str 패턴) 근사 — 문자·숫자·밑줄. */
const WORD = "[\\p{L}\\p{N}_]";

/** Python ``sorted(key=lambda t: (-len(t), t))`` — 길이(코드 포인트) 내림차순, 코드 포인트 순. */
function byLengthDescThenValue(a: string, b: string): number {
  return codePointLength(b) - codePointLength(a) || (a < b ? -1 : a > b ? 1 : 0);
}

/**
 * 주어진 값을 검출 — 미지의 개체나 철자 변형은 찾지 않는다.
 *
 * ``word`` 는 유니코드 단어 경계를 요구하고 ``substring`` 은 요구하지 않는다.
 * ``korean`` 은 전부 한글인 PERSON 값 뒤에 알려진 조사를 추가로 허용한다. 대소문자를 구분하고
 * 정규화하지 않는다. 한도 초과 시 사전·결과를 조용히 자르지 않고 실패한다.
 *
 * @param values 라벨 → 값 목록 매핑 (``Map`` 또는 일반 객체).
 */
export class LiteralDetector extends CallableDetector {
  override name = "custom-literal";

  constructor(
    values: ReadonlyMap<string, Iterable<string>> | Readonly<Record<string, Iterable<string>>>,
    options: LiteralDetectorOptions = {},
  ) {
    const boundary = options.boundary === undefined ? "word" : options.boundary;
    if (typeof boundary !== "string" || !BOUNDARIES.has(boundary)) {
      throw new ValueError("literal boundary must be word, substring or korean");
    }
    const entries: [string, Iterable<string>][] | null =
      values instanceof Map
        ? [...values.entries()]
        : typeof values === "object" && values !== null && !Array.isArray(values)
          ? Object.entries(values as Record<string, Iterable<string>>)
          : null;
    if (entries === null || entries.length === 0 || entries.length > ALL_LABELS.length) {
      throw new ValueError("literal values require a nonempty label mapping");
    }
    // key = `${label}\0${korean}` — Python dict[(label, korean)].
    const grouped = new Map<string, { label: string; korean: boolean; terms: Set<string> }>();
    const owners = new Map<string, string>();
    let count = 0;
    let chars = 0;
    try {
      for (const [label, terms] of entries) {
        if (
          !LABEL_SET.has(label) ||
          typeof terms === "string" ||
          terms instanceof Uint8Array ||
          terms === null ||
          typeof (terms as { [Symbol.iterator]?: unknown })[Symbol.iterator] !== "function"
        ) {
          throw new ValueError();
        }
        let present = false;
        for (const term of terms) {
          count += 1;
          if (typeof term !== "string" || !term.trim() || codePointLength(term) > 256) {
            throw new ValueError();
          }
          chars += codePointLength(term);
          const owner = owners.get(term);
          if (count > 1024 || chars > 65536 || (owner !== undefined && owner !== label)) {
            throw new ValueError();
          }
          owners.set(term, label);
          const korean = boundary === "korean" && label === "PERSON" && /^[가-힣]+$/.test(term);
          const key = `${label}\0${korean}`;
          let group = grouped.get(key);
          if (group === undefined) {
            group = { label, korean, terms: new Set() };
            grouped.set(key, group);
          }
          group.terms.add(term);
          present = true;
        }
        if (!present) throw new ValueError();
      }
    } catch {
      throw new ValueError(
        "invalid or beyond-limit literal values; use existing labels and bounded strings",
      );
    }
    const particles = [...PARTICLES].sort(byLengthDescThenValue).map(regexEscape).join("|");
    const groups = [...grouped.values()].sort(
      (a, b) =>
        (a.label < b.label ? -1 : a.label > b.label ? 1 : 0) || Number(a.korean) - Number(b.korean),
    );
    const patterns: [string, RegExp][] = [];
    for (const { label, korean, terms } of groups) {
      const alternatives = [...terms].sort(byLengthDescThenValue).map(regexEscape).join("|");
      const left = boundary === "substring" ? "" : `(?<!${WORD})`;
      const right =
        boundary === "substring" ? "" : korean ? `(?=(?:${particles})?(?!${WORD}))` : `(?!${WORD})`;
      // lookahead 가 겹치는 시작과 원문 오프셋을 보존한다. 경계를 lookahead 안에 두어
      // 더 긴 무효 대안이 역추적할 수 있게 한다.
      patterns.push([label, new RegExp(`${left}(?=(${alternatives})${right})`, "gdu")]);
    }

    function* matches(text: string): Generator<DetectionResult> {
      for (const [label, pattern] of patterns) {
        for (const match of text.matchAll(pattern)) {
          const span = match.indices?.[1];
          if (span === undefined) continue;
          const [start, end] = span;
          yield makeDetection({
            label,
            text: text.slice(start, end),
            start,
            end,
            riskLevel: RiskLevel.HIGH,
            confidence: 1.0,
          });
        }
      }
    }

    super(matches, { maxChars: options.maxChars, maxMatches: options.maxMatches });
  }
}
