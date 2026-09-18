/**
 * 운전면허번호 (Driver License Number) detection.
 *
 * 12-digit format: XX-YY-NNNNNN-CC.
 *   XX: 지방경찰청 코드 (11~28 range historically assigned)
 *   YY: 면허 발급 연도 끝 2자리
 *   NNNNNN: 일련번호
 *   CC: 위변조 식별번호 (check) — the algorithm is not publicly standardized,
 *       so this module verifies format and region code only, not the check.
 *
 * 검출 정책:
 * - 하이픈 있는 형태 (``XX-YY-NNNNNN-CC``) → 패턴만으로 식별 가능
 * - 하이픈 없는 12자리는 다른 카테고리 (처방번호·날짜 등) 와 충돌 위험 큼
 *   → **"운전면허" / "면허번호" 키워드 anchor 필수**
 *
 * Legal basis: 개인정보보호법 시행령 제19조 (고유식별정보의 범위 — 운전면허번호).
 */

import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "DRIVER_LICENSE";
const LEGAL_BASIS = "개인정보보호법 시행령 제19조";
const CATEGORY = "고유식별정보";

// 지방경찰청 region codes (도로교통공단). 11~28 covers the historically
// assigned range including 세종(28). 27 was not in regular use.
const VALID_REGION_CODES: ReadonlySet<string> = new Set(
  Array.from({ length: 18 }, (_, i) => String(i + 11).padStart(2, "0")),
);

// 하이픈 포함 형태 — 패턴 단독 식별 가능
const PATTERN_HYPHEN = /(?<![0-9])([0-9]{2})-([0-9]{2})-([0-9]{6})-([0-9]{2})(?![0-9])/g;

// 하이픈 없는 12자리 — 키워드 anchor 필수
const PATTERN_NO_HYPHEN = /(?<![0-9])([0-9]{2})([0-9]{2})([0-9]{6})([0-9]{2})(?![0-9])/g;

const KEYWORDS: readonly string[] = ["운전면허", "면허번호", "면허증"];

function hasKeywordBefore(text: string, start: number, window = 15): string | null {
  const head = text.slice(Math.max(0, start - window), start);
  for (const kw of KEYWORDS) {
    if (head.includes(kw)) {
      return kw;
    }
  }
  return null;
}

function emit(
  full: string,
  start: number,
  end: number,
  groups: [string, string, string, string],
  hasHyphen: boolean,
  kw: string | null,
): DetectionResult {
  const [region, year2, sequence, check2] = groups;
  const evidence = ["pattern:driver_license", `region:${region}`];
  if (hasHyphen) {
    evidence.push("format:hyphenated");
  }
  if (kw) {
    evidence.push(`keyword:${kw}`);
  }
  return makeDetection({
    label: LABEL,
    text: full,
    start,
    end,
    riskLevel: RiskLevel.CRITICAL,
    confidence: 0.85,
    evidence,
    legal_basis: LEGAL_BASIS,
    extra: {
      region_code: region,
      year_2digit: year2,
      sequence,
      check_2digit: check2,
      format: hasHyphen ? "hyphenated" : "compact",
      category: CATEGORY,
    },
  });
}

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  const seen: Array<[number, number]> = [];

  for (const m of text.matchAll(PATTERN_HYPHEN)) {
    const full = m[0] as string;
    const start = m.index;
    const end = start + full.length;
    const region = m[1] as string;
    if (!VALID_REGION_CODES.has(region)) {
      continue;
    }
    seen.push([start, end]);
    results.push(
      emit(full, start, end, [region, m[2] as string, m[3] as string, m[4] as string], true, null),
    );
  }

  for (const m of text.matchAll(PATTERN_NO_HYPHEN)) {
    const full = m[0] as string;
    const start = m.index;
    const end = start + full.length;
    const span: [number, number] = [start, end];
    if (seen.some(([s, e]) => s === span[0] && e === span[1])) {
      continue;
    }
    const region = m[1] as string;
    if (!VALID_REGION_CODES.has(region)) {
      continue;
    }
    const kw = hasKeywordBefore(text, start);
    if (kw === null) {
      continue;
    }
    seen.push(span);
    results.push(
      emit(full, start, end, [region, m[2] as string, m[3] as string, m[4] as string], false, kw),
    );
  }

  return results;
}
