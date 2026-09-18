/**
 * 인사 도메인 — 사번·직번 등 내부 식별자.
 *
 * 추가 검출:
 * - 공무원/직원 사번 — "사번"/"공무원번호"/"직원번호"/"임용번호" 가 *숫자 직전에*
 *   콜론(:) 또는 공백을 사이에 두고 위치할 때만 매칭. 일반 문장
 *   ("이것은 사번이 다르다 ... 20240001") 에서 FP 가 나지 않도록 *tight anchor*.
 *
 * 공무원 직책 사전 세분화는 사용자 도메인 입력이 필요해
 * 별도 기능으로 분리. 본 모듈은 키워드 anchor 기반 단순 룰.
 *
 * Legal basis: 개인정보보호법 제2조; 국가공무원법 제22조.
 */
import { regexEscape } from "../core/strUtils.js";
import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "EMPLOYEE_ID";
const LEGAL_BASIS = "개인정보보호법 제2조; 국가공무원법 제22조";
const CATEGORY = "일반개인정보";

// FP 위험으로 제거된 키워드:
//   - "교번" : 수학·공학의 "교차/교번" 의미 충돌
const KEYWORDS: readonly string[] = ["사번", "공무원번호", "직원번호", "임용번호", "사원번호"];

// 키워드가 *숫자 직전에* (콜론·전각콜론·공백 옵션) 위치해야만 매칭.
const ANCHOR = new RegExp(`(?:${KEYWORDS.map((kw) => regexEscape(kw)).join("|")})\\s*[:：]?\\s*$`);

const PATTERN = /(?<![0-9])([0-9]{4,12})(?![0-9])/g;

function keywordDirectlyBefore(text: string, start: number, window = 20): string | null {
  const head = text.slice(Math.max(0, start - window), start);
  const m = ANCHOR.exec(head);
  if (m) {
    return (m[0] as string).replace(/[ :：]+$/, "").trim();
  }
  return null;
}

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    const value = m[1] as string;
    const kw = keywordDirectlyBefore(text, m.index);
    if (kw === null) {
      continue;
    }
    results.push(
      makeDetection({
        label: LABEL,
        text: value,
        start: m.index,
        end: m.index + value.length,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 0.85,
        evidence: ["pattern:employee_id", `keyword:${kw}`, "domain:hr"],
        legal_basis: LEGAL_BASIS,
        extra: {
          category: CATEGORY,
          domain: "hr",
          value,
        },
      }),
    );
  }
  return results;
}
