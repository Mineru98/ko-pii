/** 우편번호 (Korean Postal Code) detection.
 *
 * Python 원본: src/ko_pii/patterns/postal_code.py — 1:1 포팅 (골드 마스터 기준).
 *
 * Two historical formats:
 *   - 5-digit (2015-08-01 onward): YXXXX — 국가기초구역번호
 *   - 6-digit legacy (~2015):       XXX-XXX
 *
 * 5자리 첫 2자리 (시·도 코드, 우정사업본부 공개 데이터) 화이트리스트 검증.
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "POSTAL_CODE";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

// 시·도별 첫 2자리 화이트리스트
const VALID_POSTAL_PREFIXES: ReadonlySet<string> = new Set(
  [
    ...seq(1, 8), // 01~08 서울
    ...seq(10, 18), // 10~18 경기
    ...seq(21, 29), // 21~29 인천·강원·충북
    ...seq(30, 35), // 30 세종, 31~33 충남, 34~35 대전
    ...seq(36, 49), // 36~49 경북·대구·울산·부산
    ...seq(50, 59), // 50~59 경남·전북·전남
    61,
    62,
    63, // 광주·제주
  ].map((n) => String(n).padStart(2, "0")),
);

function seq(fromInclusive: number, toInclusive: number): number[] {
  const out: number[] = [];
  for (let n = fromInclusive; n <= toInclusive; n++) out.push(n);
  return out;
}

const LEGACY = /(?<![0-9])([0-9]{3}-[0-9]{3})(?![0-9])/g;

const NEW_WITH_KEYWORD = /(?:우편\s*번호|우편번호|우편)\s*:?\s*([0-9]{5})(?![0-9])/dg;

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Array<readonly [number, number]> = [];

  for (const m of text.matchAll(NEW_WITH_KEYWORD)) {
    const g = m.indices?.[1];
    if (m.index === undefined || g === undefined) continue;
    const [gs, ge] = g;
    const span: readonly [number, number] = [gs, ge];
    if (seen.some(([s, e]) => s === span[0] && e === span[1])) continue;
    const code = m[1];
    if (code === undefined) continue;
    // 첫 2자리 시·도 코드 화이트리스트
    if (!VALID_POSTAL_PREFIXES.has(code.slice(0, 2))) continue;
    seen.push(span);
    out.push(
      makeDetection({
        label: LABEL,
        text: code,
        start: gs,
        end: ge,
        riskLevel: RiskLevel.LOW,
        confidence: 1.0,
        evidence: [
          "pattern:postal_code",
          "format:5_digit",
          "keyword:우편번호",
          `sido_prefix:${code.slice(0, 2)}`,
        ],
        legal_basis: LEGAL_BASIS,
        extra: { value: code, format: "5_digit", category: CATEGORY },
      }),
    );
  }

  for (const m of text.matchAll(LEGACY)) {
    if (m.index === undefined) continue;
    const start = m.index;
    const end = start + m[0].length;
    if (seen.some(([s, e]) => s === start && e === end)) continue;
    const code = m[1];
    if (code === undefined) continue;
    // 6자리 레거시도 첫 자리는 1~7 (구 우편번호 체계)
    const firstDigit = code[0];
    if (firstDigit === undefined || !"1234567".includes(firstDigit)) continue;
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: code,
        start,
        end,
        riskLevel: RiskLevel.LOW,
        confidence: 0.85,
        evidence: ["pattern:postal_code", "format:6_digit_legacy"],
        legal_basis: LEGAL_BASIS,
        extra: { value: code, format: "6_digit", category: CATEGORY },
      }),
    );
  }

  return out;
}
