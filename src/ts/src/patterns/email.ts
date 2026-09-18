/** Email address detection (simplified RFC 5322) — 난독화 이메일 포함.
 *
 * Python 원본: src/ko_pii/patterns/email.py — 1:1 포팅 (골드 마스터 기준).
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "EMAIL";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

const PATTERN =
  /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)(?![A-Za-z0-9])/g;

// 난독화 이메일(GAP 3): "hong[at]gmail.com" → hong@gmail.com,
// "hong gildong @ naver . com" → 로컬 공백·구분자 공백 주입.
// recall-safe 설계:
//   - @ 등가물은 실제 '@' 또는 대괄호/소괄호로 감싼 at 만 허용(맨단어 ' at '는 산문 FP
//     위험이 커 제외 — "meet at noon" 등).
//   - dot 등가물도 실제 '.' 또는 괄호 감싼 dot 만. 도메인 라벨이 1개 이상 점으로 이어질
//     때만 매치 → 'admin@host'(점 없음)·'10 . 5'(라벨 아님)는 미해당.
const OBF_AT = String.raw`(?:@|\[\s*at\s*\]|\(\s*at\s*\))`;
const OBF_DOT = String.raw`(?:\.|\[\s*dot\s*\]|\(\s*dot\s*\))`;
const OBF_LOCAL = String.raw`[A-Za-z0-9._%+\-]+(?:\s+[A-Za-z0-9._%+\-]+)*`;
const OBF_LABEL = String.raw`[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?`;
const OBFUSCATED = new RegExp(
  String.raw`(?<![A-Za-z0-9._%+\-@])` +
    OBF_LOCAL +
    String.raw`\s*` +
    OBF_AT +
    String.raw`\s*` +
    OBF_LABEL +
    String.raw`(?:\s*` +
    OBF_DOT +
    String.raw`\s*` +
    OBF_LABEL +
    String.raw`)+` +
    String.raw`(?![A-Za-z0-9])`,
  "gi",
);

// 난독화 토큰([at]/[dot]/괄호/공백)을 표준형으로 환원.
const DEOBF_AT = /\s*(?:\[\s*at\s*\]|\(\s*at\s*\))\s*/gi;
const DEOBF_DOT = /\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\))\s*/gi;

/** 난독화 이메일 원문 → 표준 'local@domain'. 비정상이면 null. */
function canonicalize(raw: string): string | null {
  let s = raw.replace(DEOBF_AT, "@");
  s = s.replace(DEOBF_DOT, ".");
  s = s.replaceAll(" ", ""); // 잔여 공백(@ . 주변, 로컬 분할) 제거
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

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Array<readonly [number, number]> = [];

  for (const m of text.matchAll(PATTERN)) {
    if (m.index === undefined) continue;
    const value = m[1];
    if (value === undefined) continue;
    const at = value.lastIndexOf("@");
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    // Reject obvious malformed cases the regex permits
    if (local.startsWith(".") || local.endsWith(".")) continue;
    if (local.includes("..") || domain.includes("..")) continue;
    seen.push([m.index, m.index + m[0].length]);
    out.push(
      makeDetection({
        label: LABEL,
        text: value,
        start: m.index,
        end: m.index + m[0].length,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:email"],
        legal_basis: LEGAL_BASIS,
        extra: {
          value,
          local,
          domain,
          category: CATEGORY,
        },
      }),
    );
  }

  // 난독화 이메일 — 표준 패턴에 안 잡힌 우회 형태. 표준 매치와 겹치면 건너뜀.
  for (const m of text.matchAll(OBFUSCATED)) {
    if (m.index === undefined) continue;
    const start = m.index;
    const end = start + m[0].length;
    if (seen.some(([s, e]) => s < end && start < e)) continue;
    const canon = canonicalize(m[0]);
    if (canon === null) continue;
    const at = canon.lastIndexOf("@");
    const local = canon.slice(0, at);
    const domain = canon.slice(at + 1);
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: m[0],
        start,
        end,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:email", "obfuscated:deobfuscated"],
        legal_basis: LEGAL_BASIS,
        extra: {
          value: canon,
          local,
          domain,
          category: CATEGORY,
          obfuscated: true,
        },
      }),
    );
  }

  return out;
}
