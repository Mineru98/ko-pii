/**
 * 민원 응대 문서 도메인 — 민원번호 + 신청서 번호.
 *
 * 추가 검출:
 * - 민원번호 (예: ``2024-민원-00123``) — 민원 통합관리시스템 표준
 * - 정보공개 청구번호 (예: ``정보공개-2024-00567``)
 *
 * 이름·전화·이메일 등 핵심 PII 는 기본 검출기에서 이미 잡음.
 *
 * Legal basis: 개인정보보호법 제2조, 「민원처리에 관한 법률」 제3조.
 */

import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "PETITION_ID";
const LEGAL_BASIS = "개인정보보호법 제2조; 민원처리에 관한 법률";
const CATEGORY = "참조정보";

const PATTERN =
  /(?<![A-Za-z0-9가-힣])((?:19|20)[0-9]{2}-(?:민원|정보공개|이의신청|행정심판)-[0-9]{4,8}|(?:민원|정보공개|이의신청|행정심판)-(?:19|20)[0-9]{2}-[0-9]{4,8})(?![A-Za-z0-9가-힣])/g;

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    const petitionId = m[1] as string;
    results.push(
      makeDetection({
        label: LABEL,
        text: petitionId,
        start: m.index,
        end: m.index + petitionId.length,
        riskLevel: RiskLevel.LOW,
        confidence: 0.9,
        evidence: ["pattern:petition_id", "domain:civil_petition"],
        legal_basis: LEGAL_BASIS,
        extra: {
          category: CATEGORY,
          domain: "civil_petition",
        },
      }),
    );
  }
  return results;
}
