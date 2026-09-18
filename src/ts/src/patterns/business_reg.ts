/**
 * 사업자등록번호 (Business Registration Number) detection.
 *
 * 10-digit format: XXX-XX-XXXXX, optional hyphens.
 *
 * Legal status: 사업자등록번호 자체는 법인의 경우 개인정보로 보기 어렵지만,
 * 개인사업자의 경우 사업자등록번호가 곧 개인을 식별하는 정보가 됨 → 보수적으로
 * HIGH 위험도로 보고. 후속 도메인 규칙에서 사업체 유형에 따라 조정 가능.
 *
 * Detection requires the 국세청 checksum to pass — short numeric runs that
 * happen to match the 3-2-5 pattern but fail the checksum are filtered out.
 */
import { isValidChecksum } from "../checksum/businessRegChecksum.js";
import type { DetectionResult } from "../core/types.js";
import { makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "BUSINESS_REG";
const LEGAL_BASIS = "개인정보보호법 제2조 (개인사업자의 경우 개인 식별 정보)";
const CATEGORY = "일반개인정보";

const PATTERN = /(?<![0-9])([0-9]{3})-?([0-9]{2})-?([0-9]{5})(?![0-9])/g;

export function detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(PATTERN)) {
    const full = m[0] as string;
    const digits = (m[1] as string) + (m[2] as string) + (m[3] as string);
    // 모두 0 인 placeholder 거부 (체크섬 통과해도 실제 사업자 아님)
    if (digits === "0000000000") {
      continue;
    }
    if (!isValidChecksum(digits)) {
      continue;
    }
    results.push(
      makeDetection({
        label: LABEL,
        text: full,
        start: m.index,
        end: m.index + full.length,
        riskLevel: RiskLevel.HIGH,
        confidence: 1.0,
        evidence: ["pattern:business_reg", "checksum:valid"],
        legal_basis: LEGAL_BASIS,
        extra: {
          digits,
          checksum_valid: true,
          category: CATEGORY,
        },
      }),
    );
  }
  return results;
}
