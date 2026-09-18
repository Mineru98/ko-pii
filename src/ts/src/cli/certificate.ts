/**
 * 처리 증명서 — Python ko_pii.reporting.certificate.generate_certificate
 * 1:1 포트. Legal basis: 개인정보보호법 제29조 (안전조치의무) — 처리 이력 기록.
 *
 * (ts/src/reporting 은 다른 에이전트 소유 — reporting 포팅 완료 후 이 파일을
 * reporting 쪽 구현으로 교체/재수출하면 된다.)
 */

import { riskLevelName } from "../analytics/index.js";
import { type AnonymizationResult, blockedItems, reviewItems } from "../anonymizer.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { pyIsoUtcNow } from "../vault/reversible.js";
import { formatSummaryText } from "./summaryText.js";

export function generateCertificate(
  result: AnonymizationResult,
  documentId = "(unspecified)",
  includeReviewDetails = true,
): string {
  const now = pyIsoUtcNow();
  const parts: string[] = [];
  parts.push("=".repeat(60));
  parts.push("개인정보 처리 증명서 (ko-pii)");
  parts.push("=".repeat(60));
  parts.push(`문서 식별자: ${documentId}`);
  parts.push(`생성 일시(UTC): ${now}`);
  parts.push("");
  parts.push(formatSummaryText(result));
  parts.push("");

  const blocked = blockedItems(result);
  if (blocked.length > 0) {
    parts.push("[차단/치환 처리 항목]");
    for (const rec of blocked) {
      const d = rec.detection;
      const risk = riskLevelName(d.riskLevel);
      const token = rec.token || "(no-token)";
      parts.push(
        `  - ${d.label} @[${d.start}:${d.end}] → ${token} (risk=${risk}, conf=${pyFormatFixed(d.confidence, 2)})`,
      );
    }
    parts.push("");
  }

  const review = reviewItems(result);
  if (review.length > 0 && includeReviewDetails) {
    parts.push("[검토 대기 항목]");
    for (const rec of review) {
      const d = rec.detection;
      const risk = riskLevelName(d.riskLevel);
      parts.push(
        `  - ${d.label} @[${d.start}:${d.end}] '${d.text}' (risk=${risk}, conf=${pyFormatFixed(d.confidence, 2)})`,
      );
    }
    parts.push("");
  }

  parts.push("=".repeat(60));
  parts.push("본 증명서는 개인정보보호법 제29조에 의거한 처리 기록입니다.");
  parts.push("=".repeat(60));
  return parts.join("\n");
}
