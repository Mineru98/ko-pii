/** 처리 증명서 — 감사 추적용 텍스트 보고서.
 *
 * Python `ko_pii.reporting.certificate` 1:1 포트.
 *
 * `AnonymizationResult` 를 받아 다음을 포함한 증명서를 생성한다:
 * - 처리 일시·모드·전략
 * - 카테고리별 처리 건수
 * - 차단된 항목의 토큰 매핑 (원본 노출 없음)
 * - 검토 대상 큐
 * - 적용된 법적 근거 목록
 *
 * Legal basis: 개인정보보호법 제29조 (안전조치의무) — 처리 이력 기록.
 */
import { riskLevelName } from "../analytics/index.js";
import type { AnonymizationResult } from "../anonymizer.js";
import { blockedItems, reviewItems } from "../anonymizer.js";
import { pyIsoUtcNow } from "../vault/reversible.js";
import { formatSummaryText } from "./summary.js";

/**
 * 처리 증명서를 생성한다.
 *
 * @param now 생성 일시(UTC) 문자열 — Python `datetime.now(timezone.utc).isoformat()` 에
 *   해당하는 비결정 요소. 미지정 시 현재 UTC 시각. 결정론 테스트를 위해 주입 가능.
 */
export function generateCertificate(
  result: AnonymizationResult,
  documentId = "(unspecified)",
  includeReviewDetails = true,
  now: string = pyIsoUtcNow(),
): string {
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
        `  - ${d.label} @[${d.start}:${d.end}] → ${token} (risk=${risk}, conf=${d.confidence.toFixed(2)})`,
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
        `  - ${d.label} @[${d.start}:${d.end}] '${d.text}' (risk=${risk}, conf=${d.confidence.toFixed(2)})`,
      );
    }
    parts.push("");
  }

  parts.push("=".repeat(60));
  parts.push("본 증명서는 개인정보보호법 제29조에 의거한 처리 기록입니다.");
  parts.push("=".repeat(60));
  return parts.join("\n");
}
