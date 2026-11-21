/** 처리 기록. 원문 값과 문서 식별자는 opt-in 이다.
 *
 * Python `ko_pii.reporting.certificate` 1:1 포트.
 */

import type { AnonymizationResult } from "../anonymizer.js";
import { pyIsoUtcNow } from "../vault/reversible.js";
import { type ExplanationFinding, explain } from "./explanation.js";

export interface CertificateOptions {
  /** 문서 식별자 줄 포함 (Python ``include_document_id``). */
  includeDocumentId?: boolean;
  /** BLOCK 항목의 치환값 포함 (Python ``include_replacements``). */
  includeReplacements?: boolean;
  /** 생성 일시(UTC) 문자열 — Python ``datetime.now(timezone.utc).isoformat()`` 에 해당하는
   * 비결정 요소. 미지정 시 현재 UTC 시각. 결정론 테스트를 위해 주입 가능. */
  now?: string;
}

const SECTIONS: readonly (readonly [string, string])[] = [
  ["BLOCK", "차단/치환 처리 항목"],
  ["REVIEW", "검토 대기 항목"],
  ["ALLOW", "유지 항목"],
];

/** Python f-string 보간 — None 은 "None". */
function pyStr(v: unknown): string {
  return v === null || v === undefined ? "None" : String(v);
}

/** 기본적으로 값 없는 기록을 만든다 — 법적 준수 증명서가 아니다.
 *
 * opt-in 검토 상세·치환값·문서 식별자는 PII 를 노출할 수 있다. 메모리상의 result/Vault 는
 * 이와 별개로 여전히 민감한 데이터를 담는다.
 */
export function generateCertificate(
  result: AnonymizationResult,
  documentId = "(unspecified)",
  includeReviewDetails = false,
  options: CertificateOptions = {},
): string {
  const includeDocumentId = options.includeDocumentId ?? false;
  const includeReplacements = options.includeReplacements ?? false;
  const report = explain(result);
  const findings = report.findings as ExplanationFinding[];
  const parts: string[] = [
    "=".repeat(60),
    "개인정보 처리 증명서 (ko-pii)",
    `생성 일시(UTC): ${options.now ?? pyIsoUtcNow()}`,
    `처리 모드: ${pyStr(report.mode)}`,
    `총 검출: ${pyStr(report.detection_count)} 건`,
  ];
  if (includeDocumentId) parts.push(`문서 식별자: ${documentId}`);
  if (includeReviewDetails || includeDocumentId || includeReplacements) {
    parts.push("주의: 명시적으로 요청한 민감한 상세 정보가 포함될 수 있습니다.");
  }
  for (const [action, heading] of SECTIONS) {
    const items = result.detections
      .map((rec, i) => [rec, findings[i]] as const)
      .filter(
        (pair): pair is readonly [(typeof pair)[0], ExplanationFinding] =>
          pair[1] !== undefined && pair[1].action === action,
      );
    if (items.length === 0) continue;
    parts.push(`\n[${heading}]`);
    for (const [rec, row] of items) {
      parts.push(
        `  - ${row.label} @[${row.source_span[0]}, ${row.source_span[1]}] ` +
          `strategy=${pyStr(row.applied_strategy)} status=${row.reason}`,
      );
      if (action === "REVIEW" && includeReviewDetails) {
        parts.push(`    원문: ${rec.detection.text}`);
      }
      if (action === "BLOCK" && includeReplacements && rec.token) {
        parts.push(`    치환값: ${rec.token}`);
      }
    }
  }
  parts.push(
    "",
    "본 기록은 탐지·처리 내역이며, 미탐지 정보의 부재나 법적 익명성을 보증하지 않습니다.",
    "=".repeat(60),
  );
  return parts.join("\n");
}
