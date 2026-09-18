/**
 * `ko-pii --labels` 출력 — Python ko_pii.labels.format_labels_table 1:1 포트.
 *
 * 포맷 실측:
 * - 헤더: `ko-pii PII 카테고리 33종 — include/exclude 에 쓰는 라벨 키`
 * - 그룹별 `[그룹명] (N)` 아래 `  KEY<pad>  한글명<U+3000 pad to 8>  검출방식`
 * - 한글명 폭 채움은 아이디어그래프 공백(U+3000), 폭 계산은 코드 포인트.
 */
import { ALL_LABELS, GROUPS, LABEL_INFO } from "../labels.js";

function cpLen(s: string): number {
  return [...s].length;
}

function padEndCp(s: string, width: number, fill = " "): string {
  const pad = width - cpLen(s);
  return pad <= 0 ? s : s + fill.repeat(pad);
}

/** ``ko-pii --labels`` 출력용 그룹별 표. */
export function formatLabelsTable(): string {
  const lines: string[] = [
    `ko-pii PII 카테고리 ${ALL_LABELS.length}종 — include/exclude 에 쓰는 라벨 키`,
    "",
  ];
  for (const g of GROUPS) {
    const items = Object.entries(LABEL_INFO).filter(([, v]) => v[1] === g);
    lines.push(`[${g}] (${items.length})`);
    const w = Math.max(...items.map(([k]) => cpLen(k)));
    for (const [k, [ko, , how]] of items) {
      lines.push(`  ${padEndCp(k, w)}  ${padEndCp(ko, 8, "\u3000")}  ${how}`);
    }
    lines.push("");
  }
  lines.push('사용 예: ko-pii doc.txt --include RRN,PHONE / detect_all(text, exclude=["PERSON"])');
  return lines.join("\n");
}
