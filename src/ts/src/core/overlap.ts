/**
 * 겹침 해소 — 단일 정본 구현 (Python ko_pii.core.overlap 대응).
 *
 * 정책: 위험도 → 확신도 → 길이 순으로 채택(높을수록 먼저), 이미 채택된 span 과
 * 겹치면 드롭. 시작 위치가 아니라 우선순위로 정렬하는 것이 핵심. 반환은 문서 순서.
 */
import type { DetectionResult } from "./types.js";

export function resolveOverlaps(detections: DetectionResult[]): DetectionResult[] {
  const items = [...detections].sort(
    (a, b) =>
      b.riskLevel - a.riskLevel ||
      b.confidence - a.confidence ||
      b.end - b.start - (a.end - a.start) ||
      a.start - b.start,
  );
  const accepted: DetectionResult[] = [];
  for (const d of items) {
    if (accepted.some((a) => d.start < a.end && a.start < d.end)) continue;
    accepted.push(d);
  }
  accepted.sort((a, b) => a.start - b.start || a.end - b.end);
  return accepted;
}
