/** 공통 치환 유틸리티 — DetectionResult 리스트로 문자열을 안전하게 치환. */
import { resolveOverlaps } from "../core/overlap.js";
import type { DetectionResult } from "../core/types.js";

/** span 을 대체 문자열로 바꾸는 콜백 — Python 의 ``replacer`` 대응. */
export type Replacer = (d: DetectionResult) => string;

/**
 * Apply ``replacer`` to each (deduped, sorted) detection span in *text*.
 *
 * 겹침 해소는 core/overlap 단일 구현을 dedup 으로 재사용한다 (detect_all 과
 * 동일 우선순위 — Python 이 resolve_overlaps 를 재사용하는 구조 그대로).
 */
export function applySubstitutions(
  text: string,
  detections: Iterable<DetectionResult>,
  replacer: Replacer,
): string {
  const ordered = resolveOverlaps([...detections]);
  if (ordered.length === 0) return text;
  const pieces: string[] = [];
  let cursor = 0;
  for (const d of ordered) {
    if (d.start > cursor) pieces.push(text.slice(cursor, d.start));
    pieces.push(replacer(d));
    cursor = d.end;
  }
  pieces.push(text.slice(cursor));
  return pieces.join("");
}
