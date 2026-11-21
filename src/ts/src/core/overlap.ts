/**
 * 겹침 해소 — 단일 정본 구현 (Python ko_pii.core.overlap 대응).
 *
 * detectAll / mergeDetections / 치환 경로의 겹침 선택 구현을 한 곳에 둔다. Anonymizer 병합은
 * 현재 정책의 BLOCK 후보를 우선하고 나머지 순서는 공유한다.
 *
 * 정책: (정책 BLOCK →) 위험도 → 확신도 → 길이 → 시작 위치 순으로 채택, 이미 채택된 span 과
 * 겹치면 드롭. 반환은 문서 순서.
 */

import { Action, type ModePolicy } from "./modes.js";
import { pySpanLength } from "./strUtils.js";
import type { OverlapTrace } from "./trace.js";
import type { DetectionResult } from "./types.js";

export interface OverlapOptions {
  trace?: OverlapTrace | null;
  stage?: string;
  policy?: ModePolicy | null;
}

/** Python ``bisect_left`` (정렬 배열). */
function bisectLeft(arr: readonly number[], x: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((arr[mid] as number) < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** 입력 순서대로 겹치지 않는 첫 후보를 O(n log n) 에 채택 (Python ``_select_non_overlapping``).
 *
 * 채택 구간 a 가 후보 d 와 겹치는 조건은 a.start < d.end 이고 a.end > d.start (엄격 부등호,
 * 빈 구간 포함). Fenwick 트리가 압축된 시작 좌표별 end 의 prefix 최대값을 보관한다.
 */
export function selectNonOverlapping(
  items: readonly DetectionResult[],
  options: OverlapOptions = {},
): DetectionResult[] {
  const trace = options.trace ?? null;
  const stage = options.stage ?? "primary";
  const policy = options.policy ?? null;
  const starts = [...new Set(items.map((d) => d.start))].sort((a, b) => a - b);
  const positions = new Map<number, number>();
  starts.forEach((start, i) => {
    positions.set(start, i + 1);
  });
  const ends: Array<DetectionResult | null> = new Array(starts.length + 1).fill(null);
  const accepted: DetectionResult[] = [];
  for (const d of items) {
    let i = bisectLeft(starts, d.end);
    let blocker: DetectionResult | null = null;
    while (i) {
      const end = ends[i] ?? null;
      if (end !== null && end.end > d.start) {
        blocker = end;
        break;
      }
      i -= i & -i;
    }
    if (trace !== null) trace.record(d, blocker, stage, policy);
    if (blocker !== null) continue;
    accepted.push(d);
    i = positions.get(d.start) as number;
    while (i < ends.length) {
      const end = ends[i] ?? null;
      if (end === null || d.end > end.end) ends[i] = d;
      i += i & -i;
    }
  }
  return accepted;
}

export function resolveOverlaps(
  detections: Iterable<DetectionResult>,
  options: OverlapOptions = {},
): DetectionResult[] {
  const policy = options.policy ?? null;
  // 변환 경계에서는 비차단 추정이 호출자 정책상 실제로 가려질 후보를 밀어내면 안 된다.
  const blocks = (d: DetectionResult): number =>
    policy !== null && policy.decide(d.riskLevel, d.confidence) === Action.BLOCK ? 1 : 0;
  // Array.prototype.sort 는 안정 정렬 — Python sorted 와 동률 순서 동일.
  const items = [...detections].sort(
    (a, b) =>
      blocks(b) - blocks(a) ||
      b.riskLevel - a.riskLevel ||
      b.confidence - a.confidence ||
      pySpanLength(b) - pySpanLength(a) ||
      a.start - b.start,
  );
  const accepted = selectNonOverlapping(items, { ...options, stage: options.stage ?? "primary" });
  accepted.sort((a, b) => a.start - b.start || a.end - b.end);
  return accepted;
}
