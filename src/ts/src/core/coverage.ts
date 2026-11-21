/**
 * 선택 후 완전 치환 후보의 미피복 부분 보호 — Python ko_pii.core._coverage 대응.
 */

import { Action, type ModePolicy } from "./modes.js";
import { pySpanLength } from "./strUtils.js";
import type { DetectionResult } from "./types.js";

const COMPLETE_REPLACEMENTS: ReadonlySet<string> = new Set([
  "redact",
  "tokenize",
  "asterisk",
  "hashed",
]);

/** heap 항목: [-risk, -confidence, -length, start, index] — Python 튜플 사전식 비교. */
type HeapItem = [number, number, number, number, number];

function lessThan(a: HeapItem, b: HeapItem): boolean {
  for (let k = 0; k < a.length; k++) {
    const x = a[k] as number;
    const y = b[k] as number;
    if (x !== y) return x < y;
  }
  return false;
}

function heapPush(heap: HeapItem[], item: HeapItem): void {
  heap.push(item);
  let i = heap.length - 1;
  while (i > 0) {
    const parent = (i - 1) >> 1;
    if (!lessThan(heap[i] as HeapItem, heap[parent] as HeapItem)) break;
    [heap[i], heap[parent]] = [heap[parent] as HeapItem, heap[i] as HeapItem];
    i = parent;
  }
}

function heapPop(heap: HeapItem[]): void {
  const last = heap.pop();
  if (last === undefined || heap.length === 0) return;
  heap[0] = last;
  let i = 0;
  for (;;) {
    const l = 2 * i + 1;
    const r = l + 1;
    let m = i;
    if (l < heap.length && lessThan(heap[l] as HeapItem, heap[m] as HeapItem)) m = l;
    if (r < heap.length && lessThan(heap[r] as HeapItem, heap[m] as HeapItem)) m = r;
    if (m === i) break;
    [heap[i], heap[m]] = [heap[m] as HeapItem, heap[i] as HeapItem];
    i = m;
  }
}

/** 미할당 BLOCK 피복을 O(n log n) 에 분할 — 채택된 승자를 대체하지 않는다.
 *
 * 조각은 파생 보호 구간이지 독립 검출이 아니다. 채택된 BLOCK span 은 자기 전략(partial 포함)을
 * 유지한다. 후보/선택 동일성은 객체 동일성(Python ``id()``)으로 판정한다.
 */
export function protectionRemainders(
  text: string,
  candidates: readonly DetectionResult[],
  selected: readonly DetectionResult[],
  policy: ModePolicy,
  strategyFor: (label: string) => string,
): DetectionResult[] {
  const selectedIds = new Set<DetectionResult>(selected);
  const parents = candidates.filter(
    (item) =>
      !selectedIds.has(item) &&
      policy.decide(item.riskLevel, item.confidence) === Action.BLOCK &&
      COMPLETE_REPLACEMENTS.has(strategyFor(item.label)),
  );
  if (parents.length === 0) return [];
  let covered = selected.filter(
    (item) => policy.decide(item.riskLevel, item.confidence) === Action.BLOCK,
  );
  const lower = Math.min(...parents.map((item) => item.start));
  const upper = Math.max(...parents.map((item) => item.end));
  covered = covered
    .filter((item) => item.start < upper && item.end > lower)
    .sort((a, b) => a.start - b.start || a.end - b.end);
  const pointSet = new Set<number>();
  for (const item of [...parents, ...covered]) {
    pointSet.add(item.start);
    pointSet.add(item.end);
  }
  const points = [...pointSet].sort((a, b) => a - b);
  const starts = parents
    .map((_, i) => i)
    .sort(
      (a, b) =>
        (parents[a] as DetectionResult).start - (parents[b] as DetectionResult).start || a - b,
    );
  const active: HeapItem[] = [];
  const pieces: Array<[number, number, number]> = [];
  let incoming = 0;
  let occupied = 0;
  for (let p = 0; p + 1 < points.length; p++) {
    const begin = points[p] as number;
    const end = points[p + 1] as number;
    while (incoming < starts.length) {
      const index = starts[incoming] as number;
      const parent = parents[index] as DetectionResult;
      if (parent.start > begin) break;
      heapPush(active, [
        -parent.riskLevel,
        -parent.confidence,
        -pySpanLength(parent),
        parent.start,
        index,
      ]);
      incoming += 1;
    }
    while (
      active.length > 0 &&
      (parents[(active[0] as HeapItem)[4]] as DetectionResult).end <= begin
    ) {
      heapPop(active);
    }
    while (occupied < covered.length && (covered[occupied] as DetectionResult).end <= begin) {
      occupied += 1;
    }
    if (
      active.length === 0 ||
      (occupied < covered.length && (covered[occupied] as DetectionResult).start <= begin)
    ) {
      continue;
    }
    const owner = (active[0] as HeapItem)[4];
    const last = pieces[pieces.length - 1];
    if (last !== undefined && last[1] === begin && last[2] === owner) {
      last[1] = end;
    } else {
      pieces.push([begin, end, owner]);
    }
  }
  return pieces.map(([begin, end, owner]) => {
    const parent = parents[owner] as DetectionResult;
    return {
      ...parent,
      start: begin,
      end,
      text: text.slice(begin, end),
      evidence: [...parent.evidence, "protection:overlap_remainder"],
      subruleId: "protection.overlap-remainder.v1",
      extra: {
        ...parent.extra,
        overlap_parent: {
          label: parent.label,
          source_span: [parent.start, parent.end],
        },
      },
    };
  });
}
