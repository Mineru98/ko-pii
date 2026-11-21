/**
 * 순서 있는 검출 패스용 겹침 조회 (중첩 span 포함) — Python ko_pii.core._interval_index 대응.
 */
import { ValueError } from "./errors.js";

/** 임의 구간을 스냅샷한 뒤, 전진 전용 조회/추가만 받는다.
 *
 * 다음 패스는 새 스냅샷을 만든다. 한 패스 안에서 추가된 구간은 이후 조회보다 늦게 시작하지
 * 않으므로 추가분은 최대 end 하나로 충분하다.
 */
export class ForwardIntervalIndex {
  private readonly starts: number[] = [];
  private readonly ends: number[] = [];
  private addedEnd: number | null = null;
  private lastStart: number | null = null;

  constructor(spans: Iterable<readonly [number, number]>) {
    const sorted = [...spans].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    for (const [start, end] of sorted) {
      this.starts.push(start);
      const prev = this.ends[this.ends.length - 1];
      this.ends.push(prev !== undefined ? Math.max(prev, end) : end);
    }
  }

  private forward(start: number): void {
    if (this.lastStart !== null && start < this.lastStart) {
      throw new ValueError("interval pass must move forward");
    }
    this.lastStart = start;
  }

  overlaps(start: number, end: number, margin = 0): boolean {
    this.forward(start);
    // bisect_left(starts, end + margin) - 1
    const x = end + margin;
    let lo = 0;
    let hi = this.starts.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((this.starts[mid] as number) < x) lo = mid + 1;
      else hi = mid;
    }
    const position = lo - 1;
    return (
      (position >= 0 && (this.ends[position] as number) > start - margin) ||
      (this.addedEnd !== null && this.addedEnd > start - margin)
    );
  }

  add(start: number, end: number): void {
    this.forward(start);
    this.addedEnd = this.addedEnd !== null ? Math.max(this.addedEnd, end) : end;
  }
}
