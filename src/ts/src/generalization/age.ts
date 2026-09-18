/** 연령 일반화 — 1세 단위 → 10세 (또는 임의 폭) 구간. */

import { ValueError } from "../core/errors.js";

/**
 * Return e.g. ``"30대"`` for age=34, bucket_size=10.
 *
 * For ages below ``bucket_size`` returns ``"미성년"`` style label is OUT OF
 * scope here — we keep this purely numeric. 95+ is bucketed into ``"90대"``.
 */
export function generalizeAge(age: number, bucketSize = 10): string {
  if (age < 0) throw new ValueError("age must be non-negative");
  if (bucketSize <= 0) throw new ValueError("bucket_size must be positive");
  const bucketStart = Math.floor(age / bucketSize) * bucketSize;
  return `${bucketStart}대`;
}
