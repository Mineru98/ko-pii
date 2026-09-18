/** 날짜 일반화 — 정밀도 단계: year / month / decade. */

import { ValueError } from "../core/errors.js";

/** Python ``datetime.date`` 최소 구조 대응 — 본 모듈은 year/month 만 사용. */
export interface DateLike {
  year: number;
  month: number;
}

/**
 * Generalize a date.
 *
 * ``precision``:
 *   - ``"year"`` → ``"1988년"``
 *   - ``"month"`` → ``"1988-01"``
 *   - ``"decade"`` → ``"1980년대"``
 */
export function generalizeDate(d: DateLike, precision = "year"): string {
  if (precision === "year") return `${d.year}년`;
  if (precision === "month") {
    return `${String(d.year).padStart(4, "0")}-${String(d.month).padStart(2, "0")}`;
  }
  if (precision === "decade") return `${Math.floor(d.year / 10) * 10}년대`;
  throw new ValueError(`Unknown precision: ${precision}`);
}
