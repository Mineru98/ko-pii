/** 공통 치환 유틸리티 — DetectionResult 리스트로 문자열을 안전하게 치환. */
import { ValueError } from "../core/errors.js";
import { resolveOverlaps } from "../core/overlap.js";
import type { DetectionResult } from "../core/types.js";
import { validatedDetection } from "../core/validation.js";

/** span 을 대체 문자열로 바꾸는 콜백 — Python 의 ``replacer`` 대응. */
export type Replacer = (d: DetectionResult) => string;

/** 실제로 내보낸 치환 하나의 원문/출력 좌표 (Python ``AppliedSpan``). UTF-16 코드 유닛 기준. */
export interface AppliedSpan {
  readonly start: number;
  readonly end: number;
  readonly outputStart: number;
  readonly outputEnd: number;
}

/**
 * Validate public primitive inputs before any transformation or Vault write.
 *
 * 각 원소를 꺼낼 때마다 스냅샷한다 — 생성기가 같은 가변 레코드를 재사용할 수 있다.
 * 안전한 사용자 정의 라벨은 저수준 변환 API 에서 계속 허용한다.
 * 실패 메시지에는 입력 값을 싣지 않는다 (이터레이터 오류가 원문을 담을 수 있으므로 감싼다).
 */
export function prepareDetections(text: unknown, detections: Iterable<unknown>): DetectionResult[] {
  if (typeof text !== "string") throw new ValueError("transformation source must be a string");
  try {
    const out: DetectionResult[] = [];
    for (const item of detections) {
      out.push(validatedDetection(item, text, { allowCustomLabels: true }));
    }
    return out;
  } catch {
    throw new ValueError("transformation requires valid source-bound detection results");
  }
}

/**
 * Apply ``replacer`` to each (deduped, sorted) detection span in *text*.
 *
 * 겹침 해소는 core/overlap 단일 구현을 dedup 으로 재사용한다 (detect_all 과
 * 동일 우선순위 — Python 이 resolve_overlaps 를 재사용하는 구조 그대로).
 * ``trace`` 를 주면 실제로 내보낸 치환마다 원문/출력 좌표를 덧붙인다.
 */
export function applySubstitutions(
  text: string,
  detections: Iterable<DetectionResult>,
  replacer: Replacer,
  options: { trace?: AppliedSpan[] | null } = {},
): string {
  const trace = options.trace ?? null;
  const ordered = resolveOverlaps([...detections]);
  if (ordered.length === 0) return text;
  const pieces: string[] = [];
  let cursor = 0;
  let outputCursor = 0;
  for (const d of ordered) {
    if (d.start > cursor) {
      pieces.push(text.slice(cursor, d.start));
      outputCursor += d.start - cursor;
    }
    const replacement = replacer(d);
    pieces.push(replacement);
    if (trace !== null) {
      trace.push({
        start: d.start,
        end: d.end,
        outputStart: outputCursor,
        outputEnd: outputCursor + replacement.length,
      });
    }
    outputCursor += replacement.length;
    cursor = d.end;
  }
  pieces.push(text.slice(cursor));
  return pieces.join("");
}
