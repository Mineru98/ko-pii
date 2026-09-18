/** PDF 등에서 추출된 텍스트의 불필요 줄바꿈/공백 정규화 + offset 역매핑.
 *
 * Python ko_pii/io_/text_normalizer.py 대응.
 *
 * PDF 텍스트 추출기는 글자 좌표 기반이라:
 * 1. 단어/숫자 중간에 줄바꿈 삽입 (pypdf 흔함)
 * 2. 서식 칸별 입력 시 글자 사이 공백 삽입 (주민번호: "9 5 1 2 3 0 - 1 8 5 0 4 3 1")
 *
 * 사용:
 *     const [normalized, offsetMap] = normalizeForDetection(rawPdfText);
 *     const detections = detectAll(normalized);
 *     const remapped = remapOffsets(detections, offsetMap);
 */
import type { DetectionResult } from "../core/types.js";

// --- 줄바꿈 정규화 패턴 ---
// Python \d → [0-9] (PORTING.md — 원본은 정규화로 전각을 폴딩하므로 동등)
const MID_PII_NEWLINE =
  /(?<=[0-9-])\n(?=[0-9-])|(?<=[A-Za-z])\n(?=[0-9])|(?<=[0-9])\n(?=[A-Za-z])/g;
const MID_KOREAN_NEWLINE = /(?<=[가-힣])\n(?=[가-힣])/g;
const SOFT_LINEBREAK = /(?<!\n)\n(?!\n)/g;

// --- 칸별 공백 정규화 패턴 ---
// "9 5 1 2 3 0 - 1 8 5 0 4 3 1" → "951230-1850431"
// 공백(space)만 — 줄바꿈(\n) 제외
// 기본: "9 5 1 2 3 0 - 1 8 5 0 4 3 1" (숫자 사이 공백 1개)
const SPACED_FIELD = /(?<![0-9A-Za-z-])([0-9](?: [0-9-]){4,})(?![0-9A-Za-z-]| [0-9-])/g;

// 확장: "49 9 - 8 7- 0 3 8" (하이픈 양쪽에 공백이 불균일)
// 숫자/하이픈이 공백으로 구분되되 하이픈 앞뒤 공백이 있거나 없을 수 있음
const SPACED_FIELD_WITH_HYPHEN =
  /(?<![0-9A-Za-z-])([0-9][0-9 ]{2,}\s*-\s*[0-9 ]{1,}\s*-?\s*[0-9 ]{2,}[0-9])(?![0-9])/g;

/** 칸별 공백 패턴의 공백을 제거하고 offset 맵 반환. */
function collapseSpacedField(text: string): [string, number[]] {
  // 두 패턴의 매치를 합쳐서 위치순 정렬
  const matches: Array<[number, number]> = [];
  for (const m of text.matchAll(SPACED_FIELD)) {
    matches.push([m.index, m.index + m[0].length]);
  }
  for (const m of text.matchAll(SPACED_FIELD_WITH_HYPHEN)) {
    // 기본 패턴(및 앞선 확장 패턴)과 겹치지 않는 경우만 추가
    const s = m.index;
    const e = m.index + m[0].length;
    if (!matches.some(([ms, me]) => (ms <= s && s < me) || (ms < e && e <= me))) {
      matches.push([s, e]);
    }
  }
  matches.sort((a, b) => a[0] - b[0] || a[1] - b[1]);

  const result: string[] = [];
  const offsetMap: number[] = [];
  let lastEnd = 0;
  for (const [ms, me] of matches) {
    for (let i = lastEnd; i < ms; i++) {
      result.push(text[i]!);
      offsetMap.push(i);
    }
    for (let j = ms; j < me; j++) {
      const ch = text[j]!;
      if (ch === " ") continue;
      result.push(ch);
      offsetMap.push(j);
    }
    lastEnd = me;
  }
  for (let i = lastEnd; i < text.length; i++) {
    result.push(text[i]!);
    offsetMap.push(i);
  }
  return [result.join(""), offsetMap];
}

/** PDF 추출 텍스트를 PII 검출용으로 정규화. (Python normalize_for_detection 대응)
 *
 * Returns [normalized, offsetMap].
 * offsetMap[i] = normalized[i]에 대응하는 원본 위치.
 */
export function normalizeForDetection(
  text: string,
  options?: { aggressive?: boolean },
): [string, number[]] {
  const aggressive = options?.aggressive ?? false;

  // Phase 1: 칸별 공백 정규화 (줄바꿈은 유지 — 토큰 경계)
  const [textP1, mapP1] = collapseSpacedField(text);

  // Phase 2: 줄바꿈 정규화
  const removePositions = new Set<number>();
  for (const m of textP1.matchAll(MID_KOREAN_NEWLINE)) {
    removePositions.add(m.index);
  }

  const replacePositions = new Set<number>();
  for (const m of textP1.matchAll(MID_PII_NEWLINE)) {
    const pos = m.index;
    if (!removePositions.has(pos)) {
      replacePositions.add(pos);
    }
  }
  if (aggressive) {
    for (const m of textP1.matchAll(SOFT_LINEBREAK)) {
      const pos = m.index;
      if (!removePositions.has(pos) && !replacePositions.has(pos)) {
        replacePositions.add(pos);
      }
    }
  }

  // Phase 3: 최종 텍스트 + 원본 기준 offset 맵
  const result: string[] = [];
  const offsetMap: number[] = [];
  for (let i = 0; i < textP1.length; i++) {
    if (removePositions.has(i)) continue;
    if (replacePositions.has(i)) {
      result.push(" ");
      offsetMap.push(mapP1[i]!);
      continue;
    }
    result.push(textP1[i]!);
    offsetMap.push(mapP1[i]!);
  }
  return [result.join(""), offsetMap];
}

/** 정규화 텍스트 기준 offset을 원본 텍스트 기준으로 역매핑. */
export function remapOffsets(
  detections: DetectionResult[],
  offsetMap: number[],
): DetectionResult[] {
  const n = offsetMap.length;
  return detections.map((det) => {
    const newStart = det.start < n ? offsetMap[det.start]! : det.start;
    const newEnd = det.end > 0 && det.end - 1 < n ? offsetMap[det.end - 1]! + 1 : det.end;
    return { ...det, start: newStart, end: newEnd };
  });
}
