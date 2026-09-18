import { describe, expect, it } from "vitest";
import { detectAll } from "../../src/detect.js";
import { codepointOffsetToUtf16, type GoldDetection, loadDetections } from "./harness.js";

/** 골드 검출을 TS 출력과 비교 가능한 형태로 투영 (오프셋은 코드 포인트→UTF-16 변환). */
function project(
  d: GoldDetection,
  text: string,
): [string, string, number, number, number, number, string[], string | null, unknown] {
  return [
    d.label,
    d.text,
    codepointOffsetToUtf16(text, d.start),
    codepointOffsetToUtf16(text, d.end),
    d.risk_level,
    d.confidence,
    d.evidence,
    d.legal_basis,
    d.extra,
  ];
}

function projectTs(d: ReturnType<typeof detectAll>[number]) {
  return [
    d.label,
    d.text,
    d.start,
    d.end,
    d.riskLevel,
    d.confidence,
    d.evidence,
    d.legal_basis,
    d.extra,
  ];
}

describe("detectAll gold master regression", () => {
  const { entries } = loadDetections();

  // biome-ignore lint/correctness/noUnusedFunctionParameters: it.each 케이스명은 보고용으로만 필요
  it.each(entries.map((e) => [e.id, e] as const))("parity with Python: %s", (id, gold) => {
    const ts = detectAll(gold.text);
    const expected = gold.detections.map((d) => project(d, gold.text));
    // 전체 튜플(label,text,start,end,risk,confidence,evidence,legal_basis,extra) 비교.
    // 순서까지 Python resolve_overlaps 출력과 동일해야 한다.
    const actual = ts.map(projectTs);
    expect(actual).toEqual(expected);
  });

  it("every gold detection text satisfies source.slice(start,end) invariant", () => {
    for (const entry of entries) {
      for (const d of entry.detections) {
        const s = codepointOffsetToUtf16(entry.text, d.start);
        const e = codepointOffsetToUtf16(entry.text, d.end);
        expect(entry.text.slice(s, e)).toBe(d.text);
      }
    }
  });
});
