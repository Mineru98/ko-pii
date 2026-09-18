import { describe, expect, it } from "vitest";
import { needsNormalization, normalizeUnicode } from "../../src/core/unicodeNorm.js";
import { loadUnicodeEdges } from "./harness.js";

/**
 * unicodeNorm ↔ Python unicode_edge.json 골드 대조.
 *
 * normalized 문자열과 needs_normalization 플래그는 Python 과 **문자열 등가**여야
 * 한다. offset_map 은 TS 가 UTF-16 유닛 기준이라 Python(코드 포인트)과 아스트랄
 * 문자에서 길이가 달라질 수 있어 직접 비교하지 않고 불변식만 확인한다 — remap
 * 의미론은 detection 골드(emoji_adjacent 픽스처)의 end-to-end 대조가 보증한다.
 */
describe("unicodeNorm gold regression", () => {
  const { entries } = loadUnicodeEdges();

  it.each(entries.map((e) => [e.input, e] as const))(
    "matches Python normalization: %j",
    (input, gold) => {
      expect(needsNormalization(input)).toBe(gold.needs_normalization);
      const [normalized, omap] = normalizeUnicode(input);
      expect(normalized).toBe(gold.normalized);
      // 불변식: 변경 없으면 빈 맵, 변경 시 정규화 본문(UTF-16) 길이와 1:1.
      if (gold.offset_map !== null && gold.offset_map.length > 0) {
        expect([0, normalized.length]).toContain(omap.length);
        for (let k = 1; k < omap.length; k++) {
          expect(omap[k]).toBeGreaterThanOrEqual(omap[k - 1]);
        }
      }
    },
  );

  it("ASCII plain text takes the fast path (no-op)", () => {
    const [normalized, omap] = normalizeUnicode("신청인 홍길동 (880101-1234568)");
    expect(normalized).toBe("신청인 홍길동 (880101-1234568)");
    expect(omap).toEqual([]);
  });

  it("fullwidth digits fold to ASCII with preserved offsets", () => {
    const [normalized, omap] = normalizeUnicode("８８０１０１");
    expect(normalized).toBe("880101");
    expect(omap).toEqual([0, 1, 2, 3, 4, 5]);
  });
});
