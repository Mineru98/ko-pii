import { describe, expect, it } from "vitest";
import { detectAll } from "../../src/detect.js";

/**
 * 굴절(조사·어미 결합) 회귀 테스트 — Python detect_all 실측 기준.
 *
 * 배경: personal_attr AGE 패턴에 원본에 없던 `(?![\p{L}\p{N}_])` lookahead 가
 * 들어가 "41세이다" 형태가 미검출됐던 회귀(M4 리포팅 대조 중 발견)를 잠근다.
 * Python 원본은 뒤쪽 가드가 `(?![0-9])` 뿐이다 ("한글 lookahead 제거" 주석).
 */
describe("inflected PII detection regression (Python-verified)", () => {
  const cases: readonly [string, string, number, number][] = [
    ["나이 41세이다", "41세", 3, 6],
    ["나이는 41세다", "41세", 4, 7],
    ["41세입니다", "41세", 0, 3],
    ["그는 30살인데", "30살", 3, 6],
    ["신장 175cm이다", "175cm", 3, 8],
    ["몸무게 70kg입니다", "70kg", 4, 8],
  ];

  it.each(cases.map((c) => [c[0]] as const))("detects inflected form: %s", (text) => {
    const expected = cases.find(([t]) => t === text) as readonly [string, string, number, number];
    const hits = detectAll(text);
    expect(hits.length, `${text} 에서 검출 누락`).toBeGreaterThanOrEqual(1);
    const match = hits.find((d) => d.text === expected[1]);
    expect(match, `${text} 에서 ${expected[1]} span 불일치`).toBeDefined();
    expect(match?.start).toBe(expected[2]);
    expect(match?.end).toBe(expected[3]);
  });

  it("keeps plain forms detected", () => {
    expect(detectAll("나이 41세").some((d) => d.label === "AGE" && d.text === "41세")).toBe(true);
    expect(detectAll("나이 41세,").some((d) => d.label === "AGE" && d.text === "41세")).toBe(true);
  });
});
