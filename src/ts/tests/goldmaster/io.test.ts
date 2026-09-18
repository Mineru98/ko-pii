/**
 * io 골드 대조 — spec/goldmaster/io.json vs ts/src/io 파서.
 *
 * docx/hwpx/xlsx: TS readText(원본) === gold raw_text 이고,
 *   normalizeForDetection(raw) === gold read_text (dispatcher 최종 출력) 여야 한다.
 * pdf: Python gold raw_text 는 pdf.read_text() 기본(normalize=True) 출력이므로
 *   TS readText(path) 결과와 직접 비교한다(정규화 1회 적용 상태).
 * plain/csv/tsv/hwp 는 TS 파서가 아직 없어 normalizer 검증에만 사용한다.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readText as readDocx } from "../../src/io/docx.js";
import { readText as readHwpx } from "../../src/io/hwpx.js";
import { readText as readPdfText, readTextWithMap } from "../../src/io/pdf.js";
import { normalizeForDetection } from "../../src/io/textNormalizer.js";
import { readRecords, readText as readXlsx } from "../../src/io/xlsx.js";
import { GOLDMASTER_DIR } from "./harness.js";

const FIXTURE_DIR = join(GOLDMASTER_DIR, "..", "fixtures", "io");

interface IoGoldFixture {
  file: string;
  format: string;
  raw_text: string;
  read_text: string;
  read_records?: Array<Record<string, string>>;
}

const fixtures = (
  JSON.parse(readFileSync(join(GOLDMASTER_DIR, "io.json"), "utf-8")) as {
    fixtures: IoGoldFixture[];
  }
).fixtures;

describe("io gold regression", () => {
  for (const fx of fixtures) {
    it(`matches Python output: ${fx.file}`, async () => {
      const path = join(FIXTURE_DIR, fx.file);
      let raw: string;
      if (fx.format === "docx") {
        raw = await readDocx(path);
      } else if (fx.format === "hwpx") {
        raw = await readHwpx(path);
      } else if (fx.format === "xlsx") {
        raw = await readXlsx(path);
      } else if (fx.format === "pdf") {
        // gold raw_text 는 pdf.read_text() 기본(normalize=True) 출력 — 정규화 1회 적용 상태
        const normalizedOnce = await readPdfText(path);
        expect(normalizedOnce).toBe(fx.raw_text);
        expect(normalizeForDetection(normalizedOnce)[0]).toBe(fx.read_text);
        return;
      } else {
        // TS 미포팅 포맷 — normalizer 검증만 수행
        expect(normalizeForDetection(fx.raw_text)[0]).toBe(fx.read_text);
        return;
      }
      expect(raw).toBe(fx.raw_text);
      expect(normalizeForDetection(raw)[0]).toBe(fx.read_text);
      if (fx.format === "xlsx" && fx.read_records) {
        expect(await readRecords(path)).toEqual(fx.read_records);
      }
    });
  }

  it("pdf offset map 은 normalized 위치를 raw 로 역매핑한다", async () => {
    const pdf = fixtures.find((f) => f.format === "pdf");
    expect(pdf).toBeDefined();
    const [raw, normalized, offsetMap] = await readTextWithMap(
      join(FIXTURE_DIR, pdf?.file ?? "sample.pdf"),
    );
    expect(offsetMap.length).toBe(normalized.length);
    for (let i = 0; i < normalized.length; i++) {
      const orig = raw[offsetMap[i]];
      // 개행→공백 치환분만 허용
      expect(normalized[i] === orig || (normalized[i] === " " && orig === "\n")).toBe(true);
    }
  });
});
