/**
 * io 골드 대조 — spec/goldmaster/io.json vs ts/src/io 파서.
 *
 * raw_text  — 포맷별 추출기 readText 원본 출력 (pdf 는 pdf.readText 기본 normalize=true 출력)
 * read_text — dispatcher.readText (normalizeForDetection 적용) 최종 출력
 * read_records / read_records_error — dispatcher.readRecords 결과, 또는 Python 이
 *   ValueError 로 거부한 경우의 메시지 (TS 도 같은 메시지로 throw 해야 한다)
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readText as readCsv } from "../../src/io/csvReader.js";
import { readText as dispatchReadText, readRecords } from "../../src/io/dispatcher.js";
import { readText as readDocx } from "../../src/io/docx.js";
import { readText as readHwp } from "../../src/io/hwp.js";
import { readText as readHwpx } from "../../src/io/hwpx.js";
import { readText as readPdfText, readTextWithMap } from "../../src/io/pdf.js";
import { readText as readPlain } from "../../src/io/plain.js";
import { normalizeForDetection } from "../../src/io/textNormalizer.js";
import { readText as readXlsx } from "../../src/io/xlsx.js";
import { GOLDMASTER_DIR } from "./harness.js";

const FIXTURE_DIR = join(GOLDMASTER_DIR, "..", "fixtures", "io");

interface IoGoldFixture {
  file: string;
  format: string;
  raw_text: string;
  read_text: string;
  read_records?: Array<Record<string, string>>;
  read_records_error?: string;
}

const fixtures = (
  JSON.parse(readFileSync(join(GOLDMASTER_DIR, "io.json"), "utf-8")) as {
    fixtures: IoGoldFixture[];
  }
).fixtures;

const RAW_READERS: Record<string, (path: string) => Promise<string> | string> = {
  plain: readPlain,
  csv: readCsv,
  tsv: readCsv,
  docx: readDocx,
  hwpx: readHwpx,
  xlsx: readXlsx,
  pdf: readPdfText,
  hwp: readHwp,
};

describe("io gold regression", () => {
  for (const fx of fixtures) {
    it(`matches Python output: ${fx.file}`, async () => {
      const path = join(FIXTURE_DIR, fx.file);
      const reader = RAW_READERS[fx.format];
      if (reader === undefined) throw new Error(`no TS reader for format ${fx.format}`);
      const raw = await reader(path);
      expect(raw).toBe(fx.raw_text);
      expect(normalizeForDetection(raw)[0]).toBe(fx.read_text);
      expect(await dispatchReadText(path)).toBe(fx.read_text);
      if (fx.read_records_error !== undefined) {
        await expect(readRecords(path)).rejects.toThrow(fx.read_records_error);
        await expect(readRecords(path)).rejects.toMatchObject({
          name: "ValueError",
          message: fx.read_records_error,
        });
      } else if (fx.read_records !== undefined) {
        expect(await readRecords(path)).toEqual(fx.read_records);
      }
    });
  }

  it("표 형식 골드는 read_records 또는 read_records_error 중 하나를 갖는다", () => {
    for (const fx of fixtures.filter((f) => ["csv", "tsv", "xlsx"].includes(f.format))) {
      expect((fx.read_records === undefined) !== (fx.read_records_error === undefined)).toBe(true);
    }
  });

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
