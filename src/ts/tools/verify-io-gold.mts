/** io 골드 벡터 대조 — ts/src/io/{docx,hwpx,xlsx,pdf,textNormalizer} vs spec/goldmaster/io.json.
 *
 * 실행: cd ts && npx tsx tools/verify-io-gold.mts
 */
import { readFileSync } from "node:fs";
import { normalizeForDetection } from "../src/io/textNormalizer.js";
import { readText as readDocx } from "../src/io/docx.js";
import { readText as readHwpx } from "../src/io/hwpx.js";
import { readRecords, readText as readXlsx } from "../src/io/xlsx.js";
import { readText as readPdf, readTextWithMap } from "../src/io/pdf.js";

const ROOT = new URL("../..", import.meta.url).pathname.replace(/\/src\/ts\/$/, "/");
const GOLD_PATH = `${ROOT}/spec/goldmaster/io.json`;
const FIX_DIR = `${ROOT}/spec/fixtures/io`;

interface Fixture {
  file: string;
  format: string;
  raw_text: string;
  read_text: string;
  read_records?: Array<Record<string, string>>;
}

const gold = JSON.parse(readFileSync(GOLD_PATH, "utf-8")) as { fixtures: Fixture[] };

let pass = 0;
let fail = 0;
const failures: string[] = [];

function check(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    pass++;
  } else {
    fail++;
    failures.push(
      `[FAIL] ${name}\n  expected: ${e}\n  actual:   ${a}`,
    );
  }
}

for (const fx of gold.fixtures) {
  const path = `${FIX_DIR}/${fx.file}`;
  if (fx.format === "docx") {
    const raw = await readDocx(path);
    check(`${fx.file}: raw_text`, raw, fx.raw_text);
    check(`${fx.file}: read_text(normalize)`, normalizeForDetection(raw)[0], fx.read_text);
  } else if (fx.format === "hwpx") {
    const raw = await readHwpx(path);
    check(`${fx.file}: raw_text`, raw, fx.raw_text);
    check(`${fx.file}: read_text(normalize)`, normalizeForDetection(raw)[0], fx.read_text);
  } else if (fx.format === "xlsx") {
    const raw = await readXlsx(path);
    check(`${fx.file}: raw_text`, raw, fx.raw_text);
    check(`${fx.file}: read_text(normalize)`, normalizeForDetection(raw)[0], fx.read_text);
    const records = await readRecords(path);
    check(`${fx.file}: read_records`, records, fx.read_records);
  } else if (fx.format === "pdf") {
    // Python gold raw_text 는 pdf.read_text() 기본(normalize=True) 출력이다.
    const normalizedOnce = await readPdf(path);
    check(`${fx.file}: raw_text(normalized once)`, normalizedOnce, fx.raw_text);
    check(
      `${fx.file}: read_text(normalize x2, idempotent)`,
      normalizeForDetection(normalizedOnce)[0],
      fx.read_text,
    );
    const [raw, normalized, offsetMap] = await readTextWithMap(path);
    check(
      `${fx.file}: read_text_with_map consistency`,
      [normalized, offsetMap.length],
      [normalizedOnce, normalized.length],
    );
    // offsetMap[i] 는 raw 위치. 개행→공백 치환분만 허용하고 나머지는 원본 문자와 일치해야 한다.
    let mapOk = offsetMap.length === normalized.length;
    if (mapOk) {
      for (let i = 0; i < normalized.length; i++) {
        const orig = raw[offsetMap[i]];
        if (normalized[i] !== orig && !(normalized[i] === " " && orig === "\n")) {
          mapOk = false;
          break;
        }
      }
    }
    check(`${fx.file}: offset map 정합성`, mapOk, true);
  } else {
    // TS 미포팅 포맷(plain/csv/tsv/hwp) — normalizer 자체 검증에만 사용
    check(
      `${fx.file}: read_text(normalize gold raw)`,
      normalizeForDetection(fx.raw_text)[0],
      fx.read_text,
    );
  }
}

for (const f of failures) console.log(f);
console.log(`\nio gold: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
