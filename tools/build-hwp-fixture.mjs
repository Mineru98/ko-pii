/**
 * HWP 5.x OLE 컨테이너 조립 — gen-io-gold.py 가 만든 스트림 바이트를
 * CFB 복합문서로 포장해 spec/fixtures/io/sample.hwp 를 만든다.
 *
 * 스트림 배치(원본 hwp.py 기대 구조):
 *   /FileHeader          — 256바이트, byte36 bit0 = 압축 플래그
 *   /BodyText/Section0   — 압축된 레코드 스트림
 */
import { writeFile } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const CFB = require(join(root, "src", "ts", "node_modules", "cfb"));
const { readFileSync } = await import("node:fs");

const fix = join(root, "spec", "fixtures", "io");
const file = CFB.utils.cfb_new();
CFB.utils.cfb_add(file, "/FileHeader", readFileSync(join(fix, "_hwp_FileHeader.bin")));
CFB.utils.cfb_add(
  file,
  "/BodyText/Section0",
  readFileSync(join(fix, "_hwp_BodyText_Section0.bin")),
);
CFB.writeFile(file, join(fix, "sample.hwp"));
console.log("sample.hwp assembled");
