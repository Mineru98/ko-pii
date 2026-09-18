/** Node(tsx) 에서 패리티 대조 — 실패 시 exit 1. Usage: npm run parity */
import { readFileSync } from "node:fs";
import { compare, type Reference } from "./compare.js";

const ref = JSON.parse(
  readFileSync(new URL("./reference.json", import.meta.url), "utf8"),
) as Reference;
const { total, failures } = compare(ref);
for (const f of failures.slice(0, 10)) console.error(f);
console.log(`parity: ${total} checks, ${failures.length} failures`);
process.exit(failures.length === 0 ? 0 : 1);
