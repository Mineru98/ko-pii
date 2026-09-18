#!/usr/bin/env node
/**
 * Python↔TS 검출기 차등 대조 도구.
 *
 * usage: node tools/diff-detector.mjs <모듈> "텍스트1" ["텍스트2" ...]
 *   모듈: rrn | phone | context.context_rules 등 (src/python/ko_pii 밑 경로, .py 제외)
 *
 * Python 검출기(detect)와 TS 검출기(detect)의 결과를
 * (label, start, end, risk_level, confidence) 튜플로 비교해 보고한다.
 */
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [modulePath, ...texts] = process.argv.slice(2);
if (!modulePath || texts.length === 0) {
  console.error("usage: node tools/diff-detector.mjs <module> <text> [...]");
  process.exit(2);
}

const pyScript = `
import json, sys
sys.path.insert(0, ${JSON.stringify(join(root, "src", "python"))})
import importlib
mod = importlib.import_module("ko_pii." + ${JSON.stringify(modulePath)})
out = []
for text in sys.argv[1:]:
    dets = [
        {"label": d.label, "start": d.start, "end": d.end,
         "risk": int(d.risk_level), "conf": round(d.confidence, 6)}
        for d in mod.detect(text)
    ]
    out.append(dets)
print(json.dumps(out))
`;
const pyRaw = execFileSync("python3", ["-c", pyScript, ...texts], {
  encoding: "utf-8",
  maxBuffer: 64 * 1024 * 1024,
});
const pyResults = JSON.parse(pyRaw);

// TS 쪽: 임시 스크립트를 tsx 로 실행 (NodeNext .js 스페시파이어 해석).
const tmp = mkdtempSync(join(tmpdir(), "ko-pii-diff-"));
const tsScript = join(tmp, "diff.ts");
writeFileSync(
  tsScript,
  `
import { detect } from ${JSON.stringify(join(root, "src", "ts", "src", `${modulePath.replaceAll(".", "/")}.ts`))};
const out = [];
for (const text of process.argv.slice(2)) {
  const dets = [...detect(text)].map((d) => ({
    label: d.label, start: d.start, end: d.end,
    risk: d.riskLevel, conf: Math.round(d.confidence * 1e6) / 1e6,
  }));
  out.push(dets);
}
console.log(JSON.stringify(out));
`,
  "utf-8",
);
let tsResults;
try {
  const tsRaw = execFileSync(join(root, "src", "ts", "node_modules", ".bin", "tsx"), [tsScript, ...texts], {
    cwd: join(root, "src", "ts"),
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
  });
  tsResults = JSON.parse(tsRaw);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

let mismatches = 0;
texts.forEach((text, i) => {
  const py = pyResults[i];
  const ts = tsResults[i];
  const same = JSON.stringify(py) === JSON.stringify(ts);
  if (!same) {
    mismatches += 1;
    console.log(`MISMATCH [${i}] ${JSON.stringify(text)}`);
    console.log("  python:", JSON.stringify(py));
    console.log("  ts    :", JSON.stringify(ts));
  } else {
    console.log(`ok  [${i}] ${py.length} detections: ${JSON.stringify(text.slice(0, 40))}`);
  }
});
console.log(mismatches === 0 ? "ALL MATCH" : `${mismatches}/${texts.length} MISMATCH`);
process.exit(mismatches === 0 ? 0 : 1);
