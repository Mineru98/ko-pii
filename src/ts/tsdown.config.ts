import { defineConfig } from "tsdown";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/io/index.ts",
    "src/batchWorker.ts",
    "src/mcp/server.ts",
    "src/cli/bin.ts",
    "src/mcp/bin.ts",
    "src/eval/index.ts",
    "src/eval/benchmarkBin.ts",
    "src/eval/klueBenchBin.ts",
    // Python 에서 `ko_pii.<모듈>` 로 닿는 모듈의 서브패스 (package.json exports 와 짝)
    "src/batch.ts",
    "src/tabular.ts",
    "src/reporting/index.ts",
    "src/review/index.ts",
    "src/legal/index.ts",
    "src/generalization/index.ts",
  ],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  target: "es2022",
  outDir: "dist",
  clean: true,
});
