import { defineConfig } from "tsdown";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/io/index.ts",
    "src/batchWorker.ts",
    "src/mcp/server.ts",
    "src/cli/bin.ts",
    "src/mcp/bin.ts",
  ],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  target: "es2022",
  outDir: "dist",
  clean: true,
});
