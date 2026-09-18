#!/usr/bin/env node
/** ko-pii-mcp-server bin 엔트리 — package.json "bin" 이 가리킨다. */
import { main } from "./server.js";

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
