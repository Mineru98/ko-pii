#!/usr/bin/env node
/** ko-pii-benchmark bin 엔트리 — package.json "bin" 이 가리킨다. */
import { main } from "./benchmark.js";

process.exitCode = main(process.argv.slice(2));
