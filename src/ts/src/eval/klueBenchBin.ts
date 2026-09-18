#!/usr/bin/env node
/** ko-pii-klue-bench bin 엔트리 — package.json "bin" 이 가리킨다. */
import { main } from "./klueBenchmark.js";

process.exitCode = main(process.argv.slice(2));
