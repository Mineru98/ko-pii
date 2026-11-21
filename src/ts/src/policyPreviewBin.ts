#!/usr/bin/env node
/** ko-pii-compare-policies bin 엔트리 — package.json "bin" 이 가리킨다 (Python policy_preview:main). */
import { main } from "./policyPreview.js";

process.exitCode = main(process.argv.slice(2));
