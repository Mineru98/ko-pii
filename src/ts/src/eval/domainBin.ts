#!/usr/bin/env node
/** ko-pii-evaluate bin 엔트리 (Python ``ko_pii.eval.domain:main``) — package.json "bin" 등록 대상. */
import { main } from "./domain.js";

process.exitCode = main(process.argv.slice(2));
