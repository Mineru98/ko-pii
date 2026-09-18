#!/usr/bin/env node
/** ko-pii CLI bin 엔트리 — package.json "bin" 이 가리킨다. */
import { main } from "./main.js";

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    // main 내부에서 처리 못한 예외 — Python 트레이스백 관례에 맞춰 stderr 로 전파
    console.error(err);
    process.exitCode = 1;
  },
);
