#!/usr/bin/env node
/**
 * ko-pii-mcp-server bin 엔트리 — package.json "bin" 이 가리킨다.
 * Python ``main()`` 처럼 선택 의존성(MCP SDK)이 없으면 설치 안내를 stderr 에 쓰고 1 로 끝난다.
 */
const INSTALL_HINT =
  "MCP 서버는 '@modelcontextprotocol/sdk' 패키지가 필요합니다.\n" +
  "  npm install @modelcontextprotocol/sdk";

function isMissingModule(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND";
}

import("./server.js").then(
  ({ main }) =>
    main().catch((err: unknown) => {
      console.error(err);
      process.exitCode = 1;
    }),
  (err: unknown) => {
    if (isMissingModule(err)) {
      process.stderr.write(`${INSTALL_HINT}\n`);
    } else {
      console.error(err);
    }
    process.exitCode = 1;
  },
);
