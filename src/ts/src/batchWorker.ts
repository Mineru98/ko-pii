/**
 * 배치 워커 스레드 — Python `multiprocessing.Pool` 워커의 worker_threads 대응.
 *
 * path 기반 로드: `new Worker(<batchWorker.ts 경로>, { execArgv })`.
 * ts/src/batch.ts 의 풀(workspace 내 .ts 소스)에서 스폰되며, .ts 그래프 로딩을
 * 위해 tsx 로더가 execArgv 로 지정된다 (batch.ts workerExecArgv 참조).
 *
 * 프로토콜 (단일 작업 — Python Pool 워커처럼 한 번에 하나씩 처리):
 *   부모 → 워커: { kind: "task", task: WorkerTask } | { kind: "end" }
 *   워커 → 부모: { kind: "result", result: FileResult, vaultDict: VaultDict | null }
 */
import { parentPort } from "node:worker_threads";
import type { WorkerTask } from "./batch.js";
import { processSingle } from "./batch.js";

type Inbound = { kind: "task"; task: WorkerTask } | { kind: "end" };

const port = parentPort;
if (!port) {
  throw new Error("batchWorker must run inside a worker thread");
}

port.on("message", (msg: Inbound) => {
  if (msg.kind === "end") {
    port.close();
    return;
  }
  void processSingle(msg.task, null).then(({ result, vaultDict }) => {
    port.postMessage({ kind: "result", result, vaultDict });
  });
});
