/**
 * 격리 추출 워커 진입점 — Python ko_pii/io_/_worker.py 대응. 오류에 문서 내용을 담지 않는다.
 *
 * Python 은 별도 프로세스(`python -m ko_pii.io_._worker`)가 stdin 으로 정책 JSON 을 받고
 * stdout 으로 결과 JSON 을 낸다. TS 포트는 worker_threads 워커가 workerData 로 정책을 받고
 * postMessage 로 결과를 돌려준다 (isolated.ts 가 스폰·타임아웃·종료를 맡는다).
 *
 * 이 모듈은 isolated.ts 가 import 하므로 번들에서 같은 청크에 들어간다. 워커는
 * {@link WORKER_URL}(= 이 코드가 담긴 파일) 을 실행하고, 아래 가드가 표식이 있는
 * workerData 에서만 추출을 돌린다 — 다른 워커(배치 워커 등)가 모듈을 로드해도 아무 일도 없다.
 */
import { isMainThread, parentPort, workerData } from "node:worker_threads";
import type { BoundedDocument, FileReadPolicyInit } from "./bounded.js";
import { BoundedReadError, FileReadPolicy, readTextBounded } from "./bounded.js";
import type { ExtractionCoverage } from "./coverage.js";

export const WORKER_KIND = "ko-pii-isolated-extract";

/** 워커 스크립트 위치 — 소스 실행이면 이 .ts, 번들이면 이 코드가 담긴 청크. */
export const WORKER_URL: string = import.meta.url;

export interface WorkerInput {
  kind: typeof WORKER_KIND;
  path: string;
  policy: FileReadPolicyInit;
}

export type WorkerReply =
  | { ok: true; document: BoundedDocument }
  | { ok: false; code: string; message: string; coverage?: ExtractionCoverage | null };

/** Python `_worker.main` 본체 — 예외는 코드로만 보고한다 (내용·파서 메시지 없음). */
export async function runWorker(input: WorkerInput): Promise<WorkerReply> {
  try {
    const policy = new FileReadPolicy(input.policy);
    const document = await readTextBounded(input.path, policy);
    return { ok: true, document };
  } catch (error) {
    if (error instanceof BoundedReadError) {
      return { ok: false, code: error.code, message: error.message, coverage: error.coverage };
    }
    return {
      ok: false,
      code: "extract_worker_failed",
      message: "document extraction worker failed",
    };
  }
}

function isWorkerInput(value: unknown): value is WorkerInput {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { kind?: unknown }).kind === WORKER_KIND
  );
}

if (!isMainThread && parentPort !== null && isWorkerInput(workerData)) {
  const port = parentPort;
  void runWorker(workerData).then((reply) => {
    port.postMessage(reply);
  });
}
