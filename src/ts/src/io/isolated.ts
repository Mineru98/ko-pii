/**
 * Run bounded extraction outside the caller with a wall-clock timeout.
 * Python 대응: ko_pii/io_/isolated.py.
 *
 * Python 은 서브프로세스(`python -m ko_pii.io_._worker`)에서 추출하고 시간 초과 시 종료한다.
 * TS 포트는 worker_threads 워커(worker.ts)에서 같은 readTextBounded 를 돌리고, 시간 초과 시
 * `worker.terminate()` 로 끊는다. 실패 코드는 Python 과 같다:
 * extract_timeout / extractor_unavailable / extract_worker_failed, 그리고 워커가 보고한
 * BoundedReadError 코드(coverage 포함).
 *
 * 메모리: Python 워커는 Linux 에서만 주소 공간을 512 MiB 로 묶는다. Node 워커는 모든 플랫폼에서
 * V8 힙(old generation)을 512 MiB 로 묶는다 (Buffer 같은 힙 밖 메모리는 제외). 힙 초과로 워커가
 * 죽으면 extract_worker_failed. OS 보안 샌드박스가 아니라 자원 격리다.
 */
import { createRequire } from "node:module";
import { isAbsolute, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";
import { ValueError } from "../core/errors.js";
import type { BoundedDocument } from "./bounded.js";
import { BoundedReadError, FileReadPolicy } from "./bounded.js";
import { SUPPORTED_EXTENSIONS } from "./dispatcher.js";
import type { WorkerInput, WorkerReply } from "./worker.js";
import { WORKER_KIND, WORKER_URL } from "./worker.js";

const WORKER_HEAP_MB = 512;

/** Legacy PDF/HWP parsers run in the worker, not in the calling process. */
export function defaultReadPolicy(): FileReadPolicy {
  return new FileReadPolicy({ allowedExtensions: SUPPORTED_EXTENSIONS });
}

export interface ReadTextIsolatedOptions {
  policy?: FileReadPolicy | null;
  /** 초 단위 벽시계 한도 (Python `timeout=30.0`). 유한한 양수여야 한다. */
  timeout?: number;
}

let cachedExecArgv: string[] | null = null;

/** 소스(.ts) 실행이면 tsx 로더가 있어야 워커가 .ts 그래프를 읽는다 (batch.ts 와 같은 방식). */
function workerExecArgv(): string[] | undefined {
  if (!/\.[cm]?ts$/.test(new URL(WORKER_URL).pathname)) return undefined;
  if (cachedExecArgv === null) {
    try {
      const require = createRequire(import.meta.url);
      cachedExecArgv = ["--import", pathToFileURL(require.resolve("tsx")).href];
    } catch {
      cachedExecArgv = [];
    }
  }
  return cachedExecArgv.length > 0 ? cachedExecArgv : undefined;
}

/** Python `Path(path).absolute()` — cwd 를 앞에 붙일 뿐 정규화하지 않는다. */
function absolute(path: string): string {
  return isAbsolute(path) ? path : `${process.cwd()}${sep}${path}`;
}

function isBoundedDocument(value: unknown): value is BoundedDocument {
  if (typeof value !== "object" || value === null) return false;
  const doc = value as Record<string, unknown>;
  return (
    typeof doc.text === "string" &&
    typeof doc.sha256 === "string" &&
    typeof doc.sizeBytes === "number" &&
    typeof doc.extension === "string" &&
    typeof doc.archiveMembers === "number" &&
    typeof doc.declaredDecompressedBytes === "number" &&
    (doc.coverage === null || typeof doc.coverage === "object")
  );
}

/**
 * Apply file/archive/text limits and terminate extraction on timeout.
 *
 * This is resource isolation, not an OS security sandbox.
 */
export async function readTextIsolated(
  path: string,
  options: ReadTextIsolatedOptions = {},
): Promise<BoundedDocument> {
  const timeout: unknown = options.timeout ?? 30.0;
  if (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout <= 0) {
    throw new ValueError("extraction timeout must be finite and positive");
  }
  const active = options.policy ?? defaultReadPolicy();
  const input: WorkerInput = { kind: WORKER_KIND, path: absolute(path), policy: active.toInit() };

  let worker: Worker;
  try {
    worker = new Worker(new URL(WORKER_URL), {
      workerData: input,
      execArgv: workerExecArgv(),
      resourceLimits: { maxOldGenerationSizeMb: WORKER_HEAP_MB },
      stdout: true,
      stderr: true,
    });
  } catch {
    throw new BoundedReadError(
      "extractor_unavailable",
      "document extraction worker could not start",
    );
  }

  return new Promise<BoundedDocument>((resolve, reject) => {
    let settled = false;
    let online = false;
    const finish = (outcome: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      outcome();
    };
    const failed = (message = "document extraction worker failed"): void => {
      finish(() => reject(new BoundedReadError("extract_worker_failed", message)));
    };
    const timer = setTimeout(() => {
      finish(() =>
        reject(
          new BoundedReadError("extract_timeout", "document extraction exceeded the time limit"),
        ),
      );
    }, timeout * 1000);

    worker.on("online", () => {
      online = true;
    });
    worker.on("message", (reply: WorkerReply) => {
      if (typeof reply !== "object" || reply === null) {
        failed();
        return;
      }
      if (reply.ok) {
        if (!isBoundedDocument(reply.document)) {
          failed("invalid extraction worker result");
          return;
        }
        const document = reply.document;
        finish(() => resolve(document));
        return;
      }
      if (typeof reply.code === "string") {
        const message = typeof reply.message === "string" ? reply.message : "extraction failed";
        finish(() =>
          reject(new BoundedReadError(reply.code, message, { coverage: reply.coverage ?? null })),
        );
        return;
      }
      failed();
    });
    worker.on("error", () => {
      if (online) {
        failed();
      } else {
        finish(() =>
          reject(
            new BoundedReadError(
              "extractor_unavailable",
              "document extraction worker could not start",
            ),
          ),
        );
      }
    });
    worker.on("exit", () => {
      failed();
    });
  });
}
