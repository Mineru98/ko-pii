/**
 * Vault 감사 로그 — 모든 `reveal()` / `store()` 호출 추적.
 * Python `ko_pii.vault.audit` 1:1 포트.
 *
 * 개인정보보호법 제29조 (안전조치의무) 의 *처리 이력 기록* 요건 직접 대응.
 *
 * 저장 포맷: JSON Lines (`.jsonl`) — append-only, 검색·집계 친화적.
 * 각 라인:
 *   {"ts": "ISO-8601", "action": "reveal", "token": "<RRN_1>", "label": "RRN",
 *    "actor": "user@host", "context": "..."}
 *
 * 특징:
 * - Node 단일 스레드 + 동기 append 로 Python threading.Lock 대응
 * - 라인 부분 손상 무시 (마지막 줄만 잘릴 수 있음)
 * - 디렉터리 자동 생성은 하지 않는다 (Python `open(path, "a")` 도 생성하지 않음)
 *
 * 결정론 테스트: 생성자 `options.now` 로 타임스탬프를 주입할 수 있다.
 */
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { hostname, userInfo } from "node:os";
import { pyIsoUtcNow, pyJsonDumps } from "./reversible.js";

/** 한 줄 감사 기록 (replay 반환 형태). */
export type AuditEntry = Record<string, unknown>;

export interface AuditRecordOptions {
  token?: string | null;
  label?: string | null;
  actor?: string | null;
  context?: string | null;
  extra?: Record<string, unknown> | null;
}

export interface AuditLogOptions {
  /** 타임스탬프 공급자 주입 (기본: 현재 UTC, Python isoformat 형식). 결정론 테스트용. */
  now?: () => string;
}

/** Append-only JSONL 감사 로그.
 *
 * Usage::
 *
 *     const log = new AuditLog("vault_audit.jsonl");
 *     log.recordReveal("<RRN_1>", "RRN", { actor: "alice" });
 *     log.close();
 */
export class AuditLog {
  readonly path: string;
  readonly defaultActor: string;
  private readonly nowFn: () => string;

  constructor(path: string, defaultActor?: string | null, options: AuditLogOptions = {}) {
    this.path = path;
    this.defaultActor = defaultActor ?? detectActor();
    this.nowFn = options.now ?? pyIsoUtcNow;
  }

  /** Python 컨텍스트 매니저 종료 대응 — append 방식이라 정리할 핸들이 없다 (no-op). */
  close(): void {}

  // ---------------------------------------------------------------- public

  record(action: string, opts: AuditRecordOptions = {}): void {
    const entry: Record<string, unknown> = {
      ts: this.nowFn(),
      action,
      token: opts.token ?? null,
      label: opts.label ?? null,
      actor: opts.actor ?? this.defaultActor,
      context: opts.context ?? null,
    };
    // Python `if extra:` — 빈 dict/null 은 기록하지 않는다.
    if (opts.extra != null && Object.keys(opts.extra).length > 0) {
      entry.extra = opts.extra;
    }
    this.writeLine(pyJsonDumps(entry, null));
  }

  recordStore(token: string, label: string, opts: AuditRecordOptions = {}): void {
    this.record("store", { token, label, ...opts });
  }

  recordReveal(token: string, label?: string | null, opts: AuditRecordOptions = {}): void {
    this.record("reveal", { token, label: label ?? null, ...opts });
  }

  recordAnonymize(count: number, mode: string, opts: AuditRecordOptions = {}): void {
    this.record("anonymize", { ...opts, extra: { count, mode } });
  }

  /** Python: line-buffered open("a") + flush. Node 에선 append 마다 open/write/close. */
  private writeLine(line: string): void {
    appendFileSync(this.path, `${line}\n`, "utf8");
  }
}

/** JSONL 로그를 dict 리스트로 로드 (분석·감사용). 부분 손상 라인은 건너뛴다. */
export function replay(path: string): AuditEntry[] {
  const out: AuditEntry[] = [];
  if (!existsSync(path)) return out;
  const content = readFileSync(path, "utf8");
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    try {
      out.push(JSON.parse(line) as AuditEntry);
    } catch {
      // 부분 손상 라인 무시
    }
  }
  return out;
}

/** Python `_detect_actor` 대응 — "user@host". */
function detectActor(): string {
  let user = "unknown";
  try {
    user = userInfo({ encoding: "utf8" }).username || "unknown";
  } catch {
    user = process.env.USER ?? process.env.USERNAME ?? "unknown";
  }
  let host = "host";
  try {
    host = hostname() || "host";
  } catch {
    host = "host";
  }
  return `${user}@${host}`;
}
