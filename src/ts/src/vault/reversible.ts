/**
 * 가역 가명화 Vault — Python `ko_pii.vault.reversible` 1:1 포트.
 *
 * 핵심 아이디어:
 * - 검출된 원본 PII는 외부에 직접 노출되지 않고 Vault 에만 저장된다.
 * - 본문에는 카테고리별 토큰 (예: `<RRN_1>`) 으로 치환된다.
 * - Vault 를 보유한 권한 있는 사용자만 토큰으로부터 원본을 복원할 수 있다.
 *
 * Vault JSON schema v1::
 *
 *     {
 *         "schema_version": 1,
 *         "created_at": "ISO-8601",
 *         "salt": "<hex-string>",          // 토큰 해시에 사용 (식별자 일관성)
 *         "fingerprint_scheme": "pbkdf2-sha256-v2",
 *         "fingerprint_iterations": 100000,
 *         "entries": {
 *             "<RRN_1>": {
 *                 "label": "RRN",
 *                 "original": "880101-1234568",
 *                 "risk_level": 5,
 *                 "legal_basis": "개인정보보호법 제24조의2",
 *                 "first_seen_offset": 12,
 *                 "occurrences": [12, 200]
 *             }
 *         }
 *     }
 *
 * 같은 원본 값은 같은 토큰을 받는다 (문서 내 일관성).
 *
 * Legal basis: 개인정보보호법 제28조의2~5 (가명정보 처리 특례) — 가명처리된 정보가
 * "추가 정보 (즉, 본 Vault) 없이는 특정 개인을 알아볼 수 없도록" 분리 보관되어야 함.
 *
 * 바이트 호환 참고 (Python `json.dumps(ensure_ascii=False)` 대응):
 * - `indent=null` 경로는 Python 기본 구분자 `", "` / `": "` 를 그대로 재현한다
 *   (JS `JSON.stringify` 는 공백이 없어 .kvault 평문이 달라진다).
 * - 키 순서는 Python dataclass/dict 삽입 순서와 동일하게 유지한다.
 */

import { createHash, pbkdf2Sync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { ValueError } from "../core/errors.js";
import { pyFloatRepr } from "../core/pyFormat.js";
import { writeTextAtomic } from "../io/atomic.js";
import { parseJsonOrdered, recordEntries } from "../io/recordOrder.js";
import type { AuditRecordOptions } from "./audit.js";

export const SCHEMA_VERSION = 1;

/** 지문(fingerprint) KDF 반복 횟수 기본값 — 저엔트로피 PII 무차별 대입을 늦춘다. */
const DEFAULT_FP_ITERATIONS = 100_000;
/** 강화 전 vault 지문 scheme (불려온 경우 호환 유지). */
export const FP_SCHEME_LEGACY = "sha256-v1";
/** 신규 vault 지문 scheme 기본. */
export const FP_SCHEME_KDF = "pbkdf2-sha256-v2";

/**
 * Python `json.dumps(ensure_ascii=False)` 와 바이트 동일한 직렬화 (포팅 보조).
 *
 * - `indent` 가 숫자면 Python `json.dumps(indent=n)` 와 동일한 들여쓰기 출력. `indent=0`
 *   은 Python 처럼 줄바꿈만 넣는다 (`JSON.stringify(v, null, 0)` 은 한 줄이라 다르다).
 * - `indent` 가 null 이면 Python 기본 compact 구분자 `", "` / `": "` 를 쓴다.
 * - 숫자: 정수가 아닌 값·`-0`·지수 표기 구간은 Python `repr(float)` (`1e-07`, `-0.0`,
 *   `1e+21`, `NaN`, `Infinity`) 로 쓴다.
 *   **알려진 한계**: JS 는 `1.0` 과 `1` 을 구분하지 못하므로 정숫값 float 은 `1` 로
 *   나온다 (Python 은 `1.0`). 2^53 을 넘는 정수도 JS number 로는 정확히 담지 못한다.
 *
 * `undefined` 값은 Python 직렬화 불가 항목과 마찬가지로 vault 스키마에 넣지 않는다.
 */
export function pyJsonDumps(value: unknown, indent: number | null = 2): string {
  return encodeJson(value, indent === null ? null : Math.max(0, indent), 0);
}

function encodeNumber(v: number): string {
  if (Number.isInteger(v) && !Object.is(v, -0) && Math.abs(v) < 1e16) return String(v);
  return pyFloatRepr(v);
}

function encodeJson(value: unknown, indent: number | null, level: number): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return encodeNumber(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "boolean") return value ? "true" : "false";
  const open = indent === null ? "" : `\n${" ".repeat(indent * (level + 1))}`;
  const close = indent === null ? "" : `\n${" ".repeat(indent * level)}`;
  const sep = indent === null ? ", " : `,${open}`;
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    return `[${open}${value.map((v) => encodeJson(v, indent, level + 1)).join(sep)}${close}]`;
  }
  const entries = recordEntries(value as Record<string, unknown>).filter(
    ([, v]) => v !== undefined,
  );
  if (entries.length === 0) return "{}";
  const body = entries.map(([k, v]) => `${JSON.stringify(k)}: ${encodeJson(v, indent, level + 1)}`);
  return `{${open}${body.join(sep)}${close}}`;
}

/** `datetime.now(timezone.utc).isoformat()` 대응 ("+00:00" 접미사).
 * Python 은 마이크로초, JS Date 는 밀리초 정밀도 — 초 소수부는 밀리초 + "000" 의
 * 6자리로 재현한다 (Python 도 microsecond==0 이면 소수부를 생략). */
export function pyIsoUtcNow(): string {
  return pyIsoUtc(new Date());
}

/** 주어진 시각을 Python isoformat UTC 형식("YYYY-MM-DDTHH:MM:SS[.mmm000]+00:00")으로. */
export function pyIsoUtc(d: Date): string {
  const pad2 = (n: number) => String(n).padStart(2, "0");
  const base =
    `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}` +
    `T${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
  const ms = d.getUTCMilliseconds();
  // Python 은 마이크로초 6자리 — JS 정밀도(ms) 뒤를 0 으로 채워 자릿수를 맞춘다.
  const frac = ms === 0 ? "" : `.${String(ms).padStart(3, "0")}000`;
  return `${base}${frac}+00:00`;
}

/** Vault 엔트리의 JSON 직렬화 형태 (Python dataclass 필드 순서 유지 — 바이트 호환). */
export interface VaultEntryDict {
  label: string;
  original: string;
  risk_level: number;
  legal_basis: string | null;
  first_seen_offset: number | bigint;
  occurrences: (number | bigint)[];
  extra: Record<string, unknown>;
}

/** Vault 전체의 JSON 직렬화 형태 (schema v1). */
export interface VaultDict {
  schema_version: number;
  created_at: string;
  salt: string;
  fingerprint_scheme: string;
  fingerprint_iterations: number | bigint;
  entries: Record<string, VaultEntryDict>;
}

/** 단일 vault 엔트리 — 토큰 1개에 대응하는 원본 PII 메타데이터. */
export class VaultEntry {
  constructor(
    token: string,
    label: string,
    original: string,
    riskLevel: number,
    legalBasis: string | null = null,
    firstSeenOffset: number | bigint = -1,
    occurrences: (number | bigint)[] = [],
    extra: Record<string, unknown> = {},
  ) {
    this.token = token;
    this.label = label;
    this.original = original;
    this.riskLevel = riskLevel;
    this.legalBasis = legalBasis;
    this.firstSeenOffset = firstSeenOffset;
    this.occurrences = occurrences;
    this.extra = extra;
  }

  token: string;
  label: string;
  original: string;
  riskLevel: number;
  legalBasis: string | null;
  firstSeenOffset: number | bigint;
  occurrences: (number | bigint)[];
  extra: Record<string, unknown>;

  /** Python `VaultEntry.to_dict` 대응 — token 은 제외, 필드 선언 순서 유지. */
  toDict(): VaultEntryDict {
    return {
      label: this.label,
      original: this.original,
      risk_level: this.riskLevel,
      legal_basis: this.legalBasis,
      first_seen_offset: this.firstSeenOffset,
      occurrences: [...this.occurrences],
      extra: { ...this.extra },
    };
  }
}

/** Python ``AuditFailurePolicy`` — 감사 기록 실패 시 처리 방침. */
export type AuditFailurePolicy = "best_effort" | "raise";
const AUDIT_FAILURE_POLICIES: readonly string[] = ["best_effort", "raise"];

/**
 * Vault 가 감사 로그에 요구하는 최소 계약 (Python 의 덕 타이핑 대응).
 * `AuditLog` 가 구조적으로 만족하며, 테스트용 대체 구현도 받을 수 있다.
 */
export interface VaultAuditSink {
  recordStore(token: string, label: string, opts?: AuditRecordOptions): void;
  recordReveal(token: string, label?: string | null, opts?: AuditRecordOptions): void;
}

export interface ReversibleVaultOptions {
  /** 토큰 해시 안정화용 salt. 미지정 시 16바이트 랜덤 hex. */
  salt?: string | null;
  /** 선택 감사 로그 — 모든 store/reveal 호출이 기록된다. */
  auditLog?: VaultAuditSink | null;
  /** hashed/FPE 지문용 비밀 키(pepper). 미지정 시 env `KPII_FINGERPRINT_KEY`. vault JSON 에 저장되지 않는다. */
  secretKey?: string | null;
  /** 지문 KDF 반복 횟수 (양의 정수). 미지정(null/undefined) 시 기본값 100000. */
  fingerprintIterations?: number | bigint | null;
  /**
   * 감사 기록 실패 처리. `"best_effort"`(기본) 는 기록 실패에도 계속 진행하고,
   * `"raise"` 는 기록 실패를 그대로 던져 store 를 되돌리고 reveal 을 막는다.
   */
  auditFailurePolicy?: AuditFailurePolicy;
}

/** Python `type(value) is int` 대응 — bool 은 JS 에서 별도 타입이라 자동 제외된다.
 * JSON 의 안전 범위 밖 정수는 `bigint` 로 들어온다 (`io/recordOrder.parseJsonOrdered`).
 * 한계: JSON `1.0` 은 JS 에서 정수 `1` 과 구분되지 않아 통과한다 (Python 은 float 로 거부). */
function isPyInt(value: unknown): value is number | bigint {
  return typeof value === "bigint" || (typeof value === "number" && Number.isInteger(value));
}

function positiveIterations(value: unknown): number | bigint {
  if (!isPyInt(value) || value < 1) {
    throw new ValueError("Invalid vault fingerprint_iterations: expected a positive integer");
  }
  return value;
}

function validateIdentity(label: unknown, original: unknown): [string, string] {
  if (typeof label !== "string" || !label || /[<>\r\n]/.test(label)) {
    throw new ValueError("Invalid vault label");
  }
  if (typeof original !== "string") {
    throw new ValueError("Invalid vault original: expected a string");
  }
  return [label, original];
}

function validateEntryMetadata(
  risk: unknown,
  legal: unknown,
  offset: unknown,
  extra: unknown,
): number {
  if (!isPyInt(risk) || risk < 1 || risk > 5) throw new ValueError("Invalid vault risk_level");
  if (legal !== null && legal !== undefined && typeof legal !== "string") {
    throw new ValueError("Invalid vault legal_basis");
  }
  if (!isPyInt(offset) || offset < -1) throw new ValueError("Invalid vault offset");
  if (!isPlainObject(extra)) throw new ValueError("Invalid vault extra: expected an object");
  return Number(risk); // 1..5 범위 검증 후라 항상 안전한 정수
}

function validateAuditFailurePolicy(policy: unknown): asserts policy is AuditFailurePolicy {
  if (typeof policy !== "string" || !AUDIT_FAILURE_POLICIES.includes(policy)) {
    const allowed = [...AUDIT_FAILURE_POLICIES].sort().join(", ");
    throw new ValueError(
      `Unknown audit_failure_policy: ${pyRepr(policy)}; expected one of ${allowed}`,
    );
  }
}

/** Python `repr()` 의 최소 근사 (str → 작은따옴표, 그 외 String). 오류 메시지 전용. */
function pyRepr(v: unknown): string {
  if (typeof v === "string") return `'${v.replaceAll("\\", "\\\\").replaceAll("'", "\\'")}'`;
  if (v === null || v === undefined) return "None";
  if (typeof v === "boolean") return v ? "True" : "False";
  return String(v);
}

/** In-memory vault that maps tokens to original PII values.
 *
 * Once a mapping is stored, the same `(label, original)` pair receives the
 * same token while that Vault state is reused. New token numbers depend on
 * insertion order; reusing only the `salt` does not reproduce token IDs.
 */
export class ReversibleVault {
  /** 공개 salt (공개돼도 무방 — 지문 비밀 키는 저장하지 않는다). */
  salt: string;
  /** ISO-8601 생성 시각 (UTC, "+00:00" 접미사). */
  createdAt: string;
  /** 지문 비밀 키(pepper) — Python `_secret_key` 대응. 저장되지 않으며 운영자가 재공급한다. */
  secretKey: string;
  /** 지문 KDF 반복 횟수 — Python `_fp_iterations` 대응. */
  fpIterations: number | bigint;
  /** 지문 scheme — Python `_fp_scheme` 대응. */
  fpScheme: string;

  private readonly entriesMap = new Map<string, VaultEntry>();
  /** (label, original) -> token 역색인. */
  private readonly reverse = new Map<string, string>();
  /** label -> 다음 id. */
  private readonly counters = new Map<string, number>();
  private auditLog: VaultAuditSink | null;
  private auditFailurePolicy: AuditFailurePolicy;
  /** (label, original) -> fingerprint 메모이즈. */
  private readonly fpCache = new Map<string, string>();

  constructor(options: ReversibleVaultOptions = {}) {
    const policy = options.auditFailurePolicy ?? "best_effort";
    validateAuditFailurePolicy(policy);
    this.salt = options.salt ?? randomSalt();
    this.createdAt = pyIsoUtcNow();
    this.auditLog = options.auditLog ?? null;
    this.auditFailurePolicy = policy;
    this.secretKey = options.secretKey ?? process.env.KPII_FINGERPRINT_KEY ?? "";
    this.fpIterations = positiveIterations(options.fingerprintIterations ?? DEFAULT_FP_ITERATIONS);
    this.fpScheme = FP_SCHEME_KDF; // 신규 vault = 강화 KDF
  }

  // ------------------------------------------------------------------ token

  /** Return a stable token for (label, original). Creates one on first use. */
  tokenFor(label: string, original: string): string {
    validateIdentity(label, original);
    const key = pairKey(label, original);
    const existing = this.reverse.get(key);
    if (existing !== undefined) {
      const entry = this.entriesMap.get(existing);
      if (
        entry !== undefined &&
        (entry.token !== existing || entry.label !== label || entry.original !== original)
      ) {
        throw new ValueError("Inconsistent vault token mapping");
      }
      return existing;
    }
    const nextId = (this.counters.get(label) ?? 0) + 1;
    const token = `<${label}_${nextId}>`;
    if (this.entriesMap.has(token)) throw new ValueError("Conflicting vault token mapping");
    this.counters.set(label, nextId);
    this.reverse.set(key, token);
    return token;
  }

  /** Insert or update an entry; return the assigned token. */
  store(
    label: string,
    original: string,
    riskLevel: number,
    legalBasis: string | null = null,
    offset = -1,
    extra?: Record<string, unknown> | null,
  ): string {
    validateEntryMetadata(riskLevel, legalBasis, offset, extra ?? {});
    const key = pairKey(label, original);
    const hadReverseMapping = this.reverse.has(key);
    const previousCounter = this.counters.get(label);
    const token = this.tokenFor(label, original);
    const entry = this.entriesMap.get(token);
    const isNew = entry === undefined;
    let appendedOccurrence = false;
    if (entry === undefined) {
      this.entriesMap.set(
        token,
        new VaultEntry(
          token,
          label,
          original,
          riskLevel,
          legalBasis,
          offset,
          offset >= 0 ? [offset] : [],
          { ...(extra ?? {}) },
        ),
      );
    } else if (offset >= 0) {
      entry.occurrences.push(offset);
      appendedOccurrence = true;
    }
    if (this.auditLog !== null) {
      try {
        // 모든 store 호출 기록 (재저장 포함). new=false 면 기존 토큰 재사용.
        this.auditLog.recordStore(token, label, { extra: { new: isNew } });
      } catch (err) {
        if (this.auditFailurePolicy === "raise") {
          if (isNew) {
            this.entriesMap.delete(token);
            if (!hadReverseMapping) {
              this.reverse.delete(key);
              if (previousCounter === undefined) this.counters.delete(label);
              else this.counters.set(label, previousCounter);
            }
          } else if (appendedOccurrence) {
            entry.occurrences.pop();
          }
          throw err;
        }
      }
    }
    return token;
  }

  // ----------------------------------------------------------------- lookup

  /** Return the original value for a token, or null if unknown.
   *
   * `context` is recorded in the audit log — attach a reason ("export to BI
   * dashboard", "user request id=42", etc.).
   */
  reveal(token: string, context?: string | null): string | null {
    const entry = this.entriesMap.get(token);
    if (this.auditLog !== null) {
      try {
        // 실패(존재하지 않는 토큰 probing)도 기록 — found=false 로 표시.
        this.auditLog.recordReveal(token, entry?.label ?? null, {
          context: context ?? null,
          extra: { found: entry !== undefined },
        });
      } catch (err) {
        if (this.auditFailurePolicy === "raise") throw err;
      }
    }
    return entry !== undefined ? entry.original : null;
  }

  /** Attach an audit log and optionally replace its failure policy. */
  attachAudit(
    auditLog: VaultAuditSink,
    options: { failurePolicy?: AuditFailurePolicy | null } = {},
  ): void {
    const policy = options.failurePolicy;
    if (policy !== undefined && policy !== null) {
      validateAuditFailurePolicy(policy);
      this.auditFailurePolicy = policy;
    }
    this.auditLog = auditLog;
  }

  get(token: string): VaultEntry | undefined {
    return this.entriesMap.get(token);
  }

  /** Python `token in vault` 대응. */
  has(token: string): boolean {
    return this.entriesMap.has(token);
  }

  /** Python `len(vault)` 대응. */
  get size(): number {
    return this.entriesMap.size;
  }

  entries(): VaultEntry[] {
    return [...this.entriesMap.values()];
  }

  labels(): Set<string> {
    return new Set([...this.entriesMap.values()].map((e) => e.label));
  }

  // ------------------------------------------------------------ persistence

  toDict(): VaultDict {
    const entries: Record<string, VaultEntryDict> = {};
    for (const [token, entry] of this.entriesMap) {
      entries[token] = entry.toDict();
    }
    return {
      schema_version: SCHEMA_VERSION,
      created_at: this.createdAt,
      salt: this.salt,
      fingerprint_scheme: this.fpScheme, // secret_key 는 저장 X
      fingerprint_iterations: this.fpIterations,
      entries,
    };
  }

  dumps(indent: number | null = 2): string {
    return pyJsonDumps(this.toDict(), indent);
  }

  /** 원자적 저장 — 실패해도 기존 파일을 잘라내지 않는다 (Python `write_text_atomic`). */
  save(path: string, indent: number | null = 2): void {
    writeTextAtomic(path, this.dumps(indent));
  }

  /**
   * 검증된 payload 에서 vault 를 재구성한다. 형식·타입·토큰/라벨 정합성 위반은
   * 모두 ValueError (값을 메시지에 싣지 않는다). payload 는 변경하지 않는다.
   */
  static fromDict(payload: unknown): ReversibleVault {
    if (!isPlainObject(payload)) throw new ValueError("Invalid vault: expected an object");
    const schema = payload.schema_version;
    if (!isPyInt(schema) || schema !== SCHEMA_VERSION) {
      throw new ValueError("Unsupported vault schema_version");
    }
    const salt = payload.salt;
    if (typeof salt !== "string") throw new ValueError("Invalid vault salt");
    if (Object.hasOwn(payload, "created_at") && typeof payload.created_at !== "string") {
      throw new ValueError("Invalid vault created_at");
    }
    const scheme = Object.hasOwn(payload, "fingerprint_scheme")
      ? payload.fingerprint_scheme
      : FP_SCHEME_LEGACY;
    if (scheme !== FP_SCHEME_LEGACY && scheme !== FP_SCHEME_KDF) {
      throw new ValueError("Unsupported vault fingerprint_scheme");
    }
    const iterations = positiveIterations(
      Object.hasOwn(payload, "fingerprint_iterations")
        ? payload.fingerprint_iterations
        : DEFAULT_FP_ITERATIONS,
    );
    const entries = Object.hasOwn(payload, "entries") ? payload.entries : {};
    if (!isPlainObject(entries)) throw new ValueError("Invalid vault entries: expected an object");
    const v = new ReversibleVault({ salt, fingerprintIterations: iterations });
    if (Object.hasOwn(payload, "created_at")) v.createdAt = payload.created_at as string;
    // 강화 전(legacy) vault 는 fingerprint_scheme 필드가 없음 → SHA-256 v1 유지
    // (불려온 vault 의 hashed/FPE 출력 일관성 보존). secret_key 는 env 에서.
    v.fpScheme = scheme;
    for (const [token, data] of Object.entries(entries)) {
      if (!isPlainObject(data)) throw new ValueError("Invalid vault entry");
      const [label, original] = validateIdentity(data.label, data.original);
      const prefix = `<${label}_`;
      if (!token.startsWith(prefix) || !token.endsWith(">")) {
        throw new ValueError("Vault token does not match its label");
      }
      const index = token.slice(prefix.length, -1);
      if (!/^[1-9][0-9]*$/.test(index)) throw new ValueError("Invalid vault token index");
      const num = Number(index);
      if (v.reverse.has(pairKey(label, original))) {
        throw new ValueError("Duplicate vault identity mapping");
      }
      const risk = validateEntryMetadata(
        data.risk_level,
        Object.hasOwn(data, "legal_basis") ? data.legal_basis : null,
        Object.hasOwn(data, "first_seen_offset") ? data.first_seen_offset : -1,
        Object.hasOwn(data, "extra") ? data.extra : {},
      );
      const occurrences = Object.hasOwn(data, "occurrences") ? data.occurrences : [];
      if (!Array.isArray(occurrences) || occurrences.some((x) => !isPyInt(x) || x < 0)) {
        throw new ValueError("Invalid vault occurrences");
      }
      const entry = new VaultEntry(
        token,
        label,
        original,
        risk,
        (data.legal_basis ?? null) as string | null,
        (Object.hasOwn(data, "first_seen_offset") ? data.first_seen_offset : -1) as number | bigint,
        [...(occurrences as (number | bigint)[])],
        { ...((Object.hasOwn(data, "extra") ? data.extra : {}) as Record<string, unknown>) },
      );
      v.entriesMap.set(token, entry);
      v.reverse.set(pairKey(entry.label, entry.original), token);
      // Maintain counters so future stores don't collide.
      v.counters.set(entry.label, Math.max(v.counters.get(entry.label) ?? 0, num));
    }
    return v;
  }

  /** 중복 키·비유한 수(NaN/Infinity)를 거부하는 엄격 JSON 파싱 후 `fromDict`. */
  static loads(payload: string): ReversibleVault {
    return ReversibleVault.fromDict(strictJsonLoads(payload));
  }

  static load(path: string): ReversibleVault {
    return ReversibleVault.loads(readFileSync(path, "utf8"));
  }

  // ---------------------------------------------------------- hash-based id

  /** `(label, original)` 의 안정적·비가역 지문 (hashed/FPE 모드용).
   *
   * 강화 scheme(`pbkdf2-sha256-v2`): 비밀 키(pepper)를 섞은 salt 위에
   * PBKDF2-HMAC-SHA256 을 `fpIterations` 회 적용 — 저엔트로피 PII 의 무차별
   * 대입을 막는다. (legacy vault 는 기존 SHA-256 유지.)
   * 같은 값은 메모이즈되어 KDF 비용이 *고유 값당 1회* 로 제한된다.
   */
  fingerprint(label: string, original: string): string {
    const cacheKey = pairKey(label, original);
    const cached = this.fpCache.get(cacheKey);
    if (cached !== undefined) return cached;
    let fp: string;
    if (this.fpScheme === FP_SCHEME_LEGACY) {
      const h = createHash("sha256");
      h.update(this.salt, "utf8");
      h.update(":");
      h.update(label, "utf8");
      h.update(":");
      h.update(original, "utf8");
      fp = h.digest("hex");
    } else {
      const material = Buffer.from(`${label}:${original}`, "utf8");
      // 비밀 키를 salt 에 결합 — 키가 vault JSON 에 없으므로, 키 없이는
      // salt 를 알아도 (label, original) 을 복원할 수 없다.
      const kdfSalt = Buffer.from(`${this.salt}:${this.secretKey}`, "utf8");
      fp = pbkdf2Sync(material, kdfSalt, Number(this.fpIterations), 32, "sha256").toString("hex");
    }
    this.fpCache.set(cacheKey, fp);
    return fp;
  }
}

/** (label, original) 복합 키 — Python tuple 키 대응. 구분자 결합은 값에 구분자가 들어 있으면
 * 충돌하므로(`("A\0B","C")` vs `("A","B\0C")`) JSON 배열로 인코딩한다. */
function pairKey(label: string, original: string): string {
  return JSON.stringify([label, original]);
}

const NON_FINITE_TOKEN = /"(?:[^"\\]|\\.)*"|(-?Infinity|NaN)/g;

/**
 * Python `json.loads(payload, object_pairs_hook=_unique_json_object,
 * parse_constant=_reject_json_constant)` 대응.
 *
 * - `NaN`/`Infinity`/`-Infinity` 리터럴 → "non-finite number" ValueError
 * - 모든 깊이의 중복 객체 키 → "duplicate object key" ValueError (키 값은 메시지에 싣지 않음)
 * - 그 밖의 구문 오류 → ValueError (Python JSONDecodeError 는 ValueError 하위형)
 */
export function strictJsonLoads(text: string): unknown {
  try {
    // 객체 키는 원본 순서 그대로 (Python dict) — 정수형 키도 앞으로 당겨지지 않는다.
    return parseJsonOrdered(text, () => {
      throw new ValueError("Invalid vault JSON: duplicate object key");
    });
  } catch (e) {
    if (e instanceof ValueError) throw e;
    for (const m of text.matchAll(NON_FINITE_TOKEN)) {
      if (m[1] !== undefined) throw new ValueError("Invalid vault JSON: non-finite number");
    }
    throw new ValueError("Invalid vault JSON: malformed document");
  }
}

/** Python `str.strip()`/`int()` 이 걷어내는 공백 집합. */
const PY_WS_CLASS =
  "[\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const PY_WS_TRIM = new RegExp(`^${PY_WS_CLASS}+|${PY_WS_CLASS}+$`, "g");

/** Python `str.strip()` 대응 — JS `trim()` 과 공백 집합이 다르다 (U+001C~1F·U+0085 포함, U+FEFF 제외). */
export function pyStrip(text: string): string {
  return text.replace(PY_WS_TRIM, "");
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** 16바이트 랜덤 salt hex (Python `_random_salt` 대응). */
function randomSalt(nBytes = 16): string {
  return randomBytes(nBytes).toString("hex");
}
