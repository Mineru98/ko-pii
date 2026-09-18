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
import { readFileSync, writeFileSync } from "node:fs";
import { ValueError } from "../core/errors.js";
import { pyFloatRepr } from "../core/pyFormat.js";
import { foldNdDigits } from "../modes/unicodeDigits.js";
import type { AuditLog } from "./audit.js";

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
  const entries = Object.entries(value as Record<string, unknown>).filter(
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
  first_seen_offset: number;
  occurrences: number[];
  extra: Record<string, unknown>;
}

/** Vault 전체의 JSON 직렬화 형태 (schema v1). */
export interface VaultDict {
  schema_version: number;
  created_at: string;
  salt: string;
  fingerprint_scheme: string;
  fingerprint_iterations: number;
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
    firstSeenOffset: number = -1,
    occurrences: number[] = [],
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
  firstSeenOffset: number;
  occurrences: number[];
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

export interface ReversibleVaultOptions {
  /** 토큰 해시 안정화용 salt. 미지정 시 16바이트 랜덤 hex. */
  salt?: string | null;
  /** 선택 감사 로그 — 모든 store/reveal 호출이 기록된다. */
  auditLog?: AuditLog | null;
  /** hashed/FPE 지문용 비밀 키(pepper). 미지정 시 env `KPII_FINGERPRINT_KEY`. vault JSON 에 저장되지 않는다. */
  secretKey?: string | null;
  /** 지문 KDF 반복 횟수. 0/미지정 시 기본값 100000. */
  fingerprintIterations?: number | null;
}

/** In-memory vault that maps tokens to original PII values.
 *
 * Tokens are deterministic per (label, original) pair so that the same value
 * receives the same token throughout a document — and across multiple runs
 * if the same `salt` is reused.
 */
export class ReversibleVault {
  /** 공개 salt (공개돼도 무방 — 지문 비밀 키는 저장하지 않는다). */
  salt: string;
  /** ISO-8601 생성 시각 (UTC, "+00:00" 접미사). */
  createdAt: string;
  /** 지문 비밀 키(pepper) — Python `_secret_key` 대응. 저장되지 않으며 운영자가 재공급한다. */
  secretKey: string;
  /** 지문 KDF 반복 횟수 — Python `_fp_iterations` 대응. */
  fpIterations: number;
  /** 지문 scheme — Python `_fp_scheme` 대응. */
  fpScheme: string;

  private readonly entriesMap = new Map<string, VaultEntry>();
  /** (label, original) -> token 역색인. */
  private readonly reverse = new Map<string, string>();
  /** label -> 다음 id. */
  private readonly counters = new Map<string, number>();
  private auditLog: AuditLog | null;
  /** (label, original) -> fingerprint 메모이즈. */
  private readonly fpCache = new Map<string, string>();

  constructor(options: ReversibleVaultOptions = {}) {
    this.salt = options.salt ?? randomSalt();
    this.createdAt = pyIsoUtcNow();
    this.secretKey = options.secretKey ?? process.env.KPII_FINGERPRINT_KEY ?? "";
    this.fpIterations = options.fingerprintIterations || DEFAULT_FP_ITERATIONS;
    this.fpScheme = FP_SCHEME_KDF; // 신규 vault = 강화 KDF
    this.auditLog = options.auditLog ?? null;
  }

  // ------------------------------------------------------------------ token

  /** Return a stable token for (label, original). Creates one on first use. */
  tokenFor(label: string, original: string): string {
    const key = pairKey(label, original);
    const existing = this.reverse.get(key);
    if (existing !== undefined) return existing;
    const next = (this.counters.get(label) ?? 0) + 1;
    this.counters.set(label, next);
    const token = `<${label}_${next}>`;
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
    const token = this.tokenFor(label, original);
    const existing = this.entriesMap.get(token);
    const isNew = existing === undefined;
    if (existing === undefined) {
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
      existing.occurrences.push(offset);
    }
    if (this.auditLog !== null) {
      try {
        // 모든 store 호출 기록 (재저장 포함). new=false 면 기존 토큰 재사용.
        this.auditLog.recordStore(token, label, { extra: { new: isNew } });
      } catch {
        // audit failure never blocks data flow
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
      } catch {
        // audit failure never blocks data flow
      }
    }
    return entry !== undefined ? entry.original : null;
  }

  /** Attach (or replace) an AuditLog after construction. */
  attachAudit(auditLog: AuditLog): void {
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

  save(path: string, indent: number | null = 2): void {
    writeFileSync(path, this.dumps(indent), "utf8");
  }

  /** Unsupported schema_version 인 경우 Error 발생 (Python ValueError 대응). */
  static fromDict(payload: Record<string, unknown>): ReversibleVault {
    if (payload.schema_version !== SCHEMA_VERSION) {
      throw new ValueError(`Unsupported vault schema_version: ${payload.schema_version}`);
    }
    const salt = payload.salt;
    if (typeof salt !== "string") {
      throw new Error(`vault payload missing salt: ${JSON.stringify(payload.salt)}`);
    }
    const v = new ReversibleVault({ salt });
    // Python 은 값의 타입을 검사하지 않고 그대로 받는다(`payload.get(...)`) — 키 존재 여부만 본다.
    if (Object.hasOwn(payload, "created_at")) v.createdAt = payload.created_at as string;
    // 강화 전(legacy) vault 는 fingerprint_scheme 필드가 *없음* → SHA-256 v1 유지
    // (불려온 vault 의 hashed/FPE 출력 일관성 보존). secret_key 는 env 에서.
    // 필드가 있으면 null 이라도 그대로 — legacy 가 아니므로 KDF 경로를 탄다 (Python 동일).
    v.fpScheme = Object.hasOwn(payload, "fingerprint_scheme")
      ? (payload.fingerprint_scheme as string)
      : FP_SCHEME_LEGACY;
    if (Object.hasOwn(payload, "fingerprint_iterations")) {
      v.fpIterations = pyInt(payload.fingerprint_iterations); // Python int(...)
    }
    const entries = Object.hasOwn(payload, "entries") ? payload.entries : {};
    if (!isPlainObject(entries)) {
      // Python: `None.items()` → AttributeError
      throw new TypeError("vault payload 'entries' must be an object");
    }
    for (const [token, data] of Object.entries(entries)) {
      if (!isPlainObject(data)) throw new TypeError(`vault entry must be an object: ${token}`);
      const d = data;
      const entry = new VaultEntry(
        token,
        requiredField(d, "label") as string,
        requiredField(d, "original") as string,
        requiredField(d, "risk_level") as number,
        (d.legal_basis ?? null) as string | null,
        (Object.hasOwn(d, "first_seen_offset") ? d.first_seen_offset : -1) as number,
        pyList(d.occurrences, Object.hasOwn(d, "occurrences")) as number[],
        pyDict(d.extra, Object.hasOwn(d, "extra")),
      );
      v.entriesMap.set(token, entry);
      v.reverse.set(pairKey(entry.label, entry.original), token);
      // Maintain counters so future stores don't collide.
      const n = parseTokenCounter(token);
      if (n === null) continue;
      const cur = v.counters.get(entry.label) ?? 0;
      if (n > cur) v.counters.set(entry.label, n);
    }
    return v;
  }

  static loads(payload: string): ReversibleVault {
    return ReversibleVault.fromDict(JSON.parse(payload) as Record<string, unknown>);
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
      fp = pbkdf2Sync(material, kdfSalt, this.fpIterations, 32, "sha256").toString("hex");
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

/** Python `data[key]` 대응 — 키가 없으면 예외(KeyError), 있으면 타입 검사 없이 그대로. */
function requiredField(d: Record<string, unknown>, key: string): unknown {
  if (!Object.hasOwn(d, key)) throw new Error(`vault entry missing field: ${key}`);
  return d[key];
}

/** Python `list(x)` 대응 (키 없음 → []). */
function pyList(x: unknown, present: boolean): unknown[] {
  if (!present) return [];
  if (Array.isArray(x)) return [...x];
  if (typeof x === "string") return [...x];
  if (isPlainObject(x)) return Object.keys(x);
  throw new TypeError("object is not iterable");
}

/** Python `dict(x)` 대응 (키 없음 → {}). */
function pyDict(x: unknown, present: boolean): Record<string, unknown> {
  if (!present) return {};
  if (isPlainObject(x)) return { ...x };
  if (Array.isArray(x) && x.length === 0) return {};
  throw new TypeError("cannot convert value to dict");
}

/** Python `str.strip()`/`int()` 이 걷어내는 공백 집합. */
const PY_WS_CLASS =
  "[\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const PY_WS_TRIM = new RegExp(`^${PY_WS_CLASS}+|${PY_WS_CLASS}+$`, "g");

/** Python `str.strip()` 대응 — JS `trim()` 과 공백 집합이 다르다 (U+001C~1F·U+0085 포함, U+FEFF 제외). */
export function pyStrip(text: string): string {
  return text.replace(PY_WS_TRIM, "");
}

/** Python `int(str)` 리터럴 파싱 — 공백 제거, 부호, Nd 숫자(전각 등), 숫자 사이 단일 `_`. 실패 시 null. */
function pyParseIntLiteral(text: string): number | null {
  const t = pyStrip(text);
  if (!/^[+-]?\p{Nd}+(?:_\p{Nd}+)*$/u.test(t)) return null;
  return Number(foldNdDigits(t).replaceAll("_", ""));
}

/** Python `int(x)` 대응 — float 은 0 방향 절사, 문자열은 정수 리터럴, bool 은 0/1. */
function pyInt(x: unknown): number {
  if (typeof x === "number") {
    if (!Number.isFinite(x)) throw new ValueError("cannot convert float NaN/infinity to integer");
    return Math.trunc(x);
  }
  if (typeof x === "boolean") return x ? 1 : 0;
  if (typeof x === "string") {
    const n = pyParseIntLiteral(x);
    if (n === null) throw new ValueError(`invalid literal for int() with base 10: '${x}'`);
    return n;
  }
  throw new TypeError("int() argument must be a string or a real number");
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** `<LABEL_N>` 토큰의 카운터 숫자 파싱 (Python `int(token.rsplit("_", 1)[-1].rstrip(">"))`).
 * 파싱 실패 시 null (Python ValueError → continue 대응). */
function parseTokenCounter(token: string): number | null {
  const cut = token.lastIndexOf("_");
  const tail = (cut >= 0 ? token.slice(cut + 1) : token).replace(/>+$/, "");
  // Python int() 는 앞뒤 공백·전각 숫자를 허용한다 ("<A_ 12 >" → 12, "<A_５>" → 5).
  return pyParseIntLiteral(tail);
}

/** 16바이트 랜덤 salt hex (Python `_random_salt` 대응). */
function randomSalt(nBytes = 16): string {
  return randomBytes(nBytes).toString("hex");
}
