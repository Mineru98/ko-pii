/** 이식 가능한 로컬 전용 처리 설정 — 실행 가능한 플러그인·비밀 없음. Python ko_pii.profile 대응. */
import { createHash } from "node:crypto";
import { type AnonymizationResult, Anonymizer } from "./anonymizer.js";
import { ValueError } from "./core/errors.js";
import { ProcessingMode } from "./core/modes.js";
import { codePointLength } from "./core/strUtils.js";
import { EACH, type FieldRule, rulesFromJson } from "./fieldRules.js";
import { validateLabelFilter } from "./labels.js";
import { normalizeExclusions } from "./patterns/person.js";
import { codePointCompare, validateStrategies } from "./policy.js";
import {
  anonymizeJson,
  anonymizeJsonl,
  fieldExclusions,
  fieldLabels,
  loadsJson,
  type StructuredLimits,
  type StructuredResult,
} from "./structured.js";
import type { ReversibleVault } from "./vault/reversible.js";

export const CORE_OPTIONS: ReadonlySet<string> = new Set([
  "mode",
  "strategy",
  "strategies",
  "include",
  "exclude",
  "person_exclusions",
]);
export const FIELD_OPTIONS: ReadonlySet<string> = new Set([
  "field_labels",
  "field_rules",
  "field_person_exclusions",
]);

const MODES: ReadonlySet<string> = new Set(Object.values(ProcessingMode));
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

type Settings = Record<string, unknown>;

function isMapping(value: unknown): value is Settings {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function get(value: Settings, key: string, fallback: unknown): unknown {
  return Object.hasOwn(value, key) ? value[key] : fallback;
}

function keysWithin(value: Settings, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((k) => allowed.has(k));
}

/** Python ``try: ... except (TypeError, ValueError): raise ValueError(message) from None``. */
function guarded<T>(message: string, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof ValueError || e instanceof TypeError) throw new ValueError(message);
    throw e;
  }
}

function unwrap(value: Settings | PolicyProfile): Settings {
  if (value instanceof PolicyProfile) return value.settings;
  if (!isMapping(value)) {
    throw new ValueError("policy requires an object");
  }
  if (Object.hasOwn(value, "schema_version") || Object.hasOwn(value, "settings")) {
    const version = value.schema_version;
    if (
      !Object.hasOwn(value, "schema_version") ||
      !Object.hasOwn(value, "settings") ||
      !keysWithin(value, new Set(["schema_version", "name", "settings"])) ||
      typeof version !== "number" ||
      !Number.isInteger(version) ||
      version !== 1 ||
      !isMapping(value.settings)
    ) {
      throw new ValueError("unsupported policy profile schema");
    }
    checkName(get(value, "name", ""));
    return value.settings;
  }
  return value;
}

function checkName(value: unknown): string {
  if (
    typeof value !== "string" ||
    codePointLength(value) > 80 ||
    LONE_SURROGATE.test(value) ||
    [...value].some((c) => (c.codePointAt(0) as number) < 32)
  ) {
    throw new ValueError("profile name must be a short display string");
  }
  return value;
}

function sortedStrings(values: Iterable<string>): string[] {
  return [...values].sort(codePointCompare);
}

/** 검증·정규화된 핵심 설정 (Python ``core_settings``). */
export function coreSettings(value: Settings | PolicyProfile): Settings {
  return guarded(
    "invalid core policy; Vaults, model adapters and arbitrary options are not supported",
    () => {
      const v = unwrap(value);
      if (!keysWithin(v, CORE_OPTIONS)) throw new ValueError();
      const mode = get(v, "mode", "STRICT");
      if (typeof mode !== "string" || !MODES.has(mode)) throw new ValueError();
      const strategy = get(v, "strategy", "tokenize");
      const strategies = validateStrategies(
        strategy,
        get(v, "strategies", null) as Record<string, string> | null,
      );
      const include = validateLabelFilter(
        get(v, "include", null) as Iterable<unknown> | null,
        "include",
      );
      const exclude = validateLabelFilter(
        get(v, "exclude", null) as Iterable<unknown> | null,
        "exclude",
      );
      return {
        mode,
        strategy,
        strategies,
        include: include !== null ? sortedStrings(include) : null,
        exclude: exclude ? sortedStrings(exclude) : [],
        person_exclusions: sortedStrings(
          normalizeExclusions(get(v, "person_exclusions", null) as Iterable<string> | null),
        ),
      };
    },
  );
}

function anonymizerFrom(
  core: Settings,
  options: { vault?: ReversibleVault | null; traceLimit?: number } = {},
): Anonymizer {
  return new Anonymizer(
    core.mode as ProcessingMode,
    core.strategy as string,
    options.vault ?? null,
    core.include as string[] | null,
    core.exclude as string[] | null,
    null,
    "union",
    null,
    core.person_exclusions as string[],
    { strategies: core.strategies as Record<string, string>, traceLimit: options.traceLimit ?? 0 },
  );
}

/** 검증·정규화된 구조화 설정 (Python ``structured_settings``). */
export function structuredSettings(value: Settings | PolicyProfile): Settings {
  return guarded(
    "invalid structured core policy; use bounded field settings without external state",
    () => {
      const v = unwrap(value);
      if (!Object.keys(v).every((k) => CORE_OPTIONS.has(k) || FIELD_OPTIONS.has(k))) {
        throw new ValueError();
      }
      const coreInput: Settings = {};
      for (const [k, item] of Object.entries(v)) if (CORE_OPTIONS.has(k)) coreInput[k] = item;
      const core = coreSettings(coreInput);
      const anon = anonymizerFrom(core);
      const labels = fieldLabels(
        get(v, "field_labels", null) as Record<string, string> | null,
        anon,
      );
      const paths = Object.keys(labels);
      if (paths.length > 128 || paths.some((path) => codePointLength(path) > 4096)) {
        throw new ValueError();
      }
      const rules = rulesFromJson(get(v, "field_rules", []));
      for (const rule of rules) fieldLabels({ "": rule.label }, anon);
      const exclusions = fieldExclusions(
        get(v, "field_person_exclusions", null) as Record<string, Iterable<string>> | null,
      );
      const exclusionOut: Record<string, string[]> = {};
      for (const [path, terms] of exclusions) {
        Object.defineProperty(exclusionOut, path, {
          value: sortedStrings(terms),
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      return {
        ...core,
        field_labels: labels,
        field_rules: rules.map((rule) => ({
          path: rule.path.map((p) => (p === EACH ? null : p)),
          label: rule.label,
          required: rule.required,
        })),
        field_person_exclusions: exclusionOut,
      };
    },
  );
}

/** Python ``json.dumps(ensure_ascii=False, sort_keys=True, separators=(",", ":"))``. */
function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort(codePointCompare);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/** Python 이 프로파일 인코딩을 다시 읽는 ``json.loads`` — 키는 own property 로 복원. */
function parseCanonical(text: string): Settings {
  return JSON.parse(text) as Settings;
}

/** 검증된 설정의 불변 스냅샷 — 처리마다 새 Vault 를 쓴다 (Python frozen dataclass ``PolicyProfile``).
 *
 * 설정에는 민감한 제외어·필드 이름이 들어 있을 수 있다. inspect 표현은 이를 숨기지만, 내보낸
 * 객체/JSON 은 숨기지 않는다. fingerprint 는 정규화된 설정을 식별할 뿐 프라이버시 보장·원문·
 * Vault 내용을 뜻하지 않는다.
 */
export class PolicyProfile {
  readonly #json: string;
  readonly name: string;

  constructor(settings: Settings, options: { name?: string } = {}) {
    if (
      !isMapping(settings) ||
      !Object.keys(settings).every((k) => CORE_OPTIONS.has(k) || FIELD_OPTIONS.has(k))
    ) {
      throw new ValueError("profile requires core/field settings, not executable options");
    }
    const normalized = Object.keys(settings).some((k) => FIELD_OPTIONS.has(k))
      ? structuredSettings(settings)
      : coreSettings(settings);
    const encoded = canonicalJson(normalized);
    if (codePointLength(encoded) > 100_000 || Buffer.byteLength(encoded, "utf8") > 400_000) {
      throw new ValueError("policy profile exceeds size limit");
    }
    this.#json = encoded;
    this.name = checkName(options.name ?? "");
    Object.freeze(this);
  }

  static fromDict(value: Settings): PolicyProfile {
    const settings = unwrap(value);
    const name = Object.hasOwn(value, "schema_version") ? get(value, "name", "") : "";
    return new PolicyProfile(settings, { name: name as string });
  }

  static fromJson(text: string): PolicyProfile {
    if (
      typeof text !== "string" ||
      codePointLength(text) > 100_000 ||
      Buffer.byteLength(text, "utf8") > 400_000
    ) {
      throw new ValueError("policy profile requires bounded JSON");
    }
    return PolicyProfile.fromDict(loadsJson(text) as Settings);
  }

  /** 매 호출 새 사본 — 반환값을 바꿔도 프로파일은 바뀌지 않는다. */
  get settings(): Settings {
    return parseCanonical(this.#json);
  }

  get fingerprint(): string {
    return createHash("sha256").update(this.#json, "utf8").digest("hex");
  }

  get structured(): boolean {
    return Object.keys(this.settings).some((k) => FIELD_OPTIONS.has(k));
  }

  /** Python dataclass ``__eq__`` — 정규화된 설정과 이름이 같으면 같다. */
  equals(other: unknown): boolean {
    return other instanceof PolicyProfile && other.#json === this.#json && other.name === this.name;
  }

  toDict(): { schema_version: 1; name: string; settings: Settings } {
    return { schema_version: 1, name: this.name, settings: this.settings };
  }

  makeAnonymizer(
    options: { vault?: ReversibleVault | null; traceLimit?: number } = {},
  ): Anonymizer {
    const settings: Settings = {};
    for (const [k, v] of Object.entries(this.settings)) if (CORE_OPTIONS.has(k)) settings[k] = v;
    return anonymizerFrom(settings, options);
  }

  structuredOptions(): {
    fieldLabels: Record<string, string>;
    fieldRules: FieldRule[];
    fieldPersonExclusions: Record<string, string[]>;
  } {
    const settings = structuredSettings(this);
    return {
      fieldLabels: settings.field_labels as Record<string, string>,
      fieldRules: rulesFromJson(settings.field_rules),
      fieldPersonExclusions: settings.field_person_exclusions as Record<string, string[]>,
    };
  }

  process(text: string): AnonymizationResult {
    if (this.structured) {
      throw new ValueError("field settings require process_json or process_jsonl");
    }
    return this.makeAnonymizer().process(text);
  }

  processJson(data: unknown, options: { limits?: StructuredLimits | null } = {}): StructuredResult {
    return anonymizeJson(data, {
      anonymizer: this.makeAnonymizer(),
      limits: options.limits ?? null,
      ...this.structuredOptions(),
    });
  }

  processJsonl(
    text: string,
    options: { limits?: StructuredLimits | null } = {},
  ): StructuredResult[] {
    return anonymizeJsonl(text, {
      anonymizer: this.makeAnonymizer(),
      limits: options.limits ?? null,
      ...this.structuredOptions(),
    });
  }

  /** Python ``repr`` 처럼 설정·이름을 숨긴다. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "PolicyProfile()";
  }

  toString(): string {
    return "PolicyProfile()";
  }
}
