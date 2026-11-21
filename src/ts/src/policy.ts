/** 검증된 변환 선택 — 검출기·임계값 재정의는 없다. Python ko_pii.policy 대응. */
import { createHash } from "node:crypto";
import { ValueError } from "./core/errors.js";
import { ALL_LABELS } from "./labels.js";
import { pyJsonDumps } from "./vault/reversible.js";

export const STRATEGIES: ReadonlySet<string> = new Set([
  "tokenize",
  "redact",
  "asterisk",
  "hashed",
  "partial",
  "fpe",
]);

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);

function isMapping(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Map)
  );
}

/** 라벨별 치환 전략 재정의를 검증해 사본을 반환한다 (Python ``validate_strategies``).
 *
 * ``overrides`` 는 평범한 객체 또는 ``Map`` 을 받는다.
 */
export function validateStrategies(
  defaultStrategy: unknown,
  overrides: Readonly<Record<string, string>> | ReadonlyMap<string, string> | null | undefined,
): Record<string, string> {
  if (typeof defaultStrategy !== "string" || !STRATEGIES.has(defaultStrategy)) {
    throw new ValueError("Unknown strategy");
  }
  let entries: [unknown, unknown][];
  if (overrides === null || overrides === undefined) {
    entries = [];
  } else if (overrides instanceof Map) {
    entries = [...overrides.entries()];
  } else if (isMapping(overrides)) {
    entries = Object.entries(overrides);
  } else {
    throw new ValueError("strategies must map labels to substitution strategies");
  }
  if (entries.some(([k]) => typeof k !== "string" || !LABEL_SET.has(k))) {
    throw new ValueError("strategies contains an unknown category label");
  }
  if (entries.some(([, v]) => typeof v !== "string" || !STRATEGIES.has(v))) {
    throw new ValueError("strategies contains an unknown substitution strategy");
  }
  const result: Record<string, string> = {};
  for (const [k, v] of entries) result[k as string] = v as string;
  return result;
}

/** Python ``sorted()`` 키 순서 (코드 포인트 비교). */
export function codePointCompare(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d =
      ((x[i] as string).codePointAt(0) as number) - ((y[i] as string).codePointAt(0) as number);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

function sortedRecord(value: Readonly<Record<string, string>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of Object.keys(value).sort(codePointCompare)) out[k] = value[k] as string;
  return out;
}

/** Python ``policy_digest`` — ``json.dumps(payload, sort_keys=True)`` 의 SHA-256.
 *
 * 라벨·전략·모드는 모두 ASCII 라 ``ensure_ascii`` 차이가 없다.
 */
export function policyDigest(
  mode: string,
  defaultStrategy: string,
  overrides: Readonly<Record<string, string>>,
): string {
  const payload = {
    default: defaultStrategy,
    mode,
    strategies: sortedRecord(overrides),
    version: 1,
  };
  return createHash("sha256").update(pyJsonDumps(payload, null), "utf8").digest("hex");
}
