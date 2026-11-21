/**
 * Python ``json.dumps(ensure_ascii=False, indent=n)`` 바이트 호환 직렬화 (CLI 출력용).
 *
 * JS number 는 Python 의 int/float 구분을 잃는다. 두 가지로 보완한다:
 * - ``floatKeys``: 이 키의 숫자 값은 항상 Python float (예: ``confidence``, ``elapsed_s``)
 *   이므로 ``1`` 이 아니라 ``1.0`` 으로 쓴다.
 * - ``shadow``: 원본 JSON 을 ``numberShadow`` 로 다시 읽어 얻은 숫자 어휘(lexeme) 트리. 같은
 *   위치의 숫자를 원본 어휘 종류대로(소수점/지수 → float repr, 그 밖 → 정확한 정수) 쓴다.
 */
import { pyFloatRepr } from "../core/pyFormat.js";
import { recordEntries } from "../io/recordOrder.js";

/** 원본 JSON 숫자 어휘 표시 (shadow 트리의 잎). */
class NumberLexeme {
  readonly source: string;
  constructor(source: string) {
    this.source = source;
  }
}

/**
 * 원본 JSON 텍스트의 숫자 어휘를 담은 shadow 트리 (구조는 ``JSON.parse`` 결과와 같다).
 * Node 21+ 의 reviver ``context.source`` 가 없으면 null — 그때는 JS 숫자 규칙으로 쓴다.
 */
export function numberShadow(text: string): unknown {
  let supported = false;
  try {
    const tree = JSON.parse(text, (_key, value: unknown, context?: { source?: string }) => {
      if (typeof value === "number" && context?.source !== undefined) {
        supported = true;
        return new NumberLexeme(context.source);
      }
      return value;
    }) as unknown;
    return supported ? tree : null;
  } catch {
    return null;
  }
}

function encodeNumber(value: number, lexeme: NumberLexeme | null, isFloat: boolean): string {
  if (lexeme !== null && Number(lexeme.source) === value) {
    if (/[.eE]/.test(lexeme.source)) return pyFloatRepr(value);
    return BigInt(lexeme.source).toString();
  }
  if (!isFloat && Number.isInteger(value) && !Object.is(value, -0) && Math.abs(value) < 1e16) {
    return String(value);
  }
  return pyFloatRepr(value);
}

export interface PyDumpsOptions {
  floatKeys?: ReadonlySet<string>;
  shadow?: unknown;
}

function child(shadow: unknown, key: string | number): unknown {
  if (shadow === null || typeof shadow !== "object") return null;
  return (shadow as Record<string | number, unknown>)[key] ?? null;
}

function encode(
  value: unknown,
  indent: number | null,
  level: number,
  options: PyDumpsOptions,
  shadow: unknown,
  isFloat: boolean,
): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    return encodeNumber(value, shadow instanceof NumberLexeme ? shadow : null, isFloat);
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "boolean") return value ? "true" : "false";
  const open = indent === null ? "" : `\n${" ".repeat(indent * (level + 1))}`;
  const close = indent === null ? "" : `\n${" ".repeat(indent * level)}`;
  const sep = indent === null ? ", " : `,${open}`;
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const items = value.map((v, i) =>
      encode(v, indent, level + 1, options, child(shadow, i), isFloat),
    );
    return `[${open}${items.join(sep)}${close}]`;
  }
  const entries = recordEntries(value as Record<string, unknown>).filter(
    ([, v]) => v !== undefined,
  );
  if (entries.length === 0) return "{}";
  const body = entries.map(
    ([k, v]) =>
      `${JSON.stringify(k)}: ${encode(v, indent, level + 1, options, child(shadow, k), options.floatKeys?.has(k) ?? false)}`,
  );
  return `{${open}${body.join(sep)}${close}}`;
}

/** Python ``json.dumps(value, ensure_ascii=False, indent=indent)``. ``indent=null`` 은 한 줄. */
export function pyDumps(
  value: unknown,
  indent: number | null = 2,
  options: PyDumpsOptions = {},
): string {
  return encode(value, indent, 0, options, options.shadow ?? null, false);
}
