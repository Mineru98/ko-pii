/** 명시적 타입 선택자 — 리터럴 ``"*"`` 키는 배열 와일드카드가 아니다. Python ko_pii.field_rules 대응. */
import { ValueError } from "./core/errors.js";
import { ALL_LABELS } from "./labels.js";

const LABEL_SET: ReadonlySet<string> = new Set(ALL_LABELS);

/** 배열의 각 원소를 뜻하는 경로 세그먼트 (Python ``ArrayItems.EACH``). */
export const EACH: unique symbol = Symbol.for("ko-pii.each_array_item");
export type ArrayItems = typeof EACH;

/** 객체 키(문자열) · 음이 아닌 배열 인덱스 · {@link EACH}. */
export type FieldPathSegment = string | number | ArrayItems;

function validSegment(segment: unknown): boolean {
  return (
    typeof segment === "string" ||
    (typeof segment === "number" && Number.isInteger(segment) && segment >= 0) ||
    segment === EACH
  );
}

/** JSON 경로 하나에 라벨을 단언하는 규칙 (Python frozen dataclass ``FieldRule``). */
export class FieldRule {
  readonly path: readonly FieldPathSegment[];
  readonly label: string;
  readonly required: boolean;

  constructor(path: readonly FieldPathSegment[], label: string, required = true) {
    if (!Array.isArray(path) || path.length > 128) {
      throw new ValueError("field rule path must be a tuple of at most 128 segments");
    }
    for (const segment of path) {
      if (!validSegment(segment)) {
        throw new ValueError("field rule segments must be keys, nonnegative indices or EACH");
      }
    }
    if (typeof label !== "string" || !LABEL_SET.has(label) || typeof required !== "boolean") {
      throw new ValueError("invalid field rule label or required flag");
    }
    this.path = Object.freeze([...path]);
    this.label = label;
    this.required = required;
    Object.freeze(this);
  }
}

/** Python ``bounded_rules`` — 최대 128개의 FieldRule 만 허용. */
export function boundedRules(rules: Iterable<FieldRule> | null | undefined): FieldRule[] {
  const result: FieldRule[] = [];
  for (const rule of rules ?? []) {
    if (!(rule instanceof FieldRule) || result.length >= 128) {
      throw new ValueError("field rules must contain at most 128 FieldRule objects");
    }
    result.push(rule);
  }
  return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** JSON 설정 전용 — ``null`` 경로 세그먼트가 {@link EACH} 를 뜻한다 (Python ``rules_from_json``). */
export function rulesFromJson(data: unknown): FieldRule[] {
  if (!Array.isArray(data) || data.length > 128) {
    throw new ValueError("field rules configuration must be a bounded list");
  }
  const rules: FieldRule[] = [];
  for (const row of data as unknown[]) {
    if (
      !isPlainObject(row) ||
      !Object.hasOwn(row, "path") ||
      !Object.hasOwn(row, "label") ||
      Object.keys(row).some((k) => k !== "path" && k !== "label" && k !== "required") ||
      !Array.isArray(row.path)
    ) {
      throw new ValueError("invalid field rules configuration");
    }
    const path = (row.path as unknown[]).map((p) => (p === null ? EACH : p)) as FieldPathSegment[];
    const required = Object.hasOwn(row, "required") ? row.required : true;
    rules.push(new FieldRule(path, row.label as string, required as boolean));
  }
  return boundedRules(rules);
}

/** 규칙별 일치 통계 (Python ``resolve_rules`` 보고 행). */
export interface FieldRuleReport {
  rule_index: number;
  label: string;
  required: boolean;
  matched: number;
  missing: number;
  empty_arrays: number;
  null_fields: number;
}

/** JSON Pointer 토큰 이스케이프. */
function escapeToken(key: string): string {
  return key.replaceAll("~", "~0").replaceAll("/", "~1");
}

/** JSON 트리가 크기·순환 검증을 통과한 뒤에만 해석한다 (Python ``resolve_rules``). */
export function resolveRules(
  data: unknown,
  labels: Readonly<Record<string, string>>,
  rules: readonly FieldRule[],
): [Record<string, string>, FieldRuleReport[]] {
  const resolved: Record<string, string> = { ...labels };
  const reports: FieldRuleReport[] = [];
  rules.forEach((rule, index) => {
    const stats = { matched: 0, missing: 0, empty_arrays: 0, null_fields: 0 };

    const visit = (value: unknown, depth: number, pointer: string): void => {
      if (depth === rule.path.length) {
        if (Object.hasOwn(resolved, pointer) && resolved[pointer] !== rule.label) {
          throw new ValueError(`conflicting field labels at rule ${index}`);
        }
        Object.defineProperty(resolved, pointer, {
          value: rule.label,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        stats.matched += 1;
        stats.null_fields += value === null ? 1 : 0;
        return;
      }
      const segment = rule.path[depth] as FieldPathSegment;
      if (segment === EACH) {
        if (!Array.isArray(value)) {
          throw new ValueError(`field rule ${index} expected an array`);
        }
        stats.empty_arrays += value.length === 0 ? 1 : 0;
        value.forEach((child: unknown, position) => {
          visit(child, depth + 1, `${pointer}/${position}`);
        });
        return;
      }
      let exists: boolean;
      let child: unknown;
      if (typeof segment === "string" && isPlainObject(value)) {
        exists = Object.hasOwn(value, segment);
        child = exists ? value[segment] : undefined;
      } else if (typeof segment === "number" && Array.isArray(value)) {
        exists = segment < value.length;
        child = exists ? value[segment] : undefined;
      } else {
        throw new ValueError(`field rule ${index} encountered an incompatible container`);
      }
      if (!exists) {
        stats.missing += 1;
        if (rule.required) {
          throw new ValueError(`required field missing at rule ${index}`);
        }
        return;
      }
      visit(child, depth + 1, `${pointer}/${escapeToken(String(segment))}`);
    };

    visit(data, 0, "");
    reports.push({ rule_index: index, label: rule.label, required: rule.required, ...stats });
  });
  return [resolved, reports];
}
