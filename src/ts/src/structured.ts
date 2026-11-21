/**
 * 상한이 있는 JSON 변환 — 키는 보존되며 암묵적으로 검사하지 않는다. Python ko_pii.structured 대응.
 *
 * TS 표현 차이:
 * - 오프셋·문자 수 상한은 Python 처럼 코드 포인트로 센다. 검출 span 은 UTF-16 (PORTING.md).
 * - JS number 는 ``1`` 과 ``1.0`` 을 구분하지 못해 정숫값 number 를 Python int 로 본다.
 *   ``loadsJson`` 은 안전 범위(2^53) 밖 정수를 ``bigint`` 로 정확히 보존하고, 직접 넘긴 bigint 도
 *   int 로 처리한다 (출력 직렬화 pyDumps/pyJsonDumps 도 bigint 를 그대로 쓴다).
 * - JSON 객체는 프로토타입이 ``Object.prototype``/``null`` 인 평범한 객체만 허용한다.
 * - 키 순서는 Python dict 삽입 순서를 따른다 — ``loadsJson`` 은 원본 순서를, 출력 객체는
 *   입력 순서를 ``io/recordOrder`` 로 기록한다 (JS 열거는 정수형 키를 앞으로 당긴다).
 */
import { type AnonymizationResult, Anonymizer } from "./anonymizer.js";
import { ValueError } from "./core/errors.js";
import { ProcessingMode } from "./core/modes.js";
import { codePointLength } from "./core/strUtils.js";
import { makeDetection, RiskLevel } from "./core/types.js";
import { boundedRules, type FieldRule, type FieldRuleReport, resolveRules } from "./fieldRules.js";
import { recordEntries, setField } from "./io/recordOrder.js";
import { validateLabelFilter } from "./labels.js";
import { normalizeExclusions } from "./patterns/person.js";
import { explain } from "./reporting/explanation.js";
import { pyStrip, strictJsonLoads } from "./vault/reversible.js";

export interface StructuredLimitsOptions {
  maxDepth?: number;
  maxNodes?: number;
  maxChars?: number;
  maxStringChars?: number;
  maxDocuments?: number;
}

/** 구조화 입력 상한 (Python frozen dataclass ``StructuredLimits``). */
export class StructuredLimits {
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxChars: number;
  readonly maxStringChars: number;
  readonly maxDocuments: number;

  constructor(options: StructuredLimitsOptions = {}) {
    this.maxDepth = options.maxDepth ?? 64;
    this.maxNodes = options.maxNodes ?? 100_000;
    this.maxChars = options.maxChars ?? 10_000_000;
    this.maxStringChars = options.maxStringChars ?? 1_000_000;
    this.maxDocuments = options.maxDocuments ?? 10_000;
    for (const value of [
      this.maxDepth,
      this.maxNodes,
      this.maxChars,
      this.maxStringChars,
      this.maxDocuments,
    ]) {
      if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
        throw new ValueError("structured limits must be positive integers");
      }
    }
    if (this.maxDepth > 128) {
      throw new ValueError("max_depth must not exceed 128");
    }
    Object.freeze(this);
  }
}

export interface StructuredField {
  path: string;
  result: AnonymizationResult;
}

export interface StructuredReportOptions {
  /** 객체 키 자체가 PII 일 수 있어 경로는 opt-in 이다. */
  includePaths?: boolean;
  includeTrace?: boolean;
}

export class StructuredResult {
  data: unknown;
  fields: StructuredField[];
  sourceLine: number | null;
  fieldRuleSummary: FieldRuleReport[];

  constructor(
    data: unknown,
    fields: StructuredField[] = [],
    sourceLine: number | null = null,
    fieldRuleSummary: FieldRuleReport[] = [],
  ) {
    this.data = data;
    this.fields = fields;
    this.sourceLine = sourceLine;
    this.fieldRuleSummary = fieldRuleSummary;
  }

  /** 경로는 opt-in — 객체 키 자체가 PII 를 담을 수 있다. */
  report(options: StructuredReportOptions = {}): Record<string, unknown> {
    const rows = this.fields.map((item, index) => {
      const row: Record<string, unknown> = {
        field_index: index,
        ...explain(item.result, { includeTrace: options.includeTrace ?? false }),
      };
      if (options.includePaths) row.path = item.path;
      return row;
    });
    return {
      schema_version: 1,
      contract: "ko-pii-structured-explanation-v1",
      scope: "string_values_and_asserted_integer_fields",
      keys_screened: false,
      source_line: this.sourceLine,
      field_rules: this.fieldRuleSummary,
      fields: rows,
    };
  }
}

/** 매핑 입력 — 평범한 객체 또는 ``Map``. */
export type MappingInput<V> = Readonly<Record<string, V>> | ReadonlyMap<string, V>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Python ``isinstance(x, Mapping)`` 후 ``items()`` — 매핑이 아니면 null. */
function mappingEntries(value: unknown): [unknown, unknown][] | null {
  if (value instanceof Map) return [...value.entries()];
  if (isPlainObject(value)) return recordEntries(value);
  return null;
}

function pointer(parent: string, key: string): string {
  return `${parent}/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`;
}

const BAD_ESCAPE = /~(?![01])/;
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

function isPyInt(value: unknown): value is number | bigint {
  return typeof value === "bigint" || (typeof value === "number" && Number.isInteger(value));
}

function pyIntStr(value: number | bigint): string {
  if (typeof value === "bigint" || Number.isSafeInteger(value)) return value.toString();
  return BigInt(value).toString();
}

/** @internal Python ``_field_exclusions`` — 경로별 정규화된 PERSON 제외어. */
export function fieldExclusions(
  config: MappingInput<Iterable<string>> | null | undefined,
): Map<string, ReadonlySet<string>> {
  if (config === null || config === undefined) return new Map();
  const entries = mappingEntries(config);
  if (entries === null || entries.length > 128) {
    throw new ValueError("field_person_exclusions must be a mapping of at most 128 JSON Pointers");
  }
  const result = new Map<string, ReadonlySet<string>>();
  for (const [path, terms] of entries) {
    if (
      typeof path !== "string" ||
      codePointLength(path) > 4096 ||
      (path !== "" && !path.startsWith("/")) ||
      BAD_ESCAPE.test(path)
    ) {
      throw new ValueError("field_person_exclusions contains an invalid JSON Pointer");
    }
    if (typeof terms === "string" || terms instanceof Uint8Array) {
      throw new ValueError("field person exclusions must be lists of terms, not strings");
    }
    if (
      terms === null ||
      terms === undefined ||
      typeof (terms as { [Symbol.iterator]?: unknown })[Symbol.iterator] !== "function"
    ) {
      throw new ValueError("field person exclusions must be iterable strings");
    }
    const bounded: string[] = [];
    for (const term of terms as Iterable<unknown>) {
      if (
        typeof term !== "string" ||
        !pyStrip(term) ||
        codePointLength(term) > 256 ||
        bounded.length >= 256
      ) {
        throw new ValueError(
          "field person exclusions require at most 256 nonempty terms of at most 256 characters",
        );
      }
      bounded.push(term);
    }
    const normalized = normalizeExclusions(bounded);
    if (
      bounded.some((term) => normalizeExclusions([term]).size === 0) ||
      [...normalized].some((term) => codePointLength(term) > 256)
    ) {
      throw new ValueError(
        "normalized field person exclusions must be nonempty and at most 256 characters",
      );
    }
    result.set(path, normalized);
  }
  return result;
}

function validateExclusions(data: unknown, config: ReadonlyMap<string, ReadonlySet<string>>): void {
  for (const path of config.keys()) {
    let value = data;
    for (const segment of path ? path.split("/").slice(1) : []) {
      const key = segment.replaceAll("~1", "/").replaceAll("~0", "~");
      if (isPlainObject(value) && Object.hasOwn(value, key)) {
        value = value[key];
      } else if (
        Array.isArray(value) &&
        /^(?:0|[1-9][0-9]*)$/.test(key) &&
        key.length <= 10 &&
        Number(key) < value.length
      ) {
        value = value[Number(key)];
      } else {
        throw new ValueError("field_person_exclusions contains a path absent from the document");
      }
    }
    if (value !== null && typeof value !== "string") {
      throw new ValueError("field person exclusions apply only to string or null fields");
    }
  }
}

/** @internal Python ``_labels`` — 정확한 JSON Pointer → 라벨 단언 검증. */
export function fieldLabels(
  labelsInput: MappingInput<string> | null | undefined,
  anon: Anonymizer,
): Record<string, string> {
  let entries: [unknown, unknown][] = [];
  if (labelsInput !== null && labelsInput !== undefined) {
    const found = mappingEntries(labelsInput);
    if (found === null) {
      throw new ValueError("field_labels must be a mapping of exact JSON Pointers");
    }
    entries = found;
  }
  const labels: Record<string, string> = {};
  for (const [path, label] of entries) {
    if (typeof path !== "string" || (path && !path.startsWith("/")) || BAD_ESCAPE.test(path)) {
      throw new ValueError("field_labels contains an invalid JSON Pointer");
    }
    validateLabelFilter([label], "field_labels");
    const l = label as string;
    if ((anon.include !== null && !anon.include.includes(l)) || anon.exclude?.includes(l)) {
      throw new ValueError("field_labels conflicts with include/exclude filters");
    }
    setField(labels, path, l);
  }
  return labels;
}

/** @internal Python ``_validate`` — 노드·깊이·문자 수·순환·타입 검증. */
export function validateStructured(
  data: unknown,
  labels: Readonly<Record<string, string>>,
  limits: StructuredLimits,
): void {
  let nodes = 0;
  let characters = 0;
  const ancestors = new Set<object>();
  const seen = new Set<string>();

  const countText = (text: string): void => {
    const length = codePointLength(text);
    characters += length;
    if (length > limits.maxStringChars || characters > limits.maxChars) {
      throw new ValueError("structured input exceeds character limits");
    }
    if (LONE_SURROGATE.test(text)) {
      throw new ValueError("structured input contains an invalid Unicode surrogate");
    }
  };

  const visit = (value: unknown, path: string, depth: number): void => {
    nodes += 1;
    if (nodes > limits.maxNodes || depth > limits.maxDepth) {
      throw new ValueError("structured input exceeds node or depth limits");
    }
    if (Object.hasOwn(labels, path)) {
      seen.add(path);
      if (value !== null && typeof value !== "string" && !isPyInt(value)) {
        throw new ValueError(
          "asserted fields must be strings, integers or null; floats are unsafe identifiers",
        );
      }
    }
    if (typeof value === "string") {
      countText(value);
    } else if (value === null || typeof value === "boolean") {
      return;
    } else if (isPyInt(value)) {
      countText(pyIntStr(value));
    } else if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new ValueError("structured input must contain finite JSON numbers");
      }
    } else if (Array.isArray(value) || isPlainObject(value)) {
      if (ancestors.has(value)) {
        throw new ValueError("structured input contains a cycle");
      }
      ancestors.add(value);
      if (Array.isArray(value)) {
        value.forEach((child: unknown, index) => {
          visit(child, pointer(path, String(index)), depth + 1);
        });
      } else {
        for (const [key, child] of recordEntries(value)) {
          countText(key);
          visit(child, pointer(path, key), depth + 1);
        }
      }
      ancestors.delete(value);
    } else {
      throw new ValueError("structured input contains a non-JSON value");
    }
  };

  visit(data, "", 0);
  if (Object.keys(labels).some((path) => !seen.has(path))) {
    throw new ValueError("field_labels contains a path absent from the document");
  }
}

export interface AnonymizeJsonOptions {
  anonymizer?: Anonymizer | null;
  fieldLabels?: MappingInput<string> | null;
  limits?: StructuredLimits | null;
  fieldRules?: Iterable<FieldRule> | null;
  fieldPersonExclusions?: MappingInput<Iterable<string>> | null;
}

/** JSON 값을 복사해 하나의 Anonymizer/Vault 로 처리한다 (Python ``anonymize_json``).
 *
 * 명시 필드는 추측이 아니라 라벨 단언이다 — 문자열/정수 전체가 검출 임계값과 무관하게 변환된다
 * (AUDIT 제외). 정수는 변환될 때만 문자열이 된다. 키는 보존된다. 키·일반 숫자·미검출 문자열의
 * PII 에 대해서는 아무것도 주장하지 않는다.
 *
 * ``fieldPersonExclusions`` 는 지정된 기존 문자열/null JSON Pointer 에서만 정확한 정규화 PERSON
 * 용어를 추가로 제외한다. 명시 단언이 여전히 우선한다.
 */
export function anonymizeJson(data: unknown, options: AnonymizeJsonOptions = {}): StructuredResult {
  const anon = options.anonymizer ?? new Anonymizer();
  const policy = options.limits ?? new StructuredLimits();
  let labels = fieldLabels(options.fieldLabels, anon);
  validateStructured(data, labels, policy);
  const exclusions = fieldExclusions(options.fieldPersonExclusions);
  validateExclusions(data, exclusions);
  const rules = boundedRules(options.fieldRules);
  for (const rule of rules) fieldLabels({ "": rule.label }, anon);
  const [resolved, ruleSummary] = resolveRules(data, labels, rules);
  labels = resolved;
  validateStructured(data, labels, policy);
  const fields: StructuredField[] = [];

  const transform = (value: unknown, path: string): unknown => {
    const label = Object.hasOwn(labels, path) ? labels[path] : undefined;
    if (label !== undefined && value !== null) {
      const text = typeof value === "string" ? value : pyIntStr(value as number | bigint);
      const detections = text
        ? [
            makeDetection({
              label,
              text,
              start: 0,
              end: text.length,
              riskLevel: RiskLevel.HIGH,
              evidence: ["field:asserted"],
              ruleId: "field.asserted.v1",
            }),
          ]
        : [];
      const result = anon.processDetections(text, detections, { asserted: true });
      fields.push({ path, result });
      return anon.mode === ProcessingMode.AUDIT ? value : result.text;
    }
    if (typeof value === "string") {
      const local = exclusions.get(path);
      const result =
        local !== undefined
          ? anon.processWithExclusions(value, new Set([...anon.personExclusions, ...local]))
          : anon.process(value);
      fields.push({ path, result });
      return result.text;
    }
    if (Array.isArray(value)) {
      return value.map((child: unknown, index) => transform(child, pointer(path, String(index))));
    }
    if (isPlainObject(value)) {
      const out: Record<string, unknown> = {};
      for (const [key, child] of recordEntries(value)) {
        setField(out, key, transform(child, pointer(path, key)));
      }
      return out;
    }
    return value;
  };

  return new StructuredResult(transform(data, ""), fields, null, ruleSummary);
}

/** 엄격한 상한 JSON 파싱 — 잘못된 원문을 오류에 반사하지 않는다 (Python ``loads_json``). */
export function loadsJson(
  text: string,
  options: { limits?: StructuredLimits | null } = {},
): unknown {
  const policy = options.limits ?? new StructuredLimits();
  if (typeof text !== "string" || codePointLength(text) > policy.maxChars) {
    throw new ValueError("JSON input exceeds character limits");
  }
  let data: unknown;
  try {
    data = strictJsonLoads(text);
  } catch {
    throw new ValueError("invalid JSON, duplicate key, non-finite number or excessive nesting");
  }
  validateStructured(data, {}, policy);
  return data;
}

/** 전체 상한 입력을 처리 전에 검증한다 — 부분 반환 없음 (Python ``anonymize_jsonl``).
 *
 * 처리 중 검출기가 실패하면 공유 Vault 상태는 바뀔 수 있다. 외부 Vault/감사 서비스에 걸친
 * 트랜잭션이 아니다.
 */
export function anonymizeJsonl(
  text: string,
  options: AnonymizeJsonOptions = {},
): StructuredResult[] {
  const policy = options.limits ?? new StructuredLimits();
  if (typeof text !== "string" || codePointLength(text) > policy.maxChars) {
    throw new ValueError("JSONL input exceeds character limits");
  }
  const anon = options.anonymizer ?? new Anonymizer();
  const labels = fieldLabels(options.fieldLabels, anon);
  const exclusions = fieldExclusions(options.fieldPersonExclusions);
  const rules = boundedRules(options.fieldRules);
  for (const rule of rules) fieldLabels({ "": rule.label }, anon);
  const documents: [number, unknown][] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    const number = i + 1;
    if (!pyStrip(line)) continue;
    if (documents.length >= policy.maxDocuments) {
      throw new ValueError("JSONL input exceeds document limits");
    }
    let data: unknown;
    try {
      data = loadsJson(line, { limits: policy });
      validateStructured(data, labels, policy);
      const [resolved] = resolveRules(data, labels, rules);
      validateStructured(data, resolved, policy);
      validateExclusions(data, exclusions);
    } catch (e) {
      if (e instanceof ValueError) {
        throw new ValueError(`invalid JSONL document at line ${number}`);
      }
      throw e;
    }
    documents.push([number, data]);
  }
  if (documents.length === 0) {
    throw new ValueError("JSONL input must contain at least one document");
  }
  return documents.map(([number, data]) => {
    const result = anonymizeJson(data, {
      anonymizer: anon,
      fieldLabels: labels,
      limits: policy,
      fieldRules: rules,
      fieldPersonExclusions: new Map([...exclusions].map(([k, v]) => [k, [...v]])),
    });
    result.sourceLine = number;
    return result;
  });
}
