/**
 * 표 / 컬럼 단위 가명화 — CSV·XLSX·DB record 처리.
 * Python `ko_pii.tabular` 1:1 포트.
 *
 * 평문 텍스트로 변환하지 않고 *컬럼 단위* 로 처리:
 * - 헤더 명을 PII 카테고리에 자동 매핑 (성명 → PERSON, 주민번호 → RRN, ...)
 * - 매핑된 열의 셀 전체를 해당 카테고리로 단언하여 변환
 * - 가명화 후 *같은 표 구조* 유지
 *
 * 열 매핑은 호출자 스키마의 단언이며 실제 개인정보 여부나 법적 익명성 판정이 아니다.
 *
 * TS 표현 차이: Python ``csv.DictReader`` 의 ``None`` restkey(초과 셀) 는 TS 에서 ``""`` 키
 * ({@link RESTKEY}) 로 담긴다. ``""`` 키의 값이 배열이면 초과 셀로, 스칼라면 일반 열로 본다.
 * JS number 는 ``123`` 과 ``123.0`` 을 구분하지 못하므로 정숫값 number 는 Python int 로 취급한다.
 */

import { Anonymizer } from "./anonymizer.js";
import { ValueError } from "./core/errors.js";
import { ProcessingMode } from "./core/modes.js";
import { pyTypeName, regexEscape } from "./core/strUtils.js";
import { RiskLevel } from "./core/types.js";
import { normalizeUnicode } from "./core/unicodeNorm.js";
import {
  ENGLISH_SUBJECTS,
  KOREAN_SUBJECTS,
  TABLE_HEADER_MAP,
} from "./dictionaries/generated/table_headers.js";
import { RESTKEY } from "./io/csvReader.js";
import { recordEntries, recordKeys, setField } from "./io/recordOrder.js";
import { legalBasisFor, riskFloorFor } from "./legal/mapping.js";
import { pseudonymizeValue } from "./modes/fpe.js";
import { maskValue } from "./modes/partial.js";
import { labelToHangul } from "./modes/redact.js";
import { ReversibleVault } from "./vault/reversible.js";

/** 헤더 → PII 라벨 매핑 (생성 사전 — Python dictionaries/table_headers.py). */
const HEADER_MAP: Readonly<Record<string, string>> = TABLE_HEADER_MAP;

const SCHEMA_AMBIGUOUS_HEADERS: ReadonlySet<string> = new Set([
  "name",
  "address",
  "url",
  "ip",
  "이름",
  "환자",
  "주민",
  "카드",
  "메일",
  "우편",
  "차량",
  "계좌",
]);

/** Evidence for an exact schema-column classification. */
export interface SchemaColumnClassification {
  column: string;
  label: string;
  confidence: number;
  match: "exact" | "normalized";
  matchedHeader: string;
  ambiguous: boolean;
}

/** Evidence for an exact schema-column classification. */
export interface SchemaColumnClassification {
  column: string;
  label: string;
  confidence: number;
  match: "exact" | "normalized";
  matchedHeader: string;
  ambiguous: boolean;
}

/** Python str.isspace() / re `\s` 문자 클래스 — JS `\s` 와 달리 U+001C–1F·U+0085 포함, U+FEFF 제외. */
const PY_WS =
  "[\\t\\n\\u000b\\u000c\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const RE_PY_WS_RUN = new RegExp(`${PY_WS}+`, "g");
const RE_PY_STRIP = new RegExp(`^${PY_WS}+|${PY_WS}+$`, "g");

function pyStrip(s: string): string {
  return s.replace(RE_PY_STRIP, "");
}

/** 조회용 뷰만 정규화 — 출력 열 이름은 그대로 둔다. (Python `_normalize_header`) */
function normalizeHeader(h: string): string {
  const [normalized] = normalizeUnicode(h);
  return pyStrip(normalized.replace(RE_PY_WS_RUN, ""));
}

function normalizeSchemaHeader(header: string): string {
  return normalizeHeader(header).toLowerCase(); // Python str.casefold 대응
}

/**
 * Classify schema columns without substring inference.
 *
 * Exact aliases receive confidence ``1.0`` and whitespace/case-normalized
 * aliases receive ``0.95``. Generic names such as ``name`` or ``address`` are
 * still returned as review evidence with confidence ``0.60``. Callers should
 * set an explicit threshold when compiling a blocking SQL policy.
 */
export function classifySchemaColumns(
  headers: Iterable<string>,
): Record<string, SchemaColumnClassification> {
  const aliases = new Map<string, Array<[alias: string, label: string]>>();
  for (const [alias, label] of Object.entries(HEADER_MAP)) {
    const norm = normalizeSchemaHeader(alias);
    const list = aliases.get(norm);
    if (list === undefined) aliases.set(norm, [[alias, label]]);
    else list.push([alias, label]);
  }

  const classifications: Record<string, SchemaColumnClassification> = {};
  for (const header of headers) {
    if (typeof header !== "string" || !pyStrip(header)) continue;
    const normalized = normalizeSchemaHeader(header);
    const matches = aliases.get(normalized);
    if (matches === undefined) continue;

    const labels = new Set(matches.map(([, label]) => label));
    if (labels.size !== 1) {
      // Conflicting aliases are unsafe to compile into a blocking policy.
      continue;
    }
    const label = [...labels][0] as string;
    const exactAlias = matches.find(([alias]) => alias === header)?.[0] ?? null;
    const match: "exact" | "normalized" = exactAlias !== null ? "exact" : "normalized";
    const ambiguous = SCHEMA_AMBIGUOUS_HEADERS.has(normalized);
    const confidence = ambiguous ? 0.6 : match === "exact" ? 1.0 : 0.95;
    classifications[header] = {
      column: header,
      label,
      confidence,
      match,
      matchedHeader: exactAlias ?? (matches[0] as [string, string])[0],
      ambiguous,
    };
  }
  return classifications;
}

/** Python ``_QUALIFIED_HEADER`` (re.IGNORECASE, fullmatch). ``.`` 은 Python 처럼 ``\n`` 만 제외. */
const QUALIFIED_HEADER = new RegExp(
  `^(?:(?:${KOREAN_SUBJECTS.map(regexEscape).join("|")})${PY_WS.slice(0, -1)}_-]*([^\\n]+)` +
    `|(?:${ENGLISH_SUBJECTS.map(regexEscape).join("|")})${PY_WS.slice(0, -1)}_-]+([^\\n]+))$`,
  "iu",
);

export type HeaderPolicy = "conservative" | "legacy";

function checkHeaderPolicy(headerPolicy: unknown): void {
  if (headerPolicy !== "conservative" && headerPolicy !== "legacy") {
    throw new ValueError(`Unknown header_policy: ${String(headerPolicy)}`);
  }
}

/**
 * 각 헤더에 대해 추정 PII 라벨 반환 (없으면 키 부재).
 *
 * >>> map_columns(["성명", "주민번호", "메모"])
 * {'성명': 'PERSON', '주민번호': 'RRN'}
 *
 * 기본(``conservative``)은 별칭 정확 일치(공백·대소문자 무시) 또는 알려진 주체 한정어 + 정확
 * 별칭(``신청인 연락처`` 등)만 매핑한다. 알 수 없거나 혼합된 필드는 매핑하지 않는다 — 도메인
 * 헤더는 명시적 ``columnMap`` 을 쓸 것. ``legacy`` 는 예전 첫 부분 문자열 매칭(오탐 가능)을 복원한다.
 */
export function mapColumns(
  headers: Iterable<string>,
  options: { headerPolicy?: HeaderPolicy } = {},
): Record<string, string> {
  const headerPolicy = options.headerPolicy ?? "conservative";
  checkHeaderPolicy(headerPolicy);
  const mapping: Record<string, string> = {};
  if (headerPolicy === "conservative") {
    const names = [...headers];
    for (const [h, c] of Object.entries(classifySchemaColumns(names))) mapping[h] = c.label;
    for (const h of names) {
      if (typeof h !== "string" || Object.hasOwn(mapping, h)) continue;
      const [normalized] = normalizeUnicode(h);
      const match = QUALIFIED_HEADER.exec(pyStrip(normalized));
      if (match !== null) {
        const field = (match[1] || match[2]) as string;
        const classified = classifySchemaColumns([field]);
        if (Object.hasOwn(classified, field)) {
          mapping[h] = (classified[field] as SchemaColumnClassification).label;
        }
      }
    }
    return mapping;
  }

  for (const h of headers) {
    const norm = normalizeHeader(h);
    // Python `h in _HEADER_MAP` 은 own property 만 본다 — JS `in` 은 프로토타입
    // 체인까지 보므로 ("toString" 등) Object.hasOwn 으로 대응한다.
    if (Object.hasOwn(HEADER_MAP, h)) {
      mapping[h] = HEADER_MAP[h] as string;
    } else if (Object.hasOwn(HEADER_MAP, norm)) {
      mapping[h] = HEADER_MAP[norm] as string;
    } else {
      // 부분 매칭 — "신청인 성명" 같은 합성 헤더
      const [normalized] = normalizeUnicode(h);
      for (const [key, lbl] of Object.entries(HEADER_MAP)) {
        if (key.length >= 2 && normalized.includes(key)) {
          mapping[h] = lbl;
          break;
        }
      }
    }
  }
  return mapping;
}

/**
 * 컬럼이 명시적 라벨일 때 — 검출기 점수 우회하고 cell 전체를 가명화.
 * (Python `_force_anonymize_cell`)
 */
function forceAnonymizeCell(
  value: string,
  label: string,
  strategy: string,
  vault: ReversibleVault,
): string {
  const risk = riskFloorFor(label) ?? RiskLevel.MEDIUM;
  if (strategy === "tokenize") {
    return vault.store(label, value, risk, legalBasisFor(label));
  }
  if (strategy === "redact") {
    return `[${labelToHangul(label)}]`;
  }
  if (strategy === "asterisk") {
    return "*".repeat([...value].length); // Python len() = 코드 포인트 수
  }
  if (strategy === "partial") {
    return maskValue(label, value);
  }
  if (strategy === "hashed") {
    const fp = vault.fingerprint(label, value);
    return `<${label}:${fp.slice(0, 12)}>`;
  }
  if (strategy === "fpe") {
    const fp = vault.fingerprint(label, value);
    const newVal = pseudonymizeValue(label, value, fp);
    vault.store(label, value, risk, legalBasisFor(label), -1, { fpe_value: newVal });
    return newVal;
  }
  return value;
}

const VALID_STRATEGIES: ReadonlySet<string> = new Set([
  "tokenize",
  "redact",
  "asterisk",
  "partial",
  "hashed",
  "fpe",
]);

export interface AnonymizeValueOptions {
  strategy?: string;
  vault?: ReversibleVault | null;
}

function validCellLabel(label: unknown): label is string {
  return typeof label === "string" && pyStrip(label) !== "" && !/[<>\r\n]/.test(label);
}

/**
 * Anonymize an explicitly typed value without detector inference.
 *
 * This is intended for schema-aware database results where upstream lineage
 * already established the PII label. It must not be used to label unknown
 * free text.
 */
export function anonymizeValue(
  value: string,
  label: string,
  options: AnonymizeValueOptions = {},
): [output: string, vault: ReversibleVault] {
  if (typeof value !== "string") {
    throw new TypeError(`value must be str, got ${pyTypeName(value)}`);
  }
  if (!validCellLabel(label)) {
    throw new ValueError("label must be nonempty and contain no token delimiters or newlines");
  }
  const strategy = options.strategy ?? "tokenize";
  if (!VALID_STRATEGIES.has(strategy)) {
    throw new ValueError(`Unknown strategy: ${strategy}`);
  }
  // Python `vault if vault is not None else ReversibleVault()` — 빈 명시 vault 도 유지.
  const activeVault = options.vault ?? new ReversibleVault();
  return [forceAnonymizeCell(value, label, strategy, activeVault), activeVault];
}

/** 표 셀 — 스칼라, 또는 초과 셀({@link RESTKEY}) 의 문자열/null 배열. */
export type TableCell = string | number | bigint | boolean | null | (string | null)[];
export type TableRecord = Record<string, TableCell>;

function isRowMapping(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Map) &&
    !(value instanceof Uint8Array)
  );
}

/** Python int 판정 — 정숫값 number(1.0 구분 불가) 와 bigint. */
function isPyInt(value: unknown): value is number | bigint {
  return typeof value === "bigint" || (typeof value === "number" && Number.isInteger(value));
}

function pyIntStr(value: number | bigint): string {
  if (typeof value === "bigint" || Number.isSafeInteger(value)) return value.toString();
  return BigInt(value).toString();
}

/** Python ``_table_records`` — 변환 전 전체 표 검증·얕은 복사 (입력 별칭 방지). */
function tableRecords(records: unknown): TableRecord[] {
  if (!Array.isArray(records)) {
    throw new ValueError("records must be a sequence of row mappings");
  }
  const checked: TableRecord[] = [];
  records.forEach((record: unknown, index) => {
    if (!isRowMapping(record)) {
      throw new ValueError(`record ${index} must be a row mapping`);
    }
    const row: TableRecord = {};
    for (const [header, value] of recordEntries(record)) {
      if (header === RESTKEY && Array.isArray(value)) {
        if (value.some((item) => item !== null && typeof item !== "string")) {
          throw new ValueError(`record ${index} CSV overflow must be a list of strings or null`);
        }
        setField(row, header, [...(value as (string | null)[])]);
        continue;
      }
      if (
        value !== null &&
        typeof value !== "string" &&
        typeof value !== "number" &&
        typeof value !== "bigint" &&
        typeof value !== "boolean"
      ) {
        throw new ValueError(
          `record ${index} cells must be scalars; use anonymize_json for nested data`,
        );
      }
      if (typeof value === "number" && !Number.isFinite(value)) {
        throw new ValueError(`record ${index} cells must contain finite numbers`);
      }
      setField(row, header, value);
    }
    checked.push(row);
  });
  return checked;
}

export interface AnonymizeRecordsOptions {
  /** ``{header: label}`` 매핑 명시. 미지정 시 ``mapColumns`` 로 자동 추론 (빈 매핑도 명시로 우선). */
  columnMap?: Record<string, string> | null;
  mode?: ProcessingMode;
  strategy?: string;
  vault?: ReversibleVault | null;
  /** 자동 매핑 정책 ({@link mapColumns} 참조). */
  headerPolicy?: HeaderPolicy;
}

/**
 * 레코드(표) 단위 가명화 — 같은 구조 유지.
 *
 * 매핑된 셀은 문자열/정수/null 이며, 비매핑 셀은 일반 스칼라를 보존한다. 중첩 값은 JSON API
 * (``anonymizeJson``) 를 쓸 것. 비어 있지 않은 입력에서 어느 행에도 없는 명시적 열은 오류다.
 * ``AUDIT`` 은 셀을 보존하고 Vault 에 쓰지 않는다. 그 밖의 모드에서 매핑된 열은 명시적 라벨
 * 단언으로 검출기 임계값을 우회한다. 단언된 정수는 변환될 때만 문자열이 된다. 초과 셀만
 * 문자열/null 배열을 담을 수 있고 Anonymizer 검출 정책을 따른다.
 *
 * Returns (anonymizedRecords, vault): 같은 dict 구조의 가명화 결과 + 공유된
 * vault. 매핑된 컬럼 *외* 의 값들은 원본 그대로 보존.
 */
export function anonymizeRecords(
  records: readonly Readonly<Record<string, unknown>>[],
  options: AnonymizeRecordsOptions = {},
): [out: TableRecord[], vault: ReversibleVault] {
  const {
    columnMap = null,
    mode = ProcessingMode.STRICT,
    strategy = "tokenize",
    vault = null,
    headerPolicy = "conservative",
  } = options;
  checkHeaderPolicy(headerPolicy);
  const checked = tableRecords(records);
  let activeColumnMap: Record<string, string>;
  if (columnMap !== null && columnMap !== undefined) {
    if (
      !isRowMapping(columnMap) ||
      Object.entries(columnMap as Record<string, unknown>).some(
        ([key, label]) => !pyStrip(key) || !validCellLabel(label),
      )
    ) {
      throw new ValueError(
        "column_map must map non-empty column names to valid labels without token delimiters or newlines",
      );
    }
    if (
      checked.length > 0 &&
      Object.keys(columnMap).some((key) => !checked.some((rec) => Object.hasOwn(rec, key)))
    ) {
      throw new ValueError("column_map contains columns absent from the records");
    }
    activeColumnMap = columnMap;
  } else {
    // 전체 레코드 키의 합집합에서 추론 — records[0] 만 보면 희소/이질 레코드의
    // PII 컬럼이 미매핑돼 평문 통과한다 (#10).
    const allKeys = new Set<string>();
    for (const r of checked) {
      for (const k of recordKeys(r)) {
        if (k === RESTKEY && Array.isArray(r[k])) continue; // Python None 키
        allKeys.add(k);
      }
    }
    activeColumnMap = mapColumns(allKeys, { headerPolicy });
  }
  const labelFor = (header: string): string | undefined =>
    Object.hasOwn(activeColumnMap, header) ? activeColumnMap[header] : undefined;

  // 어떤 변환이 Vault 에 쓰기 전에 표 전체를 검증한다.
  checked.forEach((record, index) => {
    for (const [header, value] of recordEntries(record)) {
      if ((header === RESTKEY && Array.isArray(value)) || value === null) continue;
      if (labelFor(header) === undefined) continue;
      if (typeof value !== "string" && !isPyInt(value)) {
        throw new ValueError(`record ${index} mapped cells must be strings, integers or null`);
      }
      if (mode !== ProcessingMode.AUDIT)
        setField(record, header, typeof value === "string" ? value : pyIntStr(value));
    }
  });

  const auto = new Anonymizer(mode, strategy, vault);
  const activeVault = auto.vault;
  if (mode === ProcessingMode.AUDIT) return [checked, activeVault];
  const out: TableRecord[] = [];
  for (const rec of checked) {
    // 헤더는 임의 문자열 — "__proto__"/"constructor" 같은 키가 프로토타입 체인을
    // 타지 않도록 own-property 로만 읽고 쓴다.
    // 순회·대입 모두 삽입 순서 기준(recordOrder) — 정수형 헤더도 Python dict 순서를 따른다.
    const newRec: TableRecord = {};
    for (const [header, value] of recordEntries(rec)) {
      if (header === RESTKEY && Array.isArray(value)) {
        // csv.DictReader restkey: 헤더보다 셀이 많은 ragged row 의 초과 셀이
        // list 로 수집됨. 정상 컬럼이 아니라 *초과 셀* 이므로 자동 검출로
        // 스캔해 평문 PII 통과를 막는다 (#11).
        setField(
          newRec,
          header,
          value.map((v) => (typeof v === "string" && v ? auto.process(v).text : v)),
        );
        continue;
      }
      const label = labelFor(header);
      if (!label || value === null || value === "") {
        setField(newRec, header, value);
        continue;
      }
      // 컬럼 매핑 = 명시적 라벨 단언 → 검출기 임계값 우회
      setField(newRec, header, forceAnonymizeCell(value as string, label, strategy, activeVault));
    }
    out.push(newRec);
  }

  return [out, activeVault];
}
