/**
 * 표 / 컬럼 단위 가명화 — CSV·XLSX·DB record 처리.
 * Python `ko_pii.tabular` 1:1 포트.
 *
 * 평문 텍스트로 변환하지 않고 *컬럼 단위* 로 처리:
 * - 헤더 명을 PII 카테고리에 자동 매핑 (성명 → PERSON, 주민번호 → RRN, ...)
 * - 각 셀에 대해 *해당 카테고리만* 검출 (다른 검출기 비활성 → 정확도 ↑)
 * - 가명화 후 *같은 표 구조* 유지
 *
 * 법적 근거: 개인정보보호법 제28조의2~5 (가명정보 처리 특례). 구조 보존이
 * 분석 호환성에 직결.
 */

import { Anonymizer } from "./anonymizer.js";
import { ValueError } from "./core/errors.js";
import { ProcessingMode } from "./core/modes.js";
import { RiskLevel } from "./core/types.js";
import type { CsvRecord } from "./io/csvReader.js";
import { recordEntries, recordKeys, setField } from "./io/recordOrder.js";
import { legalBasisFor, riskFloorFor } from "./legal/mapping.js";
import { FPE_BY_LABEL, fpeDefault } from "./modes/fpe.js";
import { maskValue } from "./modes/partial.js";
import { labelToHangul } from "./modes/redact.js";
import { ReversibleVault } from "./vault/reversible.js";

/** 헤더 → PII 라벨 매핑 (한국 공문서·민원·인사 도메인 빈출 표현) */
const HEADER_MAP: Readonly<Record<string, string>> = {
  // 성명
  성명: "PERSON",
  이름: "PERSON",
  성함: "PERSON",
  "성  명": "PERSON",
  신청인: "PERSON",
  민원인: "PERSON",
  기안자: "PERSON",
  수신자: "PERSON",
  당사자: "PERSON",
  환자명: "PERSON",
  환자: "PERSON",
  name: "PERSON",
  Name: "PERSON",
  NAME: "PERSON",
  "성명(한글)": "PERSON",

  // RRN
  주민번호: "RRN",
  주민등록번호: "RRN",
  주민: "RRN",
  "주민등록번호 13자리": "RRN",
  rrn: "RRN",
  RRN: "RRN",

  // 외국인등록번호
  외국인등록번호: "FRN",
  외등번호: "FRN",

  // 사업자번호
  사업자등록번호: "BUSINESS_REG",
  사업자번호: "BUSINESS_REG",
  biz_reg: "BUSINESS_REG",

  // 법인번호
  법인등록번호: "CORP_REG",
  법인번호: "CORP_REG",

  // 운전면허
  운전면허번호: "DRIVER_LICENSE",
  면허번호: "DRIVER_LICENSE",

  // 여권
  여권번호: "PASSPORT",
  여권: "PASSPORT",

  // 카드
  카드번호: "CARD",
  신용카드번호: "CARD",
  체크카드번호: "CARD",

  // 의료보험
  건강보험증번호: "MEDICAL_INSURANCE",
  건강보험번호: "MEDICAL_INSURANCE",

  // 처방
  처방번호: "PRESCRIPTION_ID",
  처방전번호: "PRESCRIPTION_ID",

  // 전화
  전화번호: "PHONE",
  연락처: "PHONE",
  휴대전화: "PHONE",
  휴대폰: "PHONE",
  휴대폰번호: "PHONE",
  핸드폰: "PHONE",
  이동전화: "PHONE",
  휴대전화번호: "PHONE",
  phone: "PHONE",
  tel: "PHONE",
  Tel: "PHONE",
  TEL: "PHONE",
  Phone: "PHONE",

  // 팩스
  팩스: "FAX",
  팩스번호: "FAX",

  // 이메일
  이메일: "EMAIL",
  전자우편: "EMAIL",
  메일: "EMAIL",
  email: "EMAIL",
  Email: "EMAIL",
  "E-mail": "EMAIL",
  EMAIL: "EMAIL",

  // 주소
  주소: "ADDRESS",
  거주지: "ADDRESS",
  "거주지 주소": "ADDRESS",
  도로명주소: "ADDRESS",
  지번주소: "ADDRESS",
  address: "ADDRESS",
  Address: "ADDRESS",

  // 우편번호
  우편번호: "POSTAL_CODE",
  우편: "POSTAL_CODE",
  zip: "POSTAL_CODE",
  zipcode: "POSTAL_CODE",
  Zip: "POSTAL_CODE",

  // 차량
  차량번호: "VEHICLE",
  자동차번호: "VEHICLE",
  차량: "VEHICLE",

  // 계좌
  계좌번호: "ACCOUNT",
  계좌: "ACCOUNT",
  통장번호: "ACCOUNT",
  은행계좌: "ACCOUNT",

  // 사번
  사번: "EMPLOYEE_ID",
  공무원번호: "EMPLOYEE_ID",
  직원번호: "EMPLOYEE_ID",
  교번: "EMPLOYEE_ID",

  // IP
  IP: "IP",
  ip: "IP",
  IP주소: "IP",
  ip_address: "IP",

  // URL
  URL: "URL",
  url: "URL",
  홈페이지: "URL",
  웹사이트: "URL",

  // 토지
  PNU: "PNU",
  필지고유번호: "PNU",
  토지고유번호: "PNU",

  // 약품
  약품코드: "EDI_DRUG",
  의약품코드: "EDI_DRUG",

  // 사건번호
  사건번호: "COURT_CASE",
};

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

/** Python str.isspace() / re `\s` 문자 클래스 — JS `\s` 와 달리 U+001C–1F·U+0085 포함, U+FEFF 제외. */
const PY_WS =
  "[\\t\\n\\u000b\\u000c\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const RE_PY_WS_RUN = new RegExp(`${PY_WS}+`, "g");
const RE_PY_STRIP = new RegExp(`^${PY_WS}+|${PY_WS}+$`, "g");

function pyStrip(s: string): string {
  return s.replace(RE_PY_STRIP, "");
}

/** 공백·괄호 등 정규화. (Python `_normalize_header`) */
function normalizeHeader(h: string): string {
  return pyStrip(h.replace(RE_PY_WS_RUN, ""));
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
    const label = [...labels][0]!;
    const exactAlias = matches.find(([alias]) => alias === header)?.[0] ?? null;
    const match: "exact" | "normalized" = exactAlias !== null ? "exact" : "normalized";
    const ambiguous = SCHEMA_AMBIGUOUS_HEADERS.has(normalized);
    const confidence = ambiguous ? 0.6 : match === "exact" ? 1.0 : 0.95;
    classifications[header] = {
      column: header,
      label,
      confidence,
      match,
      matchedHeader: exactAlias ?? matches[0]![0],
      ambiguous,
    };
  }
  return classifications;
}

/**
 * 각 헤더에 대해 추정 PII 라벨 반환 (없으면 키 부재).
 *
 * >>> map_columns(["성명", "주민번호", "메모"])
 * {'성명': 'PERSON', '주민번호': 'RRN'}
 */
export function mapColumns(headers: Iterable<string>): Record<string, string> {
  const mapping: Record<string, string> = {};
  for (const h of headers) {
    const norm = normalizeHeader(h);
    // Python `h in _HEADER_MAP` 은 own property 만 본다 — JS `in` 은 프로토타입
    // 체인까지 보므로 ("toString" 등) Object.hasOwn 으로 대응한다.
    if (Object.hasOwn(HEADER_MAP, h)) {
      mapping[h] = HEADER_MAP[h]!;
    } else if (Object.hasOwn(HEADER_MAP, norm)) {
      mapping[h] = HEADER_MAP[norm]!;
    } else {
      // 부분 매칭 — "신청인 성명" 같은 합성 헤더
      for (const [key, lbl] of Object.entries(HEADER_MAP)) {
        if (key.length >= 2 && h.includes(key)) {
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
    const fn = FPE_BY_LABEL.get(label) ?? fpeDefault;
    const newVal = fn(value, fp);
    vault.store(label, value, risk, legalBasisFor(label), -1, { fpe_value: newVal });
    return newVal;
  }
  return value;
}

/** Python `type(value).__name__` 대응 (에러 메시지 호환). */
function pyTypeName(value: unknown): string {
  if (value === null) return "NoneType";
  if (Array.isArray(value)) return "list";
  switch (typeof value) {
    case "string":
      return "str";
    case "boolean":
      return "bool";
    case "number":
      return Number.isInteger(value) ? "int" : "float";
    case "bigint":
      return "int";
    case "object":
      return "dict";
    default:
      return typeof value;
  }
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
  if (typeof label !== "string" || !label.trim()) {
    throw new ValueError("label must be a non-empty string");
  }
  const strategy = options.strategy ?? "tokenize";
  if (!VALID_STRATEGIES.has(strategy)) {
    throw new ValueError(`Unknown strategy: ${strategy}`);
  }
  // Python `vault or ReversibleVault()` — ReversibleVault.__len__ 때문에 *빈*
  // vault 도 falsy 로 평가되어 새 vault 로 대체된다 (실측 확인).
  const activeVault =
    options.vault !== null && options.vault !== undefined && options.vault.size > 0
      ? options.vault
      : new ReversibleVault();
  return [forceAnonymizeCell(value, label, strategy, activeVault), activeVault];
}

export interface AnonymizeRecordsOptions {
  /** ``{header: label}`` 매핑 명시. 미지정 시 ``mapColumns`` 로 자동 추론. */
  columnMap?: Record<string, string> | null;
  mode?: ProcessingMode;
  strategy?: string;
  vault?: ReversibleVault | null;
}

/** Anonymizer 생성 인자 (Python Anonymizer(mode=..., strategy=..., vault=...) 대응). */
function newAnonymizer(mode: ProcessingMode, strategy: string, vault: ReversibleVault): Anonymizer {
  return new Anonymizer(mode, strategy, vault);
}

/**
 * 레코드(표) 단위 가명화 — 같은 구조 유지.
 *
 * Returns (anonymizedRecords, vault): 같은 dict 구조의 가명화 결과 + 공유된
 * vault. 매핑된 컬럼 *외* 의 값들은 원본 그대로 보존.
 */
export function anonymizeRecords(
  records: readonly CsvRecord[],
  options: AnonymizeRecordsOptions = {},
): [out: CsvRecord[], vault: ReversibleVault] {
  const {
    columnMap = null,
    mode = ProcessingMode.STRICT,
    strategy = "tokenize",
    vault = null,
  } = options;
  if (records.length === 0) {
    // Python `return [], (vault or ReversibleVault())` — 빈 vault 는 falsy.
    return [
      [],
      vault !== null && vault !== undefined && vault.size > 0 ? vault : new ReversibleVault(),
    ];
  }

  let activeColumnMap = columnMap;
  if (activeColumnMap === null) {
    // 전체 레코드 키의 합집합에서 추론 — records[0] 만 보면 희소/이질 레코드의
    // PII 컬럼이 미매핑돼 평문 통과한다 (#10).
    const allKeys = new Set<string>();
    for (const r of records) {
      for (const k of recordKeys(r)) {
        if (typeof k === "string") allKeys.add(k);
      }
    }
    activeColumnMap = mapColumns(allKeys);
  }

  const activeVault = vault ?? new ReversibleVault();
  const auto = newAnonymizer(mode, strategy, activeVault);
  const out: CsvRecord[] = [];
  for (const rec of records) {
    // 헤더는 임의 문자열 — "__proto__"/"constructor" 같은 키가 프로토타입 체인을
    // 타지 않도록 own-property 로만 읽고 쓴다.
    // 순회·대입 모두 삽입 순서 기준(recordOrder) — 정수형 헤더도 Python dict 순서를 따른다.
    const newRec: CsvRecord = {};
    const put = (key: string, cell: CsvRecord[string]): void => setField(newRec, key, cell);
    for (const [header, value] of recordEntries(rec)) {
      if (Array.isArray(value)) {
        // csv.DictReader restkey: 헤더보다 셀이 많은 ragged row 의 초과 셀이
        // list 로 수집됨. 정상 컬럼이 아니라 *초과 셀* 이므로 자동 검출로
        // 스캔해 평문 PII 통과를 막는다 (#11).
        put(
          header,
          value.map((v) => (typeof v === "string" && v ? auto.process(v).text : v)),
        );
        continue;
      }
      const label =
        activeColumnMap && Object.hasOwn(activeColumnMap, header)
          ? activeColumnMap[header]
          : undefined;
      if (label === undefined || !label || !value) {
        put(header, value);
        continue;
      }
      // 컬럼 매핑 = 명시적 라벨 단언 → 검출기 임계값 우회
      put(header, forceAnonymizeCell(value as string, label, strategy, activeVault));
    }
    out.push(newRec);
  }

  return [out, activeVault];
}
