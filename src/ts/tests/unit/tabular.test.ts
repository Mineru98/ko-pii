/**
 * 표/컬럼 단위 가명화 단위 테스트 — tests/unit/test_tabular.py 전체 포트.
 *
 * Python 원본: src/ko_pii/tabular.py
 * 대응 구현: ts/src/tabular.ts
 *
 * 추가 회귀 (Python 실측 대조로 확인된 시맨틱):
 * - mapColumns 는 Object.prototype 키(toString 등)를 매핑하지 않는다 (dict.__contains__ 대응)
 * - anonymizeValue 는 *빈* vault 를 falsy 로 평가해 새 vault 로 대체한다
 *   (ReversibleVault.__len__ → `vault or ReversibleVault()` 시맨틱)
 */
import { describe, expect, it } from "vitest";
import { ProcessingMode } from "../../src/core/modes.js";
import {
  anonymizeRecords,
  anonymizeValue,
  classifySchemaColumns,
  mapColumns,
} from "../../src/tabular.js";
import { ReversibleVault } from "../../src/vault/reversible.js";

describe("ColumnMapping (map_columns)", () => {
  it("basic_mapping", () => {
    const m = mapColumns(["성명", "주민번호", "연락처"]);
    expect(m["성명"]).toBe("PERSON");
    expect(m["주민번호"]).toBe("RRN");
    expect(m["연락처"]).toBe("PHONE");
  });

  it("english_headers", () => {
    const m = mapColumns(["name", "phone", "email"]);
    expect(m["name"]).toBe("PERSON");
    expect(m["phone"]).toBe("PHONE");
    expect(m["email"]).toBe("EMAIL");
  });

  it("composite_header", () => {
    const m = mapColumns(["신청인 성명", "고객 연락처"]);
    expect(m["신청인 성명"]).toBe("PERSON");
    expect(m["고객 연락처"]).toBe("PHONE");
  });

  it("unmapped_passthrough", () => {
    expect(mapColumns(["메모", "비고", "기타사항"])).toEqual({});
  });

  it("프로토타입 체인 키 헤더도 매핑하지 않는다 (Python dict 시맨틱 회귀)", () => {
    const m = mapColumns(["toString", "constructor", "valueOf", "hasOwnProperty"]);
    expect(m).toEqual({});
  });
});

describe("SchemaColumnClassification (classify_schema_columns)", () => {
  it("exact_sensitive_columns_include_evidence", () => {
    const classified = classifySchemaColumns(["성명", "주민등록번호"]);

    expect(classified["성명"]?.label).toBe("PERSON");
    expect(classified["성명"]?.confidence).toBe(1.0);
    expect(classified["성명"]?.ambiguous).toBe(false);
    expect(classified["주민등록번호"]?.label).toBe("RRN");
  });

  it("normalized_match_is_explicit", () => {
    const classified = classifySchemaColumns(["성 명"]);

    expect(classified["성 명"]?.match).toBe("normalized");
    expect(classified["성 명"]?.confidence).toBe(0.95);
  });

  it("generic_name_requires_review", () => {
    const classified = classifySchemaColumns(["name"]);

    expect(classified["name"]?.label).toBe("PERSON");
    expect(classified["name"]?.ambiguous).toBe(true);
    expect(classified["name"]?.confidence).toBe(0.6);
  });

  it.each(["product_name", "사용자이름설명", "고객 연락처 메모"])(
    "schema_classification_never_uses_substrings (%s)",
    (column) => {
      expect(classifySchemaColumns([column])).toEqual({});
    },
  );
});

describe("AnonymizeRecords (anonymize_records)", () => {
  it("basic_anonymization", () => {
    const records = [
      { 성명: "홍길동", 주민번호: "880101-1234568", 비고: "신청" },
      { 성명: "김민수", 주민번호: "950101-2345676", 비고: "보호자" },
    ];
    const [out, vault] = anonymizeRecords(records, {
      mode: ProcessingMode.STRICT,
      strategy: "tokenize",
    });
    expect(out).toHaveLength(2);
    // 매핑된 컬럼은 가명화
    expect(out[0]!.성명).not.toBe("홍길동");
    expect(out[0]!.주민번호).not.toBe("880101-1234568");
    // 매핑되지 않은 컬럼은 그대로
    expect(out[0]!.비고).toBe("신청");
    // vault 에서 복원 가능
    const token = out[0]!.성명 as string;
    expect(vault.reveal(token)).toBe("홍길동");
  });

  it("same_value_same_token", () => {
    const records = [
      { 성명: "홍길동", 주민번호: "880101-1234568" },
      { 성명: "홍길동", 주민번호: "880101-1234568" },
    ];
    const [out] = anonymizeRecords(records, { strategy: "tokenize" });
    expect(out[0]!.성명).toBe(out[1]!.성명);
    expect(out[0]!.주민번호).toBe(out[1]!.주민번호);
  });

  it("explicit_column_map", () => {
    const records = [{ col1: "880101-1234568", col2: "010-1234-5678" }];
    const [out] = anonymizeRecords(records, {
      columnMap: { col1: "RRN", col2: "PHONE" },
      strategy: "redact",
    });
    expect(out[0]!.col1).toBe("[주민등록번호]");
    expect(out[0]!.col2).toBe("[전화번호]");
  });

  it("partial_strategy", () => {
    const records = [{ 성명: "홍길동", 전화번호: "010-1234-5678" }];
    const [out] = anonymizeRecords(records, { strategy: "partial" });
    expect(out[0]!.성명).toBe("홍OO");
    expect(out[0]!.전화번호).toBe("010-****-5678");
  });

  it("empty_records", () => {
    const [out] = anonymizeRecords([]);
    expect(out).toEqual([]);
  });

  it("empty_value_preserved", () => {
    const records = [{ 성명: "", 주민번호: "880101-1234568" }];
    const [out] = anonymizeRecords(records);
    expect(out[0]!.성명).toBe("");
  });

  it("explicit_value_anonymization (anonymize_value)", () => {
    const [output] = anonymizeValue("홍길동", "PERSON", { strategy: "redact" });

    expect(output).toBe("[성명]");
  });

  it("explicit_value_rejects_unknown_strategy", () => {
    expect(() => anonymizeValue("홍길동", "PERSON", { strategy: "unknown" })).toThrowError(
      "Unknown strategy: unknown",
    );
  });
});

describe("Python 실측 대조 회귀 (빈 vault truthiness)", () => {
  // Python: `vault or ReversibleVault()` — ReversibleVault.__len__ 때문에 빈 vault 는
  // falsy 로 평가되어 새(랜덤 salt) vault 로 대체된다. vault 는 ts/reversible.ts 의
  // get size 로 동일 시맨틱을 재현한다.
  it("anonymize_value 는 빈 vault 를 대체하고 비어있지 않은 vault 는 유지한다", () => {
    const empty = new ReversibleVault();
    const [, replaced] = anonymizeValue("홍길동", "PERSON", { vault: empty });
    expect(replaced).not.toBe(empty);

    const seeded = new ReversibleVault();
    seeded.store("SEED", "s", 1);
    const [, kept] = anonymizeValue("홍길동", "PERSON", { vault: seeded });
    expect(kept).toBe(seeded);
  });

  it("anonymize_records([]) 도 빈 vault 를 대체한다", () => {
    const empty = new ReversibleVault();
    const [, ret] = anonymizeRecords([], { vault: empty });
    expect(ret).not.toBe(empty);
    expect(ret.size).toBe(0);
  });
});
