/**
 * 표/컬럼 단위 가명화 단위 테스트 — tests/unit/test_tabular.py 전체 포트.
 *
 * Python 원본: src/ko_pii/tabular.py
 * 대응 구현: ts/src/tabular.ts
 *
 * 추가 회귀 (Python 실측 대조로 확인된 시맨틱):
 * - mapColumns 는 Object.prototype 키(toString 등)를 매핑하지 않는다 (dict.__contains__ 대응)
 * - 명시적 빈 vault 는 대체하지 않고 유지한다 (Python 1.27 `vault if vault is not None`)
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

describe("Python 1.27 실측 대조 회귀 (명시적 빈 vault 유지)", () => {
  // Python 1.27: `vault if vault is not None else ReversibleVault()` — 빈 vault 도 유지된다
  // (.venv 실측: anonymize_value(..., vault=v)[1] is v → True, anonymize_records([], vault=v)[1] is v → True).
  it("anonymize_value 는 빈 vault 도 그대로 쓴다", () => {
    const empty = new ReversibleVault();
    const [, kept] = anonymizeValue("홍길동", "PERSON", { vault: empty });
    expect(kept).toBe(empty);

    const seeded = new ReversibleVault();
    seeded.store("SEED", "s", 1);
    const [, kept2] = anonymizeValue("홍길동", "PERSON", { vault: seeded });
    expect(kept2).toBe(seeded);
  });

  it("anonymize_records([]) 도 빈 명시 vault 를 유지한다", () => {
    const empty = new ReversibleVault();
    const [, ret] = anonymizeRecords([], { vault: empty });
    expect(ret).toBe(empty);
    expect(ret.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Python 1.27 tabular 계약 — tests/unit/test_tabular.py (신규 3건), test_tabular_contract.py,
// test_core_consistency.py (header_policy), contracts/test_table_headers.py.
// 기대값은 .venv/bin/python 실측 (ko_pii 1.27.0).
// ---------------------------------------------------------------------------

const fixedVault = (): ReversibleVault =>
  new ReversibleVault({ salt: "00".repeat(16), secretKey: "k", fingerprintIterations: 1 });

/** 오류 메시지 캡처 (값 반사 검사용). */
function errorOf(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected an error");
}

describe("1.27 map_columns header_policy (Python 실측)", () => {
  const headers = [
    "성명",
    "신청인 성명",
    "고객 연락처",
    "신청인 연락처",
    "customer_phone",
    "Customer Phone",
    "applicant-email",
    "patient name",
    "user_name",
    "username",
    "product_name",
    "filename",
    "생년월일 이메일",
    "생년월일 전화번호",
    "고객연락처",
    "환자명",
    "환자 이름",
    "담당자_휴대폰",
    "보호자-연락처",
    "직원 사번",
    "employee id",
    "EMPLOYEE_EMAIL",
    "ＥＭＡＩＬ",
    "성​명",
    "E-mail",
    "e-mail",
    "USER\nphone",
    "신청인\n연락처",
    "주소지",
    "거주지 주소",
    "Date of Birth",
    "dob",
    "신청인",
    "고객",
    "memo",
    "phone number",
    "전화",
    "Tel.",
    "IP주소",
    "userphone",
    "customer  phone",
    "customer　phone",
    "생년월일".normalize("NFD"),
  ];

  it("conservative (기본) 은 정확 별칭 + 주체 한정어만 매핑한다", () => {
    expect(mapColumns(headers)).toEqual({
      성명: "PERSON",
      환자명: "PERSON",
      ＥＭＡＩＬ: "EMAIL",
      "성​명": "PERSON",
      "E-mail": "EMAIL",
      "e-mail": "EMAIL",
      "거주지 주소": "ADDRESS",
      "Date of Birth": "DT_BIRTH",
      dob: "DT_BIRTH",
      신청인: "PERSON",
      IP주소: "IP",
      ["생년월일".normalize("NFD")]: "DT_BIRTH",
      "신청인 성명": "PERSON",
      "고객 연락처": "PHONE",
      "신청인 연락처": "PHONE",
      customer_phone: "PHONE",
      "Customer Phone": "PHONE",
      "applicant-email": "EMAIL",
      "patient name": "PERSON",
      user_name: "PERSON",
      고객연락처: "PHONE",
      "환자 이름": "PERSON",
      담당자_휴대폰: "PHONE",
      "보호자-연락처": "PHONE",
      "직원 사번": "EMPLOYEE_ID",
      EMPLOYEE_EMAIL: "EMAIL",
      "USER\nphone": "PHONE",
      "신청인\n연락처": "PHONE",
      "customer  phone": "PHONE",
      "customer　phone": "PHONE",
    });
  });

  it("legacy 는 예전 첫 부분 문자열 매칭을 복원한다", () => {
    expect(mapColumns(headers, { headerPolicy: "legacy" })).toEqual({
      성명: "PERSON",
      "신청인 성명": "PERSON",
      "고객 연락처": "PHONE",
      "신청인 연락처": "PERSON",
      customer_phone: "PHONE",
      "Customer Phone": "PHONE",
      "applicant-email": "EMAIL",
      "patient name": "PERSON",
      user_name: "PERSON",
      username: "PERSON",
      product_name: "PERSON",
      filename: "PERSON",
      "생년월일 이메일": "EMAIL",
      "생년월일 전화번호": "PHONE",
      고객연락처: "PHONE",
      환자명: "PERSON",
      "환자 이름": "PERSON",
      담당자_휴대폰: "PHONE",
      "보호자-연락처": "PHONE",
      "직원 사번": "EMPLOYEE_ID",
      EMPLOYEE_EMAIL: "EMAIL",
      ＥＭＡＩＬ: "EMAIL",
      "성​명": "PERSON",
      "E-mail": "EMAIL",
      "USER\nphone": "PHONE",
      "신청인\n연락처": "PERSON",
      주소지: "ADDRESS",
      "거주지 주소": "ADDRESS",
      "Date of Birth": "DT_BIRTH",
      dob: "DT_BIRTH",
      신청인: "PERSON",
      "phone number": "PHONE",
      "Tel.": "PHONE",
      IP주소: "IP",
      userphone: "PHONE",
      "customer  phone": "PHONE",
      "customer　phone": "PHONE",
      ["생년월일".normalize("NFD")]: "DT_BIRTH",
    });
  });

  it("header_policy 오타는 빈 입력에도 거부", () => {
    expect(() => mapColumns([], { headerPolicy: "typo" as never })).toThrow(/header_policy/);
    expect(() => anonymizeRecords([], { headerPolicy: "typo" as never })).toThrow(/header_policy/);
  });

  it("legacy 정책은 anonymize_records 에도 전달되고, 명시 column_map 이 우선한다", () => {
    const records = [{ filename: "report.txt", "신청인 연락처": "010-1234-5678" }];
    expect(anonymizeRecords(records, { headerPolicy: "legacy", strategy: "redact" })[0]).toEqual([
      { filename: "[성명]", "신청인 연락처": "[성명]" },
    ]);
    for (const headerPolicy of ["conservative", "legacy"] as const) {
      expect(anonymizeRecords(records, { columnMap: {}, headerPolicy })[0]).toEqual(records);
      const [out] = anonymizeRecords(records, {
        columnMap: { "신청인 연락처": "PHONE" },
        headerPolicy,
        strategy: "redact",
      });
      expect(out).toEqual([{ filename: "report.txt", "신청인 연락처": "[전화번호]" }]);
    }
  });
});

describe("1.27 explicit column_map 검증 (test_tabular.py)", () => {
  it.each([[{ emial: "EMAIL" }], [{ email: "EMAIL", absent: "PHONE" }]])(
    "행에 없는 명시 열은 vault 변경 전에 거부: %o",
    (mapping) => {
      const records = [{ email: "first@example.com" }];
      const vault = new ReversibleVault();
      const err = errorOf(() => anonymizeRecords(records, { columnMap: mapping, vault }));
      expect(err.message).toMatch(/absent from the records/);
      expect(err.message).not.toContain("first@example.com");
      expect(vault.size).toBe(0);
      expect(records).toEqual([{ email: "first@example.com" }]);
    },
  );

  it.each([[[]], ["email"], [{ "": "EMAIL" }], [{ email: "" }], [{ email: null }]])(
    "잘못된 column_map 은 빈 데이터에도 거부: %o",
    (mapping) => {
      expect(() => anonymizeRecords([], { columnMap: mapping as never })).toThrow(/column_map/);
    },
  );

  it("column_map 은 희소 레코드 키의 합집합을 덮을 수 있다", () => {
    const records = [{ email: "first@example.com" }, { phone: "010-1234-5678" }];
    const [out] = anonymizeRecords(records, { columnMap: { email: "EMAIL", phone: "PHONE" } });
    expect(out).toEqual([{ email: "<EMAIL_1>" }, { phone: "<PHONE_1>" }]);
    expect(anonymizeRecords(records, { columnMap: {} })[0]).toEqual(records);
  });
});

describe("1.27 typed table columns (test_tabular_contract.py)", () => {
  // Python 실측: 고정 vault(salt=00*16, key=k, iterations=1) 로 anonymize_records 단언 정수 결과.
  const expected: Record<string, string> = {
    "tokenize:0": "<ACCOUNT_1>",
    "tokenize:12345": "<ACCOUNT_1>",
    "tokenize:-17": "<ACCOUNT_1>",
    "redact:0": "[계좌번호]",
    "redact:12345": "[계좌번호]",
    "redact:-17": "[계좌번호]",
    "asterisk:0": "*",
    "asterisk:12345": "*****",
    "asterisk:-17": "***",
    "partial:0": "*",
    "partial:12345": "*****",
    "partial:-17": "***",
    "hashed:0": "<ACCOUNT:fdfb63a4eb83>",
    "hashed:12345": "<ACCOUNT:3d49fe1ba938>",
    "hashed:-17": "<ACCOUNT:fc052fb2512e>",
    "fpe:0": "*",
    "fpe:12345": "45390",
    "fpe:-17": "-16",
  };
  const strategies = ["tokenize", "redact", "asterisk", "partial", "hashed", "fpe"];

  it.each(strategies.flatMap((s) => [0, 12345, -17].map((v) => [s, v] as const)))(
    "단언 정수 = 명시 문자열 변환: %s %d",
    (strategy, value) => {
      const vault = fixedVault();
      const [explicit] = anonymizeValue(String(value), "ACCOUNT", {
        strategy,
        vault: fixedVault(),
      });
      const original = [{ account: value, count: 7 }];
      const [output, returned] = anonymizeRecords(original, {
        columnMap: { account: "ACCOUNT" },
        strategy,
        vault,
      });
      expect(output).toEqual([{ account: expected[`${strategy}:${value}`], count: 7 }]);
      expect(output[0]?.account).toBe(explicit);
      expect(typeof output[0]?.account).toBe("string");
      expect(returned).toBe(vault);
      expect(original).toEqual([{ account: value, count: 7 }]);
    },
  );

  it.each([
    ProcessingMode.PARANOID,
    ProcessingMode.STRICT,
    ProcessingMode.BALANCED,
    ProcessingMode.PERMISSIVE,
  ])("변환 모드 %s 는 0 식별자 단언도 적용", (mode) => {
    const [output] = anonymizeRecords([{ rrn: 0 }], { mode, strategy: "redact" });
    expect(output).toEqual([{ rrn: "[주민등록번호]" }]);
  });

  it("AUDIT 은 정수 타입을 유지하고 저장하지 않는다", () => {
    const rows = [{ account: 0 }, { account: 12345 }, { account: null }];
    const vault = new ReversibleVault();
    const [output, returned] = anonymizeRecords(rows, {
      columnMap: { account: "ACCOUNT" },
      mode: ProcessingMode.AUDIT,
      vault,
    });
    expect(output).toEqual(rows);
    expect(typeof output[0]?.account).toBe("number");
    expect(returned).toBe(vault);
    expect(vault.size).toBe(0);
  });

  it("같은 식별자의 정수·문자열은 토큰을 공유하고 문자열은 다듬지 않는다", () => {
    const rows = [{ account: 12345 }, { account: "12345" }, { account: "0012345" }];
    const [output, vault] = anonymizeRecords(rows, { columnMap: { account: "ACCOUNT" } });
    expect(output[0]).toEqual(output[1]);
    expect(output[1]).not.toEqual(output[2]);
    expect(vault.reveal(output[0]?.account as string)).toBe("12345");
    expect(vault.reveal(output[2]?.account as string)).toBe("0012345");
  });

  // TS 한계: JS number 는 0.0/123.0 과 0/123 을 구분하지 못해 정수로 취급된다 (보고서 참조).
  it.each([
    [["synthetic-person"]],
    [{ nested: "synthetic-person" }],
    [true],
    [false],
    [0.5],
    [Number.POSITIVE_INFINITY],
    [new Uint8Array([1, 2])],
  ])("잘못된 단언 셀은 vault 쓰기 전에 거부: %o", (value) => {
    for (const explicit of [true, false]) {
      const rows = [{ name: "first-synthetic-person" }, { name: value }];
      const vault = new ReversibleVault();
      const err = errorOf(() =>
        anonymizeRecords(rows as never, {
          columnMap: explicit ? { name: "PERSON" } : null,
          vault,
        }),
      );
      expect(err.name).toBe("ValueError");
      expect(err.message).not.toContain("synthetic-person");
      expect(vault.size).toBe(0);
      expect(rows[0]).toEqual({ name: "first-synthetic-person" });
    }
  });

  it.each([
    ProcessingMode.PARANOID,
    ProcessingMode.STRICT,
    ProcessingMode.BALANCED,
    ProcessingMode.PERMISSIVE,
    ProcessingMode.AUDIT,
  ])("중첩 단언 필드는 자유 텍스트 검출로 떨어지지 않는다 (%s)", (mode) => {
    expect(() => anonymizeRecords([{ name: ["synthetic-person"] }] as never, { mode })).toThrow(
      /scalars/,
    );
  });

  it("비매핑 스칼라·null·빈 셀은 보존하고 사본을 반환한다", () => {
    const rows = [
      { email: "", count: 7, ratio: 0.5, enabled: false, extra: null },
      { email: null, count: 0 },
    ];
    const [output, vault] = anonymizeRecords(rows);
    expect(output).toEqual(rows);
    expect(vault.size).toBe(0);
    expect(output).not.toBe(rows);
    expect(output[0]).not.toBe(rows[0]);
  });

  it.each([[["synthetic-person"]], [{ nested: "synthetic-person" }]])(
    "중첩 비매핑 열은 구조화 API 가 필요하다: %o",
    (value) => {
      const vault = new ReversibleVault();
      expect(() =>
        anonymizeRecords([{ email: "synthetic@example.com" }, { memo: value }] as never, { vault }),
      ).toThrow();
      expect(vault.size).toBe(0);
    },
  );

  it("CSV 초과 셀(restkey) 은 검출 기반으로 처리하고 입력을 별칭하지 않는다", () => {
    const overflow = ["second@example.com", "", "public", null];
    const rows = [{ email: "first@example.com", "": overflow }];
    const [output] = anonymizeRecords(rows, { strategy: "redact" });
    // Python 실측: [{'email': '[이메일]', None: ['[이메일]', '', 'public', None]}]
    expect(output).toEqual([{ email: "[이메일]", "": ["[이메일]", "", "public", null] }]);
    expect(output[0]?.[""]).not.toBe(overflow);
    expect(overflow).toEqual(["second@example.com", "", "public", null]);
  });

  it.each([[[12345]], [[false]], [[["synthetic-person"]]]])(
    "잘못된 CSV 초과 셀은 vault 쓰기 전에 거부: %o",
    (value) => {
      const vault = new ReversibleVault();
      const err = errorOf(() =>
        anonymizeRecords([{ email: "synthetic@example.com" }, { "": value }] as never, { vault }),
      );
      expect(err.message).toMatch(/overflow/);
      expect(err.message).not.toContain("synthetic");
      expect(vault.size).toBe(0);
    },
  );

  it.each([[null], ["synthetic-person"], [[null]], [[12345]], [[["synthetic-person"]]]])(
    "잘못된 레코드 컨테이너는 입력을 반사하지 않고 거부: %o",
    (rows) => {
      const err = errorOf(() => anonymizeRecords(rows as never));
      expect(err.name).toBe("ValueError");
      expect(err.message).not.toContain("synthetic-person");
    },
  );

  it("빈 표도 strategy 를 검증한다", () => {
    expect(() => anonymizeRecords([], { strategy: "typo" })).toThrow(/strategy/);
  });

  it.each(["PERSON\nSECRET", "<PERSON", "PERSON>", "PERSON\rSECRET"])(
    "잘못된 매핑 라벨은 앞 셀 저장 전에 거부: %j",
    (label) => {
      const vault = new ReversibleVault();
      const err = errorOf(() =>
        anonymizeRecords([{ email: "synthetic@example.com", other: "synthetic-person" }], {
          columnMap: { email: "EMAIL", other: label },
          vault,
        }),
      );
      expect(vault.size).toBe(0);
      expect(err.message).not.toContain("SECRET");
      expect(() =>
        anonymizeValue("synthetic-person", label, { strategy: "redact", vault }),
      ).toThrow(/label/);
    },
  );

  it("사용자 정의 단언 라벨은 계속 지원된다", () => {
    const [output, vault] = anonymizeRecords([{ id: 12345 }], { columnMap: { id: "CUSTOM_ID" } });
    expect(output[0]?.id).toBe("<CUSTOM_ID_1>");
    expect(vault.reveal("<CUSTOM_ID_1>")).toBe("12345");
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "비유한 비매핑 숫자는 저장 전에 거부: %d",
    (value) => {
      const vault = new ReversibleVault();
      expect(() =>
        anonymizeRecords([{ email: "synthetic@example.com", ratio: value }], { vault }),
      ).toThrow(/finite/);
      expect(vault.size).toBe(0);
    },
  );

  it("bigint 단언 정수도 Python int 처럼 문자열로 변환된다", () => {
    const [output, vault] = anonymizeRecords([{ account: 10n ** 30n }], {
      columnMap: { account: "ACCOUNT" },
    });
    expect(vault.reveal(output[0]?.account as string)).toBe(`1${"0".repeat(30)}`);
  });
});
