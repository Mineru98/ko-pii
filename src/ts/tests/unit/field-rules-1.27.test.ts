/**
 * FieldRule / rulesFromJson / resolveRules — Python tests/unit/test_field_rules.py 대응
 * (CLI 케이스 제외 — cli 는 다음 웨이브). 기대값은 Python 단언 또는 .venv/bin/python 실측값.
 */
import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ValueError } from "../../src/core/errors.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { boundedRules, EACH, FieldRule, rulesFromJson } from "../../src/fieldRules.js";
import { anonymizeJson, anonymizeJsonl } from "../../src/structured.js";

const redact = () => new Anonymizer(ProcessingMode.STRICT, "redact");

describe("field rules (test_field_rules.py)", () => {
  it("반복 중첩 배열과 선택 필드 (Python 실측)", () => {
    const data = {
      groups: [{ users: [{ name: "이상" }, { name: "홍길동", phone: "018-2345-6789" }] }],
    };
    const rules = [
      new FieldRule(["groups", EACH, "users", EACH, "name"], "PERSON"),
      new FieldRule(["groups", EACH, "users", EACH, "phone"], "PHONE", false),
    ];
    const result = anonymizeJson(data, { anonymizer: redact(), fieldRules: rules });
    expect(result.data).toEqual({
      groups: [{ users: [{ name: "[성명]" }, { name: "[성명]", phone: "[전화번호]" }] }],
    });
    expect(data.groups[0]?.users[0]?.name).toBe("이상");
    expect(result.fieldRuleSummary).toEqual([
      {
        rule_index: 0,
        label: "PERSON",
        required: true,
        matched: 2,
        missing: 0,
        empty_arrays: 0,
        null_fields: 0,
      },
      {
        rule_index: 1,
        label: "PHONE",
        required: false,
        matched: 1,
        missing: 1,
        empty_arrays: 0,
        null_fields: 0,
      },
    ]);
    expect(result.report().field_rules).toEqual(result.fieldRuleSummary);
    expect(result.fields.map((f) => f.path)).toEqual([
      "/groups/0/users/0/name",
      "/groups/0/users/1/name",
      "/groups/0/users/1/phone",
    ]);
  });

  it("리터럴 '*' 와 포인터 이스케이프", () => {
    const result = anonymizeJson(
      { "*": { "a/b": { "~": "이상" } } },
      { fieldRules: [new FieldRule(["*", "a/b", "~"], "PERSON")] },
    );
    expect(result.data).toEqual({ "*": { "a/b": { "~": "<PERSON_1>" } } });
    expect(result.fields[0]?.path).toBe("/*/a~1b/~0");
  });

  it("선택 필드의 부모 누락·빈 배열을 보고한다", () => {
    const rules = [new FieldRule(["user", "name"], "PERSON", false)];
    const rows = anonymizeJsonl('{"user":{"name":"이상"}}\n{"event":"heartbeat"}', {
      fieldRules: rules,
    });
    expect(rows[1]?.fieldRuleSummary[0]?.missing).toBe(1);
    const result = anonymizeJson(
      { users: [] },
      { fieldRules: [new FieldRule(["users", EACH, "name"], "PERSON")] },
    );
    expect(result.fieldRuleSummary[0]?.empty_arrays).toBe(1);
    expect(result.fields).toEqual([]);
  });

  it.each([
    [{ users: [{ name: "x" }, {}] }, new FieldRule(["users", EACH, "name"], "PERSON")],
    [{ users: {} }, new FieldRule(["users", EACH, "name"], "PERSON", false)],
    [{ name: 1.2 }, new FieldRule(["name"], "PERSON")],
    [{ user: null }, new FieldRule(["user", "name"], "PERSON", false)],
  ])("모든 규칙 검증이 vault 쓰기보다 먼저: %o", (data, rule) => {
    const anon = new Anonymizer();
    expect(() => anonymizeJson(data, { anonymizer: anon, fieldRules: [rule] })).toThrow(ValueError);
    expect(anon.vault.entries()).toEqual([]);
  });

  it("JSONL 은 첫 행 전에 모든 규칙을 사전 검증한다", () => {
    const anon = new Anonymizer();
    expect(() =>
      anonymizeJsonl('{"name":"이상"}\n{}', {
        anonymizer: anon,
        fieldRules: [new FieldRule(["name"], "PERSON")],
      }),
    ).toThrow("invalid JSONL document at line 2");
    expect(anon.vault.entries()).toEqual([]);
  });

  it("충돌·필터·인덱스·루트·null", () => {
    expect(() =>
      anonymizeJson(
        { x: "x" },
        { fieldLabels: { "/x": "PERSON" }, fieldRules: [new FieldRule(["x"], "EMAIL")] },
      ),
    ).toThrow(/conflicting/);
    expect(() =>
      anonymizeJson(
        {},
        {
          anonymizer: new Anonymizer(ProcessingMode.STRICT, "tokenize", null, null, ["PERSON"]),
          fieldRules: [new FieldRule(["x"], "PERSON", false)],
        },
      ),
    ).toThrow(/conflicts/);
    const result = anonymizeJson([null, 123], {
      fieldRules: [new FieldRule([0], "PERSON"), new FieldRule([1], "ACCOUNT")],
    });
    expect(result.data).toEqual([null, "<ACCOUNT_1>"]);
    expect(result.fieldRuleSummary[0]?.null_fields).toBe(1);
    expect(anonymizeJson("이상", { fieldRules: [new FieldRule([], "PERSON")] }).data).toBe(
      "<PERSON_1>",
    );
  });

  it.each([
    [null],
    [[{ path: "x", label: "PERSON" }]],
    [[{ path: [true], label: "PERSON" }]],
    [[{ path: [], label: "TYPO" }]],
    [[{ path: [], label: "PERSON", required: 1 }]],
    [[{ path: [], label: "PERSON", extra: 1 }]],
    [Array(129).fill({ path: [], label: "PERSON" })],
  ])("잘못된 설정: %o", (data) => {
    expect(() => rulesFromJson(data)).toThrow(ValueError);
  });

  it("rulesFromJson 은 null 을 EACH 로 바꾸고 required 기본값은 true", () => {
    const [rule] = rulesFromJson([{ path: ["users", null, 0], label: "PERSON" }]);
    expect(rule?.path).toEqual(["users", EACH, 0]);
    expect(rule?.required).toBe(true);
  });

  it("FieldRule·boundedRules 검증", () => {
    expect(() => new FieldRule([-1], "PERSON")).toThrow(/nonnegative/);
    expect(() => new FieldRule([1.5], "PERSON")).toThrow(/nonnegative/);
    expect(() => new FieldRule(Array(129).fill("a"), "PERSON")).toThrow(/128/);
    expect(() => new FieldRule([], "PERSON", 1 as never)).toThrow(/required/);
    expect(() => boundedRules([{ path: [], label: "PERSON" } as never])).toThrow(/FieldRule/);
    const rule = new FieldRule(["a"], "PERSON");
    expect(Object.isFrozen(rule)).toBe(true);
    expect(Object.isFrozen(rule.path)).toBe(true);
  });
});
