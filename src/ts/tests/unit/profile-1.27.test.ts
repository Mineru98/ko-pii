/**
 * PolicyProfile / policyDigest — Python tests/unit/test_profile.py (CLI·policy_preview 제외),
 * test_korean_workflow.py (프로파일 경로) 대응.
 *
 * fingerprint 는 .venv/bin/python (ko_pii 1.27.0) 의 ``PolicyProfile(...).fingerprint`` 실측값이다 —
 * 정규화 JSON 이 Python ``json.dumps(ensure_ascii=False, sort_keys=True, separators=(",",":"))``
 * 와 바이트 동일해야 일치한다.
 */
import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ValueError } from "../../src/core/errors.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { policyDigest, validateStrategies } from "../../src/policy.js";
import { PolicyProfile } from "../../src/profile.js";
import { PreForwardAnonymizer } from "../../src/streaming.js";
import { StructuredLimits } from "../../src/structured.js";

describe("PolicyProfile fingerprint parity (Python 실측)", () => {
  it.each([
    [{}, "fddf7ebeefeb8a5f18a542db8fa2d6096e034937fe8f33e1498010779aa8408f"],
    [
      { strategy: "redact", include: ["EMAIL"], person_exclusions: ["private-term"] },
      "dcc7aa57924db2e3cc755d46309bf27de8734203105e17f9af9e3f32166c86cb",
    ],
    [
      {
        mode: "BALANCED",
        strategy: "redact",
        strategies: { PHONE: "partial", EMAIL: "asterisk" },
        exclude: ["RRN", "ACCOUNT"],
        person_exclusions: ["홍​길동", "법무부", "ＡＢＣ"],
      },
      "74e61d5513c3d4601a5436644e15e6779fea545c7d971af3f25923679cbd480e",
    ],
    [
      {
        strategy: "redact",
        include: ["PERSON"],
        field_rules: [{ path: ["users", null, "name"], label: "PERSON", required: true }],
      },
      "b8ec5d7e745189132dc4a2f021ce8e3c592b961bd409a046d353ebcf5446bf12",
    ],
    [
      {
        strategy: "redact",
        field_labels: { "/name": "PERSON", "/a~1b": "EMAIL" },
        field_person_exclusions: { "/memo": ["김​철수", "가나"] },
      },
      "13f6763f045bcc1d2cf342ce09b37b6fe7e50b34f32986ea0fab6897779f75f3",
    ],
  ])("%o", (settings, fingerprint) => {
    expect(new PolicyProfile(settings as Record<string, unknown>, { name: "n" }).fingerprint).toBe(
      fingerprint,
    );
  });

  it("정규화된 설정 (Python 실측)", () => {
    const profile = new PolicyProfile({
      mode: "BALANCED",
      strategy: "redact",
      strategies: { PHONE: "partial", EMAIL: "asterisk" },
      exclude: ["RRN", "ACCOUNT"],
      person_exclusions: ["홍​길동", "법무부", "ＡＢＣ"],
    });
    expect(profile.settings).toEqual({
      exclude: ["ACCOUNT", "RRN"],
      include: null,
      mode: "BALANCED",
      person_exclusions: ["ABC", "법무부", "홍길동"],
      strategies: { EMAIL: "asterisk", PHONE: "partial" },
      strategy: "redact",
    });
  });
});

describe("PolicyProfile (test_profile.py)", () => {
  it("왕복·분리·숨김 표현", () => {
    const settings = {
      strategy: "redact",
      include: ["EMAIL"],
      person_exclusions: ["private-term"],
    };
    const profile = new PolicyProfile(settings, { name: "private-name" });
    settings.include.push("PERSON");
    const exported = profile.toDict();
    (exported.settings.include as string[]).push("PERSON");
    expect(profile.settings.include).toEqual(["EMAIL"]);
    expect(String(profile)).not.toContain("private");
    expect(JSON.stringify(profile)).not.toContain("private-term");
    const restored = PolicyProfile.fromJson(JSON.stringify(profile.toDict()));
    expect(restored.equals(profile)).toBe(true);
    expect(restored.fingerprint).toBe(profile.fingerprint);
    expect(new PolicyProfile(profile.settings, { name: "other" }).fingerprint).toBe(
      profile.fingerprint,
    );
    expect(new PolicyProfile(profile.settings, { name: "other" }).equals(profile)).toBe(false);
    expect(() => {
      (profile as { name: string }).name = "changed";
    }).toThrow(TypeError);
  });

  it("처리마다 새 vault", () => {
    const profile = new PolicyProfile({ include: ["EMAIL"] });
    const a = profile.process("a@example.com");
    const b = profile.process("b@example.com");
    expect(a.text).toBe("<EMAIL_1>");
    expect(b.text).toBe("<EMAIL_1>");
    expect(a.vault).not.toBe(b.vault);
  });

  it("구조화 프로파일", () => {
    const profile = new PolicyProfile({
      strategy: "redact",
      include: ["PERSON"],
      field_rules: [{ path: ["users", null, "name"], label: "PERSON", required: true }],
    });
    const data = { users: [{ name: "unusual-name" }] };
    const result = profile.processJson(data);
    expect(result.data).toEqual({ users: [{ name: "[성명]" }] });
    expect(profile.processJsonl(JSON.stringify(data))[0]?.data).toEqual(result.data);
    expect(profile.structured).toBe(true);
    expect(() => profile.process("unusual-name")).toThrow(ValueError);
    expect(() =>
      profile.processJson(data, { limits: new StructuredLimits({ maxChars: 1 }) }),
    ).toThrow(ValueError);
  });

  it.each([
    [null],
    [[]],
    [{ schema_version: true, settings: {} }],
    [{ schema_version: 2, settings: {} }],
    [{ schema_version: 1 }],
    [{ settings: {} }],
    [{ schema_version: 1, settings: [], name: "x" }],
    [{ schema_version: 1, settings: {}, extra: 1 }],
    [{ include: ["UNKNOWN"] }],
    [{ strategy: "unknown" }],
    [{ secondary_detector: "anything" }],
    [{ vault: "secret" }],
    [{ schema_version: 1, settings: {}, name: "line\nbreak" }],
  ])("잘못된 프로파일: %o", (value) => {
    expect(() => PolicyProfile.fromJson(JSON.stringify(value))).toThrow(ValueError);
  });

  it("중복 키와 크기", () => {
    expect(() => PolicyProfile.fromJson('{"strategy":"redact","strategy":"tokenize"}')).toThrow(
      ValueError,
    );
    expect(() => PolicyProfile.fromJson(" ".repeat(100001))).toThrow(ValueError);
    expect(() => new PolicyProfile({}, { name: "\ud800" })).toThrow(ValueError);
  });

  it("makeAnonymizer 는 설정·vault·traceLimit 를 전달한다", () => {
    const profile = new PolicyProfile({
      mode: "BALANCED",
      strategy: "redact",
      strategies: { PHONE: "partial" },
      person_exclusions: ["홍길동"],
    });
    const anon = profile.makeAnonymizer({ traceLimit: 3 });
    expect(anon).toBeInstanceOf(Anonymizer);
    expect(anon.mode).toBe(ProcessingMode.BALANCED);
    expect(anon.strategyFor("PHONE")).toBe("partial");
    expect(anon.traceLimit).toBe(3);
    expect([...anon.personExclusions]).toEqual(["홍길동"]);
  });
});

describe("korean workflow 프로파일 경로 (test_korean_workflow.py)", () => {
  const SOURCE =
    "담당자는 김다은입니다. 주소: 서울특별시 강남구 테헤란로 152 (101동 1202호, 010-1234-5678)";
  const EXPECTED = "담당자는 [성명]입니다. 주소: [주소][전화번호][주소]";

  it("텍스트·JSON·스트리밍이 같은 결과", () => {
    const profile = new PolicyProfile({ strategy: "redact" });
    expect(profile.process(SOURCE).text).toBe(EXPECTED);
    expect(profile.processJson({ note: SOURCE }).data).toEqual({ note: EXPECTED });
    for (let split = 0; split <= SOURCE.length; split += 7) {
      const buffered = new PreForwardAnonymizer(new Anonymizer(ProcessingMode.STRICT, "redact"));
      buffered.feed(SOURCE.slice(0, split));
      buffered.feed(SOURCE.slice(split));
      expect(buffered.finalize().text).toBe(EXPECTED);
    }
  });
});

describe("policy (validateStrategies / policyDigest)", () => {
  it("digest 는 Python json.dumps(sort_keys=True) 의 SHA-256 (gold 와 동일)", () => {
    expect(policyDigest("STRICT", "tokenize", {})).toBe(
      "231e80ff0feb43a08b3febd7fba70bd36ef1e000f03398105fe3c63d586df258",
    );
    expect(policyDigest("STRICT", "tokenize", { RRN: "redact", PHONE: "partial" })).toBe(
      "c3086e8aa1be14990a7a0b35b65020408efe383b7a1f57828a47e8d42d05170d",
    );
  });

  it("검증 메시지", () => {
    expect(() => validateStrategies("nope", null)).toThrow("Unknown strategy");
    expect(() => validateStrategies("redact", "x" as never)).toThrow(
      "strategies must map labels to substitution strategies",
    );
    expect(() => validateStrategies("redact", { NOPE: "redact" })).toThrow(
      "strategies contains an unknown category label",
    );
    expect(() => validateStrategies("redact", { PHONE: "nope" })).toThrow(
      "strategies contains an unknown substitution strategy",
    );
    expect(validateStrategies("redact", new Map([["PHONE", "partial"]]))).toEqual({
      PHONE: "partial",
    });
  });
});
