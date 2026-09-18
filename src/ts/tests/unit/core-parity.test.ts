/**
 * Python↔TS 동작 일치 회귀 테스트 — modes / vault / analytics / legal.
 *
 * 모든 기대값은 Python 원본(src/python/ko_pii)을 **실행해 얻은 실측 출력**이다
 * (차등 하네스: 순수 함수 13,865 케이스 + 상태 시나리오 90 케이스). 각 describe 는
 * 감사 보고의 불일치 항목 번호(#n)에 대응한다.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { classify_attribute, k_anonymity } from "../../src/analytics/index.js";
import { Anonymizer } from "../../src/anonymizer.js";
import { IndexError } from "../../src/core/errors.js";
import { type DetectionResult, makeDetection } from "../../src/core/types.js";
import * as publicApi from "../../src/index.js";
import { categoryFor, legalBasisFor, riskFloorFor } from "../../src/legal/index.js";
import { FPE_BY_LABEL, fpe, fpeDefault } from "../../src/modes/fpe.js";
import { hashed } from "../../src/modes/hashed.js";
import { maskValue } from "../../src/modes/partial.js";
import { tokenize } from "../../src/modes/tokenize.js";
import { AuditLog, replay } from "../../src/vault/audit.js";
import { pyJsonDumps, ReversibleVault } from "../../src/vault/reversible.js";

const E = "\u{1F600}"; // 😀 (아스트랄 — UTF-16 2유닛, 코드 포인트 1개)
// 수학 굵은 숫자 U+1D7CE.. (아스트랄 Nd): "010-1234-5678"
const MATH_PHONE =
  "\u{1D7CE}\u{1D7CF}\u{1D7CE}-\u{1D7CF}\u{1D7D0}\u{1D7D1}\u{1D7D2}-\u{1D7D3}\u{1D7D4}\u{1D7D5}\u{1D7D6}";
const MATH_32 = "\u{1D7DB}\u{1D7DA}"; // 이중선 3, 2 — 10자 묶음이 5개 붙은 Nd 블록
const FW = (s: string) => s.replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + Number(d)));
const FP = "0123456789abcdef".repeat(4);
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const TEXT = "신청인 홍길동 880101-1234568 연락처 010-1234-5678 메일 user@example.com 끝";
function dets(): DetectionResult[] {
  const f = (label: string, s: string, risk: number, conf = 1.0, legal: string | null = null) => {
    const i = TEXT.indexOf(s);
    return makeDetection({
      label,
      text: s,
      start: i,
      end: i + s.length,
      riskLevel: risk,
      confidence: conf,
      legal_basis: legal,
    });
  };
  return [
    f("PHONE", "010-1234-5678", 3, 0.9, "개인정보보호법 제2조"),
    f("RRN", "880101-1234568", 5, 1.0, "개인정보보호법 제24조의2"),
    f("PERSON", "홍길동", 4, 0.8),
    f("EMAIL", "user@example.com", 3, 1.0, ""),
    f("URL", "example.com", 1, 0.5), // EMAIL 과 겹침 — 우선순위에서 밀린다
    f("CUSTOM", "연락처", 2, 0.7),
  ];
}
const newVault = () =>
  new ReversibleVault({ salt: "00112233", secretKey: "pepper", fingerprintIterations: 1 });

describe("#1 tokenize/hashed/fpe 직접 호출 — 실제 ReversibleVault 와 동작", () => {
  it("tokenize 는 ReversibleVault 에 위치 인자로 저장하고 복원 가능하다", () => {
    const v = newVault();
    const [replaced, returned] = tokenize(TEXT, dets(), v);
    expect(replaced).toBe("신청인 <PERSON_1> <RRN_1> <CUSTOM_1> <PHONE_1> 메일 <EMAIL_1> 끝");
    expect(returned).toBe(v);
    expect(v.reveal("<RRN_1>")).toBe("880101-1234568");
    expect(v.get("<PHONE_1>")?.legalBasis).toBe("개인정보보호법 제2조");
    expect(v.get("<PHONE_1>")?.occurrences).toEqual([27]);
    expect(v.size).toBe(5);
  });

  it("fpe 는 Python 과 같은 가명값을 내고 fpe_value 를 vault 에 남긴다", () => {
    const v = newVault();
    const [replaced] = fpe(TEXT, dets(), v);
    expect(replaced).toBe(
      "신청인 \ubf25\ub025\uc3a6 642619-1077231 \uc6fd\ud43e\uc455 010-8525-4712 메일 athb@example.com 끝",
    );
    expect(v.get("<RRN_1>")?.extra).toEqual({ fpe_value: "642619-1077231" });
  });

  it("vault 를 생략하면 새 ReversibleVault 를 만든다 (Python vault=None)", () => {
    const [t, tv] = tokenize(TEXT, dets());
    expect(t).toBe("신청인 <PERSON_1> <RRN_1> <CUSTOM_1> <PHONE_1> 메일 <EMAIL_1> 끝");
    expect(tv).toBeInstanceOf(ReversibleVault);
    expect(tv.size).toBe(5);
    const [, fv] = fpe(TEXT, dets());
    expect(fv).toBeInstanceOf(ReversibleVault);
    expect(fv.size).toBe(5);
    const [h, hv] = hashed(TEXT, dets());
    expect(hv).toBeInstanceOf(ReversibleVault);
    expect(hv.size).toBe(0); // Python 실측: hashed 는 vault 에 저장하지 않는다 (len == 0)
    expect(h).toMatch(/^신청인 <PERSON:[0-9a-f]{12}> <RRN:[0-9a-f]{12}> /);
    expect(hashed(TEXT, dets(), null, 5)[0]).toMatch(/<RRN:[0-9a-f]{5}>/);
  });
});

describe("#9 아스트랄 문자 포함 값 — 길이·슬라이스는 코드 포인트 기준", () => {
  it.each([
    ["URL", `김철수${E}`, "****"],
    ["URL", E.repeat(6), `${E}${E}**${E}${E}`],
    ["PERSON", `김철수${E}`, "김OOO"],
    ["PERSON", `${E}880101-1234568`, `${E}OOOOOOOOOOOOOO`],
    ["EMAIL", `${E}user@example.com`, `${E}****@example.com`],
    ["EMAIL", `us${E}er@example.com`, "u****@example.com"],
    ["RRN", `김철수${E}`, "****"],
    ["MAJOR", `수학${E}과`, "○○○과"],
    ["PHONE", MATH_PHONE, "\u{1D7CE}\u{1D7CF}\u{1D7CE}-****-\u{1D7D3}\u{1D7D4}\u{1D7D5}\u{1D7D6}"],
    [
      "CARD",
      MATH_PHONE,
      "\u{1D7CE}\u{1D7CF}\u{1D7CE}\u{1D7CF}-***-\u{1D7D3}\u{1D7D4}\u{1D7D5}\u{1D7D6}",
    ],
  ])("maskValue(%s, %j)", (label, value, want) => {
    const got = maskValue(label, value);
    expect(got).toBe(want);
    expect(LONE_SURROGATE.test(got)).toBe(false); // 반쪽 서로게이트 출력 금지
  });

  it("fpe 도 코드 포인트 기준으로 길이를 센다", () => {
    expect(FPE_BY_LABEL.get("EMAIL")?.(`us${E}er@example.com`, FP)).toBe("ztsst@example.com");
    expect(fpeDefault(`a${E}bcd`, FP)).toBe(`z${E}tss`);
    expect(FPE_BY_LABEL.get("PHONE")?.(MATH_PHONE, FP)).toBe("\u{1D7CE}\u{1D7CF}5-5262-9119");
    expect(FPE_BY_LABEL.get("RRN")?.(`${MATH_32}세`, FP)).toBe("55");
    expect(FPE_BY_LABEL.get("CARD")?.(FW("1234-5678-9012-3456"), FP)).toBe(
      `${FW("1234")}-${FW("56")}55-2629-1198`,
    );
  });
});

describe("#7 Nd 자릿값 — 묶음이 연달아 붙은 블록(수학 숫자)", () => {
  it.each([
    ["AGE", "30대"],
    ["HEIGHT", "30-35cm"],
    ["WEIGHT", "30-35kg"],
  ])("maskValue(%s, 𝟛𝟚세)", (label, want) => {
    expect(maskValue(label, `${MATH_32}세`)).toBe(want);
  });
  it("전각·아랍-인도 숫자", () => {
    expect(maskValue("AGE", `${FW("32")}세`)).toBe("30대");
    expect(maskValue("AGE", "\u0663\u0662세")).toBe("30대");
  });
});

describe("#8 fpe 의 Python str.isdigit() 집합 (Nd + 위첨자·원문자)", () => {
  it("_fpe_default 는 \xb2·\u2460 도 숫자로 치환한다", () => {
    expect(fpeDefault("x\xb2y", FP)).toBe("z5t");
    expect(fpeDefault("\u2460\u2461\u2462\u2463\u2464", FP)).toBe("55262");
  });
  it("자릿수(Nd)보다 isdigit 문자가 많으면 Python IndexError 처럼 예외", () => {
    // Python 실측: `IndexError: string index out of range` (PHONE·CARD 공통) — batch 의
    // error 문자열 "{클래스명}: {메시지}" 에 그대로 나오므로 name·message 를 모두 단언한다.
    for (const [label, value] of [
      ["PHONE", "010-1234-5678\xb2"],
      ["CARD", "4111-1111-1111-1111\u2460"],
    ] as const) {
      let caught: unknown;
      try {
        FPE_BY_LABEL.get(label)?.(value, FP);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(IndexError);
      expect((caught as Error).name).toBe("IndexError");
      expect((caught as Error).message).toBe("string index out of range");
      expect(String(caught)).toBe("IndexError: string index out of range");
    }
  });
});

describe("#3 #4 #5 #6 정규식·repeat 의미론", () => {
  it("#3 PASSPORT 숫자 1~2자리 — 음수 repeat 가드", () => {
    expect(maskValue("PASSPORT", "M1")).toBe("M1");
    expect(maskValue("PASSPORT", "M12")).toBe("M12");
  });
  it("#4 Python `$` 는 끝의 개행 직전에도 매칭한다", () => {
    expect(maskValue("PASSPORT", "M12345678\n")).toBe("M******78");
    expect(maskValue("DT_BIRTH", "1988-01-01\n")).toBe("1988-**-**");
    expect(maskValue("DT_BIRTH", "1988년 1월 1일\n")).toBe("1988년 **월 **일");
    expect(FPE_BY_LABEL.get("PASSPORT")?.("M12345678\n", FP)).toBe("M55262911");
  });
  it("#5 fpe PASSPORT 는 전각 숫자(Nd)도 받는다", () => {
    expect(FPE_BY_LABEL.get("PASSPORT")?.(`M${FW("12345678")}`, FP)).toBe("M55262911");
  });
  it("#6 DT_BIRTH 의 공백은 Python `\\s` 집합", () => {
    expect(maskValue("DT_BIRTH", "1988년\x1f1월 1일")).toBe("1988년 **월 **일");
    expect(maskValue("DT_BIRTH", "1988년\x851월 1일")).toBe("1988년 **월 **일");
    expect(maskValue("DT_BIRTH", "1988년\u30001월 1일")).toBe("1988년 **월 **일");
    expect(maskValue("DT_BIRTH", "1988년\ufeff1월 1일")).toBe("***********"); // BOM 은 공백 아님
  });
});

describe("#10 거대 숫자열 — 임의 정밀도 정수 출력", () => {
  it("AGE/HEIGHT/WEIGHT", () => {
    expect(maskValue("AGE", "99999999999999999999세")).toBe("99999999999999999990대");
    expect(maskValue("HEIGHT", "12345678901234567890123cm")).toBe(
      "12345678901234567741440-12345678901234567741445cm",
    );
    expect(maskValue("WEIGHT", "99999999999999999999세")).toBe(
      "100000000000000000000-100000000000000000005kg",
    );
  });
  it("부동소수 경계는 그대로", () => {
    expect(maskValue("HEIGHT", "1.15m")).toBe("110-115cm");
    expect(maskValue("HEIGHT", "2.675m")).toBe("265-270cm");
    expect(maskValue("HEIGHT", "175cm")).toBe("175-180cm");
  });
});

describe("#11 프로토타입 체인 키 조회 차단", () => {
  it.each(["constructor", "toString", "__proto__", "hasOwnProperty"])("%s", (label) => {
    expect(classify_attribute(label)).toBe("general");
    expect(legalBasisFor(label)).toBeNull();
    expect(categoryFor(label)).toBeNull();
    expect(riskFloorFor(label)).toBeNull();
  });
});

describe("#12 k_anonymity — Python tuple 동등성·repr·TypeError", () => {
  it("1 == True == 1.0 은 한 그룹", () => {
    const r = k_anonymity([{ AGE: 1 }, { AGE: true }, { AGE: 1.0 }]);
    expect([r.k, r.group_count, r.smallest_group_values]).toEqual([3, 1, [1]]);
  });
  it("0 == False, None 과 '' 는 각각 별도 그룹", () => {
    const r = k_anonymity([{ AGE: 0 }, { AGE: false }, { AGE: null }, { AGE: "" }]);
    expect([r.k, r.group_count, r.smallest_group_values]).toEqual([1, 3, [null]]);
  });
  it("숫자 1 과 문자열 '1' 은 다른 그룹", () => {
    expect(k_anonymity([{ AGE: 1 }, { AGE: "1" }]).group_count).toBe(2);
  });
  it("rationale 의 키 목록은 Python repr(list[str])", () => {
    const keys = ["a'b", "x\ny", 'q"', "한", "b\\s", "a'\"b", "\x7f\u200b"];
    const r = k_anonymity([{ "a'b": 1, "x\ny": 2, 'q"': 3, 한: 4, "b\\s": 5 }], keys);
    expect(r.rationale[0]).toBe(
      "준식별자 [\"a'b\", 'x\\ny', 'q\"', '한', 'b\\\\s', 'a\\'\"b', '\\x7f\\u200b'] 기준 1개 그룹",
    );
    // 누락 키는 Python `rec.get(k)` 의 None — TS 는 null 로 담는다 (Python 실측 [1,2,3,4,5,None,None]).
    expect(r.smallest_group_values).toEqual([1, 2, 3, 4, 5, null, null]);
    expect(JSON.stringify(r.smallest_group_values)).toBe("[1,2,3,4,5,null,null]");
  });
  it("준식별자 키는 레코드 자기 키만 조회 (프로토타입 체인 차단) — Python 실측", () => {
    const recs = [{ AGE: 1 }, { AGE: 1 }];
    const view = (keys: string[], records: Record<string, unknown>[] = recs) => {
      const r = k_anonymity(records, keys, 1);
      return [r.k, r.group_count, r.smallest_group_values, r.rationale[0]];
    };
    expect(view(["constructor"])).toEqual([2, 1, [null], "준식별자 ['constructor'] 기준 1개 그룹"]);
    expect(view(["__proto__", "toString", "hasOwnProperty"])).toEqual([
      2,
      1,
      [null, null, null],
      "준식별자 ['__proto__', 'toString', 'hasOwnProperty'] 기준 1개 그룹",
    ]);
    expect(view(["AGE", "constructor"])).toEqual([
      2,
      1,
      [1, null],
      "준식별자 ['AGE', 'constructor'] 기준 1개 그룹",
    ]);
    // 자기 키로 실제 들어 있으면 값으로 쓴다
    expect(view(["toString"], [{ AGE: 1, toString: "x" }, { AGE: 1 }])).toEqual([
      1,
      2,
      ["x"],
      "준식별자 ['toString'] 기준 2개 그룹",
    ]);
  });
  it("list/dict 값은 해시 불가 — TypeError", () => {
    expect(() => k_anonymity([{ AGE: [1, 2] }, { AGE: [1, 2] }])).toThrow(TypeError);
    expect(() => k_anonymity([{ AGE: { a: 1 } }])).toThrow(TypeError);
  });
});

describe("#13 vault/audit — truthiness·타입 강제·직렬화", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "kopii-parity-"));
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('actor="" / defaultActor="" 는 기본값으로 대체 (Python `or`)', () => {
    const p = join(dir, "actor.jsonl");
    new AuditLog(p, "tester", { now: () => "T" }).record("custom", { actor: "", context: "" });
    expect(readFileSync(p, "utf8")).toBe(
      '{"ts": "T", "action": "custom", "token": null, "label": null, "actor": "tester", "context": ""}\n',
    );
    const auto = new AuditLog(p, "");
    expect(auto.defaultActor).toMatch(/.+@.+/);
  });

  it("replay: NaN/Infinity 줄은 파싱, 손상 줄은 건너뜀, \\r\\n·\\r 도 줄 구분", () => {
    const p = join(dir, "replay.jsonl");
    writeFileSync(
      p,
      '{"a": 1}\nnot json\n\n  {"n": NaN, "i": -Infinity, "s": "NaN stays"}\r\n{"b": 2}\r{"c": 3}\n{"trunc": ',
    );
    const rows = replay(p);
    expect(rows).toHaveLength(4);
    expect(rows[1]).toEqual({ n: Number.NaN, i: Number.NEGATIVE_INFINITY, s: "NaN stays" });
    expect(rows[3]).toEqual({ c: 3 });
  });

  it("replay: BOM 으로 시작하는 첫 줄은 Python 처럼 버려진다", () => {
    const p = join(dir, "bom.jsonl");
    writeFileSync(p, '\ufeff{"a": 1}\n{"b": 2}\n', "utf8");
    expect(replay(p)).toEqual([{ b: 2 }]);
  });

  const load = (payload: unknown) => ReversibleVault.loads(JSON.stringify(payload));
  const base = { schema_version: 1, salt: "a" };

  it("fingerprint_iterations 는 int() 강제 변환", () => {
    expect(load({ ...base, fingerprint_iterations: "7" }).fpIterations).toBe(7);
    expect(load({ ...base, fingerprint_iterations: 7.9 }).fpIterations).toBe(7);
    expect(() => load({ ...base, fingerprint_iterations: "x" })).toThrow();
  });

  it("fingerprint_scheme: 필드 없음 → legacy, null 은 그대로(KDF 경로)", () => {
    expect(load(base).fpScheme).toBe("sha256-v1");
    const v = load({ ...base, fingerprint_scheme: null });
    expect(v.toDict().fingerprint_scheme).toBeNull();
    const kdf = new ReversibleVault({ salt: "a", fingerprintIterations: v.fpIterations });
    expect(v.fingerprint("RRN", "x")).toBe(kdf.fingerprint("RRN", "x"));
  });

  it("엔트리 값은 타입 검사 없이 보존, 필수 키 누락·entries null 은 예외", () => {
    const e1 = { label: "A", original: "x", risk_level: "5" };
    expect(load({ ...base, entries: { "<A_1>": e1 } }).toDict().entries["<A_1>"]).toEqual({
      label: "A",
      original: "x",
      risk_level: "5",
      legal_basis: null,
      first_seen_offset: -1,
      occurrences: [],
      extra: {},
    });
    const e2 = { label: "A", original: "x", risk_level: 1, legal_basis: 5, first_seen_offset: "3" };
    const d2 = load({ ...base, entries: { "<A_1>": e2 } }).toDict().entries["<A_1>"];
    expect([d2?.legal_basis, d2?.first_seen_offset]).toEqual([5, "3"]);
    expect(load({ ...base, created_at: 5 }).toDict().created_at).toBe(5);
    expect(() => load({ ...base, entries: null })).toThrow();
    expect(() =>
      load({ ...base, entries: { "<A_1>": { original: "x", risk_level: 1 } } }),
    ).toThrow();
  });

  it("토큰 카운터는 Python int() 처럼 공백·전각 숫자를 허용한다", () => {
    const entry = (original: string) => ({ label: "A", original, risk_level: 1 });
    const v = load({
      ...base,
      entries: { "<A_ 12 >": entry("x"), "<A_1_0>": entry("y"), "<A_\uff15>": entry("z") },
    });
    expect(v.store("A", "fresh", 1)).toBe("<A_13>");
  });

  it("(label, original) 키는 NUL 이 들어 있어도 충돌하지 않는다", () => {
    const v = new ReversibleVault({ salt: "s", fingerprintIterations: 1 });
    expect([v.store("A\x00B", "C", 1), v.store("A", "B\x00C", 1), v.size]).toEqual([
      "<A\x00B_1>",
      "<A_1>",
      2,
    ]);
    expect(v.fingerprint("A\x00B", "C")).not.toBe(v.fingerprint("A", "B\x00C"));
  });

  it("pyJsonDumps: float 표기(1e-07, -0.0, 1e+21)와 indent=0 은 Python 과 같다", () => {
    const value = { h: 1e-7, i: -0.0, g: 1e21, x: 2.5, n: 3, z: [], y: {} };
    expect(pyJsonDumps(value, null)).toBe(
      '{"h": 1e-07, "i": -0.0, "g": 1e+21, "x": 2.5, "n": 3, "z": [], "y": {}}',
    );
    expect(pyJsonDumps({ a: [1, 2], b: {} }, 0)).toBe('{\n"a": [\n1,\n2\n],\n"b": {}\n}');
    expect(pyJsonDumps({ a: [1, { b: "한" }] }, 2)).toBe(
      '{\n  "a": [\n    1,\n    {\n      "b": "한"\n    }\n  ]\n}', // Python json.dumps(indent=2) 실측
    );
    // 알려진 한계: JS 는 1.0 과 1 을 구분하지 못한다 (Python 은 "1.0").
    expect(pyJsonDumps({ f: 1.0 }, null)).toBe('{"f": 1}');
  });
});

describe('미확인→재현: Anonymizer 요약의 legal_basis "" 는 "—"', () => {
  it('Python `legal_basis or "—"`', () => {
    const anon = new Anonymizer();
    const records = [
      { detection: dets()[3], action: "BLOCK", token: null }, // legal_basis ""
      { detection: dets()[2], action: "BLOCK", token: null }, // legal_basis null
    ];
    const combined = publicApi.score_combined_risk([]);
    // biome-ignore lint/suspicious/noExplicitAny: private buildSummary 를 직접 검증
    const summary = (anon as any).buildSummary(records, combined);
    expect(summary.by_legal_basis).toEqual({ "—": 2 });
  });
});

describe("Anonymizer asterisk — 아스트랄 span 의 별표 수는 코드 포인트 기준", () => {
  it("수학 숫자 RRN (Python 실측: 별표 14개)", () => {
    const rrn =
      "\u{1D7D7}\u{1D7CE}\u{1D7CE}\u{1D7CF}\u{1D7CE}\u{1D7CF}-\u{1D7CF}\u{1D7D0}\u{1D7D1}\u{1D7D2}\u{1D7D3}\u{1D7D4}\u{1D7D5}";
    const r = new Anonymizer(undefined, "asterisk").process(`주민 ${rrn} 확인`);
    expect(r.text).toBe(`주민 ${"*".repeat(14)} 확인`);
  });
});

describe("index.ts 공개 export", () => {
  it("reviewItems / blockedItems 가 공개된다", () => {
    expect(typeof publicApi.reviewItems).toBe("function");
    expect(typeof publicApi.blockedItems).toBe("function");
    const r = new publicApi.Anonymizer().process("연락처 010-1234-5678");
    expect(publicApi.blockedItems(r).length).toBe(1);
    expect(publicApi.reviewItems(r)).toEqual([]);
    const id: publicApi.Identifier = {
      label: "RRN",
      text: "x",
      attribute_class: "identifier" as never,
    };
    expect(id.label).toBe("RRN");
  });
});
