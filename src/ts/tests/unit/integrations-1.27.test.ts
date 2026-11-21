/**
 * integrations 1.27 — custom/literal 검출기, hybrid 병합 자격 규칙, secondary 검증.
 *
 * 기대값 근거: src/python/tests/unit/integrations/{test_custom,test_literal,test_hybrid,
 * test_secondary_validation}.py 와 `.venv/bin/python` 실측 (주석의 값).
 */
import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ValueError } from "../../src/core/errors.js";
import { Action, ProcessingMode, policyFor } from "../../src/core/modes.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../../src/core/types.js";
import type { SecondaryDetector } from "../../src/integrations/base.js";
import {
  CallableDetector,
  LiteralDetector,
  MergeMode,
  mergeCandidates,
  mergeDetections,
  RegexDetector,
  validateMergeConfig,
} from "../../src/integrations/index.js";
import { ReversibleVault } from "../../src/vault/reversible.js";

const det = (
  label: string,
  start: number,
  end: number,
  text: string,
  risk: RiskLevel = RiskLevel.MEDIUM,
  conf = 0.8,
  evidence: string[] = [],
): DetectionResult =>
  makeDetection({ label, text, start, end, riskLevel: risk, confidence: conf, evidence });

const spans = (it: Iterable<DetectionResult>) => [...it].map((r) => [r.text, r.start, r.end]);

function permutations<T>(xs: readonly T[]): T[][] {
  if (xs.length <= 1) return [[...xs]];
  return xs.flatMap((x, i) =>
    permutations([...xs.slice(0, i), ...xs.slice(i + 1)]).map((rest) => [x, ...rest]),
  );
}

function errorOf(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected an error");
}

/** Python 테스트의 DirectAdapter — 검증 없이 콜백 결과를 그대로 넘긴다. */
const direct = (callback: (text: string) => Iterable<unknown>): SecondaryDetector => ({
  name: "direct",
  detect: (text: string) => callback(text) as Iterable<DetectionResult>,
});

const anon = (opts: {
  mode?: ProcessingMode;
  strategy?: string;
  vault?: ReversibleVault;
  include?: string[] | null;
  exclude?: string[] | null;
  secondary?: SecondaryDetector | null;
  mergeMode?: string;
  roleSplitLabels?: Iterable<string> | null;
  personExclusions?: string[] | null;
}) =>
  new Anonymizer(
    opts.mode ?? ProcessingMode.STRICT,
    opts.strategy ?? "tokenize",
    opts.vault,
    opts.include ?? null,
    opts.exclude ?? null,
    opts.secondary ?? null,
    opts.mergeMode ?? "union",
    opts.roleSplitLabels ?? null,
    opts.personExclusions ?? null,
  );

describe("RegexDetector / CallableDetector (test_custom)", () => {
  it("이름 있는 캡처 그룹은 원문 오프셋과 기존 라벨을 쓴다", () => {
    const d = new RegexDetector("사번: (?<value>EMP-[0-9]{4})", {
      label: "ACCOUNT",
      group: "value",
    });
    const out = [...d.detect("사번: EMP-1042 사번: EMP-2")];
    // Python: [('ACCOUNT', 'EMP-1042', 4, 12, 4, 1.0, [], {})]
    expect(out).toEqual([
      makeDetection({
        label: "ACCOUNT",
        text: "EMP-1042",
        start: 4,
        end: 12,
        riskLevel: RiskLevel.HIGH,
        confidence: 1.0,
      }),
    ]);
    expect(d.name).toBe("custom-regex");
    expect(new CallableDetector(() => []).name).toBe("custom-callable");
  });

  it("Anonymizer 경로 — 문맥은 보존하고 캡처만 치환", () => {
    const d = new RegexDetector("사번: (?<value>EMP-[0-9]{4})", {
      label: "ACCOUNT",
      group: "value",
    });
    const result = anon({ strategy: "redact", include: ["ACCOUNT"], secondary: d }).process(
      "사번: EMP-1042",
    );
    expect(result.text).toBe("사번: [계좌번호]");
    const first = result.detections[0]?.detection;
    expect([first?.text, first?.start, first?.end]).toEqual(["EMP-1042", 4, 12]);
  });

  it("번호 그룹 — 참여하지 않은 선택 그룹은 건너뛴다", () => {
    // Python: RegexDetector("(a)|(b)", group=2).detect("ab ab") → [('b',1,2),('b',4,5)]
    expect(
      spans(new RegexDetector("(a)|(b)", { label: "PERSON", group: 2 }).detect("ab ab")),
    ).toEqual([
      ["b", 1, 2],
      ["b", 4, 5],
    ]);
    expect([...new RegexDetector("(abc)?x", { label: "PERSON", group: 1 }).detect("x")]).toEqual(
      [],
    );
  });

  const bad: Record<string, unknown>[] = [
    { pattern: "[" },
    { pattern: new Uint8Array([120]) },
    { pattern: "" },
    { label: "NEW_LABEL" },
    { label: [] },
    { group: 2 },
    { group: true },
    { group: "missing" },
    { confidence: Number.NaN },
    { confidence: Number.POSITIVE_INFINITY },
    { confidence: true },
    { confidence: -0.1 },
    { confidence: 1.1 },
    { riskLevel: 9 },
    { maxChars: 0 },
    { maxMatches: -1 },
    { maxMatches: true },
    { pattern: "x".repeat(4097) },
    { flags: "Q" },
  ];
  it.each(bad.map((kw) => [JSON.stringify(kw), kw] as const))(
    "잘못된 설정 %s → ValueError",
    (_n, kw) => {
      const { pattern = "x", ...rest } = kw;
      expect(
        () =>
          new RegexDetector(
            pattern as string,
            {
              label: "PERSON",
              ...(rest as object),
            } as never,
          ),
      ).toThrow(ValueError);
    },
  );

  const BASE = det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 1.0);
  const badResults: unknown[] = [
    null,
    "abc",
    { ...BASE, start: true },
    { ...BASE, start: -1 },
    { ...BASE, end: 4 },
    { ...BASE, end: 0 },
    { ...BASE, start: 1 },
    { ...BASE, text: "secret" },
    { ...BASE, label: "SECRET" },
    { ...BASE, riskLevel: "HIGH" },
    { ...BASE, confidence: Number.NaN },
    { ...BASE, confidence: 2 },
  ];
  it.each(badResults.map((b, i) => [i, b] as const))(
    "두 번째 결과가 잘못되면(#%s) 부분 결과 없이 실패하고 Vault 를 바꾸지 않는다",
    (_i, b) => {
      const detector = new CallableDetector(() => [BASE, b as DetectionResult]);
      const iter = detector.detect("abc");
      expect(() => iter.next()).toThrow(ValueError);
      const a = anon({ secondary: detector });
      expect(() => a.process("abc")).toThrow(ValueError);
      expect(a.vault.size).toBe(0);
    },
  );

  it("콜백 예외는 원문을 되울리지 않는다", () => {
    const broken = new CallableDetector((text) => {
      throw new Error(text);
    });
    const e = errorOf(() => [...broken.detect("DO_NOT_LOG_THIS")]);
    expect(e).toBeInstanceOf(ValueError);
    expect(e.message).not.toContain("DO_NOT_LOG_THIS");
  });

  it("한도·빈 매치·메타데이터 제거", () => {
    function* forever() {
      for (;;) yield BASE;
    }
    expect(() => [...new CallableDetector(forever, { maxMatches: 2 }).detect("abc")]).toThrow(
      ValueError,
    );
    expect(() => [
      ...new RegexDetector("x", { label: "PERSON", maxChars: 2 }).detect("xxx"),
    ]).toThrow(ValueError);
    expect(() => [...new RegexDetector("x*", { label: "PERSON" }).detect("abc")]).toThrow(
      ValueError,
    );
    const value = makeDetection({
      ...BASE,
      evidence: ["secret"],
      extra: { secret: "secret" },
      legal_basis: "secret",
      ruleId: "secret",
    });
    const [result] = [...new CallableDetector(() => [value]).detect("abc")];
    expect(result).toEqual(BASE);
    expect(result).not.toBe(value);
  });

  it("사용자 규칙 결과도 include/exclude 를 따른다", () => {
    const d = new RegexDetector("abc", { label: "PERSON" });
    expect(() => anon({ include: [], secondary: d })).toThrow(ValueError);
    expect(anon({ include: ["EMAIL"], secondary: d }).process("abc").text).toBe("abc");
    expect(anon({ exclude: ["PERSON"], secondary: d }).process("abc").text).toBe("abc");
  });
});

describe("LiteralDetector (test_literal)", () => {
  const TEXT = "김도구 김도구에게 김도구에게서 김도구리 큰김도구 김도구에게서는";
  // Python 실측 오프셋.
  it.each([
    ["word", [[0, 3]]],
    [
      "korean",
      [
        [0, 3],
        [4, 7],
        [10, 13],
      ],
    ],
    [
      "substring",
      [
        [0, 3],
        [4, 7],
        [10, 13],
        [17, 20],
        [23, 26],
        [27, 30],
      ],
    ],
  ] as const)("경계 %s 와 원문 오프셋", (boundary, expected) => {
    const found = [...new LiteralDetector({ PERSON: ["김도구"] }, { boundary }).detect(TEXT)];
    expect(found.map((r) => [r.start, r.end])).toEqual(expected);
    expect(found.every((r) => TEXT.slice(r.start, r.end) === r.text && r.text === "김도구")).toBe(
      true,
    );
  });

  it("이스케이프와 가장 긴 유효 값", () => {
    const d = new LiteralDetector({ PERSON: ["A+B", "A+B", "A+B Co", "A"] });
    expect(spans(d.detect("A+B! A+B Company A+B Co"))).toEqual([
      ["A+B", 0, 3],
      ["A+B", 5, 8],
      ["A+B Co", 17, 23],
    ]);
  });

  it("겹치는 시작 허용, 정규화 없음", () => {
    const d = new LiteralDetector({ PERSON: ["aba"] }, { boundary: "substring" });
    expect([...d.detect("ababa")].map((r) => [r.start, r.end])).toEqual([
      [0, 3],
      [2, 5],
    ]);
    expect([...d.detect("ABA ａｂａ a​ba")]).toEqual([]);
  });

  it.each([
    ["EMAIL", "김도구"],
    ["PERSON", "Alice"],
  ])("조사 허용은 한글 PERSON 한정 (%s %s)", (label, term) => {
    expect([
      ...new LiteralDetector({ [label]: [term] }, { boundary: "korean" }).detect(`${term}에게`),
    ]).toEqual([]);
  });

  it("라벨 그룹 순서·유니코드 단어 경계 (Python 실측)", () => {
    const d = new LiteralDetector(
      { PERSON: ["홍길동"], EMAIL: ["a@b.co"], ACCOUNT: ["110-123"] },
      { boundary: "korean" },
    );
    // Python: [('PERSON', '홍길동', 24, 27)]
    expect(
      [...d.detect("홍길동님 a@b.co에게 110-123으로 홍길동은 x홍길동")].map((r) => [
        r.label,
        r.start,
        r.end,
      ]),
    ).toEqual([["PERSON", 24, 27]]);
    // Python: [10, 20]
    expect(
      [...new LiteralDetector({ PERSON: ["Kim"] }).detect("Kim_ Kim1 Kim! 가Kim Kim")].map(
        (r) => r.start,
      ),
    ).toEqual([10, 20]);
    expect(new LiteralDetector({ PERSON: ["x"] }).name).toBe("custom-literal");
  });

  const invalid: unknown[] = [
    {},
    { UNKNOWN: ["secret"] },
    { PERSON: "secret" },
    { PERSON: [] },
    { PERSON: [""] },
    { PERSON: ["  "] },
    { PERSON: [null] },
    { PERSON: ["x".repeat(257)] },
    { PERSON: Array(1025).fill("secret") },
    { PERSON: Array(257).fill("a".repeat(256)) },
    { PERSON: ["secret"], EMAIL: ["secret"] },
  ];
  it.each(invalid.map((v, i) => [i, v] as const))(
    "잘못된 설정은 값 없이 거부 (#%s)",
    (_i, values) => {
      const e = errorOf(() => new LiteralDetector(values as Record<string, string[]>));
      expect(e).toBeInstanceOf(ValueError);
      expect(e.message).not.toContain("secret");
    },
  );

  it("실패하는 생성기도 값 없이 거부", () => {
    function* bad(): Generator<string> {
      yield "Alice";
      throw new Error("private value");
    }
    const e = errorOf(() => new LiteralDetector({ PERSON: bad() }));
    expect(e.message).toContain("invalid or beyond-limit");
    expect(e.message).not.toContain("private");
  });

  it.each([null, [], "fuzzy"])("잘못된 boundary %j", (boundary) => {
    expect(
      () => new LiteralDetector({ PERSON: ["Alice"] }, { boundary: boundary as never }),
    ).toThrow(ValueError);
  });

  it("한도는 yield 전에 실패", () => {
    const d = new LiteralDetector({ PERSON: ["Alice"] }, { maxMatches: 1 });
    expect(() => d.detect("Alice Alice").next()).toThrow(ValueError);
    expect(() => [
      ...new LiteralDetector({ PERSON: ["Alice"] }, { maxChars: 2 }).detect("Alice"),
    ]).toThrow(ValueError);
  });

  it("Map 입력도 받는다", () => {
    const d = new LiteralDetector(new Map([["PERSON", ["Alice"]]]));
    expect(spans(d.detect("to Alice."))).toEqual([["Alice", 3, 8]]);
  });

  it("Anonymizer 통합과 제외", () => {
    const d = new LiteralDetector({ PERSON: ["김도구"] }, { boundary: "korean" });
    expect(
      anon({ mode: ProcessingMode.STRICT, secondary: d, include: ["PERSON"] }).process("김도구에게")
        .text,
    ).toBe("<PERSON_1>에게");
    expect(anon({ secondary: d, exclude: ["PERSON"] }).process("김도구에게").text).toBe(
      "김도구에게",
    );
    expect(anon({ secondary: d, personExclusions: ["김도구"] }).process("김도구에게").text).toBe(
      "김도구에게",
    );
  });
});

describe("hybrid 1.27 병합 자격 (test_hybrid)", () => {
  const strict = policyFor(ProcessingMode.STRICT);

  it.each([MergeMode.ENRICH_PRIMARY, MergeMode.CROSS_VALIDATION])(
    "%s — 중복 secondary 는 확신도 보너스를 한 번만",
    (mode) => {
      const primary = det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.6);
      const secondary = det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.9);
      const once = mergeDetections([primary], [secondary], mode, null, { policy: strict })[0]!;
      for (const count of [2, 10]) {
        const repeated = mergeDetections([primary], Array(count).fill(secondary), mode, null, {
          policy: strict,
        })[0]!;
        expect(once.confidence).toBe(0.65);
        expect(repeated.confidence).toBe(0.65);
        expect(repeated.evidence).toEqual(once.evidence);
      }
      expect(primary.confidence).toBe(0.6);
    },
  );

  it("ENRICH_PRIMARY — 후보 순서와 무관하게 가장 높은 확신도로 보강", () => {
    const primary = det("PERSON", 0, 3, "abc", RiskLevel.MEDIUM, 0.6);
    const low = det("PERSON", 0, 3, "abc", RiskLevel.MEDIUM, 0.7, ["low"]);
    const high = det("PERSON", 0, 3, "abc", RiskLevel.MEDIUM, 0.9, ["high"]);
    for (const candidates of permutations([low, high, high])) {
      const out = mergeDetections([primary], candidates, MergeMode.ENRICH_PRIMARY)[0]!;
      expect(out.confidence).toBe(0.65);
      expect(out.extra.secondary_confirmed_by).toEqual(["high"]);
    }
  });

  it("CROSS_VALIDATION — 반복 secondary 는 primary 확신도를 누적하지 않는다", () => {
    const p = det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.6);
    const s = det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.9);
    const once = mergeDetections([p], [s], "cross_validation");
    const many = mergeDetections([p], Array(20).fill(s), "cross_validation");
    expect(many).toEqual(once);
    expect(many[0]?.confidence).toBe(0.65);
    const solo = det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.95);
    expect(mergeDetections([], Array(10).fill(solo), "cross_validation")).toEqual(
      mergeDetections([], [solo], "cross_validation"),
    );
  });

  it("CROSS_VALIDATION — secondary 단독 후보는 순서와 무관하게 최고 확신도×0.7 (Python 0.693)", () => {
    for (const confidences of permutations([0.99, 0.2, 0.95])) {
      const cands = confidences.map((c) => det("PERSON", 0, 3, "abc", RiskLevel.HIGH, c));
      const out = mergeDetections([], cands, "cross_validation");
      expect(out.map((d) => [d.confidence, d.evidence, d.extra])).toEqual([
        [0.99 * 0.7, ["uncorroborated:primary_missed"], { cross_val: "secondary_only" }],
      ]);
    }
  });

  it("FALLBACK_SECONDARY — REVIEW primary 를 완전히 덮는 같은 라벨 secondary 만 확신도 상향 (Python 실측)", () => {
    const p = det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.6);
    expect(strict.decide(p.riskLevel, p.confidence)).toBe(Action.REVIEW);
    const run = (sec: DetectionResult[]) =>
      mergeDetections([p], sec, "fallback_secondary").map((o) => [
        o.label,
        o.start,
        o.end,
        o.confidence,
        o.evidence,
      ]);
    expect(run([det("PERSON", 0, 4, "abcd", RiskLevel.HIGH, 0.9)])).toEqual([
      ["PERSON", 0, 3, 0.9, ["corroborated_by:secondary(PERSON)"]],
    ]);
    expect(run([det("PERSON", 0, 2, "ab", RiskLevel.HIGH, 0.99)])).toEqual([
      ["PERSON", 0, 3, 0.6, []],
    ]);
    expect(
      run([
        det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.95),
        det("PERSON", 0, 3, "abc", RiskLevel.HIGH, 0.97),
      ]),
    ).toEqual([["PERSON", 0, 3, 0.97, ["corroborated_by:secondary(PERSON)"]]]);
    expect(run([det("EMAIL", 0, 3, "abc", RiskLevel.HIGH, 0.99)])).toEqual([
      ["PERSON", 0, 3, 0.6, []],
    ]);
  });

  it("mergeCandidates 는 겹침을 남긴다 (해소는 mergeDetections)", () => {
    const a = det("PERSON", 0, 3, "abc");
    const b = det("ADDRESS", 1, 4, "bcd");
    expect(mergeCandidates([a], [b], "union")).toEqual([a, b]);
    expect(mergeDetections([a], [b], "union")).toHaveLength(1);
  });

  it.each([
    ["typo", null],
    ["union", ["PESRON"]],
    ["role_split", "PERSON"],
    ["union", [true]],
  ] as const)("잘못된 설정(%s, %j)은 입력 소비 전에 단일 메시지 ValueError", (mode, labels) => {
    function* unexpected(): Generator<DetectionResult> {
      throw new Error("bad merge settings must not consume input");
      // biome-ignore lint/correctness/noUnreachable: Python 테스트와 같은 생성기 형태 유지
      yield det("PERSON", 0, 1, "x");
    }
    const e = errorOf(() =>
      mergeDetections(unexpected(), unexpected(), mode, labels as unknown as string[]),
    );
    expect(e).toBeInstanceOf(ValueError);
    expect(e.message).toBe(
      "invalid merge_mode or role_split_labels; use registered modes and labels",
    );
  });

  it("validateMergeConfig — 빈 라벨은 빈 집합, null 은 기본", () => {
    expect(validateMergeConfig("role_split", [])).toEqual([MergeMode.ROLE_SPLIT, new Set()]);
    expect(validateMergeConfig("union", null)).toEqual([MergeMode.UNION, null]);
    expect(validateMergeConfig("role_split", ["PERSON", "PERSON"])[1]).toEqual(new Set(["PERSON"]));
  });

  it("Anonymizer — 중복 secondary 는 출력을 바꾸지 않는다", () => {
    const repeat = (count: number): SecondaryDetector => ({
      name: "repeat",
      detect: (text) => {
        const once = [
          ...new RegexDetector("이도윤", { label: "PERSON", riskLevel: RiskLevel.HIGH }).detect(
            text,
          ),
        ];
        return Array.from({ length: count }, () => once).flat();
      },
    });
    const text = "담당자 이도윤에게 문의하세요";
    const results = [1, 2, 10].map((n) =>
      anon({
        mode: ProcessingMode.BALANCED,
        mergeMode: "enrich_primary",
        secondary: repeat(n),
      }).process(text),
    );
    expect(new Set(results.map((r) => r.text)).size).toBe(1);
    expect(new Set(results.map((r) => r.detections[0]?.action)).size).toBe(1);
  });

  it("Anonymizer — cross_validation 자기 확인 금지 (REVIEW, 0.99×0.7)", () => {
    for (const confidences of permutations([0.99, 0.2, 0.95])) {
      const d: SecondaryDetector = {
        name: "d",
        detect: (text) =>
          confidences.map((c) => det("PERSON", 0, text.length, text, RiskLevel.HIGH, c)),
      };
      const result = anon({
        include: ["PERSON"],
        mergeMode: "cross_validation",
        secondary: d,
      }).process("XQZtoken");
      const record = result.detections[0]!;
      expect(record.action).toBe(Action.REVIEW);
      expect(record.detection.confidence).toBe(0.99 * 0.7);
      expect(record.detection.evidence.some((e) => e.startsWith("corroborated_by:"))).toBe(false);
    }
  });
});

describe("secondary 검증 (test_secondary_validation)", () => {
  const GOOD = det("ACCOUNT", 0, 3, "abc", RiskLevel.HIGH, 1.0);
  const malformed: unknown[] = [
    null,
    "abc",
    { ...GOOD, label: "UNKNOWN" },
    { ...GOOD, text: "xyz" },
    { ...GOOD, start: -1 },
    { ...GOOD, start: true },
    { ...GOOD, end: 0 },
    { ...GOOD, end: 4 },
    { ...GOOD, riskLevel: 9 },
    { ...GOOD, confidence: Number.NaN },
    { ...GOOD, confidence: 1.1 },
    { ...GOOD, evidence: "private" },
    { ...GOOD, extra: [] },
    { ...GOOD, normalized: "private" },
    { ...GOOD, ruleId: [] },
    { ...GOOD, legal_basis: 123 },
  ];
  it.each(malformed.map((b, i) => [i, b] as const))(
    "뒤쪽 결과가 잘못되면(#%s) Vault 쓰기 없이 거부",
    (_i, bad) => {
      const vault = new ReversibleVault();
      vault.store("ACCOUNT", "existing", 4);
      const before = vault.dumps();
      const a = anon({ vault, secondary: direct(() => [GOOD, bad]) });
      const e = errorOf(() => a.process("abc"));
      expect(e).toBeInstanceOf(ValueError);
      expect(e.message).toContain("secondary detector");
      expect(vault.dumps()).toBe(before);
    },
  );

  it.each(
    Object.values(MergeMode).flatMap((m) =>
      Object.values(ProcessingMode).map((p) => [m, p] as const),
    ),
  )("필터·병합 전에 검증 (%s / %s)", (mergeMode, mode) => {
    const bad = { ...GOOD, text: "DO_NOT_LOG_THIS" };
    const a = anon({ include: ["EMAIL"], mode, mergeMode, secondary: direct(() => [bad]) });
    const e = errorOf(() => a.process("abc"));
    expect(e).toBeInstanceOf(ValueError);
    expect(e.message).not.toContain("DO_NOT_LOG_THIS");
    expect(a.vault.size).toBe(0);
  });

  it.each([{ mergeMode: "typo" }, { roleSplitLabels: ["PESRON"] }, { roleSplitLabels: "PERSON" }])(
    "생성자 설정 오류는 검출기 호출 전에 (%j)",
    (settings) => {
      const unexpected = direct(() => {
        throw new Error("configuration error must precede detector invocation");
      });
      expect(() => anon({ secondary: unexpected, ...(settings as object) })).toThrow(ValueError);
    },
  );

  it("role_split 빈 라벨·중복 라벨 의미 보존", () => {
    const adapter = direct(() => [{ ...GOOD, label: "PERSON" }]);
    const a = anon({
      secondary: adapter,
      mergeMode: "role_split",
      roleSplitLabels: ["PERSON", "PERSON"],
    });
    expect(a.roleSplitLabels).toEqual(new Set(["PERSON"]));
    expect(a.process("abc").text).toBe("<PERSON_1>");
    expect(a.process("abc").text).toBe("<PERSON_1>");
    const empty = anon({ secondary: adapter, mergeMode: "role_split", roleSplitLabels: [] });
    expect(empty.process("abc").text).toBe("abc");
  });
});

describe("rag.maskMetadata (_rag.mask_metadata)", () => {
  it("문자열 값만 마스킹하고 키·비문자열은 유지 (Python 실측)", async () => {
    const { maskMetadata } = await import("../../src/integrations/rag.js");
    const a = new Anonymizer();
    expect(
      maskMetadata(
        {
          contact: "demo@example.com",
          nested: ["demo@example.com", { k: "010-1234-5678" }],
          count: 2,
          ok: true,
          n: null,
        },
        a,
      ),
    ).toEqual({
      contact: "<EMAIL_1>",
      nested: ["<EMAIL_1>", { k: "<PHONE_1>" }],
      count: 2,
      ok: true,
      n: null,
    });
    expect(maskMetadata({ v: 1.5 }, new Anonymizer())).toEqual({ v: 1.5 });
    expect(
      maskMetadata(
        { note: "담당자는 김다은입니다." },
        new Anonymizer(ProcessingMode.STRICT, "redact"),
      ),
    ).toEqual({ note: "담당자는 [성명]입니다." });
  });

  it("마스킹이 필요한 키·지원하지 않는 값은 실패", async () => {
    const { maskMetadata } = await import("../../src/integrations/rag.js");
    expect(errorOf(() => maskMetadata({ "demo@example.com": "x" }, new Anonymizer())).message).toBe(
      "RAG metadata keys must not contain values requiring masking",
    );
    expect(() => maskMetadata({ value: () => 1 }, new Anonymizer())).toThrow(ValueError);
  });
});
