/**
 * Python v1.27 검출 동등성 — tools/gen-detect-parity.py 가 Python 테스트 소스의 문자열
 * 리터럴로 실측한 detect_all / normalize_unicode 결과와 TS 를 대조한다 (골드 35 픽스처 보강).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { protectionRemainders } from "../../src/core/coverage.js";
import { ForwardIntervalIndex } from "../../src/core/intervalIndex.js";
import { Action, ProcessingMode, policyFor } from "../../src/core/modes.js";
import { resolveOverlaps, selectNonOverlapping } from "../../src/core/overlap.js";
import { OverlapTrace, validateTraceLimit } from "../../src/core/trace.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../../src/core/types.js";
import { needsNormalization, normalizeUnicode, remapToSource } from "../../src/core/unicodeNorm.js";
import { validatedDetection } from "../../src/core/validation.js";
import { detectAll, detectCandidates } from "../../src/detect.js";
import { validateLabelFilter } from "../../src/labels.js";
import * as person from "../../src/patterns/person.js";
import { codepointOffsetToUtf16 } from "../goldmaster/harness.js";

type Proj = [
  string,
  string,
  number,
  number,
  number,
  number,
  string[],
  string | null,
  Record<string, unknown>,
  string | null,
  boolean,
  string | null,
];

interface Case {
  text: string;
  detections: Proj[];
  needs_normalization: boolean;
  normalized: string;
  offset_map: number[];
  literal_normalized: string;
}

const fixture = JSON.parse(
  readFileSync(join(import.meta.dirname, "detect-1.27.fixture.json"), "utf-8"),
) as {
  cases: Case[];
  exclusion_cases: { text: string; exclusions: string[]; detections: Proj[]; person: Proj[] }[];
  filter_cases: {
    text: string;
    include: string[] | null;
    exclude: string[] | null;
    detections: Proj[];
  }[];
  nd_cases: {
    text: string;
    detections: Proj[];
    anonymized: string;
    records: [string, number, number, string, string | null][];
  }[];
};

const toUtf16 = (text: string, p: Proj): Proj => [
  p[0],
  p[1],
  codepointOffsetToUtf16(text, p[2]),
  codepointOffsetToUtf16(text, p[3]),
  p[4],
  p[5],
  p[6],
  p[7],
  p[8],
  p[9],
  p[10],
  p[11],
];

const project = (d: DetectionResult): Proj => [
  d.label,
  d.text,
  d.start,
  d.end,
  d.riskLevel,
  d.confidence,
  d.evidence,
  d.legal_basis,
  d.extra,
  d.ruleId ?? null,
  d.normalized ?? false,
  d.subruleId ?? null,
];

const hasAstral = (s: string): boolean => /[\uD800-\uDFFF]/.test(s);

describe("detectAll — Python 1.27 실측 대조 (테스트 리터럴 전수)", () => {
  it("픽스처가 충분히 크다", () => {
    expect(fixture.cases.length).toBeGreaterThan(1000);
  });
  it.each(fixture.cases.map((c, i) => [i, c.text.slice(0, 40), c] as const))(
    "#%i %j",
    (_i, _label, c) => {
      expect(detectAll(c.text).map(project)).toEqual(c.detections.map((p) => toUtf16(c.text, p)));
    },
  );
});

describe("비ASCII 십진 숫자 + 보이지 않는 문자 — Python 1.27 실측 대조 (원문 재검사 패스)", () => {
  // 보이지 않는 문자가 두 값을 이어 붙이면 원문에서 검출기를 한 번 더 돌린다. 이 패스는 숫자가
  // 접히지 않은 텍스트를 보므로 Python ``\d``(유니코드 Nd)·``\s`` 의미가 그대로 필요하다.
  it("픽스처가 모든 Nd 체계를 덮는다", () => {
    expect(fixture.nd_cases.length).toBeGreaterThan(400);
    const scripts = new Set<number>();
    for (const c of fixture.nd_cases) {
      for (const ch of c.text) {
        if (/\p{Nd}/u.test(ch) && !/[0-9]/.test(ch)) {
          const cp = ch.codePointAt(0) as number;
          let zero = cp;
          while (/\p{Nd}/u.test(String.fromCodePoint(zero - 1)) && (cp - zero + 1) % 10 !== 0) {
            zero -= 1;
          }
          scripts.add(zero);
        }
      }
    }
    expect(scripts.size).toBeGreaterThanOrEqual(60);
  });
  it.each(fixture.nd_cases.map((c, i) => [i, c.text.slice(0, 40), c] as const))(
    "#%i %j",
    (_i, _label, c) => {
      expect(detectAll(c.text).map(project)).toEqual(c.detections.map((p) => toUtf16(c.text, p)));
      const result = new Anonymizer(ProcessingMode.STRICT, "tokenize").process(c.text);
      expect(result.text).toBe(c.anonymized);
      expect(
        result.detections.map((r) => [
          r.detection.label,
          r.detection.start,
          r.detection.end,
          r.action,
          r.token,
        ]),
      ).toEqual(
        c.records.map(([label, start, end, action, token]) => [
          label,
          codepointOffsetToUtf16(c.text, start),
          codepointOffsetToUtf16(c.text, end),
          action,
          token,
        ]),
      );
    },
  );
});

describe("normalizeUnicode — Python 1.27 실측 대조", () => {
  it("needsNormalization·normalized·fold_numeric=False 문자열과 (BMP) offset_map", () => {
    for (const c of fixture.cases) {
      expect(needsNormalization(c.text), c.text).toBe(c.needs_normalization);
      const [norm, omap] = normalizeUnicode(c.text);
      expect(norm, c.text).toBe(c.normalized);
      if (!hasAstral(c.text) && !hasAstral(norm)) expect(omap, c.text).toEqual(c.offset_map);
      expect(normalizeUnicode(c.text, { foldNumeric: false })[0], c.text).toBe(
        c.literal_normalized,
      );
    }
  });

  it("remapToSource: 호환 확장 안에서 끝나는 매치는 원본 글자를 통째로 덮는다", () => {
    const source = "aﬁb"; // ﬁ → fi
    const [norm, omap] = normalizeUnicode(source);
    expect(norm).toBe("afib");
    const d = makeDetection({
      label: "URL",
      text: "af",
      start: 0,
      end: 2,
      riskLevel: RiskLevel.LOW,
    });
    const [r] = remapToSource([d], omap, source);
    expect([r?.start, r?.end, r?.text, r?.normalized]).toEqual([0, 2, "aﬁ", true]);
  });
});

describe("PERSON exclusions·label 필터 — Python 1.27 실측 대조", () => {
  it.each(fixture.exclusion_cases.map((c) => [c.text, c] as const))("%j", (_t, c) => {
    expect(detectAll(c.text, null, null, { personExclusions: c.exclusions }).map(project)).toEqual(
      c.detections.map((p) => toUtf16(c.text, p)),
    );
    // person.detect 단독은 ruleId 를 채우지 않는다 (detect_all 만 채움).
    expect(person.detect(c.text, { exclusions: c.exclusions }).map(project)).toEqual(
      c.person.map((p) => toUtf16(c.text, p)),
    );
  });
  it.each(fixture.filter_cases.map((c) => [c.text, c] as const))("%j", (_t, c) => {
    expect(detectAll(c.text, c.include, c.exclude).map(project)).toEqual(
      c.detections.map((p) => toUtf16(c.text, p)),
    );
  });
  it("person exclusions 는 문자열 단독·비문자열 원소를 거부한다", () => {
    expect(() => person.normalizeExclusions("홍길동" as unknown as string[])).toThrow(TypeError);
    expect(() => person.normalizeExclusions([1 as unknown as string])).toThrow(TypeError);
    expect([...person.normalizeExclusions(["  김민수 ", "", "ＡＢ"])]).toEqual(["김민수", "AB"]);
  });
  it("validateLabelFilter — 순서 보존 중복 제거", () => {
    expect(validateLabelFilter(["PHONE", "EMAIL", "PHONE"], "include")).toEqual(["PHONE", "EMAIL"]);
    expect(validateLabelFilter(null, "include")).toBeNull();
    expect(validateLabelFilter([], "exclude")).toEqual([]);
  });
});

describe("core 신규 모듈 (Python trace/validation/_interval_index/_coverage 대응)", () => {
  const mk = (label: string, start: number, end: number, risk: RiskLevel, conf = 1.0) =>
    makeDetection({
      label,
      text: "x".repeat(end - start),
      start,
      end,
      riskLevel: risk,
      confidence: conf,
    });

  it("selectNonOverlapping: 입력 순서 우선, 엄격 부등호(인접 허용)", () => {
    const a = mk("PHONE", 0, 5, RiskLevel.HIGH);
    const b = mk("EMAIL", 4, 8, RiskLevel.HIGH);
    const c = mk("EMAIL", 5, 9, RiskLevel.HIGH);
    expect(selectNonOverlapping([a, b, c])).toEqual([a, c]);
  });

  it("resolveOverlaps policy: BLOCK 후보가 비차단 고위험보다 먼저", () => {
    const policy = policyFor(ProcessingMode.BALANCED);
    const lowConfHigh = mk("PERSON", 0, 5, RiskLevel.CRITICAL, 0.5); // BALANCED 에서 BLOCK 아님
    const blocked = mk("PHONE", 2, 7, RiskLevel.HIGH, 1.0);
    expect(policy.decide(lowConfHigh.riskLevel, lowConfHigh.confidence)).not.toBe(Action.BLOCK);
    expect(resolveOverlaps([lowConfHigh, blocked])).toEqual([lowConfHigh]);
    expect(resolveOverlaps([lowConfHigh, blocked], { policy })).toEqual([blocked]);
  });

  it("OverlapTrace 보고서 (Python 실측 — 동률 길이는 앞선 시작이 먼저 정렬)", () => {
    const trace = new OverlapTrace(1);
    const kept = mk("RRN", 0, 14, RiskLevel.CRITICAL);
    kept.ruleId = "ko-pii.rrn.v1";
    const dropped = mk("PHONE", 3, 10, RiskLevel.HIGH);
    const dropped2 = mk("PHONE", 2, 9, RiskLevel.HIGH);
    resolveOverlaps([kept, dropped, dropped2], { trace });
    expect(trace.report()).toEqual({
      schema_version: 1,
      contract: "ko-pii-overlap-trace-v1",
      scope: "common_overlap_only; excludes_detector_internal_and_merge_policy_rejections",
      limit: 1,
      truncated: true,
      omitted_events: 1,
      stages: { primary: { candidates: 3, kept: 1, discarded: 2 } },
      discarded: [
        {
          stage: "primary",
          reason: "lower_risk_priority",
          candidate: { label: "PHONE", rule_id: null, subrule_id: null, source_span: [2, 9] },
          blocker: {
            label: "RRN",
            rule_id: "ko-pii.rrn.v1",
            subrule_id: null,
            source_span: [0, 14],
          },
        },
      ],
    });
    expect(() => validateTraceLimit(1001)).toThrow(
      "trace_limit must be an integer between 0 and 1000",
    );
    expect(() => validateTraceLimit(1.5)).toThrow();
    expect(() => trace.record(kept, null, "other")).toThrow("unknown overlap stage");
  });

  it("detectAll trace 는 detectCandidates + resolveOverlaps 와 같은 결과", () => {
    const text = "주민 880101-1234568 연락처 010-1234-5678";
    const trace = new OverlapTrace();
    const out = detectAll(text, null, null, { trace });
    expect(out).toEqual(resolveOverlaps(detectCandidates(text)));
    expect(out.every((d) => d.ruleId === `ko-pii.${d.label.toLowerCase()}.v1`)).toBe(true);
    expect(trace.report().stages.primary?.candidates).toBe(detectCandidates(text).length);
  });

  it("validatedDetection: 원문 결속 검증", () => {
    const text = "홍길동 010";
    const ok = makeDetection({
      label: "PERSON",
      text: "홍길동",
      start: 0,
      end: 3,
      riskLevel: RiskLevel.HIGH,
    });
    const v = validatedDetection(ok, text);
    expect(v).toEqual(ok);
    expect(v).not.toBe(ok);
    expect(() => validatedDetection({ ...ok, end: 2 }, text)).toThrow(
      "detector text must equal the source slice",
    );
    expect(() => validatedDetection({ ...ok, label: "NAME" }, text)).toThrow(
      "detector must use an existing ko-pii label",
    );
    expect(
      validatedDetection({ ...ok, label: "NAME" }, text, { allowCustomLabels: true }).label,
    ).toBe("NAME");
    expect(() => validatedDetection({ ...ok, confidence: 2 }, text)).toThrow(
      "detector confidence must be finite and between 0 and 1",
    );
    expect(() => validatedDetection({ ...ok, start: 3, end: 3, text: "" }, text)).toThrow(
      "detector returned an invalid source span",
    );
    expect(() => validatedDetection(null, text)).toThrow(
      "detector must return DetectionResult objects",
    );
  });

  it("ForwardIntervalIndex: 중첩·margin·전진 전용", () => {
    const idx = new ForwardIntervalIndex([
      [10, 30],
      [12, 14],
    ]);
    expect(idx.overlaps(0, 10)).toBe(false);
    expect(idx.overlaps(15, 16)).toBe(true);
    idx.add(40, 45);
    expect(idx.overlaps(44, 50)).toBe(true);
    expect(idx.overlaps(46, 50)).toBe(false);
    expect(idx.overlaps(48, 50, 2)).toBe(false); // 45 > 48-2 아님 (Python 실측과 동일)
    expect(idx.overlaps(48, 50, 4)).toBe(true);
    expect(() => idx.overlaps(1, 2)).toThrow("interval pass must move forward");
  });

  it("protectionRemainders: 미피복 BLOCK 구간만 조각으로", () => {
    const text = "0123456789";
    const policy = policyFor(ProcessingMode.BALANCED);
    const parent = makeDetection({
      label: "RRN",
      text: "0123456789",
      start: 0,
      end: 10,
      riskLevel: RiskLevel.CRITICAL,
    });
    const winner = makeDetection({
      label: "PHONE",
      text: "3456",
      start: 3,
      end: 7,
      riskLevel: RiskLevel.HIGH,
    });
    const parts = protectionRemainders(text, [parent, winner], [winner], policy, () => "redact");
    expect(parts.map((p) => [p.start, p.end, p.text, p.subruleId, p.evidence.at(-1)])).toEqual([
      [0, 3, "012", "protection.overlap-remainder.v1", "protection:overlap_remainder"],
      [7, 10, "789", "protection.overlap-remainder.v1", "protection:overlap_remainder"],
    ]);
    expect(parts[0]?.extra.overlap_parent).toEqual({ label: "RRN", source_span: [0, 10] });
    expect(protectionRemainders(text, [parent, winner], [winner], policy, () => "partial")).toEqual(
      [],
    );
  });
});
