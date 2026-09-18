/**
 * integrations(hybrid 병합) + Anonymizer secondary 경로 — Python 실측 대조.
 *
 * integrations.fixture.json 은 Python ko-pii 가 같은 입력에 낸 출력이다(무작위 검출 목록 ×
 * 6 병합 모드, MockSecondaryDetector 를 붙인 Anonymizer). 전체 대조(400×6 + 216건)는
 * 포팅 시점에 불일치 0건이었고, 여기에는 그 일부를 회귀용으로 고정한다.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { type DetectionResult, makeDetection } from "../../src/core/types.js";
import {
  DEFAULT_ROLE_SPLIT_LABELS,
  MergeMode,
  MockSecondaryDetector,
  mergeDetections,
} from "../../src/index.js";
import { ReversibleVault } from "../../src/vault/reversible.js";

interface Det {
  label: string;
  text: string;
  start: number;
  end: number;
  risk: number;
  conf: number;
  evidence: string[];
  legal_basis: string | null;
  extra: Record<string, unknown>;
}
interface Fixture {
  cases: {
    primary: Det[];
    secondary: Det[];
    rsl: string[] | null;
    result: Record<string, Det[]>;
  }[];
  anon: {
    text: string;
    fixed: Det[];
    mode: string;
    inc: string[] | null;
    exc: string[] | null;
    strategy: string;
    out: string;
    records: [string, string, string | null, number, number, number, string[]][];
    summary: Record<string, unknown>;
  }[];
  bad_mode: string;
}

const fixture = JSON.parse(
  readFileSync(join(import.meta.dirname, "integrations.fixture.json"), "utf-8"),
) as Fixture;

const mk = (d: Det): DetectionResult =>
  makeDetection({
    label: d.label,
    text: d.text,
    start: d.start,
    end: d.end,
    riskLevel: d.risk,
    confidence: d.conf,
    evidence: [...d.evidence],
    legal_basis: d.legal_basis,
    extra: { ...d.extra },
  });
const toDict = (d: DetectionResult): Det => ({
  label: d.label,
  text: d.text,
  start: d.start,
  end: d.end,
  risk: d.riskLevel,
  conf: d.confidence,
  evidence: [...d.evidence],
  legal_basis: d.legal_basis,
  extra: { ...d.extra },
});

describe("mergeDetections — Python 실측 대조", () => {
  it("픽스처가 비어 있지 않다", () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(10);
    expect(fixture.anon.length).toBeGreaterThanOrEqual(10);
  });

  it.each(Object.values(MergeMode))("모드 %s", (mode) => {
    for (const c of fixture.cases) {
      const out = mergeDetections(c.primary.map(mk), c.secondary.map(mk), mode, c.rsl);
      expect(out.map(toDict)).toEqual(c.result[mode]);
    }
  });

  it("ROLE_SPLIT 기본 위임 라벨은 퍼지 10종", () => {
    expect([...DEFAULT_ROLE_SPLIT_LABELS].sort()).toEqual(
      [
        "ADDRESS",
        "AGE",
        "DT_BIRTH",
        "EDUCATION",
        "HEIGHT",
        "MAJOR",
        "NATIONALITY",
        "PERSON",
        "POSITION",
        "WEIGHT",
      ].sort(),
    );
  });

  it("MockSecondaryDetector 는 본문에 있는 토큰만 반환한다", () => {
    const d = mk({
      label: "PERSON",
      text: "홍길동",
      start: 0,
      end: 3,
      risk: 3,
      conf: 0.9,
      evidence: [],
      legal_basis: null,
      extra: {},
    });
    const mock = new MockSecondaryDetector([d]);
    expect([...mock.detect("홍길동 과장")]).toEqual([d]);
    expect([...mock.detect("김철수 과장")]).toEqual([]);
    expect(mock.name).toBe("mock");
  });
});

describe("Anonymizer secondary 병합 — Python 실측 대조", () => {
  it.each(fixture.anon.map((a, i) => [`#${i} ${a.mode} inc=${a.inc} exc=${a.exc}`, a] as const))(
    "%s",
    (_name, a) => {
      const vault = new ReversibleVault({
        salt: "00".repeat(16),
        secretKey: "k",
        fingerprintIterations: 1,
      });
      const result = new Anonymizer(
        ProcessingMode.STRICT,
        a.strategy,
        vault,
        a.inc,
        a.exc,
        new MockSecondaryDetector(a.fixed.map(mk)),
        a.mode,
      ).process(a.text);

      expect(result.text).toBe(a.out);
      expect(
        result.detections.map((r) => [
          r.detection.label,
          r.action,
          r.token,
          r.detection.start,
          r.detection.end,
          r.detection.confidence,
          [...r.detection.evidence],
        ]),
      ).toEqual(a.records);
      expect(result.summary).toEqual(a.summary);
    },
  );

  it("잘못된 merge_mode 는 Python 과 같은 ValueError", () => {
    const run = () =>
      new Anonymizer(
        undefined,
        undefined,
        undefined,
        null,
        null,
        new MockSecondaryDetector([]),
        "bogus",
      ).process("x");
    let message = "no error";
    try {
      run();
    } catch (e) {
      message = `${(e as Error).name}: ${(e as Error).message}`;
    }
    expect(message).toBe(fixture.bad_mode);
  });

  it("secondary 가 없으면 기존 동작 그대로 (생성자 인자 5개 호환)", () => {
    const text = "담당자 홍길동 010-1234-5678";
    const a = new Anonymizer(ProcessingMode.STRICT, "redact").process(text);
    const b = new Anonymizer(ProcessingMode.STRICT, "redact", undefined, null, null).process(text);
    expect(a.text).toBe(b.text);
  });
});
