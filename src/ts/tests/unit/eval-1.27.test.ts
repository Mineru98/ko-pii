/**
 * eval 1.27 — metrics 최대 일대일 매칭, output/domain/external 평가, ko-pii-evaluate CLI.
 *
 * 기대값 근거: src/python/tests/unit/eval/{test_metrics,test_output,test_domain,test_external,
 * test_slices,test_evaluation_integrity,test_domain_scenarios}.py 와 `.venv/bin/python` 실측.
 * Python 의 monkeypatch(label_to_hangul·_detect_candidates·_apply 교체)는 ESM 에서 불가하므로
 * 같은 상태를 만드는 AnonymizationResult·보고서·baseline 파일을 직접 구성해 대조한다.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type AnonymizationResult, Anonymizer } from "../../src/anonymizer.js";
import { ValueError } from "../../src/core/errors.js";
import { Action, ProcessingMode } from "../../src/core/modes.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../../src/core/types.js";
import {
  compareReports,
  type EvaluationReport,
  evaluate,
  formatSummary,
  LabeledDocument,
  loadDataset,
  main,
  validateProvenance,
} from "../../src/eval/domain.js";
import { K_PII_LABELS, loadKPiiBench } from "../../src/eval/external.js";
import { matchingSize, scoreCorpus, scoreDocument } from "../../src/eval/metrics.js";
import { assessOutput, OUTPUT_STATES } from "../../src/eval/output.js";
import type { GoldDocument, GoldSpan } from "../../src/eval/types.js";

const g = (label: string, start: number, end: number, text: string): GoldSpan => ({
  label,
  start,
  end,
  text,
});
const p = (label: string, start: number, end: number, text: string): DetectionResult =>
  makeDetection({ label, text, start, end, riskLevel: RiskLevel.HIGH });

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

const clone = <T>(v: T): T => structuredClone(v);
const json = (v: unknown) => JSON.stringify(v);

describe("metrics — 최대 일대일 매칭 (test_metrics)", () => {
  it("partial 매칭은 gold·예측 순서와 무관", () => {
    const spans = [g("PERSON", 0, 2, "ab"), g("PERSON", 2, 4, "cd")];
    const preds = [p("PERSON", 1, 3, "bc"), p("PERSON", 0, 1, "a")];
    for (const go of permutations(spans)) {
      for (const po of permutations(preds)) {
        const m = scoreDocument({ text: "abcd", spans: go }, po.values()).get("PERSON")!;
        expect([m.tp, m.fp, m.fn, m.f1]).toEqual([2, 0, 0, 1.0]);
      }
    }
  });

  it.each(["strcit", "PARTIAL", "", null, [], 1])(
    "잘못된 매칭 모드 %j 는 빈 데이터에도 거부",
    (mode) => {
      expect(() => scoreDocument({ text: "", spans: [] }, [], mode as string)).toThrow(
        /match mode/,
      );
      expect(() => scoreCorpus([], () => [], mode as string)).toThrow(/match mode/);
    },
  );

  it("예측 하나가 gold 둘을 확인할 수 없다", () => {
    const doc = { text: "abcd", spans: [g("PERSON", 0, 2, "ab"), g("PERSON", 2, 4, "cd")] };
    const m = scoreDocument(doc, [p("PERSON", 0, 4, "abcd")]).get("PERSON")!;
    expect([m.tp, m.fp, m.fn]).toEqual([1, 0, 1]);
  });

  it("strict 중복 span 은 한 번씩만", () => {
    const doc = { text: "ab", spans: [g("PERSON", 0, 2, "ab")] };
    const m = scoreDocument(doc, [p("PERSON", 0, 2, "ab"), p("PERSON", 0, 2, "ab")], "strict").get(
      "PERSON",
    )!;
    expect([m.tp, m.fp, m.fn]).toEqual([1, 1, 0]);
  });

  it("라벨 키는 정렬 순서", () => {
    const doc = { text: "abcd", spans: [g("PHONE", 0, 1, "a"), g("EMAIL", 1, 2, "b")] };
    expect([...scoreDocument(doc, [p("ADDRESS", 3, 4, "d")]).keys()]).toEqual([
      "ADDRESS",
      "EMAIL",
      "PHONE",
    ]);
  });

  it("소형 그래프 전수 오라클과 일치", () => {
    const oracle = (
      edges: number[][],
      index = 0,
      used: ReadonlySet<number> = new Set(),
    ): number => {
      if (index === edges.length) return 0;
      let best = oracle(edges, index + 1, used);
      for (const q of edges[index]!) {
        if (!used.has(q))
          best = Math.max(best, 1 + oracle(edges, index + 1, new Set([...used, q])));
      }
      return best;
    };
    let seed = 20261027;
    const rand = () => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed / 2 ** 31;
    };
    for (let k = 0; k < 200; k++) {
      const predictions = Math.floor(rand() * 7);
      const gold = Math.floor(rand() * 7);
      const edges = Array.from({ length: gold }, () =>
        Array.from({ length: predictions }, (_, q) => q).filter(() => rand() < 0.5),
      );
      expect(matchingSize(edges, predictions)).toBe(oracle(edges));
    }
  });

  it("긴 증가 경로도 재귀 없이", () => {
    const edges = [...Array.from({ length: 1500 }, (_, i) => [i, i + 1]), [0]];
    expect(matchingSize(edges, 1501)).toBe(1501);
  });
});

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "kopii-eval-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function writeJsonl(name: string, rows: unknown[]): string {
  const file = path.join(tmp, name);
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n"), "utf-8");
  return file;
}

function capture(): { out: () => string; err: () => string } {
  let out = "";
  let err = "";
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    out += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
    err += String(chunk);
    return true;
  });
  return { out: () => out, err: () => err };
}

const readJson = (file: string) => JSON.parse(fs.readFileSync(file, "utf-8"));

const PHONE = "010-1234-5678";
const phoneDocument = () =>
  new LabeledDocument("sample-1", { text: PHONE, spans: [g("PHONE", 0, PHONE.length, PHONE)] });

describe("output 평가 (test_output)", () => {
  it.each(["redact", "asterisk", "tokenize", "hashed", "fpe"])(
    "%s — 실제 치환을 측정하고 원문을 복사하지 않는다",
    (strategy) => {
      const report = evaluate([phoneDocument()], {
        labels: ["PHONE"],
        outputMode: ProcessingMode.STRICT,
        outputStrategy: strategy,
      });
      expect(report.output_evaluation!.counts.replaced).toBe(1);
      expect(report.output_evaluation!.not_fully_replaced).toBe(0);
      expect(json(report)).not.toContain(PHONE);
    },
  );

  it("AUDIT 모드 — 검출 성공은 출력 성공이 아니다", () => {
    const report = evaluate([phoneDocument()], {
      labels: ["PHONE"],
      outputMode: ProcessingMode.AUDIT,
    });
    expect(report.micro.tp).toBe(1);
    expect(report.output_evaluation!.counts.retained_by_policy).toBe(1);
  });

  it("partial 전략은 제거로 인증하지 않는다", () => {
    const report = evaluate([phoneDocument()], {
      labels: ["PHONE"],
      outputMode: ProcessingMode.STRICT,
      outputStrategy: "partial",
    });
    expect(report.output_evaluation!.counts.partial_strategy).toBe(1);
    expect(report.output_evaluation!.not_fully_replaced).toBe(1);
  });

  it("미검출 gold 는 missed", () => {
    const text = "synthetic secret";
    const doc = new LabeledDocument("sample-1", {
      text,
      spans: [g("PERSON", 0, text.length, text)],
    });
    const report = evaluate([doc], { labels: ["PERSON"], outputMode: ProcessingMode.STRICT });
    expect(report.output_evaluation!.counts.missed).toBe(1);
  });

  const fakeResult = (
    text: string,
    detection: DetectionResult,
    action: Action,
    substitutions: { start: number; end: number; outputStart: number; outputEnd: number }[],
    strategy: string | null = "redact",
  ) =>
    ({
      text,
      detections: [{ detection, action, token: null, strategy }],
      substitutions,
    }) as unknown as AnonymizationResult;

  it("불완전 검출은 전체 치환을 주장할 수 없다 (partially_replaced)", () => {
    const d = p("PHONE", 4, PHONE.length, PHONE.slice(4));
    const out = `010-[전화번호]`;
    const result = fakeResult(out, d, Action.BLOCK, [
      { start: 4, end: PHONE.length, outputStart: 4, outputEnd: out.length },
    ]);
    const [row] = assessOutput(phoneDocument().gold, result, "redact");
    expect(row!.state).toBe("partially_replaced");
    expect(row!.covered_source_characters).toBe(PHONE.length - 4);
  });

  it("내보낸 치환 문자열을 검사한다 (literal_retained)", () => {
    const d = p("PHONE", 0, PHONE.length, PHONE);
    const result = fakeResult(PHONE, d, Action.BLOCK, [
      { start: 0, end: PHONE.length, outputStart: 0, outputEnd: PHONE.length },
    ]);
    expect(assessOutput(phoneDocument().gold, result, "redact")[0]!.state).toBe("literal_retained");
  });

  it("REVIEW 결정은 치환이 아니다", () => {
    const d = makeDetection({
      label: "PHONE",
      text: PHONE,
      start: 0,
      end: PHONE.length,
      riskLevel: RiskLevel.HIGH,
      confidence: 0.6,
    });
    const result = fakeResult(PHONE, d, Action.REVIEW, []);
    expect(assessOutput(phoneDocument().gold, result, "redact")[0]!.state).toBe(
      "retained_by_policy",
    );
  });

  it("치환 좌표는 반복·정규화 입력에서 원문 기준", () => {
    const text = `연락처: ${PHONE} / ${PHONE}`;
    const result = new Anonymizer(ProcessingMode.STRICT, "tokenize", null, ["PHONE"]).process(text);
    expect(result.substitutions).toHaveLength(2);
    for (const span of result.substitutions) {
      expect(text.slice(span.start, span.end)).toBe(PHONE);
      expect(result.text.slice(span.outputStart, span.outputEnd)).toBe("<PHONE_1>");
    }
    const source = "０１０-１２３４-５６７８";
    const gold: GoldDocument = { text: source, spans: [g("PHONE", 0, source.length, source)] };
    const r2 = new Anonymizer(ProcessingMode.STRICT, "redact", null, ["PHONE"]).process(source);
    expect(assessOutput(gold, r2, "redact")[0]!.state).toBe("replaced");
    const s = r2.substitutions[0]!;
    expect(r2.text.slice(s.outputStart, s.outputEnd)).toBe("[전화번호]");
  });

  it("gold 가 없으면 정확도 통과로 주장하지 않는다", () => {
    const report = evaluate([new LabeledDocument("negative", { text: "normal", spans: [] })], {
      outputMode: ProcessingMode.STRICT,
    });
    expect(Object.values(report.output_evaluation!.counts).reduce((a, b) => a + b, 0)).toBe(0);
    expect(report.micro.recall).toBeNull();
  });

  it("검출 점수가 같아도 출력 회귀가 보인다", () => {
    const baseline = evaluate([phoneDocument()], {
      labels: ["PHONE"],
      outputMode: ProcessingMode.STRICT,
    });
    const current = clone(baseline);
    current.output_evaluation!.documents![0]!.spans[0]!.state = "literal_retained";
    const regression = compareReports(current, baseline);
    expect(Object.values(regression.counts).some(Boolean)).toBe(false);
    expect(regression.output!.new_not_fully_replaced).toBe(1);
    expect(regression.output!.changes[0]!.after).toBe("literal_retained");
    expect(compareReports(baseline, current).output!.resolved_not_fully_replaced).toBe(1);
    expect(json(regression)).not.toContain(PHONE);
  });

  it("라벨별 정책이 다르면 비교 거부", () => {
    const baseline = evaluate([phoneDocument()], {
      labels: ["PHONE"],
      outputMode: ProcessingMode.STRICT,
    });
    const current = evaluate([phoneDocument()], {
      labels: ["PHONE"],
      outputMode: ProcessingMode.STRICT,
      outputStrategies: { PHONE: "partial" },
    });
    expect(current.output_evaluation!.counts.partial_strategy).toBe(1);
    expect(() => compareReports(current, baseline)).toThrow(/output policies differ/);
  });

  it("CLI 보존 게이트 — 실패 전에 보고서를 쓴다", () => {
    capture();
    const source = writeJsonl("gold.jsonl", [
      { id: "sample-1", text: PHONE, spans: [{ label: "PHONE", start: 0, end: PHONE.length }] },
    ]);
    const output = path.join(tmp, "report.json");
    expect(
      main([
        source,
        "--output",
        output,
        "--labels",
        "PHONE",
        "--output-mode",
        "AUDIT",
        "--fail-on-retained",
      ]),
    ).toBe(1);
    expect(readJson(output).output_evaluation.not_fully_replaced).toBe(1);
  });

  it("CLI 새 보존 회귀 게이트 — baseline 이 replaced 였던 span 이 missed 면 1", () => {
    capture();
    const text = "synthetic secret";
    const source = writeJsonl("gold.jsonl", [
      { id: "sample-1", text, spans: [{ label: "PERSON", start: 0, end: text.length }] },
    ]);
    const baseline = path.join(tmp, "baseline.json");
    const output = path.join(tmp, "current.json");
    const args = [source, "--labels", "PERSON", "--output-mode", "STRICT"];
    expect(main([...args, "--output", baseline])).toBe(0);
    const check = [...args, "--baseline", baseline, "--output", output, "--fail-on-new-retained"];
    expect(main(check)).toBe(0);
    // Python 은 label_to_hangul 교체로 현재 출력을 퇴행시킨다 — 여기서는 baseline 을 replaced 로 만든다.
    const previous = readJson(baseline);
    Object.assign(previous.output_evaluation.documents[0].spans[0], {
      state: "replaced",
      covered_source_characters: text.length,
    });
    fs.writeFileSync(baseline, JSON.stringify(previous), "utf-8");
    expect(main(check)).toBe(1);
    const report = readJson(output);
    expect(report.comparison.output.new_not_fully_replaced).toBe(1);
    expect(Object.values(report.comparison.counts).some(Boolean)).toBe(false);
    expect(fs.readFileSync(output, "utf-8")).not.toContain(text);
  });

  it("CLI 라벨별 전략 재정의 기록 (--output-strategy-for)", () => {
    capture();
    const source = writeJsonl("gold.jsonl", [
      { id: "sample-1", text: PHONE, spans: [{ label: "PHONE", start: 0, end: PHONE.length }] },
    ]);
    const output = path.join(tmp, "output.json");
    expect(
      main([
        source,
        "--labels",
        "PHONE",
        "--output-mode",
        "STRICT",
        "--output-strategy",
        "redact",
        "--output-strategy-for",
        "PHONE=partial",
        "--fail-on-retained",
        "--output",
        output,
      ]),
    ).toBe(1);
    const report = readJson(output);
    expect(report.output_evaluation.strategies).toEqual({ PHONE: "partial" });
    expect(report.output_evaluation.counts.partial_strategy).toBe(1);
  });
});

describe("domain 평가·비교 (test_domain)", () => {
  const dataset = (rows?: unknown[]) =>
    writeJsonl(
      "corpus.jsonl",
      rows ?? [
        { id: "phone-1", text: PHONE, spans: [{ label: "PHONE", start: 0, end: 13 }] },
        { id: "name-1", text: "성명: 김도구", spans: [{ label: "PERSON", start: 4, end: 7 }] },
      ],
    );

  it("라벨별 측정, 원문 값 생략", () => {
    const report = evaluate(loadDataset(dataset()), { labels: ["PHONE", "PERSON"] });
    expect(report.per_label.PHONE!.tp).toBe(1);
    expect(report.per_label.PERSON!.tp).toBe(1);
    expect(report.micro.recall).toBe(1.0);
    const s = json(report);
    expect(s).not.toContain("김도구");
    expect(s).not.toContain(PHONE);
  });

  it("다른 미탐이 해결돼도 새 미탐을 잡는다", () => {
    const docs = loadDataset(dataset());
    const baseline = evaluate(docs, { labels: ["PHONE", "PERSON"] });
    baseline.documents.find((r) => r.id === "phone-1")!.predictions = [];
    const current = evaluate(docs, { labels: ["PHONE", "PERSON"], personExclusions: ["김도구"] });
    const c = compareReports(current, baseline);
    expect(c.counts.new_false_negatives).toBe(1);
    expect(c.counts.resolved_false_negatives).toBe(1);
    expect(c.new_false_negatives).toEqual([{ id: "name-1", label: "PERSON", start: 4, end: 7 }]);
  });

  it("비교는 낡은 요약이 아니라 예측에서 재계산", () => {
    const report = evaluate(loadDataset(dataset()), { labels: ["PHONE", "PERSON"] });
    const old = clone(report);
    old.micro.fn = 100;
    (old.documents[0] as unknown as Record<string, unknown>).false_negatives = [{ bogus: true }];
    expect(Object.values(compareReports(report, old).counts).every((n) => n === 0)).toBe(true);
  });

  it.each([
    ["dataset_sha256", "other"],
    ["match_mode", "partial"],
    ["evaluated_labels", ["PHONE"]],
    ["schema_version", 99],
  ])("비교 불가 baseline (%s)", (field, value) => {
    const report = evaluate(loadDataset(dataset()));
    const baseline = clone(report) as Record<string, unknown>;
    baseline[field] = value;
    expect(() => compareReports(report, baseline)).toThrow(new RegExp(field));
  });

  it("baseline 예측 오프셋 검증", () => {
    const report = evaluate(loadDataset(dataset()));
    const baseline = clone(report);
    baseline.documents[0]!.predictions = [{ label: "PERSON", start: 1, end: 9999 }];
    expect(() => compareReports(report, baseline)).toThrow(/offsets/);
  });

  it.each([
    { label: "PHONE", start: -1, end: 13 },
    { label: "PHONE", start: 0, end: 14 },
    { label: "PHONE", start: false, end: 13 },
    { label: "INVALID", start: 0, end: 13 },
  ])("잘못된 주석 %j → dataset line 1", (badSpan) => {
    const file = dataset([{ id: "sample", text: PHONE, spans: [badSpan] }]);
    expect(() => loadDataset(file)).toThrow(/dataset line 1/);
  });

  it("빈 데이터·중복 문서 거부, 잘못된 JSON 메시지", () => {
    expect(() => loadDataset(dataset([]))).toThrow(/at least one/);
    const doc = { id: "same", text: "no identifiers", spans: [] };
    expect(() => loadDataset(dataset([doc, doc]))).toThrow(/unique/);
    const file = path.join(tmp, "bad.jsonl");
    fs.writeFileSync(file, '{"id": "a", "id": "b", "text": "", "spans": []}', "utf-8");
    // Python 실측: dataset line 1: invalid JSON, duplicate key, non-finite number or excessive nesting
    expect(errorOf(() => loadDataset(file)).message).toBe(
      "dataset line 1: invalid JSON, duplicate key, non-finite number or excessive nesting",
    );
  });

  it("양성 예시가 없으면 재현율 측정 불가", () => {
    const report = evaluate(
      loadDataset(dataset([{ id: "negative", text: "plain text", spans: [] }])),
      {
        labels: ["PHONE"],
      },
    );
    expect(report.micro.recall).toBeNull();
    expect(report.micro.f1).toBeNull();
  });

  it("문서 순서는 코퍼스 동일성을 바꾸지 않는다", () => {
    const docs = loadDataset(dataset());
    const before = evaluate(docs);
    const after = evaluate([...docs].reverse());
    expect(after.dataset_sha256).toBe(before.dataset_sha256);
    expect(Object.values(compareReports(after, before).counts).every((n) => n === 0)).toBe(true);
  });

  it("dataset_sha256·person_exclusions_sha256·per_label 은 Python 과 바이트 동일", () => {
    const report = evaluate(
      [
        new LabeledDocument("x", {
          text: "성명: 김도구 010-1234-5678",
          spans: [g("PERSON", 4, 7, "김도구")],
        }),
      ],
      { personExclusions: ["홍길동"] },
    );
    // Python 실측.
    expect(report.dataset_sha256).toBe(
      "a42f75d0bcd8ec4f66d7c4ad4d53e101b3fac27b50f31555d7e6d9e9c54eaf62",
    );
    expect(report.person_exclusions_sha256).toBe(
      "c138cd9a73ab721d08e869fabd77d6c7971ee2b1d02c824cdd57483d3c405eb9",
    );
    expect(report.per_label).toEqual({
      PERSON: { tp: 1, fp: 0, fn: 0, precision: 1.0, recall: 1.0, f1: 1.0 },
      PHONE: { tp: 0, fp: 1, fn: 0, precision: 0.0, recall: null, f1: 0.0 },
    });
  });

  it("CLI 비교 — 새 미탐이면 1, 보고서 유지", () => {
    const io = capture();
    const file = dataset();
    const baseline = path.join(tmp, "baseline.json");
    const output = path.join(tmp, "current.json");
    const exclusions = path.join(tmp, "exclusions.txt");
    fs.writeFileSync(exclusions, "김도구\n", "utf-8");
    expect(main([file, "--labels", "PHONE,PERSON", "--output", baseline])).toBe(0);
    const rc = main([
      file,
      "--labels",
      "PHONE,PERSON",
      "--output",
      output,
      "--baseline",
      baseline,
      "--person-exclusions-file",
      exclusions,
      "--fail-on-new-misses",
    ]);
    expect(rc).toBe(1);
    expect(readJson(output).comparison.counts.new_false_negatives).toBe(1);
    expect(io.out()).toContain("new_false_negatives: 1");
  });

  it("CLI 오탐 변화 보고", () => {
    capture();
    const file = dataset([{ id: "benign", text: "성명: 김도구", spans: [] }]);
    const exclusions = path.join(tmp, "exclusions.txt");
    fs.writeFileSync(exclusions, "김도구", "utf-8");
    const baseline = path.join(tmp, "baseline.json");
    expect(
      main([
        file,
        "--output",
        baseline,
        "--labels",
        "PERSON",
        "--person-exclusions-file",
        exclusions,
      ]),
    ).toBe(0);
    expect(
      main([
        file,
        "--output",
        path.join(tmp, "after.json"),
        "--labels",
        "PERSON",
        "--baseline",
        baseline,
        "--fail-on-new-false-positives",
      ]),
    ).toBe(1);
  });

  it("CLI 는 원본·baseline 을 덮어쓰지 않고, 회귀 게이트는 baseline 필요 (argparse 오류 2)", () => {
    const io = capture();
    const file = dataset();
    const before = fs.readFileSync(file);
    expect(main([file, "--output", file])).toBe(2);
    expect(fs.readFileSync(file)).toEqual(before);
    expect(io.err()).toContain("ko-pii-evaluate: error: output must not overwrite");
    expect(main([file, "--output", path.join(tmp, "out.json"), "--fail-on-new-misses"])).toBe(2);
    expect(main([file])).toBe(2);
    expect(io.err()).toContain("the following arguments are required: --output");
  });

  it("formatSummary — Python 형식", () => {
    const report = evaluate(loadDataset(dataset()), { labels: ["PHONE"] });
    expect(formatSummary(report).split("\n").slice(0, 4)).toEqual([
      "Documents: 2 | matching: strict character spans",
      "Label                 TP     FP     FN   Precision  Recall",
      "PHONE                    1      0      0      1.000   1.000",
      "Documents with unmatched gold spans: 0",
    ]);
  });
});

const sliceDocuments = () => [
  new LabeledDocument(
    "a",
    { text: "a@example.com", spans: [g("EMAIL", 0, 13, "a@example.com")] },
    "form",
    "clean",
  ),
  new LabeledDocument(
    "b",
    { text: "a at example dot com", spans: [g("EMAIL", 0, 20, "a at example dot com")] },
    "chat",
    "obfuscated",
  ),
  new LabeledDocument("c", { text: "ordinary", spans: [] }, "chat", "negative"),
  new LabeledDocument("d", { text: "b@example.com", spans: [g("EMAIL", 0, 13, "b@example.com")] }),
];

/** Python 실측 보고서 (generated_at / evaluation_date / package_version 제외). */
const PY_SLICE_REPORT = JSON.parse(
  String.raw`{"schema_version":1,"dataset_sha256":"2d6c3cf7c37fa3e87695d38b8e51f46981f2eecf7d56ff59f4de76a86c28a99c","match_mode":"strict","evaluated_labels":["EMAIL"],"person_exclusions_sha256":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945","document_count":4,"documents_with_misses":1,"micro":{"tp":2,"fp":0,"fn":1,"precision":1.0,"recall":0.6666666666666666,"f1":0.8},"per_label":{"EMAIL":{"tp":2,"fp":0,"fn":1,"precision":1.0,"recall":0.6666666666666666,"f1":0.8}},"documents":[{"id":"a","characters":13,"gold":[{"label":"EMAIL","start":0,"end":13}],"predictions":[{"label":"EMAIL","start":0,"end":13}],"false_negatives":[],"false_positives":[]},{"id":"b","characters":20,"gold":[{"label":"EMAIL","start":0,"end":20}],"predictions":[],"false_negatives":[{"label":"EMAIL","start":0,"end":20}],"false_positives":[]},{"id":"c","characters":8,"gold":[],"predictions":[],"false_negatives":[],"false_positives":[]},{"id":"d","characters":13,"gold":[{"label":"EMAIL","start":0,"end":13}],"predictions":[{"label":"EMAIL","start":0,"end":13}],"false_negatives":[],"false_positives":[]}],"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":2,"missed":1,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{"EMAIL":{"replaced":2,"missed":1,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0}},"not_fully_replaced":1,"documents":[{"id":"a","spans":[{"label":"EMAIL","start":0,"end":13,"state":"replaced","covered_source_characters":13}]},{"id":"b","spans":[{"label":"EMAIL","start":0,"end":20,"state":"missed","covered_source_characters":0}]},{"id":"c","spans":[]},{"id":"d","spans":[{"label":"EMAIL","start":0,"end":13,"state":"replaced","covered_source_characters":13}]}],"strategies":{}},"slices":{"domain":[{"value":null,"document_count":1,"micro":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0},"per_label":{"EMAIL":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0}},"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{"EMAIL":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0}},"not_fully_replaced":0,"strategies":{}}},{"value":"chat","document_count":2,"micro":{"tp":0,"fp":0,"fn":1,"precision":null,"recall":0.0,"f1":0.0},"per_label":{"EMAIL":{"tp":0,"fp":0,"fn":1,"precision":null,"recall":0.0,"f1":0.0}},"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":0,"missed":1,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{"EMAIL":{"replaced":0,"missed":1,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0}},"not_fully_replaced":1,"strategies":{}}},{"value":"form","document_count":1,"micro":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0},"per_label":{"EMAIL":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0}},"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{"EMAIL":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0}},"not_fully_replaced":0,"strategies":{}}}],"variant":[{"value":null,"document_count":1,"micro":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0},"per_label":{"EMAIL":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0}},"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{"EMAIL":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0}},"not_fully_replaced":0,"strategies":{}}},{"value":"clean","document_count":1,"micro":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0},"per_label":{"EMAIL":{"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0}},"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{"EMAIL":{"replaced":1,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0}},"not_fully_replaced":0,"strategies":{}}},{"value":"negative","document_count":1,"micro":{"tp":0,"fp":0,"fn":0,"precision":null,"recall":null,"f1":null},"per_label":{},"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":0,"missed":0,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{},"not_fully_replaced":0,"strategies":{}}},{"value":"obfuscated","document_count":1,"micro":{"tp":0,"fp":0,"fn":1,"precision":null,"recall":0.0,"f1":0.0},"per_label":{"EMAIL":{"tp":0,"fp":0,"fn":1,"precision":null,"recall":0.0,"f1":0.0}},"output_evaluation":{"contract":"source-span-substitution-v1","mode":"STRICT","strategy":"redact","counts":{"replaced":0,"missed":1,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0},"per_label":{"EMAIL":{"replaced":0,"missed":1,"retained_by_policy":0,"partially_replaced":0,"partial_strategy":0,"literal_retained":0}},"not_fully_replaced":1,"strategies":{}}}]}}`,
);

describe("slices (test_slices)", () => {
  it("보고서 전체가 Python 실측과 같다", () => {
    const report = evaluate(sliceDocuments(), {
      labels: ["EMAIL"],
      outputMode: ProcessingMode.STRICT,
    });
    const { generated_at, evaluation_date, package_version, ...rest } = report;
    expect(JSON.parse(json(rest))).toEqual(PY_SLICE_REPORT);
    expect(generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?\+00:00$/);
    expect(evaluation_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(typeof package_version).toBe("string");
  });

  it("슬라이스 합 = 전체, 원문 없음", () => {
    const spy = vi.spyOn(Anonymizer.prototype, "process");
    const report = evaluate(sliceDocuments(), {
      labels: ["EMAIL"],
      outputMode: ProcessingMode.STRICT,
    });
    expect(spy).toHaveBeenCalledTimes(4);
    expect([report.micro.tp, report.micro.fn]).toEqual([2, 1]);
    for (const summaries of Object.values(report.slices!)) {
      expect(summaries.reduce((a, r) => a + r.document_count, 0)).toBe(4);
      for (const k of ["tp", "fp", "fn"] as const) {
        expect(summaries.reduce((a, r) => a + r.micro[k], 0)).toBe(report.micro[k]);
      }
      expect(summaries.reduce((a, r) => a + r.output_evaluation!.not_fully_replaced, 0)).toBe(1);
    }
    expect(json(report)).not.toContain("a@example.com");
  });

  it("메타데이터는 비교 범위를 바꾸고, 순서와는 무관", () => {
    const docs = sliceDocuments();
    const original = evaluate(docs, { labels: ["EMAIL"] });
    const reversed = evaluate([...docs].reverse(), { labels: ["EMAIL"] });
    expect(reversed.dataset_sha256).toBe(original.dataset_sha256);
    expect(reversed.slices).toEqual(original.slices);
    compareReports(reversed, original);
    docs[0] = new LabeledDocument(docs[0]!.id, docs[0]!.gold, docs[0]!.domain, "other");
    expect(() => compareReports(evaluate(docs, { labels: ["EMAIL"] }), original)).toThrow(/corpus/);
    const bare = evaluate(
      docs.map((d) => new LabeledDocument(d.id, d.gold)),
      { labels: ["EMAIL"] },
    );
    expect("slices" in bare).toBe(false);
  });

  it.each([
    null,
    [],
    { unknown: "x" },
    { domain: "private text" },
    { variant: 1 },
    { variant: "x".repeat(65) },
  ])("잘못된 메타데이터 %j", (metadata) => {
    const file = writeJsonl("data.jsonl", [{ id: "a", text: "", spans: [], metadata }]);
    const e = errorOf(() => loadDataset(file));
    expect(e).toBeInstanceOf(ValueError);
    expect(e.message).not.toContain("private text");
  });

  it("범주 수 상한·중복 id", () => {
    const docs = Array.from(
      { length: 129 },
      (_, i) => new LabeledDocument(String(i), { text: "", spans: [] }, String(i)),
    );
    expect(() => evaluate(docs)).toThrow(/128 categories/);
    const d = sliceDocuments();
    expect(() => evaluate([d[0]!, new LabeledDocument(d[0]!.id, d[1]!.gold, "chat")])).toThrow(
      /unique/,
    );
  });

  it("배포된 합성 예시 (docs/examples/evaluation-slices.jsonl)", () => {
    const file = path.join(
      import.meta.dirname,
      "../../../../docs/examples/evaluation-slices.jsonl",
    );
    const report = evaluate(loadDataset(file), {
      labels: ["PHONE"],
      outputMode: ProcessingMode.STRICT,
    });
    expect(report.document_count).toBe(6);
    expect(report.micro.tp).toBe(5);
    expect([report.micro.fn, report.micro.fp]).toEqual([0, 0]);
    expect(report.output_evaluation!.not_fully_replaced).toBe(0);
  });

  it("provenance 는 바이트만 검증하고 revision 은 검증하지 않는다", async () => {
    const { createHash } = await import("node:crypto");
    const source = '{"id":"a","text":"","spans":[]}\n';
    const config = {
      schema_version: 1,
      source_sha256: createHash("sha256").update(source).digest("hex"),
      revision: "abc123",
      split: "test-shard-01",
    };
    expect(validateProvenance(config, source).upstream_revision_verified).toBe(false);
    expect(() => validateProvenance(config, `${source}\n`)).toThrow(/digest/);
    expect(() => validateProvenance({ ...config, schema_version: true }, source)).toThrow(
      ValueError,
    );
    expect(() => validateProvenance({ ...config, revision: "secret value" }, source)).toThrow(
      ValueError,
    );
    const report = evaluate(sliceDocuments(), { labels: ["EMAIL"] });
    expect(() => compareReports({ ...report, provenance: config }, report)).toThrow(/provenance/);
  });

  it("CLI provenance manifest 왕복", async () => {
    const { createHash } = await import("node:crypto");
    const io = capture();
    const data = path.join(tmp, "data.jsonl");
    fs.writeFileSync(
      data,
      `${JSON.stringify({ id: "a", text: "a@example.com", spans: [{ label: "EMAIL", start: 0, end: 13 }], metadata: { domain: "forms", variant: "clean" } })}\n`,
      "utf-8",
    );
    const manifest = path.join(tmp, "manifest.json");
    const config = {
      schema_version: 1,
      source_sha256: createHash("sha256").update(fs.readFileSync(data)).digest("hex"),
      revision: "synthetic-v1",
      split: "regression",
    };
    fs.writeFileSync(manifest, JSON.stringify(config), "utf-8");
    const output = path.join(tmp, "report.json");
    const args = [data, "--provenance", manifest, "--labels", "EMAIL", "--output", output];
    expect(main(args)).toBe(0);
    const report = readJson(output);
    expect(report.provenance.source_sha256).toBe(config.source_sha256);
    expect(report.slices.domain[0].micro.tp).toBe(1);
    const snapshot = fs.readFileSync(output);
    fs.appendFileSync(data, "\n");
    expect(main(args)).toBe(2);
    expect(fs.readFileSync(output)).toEqual(snapshot);
    expect(io.err()).toContain("digest");
    expect(main([data, "--provenance", manifest, "--output", manifest])).toBe(2);
  });
});

describe("external K-PII-Bench (test_external)", () => {
  const row = () => ({
    doc_id: "private-id",
    text: "user@example.com ACME",
    entities: [
      { type: "EMAIL_ADDRESS", start: 0, end: 16, surface: "user@example.com" },
      { type: "ORGANIZATION", start: 17, end: 21, surface: "ACME" },
    ],
  });

  it("미매핑 기록과 안전한 id", () => {
    capture();
    const file = writeJsonl("sample.jsonl", [row()]);
    const [docs, metadata] = loadKPiiBench(file);
    expect(docs[0]!.id).not.toBe("private-id");
    expect(docs[0]!.gold.spans.map((s) => s.label)).toEqual(["EMAIL"]);
    expect(metadata.unmapped_span_count).toBe(1);
    expect(metadata.unmapped_spans).toEqual({ ORGANIZATION: 1 });
    expect(metadata.mapped_spans).toEqual({ EMAIL_ADDRESS: 1 });
    expect(Object.keys(K_PII_LABELS)).toHaveLength(18);
    const output = path.join(tmp, "eval.json");
    expect(
      main([
        file,
        "--dataset-format",
        "k-pii-bench",
        "--labels",
        "EMAIL",
        "--output-mode",
        "STRICT",
        "--output",
        output,
      ]),
    ).toBe(0);
    const report = readJson(output);
    expect(report.per_label.EMAIL.tp).toBe(1);
    expect(fs.readFileSync(output, "utf-8")).not.toContain("user@example.com");
    expect(report.dataset_adapter.unmapped_span_count).toBe(1);
  });

  it.each(["surface", "offset", "unknown", "duplicate", "bool"])(
    "잘못된 gold 거부 (%s)",
    (change) => {
      const r = row() as { entities: Record<string, unknown>[] };
      if (change === "surface") r.entities[0]!.surface = "private-value";
      else if (change === "offset") r.entities[0]!.end = 100;
      else if (change === "unknown") r.entities[0]!.type = "private-value";
      else if (change === "bool") r.entities[0]!.start = false;
      else r.entities.push(r.entities[0]!);
      const e = errorOf(() => loadKPiiBench(writeJsonl("sample.jsonl", [r])));
      expect(e).toBeInstanceOf(ValueError);
      expect(e.message).not.toContain("private-value");
      expect(e.message).toBe(
        "invalid k-pii-bench record at line 1; check schema, label and offsets",
      );
    },
  );

  it("출력 baseline 차이와 정책 동일성", () => {
    const [docs] = loadKPiiBench(writeJsonl("sample.jsonl", [row()]));
    const base = evaluate(docs, { labels: ["EMAIL"], outputMode: ProcessingMode.STRICT });
    const next = clone(base);
    next.output_evaluation!.documents![0]!.spans[0]!.state = "literal_retained";
    const difference = compareReports(next, base);
    expect(difference.output!.new_not_fully_replaced).toBe(1);
    expect(difference.counts.new_false_negatives).toBe(0);
    expect(compareReports(base, next).output!.resolved_not_fully_replaced).toBe(1);
    next.output_evaluation!.mode = "AUDIT";
    expect(() => compareReports(next, base)).toThrow(/policies differ/);
    const missing = clone(base);
    missing.output_evaluation!.documents![0]!.spans = [];
    expect(() => compareReports(base, missing)).toThrow(/annotations/);
  });

  it("범위 밖 라벨·출력 없는 baseline 의 보존 비교는 2 (보고서 미작성)", () => {
    capture();
    const file = writeJsonl("sample.jsonl", [row()]);
    expect(
      main([
        file,
        "--dataset-format",
        "k-pii-bench",
        "--labels",
        "BUSINESS_REG",
        "--output",
        path.join(tmp, "out.json"),
      ]),
    ).toBe(2);
    expect(fs.existsSync(path.join(tmp, "out.json"))).toBe(false);
    const baseline = path.join(tmp, "base.json");
    const output = path.join(tmp, "out2.json");
    expect(main([file, "--dataset-format", "k-pii-bench", "--output", baseline])).toBe(0);
    expect(
      main([
        file,
        "--dataset-format",
        "k-pii-bench",
        "--output",
        output,
        "--baseline",
        baseline,
        "--output-mode",
        "STRICT",
        "--fail-on-new-retained",
      ]),
    ).toBe(2);
    expect(fs.existsSync(output)).toBe(false);
  });

  it("명시 범주 보존과 원본 해시", async () => {
    const { createHash } = await import("node:crypto");
    const file = writeJsonl("bench.jsonl", [
      { doc_id: "a", text: "", entities: [], domain: "finance", variant: "clean" },
    ]);
    const [docs, metadata] = loadKPiiBench(file);
    expect([docs[0]!.domain, docs[0]!.variant]).toEqual(["finance", "clean"]);
    expect(metadata.source_sha256).toBe(
      createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    );
  });
});

describe("평가 입력 무결성 (test_evaluation_integrity)", () => {
  const SPAN = g("PHONE", 0, PHONE.length, PHONE);
  const document = (spans?: GoldSpan[]) =>
    new LabeledDocument("sample", { text: PHONE, spans: spans ?? [SPAN] });

  it.each([
    { label: "PHNOE" },
    { label: [] },
    { start: false },
    { start: -1 },
    { start: 13 },
    { end: true },
    { end: 14 },
    { text: "different synthetic source" },
    { text: null },
  ])("범위 밖이라도 잘못된 gold 는 거부 (%j)", (change) => {
    for (const labels of [["PHONE"], ["EMAIL"]]) {
      expect(() =>
        evaluate([document([{ ...SPAN, ...(change as object) } as GoldSpan])], {
          labels,
          outputMode: ProcessingMode.STRICT,
        }),
      ).toThrow(ValueError);
    }
  });

  it("중복 gold 는 거부", () => {
    expect(() => evaluate([document([SPAN, { ...SPAN }])])).toThrow(/duplicate span/);
  });

  it.each([
    null,
    { text: null, spans: [] },
    { text: PHONE, spans: null },
    { text: PHONE, spans: [{}] },
    { text: "bad\ud800text", spans: [] },
  ])("잘못된 문서는 원문 없이 거부 (#%#)", (gold) => {
    const e = errorOf(() =>
      evaluate([new LabeledDocument("sample", gold as unknown as GoldDocument)]),
    );
    expect(e).toBeInstanceOf(ValueError);
    expect(e.message).not.toContain(PHONE);
  });

  it("모든 주석을 검출 전에 검증 (Anonymizer 미호출)", () => {
    const spy = vi.spyOn(Anonymizer.prototype, "process");
    const bad = new LabeledDocument("z-last", { text: PHONE, spans: [{ ...SPAN, label: "TYPO" }] });
    expect(() => evaluate([document(), bad], { outputMode: ProcessingMode.STRICT })).toThrow(
      ValueError,
    );
    expect(spy).not.toHaveBeenCalled();
    expect(() => evaluate([document()], { outputMode: "" as ProcessingMode })).toThrow(
      /output_mode/,
    );
    expect(() => evaluate([document()], { outputMode: 1 as unknown as ProcessingMode })).toThrow(
      /output_mode/,
    );
  });

  const report = (): EvaluationReport =>
    evaluate([document(), new LabeledDocument("negative", { text: "ordinary", spans: [] })], {
      labels: ["PHONE"],
      outputMode: ProcessingMode.STRICT,
    });
  const sampleSpan = (r: EvaluationReport) =>
    r.output_evaluation!.documents!.find((d) => d.id === "sample")!.spans[0] as unknown as Record<
      string,
      unknown
    >;

  it.each([
    ["replaced", 0],
    ["replaced", 12],
    ["replaced", 14],
    ["replaced", -1],
    ["replaced", true],
    ["replaced", 13.5],
    ["replaced", "13"],
    ["replaced", null],
    ["partial_strategy", 0],
    ["literal_retained", 12],
    ["partially_replaced", 0],
    ["partially_replaced", 13],
    ["missed", 1],
    ["retained_by_policy", 13],
  ] as const)("불가능한 커버리지 %s/%j 는 양쪽 모두 거부", (state, covered) => {
    const original = report();
    const invalid = report();
    Object.assign(sampleSpan(invalid), { state, covered_source_characters: covered });
    expect(() => compareReports(original, invalid)).toThrow(/covered characters/);
    expect(() => compareReports(invalid, original)).toThrow(/covered characters/);
  });

  it.each(OUTPUT_STATES)("일관된 상태 %s 는 받아 변화량을 재계산", (state) => {
    const original = report();
    const changed = report();
    const covered =
      state === "missed" || state === "retained_by_policy"
        ? 0
        : state === "partially_replaced"
          ? 4
          : PHONE.length;
    Object.assign(sampleSpan(changed), { state, covered_source_characters: covered });
    expect(compareReports(changed, original).output!.new_not_fully_replaced).toBe(
      Number(state !== "replaced"),
    );
    expect(compareReports(original, changed).output!.resolved_not_fully_replaced).toBe(
      Number(state !== "replaced"),
    );
  });

  it.each(["omit-negative", "extra-negative", "duplicate", "wrong-source-end"])(
    "출력 문서 집합·좌표 완전성 (%s)",
    (change) => {
      const original = report();
      const invalid = report();
      const rows = invalid.output_evaluation!.documents!;
      if (change === "omit-negative")
        rows.splice(
          rows.findIndex((r) => r.id === "negative"),
          1,
        );
      else if (change === "extra-negative") rows.push({ id: "not-in-corpus", spans: [] });
      else if (change === "duplicate") rows.push(clone(rows[0]!));
      else sampleSpan(invalid).end = 14;
      expect(() => compareReports(original, invalid)).toThrow(ValueError);
      expect(() => compareReports(invalid, original)).toThrow(ValueError);
    },
  );

  it.each([
    ["contract", "unknown"],
    ["mode", "STRCIT"],
    ["strategy", "unknown"],
    ["strategies", { PHNOE: "redact" }],
  ])("같지만 잘못된 출력 계약(%s)은 비교 불가", (key, value) => {
    const first = report();
    const second = report();
    (first.output_evaluation as unknown as Record<string, unknown>)[key] = value;
    (second.output_evaluation as unknown as Record<string, unknown>)[key] = value;
    expect(() => compareReports(first, second)).toThrow(ValueError);
  });

  it.each(["duplicate-key", "nan", "infinity", "deep"])(
    "모호한 baseline JSON(%s)은 보고서를 덮지 않고 2",
    (kind) => {
      const io = capture();
      const source = writeJsonl("input.jsonl", [
        { id: "sample", text: PHONE, spans: [{ label: "PHONE", start: 0, end: PHONE.length }] },
      ]);
      const baseline = path.join(tmp, "baseline.json");
      const output = path.join(tmp, "current.json");
      const args = [source, "--labels", "PHONE", "--output-mode", "STRICT"];
      expect(main([...args, "--output", baseline])).toBe(0);
      const extra = {
        "duplicate-key": '"package_version":"ambiguous",',
        nan: '"extra":NaN,',
        infinity: '"extra":Infinity,',
        deep: `"extra":${"[".repeat(70)}0${"]".repeat(70)},`,
      }[kind]!;
      fs.writeFileSync(
        baseline,
        fs.readFileSync(baseline, "utf-8").replace("{", `{${extra}`),
        "utf-8",
      );
      fs.writeFileSync(output, "previous report", "utf-8");
      expect(
        main([...args, "--baseline", baseline, "--output", output, "--fail-on-new-retained"]),
      ).toBe(2);
      expect(fs.readFileSync(output, "utf-8")).toBe("previous report");
      expect(io.err()).not.toContain(PHONE);
    },
  );

  it("일관되지 않은 보존 baseline 은 무회귀로 보고하지 않고 2", () => {
    capture();
    const source = writeJsonl("input.jsonl", [
      { id: "sample", text: PHONE, spans: [{ label: "PHONE", start: 0, end: PHONE.length }] },
    ]);
    const baseline = path.join(tmp, "baseline.json");
    const output = path.join(tmp, "current.json");
    const args = [source, "--labels", "PHONE", "--output-mode", "STRICT"];
    expect(main([...args, "--output", baseline])).toBe(0);
    const previous = readJson(baseline);
    previous.output_evaluation.documents[0].spans[0].covered_source_characters = 0;
    fs.writeFileSync(baseline, JSON.stringify(previous), "utf-8");
    expect(
      main([...args, "--baseline", baseline, "--output", output, "--fail-on-new-retained"]),
    ).toBe(2);
    expect(fs.existsSync(output)).toBe(false);
  });
});

describe("도메인 시나리오 (test_domain_scenarios)", () => {
  type Part = [string, string | null, string | null];
  const SCENARIOS: [string, string, string[], Part[]][] = [
    [
      "form-legacy-mobile",
      "forms",
      ["PHONE"],
      [
        ["연락처: ", null, null],
        ["018-234-6789", "PHONE", "PHONE"],
      ],
    ],
    [
      "form-parenthesized",
      "forms",
      ["PHONE"],
      [
        ["전화: ", null, null],
        ["(018) 2345-6789", "PHONE", "PHONE"],
      ],
    ],
    [
      "form-international",
      "forms",
      ["PHONE"],
      [
        ["Mobile: ", null, null],
        ["+82-18-2345-6789", "PHONE", "PHONE"],
      ],
    ],
    [
      "form-rrn",
      "forms",
      ["RRN"],
      [
        ["주민등록번호: ", null, null],
        ["880101-1234568", "RRN", "RRN"],
      ],
    ],
    [
      "form-name",
      "forms",
      ["PERSON"],
      [
        ["성명: ", null, null],
        ["김도구", "PERSON", "PERSON"],
      ],
    ],
    [
      "form-address",
      "forms",
      ["ADDRESS"],
      [
        ["주소: ", null, null],
        ["서울특별시 강남구 테헤란로 152", "ADDRESS", "ADDRESS"],
      ],
    ],
    [
      "chat-repeated-email",
      "chat",
      ["EMAIL"],
      [
        ["여기로 보내줘: ", null, null],
        ["user@example.com", "EMAIL", "EMAIL"],
        [". 다시 적을게 ", null, null],
        ["user@example.com", "EMAIL", "EMAIL"],
      ],
    ],
    [
      "chat-idn-email",
      "chat",
      ["EMAIL"],
      [
        ["메일은 ", null, null],
        ["user@예시.kr", "EMAIL", "EMAIL"],
        [" 이야", null, null],
      ],
    ],
    [
      "chat-wide-digits",
      "chat",
      ["PHONE"],
      [
        ["전화해 ", null, null],
        ["０１０-２３４５-６７８９", "PHONE", "PHONE"],
      ],
    ],
    [
      "chat-invisible-character",
      "chat",
      ["PHONE"],
      [
        ["연락줘 ", null, null],
        ["010-23​45-6789", "PHONE", "PHONE"],
      ],
    ],
    [
      "chat-obfuscated-email",
      "chat",
      ["EMAIL"],
      [
        ["메일 ", null, null],
        ["user[at]example.com", "EMAIL", "EMAIL"],
      ],
    ],
    [
      "free-model-code-known-fp",
      "free_text",
      ["PHONE"],
      [
        ["MODEL", null, null],
        ["010-2345-6789", null, "PHONE"],
        ["CODE", null, null],
      ],
    ],
    [
      "free-attached-phone",
      "free_text",
      ["PHONE"],
      [
        ["TEL", null, null],
        ["010-2345-6789", "PHONE", "PHONE"],
      ],
    ],
    ["free-unrelated-date", "free_text", ["DT_BIRTH"], [["시행일자: 2026-05-21", null, null]]],
    [
      "free-common-word",
      "free_text",
      ["PERSON"],
      [["이상 없음. 구현 결과를 확인했습니다.", null, null]],
    ],
    [
      "free-product-numbers",
      "free_text",
      ["PHONE", "RRN"],
      [["version 1.2.3, build 20261022, range 100-200-300", null, null]],
    ],
    // 미래 생년(2099) — 시험 시계와 무관하게 알려진 미탐.
    [
      "form-future-rrn-known-fn",
      "forms",
      ["RRN"],
      [
        ["Synthetic RRN: ", null, null],
        ["991231-3123456", "RRN", null],
      ],
    ],
  ];

  const build = (caseId: string, parts: Part[]) => {
    let text = "";
    const gold: GoldSpan[] = [];
    const predictions: { label: string; start: number; end: number }[] = [];
    for (const [value, goldLabel, predictionLabel] of parts) {
      const start = text.length;
      text += value;
      if (goldLabel) gold.push(g(goldLabel, start, text.length, value));
      if (predictionLabel) predictions.push({ label: predictionLabel, start, end: text.length });
    }
    return [new LabeledDocument(caseId, { text, spans: gold }), predictions] as const;
  };
  const key = (s: { label: string; start: number; end: number }) =>
    `${s.label}:${s.start}:${s.end}`;

  it.each(SCENARIOS)("%s (%s)", (caseId, _domain, labels, parts) => {
    const [document, expected] = build(caseId, parts);
    const report = evaluate([document], { labels, outputMode: ProcessingMode.STRICT });
    const row = report.documents[0]!;
    expect(row.predictions.map(key).sort()).toEqual(expected.map(key).sort());
    const expectedSpans = new Set(expected.map(key));
    const goldSpans = new Set(document.gold.spans.map(key));
    expect(row.false_negatives).toHaveLength(
      [...goldSpans].filter((k) => !expectedSpans.has(k)).length,
    );
    expect(row.false_positives).toHaveLength(
      [...expectedSpans].filter((k) => !goldSpans.has(k)).length,
    );
    for (const span of report.output_evaluation!.documents![0]!.spans) {
      expect(span.state).toBe(expectedSpans.has(key(span)) ? "replaced" : "missed");
    }
  });
});

describe("ko-pii-evaluate argparse (COLUMNS=100, .venv/bin/python 실측 바이트)", () => {
  const USAGE = `usage: ko-pii-evaluate [-h] [--dataset-format {ko-pii,k-pii-bench}] [--provenance PROVENANCE]
                       --output OUTPUT [--labels LABELS]
                       [--person-exclusions-file PERSON_EXCLUSIONS_FILE] [--baseline BASELINE]
                       [--fail-on-new-misses] [--fail-on-new-false-positives]
                       [--output-mode {PARANOID,STRICT,BALANCED,PERMISSIVE,AUDIT}]
                       [--output-strategy {redact,tokenize,asterisk,partial,hashed,fpe}]
                       [--fail-on-retained] [--fail-on-new-retained]
                       [--output-strategy-for LABEL=STRATEGY]
                       dataset
`;
  const HELP = `${USAGE}
Evaluate labeled local JSONL documents and compare detector regressions.

positional arguments:
  dataset               UTF-8 JSONL containing id, text and spans

options:
  -h, --help            show this help message and exit
  --dataset-format {ko-pii,k-pii-bench}
  --provenance PROVENANCE
                        Local revision/split manifest with required source SHA-256
  --output OUTPUT       JSON report (no source text or span values)
  --labels LABELS       Comma-separated labels; annotate all occurrences of these labels
  --person-exclusions-file PERSON_EXCLUSIONS_FILE
  --baseline BASELINE   Earlier report for the same corpus and label scope
  --fail-on-new-misses
  --fail-on-new-false-positives
  --output-mode {PARANOID,STRICT,BALANCED,PERMISSIVE,AUDIT}
  --output-strategy {redact,tokenize,asterisk,partial,hashed,fpe}
  --fail-on-retained    Fail if any gold span is not fully replaced, including intentional partial
                        masking
  --fail-on-new-retained
                        Fail if a previously fully replaced gold span is no longer fully replaced
  --output-strategy-for LABEL=STRATEGY
`;
  let columns: string | undefined;
  beforeEach(() => {
    columns = process.env.COLUMNS;
    process.env.COLUMNS = "100";
  });
  afterEach(() => {
    if (columns === undefined) delete process.env.COLUMNS;
    else process.env.COLUMNS = columns;
  });

  it("--help", () => {
    const io = capture();
    expect(main(["--help"])).toBe(0);
    expect(io.out()).toBe(HELP);
    expect(io.err()).toBe("");
  });

  it.each([
    [[], "the following arguments are required: dataset, --output"],
    [["d.jsonl"], "the following arguments are required: --output"],
    [
      ["d.jsonl", "--output-strategy-for", "PHONE=redact"],
      "the following arguments are required: --output",
    ],
    [
      ["d.jsonl", "--output", "o.json", "--output-strategy-for"],
      "argument --output-strategy-for: expected one argument",
    ],
    [
      ["d.jsonl", "--output", "o.json", "--output-strategy-for", "PHONE=redact"],
      "--output-strategy-for requires --output-mode",
    ],
  ])("usage 오류 %j", (argv, message) => {
    const io = capture();
    expect(main(argv)).toBe(2);
    expect(io.out()).toBe("");
    expect(io.err()).toBe(`${USAGE}ko-pii-evaluate: error: ${message}\n`);
  });
});
