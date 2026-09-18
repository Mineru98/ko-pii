/**
 * eval 패키지 단위 테스트 — src/python/tests/unit/eval/ 포트.
 *
 * - test_metrics.py, test_dataset_integrity.py, test_kdpii_matcher.py 전체
 * - test_benchmark_smoke.py 중 synth(generate_corpus) 비의존 부분. synth 의존 테스트
 *   (baseline recall / critical labels / CLI floor)는 동결 코퍼스
 *   data/generated_eval.jsonl 기반으로 바꿨다.
 * - test_kdpii_matcher.py 의 model_comparison 관련 2건은 대상 모듈이 포팅 범위 밖이라 제외.
 *
 * 문자열·수치 기대값은 전부 Python(ko_pii.eval.*) 실측값이다.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type DetectionResult, makeDetection, RiskLevel } from "../../src/core/types.js";
import { detectAll } from "../../src/detect.js";
import * as benchmark from "../../src/eval/benchmark.js";
import { assertNoTextLeakage, textLeakageCount } from "../../src/eval/datasetIntegrity.js";
import { collectFromJsonl, collectFromText } from "../../src/eval/fpCollector.js";
import * as evalIndex from "../../src/eval/index.js";
import * as kdpii from "../../src/eval/kdpii.js";
import * as klueNer from "../../src/eval/klueNer.js";
import {
  BenchmarkReport,
  formatReport,
  PerLabelMetrics,
  scoreCorpus,
  scoreDocument,
} from "../../src/eval/metrics.js";
import type { GoldDocument, GoldSpan } from "../../src/eval/types.js";

const REPO = join(import.meta.dirname, "..", "..", "..", "..");
const EVAL_CORPUS = join(REPO, "data", "generated_eval.jsonl");

function det(label: string, start: number, end: number, text: string): DetectionResult {
  return makeDetection({ label, text, start, end, riskLevel: RiskLevel.HIGH });
}

function gold(label: string, start: number, end: number, text: string): GoldSpan {
  return { label, start, end, text };
}

function doc(text: string, spans: GoldSpan[]): GoldDocument {
  return { text, spans };
}

/** process.stdout/stderr.write 캡처. */
function capture(): { out: () => string; err: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  vi.spyOn(process.stdout, "write").mockImplementation((s) => {
    out.push(String(s));
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((s) => {
    err.push(String(s));
    return true;
  });
  return { out: () => out.join(""), err: () => err.join("") };
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ─────────────────────────────────────────────────────────────────────
// test_metrics.py
// ─────────────────────────────────────────────────────────────────────

describe("metrics (test_metrics.py)", () => {
  it("perfect match", () => {
    const d = doc("A 880101-1234568 B", [gold("RRN", 2, 16, "880101-1234568")]);
    const m = scoreDocument(d, [det("RRN", 2, 16, "880101-1234568")]);
    const rrn = m.get("RRN")!;
    expect([rrn.tp, rrn.fp, rrn.fn]).toEqual([1, 0, 0]);
    expect(rrn.precision).toBe(1.0);
    expect(rrn.recall).toBe(1.0);
    expect(rrn.f1).toBe(1.0);
  });

  it("partial overlap counts as TP under partial mode", () => {
    const d = doc("abcdef", [gold("RRN", 0, 6, "abcdef")]);
    const m = scoreDocument(d, [det("RRN", 2, 5, "cde")], "partial");
    expect(m.get("RRN")!.tp).toBe(1);
  });

  it("strict requires exact offsets", () => {
    const d = doc("abcdef", [gold("RRN", 0, 6, "abcdef")]);
    const m = scoreDocument(d, [det("RRN", 1, 6, "bcdef")], "strict");
    const rrn = m.get("RRN")!;
    expect([rrn.tp, rrn.fn, rrn.fp]).toEqual([0, 1, 1]);
  });

  it("false positive and negative", () => {
    const d = doc("abcdefghij", [gold("RRN", 0, 3, "abc"), gold("PHONE", 5, 9, "fghi")]);
    const m = scoreDocument(d, [det("RRN", 0, 3, "abc")]);
    expect(m.get("RRN")!.tp).toBe(1);
    expect(m.get("PHONE")!.fn).toBe(1);
  });

  it("scoreCorpus aggregates", () => {
    const docs = [
      doc("aaaa", [gold("RRN", 0, 4, "aaaa")]),
      doc("bbbb", [gold("RRN", 0, 4, "bbbb")]),
    ];
    const rpt = scoreCorpus(docs, (text) => [det("RRN", 0, 4, text)]);
    expect(rpt.documentCount).toBe(2);
    expect(rpt.perLabel.get("RRN")!.tp).toBe(2);
    expect(rpt.micro().f1).toBe(1.0);
  });

  it("formatReport contains headers", () => {
    const rpt = scoreCorpus([doc("aaaa", [gold("RRN", 0, 4, "aaaa")])], (text) => [
      det("RRN", 0, 4, text),
    ]);
    const out = formatReport(rpt);
    for (const s of ["정확도", "재현율", "F1", "(전체)"]) expect(out).toContain(s);
  });

  it("formatReport — Python 실측 문자열 (라벨 정렬, half-even tie 0.0625 → 0.062)", () => {
    const r = new BenchmarkReport({
      perLabel: new Map([
        ["RRN", new PerLabelMetrics("RRN", 1, 15, 0)],
        ["PERSON", new PerLabelMetrics("PERSON", 8, 2, 1)],
        ["ADDRESS", new PerLabelMetrics("ADDRESS", 0, 0, 3)],
      ]),
      documentCount: 7,
      matchMode: "strict",
    });
    expect(formatReport(r)).toBe(
      "문서 수: 7\n매칭 정책: strict\n\n라벨                       정탐   오탐   미탐        정확도      재현율      F1\n-----------------------------------------------------------------\nADDRESS                   0    0    3     0.000    0.000   0.000\nPERSON                    8    2    1     0.800    0.889   0.842\nRRN                       1   15    0     0.062    1.000   0.118\n-----------------------------------------------------------------\n(전체)                      9   17    4     0.346    0.692   0.462\n(macro F1)                                                  0.320",
    );
    expect(r.micro().precision).toBe(0.34615384615384615);
    expect(r.micro().recall).toBe(0.6923076923076923);
    expect(r.micro().f1).toBe(0.46153846153846156);
    expect(r.macroF1()).toBe(0.31991744066047473);
  });

  it("formatReport — 빈 리포트 (0 나눗셈 가드)", () => {
    expect(formatReport(new BenchmarkReport())).toBe(
      "문서 수: 0\n매칭 정책: partial\n\n라벨                       정탐   오탐   미탐        정확도      재현율      F1\n-----------------------------------------------------------------\n-----------------------------------------------------------------\n(전체)                      0    0    0     0.000    0.000   0.000\n(macro F1)                                                  0.000",
    );
  });
});

// ─────────────────────────────────────────────────────────────────────
// test_dataset_integrity.py
// ─────────────────────────────────────────────────────────────────────

describe("datasetIntegrity (test_dataset_integrity.py)", () => {
  it("detects leakage", () => {
    expect(() => assertNoTextLeakage(["a", "b", "공유문장"], ["공유문장", "c"])).toThrow(
      "[dataset] train↔test 문장 누수 1건 — train 이 test 코퍼스를 외워 평가가 오염됨. 예: ['공유문장']",
    );
  });

  it("error name / repr 규칙은 Python 과 같다", () => {
    try {
      assertNoTextLeakage([`it's "q"`], [`it's "q"`], { name: "q" });
      expect.unreachable();
    } catch (e) {
      expect((e as Error).name).toBe("AssertionError");
      expect((e as Error).message).toBe(
        `[q] train↔test 문장 누수 1건 — train 이 test 코퍼스를 외워 평가가 오염됨. 예: ['it\\'s "q"']`,
      );
    }
  });

  it("clean passes", () => {
    expect(() => assertNoTextLeakage(["a", "b"], ["c", "d"])).not.toThrow();
  });

  it("count", () => {
    expect(textLeakageCount(["a", "b", "x"], ["x", "y"])).toBe(1);
    expect(textLeakageCount(["a"], ["b"])).toBe(0);
  });

  it("whitespace normalized", () => {
    expect(() => assertNoTextLeakage(["hello  world"], ["hello world"])).toThrow();
  });

  it("Python \\s 집합 — U+001C/U+0085 는 공백, U+FEFF 는 아님 (실측: 누수 2건)", () => {
    expect(textLeakageCount(["a\x1cb", "x\x85y", "\ufeffz"], ["a b", "x y", "z"])).toBe(2);
    expect(textLeakageCount([null, "", "   "], ["", null])).toBe(0);
  });

  const kd = join(REPO, "data", "kdpii");
  it.skipIf(!existsSync(join(kd, "train.json")))(
    "KDPII 원본 train/test 의 PII 보유 누수는 무시 가능 (Python 실측 1건)",
    () => {
      type Rec = { sentence: string; PII_set?: unknown[] };
      const load = (n: string): Rec[] => JSON.parse(readFileSync(join(kd, n), "utf-8"));
      const pick = (ds: Rec[]) => ds.filter((d) => d.PII_set?.length).map((d) => d.sentence);
      expect(textLeakageCount(pick(load("train.json")), pick(load("test.json")))).toBe(1);
    },
    60_000,
  );
});

// ─────────────────────────────────────────────────────────────────────
// test_kdpii_matcher.py
// ─────────────────────────────────────────────────────────────────────

describe("kdpii (test_kdpii_matcher.py)", () => {
  it("matchFormsOverlap is public", () => {
    expect(typeof kdpii.matchFormsOverlap).toBe("function");
  });

  it("exact match", () => {
    const [mp, mg] = kdpii.matchFormsOverlap(new Set(["홍길동"]), new Set(["홍길동"]));
    expect([...mp]).toEqual(["홍길동"]);
    expect([...mg]).toEqual(["홍길동"]);
  });

  it("substring match when both 2char plus", () => {
    const [mp, mg] = kdpii.matchFormsOverlap(new Set(["역삼동 123"]), new Set(["역삼동"]));
    expect([...mp]).toEqual(["역삼동 123"]);
    expect([...mg]).toEqual(["역삼동"]);
  });

  it("one char substring rejected", () => {
    const [mp, mg] = kdpii.matchFormsOverlap(new Set(["김"]), new Set(["김철수"]));
    expect(mp.size).toBe(0);
    expect(mg.size).toBe(0);
  });

  it("personMinLength 기본값 3", () => {
    // Python: inspect.signature(evaluate_kdpii).parameters["person_min_length"].default == 3
    const docs: kdpii.KdpiiDocument[] = [
      { query: "x", gold: new Map([["PERSON", new Set(["민지"])]]) },
    ];
    const none = () => [];
    expect(kdpii.evaluateKdpii(docs, none).perLabel.get("PERSON")!.fn).toBe(0);
    expect(kdpii.evaluateKdpii(docs, none, { personMinLength: 1 }).perLabel.get("PERSON")!.fn).toBe(
      1,
    );
  });

  it("load + evaluate + format — Python 실측 (JSONL/Zenodo 혼합, 실제 검출기)", () => {
    const dir = mkdtempSync(join(tmpdir(), "kopii-eval-"));
    try {
      const path = join(dir, "kd.jsonl");
      const recs = [
        {
          query: "제 이름은 김민지이고 번호는 010-1234-5678, 메일은 mj.kim@example.com 입니다.",
          answer: [
            { label: "PS_NAME", form: "김민지" },
            { label: "QT_MOBILE", form: "010 1234 5678" },
            { label: "TMI_EMAIL", form: "mj.kim@example.com" },
            { label: "PS_NICKNAME", form: "민지" },
          ],
        },
        {
          sentence: "저는 서울대학교 컴퓨터공학과를 졸업한 박 과장입니다.",
          PII_set: [
            { label: "OGG_EDUCATION", form: "서울대학교" },
            { label: "FD_MAJOR", form: "컴퓨터공학과" },
            { label: "PS_NAME", form: "박" },
            { label: "", form: "x" },
          ],
        },
      ];
      writeFileSync(path, `${recs.map((r) => JSON.stringify(r)).join("\n\n")}\n`);
      const docs = kdpii.loadKdpii(path);
      expect(docs.map((d) => [...d.gold.keys()])).toEqual([
        ["PERSON", "PHONE", "EMAIL"],
        ["EDUCATION", "MAJOR", "PERSON"],
      ]);
      expect(kdpii.formatKdpiiReport(kdpii.evaluateKdpii(docs))).toBe(
        "문서 수: 2\n라벨 매핑: 22 KDPII → 20 ko-pii LABEL\n\n라벨                 정탐    오탐    미탐     정확도     재현율      F1\n---------------------------------------------------------\nEDUCATION           1     0     0   1.000   1.000   1.000\nEMAIL               1     0     0   1.000   1.000   1.000\nMAJOR               1     0     0   1.000   1.000   1.000\nPERSON              0     0     1   0.000   0.000   0.000\nPHONE               0     1     1   0.000   0.000   0.000\n---------------------------------------------------------\n(전체)                3     1     2   0.750   0.600   0.667\n\n정탐 = 정확히 잡은 것 (gold 도 있음)\n오탐 = 잘못 잡은 것 (gold 없는데 잡음)\n미탐 = 놓친 것 (gold 있는데 못 잡음)",
      );
      const rep1 = kdpii.evaluateKdpii(docs, detectAll, { personMinLength: 1 });
      const person = rep1.perLabel.get("PERSON")!;
      expect([person.tp, person.fp, person.fn]).toEqual([0, 0, 2]);

      // Zenodo 배열 형식 자동 감지
      const arr = join(dir, "kd.json");
      writeFileSync(arr, `  \n${JSON.stringify([recs[1]])}`);
      expect(kdpii.loadKdpii(arr)[0]!.query).toBe(recs[1]!.sentence);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// klue_ner (Python 테스트 없음 — 실측값 회귀)
// ─────────────────────────────────────────────────────────────────────

describe("klueNer (Python 실측)", () => {
  const tsv =
    "## klue-ner-v1.1_dev_00000\n김\tB-PS\n철\tI-PS\n수\tI-PS\n \tO\n과\tB-PS\n장\tO\n은\tO\n \tO\n서\tB-LC\n울\tI-LC\n에\tO\n \tO\n산\tO\n다\tO\n.\tO\n\n## x\n박\tB-PS\n지\tI-PS\n성\tI-PS\n이\tO\n \tO\n골\tO\n을\tO\n \tO\n넣\tO\n었\tO\n다\tO\n";
  const sents = klueNer.parseCharsAndTags(tsv.split("\n"));

  it("BIO → span", () => {
    expect(sents.map((s) => s.text)).toEqual([
      "김철수 과장은 서울에 산다.",
      "박지성이 골을 넣었다",
    ]);
    expect(sents[0]!.spans).toEqual([
      { label: "PS", start: 0, end: 3, text: "김철수" },
      { label: "PS", start: 4, end: 5, text: "과" },
      { label: "LC", start: 8, end: 10, text: "서울" },
    ]);
  });

  it("아스트랄 글자 뒤의 span 은 UTF-16 오프셋 (slice 불변식)", () => {
    const [s] = klueNer.parseCharsAndTags(["😀\tO", "김\tB-PS", "철\tI-PS"]);
    expect(s!.spans).toEqual([{ label: "PS", start: 2, end: 4, text: "김철" }]);
    expect(s!.text.slice(2, 4)).toBe("김철");
  });

  it("evaluatePerson 옵션별 (tp, fp, fn, 문장 수)", () => {
    const run = (o: klueNer.EvaluatePersonOptions) => {
      const r = klueNer.evaluatePerson(sents, o);
      return [r.tp, r.fp, r.fn, r.sentenceCount];
    };
    expect(run({})).toEqual([1, 0, 1, 2]);
    expect(run({ mode: "strict" })).toEqual([1, 0, 1, 2]);
    expect(run({ fullnameOnly: false })).toEqual([1, 0, 2, 2]);
    expect(run({ koreanOnly: true })).toEqual([1, 0, 1, 2]);
    expect(run({ sampleLimit: 1 })).toEqual([1, 0, 0, 1]);
  });

  it("format / sampleErrors", () => {
    expect(klueNer.evaluatePerson(sents).format()).toBe(
      "[KLUE-NER PERSON]  문장 2건  TP=1  FP=0  FN=1\n  Precision = 1.000\n  Recall    = 0.500\n  F1        = 0.667",
    );
    expect(klueNer.sampleErrors(sents, "fn").map(([, n]) => n)).toEqual([["과"], ["박지성"]]);
    expect(klueNer.sampleErrors(sents, "fp")).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────
// fp_collector
// ─────────────────────────────────────────────────────────────────────

describe("fpCollector", () => {
  it("knownGold 와 겹치는 검출은 제외, 나머지는 삽입 순으로 집계", () => {
    const text = "담당자 김철수 과장과 박영희 대리가 참석했고, 김철수 과장이 발표했다.";
    const persons = detectAll(text)
      .filter((r) => r.label === "PERSON")
      .map((r) => r.text);
    const all = collectFromText(text);
    expect([...all.values()].reduce((a, b) => a + b, 0)).toBe(persons.length);
    const filtered = collectFromText(text, { knownGold: new Set(["김철수"]) });
    expect(filtered.has("김철수")).toBe(false);
  });

  it("JSONL 모드 — 빈 줄 무시, gold 는 minLength 이상만", () => {
    const dir = mkdtempSync(join(tmpdir(), "kopii-eval-"));
    try {
      const path = join(dir, "x.jsonl");
      const q = "담당자 김철수 과장에게 문의하세요.";
      writeFileSync(
        path,
        `${JSON.stringify({ query: q, answer: [{ label: "PS_NAME", form: "김철수" }] })}\n\n${JSON.stringify({ query: q })}\n`,
      );
      const c = collectFromJsonl(path);
      // 첫 줄은 gold 로 제외, 둘째 줄만 집계
      expect(c.get("김철수") ?? 0).toBe(collectFromText(q).get("김철수") ?? 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// test_benchmark_smoke.py — 동결 코퍼스 기반
// ─────────────────────────────────────────────────────────────────────

function fixedReport(): BenchmarkReport {
  return new BenchmarkReport({
    perLabel: new Map([["PERSON", new PerLabelMetrics("PERSON", 8, 2, 1)]]),
    documentCount: 1,
  });
}

describe("benchmark (test_benchmark_smoke.py)", () => {
  it("locateSpans — 등장 순서대로 앞으로 찾고, 어긋나면 처음부터 다시 찾는다", () => {
    const text = "김철수(010-1111-2222)와 김철수(010-3333-4444)";
    const spans = benchmark.locateSpans(text, [
      { type: "PERSON", text: "김철수" },
      { type: "PHONE", text: "010-1111-2222" },
      { type: "PERSON", text: "김철수" },
      { type: "PHONE", text: "010-3333-4444" },
      { type: "PHONE", text: "010-1111-2222" },
    ]);
    expect(spans.map((s) => s.start)).toEqual([0, 4, 20, 24, 4]);
    for (const s of spans) expect(text.slice(s.start, s.end)).toBe(s.text);
    expect(() => benchmark.locateSpans("abc", [{ type: "X", text: "zzz" }])).toThrow(
      "gold text not found in document: 'zzz'",
    );
  });

  it.skipIf(!existsSync(EVAL_CORPUS))(
    "동결 코퍼스 540건 — Python 실측 리포트와 일치 + 요청한 하한 강제",
    () => {
      const cap = capture();
      expect(benchmark.main([EVAL_CORPUS, "--min-micro-f1", "0.73"])).toBe(0);
      const lines = cap.out().split("\n");
      expect(lines[0]).toBe("문서 수: 540");
      expect(lines).toContain("RRN                     191   12    5     0.941    0.974   0.957");
      expect(lines).toContain("PHONE                   552   10    3     0.982    0.995   0.988");
      expect(lines).toContain("EMAIL                   204    1    0     0.995    1.000   0.998");
      expect(lines).toContain("(전체)                   2874 1277  761     0.692    0.791   0.738");
      expect(lines).toContain("(macro F1)                                                  0.667");

      expect(benchmark.main([EVAL_CORPUS, "--min-micro-f1", "0.99"])).toBe(1);
      expect(cap.err()).toBe(
        "\nRegression gate failed:\n- micro F1=0.738248 is below floor=0.990000\n",
      );
    },
    60_000,
  );

  it.skipIf(!existsSync(EVAL_CORPUS))(
    "critical labels recall (RRN / PHONE / EMAIL)",
    () => {
      const report = scoreCorpus(benchmark.loadJsonlCorpus(EVAL_CORPUS), detectAll, "partial");
      for (const label of ["RRN", "PHONE", "EMAIL"]) {
        expect(report.perLabel.get(label)!.recall).toBeGreaterThanOrEqual(0.95);
      }
    },
    60_000,
  );

  const corpusArgs = existsSync(EVAL_CORPUS) ? [EVAL_CORPUS, "-n", "1"] : null;

  it.skipIf(corpusArgs === null)("enforces all requested floors", () => {
    capture();
    const code = benchmark.main(
      [
        ...corpusArgs!,
        "--min-micro-precision",
        "0.79",
        "--min-micro-recall",
        "0.88",
        "--min-micro-f1",
        "0.84",
        "--min-macro-f1",
        "0.84",
      ],
      { scoreCorpus: fixedReport },
    );
    expect(code).toBe(0);
  });

  it.skipIf(corpusArgs === null).each([
    ["--min-micro-precision", "micro precision=0.800000"],
    ["--min-micro-recall", "micro recall=0.888889"],
    ["--min-micro-f1", "micro F1=0.842105"],
    ["--min-macro-f1", "macro F1=0.842105"],
  ])("reports each failed floor: %s", (option, expected) => {
    const cap = capture();
    expect(benchmark.main([...corpusArgs!, option, "0.90"], { scoreCorpus: fixedReport })).toBe(1);
    expect(cap.err()).toBe(`\nRegression gate failed:\n- ${expected} is below floor=0.900000\n`);
  });

  it.each(["--min-micro-precision", "--min-micro-recall", "--min-micro-f1", "--min-macro-f1"])(
    "rejects invalid floor: %s",
    (option) => {
      const cap = capture();
      expect(benchmark.main(["corpus.jsonl", "-n", "1", option, "1.01"])).toBe(2);
      expect(cap.err()).toContain(`ko-pii-benchmark: error: ${option} must be between 0 and 1\n`);
      expect(benchmark.main(["corpus.jsonl", option, "abc"])).toBe(2);
      expect(cap.err()).toContain(`argument ${option}: invalid float value: 'abc'`);
    },
  );

  it("코퍼스 인자 누락 / --seed 는 없는 옵션", () => {
    const cap = capture();
    expect(benchmark.main([])).toBe(2);
    expect(cap.err()).toContain("error: the following arguments are required: corpus");
    expect(benchmark.main(["c.jsonl", "--seed", "0"])).toBe(2);
    expect(cap.err()).toContain("error: unrecognized arguments: --seed 0");
  });
});

describe("eval/index 재노출 (eval/__init__.py — synth 생성 함수 제외)", () => {
  it("__all__ 대응", () => {
    for (const name of [
      "PerLabelMetrics",
      "BenchmarkReport",
      "scoreDocument",
      "scoreCorpus",
      "formatReport",
    ]) {
      expect(evalIndex).toHaveProperty(name);
    }
    expect(evalIndex).not.toHaveProperty("generateCorpus");
    expect(evalIndex.kdpii.matchFormsOverlap).toBe(kdpii.matchFormsOverlap);
  });
});
