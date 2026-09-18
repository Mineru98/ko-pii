/**
 * 회귀 감지용 벤치마크 — ``ko-pii-benchmark``. Python ``ko_pii.eval.benchmark`` 대응.
 *
 * ⚠ **Python 과 코퍼스 출처가 다르다.** Python 은 ``synth.generate_corpus(n, seed)`` 로
 * 매번 합성 코퍼스를 만들지만, 그 생성기는 CPython MT19937 난수열에 의존해 포팅 범위
 * 밖이다. TS 판은 **동결된 JSONL 코퍼스**(예: ``data/generated_eval.jsonl``,
 * ``data/generated_eval_large.jsonl``)를 읽는다. 그에 따른 CLI 차이:
 *
 * - 위치 인자 ``corpus`` (JSONL 경로) 가 추가됐다 — 필수.
 * - ``--seed`` 는 없다 (동결 코퍼스에는 의미가 없어, 받는 척하지 않는다).
 * - ``-n/--num-docs`` 는 "생성할 문서 수" 가 아니라 "앞에서부터 평가할 문서 수" 이고
 *   기본값은 50 이 아니라 전체다.
 *
 * ``--mode``, ``--min-*`` 하한 옵션, 리포트 포맷(``formatReport``), stderr 메시지,
 * 종료 코드(0 통과 / 1 하한 미달 / 2 인자 오류)는 Python 과 같다.
 *
 * 코퍼스 형식: 한 줄당 ``{"text": ..., "pii": [{"type": LABEL, "text": FORM}, ...], ...}``.
 * **오프셋이 없으므로** gold span 위치는 ``loadJsonlCorpus`` 가 본문 검색으로 복원한다
 * (아래 주석 참조). 같은 어휘가 본문에 여러 번 나오면 gold 는 그중 한 곳만 가리키므로
 * 나머지 검출은 오탐으로 집계된다 — 즉 이 점수는 ``match_forms_overlap`` 기반 공식
 * 수치(docs/BENCHMARK.md)와 다른 값이며, **회귀 감지용**으로만 쓴다.
 *
 * ⚠ **이 점수는 실제 정확도가 아니다.** 실제 정확도 측정은 KDPII 벤치마크(``kdpii.ts``)로.
 */
import { ArgumentParser, ParseExit, pyRepr } from "../cli/argparse.js";
import { ValueError } from "../core/errors.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { detectAll } from "../detect.js";
import { formatReport, scoreCorpus } from "./metrics.js";
import { pyFloat, pySplitlines, pyStrip, readUtf8 } from "./pyCompat.js";
import type { GoldDocument, GoldSpan } from "./types.js";

interface CorpusRecord {
  text: string;
  pii?: Array<{ type: string; text: string }>;
  domain?: string;
}

/**
 * 오프셋 없는 ``{type, text}`` gold 목록 → ``GoldSpan[]`` (UTF-16 오프셋).
 *
 * gold 는 대체로 본문 등장 순서로 나열돼 있으므로, 직전 span 끝(cursor)부터 앞으로 찾고,
 * 없으면 본문 처음부터 다시 찾는다(순서가 어긋난 항목). 어디에도 없으면 ValueError —
 * 코퍼스 계약("gold 의 모든 text 는 본문에 글자 그대로 등장") 위반이다.
 */
export function locateSpans(text: string, pii: Array<{ type: string; text: string }>): GoldSpan[] {
  const spans: GoldSpan[] = [];
  let cursor = 0;
  for (const item of pii) {
    let at = text.indexOf(item.text, cursor);
    if (at < 0) at = text.indexOf(item.text);
    if (at < 0 || item.text === "") {
      throw new ValueError(`gold text not found in document: ${pyRepr(item.text)}`);
    }
    const end = at + item.text.length;
    spans.push({ label: item.type, start: at, end, text: item.text });
    cursor = end;
  }
  return spans;
}

/** 동결 JSONL 코퍼스 로더. ``domain`` 은 ``GoldDocument.template`` 으로 옮긴다. */
export function loadJsonlCorpus(path: string): GoldDocument[] {
  const docs: GoldDocument[] = [];
  for (const raw of pySplitlines(readUtf8(path))) {
    const line = pyStrip(raw);
    if (!line) continue;
    const d = JSON.parse(line) as CorpusRecord;
    docs.push({ text: d.text, spans: locateSpans(d.text, d.pii ?? []), template: d.domain ?? "" });
  }
  return docs;
}

const FLOOR_OPTIONS = [
  ["min_micro_precision", "--min-micro-precision", "micro precision"],
  ["min_micro_recall", "--min-micro-recall", "micro recall"],
  ["min_micro_f1", "--min-micro-f1", "micro F1"],
  ["min_macro_f1", "--min-macro-f1", "macro F1"],
] as const;

/** 테스트용 주입점 — Python 테스트의 ``monkeypatch.setattr(benchmark, "score_corpus", ...)`` 대응. */
export interface BenchmarkDeps {
  scoreCorpus?: typeof scoreCorpus;
}

export function main(argv?: string[], deps: BenchmarkDeps = {}): number {
  const score = deps.scoreCorpus ?? scoreCorpus;
  const p = new ArgumentParser(
    "ko-pii-benchmark",
    "동결 JSONL 코퍼스에서 ko-pii 검출 정확도 평가 (회귀 감지용)",
  );
  p.addArgument({
    dest: "corpus",
    help: "동결 코퍼스 JSONL 경로 (예: data/generated_eval.jsonl)",
  });
  p.addArgument({
    dest: "num_docs",
    optionStrings: ["-n", "--num-docs"],
    isInt: true,
    help: "앞에서부터 평가할 문서 수 (기본: 전체)",
  });
  p.addArgument({
    dest: "mode",
    optionStrings: ["--mode"],
    choices: ["partial", "strict"],
    def: "partial",
  });
  for (const [dest, option, name] of FLOOR_OPTIONS) {
    p.addArgument({
      dest,
      optionStrings: [option],
      help: `exit nonzero when measured ${name === "micro F1" ? "micro-F1" : name === "macro F1" ? "macro-F1" : name} is below this floor`,
    });
  }

  try {
    const args = p.parseArgs(argv);
    // argparse-lite 에는 type=float 이 없어 파싱 후 변환한다 (오류 문구는 argparse 와 동일).
    const floors = new Map<string, number>();
    for (const [dest, option] of FLOOR_OPTIONS) {
      const raw = args[dest] as string | null;
      if (raw === null) continue;
      const floor = pyFloat(raw);
      if (floor === null) {
        return p.errorExit(`argument ${option}: invalid float value: ${pyRepr(raw)}`);
      }
      floors.set(dest, floor);
    }
    if (args.corpus === null) p.errorExit("the following arguments are required: corpus");
    for (const [dest, option] of FLOOR_OPTIONS) {
      const floor = floors.get(dest);
      if (floor !== undefined && !(floor >= 0.0 && floor <= 1.0)) {
        p.errorExit(`${option} must be between 0 and 1`);
      }
    }

    let corpus = loadJsonlCorpus(args.corpus as string);
    const numDocs = args.num_docs as number | null;
    if (numDocs !== null) corpus = corpus.slice(0, Math.max(0, numDocs));

    const report = score(corpus, detectAll, args.mode as string);
    process.stdout.write(`${formatReport(report)}\n`);
    const micro = report.micro();
    const measured: Array<[string, string, number]> = [
      ["min_micro_precision", "micro precision", micro.precision],
      ["min_micro_recall", "micro recall", micro.recall],
      ["min_micro_f1", "micro F1", micro.f1],
      ["min_macro_f1", "macro F1", report.macroF1()],
    ];
    const failures: string[] = [];
    for (const [dest, name, value] of measured) {
      const floor = floors.get(dest);
      if (floor !== undefined && value < floor) {
        failures.push(
          `${name}=${pyFormatFixed(value, 6)} is below floor=${pyFormatFixed(floor, 6)}`,
        );
      }
    }
    if (failures.length > 0) {
      process.stderr.write(
        `\nRegression gate failed:\n${failures.map((f) => `- ${f}\n`).join("")}`,
      );
      return 1;
    }
    return 0;
  } catch (e) {
    if (e instanceof ParseExit) {
      (e.stream === "stdout" ? process.stdout : process.stderr).write(e.text);
      return e.code;
    }
    throw e;
  }
}
