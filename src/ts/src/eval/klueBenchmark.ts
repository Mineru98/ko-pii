/**
 * KLUE-NER 한국어 자연어 NER 외부 벤치마크 — CLI 진입점. Python ``ko_pii.eval.klue_benchmark`` 대응.
 *
 * KLUE-NER 는 신문기사 기반이라 *공문서가 아님* — 의도된 사용 시나리오와 다른 *외부 검증*
 * 이다. F1 이 합성 공문서 벤치마크보다 낮은 것은 자연스럽다.
 *
 * 데이터: https://raw.githubusercontent.com/KLUE-benchmark/KLUE/main/klue_benchmark/klue-ner-v1.1/klue-ner-v1.1_dev.tsv
 *
 * 실행: ``ko-pii-klue-bench /path/to/klue-ner-v1.1_dev.tsv``
 */
import { ArgumentParser, ParseExit } from "../cli/argparse.js";
import { evaluatePerson, loadKlueNer, sampleErrors } from "./klueNer.js";
import { cpHead, padRight } from "./pyCompat.js";

export function main(argv?: string[]): number {
  const p = new ArgumentParser("ko-pii-klue-bench", "KLUE-NER 한국어 자연어 NER 외부 벤치마크");
  p.addArgument({ dest: "path", help: "KLUE-NER TSV 파일 경로 (예: klue-ner-v1.1_dev.tsv)" });
  p.addArgument({
    dest: "mode",
    optionStrings: ["--mode"],
    choices: ["partial", "strict"],
    def: "partial",
  });
  p.addArgument({
    dest: "limit",
    optionStrings: ["--limit"],
    isInt: true,
    help: "평가할 문장 수 (디버그용)",
  });
  p.addArgument({
    dest: "all_labels",
    optionStrings: ["--all-labels"],
    isFlag: true,
    def: false,
    help: "모든 PS span 평가 (영문 1자·외래어 포함). 기본은 한글 풀네임만.",
  });
  p.addArgument({
    dest: "korean_only",
    optionStrings: ["--korean-only"],
    isFlag: true,
    def: false,
    help: "한국 인명만 평가 (외국인·가공인물 제외) — 본 라이브러리 정책 대상",
  });
  p.addArgument({
    dest: "show_errors",
    optionStrings: ["--show-errors"],
    isInt: true,
    def: 0,
    help: "FN/FP 샘플 N개씩 출력",
  });

  try {
    const args = p.parseArgs(argv);
    if (args.path === null) p.errorExit("the following arguments are required: path");
    const path = args.path as string;

    process.stdout.write(`Loading: ${path}\n`);
    const sentences = loadKlueNer(path);
    process.stdout.write(`Sentences: ${sentences.length}\n`);

    const report = evaluatePerson(sentences, {
      mode: args.mode as string,
      sampleLimit: args.limit as number | null,
      fullnameOnly: !args.all_labels,
      koreanOnly: Boolean(args.korean_only),
    });
    const out: string[] = ["", report.format()];

    const showErrors = args.show_errors as number;
    if (showErrors > 0) {
      out.push("");
      out.push("=== FN 샘플 (ko-pii 가 놓친 이름) ===");
      for (const [sent, names] of sampleErrors(sentences, "fn", showErrors)) {
        out.push(`  - ${padRight(names[0]!, 10)} ... ${cpHead(sent.text, 100)}`);
      }
      out.push("");
      out.push("=== FP 샘플 (ko-pii 가 잘못 잡은 토큰) ===");
      for (const [sent, names] of sampleErrors(sentences, "fp", showErrors)) {
        out.push(`  - ${padRight(names[0]!, 10)} ... ${cpHead(sent.text, 100)}`);
      }
    }
    process.stdout.write(`${out.join("\n")}\n`);
    return 0;
  } catch (e) {
    if (e instanceof ParseExit) {
      (e.stream === "stdout" ? process.stdout : process.stderr).write(e.text);
      return e.code;
    }
    throw e;
  }
}
