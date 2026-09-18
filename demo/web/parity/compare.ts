/** reference.json(Python app.py 출력) 과 TS process() 를 바이트 단위로 대조 — Node·브라우저 공용. */
import { EXAMPLES, type ModeName, process, pyPercent0, pyRound0 } from "../src/process.js";

export interface Reference {
  examples: [string, string, boolean, boolean][];
  formats: { percent0: [number, string][]; round0: [number, string][] };
  cases: { input: [string, string, boolean, boolean]; output: string[] }[];
}

export interface ParityReport {
  total: number;
  failures: string[];
}

const OUTPUT_NAMES = ["kpii_html", "openai_html", "presidio_html", "anon_text"];

export function compare(ref: Reference): ParityReport {
  const failures: string[] = [];
  if (JSON.stringify(EXAMPLES) !== JSON.stringify(ref.examples)) {
    failures.push("EXAMPLES 상수가 app.py 와 다르다");
  }
  for (const [name, fn] of [["percent0", pyPercent0], ["round0", pyRound0]] as const) {
    for (const [x, want] of ref.formats[name]) {
      const got = fn(x);
      if (got !== want) failures.push(`${name}(${x}) 불일치 — py: ${want} ts: ${got}`);
    }
  }
  for (const c of ref.cases) {
    const [text, mode, showOpenai, showPresidio] = c.input;
    const got = process(text, mode as ModeName, showOpenai, showPresidio, () => 0);
    got.forEach((g, i) => {
      if (g !== c.output[i]) {
        failures.push(
          `${OUTPUT_NAMES[i]} 불일치 — input=${JSON.stringify(c.input)}\n  py: ${JSON.stringify(c.output[i])}\n  ts: ${JSON.stringify(g)}`,
        );
      }
    });
  }
  return { total: ref.cases.length + ref.formats.percent0.length + ref.formats.round0.length, failures };
}
