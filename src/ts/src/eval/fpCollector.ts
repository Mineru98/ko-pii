/**
 * PII 없는 텍스트에서 PERSON 과탐 어휘 자동 수집. Python ``ko_pii.eval.fp_collector`` 대응.
 *
 * 사용 시나리오:
 * - 비식별된 판결서 / 정부 보도자료 / 뉴스 기사 / 위키백과 등
 *   → 그 텍스트에 PII 없다는 전제로 우리 검출이 *모두 과탐*
 *   → 반복 등장 어휘는 일반어 → ``COMMON_WORDS`` 추가 후보
 *
 * JSONL 모드 (KDPII 같은 라벨 데이터): ``--jsonl kdpii.jsonl --gold-label PS_NAME``
 *
 * 출력: ``(빈도, 어휘)`` 형식 — 빈도 내림차순.
 *
 * 자동 추가 시 주의: 일부 어휘는 *진짜 인명* 일 수 있어 사람 검토 후 추가 권장.
 */
import { existsSync } from "node:fs";
import { ArgumentParser, ParseExit, pyRepr } from "../cli/argparse.js";
import { detectAll } from "../detect.js";
import { isCommonWord } from "../dictionaries/index.js";
import { cpLen, padLeft, pyFileLines, pyPathStr, pyStrip, readUtf8 } from "./pyCompat.js";

/** Python ``Counter`` 대응 — Map 은 첫 삽입 순서를 유지한다. */
export type Counter = Map<string, number>;

function bump(counter: Counter, key: string, by = 1): void {
  counter.set(key, (counter.get(key) ?? 0) + by);
}

/** 텍스트에서 ``label`` 검출 중 ``knownGold`` 와 매칭 안 되는 것 = 과탐 후보. */
export function collectFromText(
  text: string,
  options: { label?: string; minLength?: number; knownGold?: Set<string> | null } = {},
): Counter {
  const label = options.label ?? "PERSON";
  const minLength = options.minLength ?? 3;
  const known = options.knownGold ?? new Set<string>();
  const counter: Counter = new Map();
  for (const r of detectAll(text)) {
    if (r.label !== label) continue;
    if (cpLen(r.text) < minLength) continue;
    if (isCommonWord(r.text)) continue; // 이미 사전에 있음
    let matched = false;
    for (const g of known) {
      if (g.includes(r.text) || r.text.includes(g)) {
        matched = true;
        break;
      }
    }
    if (matched) continue; // 정답 매칭
    bump(counter, r.text);
  }
  return counter;
}

interface JsonlRecord {
  query?: string;
  answer?: Array<{ label: string; form: string }>;
}

/** JSONL 형식 (query + answer) 에서 ``goldLabel`` 제외하고 과탐 수집. */
export function collectFromJsonl(
  path: string,
  options: { goldLabel?: string; piiLabel?: string; minLength?: number } = {},
): Counter {
  const goldLabel = options.goldLabel ?? "PS_NAME";
  const piiLabel = options.piiLabel ?? "PERSON";
  const minLength = options.minLength ?? 3;
  const counter: Counter = new Map();
  for (const raw of pyFileLines(readUtf8(path))) {
    const line = pyStrip(raw);
    if (!line) continue;
    const d = JSON.parse(line) as JsonlRecord;
    const text = d.query ?? "";
    // 풀네임 (minLength) 만 정답으로
    const gold = new Set<string>();
    for (const a of d.answer ?? []) {
      if (a.label === goldLabel && cpLen(a.form) >= minLength) gold.add(a.form);
    }
    const found = collectFromText(text, { label: piiLabel, minLength, knownGold: gold });
    for (const [t, c] of found) bump(counter, t, c);
  }
  return counter;
}

export function main(argv?: string[]): number {
  const p = new ArgumentParser(
    "ko-pii-fp-collector",
    "PII 없는 텍스트에서 PERSON 과탐 어휘 자동 수집",
  );
  p.addArgument({ dest: "path", nargs: "opt", help: "입력 파일 (txt 또는 jsonl)" });
  p.addArgument({
    dest: "jsonl",
    optionStrings: ["--jsonl"],
    isFlag: true,
    def: false,
    help: "JSONL 모드 (KDPII 같은 라벨링된 데이터)",
  });
  p.addArgument({
    dest: "gold_label",
    optionStrings: ["--gold-label"],
    def: "PS_NAME",
    help: "JSONL 의 인명 라벨 (default: PS_NAME)",
  });
  p.addArgument({
    dest: "pii_label",
    optionStrings: ["--pii-label"],
    def: "PERSON",
    help: "ko-pii 의 라벨 (default: PERSON)",
  });
  p.addArgument({
    dest: "min_freq",
    optionStrings: ["--min-freq"],
    isInt: true,
    def: 2,
    help: "최소 반복 횟수 (default: 2)",
  });
  p.addArgument({
    dest: "min_length",
    optionStrings: ["--min-length"],
    isInt: true,
    def: 3,
    help: "최소 길이 (default: 3, 풀네임)",
  });
  p.addArgument({
    dest: "top",
    optionStrings: ["--top"],
    isInt: true,
    def: 100,
    help: "출력할 상위 N개 (default: 100)",
  });

  try {
    const args = p.parseArgs(argv);
    if (!args.path) p.errorExit("입력 파일 필요");
    const path = pyPathStr(args.path as string);
    if (!existsSync(path)) p.errorExit(`파일 없음: ${path}`);

    const piiLabel = args.pii_label as string;
    const minLength = args.min_length as number;
    const minFreq = args.min_freq as number;
    const counter = args.jsonl
      ? collectFromJsonl(path, { goldLabel: args.gold_label as string, piiLabel, minLength })
      : collectFromText(readUtf8(path), { label: piiLabel, minLength });

    // min_freq 필터 — 정렬은 안정적(동률은 삽입 순).
    const filtered = [...counter].filter(([, c]) => c >= minFreq);
    filtered.sort((a, b) => b[1] - a[1]);

    const total = filtered.reduce((s, [, c]) => s + c, 0);
    const out: string[] = [];
    out.push(
      `# ${path} — 고유 ${counter.size} 종 / 빈도 ${minFreq}+ = ${filtered.length} 종 (총 ${total} 건)`,
    );
    out.push(`# 라벨: ${piiLabel}, 최소 길이: ${minLength}`);
    out.push("");
    out.push(`${padLeft("빈도", 6)}  어휘`);
    out.push("-".repeat(40));
    for (const [t, c] of filtered.slice(0, args.top as number)) {
      out.push(`${padLeft(String(c), 6)}  ${pyRepr(t)}`);
    }
    out.push("");
    out.push(
      "# 일반어 (PERSON 아님) 으로 확인한 어휘만 ``common_words.COMMON_WORDS`` 에 추가 권장.",
    );
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
