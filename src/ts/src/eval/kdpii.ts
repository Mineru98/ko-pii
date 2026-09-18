/**
 * KDPII (Korean Dialog PII) 벤치마크 어댑터. Python ``ko_pii.eval.kdpii`` 대응.
 *
 * KDPII 코퍼스 (KAIST/KETI 한국어 대화체 PII 데이터셋) 를 읽어 ko-pii detectAll 출력과
 * 라벨별 P/R/F1 측정.
 *
 * 데이터 포맷 (per line):
 *     { "query": "<대화 텍스트>", "answer": [{"label": "PS_NAME", "form": "김민지"}, ...] }
 *
 * 매칭 정책: **substring overlap** — 예측 텍스트가 gold form 의 부분 문자열이거나 그
 * 반대일 경우 TP. 위치를 쓰지 않으므로 오프셋 단위(UTF-16/코드 포인트) 차이와 무관하다.
 */
import { ArgumentParser, ParseExit, pyStrCompare } from "../cli/argparse.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import type { DetectionResult } from "../core/types.js";
import { detectAll } from "../detect.js";
import { cpLen, padLeft, padRight, pyLstrip, pySplitlines, pyStrip, readUtf8 } from "./pyCompat.js";

// KDPII 라벨 → ko-pii LABEL 매핑.
//
// 매핑 안 된 KDPII 라벨 (ko-pii 스코프 밖):
//   PS_NICKNAME (별명)  — 가명 vs PII 모호, 별도 카테고리 미구현
//   OGG_CLUB / OGG_RELIGION — 소속 단체, 별도 카테고리 미구현
//   LC_PLACE — 일반 장소 (특정 행정구역 아닌 명사), ADDRESS 와 분리
//   OG_WORKPLACE / OG_DEPARTMENT — 회사·부서명, 별도 카테고리 미구현
//   CV_SEX / CV_MILITARY_CAMP / TM_BLOOD_TYPE / QT_GRADE — 미구현
export const KDPII_LABEL_MAP: Readonly<Record<string, string>> = {
  PS_NAME: "PERSON",
  QT_AGE: "AGE",
  OGG_EDUCATION: "EDUCATION",
  FD_MAJOR: "MAJOR",
  CV_POSITION: "POSITION",
  DT_BIRTH: "DT_BIRTH",
  QT_PHONE: "PHONE",
  QT_MOBILE: "PHONE",
  TMI_EMAIL: "EMAIL",
  TMI_SITE: "URL", // 웹사이트 = URL
  QT_RESIDENT_NUMBER: "RRN",
  LC_ADDRESS: "ADDRESS",
  LCP_COUNTRY: "ADDRESS", // 국가 = ADDRESS (admin_alone country kind)
  QT_CARD_NUMBER: "CARD",
  QT_ACCOUNT_NUMBER: "ACCOUNT",
  QT_PASSPORT_NUMBER: "PASSPORT",
  QT_DRIVER_NUMBER: "DRIVER_LICENSE",
  QT_IP: "IP",
  QT_ALIEN_NUMBER: "FRN",
  QT_PLATE_NUMBER: "VEHICLE",
  QT_LENGTH: "HEIGHT",
  QT_WEIGHT: "WEIGHT",
};

function mapLabel(label: string): string | undefined {
  return Object.hasOwn(KDPII_LABEL_MAP, label) ? KDPII_LABEL_MAP[label] : undefined;
}

export interface KdpiiDocument {
  query: string;
  /** label → {form} */
  gold: Map<string, Set<string>>;
}

export class LabelMetrics {
  label: string;
  tp: number;
  fp: number;
  fn: number;

  constructor(label: string, tp = 0, fp = 0, fn = 0) {
    this.label = label;
    this.tp = tp;
    this.fp = fp;
    this.fn = fn;
  }

  get precision(): number {
    return this.tp + this.fp ? this.tp / (this.tp + this.fp) : 0.0;
  }

  get recall(): number {
    return this.tp + this.fn ? this.tp / (this.tp + this.fn) : 0.0;
  }

  get f1(): number {
    const p = this.precision;
    const r = this.recall;
    return p + r ? (2 * p * r) / (p + r) : 0.0;
  }
}

export class KdpiiReport {
  perLabel: Map<string, LabelMetrics> = new Map();
  nDocuments = 0;

  private sum(key: "tp" | "fp" | "fn"): number {
    let s = 0;
    for (const m of this.perLabel.values()) s += m[key];
    return s;
  }

  get microTp(): number {
    return this.sum("tp");
  }

  get microFp(): number {
    return this.sum("fp");
  }

  get microFn(): number {
    return this.sum("fn");
  }

  get microPrecision(): number {
    const t = this.microTp;
    const f = this.microFp;
    return t + f ? t / (t + f) : 0.0;
  }

  get microRecall(): number {
    const t = this.microTp;
    const f = this.microFn;
    return t + f ? t / (t + f) : 0.0;
  }

  get microF1(): number {
    const p = this.microPrecision;
    const r = this.microRecall;
    return p + r ? (2 * p * r) / (p + r) : 0.0;
  }
}

type Json = Record<string, unknown>;

function addGold(doc: KdpiiDocument, mapped: string, form: string): void {
  let s = doc.gold.get(mapped);
  if (s === undefined) {
    s = new Set();
    doc.gold.set(mapped, s);
  }
  s.add(form);
}

/** Python ``d[key]`` — 없으면 KeyError. */
function requireKey(d: Json, key: string): unknown {
  if (!Object.hasOwn(d, key)) {
    const err = new Error(`'${key}'`);
    err.name = "KeyError";
    throw err;
  }
  return d[key];
}

/** Original JSONL schema (cloud session input): {query, answer:[{label,form}]}. */
function fromJsonlRecord(d: Json): KdpiiDocument {
  const doc: KdpiiDocument = { query: requireKey(d, "query") as string, gold: new Map() };
  for (const a of (d.answer ?? []) as Json[]) {
    const mapped = mapLabel(requireKey(a, "label") as string);
    if (mapped === undefined) continue;
    addGold(doc, mapped, requireKey(a, "form") as string);
  }
  return doc;
}

/** Zenodo schema (record 10968609): {sentence, PII_set:[{label,form,begin,end}], ...}. */
function fromZenodoRecord(d: Json): KdpiiDocument {
  const doc: KdpiiDocument = { query: (d.sentence ?? "") as string, gold: new Map() };
  for (const a of (d.PII_set ?? []) as Json[]) {
    const label = a.label as string | null | undefined;
    const form = a.form as string | null | undefined;
    if (!label || !form) continue;
    const mapped = mapLabel(label);
    if (mapped === undefined) continue;
    addGold(doc, mapped, form);
  }
  return doc;
}

/**
 * KDPII 로더 — 입력 형식 자동 감지.
 *
 * - Zenodo JSON (record 10968609): top-level array, 각 record는 ``sentence``/``PII_set`` 필드.
 * - 원래 JSONL: 라인당 ``{query, answer}``.
 *
 * 매핑 안 된 KDPII 라벨은 무시 (``KDPII_LABEL_MAP`` 참조).
 */
export function loadKdpii(path: string): KdpiiDocument[] {
  const text = readUtf8(path);
  const docs: KdpiiDocument[] = [];
  if (pyLstrip(text).startsWith("[")) {
    // Zenodo JSON array
    for (const d of JSON.parse(text) as Json[]) docs.push(fromZenodoRecord(d));
  } else {
    // JSONL
    for (const raw of pySplitlines(text)) {
      const line = pyStrip(raw);
      if (!line) continue;
      const d = JSON.parse(line) as Json;
      if (Object.hasOwn(d, "sentence") && Object.hasOwn(d, "PII_set")) {
        docs.push(fromZenodoRecord(d));
      } else {
        docs.push(fromJsonlRecord(d));
      }
    }
  }
  return docs;
}

/**
 * ``[matchedPred, matchedGold]`` substring overlap 매칭. **단일 canonical 매처.**
 *
 * 예측 텍스트가 gold form 의 부분이거나 반대이면 TP. 1:N / N:1 모두 허용
 * (per-label set 평가; 위치 무시).
 */
export function matchFormsOverlap(
  pred: ReadonlySet<string>,
  gold: ReadonlySet<string>,
): [Set<string>, Set<string>] {
  const mp = new Set<string>();
  const mg = new Set<string>();
  for (const pi of pred) {
    for (const gi of gold) {
      // 정확 일치, 또는 한쪽이 다른 쪽을 포함하되 *짧은 쪽이 2자 이상* 일 때만 TP.
      if (
        pi === gi ||
        ((gi.includes(pi) || pi.includes(gi)) && Math.min(cpLen(pi), cpLen(gi)) >= 2)
      ) {
        mp.add(pi);
        mg.add(gi);
      }
    }
  }
  return [mp, mg];
}

const EMPTY: ReadonlySet<string> = new Set();

/**
 * KDPII 평가.
 *
 * ``personMinLength``: PERSON gold form 의 최소 길이(코드 포인트). **기본 3** — 풀네임만 평가.
 * 1 이면 모든 PERSON 평가. 예측에도 동일한 길이 필터 적용.
 */
export function evaluateKdpii(
  docs: Iterable<KdpiiDocument>,
  detector: (text: string) => Iterable<DetectionResult> = detectAll,
  options: { personMinLength?: number } = {},
): KdpiiReport {
  const personMinLength = options.personMinLength ?? 3;
  const report = new KdpiiReport();
  for (const doc of docs) {
    report.nDocuments += 1;
    const predByLabel = new Map<string, Set<string>>();
    for (const r of detector(doc.query)) {
      // PERSON 예측도 길이 필터 적용 (gold 기준과 일치)
      if (r.label === "PERSON" && cpLen(r.text) < personMinLength) continue;
      let s = predByLabel.get(r.label);
      if (s === undefined) {
        s = new Set();
        predByLabel.set(r.label, s);
      }
      s.add(r.text);
    }
    for (const lab of new Set([...doc.gold.keys(), ...predByLabel.keys()])) {
      let g: ReadonlySet<string> = doc.gold.get(lab) ?? EMPTY;
      // PERSON gold 도 길이 필터
      if (lab === "PERSON" && personMinLength > 1) {
        g = new Set([...g].filter((gi) => cpLen(gi) >= personMinLength));
      }
      const p = predByLabel.get(lab) ?? EMPTY;
      const [mp, mg] = matchFormsOverlap(p, g);
      let m = report.perLabel.get(lab);
      if (m === undefined) {
        m = new LabelMetrics(lab);
        report.perLabel.set(lab, m);
      }
      m.tp += mp.size;
      m.fp += p.size - mp.size; // mp ⊆ p
      m.fn += g.size - mg.size; // mg ⊆ g
    }
  }
  return report;
}

function f3(x: number): string {
  return padLeft(pyFormatFixed(x, 3), 8);
}

export function formatKdpiiReport(report: KdpiiReport): string {
  const lines: string[] = [];
  lines.push(`문서 수: ${report.nDocuments}`);
  lines.push(
    `라벨 매핑: ${Object.keys(KDPII_LABEL_MAP).length} KDPII → ` +
      `${new Set(Object.values(KDPII_LABEL_MAP)).size} ko-pii LABEL`,
  );
  lines.push("");
  lines.push(
    `${padRight("라벨", 15)}${padLeft("정탐", 6)}${padLeft("오탐", 6)}${padLeft("미탐", 6)}` +
      `${padLeft("정확도", 8)}${padLeft("재현율", 8)}${padLeft("F1", 8)}`,
  );
  lines.push("-".repeat(57));
  for (const lab of [...report.perLabel.keys()].sort(pyStrCompare)) {
    const m = report.perLabel.get(lab)!;
    lines.push(
      `${padRight(lab, 15)}${padLeft(String(m.tp), 6)}${padLeft(String(m.fp), 6)}` +
        `${padLeft(String(m.fn), 6)}${f3(m.precision)}${f3(m.recall)}${f3(m.f1)}`,
    );
  }
  lines.push("-".repeat(57));
  lines.push(
    `${padRight("(전체)", 15)}${padLeft(String(report.microTp), 6)}` +
      `${padLeft(String(report.microFp), 6)}${padLeft(String(report.microFn), 6)}` +
      `${f3(report.microPrecision)}${f3(report.microRecall)}${f3(report.microF1)}`,
  );
  lines.push("");
  lines.push("정탐 = 정확히 잡은 것 (gold 도 있음)");
  lines.push("오탐 = 잘못 잡은 것 (gold 없는데 잡음)");
  lines.push("미탐 = 놓친 것 (gold 있는데 못 잡음)");
  return lines.join("\n");
}

export function main(argv?: string[]): number {
  const p = new ArgumentParser("ko-pii-kdpii", "KDPII 코퍼스에서 ko-pii 검출 정확도 평가");
  p.addArgument({ dest: "path", help: "KDPII JSONL 파일" });
  p.addArgument({
    dest: "person_min_length",
    optionStrings: ["--person-min-length"],
    isInt: true,
    def: 3,
    help:
      "PERSON 최소 길이 (기본 3 — 풀네임만 평가, " +
      "한국 개인정보보호법 제2조: 단독 1-2자 별명은 " +
      "그 자체로 PII 아님). 1 로 두면 별명 포함.",
  });
  try {
    const args = p.parseArgs(argv);
    if (args.path === null) p.errorExit("the following arguments are required: path");
    const personMinLength = args.person_min_length as number;
    const docs = loadKdpii(args.path as string);
    const report = evaluateKdpii(docs, detectAll, { personMinLength });
    let out = `${formatKdpiiReport(report)}\n`;
    if (personMinLength >= 3) {
      out +=
        `\n※ PERSON 평가는 풀네임 (${personMinLength}자+) 만 — ` +
        "단독 1-2자 별명 제외 (제2조: 그 자체로 식별 불가)\n";
    }
    process.stdout.write(out);
    return 0;
  } catch (e) {
    if (e instanceof ParseExit) {
      (e.stream === "stdout" ? process.stdout : process.stderr).write(e.text);
      return e.code;
    }
    throw e;
  }
}
