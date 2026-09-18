/**
 * KLUE-NER 한국어 NER 벤치마크 어댑터. Python ``ko_pii.eval.klue_ner`` 대응.
 *
 * KLUE benchmark (https://github.com/KLUE-benchmark/KLUE) 의 NER 서브셋:
 * - 자연어 신문기사 문장 단위, BIO 캐릭터-단위 태깅
 * - 6 entity types: PS (사람), OG (기관), LC (장소), DT (날짜), TI (시간), QT (수량)
 *
 * 본 모듈은 ko-pii 의 ``PERSON`` 검출을 KLUE-NER 의 ``PS`` 라벨에 대해 평가한다.
 *
 * 주의: KLUE-NER PS 는 *모든 인명* 포함 (역사인물·외국인·정치인 등) — 본 평가는
 * *자연어 PERSON recall* 의 어림짐작용이다.
 *
 * 오프셋: Python 은 span 의 start/end 로 *태그 인덱스*(= 한 줄 한 글자이므로 코드 포인트
 * 오프셋)를 쓴다. TS 판은 정책대로 UTF-16 코드 유닛 오프셋(앞선 글자들의 ``length`` 합)을
 * 써서 ``text.slice(start, end) === span.text`` 를 유지한다. 한 줄이 한 코드 포인트인 한
 * (KLUE 원본 데이터는 전부 그렇다) 매칭 결과는 Python 과 같다.
 */
import { classifyNameOrigin } from "../context/nameOrigin.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { detect as detectPerson } from "../patterns/person.js";
import { cpLen, pyFileLines, pyStrip, readUtf8 } from "./pyCompat.js";

export interface NerSpan {
  label: string;
  start: number;
  end: number;
  text: string;
}

export interface NerSentence {
  text: string;
  spans: NerSpan[];
}

function bioToSpans(chars: string[], tags: string[]): NerSpan[] {
  // 태그 인덱스 → UTF-16 오프셋
  const offsets: number[] = [0];
  for (const ch of chars) offsets.push(offsets[offsets.length - 1]! + ch.length);

  const spans: NerSpan[] = [];
  let i = 0;
  const n = tags.length;
  while (i < n) {
    const tag = tags[i]!;
    if (tag.startsWith("B-")) {
      const label = tag.slice(2);
      const start = i;
      i += 1;
      while (i < n && tags[i] === `I-${label}`) i += 1;
      spans.push({
        label,
        start: offsets[start]!,
        end: offsets[i]!,
        text: chars.slice(start, i).join(""),
      });
    } else {
      i += 1;
    }
  }
  return spans;
}

/**
 * KLUE-NER 줄 단위 (CHAR \t TAG) → 문장 단위 변환.
 *
 * 문장 구분: 빈 줄. 헤더: ``##`` 로 시작 — 무시.
 */
export function parseCharsAndTags(lines: Iterable<string>): NerSentence[] {
  const out: NerSentence[] = [];
  let chars: string[] = [];
  let tags: string[] = [];

  const flush = (): void => {
    if (chars.length === 0) return;
    out.push({ text: chars.join(""), spans: bioToSpans(chars, tags) });
  };

  for (const raw of lines) {
    const line = raw.endsWith("\n") ? raw.slice(0, -1) : raw;
    if (line.startsWith("##")) continue;
    if (!pyStrip(line)) {
      flush();
      chars = [];
      tags = [];
      continue;
    }
    const parts = line.split("\t");
    if (parts.length < 2) continue;
    chars.push(parts[0]!);
    tags.push(parts[1]!);
  }
  flush();
  return out;
}

/** KLUE-NER 파일을 문장 리스트로 로드. */
export function loadKlueNer(path: string): NerSentence[] {
  return parseCharsAndTags(pyFileLines(readUtf8(path)));
}

// ─────────────────────────────────────────────────────────────────────
// 평가
// ─────────────────────────────────────────────────────────────────────

export class NerEvalReport {
  label: string;
  tp = 0;
  fp = 0;
  fn = 0;
  sentenceCount = 0;

  constructor(label: string) {
    this.label = label;
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

  format(): string {
    return (
      `[KLUE-NER ${this.label}]  문장 ${this.sentenceCount}건  ` +
      `TP=${this.tp}  FP=${this.fp}  FN=${this.fn}\n` +
      `  Precision = ${pyFormatFixed(this.precision, 3)}\n` +
      `  Recall    = ${pyFormatFixed(this.recall, 3)}\n` +
      `  F1        = ${pyFormatFixed(this.f1, 3)}`
    );
  }
}

export interface EvaluatePersonOptions {
  /** ``"partial"`` : span 겹침 = TP / ``"strict"`` : 정확 일치. 기본 partial. */
  mode?: string;
  sampleLimit?: number | null;
  /** true(기본) 면 *한글 3~5자 풀네임* 만 gold 로 인정. */
  fullnameOnly?: boolean;
  /** true 면 한국 이름만 평가 (외국인명 제외). 기본 false. */
  koreanOnly?: boolean;
}

function allHangulSyllables(text: string): boolean {
  for (const ch of text) if (!(ch >= "가" && ch <= "힣")) return false;
  return true;
}

/** ko-pii PERSON 검출을 KLUE-NER PS 라벨에 대해 평가. */
export function evaluatePerson(
  sentences: Iterable<NerSentence>,
  options: EvaluatePersonOptions = {},
): NerEvalReport {
  const mode = options.mode ?? "partial";
  const fullnameOnly = options.fullnameOnly ?? true;
  const koreanOnly = options.koreanOnly ?? false;

  const report = new NerEvalReport("PERSON");
  let sentencesList = [...sentences];
  // Python: ``if sample_limit:`` — 0/None 은 전체, 음수는 ``[:n]`` 슬라이스 그대로.
  if (options.sampleLimit) sentencesList = sentencesList.slice(0, options.sampleLimit);

  const isValidKoreanFullname = (text: string): boolean => {
    if (!fullnameOnly) return true;
    const len = cpLen(text);
    if (len < 3 || len > 5) return false; // 풀네임 = 3-5자 (단성/외자 제외)
    if (!allHangulSyllables(text)) return false;
    if (koreanOnly) return classifyNameOrigin(text) === "korean";
    return true;
  };

  for (const sent of sentencesList) {
    report.sentenceCount += 1;
    const goldPersons = sent.spans.filter((s) => s.label === "PS" && isValidKoreanFullname(s.text));
    const predictedRaw = detectPerson(sent.text);
    // koreanOnly 모드면 외국인 origin 검출도 평가에서 제외
    const predicted = koreanOnly
      ? predictedRaw.filter((p) => p.extra.origin !== "foreign")
      : predictedRaw;

    const matchedPred = new Set<number>();
    for (const g of goldPersons) {
      let hit = -1;
      for (let i = 0; i < predicted.length; i++) {
        if (matchedPred.has(i)) continue;
        const p = predicted[i]!;
        if (mode === "strict") {
          if (p.start === g.start && p.end === g.end) {
            hit = i;
            break;
          }
        } else if (p.start < g.end && g.start < p.end) {
          hit = i;
          break;
        }
      }
      if (hit >= 0) {
        report.tp += 1;
        matchedPred.add(hit);
      } else {
        report.fn += 1;
      }
    }
    for (let i = 0; i < predicted.length; i++) {
      if (matchedPred.has(i)) continue;
      // FP 도 *한글 풀네임* 기준에 맞춰 필터
      if (isValidKoreanFullname(predicted[i]!.text)) report.fp += 1;
    }
  }
  return report;
}

/**
 * 오류 사례 샘플 — FN/FP 분석용.
 *
 * errorType: ``"fn"`` (gold 인데 못 잡음) / 그 외 (잘못 잡음).
 */
export function sampleErrors(
  sentences: Iterable<NerSentence>,
  errorType = "fn",
  limit = 10,
): Array<[NerSentence, string[]]> {
  const out: Array<[NerSentence, string[]]> = [];
  for (const sent of sentences) {
    const goldPersons = sent.spans.filter((s) => s.label === "PS");
    const predicted = detectPerson(sent.text);
    if (errorType === "fn") {
      for (const g of goldPersons) {
        if (!predicted.some((p) => p.start < g.end && g.start < p.end)) {
          out.push([sent, [g.text]]);
          if (out.length >= limit) return out;
        }
      }
    } else {
      for (const p of predicted) {
        if (!goldPersons.some((g) => p.start < g.end && g.start < p.end)) {
          out.push([sent, [p.text]]);
          if (out.length >= limit) return out;
        }
      }
    }
  }
  return out;
}
