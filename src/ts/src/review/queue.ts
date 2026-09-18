/** 검토 큐 (Review Queue) — REVIEW 항목의 영구 저장 + 마킹.
 *
 * Python `ko_pii.review.queue` 1:1 포트.
 *
 * 저장 포맷: JSON Lines (``.jsonl``). 각 라인 = 한 항목:
 *
 *   {"id": "uuid", "doc": "doc.hwpx", "label": "PERSON", "text": "홍길동",
 *    "span": [42, 45], "confidence": 0.6, "evidence": [...],
 *    "verdict": null, "verdict_at": null, "verdict_by": null, "verdict_note": ""}
 *
 * verdict 가 ``null`` 이면 미검토. ``"OK"`` / ``"FP"`` / ``"FN"`` 셋 중 하나.
 *
 * 바이트 호환: 라인 직렬화는 Python `json.dumps(..., ensure_ascii=False)` 기본
 * 구분자(`", "` / `": "`)를 재현한다. `float` 인 confidence 는 Python 처럼 정숫값에
 *도 `.0` 을 붙인다 (`1.0` vs JS `1`). Python 이 파일을 통째로 다시 쓰는
 * (임시파일+rename 없는) 단순 rewrite 를 쓰므로 그대로 따른다.
 */
import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { DetectionRecord } from "../anonymizer.js";
import { pyFloatRepr } from "../core/pyFormat.js";
import type { DetectionResult } from "../core/types.js";
import { pyIsoUtcNow, pyStrip } from "../vault/reversible.js";

/** Python `Verdict(str, Enum)` 대응. */
export enum Verdict {
  OK = "OK", // 검출 맞음 (true positive)
  FP = "FP", // 잘못 검출 (false positive — 사전·룰 보강 필요)
  FN = "FN", // 진짜였지만 놓침 (사용자 수동 추가)
}

/** Python `_load` 가 건너뛰는 KeyError 대응 (JSONDecodeError 와 구별). */
class MissingKeyError extends Error {
  constructor(key: string) {
    super(`missing required key: ${key}`);
    this.name = "MissingKeyError";
  }
}

/** Python `ReviewItem.to_dict()` (dataclass asdict) 형태 — 필드 선언 순서 유지. */
export interface ReviewItemDict {
  id: string;
  doc: string;
  label: string;
  text: string;
  span: number[];
  confidence: number;
  evidence: string[];
  legal_basis: string | null;
  verdict: string | null;
  verdict_at: string | null;
  verdict_by: string | null;
  verdict_note: string;
}

export class ReviewItem {
  id: string;
  doc: string;
  label: string;
  text: string;
  span: number[];
  confidence: number;
  evidence: string[];
  legal_basis: string | null;
  verdict: string | null;
  verdict_at: string | null;
  verdict_by: string | null;
  verdict_note: string;

  constructor(
    id: string,
    doc: string,
    label: string,
    text: string,
    span: number[],
    confidence: number,
    evidence: string[] = [],
    legal_basis: string | null = null,
    verdict: string | null = null,
    verdictAt: string | null = null,
    verdictBy: string | null = null,
    verdictNote = "",
  ) {
    this.id = id;
    this.doc = doc;
    this.label = label;
    this.text = text;
    this.span = span;
    this.confidence = confidence;
    this.evidence = evidence;
    this.legal_basis = legal_basis;
    this.verdict = verdict;
    this.verdict_at = verdictAt;
    this.verdict_by = verdictBy;
    this.verdict_note = verdictNote;
  }

  toDict(): ReviewItemDict {
    return {
      id: this.id,
      doc: this.doc,
      label: this.label,
      text: this.text,
      span: [...this.span],
      confidence: this.confidence,
      evidence: [...this.evidence],
      legal_basis: this.legal_basis,
      verdict: this.verdict,
      verdict_at: this.verdict_at,
      verdict_by: this.verdict_by,
      verdict_note: this.verdict_note,
    };
  }

  static fromDict(d: Record<string, unknown>): ReviewItem {
    const requiredString = (key: string): string => {
      const v = d[key];
      if (v === undefined) throw new MissingKeyError(key);
      return typeof v === "string" ? v : String(v);
    };
    const optString = (key: string): string | null => {
      const v = d[key];
      return v === undefined || v === null ? null : String(v);
    };
    const rawSpan = d.span;
    if (rawSpan === undefined) throw new MissingKeyError("span");
    const span = Array.isArray(rawSpan) ? rawSpan.map((x) => Number(x)) : [];
    return new ReviewItem(
      requiredString("id"),
      d.doc === undefined ? "" : String(d.doc),
      requiredString("label"),
      requiredString("text"),
      span,
      pyFloat(d.confidence === undefined ? 0.0 : d.confidence),
      Array.isArray(d.evidence) ? (d.evidence as string[]) : [],
      optString("legal_basis"),
      optString("verdict"),
      optString("verdict_at"),
      optString("verdict_by"),
      d.verdict_note === undefined ? "" : String(d.verdict_note),
    );
  }
}

/** Python `float()` 대응 — bool 은 int 서브클래스이므로 1.0/0.0, 나머지 비숫자는 TypeError. */
function pyFloat(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "string") return Number(v);
  const t = v === null ? "NoneType" : typeof v === "object" ? "dict" : typeof v;
  throw new TypeError(`float() argument must be a string or a real number, not '${t}'`);
}

/** Python `json.dumps(item.to_dict(), ensure_ascii=False)` 바이트 동등 라인. */
function serializeItem(item: ReviewItem): string {
  const d = item.toDict();
  const opt = (v: string | null): string => (v === null ? "null" : JSON.stringify(v));
  return (
    `{"id": ${JSON.stringify(d.id)}` +
    `, "doc": ${JSON.stringify(d.doc)}` +
    `, "label": ${JSON.stringify(d.label)}` +
    `, "text": ${JSON.stringify(d.text)}` +
    `, "span": [${d.span.join(", ")}]` +
    `, "confidence": ${pyFloatRepr(d.confidence)}` +
    `, "evidence": ${pyJsonArray(d.evidence)}` +
    `, "legal_basis": ${opt(d.legal_basis)}` +
    `, "verdict": ${opt(d.verdict)}` +
    `, "verdict_at": ${opt(d.verdict_at)}` +
    `, "verdict_by": ${opt(d.verdict_by)}` +
    `, "verdict_note": ${JSON.stringify(d.verdict_note)}}`
  );
}

/** Python `json.dumps([...], ensure_ascii=False)` 대응 문자열 배열 직렬화. */
function pyJsonArray(xs: string[]): string {
  if (xs.length === 0) return "[]";
  return `[${xs.map((x) => JSON.stringify(x)).join(", ")}]`;
}

function ensureDir(path: string): void {
  mkdirSync(dirname(path) || ".", { recursive: true });
}

/** Python `ReviewQueue.stats()` 형태. */
export interface QueueStats {
  total: number;
  pending: number;
  OK: number;
  FP: number;
  FN: number;
}

/** 파일 기반 검토 큐 (append + rewrite-on-mark). */
export class ReviewQueue {
  readonly path: string;
  private items: ReviewItem[] = [];
  private loaded = false;

  constructor(path: string) {
    this.path = path;
  }

  private load(): void {
    if (this.loaded) return;
    if (!existsSync(this.path)) {
      this.loaded = true;
      return;
    }
    const content = readFileSync(this.path, "utf8");
    // Python 텍스트 모드(universal newlines): \n·\r\n·\r 모두 줄 구분. `str.strip()` 은 JS
    // `trim()` 과 달리 BOM(U+FEFF)을 걷어내지 않는다 (vault/audit.ts replay 와 같은 규칙).
    for (const rawLine of content.split(/\r\n|\r|\n/)) {
      const line = pyStrip(rawLine);
      if (!line) continue;
      try {
        const parsed: unknown = JSON.parse(line);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          // Python: d["id"] 가 list/str/int 에서 TypeError — 건너뛰지 않고 중단된다.
          throw new TypeError("review queue line must be a JSON object");
        }
        this.items.push(ReviewItem.fromDict(parsed as Record<string, unknown>));
      } catch (e) {
        // Python: json.JSONDecodeError / KeyError 만 건너뛴다.
        if (e instanceof SyntaxError || e instanceof MissingKeyError) continue;
        throw e;
      }
    }
    this.loaded = true;
  }

  private save(): void {
    ensureDir(this.path);
    writeFileSync(this.path, this.items.map((it) => `${serializeItem(it)}\n`).join(""), "utf8");
  }

  // ─────────────────────── 큐 조작

  /** ``DetectionResult`` 를 검토 큐에 추가. */
  enqueueDetection(detection: DetectionResult, document = ""): ReviewItem {
    this.load();
    const item = new ReviewItem(
      randomUUID(),
      document,
      detection.label,
      detection.text,
      [detection.start, detection.end],
      detection.confidence,
      [...detection.evidence],
      detection.legal_basis,
    );
    this.items.push(item);
    // append-only 로 단일 항목 추가 (성능)
    ensureDir(this.path);
    appendFileSync(this.path, `${serializeItem(item)}\n`, "utf8");
    return item;
  }

  /** ``AnonymizationResult.reviewItems()`` 결과를 일괄 추가. */
  enqueueReviewRecords(records: Iterable<DetectionRecord>, document = ""): ReviewItem[] {
    this.load();
    const items: ReviewItem[] = [];
    // buffer + single open
    ensureDir(this.path);
    let buffer = "";
    for (const r of records) {
      const d = r.detection;
      const item = new ReviewItem(
        randomUUID(),
        document,
        d.label,
        d.text,
        [d.start, d.end],
        d.confidence,
        [...d.evidence],
        d.legal_basis,
      );
      this.items.push(item);
      items.push(item);
      buffer += `${serializeItem(item)}\n`;
    }
    // Python `open(path, "a")` 는 records 가 비어도 빈 파일을 만든다.
    appendFileSync(this.path, buffer, "utf8");
    return items;
  }

  // ─────────────────────── 조회

  pending(): ReviewItem[] {
    this.load();
    return this.items.filter((it) => it.verdict === null);
  }

  all(): ReviewItem[] {
    this.load();
    return [...this.items];
  }

  byId(itemId: string): ReviewItem | null {
    this.load();
    for (const it of this.items) {
      if (it.id === itemId) return it;
    }
    return null;
  }

  /** Python `len(queue)` 대응. */
  size(): number {
    this.load();
    return this.items.length;
  }

  // ─────────────────────── 마킹

  /** 항목에 verdict 부여. true 면 성공, false 면 ID 없음. */
  mark(
    itemId: string,
    verdict: Verdict | string,
    opts: { by?: string | null; note?: string } = {},
  ): boolean {
    this.load();
    for (const it of this.items) {
      if (it.id === itemId) {
        it.verdict = String(verdict);
        it.verdict_at = pyIsoUtcNow();
        it.verdict_by = opts.by ?? null;
        it.verdict_note = opts.note ?? "";
        this.save(); // 전체 재기록 — 마킹은 빈번하지 않음
        return true;
      }
    }
    return false;
  }

  stats(): QueueStats {
    this.load();
    const stats: QueueStats = { total: this.items.length, pending: 0, OK: 0, FP: 0, FN: 0 };
    for (const it of this.items) {
      if (it.verdict === null) {
        stats.pending += 1;
      } else if (Object.hasOwn(stats, it.verdict)) {
        const key = it.verdict as keyof QueueStats;
        stats[key] += 1;
      }
    }
    return stats;
  }
}
