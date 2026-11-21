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
 * 도 `.0` 을 붙인다 (`1.0` vs JS `1`). 마킹은 원자적 교체(writeTextAtomic), 추가는
 * O_APPEND 로 기록한다. 손상·스키마 오류·중복 ID 레코드는 건너뛰지 않고 원본을 보존한 채
 * ``ValueError`` 로 실패한다.
 *
 * TS 표현 차이: JSON.parse 는 `1` 과 `1.0` 을 구분하지 못해 span 의 `1.0` 같은 float 표기를
 * 정수로 받아들인다 (Python 은 거부). 직렬화기는 항상 정수를 쓰므로 수동 편집 파일에서만 다르다.
 */
import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import type { DetectionRecord } from "../anonymizer.js";
import { ValueError } from "../core/errors.js";
import { pyFloatRepr } from "../core/pyFormat.js";
import type { DetectionResult } from "../core/types.js";
import { writeTextAtomic } from "../io/atomic.js";
import { loadsJson } from "../structured.js";
import { pyIsoUtcNow, pyStrip } from "../vault/reversible.js";

/** Python `Verdict(str, Enum)` 대응. */
export enum Verdict {
  OK = "OK", // 검출 맞음 (true positive)
  FP = "FP", // 잘못 검출 (false positive — 사전·룰 보강 필요)
  FN = "FN", // 진짜였지만 놓침 (사용자 수동 추가)
}

const ITEM_FIELDS: ReadonlySet<string> = new Set([
  "id",
  "doc",
  "label",
  "text",
  "span",
  "confidence",
  "evidence",
  "legal_basis",
  "verdict",
  "verdict_at",
  "verdict_by",
  "verdict_note",
]);
const VERDICTS: ReadonlySet<unknown> = new Set(["OK", "FP", "FN"]);
/** `u` 플래그에서는 짝 없는 서로게이트만 매칭된다 — Python 의 UTF-8 인코딩 실패 대응. */
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

function isPlainDict(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Python `ReviewItem.to_dict()` (dataclass asdict) 형태 — 필드 선언 순서 유지. */
export interface ReviewItemDict {
  id: string;
  doc: string;
  label: string;
  text: string;
  span: (number | bigint)[];
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
  span: (number | bigint)[];
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
    span: (number | bigint)[],
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

  /** 엄격 검증 — 알 수 없는 필드·잘못된 span/confidence/verdict 는 값 없는 ``ValueError``. */
  static fromDict(d: unknown): ReviewItem {
    if (
      !isPlainDict(d) ||
      !["id", "label", "text", "span"].every((k) => Object.hasOwn(d, k)) ||
      !Object.keys(d).every((k) => ITEM_FIELDS.has(k))
    ) {
      throw new ValueError("invalid review item fields");
    }
    for (const key of ["id", "label", "text"]) {
      const v = d[key];
      if (typeof v !== "string" || !v) throw new ValueError("invalid review item string");
    }
    for (const key of ["doc", "verdict_note"]) {
      if (Object.hasOwn(d, key) && typeof d[key] !== "string") {
        throw new ValueError("invalid review metadata");
      }
    }
    for (const key of ["legal_basis", "verdict_at", "verdict_by"]) {
      const v = Object.hasOwn(d, key) ? d[key] : null;
      if (v !== null && v !== undefined && typeof v !== "string") {
        throw new ValueError("invalid review metadata");
      }
    }
    const span = d.span;
    const confidence = Object.hasOwn(d, "confidence") ? d.confidence : 0.0;
    const evidence = Object.hasOwn(d, "evidence") ? d.evidence : [];
    if (
      !Array.isArray(span) ||
      span.length !== 2 ||
      // Python ``type(n) is int`` — 안전 범위 밖 JSON 정수는 bigint 로 들어온다.
      span.some((n) => typeof n !== "bigint" && (typeof n !== "number" || !Number.isInteger(n))) ||
      !(
        0 <= (span[0] as number | bigint) &&
        (span[0] as number | bigint) < (span[1] as number | bigint)
      )
    ) {
      throw new ValueError("invalid review span");
    }
    if (
      typeof confidence !== "number" ||
      !(0 <= confidence && confidence <= 1) ||
      !Number.isFinite(confidence)
    ) {
      throw new ValueError("invalid review confidence");
    }
    if (!Array.isArray(evidence) || evidence.some((e) => typeof e !== "string")) {
      throw new ValueError("invalid review evidence");
    }
    const verdict = Object.hasOwn(d, "verdict") ? d.verdict : null;
    if (verdict !== null && verdict !== undefined && !VERDICTS.has(verdict)) {
      throw new ValueError("invalid review verdict");
    }
    const opt = (key: string): string | null =>
      Object.hasOwn(d, key) ? ((d[key] as string | null | undefined) ?? null) : null;
    return new ReviewItem(
      d.id as string,
      Object.hasOwn(d, "doc") ? (d.doc as string) : "",
      d.label as string,
      d.text as string,
      [...(span as (number | bigint)[])],
      confidence,
      [...(evidence as string[])],
      opt("legal_basis"),
      opt("verdict"),
      opt("verdict_at"),
      opt("verdict_by"),
      Object.hasOwn(d, "verdict_note") ? (d.verdict_note as string) : "",
    );
  }
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
      this.items = [];
      this.loaded = true;
      return;
    }
    // Python open(encoding="utf-8"): BOM 을 벗기지 않고, 잘못된 UTF-8 은 디코딩 오류.
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
        readFileSync(this.path),
      );
    } catch {
      throw new ValueError("'utf-8' codec can't decode review queue bytes");
    }
    const loaded: ReviewItem[] = [];
    const ids = new Set<string>();
    // Python 텍스트 모드(universal newlines): \n·\r\n·\r 모두 줄 구분. `str.strip()` 은 JS
    // `trim()` 과 달리 BOM(U+FEFF)을 걷어내지 않는다.
    const lines = content.split(/\r\n|\r|\n/);
    if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    for (const [index, rawLine] of lines.entries()) {
      const line = pyStrip(rawLine);
      if (!line) continue;
      let item: ReviewItem;
      try {
        item = ReviewItem.fromDict(loadsJson(line));
        if (ids.has(item.id)) throw new ValueError("duplicate review id");
      } catch (e) {
        if (e instanceof ValueError || e instanceof TypeError) {
          throw new ValueError(
            `invalid review queue record at line ${index + 1}; original file preserved`,
          );
        }
        throw e;
      }
      ids.add(item.id);
      loaded.push(item);
    }
    this.items = loaded;
    this.loaded = true;
  }

  private save(items: ReviewItem[]): void {
    const content = ReviewQueue.serialize(items);
    ensureDir(this.path);
    writeTextAtomic(this.path, content);
  }

  private static serialize(items: ReviewItem[]): string {
    const validated = items.map((item) => ReviewItem.fromDict(item.toDict()));
    if (new Set(validated.map((item) => item.id)).size !== validated.length) {
      throw new ValueError("duplicate review id");
    }
    for (const item of validated) {
      const d = item.toDict();
      const strings = [
        d.id,
        d.doc,
        d.label,
        d.text,
        ...d.evidence,
        d.legal_basis,
        d.verdict,
        d.verdict_at,
        d.verdict_by,
        d.verdict_note,
      ];
      if (strings.some((v) => typeof v === "string" && LONE_SURROGATE.test(v))) {
        throw new ValueError("review items must contain valid Unicode");
      }
    }
    return validated.map((item) => `${serializeItem(item)}\n`).join("");
  }

  private append(items: ReviewItem[]): void {
    const content = ReviewQueue.serialize(items);
    if (items.length === 0) return;
    ensureDir(this.path);
    let isLink = false;
    try {
      isLink = lstatSync(this.path).isSymbolicLink();
    } catch {
      isLink = false;
    }
    if (isLink) throw new ValueError("review queue must not be a symbolic link");
    let prefix = "";
    if (existsSync(this.path) && statSync(this.path).size > 0) {
      const fd = openSync(this.path, "r");
      try {
        const last = Buffer.alloc(1);
        readSync(fd, last, 0, 1, statSync(this.path).size - 1);
        if (last[0] !== 0x0a) prefix = "\n";
      } finally {
        closeSync(fd);
      }
    }
    try {
      const fd = openSync(this.path, "a", 0o600);
      try {
        const bytes = Buffer.from(prefix + content, "utf8");
        let offset = 0;
        while (offset < bytes.length) offset += writeSync(fd, bytes, offset);
      } finally {
        closeSync(fd);
      }
    } catch (e) {
      this.loaded = false;
      throw e;
    }
    this.items.push(...items);
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
    this.append([item]);
    return item;
  }

  /** ``AnonymizationResult.reviewItems()`` 결과를 일괄 추가. */
  enqueueReviewRecords(records: Iterable<DetectionRecord>, document = ""): ReviewItem[] {
    this.load();
    const items: ReviewItem[] = [];
    for (const r of records) {
      const d = r.detection;
      items.push(
        new ReviewItem(
          randomUUID(),
          document,
          d.label,
          d.text,
          [d.start, d.end],
          d.confidence,
          [...d.evidence],
          d.legal_basis,
        ),
      );
    }
    this.append(items);
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

  /** 항목에 verdict 부여. true 면 성공, false 면 ID 없음. 저장 실패 시 메모리·디스크 모두 유지. */
  mark(
    itemId: string,
    verdict: Verdict | string,
    opts: { by?: string | null; note?: string } = {},
  ): boolean {
    if (!VERDICTS.has(verdict)) throw new ValueError("invalid review verdict");
    this.load();
    for (const [index, it] of this.items.entries()) {
      if (it.id === itemId) {
        const updated = ReviewItem.fromDict({
          ...it.toDict(),
          verdict: String(verdict),
          verdict_at: pyIsoUtcNow(),
          verdict_by: opts.by ?? null,
          verdict_note: opts.note ?? "",
        });
        const candidate = [...this.items];
        candidate[index] = updated;
        this.save(candidate);
        this.items = candidate;
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
