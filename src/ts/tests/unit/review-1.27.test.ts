/**
 * Review 1.27 — Python tests/unit/review/test_review_integrity.py, test_queue.py, test_feedback.py 대응.
 * 기대값은 Python 테스트 단언 또는 .venv/bin/python (ko_pii 1.27.0) 실측값이다.
 */
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Anonymizer, reviewItems } from "../../src/anonymizer.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { makeDetection, RiskLevel } from "../../src/core/types.js";
import { applyFeedback } from "../../src/review/feedback.js";
import { ReviewQueue, Verdict } from "../../src/review/queue.js";

const hoisted = vi.hoisted(() => ({ failRename: false }));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const renameSync: typeof actual.renameSync = (...args) => {
    if (hoisted.failRename)
      throw Object.assign(new Error("simulated replace failure"), { code: "EIO" });
    return actual.renameSync(...args);
  };
  return { ...actual, default: { ...actual, renameSync }, renameSync };
});

const roots: string[] = [];
afterEach(() => {
  hoisted.failRename = false;
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
});
const tmp = (): string => {
  const root = mkdtempSync(join(tmpdir(), "ko-pii-review-"));
  roots.push(root);
  return root;
};

const det = (label: string, text: string, confidence = 0.6) =>
  makeDetection({
    label,
    text,
    start: 0,
    end: text.length,
    riskLevel: RiskLevel.HIGH,
    confidence,
  });

function populate(path: string) {
  const queue = new ReviewQueue(path);
  const item = queue.enqueueDetection(det("PERSON", "홍길동"));
  return [queue, item] as const;
}

function errorOf(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected an error");
}

/** Python json.dumps(dict) 기본 구분자 — 기존 항목 dict 에 변경을 덧붙인 손상 라인. */
function pyLine(d: Record<string, unknown>): string {
  return `{${Object.entries(d)
    .map(([k, v]) => `${JSON.stringify(k)}: ${JSON.stringify(v).replaceAll(",", ", ")}`)
    .join(", ")}}`;
}

describe("feedback — 철회와 출력 소유", () => {
  for (const [verdict, filename, attribute] of [
    [Verdict.FP, "common_words_additions.txt", "common_word_candidates"],
    [Verdict.FN, "names_to_add.txt", "name_candidates"],
  ] as const) {
    it(`${verdict} 철회 시 소유 파일을 비운다`, () => {
      const root = tmp();
      const [queue, item] = populate(join(root, "review.jsonl"));
      queue.mark(item.id, verdict);
      const output = join(root, "feedback");
      const first = applyFeedback(queue.path, output, 1);
      expect(first[attribute]).toEqual(["홍길동"]);
      writeFileSync(join(output, "keep.txt"), "keep");
      queue.mark(item.id, Verdict.OK);
      const current = applyFeedback(queue.path, output, 1);
      expect(current[attribute]).toEqual([]);
      expect(readFileSync(join(output, filename), "utf8")).not.toContain("홍길동");
      expect(readFileSync(join(output, "keep.txt"), "utf8")).toBe("keep");
      expect(JSON.parse(readFileSync(join(output, "summary.json"), "utf8"))[attribute]).toEqual([]);
      applyFeedback(queue.path, output, 1);
      expect(readFileSync(join(output, filename), "utf8")).not.toContain("홍길동");
    });
  }

  for (const count of [0, -1, true, 0.5]) {
    it(`잘못된 min_repeat=${String(count)} 은 출력 없음`, () => {
      const root = tmp();
      expect(() =>
        applyFeedback(join(root, "absent"), join(root, "output"), count as unknown as number),
      ).toThrow(/min_repeat/);
      expect(existsSync(join(root, "output"))).toBe(false);
    });
  }

  for (const text of ["a\nb", " # ignored", "   "]) {
    it(`모호한 줄 ${JSON.stringify(text)} 은 쓰기 전에 거부`, () => {
      const root = tmp();
      const queue = new ReviewQueue(join(root, "q.jsonl"));
      const item = queue.enqueueDetection(det("PERSON", text));
      queue.mark(item.id, Verdict.FP);
      const output = join(root, "patches");
      expect(() => applyFeedback(queue.path, output, 1)).toThrow(/single non-comment/);
      expect(existsSync(output)).toBe(false);
    });
  }

  it("출력 파일 형식 (Python 실측)", () => {
    const root = tmp();
    const queue = new ReviewQueue(join(root, "q.jsonl"));
    for (let i = 0; i < 3; i++) {
      const it2 = queue.enqueueDetection(det("PERSON", "검토"));
      queue.mark(it2.id, Verdict.FP, { note: "일반 단어" });
    }
    const fn = queue.enqueueDetection(det("PERSON", "특이한이름"));
    queue.mark(fn.id, Verdict.FN);
    const ok = queue.enqueueDetection(det("PERSON", "x"));
    queue.mark(ok.id, Verdict.OK);
    queue.enqueueDetection(det("PHONE", "010"));
    const out = join(root, "patches");
    const summary = applyFeedback(queue.path, out, 2);
    expect(summary.fp_count).toBe(3);
    expect(summary.common_word_candidates).toEqual(["검토"]);
    expect(summary.name_candidates).toEqual(["특이한이름"]);
    expect(readFileSync(join(out, "common_words_additions.txt"), "utf8")).toBe(
      "# ko-pii generated candidates; review before applying\n검토\n",
    );
    expect(readFileSync(join(out, "names_to_add.txt"), "utf8")).toBe(
      "# ko-pii generated name candidates; review before applying\n특이한이름\n",
    );
    expect(readFileSync(join(out, "summary.json"), "utf8")).toBe(
      '{\n  "fp_count": 3,\n  "ok_count": 1,\n  "fn_count": 1,\n  "pending": 1,\n' +
        '  "common_word_candidates": [\n    "검토"\n  ],\n  "name_candidates": [\n    "특이한이름"\n  ],\n' +
        '  "fp_by_label": {\n    "PERSON": 3\n  }\n}\n',
    );
    expect(applyFeedback(queue.path, join(root, "p2"), 4).common_word_candidates).toEqual([]);
  });
});

describe("queue — 손상 레코드는 원본 보존 후 실패", () => {
  const changes: Record<string, unknown>[] = [
    { span: [-1, 3] },
    { span: [true, 3] },
    { confidence: "secret@example.com" },
    { verdict: "WRONG" },
    { evidence: "secret@example.com" },
    { surprise: "lost-on-save" },
    { confidence: 2 },
  ];
  for (const change of changes) {
    it(`잘못된 레코드 ${JSON.stringify(change)}`, () => {
      const path = join(tmp(), "q.jsonl");
      const [, item] = populate(path);
      appendFileSync(path, `${pyLine({ ...item.toDict(), id: "bad", ...change })}\n`);
      const original = readFileSync(path);
      const queue = new ReviewQueue(path);
      for (let i = 0; i < 2; i++) {
        const error = errorOf(() => queue.mark(item.id, Verdict.OK));
        expect(error.name).toBe("ValueError");
        expect(error.message).toBe(
          "invalid review queue record at line 2; original file preserved",
        );
        expect(error.message).not.toContain("secret@");
        expect(readFileSync(path).equals(original)).toBe(true);
      }
    });
  }

  for (const raw of ['{"confidence": NaN}', '{"confidence": 1e400}']) {
    it(`비유한 confidence ${raw}`, () => {
      const path = join(tmp(), "q.jsonl");
      const [, item] = populate(path);
      const line = pyLine({ ...item.toDict(), id: "bad" }).replace(
        /"confidence": [^,]+/,
        raw.slice(1, -1),
      );
      appendFileSync(path, `${line}\n`);
      expect(() => new ReviewQueue(path).all()).toThrow(/line 2/);
    });
  }

  for (const suffix of ['{"id":"broken"\n', "[]\n", '{"id":"a","id":"b"}\n']) {
    it(`잘린/객체 아닌 레코드 ${JSON.stringify(suffix)}`, () => {
      const path = join(tmp(), "q.jsonl");
      const [, item] = populate(path);
      appendFileSync(path, suffix);
      const original = readFileSync(path);
      const queue = new ReviewQueue(path);
      expect(() => queue.mark(item.id, Verdict.OK)).toThrow(/line 2/);
      expect(readFileSync(path).equals(original)).toBe(true);
      expect(queue.size.bind(queue)).toThrow(/line 2/);
    });
  }

  it("중복 ID 는 조용히 병합하지 않는다", () => {
    const path = join(tmp(), "q.jsonl");
    const [, item] = populate(path);
    appendFileSync(path, `${JSON.stringify(item.toDict())}\n`);
    expect(() => new ReviewQueue(path).all()).toThrow(/line 2/);
  });

  it("BOM 첫 줄 / 잘못된 UTF-8 (Python 실측)", () => {
    const root = tmp();
    const path = join(root, "q.jsonl");
    const [, item] = populate(path);
    writeFileSync(path, `﻿${readFileSync(path, "utf8")}`);
    expect(() => new ReviewQueue(path).all()).toThrow(
      "invalid review queue record at line 1; original file preserved",
    );
    writeFileSync(path, Buffer.from([0xff, 0xfe, 0x0a]));
    expect(() => new ReviewQueue(path).all()).toThrow(/codec can't decode/);
    expect(item.id).toBeTruthy();
  });

  it("저장 실패 시 메모리·디스크 보존, 임시 파일 없음", () => {
    const root = tmp();
    const path = join(root, "q.jsonl");
    const [queue, item] = populate(path);
    const original = readFileSync(path);
    hoisted.failRename = true;
    expect(() => queue.mark(item.id, Verdict.OK)).toThrow(/simulated replace failure/);
    hoisted.failRename = false;
    expect(queue.byId(item.id)?.verdict).toBeNull();
    expect(readFileSync(path).equals(original)).toBe(true);
    expect(readdirSync(root).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });

  it("끝 개행이 없는 파일에 추가 + 잘못된 verdict 는 파일 불변", () => {
    const path = join(tmp(), "q.jsonl");
    const [, item] = populate(path);
    writeFileSync(path, readFileSync(path, "utf8").replace(/\n+$/, ""));
    const queue = new ReviewQueue(path);
    queue.enqueueDetection(det("PERSON", "홍길동"));
    expect(new ReviewQueue(path).size()).toBe(2);
    const before = readFileSync(path);
    expect(() => queue.mark(item.id, "TYPO")).toThrow(/verdict/);
    expect(readFileSync(path).equals(before)).toBe(true);
  });

  it("잘못된 유니코드 추가는 기존 파일 보존", () => {
    const path = join(tmp(), "q.jsonl");
    const [queue] = populate(path);
    const before = readFileSync(path);
    expect(() =>
      queue.enqueueDetection(
        makeDetection({
          label: "PERSON",
          text: "\ud800",
          start: 0,
          end: 1,
          riskLevel: RiskLevel.HIGH,
        }),
      ),
    ).toThrow(/Unicode/);
    expect(readFileSync(path).equals(before)).toBe(true);
    expect(queue.size()).toBe(1);
  });

  it("빈 enqueue 는 파일을 만들지 않는다 (1.27)", () => {
    const path = join(tmp(), "nested", "q.jsonl");
    expect(new ReviewQueue(path).enqueueReviewRecords([])).toEqual([]);
    expect(existsSync(path)).toBe(false);
  });
});

describe("queue 기본 동작 (test_queue.py)", () => {
  const d = (text = "홍길동") =>
    makeDetection({
      label: "PERSON",
      text,
      start: 0,
      end: text.length,
      riskLevel: RiskLevel.HIGH,
      confidence: 0.55,
      evidence: ["pos:surname"],
      legal_basis: "개인정보보호법 제2조",
    });

  it("추가·재로드·마킹·통계", () => {
    const path = join(tmp(), "queue.jsonl");
    const q = new ReviewQueue(path);
    const a = q.enqueueDetection(d("A"), "doc1.txt");
    const b = q.enqueueDetection(d("B"));
    q.enqueueDetection(d("C"));
    expect(q.mark(a.id, Verdict.OK)).toBe(true);
    expect(q.mark(b.id, Verdict.FP, { by: "reviewer1", note: "동음이의어" })).toBe(true);
    expect(q.mark("missing", Verdict.OK)).toBe(false);
    const q2 = new ReviewQueue(path);
    expect(q2.stats()).toEqual({ total: 3, pending: 1, OK: 1, FP: 1, FN: 0 });
    const marked = q2.byId(b.id);
    expect([marked?.verdict, marked?.verdict_by, marked?.verdict_note]).toEqual([
      "FP",
      "reviewer1",
      "동음이의어",
    ]);
    expect(q2.pending().map((it) => it.text)).toEqual(["C"]);
    // Python json.dumps(ensure_ascii=False) 라인 형식
    const first = readFileSync(path, "utf8").split("\n")[0] as string;
    expect(first).toMatch(
      /^\{"id": "[0-9a-f-]{36}", "doc": "doc1.txt", "label": "PERSON", "text": "A", "span": \[0, 1\], "confidence": 0\.55, "evidence": \["pos:surname"\], "legal_basis": "개인정보보호법 제2조", "verdict": "OK", "verdict_at": "[^"]+", "verdict_by": null, "verdict_note": ""\}$/,
    );
  });

  it("AnonymizationResult REVIEW 항목 일괄 추가", () => {
    const result = new Anonymizer(ProcessingMode.PERMISSIVE).process("주민번호 880101-1234567");
    const q = new ReviewQueue(join(tmp(), "q.jsonl"));
    const items = q.enqueueReviewRecords(reviewItems(result), "doc");
    expect(items.length).toBeGreaterThanOrEqual(1);
    expect(items.every((it) => it.verdict === null)).toBe(true);
  });
});
