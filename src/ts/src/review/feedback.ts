/** 사용자 피드백 → 사전·룰 학습. Python `ko_pii.review.feedback` 1:1 포트.
 *
 * 검토 큐에서 ``verdict`` 가 설정된 항목들을 분석하여:
 *
 * - **FP (false positive)** 표시된 토큰: 다음 실행에서 다시 잡지 않도록 후보로 등록
 *   - PERSON FP 였으면 → ``common_words`` 후보로 제안
 *   - 카테고리별 패턴 분석은 별도 작업
 * - **FN (false negative)** 표시된 토큰: 사용자 사전에 추가하여 다음부터 잡도록
 *
 * 학습은 *자동 적용* 이 아니라 **patch 파일 생성** 후 사용자 검토 → 수동 반영.
 * 잘못된 학습이 누적되는 것을 방지.
 *
 * 출력: ``feedback_patches/`` 디렉토리에:
 * - ``common_words_additions.txt`` — PERSON FP 들 (한 줄당 1단어)
 * - ``names_to_add.txt`` — FN 으로 표시된 이름들
 * - ``summary.json`` — 통계
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { compareCodePoints } from "../reporting/summary.js";
import { pyJsonDumps } from "../vault/reversible.js";
import { ReviewQueue } from "./queue.js";

/** Python `FeedbackSummary` dataclass 대응 — 필드명/순서 동일 유지. */
export interface FeedbackSummary {
  fp_count: number;
  ok_count: number;
  fn_count: number;
  pending: number;
  common_word_candidates: string[];
  name_candidates: string[];
  fp_by_label: Record<string, number>;
}

/**
 * 검토 큐에서 verdict 마킹을 읽어 패치 파일 생성.
 *
 * @param minRepeat 같은 토큰이 ``minRepeat`` 회 이상 FP 마킹되어야 후보로 등록
 *   (오류 표시 한 번에 사전이 오염되는 것 방지).
 */
export function applyFeedback(
  queuePath: string,
  outputDir: string,
  minRepeat = 2,
): FeedbackSummary {
  const q = new ReviewQueue(queuePath);
  const items = q.all();

  const summary: FeedbackSummary = {
    fp_count: 0,
    ok_count: 0,
    fn_count: 0,
    pending: 0,
    common_word_candidates: [],
    name_candidates: [],
    fp_by_label: {},
  };
  // (label, text) → 표시 횟수. Python Counter 튜플 키를 \u0000 조합 키로 대응.
  const fpTokens = new Map<string, number>();
  const fnTokens = new Map<string, number>();
  const tupleKey = (label: string, text: string): string => `${label}\u0000${text}`;

  for (const item of items) {
    if (item.verdict === null) {
      summary.pending += 1;
    } else if (item.verdict === "FP") {
      summary.fp_count += 1;
      summary.fp_by_label[item.label] = (summary.fp_by_label[item.label] ?? 0) + 1;
      const k = tupleKey(item.label, item.text);
      fpTokens.set(k, (fpTokens.get(k) ?? 0) + 1);
    } else if (item.verdict === "OK") {
      summary.ok_count += 1;
    } else if (item.verdict === "FN") {
      summary.fn_count += 1;
      const k = tupleKey(item.label, item.text);
      fnTokens.set(k, (fnTokens.get(k) ?? 0) + 1);
    }
  }

  // PERSON FP → common_words 후보
  const personFps = [...fpTokens.entries()]
    .filter(([k, n]) => k.startsWith(`PERSON\u0000`) && n >= minRepeat)
    .map(([k]) => k.slice(1 + "PERSON".length))
    .sort(compareCodePoints);
  summary.common_word_candidates = personFps;

  // 모든 FN → 이름 후보 (PERSON 가정)
  summary.name_candidates = [...fnTokens.entries()]
    .filter(([k]) => k.startsWith(`PERSON\u0000`))
    .map(([k]) => k.slice(1 + "PERSON".length))
    .sort(compareCodePoints);

  mkdirSync(outputDir, { recursive: true });

  if (personFps.length > 0) {
    writeFileSync(
      join(outputDir, "common_words_additions.txt"),
      "# ko-pii 검토 큐에서 자동 생성된 일반 단어 후보\n" +
        "# 검토 후 src/ko_pii/dictionaries/common_words.py 에 반영하세요.\n" +
        personFps.map((w) => `${w}\n`).join(""),
      "utf8",
    );
  }

  if (summary.name_candidates.length > 0) {
    writeFileSync(
      join(outputDir, "names_to_add.txt"),
      "# 사용자가 FN 으로 표시한 이름들\n" +
        "# 사용자 사전 (사이트별 names.txt) 에 추가 후 person 검출 부스트로 활용 가능\n" +
        summary.name_candidates.map((n) => `${n}\n`).join(""),
      "utf8",
    );
  }

  writeFileSync(
    join(outputDir, "summary.json"),
    pyJsonDumps(
      {
        fp_count: summary.fp_count,
        ok_count: summary.ok_count,
        fn_count: summary.fn_count,
        pending: summary.pending,
        common_word_candidates: summary.common_word_candidates,
        name_candidates: summary.name_candidates,
        fp_by_label: summary.fp_by_label,
      },
      2,
    ),
    "utf8",
  );

  return summary;
}
