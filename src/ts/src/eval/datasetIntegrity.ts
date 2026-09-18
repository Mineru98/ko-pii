/**
 * 평가 데이터 무결성 가드 — train/test 누수 차단. Python ``ko_pii.eval.dataset_integrity`` 대응.
 *
 * PII 데이터셋을 재분할(merge→reshuffle)하면 원본 파티션이 해체돼 **train 에 test 문장이
 * 섞여 들어가는 누수**가 발생할 수 있다. 데이터 빌더는 분할 직후 ``assertNoTextLeakage`` 로
 * train∩test = ∅ 를 단언해야 한다.
 */
import { pyRepr } from "../cli/argparse.js";
import { pyStrip, pySubWhitespace } from "./pyCompat.js";

/** Python ``AssertionError`` 대응 (``error.name`` 일치). */
export class AssertionError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "AssertionError";
  }
}

/** 공백 정규화 후 비교 키 — 사소한 공백 차이로 누수를 놓치지 않도록. */
function norm(t: string | null | undefined): string {
  return pyStrip(pySubWhitespace(t || "", " "));
}

function normSet(texts: Iterable<string | null | undefined>): Set<string> {
  const out = new Set<string>();
  for (const t of texts) {
    const n = norm(t);
    if (n) out.add(n);
  }
  return out;
}

function intersect(a: Set<string>, b: Set<string>): string[] {
  const out: string[] = [];
  for (const x of a) if (b.has(x)) out.push(x);
  return out;
}

/**
 * train 과 test 의 (정규화된) 문장 교집합이 비어있지 않으면 AssertionError.
 *
 * 메시지의 예시 3건은 Python 에서는 set 순회 순서(해시 시드 의존, 비결정적)이고
 * 여기서는 train 삽입 순서다 — 누수 건수와 나머지 문구는 동일.
 */
export function assertNoTextLeakage(
  trainTexts: Iterable<string | null | undefined>,
  testTexts: Iterable<string | null | undefined>,
  options: { name?: string } = {},
): void {
  const name = options.name ?? "dataset";
  const leaked = intersect(normSet(trainTexts), normSet(testTexts));
  if (leaked.length > 0) {
    const sample = `[${leaked.slice(0, 3).map(pyRepr).join(", ")}]`;
    throw new AssertionError(
      `[${name}] train↔test 문장 누수 ${leaked.length}건 — ` +
        `train 이 test 코퍼스를 외워 평가가 오염됨. 예: ${sample}`,
    );
  }
}

/** 누수 문장 수만 반환 (assert 없이 점검용). */
export function textLeakageCount(
  trainTexts: Iterable<string | null | undefined>,
  testTexts: Iterable<string | null | undefined>,
): number {
  return intersect(normSet(trainTexts), normSet(testTexts)).length;
}
