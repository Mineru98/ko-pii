import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { ReversibleVault } from "../../src/vault/reversible.js";
import { codepointOffsetToUtf16, loadAnonymize, loadMeta } from "./harness.js";

/**
 * Anonymizer ↔ Python anonymize.json (6 전략 × 35 픽스처 = 210건) 골드 대조.
 * 각 엔트리는 고정 salt/secret_key 의 신규 vault 로 처리한다 (골드 생성 방식과 동일).
 */
describe("Anonymizer gold master regression", () => {
  const meta = loadMeta();
  const { entries } = loadAnonymize();

  it("covers all strategies × fixtures", () => {
    expect(entries.length).toBe(meta.fixture_ids.length * meta.strategies.length);
  });

  it.each(entries.map((e) => [`${e.id}:${e.strategy}`, e] as const))(
    "parity with Python: %s",
    (_caseId, gold) => {
      const vault = new ReversibleVault({
        salt: meta.fixed_salt,
        secretKey: meta.fixed_secret_key,
      });
      const result = new Anonymizer(ProcessingMode.STRICT, gold.strategy, vault).process(
        gold.text_in,
      );

      expect(result.text).toBe(gold.text_out);

      // records: 라벨/액션/토큰/오프셋 — 골드 오프셋은 코드 포인트이므로 UTF-16으로
      // 변환 후 TS 값(UTF-16 기준)과 비교한다.
      expect(
        result.detections.map((r) => ({
          label: r.detection.label,
          action: r.action,
          token: r.token,
          start: r.detection.start,
          end: r.detection.end,
        })),
      ).toEqual(
        gold.records.map((r) => ({
          label: r.label,
          action: r.action,
          token: r.token,
          start: codepointOffsetToUtf16(gold.text_in, r.start),
          end: codepointOffsetToUtf16(gold.text_in, r.end),
        })),
      );

      // summary: 전체 구조 비교 (combined_risk 이름, rationale 순서, 집계 키)
      expect(result.summary).toEqual(gold.summary);
    },
  );
});
