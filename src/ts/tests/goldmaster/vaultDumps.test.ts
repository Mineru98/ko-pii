import { describe, expect, it } from "vitest";
import { Anonymizer } from "../../src/anonymizer.js";
import { ProcessingMode } from "../../src/core/modes.js";
import { ReversibleVault } from "../../src/vault/reversible.js";
import { codepointOffsetToUtf16, loadAnonymize, loadMeta, loadVaults } from "./harness.js";

/**
 * tokenize 전략의 Vault JSON 직렬화 ↔ Python vault.json 대조.
 * created_at 은 골드 생성 시 상수로 치환되므로 비교에서 제외하고, 나머지 전체
 * (schema/salt/fingerprint_scheme/iterations/entries 키·값)를 대조한다.
 */
describe("vault dumps gold master regression", () => {
  const meta = loadMeta();
  const { entries } = loadVaults();
  const textById = new Map(
    loadAnonymize()
      .entries.filter((e) => e.strategy === "tokenize")
      .map((e) => [e.id, e.text_in] as const),
  );

  it.each(entries.map((e) => [e.id, e] as const))("vault entries match Python: %s", (id, gold) => {
    const text = textById.get(id);
    expect(text).toBeDefined();
    const vault = new ReversibleVault({
      salt: meta.fixed_salt,
      secretKey: meta.fixed_secret_key,
    });
    new Anonymizer(ProcessingMode.STRICT, "tokenize", vault).process(text as string);
    const actual = JSON.parse(vault.dumps()) as Record<string, unknown>;
    const expected = JSON.parse(gold.dumps) as {
      created_at?: string;
      entries: Record<
        string,
        { first_seen_offset: number; occurrences: number[] } & Record<string, unknown>
      >;
    };
    delete (actual as { created_at?: string }).created_at;
    delete expected.created_at;
    // 골드 오프셋(first_seen_offset/occurrences)은 코드 포인트 → UTF-16 변환.
    const source = text as string;
    for (const entry of Object.values(expected.entries)) {
      entry.first_seen_offset = codepointOffsetToUtf16(source, entry.first_seen_offset);
      entry.occurrences = entry.occurrences.map((o) => codepointOffsetToUtf16(source, o));
    }
    expect(actual).toEqual(expected);
  });
});
