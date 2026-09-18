import { describe, expect, it } from "vitest";
import {
  codepointOffsetToUtf16,
  loadAnonymize,
  loadDetections,
  loadFingerprints,
  loadKdf,
  loadMeta,
  loadUnicodeEdges,
  loadVaults,
} from "./harness.js";

/**
 * M0: 골드 마스터 데이터가 TS 하네스 스키마와 일치하는지 검증한다.
 * (Python产 데이터의 무결성 + 픽스처 정합성 — TS 구현 비교는 M1/M2 테스트에서)
 */
describe("goldmaster data schema", () => {
  const meta = loadMeta();

  it("meta.json has required fields and fixtures", () => {
    expect(meta.ko_pii_version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(meta.offset_unit).toBe("codepoint");
    expect(meta.fixed_salt).toMatch(/^[0-9a-f]{32}$/);
    expect(meta.strategies).toEqual(["tokenize", "redact", "asterisk", "hashed", "partial", "fpe"]);
    expect(meta.fixture_ids.length).toBeGreaterThanOrEqual(20);
  });

  it("detection.json entries match meta fixture ids", () => {
    const { entries } = loadDetections();
    expect(entries.map((e) => e.id)).toEqual(meta.fixture_ids);
    for (const entry of entries) {
      for (const d of entry.detections) {
        expect(d.start).toBeLessThan(d.end);
        expect(d.risk_level).toBeGreaterThanOrEqual(1);
        expect(d.risk_level).toBeLessThanOrEqual(5);
        // 골드 오프셋은 코드 포인트 — UTF-16 유닛으로 변환 후 본문과 대조.
        const u16Start = codepointOffsetToUtf16(entry.text, d.start);
        const u16End = codepointOffsetToUtf16(entry.text, d.end);
        expect(d.text).toBe(entry.text.slice(u16Start, u16End));
      }
    }
  });

  it("detection coverage includes core PII labels", () => {
    const { entries } = loadDetections();
    const labels = new Set(entries.flatMap((e) => e.detections.map((d) => d.label)));
    for (const label of ["RRN", "PHONE", "PERSON", "ADDRESS", "EMAIL", "CARD"]) {
      expect(labels, `골드 벡터에 ${label} 검출이 없음`).toContain(label);
    }
  });

  it("anonymize.json covers 6 strategies × all fixtures", () => {
    const { entries } = loadAnonymize();
    expect(entries.length).toBe(meta.fixture_ids.length * meta.strategies.length);
    for (const entry of entries) {
      expect(typeof entry.text_out).toBe("string");
      for (const record of entry.records) {
        expect(["BLOCK", "REVIEW", "ALLOW"]).toContain(record.action);
      }
    }
  });

  it("vault.json tokenize dumps round-trip as JSON with schema v1", () => {
    const { salt, entries } = loadVaults();
    expect(entries.length).toBe(meta.fixture_ids.length);
    for (const entry of entries) {
      const parsed = JSON.parse(entry.dumps);
      expect(parsed.schema_version).toBe(1);
      expect(parsed.salt).toBe(salt);
      expect(parsed.created_at).toBe("1970-01-01T00:00:00+00:00");
      for (const [, data] of Object.entries(parsed.entries)) {
        expect(data).toHaveProperty("label");
        expect(data).toHaveProperty("original");
      }
    }
  });

  it("fingerprint.json vectors are 64-hex digests", () => {
    const { entries } = loadFingerprints();
    expect(entries.length).toBeGreaterThanOrEqual(7);
    for (const e of entries) {
      expect(e.hex).toMatch(/^[0-9a-f]{64}$/);
      expect(["sha256-v1", "pbkdf2-sha256-v2"]).toContain(e.scheme);
    }
    // 같은 (label, original)에 secret_key 가 다르면 pbkdf2 지문이 달라야 한다.
    const rrn = entries.filter(
      (e) => e.scheme === "pbkdf2-sha256-v2" && e.iterations === 1000 && e.label === "RRN",
    );
    const hexes = new Set(rrn.map((e) => e.hex));
    expect(hexes.size).toBe(rrn.length);
  });

  it("kdf.json 480k iterations vectors are 32-byte keys", () => {
    const { entries } = loadKdf();
    for (const e of entries) {
      expect(e.key_hex).toMatch(/^[0-9a-f]{64}$/);
      expect(e.dklen).toBe(32);
    }
    expect(entries.some((e) => e.iterations === 480_000)).toBe(true);
  });

  it("unicode_edge.json covers fullwidth/NFD/zerowidth/emoji cases", () => {
    const { offset_unit, entries } = loadUnicodeEdges();
    expect(offset_unit).toBe("codepoint");
    expect(entries.length).toBeGreaterThanOrEqual(10);
    for (const e of entries) {
      expect(typeof e.normalized).toBe("string");
      if (e.offset_map !== null) {
        // 빈 맵 = 변경 없음. 변경 시 정규화 본문 길이와 1:1 대응.
        expect([0, e.normalized.length]).toContain(e.offset_map.length);
      }
    }
  });
});
