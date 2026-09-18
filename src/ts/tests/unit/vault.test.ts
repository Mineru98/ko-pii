/**
 * Vault (reversible/encrypted/audit) 단위 테스트 + 골드 마스터 벡터 대조.
 *
 * Python 원본: tests/unit/vault/test_reversible.py, test_encrypted.py, test_audit.py
 * 골드 벡터: spec/goldmaster/{fingerprint,kdf,kvault}.json (바이트 호환 판정 기준)
 */
import { createHash, pbkdf2Sync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RiskLevel } from "../../src/core/types.js";
import {
  decryptBlob,
  deriveKey,
  encryptWithFixedSaltNonce,
  isEncryptedFile,
  KDF_ITERATIONS,
  KDF_SALT_LEN,
  KEY_LEN,
  loadEncrypted,
  MAGIC,
  NONCE_LEN,
  saveEncrypted,
} from "../../src/vault/encrypted.js";
import { AuditLog, ReversibleVault, replay, VaultEntry } from "../../src/vault/index.js";
import { loadFingerprints, loadKdf } from "../goldmaster/harness.js";

// 골드 kvault.json — harness 에 로더가 없어 직접 읽는다 (기존 테스트 파일 수정 금지).
const GOLD_DIR = join(import.meta.dirname, "..", "..", "..", "..", "spec", "goldmaster");
interface GoldKvault {
  password: string;
  kdf_iterations: number;
  kdf_salt_len: number;
  nonce_len: number;
  magic_hex: string;
  blob_hex: string;
  plaintext_len: number;
}
const goldKvault = JSON.parse(readFileSync(join(GOLD_DIR, "kvault.json"), "utf8")) as GoldKvault;

const GOLD_SALT = "00112233445566778899aabbccddeeff";
const GOLD_KEY = "gold-master-key";
const KDF_SALT = Buffer.from("a1b2c3d4e5f60718293a4b5c6d7e8f90", "hex");
const NONCE = Buffer.from("000102030405060708090a0b", "hex");

let tmp: string;
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "kopii-vault-test-"));
});
afterAll(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe("fingerprint gold vectors", () => {
  for (const c of loadFingerprints().entries) {
    it(`${c.scheme} ${c.label} iters=${c.iterations} key="${c.secret_key}"`, () => {
      let v: ReversibleVault;
      if (c.scheme === "sha256-v1") {
        // Python 생성 방식 재현: from_dict 로 legacy scheme 로드 후 키 재공급
        v = ReversibleVault.fromDict({
          schema_version: 1,
          salt: c.salt,
          fingerprint_scheme: "sha256-v1",
          entries: {},
        });
        v.secretKey = c.secret_key;
      } else {
        v = new ReversibleVault({
          salt: c.salt,
          secretKey: c.secret_key,
          fingerprintIterations: c.iterations,
        });
      }
      expect(v.fingerprint(c.label, c.original)).toBe(c.hex);
    });
  }
});

describe("kdf gold vectors (encrypted.py 키 유도)", () => {
  for (const c of loadKdf().entries) {
    it(`pbkdf2 ${JSON.stringify(c.password)} iters=${c.iterations}`, () => {
      expect(KDF_ITERATIONS).toBe(480_000);
      expect(KEY_LEN).toBe(c.dklen);
      // 480k 케이스는 deriveKey(password, salt), 그 외는 같은 프리미티브 직접 대조
      const key =
        c.iterations === KDF_ITERATIONS
          ? deriveKey(c.password, Buffer.from(c.salt_hex, "hex"))
          : pbkdf2Sync(
              Buffer.from(c.password, "utf8"),
              Buffer.from(c.salt_hex, "hex"),
              c.iterations,
              c.dklen,
              "sha256",
            );
      expect(key.toString("hex")).toBe(c.key_hex);
    });
  }
});

describe(".kvault 골드 벡터 (바이트 호환)", () => {
  it("상수 레이아웃이 Python 과 동일", () => {
    expect(MAGIC.toString("hex")).toBe(goldKvault.magic_hex);
    expect(MAGIC.length).toBe(8);
    expect(KDF_SALT_LEN).toBe(goldKvault.kdf_salt_len);
    expect(NONCE_LEN).toBe(goldKvault.nonce_len);
  });

  it("gold blob 을 loadEncrypted(Buffer) 로 복호화 — schema v1 + RRN/PHONE 2 엔트리", () => {
    const blob = Buffer.from(goldKvault.blob_hex, "hex");
    const v = loadEncrypted(blob, goldKvault.password);
    const d = v.toDict();
    expect(d.schema_version).toBe(1);
    expect(d.created_at).toBe("1970-01-01T00:00:00+00:00");
    expect(v.size).toBe(2);
    expect(v.reveal("<RRN_1>")).toBe("880101-1234568");
    expect(v.reveal("<PHONE_1>")).toBe("010-1234-5678");
    const rrn = v.get("<RRN_1>");
    expect(rrn?.riskLevel).toBe(5);
    expect(rrn?.legalBasis).toBe("개인정보보호법 제24조의2");
    expect(rrn?.firstSeenOffset).toBe(4);
    expect(rrn?.occurrences).toEqual([4]);
    const phone = v.get("<PHONE_1>");
    expect(phone?.riskLevel).toBe(4);
    expect(phone?.legalBasis).toBe("개인정보보호법 제23조");
    expect(phone?.firstSeenOffset).toBe(24);
  });

  it("복호화→재직렬화→재암호화(고정 salt/nonce) 결과가 gold blob 과 바이트 동일", () => {
    const gold = Buffer.from(goldKvault.blob_hex, "hex");
    const v = loadEncrypted(gold, goldKvault.password);
    const plaintext = Buffer.from(v.dumps(null), "utf8");
    // Python json.dumps(ensure_ascii=False, indent=None) 와 바이트 동일해야 한다
    expect(plaintext.length).toBe(goldKvault.plaintext_len);
    const blob = encryptWithFixedSaltNonce(plaintext, goldKvault.password, KDF_SALT, NONCE);
    expect(blob.equals(gold)).toBe(true);
  });

  it("Python 생성 경로 재현 (fresh store → created_at 고정 → 암호화) 바이트 동일", () => {
    const v = new ReversibleVault({ salt: GOLD_SALT, secretKey: GOLD_KEY });
    v.store("RRN", "880101-1234568", 5, "개인정보보호법 제24조의2", 4);
    v.store("PHONE", "010-1234-5678", 4, "개인정보보호법 제23조", 24);
    v.createdAt = "1970-01-01T00:00:00+00:00";
    const plaintext = Buffer.from(v.dumps(null), "utf8");
    expect(plaintext.length).toBe(goldKvault.plaintext_len);
    const blob = encryptWithFixedSaltNonce(plaintext, goldKvault.password, KDF_SALT, NONCE);
    expect(blob.toString("hex")).toBe(goldKvault.blob_hex);
  });
});

describe("ReversibleVault 토큰/엔트리 (Python test_reversible 대응)", () => {
  it("같은 값은 같은 토큰", () => {
    const v = new ReversibleVault({ salt: "abc" });
    const t1 = v.store("RRN", "880101-1234568", RiskLevel.CRITICAL);
    const t2 = v.store("RRN", "880101-1234568", RiskLevel.CRITICAL);
    expect(t1).toBe(t2);
    expect(t1).toBe("<RRN_1>");
  });

  it("다른 값은 다른 토큰, 라벨별 카운터", () => {
    const v = new ReversibleVault({ salt: "abc" });
    expect(v.store("RRN", "880101-1234568", 5)).toBe("<RRN_1>");
    expect(v.store("RRN", "950101-2345676", 5)).toBe("<RRN_2>");
    expect(v.store("PHONE", "010-1234-5678", 3)).toBe("<PHONE_1>");
    expect(v.labels()).toEqual(new Set(["RRN", "PHONE"]));
    expect(v.size).toBe(3);
    expect(v.has("<RRN_1>")).toBe(true);
    expect(v.has("<RRN_9>")).toBe(false);
  });

  it("reveal 왕복 + 미지 토큰 null", () => {
    const v = new ReversibleVault({ salt: "abc" });
    const token = v.store("EMAIL", "user@example.com", 3, "개인정보보호법 제2조");
    expect(v.reveal(token)).toBe("user@example.com");
    expect(v.reveal("<NONEXISTENT_99>")).toBeNull();
  });

  it("occurrences 누적", () => {
    const v = new ReversibleVault({ salt: "abc" });
    v.store("EMAIL", "a@b.c", 3, null, 10);
    v.store("EMAIL", "a@b.c", 3, null, 50);
    v.store("EMAIL", "a@b.c", 3, null, 120);
    const entry = v.get("<EMAIL_1>");
    expect(entry).toBeDefined();
    expect(entry?.occurrences).toEqual([10, 50, 120]);
    expect(entry?.firstSeenOffset).toBe(10);
  });

  it("dumps → loads 왕복 + 카운터 보존", () => {
    const v = new ReversibleVault({ salt: "abc" });
    v.store("RRN", "880101-1234568", 5);
    v.store("RRN", "950101-2345676", 5);
    v.store("PHONE", "010-1234-5678", 3);
    const v2 = ReversibleVault.loads(v.dumps());
    expect(v2.salt).toBe("abc");
    expect(v2.reveal("<RRN_1>")).toBe("880101-1234568");
    expect(v2.reveal("<PHONE_1>")).toBe("010-1234-5678");
    // 신규 store 는 기존 RRN_1/2 와 충돌하지 않는다
    expect(v2.store("RRN", "100101-3000005", 5)).toBe("<RRN_3>");
  });

  it("save/load 파일 왕복", () => {
    const v = new ReversibleVault({ salt: "abc" });
    v.store("EMAIL", "a@b.c", 3);
    const p = join(tmp, "vault.json");
    v.save(p);
    const v2 = ReversibleVault.load(p);
    expect(v2.reveal("<EMAIL_1>")).toBe("a@b.c");
  });

  it("미지 schema_version 거부", () => {
    expect(() => ReversibleVault.fromDict({ schema_version: 99, salt: "x", entries: {} })).toThrow(
      /schema_version/,
    );
  });

  it("entry 역색인/카운터 재구성 + 비정상 토큰 skip", () => {
    const v = ReversibleVault.fromDict({
      schema_version: 1,
      created_at: "t",
      salt: "s",
      entries: {
        "<RRN_2>": { label: "RRN", original: "a", risk_level: 5 },
        "weird-token": { label: "RRN", original: "b", risk_level: 4 },
        "<PHONE_x>": { label: "PHONE", original: "c", risk_level: 3 },
      },
    });
    // 역색인: 같은 (label, original) 재저장 시 기존 토큰(비정상 토큰 포함) 재사용 — Python 동일
    expect(v.store("RRN", "a", 5)).toBe("<RRN_2>");
    expect(v.store("RRN", "b", 4)).toBe("weird-token");
    // 카운터는 <RRN_2> 만 반영, 비정상 토큰 2개는 skip
    expect(v.store("RRN", "z", 5)).toBe("<RRN_3>");
    expect(v.store("PHONE", "d", 3)).toBe("<PHONE_1>"); // <PHONE_x> 숫자 파싱 실패 → 카운터 없음
  });

  it("secret_key 는 직렬화되지 않는다", () => {
    const v = new ReversibleVault({
      salt: "s",
      secretKey: "topsecret",
      fingerprintIterations: 1000,
    });
    const d = v.toDict();
    expect(d).not.toHaveProperty("secret_key");
    expect(JSON.stringify(d)).not.toContain("topsecret");
  });

  it("legacy vault 는 sha256-v1 지문 유지", () => {
    const v = ReversibleVault.fromDict({
      schema_version: 1,
      created_at: "t",
      salt: "s",
      entries: {},
    });
    const expected = createHash("sha256").update("s:RRN:900101-1234567").digest("hex");
    expect(v.fingerprint("RRN", "900101-1234567")).toBe(expected);
  });

  it("KDF 지문은 재적재 후 키 재공급으로 재현 가능", () => {
    const v = new ReversibleVault({ salt: "s", secretKey: "k", fingerprintIterations: 1000 });
    const before = v.fingerprint("RRN", "900101-1234567");
    const v2 = ReversibleVault.fromDict(v.toDict());
    v2.secretKey = "k";
    expect(v2.fingerprint("RRN", "900101-1234567")).toBe(before);
  });

  it("env KPII_FINGERPRINT_KEY 사용", () => {
    const prev = process.env.KPII_FINGERPRINT_KEY;
    process.env.KPII_FINGERPRINT_KEY = "envkey";
    try {
      const withEnv = new ReversibleVault({ salt: "s", fingerprintIterations: 1000 });
      delete process.env.KPII_FINGERPRINT_KEY;
      const without = new ReversibleVault({ salt: "s", fingerprintIterations: 1000 });
      expect(withEnv.fingerprint("RRN", "900101-1234567")).not.toBe(
        without.fingerprint("RRN", "900101-1234567"),
      );
    } finally {
      if (prev === undefined) delete process.env.KPII_FINGERPRINT_KEY;
      else process.env.KPII_FINGERPRINT_KEY = prev;
    }
  });

  it("지문 메모이즈 — 반복 호출이 같은 값 (KDF 1회)", () => {
    const v = new ReversibleVault({ salt: "s", secretKey: "k", fingerprintIterations: 1000 });
    expect(v.fingerprint("RRN", "900101-1234567")).toBe(v.fingerprint("RRN", "900101-1234567"));
  });

  it("dumps compact 포맷이 Python json.dumps(indent=None) 구분자와 동일", () => {
    const v = new ReversibleVault({ salt: "abc" });
    v.store("RRN", "880101-1234568", 5);
    const compact = v.dumps(null);
    expect(compact).toContain('{"schema_version": 1,');
    expect(compact).toContain('"risk_level": 5, "legal_basis": null');
    expect(compact).toContain('"occurrences": [], "extra": {}}}');
    expect(JSON.parse(compact)).toEqual(JSON.parse(v.dumps(2)));
  });
});

describe("encrypted 왕복 (Python test_encrypted 대응)", () => {
  it("save → isEncryptedFile → load 왕복", () => {
    const v = new ReversibleVault({ salt: "abc" });
    v.store("RRN", "880101-1234568", 5);
    v.store("PHONE", "010-1234-5678", 3);
    const path = join(tmp, "roundtrip.kvault");
    saveEncrypted(v, path, "mysecret123");
    expect(isEncryptedFile(path)).toBe(true);
    const v2 = loadEncrypted(path, "mysecret123");
    expect(v2.reveal("<RRN_1>")).toBe("880101-1234568");
    expect(v2.reveal("<PHONE_1>")).toBe("010-1234-5678");
    expect(v2.salt).toBe("abc");
  });

  it("잘못된 비밀번호 → Error (AAD/tag 불일치)", () => {
    const v = new ReversibleVault({ salt: "abc" });
    v.store("RRN", "880101-1234568", 5);
    const path = join(tmp, "wrongpw.kvault");
    saveEncrypted(v, path, "right_password");
    expect(() => loadEncrypted(path, "wrong_password")).toThrow(/decryption failed/);
  });

  it("빈 비밀번호 거부 (save/고정 헬퍼 모두)", () => {
    const v = new ReversibleVault({ salt: "abc" });
    expect(() => saveEncrypted(v, join(tmp, "x.kvault"), "")).toThrow(/non-empty/);
    expect(() => encryptWithFixedSaltNonce("{}", "", KDF_SALT, NONCE)).toThrow(/non-empty/);
    expect(encryptWithFixedSaltNonce("{}", "pw", KDF_SALT, NONCE).length).toBeGreaterThan(0);
  });

  it("일반 JSON 파일/짧은 파일은 암호화 파일 아님", () => {
    const plain = join(tmp, "plain.json");
    writeFileSync(plain, '{"schema_version": 1, "salt": "x", "entries": {}}');
    expect(isEncryptedFile(plain)).toBe(false);
    const garbage = join(tmp, "garbage.dat");
    writeFileSync(
      garbage,
      Buffer.from("not a vault, but long enough to pass the length check", "utf8"),
    );
    expect(isEncryptedFile(garbage)).toBe(false);
    expect(() => loadEncrypted(garbage, "any")).toThrow(/magic mismatch/);
    // 52바이트 미만은 Python 과 같이 길이 검사가 magic 검사보다 먼저다
    expect(() => loadEncrypted(Buffer.from("short", "utf8"), "any")).toThrow(
      /truncated or invalid/,
    );
  });

  it("decryptBlob 은 saveEncrypted 출력과 역연산", () => {
    const v = new ReversibleVault({ salt: "abc" });
    v.store("RRN", "880101-1234568", 5);
    const path = join(tmp, "blob.kvault");
    saveEncrypted(v, path, "pw-한글");
    const pt = decryptBlob(readFileSync(path), "pw-한글");
    expect(JSON.parse(pt.toString("utf8")).salt).toBe("abc");
  });

  it("tag 는 ciphertext 뒤에 결합된다 (blob 길이 = 36 + ct + 16)", () => {
    const v = new ReversibleVault({ salt: "abc" });
    const path = join(tmp, "layout.kvault");
    saveEncrypted(v, path, "pw");
    const pt = Buffer.from(v.dumps(null), "utf8");
    // GCM tag 16 바이트가 평문 길이에 추가되어 들어있다
    expect(readFileSync(path).length).toBe(8 + 16 + 12 + pt.length + 16);
  });
});

describe("AuditLog (Python test_audit 대응)", () => {
  it("record_store/record_reveal 기록 + replay (결정론 타임스탬프 주입)", () => {
    const path = join(tmp, "audit-basic.jsonl");
    const ticks = [
      "2024-01-01T00:00:01+00:00",
      "2024-01-01T00:00:02+00:00",
      "2024-01-01T00:00:03+00:00",
    ];
    let i = 0;
    const log = new AuditLog(path, "tester", { now: () => ticks[Math.min(i++, ticks.length - 1)] });
    log.recordStore("<RRN_1>", "RRN", { actor: "alice" });
    log.recordReveal("<RRN_1>", "RRN", { actor: "bob", context: "export to BI" });
    log.close();

    const entries = replay(path);
    expect(entries).toHaveLength(2);
    expect(entries[0]?.action).toBe("store");
    expect(entries[0]?.actor).toBe("alice");
    expect(entries[0]?.ts).toBe("2024-01-01T00:00:01+00:00");
    expect(entries[1]?.action).toBe("reveal");
    expect(entries[1]?.context).toBe("export to BI");
  });

  it("vault 연동 — 재저장 new=false, probing reveal found=false", () => {
    const path = join(tmp, "audit-vault.jsonl");
    const log = new AuditLog(path, "tester", { now: () => "2024-01-01T00:00:00+00:00" });
    const v = new ReversibleVault({ salt: "x", auditLog: log });
    v.store("RRN", "880101-1234568", 5);
    v.store("RRN", "880101-1234568", 5); // 재저장도 기록 (new=false)
    expect(v.reveal("<RRN_1>", "legitimate request")).toBe("880101-1234568");
    v.reveal("<NOPE_9>"); // 실패(probing) reveal — 보안상 반드시 기록

    const entries = replay(path);
    const stores = entries.filter((e) => e.action === "store");
    const reveals = entries.filter((e) => e.action === "reveal");
    expect(stores).toHaveLength(2);
    expect(stores.map((e) => (e.extra as { new: boolean } | undefined)?.new)).toEqual([
      true,
      false,
    ]);
    expect(reveals).toHaveLength(2);
    expect(reveals.map((e) => (e.extra as { found: boolean } | undefined)?.found)).toEqual([
      true,
      false,
    ]);
    const ok = reveals.find((e) => (e.extra as { found: boolean }).found);
    expect(ok?.context).toBe("legitimate request");
  });

  it("attachAudit 로 생성 후 연결", () => {
    const path = join(tmp, "audit-attach.jsonl");
    const v = new ReversibleVault({ salt: "x" });
    v.store("RRN", "880101-1234568", 5); // 감사 X
    const log = new AuditLog(path, "tester", { now: () => "2024-01-01T00:00:00+00:00" });
    v.attachAudit(log);
    v.reveal("<RRN_1>", "now logged");
    const entries = replay(path);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.action).toBe("reveal");
  });

  it("없는 파일 replay 는 빈 배열", () => {
    expect(replay(join(tmp, "no_such.jsonl"))).toEqual([]);
  });

  it("손상 라인은 건너뛴다", () => {
    const path = join(tmp, "audit-corrupt.jsonl");
    writeFileSync(
      path,
      '{"ts": "t", "action": "store"}\n{broken json\n\n{"ts": "t2", "action": "reveal"}\n',
    );
    const entries = replay(path);
    expect(entries).toHaveLength(2);
    expect(entries[1]?.action).toBe("reveal");
  });

  it("빈 extra 는 기록하지 않고 (Python if extra:), 존재하면 기록", () => {
    const path = join(tmp, "audit-extra.jsonl");
    const log = new AuditLog(path, "tester", { now: () => "2024-01-01T00:00:00+00:00" });
    log.record("anonymize", { extra: {} });
    log.recordAnonymize(3, "STRICT");
    const entries = replay(path);
    expect(entries[0]).not.toHaveProperty("extra");
    expect(entries[1]?.extra).toEqual({ count: 3, mode: "STRICT" });
  });
});

describe("VaultEntry", () => {
  it("toDict 는 token 제외 + Python 필드 순서 유지", () => {
    const e = new VaultEntry("<X_1>", "X", "orig", 5, "basis", 3, [3], { k: "v" });
    const d = e.toDict();
    expect(Object.keys(d)).toEqual([
      "label",
      "original",
      "risk_level",
      "legal_basis",
      "first_seen_offset",
      "occurrences",
      "extra",
    ]);
    expect(d.label).toBe("X");
    expect(d.risk_level).toBe(5);
  });
});
