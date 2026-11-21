/**
 * Vault (reversible/encrypted/audit) 단위 테스트 + 골드 마스터 벡터 대조.
 *
 * Python 원본: tests/unit/vault/test_reversible.py, test_encrypted.py, test_audit.py
 * 골드 벡터: spec/goldmaster/{fingerprint,kdf,kvault}.json (바이트 호환 판정 기준)
 */
import { createHash, pbkdf2Sync } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ValueError } from "../../src/core/errors.js";
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

  it("entry 역색인/카운터 재구성 — 비정상 토큰은 거부 (1.27: skip → ValueError)", () => {
    const v = ReversibleVault.fromDict({
      schema_version: 1,
      created_at: "t",
      salt: "s",
      entries: {
        "<RRN_2>": { label: "RRN", original: "a", risk_level: 5 },
        "<RRN_7>": { label: "RRN", original: "b", risk_level: 4 },
      },
    });
    expect(v.store("RRN", "a", 5)).toBe("<RRN_2>");
    expect(v.store("RRN", "b", 4)).toBe("<RRN_7>");
    expect(v.store("RRN", "z", 5)).toBe("<RRN_8>");
    expect(v.store("PHONE", "d", 3)).toBe("<PHONE_1>");
    for (const token of ["weird-token", "<PHONE_x>"]) {
      expect(() =>
        ReversibleVault.fromDict({
          schema_version: 1,
          salt: "s",
          entries: { [token]: { label: "PHONE", original: "c", risk_level: 3 } },
        }),
      ).toThrow(ValueError);
    }
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
    expect(entries[1]?.extra).toEqual({ count: 3, mode: "STRICT", status: "completed" });
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

// ---------------------------------------------------------------------------
// 1.27.0 — 적재 검증·토큰 정합성·감사 실패 정책 (Python tests/unit/test_email_vault_boundaries.py,
// tests/unit/vault/test_audit.py). 기대 메시지는 .venv/bin/python 실측값.
// ---------------------------------------------------------------------------

const PY_VALID_DUMP =
  '{"schema_version": 1, "created_at": "2026-01-01T00:00:00+00:00", "salt": "test", "fingerprint_scheme": "pbkdf2-sha256-v2", "fingerprint_iterations": 100000, "entries": {"<PHONE_1>": {"label": "PHONE", "original": "018-2345-6789", "risk_level": 3, "legal_basis": null, "first_seen_offset": -1, "occurrences": [], "extra": {}}}}';

// biome-ignore lint/suspicious/noExplicitAny: Python 테스트처럼 payload 를 자유롭게 변형하는 동적 JSON
type JsonPayload = Record<string, any>;

function boundaryPayload(): JsonPayload {
  const v = new ReversibleVault({ salt: "test" });
  v.store("PHONE", "018-2345-6789", 3);
  v.createdAt = "2026-01-01T00:00:00+00:00";
  return JSON.parse(v.dumps(null)) as JsonPayload;
}

function loadOutcome(payload: unknown): string {
  try {
    const raw = typeof payload === "string" ? payload : JSON.stringify(payload);
    ReversibleVault.loads(raw);
    return "OK";
  } catch (e) {
    if (!(e instanceof ValueError)) throw e;
    return e.message;
  }
}

describe("1.27 Vault 적재 검증 (Python 실측 메시지 대조)", () => {
  it("유효 payload 는 Python dumps 와 바이트 동일하게 왕복", () => {
    expect(boundaryPayload()).toEqual(JSON.parse(PY_VALID_DUMP));
    expect(ReversibleVault.loads(PY_VALID_DUMP).dumps(null)).toBe(PY_VALID_DUMP);
    const multi =
      '{"schema_version": 1, "created_at": "t", "salt": "s", "fingerprint_scheme": "pbkdf2-sha256-v2", "fingerprint_iterations": 100000, "entries": {"<PHONE_1>": {"label": "PHONE", "original": "a", "risk_level": 3, "legal_basis": null, "first_seen_offset": 4, "occurrences": [4], "extra": {}}, "<PHONE_2>": {"label": "PHONE", "original": "b", "risk_level": 3, "legal_basis": null, "first_seen_offset": -1, "occurrences": [], "extra": {}}, "<CUSTOM_LABEL_1>": {"label": "CUSTOM_LABEL", "original": "c", "risk_level": 2, "legal_basis": "basis", "first_seen_offset": 9, "occurrences": [9], "extra": {"k": [1, 2]}}}}';
    const v = new ReversibleVault({ salt: "s" });
    v.store("PHONE", "a", 3, null, 4);
    v.store("PHONE", "b", 3);
    v.store("CUSTOM_LABEL", "c", 2, "basis", 9, { k: [1, 2] });
    v.createdAt = "t";
    expect(v.dumps(null)).toBe(multi);
    expect(ReversibleVault.loads(multi).dumps(null)).toBe(multi);
  });

  it.each([
    ["<PHONE_0>", "Invalid vault token index"],
    ["<PHONE_-1>", "Invalid vault token index"],
    ["<PHONE_01>", "Invalid vault token index"],
    ["<PHONE_1", "Vault token does not match its label"],
    ["PHONE_1>", "Vault token does not match its label"],
    ["<PHONE_١>", "Invalid vault token index"],
    ["<PHONE_1>>", "Invalid vault token index"],
    ["1", "Vault token does not match its label"],
    ["<PHONE_>", "Invalid vault token index"],
    ["<PHONE_99>", "OK"],
  ])("토큰 %s → %s", (token, expected) => {
    const p = boundaryPayload();
    p.entries[token] = p.entries["<PHONE_1>"];
    delete p.entries["<PHONE_1>"];
    expect(loadOutcome(p)).toBe(expected);
  });

  it("라벨-토큰 불일치는 거부하고 payload 를 바꾸지 않는다", () => {
    const p = boundaryPayload();
    p.entries["<PHONE_1>"].label = "EMAIL";
    const before = structuredClone(p);
    expect(() => ReversibleVault.fromDict(p)).toThrow(/token does not match/);
    expect(p).toEqual(before);
  });

  it.each([
    ["label", null, "Invalid vault label"],
    ["label", [], "Invalid vault label"],
    ["label", "", "Invalid vault label"],
    ["label", "A<B", "Invalid vault label"],
    ["original", 1, "Invalid vault original: expected a string"],
    ["original", [], "Invalid vault original: expected a string"],
    ["risk_level", true, "Invalid vault risk_level"],
    ["risk_level", 0, "Invalid vault risk_level"],
    ["risk_level", 6, "Invalid vault risk_level"],
    ["risk_level", "3", "Invalid vault risk_level"],
    ["risk_level", 1.5, "Invalid vault risk_level"],
    ["legal_basis", [], "Invalid vault legal_basis"],
    ["first_seen_offset", -2, "Invalid vault offset"],
    ["first_seen_offset", true, "Invalid vault offset"],
    ["occurrences", "12", "Invalid vault occurrences"],
    ["occurrences", [-1], "Invalid vault occurrences"],
    ["occurrences", [true], "Invalid vault occurrences"],
    ["extra", [], "Invalid vault extra: expected an object"],
    ["extra", null, "Invalid vault extra: expected an object"],
  ])("entry %s=%j → %s", (field, value, expected) => {
    const p = boundaryPayload();
    p.entries["<PHONE_1>"][field] = value;
    expect(loadOutcome(p)).toBe(expected);
  });

  it.each([
    ["risk_level", "Invalid vault risk_level"],
    ["legal_basis", "OK"],
    ["first_seen_offset", "OK"],
    ["occurrences", "OK"],
    ["extra", "OK"],
    ["label", "Invalid vault label"],
    ["original", "Invalid vault original: expected a string"],
  ])("entry 필드 %s 누락 → %s", (field, expected) => {
    const p = boundaryPayload();
    delete p.entries["<PHONE_1>"][field];
    expect(loadOutcome(p)).toBe(expected);
  });

  const ITER = "Invalid vault fingerprint_iterations: expected a positive integer";
  it.each([
    ["schema_version", true, "Unsupported vault schema_version"],
    ["schema_version", 2, "Unsupported vault schema_version"],
    ["salt", null, "Invalid vault salt"],
    ["created_at", [], "Invalid vault created_at"],
    ["entries", [], "Invalid vault entries: expected an object"],
    ["entries", null, "Invalid vault entries: expected an object"],
    ["fingerprint_scheme", "unsupported", "Unsupported vault fingerprint_scheme"],
    ["fingerprint_scheme", [], "Unsupported vault fingerprint_scheme"],
    ["fingerprint_scheme", null, "Unsupported vault fingerprint_scheme"],
    ["fingerprint_iterations", 0, ITER],
    ["fingerprint_iterations", -1, ITER],
    ["fingerprint_iterations", true, ITER],
    ["fingerprint_iterations", "1000", ITER],
    ["fingerprint_iterations", 1.5, ITER],
    ["fingerprint_iterations", null, ITER],
  ])("vault %s=%j → %s", (field, value, expected) => {
    const p = boundaryPayload();
    p[field] = value;
    expect(loadOutcome(p)).toBe(expected);
  });

  it.each([
    ["schema_version", "Unsupported vault schema_version"],
    ["salt", "Invalid vault salt"],
    ["entries", "OK"],
    ["fingerprint_scheme", "OK"],
    ["fingerprint_iterations", "OK"],
  ])("vault 필드 %s 누락 → %s", (field, expected) => {
    const p = boundaryPayload();
    delete p[field];
    expect(loadOutcome(p)).toBe(expected);
  });

  it("legacy(scheme 누락) 는 sha256-v1, 반복 횟수 누락은 기본값", () => {
    const p = boundaryPayload();
    delete p.fingerprint_scheme;
    delete p.fingerprint_iterations;
    const v = ReversibleVault.fromDict(p);
    expect(v.fpScheme).toBe("sha256-v1");
    expect(v.fpIterations).toBe(100_000);
  });

  it.each(["null", "[]", '"secret-text"', "1"])("객체가 아닌 vault %s 거부", (raw) => {
    expect(loadOutcome(raw)).toBe("Invalid vault: expected an object");
    expect(() => ReversibleVault.fromDict(JSON.parse(raw))).toThrow(ValueError);
  });

  it("같은 identity 가 두 토큰을 가질 수 없다", () => {
    const p = boundaryPayload();
    p.entries["<PHONE_2>"] = structuredClone(p.entries["<PHONE_1>"]);
    expect(loadOutcome(p)).toBe("Duplicate vault identity mapping");
  });

  it.each([
    ['{"schema_version":1,"salt":"x","entries":{},"entries":{}}', "dup"],
    ['{"schema_version":1,"salt":"x","entries":{"private-key":{},"private-key":{}}}', "dup"],
    ['{"schema_version":1,"salt":"x","extra":{"private-key":1,"private-key":2}}', "dup"],
    ['{"schema_version":1,"salt":"x","a":{"k\\u0031":1,"k1":2}}', "dup"],
    ['{"schema_version":1,"salt":"x","a":[{"k":1},{"k":2}]}', "OK"],
  ])("JSON 중복 키는 모든 깊이에서 거부, 값은 메시지에 없음: %s", (raw, kind) => {
    const out = loadOutcome(raw);
    if (kind === "OK") expect(out).toBe("OK");
    else expect(out).toBe("Invalid vault JSON: duplicate object key");
    expect(out).not.toContain("private-key");
  });

  it.each(["NaN", "Infinity", "-Infinity"])("비유한 JSON 상수 %s 거부", (c) => {
    expect(loadOutcome(`{"schema_version":1,"salt":"x","extra":${c}}`)).toBe(
      "Invalid vault JSON: non-finite number",
    );
  });

  it("문자열 안의 NaN/Infinity 와 구문 오류", () => {
    expect(loadOutcome('{"schema_version":1,"salt":"NaN Infinity","entries":{}}')).toBe("OK");
    expect(() => ReversibleVault.loads('{"schema_version":1,')).toThrow(ValueError);
  });

  it("변조된 entry 로 store 하면 Inconsistent — 상태 불변", () => {
    const vault = ReversibleVault.fromDict(boundaryPayload());
    const entry = vault.get("<PHONE_1>");
    if (entry) entry.original = "other value";
    const before = vault.dumps(null);
    expect(() => vault.store("PHONE", "018-2345-6789", 3, null, 100)).toThrow(/Inconsistent/);
    expect(vault.dumps(null)).toBe(before);
  });

  it("토큰 충돌은 카운터 예약 전에 검사 (Conflicting) — 상태 불변", () => {
    const vault = ReversibleVault.fromDict(boundaryPayload());
    const internals = vault as unknown as {
      counters: Map<string, number>;
      reverse: Map<string, string>;
    };
    internals.counters.set("PHONE", 0);
    const before = vault.dumps(null);
    const reverse = new Map(internals.reverse);
    expect(() => vault.store("PHONE", "010-9876-5432", 3)).toThrow(/Conflicting/);
    expect(vault.dumps(null)).toBe(before);
    expect(internals.reverse).toEqual(reverse);
    expect(internals.counters.get("PHONE")).toBe(0);
  });

  it("legacy/current 무작위 왕복 — 토큰 재현 + 신규 토큰 비충돌", () => {
    let seed = 20261022;
    const rand = (n: number): number => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed % n;
    };
    const labels = ["PHONE", "EMAIL", "CUSTOM_LABEL"];
    for (let round = 0; round < 30; round++) {
      const vault = new ReversibleVault({ salt: "test" });
      const pairs = Array.from(
        { length: 30 },
        () => [labels[rand(3)] ?? "PHONE", String(rand(100))] as const,
      );
      const tokens = pairs.map(([label, value], i) => vault.store(label, value, 3, null, i));
      for (const legacy of [false, true]) {
        const payload = vault.toDict() as unknown as Record<string, unknown>;
        if (legacy) {
          delete payload.fingerprint_scheme;
          delete payload.fingerprint_iterations;
        }
        const loaded = ReversibleVault.loads(JSON.stringify(payload));
        pairs.forEach(([label, value], i) => {
          expect(loaded.store(label, value, 3)).toBe(tokens[i]);
          expect(loaded.reveal(tokens[i] ?? "")).toBe(value);
        });
        const fresh = loaded.store("PHONE", "new-value", 3);
        expect(tokens).not.toContain(fresh);
        expect(loaded.reveal(fresh)).toBe("new-value");
      }
    }
  });

  it("거부된 파일은 그대로 남는다 (plain / .kvault)", () => {
    const p = boundaryPayload();
    p.entries["<PHONE_1>"].label = "EMAIL";
    const path = join(tmp, "rejected.json");
    const original = JSON.stringify(p);
    writeFileSync(path, original, "utf8");
    expect(() => ReversibleVault.load(path)).toThrow(ValueError);
    expect(readFileSync(path, "utf8")).toBe(original);

    const vault = ReversibleVault.fromDict(boundaryPayload());
    const entry = vault.get("<PHONE_1>");
    if (entry) entry.label = "EMAIL";
    const kpath = join(tmp, "broken.kvault");
    saveEncrypted(vault, kpath, "test-only-password");
    const bytes = readFileSync(kpath);
    expect(() => loadEncrypted(kpath, "test-only-password")).toThrow(/token does not match/);
    expect(readFileSync(kpath).equals(bytes)).toBe(true);
  });

  it.each([0, -1, true, "1000", 1.5])("생성자 fingerprintIterations=%j 거부", (iterations) => {
    expect(
      () => new ReversibleVault({ fingerprintIterations: iterations as unknown as number }),
    ).toThrow(/fingerprint_iterations/);
  });

  it("store/tokenFor 입력 검증 (Python 메시지 동일, 실패 시 상태 불변)", () => {
    const v = new ReversibleVault({ salt: "s" });
    const cases: [() => unknown, string][] = [
      [() => v.store("", "x", 3), "Invalid vault label"],
      [() => v.store("A>", "x", 3), "Invalid vault label"],
      [() => v.store("A", 1 as unknown as string, 3), "Invalid vault original: expected a string"],
      [() => v.store("A", "x", 0), "Invalid vault risk_level"],
      [() => v.store("A", "x", 3, null, -2), "Invalid vault offset"],
      [() => v.store("A", "x", 3, 1 as unknown as string), "Invalid vault legal_basis"],
      [
        () => v.store("A", "x", 3, null, -1, [] as unknown as Record<string, unknown>),
        "Invalid vault extra: expected an object",
      ],
      [() => v.tokenFor("B\n", "x"), "Invalid vault label"],
    ];
    for (const [fn, msg] of cases) expect(fn).toThrow(new ValueError(msg));
    expect(v.size).toBe(0);
    expect(v.store("A", "x", 3, null, -1, null)).toBe("<A_1>");
  });

  it("save 는 원자적 교체 — 임시 파일을 남기지 않는다", () => {
    const dir = mkdtempSync(join(tmp, "atomic-"));
    const path = join(dir, "vault.json");
    writeFileSync(path, "old", "utf8");
    const v = new ReversibleVault({ salt: "abc" });
    v.store("EMAIL", "a@b.c", 3);
    v.save(path);
    expect(readFileSync(path, "utf8")).toBe(v.dumps());
    saveEncrypted(v, join(dir, "v.kvault"), "pw");
    expect(readdirSync(dir).sort()).toEqual(["v.kvault", "vault.json"]);
  });
});

describe("1.27 감사 실패 정책 (Python tests/unit/vault/test_audit.py)", () => {
  class FailingAudit {
    recordStore(): void {
      throw new Error("audit unavailable");
    }
    recordReveal(): void {
      throw new Error("audit unavailable");
    }
  }

  it("best_effort(기본) 는 기존 동작 유지", () => {
    const vault = new ReversibleVault({ salt: "x", auditLog: new FailingAudit() });
    const token = vault.store("RRN", "880101-1234568", RiskLevel.CRITICAL);
    expect(vault.reveal(token)).toBe("880101-1234568");
  });

  it("raise 는 기록되지 않은 store/reveal 을 막는다", () => {
    const vault = new ReversibleVault({
      salt: "x",
      auditLog: new FailingAudit(),
      auditFailurePolicy: "raise",
    });
    expect(() => vault.store("RRN", "880101-1234568", RiskLevel.CRITICAL)).toThrow(
      "audit unavailable",
    );
    expect(vault.size).toBe(0);
    expect(vault.get("<RRN_1>")).toBeUndefined();
    // 롤백 후 카운터도 원복 — 다음 store 가 <RRN_1> 을 다시 받는다
    vault.attachAudit(new AuditLog(join(tmp, "audit-rollback.jsonl"), "t"));
    expect(vault.store("RRN", "880101-1234568", RiskLevel.CRITICAL)).toBe("<RRN_1>");

    const v2 = new ReversibleVault({ salt: "x" });
    const token = v2.store("RRN", "880101-1234568", RiskLevel.CRITICAL);
    v2.attachAudit(new FailingAudit(), { failurePolicy: "raise" });
    expect(() => v2.reveal(token)).toThrow("audit unavailable");
  });

  it("raise 는 occurrence 추가도 되돌린다", () => {
    const vault = new ReversibleVault({ salt: "x" });
    const token = vault.store("RRN", "880101-1234568", RiskLevel.CRITICAL, null, 3);
    vault.attachAudit(new FailingAudit(), { failurePolicy: "raise" });
    expect(() => vault.store("RRN", "880101-1234568", RiskLevel.CRITICAL, null, 17)).toThrow(
      "audit unavailable",
    );
    expect(vault.get(token)?.occurrences).toEqual([3]);
  });

  it("미지 정책 거부 (생성자/attachAudit)", () => {
    expect(
      () => new ReversibleVault({ auditFailurePolicy: "ignore" as unknown as "raise" }),
    ).toThrow(
      new ValueError("Unknown audit_failure_policy: 'ignore'; expected one of best_effort, raise"),
    );
    const v = new ReversibleVault({ salt: "x" });
    expect(() =>
      v.attachAudit(new FailingAudit(), { failurePolicy: "nope" as unknown as "raise" }),
    ).toThrow(/audit_failure_policy/);
  });

  it("record_anonymize status 기록", () => {
    const path = join(tmp, "audit-status.jsonl");
    const log = new AuditLog(path, "tester", { now: () => "2024-01-01T00:00:00+00:00" });
    log.recordAnonymize(2, "STRICT", { status: "prepared" });
    const [entry] = replay(path);
    expect(entry?.extra).toEqual({ count: 2, mode: "STRICT", status: "prepared" });
    expect(readFileSync(path, "utf8")).toBe(
      '{"ts": "2024-01-01T00:00:00+00:00", "action": "anonymize", "token": null, "label": null, "actor": "tester", "context": null, "extra": {"count": 2, "mode": "STRICT", "status": "prepared"}}\n',
    );
  });
});
