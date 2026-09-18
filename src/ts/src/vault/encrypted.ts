/**
 * Vault 암호화 — 개인정보보호법 제29조 (안전조치의무) 직접 대응.
 * Python `ko_pii.vault.encrypted` 1:1 포트 (외부 패키지 없이 `node:crypto` 사용).
 *
 * 알고리즘:
 * - AES-256-GCM (NIST SP 800-38D, 안전·검증된 AEAD)
 * - 키 유도: PBKDF2-HMAC-SHA256 (RFC 8018), 480,000 iterations (OWASP 2023 권장)
 * - Salt: 16 bytes (per-vault), Nonce: 12 bytes (per-encryption)
 * - 평문 JSON 을 *통째로* 암호화 → 단일 파일로 저장
 *
 * 파일 포맷 (.kvault):
 *   magic(8) + kdf_salt(16) + nonce(12) + ciphertext(...) + tag(16)
 *   magic = b"KPIIVT\x01\x00"
 *
 * Python `cryptography` AESGCM 관례 호환: 암호화 출력은 ciphertext||tag 결합 형태이며,
 * Node 는 tag 를 `getAuthTag()` 로 별도 반환하므로 파일에 쓰기 전 뒤에 결합한다.
 * AAD = magic (포맷 무결성 바인딩).
 *
 * 복호화 실패 (잘못된 비밀번호) 시 Error 발생 (Python ValueError 대응).
 */
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { closeSync, openSync, readFileSync, readSync, writeFileSync } from "node:fs";
import { ReversibleVault } from "./reversible.js";

/** 8 bytes (대문자 KPIIVT + version 1.0). */
export const MAGIC = Buffer.from([0x4b, 0x50, 0x49, 0x49, 0x56, 0x54, 0x01, 0x00]);
export const KDF_ITERATIONS = 480_000;
export const KDF_SALT_LEN = 16;
export const NONCE_LEN = 12;
/** AES-256. */
export const KEY_LEN = 32;
const TAG_LEN = 16;

/** PBKDF2-HMAC-SHA256 키 유도 — Python `_derive_key` 와 바이트 동일 (kdf.json 골드 벡터 대응). */
export function deriveKey(password: string, salt: Buffer): Buffer {
  return pbkdf2Sync(Buffer.from(password, "utf8"), salt, KDF_ITERATIONS, KEY_LEN, "sha256");
}

/** AES-256-GCM 암호화 — 반환값은 Python AESGCM 관례(ciphertext||tag). */
function encryptRaw(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_LEN });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

/**
 * @internal 테스트·골드 벡터 재현용 — 고정 kdf salt/nonce 로 .kvault blob 전체를 생성.
 * (saveEncrypted 는 랜덤 salt/nonce 를 쓴다. 결정론 테스트는 이 헬퍼를 사용.)
 * 반환: MAGIC + kdfSalt + nonce + ciphertext + tag
 */
export function encryptWithFixedSaltNonce(
  plaintext: Buffer | string,
  password: string,
  kdfSalt: Buffer,
  nonce: Buffer,
): Buffer {
  if (!password) throw new Error("password must be non-empty");
  const key = deriveKey(password, kdfSalt);
  const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const body = encryptRaw(key, nonce, pt, MAGIC);
  return Buffer.concat([MAGIC, kdfSalt, nonce, body]);
}

/** blob 복호화 (MAGIC 검사 + AAD=magic + 마지막 16바이트 auth tag 검증). 실패 시 Error. */
export function decryptBlob(blob: Buffer, password: string): Buffer {
  const minLen = MAGIC.length + KDF_SALT_LEN + NONCE_LEN + TAG_LEN;
  if (blob.length < minLen) throw new Error("vault file truncated or invalid");
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("not a ko-pii encrypted vault (magic mismatch)");
  }
  const salt = blob.subarray(MAGIC.length, MAGIC.length + KDF_SALT_LEN);
  const nonceStart = MAGIC.length + KDF_SALT_LEN;
  const nonce = blob.subarray(nonceStart, nonceStart + NONCE_LEN);
  const ctAndTag = blob.subarray(nonceStart + NONCE_LEN);
  const ciphertext = ctAndTag.subarray(0, ctAndTag.length - TAG_LEN);
  const tag = ctAndTag.subarray(ctAndTag.length - TAG_LEN);
  const key = deriveKey(password, salt);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_LEN });
  decipher.setAAD(MAGIC);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`decryption failed (wrong password or corruption): ${msg}`);
  }
}

/** Encrypt the vault and write to *path*.
 *
 * `password` is the user-supplied passphrase. Keep it out of source code —
 * use environment variables or a key management service in production.
 */
export function saveEncrypted(vault: ReversibleVault, path: string, password: string): void {
  if (!password) throw new Error("password must be non-empty");
  const salt = randomBytes(KDF_SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const key = deriveKey(password, salt);
  const plaintext = Buffer.from(vault.dumps(null), "utf8");
  // AAD = magic + version → integrity binds to the file format
  const ciphertextWithTag = encryptRaw(key, nonce, plaintext, MAGIC);
  writeFileSync(path, Buffer.concat([MAGIC, salt, nonce, ciphertextWithTag]));
}

/** Decrypt and return a vault. Raises Error on wrong password.
 * `source` 는 파일 경로(Python `load_encrypted` 호환) 또는 blob Buffer. */
export function loadEncrypted(source: string | Buffer, password: string): ReversibleVault {
  const blob = typeof source === "string" ? readFileSync(source) : source;
  const plaintext = decryptBlob(blob, password);
  return ReversibleVault.loads(plaintext.toString("utf8"));
}

/** 파일이 암호화된 vault 인지 확인 (magic byte 검사). */
export function isEncryptedFile(path: string): boolean {
  try {
    const fd = openSync(path, "r");
    try {
      const head = Buffer.alloc(MAGIC.length);
      const n = readSync(fd, head, 0, MAGIC.length, 0);
      return head.subarray(0, n).equals(MAGIC);
    } finally {
      closeSync(fd);
    }
  } catch {
    return false;
  }
}
