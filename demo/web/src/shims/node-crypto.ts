/**
 * 브라우저용 `node:crypto` 대체 — ReversibleVault 가 import 하는 심볼만 둔다.
 *
 * 데모는 tokenize 전략만 쓰므로 실제로 호출되는 것은 salt 생성용 `randomBytes` 뿐이다.
 * 지문(hashed/fpe)용 동기 해시는 Web Crypto 에 없으므로 호출되면 바로 실패시킨다.
 */
export function randomBytes(n: number): { toString(encoding: "hex"): string } {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  return {
    toString: () => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""),
  };
}

function unsupported(name: string): never {
  throw new Error(`node:crypto.${name} 는 브라우저 데모에서 지원하지 않는다 (tokenize 전략 전용)`);
}

export const createHash = (): never => unsupported("createHash");
export const pbkdf2Sync = (): never => unsupported("pbkdf2Sync");
