/** 브라우저용 `node:fs` 대체 — vault 파일 저장/로드는 데모에서 쓰지 않는다. */
function unsupported(name: string): never {
  throw new Error(`node:fs.${name} 는 브라우저 데모에서 지원하지 않는다`);
}

export const readFileSync = (): never => unsupported("readFileSync");
export const writeFileSync = (): never => unsupported("writeFileSync");
