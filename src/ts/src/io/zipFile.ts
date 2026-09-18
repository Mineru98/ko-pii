/** ZIP 컨테이너 공용 헬퍼 — Python zipfile.ZipFile 의 TS 대응 (jszip 기반).
 *
 * Python ``zipfile.BadZipFile("File is not a zip file")`` 메시지를 재현한다.
 */
import { readFile } from "node:fs/promises";
import JSZip from "jszip";

export type ZipFile = JSZip;

/** ZIP 열기 — 실패 시 Python BadZipFile 과 동일한 메시지의 Error. */
export async function openZip(path: string): Promise<ZipFile> {
  const data = await readFile(path);
  try {
    return await JSZip.loadAsync(data);
  } catch {
    throw new Error("File is not a zip file");
  }
}

/** Python ``zf.namelist()`` 대응 — 엔트리 이름 목록 (폴더 엔트리 포함 가능). */
export function zipNames(zf: ZipFile): string[] {
  return Object.keys(zf.files);
}

/** Python ``zf.read(name)`` 대응 — 엔트리 바이트. */
export async function zipRead(zf: ZipFile, name: string): Promise<Uint8Array> {
  const entry = zf.files[name];
  if (entry === undefined) throw new Error(`There is no item named '${name}' in the archive`);
  return entry.async("uint8array");
}
