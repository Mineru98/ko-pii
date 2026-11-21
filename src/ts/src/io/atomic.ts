/**
 * Single-file replacement without truncating an existing destination.
 * Python 대응: ko_pii/io_/atomic.py.
 */
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { ValueError } from "../core/errors.js";

/**
 * Stage privately on the same filesystem, flush, then replace the file.
 *
 * This is one file's commit boundary, not a multi-file transaction or a lock
 * against concurrent writers. New files have owner-only permissions.
 */
export function writeBytesAtomic(target: string, content: Uint8Array): void {
  let isLink = false;
  try {
    isLink = fs.lstatSync(target).isSymbolicLink();
  } catch {
    isLink = false;
  }
  if (isLink) throw new ValueError("output must not be a symbolic link");
  const dir = path.dirname(target);
  const name = path.basename(target);
  let temporary = "";
  let fd = -1;
  // mkstemp 동등: O_EXCL + 0o600, 충돌 시 재시도.
  for (let attempt = 0; attempt < 100; attempt++) {
    const candidate = path.join(dir, `.${name}.${randomBytes(6).toString("hex")}.tmp`);
    try {
      fd = fs.openSync(candidate, "wx", 0o600);
      temporary = candidate;
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
  }
  if (fd < 0) throw new Error("could not create temporary file");
  try {
    try {
      let offset = 0;
      while (offset < content.length) {
        offset += fs.writeSync(fd, content, offset, content.length - offset);
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temporary, target);
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

export function writeTextAtomic(target: string, content: string): void {
  writeBytesAtomic(target, Buffer.from(content, "utf-8"));
}
