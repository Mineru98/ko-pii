/**
 * 비밀번호 프롬프트 — Python getpass.getpass("Vault password: ") 대응.
 *
 * - /dev/tty 를 열 수 있으면: raw 모드로 에코 off 입력 (Python termios 경로 대응)
 * - /dev/tty 가 없으면: getpass fallback 처럼 경고 후 stdin 에서 한 줄 읽는다.
 *   (Python 의 warnings 프레임 "Can not control echo on the terminal." 은
 *   런타임 세부 정보라 한 줄 경고로 단순화)
 */
import { closeSync, openSync, readSync } from "node:fs";
import { ReadStream, WriteStream } from "node:tty";

function readRawLineFromTty(ttyFd: number, prompt: string): string {
  // ReadStream 은 paused 상태로 유지 — termios(raw) 설정용으로만 쓴다.
  // resume() 하면 스트림이 비동기로 fd 를 소비해 동기 readSync 와 충돌한다.
  const input = new ReadStream(ttyFd);
  const output = new WriteStream(ttyFd);
  try {
    input.setRawMode(true);
    output.write(prompt);
    const bytes: number[] = [];
    const buf = Buffer.alloc(1);
    for (;;) {
      const n = readSync(ttyFd, buf, 0, 1, null);
      if (n === 0) break; // EOF
      const b = buf[0]!;
      if (b === 0x0a || b === 0x0d) break; // Enter
      if (b === 0x03) throw new Error("canceled"); // Ctrl-C
      if (b === 0x7f || b === 0x08) {
        bytes.pop(); // Backspace
        continue;
      }
      bytes.push(b);
    }
    output.write("\n");
    return Buffer.from(bytes).toString("utf8");
  } finally {
    try {
      input.setRawMode(false);
    } catch {
      // 스트림이 이미 닫힌 경우
    }
    input.destroy();
    output.destroy();
  }
}

function readLineFromStdin(prompt: string): string {
  process.stderr.write("Warning: Password input may be echoed.\n");
  process.stderr.write(prompt);
  const bytes: number[] = [];
  const buf = Buffer.alloc(1);
  for (;;) {
    const n = readSync(0, buf, 0, 1, null);
    if (n === 0) break;
    const b = buf[0]!;
    if (b === 0x0a) break;
    bytes.push(b);
  }
  // Python readline().rstrip("\n\r\n") 대응
  return Buffer.from(bytes)
    .toString("utf8")
    .replace(/[\r\n]+$/, "");
}

/** getpass.getpass(prompt) 대응. */
export function promptPassword(prompt: string): string {
  let ttyFd: number | null = null;
  try {
    ttyFd = openSync("/dev/tty", "r+");
  } catch {
    ttyFd = null;
  }
  if (ttyFd !== null) {
    try {
      return readRawLineFromTty(ttyFd, prompt);
    } finally {
      closeSync(ttyFd);
    }
  }
  return readLineFromStdin(prompt);
}
