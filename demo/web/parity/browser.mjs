/**
 * 브라우저 번들(shim + vite alias 포함) 안에서 패리티 대조 — `npm run parity` 는 Node 에서 돌아
 * node:crypto/node:fs 가 진짜 builtin 으로 풀리므로 shim 경로는 이 러너만 검증한다.
 *
 * Usage: npm run parity:browser   (CHROME 환경변수로 Chrome/Chromium 실행 파일 지정 가능)
 */
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const vite = fileURLToPath(new URL("../../../src/ts/node_modules/.bin/vite", import.meta.url));
const chrome = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = "5998"; // dev(5173) 와 겹치지 않게

execFileSync(vite, ["build", "--config", "vite.config.mjs", "--logLevel", "warn"], { cwd: root, stdio: "inherit" });
const server = spawn(vite, ["preview", "--config", "vite.config.mjs", "--port", PORT, "--strictPort"], { cwd: root, stdio: "ignore" });
try {
  const url = `http://localhost:${PORT}/parity.html`;
  for (let i = 0; ; i++) {
    try { if ((await fetch(url)).ok) break; } catch {}
    if (i > 40) throw new Error("preview 서버가 뜨지 않았다");
    await new Promise((r) => setTimeout(r, 250));
  }
  const dom = execFileSync(chrome, ["--headless=new", "--disable-gpu", "--virtual-time-budget=30000", "--dump-dom", url],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 << 20 });
  const result = /<pre id="result"[^>]*>([\s\S]*?)<\/pre>/.exec(dom)?.[0] ?? "(#result 없음)";
  console.log(result.replace(/<[^>]+>/g, "").slice(0, 2000));
  // PASS 를 명시적으로 단언한다 — "FAIL 이 아니면 통과" 로 두면 멈춘 페이지가 통과한다.
  process.exitCode = result.includes('data-status="PASS"') ? 0 : 1;
} finally {
  server.kill(); // 이 러너가 띄운 PID 만 종료한다.
}
