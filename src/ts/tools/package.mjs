/** npm 배포용 타르볼 생성 + 검증 — 게시(`npm publish`)는 하지 않는다.
 *
 * 실행: cd src/ts && npm run package [-- --skip-checks] [-- --no-smoke]
 *
 *   1. 게이트: typecheck → lint → test (--skip-checks 로 생략)
 *   2. build (tsdown, dist 재생성)
 *   3. 저장소 루트 LICENSE 를 임시 동봉해 `npm pack`
 *   4. 타르볼 내용 검증: package.json 의 main/module/types/exports/bin 대상이 전부 있고
 *      dist 밖 소스가 새지 않았는지
 *   5. 스모크: 임시 프로젝트에 타르볼을 설치해 ESM/CJS/서브패스/bin 확인 (--no-smoke 로 생략,
 *      런타임 의존성 설치에 네트워크 필요)
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_DIR = resolve(fileURLToPath(new URL("..", import.meta.url)));
const REPO_ROOT = resolve(PKG_DIR, "../..");
const args = new Set(process.argv.slice(2));
const pkg = JSON.parse(readFileSync(join(PKG_DIR, "package.json"), "utf8"));

function run(cmd, cmdArgs, opts = {}) {
  return execFileSync(cmd, cmdArgs, {
    cwd: PKG_DIR,
    stdio: "inherit",
    shell: process.platform === "win32",
    ...opts,
  });
}

function step(title) {
  console.log(`\n==> ${title}`);
}

/** package.json 이 가리키는 배포 대상 파일 (타르볼 기준 상대 경로). */
function declaredTargets() {
  const targets = new Set();
  const add = (p) => typeof p === "string" && targets.add(p.replace(/^\.\//, ""));
  const walk = (node) => {
    if (typeof node === "string") add(node);
    else if (node && typeof node === "object") Object.values(node).forEach(walk);
  };
  [pkg.main, pkg.module, pkg.types].forEach(add);
  walk(pkg.exports);
  walk(pkg.bin);
  return [...targets];
}

function pack() {
  const license = join(PKG_DIR, "LICENSE");
  const stagedLicense = !existsSync(license);
  if (stagedLicense) copyFileSync(join(REPO_ROOT, "LICENSE"), license);
  try {
    const out = run("npm", ["pack", "--json"], { stdio: ["ignore", "pipe", "inherit"] });
    return JSON.parse(out.toString("utf8"))[0];
  } finally {
    if (stagedLicense) rmSync(license);
  }
}

function verifyContents(info) {
  const files = new Set(info.files.map((f) => f.path));
  const problems = [];
  for (const required of ["package.json", "README.md", "LICENSE", ...declaredTargets()]) {
    if (!files.has(required)) problems.push(`누락: ${required}`);
  }
  for (const path of files) {
    if (path.startsWith("src/") || path.startsWith("tests/") || path.startsWith("tools/")) {
      problems.push(`소스 유출: ${path}`);
    }
  }
  if (problems.length > 0) {
    throw new Error(`타르볼 내용 검증 실패\n  ${problems.join("\n  ")}`);
  }
}

function smoke(tarball) {
  const dir = mkdtempSync(join(tmpdir(), "ko-pii-pack-"));
  try {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "smoke", private: true }));
    run("npm", ["install", "--no-audit", "--no-fund", tarball], { cwd: dir });
    const expected = JSON.stringify(pkg.version);
    const esm = `
      import { Anonymizer, VERSION } from "ko-pii";
      import { SUPPORTED_EXTENSIONS } from "ko-pii/io";
      import { anonymizeRecords } from "ko-pii/tabular";
      if (VERSION !== ${expected}) throw new Error("VERSION " + VERSION);
      const text = new Anonymizer().process("신청인 880101-1234568").text;
      if (!text.includes("<RRN_1>")) throw new Error("anonymize: " + text);
      if (!SUPPORTED_EXTENSIONS || typeof anonymizeRecords !== "function") throw new Error("subpath");
    `;
    run("node", ["--input-type=module", "-e", esm], { cwd: dir, shell: false });
    const cjs = `if (require("ko-pii").VERSION !== ${expected}) throw new Error("cjs VERSION");`;
    run("node", ["-e", cjs], { cwd: dir, shell: false });
    const bin = run("npm", ["exec", "--no", "--", "ko-pii", "--version"], {
      cwd: dir,
      stdio: ["ignore", "pipe", "inherit"],
    }).toString("utf8");
    if (!bin.includes(pkg.version)) throw new Error(`bin --version: ${bin}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (!args.has("--skip-checks")) {
  for (const script of ["typecheck", "lint", "test"]) {
    step(`npm run ${script}`);
    run("npm", ["run", script]);
  }
}

step("npm run build");
run("npm", ["run", "build"]);

step("npm pack");
const info = pack();
verifyContents(info);
const tarball = join(PKG_DIR, info.filename);
console.log(
  `${info.filename}: ${info.entryCount} files, ${(info.size / 1024).toFixed(0)} KiB packed, ` +
    `${(info.unpackedSize / 1024).toFixed(0)} KiB unpacked`,
);

if (!args.has("--no-smoke")) {
  step("설치 스모크 (ESM / CJS / 서브패스 / bin)");
  smoke(tarball);
}

console.log(`\n완료: ${tarball}`);
console.log("게시는 직접 실행한다 (npm login 필요):");
console.log(`  npm publish ${info.filename} --access public`);
