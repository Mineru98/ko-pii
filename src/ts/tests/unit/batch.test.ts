/**
 * 배치/병렬 처리 단위 테스트 — tests/unit/test_batch.py 포트 + 확장.
 *
 * Python 원본: src/ko_pii/batch.py
 * 대응 구현: ts/src/batch.ts (+ ts/src/batchWorker.ts)
 *
 * Python 실측 대조(6파일 디렉터리 트리, workers 1/2, glob 재귀, 충돌 해시,
 * 출력 본문 토큰까지) 결과를 회귀 테스트로 함께 포함한다.
 * workers>=2 테스트는 실제 worker_threads 풀을 스폰한다 (tsx 로더 경유).
 */
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectFiles, outputPathFor, processPaths } from "../../src/batch.js";
import { ProcessingMode } from "../../src/core/modes.js";

const TMP_DIRS: string[] = [];
function tmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "ko-pii-batch-"));
  TMP_DIRS.push(dir);
  return dir;
}
afterEach(() => {
  TMP_DIRS.length = 0; // 정리는 OS tmpdir 에 위임
});

// ---------------------------------------------------------------------------
// test_batch.py 포트
// ---------------------------------------------------------------------------

describe("collect_files (test_batch.py 포트)", () => {
  it("test_single_file", () => {
    const dir = tmp();
    const p = join(dir, "a.txt");
    writeFileSync(p, "hello", "utf-8");
    expect(collectFiles([p])).toEqual([p]);
  });

  it("test_directory_recursive", () => {
    const dir = tmp();
    mkdirSync(join(dir, "sub"));
    writeFileSync(join(dir, "a.txt"), "a", "utf-8");
    writeFileSync(join(dir, "b.csv"), "h\nv", "utf-8");
    writeFileSync(join(dir, "sub", "c.txt"), "c", "utf-8");
    const files = collectFiles([dir], true);
    const names = files.map((f) => f.split("/").pop()!).sort();
    expect(names).toContain("a.txt");
    expect(names).toContain("b.csv");
    expect(names).toContain("c.txt");
  });

  it("test_extension_filter", () => {
    const dir = tmp();
    writeFileSync(join(dir, "ok.txt"), "x", "utf-8");
    writeFileSync(join(dir, "skip.bin"), "y", "utf-8");
    const files = collectFiles([dir]);
    expect(files.some((f) => f.endsWith("ok.txt"))).toBe(true);
    expect(files.some((f) => f.endsWith("skip.bin"))).toBe(false);
  });

  it("glob 패턴 수집 — 재귀 ** 은 디렉터리 경계를 넘고, 비재귀 시는 단일 세그먼트", () => {
    const dir = tmp();
    mkdirSync(join(dir, "sub"));
    writeFileSync(join(dir, "a.txt"), "a", "utf-8");
    writeFileSync(join(dir, "sub", "b.txt"), "b", "utf-8");
    writeFileSync(join(dir, "sub", "c.log"), "c", "utf-8");
    // Python glob: **/*.txt 는 sub/b.txt 를 잡는다 (recursive=True)
    expect(collectFiles([join(dir, "**", "*.txt")], true).sort()).toEqual(
      [join(dir, "a.txt"), join(dir, "sub", "b.txt")].sort(),
    );
    // recursive=False → ** 이 * 처럼 한 세그먼트만 채운다 (Python glob 계약).
    // dir/* 후보 중 디렉터리(sub)만 다음 세그먼트 진행 → sub/b.txt (Python 실측과 일치)
    expect(collectFiles([join(dir, "**", "*.txt")], false)).toEqual([join(dir, "sub", "b.txt")]);
  });
});

describe("process_paths (test_batch.py 포트)", () => {
  it("test_basic_batch", async () => {
    const dir = tmp();
    const inDir = join(dir, "in");
    mkdirSync(inDir);
    writeFileSync(join(inDir, "doc1.txt"), "신청인 880101-1234568", "utf-8");
    writeFileSync(join(inDir, "doc2.txt"), "연락처 010-1234-5678", "utf-8");
    const outDir = join(dir, "out");

    const summary = await processPaths([inDir], outDir, {
      mode: ProcessingMode.STRICT,
      strategy: "tokenize",
      workers: 1,
      progress: false,
    });
    expect(summary.totalFiles).toBe(2);
    expect(summary.succeeded).toBe(2);
    expect(summary.failed).toBe(0);

    const outFiles = readdirSync(outDir).sort();
    expect(outFiles).toContain("doc1.txt");
    expect(outFiles).toContain("doc2.txt");

    // 결과에서 원본 PII 가 사라졌는지
    const body = readFileSync(join(outDir, "doc1.txt"), "utf-8");
    expect(body).not.toContain("880101-1234568");
  });

  it("test_skip_unreadable", async () => {
    const dir = tmp();
    const inDir = join(dir, "in");
    mkdirSync(inDir);
    // 정상 파일
    writeFileSync(join(inDir, "ok.txt"), "plain", "utf-8");
    // 손상된 HWPX 흉내 (잘못된 ZIP)
    writeFileSync(join(inDir, "broken.hwpx"), Buffer.from("not a zip"));
    const outDir = join(dir, "out");

    const summary = await processPaths([inDir], outDir, { workers: 1, progress: false });
    // 1개 성공, 1개 실패
    expect(summary.succeeded).toBe(1);
    expect(summary.failed).toBe(1);
    // 실패 파일은 error 보고 + 출력 미생성
    const failed = summary.results.find((r) => r.error !== null);
    expect(failed?.inputPath).toContain("broken.hwpx");
    expect(failed?.outputPath).toBeNull();
    expect(readdirSync(outDir).sort()).toEqual(["ok.txt"]);
  });
});

// ---------------------------------------------------------------------------
// Python 실측 대조 회귀
// ---------------------------------------------------------------------------

describe("batch 회귀 (Python 실측 대조 기반)", () => {
  function makeTree(dir: string): { inDir: string; outDir: string } {
    const inDir = join(dir, "in");
    mkdirSync(join(inDir, "sub"), { recursive: true });
    writeFileSync(
      join(inDir, "doc1.txt"),
      "신청인 홍길동 (주민번호 880101-1234568) 이 민원을 제출했다. 연락처 010-1234-5678",
      "utf-8",
    );
    writeFileSync(
      join(inDir, "doc2.txt"),
      "김철수의 이메일은 kim@example.com 이고 전화 02-987-6543 이다.",
      "utf-8",
    );
    writeFileSync(
      join(inDir, "sub", "doc1.txt"),
      "이름 박영희, 주민등록번호 900101-2345678, 사건번호 2023가합12345",
      "utf-8",
    );
    writeFileSync(join(inDir, "memo.md"), "메모: 예산 5천만원, 다음 회의는 목요일이다.", "utf-8");
    return { inDir, outDir: join(dir, "out") };
  }

  it("워커풀(workers=2) 도 순차 실행과 동일한 요약·출력을 낸다", async () => {
    const dir = tmp();
    const { inDir } = makeTree(dir);
    const out1 = join(dir, "out1");
    const out2 = join(dir, "out2");

    const seq = await processPaths([inDir], out1, { workers: 1, progress: false });
    const par = await processPaths([inDir], out2, { workers: 2, progress: false });

    expect(par.totalFiles).toBe(seq.totalFiles);
    expect(par.succeeded).toBe(seq.succeeded);
    expect(par.failed).toBe(seq.failed);
    expect(par.totalDetections).toBe(seq.totalDetections);
    expect(par.totalBlocked).toBe(seq.totalBlocked);
    expect(par.totalReview).toBe(seq.totalReview);
    // 결과는 완료 순서가 아닌 입력 경로로 비교 — basename 키는 in/doc1.txt 와
    // in/sub/doc1.txt 가 충돌해 워커 완료 순서에 따라 플레이키했다.
    const byInput = (rs: typeof seq.results) => new Map(rs.map((r) => [r.inputPath, r]));
    const a = byInput(seq.results);
    const b = byInput(par.results);
    expect(b.size).toBe(a.size);
    for (const [key, ra] of a) {
      const rb = b.get(key);
      expect(rb).toBeDefined();
      expect(rb!.detections).toBe(ra.detections);
      expect(rb!.combinedRisk).toBe(ra.combinedRisk);
      expect(rb!.blocked).toBe(ra.blocked);
      expect(rb!.review).toBe(ra.review);
      expect((rb!.error ?? null) === null).toBe((ra.error ?? null) === null);
    }
    // 출력 파일 집합 동일
    expect(readdirSync(out2).sort()).toEqual(readdirSync(out1).sort());
  });

  it("동명 파일 충돌 시 입력경로 sha1 접미사로 유일성 보장 (#12 실측)", async () => {
    const dir = tmp();
    const { inDir, outDir } = makeTree(dir);
    await processPaths([inDir], outDir, { workers: 1, progress: false });

    const names = readdirSync(outDir).sort();
    // doc1.txt (루트) 와 sub/doc1.txt 가 충돌 → 첫 파일은 doc1.txt 유지,
    // 충돌 파일만 <stem>_<sha1-8>.txt
    expect(names).toContain("doc1.txt");
    const hashed = names.filter((n) => /^doc1_[0-9a-f]{8}\.txt$/.test(n));
    expect(hashed).toHaveLength(1);
    // outputPathFor 기본 형태
    expect(outputPathFor(join(inDir, "doc1.txt"), outDir)).toBe(join(outDir, "doc1.txt"));
  });

  it("sharedVault + workers=1 — 문서 간 토큰 일관성 (docstring 의도)", async () => {
    const dir = tmp();
    const inDir = join(dir, "in");
    mkdirSync(inDir);
    writeFileSync(join(inDir, "a.txt"), "신청인 홍길동", "utf-8");
    writeFileSync(join(inDir, "b.txt"), "신청인 홍길동", "utf-8");
    const outDir = join(dir, "out");

    const summary = await processPaths([inDir], outDir, {
      workers: 1,
      progress: false,
      sharedVault: true,
    });
    const bodyA = readFileSync(join(outDir, "a.txt"), "utf-8");
    const tokA = /<PERSON_\d+>/.exec(bodyA)?.[0];
    expect(tokA).toBeDefined();
    const bodyB = readFileSync(join(outDir, "b.txt"), "utf-8");
    // 같은 원본 → 같은 토큰 (기본 모드에서는 파일별 vault 라 어긋난다)
    expect(bodyB).toContain(tokA!);
    expect(summary.vault).not.toBeNull();
    expect(summary.vault!.reveal(tokA!)).toBe("홍길동");
  });

  it("sharedVault + workers=2 — 워커 vault 를 수집해 메인에서 병합한다", async () => {
    const dir = tmp();
    const inDir = join(dir, "in");
    mkdirSync(inDir);
    writeFileSync(join(inDir, "a.txt"), "신청인 홍길동", "utf-8");
    writeFileSync(join(inDir, "b.txt"), "피해자 김민수", "utf-8");
    const outDir = join(dir, "out");

    const summary = await processPaths([inDir], outDir, {
      workers: 2,
      progress: false,
      sharedVault: true,
    });
    expect(summary.vault).not.toBeNull();
    // 병합 vault 는 두 워커의 원본을 모두 보존한다
    const originals = summary
      .vault!.entries()
      .map((e) => e.original)
      .sort();
    expect(originals).toEqual(["김민수", "홍길동"]);
    // 병합 후 카운터가 이어져 새 store 가 충돌하지 않는다
    const nextToken = summary.vault!.store("PERSON", "박철수", 4);
    expect(nextToken).toBe("<PERSON_3>");
  });

  it("sharedVault 없는 기본 동작은 Python 과 동일 — 요약에 vault 없음", async () => {
    const dir = tmp();
    const inDir = join(dir, "in");
    mkdirSync(inDir);
    writeFileSync(join(inDir, "a.txt"), "홍길동", "utf-8");
    const summary = await processPaths([inDir], join(dir, "out"), { workers: 1, progress: false });
    expect(summary.vault).toBeNull();
  });

  it("exclude 필터 — 지정 라벨 검출기를 끄면 평문이 유지된다", async () => {
    const dir = tmp();
    const inDir = join(dir, "in");
    mkdirSync(inDir);
    writeFileSync(join(inDir, "mail.txt"), "kim@example.com", "utf-8");
    const outDir = join(dir, "out");
    const summary = await processPaths([inDir], outDir, {
      workers: 1,
      progress: false,
      exclude: ["EMAIL"],
    });
    expect(summary.totalDetections).toBe(0);
    expect(readFileSync(join(outDir, "mail.txt"), "utf-8")).toContain("kim@example.com");
  });

  it("잘못된 모드 문자열 — Python 처럼 호출 수준에서 즉시 실패", async () => {
    const dir = tmp();
    await expect(
      processPaths([join(dir, "x.txt")], join(dir, "out"), { mode: "BOGUS", progress: false }),
    ).rejects.toThrowError("'BOGUS' is not a valid ProcessingMode");
  });
});
