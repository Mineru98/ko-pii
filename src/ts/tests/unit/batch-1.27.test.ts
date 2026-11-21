/**
 * batch 1.27 — Python tests/unit/test_batch.py 신규 케이스 + test_safe_processing 배치 경계.
 * 기대값은 Python v1.27.0 실측.
 */
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import JSZip from "jszip";
import { describe, expect, it } from "vitest";
import { collectFiles, processPaths, pyRealpath } from "../../src/batch.js";
import { FileReadPolicy } from "../../src/io/bounded.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "ko-pii-batch127-"));
}

describe("process_paths 출력 디렉터리 경계 (test_batch.py)", () => {
  it("test_rerun_does_not_reprocess_nested_output", async () => {
    const root = tmp();
    writeFileSync(join(root, "doc.txt"), "연락처 010-1234-5678", "utf-8");
    const output = join(root, "out");
    for (let i = 0; i < 2; i++) {
      const result = await processPaths([root], output, { progress: false });
      expect(result.totalFiles).toBe(1);
      expect(result.succeeded).toBe(1);
    }
    expect(readFileSync(join(output, "doc.txt"), "utf-8")).toBe("연락처 <PHONE_1>");
  });

  it("test_rejects_input_directory_as_output", async () => {
    const root = tmp();
    writeFileSync(join(root, "doc.txt"), "original");
    await expect(processPaths([root], root, { progress: false })).rejects.toThrow(/differ/);
    expect(readFileSync(join(root, "doc.txt"), "utf-8")).toBe("original");
  });

  for (const kind of ["directory", "file", "mixed"] as const) {
    it(`test_rejects_output_ancestor_instead_of_dropping_input[${kind}]`, async () => {
      const root = tmp();
      const sourceDir = join(root, "job", "input");
      mkdirSync(sourceDir, { recursive: true });
      const source = join(sourceDir, "doc.txt");
      writeFileSync(source, "original");
      const inputs = kind === "directory" ? [sourceDir] : [source];
      if (kind === "mixed") {
        writeFileSync(join(root, "outside.txt"), "another document");
        inputs.push(join(root, "outside.txt"));
      }
      await expect(processPaths(inputs, join(root, "job"), { progress: false })).rejects.toThrow(
        /must not contain/,
      );
      expect(readFileSync(source, "utf-8")).toBe("original");
    });
  }

  it("출력 디렉터리가 입력 트리 안이면 건너뛰고 skipped 에 기록한다", async () => {
    const root = tmp();
    writeFileSync(join(root, "a.txt"), "연락처 010-1234-5678");
    mkdirSync(join(root, "out"));
    writeFileSync(join(root, "out", "old.txt"), "x");
    const summary = await processPaths([root], join(root, "out"), { progress: false });
    expect(summary.totalFiles).toBe(1);
    expect(summary.skipped).toEqual([
      { input_path: join(root, "out"), reason: "directory_not_traversed" },
    ]);
  });
});

describe("수집 오류 코드 (Python 실측)", () => {
  it("없는 파일·매칭 없는 glob·명시한 미지원 확장자·빈 디렉터리", async () => {
    const root = tmp();
    mkdirSync(join(root, "empty"));
    writeFileSync(join(root, "skip.bin"), "x");
    writeFileSync(join(root, "ok.txt"), "plain");
    const summary = await processPaths(
      [
        join(root, "nope.txt"),
        join(root, "*.zzz"),
        join(root, "skip.bin"),
        join(root, "empty"),
        join(root, "ok.txt"),
      ],
      join(root, "out"),
      { progress: false },
    );
    expect(summary.totalFiles).toBe(5);
    expect(summary.succeeded).toBe(1);
    expect(summary.results.slice(0, 4).map((r) => [r.error, r.errorCode])).toEqual([
      ["file_unavailable", "file_unavailable"],
      ["glob_no_matches", "glob_no_matches"],
      ["unsupported_extension", "unsupported_extension"],
      ["no_input_files", "no_input_files"],
    ]);
  });

  it("디렉터리 안 미지원 확장자는 실패가 아니라 skipped", async () => {
    const root = tmp();
    mkdirSync(join(root, "d"));
    writeFileSync(join(root, "d", "a.txt"), "x");
    writeFileSync(join(root, "d", "b.bin"), "y");
    const summary = await processPaths([join(root, "d")], join(root, "out"), { progress: false });
    expect(summary.failed).toBe(0);
    expect(summary.skipped).toEqual([
      { input_path: join(root, "d", "b.bin"), reason: "unsupported_extension" },
    ]);
  });

  it("allowEmpty 는 빈 디렉터리·glob 만 허용하고 명시 파일 누락은 여전히 실패", async () => {
    const root = tmp();
    mkdirSync(join(root, "empty"));
    const summary = await processPaths(
      [join(root, "empty"), join(root, "*.zzz"), join(root, "nope.txt")],
      join(root, "out"),
      { progress: false, allowEmpty: true },
    );
    expect(summary.results.map((r) => r.errorCode)).toEqual(["file_unavailable"]);
  });

  it("symlink 디렉터리는 따라가지 않는다", () => {
    const root = tmp();
    mkdirSync(join(root, "real"));
    writeFileSync(join(root, "real", "a.txt"), "x");
    mkdirSync(join(root, "in"));
    symlinkSync(join(root, "real"), join(root, "in", "link"));
    writeFileSync(join(root, "in", "b.txt"), "y");
    expect(collectFiles([join(root, "in")])).toEqual([join(root, "in", "b.txt")]);
  });

  it("workers·extraction timeout 은 양수여야 한다", async () => {
    const root = tmp();
    await expect(processPaths([root], join(root, "o"), { workers: 0 })).rejects.toThrow(
      "workers and extraction timeout must be positive",
    );
    await expect(
      processPaths([root], join(root, "o"), { extractionTimeout: Number.NaN }),
    ).rejects.toThrow("workers and extraction timeout must be positive");
  });

  it("알 수 없는 include 라벨은 호출 수준 ValueError", async () => {
    const root = tmp();
    await expect(processPaths([root], join(root, "o"), { include: ["NOPE"] })).rejects.toThrow(
      /unknown category label/,
    );
  });
});

describe("파일별 처리 결과", () => {
  it("read policy 위반은 BoundedReadError 코드·메시지 그대로", async () => {
    const root = tmp();
    writeFileSync(join(root, "a.txt"), "oversized");
    const summary = await processPaths([join(root, "a.txt")], join(root, "out"), {
      progress: false,
      readPolicy: new FileReadPolicy({ maxFileBytes: 2 }),
    });
    expect(summary.results[0]).toMatchObject({
      errorCode: "file_too_large",
      outputPath: null,
      combinedRisk: "UNKNOWN",
    });
  });

  it("test_batch_rejects_zip_expansion_without_output (compression_ratio_exceeded)", async () => {
    const root = tmp();
    const zip = new JSZip();
    zip.file("Contents/section0.xml", "A".repeat(20_000));
    const bytes = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
    writeFileSync(join(root, "input.hwpx"), bytes);
    const output = join(root, "out");
    const summary = await processPaths([join(root, "input.hwpx")], output, { progress: false });
    expect(summary.results[0]?.errorCode).toBe("compression_ratio_exceeded");
    expect(summary.failed).toBe(1);
  });

  it("PERSON 제외어가 파일별 Anonymizer 에 전달된다", async () => {
    const root = tmp();
    writeFileSync(join(root, "a.txt"), "성명: 김도구");
    const summary = await processPaths([join(root, "a.txt")], join(root, "out"), {
      progress: false,
      strategy: "redact",
      personExclusions: ["김도구"],
    });
    expect(summary.succeeded).toBe(1);
    expect(readFileSync(join(root, "out", "a.txt"), "utf-8")).toBe("성명: 김도구");
  });

  it("동명 출력은 해시 접미사, 대소문자만 다른 이름도 충돌로 본다", async () => {
    const root = tmp();
    mkdirSync(join(root, "x"));
    mkdirSync(join(root, "y"));
    writeFileSync(join(root, "x", "Doc.txt"), "a");
    writeFileSync(join(root, "y", "doc.txt"), "b");
    const summary = await processPaths([join(root, "x"), join(root, "y")], join(root, "out"), {
      progress: false,
    });
    const outs = summary.results.map((r) => r.outputPath ?? "");
    expect(outs[0]).toBe(join(root, "out", "Doc.txt"));
    expect(outs[1]).toMatch(/\/out\/doc_[0-9a-f]{8}\.txt$/);
  });

  it("protectedPaths 와 겹치는 출력은 쓰기 전에 거부 (하드링크 포함)", async () => {
    const root = tmp();
    mkdirSync(join(root, "in"));
    writeFileSync(join(root, "in", "terms.txt"), "x");
    mkdirSync(join(root, "out"));
    writeFileSync(join(root, "cfg.txt"), "keep");
    linkSync(join(root, "cfg.txt"), join(root, "out", "terms.txt"));
    await expect(
      processPaths([join(root, "in")], join(root, "out"), {
        progress: false,
        protectedPaths: [join(root, "cfg.txt")],
      }),
    ).rejects.toThrow("batch output conflicts with a protected configuration file");
    expect(readFileSync(join(root, "cfg.txt"), "utf-8")).toBe("keep");
  });
});

describe("pyRealpath (Python os.path.realpath, strict=False)", () => {
  it("존재하지 않는 꼬리와 symlink 를 Python 처럼 푼다", () => {
    const root = pyRealpath(tmp());
    mkdirSync(join(root, "real"));
    symlinkSync(join(root, "real"), join(root, "link"));
    expect(pyRealpath(join(root, "link", "missing", "x"))).toBe(join(root, "real", "missing", "x"));
    expect(pyRealpath(join(root, "link", "..", "real"))).toBe(join(root, "real"));
  });
});
