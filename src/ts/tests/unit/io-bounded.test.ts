/**
 * Bounded 문서 추출 단위 테스트 — tests/unit/test_bounded_io.py 전체 포트.
 *
 * Python 원본: src/ko_pii/io_/bounded.py
 * 대응 구현: ts/src/io/bounded.ts
 *
 * 악성 픽스처(높은 압축비 zip, DTD ENTITY XML, 매직바이트 위조, CRC/CD 손상,
 * 암호화 플래그, 아카이브 symlink 등)는 jszip + Buffer 패치로 테스트 안에서
 * 직접 제작한다. Python 실측 대조(/tmp 픽스처 32종) 결과를 회귀 테스트로
 * 함께 포함한다.
 */
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import JSZip from "jszip";
import { afterEach, describe, expect, it } from "vitest";
import {
  BoundedReadError,
  FileReadPolicy,
  readTextBounded,
  ZlibError,
} from "../../src/io/bounded.js";

const TMP_DIRS: string[] = [];
function tmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "ko-pii-bounded-"));
  TMP_DIRS.push(dir);
  return dir;
}
afterEach(() => {
  // 디렉터리 정리는 OS tmpdir 에 위임 (심링크 등 특수 엔트리 유지) — 테스트 간 충돌 없음
  TMP_DIRS.length = 0;
});

/** jszip 으로 zip 바이트 생성 (Python zipfile.ZipFile 대응). */
async function makeZip(
  entries: Array<[name: string, content: string]>,
  compression: "DEFLATE" | "STORE" = "DEFLATE",
): Promise<Buffer> {
  const zip = new JSZip();
  for (const [name, content] of entries) {
    // createFolders: false — Python zipfile.writestr 처럼 부모 폴더 엔트리를
    // 만들지 않는다 (폴더 엔트리가 있으면 바이트 패치 대상 CD 엔트리가 밀린다)
    zip.file(name, content, { createFolders: false });
  }
  return zip.generateAsync({ type: "nodebuffer", compression });
}

/** 시그니처(PK\x03\x04 로컬 / PK\x01\x02 중앙) 위치 탐색. */
function findSig(buf: Buffer, sig: Buffer): number {
  const idx = buf.indexOf(sig);
  if (idx < 0) throw new Error(`signature ${sig.toString("hex")} not found`);
  return idx;
}

function writeTmp(dir: string, name: string, data: Buffer | string): string {
  const p = join(dir, name);
  writeFileSync(p, data);
  return p;
}

async function expectCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
    expect.fail(`expected BoundedReadError with code ${code}`);
  } catch (e) {
    expect(e).toBeInstanceOf(BoundedReadError);
    expect((e as BoundedReadError).code).toBe(code);
  }
}

// ---------------------------------------------------------------------------
// test_bounded_io.py 포트
// ---------------------------------------------------------------------------

describe("read_text_bounded (test_bounded_io.py 포트)", () => {
  it("test_reads_plain_text_with_content_free_provenance", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "input.txt", "민원 처리 문서");

    const result = await readTextBounded(source);

    expect(result.text).toBe("민원 처리 문서");
    expect(result.sizeBytes).toBe(readFileSync(source).length);
    expect(result.sha256).toHaveLength(64);
    expect(result.archiveMembers).toBe(0);
  });

  it("test_rejects_oversized_file_before_extraction", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "input.txt", "1234");

    await expectCode(
      () => readTextBounded(source, new FileReadPolicy({ maxFileBytes: 3 })),
      "file_too_large",
    );
  });

  it("test_rejects_symlink", async () => {
    const dir = tmp();
    const target = writeTmp(dir, "target.txt", "safe");
    const source = join(dir, "input.txt");
    symlinkSync(target, source);

    await expectCode(() => readTextBounded(source), "symlink_rejected");
  });

  it("test_explicit_policy_can_follow_symlink", async () => {
    const dir = tmp();
    const target = writeTmp(dir, "target.txt", "safe");
    const source = join(dir, "input.txt");
    symlinkSync(target, source);

    const result = await readTextBounded(source, new FileReadPolicy({ rejectSymlinks: false }));
    expect(result.text).toBe("safe");
  });

  it("test_rejects_binary_content_with_text_extension", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "input.txt", Buffer.from("text\x00binary", "latin1"));

    await expectCode(() => readTextBounded(source), "format_mismatch");
  });

  it("test_rejects_nul_after_signature_prefix", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "input.txt", Buffer.from("ordinary text prefix\x00binary tail"));

    await expectCode(() => readTextBounded(source), "format_mismatch");
  });

  it("test_reads_preflighted_hwpx", async () => {
    const dir = tmp();
    const source = writeTmp(
      dir,
      "input.hwpx",
      await makeZip([["Contents/section0.xml", "<p><t>안전한 문서</t></p>"]]),
    );

    const result = await readTextBounded(source);

    expect(result.text).toContain("안전한 문서");
    expect(result.archiveMembers).toBe(1);
    expect(result.declaredDecompressedBytes).toBeGreaterThan(0);
  });

  it("test_rejects_archive_path_traversal", async () => {
    const dir = tmp();
    const source = writeTmp(
      dir,
      "input.hwpx",
      await makeZip([
        ["Contents/section0.xml", "<p><t>본문</t></p>"],
        ["../escape.txt", "escape"],
      ]),
    );

    await expectCode(() => readTextBounded(source), "unsafe_archive_path");
  });

  it("test_rejects_excessive_compression_ratio", async () => {
    const dir = tmp();
    const source = writeTmp(
      dir,
      "input.hwpx",
      await makeZip([["Contents/section0.xml", "A".repeat(20_000)]]),
    );

    const policy = new FileReadPolicy({ maxCompressionRatio: 2.0 });
    await expectCode(() => readTextBounded(source, policy), "compression_ratio_exceeded");
  });

  it("test_rejects_archive_xml_dtd_before_parsing", async () => {
    const dir = tmp();
    const xml = "<!DOCTYPE p [<!ENTITY x 'expanded'>]><p><t>&x;</t></p>";
    const source = writeTmp(dir, "input.hwpx", await makeZip([["Contents/section0.xml", xml]]));

    await expectCode(() => readTextBounded(source), "xml_dtd_rejected");
  });

  it("test_legacy_parser_formats_require_explicit_opt_in", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "input.pdf", Buffer.from("%PDF-1.7\n", "latin1"));

    await expectCode(() => readTextBounded(source), "unsupported_extension");
  });
});

// ---------------------------------------------------------------------------
// Python 실측 대조 회귀 (픽스처 자체 제작)
// ---------------------------------------------------------------------------

describe("bounded 회귀 (Python 실측 32종 픽스처 대조 기반)", () => {
  it("zip 시그니처는 EOCD 존재만 본다 — CD 손상은 invalid_archive (is_zipfile 실측)", async () => {
    const dir = tmp();
    const zip = await makeZip([["Contents/section0.xml", "<p><t>x</t></p>"]]);
    // 중앙 디렉터리 시그니처 PK\x01\x02 훼손 — EOCD 는 정상
    const idx = findSig(zip, Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    zip[idx] = 0x58;
    zip[idx + 1] = 0x58;
    const source = writeTmp(dir, "badcd.hwpx", zip);

    // Python: is_zipfile True → 검증 단계 BadZipFile → invalid_archive
    await expectCode(() => readTextBounded(source), "invalid_archive");
  });

  it("멤버 CRC-32 불일치 → invalid_archive (ZipFile.read 실측)", async () => {
    const dir = tmp();
    const zip = await makeZip([
      ["Contents/section0.xml", "<p><t>hello world padding padding</t></p>"],
    ]);
    // 중앙 디렉터리 crc32 필드(오프셋 16) 변조 — deflate 스트림은 정상
    const idx = findSig(zip, Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    zip[idx + 16] ^= 0xff;
    const source = writeTmp(dir, "badcrc.hwpx", zip);

    await expectCode(() => readTextBounded(source), "invalid_archive");
  });

  it("손상된 deflate 스트림은 zlib 계열 오류로 탈출한다 (zlib.error 실측)", async () => {
    const dir = tmp();
    const zip = await makeZip([
      ["Contents/section0.xml", "<p><t>hello world padding padding</t></p>"],
    ]);
    // 로컬 헤더 뒤 deflate 데이터 일부 교환 — 스트림 자체가 손상
    const i3 = findSig(zip, Buffer.from([0x50, 0x4b, 0x03, 0x04]));
    const nameLen = zip.readUInt16LE(i3 + 26);
    const start = i3 + 30 + nameLen;
    [zip[start], zip[start + 1]] = [zip[start + 1]!, zip[start]!];
    const source = writeTmp(dir, "baddeflate.hwpx", zip);

    // Python 은 BoundedReadError 가 아니라 zlib.error 를 그대로 던진다 (except 절 밖)
    await expect(async () => readTextBounded(source)).rejects.toBeInstanceOf(ZlibError);
  });

  it("stored(무압축) 멤버 아카이브도 읽힌다", async () => {
    const dir = tmp();
    const source = writeTmp(
      dir,
      "stored.hwpx",
      await makeZip([["Contents/section0.xml", "<p><t>stored ok</t></p>"]], "STORE"),
    );

    const result = await readTextBounded(source);
    expect(result.text).toContain("stored ok");
  });

  it("중복 멤버 이름 → duplicate_archive_member", async () => {
    const dir = tmp();
    // jszip 은 중복 이름을 허용하지 않으므로 CD 엔트리를 직접 복제한다
    const zip = await makeZip([["Contents/section0.xml", "<p><t>a</t></p>"]]);
    const cd = findSig(zip, Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    const entry = zip.subarray(cd, eocd);
    const patched = Buffer.concat([zip.subarray(0, eocd), entry, zip.subarray(eocd)]);
    // EOCD 엔트리 수 1 → 2 (마지막 EOCD 기준)
    const e2 = patched.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    patched.writeUInt16LE(2, e2 + 10);
    const source = writeTmp(dir, "dup.hwpx", patched);

    await expectCode(() => readTextBounded(source), "duplicate_archive_member");
  });

  it("암호화 플래그(bit 0) 멤버 → encrypted_archive", async () => {
    const dir = tmp();
    const zip = await makeZip([["Contents/section0.xml", "<p><t>e</t></p>"]]);
    // 로컬 헤더(오프셋 6)와 중앙 디렉터리(오프셋 8)의 general purpose flag 에 bit 0 설정
    for (const [sig, off] of [
      [Buffer.from([0x50, 0x4b, 0x03, 0x04]), 6],
      [Buffer.from([0x50, 0x4b, 0x01, 0x02]), 8],
    ] as const) {
      const i = findSig(zip, sig);
      zip.writeUInt16LE(zip.readUInt16LE(i + off) | 1, i + off);
    }
    const source = writeTmp(dir, "enc.hwpx", zip);

    await expectCode(() => readTextBounded(source), "encrypted_archive");
  });

  it("아카이브 symlink 멤버(external_attr S_IFLNK) → archive_symlink", async () => {
    const dir = tmp();
    const zip = await makeZip([
      ["Contents/section0.xml", "<p><t>s</t></p>"],
      ["link.txt", "../target"],
    ]);
    // link.txt 중앙 디렉터리 엔트리의 external_attr 상위 16비트를 S_IFLNK(0o120000)로
    const sig = Buffer.from([0x50, 0x4b, 0x01, 0x02]);
    let idx = zip.indexOf(sig);
    while (idx >= 0) {
      const nameLen = zip.readUInt16LE(idx + 28);
      const name = zip.subarray(idx + 46, idx + 46 + nameLen).toString("latin1");
      if (name === "link.txt") {
        zip.writeUInt32LE((0o120777 << 16) >>> 0, idx + 38);
        break;
      }
      idx = zip.indexOf(sig, idx + 1);
    }
    const source = writeTmp(dir, "ziplink.hwpx", zip);

    await expectCode(() => readTextBounded(source), "archive_symlink");
  });

  it("미지원 압축 방식(Shrink) 멤버 → invalid_archive", async () => {
    const dir = tmp();
    const zip = await makeZip([["Contents/section0.xml", "<p><t>m</t></p>"]]);
    const idx = findSig(zip, Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    zip.writeUInt16LE(1, idx + 10); // compression method = 1 (Shrink)
    const source = writeTmp(dir, "shrink.hwpx", zip);

    await expectCode(() => readTextBounded(source), "invalid_archive");
  });

  it("docx 에 word/document.xml 누락 → format_mismatch", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "broken.docx", await makeZip([["word/other.xml", "<x/>"]]));
    await expectCode(() => readTextBounded(source), "format_mismatch");
  });

  it("xlsx 에 xl/workbook.xml 누락 → format_mismatch", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "broken.xlsx", await makeZip([["xl/other.xml", "<x/>"]]));
    await expectCode(() => readTextBounded(source), "format_mismatch");
  });

  it("hwpx 에 section XML 누락 → format_mismatch", async () => {
    const dir = tmp();
    const source = writeTmp(
      dir,
      "nosection.hwpx",
      await makeZip([["Contents/other.xml", "<p><t>x</t></p>"]]),
    );
    await expectCode(() => readTextBounded(source), "format_mismatch");
  });

  it("멤버 절대 경로 / 드라이브 경로 → unsafe_archive_path", async () => {
    const dir = tmp();
    const abs = writeTmp(
      dir,
      "abs.hwpx",
      await makeZip([
        ["Contents/section0.xml", "<p><t>x</t></p>"],
        ["/etc/passwd", "evil"],
      ]),
    );
    await expectCode(() => readTextBounded(abs), "unsafe_archive_path");

    const drive = writeTmp(
      dir,
      "drive.hwpx",
      await makeZip([
        ["Contents/section0.xml", "<p><t>x</t></p>"],
        ["C:/evil", "evil"],
      ]),
    );
    await expectCode(() => readTextBounded(drive), "unsafe_archive_path");
  });

  it("zip 이 아닌 .hwpx → format_mismatch", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "notzip.hwpx", Buffer.from("not a zip", "latin1"));
    await expectCode(() => readTextBounded(source), "format_mismatch");
  });

  it("디렉터리/부재 파일 — not_regular_file / file_unavailable", async () => {
    const dir = tmp();
    const subdir = join(dir, "dir.txt");
    mkdirSync(subdir);
    await expectCode(() => readTextBounded(subdir), "not_regular_file");
    await expectCode(() => readTextBounded(join(dir, "no_such.txt")), "file_unavailable");
  });

  it("bounded 텍스트는 dispatcher 정규화를 거친다 (줄바꿈 복원 실측)", async () => {
    const dir = tmp();
    const source = writeTmp(dir, "wrapped.txt", "880101-\n1234568 및 010-1234-\n5678");

    const result = await readTextBounded(source);
    expect(result.text).toBe("880101- 1234568 및 010-1234- 5678");
  });

  it("docx 본문 추출도 라우팅된다 (Python dispatcher 실측과 동일)", async () => {
    const dir = tmp();
    const source = writeTmp(
      dir,
      "simple.docx",
      await makeZip([
        [
          "word/document.xml",
          "<w:document><w:body><w:p><w:r><w:t>안녕하세요</w:t></w:r></w:p></w:body></w:document>",
        ],
      ]),
    );

    const result = await readTextBounded(source);
    expect(result.archiveMembers).toBe(1);
    expect(result.extension).toBe(".docx");
  });
});
