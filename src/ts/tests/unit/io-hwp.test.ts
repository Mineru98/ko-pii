/**
 * HWP 5.x 바이너리 파서 단위 테스트 + 골드 마스터 벡터 대조.
 *
 * Python 원본: src/ko_pii/io_/hwp.py
 * 골드 벡터: spec/goldmaster/io.json (hwp_primitives, fixtures(sample.hwp))
 *   - extended_size_stream: 0xFFF 확장 사이즈 레코드 스트림 hex → records[]
 *   - decode_cases: PARA_TEXT body hex → 디코드 문자열
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { decodeParaText, isCompressed, iterRecords, readText } from "../../src/io/hwp.js";

const ROOT = join(import.meta.dirname, "..", "..", "..", "..");
const IO_GOLD = JSON.parse(readFileSync(join(ROOT, "spec", "goldmaster", "io.json"), "utf8")) as {
  hwp_primitives: {
    extended_size_stream: { hex: string; records: { tag: number; level: number; size: number }[] };
    decode_cases: { body_hex: string; text: string }[];
  };
  fixtures: { file: string; read_text: string }[];
};

describe("decodeParaText", () => {
  it("골드 decode_cases 와 일치", () => {
    for (const c of IO_GOLD.hwp_primitives.decode_cases) {
      expect(decodeParaText(Buffer.from(c.body_hex, "hex"))).toBe(c.text);
    }
  });

  it("한글 UTF-16LE 디코드", () => {
    expect(decodeParaText(Buffer.from("가나다", "utf16le"))).toBe("가나다");
  });

  it("제어문자 0x00~0x1F 전수 — Python _decode_para_text 와 동일 테이블", () => {
    // 1워드 코드 + (WithData 면 14바이트 payload) + 'A'; 기대값은 Python 실측과 동일
    const withData = new Set([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    ]);
    let body = Buffer.alloc(0);
    let expected = "";
    for (let cp = 0; cp < 32; cp++) {
      const word = Buffer.alloc(2);
      word.writeUInt16LE(cp);
      body = Buffer.concat([body, word]);
      if (withData.has(cp)) {
        body = Buffer.concat([body, Buffer.alloc(14)]);
        if (cp === 9) {
          expected += "\t";
        }
      } else {
        // 데이터 없는 char control — 코드 1워드만 소비 (골드 0d004100 → "\nA" 참조:
        // 0x0D 도 자기 뒤 텍스트는 그대로 디코드된다)
        body = Buffer.concat([body, Buffer.from([0x41, 0x00])]); // 'A'
        if (cp === 13) {
          expected += "\n";
        }
        expected += "A";
      }
    }
    expect(decodeParaText(body)).toBe(expected);
  });

  it("홀수 길이 본문 — 마지막 1바이트는 버림", () => {
    expect(decodeParaText(Buffer.from([0x41, 0x00, 0x42]))).toBe("A");
  });

  it("lone surrogate 도 Python chr 과 동일하게 보존", () => {
    const body = Buffer.from([0x00, 0xd8]);
    expect(decodeParaText(body)).toBe("\ud800");
  });
});

describe("iterRecords", () => {
  it("골드 extended_size_stream (0xFFF 확장 사이즈) 와 일치", () => {
    const { hex, records } = IO_GOLD.hwp_primitives.extended_size_stream;
    const got = [...iterRecords(Buffer.from(hex, "hex"))].map(([tag, level, body]) => ({
      tag,
      level,
      size: body.length,
    }));
    expect(got).toEqual(records);
  });

  it("level 값 보존 + 연속 복수 레코드", () => {
    const stream = Buffer.concat([
      header(0x42, 3, 2),
      Buffer.from("AB"),
      header(0x43, 1, 4),
      Buffer.from("CDEF"),
    ]);
    expect([...iterRecords(stream)]).toEqual([
      [0x42, 3, Buffer.from("AB")],
      [0x43, 1, Buffer.from("CDEF")],
    ]);
  });

  it("확장 사이즈 레코드 뒤 일반 레코드가 이어짐", () => {
    const stream = Buffer.concat([
      header(0x43, 0, 0xfff),
      size32(3),
      Buffer.from("XYZ"),
      header(0x42, 2, 1),
      Buffer.from("Q"),
    ]);
    expect([...iterRecords(stream)].map(([, tag, body]) => [tag, body.toString()])).toEqual([
      [0, "XYZ"],
      [2, "Q"],
    ]);
  });

  it("잘린 스트림 — i+size > n 이면 break", () => {
    expect([...iterRecords(Buffer.concat([header(0x43, 0, 5), Buffer.from("ABC")]))]).toEqual([]);
  });

  it("확장 사이즈 4바이트가 잘린 스트림 — break", () => {
    expect([...iterRecords(header(0x43, 0, 0xfff))]).toEqual([]);
    expect([
      ...iterRecords(Buffer.concat([header(0x43, 0, 0xfff), Buffer.from([5, 0, 0])])),
    ]).toEqual([]);
  });

  it("4바이트 미만 스트림 — 레코드 없음", () => {
    expect([...iterRecords(Buffer.alloc(0))]).toEqual([]);
    expect([...iterRecords(Buffer.from([1, 2, 3]))]).toEqual([]);
  });
});

describe("isCompressed", () => {
  it("FileHeader byte36 bit0 = 압축 플래그", () => {
    expect(isCompressed(Buffer.alloc(0))).toBe(true); // 길이 < 37 → 안전 기본값
    expect(isCompressed(Buffer.alloc(36))).toBe(true);
    const h = (b: number) => Buffer.concat([Buffer.alloc(36), Buffer.from([b])]);
    expect(isCompressed(h(0x01))).toBe(true);
    expect(isCompressed(h(0x00))).toBe(false);
    expect(isCompressed(h(0x02))).toBe(false);
    expect(isCompressed(h(0x03))).toBe(true);
  });
});

describe("readText (end-to-end)", () => {
  it("sample.hwp === io.json 골드 read_text (tab/제어문자/문단구분 포함)", () => {
    const gold = IO_GOLD.fixtures.find((f) => f.file === "sample.hwp");
    if (!gold) {
      throw new Error("goldmaster sample.hwp fixture missing");
    }
    expect(readText(join(ROOT, "spec", "fixtures", "io", "sample.hwp"))).toBe(gold.read_text);
  });

  it("존재하지 않는 파일 — throw", () => {
    expect(() => readText(join(ROOT, "spec", "fixtures", "io", "no_such.hwp"))).toThrow();
  });

  it("OLE 이 아닌 파일(sample.txt) — throw (Python: NotOleFileError)", () => {
    expect(() => readText(join(ROOT, "spec", "fixtures", "io", "sample.txt"))).toThrow();
  });
});

/** 레코드 헤더 4바이트 LE: tag 10bit | level 10bit | size 12bit */
function header(tag: number, level: number, size: number): Buffer {
  const b = Buffer.alloc(4);
  // 0xFFF<<20 은 int32 부호를 넘으므로 unsigned 로 정규화
  b.writeUInt32LE((((size & 0xfff) << 20) | ((level & 0x3ff) << 10) | (tag & 0x3ff)) >>> 0);
  return b;
}

function size32(size: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(size);
  return b;
}
