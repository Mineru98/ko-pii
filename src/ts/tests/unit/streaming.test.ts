/**
 * PreForwardAnonymizer 단위 테스트.
 *
 * Python 원본: src/python/tests/unit/test_streaming.py (케이스 1:1) + TS 고유(코드 포인트 길이).
 */
import { describe, expect, it } from "vitest";
import { ValueError } from "../../src/core/errors.js";
import {
  Anonymizer,
  PreForwardAnonymizer,
  ProcessingMode,
  StreamBufferClosed,
  StreamBufferLimitExceeded,
} from "../../src/index.js";

describe("PreForwardAnonymizer", () => {
  it("cross-chunk identifier is anonymized before release", () => {
    const stream = new PreForwardAnonymizer(new Anonymizer(ProcessingMode.STRICT, "tokenize"));

    const first = stream.feed("주민번호 880101-");
    const second = stream.feed("1234568 입니다");

    expect(first.bufferedChars).toBe(12);
    expect(second.closed).toBe(false);
    const result = stream.finalize();
    expect(result.text).not.toContain("880101-1234568");
    expect(result.text).toContain("<RRN_1>");
    expect(stream.status.closed).toBe(true);
  });

  it("limit failure discards buffer and closes session", () => {
    const stream = new PreForwardAnonymizer(null, { maxChars: 5 });
    stream.feed("1234");

    expect(() => stream.feed("56")).toThrow(StreamBufferLimitExceeded);
    expect(stream.status.bufferedChars).toBe(0);
    expect(stream.status.failed).toBe(true);
    expect(stream.status.closed).toBe(true);
    expect(() => stream.finalize()).toThrow(StreamBufferClosed);
  });

  it("limit error message and hierarchy match Python", () => {
    const stream = new PreForwardAnonymizer(null, { maxChars: 5 });
    let caught: unknown;
    try {
      stream.feed("123456");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ValueError);
    expect((caught as Error).name).toBe("StreamBufferLimitExceeded");
    expect((caught as Error).message).toBe(
      "chunked input exceeds max_chars=5; no content was released",
    );
  });

  it("abort discards content and prevents reuse", () => {
    const stream = new PreForwardAnonymizer();
    stream.feed("010-1234-5678");
    const status = stream.abort();

    expect(status.bufferedChars).toBe(0);
    expect(status.closed).toBe(true);
    expect(status.failed).toBe(false);
    expect(() => stream.feed("more")).toThrow(StreamBufferClosed);
  });

  it.each([0, -1, true, 1.5])("maxChars must be a positive integer: %s", (value) => {
    expect(() => new PreForwardAnonymizer(null, { maxChars: value as number })).toThrow(ValueError);
  });

  it("feed rejects non-text without closing", () => {
    const stream = new PreForwardAnonymizer();
    expect(() => stream.feed(new Uint8Array([116]) as unknown as string)).toThrow(
      new TypeError("feed() expects str, got bytes"),
    );
    expect(stream.status.closed).toBe(false);
  });

  it("counts code points like Python len(), not UTF-16 units", () => {
    const stream = new PreForwardAnonymizer(null, { maxChars: 3 });
    const status = stream.feed("a😀b"); // Python len == 3, JS length == 4
    expect(status.bufferedChars).toBe(3);
    expect(status.remainingChars).toBe(0);
  });

  it("status is a frozen snapshot", () => {
    const stream = new PreForwardAnonymizer(null, { maxChars: 10 });
    const before = stream.feed("abc");
    stream.feed("de");
    expect(before.bufferedChars).toBe(3);
    expect(before.remainingChars).toBe(7);
    expect(Object.isFrozen(before)).toBe(true);
  });
});
