/**
 * Bounded pre-forward handling for chunked text — Python `ko_pii/streaming.py` 1:1 포트.
 *
 * PII can be split across arbitrary transport chunks. Releasing each chunk after
 * scanning it independently therefore cannot guarantee that a complete identifier
 * was inspected. `PreForwardAnonymizer` buffers a bounded message and releases
 * only the anonymized final result.
 */
import type { AnonymizationResult } from "./anonymizer.js";
import { Anonymizer } from "./anonymizer.js";
import { ValueError } from "./core/errors.js";
import { codePointLength, pyTypeName } from "./core/strUtils.js";

/** Raised when a finalized, aborted, or failed buffer is reused. (Python: RuntimeError 하위) */
export class StreamBufferClosed extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "StreamBufferClosed";
  }
}

/** Raised after a buffer exceeds its configured character budget. (Python: ValueError 하위) */
export class StreamBufferLimitExceeded extends ValueError {
  constructor(message?: string) {
    super(message);
    this.name = "StreamBufferLimitExceeded";
  }
}

/** Content-free state safe to expose in metrics or logs. (Python: frozen dataclass) */
export class StreamBufferStatus {
  constructor(
    readonly bufferedChars: number,
    readonly maxChars: number,
    readonly closed: boolean,
    readonly failed: boolean,
  ) {
    Object.freeze(this);
  }

  get remainingChars(): number {
    return Math.max(0, this.maxChars - this.bufferedChars);
  }
}

export interface PreForwardAnonymizerOptions {
  /** 버퍼 상한 — Python `len()` 과 같은 **코드 포인트** 수. 기본 2,000,000. */
  maxChars?: number;
}

/**
 * Accumulate chunks and anonymize once before any content is forwarded.
 *
 * `feed` never returns source text. Call `finalize` exactly once and use
 * only the returned `AnonymizationResult.text` downstream. This deliberately
 * favors a defensible privacy boundary over token-by-token latency.
 */
export class PreForwardAnonymizer {
  readonly anonymizer: Anonymizer;
  readonly maxChars: number;
  private chunks: string[] = [];
  private chars = 0;
  private closed = false;
  private failed = false;

  constructor(anonymizer?: Anonymizer | null, options: PreForwardAnonymizerOptions = {}) {
    const maxChars = options.maxChars ?? 2_000_000;
    if (!Number.isInteger(maxChars) || maxChars < 1) {
      throw new ValueError("max_chars must be a positive integer");
    }
    this.anonymizer = anonymizer ?? new Anonymizer();
    this.maxChars = maxChars;
  }

  get status(): StreamBufferStatus {
    return new StreamBufferStatus(this.chars, this.maxChars, this.closed, this.failed);
  }

  /** Buffer one text chunk without returning any source content. */
  feed(chunk: string): StreamBufferStatus {
    this.ensureOpen();
    if (typeof chunk !== "string") {
      throw new TypeError(`feed() expects str, got ${pyTypeName(chunk)}`);
    }
    const length = codePointLength(chunk);
    if (this.chars + length > this.maxChars) {
      this.chunks = [];
      this.chars = 0;
      this.failed = true;
      this.closed = true;
      throw new StreamBufferLimitExceeded(
        `chunked input exceeds max_chars=${this.maxChars}; no content was released`,
      );
    }
    this.chunks.push(chunk);
    this.chars += length;
    return this.status;
  }

  /** Close the buffer and return one anonymized result. */
  finalize(): AnonymizationResult {
    this.ensureOpen();
    const source = this.chunks.join("");
    this.chunks = [];
    this.chars = 0;
    this.closed = true;
    try {
      return this.anonymizer.process(source);
    } catch (e) {
      this.failed = true;
      throw e;
    }
  }

  /** Discard all buffered source text and close the session. */
  abort(): StreamBufferStatus {
    this.ensureOpen();
    this.chunks = [];
    this.chars = 0;
    this.closed = true;
    return this.status;
  }

  private ensureOpen(): void {
    if (this.closed) {
      throw new StreamBufferClosed("pre-forward buffer is already closed");
    }
  }
}
