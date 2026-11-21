/**
 * 오프라인 K-PII-Bench JSONL 어댑터 — 데이터셋 다운로드·라벨 추론 없음.
 * Python ``ko_pii.eval.external`` 대응.
 *
 * 오프셋은 TS 판 정책대로 UTF-16 코드 유닛 (PORTING.md).
 */
import { createHash } from "node:crypto";
import { ValueError } from "../core/errors.js";
import { loadsJson } from "../structured.js";
import {
  LabeledDocument,
  MAX_DATASET_BYTES,
  MAX_DOCUMENT_CHARS,
  MAX_DOCUMENTS,
  MAX_SPANS,
  readJsonFile,
  sliceValue,
} from "./domain.js";
import { cpLen, pyStrip } from "./pyCompat.js";
import type { GoldSpan } from "./types.js";

/** 일대일 ko-pii 의미가 없는 넓은 분류는 명시적으로 매핑하지 않는다 (null). */
export const K_PII_LABELS: Readonly<Record<string, string | null>> = Object.freeze({
  PERSON: "PERSON",
  EMAIL_ADDRESS: "EMAIL",
  KR_PHONE_NUMBER: "PHONE",
  KR_RRN: "RRN",
  KR_BANK_ACCOUNT: "ACCOUNT",
  KR_DRIVER_LICENSE: "DRIVER_LICENSE",
  KR_PASSPORT: "PASSPORT",
  KR_NHIS: "MEDICAL_INSURANCE",
  KR_VEHICLE_PLATE: "VEHICLE",
  KR_LOCATION: "ADDRESS",
  CREDIT_CARD: "CARD",
  IP_ADDRESS: "IP",
  URL: "URL",
  DATE_OF_BIRTH: "DT_BIRTH",
  USERNAME: null,
  ORGANIZATION: null,
  NRP: null,
  PERSONAL_ATTRIBUTE: null,
});

/**
 * 한도 있는 로컬 부분집합을 검증 — 오프셋은 선택 필드 ``surface`` 와 일치해야 한다.
 *
 * 업스트림 BIO 채점기가 아니라 ko-pii strict 문자 span 채점기를 쓴다.
 * KR_LOCATION -> ADDRESS 는 선언된 정렬이지 의미 동등성이 아니다.
 */
export function loadKPiiBench(file: string): [LabeledDocument[], Record<string, unknown>] {
  return loadKPiiBenchText(readJsonFile(file, MAX_DATASET_BYTES));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInt(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

function bump(counter: Record<string, number>, key: string): void {
  counter[key] = (counter[key] ?? 0) + 1;
}

/** @internal Python ``_load_k_pii_bench_text``. */
export function loadKPiiBenchText(raw: string): [LabeledDocument[], Record<string, unknown>] {
  const documents: LabeledDocument[] = [];
  const seenIds = new Set<string>();
  const mapped: Record<string, number> = {};
  const unmapped: Record<string, number> = {};
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (!pyStrip(line)) continue;
    try {
      const item = loadsJson(line);
      if (!isRecord(item)) throw new ValueError();
      const docId = item.doc_id;
      const text = item.text;
      const entities = item.entities;
      if (typeof docId !== "string" || !docId || cpLen(docId) > 128 || seenIds.has(docId)) {
        throw new ValueError();
      }
      if (typeof text !== "string" || cpLen(text) > MAX_DOCUMENT_CHARS) throw new ValueError();
      if (!Array.isArray(entities) || entities.length > MAX_SPANS) throw new ValueError();
      const spans: GoldSpan[] = [];
      const seenSpans = new Set<string>();
      for (const entity of entities as unknown[]) {
        if (!isRecord(entity)) throw new ValueError();
        const { type: label, start, end } = entity;
        if (typeof label !== "string" || !Object.hasOwn(K_PII_LABELS, label)) {
          throw new ValueError();
        }
        if (!isInt(start) || !isInt(end) || !(start >= 0 && start < end && end <= text.length)) {
          throw new ValueError();
        }
        if (Object.hasOwn(entity, "surface") && entity.surface !== text.slice(start, end)) {
          throw new ValueError();
        }
        const key = `${label}\u0000${start}\u0000${end}`;
        if (seenSpans.has(key)) throw new ValueError();
        seenSpans.add(key);
        const target = K_PII_LABELS[label] ?? null;
        if (target === null) {
          bump(unmapped, label);
        } else {
          bump(mapped, label);
          spans.push({ label: target, start, end, text: text.slice(start, end) });
        }
      }
      seenIds.add(docId);
      const safeId = createHash("sha256").update(docId, "utf8").digest("hex");
      documents.push(
        new LabeledDocument(
          safeId,
          { text, spans },
          sliceValue(item.domain),
          sliceValue(item.variant),
        ),
      );
      if (documents.length > MAX_DOCUMENTS) throw new ValueError();
    } catch (e) {
      if (e instanceof ValueError || e instanceof TypeError) {
        throw new ValueError(
          `invalid k-pii-bench record at line ${i + 1}; check schema, label and offsets`,
        );
      }
      throw e;
    }
  }
  if (documents.length === 0) throw new ValueError("dataset must contain at least one document");
  let unmappedCount = 0;
  for (const n of Object.values(unmapped)) unmappedCount += n;
  const metadata: Record<string, unknown> = {
    format: "k-pii-bench-jsonl",
    adapter_version: 1,
    source_sha256: createHash("sha256").update(raw, "utf8").digest("hex"),
    label_map: { ...K_PII_LABELS },
    mapped_spans: mapped,
    unmapped_spans: unmapped,
    unmapped_span_count: unmappedCount,
    warning:
      "Mapped-label strict-span evaluation only; not the official upstream score or a full-coverage claim.",
  };
  return [documents, metadata];
}
