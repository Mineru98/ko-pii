/**
 * 확장자 기반 자동 디스패처 — Python ko_pii.io_.dispatcher 대응.
 *
 * 모든 포맷의 raw 텍스트에 text_normalizer 를 적용해 셀 줄바꿈/래핑으로 쪼개진
 * PII 를 검출 전에 복원한다 (원본과 동일).
 */
import * as csvReader from "./csvReader.js";
import * as docx from "./docx.js";
import * as hwp from "./hwp.js";
import * as hwpx from "./hwpx.js";
import * as pdf from "./pdf.js";
import * as plain from "./plain.js";
import { normalizeForDetection } from "./textNormalizer.js";
import * as xlsx from "./xlsx.js";

export const SUPPORTED_EXTENSIONS: readonly string[] = [
  ".txt",
  ".md",
  ".log",
  ".csv",
  ".tsv",
  ".hwpx",
  ".hwp", // 한컴 (신/구)
  ".docx",
  ".xlsx",
  ".pdf",
];

export function extensionOf(path: string): string {
  const idx = path.lastIndexOf(".");
  // Python os.path.splitext: 확장자가 없거나 점만 있으면 빈 문자열
  if (idx <= 0) return "";
  return path.slice(idx).toLowerCase();
}

export async function readText(path: string): Promise<string> {
  const ext = extensionOf(path);
  let raw: string;
  if (ext === ".hwpx") {
    raw = await hwpx.readText(path);
  } else if (ext === ".hwp") {
    raw = hwp.readText(path);
  } else if (ext === ".pdf") {
    raw = await pdf.readText(path);
  } else if (ext === ".docx") {
    raw = await docx.readText(path);
  } else if (ext === ".xlsx") {
    raw = await xlsx.readText(path);
  } else if (ext === ".csv" || ext === ".tsv") {
    raw = csvReader.readText(path);
  } else {
    raw = plain.readText(path);
  }
  // 셀 줄바꿈/래핑으로 쪼개진 PII 를 검출 전에 복원 — 모든 포맷 공통.
  // pdf 는 내부에서도 적용하지만 정규화는 idempotent.
  const [normalized] = normalizeForDetection(raw);
  return normalized;
}

export async function readRecords(path: string): Promise<Record<string, string>[]> {
  const ext = extensionOf(path);
  if (ext === ".csv" || ext === ".tsv") {
    return csvReader.readRecords(path);
  }
  if (ext === ".xlsx") {
    return xlsx.readRecords(path);
  }
  return [];
}
