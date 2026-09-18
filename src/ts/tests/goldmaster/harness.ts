/**
 * 골드 마스터 하네스 — Python ko-pii가 생성한 진실 벡터를 로드한다.
 *
 * 골드 오프셋 단위는 코드 포인트(Python 기준)이고 TS 구현은 UTF-16 코드 유닛을
 * 쓴다. M1 하네스에서 코드 포인트→UTF-16 변환 유틸(codepointToUtf16Offset)을
 * 거쳐 비교한다. 파일 자체는 변환 없이 원형으로 보관한다.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const GOLDMASTER_DIR = join(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "..",
  "spec",
  "goldmaster",
);

export interface GoldMeta {
  generator: string;
  ko_pii_version: string;
  python: string;
  offset_unit: "codepoint";
  fixed_salt: string;
  fixed_secret_key: string;
  strategies: string[];
  fixture_ids: string[];
}

export interface GoldDetection {
  label: string;
  text: string;
  start: number;
  end: number;
  risk_level: number;
  confidence: number;
  evidence: string[];
  legal_basis: string | null;
  extra: Record<string, unknown>;
}

export interface GoldDetectionEntry {
  id: string;
  text: string;
  detections: GoldDetection[];
}

export interface GoldAnonymizeEntry {
  id: string;
  strategy: string;
  text_in: string;
  text_out: string;
  records: {
    label: string;
    action: string;
    token: string | null;
    start: number;
    end: number;
  }[];
  summary: Record<string, unknown>;
}

export interface GoldFingerprintEntry {
  scheme: string;
  salt: string;
  secret_key: string;
  iterations: number;
  label: string;
  original: string;
  hex: string;
}

export interface GoldKdfEntry {
  password: string;
  salt_hex: string;
  iterations: number;
  dklen: number;
  key_hex: string;
}

export interface GoldUnicodeEdgeEntry {
  input: string;
  needs_normalization: boolean;
  normalized: string;
  offset_map: number[] | null;
}

export interface GoldVaultEntry {
  id: string;
  dumps: string;
}

function load<T>(name: string): T {
  return JSON.parse(readFileSync(join(GOLDMASTER_DIR, name), "utf-8")) as T;
}

export function loadMeta(): GoldMeta {
  return load<GoldMeta>("meta.json");
}

export function loadDetections(): { offset_unit: string; entries: GoldDetectionEntry[] } {
  return load("detection.json");
}

export function loadAnonymize(): { entries: GoldAnonymizeEntry[] } {
  return load("anonymize.json");
}

export function loadVaults(): { salt: string; secret_key: string; entries: GoldVaultEntry[] } {
  return load("vault.json");
}

export function loadFingerprints(): { entries: GoldFingerprintEntry[] } {
  return load("fingerprint.json");
}

export function loadKdf(): { entries: GoldKdfEntry[] } {
  return load("kdf.json");
}

export function loadUnicodeEdges(): {
  offset_unit: string;
  entries: GoldUnicodeEdgeEntry[];
} {
  return load("unicode_edge.json");
}

export interface GoldKvault {
  password: string;
  kdf_iterations: number;
  kdf_salt_len: number;
  nonce_len: number;
  magic_hex: string;
  blob_hex: string;
  plaintext_len: number;
}

export function loadKvault(): GoldKvault {
  return load<GoldKvault>("kvault.json");
}

/** 코드 포인트 오프셋 → UTF-16 코드 유닛 오프셋 변환 (M1 하네스 공용). */
export function codepointOffsetToUtf16(text: string, cpOffset: number): number {
  if (cpOffset <= 0) return 0;
  let units = 0;
  let points = 0;
  for (const ch of text) {
    if (points >= cpOffset) break;
    points += 1;
    units += ch.length;
  }
  return units;
}
