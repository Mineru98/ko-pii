/**
 * Hashed mode — salt + SHA-256 일관성 식별자.
 *
 * 원본은 복원할 수 없지만, 같은 원본은 같은 해시 → 동일성 분석 가능.
 * Vault salt 를 공유하면 문서 간 일관성도 유지.
 *
 * Legal basis: 개인정보보호법 비식별 조치 가이드라인 (해시 기반 가명처리).
 */
import type { DetectionResult } from "../core/types.js";
import { ReversibleVault } from "../vault/reversible.js";
import { applySubstitutions } from "./apply.js";
import type { ModesVault } from "./vault.js";

/**
 * Replace each detection with ``<LABEL:hash>`` derived from a salted SHA-256.
 *
 * ``digest_len`` truncates the hex digest for readability (default 12 chars
 * ≈ 48 bits — collision-resistant within a typical document).
 * vault 를 생략(또는 null)하면 새 ReversibleVault 를 만든다 (Python ``vault=None`` 대응).
 */
export function hashed(
  text: string,
  detections: Iterable<DetectionResult>,
  vault?: null,
  digestLen?: number,
): [string, ReversibleVault];
export function hashed<V extends ModesVault>(
  text: string,
  detections: Iterable<DetectionResult>,
  vault: V,
  digestLen?: number,
): [string, V];
export function hashed(
  text: string,
  detections: Iterable<DetectionResult>,
  vault?: ModesVault | null,
  digestLen?: number,
): [string, ModesVault];
export function hashed(
  text: string,
  detections: Iterable<DetectionResult>,
  vault?: ModesVault | null,
  digestLen = 12,
): [string, ModesVault] {
  const v: ModesVault = vault ?? new ReversibleVault();
  const list = [...detections];

  const replace = (d: DetectionResult): string => {
    const fp = v.fingerprint(d.label, d.text);
    return `<${d.label}:${fp.slice(0, digestLen)}>`;
  };

  const replaced = applySubstitutions(text, list, replace);
  return [replaced, v];
}
