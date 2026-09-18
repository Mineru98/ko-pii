/**
 * Reversible tokenization mode.
 *
 * 각 검출 결과를 ``<LABEL_N>`` 토큰으로 치환하고, Vault 에 원본을 저장한다.
 * 같은 원본 값은 같은 토큰을 받는다 (문서 내 일관성). Vault 가 있으면 원본 복원 가능.
 *
 * Legal basis: 개인정보보호법 제28조의2~5 (가명정보 처리 특례).
 */
import type { DetectionResult } from "../core/types.js";
import { ReversibleVault } from "../vault/reversible.js";
import { applySubstitutions } from "./apply.js";
import type { ModesVault } from "./vault.js";

/**
 * Replace each detection span with a stable ``<LABEL_N>`` token.
 *
 * Returns ``[replaced_text, vault]``. If no vault is supplied a fresh
 * ReversibleVault is created (Python ``vault=None`` 기본값 대응). The same vault
 * can be reused across multiple calls to maintain token identity across documents.
 */
export function tokenize(
  text: string,
  detections: Iterable<DetectionResult>,
): [string, ReversibleVault];
export function tokenize<V extends ModesVault>(
  text: string,
  detections: Iterable<DetectionResult>,
  vault: V,
): [string, V];
export function tokenize(
  text: string,
  detections: Iterable<DetectionResult>,
  vault?: ModesVault | null,
): [string, ModesVault];
export function tokenize(
  text: string,
  detections: Iterable<DetectionResult>,
  vault?: ModesVault | null,
): [string, ModesVault] {
  const v: ModesVault = vault ?? new ReversibleVault();
  const list = [...detections]; // consume iterator once

  const replace = (d: DetectionResult): string =>
    v.store(d.label, d.text, d.riskLevel, d.legal_basis, d.start, { ...d.extra });

  const replaced = applySubstitutions(text, list, replace);
  return [replaced, v];
}
