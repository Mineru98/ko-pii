/**
 * Hashed mode — Vault fingerprint 기반의 일관성 식별자.
 *
 * 복원용 Vault 항목을 만들지 않지만 메모리 지문 캐시에는 원문이 남을 수 있다.
 * 저엔트로피 값은 비밀 키 없이 추측 공격이 가능하다.
 * 같은 라벨·원문과 Vault 지문 설정(키·salt·scheme·반복 횟수)에서 같은 결과를 얻는다.
 * 신규 Vault는 PBKDF2, 과거 Vault는 저장된 지문 scheme을 따른다.
 *
 * Legal basis: 개인정보보호법 비식별 조치 가이드라인 (해시 기반 가명처리).
 */

import { ValueError } from "../core/errors.js";
import type { DetectionResult } from "../core/types.js";
import { ReversibleVault } from "../vault/reversible.js";
import { applySubstitutions, prepareDetections } from "./apply.js";
import type { ModesVault } from "./vault.js";

/**
 * Replace each detection with ``<LABEL:hash>`` from its Vault fingerprint.
 *
 * ``digestLen`` must be an integer from 1 to 64 (default 12 hex characters,
 * 48 bits). Shorter digests collide more often; none is a unique-ID guarantee.
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
  if (
    typeof digestLen !== "number" ||
    !Number.isInteger(digestLen) ||
    digestLen < 1 ||
    digestLen > 64
  ) {
    throw new ValueError("digest_len must be an integer from 1 to 64");
  }
  const list = prepareDetections(text, detections);
  const v: ModesVault = vault ?? new ReversibleVault();

  const replace = (d: DetectionResult): string => {
    const fp = v.fingerprint(d.label, d.text);
    return `<${d.label}:${fp.slice(0, digestLen)}>`;
  };

  const replaced = applySubstitutions(text, list, replace);
  return [replaced, v];
}
