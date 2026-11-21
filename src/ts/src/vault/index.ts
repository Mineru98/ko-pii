/**
 * Reversible pseudonymization storage primitives — Python `ko_pii/vault/__init__.py` 의
 * `__all__` 대응 재수출. The vault does not authenticate callers; applications
 * must enforce access control.
 *
 * 선택 서브모듈 (개별 import):
 * - `./vault/encrypted.js` — AES-GCM .kvault 암호화 (node:crypto 기반, Python 의
 *   optional `cryptography` 의존과 달리 항상 사용 가능)
 * - `./vault/audit.js` — 모든 store/reveal 호출 추적
 */

export { AuditLog, replay } from "./audit.js";
export type { AuditFailurePolicy } from "./reversible.js";
export { ReversibleVault, VaultEntry } from "./reversible.js";
