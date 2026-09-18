/**
 * 모드 계층이 요구하는 Vault 최소 계약 (구조적 타입).
 *
 * `ts/src/vault/reversible.ts` (Python ko_pii.vault.reversible.ReversibleVault
 * 대응) 가 아직 TS 에 없고 본 모듈 범위 밖이므로, tokenize/hashed/fpe 는 이
 * 계약에만 의존한다. 정식 ReversibleVault 구현은 store/fingerprint 시그니처가
 * 호환되면 이 인터페이스를 구조적으로 만족한다.
 */

/** Python ReversibleVault 가 모드 계층에 노출하는 최소 인터페이스. */
export interface ModesVault {
  /** Python ``ReversibleVault.store`` 대응 — 할당된 토큰을 반환한다. */
  store(init: {
    label: string;
    original: string;
    riskLevel: number;
    legal_basis?: string | null;
    offset?: number;
    extra?: Record<string, unknown>;
  }): string;
  /** Python ``ReversibleVault.fingerprint`` 대응 — (label, original) 의 안정 지문 (hex). */
  fingerprint(label: string, original: string): string;
}
