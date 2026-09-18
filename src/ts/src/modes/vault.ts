/**
 * 모드 계층이 요구하는 Vault 최소 계약 (구조적 타입).
 *
 * `vault/reversible.ts` 의 ReversibleVault (Python ko_pii.vault.reversible 대응) 가
 * 이 인터페이스를 구조적으로 만족한다 — `store` 는 ReversibleVault 와 같은 *위치 인자*
 * 시그니처다. tokenize/hashed/fpe 는 이 계약에만 의존하므로 테스트용 대체 vault 도
 * 받을 수 있고, vault 를 생략하면 Python 과 같이 새 ReversibleVault 를 만든다.
 */

/** Python ReversibleVault 가 모드 계층에 노출하는 최소 인터페이스. */
export interface ModesVault {
  /** Python ``ReversibleVault.store`` 대응 — 할당된 토큰을 반환한다. */
  store(
    label: string,
    original: string,
    riskLevel: number,
    legalBasis?: string | null,
    offset?: number,
    extra?: Record<string, unknown> | null,
  ): string;
  /** Python ``ReversibleVault.fingerprint`` 대응 — (label, original) 의 안정 지문 (hex). */
  fingerprint(label: string, original: string): string;
}
