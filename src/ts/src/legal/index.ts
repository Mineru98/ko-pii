/** Legal mapping — PII category ↔ 법조항 단일 매핑 소스.
 *
 * Python `ko_pii.legal.__init__` (`__all__`) 대응 재수출.
 * 함수명은 Python snake_case(`legal_basis_for` 등) 대신 TS 컨벤션
 * (`legalBasisFor` 등) 를 쓴다 — `mapping.ts` 가 이미 이 이름으로 export 한다.
 */
export {
  CATEGORY_BY_LABEL,
  categoryFor,
  LEGAL_BASIS_BY_LABEL,
  legalBasisFor,
  riskFloorFor,
} from "./mapping.js";
