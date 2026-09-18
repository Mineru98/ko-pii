/** Analytics — 검출 결과의 *조합* 위험도 평가 및 k-익명성 검증.
 *
 * Python ko_pii.analytics.__init__ 의 `__all__` 재수출 대응.
 * (추가로 is_re_identifiable / riskLevelName 도 재수출 — 보고서 공개 API)
 */

export {
  AttributeClass,
  type CombinedRiskReport,
  classify_attribute,
  type Identifier,
  is_re_identifiable,
  riskLevelName,
  score_combined_risk,
} from "./combinedRisk.js";
export {
  evaluate_dataset,
  type KAnonymityReport,
  k_anonymity,
} from "./kAnonymity.js";
