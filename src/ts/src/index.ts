/**
 * ko-pii — 한국어 PII 검출 + 가역 가명화 (TypeScript 포트).
 *
 * Python 원본(src/ko_pii/__init__.py)의 공개 API에 대응하는 엔트리.
 * 마이그레이션 마일스톤(M0~M5)에 따라 순차적으로 채워진다:
 *   M1  detectAll / DetectionResult / RiskLevel  ✅
 *   M2  Anonymizer / 치환 프리미티브 / ReversibleVault / analytics  ✅
 *   M3  io 서브패스   M4  cli / mcp 서브패스
 */

export type { CombinedRiskReport, Identifier, KAnonymityReport } from "./analytics/index.js";
// analytics
export {
  AttributeClass,
  classify_attribute,
  evaluate_dataset,
  k_anonymity,
  score_combined_risk,
} from "./analytics/index.js";
export type { AnonymizationResult, DetectionRecord } from "./anonymizer.js";
export { Anonymizer, blockedItems, reviewItems } from "./anonymizer.js";
export type { ModePolicy } from "./core/modes.js";
export { Action, ProcessingMode, policyFor } from "./core/modes.js";
export { resolveOverlaps } from "./core/overlap.js";
export type { DetectionResult } from "./core/types.js";
// 핵심 데이터 타입
export { makeDetection, RiskLevel } from "./core/types.js";
export { needsNormalization, normalizeUnicode, remapToSource } from "./core/unicodeNorm.js";
// 검출
export type { DetectAllOptions, Detector } from "./detect.js";
export { DETECTORS, detectAll } from "./detect.js";
// integrations (Python __all__: SecondaryDetector / MockSecondaryDetector / MergeMode /
// merge_detections — get_privacy_filter_adapter 는 torch 의존이라 Python 전용)
export type { SecondaryDetector } from "./integrations/index.js";
export {
  DEFAULT_ROLE_SPLIT_LABELS,
  MergeMode,
  MockSecondaryDetector,
  mergeDetections,
} from "./integrations/index.js";
export { ALL_LABELS, GROUPS, LABEL_INFO } from "./labels.js";
// 가명화 (Python __init__.py: tokenize / redact / hashed / partial / mask_value / fpe)
export {
  applySubstitutions,
  fpe,
  hashed,
  maskValue,
  partial,
  redact,
  tokenize,
} from "./modes/index.js";
// streaming (Python __all__: PreForwardAnonymizer / StreamBuffer*)
export type { PreForwardAnonymizerOptions } from "./streaming.js";
export {
  PreForwardAnonymizer,
  StreamBufferClosed,
  StreamBufferLimitExceeded,
  StreamBufferStatus,
} from "./streaming.js";
export { isEncryptedFile, loadEncrypted, saveEncrypted } from "./vault/encrypted.js";
// Vault
export { AuditLog, ReversibleVault, replay, VaultEntry } from "./vault/index.js";
export { VERSION } from "./version.js";
