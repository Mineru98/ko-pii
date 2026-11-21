/**
 * 외부 PII 검출기 통합 — Python ko_pii.integrations 대응.
 *
 * 포팅 범위: 순수 로직(SecondaryDetector 프로토콜, mock, 병합, 사용자 규칙 검출기
 * CallableDetector/RegexDetector/LiteralDetector, RAG 메타데이터 마스킹 rag.maskMetadata).
 * torch/transformers·Presidio·LangChain·LlamaIndex 의존 어댑터(get_privacy_filter_adapter,
 * KoPIIRecognizer, KoPIIDocumentTransformer, KoPIINodePostprocessor 등)는 JS 등가물이
 * 없어 Python 에 남는다 (docs/TS_MIGRATION_FEASIBILITY.md). TS 에서는 같은
 * ``SecondaryDetector`` 인터페이스를 구현해 ``Anonymizer`` 에 넘기면 된다.
 */

export type { SecondaryDetector } from "./base.js";
export { MockSecondaryDetector } from "./base.js";
export type { CustomDetectorLimits, RegexDetectorOptions } from "./custom.js";
export { CallableDetector, RegexDetector } from "./custom.js";
export type { MergeCandidatesOptions, MergeDetectionsOptions } from "./hybrid.js";
export {
  DEFAULT_ROLE_SPLIT_LABELS,
  MergeMode,
  mergeCandidates,
  mergeDetections,
  toMergeMode,
  validateMergeConfig,
} from "./hybrid.js";
export type { LiteralBoundary, LiteralDetectorOptions } from "./literal.js";
export { LiteralDetector } from "./literal.js";
