/**
 * 평가 (Evaluation) — 라벨 + Precision/Recall/F1. Python ``ko_pii.eval.__init__`` 의 재노출 대응.
 *
 * synth 의 생성 함수(generate_document / generate_corpus)는 포팅 범위 밖이라 없다 —
 * 타입(GoldSpan / GoldDocument)만 있다. 그 외 eval 모듈(kdpii, klueNer, fpCollector,
 * datasetIntegrity, 동결 코퍼스 로더)도 패키지 서브패스 ``ko-pii/eval`` 하나로 쓸 수 있게
 * 네임스페이스로 함께 내보낸다.
 */

export { loadJsonlCorpus, locateSpans } from "./benchmark.js";
export * as datasetIntegrity from "./datasetIntegrity.js";
export * as fpCollector from "./fpCollector.js";
export * as kdpii from "./kdpii.js";
export * as klueNer from "./klueNer.js";
export {
  BenchmarkReport,
  formatReport,
  PerLabelMetrics,
  scoreCorpus,
  scoreDocument,
} from "./metrics.js";
export type { GoldDocument, GoldSpan } from "./types.js";
