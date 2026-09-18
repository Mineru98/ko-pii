/**
 * SecondaryDetector 프로토콜 — 외부 PII 검출기의 공통 인터페이스.
 * Python ko_pii.integrations.base 대응.
 *
 * 모든 통합 어댑터는 본 프로토콜을 따른다. ko-pii 의 ``Anonymizer`` 가 *어떤*
 * 외부 검출기든 받을 수 있도록 일관된 인터페이스 정의.
 */

import type { DetectionResult } from "../core/types.js";

/**
 * 외부 PII 검출기가 따라야 할 프로토콜.
 *
 * 구현체는 ``detect(text)`` 가 ``DetectionResult`` 를 반환해야 하며, 라벨은 ko-pii 와
 * 호환되는 카테고리 (PERSON/EMAIL/PHONE/RRN/ADDRESS/CARD/...) 를 사용해야 한다.
 * 오프셋은 TS 판 정책대로 UTF-16 코드 유닛 기준이다 (PORTING.md).
 */
export interface SecondaryDetector {
  /** 식별용 이름 (예: 'openai-privacy-filter', 'presidio-analyzer'). */
  name: string;
  /** 텍스트에서 PII 를 검출. */
  detect(text: string): Iterable<DetectionResult>;
}

/**
 * 테스트용 mock — 미리 정의된 결과를 항상 반환.
 * 실제 ML 모델 없이 hybrid 로직을 검증할 때 사용.
 */
export class MockSecondaryDetector implements SecondaryDetector {
  name = "mock";
  private readonly fixed: DetectionResult[];

  constructor(fixedResults?: Iterable<DetectionResult> | null) {
    this.fixed = fixedResults ? [...fixedResults] : [];
  }

  *detect(text: string): Generator<DetectionResult> {
    for (const r of this.fixed) {
      // text 내에 해당 토큰이 실제 있을 때만 반환
      if (text.includes(r.text)) yield r;
    }
  }
}
