/**
 * 평가 골드 타입 — Python ``ko_pii.eval.synth`` 의 ``GoldSpan`` / ``GoldDocument`` 대응.
 *
 * synth 의 *생성기*(generate_document / generate_corpus)는 CPython MT19937 난수에
 * 의존하므로 포팅 범위 밖이다. metrics 가 import 하는 데이터 타입만 옮겼다.
 * 오프셋은 TS 판 정책대로 UTF-16 코드 유닛 (PORTING.md).
 */

export interface GoldSpan {
  label: string;
  start: number;
  end: number;
  text: string;
}

export interface GoldDocument {
  text: string;
  spans: GoldSpan[];
  /** Python 기본값 "" */
  template?: string;
}
