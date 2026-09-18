/**
 * Python 내장 예외 대응 — `error.name` 이 Python 클래스명과 같아야
 * `"{type(e).__name__}: {e}"` 형태의 관찰 가능한 문자열(batch 결과의 error 필드 등)이 일치한다.
 */
export class ValueError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "ValueError";
  }
}
