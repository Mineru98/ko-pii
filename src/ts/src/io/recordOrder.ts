/**
 * 레코드 필드 순서 보존 — Python dict 삽입 순서 대응.
 *
 * JS 객체는 정수형 키("2023", "1")를 삽입 순서와 무관하게 앞으로, 오름차순으로 열거한다.
 * CSV/XLSX 헤더가 연도·번호면 Python(dict = 헤더 순서)과 컬럼 순서가 달라진다.
 * 공개 타입(평범한 Record)은 유지한 채, 열거되지 않는 심볼 프로퍼티에 삽입 순서를
 * 기록해 읽기·가명화·쓰기 경로가 그 순서를 쓰게 한다.
 *
 * 값 대입은 defineProperty 로 한다 — 헤더는 임의 문자열이라 "__proto__" 같은 키가
 * 프로토타입 체인을 타면 안 된다.
 */

const FIELD_ORDER: unique symbol = Symbol.for("ko-pii.fieldOrder");

type Ordered = { [FIELD_ORDER]?: string[] };

/** Python ``d[key] = value`` — 새 키는 끝에 추가, 기존 키는 자리를 지킨 채 값만 바뀐다. */
export function setField<V>(record: Record<string, V>, key: string, value: NoInfer<V>): void {
  const isNew = !Object.hasOwn(record, key);
  Object.defineProperty(record, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
  if (!isNew) return;
  const holder = record as Ordered;
  let order = holder[FIELD_ORDER];
  if (order === undefined) {
    // 순서 정보 없이 만들어진 객체에 처음 쓰는 경우 — 기존 키의 열거 순서를 이어받는다.
    order = Object.keys(record).filter((k) => k !== key);
    Object.defineProperty(record, FIELD_ORDER, { value: order, enumerable: false });
  }
  order.push(key);
}

/**
 * 레코드의 키를 삽입 순서로 — Python ``list(d)``.
 * 순서 정보가 없거나(호출자가 만든 평범한 객체) 이후 직접 대입으로 어긋났으면
 * ``Object.keys`` 로 폴백한다.
 */
export function recordKeys(record: Record<string, unknown>): string[] {
  const order = (record as Ordered)[FIELD_ORDER];
  const keys = Object.keys(record);
  if (order === undefined || order.length !== keys.length) return keys;
  for (const k of order) if (!Object.hasOwn(record, k)) return keys;
  return [...order];
}

/** 삽입 순서의 ``[key, value]`` 쌍 — Python ``d.items()``. */
export function recordEntries<V>(record: Record<string, V>): [string, V][] {
  return recordKeys(record).map((k) => [k, record[k] as V]);
}
