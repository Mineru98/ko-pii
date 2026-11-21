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

import { ValueError } from "../core/errors.js";

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

const JSON_NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/** Python ``sys.get_int_max_str_digits()`` 기본값 — 이보다 긴 정수 문자열은 ``int()`` 가 거부한다. */
export const PY_INT_MAX_STR_DIGITS = 4300;

/**
 * JSON 숫자 어휘 → Python ``json.loads`` 의 값. 소수점·지수가 없으면 Python int 이므로
 * ``Number.isSafeInteger`` 범위를 넘는 값은 ``bigint`` 로 정확히 보존하고 ``-0`` 은 ``0`` 으로 둔다.
 * 부호를 뺀 자릿수가 4300 을 넘으면 Python 과 같은 메시지의 ValueError.
 */
function jsonNumber(lexeme: string): number | bigint {
  if (/[.eE]/.test(lexeme)) return Number(lexeme);
  const digits = lexeme.startsWith("-") ? lexeme.length - 1 : lexeme.length;
  if (digits > PY_INT_MAX_STR_DIGITS) {
    throw new ValueError(
      `Exceeds the limit (${PY_INT_MAX_STR_DIGITS} digits) for integer string conversion: ` +
        `value has ${digits} digits; use sys.set_int_max_str_digits() to increase the limit`,
    );
  }
  const n = Number(lexeme);
  return Number.isSafeInteger(n) ? n + 0 : BigInt(lexeme);
}

/**
 * ``JSON.parse`` 와 같은 값을 만들되 객체는 ``setField`` 로 채운다 — Python ``json.loads`` 처럼
 * 원본 키 순서(정수형 키 포함)를 보존하고 ``"__proto__"`` 도 own property 로 둔다.
 * 정수는 Python int 처럼 정확히 읽는다 (안전 범위 밖은 ``bigint`` — ``jsonNumber``).
 * 문법 오류는 ``JSON.parse`` 의 SyntaxError 그대로. 같은 객체에 키가 다시 나오면
 * ``onDuplicateKey`` 를 부르고, 없으면 마지막 값이 첫 자리를 차지한다 (Python dict 갱신).
 */
export function parseJsonOrdered(text: string, onDuplicateKey?: (key: string) => never): unknown {
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed === "number") return jsonNumber(text.trim());
  if (parsed === null || typeof parsed !== "object") return parsed;
  // 문법은 위에서 검증됐다 — 토큰을 다시 훑어 컨테이너를 문서 순서대로 만든다.
  type Frame = { value: Record<string, unknown> | unknown[]; key: string | null };
  const stack: Frame[] = [];
  let root: unknown;
  const emit = (value: unknown): void => {
    const top = stack[stack.length - 1];
    if (top === undefined) {
      root = value;
    } else if (Array.isArray(top.value)) {
      top.value.push(value);
    } else {
      const key = top.key as string;
      if (onDuplicateKey !== undefined && Object.hasOwn(top.value, key)) onDuplicateKey(key);
      setField(top.value, key, value);
      top.key = null;
    }
  };
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "{" || ch === "[") {
      stack.push({ value: ch === "{" ? {} : [], key: null });
      i += 1;
    } else if (ch === "}" || ch === "]") {
      emit((stack.pop() as Frame).value);
      i += 1;
    } else if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const s = JSON.parse(text.slice(i, j + 1)) as string;
      i = j + 1;
      const top = stack[stack.length - 1];
      if (top !== undefined && !Array.isArray(top.value) && top.key === null) top.key = s;
      else emit(s);
    } else if (ch === "t") {
      emit(true);
      i += 4;
    } else if (ch === "f") {
      emit(false);
      i += 5;
    } else if (ch === "n") {
      emit(null);
      i += 4;
    } else if (ch === "-" || (ch !== undefined && ch >= "0" && ch <= "9")) {
      JSON_NUMBER.lastIndex = i;
      const m = JSON_NUMBER.exec(text) as RegExpExecArray;
      emit(jsonNumber(m[0]));
      i = JSON_NUMBER.lastIndex;
    } else {
      i += 1; // 공백 · ':' · ','
    }
  }
  return root;
}
