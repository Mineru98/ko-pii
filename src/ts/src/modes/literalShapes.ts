/**
 * 변환기(partial/fpe)가 원문 형식을 보존해도 되는지 판정하는 리터럴 형식 검사.
 *
 * Python 대응: `ko_pii.patterns.email._split_literal_email`,
 * `ko_pii.patterns.passport._is_modern_number` — Python 에서도 modes 만 쓰는 비공개
 * 헬퍼다. 정규식은 patterns/email.py `_PATTERN`·`_IDN_PATTERN`, patterns/passport.py
 * `_MODERN_FORMAT` 과 같은 문자열을 쓴다 (fullmatch 이므로 경계 lookaround 는 생략).
 */
import { domainToASCII } from "node:url";
import { pyIsAscii } from "../core/strUtils.js";

const ASCII_EMAIL =
  /^[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;
// Korean IDN labels with an ASCII final label.
const IDN_LABEL = "[A-Za-z0-9가-힣](?:[A-Za-z0-9가-힣-]*[A-Za-z0-9가-힣])?";
const IDN_EMAIL = new RegExp(
  `^[A-Za-z0-9._%+-]+@${IDN_LABEL}(?:\\.${IDN_LABEL})*\\.[A-Za-z]{2,63}$`,
);

const MODERN_PASSPORT = /^[MSROD][0-9]{3}[A-Z][0-9]{4}$/;

/** Python `re.fullmatch(_MODERN_FORMAT, text) is not None` (예: `M123A4567`). */
export function isModernPassportNumber(text: string): boolean {
  return MODERN_PASSPORT.test(text);
}

/**
 * Python `domain.encode("idna")` 의 바이트 길이. 실패(UnicodeError)면 null.
 *
 * 순수 ASCII 도메인은 Python 빠른 경로처럼 라벨 길이(1..63)만 검사한다. 비ASCII 라벨은
 * ToASCII(nameprep + punycode)를 거친다 — 정규식이 허용하는 한글 음절·ASCII 조합에서는
 * WHATWG `domainToASCII` 의 punycode 결과와 같다. ACE 접두(`xn--`)로 시작하는 비ASCII
 * 라벨은 Python 처럼 거부한다.
 */
function idnaEncodedLength(domain: string): number | null {
  const labels = domain.split(".");
  let total = 0;
  for (const label of labels) {
    let ascii = label;
    if (!pyIsAscii(label)) {
      if (label.slice(0, 4).toLowerCase() === "xn--") return null;
      ascii = domainToASCII(label);
      if (!ascii || ascii.includes(".")) return null;
    }
    if (ascii.length === 0 || ascii.length >= 64) return null;
    total += ascii.length;
  }
  return total + labels.length - 1;
}

/**
 * Return parts only for one complete address in our supported subset.
 *
 * Field assertions may contain lists or prose. Transformers must not retain
 * everything after the first @ as if it were a single harmless domain.
 */
export function splitLiteralEmail(value: string): [string, string] | null {
  if (!ASCII_EMAIL.test(value) && !IDN_EMAIL.test(value)) return null;
  const at = value.indexOf("@");
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
  const encoded = idnaEncodedLength(domain);
  if (encoded === null || encoded > 253) return null;
  return [local, domain];
}
