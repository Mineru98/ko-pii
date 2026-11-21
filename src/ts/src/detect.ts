/**
 * 전체 검출기 진입점 — Python ko_pii.detect 대응.
 *
 * 모든 검출기를 직렬 실행하고 정규화 원본 재검사 합집합 + 겹침 해소로 병합한다.
 */

import { resolveOverlaps } from "./core/overlap.js";
import { pyTypeName } from "./core/strUtils.js";
import type { OverlapTrace } from "./core/trace.js";
import type { DetectionResult } from "./core/types.js";
import { needsNormalization, normalizeUnicode, remapToSource } from "./core/unicodeNorm.js";
import * as civilPetition from "./domain/civil_petition.js";
import * as government from "./domain/government.js";
import * as hr from "./domain/hr.js";
import { validateLabelFilter } from "./labels.js";
import * as account from "./patterns/account.js";
import * as address from "./patterns/address.js";
import * as birth from "./patterns/birth.js";
import * as businessReg from "./patterns/business_reg.js";
import * as card from "./patterns/card.js";
import * as corpReg from "./patterns/corp_reg.js";
import * as courtCase from "./patterns/court_case.js";
import * as driverLicense from "./patterns/driver_license.js";
import * as ediDrug from "./patterns/edi_drug.js";
import * as email from "./patterns/email.js";
import * as fax from "./patterns/fax.js";
import * as frn from "./patterns/frn.js";
import * as ip from "./patterns/ip.js";
import * as medicalInsurance from "./patterns/medical_insurance.js";
import * as nationality from "./patterns/nationality.js";
import * as passport from "./patterns/passport.js";
import * as person from "./patterns/person.js";
import * as personalAttr from "./patterns/personal_attr.js";
import * as phone from "./patterns/phone.js";
import * as pnu from "./patterns/pnu.js";
import * as postalCode from "./patterns/postal_code.js";
import * as prescription from "./patterns/prescription.js";
import * as rrn from "./patterns/rrn.js";
import * as url from "./patterns/url.js";
import * as vehicle from "./patterns/vehicle.js";

/** Python 검출기는 Iterator 를 반환하므로 Iterable 로 수용한다. */
export type Detector = (text: string) => Iterable<DetectionResult>;

/** 실행 순서는 Python detect.py 의 DETECTORS 와 동일하게 유지한다. */
export const DETECTORS: readonly Detector[] = [
  rrn.detect,
  frn.detect,
  businessReg.detect,
  corpReg.detect,
  driverLicense.detect,
  passport.detect,
  card.detect,
  medicalInsurance.detect,
  prescription.detect,
  pnu.detect,
  fax.detect,
  phone.detect,
  email.detect,
  postalCode.detect,
  ip.detect,
  vehicle.detect,
  url.detect,
  address.detect,
  nationality.detect,
  account.detect,
  person.detect,
  // 식의약·법조 도메인
  ediDrug.detect,
  courtCase.detect,
  // 인적 속성 (준식별자) — 학력·전공·직책·측정치 + 생년월일
  birth.detect,
  personalAttr.detect,
  // Domain-specific
  government.detect,
  civilPetition.detect,
  hr.detect,
];

// 영숫자 런(ASCII + 전각) — 원본 재검사 필요 여부 판정용.
const PII_RUN = /[0-9A-Za-z０-９Ａ-Ｚａ-ｚ]+/g;
// 숫자 우회 차단 정규화가 지우는 줄 구분 제어문자.
// biome-ignore lint/suspicious/noControlCharactersInRegex: 제어문자 판정이 목적
const EMAIL_LINE_CONTROLS = /[\x0b\x0c\x1c-\x1e\x85]/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: 제어문자 치환이 목적
const EMAIL_LINE_CONTROLS_G = /[\x0b\x0c\x1c-\x1e\x85]/g;

function runShape(s: string): number[] {
  PII_RUN.lastIndex = 0;
  return [...s.matchAll(PII_RUN)].map((m) => m[0].length);
}

function runDetectors(
  text: string,
  personExclusions: ReadonlySet<string>,
  includePerson = true,
  includeEmail = true,
): DetectionResult[] {
  const raw: DetectionResult[] = [];
  for (const fn of DETECTORS) {
    if (fn === person.detect) {
      if (includePerson) raw.push(...person.detectWithExclusions(text, personExclusions));
    } else if (fn === email.detect && !includeEmail) {
    } else {
      raw.push(...fn(text));
    }
  }
  return raw;
}

export interface DetectAllOptions {
  /** 전각/호환문자 폴딩 + 제로폭 제거 (기본 true) — 결과 offset 은 원본 기준으로 역매핑. */
  normalize?: boolean;
  /** 이 호출에서 PERSON 으로 검출하지 않을 도메인 용어 (패키지 사전 불변, 호출 범위). */
  personExclusions?: Iterable<string> | null;
  /** 공통 겹침 해소 메타데이터 수집기 — 입력마다 새 OverlapTrace 를 쓸 것. */
  trace?: OverlapTrace | null;
}

/** 전체 검출기 실행 후 병합·겹침 해소 (Python ``detect_all``).
 *
 * 겹침은 위험도 → 확신도 → 길이 → 시작 위치 순으로 해소한다. 검출 전용 API 라 출력 정책은
 * 없다 — Anonymizer 는 처리 정책을 적용한 뒤 후보를 해소한다.
 *
 * include / exclude 는 ``validateLabelFilter`` 로 검증된다: 알 수 없는 라벨·문자열 단독·빈
 * include 는 ValueError (null/undefined 는 제한 없음, 빈 exclude 는 아무것도 제외 안 함).
 */
export function detectAll(
  text: string,
  include?: Iterable<string> | null,
  exclude?: Iterable<string> | null,
  options: DetectAllOptions = {},
): DetectionResult[] {
  return resolveOverlaps(detectCandidates(text, include, exclude, options), {
    trace: options.trace ?? null,
  });
}

/** 원문 결속 후보를 정책/병합 근거 손실 없이 수집 (Python ``_detect_candidates``).
 *
 * 반환 후보는 겹침 해소 전이며 모두 ``ruleId = ko-pii.<label>.v1`` 을 갖는다.
 */
export function detectCandidates(
  text: string,
  include?: Iterable<string> | null,
  exclude?: Iterable<string> | null,
  options: Omit<DetectAllOptions, "trace"> = {},
): DetectionResult[] {
  const normalize = options.normalize ?? true;
  if (typeof text !== "string") {
    throw new TypeError(`detect_all() expects str, got ${pyTypeName(text)}`);
  }
  const inc = validateLabelFilter(include, "include");
  const exc = validateLabelFilter(exclude, "exclude");
  const normalizedExclusions = person.normalizeExclusions(options.personExclusions);
  const source = text;
  let offsetMap: number[] | null = null;
  let work = text;
  if (normalize && needsNormalization(text)) {
    const [norm, omap] = normalizeUnicode(text);
    if (norm !== text) {
      work = norm;
      offsetMap = omap;
    }
  }

  const separateEmail = normalize && EMAIL_LINE_CONTROLS.test(source);
  let raw = runDetectors(work, normalizedExclusions, true, !separateEmail);

  if (offsetMap !== null) {
    // 정규화가 텍스트를 바꿨다: offset 을 원본으로 역매핑한 뒤 원본에도 한 번 더
    // 검출해 합집합(누출 차단). 원본 재검사는 영숫자 런 모양이 바뀐 경우만 — DoS 완화.
    raw = remapToSource(raw, offsetMap, source);
    if (JSON.stringify(runShape(source)) !== JSON.stringify(runShape(work))) {
      raw.push(...runDetectors(source, normalizedExclusions, false, !separateEmail));
    }
  }

  if (separateEmail) {
    // 숫자 제어문자 주입 검출을 약화하지 않고 이메일 줄 경계를 유지한다. 치환이 1:1 이라
    // offset 은 여전히 원본 기준이다.
    const [emailText, emailOffsets] = normalizeUnicode(source.replace(EMAIL_LINE_CONTROLS_G, "\n"));
    raw.push(...remapToSource(email.detect(emailText), emailOffsets, source));
    raw.push(...email.detect(source));
  }

  const personAllowed = (inc === null || inc.includes("PERSON")) && !(exc ?? []).includes("PERSON");
  if (normalize && EMAIL_LINE_CONTROLS.test(source) && personAllowed) {
    // 숫자 우회 차단이 이 제어문자를 지우면 이름이 다음 필드 라벨과 붙을 수 있다. 이름·식별자
    // 안에 끼운 제어문자 보호는 유지한 채 줄 경계를 아는 PERSON 뷰를 추가한다.
    const [personText, personOffsets] = normalizeUnicode(
      source.replace(EMAIL_LINE_CONTROLS_G, "\n"),
    );
    raw.push(
      ...remapToSource(
        person.detectWithExclusions(personText, normalizedExclusions),
        personOffsets,
        source,
      ),
    );
  }

  const passportAllowed =
    (inc === null || inc.includes("PASSPORT")) && !(exc ?? []).includes("PASSPORT");
  if (offsetMap !== null && passportAllowed) {
    // 숫자 닮은꼴 폴딩은 유효한 여권 문자(S/O/G)를 지울 수 있다. 이 검출기만 문자 그대로의
    // 뷰가 필요하다 — 전체 재검사는 하지 않는다.
    const [passportText, passportOffsets] = normalizeUnicode(source, { foldNumeric: false });
    if (passportText !== work) {
      raw.push(...remapToSource(passport.detect(passportText), passportOffsets, source));
    }
  }

  if (inc !== null) {
    const incSet = new Set(inc);
    raw = raw.filter((d) => incSet.has(d.label));
  }
  if (exc !== null && exc.length > 0) {
    const excSet = new Set(exc);
    raw = raw.filter((d) => !excSet.has(d.label));
  }

  for (const detection of raw) {
    detection.ruleId = `ko-pii.${detection.label.toLowerCase()}.v1`;
  }
  return raw;
}
