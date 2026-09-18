/**
 * 전체 검출기 진입점 — Python ko_pii.detect 대응.
 *
 * 모든 검출기를 직렬 실행하고 정규화 원본 재검사 합집합 + 겹침 해소로 병합한다.
 */

import { resolveOverlaps } from "./core/overlap.js";
import type { DetectionResult } from "./core/types.js";
import { needsNormalization, normalizeUnicode, remapToSource } from "./core/unicodeNorm.js";
import * as civilPetition from "./domain/civil_petition.js";
import * as government from "./domain/government.js";
import * as hr from "./domain/hr.js";
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

function runShape(s: string): number[] {
  PII_RUN.lastIndex = 0;
  return [...s.matchAll(PII_RUN)].map((m) => m[0].length);
}

export interface DetectAllOptions {
  include?: Iterable<string>;
  exclude?: Iterable<string>;
  /** 전각/호환문자 폴딩 + 제로폭 제거 (기본 true) — 결과 offset 은 원본 기준으로 역매핑. */
  normalize?: boolean;
}

export function detectAll(
  text: string,
  include?: Iterable<string> | null,
  exclude?: Iterable<string> | null,
  options?: { normalize?: boolean },
): DetectionResult[] {
  const normalize = options?.normalize ?? true;
  if (typeof text !== "string") {
    throw new TypeError(`detectAll() expects string, got ${typeof text}`);
  }
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

  const raw: DetectionResult[] = [];
  for (const fn of DETECTORS) {
    raw.push(...fn(work));
  }

  if (offsetMap !== null) {
    // 정규화가 텍스트를 바꿨다: offset 을 원본으로 역매핑한 뒤 원본에도 한 번 더
    // 검출해 합집합(누출 차단). 원본 재검사는 영숫자 런 모양이 바뀐 경우만 — DoS 완화.
    const remapped = remapToSource(raw, offsetMap, source);
    if (JSON.stringify(runShape(source)) !== JSON.stringify(runShape(work))) {
      for (const fn of DETECTORS) {
        remapped.push(...fn(source));
      }
    }
    raw.length = 0;
    raw.push(...remapped);
  }

  // Python: `set(include) if include else None` — 빈 include 는 "필터 없음"이고,
  // include 와 exclude 는 둘 다 적용된다.
  const incSet = include ? new Set(include) : null;
  const inc = incSet !== null && incSet.size > 0 ? incSet : null;
  const exc = exclude ? new Set(exclude) : new Set<string>();
  let filtered = raw;
  if (inc !== null) filtered = filtered.filter((d) => inc.has(d.label));
  if (exc.size > 0) filtered = filtered.filter((d) => !exc.has(d.label));

  return resolveOverlaps(filtered);
}
