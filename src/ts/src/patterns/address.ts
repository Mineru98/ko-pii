/** 주소 (Korean address) detection — Python ko_pii.patterns.address 대응.
 *
 * 도로명(road-name) 주소: 로·길·대로 + 건물번호.
 * 지번(jibun) 주소:        동·읍·면·리 + 번지(번지수).
 * 대화체 (loose):          시군구 또는 동 단독 + context keyword (살던/이사/명함 등)
 *
 * 정밀도 유지를 위해 다음 중 하나를 요구한다:
 *   - 도로/동 구성요소 바로 앞의 시·도·시·군·구 토큰, OR
 *   - 매치 20자 이내 앞의 "주소" keyword, OR
 *   - 대화체 강한 anchor (살던/거주/이사/명함 등) + 실제 행정구역 토큰
 *
 * Legal basis: 개인정보보호법 제2조 (거주지 식별 가능 정보).
 */
import { stripTrailingParticle } from "../context/particles.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";
import { ALL_DISTRICTS } from "../dictionaries/generated/districts.js";
import {
  isCommonDong,
  isCountry,
  isDistrict,
  isExtraCity,
  isLegalDong,
  isProvince,
  isValidProvinceDistrict,
} from "../dictionaries/index.js";

const LABEL = "ADDRESS";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

// 단독 행정구역 토큰 — 합성어 부분 매칭 방지 (앞뒤 한글/영숫자 거부)
const _PATTERN_ADMIN_TOKEN = /(?<![가-힣A-Za-z0-9])([가-힣]{2,6})(?![가-힣A-Za-z0-9])/g;

// 대화체 보강용 anchor — 강한 주거·접촉 정보 신호
const _LOOSE_ANCHORS: readonly string[] = [
  "주소",
  "자택",
  "거주",
  "본적",
  "사세요",
  "사신다",
  "사셨",
  "사신",
  "사세",
  "사는",
  "사니까",
  "살던",
  "살아",
  "살고",
  "산다",
  "산대",
  "이사",
  "이사하",
  "이사했",
  "명함",
];

// Optional 시·도 + 0~2 시·군·구 (성남시 분당구 같은 2단계) + road + 번지
const _PATTERN_ROAD =
  /(?:([가-힣]{1,8}(?:특별시|광역시|특별자치도|특별자치시|도))\s*)?((?:[가-힣]{1,8}(?:시|군|구)\s*){0,2})([가-힣A-Za-z0-9]{1,16}(?:대로|로|길))\s*([0-9]+(?:-[0-9]+)?)(?![0-9-])/g;

// 지번 주소: 동/읍/면/리 + 번지수 (0~2 시·군·구 허용)
const _PATTERN_JIBUN =
  /(?:([가-힣]{1,8}(?:특별시|광역시|특별자치도|특별자치시|도))\s*)?((?:[가-힣]{1,8}(?:시|군|구)\s*){0,2})([가-힣]{1,8}(?:동|읍|면|리))\s*([0-9]+(?:-[0-9]+)?)(?![0-9-])(?:\s*번지)?/g;

// 동호수 확장 패턴 — 주소 직후 "(N동N호)" / "N동 N호" / "N층" / "(아파트명)"
// sticky 플래그로 re.match(text, pos) 위치 앵커를 재현한다 (PORTING.md 참조).
const _PATTERN_DETAIL = /\s*(?:[0-9]+동\s*[0-9]+호|[0-9]+동|[0-9]+호|[0-9]+층)/y;

// 괄호 안 상세 — "(신정동,롯데캐슬킹덤아파트)" 등
const _PATTERN_PAREN_DETAIL = /\s*\([가-힣A-Za-z0-9,·\s]+\)/y;

// 건물명/단지명 — 도로명+번호 뒤 상세주소. 임의 고유명사라 사전 대신 위치로 식별.
//  (a) bridge: 뒤에 숫자 동/호/층이 이어지면 양쪽 anchor 로 끼인 건물명
//              ("월드컵북로 396 [누리꿈스퀘어] 12층")
//  (b) tail:   건물 접미사로 끝나는 토큰 — 층 없이도 포함
//              ("테헤란로 152 [강남파이낸스센터]")
const _BLDG_SUFFIX =
  // 일반 건물 유형
  "빌딩|타워|센터|스퀘어|플라자|프라자|오피스텔|아파트|맨션|하이츠|" +
  "캐슬|팰리스|레지던스|펜트하우스|" +
  // 아파트/주거 브랜드 (실존 건설사 브랜드)
  "자이|래미안|푸르지오|더샵|아이파크|힐스테이트|디에이치|e편한세상|" +
  "위브|센트레빌|롯데캐슬|데시앙|스위첸|꿈에그린|베르디움|리슈빌|코아루|" +
  "우미린|한라비발디|효성해링턴|어울림|하늘채|호반써밋|아크로|써밋|주공";
const _PATTERN_BLDG = new RegExp(
  `\\s+[가-힣A-Za-z0-9]{2,}(?=\\s+[0-9]+(?:동|호|층))` + // (a) 뒤에 동/호/층
    `|\\s+[가-힣A-Za-z0-9]*(?:${_BLDG_SUFFIX})`, // (b) 건물 접미사
  "y",
);

// 대화체 단독 주소 — 시군구 또는 동 (번지 옵션), 광역 없음
// 강한 anchor keyword 25자 윈도우 내 필수.
const _PATTERN_LOOSE =
  /(?<![가-힣])([가-힣]{2,}(?:시|군|구|동|읍|면|리))(?:\s+([가-힣]+(?:동|읍|면|리)))?(?:\s+([0-9]+(?:-[0-9]+)?))?(?![가-힣])/g;

// loose 1토큰 예외 허용 — 광역 약칭 또는 큰 시
const _LOOSE_ALLOWED_CITIES: ReadonlySet<string> = new Set([
  "서울시",
  "부산시",
  "대구시",
  "광주시",
  "대전시",
  "울산시",
  "인천시",
  "수원시",
  "고양시",
  "용인시",
]);

// admin_alone province 폴백 — 옛 5도 광역명 + 광역 시 약칭
const _ADMIN_PROVINCE_FALLBACK: ReadonlySet<string> = new Set([
  "강원도",
  "충청도",
  "전라도",
  "경상도",
  "제주도",
  "서울시",
  "부산시",
  "대구시",
  "인천시",
  "광주시",
  "대전시",
  "울산시",
]);

function _hasAnchor(
  text: string,
  start: number,
  city: string | null,
  district: string,
): string | null {
  if (city || district) {
    return "prefix";
  }
  const windowStart = Math.max(0, start - 20);
  if (text.slice(windowStart, start).includes("주소")) {
    return "keyword";
  }
  return null;
}

function _hasLooseAnchor(text: string, start: number, end: number): string | null {
  // 대화체 anchor — 매치 *주변* (앞·뒤) 25자 윈도우에서 강한 keyword 검색.
  // '살던 응암동에서' (앞) / '구로구로 이사했고' (뒤) 모두 커버.
  const head = text.slice(Math.max(0, start - 25), start);
  const tail = text.slice(end, Math.min(text.length, end + 12));
  for (const kw of _LOOSE_ANCHORS) {
    if (head.includes(kw) || tail.includes(kw)) {
      return kw;
    }
  }
  return null;
}

function _firstDistrictOf(districtsStr: string): string | null {
  // ``"성남시 분당구 "`` → ``"성남시"`` (첫 시·군·구 추출).
  if (!districtsStr) {
    return null;
  }
  const parts = districtsStr.split(/\s+/);
  return parts.length > 0 ? parts[0]! : null;
}

function _extendWithDetail(det: DetectionResult, text: string): DetectionResult {
  // 주소 검출 결과 직후 동호수/층/괄호 상세가 이어지면 span 확장.
  // 반복 적용: "396 401호 12층" → 401호 잡고 → 12층 잡고 → 끝.
  let pos = det.end;
  let extendedEnd = det.end;

  // 동호수/층 + 건물명(접미사·bridge) 반복 적용
  //   "396 누리꿈스퀘어 12층" → [건물명] 누리꿈스퀘어 → [층] 12층 순차 확장
  //   "396 401호 12층"        → [호] 401호 → [층] 12층
  for (;;) {
    _PATTERN_DETAIL.lastIndex = pos;
    let m = _PATTERN_DETAIL.exec(text);
    if (m === null) {
      _PATTERN_BLDG.lastIndex = pos;
      m = _PATTERN_BLDG.exec(text);
    }
    if (m === null) {
      break;
    }
    extendedEnd = m.index + m[0].length;
    pos = extendedEnd;
  }

  // 괄호 상세 "(신정동,롯데캐슬킹덤아파트)"
  _PATTERN_PAREN_DETAIL.lastIndex = pos;
  const m2 = _PATTERN_PAREN_DETAIL.exec(text);
  if (m2 !== null) {
    extendedEnd = m2.index + m2[0].length;
  }

  if (extendedEnd === det.end) {
    return det;
  }
  return { ...det, text: text.slice(det.start, extendedEnd).trim(), end: extendedEnd };
}

export function detect(text: string): DetectionResult[] {
  const seen: [number, number][] = [];
  const results: DetectionResult[] = [];

  // 1) 도로명 주소
  for (const m of text.matchAll(_PATTERN_ROAD)) {
    const mStart = m.index!;
    const mEnd = mStart + m[0]!.length;
    const city = m[1] ?? null;
    const districts = (m[2] ?? "").trim();
    // 시·도 prefix 가 있다면 *실제 한국 17개 광역지자체* 인지 검증
    if (city !== null && !isProvince(city)) {
      continue;
    }
    // (광역+기초) 조합 검증 — 둘 다 있으면 실제 매핑인지 확인
    // 예: "경기도 강남구 ..." → 강남구는 서울 → 거부
    const firstDistrict = _firstDistrictOf(districts);
    if (city !== null && firstDistrict !== null && !isValidProvinceDistrict(city, firstDistrict)) {
      continue;
    }
    const anchor = _hasAnchor(text, mStart, city, districts);
    if (anchor === null) {
      continue;
    }
    let det = makeDetection({
      label: LABEL,
      text: m[0]!.trim(),
      start: mStart,
      end: mEnd,
      riskLevel: RiskLevel.MEDIUM,
      confidence: 0.8,
      evidence: ["pattern:address_road", `anchor:${anchor}`],
      legal_basis: LEGAL_BASIS,
      extra: {
        format: "road_name",
        city: city,
        districts: districts,
        road: m[3] ?? null,
        building_number: m[4] ?? null,
        category: CATEGORY,
      },
    });
    det = _extendWithDetail(det, text);
    seen.push([det.start, det.end]);
    results.push(det);
  }

  // 2) 지번 주소
  for (const m of text.matchAll(_PATTERN_JIBUN)) {
    const mStart = m.index!;
    const mEnd = mStart + m[0]!.length;
    // road 패턴이 이미 점유한 span 과의 중복 거부
    if (seen.some(([s, e]) => mStart < e && s < mEnd)) {
      continue;
    }
    const city = m[1] ?? null;
    const districts = (m[2] ?? "").trim();
    // 시·도 prefix 검증 ("바티스타밤이라도" 거부)
    if (city !== null && !isProvince(city)) {
      continue;
    }
    // (광역+기초) 조합 검증
    const firstDistrict = _firstDistrictOf(districts);
    if (city !== null && firstDistrict !== null && !isValidProvinceDistrict(city, firstDistrict)) {
      continue;
    }
    const anchor = _hasAnchor(text, mStart, city, districts);
    if (anchor === null) {
      continue;
    }
    let det = makeDetection({
      label: LABEL,
      text: m[0]!.trim(),
      start: mStart,
      end: mEnd,
      riskLevel: RiskLevel.MEDIUM,
      confidence: 0.75,
      evidence: ["pattern:address_jibun", `anchor:${anchor}`],
      legal_basis: LEGAL_BASIS,
      extra: {
        format: "jibun",
        city: city,
        districts: districts,
        dong: m[3] ?? null,
        lot_number: m[4] ?? null,
        category: CATEGORY,
      },
    });
    det = _extendWithDetail(det, text);
    seen.push([det.start, det.end]);
    results.push(det);
  }

  // 3) 대화체 단독 주소 — 시군구 또는 동, 강한 keyword anchor 필요
  for (const m of text.matchAll(_PATTERN_LOOSE)) {
    const mStart = m.index!;
    const mEnd = mStart + m[0]!.length;
    // 기존 jibun/road 매치와 *인접* 한 경우 = 같은 주소의 일부일 가능성 ↑ → skip
    // (예: 가평군 청평면 청평리 45-6 에서 loose 가 "가평군 청평면" 만 떼면
    // jibun 의 "청평리 45-6" 과 인접 → 같은 주소 → loose 거부)
    const ADJACENCY = 30;
    if (seen.some(([s, e]) => mStart < e + ADJACENCY && s - ADJACENCY < mEnd)) {
      continue; // adjacent to another address match
    }
    const firstToken = m[1]!;
    // 첫 토큰이 *실제 한국 행정구역* 인지 확인 (강남구·해운대구·응암동 ...)
    // is_province 거부는 별도 — 광역명은 단독 매치 의도 아님.
    if (_LOOSE_ALLOWED_CITIES.has(firstToken)) {
      // 광역 약칭 또는 큰 시는 허용 (시군구 사전과 함께 검증)
    } else if (!ALL_DISTRICTS.has(firstToken)) {
      continue;
    }
    const anchor = _hasLooseAnchor(text, mStart, mEnd);
    if (anchor === null) {
      continue;
    }
    seen.push([mStart, mEnd]);
    results.push(
      makeDetection({
        label: LABEL,
        text: m[0]!.trim(),
        start: mStart,
        end: mEnd,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 0.6, // 대화체 = 정확도 낮음
        evidence: ["pattern:address_loose", `anchor:context_keyword(${anchor})`],
        legal_basis: LEGAL_BASIS,
        extra: {
          format: "loose",
          first_token: firstToken,
          category: CATEGORY,
        },
      }),
    );
  }

  // 4) 단독 행정구역 — anchor 필수 (대화체) + dict 매칭 (LOW risk)
  // 국가명은 nationality.ts 로 분리 — 여기서는 행정구역만.
  const ADMIN_ALONE_ADJACENCY = 50;
  for (const m of text.matchAll(_PATTERN_ADMIN_TOKEN)) {
    const mStart = m.index!;
    const mEnd = mStart + m[0]!.length;
    const rawToken = m[1]!;
    const [token, particle] = stripTrailingParticle(rawToken);
    if (token.length < 2) {
      continue;
    }
    // 국가명은 nationality.ts 에서 처리 — 여기서 건너뜀
    if (
      isCountry(token) ||
      (token.length >= 3 && token.endsWith("인") && isCountry(token.slice(0, -1)))
    ) {
      continue;
    }
    const actualEnd = mEnd - (particle !== null ? particle.length : 0);
    if (
      seen.some(
        ([s, e]) => mStart < e + ADMIN_ALONE_ADJACENCY && s - ADMIN_ALONE_ADJACENCY < actualEnd,
      )
    ) {
      continue;
    }
    let kind: string;
    if (isProvince(token) || _ADMIN_PROVINCE_FALLBACK.has(token)) {
      kind = "province";
    } else if (isDistrict(token)) {
      kind = "district";
    } else if (isExtraCity(token)) {
      kind = "city";
    } else if (isCommonDong(token)) {
      kind = "dong";
    } else if (isLegalDong(token)) {
      // 법정동 가제티어 — 빈출 동(COMMON_DONGS)보다 희귀/모호 → anchor 필수(아래)
      kind = "dong";
    } else {
      continue;
    }
    const anchor = _hasLooseAnchor(text, mStart, actualEnd);
    if (anchor === null) {
      continue;
    }
    seen.push([mStart, actualEnd]);
    results.push(
      makeDetection({
        label: LABEL,
        text: token,
        start: mStart,
        end: actualEnd,
        riskLevel: RiskLevel.LOW,
        confidence: 0.7,
        evidence: [`pattern:admin_alone(${kind})`, `dict:${kind}`, `anchor:${anchor}`],
        legal_basis: LEGAL_BASIS,
        extra: {
          format: "admin_alone",
          admin_kind: kind,
          category: CATEGORY,
        },
      }),
    );
  }

  return results;
}
