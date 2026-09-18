/** 인적 속성 (Personal Attributes) — 학력·전공·직책·측정치.
 * Python ko_pii.patterns.personal_attr 대응.
 *
 * 검출 카테고리:
 * - ``EDUCATION`` : 대학교/전문대 (사전 매칭)
 * - ``MAJOR``     : 전공·학과 (사전 + suffix 정규화)
 * - ``POSITION``  : 직책·직급 (titles 사전, 단독 emit)
 * - ``AGE``       : 32세 / 32살
 * - ``HEIGHT``    : 175cm / 1.75m
 * - ``WEIGHT``    : 70kg / 70kilo
 *
 * Legal basis: 개인정보보호법 제2조; 「개인정보 비식별 조치 가이드라인」
 * 준식별자 (Quasi-Identifier) 분류.
 */
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";
import { isMajor, normalizeMajor } from "../dictionaries/majors.js";
import { isTitle, titleDomain } from "../dictionaries/titles.js";
import { isUniversity, normalizeUniversity } from "../dictionaries/universities.js";

const LEGAL_BASIS = "개인정보보호법 제2조";

// ---------------------------------------------------------------------------
// Python float str() 재현 — 정수값 float 은 "175.0" 형태 (JS String 은 "175")
// ---------------------------------------------------------------------------
function pyFloatStr(x: number): string {
  if (Number.isInteger(x) && Math.abs(x) < 1e16) {
    return `${x}.0`;
  }
  return String(x);
}

// Python str.strip() whitespace 클래스 근사
const _PY_WS_CLASS =
  "[\\t\\n\\u000b\\u000c\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const _RE_PY_STRIP = new RegExp(`^${_PY_WS_CLASS}+|${_PY_WS_CLASS}+$`, "g");

function pyStrip(s: string): string {
  return s.replace(_RE_PY_STRIP, "");
}

type Span = [number, number];

function spanSeenExact(span: Span, seen: Span[]): boolean {
  return seen.some(([s, e]) => s === span[0] && e === span[1]);
}

function spanOverlapsSeen(span: Span, seen: Span[]): boolean {
  return seen.some(([s, e]) => span[0] < e && s < span[1]);
}

// ═══════════════════════════════════════════════════════════════════════
// EDUCATION (학력)
// ═══════════════════════════════════════════════════════════════════════
// 대학교 정식명: 2-15자 + (대학교/대학/대학원/전문대학/대학원대학교)
// 약칭: 2-5자 + 대 (서울대/연대/고대 등) — 사전 매칭 필수
// 외국어 약칭: KAIST/POSTECH/UNIST/GIST/DGIST
// 초중고: 2-10자 + (초/중/고/초등학교/중학교/고등학교)
const _EDUCATION_PATTERN =
  /(?<![가-힣A-Za-z])(?:(?<full>[가-힣]{2,15}(?:대학교|대학원대학교|전문대학|대학원|대학))|(?<abbrev>[가-힣]{1,5}대)|(?<eng>KAIST|POSTECH|UNIST|GIST|DGIST)|(?<kor>카이스트|포스텍|유니스트|지스트|디지스트)|(?<elem>[가-힣]{2,10}초등학교|[가-힣]{2,8}초)|(?<mid>[가-힣]{2,10}중학교|[가-힣]{2,8}중)|(?<high>[가-힣]{2,10}고등학교|[가-힣]{2,8}고))(?![가-힣A-Za-z])/dg;

const _SCHOOL_ANCHORS: readonly string[] = [
  "졸업",
  "다녀",
  "다닌",
  "출신",
  "재학",
  "입학",
  "퇴학",
  "전학",
  "모교",
  "동문",
  "동창",
];

function hasSchoolAnchor(text: string, start: number, end: number, window = 15): boolean {
  const head = text.slice(Math.max(0, start - window), start);
  const tail = text.slice(end, end + window);
  return _SCHOOL_ANCHORS.some((kw) => head.includes(kw) || tail.includes(kw));
}

export function detectEducation(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  for (const m of text.matchAll(_EDUCATION_PATTERN)) {
    const raw = m[0]!;
    const mStart = m.index!;
    const mEnd = mStart + raw.length;
    const groups = m.indices?.groups;
    const inGroup = (name: string): boolean => groups?.[name] !== undefined;
    let canonical: string;
    let eduType: string;
    // 약칭이면 사전 검증
    if (inGroup("abbrev")) {
      if (!isUniversity(raw)) {
        continue;
      }
      canonical = normalizeUniversity(raw);
      eduType = "university_abbrev";
    } else if (inGroup("full") || inGroup("eng") || inGroup("kor")) {
      if (!isUniversity(raw)) {
        continue;
      }
      canonical = normalizeUniversity(raw);
      eduType = "university";
    } else if (inGroup("elem")) {
      // 정식명 (X초등학교) 은 anchor 없이도 OK, 약칭 (X초) 은 anchor 필수
      canonical = raw;
      eduType = "elementary_school";
      if (raw.endsWith("초") && !raw.endsWith("초등학교")) {
        if (!hasSchoolAnchor(text, mStart, mEnd)) {
          continue;
        }
      }
    } else if (inGroup("mid")) {
      canonical = raw;
      eduType = "middle_school";
      if (raw.endsWith("중") && !raw.endsWith("중학교")) {
        if (!hasSchoolAnchor(text, mStart, mEnd)) {
          continue;
        }
      }
    } else if (inGroup("high")) {
      canonical = raw;
      eduType = "high_school";
      if (raw.endsWith("고") && !raw.endsWith("고등학교")) {
        if (!hasSchoolAnchor(text, mStart, mEnd)) {
          continue;
        }
      }
    } else {
      continue;
    }
    results.push(
      makeDetection({
        label: "EDUCATION",
        text: raw,
        start: mStart,
        end: mEnd,
        riskLevel: RiskLevel.MEDIUM,
        confidence: eduType.startsWith("university") ? 0.95 : 0.85,
        evidence: ["pattern:education", `type:${eduType}`, `canonical:${canonical}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", canonical, type: eduType },
      }),
    );
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// MAJOR (전공)
// ═══════════════════════════════════════════════════════════════════════
// 명확한 학과/학부/전공 suffix — lookahead 없음 (조사 부착 "경영학과니까" 매칭).
const _MAJOR_PATTERN_LONG = /(?<![가-힣A-Za-z])([가-힣]{1,11}(?:학과|학부|전공))/g;

// 짧은 학/과 suffix — 합성어 거부 위해 lookahead 유지 ("법학", "의예과").
const _MAJOR_PATTERN_SHORT = /(?<![가-힣A-Za-z])([가-힣]{1,10}(?:학|과))(?![가-힣A-Za-z])/g;

// 단과대 약칭 — 의대/공대/미대/약대/법대/치대/한의대 등 (KDPII gold 빈출)
const _MAJOR_FACULTY_ABBREV: ReadonlySet<string> = new Set([
  "의대",
  "치대",
  "한의대",
  "약대",
  "수의대",
  "의과대학",
  "법대",
  "행정대",
  "경상대학",
  "경상대",
  "공대",
  "미대",
  "음대",
  "체대",
  "예대",
  "사범대",
  "신학대",
  "농대",
  "건축대",
  "경영대",
  "생과대",
]);
const _MAJOR_FACULTY_PATTERN = /(?<![가-힣A-Za-z])([가-힣]{2,4})(?![가-힣A-Za-z])/g;

export function detectMajor(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  const seen: Span[] = [];
  // 1) 학과/학부/전공 suffix (lookahead 없음 — 조사 부착도 매칭)
  for (const m of text.matchAll(_MAJOR_PATTERN_LONG)) {
    const raw = m[1]!;
    if (!isMajor(raw)) {
      continue;
    }
    const span: Span = [m.index!, m.index! + raw.length];
    if (spanSeenExact(span, seen)) {
      continue;
    }
    seen.push(span);
    const canonical = normalizeMajor(raw);
    results.push(
      makeDetection({
        label: "MAJOR",
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.LOW,
        confidence: 0.9,
        evidence: ["pattern:major", `canonical:${canonical}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", canonical },
      }),
    );
  }
  // 2) 짧은 학/과 suffix — "법학", "의예과", "수학" 등
  for (const m of text.matchAll(_MAJOR_PATTERN_SHORT)) {
    const raw = m[1]!;
    if (!isMajor(raw)) {
      continue;
    }
    const span: Span = [m.index!, m.index! + raw.length];
    if (spanOverlapsSeen(span, seen)) {
      continue;
    }
    seen.push(span);
    const canonical = normalizeMajor(raw);
    results.push(
      makeDetection({
        label: "MAJOR",
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.LOW,
        confidence: 0.85,
        evidence: ["pattern:major_short", `canonical:${canonical}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", canonical },
      }),
    );
  }
  // 3) 단과대 약칭 — 의대/공대/미대/약대/법대 등 (KDPII gold MAJOR 로 라벨)
  for (const m of text.matchAll(_MAJOR_FACULTY_PATTERN)) {
    const raw = m[1]!;
    if (!_MAJOR_FACULTY_ABBREV.has(raw)) {
      continue;
    }
    const span: Span = [m.index!, m.index! + raw.length];
    if (spanOverlapsSeen(span, seen)) {
      continue;
    }
    seen.push(span);
    results.push(
      makeDetection({
        label: "MAJOR",
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.LOW,
        confidence: 0.8,
        evidence: ["pattern:major_faculty_abbrev"],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", canonical: raw, kind: "faculty_abbrev" },
      }),
    );
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// POSITION (직책)
// ═══════════════════════════════════════════════════════════════════════
// titles 사전을 사용 — 단독 직책 emit (PERSON 컨텍스트와 별개)
// *키워드 anchor 필수* — "직급:" "직책:" "직위:" 등이 있어야 단독 emit.
const _POSITION_ANCHORS: readonly string[] = ["직급", "직책", "직위", "보직", "직군"];
const _POSITION_PATTERN = /(?<![가-힣A-Za-z])([가-힣]{1,6})(?![가-힣A-Za-z])/g;

function positionAnchorBefore(text: string, start: number, window = 12): string | null {
  const head = text.slice(Math.max(0, start - window), start);
  for (const kw of _POSITION_ANCHORS) {
    if (head.includes(kw)) {
      return kw;
    }
  }
  return null;
}

// lookahead 제거 — "부장님께/부장님이/팀장님일" 같은 조사 부착 허용
const _POSITION_HONORIFIC_PATTERN = /(?<![가-힣A-Za-z])([가-힣]{1,6})님/g;

export function detectPosition(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  const seen: Span[] = [];
  // 1) 키워드 anchor 모드 ("직급:/직책:/직위:")
  for (const m of text.matchAll(_POSITION_PATTERN)) {
    const raw = m[1]!;
    if (!isTitle(raw)) {
      continue;
    }
    const kw = positionAnchorBefore(text, m.index!);
    if (kw === null) {
      continue;
    }
    const span: Span = [m.index!, m.index! + raw.length];
    if (spanSeenExact(span, seen)) {
      continue;
    }
    seen.push(span);
    const domain = titleDomain(raw) ?? "unknown";
    results.push(
      makeDetection({
        label: "POSITION",
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.LOW,
        confidence: 0.85,
        evidence: ["pattern:position", `keyword:${kw}`, `domain:${domain}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", domain },
      }),
    );
  }

  // 2) 호칭 모드 — "부장님", "사장님", "팀장님" 같이 "님" suffix 가 붙은 직급
  //    KDPII 대화체에서 빈번 ("아 저 재무팀 김명진 과장님 만나러 왔는데요")
  for (const m of text.matchAll(_POSITION_HONORIFIC_PATTERN)) {
    const raw = m[1]!;
    if (!isTitle(raw)) {
      continue;
    }
    // 호칭 자체 ("부장님") 보다는 직급 부분만 ("부장") emit
    const span: Span = [m.index!, m.index! + raw.length];
    if (spanOverlapsSeen(span, seen)) {
      continue;
    }
    seen.push(span);
    const domain = titleDomain(raw) ?? "unknown";
    results.push(
      makeDetection({
        label: "POSITION",
        text: raw,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.LOW,
        confidence: 0.8,
        evidence: ["pattern:position_honorific", `domain:${domain}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", domain, honorific: true },
      }),
    );
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// AGE / HEIGHT / WEIGHT (측정치)
// ═══════════════════════════════════════════════════════════════════════
// "32세/30살" — 조사·연결어미 다양 ("30살인데/30살밖에/41세이다").
// 원본 주석: "한글 lookahead 제거 — KDPII gold 와 substring overlap 최대화".
// 뒤쪽 가드는 숫자 직후만 거부한다 — 한글 어미(세이다/세다)는 매칭 허용.
const _AGE_PATTERN = /(?<![0-9])([0-9]{1,3})\s*(?:세|살)(?![0-9])/g;

// 연령대 — "30대/20대 후반/40대 초반" 등 ("X0대" 형식, 10~99)
const _AGE_RANGE_PATTERN = /(?<![0-9])([0-9]{1,2}0)대(?![0-9가-힣])/g;

// 한글 음역 — "서른두 살", "스물여섯 살", "마흔 다섯 살" 등
const _KOREAN_AGE_TENS: ReadonlyArray<readonly [string, number]> = [
  ["열", 10],
  ["스물", 20],
  ["서른", 30],
  ["마흔", 40],
  ["쉰", 50],
  ["예순", 60],
  ["일흔", 70],
  ["여든", 80],
  ["아흔", 90],
];
const _KOREAN_AGE_ONES: ReadonlyMap<string, number> = new Map([
  ["한", 1],
  ["두", 2],
  ["세", 3],
  ["네", 4],
  ["다섯", 5],
  ["여섯", 6],
  ["일곱", 7],
  ["여덟", 8],
  ["아홉", 9],
]);
const _KOREAN_AGE_PATTERN =
  /(?<![가-힣])(스무|(?:열|스물|서른|마흔|쉰|예순|일흔|여든|아흔)(?:\s*(?:한|두|세|네|다섯|여섯|일곱|여덟|아홉))?|한|두|세|네|다섯|여섯|일곱|여덟|아홉)\s*살/g;

// 한자어 나이 명사 — 환갑/칠순/팔순 등 (60대 이상 명시적 호칭)
const _KOREAN_AGE_NOUN: ReadonlyMap<string, number> = new Map([
  ["환갑", 60],
  ["회갑", 60],
  ["진갑", 61],
  ["고희", 70],
  ["칠순", 70],
  ["고희연", 70],
  ["산수", 80],
  ["팔순", 80],
  ["구순", 90],
  ["졸수", 90],
  ["백수", 99],
  ["백세", 100],
]);
const _KOREAN_AGE_NOUN_PATTERN =
  /(?<![가-힣])(환갑|회갑|진갑|고희연|고희|칠순|산수|팔순|구순|졸수|백수|백세)(?![가-힣])/g;

// 영유아 연령 — N개월 + 키워드 anchor ("아기/돌/생후/만") 필요
const _INFANT_MONTH_PATTERN = /(?<![0-9])([0-9]{1,2})\s*개월(?![0-9])/g;
const _INFANT_ANCHORS: readonly string[] = [
  "아기",
  "아이",
  "딸",
  "아들",
  "둘째",
  "첫째",
  "생후",
  "만 ",
  "되었",
  "되었어",
  "되었네",
  "지났",
  "돌",
  "출산",
];

const _HEIGHT_PATTERN =
  /(?<![0-9.])([0-9]{2,3}(?:\.[0-9]{1,2})?)\s*(?:cm|센티(?:미터)?|㎝)(?![A-Za-z])/gi;

// 키 (m 단위): 1.75m / 1m75 — 위험은 일반 거리와 충돌 (대소문자 구분 — Python 원본)
const _HEIGHT_M_PATTERN = /(?<![0-9.])(1\.[0-9]{1,2})\s*m(?![A-Za-z])/g;

const _WEIGHT_PATTERN =
  /(?<![0-9.])([0-9]{1,3}(?:\.[0-9]{1,2})?)\s*(?:kg|키로(?:그램)?|킬로(?:그램)?|㎏|kilogram)(?![A-Za-z])/gi;

/** '서른두', '스물여섯', '마흔다섯' 등을 숫자로 변환.
 *
 * 일의자리 단독 ("한/두/세/.../아홉") 도 지원 — "한 살" 같은 영유아 표현.
 */
function parseKoreanAge(token: string): number | null {
  // Python: token in _KOREAN_AGE_TWENTIES
  if (token === "스무") {
    return 20;
  }
  // 일의자리 단독
  const one = _KOREAN_AGE_ONES.get(token);
  if (one !== undefined) {
    return one;
  }
  // 십대 + (일의자리)
  for (const [tensKor, tensVal] of _KOREAN_AGE_TENS) {
    if (token.startsWith(tensKor)) {
      const rest = pyStrip(token.slice(tensKor.length));
      if (!rest) {
        return tensVal;
      }
      const r = _KOREAN_AGE_ONES.get(rest);
      if (r !== undefined) {
        return tensVal + r;
      }
    }
  }
  return null;
}

export function detectMeasurements(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  const seenAge: Span[] = [];
  for (const m of text.matchAll(_AGE_PATTERN)) {
    const age = Number(m[1]);
    if (0 <= age && age <= 150) {
      const span: Span = [m.index!, m.index! + m[0]!.length];
      seenAge.push(span);
      results.push(
        makeDetection({
          label: "AGE",
          text: m[0]!,
          start: span[0],
          end: span[1],
          riskLevel: RiskLevel.INFO,
          confidence: 0.95,
          evidence: ["pattern:age", `value:${age}`],
          legal_basis: LEGAL_BASIS,
          extra: { category: "준식별자", value: age, unit: "year" },
        }),
      );
    }
  }

  // 연령대 ("30대/40대 후반")
  for (const m of text.matchAll(_AGE_RANGE_PATTERN)) {
    const age = Number(m[1]);
    if (10 <= age && age <= 90) {
      const span: Span = [m.index!, m.index! + m[0]!.length];
      if (spanOverlapsSeen(span, seenAge)) {
        continue;
      }
      seenAge.push(span);
      results.push(
        makeDetection({
          label: "AGE",
          text: m[0]!,
          start: span[0],
          end: span[1],
          riskLevel: RiskLevel.INFO,
          confidence: 0.85,
          evidence: ["pattern:age_range", `value:${age}대`],
          legal_basis: LEGAL_BASIS,
          extra: { category: "준식별자", value: age, unit: "decade", format: "range" },
        }),
      );
    }
  }

  // 한글 음역
  for (const m of text.matchAll(_KOREAN_AGE_PATTERN)) {
    const span: Span = [m.index!, m.index! + m[0]!.length];
    if (spanOverlapsSeen(span, seenAge)) {
      continue;
    }
    const token = pyStrip(m[1] ?? "");
    const parsed = parseKoreanAge(token);
    if (parsed === null || !(0 <= parsed && parsed <= 99)) {
      continue;
    }
    const age = parsed;
    seenAge.push(span);
    results.push(
      makeDetection({
        label: "AGE",
        text: m[0]!,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.INFO,
        confidence: 0.85,
        evidence: ["pattern:age_korean", `value:${age}`, `token:${token}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", value: age, unit: "year", format: "korean" },
      }),
    );
  }

  // 한자어 나이 명사 (환갑/칠순/팔순 등)
  for (const m of text.matchAll(_KOREAN_AGE_NOUN_PATTERN)) {
    const span: Span = [m.index!, m.index! + m[0]!.length];
    if (spanOverlapsSeen(span, seenAge)) {
      continue;
    }
    const token = m[1]!;
    const age = _KOREAN_AGE_NOUN.get(token)!;
    seenAge.push(span);
    results.push(
      makeDetection({
        label: "AGE",
        text: m[0]!,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.INFO,
        confidence: 0.9,
        evidence: ["pattern:age_noun", `value:${age}`, `token:${token}`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", value: age, unit: "year", format: "noun" },
      }),
    );
  }

  // 영유아 연령 — N개월 + anchor 필요 (일반 N개월 차이/일정/근무 등 거부)
  for (const m of text.matchAll(_INFANT_MONTH_PATTERN)) {
    const months = Number(m[1]);
    if (!(0 <= months && months <= 60)) {
      // 5세 이하만
      continue;
    }
    const span: Span = [m.index!, m.index! + m[0]!.length];
    if (spanOverlapsSeen(span, seenAge)) {
      continue;
    }
    // anchor 윈도우 25자
    const windowStart = Math.max(0, span[0] - 25);
    const windowEnd = Math.min(text.length, span[1] + 10);
    if (!_INFANT_ANCHORS.some((a) => text.slice(windowStart, windowEnd).includes(a))) {
      continue;
    }
    seenAge.push(span);
    results.push(
      makeDetection({
        label: "AGE",
        text: m[0]!,
        start: span[0],
        end: span[1],
        riskLevel: RiskLevel.INFO,
        confidence: 0.85,
        evidence: ["pattern:age_months", `value:${months}개월`],
        legal_basis: LEGAL_BASIS,
        extra: { category: "준식별자", value: months, unit: "month", format: "infant" },
      }),
    );
  }

  for (const m of text.matchAll(_HEIGHT_PATTERN)) {
    const height = Number(m[1]);
    if (50 <= height && height <= 250) {
      results.push(
        makeDetection({
          label: "HEIGHT",
          text: m[0]!,
          start: m.index!,
          end: m.index! + m[0]!.length,
          riskLevel: RiskLevel.INFO,
          confidence: 0.9,
          evidence: ["pattern:height", `value:${pyFloatStr(height)}cm`],
          legal_basis: LEGAL_BASIS,
          extra: { category: "준식별자", value: height, unit: "cm" },
        }),
      );
    }
  }

  for (const m of text.matchAll(_HEIGHT_M_PATTERN)) {
    const heightM = Number(m[1]);
    if (0.5 <= heightM && heightM <= 2.5) {
      results.push(
        makeDetection({
          label: "HEIGHT",
          text: m[0]!,
          start: m.index!,
          end: m.index! + m[0]!.length,
          riskLevel: RiskLevel.INFO,
          confidence: 0.85,
          evidence: ["pattern:height_m", `value:${pyFloatStr(heightM)}m`],
          legal_basis: LEGAL_BASIS,
          extra: { category: "준식별자", value: heightM * 100, unit: "cm" },
        }),
      );
    }
  }

  for (const m of text.matchAll(_WEIGHT_PATTERN)) {
    const weight = Number(m[1]);
    if (1 <= weight && weight <= 300) {
      results.push(
        makeDetection({
          label: "WEIGHT",
          text: m[0]!,
          start: m.index!,
          end: m.index! + m[0]!.length,
          riskLevel: RiskLevel.INFO,
          confidence: 0.9,
          evidence: ["pattern:weight", `value:${pyFloatStr(weight)}kg`],
          legal_basis: LEGAL_BASIS,
          extra: { category: "준식별자", value: weight, unit: "kg" },
        }),
      );
    }
  }

  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// 통합 detect 진입점
// ═══════════════════════════════════════════════════════════════════════
/** 모든 인적 속성 카테고리 검출. */
export function detect(text: string): DetectionResult[] {
  return [
    ...detectEducation(text),
    ...detectMajor(text),
    ...detectPosition(text),
    ...detectMeasurements(text),
  ];
}
