/** 생년월일 (Date of Birth) detection — Python ko_pii.patterns.birth 대응.
 *
 * 지원 포맷:
 *   - 1988년 1월 1일 / 1988년 01월 01일
 *   - 1988.1.1 / 1988.01.01 / 1988-01-01 / 1988/01/01
 *   - 88년 1월 1일 / 88.1.1 (2자리 연도)
 *   - 880101 (RRN 앞 6자리 — 키워드 anchor 필수)
 *   - 88년생 / 1988년생
 *
 * 키워드 anchor (단순 날짜 vs 생년월일 구분):
 *   - "생년월일" / "생일" / "출생" / "DOB" 등
 *   - "년생" suffix (88년생 = 1988년생)
 *   - 키워드 없는 단순 날짜 (예: "2024년 4월 15일 회의") 는 검출 안 함
 */
import { stripTrailingParticle } from "../context/particles.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";
import { isCommonWord } from "../dictionaries/commonWords.js";
import { surnamePrefixLen } from "../dictionaries/surnames.js";
import { isTitle } from "../dictionaries/titles.js";

const LABEL = "DT_BIRTH";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "준식별자";

// 한국어 키워드 anchor — 25자 윈도우 (대화체 변형 포함)
const _KEYWORDS: readonly string[] = [
  "생년월일",
  "생일",
  "출생일",
  "출생",
  "탄생",
  "태어난",
  "태어났",
  "태어나",
  "DOB",
  "Date of Birth",
  "Birth Date",
  "birthday",
];

// 명시적 비-생일 일자 키워드 — 직전에 있으면 DT_BIRTH 거부 (공문서에 흔함)
// 보도자료 "배포일자", 회의 "회의일자", 결재 "시행일자", 인사 "발령일자" 등.
const _NON_BIRTH_KEYWORDS: readonly string[] = [
  "선고일자",
  "선고일",
  "심사일자",
  "심사일",
  "처리일자",
  "처리일",
  "회의일자",
  "회의일",
  "시행일자",
  "시행일",
  "공포일자",
  "공포일",
  "배포일자",
  "배포일",
  "발령일자",
  "발령일",
  "접수일자",
  "접수일",
  "회신일자",
  "회신일",
  "통보일자",
  "통보일",
  "처분일자",
  "처분일",
  "발급일자",
  "발급일",
  "유효기간",
  "평가기간",
  "계약기간",
  "감사기간",
  "출동일자",
  "종결일자",
  "작성일자",
  "발생일시",
  "발생일",
  "발효일",
  "효력 발생일",
  "결재일자",
  "결재일",
  "회계기간",
  "회계연도",
  "기준일",
  // 식약처 제품 라벨 일자 — 생년월일이 아니라 제품 기한/일자.
  "사용기한",
  "유통기한",
  "제조일자",
  "제조일",
  "제조연월일",
  "소비기한",
  "유효일자",
  "유효일",
  "포장일자",
  "포장일",
  "출고일자",
  "출고일",
];

function _hasNonBirthKeywordBefore(text: string, start: number, window = 15): boolean {
  const head = text.slice(Math.max(0, start - window), start);
  return _NON_BIRTH_KEYWORDS.some((kw) => head.includes(kw));
}

// 패턴 1: YYYY년 M월 D일 / YYYY년 MM월 DD일
const _PATTERN_KOREAN =
  /(?<![0-9])([0-9]{4}|[0-9]{2})\s*년\s*([0-9]{1,2})\s*월\s*([0-9]{1,2})\s*일/g;

// 패턴 2: YYYY.M.D / YYYY-MM-DD / YYYY/MM/DD / YY.MM.DD (구분자 통일 — 후방참조 \2)
const _PATTERN_NUMERIC = /(?<![0-9])([0-9]{2,4})([./-])([0-9]{1,2})\2([0-9]{1,2})(?![0-9])/g;

// 패턴 3: YY년생 / YYYY년생 (연도만)
const _PATTERN_BIRTH_YEAR = /(?<![0-9])([0-9]{2,4})\s*년\s*생/g;

function _normalizeYear(year: number): number | null {
  // 2자리 연도를 4자리로 정규화. 1900 ~ 현재년도 범위만 허용.
  const currentYear = new Date().getFullYear();
  let y = year;
  if (y < 100) {
    // 2자리: 현재 년도 뒤두자리 이하면 20XX, 그 이상은 19XX
    y = y <= currentYear % 100 ? 2000 + y : 1900 + y;
  }
  if (1900 <= y && y <= currentYear) {
    return y;
  }
  return null;
}

function _validDate(year: number, month: number, day: number): boolean {
  // 월/일 + 윤년 검증 (Python date(year, month, day) 성공 여부와 동일)
  const d = new Date(year, month - 1, day);
  return d.getFullYear() === year && d.getMonth() === month - 1 && d.getDate() === day;
}

function _hasKeywordBefore(text: string, start: number, window = 25): string | null {
  const head = text.slice(Math.max(0, start - window), start);
  for (const kw of _KEYWORDS) {
    if (head.includes(kw)) {
      return kw;
    }
  }
  return null;
}

function _hasBirthMarkerAfter(text: string, end: number): boolean {
  // 패턴 매치 끝 뒤에 '생' (예: "88년생") 이 붙어있는지.
  return text.slice(end, end + 2).startsWith("생");
}

// 이름 끝 음절 자주 등장 패턴 — ko_pii.patterns.person._NAME_FINAL_SYLLABLES 와
// 동일한 데이터 (person.ts 미포팅 상태이므로 로컬 복제 — 원본 frozenset 과 set 으로
// 동등하도록 중복 항목을 정리했다).
const _NAME_FINAL_SYLLABLES: ReadonlySet<string> = new Set([
  // 남자 이름 빈출
  "수",
  "호",
  "준",
  "훈",
  "진",
  "민",
  "철",
  "혁",
  "한",
  "현",
  "성",
  "석",
  "환",
  "식",
  "원",
  "운",
  "웅",
  "용",
  "영",
  "정",
  "재",
  "균",
  "근",
  "광",
  "관",
  "구",
  "규",
  "기",
  "길",
  "동",
  "두",
  "찬",
  "충",
  "탁",
  "태",
  "택",
  "필",
  // 여자 이름 빈출
  "지",
  "희",
  "은",
  "미",
  "주",
  "경",
  "선",
  "연",
  "린",
  "옥",
  "유",
  "윤",
  "이",
  "인",
  "임",
  "자",
  "전",
  "조",
  "참",
  "채",
  "혜",
  "화",
  "효",
  "후",
  "흠",
  "흥",
  // 중성
  "아",
  "야",
  "예",
  "오",
  "우",
]);

// 한국어 조사·동사 활용 종결 — 풀네임 끝 글자가 이걸로 끝나면 일반 어휘
const _PARTICLE_CHARS: ReadonlySet<string> = new Set("는은이가도을를의에로와과만");
const _VERB_ENDINGS: ReadonlySet<string> = new Set("다네요지까려면고잖야아어라사세"); // 동사·형용사 활용

// 이름 끝에 잘 안 오는 글자 (안전망)
const _NON_NAME_FINAL: ReadonlySet<string> = new Set([..._PARTICLE_CHARS, ..._VERB_ENDINGS]);

// 3~5자 한글 토큰 — 조사 stripping 까지 시도 (이하이가 → 이하이)
const _HANGUL_TOKEN = /(?<![가-힣])([가-힣]{3,5})(?![가-힣])/g;

function _hasPersonContextNearby(text: string, start: number, end: number, window = 15): boolean {
  // 매치 *주변* 15자 윈도우에 *풀네임 인명* 패턴이 있는지.
  //
  // 조건:
  //   1) 정확히 3-4자 한글 토큰
  //   2) 첫 글자가 성씨
  //   3) 마지막 글자가 조사 (는/은/이/가/도/...) 가 *아님* — "회의는" 거부
  //   4) common_word·title 아님
  //
  // "이계용, 88년 7월 4일" → "이계용" = "용" (조사 X) → True
  // "96년 7월 29일 조윤경" → "조윤경" → True
  // "회의는 2024년 4월 15일" → "회의는" → "는" 조사 → False
  const head = text.slice(Math.max(0, start - window), start);
  const tail = text.slice(end, end + window);
  for (const chunk of [head, tail]) {
    for (const m of chunk.matchAll(_HANGUL_TOKEN)) {
      // biome-ignore lint/style/noNonNullAssertion: 정규식 그룹 보장 접근
      const raw = m[1]!;
      // 조사 떨기 — 예: "이하이가" → ("이하이", "가")
      const [token] = stripTrailingParticle(raw);
      if (token.length < 2 || token.length > 4) {
        continue;
      }
      if (surnamePrefixLen(token) === 0) {
        continue;
      }
      // biome-ignore lint/style/noNonNullAssertion: 정규식 그룹 보장 접근
      const last = token[token.length - 1]!;
      if (_NON_NAME_FINAL.has(last)) {
        continue; // 조사·동사 활용 어미 = 일반 단어
      }
      if (!_NAME_FINAL_SYLLABLES.has(last)) {
        continue;
      }
      if (isCommonWord(token) || isTitle(token)) {
        continue;
      }
      return true;
    }
  }
  return false;
}

export function detect(text: string): DetectionResult[] {
  const seen: [number, number][] = [];
  const results: DetectionResult[] = [];

  // 패턴 1: 한국어 (YYYY년 M월 D일)
  for (const m of text.matchAll(_PATTERN_KOREAN)) {
    // biome-ignore lint/style/noNonNullAssertion: 정규식 그룹 보장 접근
    const mStart = m.index!;
    // biome-ignore lint/style/noNonNullAssertion: 정규식 그룹 보장 접근
    const mEnd = mStart + m[0]!.length;
    const year = _normalizeYear(Number(m[1]!));
    if (year === null) {
      continue;
    }
    const month = Number(m[2]!);
    const day = Number(m[3]!);
    if (!_validDate(year, month, day)) {
      continue;
    }
    // 명시적 비-생일 키워드 ("선고일자/시행일자/배포일자" 등) 직전 → 거부
    if (_hasNonBirthKeywordBefore(text, mStart)) {
      continue;
    }
    const kw = _hasKeywordBefore(text, mStart);
    // context anchor 완화: 키워드 없어도 (a) "년생" marker (b) 풀네임 인접 OK
    const hasMarker = _hasBirthMarkerAfter(text, mEnd);
    const hasNameCtx = _hasPersonContextNearby(text, mStart, mEnd);
    if (kw === null && !hasMarker && !hasNameCtx) {
      continue; // 단순 날짜 (회의·작성일 등) — 거부
    }
    seen.push([mStart, mEnd]);
    results.push(
      makeDetection({
        label: LABEL,
        text: m[0]!,
        start: mStart,
        end: mEnd,
        riskLevel: RiskLevel.HIGH,
        confidence: 0.95,
        evidence: [
          "pattern:birth_korean",
          `date:${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`,
          kw ? `keyword:${kw}` : "marker:생",
        ],
        legal_basis: LEGAL_BASIS,
        extra: {
          year: year,
          month: month,
          day: day,
          format: "korean",
          category: CATEGORY,
        },
      }),
    );
  }

  // 패턴 2: 숫자 구분자 (YYYY.M.D)
  for (const m of text.matchAll(_PATTERN_NUMERIC)) {
    const mStart = m.index!;
    const mEnd = mStart + m[0]!.length;
    if (seen.some(([s, e]) => mStart < e && s < mEnd)) {
      continue;
    }
    const year = _normalizeYear(Number(m[1]!));
    if (year === null) {
      continue;
    }
    const month = Number(m[3]!);
    const day = Number(m[4]!);
    if (!_validDate(year, month, day)) {
      continue;
    }
    // 명시적 비-생일 키워드 직전 → 거부
    if (_hasNonBirthKeywordBefore(text, mStart)) {
      continue;
    }
    const kw = _hasKeywordBefore(text, mStart);
    // 숫자 날짜: 키워드 또는 풀네임 인접 필요
    if (kw === null && !_hasPersonContextNearby(text, mStart, mEnd)) {
      continue;
    }
    seen.push([mStart, mEnd]);
    results.push(
      makeDetection({
        label: LABEL,
        text: m[0]!,
        start: mStart,
        end: mEnd,
        riskLevel: RiskLevel.HIGH,
        confidence: 0.9,
        evidence: [
          "pattern:birth_numeric",
          `date:${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`,
          `keyword:${kw === null ? "None" : kw}`,
        ],
        legal_basis: LEGAL_BASIS,
        extra: {
          year: year,
          month: month,
          day: day,
          format: "numeric",
          category: CATEGORY,
        },
      }),
    );
  }

  // 패턴 3: YY년생 (연도만, "생" marker 자체가 anchor)
  for (const m of text.matchAll(_PATTERN_BIRTH_YEAR)) {
    const mStart = m.index!;
    const mEnd = mStart + m[0]!.length;
    if (seen.some(([s, e]) => mStart < e && s < mEnd)) {
      continue;
    }
    const year = _normalizeYear(Number(m[1]!));
    if (year === null) {
      continue;
    }
    seen.push([mStart, mEnd]);
    results.push(
      makeDetection({
        label: LABEL,
        text: m[0]!,
        start: mStart,
        end: mEnd,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 0.85,
        evidence: ["pattern:birth_year_only", `year:${year}`, "marker:년생"],
        legal_basis: LEGAL_BASIS,
        extra: {
          year: year,
          format: "year_only",
          category: CATEGORY,
        },
      }),
    );
  }

  return results;
}
