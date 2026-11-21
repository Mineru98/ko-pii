/** 성명 (Korean person name) 컨텍스트 기반 검출 — Python ko_pii.patterns.person 대응.
 *
 * 전체 파이프라인:
 *   1. 결정적 PII (RRN/PHONE/EMAIL/MEDICAL_INSURANCE) 위치를 별도 패스에서
 *      식별해 두고, 그 근방을 "deterministic_nearby" 플래그로 표시.
 *   2. 후보 추출: 2~4글자 한글 토큰 + 성씨 시작.
 *   3. 컨텍스트 점수 (`scoreCandidate`) 로 평가.
 *   4. 임계값 이상이면 emit + 누적 사전 등록.
 *   5. 누적 사전 보유 이름은 약한 단서로 등장해도 두 번째 패스에서 emit.
 *
 * Legal basis: 개인정보보호법 제2조 (성명을 통한 개인 식별).
 */

import { hasUnitTail } from "../context/addressUnits.js";
import {
  type AgencySentenceCache,
  agencySentenceBoundaries,
  makeNameCandidate,
  type NameCandidate,
  scoreCandidate,
} from "../context/contextRules.js";
import { literalNameFields, literalNameMentions } from "../context/literalNameFields.js";
import { NameDictionary } from "../context/nameDictionary.js";
import {
  boundedNameValueEnd,
  nameFieldBefore,
  nameListSeparator,
  nameRoleBefore,
  PERSON_NAME_LABELS,
} from "../context/nameFields.js";
import { classifyNameOrigin } from "../context/nameOrigin.js";
import { nameShapeBonus } from "../context/nameSyllables.js";
import { stripTrailingParticle } from "../context/particles.js";
import { pyFormatFixed } from "../core/pyFormat.js";
import { cpWindowAfter, PY_S, PY_S_CHARS } from "../core/strUtils.js";
import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";
import { normalizeUnicode } from "../core/unicodeNorm.js";
import { isAgency } from "../dictionaries/agencies.js";
import { normalizeAgency } from "../dictionaries/agencyAbbrev.js";
import { isValidAgencyTitle } from "../dictionaries/agencyTitles.js";
import { isCommonWord } from "../dictionaries/commonWords.js";
import {
  isCommonDong,
  isCountry,
  isDistrict,
  isExtraCity,
  isProvince,
} from "../dictionaries/districts.js";
import { isFieldLabel } from "../dictionaries/fieldLabels.js";
import { surnamePrefixLen } from "../dictionaries/surnames.js";
import { isTitle } from "../dictionaries/titles.js";
import { isUniversity } from "../dictionaries/universities.js";

const LABEL = "PERSON";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

// 이름 후보: 한글 2~4글자 (조사 포함하면 더 길어질 수 있음)
const _CANDIDATE_SRC = "(?<![가-힣])([가-힣]{2,7})(?![가-힣])";
const _CANDIDATE = new RegExp(_CANDIDATE_SRC, "g");
const _EMPTY_FIELD_ITEM = "(?:n/a|n\\.a\\.|na|null|none)";
// Python re.IGNORECASE + 유니코드 \w (u 플래그).
const _FIELD_ITEM = new RegExp(
  `${_CANDIDATE_SRC}|(?<empty>(?<![\\p{L}\\p{N}_/])(?:__${_EMPTY_FIELD_ITEM}__|${_EMPTY_FIELD_ITEM})(?![\\p{L}\\p{N}_/]))`,
  "giu",
);
const _FLOOR_AFTER = /[ \t]*[0-9]+층/y;
const _ROOM_AFTER = /[ \t]*[0-9]+(?:호실|호|층)/y;

/** Python str.isdecimal() (단일 문자) — Nd. */
function _isDecimal(ch: string | undefined): boolean {
  return ch !== undefined && /^\p{Nd}$/u.test(ch);
}

/** Python ``text[i - 1]`` — 코드 포인트 단위 (아스트랄 Nd 인 수학 숫자도 한 글자). */
function _charBefore(text: string, i: number): string {
  const lo = text.charCodeAt(i - 1);
  return lo >= 0xdc00 && lo <= 0xdfff && i >= 2 ? text.slice(i - 2, i) : text.slice(i - 1, i);
}

function _isAddressUnitContext(text: string, start: number, name: string): boolean {
  if (start > 0 && _isDecimal(_charBefore(text, start))) {
    for (const unit of ["호실", "호", "동", "층"]) {
      if (name.startsWith(unit) && hasUnitTail(text, start + unit.length)) {
        return true;
      }
    }
  }
  let pattern: RegExp;
  if (name === "지하" || name === "지상") {
    pattern = _FLOOR_AFTER;
  } else if (name.length === 2 && name.endsWith("동")) {
    pattern = _ROOM_AFTER;
  } else {
    return false;
  }
  pattern.lastIndex = start + name.length;
  const match = pattern.exec(text);
  return match !== null && hasUnitTail(text, match.index + match[0].length);
}

// 결정적 PII 의 *위치 마커* 만 빠르게 찾기 위한 보조 패턴 (성능)
const _DETERMINISTIC_HINTS = new RegExp(
  String.raw`(?<![0-9])\p{Nd}{6}-?\p{Nd}{7}(?![0-9])` +
    String.raw`|01[01679][-.${PY_S_CHARS}]?\p{Nd}{3,4}[-.${PY_S_CHARS}]?\p{Nd}{4}` +
    String.raw`|[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}`,
  "gu",
);

// 한국어 동사/형용사·계사(이다) 활용형. 이름은 거의 이 형태로 끝나지 않음.
const _VERB_LIKE_SUFFIXES: readonly string[] = [
  // 하다 활용
  "하다",
  "하고",
  "하여",
  "하지",
  "하니",
  "하면",
  "한다",
  "한",
  "할",
  "함",
  "하기",
  "하는",
  "하신",
  "하시",
  "하셨",
  "하셔",
  "하게",
  "하며",
  "하면서",
  "했다",
  "했고",
  "했지",
  "했음",
  "했으며",
  // 되다 활용
  "되다",
  "되고",
  "되어",
  "되지",
  "되니",
  "되면",
  "된다",
  "된",
  "될",
  "됨",
  "되기",
  "되는",
  "되며",
  "되었",
  // 드리다 활용
  "드린",
  "드리는",
  "드리고",
  "드립니다",
  "드린다",
  "드리며",
  // 이다 계사 + 명사화 (단계임/사실임/현실임 등)
  "임",
  "임을",
  "임에",
  "임으로",
  "임에도",
  "임이",
  "인",
  "인지",
  "인데",
  "인가",
  "이라",
  // 형용사 관형형 / 활용형 (강한·이상한·민감한 등 — surname-시작 2~3자 빈출)
  "운",
  "운데",
  "운지",
  "라운",
  "로운",
  "스러운",
  "이다",
  "이며",
  "이지만",
  "이라서",
  // 부사형
  "히",
  // 어미 자주 끝
  "에서",
  "에는",
  "에도",
  "에게",
];

// 부분 가명 (이미 가명화된 표기) — PII 가 아니므로 거부
const _ANONYMIZED_MARKERS: ReadonlySet<string> = new Set(["씨", "모", "군", "양"]);

function _looksLikeAnonymized(raw: string): boolean {
  return raw.length === 2 && _ANONYMIZED_MARKERS.has(raw[1] ?? "");
}

// 한국어 명사 접미사 / 복수 표지 — 사람 이름에는 거의 안 등장
const _NOUN_SUFFIXES_FORBIDDEN: readonly string[] = [
  "들",
  "성",
  "력",
  "감",
  "률",
  "적",
  // 안전 확장 (이름 끝 글자 절대 충돌 없는 것만)
  "증",
  "점",
  "팀",
  "부",
  "처",
  "회",
  "료",
  "님",
  "측",
  "쪽",
];

function _looksLikeCommonNounSuffix(raw: string): boolean {
  return raw.length >= 3 && _NOUN_SUFFIXES_FORBIDDEN.some((s) => raw.endsWith(s));
}

// 토큰 마지막 글자가 *명확한 동사 활용 어미* 면 거부.
const _VERB_ENDINGS_FINAL: ReadonlySet<string> = new Set([
  "다",
  "네",
  "요",
  "까",
  "잖",
  "면",
  "려",
]);

// 토큰 마지막 글자가 *명확한 조사 부착* 형태이면 거부.
const _PARTICLE_FINAL: ReadonlySet<string> = new Set([
  "은",
  "는",
  "이",
  "가",
  "을",
  "를",
  "의",
  "에",
  "로",
  "와",
  "과",
]);

// 한국어 *어말 연결어미 + 종결 어미* 패턴 — 2자 이상 suffix.
const _COMMON_KOREAN_ENDINGS: readonly string[] = [
  // 연결어미
  "은데",
  "는데",
  "라서",
  "어서",
  "아서",
  "면서",
  "다가",
  "지만",
  "거나",
  "더라",
  "더라도",
  "이라도",
  "고요",
  "는걸",
  "는군",
  "더군",
  "는데요",
  "거든",
  "을까",
  "을지",
  "려고",
  "려면",
  "도록",
  "토록",
  // 종결어미 (반말·존댓말 변형)
  "이에요",
  "예요",
  "이고",
  "이며",
  "이니",
  "이라",
  "입니다",
  "이지요",
  // 조사 결합
  "에서",
  "에게",
  "한테",
  "보다",
  "처럼",
  "마다",
  "조차",
  "마저",
  "부터",
  "까지",
  "라고",
  "이라고",
];

function _endsWithCommonKoreanEnding(raw: string): boolean {
  return _COMMON_KOREAN_ENDINGS.some((end) => raw.endsWith(end));
}

function _endsWithVerbOrParticle(raw: string): boolean {
  if (!raw) {
    return false;
  }
  const last = raw[raw.length - 1] ?? "";
  return _VERB_ENDINGS_FINAL.has(last) || _PARTICLE_FINAL.has(last);
}

// 한국어 동사 어간 빈출 패턴 — "다" 없이 종결되어 candidate 가 매칭되는 형태
const _VERB_STEM_FINAL_PATTERNS: readonly string[] = [
  "추정되",
  "재미있",
  "재밌",
  "나오",
  "들어가",
  "들어와",
  "만드",
  "만들",
  "만나",
  "흐르",
];

function _looksLikeVerbStem(raw: string): boolean {
  return _VERB_STEM_FINAL_PATTERNS.some((p) => raw.endsWith(p));
}

// 토큰 안에 직책이 *포함* 된 경우 — 예: "강회장이", "김의원이", "박교수가"
const _EMBEDDED_TITLE_SUFFIXES: readonly string[] = [
  "회장",
  "사장",
  "이사",
  "대표",
  "대표이사",
  "부사장",
  "전무",
  "상무",
  "본부장",
  "팀장",
  "실장",
  "센터장",
  "원장",
  "지점장",
  // 회사 직급 (성씨 1자 + 직급 = 호칭, PII 아님 — "김부장" "박과장" 등)
  "부장",
  "과장",
  "차장",
  "주임",
  "대리",
  "사원",
  "수석",
  "선임",
  "책임",
  "전임",
  "의원",
  "장관",
  "차관",
  "총리",
  "비서관",
  "보좌관",
  "교수",
  "박사",
  "강사",
  "의사",
  "약사",
  "간호사",
  "한의사",
  "변호사",
  "검사",
  "판사",
  "법무사",
  "대사",
  "총영사",
  "영사",
  "선수",
  "감독",
  "코치",
  "기자",
  "PD",
  "작가",
];

// Python sorted(key=len, reverse=True) — 길이 내림차순, 동률은 원본 순서(안정).
const _EMBEDDED_TITLE_SUFFIXES_BY_LEN: readonly string[] = [..._EMBEDDED_TITLE_SUFFIXES].sort(
  (a, b) => b.length - a.length,
);

/** ``"강회장"`` → ``["강", "회장"]``. 분리 안 되면 ``[stem, null]``.
 *
 * 조건: stem 끝이 직책으로 끝나야 하고, 앞부분이 1~3자 한글이어야 한다.
 */
function _splitEmbeddedTitle(stem: string): [string, string | null] {
  for (const suf of _EMBEDDED_TITLE_SUFFIXES_BY_LEN) {
    if (stem.endsWith(suf) && stem.length > suf.length) {
      const front = stem.slice(0, stem.length - suf.length);
      if (front.length >= 1 && front.length <= 3) {
        let allHangul = true;
        for (const ch of front) {
          const code = ch.codePointAt(0) as number;
          if (code < 0xac00 || code > 0xd7a3) {
            allHangul = false;
            break;
          }
        }
        if (allHangul) {
          return [front, suf];
        }
      }
    }
  }
  return [stem, null];
}

// 이름 끝 음절 자주 등장 패턴 — recall 보강용 보너스 (강한 신호 아님)
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

function _hasNameLikeFinal(stem: string): boolean {
  return stem.length >= 2 && _NAME_FINAL_SYLLABLES.has(stem[stem.length - 1] ?? "");
}

// 나이·성별·신원 단서 — 이름 인접 시 PERSON 확신 ↑
// "홍길동(32세)", "홍길동 32세", "홍길동, 남자", "홍길동(남)"
// Python ``세\b`` 는 유니코드 \w 기준 — JS ASCII \b 와 달라 아래 lookahead 로 재현.
const _NOT_PY_WORD_AFTER = "(?![\\p{L}\\p{N}_])";
const _AGE_GENDER_PATTERN = new RegExp(
  String.raw`${PY_S}*\(${PY_S}*(?:\p{Nd}{1,3}${PY_S}*세|남자|여자|남|여|미혼|기혼)${PY_S}*\)` +
    String.raw`|${PY_S}*,${PY_S}*(?:\p{Nd}{1,3}${PY_S}*세|남자|여자|미혼|기혼)` +
    String.raw`|${PY_S}+\p{Nd}{1,3}${PY_S}*세${_NOT_PY_WORD_AFTER}`,
  "yu",
);

// 3중 매크로 패턴 — <AGENCY> <PERSON> <TITLE>
// 예: "기획재정부 김민수 장관", "환경부 박영수 차관", "경찰청 이형사 경감"
const _MACRO_GAP = `(?:${PY_S}+|[${PY_S_CHARS}\\-/])`;
const _MACRO_AGENCY_PERSON_TITLE = new RegExp(
  `(?<![가-힣A-Za-z0-9])([가-힣]{2,15}(?:부|처|청|위원회|원|국|실|단|장|소))${_MACRO_GAP}([가-힣]{2,4})${_MACRO_GAP}([가-힣]{2,8})(?![가-힣A-Za-z0-9])`,
  "dgu",
);

type MacroMatch = [number, number, string, string, string];

/** 매크로 패턴 매칭 → ``[person_start, person_end, agency, person, title]``.
 *
 * 조건: agency 가 *알려진 기관* (또는 약칭) 이고, title 이 *해당 기관에서
 * 유효* 한 직급/직위.
 */
function _macroMatches(text: string): MacroMatch[] {
  const out: MacroMatch[] = [];
  for (const m of text.matchAll(_MACRO_AGENCY_PERSON_TITLE)) {
    const agency = m[1]!;
    const personCand = m[2]!;
    const titleCand = m[3]!;
    // agency 검증 — 사전 + 약칭
    let canonicalAgency: string | null = null;
    if (isAgency(agency)) {
      canonicalAgency = agency;
    } else {
      const normalized = normalizeAgency(agency);
      if (normalized) {
        canonicalAgency = normalized;
      }
    }
    if (canonicalAgency === null) {
      continue;
    }
    // title 검증 — 해당 기관에서 유효한가?
    if (!isValidAgencyTitle(canonicalAgency, titleCand)) {
      continue;
    }
    // person 후보 위치 — group(2) 시작
    const indices = m.indices?.[2];
    if (indices === undefined) {
      continue;
    }
    out.push([indices[0]!, indices[1]!, canonicalAgency, personCand, titleCand]);
  }
  return out;
}

// Python str.strip() whitespace 클래스 근사
const _PY_WS_CLASS =
  "[\\t\\n\\u000b\\u000c\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const _RE_PY_STRIP = new RegExp(`^${_PY_WS_CLASS}+|${_PY_WS_CLASS}+$`, "g");

function _pyStrip(s: string): string {
  return s.replace(_RE_PY_STRIP, "");
}

function _hasAgeOrGenderAfter(text: string, end: number, window = 12): string | null {
  const tail = cpWindowAfter(text, end, window);
  _AGE_GENDER_PATTERN.lastIndex = 0;
  const m = _AGE_GENDER_PATTERN.exec(tail);
  if (m) {
    return _pyStrip(m[0]!);
  }
  return null;
}

function _looksLikeVerbForm(token: string): boolean {
  return _VERB_LIKE_SUFFIXES.some((s) => token.endsWith(s));
}

// 행정구역 접미사. "경기도", "성남시", "가평군" 등.
const _ADMIN_UNIT_CHARS: ReadonlySet<string> = new Set(["시", "군", "구", "도", "읍", "면", "리"]);
const _STREET_SUFFIXES: readonly string[] = ["대로", "로", "길"];

function _looksLikeAdminUnit(raw: string): boolean {
  return raw.length >= 2 && _ADMIN_UNIT_CHARS.has(raw[raw.length - 1] ?? "");
}

function _looksLikeStreetName(raw: string): boolean {
  return raw.length >= 3 && _STREET_SUFFIXES.some((s) => raw.endsWith(s));
}

/** 호출 단위 PERSON 오탐 제외어 검증·정규화 (Python ``normalize_exclusions``). */
export function normalizeExclusions(exclusions: Iterable<string> | null | undefined): Set<string> {
  if (exclusions === null || exclusions === undefined) return new Set();
  if (typeof exclusions === "string" || exclusions instanceof Uint8Array) {
    throw new TypeError("person exclusions must be an iterable of strings, not a string");
  }
  const normalized = new Set<string>();
  for (const value of exclusions as Iterable<unknown>) {
    if (typeof value !== "string") {
      throw new TypeError("person exclusions must contain only strings");
    }
    const folded = _pyStrip(normalizeUnicode(value)[0]);
    if (folded) normalized.add(folded);
  }
  return normalized;
}

/** PERSON 값이 정규화된 제외어와 정확히 일치하는가 (Python ``is_person_excluded``). */
export function isPersonExcluded(value: string, exclusions: ReadonlySet<string>): boolean {
  if (exclusions.size === 0) return false;
  return exclusions.has(_pyStrip(normalizeUnicode(value)[0]));
}

function _isCommonOrExcluded(value: string, exclusions: ReadonlySet<string>): boolean {
  return isPersonExcluded(value, exclusions) || isCommonWord(value);
}

const _UNSET_NAME_VALUES: ReadonlySet<string> = new Set([
  "없음",
  "미상",
  "익명",
  "비공개",
  "미기재",
  "미입력",
  "미등록",
  "미작성",
  "정보없음",
  "알수없음",
  "해당없음",
  "생략",
  "공란",
  "무기명",
]);
const _NAME_DECLARATION_ENDINGS: readonly string[] = [
  "이라고",
  "이라는",
  "입니다",
  "이며",
  "이고",
  "이라",
];

function _splitDeclarationEnding(raw: string): [string, string | null] {
  for (const ending of _NAME_DECLARATION_ENDINGS) {
    if (
      raw.endsWith(ending) &&
      raw.length - ending.length >= 2 &&
      raw.length - ending.length <= 4
    ) {
      return [raw.slice(0, raw.length - ending.length), ending];
    }
  }
  return [raw, null];
}

function _rejectLabeledValue(
  value: string,
  label: string,
  exclusions: ReadonlySet<string>,
): boolean {
  if (_UNSET_NAME_VALUES.has(value) || isFieldLabel(value) || isPersonExcluded(value, exclusions)) {
    return true;
  }
  return (
    !PERSON_NAME_LABELS.has(label) &&
    (isCommonWord(value) ||
      isTitle(value) ||
      isAgency(value) ||
      normalizeAgency(value) !== null ||
      isProvince(value) ||
      isDistrict(value) ||
      isCountry(value) ||
      isCommonDong(value) ||
      isExtraCity(value) ||
      isUniversity(value) ||
      ["은행", "회사", "팀", "부서"].some((suffix) => value.endsWith(suffix)) ||
      _looksLikeAnonymized(value))
  );
}

function _labeledNameValues(
  text: string,
  exclusions: ReadonlySet<string>,
): Array<[NameCandidate, string]> {
  const out: Array<[NameCandidate, string]> = [];
  let previousLabel: string | null = null;
  let previousEnd = 0;
  for (const match of text.matchAll(_FIELD_ITEM)) {
    const raw = match[1];
    const mStart = match.index;
    const mEnd = mStart + match[0].length;
    let label = nameFieldBefore(text, mStart);
    if (label === null && previousLabel !== null && nameListSeparator(text, previousEnd, mStart)) {
      label = previousLabel;
    }
    previousLabel = null;
    if (label === null || !boundedNameValueEnd(text, mEnd)) continue;
    previousLabel = label;
    previousEnd = mEnd;
    if (raw === undefined) continue;
    const [stem, particle] = stripTrailingParticle(raw);
    // 경계가 분명한 2~4음절 필드는 그 자체가 조사처럼 보이는 음절로 끝날 수 있다 —
    // 유효한 전체 이름 일부를 남기지 않도록 통째로 둔다.
    const value = particle !== null && raw.length > 4 ? stem : raw;
    if (value.length < 2 || value.length > 4) continue;
    // 제외/빈 항목이 다음 목록 항목의 보호를 멈추면 안 된다.
    if (
      _rejectLabeledValue(raw, label, exclusions) ||
      _rejectLabeledValue(value, label, exclusions)
    ) {
      continue;
    }
    out.push([makeNameCandidate(value, mStart, mStart + value.length), label]);
  }
  return out;
}

function _fieldEvidence(text: string, candidate: NameCandidate, label: string): string[] {
  const evidence = ["pattern:person_name_field", `pos:field_label(${label})`];
  if (nameFieldBefore(text, candidate.start) === null) {
    evidence.push("pattern:person_name_field_list");
  }
  return evidence;
}

function _declaredNameValues(
  text: string,
  exclusions: ReadonlySet<string>,
  knownNames: ReadonlySet<string>,
): Array<[NameCandidate, string, string | null]> {
  const out: Array<[NameCandidate, string, string | null]> = [];
  for (const match of text.matchAll(_CANDIDATE)) {
    const raw = match[1] as string;
    const mStart = match.index;
    if (knownNames.has(raw) || isPersonExcluded(raw, exclusions)) continue;
    const fieldLabel = nameFieldBefore(text, mStart);
    const roleLabel = fieldLabel === null ? nameRoleBefore(text, mStart) : null;
    const label = fieldLabel ?? roleLabel;
    if (label === null) continue;
    let [value, ending] = _splitDeclarationEnding(raw);
    if (ending === null) continue;
    const bounded = boundedNameValueEnd(text, mStart + match[0].length);
    // 짧고 경계가 분명한 역할 값은 리터럴 필드와 같은 모호성을 가진다.
    if (roleLabel && raw.length <= 4 && bounded && !knownNames.has(value)) {
      value = raw;
      ending = null;
    }
    if (value.length < 2 || value.length > 4 || _rejectLabeledValue(value, label, exclusions)) {
      continue;
    }
    out.push([makeNameCandidate(value, mStart, mStart + value.length), label, ending]);
  }
  return out;
}

function _declarationEvidence(label: string, ending: string | null): string[] {
  const evidence = ["pattern:person_name_declaration", `pos:name_role(${label})`];
  if (ending !== null) evidence.push(`pos:copula(${ending})`);
  return evidence;
}

export interface PersonDetectOptions {
  /** 이 호출에서 PERSON 으로 내보내지 않을 도메인 용어 (패키지 사전은 변경하지 않음). */
  exclusions?: Iterable<string> | null;
}

/** PERSON 검출 (Python detect 대응 — 문서 단위 누적 사전은 호출마다 새로 생성). */
export function detect(text: string, options: PersonDetectOptions = {}): DetectionResult[] {
  return _detectWithDict(text, new NameDictionary(), normalizeExclusions(options.exclusions));
}

/** 이미 정규화된 제외어 집합으로 검출 (detectAll 내부용 — 재정규화 생략). */
export function detectWithExclusions(
  text: string,
  exclusions: ReadonlySet<string>,
): DetectionResult[] {
  return _detectWithDict(text, new NameDictionary(), exclusions);
}

type EmittedEntry = [NameCandidate, string | null, number, string[]];
type PendingEntry = [NameCandidate, number, string[], string | null];

/** Python ``bisect_left``. */
function _bisectLeft(arr: readonly number[], x: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((arr[mid] as number) < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

const _spanKey = (start: number, end: number): string => `${start},${end}`;

function _detectWithDict(
  text: string,
  nameDict: NameDictionary,
  exclusions: ReadonlySet<string> = new Set(),
): DetectionResult[] {
  const deterministicSpans: Array<[number, number]> = [];
  for (const m of text.matchAll(_DETERMINISTIC_HINTS)) {
    deterministicSpans.push([m.index, m.index + m[0].length]);
  }
  const deterministicEndpoints = deterministicSpans.flat();
  const threshold = 0.5;
  // 문장별 '기관 포함 여부' 캐시 — score_candidate 와 공유 (O(n²) 방지)
  const agencyCache: AgencySentenceCache = new Map();
  const agencyBoundaries = agencySentenceBoundaries(text);

  const parsedFields = literalNameFields(text);
  const excludedFields = parsedFields.filter((c) => isPersonExcluded(c.name, exclusions));
  // Python set[tuple] — 키 문자열로 집합화하고 정렬 시 숫자 튜플로 되돌린다.
  const excludedSpans = new Map<string, [number, number]>();
  for (const c of excludedFields) excludedSpans.set(_spanKey(c.start, c.end), [c.start, c.end]);
  for (const [start, end] of literalNameMentions(
    text,
    excludedFields.map((c) => c.name),
  )) {
    excludedSpans.set(_spanKey(start, end), [start, end]);
  }
  const literalFields = parsedFields.filter(
    (c) =>
      !_rejectLabeledValue(c.name, c.parenthetical ? "이름" : c.label, exclusions) &&
      !_UNSET_NAME_VALUES.has(c.name.replaceAll(" ", "")),
  );
  const literalBySpan = new Map<string, (typeof literalFields)[number]>();
  for (const c of literalFields) literalBySpan.set(_spanKey(c.start, c.end), c);
  const literalSpans = new Map<string, [number, number, string | null]>();
  for (const [start, end, ending] of literalNameMentions(
    text,
    literalFields.map((c) => c.name),
  )) {
    literalSpans.set(_spanKey(start, end), [start, end, ending]);
  }
  // 선언 값은 밑줄로 감싸일 수 있다 — 재사용은 여전히 단어 경계가 필요하다.
  for (const [key, c] of literalBySpan) literalSpans.set(key, [c.start, c.end, c.ending]);
  type SpanLike = readonly [number, number, ...unknown[]];
  const byTuple = (a: SpanLike, b: SpanLike): number => a[0] - b[0] || a[1] - b[1];
  const literalValues: EmittedEntry[] = [];
  for (const [start, end, ending] of [...literalSpans.values()].sort(byTuple)) {
    const direct = literalBySpan.get(_spanKey(start, end));
    const evidence =
      direct !== undefined
        ? [
            "pattern:person_name_field",
            "pattern:person_literal_name_field",
            `pos:field_label(${direct.label})`,
          ]
        : ["pos:confirmed_name_field_reuse", "pattern:person_literal_name_field"];
    if (ending !== null) evidence.push(`pos:confirmed_name_ending(${ending})`);
    literalValues.push([
      makeNameCandidate(text.slice(start, end), start, end),
      null,
      0.9,
      evidence,
    ]);
  }
  const occupied: Array<[number, number]> = [];
  const claimedSpans = new Map<string, [number, number]>();
  for (const [start, end] of literalSpans.values())
    claimedSpans.set(_spanKey(start, end), [start, end]);
  for (const [key, span] of excludedSpans) claimedSpans.set(key, span);
  for (const [start, end] of [...claimedSpans.values()].sort(byTuple)) {
    const last = occupied[occupied.length - 1];
    if (last !== undefined && start < last[1]) {
      last[1] = Math.max(last[1], end);
    } else {
      occupied.push([start, end]);
    }
  }
  const literalStarts = occupied.map(([start]) => start);
  // 정확히 제외된 값도 부분 legacy 후보에 대해 자기 span 을 예약한다.
  const reservedSpans = new Map<string, [number, number]>();
  for (const c of literalFields) {
    if (!c.legacy) reservedSpans.set(_spanKey(c.start, c.end), [c.start, c.end]);
  }
  for (const [key, span] of excludedSpans) reservedSpans.set(key, span);
  const extendedDirect = [...reservedSpans.values()].sort(byTuple);
  const extendedStarts = extendedDirect.map(([start]) => start);
  const extendedEnds: number[] = [];
  for (const [, end] of extendedDirect) {
    const prev = extendedEnds[extendedEnds.length - 1];
    extendedEnds.push(prev !== undefined ? Math.max(prev, end) : end);
  }

  const claimed = (start: number, end: number): boolean => {
    const index = _bisectLeft(literalStarts, end) - 1;
    return index >= 0 && (occupied[index] as [number, number])[1] > start;
  };
  const reserved = (start: number, end: number): boolean => {
    const index = _bisectLeft(extendedStarts, end) - 1;
    return index >= 0 && (extendedEnds[index] as number) > start;
  };

  const labeledValues = new Map<string, [NameCandidate, string]>();
  for (const [candidate, label] of _labeledNameValues(text, exclusions)) {
    if (!reserved(candidate.start, candidate.end)) {
      labeledValues.set(_spanKey(candidate.start, candidate.end), [candidate, label]);
    }
  }
  const fieldNames = new Set<string>([...labeledValues.values()].map(([c]) => c.name));
  const declarations = new Map<number, [NameCandidate, string, string | null]>();
  for (const [candidate, label, ending] of _declaredNameValues(text, exclusions, fieldNames)) {
    if (!reserved(candidate.start, candidate.end)) {
      declarations.set(candidate.start, [candidate, label, ending]);
    }
  }
  for (const [candidate] of declarations.values()) fieldNames.add(candidate.name);
  for (const [candidate, label] of labeledValues.values()) {
    nameDict.add(
      candidate.name,
      0.9,
      [candidate.start, candidate.end],
      _fieldEvidence(text, candidate, label),
    );
  }
  for (const [candidate, label, ending] of declarations.values()) {
    nameDict.add(
      candidate.name,
      0.9,
      [candidate.start, candidate.end],
      _declarationEvidence(label, ending),
    );
  }

  // ------ Pass 0: 3중 매크로 패턴 — <AGENCY> <PERSON> <TITLE>
  // 고신뢰 인명 추출 + 누적 사전에 *즉시 등록* → 같은 문서 내 다른 등장도
  // 누적 사전 부스트로 잡힘
  const macroSpans = new Set<string>();
  for (const [pStart, pEnd, agency, personText, title] of _macroMatches(text)) {
    if (claimed(pStart, pEnd)) continue;
    // 합리성 추가 검증 — 이름 부분이 common_word 가 아닌지
    if (_isCommonOrExcluded(personText, exclusions)) continue;
    // field_label / title 자체는 PERSON 이 아님
    if (isFieldLabel(personText) || isTitle(personText)) continue;
    if (isAgency(personText) || normalizeAgency(personText) !== null) continue;
    const evidence = [
      "pattern:macro_agency_person_title",
      `pos:agency(${agency})`,
      `pos:title_validated(${title})`,
    ];
    // 매크로 통과 = 0.95 신뢰
    nameDict.add(personText, 0.95, [pStart, pEnd], evidence);
    macroSpans.add(_spanKey(pStart, pEnd));
  }

  const pending: PendingEntry[] = [];
  const emitted: EmittedEntry[] = [];
  // 매크로로 잡은 것은 우선 emit
  for (const [pStart, pEnd, agency, personText, title] of _macroMatches(text)) {
    if (claimed(pStart, pEnd)) continue;
    if (_isCommonOrExcluded(personText, exclusions)) continue;
    if (isFieldLabel(personText) || isTitle(personText)) continue;
    if (isAgency(personText) || normalizeAgency(personText) !== null) continue;
    const cand = makeNameCandidate(personText, pStart, pEnd);
    const evidence = [
      "pattern:macro_agency_person_title",
      `pos:agency(${agency})`,
      `pos:title_validated(${title})`,
    ];
    emitted.push([cand, null, 0.95, evidence]);
  }
  // ------ Pass A
  for (const m of text.matchAll(_CANDIDATE)) {
    const raw = m[1] as string;
    const mStart = m.index;
    const mEnd = mStart + m[0].length;
    if (claimed(mStart, mEnd)) continue;
    if (isPersonExcluded(raw, exclusions)) continue;
    // 매크로로 이미 잡힌 span 은 중복 emit 방지
    if (macroSpans.has(_spanKey(mStart, mStart + raw.length))) continue;
    const declaration = declarations.get(mStart);
    if (declaration !== undefined) {
      const [candidate, label, ending] = declaration;
      emitted.push([candidate, null, 0.9, _declarationEvidence(label, ending)]);
      continue;
    }
    if (fieldNames.size > 0) {
      const [name, ending] = _splitDeclarationEnding(raw);
      if (ending !== null && fieldNames.has(name) && !fieldNames.has(raw)) {
        const candidate = makeNameCandidate(name, mStart, mStart + name.length);
        emitted.push([
          candidate,
          null,
          0.9,
          ["pos:confirmed_name_field_reuse", `pos:copula(${ending})`],
        ]);
        continue;
      }
    }
    let [stem, particle] = stripTrailingParticle(raw);
    if (fieldNames.has(raw) || fieldNames.has(stem)) {
      if (fieldNames.has(raw)) {
        stem = raw;
        particle = null;
      }
      const cand = makeNameCandidate(stem, mStart, mStart + stem.length);
      const labeled = labeledValues.get(_spanKey(cand.start, cand.end));
      const evidence =
        labeled !== undefined
          ? _fieldEvidence(text, cand, labeled[1])
          : ["pos:confirmed_name_field_reuse"];
      if (particle) evidence.push(`pos:particle(${particle})`);
      emitted.push([cand, particle, 0.9, evidence]);
      continue;
    }
    const candidateLabel = nameFieldBefore(text, mStart);
    const labelBefore = candidateLabel !== null;
    if (
      candidateLabel !== null &&
      boundedNameValueEnd(text, mEnd) &&
      _rejectLabeledValue(raw, candidateLabel, exclusions)
    ) {
      continue;
    }
    // Reject raw tokens that match an agency in the dictionary, or look
    // like an administrative-unit name (경기도, 성남시, 가평군) — unless
    // a person-field label is right before.
    if (!labelBefore) {
      if (
        isAgency(raw) ||
        normalizeAgency(raw) !== null ||
        isProvince(raw) ||
        isDistrict(raw) ||
        _looksLikeAdminUnit(raw) ||
        _looksLikeStreetName(raw)
      ) {
        continue;
      }
    }
    // Try stripping a trailing particle to get the bare name
    if (stem.length < 2 || stem.length > 4) continue;
    // 유형 호실/층 문법은 일반 이름 단서가 아니다. 명시적 사람 필드와 이 문서에서 이미
    // 확인된 이름이 우선한다.
    if (!labelBefore && _isAddressUnitContext(text, mStart, stem)) continue;
    // 부분 가명 표기 (박씨/이모/김군) — 이미 익명화된 표기이므로 거부
    if (_looksLikeAnonymized(stem)) continue;
    if (_isCommonOrExcluded(stem, exclusions)) continue;
    // Skip tokens that are themselves dictionary words (field label,
    // title, agency) — those are infrastructure markers, not names.
    if (isFieldLabel(stem) || isTitle(stem) || isAgency(stem)) continue;
    // Skip 행정구역명·국가명 — LC_ADDRESS 영역이지 PERSON 아님
    if (
      isProvince(stem) ||
      isDistrict(stem) ||
      isCountry(stem) ||
      isCommonDong(stem) ||
      isExtraCity(stem)
    ) {
      continue;
    }
    // Skip 학교명 (정식명·약칭 모두 universities 사전 활용)
    if (isUniversity(stem)) continue;
    if (
      stem.endsWith("대학교") ||
      stem.endsWith("고등학교") ||
      stem.endsWith("중학교") ||
      stem.endsWith("초등학교")
    ) {
      continue;
    }
    // Skip 은행명 (...은행 끝나는 토큰)
    if (stem.endsWith("은행")) continue;
    // Skip tokens that look like Korean verb/adjective conjugations.
    if (_looksLikeVerbForm(stem)) continue;
    // Skip 복수형 (X들) / 명사 접미사 (X성·X력·X감 등) — 사람 이름 아님
    if (_looksLikeCommonNounSuffix(stem)) continue;
    // Skip 동사 어간 패턴 (나오·추정되·재미있 등)
    if (_looksLikeVerbStem(stem)) continue;
    // Skip 토큰 끝이 동사 어미/조사 부착 형태 (KDPII FP 분석)
    // 단, 2자 토큰은 surname+이름 패턴이 흔하므로 예외 (성씨 확실한 경우에만)
    if (stem.length >= 3 && _endsWithVerbOrParticle(stem)) continue;
    // Skip 토큰이 흔한 한국어 어말로 끝남 ("같은데/먹는데/하라서" 등)
    if (stem.length >= 3 && _endsWithCommonKoreanEnding(stem)) continue;

    // Embedded title — "강회장이" 같이 토큰 안에 직책이 들어있으면
    // 직책 부분 떼고 앞부분 (성+이름 후보) 만 사용
    let embeddedTitle: string | null = null;
    const [front, titleSuffix] = _splitEmbeddedTitle(stem);
    if (titleSuffix !== null && front.length >= 2) {
      stem = front;
      embeddedTitle = titleSuffix;
    } else if (titleSuffix !== null && front.length === 1) {
      // 1자 + 직책 (예: "강회장") — 1자 단독은 신뢰도 너무 낮음 → 거부
      continue;
    }
    if (isPersonExcluded(stem, exclusions)) continue;

    // Heuristic: skip tokens without any leading surname unless the
    // field label is right before (we'll let the scorer decide).
    const sp = surnamePrefixLen(stem);
    const roleBefore = sp === 0 && !labelBefore ? nameRoleBefore(text, mStart) : null;
    if (sp === 0 && !labelBefore && roleBefore === null) continue;

    const candStart = mStart;
    const candEnd = mStart + stem.length;
    const cand = makeNameCandidate(stem, candStart, candEnd);
    const detNearby = _isWithin(deterministicEndpoints, candStart, 25);
    // 추가 신호: 토큰 안 직책, 이름끝 음절, 나이/성별 인접, 음절 통계
    const extraSignals: string[] = [];
    let extraScore = 0.0;
    if (roleBefore !== null) extraSignals.push(`pos:name_role(${roleBefore})`);
    if (embeddedTitle !== null) {
      extraScore += 0.35;
      extraSignals.push(`pos:embedded_title(${embeddedTitle})`);
    }
    if (_hasNameLikeFinal(stem)) {
      extraScore += 0.1;
      extraSignals.push("pos:name_final_syllable");
    }
    // Method 1: 음절 통계 likelihood
    const shapeBonus = nameShapeBonus(stem);
    if (shapeBonus > 0) {
      extraScore += shapeBonus;
      extraSignals.push(`pos:name_likelihood(${pyFormatFixed(shapeBonus, 2)})`);
    }
    // 원본 토큰 끝(particle 포함) 다음 위치에서 나이/성별 단서
    const ageGender = _hasAgeOrGenderAfter(text, mEnd);
    if (ageGender) {
      extraScore += 0.3;
      extraSignals.push(`pos:age_gender_after(${ageGender})`);
    }
    const score = scoreCandidate(
      text,
      cand,
      detNearby,
      nameDict.boostFor(stem),
      agencyCache,
      agencyBoundaries,
    );
    // 추가 신호 합산
    const totalValue = Math.min(1.0, score.value + extraScore);
    const totalEvidence = [...score.evidence, ...extraSignals];

    // 동적 threshold:
    // - 2자 토큰: 끝 글자가 *이름 글자가 아니면* 엄격 (+0.10)
    // - 3자+ 토큰: 기본 임계값
    // - field_label 가 직전에 있거나 직책이 명시되면 기본 임계값
    let effThreshold = threshold;
    if (
      stem.length === 2 &&
      !_hasNameLikeFinal(stem) &&
      !labelBefore &&
      embeddedTitle === null &&
      !totalEvidence.join(" ").includes("pos:field_label") &&
      !totalEvidence.join(" ").includes("pos:title")
    ) {
      effThreshold = threshold + 0.1;
      totalEvidence.push("threshold:strict_short");
    }

    if (totalValue >= effThreshold) {
      nameDict.add(stem, totalValue, [candStart, candEnd], totalEvidence);
      emitted.push([cand, particle, totalValue, totalEvidence]);
    } else {
      pending.push([cand, totalValue, totalEvidence, particle]);
    }
  }

  // ------ Method 2: 같은 문장 내 후보 상호 보강 (Co-occurrence Boost)
  // Pass A 에서 *높은 신뢰* PERSON 이 잡힌 문장의 *약한 후보* 들도 +0.15
  // 보강 후 임계값 재평가.
  const sentenceBoundaries = _findSentenceBoundaries(text);
  const strongSentenceIds = new Set<number>();
  for (const [candidate] of labeledValues.values()) {
    strongSentenceIds.add(_sentenceId(candidate.start, sentenceBoundaries));
  }
  for (const [cand, , scoreV] of emitted) {
    if (scoreV >= 0.7) {
      strongSentenceIds.add(_sentenceId(cand.start, sentenceBoundaries));
    }
  }

  const coBoosted: EmittedEntry[] = [];
  const stillPending: PendingEntry[] = [];
  for (const [cand, scoreV, ev, particle] of pending) {
    const sid = _sentenceId(cand.start, sentenceBoundaries);
    if (strongSentenceIds.has(sid)) {
      const boostedScore = Math.min(1.0, scoreV + 0.15);
      const boostedEv = [...ev, "pos:co_occurrence_in_sentence"];
      if (boostedScore >= threshold) {
        coBoosted.push([cand, particle, boostedScore, boostedEv]);
        nameDict.add(cand.name, boostedScore, [cand.start, cand.end], boostedEv);
        continue;
      }
    }
    stillPending.push([cand, scoreV, ev, particle]);
  }

  // 모두 emit
  const results: DetectionResult[] = [];
  for (const [cand, particle, scoreV, ev] of [...literalValues, ...emitted, ...coBoosted]) {
    results.push(_emit(cand, particle, scoreV, ev));
  }

  // ------ Pass B: re-score remaining pending using the now-populated dictionary
  for (const [cand, , , particle] of stillPending) {
    const boost = nameDict.boostFor(cand.name);
    if (boost <= 0) continue;
    const rescored = scoreCandidate(
      text,
      cand,
      _isWithin(deterministicEndpoints, cand.start, 25),
      boost,
      agencyCache,
      agencyBoundaries,
    );
    if (rescored.value >= threshold) {
      results.push(_emit(cand, particle, rescored.value, rescored.evidence));
    }
  }

  return results;
}

/** 정렬된 끝점 목록에서 pos±window 안의 끝점 존재 여부 (Python ``_is_within`` endpoints 경로). */
function _isWithin(endpoints: readonly number[], pos: number, window = 25): boolean {
  const index = _bisectLeft(endpoints, pos - window);
  return index < endpoints.length && (endpoints[index] as number) <= pos + window;
}

function _emit(
  cand: NameCandidate,
  particle: string | null,
  score: number,
  evidence: string[],
): DetectionResult {
  const origin = classifyNameOrigin(cand.name);
  return makeDetection({
    label: LABEL,
    text: cand.name,
    start: cand.start,
    end: cand.end,
    riskLevel: RiskLevel.HIGH,
    confidence: score,
    evidence: [...evidence, `origin:${origin}`],
    legal_basis: LEGAL_BASIS,
    extra: {
      category: CATEGORY,
      particle,
      origin,
    },
  });
}

// ---------------------------------------------------------------------
// Method 2 보조: 문장 경계 (마침표·줄바꿈·물음표·느낌표)
// ---------------------------------------------------------------------

function _findSentenceBoundaries(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "." || ch === "!" || ch === "?" || ch === "\n") {
      if (i + 1 < text.length) {
        starts.push(i + 1);
      }
    }
  }
  return starts;
}

function _sentenceId(pos: number, boundaries: number[]): number {
  // Python: bisect.bisect_right(boundaries, pos) - 1
  let lo = 0;
  let hi = boundaries.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (pos < (boundaries[mid] as number)) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }
  return Math.max(0, lo - 1);
}
