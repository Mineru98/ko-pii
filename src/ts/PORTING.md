# ko-pii Python→TypeScript 포팅 컨벤션

Python ko-pii(src/python/ko_pii)를 TypeScript(src/ts/src)로 1:1 포팅하기 위한 규칙. 골드 마스터
회귀(spec/goldmaster)가 최종 판정이므로, 애매하면 Python 동작에 맞춘다.

## 파일 매핑과 시그니처

- `src/python/ko_pii/patterns/X.py` → `src/ts/src/patterns/X.ts`
- `src/python/ko_pii/context/X.py` → `src/ts/src/context/X.ts`
- `src/python/ko_pii/domain/X.py` → `src/ts/src/domain/X.ts`
- 검출기: `def detect(text) -> Iterator[DetectionResult]` →
  `export function detect(text: string): DetectionResult[]` (generator 도 허용)
- personal_attr 처럼 보조 함수(detect_education 등)가 있으면 동일하게 export 한다.

## 핵심 타입 (이미 존재 — 수정 금지)

```ts
import { DetectionResult, RiskLevel, makeDetection } from "../core/types.js";
import { RiskLevel } from "../core/types.js"; // INFO=1 LOW=2 MEDIUM=3 HIGH=4 CRITICAL=5
```

생성: `makeDetection({ label, text, start, end, riskLevel, confidence?, evidence?, legal_basis?, extra? })`
- `confidence` 기본 1.0, `evidence` 기본 [], `legal_basis` 기본 null, `extra` 기본 {}
- 필드명은 카멜케이드 원칙이나 `legal_basis`/`extra` 는 원본 JSON 직렬화 호환을 위해
  스네이크 유지 (types.ts 참조)

## 오프셋 정책 (중요)

모든 start/end 는 **UTF-16 코드 유닛** 기준. Python 은 코드 포인트지만 아스트랄
문자(이모지)가 없는 한 수치가 동일하다. `text.slice(start, end) === det.text`
불변식을 유지할 것.

## 정규식 변환 규칙

| Python | TypeScript |
|---|---|
| `\d` | `[0-9]` (Python 은 전각도 매칭 — 원본은 정규화로 전각을 폴딩하므로 동등) |
| `(?P<name>...)` | `(?<name>...)` |
| `re.finditer(pat, s)` | `s.matchAll(new RegExp(pat, "g"))` (플래그 g 필수, lastIndex 공유 주의) |
| `re.search` / `re.match(s, pos)` | `.exec()` + sticky 플래그 `y` 와 `re.lastIndex = pos` |
| `m.start(g)` / `m.end(g)` (그룹 인덱스) | `d` 플래그 + `m.indices[g]` (Node 16.4+) 또는 래퍼 재구조화 |
| `re.escape` | `regexEscape()` (core/strUtils.ts) |
| `re.IGNORECASE` | `i` 플래그, `re.MULTILINE` → `m` |
| lookbehind `(?<!...)` | 동일 지원 (JS 가 오히려 가변폭 허용) |
| `[가-힣]` 등 범위 | 동일. 유니코드 이스케이프는 `\uAC00` 형태 권장 |

정규식 리터럴에 `g` 플래그를 쓰면 `lastIndex` 가 모듈 수준에서 공유된다. 함수 재진입
안전을 위해 matchAll 또는 호출마다 `re.lastIndex = 0` 리셋.

## Python→TS 관용구

| Python | TypeScript |
|---|---|
| `s[a:b]` | `s.slice(a, b)` |
| `s.isdigit()` (단일 문자) | `pyIsDigit()` (core/strUtils.ts) |
| `s.isalpha()` | `pyIsAlpha()` |
| `s.isascii()` | `pyIsAscii()` |
| `ch in "abc"` / `c in set` | `set.has(c)` / `includes` |
| dict `d[k]` (KeyError) | `d[k]` (`undefined` 가능 — noUncheckedIndexedAccess) |
| `for i, ch in enumerate(s)` | `for (let i = 0; i < s.length; i++) { const ch = s[i]! }` |
| tuple 반환 | `[a, b]` 튜플 |
| `f"{x}"` | 템플릿 리터럴 |
| dataclasses.replace(d, ...) | `{ ...d, field }` |
| `Optional[str]` | `string \| null` |
| `int(d)` (한 글자 숫자) | `Number(d)` |

## 존재하는 재단 (import 해 사용 — 재구현 금지)

- `core/types.js` (DetectionResult/RiskLevel/makeDetection), `core/modes.js`,
  `core/overlap.js`, `core/unicodeNorm.js`, `core/strUtils.js`
- `checksum/*.js` (rrn/businessReg/corpReg/luhn) — `import { isValidChecksum } from "../checksum/rrnChecksum.js"`
- `labels.js` (LABEL_INFO/ALL_LABELS)
- `dictionaries/generated/*.js` (데이터 상수, snake_case 파일명) +
  `dictionaries/index.js` (게이트 함수: isSurname, surnamePrefixLen, isTitle,
  titleDomain, isAgency, normalizeAgency, isDocIdPrefix, isValidAgencyTitle,
  isUniversity, normalizeUniversity, isMajor, normalizeMajor, isCommonWord,
  isCountry, isProvince, isDistrict, isAdminUnit, isValidProvinceDistrict,
  districtsOf, normalizeProvince, isCommonDong, isExtraCity, isFieldLabel,
  isNameFieldLabel, isLegalDong, legalDongs, validTitlesFor,
  specializedAgenciesFor)
- `context/particles.js` (stripTrailingParticle, startsWithParticle, PARTICLES)

## 검증 (매 파일 필수)

1. 컴파일: `cd src/ts cd ts &&cd ts && npx tsc --noEmit` (0 에러)
2. **Python↔TS 차등 대조**: `node tools/diff-detector.mjs <모듈경로> "텍스트" ...`
   Python 검출기와 TS 검출기의 (label,start,end,risk,confidence) 를 비교한다.
   최소 5개 이상의 대표 텍스트(정상 검출, 거부, 경계, 조사 결합, 엣지)로 확인.
3. lint: `npx biome check src/patterns/<파일>.ts`

## 금지사항

- 런타임 외부 의존성 추가 금지 (Node 표준만)
- 재단/generated 파일 수정 금지 — 부족하면 보고
- Python 원본 수정 금지
- 동작 변경 금지: docstring 의 "의도"가 코드와 다르면 **코드**가 진실 (실측)

## 알려진 관례

- 위험도: `RiskLevel.CRITICAL` 등 enum 사용. `int(d.risk_level)` 대응은 `d.riskLevel`
- confidence 는 0~1 float. 골드 대조 시 정확히 일치해야 함 (같은 산술 사용)
- evidence 배열 순서도 Python 과 동일하게
