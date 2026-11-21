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
| `\d` / `\D` | `\p{Nd}` / `\P{Nd}` + `u` 플래그 (`PY_D`/`PY_ND`). 원본이 `[0-9]` 를 쓴 자리는 `[0-9]` 그대로 |
| `\s` / `\S` | `PY_S` / `PY_NS` (클래스 안은 `PY_S_CHARS`) + `u` — JS `\s` 와 집합이 다르다 (U+001C~1F·U+0085 포함, U+FEFF 제외) |
| `\w` / `\W` / `\b` | `PY_W` / `PY_NW` (`[\p{L}\p{N}_]`) + `u`, `\b` 는 이 집합의 lookaround 로. JS `\w`·`\b` 는 ASCII 전용 |
| `(?P<name>...)` | `(?<name>...)` |
| `re.finditer(pat, s)` | `s.matchAll(new RegExp(pat, "g"))` (플래그 g 필수, lastIndex 공유 주의) |
| `re.search` / `re.match(s, pos)` | `.exec()` + sticky 플래그 `y` 와 `re.lastIndex = pos` |
| `m.start(g)` / `m.end(g)` (그룹 인덱스) | `d` 플래그 + `m.indices[g]` (Node 16.4+) 또는 래퍼 재구조화 |
| `re.escape` | `regexEscape()` (core/strUtils.ts) |
| `re.IGNORECASE` | `i` 플래그, `re.MULTILINE` → `m` |
| lookbehind `(?<!...)` | 동일 지원 (JS 가 오히려 가변폭 허용) |
| `[가-힣]` 등 범위 | 동일. 유니코드 이스케이프는 `\uAC00` 형태 권장 |

`\d` 를 `[0-9]` 로 옮기면 안 된다. 정규화는 숫자를 접지만, 보이지 않는 문자가 값을 이어 붙인
입력은 detect.ts 가 **정규화하지 않은 원문**에서 검출기를 한 번 더 돌린다. 이 패스에서 Python
`\d` 는 아랍-인도·전각·수학 숫자 등 Nd 전체에 매칭하므로 `[0-9]` 포트는 PII 를 평문으로 남긴다.
`PY_*` 상수는 `core/strUtils.ts` 에 있다. 숫자 값을 계산할 때는 `Number()` 대신 `ndToNumber()`
(Python `int()`/`float()` 처럼 Nd 를 값으로 읽는다), 매치한 숫자열의 길이·슬라이스는 코드 포인트
(`[...s]`, `cpSlice`)로, 키워드 창 `text[max(0, start - n):start]` 은 `cpWindowBefore`/`cpWindowAfter`
로, 겹침 해소의 span 길이는 `pySpanLength` 로 잰다 — 아스트랄 Nd(수학 숫자 등)가 섞이면 UTF-16
길이와 달라진다. `str.strip()`/`str.split()` 은 `pyStrip`/`pySplitWs` (JS `trim()` 과 공백 집합이 다르다).
알려진 차이: `\p{Nd}` 는 Node 의 Unicode 버전(Python 3.12 는 15.0)을 따르므로 이후 추가된 Nd 숫자는
TS 만 숫자로 본다 (더 가리는 쪽).

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
| `int(s)` / `float(s)` (정규식이 `\d` 로 잡은 숫자열) | `ndToNumber(s)` — `Number()` 는 비ASCII 숫자를 NaN 으로 만든다 |

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

## Python 1.27.0 대비 알려진 차이 (의도적으로 남김)

- 오프셋: 검출 span·trace·인증서 `source_span` 은 UTF-16 단위. 아스트랄 문자가 있을 때만 Python
  코드 포인트 값과 다르다 (HTML 리포트의 `data-start`/`data-end` 는 코드 포인트로 변환해 일치).
- 숫자 표현: JS 는 `1.0` 과 `1` 을 구분하지 못해 Python 이 float 로 거부하는 정수 필드 값을 받아들인다.
  2^53 초과 정수는 bigint 로 보존한다.
- ZIP: bzip2·LZMA 압축 멤버는 런타임 의존성 없이 풀 수 없어 `invalid_archive` 로 거부한다 (Python 은 처리).
- 오류 문구: 라이브러리 수준 JSON·XML·UTF-8 파싱 예외의 세부 메시지는 Python 과 다를 수 있다
  (예외 계열·CLI 오류 코드는 같다).
- 메모리 상한: Python 은 Linux 에서 주소 공간 512 MiB, TS 는 모든 플랫폼에서 V8 힙 512 MiB (힙 밖 Buffer 제외).
- 타임스탬프: 감사 로그·Vault 시각은 ms 해상도 (Python 은 µs).
- Unicode 버전: `\p{Nd}` 는 Node 의 Unicode 버전을 따르므로 Python 3.12(Unicode 15) 이후 추가된
  숫자 문자도 숫자로 본다 (더 많이 가리는 방향).
- Node 20: CLI JSON 출력의 int/float 원문 보존은 `JSON.parse` reviver source 접근(Node 21+)을 쓰며
  Node 20 에서는 일반 JS 숫자 포맷으로 폴백한다.
- Python 전용: ML·Presidio·LangChain·LlamaIndex 어댑터, `ko-pii-classify`, `get_privacy_filter_adapter`.
