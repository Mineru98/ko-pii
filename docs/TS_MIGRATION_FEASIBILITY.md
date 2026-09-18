# ko-pii → TypeScript 마이그레이션 실현성 조사 보고서

> 조사일: 2026-08-31 | 대상: ko-pii v1.15.4 (Python 3.10+, 코어 의존성 0, 약 19,000줄)
> 조사 방법: 소스 코드 전수 분석 + npm 레지스트리/공식 문서 웹 조사 (독립 조사 에이전트 5개 병렬 수행)

---

## 결론 (TL;DR)

**✅ TS 재구현 가능합니다.** 전 5개 영역 중 블로커(❌ 완전 불가)는 없으며, 예상 최대 리스크였던 HWP 파싱과 암호화도 원본 코드의 설계 특성 덕분에 예상보다 훨씬 유리하게 평가되었습니다.

| 영역 | 난이도 | 판정 | 핵심 요약 |
|---|---|---|---|
| ① 코어 검출 엔진 (패턴/사전/체크섬/유니코드) | **중 (하편저)** | ✅ ❌ 없음 | 사용된 regex가 전부 JS 표준 범위. 유일한 설계 변경점은 `unicodedata` 저수준 API 대체 |
| ② 가명화·Vault·암호화 | **중** | ✅ 전 기능 가능 | FPE가 FF1/FF3가 아닌 해시 기반 결정적 매핑이라 라이브러리 조달 문제 원천 제거. AES-GCM은 표준 알고리즘으로 상호 복호화 가능 |
| ③ 파일 포맷 I/O (HWP/DOCX/PDF…) | **중 (관리 가능)** | ⚠️ HWP만 조건부 | HWP 레코드 파서가 이미 자체 구현(약 100줄)이라 커뮤니티 JS 파서 부재가 치명적이지 않음 |
| ④ CLI·MCP·RAG 연동·리포팅 | **하~중** | ✅ 대부분 | MCP는 TS SDK가 공식 1급 지원 — 오히려 Python보다 유리. Presidio 플러그인만 ❌ |
| ⑤ ML 분류기·평가·테스트 | **중 (하~중)** | ✅ 전략적 분리로 가능 | "학습은 Python, 추론은 ONNX" 분리. 코어가 애초 ML-free라 영향 제한적 |

**전체 소요 난이도: 중.** Python판과 동등한 기능을 갖춘 TS판 구현이 현실적으로 가능하며, TS판에서만 **포기·대체해야 할 4가지**가 명확히 확인되었습니다(아래 참조).

---

## 영역별 상세 요약

### ① 코어 검출 엔진 — 판정: ✅ (난이도 중, 하편저)

**인벤토리**: 27개 검출기(RRN/전화/생일/주소/PERSON 등), 체크섬 4종(RRN·사업자·법인·Luhn — 전부 순수 산술), 유니코드 정규화(NFKC 폴딩 + offset 맵 + 전수 숫자 폴딩 테이블), 컨텍스트 엔진(조사 25종 분리, 한자 병기, 로마자 RR 표기, 음절 통계 부스트), 사전 14종(약 160KB), 33개 라벨 레지스트리.

**긍정 요인**
- 사용된 regex가 고정폭 lookbehind + lookahead + numbered group + backref뿐 → 전부 JS 표준(ES2018+, Node 8.3+). Python의 고정폭 제약 탓에 코드가 오히려 "이식하기 쉬운 형태"로 작성됨.
- JS lookbehind는 가변폭까지 허용하므로 Python보다 상위호환. `re.match(text, pos)`는 sticky flag `y`, 그룹별 오프셋은 `d` flag(hasIndices, Node 16.4+)로 완전 대체.
- 조사 분리는 `endsWith` 리스트 매칭, 한자는 수기 맵(~100자), 로마자는 0xAC00 산술 + 정적 테이블 → **전부 자체 구현이라 라이브러리 의존 없이 1:1 포팅**. hangul-js/es-hangul 등 npm 한글 유틸도 존재하나 선택 사항.

**주의·대체 필요 (⚠️)**
- `unicodedata.category/combining/decimal`은 JS 내장 대응물이 없음 → `unicode-properties` npm 도입 또는 **빌드 타임 유니코드 테이블 코드젠**(의존성 0 정책 유지 가능, 권장).
- Python `\d`는 유니코드 Nd 전체(전각 포함), JS `\d`는 `[0-9]` 한정 → `[0-9]` 명시 또는 `\p{Nd}` + `u` flag 통일 필요.
- Python 문자열 인덱스는 코드 포인트, JS는 UTF-16 코드 유닛 → offset 맵/redact span 체계의 인덱스 정책을 초기에 결정해야 함(한국어 PII 도메인에서 실질 리스크는 낮음).

### ② 가명화·Vault·암호화 — 판정: ✅ (난이도 중, 블로커 없음)

**인벤토리**: Anonymizer 6종 전략(tokenize/redact/asterisk/hashed/partial/fpe), 5종 처리 모드, 카운터 기반 토큰 Vault(`<LABEL_N>`) + PBKDF2 지문, AES-256-GCM 암호화 Vault(`.kvault`), JSONL 감사 로그, 검수 큐, 결합 위험도, k-익명성(순수 구현), 일반화, 법령 매핑.

**핵심 발견**
- **"fpe"는 NIST FF1/FF3가 아니라** PBKDF2 지문 → 256비트 정수(BigInt) → 숫자/영문/한글 음절 매핑이라는 해시 기반 결정적 형식 보존 매핑(코드 docstring에 명시). 가장 어려운 "JS FPE 라이브러리 조달" 문제가 원천적으로 없음. 필요한 것은 `BigInt` 이식뿐.
- **AES-256-GCM (.kvault)**: 표준 AEAD라 Node 내장 `crypto` 또는 WebCrypto로 Python産 파일과 **상호 복호화 가능**. 재현 조건 4가지 — ① 태그를 ciphertext 뒤에 결합(Python `AESGCM.encrypt` 반환 관례, WebCrypto는 자동, Node 네이티브는 수동 결합) ② AAD=8바이트 magic(`KPIIVT\x01\x00`) ③ PBKDF2-SHA256 480,000회/salt 16B/nonce 12B ④ 파일 레이아웃 `magic‖salt‖nonce‖ct‖tag`.
- Vault 지문(PBKDF2 100k)도 `crypto.pbkdf2Sync`로 바이트 동일 구현 가능 — 기존 Python産 Vault JSON 상호 호환 유지 가능.
- k-익명성·결합위험도·검수·감사 로그는 전부 순수 Python(numpy/pandas/DB 미사용) → 이식 난이도 하.

**리스크 완화**: Python↔TS **양방향 .kvault 복호화 골든 테스트**를 최우선 스파이크로 권장.

### ③ 파일 포맷 I/O — 판정: ⚠️→✅ (난이도 중, 예상보다 유리)

**포맷별 판정**

| 포맷 | 판정 | TS 방법 |
|---|---|---|
| TXT/MD/LOG | ✅ | Buffer + **iconv-lite**(cp949/euc-kr 폴백 체인 — Node Buffer는 EUC-KR 미지원이라 필수) |
| CSV/TSV | ✅ | csv-parse 또는 papaparse + 자체 delimiter 감지 포팅 |
| XLSX | ✅ | 원본도 stdlib 자체 OOXML 파싱 → **jszip + fast-xml-parser로 자체 파서 포팅 권장**(SheetJS는 npm 배포가 스테일) |
| DOCX | ✅ | 동일하게 자체 파서 포팅(`w:t/p` + header/footer + core.xml). mammoth/officeparser는 교차검증용 |
| HWPX | ✅ | ZIP+XML 1:1 대응 (`<hp:t>` 재귀 수집) |
| **HWP 5.x** | **⚠️ (조건부 ✅)** | **cfb(SheetJS js-cfb)** 로 OLE 컨테이너만 열고, 레코드 파서는 원본 코드 직접 포팅 |
| PDF | ✅ (품질 검증 필요) | **unpdf**(pdf.js 래퍼, MIT) 또는 pdfjs-dist — 원본도 `extract_text()` 수준만 사용 |

**핵심 발견**: `hwp.py`의 olefile 의존은 "OLE 컨테이너에서 스트림 읽기"가 전부이고, 실제 파싱(FileHeader 압축 플래그, raw deflate, 레코드 헤더 비트 필드, PARA_TEXT UTF-16LE, inline control 14바이트 스킵)은 **자체 구현 약 100줄**. "신뢰할 만한 JS HWP 파서 부재"(node-hwp 2019 방치, @hwp.js/parser alpha 정체, @ohah/hwpjs는 RC+Rust 네이티브)라는 생태계 최대 약점이 치명적이지 않음. 커뮤니티 라이브러리 의존은 비권장 — 자체 포팅이 정합성·감사 가능성 면에서 유리.

**주의**: HWP 레코드 파서의 `struct.unpack`→`DataView`, `zlib(raw)`→`zlib.inflateRawSync`, UTF-16LE→`toString('utf16le')` 치환. PDF는 pdfplumber 대비 줄바꿈·공백 패턴이 달라질 수 있어 `text_normalizer` 정규식의 실 공공 PDF 코퍼스 회귀 테스트 필요. bounded.py 보안 게이트(zip bomb/DTD/symlink/매직바이트)는 전부 자체 로직이라 그대로 포팅.

### ④ CLI·MCP·RAG 연동·리포팅 — 판정: ✅ (난이도 하~중)

- **MCP 서버: TS가 오히려 유리.** 공식 `@modelcontextprotocol/sdk` v1.30.0 (Node/Bun/Deno), Python판의 원시 JSON Schema dict를 zod 스키마로 타입 안전화. 도구 4개(detect/anonymize/reveal/combined_risk)는 순수 JSON 입출력.
- **CLI**: commander(성숙) 또는 citty(의존성 0 원칙 부합). 한국어 help는 문자열일 뿐 문제 없음.
- **LangChain/LlamaIndex**: Python판의 "런타임 동적 서브클래싱" 패턴은 TS 정적 타입과 안 맞지만, LangChain.js `RunnableLambda` / LlamaIndex.TS 커스텀 postprocessor 같은 **정식 함수형 API로 대체되며 코드가 오히려 줄어듦**. 단, LangChain.js v1 자체 `piiRedactionMiddleware`(영어 중심)와의 차별점(한국 33 라벨 + 체크섬 + 가역 vault + 법적 근거) 문서화 필요.
- **HTML 리포트**: f-string→템플릿 리터럴 1:1, 외부 의존성 0 원칙 유지 가능.
- **배포**: tsdown으로 ESM+CJS 듀얼 + `.d.ts`, `bin` 필드로 npx 엔트리(콘솔 스크립트 5개 대응), 선택 jsr.io.
- **경쟁 환경**: npm의 한국어 PII 라이브러리(월간 다운로드 2,348회 이하 전부)는 어느 것도 33 라벨 + 5모드 + 가역 vault + MCP를 갖추지 못함 → TS판은 **선점 기회**.

### ⑤ ML 분류기·평가·테스트 — 판정: ✅ (난이도 하~중, 전략적 분리)

- **TF-IDF는 sklearn 의존**(순수 구현 아님 — 조사 중 확인된 의외 병목). 해법: (a) char 2-5gram + sublinear TF-IDF + 로지스틱 점수의 **추론 경로만 자체 구현(~300줄)** 또는 (b) skl2onnx → onnxruntime-node(수치 동등성 유리).
- **BERT류 학습(train.py, HF Trainer)은 TS 대체 불가** → 학습은 Python 잔류, optimum으로 ONNX export 후 transformers.js로 **추론만** 제공. 애초 "가중치 미배포 + 사용자 직접 학습" 모델이라 이 분리가 자연스러움.
- **합성 코퍼스(synth.py)**: 로직은 기계적 이식 가능하나 CPython MT19937은 JS와 비트 비호환 → **Python 1회 생성 후 JSONL 동결 권장**(저장소의 `data/generated_eval.jsonl` 선행 패턴과 일치). 회귀 게이트의 목적(고정 seed 회귀 감지)은 TS 자체 PRNG + 기준선 재기록으로도 달성.
- **테스트 체계**: pytest parametrize 16곳 → vitest `test.each`, module fixture → `beforeAll`, 조건부 skip → `describe.skipIf` — 1:1 매핑. 성능 가드의 `process_time`→`process.cpuUsage` 동일 개념, 절대 임계(2초)만 V8 기준 재보정.

---

## TS판에서 포기·대체해야 할 4가지

| 항목 | 사유 | 대안 |
|---|---|---|
| 1. Presidio 플러그인 (`presidio_plugin.py`) | Microsoft Presidio는 Python 전용, 공식 JS 포트 없음 | 없음(개념 소멸). Presidio Docker REST 어댑터만 가능 |
| 2. ML 학습 파이프라인 (`classifier/train.py`) | HF Trainer의 JS 등가물 없음 | Python 잔류 → ONNX 아티팩트만 TS에 공급 |
| 3. 모델 비교 평가 (`eval/model_comparison.py`, `presidio_compare.py`) | `trust_remote_code` 커스텀 아키텍처 + Python 전용 라이브러리 | Python 하네스 잔류, 결과(BENCHMARK.md 수치)는 문서 공유 |
| 4. OpenAI Privacy Filter / HF NER 어댑터 | 1.5B MoE 커스텀 모델의 JS 추론 보장 없음 | Transformers.js+ONNX 재검증 또는 v1 제외, "Python ko-pii를 secondary로 호출" 하이브리드 |

이 4가지는 모두 **코어 기능이 아닌 opt-in 부가물**이며, 코어(검출+가명화+vault+CLI+MCP)의 동등성에는 영향이 없습니다.

---

## 권장 TS 스택

| 용도 | 권장 | 비고 |
|---|---|---|
| 언어/빌드 | TypeScript 5.x + **tsdown** | ESM+CJS 듀얼 + `.d.ts` |
| 테스트 | **vitest** | `test.each`, bench 내장 |
| CLI | **citty**(의존성 0) 또는 commander | |
| MCP | **@modelcontextprotocol/sdk** + zod | 공식 1급 |
| ZIP/XML | jszip + **fast-xml-parser** (2026-08 활발) | DOCX/HWPX/XLSX |
| OLE(CFB) | **cfb** (SheetJS, Apache-2.0) | HWP 컨테이너 — npm 버전 스테일이므로 버전 고정 |
| PDF | **unpdf** 또는 pdfjs-dist | 실문서 회귀 테스트 필수 |
| 인코딩 | **iconv-lite** | CP949/EUC-KR |
| 암호 | Node 내장 `crypto` / WebCrypto | 외부 패키지 불필요 |
| 유니코드 카테고리 | 빌드 타임 코드젠 (regenerate-unicode-properties) 또는 unicode-properties | 의존성 0 유지 가능 |

## 권장 이식 순서 (리스크 소거 기준)

1. **스파이크**: TS `encrypted.ts`로 Python産 `.kvault` 복호화 검증 (양방향 골든 테스트)
2. 코어: `unicode_norm` 이식 (빌드 타임 테이블 코드젠 포함) + 기존 pytest를 **골드 마스터**(입력→검출 span JSON)로 변환해 TS 회귀 하네스 구축 — `\d` 시맨틱·UTF-16 인덱스 차이가 여기서 자동 검출됨
3. 패턴/체크섬/컨텍스트/사전 일괄 포팅
4. anonymizer + vault + modes 6종 (BigInt FPE 포함)
5. 파일 I/O (HWP 레코드 파서 먼저 — 원본 코드 직접 포팅)
6. CLI / MCP 서버 / RAG 연동 / 리포팅
7. 평가 체계 (동결 JSONL 코퍼스 소비 방식) + vitest 테스트 이식

## 검증 전략 (공통)

- Python판을 **진실 원천**으로 삼아 골든 벡터 테스트: 검출 span, 가명화 출력, Vault JSON, `.kvault` 바이트, FPE 결정적 출력, 감사 로그
- 유니코드 엣지 케이스(전각 숫자, NFD 자모, 이모지, 조사 결합, lone surrogate) 전수 회귀
- 성능 임계는 V8 기준 재보정, 스케일링 비율 검사(4배 입력→8배 시간)는 그대로 계승
