# 아키텍처 — 다중 언어 구현 (Polyglot Monorepo)

ko-pii 는 하나의 라이브러리를 여러 언어로 동일하게 구현하는 저장소다.
Python 구현이 **캐노컬(참조) 구현**이고, TypeScript 구현이 이를 재구현하며,
두 구현은 **공유 컨포먼스(conformance) 계약**으로 동일성을 보장한다.

> TypeScript 이식의 실현성 조사와 마일스톤은
> [docs/TS_MIGRATION_FEASIBILITY.md](docs/TS_MIGRATION_FEASIBILITY.md) 참조.

---

## 1. 채택 패턴

"동일 구현체의 다중 언어 포팅"에 대해 업계에서 검증된 패턴은 다음과 같다.

| 패턴 | 대표 사례 | 채택 |
|---|---|---|
| 스펙 리포 + 언어별 구현 저장소 | msgpack, multiformats, ULID | ✗ (저장소 분리 시 동기화 비용) |
| **언어별 최상위 디렉터리 모노레포** | gRPC(`src/python`, `src/node`…), protobuf | **✓** (`src/python`, `src/ts`) |
| 캐노컬 구현(루트) + 포트 서브디렉터리 | brotli(C 루트 + `java/`·`js/`), highwayhash | ✗ (2언어 시행 후 모노레포로 전환) |
| **공유 메타데이터 + 코드젠** | libphonenumber(`PhoneNumberMetadata.xml` SSOT) | **✓** (데이터 흐름) |
| 단일 코어 + 바인딩 (PyO3 / WASM) | pydantic-core, protobuf/upb | ✗ (네이티브 TS 재구현이 확정됨) |
| **공유 컨포먼스 스위트** | gRPC interop/conformance, W3C WPT | **✓** |

ko-pii 는 **"언어별 최상위 모노레포" 뼈대 위에 "데이터 코드젠"과 "공유 컨포먼스"를 얹는**
하이브리드를 채택한다. 이유:

1. Python 패키지가 PyPI 배포 체계를 갖춘 캐노컬이고, 각 언어 구현은 `src/<언어>/`
   아래 독립 패키지로 자립해 빌드·배포 경계가 명확하다 (gRPC/protobuf 방식).
2. 검출 규칙의 80%는 데이터(사전·패턴·벡터)라서, 데이터를 한 곳에서 코드젠하면
   구현 간 불일치가 구조적으로 발생하지 않는다 (libphonenumber 방식).
3. 알고리즘 동등성은 사람이 눈으로 보장할 수 없으므로, Python 이 생성한
   고정 벡터(gold master)를 모든 언어가 통과해야 커밋된다 (gRPC interop 방식).

## 2. 디렉터리 구조

```
ko-pii/
├── src/
│   ├── python/            # Python 캐노컬 구현 (PyPI: ko-pii) — 행동·데이터 SSOT
│   │   ├── ko_pii/        #   패키지
│   │   └── tests/         #   pytest (동기화 가드 포함)
│   └── ts/                # TypeScript 구현 (npm: ko-pii) — 독립 패키지
│       ├── src/           #   런타임 코드 (dictionaries/generated 는 코드젠 산출물)
│       └── tests/         #   vitest — spec/goldmaster 소비
├── spec/                  # ★ 다중 언어 컨포먼스 계약 (어느 한 언어 소유가 아님)
│   ├── README.md          #   벡터 프로토콜 (생성·소비·오프셋 단위 계약)
│   ├── goldmaster/*.json  #   Python 이 생성한 고정 벡터 — 수동 편집 금지
│   └── fixtures/io/       #   I/O 골드 벡터가 소비하는 원본 문서 픽스처
├── tools/                 # ★ 다중 언어 코드젠·대조 도구 (Python ↔ TS 데이터 흐름)
│   ├── convert-dicts.py       # Python 사전 → TS 사전 모듈 (--check 지원)
│   ├── gen-gold-master.py     # 골드 벡터 생성 (--check 지원)
│   ├── gen-io-gold.py         # I/O 골드 벡터·픽스처 생성 (olefile/pdfplumber 필요)
│   ├── gen-unicode-tables.mjs # Python unicodedata → TS 유니코드 테이블 (--check 지원)
│   ├── build-hwp-fixture.mjs  # HWP 5.x OLE 픽스처 조립 (gen-io-gold 보조)
│   └── diff-detector.mjs      # Python↔TS 검출기 차등 대조 (디버그)
├── data/, eval/, docs/, demo/  # 평가·문서·데모 자산
└── .github/workflows/     # 언어별 잡 + cross-language sync 게이트
```

## 3. 데이터·행동의 흐름 (SSOT 규칙)

```
src/python/ko_pii/dictionaries/*.py  ──(tools/convert-dicts.py)──▶  src/ts/src/dictionaries/generated/*.ts
src/python/ko_pii (동작 전체)        ──(tools/gen-gold-master.py)─▶  spec/goldmaster/*.json
Python unicodedata                   ──(tools/gen-unicode-tables.mjs)▶ src/ts/src/core/unicode-tables.gen.ts
```

- **데이터 SSOT**: Python 사전 모듈(`src/python/ko_pii/dictionaries`). 사전 데이터를
  바꿀 때는 Python 쪽만 고치고 재생성한다. 생성물은 커밋 대상이며, 재생성 diff 가
  곧 데이터 변경 리뷰다.
- **행동 SSOT**: Python 구현. 검출·가명화 동작을 바꿀 때도 Python 을 먼저 고치고
  골드 벡터를 재생성한다. 벡터 diff 가 행동 변경의 명세가 된다.
- **유니코드 권위 데이터**: Python `unicodedata`. V8 내장 유니코드 데이터는
  Python 런타임과 버전이 다를 수 있어, 테이블을 Python 에서 코드젠한다.
- **TS 는 Python 을 임포트하지 않는다.** 언어 구현 간 런타임 의존은 없으며,
  연결은 오직 "커밋된 생성물 + 벡터"를 통해서만 이뤄진다. 각 언어 패키지는
  독립적으로 빌드·배포된다 (PyPI / npm).

## 4. 컨포먼스(동일성) 계약

1. **골드 벡터는 계약서다.** `spec/goldmaster/*.json` 은 Python 이 생성한 고정
   입력→출력 벡터로, 모든 언어 구현이 동일한 값을 내야 한다. 수동 편집 금지.
   동작 변경은 "Python 수정 → 벡터 재생성 → diff 리뷰 → 각 언어 정렬" 순서다.
2. **드리프트는 CI 가 잡는다.**
   - Python 진영: `tests/unit/test_cross_language_sync.py` — 커밋된 생성물/벡터가
     현재 Python 구현과 일치하는지(재생성 잊음 방지).
   - quality 잡: `tools/*.py --check` + `tools/gen-unicode-tables.mjs --check`
     상시 게이트 (Node 22 함께 세팅; 유니코드 테이블은 unicodedata 권위 버전
     고정을 위해 Python 3.12 환경에서 검증).
   - TS 진영: vitest 가 벡터를 구현 출력과 대조 (아직 미포팅 동작은 자연 스킵).
3. **오프셋 단위 계약**: 골드 벡터의 span 오프셋은 Python 기준 **코드 포인트**.
   TS 는 UTF-16 코드 유닛을 쓰므로 `src/ts/tests/goldmaster/harness.ts` 의
   `codepointOffsetToUtf16()` 으로 변환해 비교한다.
4. **결정론 계약**: 벡터 생성은 salt/secret/created_at 을 고정한다. cryptography
   미설치 환경에서는 `kvault.json` 만 생성·검증이 스킵된다(나머지는 표준 라이브러리).

## 5. 새 언어 구현 추가 절차 (예: `src/go/`, `src/rust/`)

1. `src/<언어>/` 아래 독립 패키지(빌드 설정·테스트 포함)를 만든다.
2. `spec/README.md` 의 벡터 프로토콜을 읽고 골드 벡터 로더를 작성한다.
3. 사전이 필요하면 `tools/convert-dicts.py` 에 해당 언어 코드젠 타깃을 추가한다.
4. 유니코드 테이블이 필요하면 `tools/gen-unicode-tables.mjs` 를 참조해 권위
   데이터(Python unicodedata)에서 코드젠한다.
5. CI 에 언어 잡을 추가하고, `spec/goldmaster` 대비 회귀 테스트를 게이트로 건다.
6. 이 문서의 디렉터리 맵과 채택 패턴 표를 갱신한다.

## 6. 언어별 범위 매트릭스

| 기능 | Python | TypeScript |
|---|---|---|
| 검출 엔진(패턴·체크섬·사전·컨텍스트·유니코드) | ✓ (SSOT) | ✓ M1 |
| 가명화 6전략·Vault·암호화·analytics | ✓ (SSOT) | ✓ M2 (`.kvault` 상호 복호화 포함) |
| 파일 I/O (HWP/HWPX/DOCX/PDF/CSV/XLSX) | ✓ | ✓ M3 |
| CLI / MCP 서버 / 리포팅 | ✓ | ✓ M4 |
| ML 추론 (TF-IDF/BERT, opt-in) | ✓ | ONNX 추론만 (M5) |
| ML 학습(`classifier/train.py`)·Presidio 플러그인·모델 비교 평가 | ✓ | ✗ (Python 전용 — [실현성 보고서](docs/TS_MIGRATION_FEASIBILITY.md) 참조) |
