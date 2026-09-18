# ko-pii TypeScript 포트

Python ko-pii(`src/python/ko_pii`)의 TypeScript 재구현. 저장소 전체의 다중 언어
아키텍처는 [ARCHITECTURE.md](../ARCHITECTURE.md)를, 마이그레이션 계획과 실현성
조사는 [docs/TS_MIGRATION_FEASIBILITY.md](../docs/TS_MIGRATION_FEASIBILITY.md) 참조.

## 마일스톤

| 단계 | 범위 | 상태 |
|---|---|---|
| M0 | 스캐폴딩 + 골드 마스터 회귀 하니스 | ✅ |
| M1 | 코어 검출 엔진 (unicode_norm → checksum → dictionaries → context → patterns 28개 → detect) | ✅ 골드 마스터 35 픽스처(43 검출) 전부 일치 |
| M2 | 가명화 + Vault + analytics | ✅ anonymize 210건·vault dumps 35건 일치, `.kvault` 바이트 동일 + Python↔TS 양방향 복호화 검증 |
| M3 | 파일 I/O (`ko-pii/io` 서브패스 — HWP/HWPX/DOCX/PDF/CSV/XLSX) | ✅ 골드 추출 벡터 10 포맷 일치 + Python 테스트 포팅(tabular 21·bounded 27·batch 13) + 악성 픽스처 31/32 일치 |
| M4 | CLI (`ko-pii` bin) + MCP 서버 (`ko-pii/mcp`·`ko-pii-mcp-server`) + 리포팅/검수/법령 | ✅ CLI E2E 34케이스(stdout/stderr/rc, `--help` 3,353B) 동일, MCP 도구 출력 Python 실측 바이트 동일, HTML 리포트 바이트 동일 |
| M5 | ML opt-in (ONNX 추론) + RAG 연동 | 선택 |

## 골드 마스터 회귀 (검증 전략)

Python판이 진실 원천이다. 저장소 루트 [`spec/goldmaster/`](../../spec/README.md)의
`*.json`은 Python ko-pii로 생성한 고정 벡터(검출 span, 6종 전략 가명화 출력,
Vault JSON, 지문/KDF, 유니코드 정규화)이며, vitest가 TS 구현 출력과 대조한다.

- **오프셋 단위**: 골드 벡터는 Python 기준 **코드 포인트**, TS 구현은 **UTF-16
  코드 유닛**. 비교 시 `tests/goldmaster/harness.ts`의 `codepointOffsetToUtf16()`으로 변환.
- **결정론**: salt/secret_key/created_at 고정. `kvault.json`(AES-GCM 바이트)은
  `cryptography` 설치 환경에서만 생성·검증된다.

생성·검증 도구는 저장소 루트 [`tools/`](../../tools)에 있다 (다른 언어 구현과 공유):

```bash
npm run goldmaster     # python3 ../../tools/gen-gold-master.py   — 벡터 재생성
npm run dicts          # python3 ../../tools/convert-dicts.py     — 사전 재생성 (원본: src/python/ko_pii/dictionaries)
npm run unicode-tables # node    ../../tools/gen-unicode-tables.mjs — 유니코드 테이블 코드젠 (M1)
npm run sync:check     # 생성물/벡터가 Python 원본과 동기화됐는지 검증 (CI 게이트와 동일)
```

생성물은 커밋 대상. 데이터 변경은 Python 쪽에서 한 뒤 재생성하고 diff를 리뷰한다.

## 개발

```bash
npm install
npm test        # vitest (골드 마스터 회귀 포함)
npm run build   # tsdown — ESM+CJS 듀얼 + .d.ts
npm run lint    # biome
npm run typecheck
```

Node 20+. 코어 런타임 의존성 0 (파일 I/O 서브패스만 예외 — M3).

### 참고

- `../../tools/convert-dicts.py`가 변환하지 못한 사전 2종은 M1에서 수동 포팅:
  `agency_titles`(데이터가 함수 내부), `legal_dongs`(gzip 지연 로딩).
- npm 이름 `ko-pii` 가용 확인 완료 (2026-08-31, registry 404 = 미점유).
