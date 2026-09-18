# spec/ — 다중 언어 컨포먼스 계약

이 디렉터리는 ko-pii 의 언어 구현(Python, TypeScript, 향후 확장)이 공통으로
준수해야 하는 **행동 계약**을 담는다. 어느 한 언어의 소유가 아니다.

전체 아키텍처는 [ARCHITECTURE.md](../ARCHITECTURE.md) 참조.

## goldmaster/ — 고정 벡터

`goldmaster/*.json` 은 Python 캐노컬 구현(`src/python/ko_pii`)이 고정 입력에 대해
출력한 결과다. 각 언어 구현은 같은 입력에 같은 값을 내야 하며, CI 가 이를
게이트로 검증한다. **수동 편집 금지** — 유일한 변경 경로는 재생성이다.

```bash
python3 tools/gen-gold-master.py            # 재생성 (diff 리뷰 후 커밋)
python3 tools/gen-gold-master.py --check    # 커밋분이 현재 Python 구현과 일치하는지 검증
```

`npm run goldmaster` / `npm run sync:check` (src/ts 디렉터리) 로도 실행 가능하다.

## 벡터 파일

| 파일 | 내용 | 생성 조건 |
|---|---|---|
| `meta.json` | 생성기·버전·픽스처 목록 등 메타 | 항상 |
| `detection.json` | `detect_all` 검출 span (35 픽스처) | 항상 |
| `anonymize.json` | Anonymizer 6전략 × 픽스처 출력 + 요약 | 항상 |
| `vault.json` | tokenize 전략 Vault dumps | 항상 |
| `fingerprint.json` | Vault 지문 (sha256-v1 / pbkdf2-sha256-v2) | 항상 |
| `kdf.json` | PBKDF2-HMAC-SHA256 키 유도 벡터 | 항상 |
| `unicode_edge.json` | 유니코드 정규화 + offset 맵 | 항상 |
| `kvault.json` | AES-256-GCM `.kvault` 바이트 | `cryptography` 설치 시에만 |

## 계약

1. **오프셋 단위**: 모든 span 오프셋은 Python 기준 **코드 포인트**.
   UTF-16 코드 유닛을 쓰는 구현(JS/TS)은 소비 시 변환한다
   (참조 구현: `src/ts/tests/goldmaster/harness.ts` 의 `codepointOffsetToUtf16`).
2. **결정론**: salt(`0011…eeff`)·secret(`gold-master-key`)·`created_at`
   (`1970-01-01T00:00:00+00:00`) 은 고정값이다. 어떤 환경에서 생성해도
   바이트 동일한 결과가 나와야 한다.
3. **동작 변경 절차**: Python 구현 수정 → 벡터 재생성 → diff 리뷰(변경된
   벡터가 곧 행동 변경 명세) → 각 언어 구현이 새 벡터를 통과하도록 정렬.
   재생성 없이 커밋하면 Python 테스트의 동기화 가드와 CI `--check` 가 실패한다.
4. **검증 스킵 규칙**: 현재 환경에서 생성 불가한 벡터(예: cryptography 미설치의
   `kvault.json`)는 검증에서 스킵되며 나머지는 엄격 비교된다.
5. **소비 방법**: 벡터를 런타임에 import 하지 않는다(테스트 전용 계약).
   테스트에서 벡터를 바꾸는 일로 "통과"를 만드는 것 금지 — 구현이 벡터에
   맞춰진다, 그 반대가 아니다.

## 픽스처 추가 규칙

새 엣지 케이스(유니코드·조사·도메인)를 추가할 때는
`tools/gen-gold-master.py` 의 `FIXTURES` 에 `{id, text}` 를 추가하고 재생성한다.
픽스처 id 는 불변이며, 제거는 해당 벡터를 소비하는 모든 구현의 테스트 변경을
수반하므로 신중히 한다.
