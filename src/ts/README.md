# ko-pii

**한국어 문서의 개인정보를 검출하고 가역적으로 가명화하는 TypeScript 라이브러리.** 외부 ML 의존성 없이 룰 + 사전 + 체크섬만으로 동작합니다. [Python ko-pii](https://pypi.org/project/ko-pii/)의 1:1 포트이며, 같은 입력에 같은 결과를 냅니다 — Python 이 생성한 골드 마스터 벡터로 검출 span·가명화 출력·Vault 바이트까지 대조합니다.

전체 문서(33 PII 카테고리, 검출 정책, 평가 결과, 알려진 한계): [README (한국어)](https://github.com/Marker-Inc-Korea/ko-pii#readme) · [README (English)](https://github.com/Marker-Inc-Korea/ko-pii/blob/main/README.en.md)

## 설치

```bash
npm install ko-pii
```

Node 20 이상. ESM·CJS 듀얼 패키지 + 타입 선언 포함. 코어(`ko-pii` 루트 import)는 런타임 의존성 없이 동작하고, 파일 파서는 `ko-pii/io` 서브패스로 분리돼 있습니다.

## 빠른 시작

```ts
import { Anonymizer, ProcessingMode, RiskLevel } from "ko-pii";

const result = new Anonymizer(ProcessingMode.STRICT, "tokenize").process(
  "신청인 홍길동 (880101-1234568) 연락처 010-1234-5678",
);
console.log(result.text);
// 신청인 <PERSON_1> (<RRN_1>) 연락처 <PHONE_1>

console.log(result.vault?.reveal("<RRN_1>"));                  // 880101-1234568
console.log(RiskLevel[result.combined_risk!.combined_risk]);   // CRITICAL
```

- 처리 모드: `PARANOID` · `STRICT`(기본) · `BALANCED` · `PERMISSIVE` · `AUDIT`
- 치환 전략: `tokenize`(가역, Vault 보관) · `redact` · `partial` · `asterisk` · `hashed` · `fpe`

## API

Python 공개 API 와 1:1 대응입니다. 함수·메서드는 camelCase(`detectAll`, `reviewItems`), 생성자 인자는 위치 인자(`mode, strategy, vault, include, exclude, ...`)이고, 직렬화되는 결과 필드(`combined_risk`, `summary.by_label`, `legal_basis`)는 Python JSON 과 호환되도록 snake_case 를 유지합니다.

```ts
import { Anonymizer, ProcessingMode, detectAll, reviewItems, saveEncrypted } from "ko-pii";
import { readText } from "ko-pii/io";                 // HWP/HWPX/DOCX/XLSX/PDF/CSV/TXT (비동기)
import { anonymizeRecords } from "ko-pii/tabular";

const anon = new Anonymizer(ProcessingMode.STRICT, "tokenize");
const result = anon.process(await readText("notice.hwpx"));

console.log(result.summary.by_label);            // { RRN: 1, PHONE: 1, PERSON: 1 }
console.log(reviewItems(result));                // confidence 낮아 REVIEW 분류된 검출
saveEncrypted(result.vault!, "vault.kvault", process.env.KPII_VAULT_PASSWORD!);  // Python 과 상호 복호화 가능

for (const d of detectAll("신청인 880101-1234568")) {
  console.log(d.label, d.text, d.confidence, d.legal_basis);
}
// RRN 880101-1234568 1 개인정보보호법 제24조의2

const [rows, vault] = anonymizeRecords(
  [{ 성명: "홍길동", 주민번호: "880101-1234568" }],
  { strategy: "tokenize" },
);
// [{ 성명: "<PERSON_1>", 주민번호: "<RRN_1>" }]
```

| 서브패스 | 내용 (대응 Python 모듈) |
|---|---|
| `ko-pii` | `Anonymizer` · `detectAll` · `ReversibleVault` · `AuditLog` · 암호화 Vault · `k_anonymity` · `score_combined_risk` |
| `ko-pii/io` | 파일 파서 + `readTextBounded` / `FileReadPolicy` (`ko_pii.io_`) |
| `ko-pii/tabular` | `anonymizeRecords` · `mapColumns` · `classifySchemaColumns` (`ko_pii.tabular`) |
| `ko-pii/batch` | 디렉토리 일괄·병렬 처리 (`ko_pii.batch`) |
| `ko-pii/review` · `ko-pii/reporting` · `ko-pii/legal` · `ko-pii/generalization` | 검토 큐 · HTML 리포트 · 법령 근거 · 일반화 |
| `ko-pii/mcp` | MCP 서버 빌더 (`buildMcpServer`) |
| `ko-pii/eval` | KDPII·KLUE 벤치마크 하니스 |

> **오프셋 단위:** `start`/`end` 는 UTF-16 코드 유닛입니다 (Python 은 코드 포인트). 이모지 등 BMP 밖 문자가 없으면 수치가 같고, 항상 `text.slice(start, end) === detection.text` 가 성립합니다.

HF 토큰 NER 어댑터·문서 분류기·LlamaIndex/LangChain 연동은 torch 의존이라 Python 전용입니다. TypeScript 에서는 `SecondaryDetector` 인터페이스를 구현해 `Anonymizer` 에 직접 주입합니다.

## CLI

```bash
npx ko-pii input.txt --mode STRICT --strategy tokenize --vault vault.json -o output.txt
npx ko-pii ./incoming/ --batch --workers 4 --output-dir ./anonymized/
npx ko-pii --labels      # 전체 라벨 목록
```

옵션·출력·종료 코드는 Python CLI 와 같습니다.

## MCP 서버

`detect_pii` · `anonymize` · `reveal` · `combined_risk` 4개 도구를 stdio MCP 서버로 제공합니다. MCP SDK 와 zod 는 선택 peer 라 자동 설치되지 않으므로 함께 지정합니다.

```json
{
  "mcpServers": {
    "ko-pii": {
      "command": "npx",
      "args": ["-y", "-p", "ko-pii", "-p", "@modelcontextprotocol/sdk", "-p", "zod", "ko-pii-mcp-server"]
    }
  }
}
```

## 개발

저장소는 Python 이 캐노니컬 구현인 polyglot monorepo 입니다. 설계는 [docs/ARCHITECTURE.md](https://github.com/Marker-Inc-Korea/ko-pii/blob/main/docs/ARCHITECTURE.md), 포팅 규칙은 [PORTING.md](https://github.com/Marker-Inc-Korea/ko-pii/blob/main/src/ts/PORTING.md), 마이그레이션 조사는 [docs/TS_MIGRATION_FEASIBILITY.md](https://github.com/Marker-Inc-Korea/ko-pii/blob/main/docs/TS_MIGRATION_FEASIBILITY.md) 참조.

```bash
cd src/ts
npm install
npm test             # vitest (골드 마스터 회귀 포함)
npm run build        # tsdown — ESM+CJS 듀얼 + .d.ts
npm run lint         # biome
npm run typecheck
npm run sync:check   # 생성물·골드 벡터가 Python 원본과 동기화됐는지 검증
npm run package      # 게이트 → 빌드 → npm pack → 타르볼 검증 → 설치 스모크 (게시는 하지 않음)
```

### 골드 마스터 회귀

Python 판이 진실 원천입니다. 저장소 루트 [`spec/goldmaster/`](https://github.com/Marker-Inc-Korea/ko-pii/blob/main/spec/README.md)의 `*.json` 은 Python ko-pii 로 생성한 고정 벡터(검출 span, 6종 전략 가명화 출력, Vault JSON, 지문/KDF, 유니코드 정규화)이며, vitest 가 TS 구현 출력과 대조합니다.

- **오프셋 단위**: 골드 벡터는 코드 포인트, TS 구현은 UTF-16 코드 유닛. 비교 시 `tests/goldmaster/harness.ts` 의 `codepointOffsetToUtf16()` 으로 변환.
- **결정론**: salt/secret_key/created_at 고정. `kvault.json`(AES-GCM 바이트)은 `cryptography` 설치 환경에서만 생성·검증.

```bash
npm run goldmaster     # 벡터 재생성
npm run dicts          # 사전 재생성 (원본: src/python/ko_pii/dictionaries)
npm run unicode-tables # 유니코드 테이블 코드젠
```

생성물은 커밋 대상입니다. 데이터 변경은 Python 쪽에서 한 뒤 재생성하고 diff 를 리뷰합니다. `convert-dicts.py` 가 변환하지 못하는 사전 2종(`agency_titles`, `legal_dongs`)은 수동 포팅입니다.

## 라이선스

MIT
