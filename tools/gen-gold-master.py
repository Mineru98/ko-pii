#!/usr/bin/env python3
"""골드 마스터 벡터 생성 — Python ko-pii를 진실 원천으로 다중 언어 회귀 테스트용 데이터 dump.

실행: python3 tools/gen-gold-master.py [--check]
출력: spec/goldmaster/*.json

생성 파일:
- meta.json          버전/환경 메타 + 픽스처 목록
- detection.json     detect_all 검출 span (offset 단위: 코드 포인트 — M1에서 TS 정책과 대조)
- anonymize.json     Anonymizer 6종 전략 출력 + 요약
- vault.json         tokenize 전략 Vault dumps (created_at 고정)
- fingerprint.json   Vault.fingerprint 벡터 (legacy sha256-v1 + pbkdf2-sha256-v2)
- kdf.json           PBKDF2-HMAC-SHA256 벡터 (encrypted.py 키 유도와 동일 프리미티브)
- unicode_edge.json  unicode_norm 정규화 + offset 맵 벡터
- kvault.json        AES-256-GCM .kvault 바이트 (cryptography 설치 시에만)

결정론성: salt/secret_key/iterations 를 고정하고 created_at 을 상수로 치환한다.
`cryptography` 미설치 환경에서도 코어 벡터는 표준 라이브러리만으로 생성된다.

--check: 재생성 없이 커밋된 벡터가 현재 Python 구현과 동기화되어 있는지 검증한다.
동작을 바꿨다면 재생성 → diff 리뷰 → 각 언어 구현 정렬 순서로 진행한다.
(CI 와 tests/unit/test_cross_language_sync.py 가 동일 로직을 사용한다.)
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "python"))

from ko_pii.anonymizer import Anonymizer  # noqa: E402
from ko_pii.core.modes import ProcessingMode  # noqa: E402
from ko_pii.core.types import DetectionResult  # noqa: E402
from ko_pii.core.unicode_norm import needs_normalization, normalize_unicode  # noqa: E402
from ko_pii.detect import detect_all  # noqa: E402
from ko_pii.vault.reversible import ReversibleVault  # noqa: E402

# --- 결정론 고정값 -----------------------------------------------------------
FIXED_SALT = "00112233445566778899aabbccddeeff"
FIXED_KEY = "gold-master-key"
FIXED_CREATED_AT = "1970-01-01T00:00:00+00:00"
STRATEGIES = ["tokenize", "redact", "asterisk", "hashed", "partial", "fpe"]

OUT = ROOT / "spec" / "goldmaster"

# --- 픽스처 -------------------------------------------------------------------
_NFD_HONG = __import__("unicodedata").normalize("NFD", "홍길동")

FIXTURES: list[dict[str, str]] = [
    {"id": "basic_rrn_phone", "text": "신청인 홍길동 (880101-1234568) 연락처 010-1234-5678"},
    {"id": "josa_attachment", "text": "홍길동이 서울특별시 강남구 테헤란로 152로 이사했다. 김철수에게 전달 요청."},
    {"id": "hanja_bracket", "text": "성명: 홍길동(洪吉童)"},
    {"id": "fullwidth_digits", "text": "주민번호: ８８０１０１－１２３４５６８"},
    {"id": "nfd_jamo", "text": f"담당자 {_NFD_HONG} 확인"},
    {"id": "zerowidth_split", "text": "880101-1​234568"},
    {"id": "emoji_adjacent", "text": "담당자 홍길동😀 010-1234-5678"},
    {"id": "date_keyword_reject", "text": "시행일자: 2026-05-21, 문서번호: 제2026-123호"},
    {"id": "pseudonym_reject", "text": "박씨와 김모씨가 참석했다."},
    {"id": "card_luhn", "text": "카드번호 4111-1111-1111-1111"},
    {"id": "email_url", "text": "이메일 hong@example.com, 사이트 https://example.kr"},
    {"id": "birth_kr", "text": "생년월일 1988년 1월 1일"},
    {"id": "address_road", "text": "주소: 서울특별시 강남구 테헤란로 152, 3층"},
    {"id": "business_reg", "text": "사업자등록번호 123-45-67890"},
    {"id": "official_doc", "text": (
        "개인정보 처리 동의서\n"
        "성명: 홍길동\n"
        "주민등록번호: 880101-1234568\n"
        "연락처: 010-1234-5678\n"
        "주소: 서울특별시 강남구 테헤란로 152\n"
        "이메일: hong@example.com\n"
    )},
    {"id": "latin_name", "text": "Hong Gildong (hong@example.com)"},
    {"id": "passport_driver", "text": "여권 M12345678, 운전면허 12-345678-90"},
    {"id": "ip_vehicle", "text": "IP 192.168.1.10, 차량번호 서울12가3456"},
    {"id": "frn", "text": "외국인등록번호 880101-5123456"},
    {"id": "business_reg_valid", "text": "사업자등록번호 123-45-67891 (국세청 등록)"},
    {"id": "corp_reg", "text": "법인등록번호 130111-0006246"},
    {"id": "driver_license_2", "text": "운전면허번호: 11-123456-01"},
    {"id": "medical_insurance", "text": "건강보험증번호: 2-123456789-01"},
    {"id": "prescription_id", "text": "처방전 교부번호 20260831-123456"},
    {"id": "pnu", "text": "토지번호 1165010100101090000 (강남구)"},
    {"id": "postal_code", "text": "우편번호 06236, 팩스 02-1234-5678"},
    {"id": "vehicle_2", "text": "차량: 경기45아6789"},
    {"id": "nationality", "text": "국적: 대한민국 (중국 국적자 제외)"},
    {"id": "account", "text": "급여계좌: 신한은행 110-123-456789"},
    {"id": "edi_drug", "text": "약품코드 198303432 (EDI)"},
    {"id": "court_case", "text": "사건번호 2023가합12345"},
    {"id": "doc_id_gov", "text": "기획재정부 예산고시 제2026-123호"},
    {"id": "personal_attrs", "text": "학력: 서울대학교 졸업, 전공: 컴퓨터공학과, 직책: 팀장, 나이 35세, 신장 175cm, 체중 70kg"},
    {"id": "empty", "text": ""},
    {"id": "whitespace", "text": "   \n\t  "},
    # 접미가 겹치는 필드 라벨(평가자/피평가자) — evidence 는 가장 긴 라벨로 결정적이어야 한다.
    {"id": "field_label_suffix_overlap", "text": "피평가자: 윤하늘\n직급: 차장"},
    # 아스트랄 수학 숫자(U+1D7CE~) — 코드 포인트 단위 폴딩 + offset 역매핑.
    {"id": "astral_math_digits", "text": "주민 " + "".join(
        chr(0x1D7CE + int(c)) if c.isdigit() else c for c in "900101-1234567"
    ) + " 확인"},
    # 아스트랄 결합표시(U+1D165)로 숫자열 분할 — 빠른 경로로 새지 않아야 한다.
    {"id": "astral_combining_split", "text": "값 8" + chr(0x1D165) + "80101-1234568 확인"},
]


def _detection_to_dict(d: DetectionResult) -> dict:
    return {
        "label": d.label,
        "text": d.text,
        "start": d.start,
        "end": d.end,
        "risk_level": int(d.risk_level),
        "confidence": d.confidence,
        "evidence": list(d.evidence),
        "legal_basis": d.legal_basis,
        "extra": dict(d.extra),
    }


def build_payloads() -> dict[str, object]:
    """모든 골드 벡터를 {파일명: payload} 로 결정론적으로 생성한다."""
    import ko_pii

    print(f"ko-pii {ko_pii.__version__} / Python {platform.python_version()}")
    payloads: dict[str, object] = {}

    # 1. detection -------------------------------------------------------------
    detection_entries = []
    for fx in FIXTURES:
        dets = detect_all(fx["text"])
        detection_entries.append({
            "id": fx["id"],
            "text": fx["text"],
            "detections": [_detection_to_dict(d) for d in dets],
        })
    payloads["detection.json"] = {
        "offset_unit": "codepoint",
        "entries": detection_entries,
    }
    n_det = sum(len(e["detections"]) for e in detection_entries)
    print(f"  -> 총 검출 {n_det}개 (픽스처 {len(FIXTURES)}건)")

    # 2. anonymize (6 전략 × 픽스처) --------------------------------------------
    anonymize_entries = []
    vault_entries = []
    for fx in FIXTURES:
        for strategy in STRATEGIES:
            vault = ReversibleVault(salt=FIXED_SALT, secret_key=FIXED_KEY)
            result = Anonymizer(
                mode=ProcessingMode.STRICT, strategy=strategy, vault=vault,
            ).process(fx["text"])
            payload = vault.to_dict()
            payload["created_at"] = FIXED_CREATED_AT
            records = [
                {
                    "label": r.detection.label,
                    "action": r.action.value,
                    "token": r.token,
                    "start": r.detection.start,
                    "end": r.detection.end,
                }
                for r in result.detections
            ]
            anonymize_entries.append({
                "id": fx["id"],
                "strategy": strategy,
                "text_in": fx["text"],
                "text_out": result.text,
                "records": records,
                "summary": result.summary,
            })
            if strategy == "tokenize":
                vault_entries.append({
                    "id": fx["id"],
                    "dumps": json.dumps(payload, ensure_ascii=False, indent=2),
                })
    payloads["anonymize.json"] = {"entries": anonymize_entries}
    payloads["vault.json"] = {
        "salt": FIXED_SALT,
        "secret_key": FIXED_KEY,
        "entries": vault_entries,
    }
    print(f"  -> 익명화 {len(anonymize_entries)}건, vault {len(vault_entries)}건")

    # 3. fingerprint 벡터 --------------------------------------------------------
    fp_entries = []

    def fp_case(scheme: str, label: str, original: str, iterations: int, secret: str) -> None:
        if scheme == "sha256-v1":
            payload = {
                "schema_version": 1,
                "salt": FIXED_SALT,
                "fingerprint_scheme": "sha256-v1",
                "entries": {},
            }
            v = ReversibleVault.from_dict(payload)
            v._secret_key = secret
        else:
            v = ReversibleVault(
                salt=FIXED_SALT, secret_key=secret, fingerprint_iterations=iterations,
            )
        fp_entries.append({
            "scheme": scheme,
            "salt": FIXED_SALT,
            "secret_key": secret,
            "iterations": iterations,
            "label": label,
            "original": original,
            "hex": v.fingerprint(label, original),
        })

    fp_case("sha256-v1", "RRN", "880101-1234568", 0, "")
    fp_case("sha256-v1", "PHONE", "010-1234-5678", 0, "ignored-by-legacy")
    fp_case("pbkdf2-sha256-v2", "RRN", "880101-1234568", 1000, FIXED_KEY)
    fp_case("pbkdf2-sha256-v2", "RRN", "880101-1234568", 1000, "other-key")
    fp_case("pbkdf2-sha256-v2", "RRN", "880101-1234568", 1000, "")
    fp_case("pbkdf2-sha256-v2", "PHONE", "010-1234-5678", 1000, FIXED_KEY)
    fp_case("pbkdf2-sha256-v2", "RRN", "880101-1234568", 100_000, FIXED_KEY)
    payloads["fingerprint.json"] = {"entries": fp_entries}
    print(f"  -> 지문 벡터 {len(fp_entries)}건 (기본 100k 반복 1건 포함)")

    # 4. KDF 벡터 (encrypted.py 키 유도 프리미티브) -------------------------------
    kdf_entries = []
    for password, salt_hex, iters in [
        ("correct horse battery staple", "a1b2c3d4e5f60718293a4b5c6d7e8f90", 480_000),
        ("gold-master-key", "00112233445566778899aabbccddeeff", 480_000),
        ("pw", "00112233445566778899aabbccddeeff", 1000),
    ]:
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iters, dklen=32,
        )
        kdf_entries.append({
            "password": password,
            "salt_hex": salt_hex,
            "iterations": iters,
            "dklen": 32,
            "key_hex": key.hex(),
        })
    payloads["kdf.json"] = {"entries": kdf_entries}
    print(f"  -> KDF 벡터 {len(kdf_entries)}건")

    # 5. 유니코드 정규화 벡터 ------------------------------------------------------
    edge_inputs = [
        "신청인 홍길동 (880101-1234568)",
        "주민번호: ８８０１０１－１２３４５６８",
        _NFD_HONG + " 010-1234-5678",
        "880101-1​234568",
        "전화: ０１０－１２３４－５６７８",
        "①②③ ⒈⒉⒊ ﬁle",
        "홍길동😀 010-1234-5678",
        "　　　전각　공백　　　",
        "8 8 0 1 0 1 - 1 2 3 4 5 6 8",
        "洪吉童",
    ]
    edge_entries = []
    for text in edge_inputs:
        norm, omap = normalize_unicode(text)
        edge_entries.append({
            "input": text,
            "needs_normalization": needs_normalization(text),
            "normalized": norm,
            "offset_map": list(omap) if omap is not None else None,
        })
    payloads["unicode_edge.json"] = {"offset_unit": "codepoint", "entries": edge_entries}
    print(f"  -> 유니코드 벡터 {len(edge_entries)}건")

    # 6. AES-GCM .kvault (cryptography 설치 시에만) --------------------------------
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("  kvault.json: SKIP (cryptography 미설치 — M2 스파이크 전 재생성)")
    else:
        from ko_pii.vault.encrypted import KDF_ITERATIONS, KDF_SALT_LEN, MAGIC, NONCE_LEN
        vault = ReversibleVault(salt=FIXED_SALT, secret_key=FIXED_KEY)
        vault.store(label="RRN", original="880101-1234568", risk_level=5,
                    legal_basis="개인정보보호법 제24조의2", offset=4)
        vault.store(label="PHONE", original="010-1234-5678", risk_level=4,
                    legal_basis="개인정보보호법 제23조", offset=24)
        payload = vault.to_dict()
        payload["created_at"] = FIXED_CREATED_AT
        plaintext = json.dumps(payload, ensure_ascii=False, indent=None).encode("utf-8")
        kdf_salt = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        nonce = bytes.fromhex("000102030405060708090a0b")
        key = hashlib.pbkdf2_hmac("sha256", b"gold-master-pw", kdf_salt,
                                  KDF_ITERATIONS, dklen=32)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
        blob = MAGIC + kdf_salt + nonce + ciphertext
        payloads["kvault.json"] = {
            "password": "gold-master-pw",
            "kdf_iterations": KDF_ITERATIONS,
            "kdf_salt_len": KDF_SALT_LEN,
            "nonce_len": NONCE_LEN,
            "magic_hex": MAGIC.hex(),
            "blob_hex": blob.hex(),
            "plaintext_len": len(plaintext),
        }
        print("  -> .kvault 결정론적 벡터 1건 (고정 salt/nonce)")

    # 7. meta -------------------------------------------------------------------
    payloads["meta.json"] = {
        "generator": "tools/gen-gold-master.py",
        "ko_pii_version": ko_pii.__version__,
        "python": platform.python_version(),
        "offset_unit": "codepoint",
        "fixed_salt": FIXED_SALT,
        "fixed_secret_key": FIXED_KEY,
        "strategies": STRATEGIES,
        "fixture_ids": [fx["id"] for fx in FIXTURES],
    }
    return payloads


def check() -> tuple[list[str], list[str]]:
    """(드리프트 파일, 검증 스킵 파일) 목록을 반환.

    현재 환경에서 생성 가능한 벡터만 비교한다. cryptography 미설치로 생성하지
    못한 파일은 스킵으로 보고하며, 생성 가능한데 디스크에 없으면 드리프트로
    간주한다 (재생성 + 커밋 필요). 이 도구의 생성 범위 밖 벡터(io.json —
    tools/gen-io-gold.py 전용)도 스킵으로 보고한다.
    """
    payloads = build_payloads()
    drifts = []
    skipped = []
    for name, payload in payloads.items():
        path = OUT / name
        expected = json.dumps(payload, ensure_ascii=False, indent=2)
        actual = path.read_text(encoding="utf-8") if path.exists() else None
        if actual != expected:
            drifts.append(name)
    produced = set(payloads)
    for path in sorted(OUT.glob("*.json")):
        if path.name not in produced:
            skipped.append(path.name)
    return drifts, skipped


def main(argv: list[str]) -> int:
    if "--check" in argv:
        drifts, skipped = check()
        for name in skipped:
            if name == "io.json":
                # io.json 은 tools/gen-io-gold.py (olefile/pdfplumber/pypdf 필요)가
                # 생성하는 별도 벡터다. TS 진영에서는 vitest io.test.ts 가 상시 검증.
                print(f"  skip: {name} (이 도구의 생성 범위 밖 — 재생성·검증: tools/gen-io-gold.py)")
            else:
                print(f"  skip: {name} (현재 환경에서 생성 불가 — cryptography 설치 후 검증 가능)")
        if drifts:
            print(
                "골드 마스터 드리프트 — python3 tools/gen-gold-master.py 로 재생성하세요:",
                file=sys.stderr,
            )
            for name in drifts:
                print(f"  {OUT / name}", file=sys.stderr)
            return 1
        print("ok: spec/goldmaster 골드 벡터가 Python 구현과 동기화됨")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    payloads = build_payloads()
    print(f"output: {OUT}")
    for name, payload in payloads.items():
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        path = OUT / name
        path.write_text(text, encoding="utf-8")
        print(f"  {name}: {len(text.encode('utf-8')):,} bytes")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
