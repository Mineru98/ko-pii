"""TS 검출 동등성 픽스처 생성기 — Python v1.27 detect_all / normalize_unicode 실측.

Python 테스트 소스(src/python/tests)의 문자열 리터럴을 모아 detect_all 결과를 기록한다.
산출물: src/ts/tests/unit/detect-1.27.fixture.json (offset 은 코드 포인트).
``nd_cases`` 는 비ASCII 십진 숫자(유니코드 Nd 전 체계)와 보이지 않는 문자·유니코드 공백을 섞은
입력의 detect_all / Anonymizer(tokenize) 결과다 — 원문 재검사 패스에서 Python ``\\d``·``\\s`` 가
유니코드 의미로 매칭하는 경로를 고정한다.
실행: .venv/bin/python src/ts/tools/gen-detect-parity.py
"""
from __future__ import annotations

import ast
import json
import pathlib
import random
import re
import sys
import unicodedata

from ko_pii.anonymizer import Anonymizer
from ko_pii.core.unicode_norm import needs_normalization, normalize_unicode
from ko_pii.detect import detect_all
from ko_pii.patterns import person

ROOT = pathlib.Path(__file__).resolve().parents[3]
TESTS = ROOT / "src" / "python" / "tests"
OUT = ROOT / "src" / "ts" / "tests" / "unit" / "detect-1.27.fixture.json"

DIRS = ["unit/patterns", "unit/context", "unit/checksum", "unit/dictionaries", "unit/domain",
        "property", "integration"]
TOP_LEVEL = re.compile(r"test_(address|birth|core|detect|detector|digit|email|failure|field|financial|"
                       r"form|fp_|frn|korean|leak|masking|normalization|output|overlap|passport|person|"
                       r"primary|robustness|typed).*\.py$")
INTERESTING = re.compile(r"[가-힣0-9@ᄀ-ᇿ]")


def literals() -> list[str]:
    files: list[pathlib.Path] = []
    for d in DIRS:
        files += sorted((TESTS / d).rglob("*.py"))
    files += sorted(p for p in (TESTS / "unit").glob("test_*.py") if TOP_LEVEL.match(p.name))
    seen: dict[str, None] = {}
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if 3 <= len(s) <= 2000 and INTERESTING.search(s) and "\x00" not in s:
                    seen.setdefault(s, None)
    return list(seen)


def project(d) -> list:
    return [d.label, d.text, d.start, d.end, int(d.risk_level), d.confidence, d.evidence,
            d.legal_basis, d.extra, d.rule_id, d.normalized, d.subrule_id]


ND_ZEROS = [c for c in range(sys.maxunicode + 1)
            if unicodedata.category(chr(c)) == "Nd" and unicodedata.digit(chr(c)) == 0]
ND_SEEDS = [
    "연락처 010-1111-2222\u200b010-1234-5\u066678",
    "900101-1234568\u200b010-1234-\uff15\uff16\uff17\uff18",
    "900101-1234568\u200b02-123-4\u066567",
    "1\u200b20\u06624가합1234\u0665",
    "900101-1234568\u200b20\uff124가합12345",
    "나이\u200b\u0663\u0665세",
    "체중\u200b\uff17\uff10kg",
    "1\u200b\uff1175cm",
    "a\u200b(02) \u066123-4567",
]
ND_VALUES = [
    "010-1234-5678", "010-1111-2222", "02-123-4567", "(02) 123-4567", "031-123-4567", "+82 10-1234-5678",
    "1588-1234", "900101-1234568", "2024가합12345", "2023고단1234", "35세", "만 42세", "70kg", "175cm",
    "키 182cm", "몸무게 65.5kg", "팩스 02-123-4567", "FAX: 031-111-2222", "1990.01.01", "1990년 1월 1일",
    "생년월일 1985-03-15", "90년생", "생후 6개월 아기", "30대 후반", "처방전 202401011234",
    "요양기관기호 12345678", "EDI 643501234", "KD코드 8806500012345", "1168010100100010000",
    "사번: 20210001", "2024-민원-12345", "기재부-인사-2024-00123", "홍길동 (32세)", "김철수 35세",
    "::ffff:1.2.3.4", "월드컵북로 396 누리꿈스퀘어 12층", "주민번호 900101 1234568", "우편 번호 : 06234",
    "국민은행 352-1234-5678-12", "kim [at] test [dot] com", "버전 2.10.4.5",
]
ND_JOINERS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "", " ", ", "]
ND_SPACES = [" ", "\x1c", "\x1f", "\x85", "\u3000", "\u00a0", "\ufeff", "\u2003", "\t"]
ND_PREFIXES = ["", "연락처 ", "나이 ", "a", "1", "전화 ", "번호: "]


def nd_texts(count: int = 400) -> list[str]:
    rng = random.Random(127)
    out = list(ND_SEEDS)
    for i in range(count):
        zero = ND_ZEROS[i % len(ND_ZEROS)]  # 모든 Nd 체계를 고르게 순회
        digit_p = rng.choice([0.3, 0.7, 1.0])
        space_p = rng.choice([0.0, 0.0, 0.5])
        parts = [rng.choice(ND_PREFIXES)]
        for k in range(rng.randint(1, 3)):
            if k:
                parts.append(rng.choice(ND_JOINERS))
            for ch in rng.choice(ND_VALUES):
                if "0" <= ch <= "9" and rng.random() < digit_p:
                    parts.append(chr(zero + int(ch)))
                elif ch == " " and rng.random() < space_p:
                    parts.append(rng.choice(ND_SPACES))
                else:
                    parts.append(ch)
        out.append("".join(parts))
    return out


def nd_cases() -> list[dict]:
    cases = []
    for text in nd_texts():
        result = Anonymizer(strategy="tokenize").process(text)
        cases.append({
            "text": text,
            "detections": [project(d) for d in detect_all(text)],
            "anonymized": result.text,
            "records": [[r.detection.label, r.detection.start, r.detection.end, r.action.value, r.token]
                        for r in result.detections],
        })
    return cases


def main() -> None:
    texts = literals()
    cases = []
    for text in texts:
        try:
            dets = detect_all(text)
        except Exception as exc:  # noqa: BLE001 - 기록만
            cases.append({"text": text, "error": f"{type(exc).__name__}: {exc}"})
            continue
        norm, omap = normalize_unicode(text)
        lit, _ = normalize_unicode(text, fold_numeric=False)
        cases.append({
            "text": text,
            "detections": [project(d) for d in dets],
            "needs_normalization": needs_normalization(text),
            "normalized": norm,
            "offset_map": omap,
            "literal_normalized": lit,
        })
    exclusion_cases = []
    for text, excl in [
        ("성명: 남궁 다은\n담당자 남궁 확인", ["남궁 다은"]),
        ("신청인 홍길동 연락처 010-1234-5678", ["홍길동"]),
        ("민원인 김철수, 이영희 방문", ["이영희"]),
        ("성명: 김민수 / 박지성", ["  김민수  "]),
        ("담당자: 국민연금 처리", ["국민연금"]),
    ]:
        exclusion_cases.append({
            "text": text, "exclusions": excl,
            "detections": [project(d) for d in detect_all(text, person_exclusions=excl)],
            "person": [project(d) for d in person.detect(text, exclusions=excl)],
        })
    filter_cases = []
    for text, inc, exc in [
        ("홍길동 010-1234-5678 hong@example.com 여권 M12345678", ["PHONE", "EMAIL"], ["EMAIL"]),
        ("여권번호 M1234567８ 와 S１２３４５６７８", ["PASSPORT"], None),
        ("성명: 홍길동\x0b연락처 010-1234-5678", None, ["PHONE"]),
        ("메일 hong@example.com\x0c담당 kim@example.org", None, None),
        ("성명: 홍길동\x1e전화번호: 010-1234-5678", ["PERSON"], None),
    ]:
        filter_cases.append({
            "text": text, "include": inc, "exclude": exc,
            "detections": [project(d) for d in detect_all(text, include=inc, exclude=exc)],
        })
    OUT.write_text(json.dumps({"generator": "src/ts/tools/gen-detect-parity.py", "offset_unit": "codepoint",
                               "cases": cases, "exclusion_cases": exclusion_cases,
                               "filter_cases": filter_cases, "nd_cases": nd_cases()}, ensure_ascii=False, indent=None) + "\n",
                   encoding="utf-8")
    print(len(cases), "cases ->", OUT)


if __name__ == "__main__":
    main()
