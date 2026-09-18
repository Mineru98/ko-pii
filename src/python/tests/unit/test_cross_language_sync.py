"""다중 언어 아티팩트 동기화 가드.

Python 구현이 진실 원천이다. TS 사전 코드젠(src/ts/src/dictionaries/generated)과
골드 마스터 벡터(spec/goldmaster)는 Python 에서 생성해 커밋하는 아티팩트이므로,
Python 동작 변경 후 재생성을 잊으면 두 언어 구현이 어긋난다. 이 테스트는 그
드리프트를 커밋 전에 잡는다. 생성 도구도 동일 검증을 제공한다
(`python3 tools/<도구>.py --check`, CI quality 잡에서 상시 실행).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# src/python/tests/unit/ → 저장소 루트는 4단계 위.
ROOT = Path(__file__).resolve().parents[4]


def _load_tool(filename: str, module_name: str):
    path = ROOT / "tools" / filename
    if not path.is_file():
        pytest.skip(f"{path} 가 없어 검증 불가 (sdist 환경)")
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_ts_dictionary_codegen_in_sync() -> None:
    """커밋된 TS 사전 생성물이 Python 사전 모듈과 byte 동일해야 한다."""
    if not (ROOT / "src" / "ts" / "src" / "dictionaries" / "generated").is_dir():
        pytest.skip("src/ts 가 없어 검증 불가 (sdist 환경)")
    tool = _load_tool("convert-dicts.py", "_ko_pii_convert_dicts_tool")
    drifts = tool.check()
    assert drifts == [], (
        f"TS 사전 생성물 드리프트: {drifts} — 재생성: python3 tools/convert-dicts.py"
    )


def test_goldmaster_vectors_in_sync() -> None:
    """커밋된 골드 벡터가 현재 Python 구현 출력과 일치해야 한다.

    현재 환경에서 생성 불가한 벡터(예: cryptography 미설치의 kvault.json)는
    스킵되며, 검증 결과는 실패 메시지에 함께 표시된다.
    """
    if not (ROOT / "spec" / "goldmaster").is_dir():
        pytest.skip("spec/goldmaster 가 없어 검증 불가 (sdist 환경)")
    tool = _load_tool("gen-gold-master.py", "_ko_pii_gen_gold_master_tool")
    drifts, skipped = tool.check()
    assert drifts == [], (
        f"골드 마스터 드리프트: {drifts} (검증 스킵: {skipped})"
        " — 재생성: python3 tools/gen-gold-master.py"
    )


def test_unicode_tables_in_sync() -> None:
    """커밋된 TS 유니코드 테이블이 Python unicodedata 출력과 일치해야 한다.

    검증은 PATH 의 python3 기준이다(테이블 권위 데이터가 unicodedata 이므로).
    커밋분 테이블이 다른 unicodedata 버전에서 생성됐으면 실패하며,
    PATH python3 로 재생성해 정렬한다.
    """
    import shutil
    import subprocess

    if not (ROOT / "tools" / "gen-unicode-tables.mjs").is_file():
        pytest.skip("tools/gen-unicode-tables.mjs 가 없어 검증 불가 (sdist 환경)")
    if not (ROOT / "src" / "ts" / "src" / "core" / "unicode-tables.gen.ts").is_file():
        pytest.skip("src/ts 가 없어 검증 불가 (sdist 환경)")
    node = shutil.which("node")
    if node is None:
        pytest.skip("node 가 없어 유니코드 테이블 검증 불가")
    result = subprocess.run(
        [node, str(ROOT / "tools" / "gen-unicode-tables.mjs"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"유니코드 테이블 드리프트: {(result.stdout + result.stderr).strip()}"
        " — 재생성: node tools/gen-unicode-tables.mjs"
    )
