"""demo/app.py 의 process() 출력을 기준값(reference.json)으로 떠낸다.

app.py 를 *수정 없이 그대로* import 해 호출한다. 결정성을 위해 세 가지만 고정한다:
  - gradio: 미설치여도 import 되도록 MagicMock 으로 대체 (UI 구성 코드는 process 와 무관)
  - time.time: 0 고정 → 엔진 라벨이 항상 "ko-pii (0ms)"
  - 비교 엔진 로더: None 고정 → openai/Presidio "미설치" 분기 (브라우저에는 두 엔진이 없다)

Usage: .venv/bin/python demo/web/parity/gen_reference.py
"""
from __future__ import annotations

import importlib.util
import itertools
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

HERE = Path(__file__).resolve().parent
APP = HERE.parents[1] / "app.py"

sys.modules.setdefault("gradio", MagicMock())
spec = importlib.util.spec_from_file_location("demo_app", APP)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

# app 네임스페이스의 참조만 바꾼다 — 전역 time.time 을 건드리면 라이브러리의
# "현재 날짜" 기반 검증(RRN 생년 유효성 등)까지 1970년 기준으로 바뀐다.
app.time = SimpleNamespace(time=lambda: 0.0)
app._get_openai = lambda: None
app._get_presidio = lambda: None

MODES = ["PARANOID", "STRICT", "BALANCED", "PERMISSIVE", "AUDIT"]

EXTRA_TEXTS = [
    "",
    "   \n\t ",
    "\x1c\x1f",  # Python strip() 은 지우지만 JS trim() 은 안 지우는 공백
    "﻿",  # JS trim() 은 지우지만 Python strip() 은 안 지우는 문자
    "오늘 날씨가 맑습니다. 개인정보 없음.",
    "<b>김민지</b> & \"연락처\" '010-1234-5678' <script>alert(1)</script>",
    "😀 담당자 박철수 010-2222-3333 👍🏽 메일 a.b@example.com 🇰🇷",
    "김민지 010-1234-5678 / 김민지 010-1234-5678 / 박철수 010-1234-5678",  # 토큰 재사용
    "주민번호 880101-2123456, 잘못된 체크섬 880101-2123457",
    "카드 4111-1111-1111-1111 계좌 110-123-456789 법인 110111-1234567",
    "키 175cm 몸무게 70kg 나이 34세, 서울대학교 컴퓨터공학과 졸업, 과장",
    "줄바꿈\r\n혼합\n홍길동 (010-9876-5432)\r\n끝",
    "０１０－１２３４－５６７８ 전각 숫자와 ﬁ 합자",
]

texts = [ex[0] for ex in app.EXAMPLES] + EXTRA_TEXTS
cases = []
for text, mode in itertools.product(texts, MODES):
    for show_openai, show_presidio in itertools.product([False, True], repeat=2):
        out = app.process(text, mode, show_openai, show_presidio)
        cases.append({"input": [text, mode, show_openai, show_presidio], "output": list(out)})

# 숫자 포맷은 입력 텍스트로는 격자 밖 값에 도달할 수 없어(confidence 는 0.05 격자, ms 는 0 고정)
# 포맷 결과 표를 따로 떠서 TS 포맷 함수와 직접 대조한다.
grid = [i / 1000 for i in range(0, 1001)] + [0.6000000000000001, 0.15000000000000002]
formats = {
    "percent0": [[x, f"{x:.0%}"] for x in grid],
    "round0": [[x, f"{x:.0f}"] for x in [i / 4 for i in range(0, 2001)] + [0.49999999999999994, 1234.5, 99999.5]],
}
# app.py 의 EXAMPLES 자체도 TS 쪽 상수와 대조한다.
ref = {"examples": [list(ex) for ex in app.EXAMPLES], "formats": formats, "cases": cases}
out_path = HERE / "reference.json"
out_path.write_text(json.dumps(ref, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"{len(cases)} cases + {sum(map(len, formats.values()))} format rows -> {out_path}")
