#!/usr/bin/env python3
"""integrations(hybrid 병합) 회귀 픽스처 생성 — Python ko-pii 를 진실 원천으로.

실행: python3 tools/gen-integrations-fixture.py [--check]
출력: src/ts/tests/unit/integrations.fixture.json
      (소비: src/ts/tests/unit/integrations.test.ts)

무작위(고정 seed) 검출 목록 × 6 병합 모드와, MockSecondaryDetector 를 붙인 Anonymizer
전체 경로의 Python 실측 출력을 기록한다. 픽스처는 수동 편집 금지 — Python 동작을
바꿨다면 재생성 후 diff 를 리뷰한다. 생성 뒤 `npx biome format --write` 로 포맷을 맞춘다
(--check 는 포맷과 무관하게 JSON 값으로 비교한다).
"""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "python"))

from ko_pii.anonymizer import Anonymizer  # noqa: E402
from ko_pii.core.modes import ProcessingMode  # noqa: E402
from ko_pii.core.types import DetectionResult, RiskLevel  # noqa: E402
from ko_pii.integrations import MergeMode, MockSecondaryDetector, merge_detections  # noqa: E402
from ko_pii.vault.reversible import ReversibleVault  # noqa: E402

OUT = ROOT / "src" / "ts" / "tests" / "unit" / "integrations.fixture.json"

random.seed(23)
LABELS = ["PERSON", "ADDRESS", "PHONE", "RRN", "EMAIL", "POSITION", "AGE", "CARD"]
CONFS = [0.3, 0.5, 0.55, 0.7, 0.85, 0.9, 0.95, 0.96, 1.0]


def det_to_dict(d):
    return {
        "label": d.label, "text": d.text, "start": d.start, "end": d.end,
        "risk": int(d.risk_level), "conf": d.confidence, "evidence": list(d.evidence),
        "legal_basis": d.legal_basis, "extra": dict(d.extra),
    }


def rand_det(n):
    a = random.randrange(0, n - 1)
    b = min(n, a + random.randrange(1, 9))
    return {
        "label": random.choice(LABELS), "text": "x" * (b - a), "start": a, "end": b,
        "risk": random.randrange(1, 6), "conf": random.choice(CONFS),
        "evidence": random.sample(["a", "b", "pos:x"], random.randrange(0, 3)),
        "legal_basis": random.choice([None, "법 제2조"]),
        "extra": random.choice([{}, {"k": 1}, {"cross_val": "old"}]),
    }


def mk(d):
    return DetectionResult(
        label=d["label"], text=d["text"], start=d["start"], end=d["end"],
        risk_level=RiskLevel(d["risk"]), confidence=d["conf"], evidence=list(d["evidence"]),
        legal_basis=d["legal_basis"], extra=dict(d["extra"]),
    )


cases = []
for _ in range(400):
    n = random.randrange(10, 40)
    prim = [rand_det(n) for _ in range(random.randrange(0, 6))]
    sec = [rand_det(n) for _ in range(random.randrange(0, 6))]
    # 일치(같은 라벨·겹침) 케이스를 의도적으로 섞는다
    if prim and random.random() < 0.6:
        c = dict(random.choice(prim))
        c["conf"] = random.choice(CONFS)
        c["evidence"] = ["sec"]
        sec.append(c)
    rsl = random.choice([None, [], ["PERSON"], ["PHONE", "RRN", "CARD"]])
    res = {}
    for mode in MergeMode:
        out = merge_detections([mk(d) for d in prim], [mk(d) for d in sec], mode=mode, role_split_labels=rsl)
        res[mode.value] = [det_to_dict(d) for d in out]
    cases.append({"primary": prim, "secondary": sec, "rsl": rsl, "result": res})

# Anonymizer + MockSecondaryDetector 전체 경로
TEXTS = [
    "담당자 홍길동 과장 010-1234-5678 서울특별시 강남구 테헤란로 152",
    "신청인 김철수 (880101-1234568) hong@example.com 박영희 팀장",
    "회의 참석: 이민수, 최지우. 연락처 02-345-6789",
]
anon = []
for text in TEXTS:
    fixed = []
    for word, label, risk, conf in [
        ("홍길동", "PERSON", 3, 0.99), ("과장", "POSITION", 2, 0.8), ("김철수", "PERSON", 3, 0.6),
        ("이민수", "PERSON", 3, 0.9), ("최지우", "PERSON", 3, 0.4), ("테헤란로 152", "ADDRESS", 3, 0.9),
        ("010-1234-5678", "PHONE", 4, 0.5), ("회의", "PERSON", 3, 0.95),
    ]:
        i = text.find(word)
        if i >= 0:
            fixed.append({"label": label, "text": word, "start": i, "end": i + len(word), "risk": risk,
                          "conf": conf, "evidence": ["ml"], "legal_basis": None, "extra": {}})
    for mode in [m.value for m in MergeMode]:
        for inc, exc in [(None, None), (["PERSON", "PHONE"], None), (None, ["PERSON"]), ([], [])]:
            for strategy in ["tokenize", "redact", "partial"]:
                v = ReversibleVault(salt="00" * 16, secret_key="k", fingerprint_iterations=1)
                a = Anonymizer(mode=ProcessingMode.STRICT, strategy=strategy, vault=v, include=inc, exclude=exc,
                               secondary_detector=MockSecondaryDetector([mk(d) for d in fixed]), merge_mode=mode)
                r = a.process(text)
                anon.append({
                    "text": text, "fixed": fixed, "mode": mode, "inc": inc, "exc": exc, "strategy": strategy,
                    "out": r.text,
                    "records": [[x.detection.label, x.action.value, x.token, x.detection.start, x.detection.end,
                                 x.detection.confidence, list(x.detection.evidence)] for x in r.detections],
                    "summary": r.summary,
                })
try:
    Anonymizer(merge_mode="bogus", secondary_detector=MockSecondaryDetector([])).process("x")
    bad = "no error"
except Exception as e:  # noqa: BLE001
    bad = f"{type(e).__name__}: {e}"

def build() -> dict:
    # 회귀용 부분집합: primary·secondary 가 모두 있는 앞쪽 케이스 + role_split 라벨 변형별 1개 이상
    picked, seen = [], set()
    for c in cases:
        key = json.dumps(c["rsl"])
        if c["primary"] and c["secondary"] and (len(picked) < 10 or key not in seen):
            picked.append(c)
            seen.add(key)
        if len(picked) >= 14 and len(seen) >= 4:
            break
    return {
        "_comment": "Python ko-pii 실측 출력 (tools/gen-integrations-fixture.py, seed 23). 수동 편집 금지 — 구현이 이 값에 맞춰진다.",
        "cases": picked,
        "anon": [a for a in anon if a["strategy"] == "tokenize"][::4][:18],
        "bad_mode": bad,
    }


def main(argv: list[str]) -> int:
    payload = build()
    if "--check" in argv:
        current = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else None
        # JSON 왕복으로 정규화해 비교 (포맷·float 표기 무관)
        if current != json.loads(json.dumps(payload)):
            print(f"드리프트: {OUT} — python3 tools/gen-integrations-fixture.py 로 재생성", file=sys.stderr)
            return 1
        print(f"ok: {OUT.name} 가 Python 구현과 동기화됨 (merge {len(payload['cases'])}건, anon {len(payload['anon'])}건)")
        return 0
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} (merge {len(payload['cases'])}건, anon {len(payload['anon'])}건)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
