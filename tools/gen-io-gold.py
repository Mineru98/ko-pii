#!/usr/bin/env python3
"""M3 파일 I/O 골드 벡터 생성 — 픽스처 문서 제작 + Python 추출기 출력 dump.

실행: /tmp/ko-pii-venv/bin/python3 tools/gen-io-gold.py   (olefile/pdfplumber/pypdf 필요)
출력: spec/fixtures/io/*.{txt,csv,tsv,docx,hwpx,xlsx,pdf,hwp}
      spec/goldmaster/io.json

픽스처는 본 스크립트가 stdlib(zipfile/struct/zlib)만으로 제작한다. HWP 5.x 는
OLE 컨테이너 조립만 Node(cfb) 도구가 담당한다(tools/build-hwp-fixture.mjs) —
본 스크립트가 스트림 바이트를 만들고 subprocess 로 node 를 호출한 뒤 추출한다.

골드는 Python 추출기가 진실 원천:
- raw_text      — 포맷별 extractor read_text 원본 출력
- read_text     — dispatcher 경로 (normalize_for_detection 적용, TS readText 대상)
- read_records  — 표 형식(csv/tsv/xlsx)
- hwp_primitives— _iter_records/_decode_para_text 합성 스트림 벡터 (단위 정합용)
"""
from __future__ import annotations

import json
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "python"))

FIX = ROOT / "spec" / "fixtures" / "io"
OUT = ROOT / "spec" / "goldmaster"

DOC_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>신청서</w:t></w:r></w:p>
<w:p><w:r><w:t>성명: 홍길동</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>연락처 010-1234-5678</w:t></w:r></w:p>
<w:p><w:r><w:t>주민번호 880101-1234568</w:t></w:r><w:r><w:br/></w:r><w:r><w:t>주소 서울특별시 강남구 테헤란로 152</w:t></w:r></w:p>
</w:body></w:document>"""

CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:title>개인정보 동의서</dc:title><dc:creator>홍길동</dc:creator>
<cp:lastModifiedBy>김철수</cp:lastModifiedBy></cp:coreProperties>"""

HEADER_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:p><w:r><w:t>문서번호 2026-001</w:t></w:r></w:p></w:hdr>"""

HWPX_SECTION = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<hs:root xmlns:hs="http://www.hancom.co.kr/hwpml/1.0/section">
<hs:p><hs:run><hs:t>개인정보 처리동의서</hs:t></hs:run></hs:p>
<hs:p><hs:run><hs:t>성명 홍길동</hs:t></hs:run><hs:lineBreak/><hs:run><hs:t>주민등록번호 880101-1234568</hs:t></hs:run></hs:p>
<hs:p><hs:run><hs:t>테헤란로 152</hs:t></hs:run></hs:p>
</hs:root>"""

HWPX_CORE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<core xmlns="http://www.hancom.co.kr/hwpml/1.0/core">
<Author>홍길동</Author><Title>동의서</Title></core>"""


def build_text_fixtures() -> None:
    (FIX / "sample.txt").write_text(
        "신청인 홍길동 (880101-1234568) 연락처 010-1234-5678\n"
        "주소: 서울특별시 강남구 테헤란로 152\n",
        encoding="utf-8",
    )
    (FIX / "sample_bom.txt").write_text("작성자 홍길동\n", encoding="utf-8-sig")
    (FIX / "sample_euckr.txt").write_text("작성자 홍길동 연락처 010-1234-5678\n", encoding="cp949")
    (FIX / "sample.csv").write_text(
        '성명,주민번호,연락처\n홍길동,880101-1234568,010-1234-5678\n'
        '"김철수,둘리",900101-2123456,"02-123-4567"\n',
        encoding="utf-8",
    )
    (FIX / "sample.tsv").write_text(
        "성명\t주민번호\n홍길동\t880101-1234568\n김철수\t900101-2123456\n",
        encoding="utf-8",
    )


def build_docx() -> None:
    with zipfile.ZipFile(FIX / "sample.docx", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("docProps/core.xml", CORE_XML)
        zf.writestr("word/document.xml", DOC_XML)
        zf.writestr("word/header1.xml", HEADER_XML)


def build_hwpx() -> None:
    with zipfile.ZipFile(FIX / "sample.hwpx", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/core.xml", HWPX_CORE)
        zf.writestr("Contents/section0.xml", HWPX_SECTION)


def build_xlsx() -> None:
    shared = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<si><t>성명</t></si><si><t>주민번호</t></si><si><t>홍길동</t></si>
<si><t>880101-1234568</t></si><si><t>김철수</t></si><si><t>900101-2123456</t></si>
</sst>"""
    sheet1 = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>
<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2" t="s"><v>3</v></c><c r="C2" t="inlineStr"><is><t>비고</t></is></c></row>
<row r="3"><c r="A3" t="s"><v>4</v></c><c r="B3" t="s"><v>5</v></c><c r="C3"><v>35</v></c></row>
</sheetData></worksheet>"""
    with zipfile.ZipFile(FIX / "sample.xlsx", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/sharedStrings.xml", shared)
        zf.writestr("xl/worksheets/sheet1.xml", sheet1)


def build_pdf() -> None:
    # 최소 PDF 1.4 — ASCII 텍스트 2줄(두 번째 줄은 하이픈 개행 분할 RRN 복원 대상).
    # 한국어 CID 폰트 없이 표준 인코딩으로 추출 가능한 형태.
    content = b"BT /F1 12 Tf 72 720 Td (Appliant: Hong Gildong) Tj ET\n"
    content += b"BT /F1 12 Tf 72 700 Td (RRN: 880101-) Tj ET\n"
    content += b"BT /F1 12 Tf 72 686 Td (1234568) Tj ET\n"
    stream_len = len(content)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(stream_len).encode() + b" >>\nstream\n" + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf = b"%PDF-1.4\n"
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(pdf)
    pdf += b"xref\n0 6\n0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode()
    pdf += (
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref_pos).encode()
        + b"\n%%EOF\n"
    )
    (FIX / "sample.pdf").write_bytes(pdf)


def build_hwp_parts() -> None:
    """HWP 레코드 스트림 제작 — FileHeader/BodyText 스트림 바이트를 파일로 남긴다.

    PARA_TEXT 제어 문자 처리(0x0D 문단구분, 0x09 탭+14바이트, control+14바이트
    skip)를 검증하는 바이트를 포함한다.
    """
    def record(tag: int, body: bytes, level: int = 0) -> bytes:
        assert len(body) < 0xFFF
        header = (tag & 0x3FF) | ((level & 0x3FF) << 10) | (len(body) & 0xFFF) << 20
        return struct.pack("<I", header) + body

    def para_text(text_utf16_units: list[int]) -> bytes:
        return struct.pack("<HII", 0, len(text_utf16_units), 0) + b"".join(
            struct.pack("<H", u) for u in text_utf16_units
        )

    # 문단 1: "신청인 홍길동 (880101-1234568)" + 0x0D
    p1 = [ord(c) for c in "신청인 홍길동 (880101-1234568)"] + [0x0D]
    # 문단 2: "연락처" + TAB(0x09 + 14B 데이터) + "010-1234-5678" + 0x0D
    p2 = [ord(c) for c in "연락처"] + [0x09] + [0x00] * 14 + [ord(c) for c in "010-1234-5678"] + [0x0D]
    # 문단 3: "비고" + control-with-data(0x05 + 14B) + "홍OO" + 0x00(char control, no data)
    p3 = [ord(c) for c in "비고"] + [0x05] + [0x00] * 14 + [ord(c) for c in "홍OO"] + [0x00]

    records = b""
    records += record(0x42, struct.pack("<HII", 0, 0, 0))  # PARA_HEADER
    records += record(0x43, para_text(p1))
    records += record(0x42, struct.pack("<HII", 0, 0, 0))
    records += record(0x43, para_text(p2))
    records += record(0x42, struct.pack("<HII", 0, 0, 0))
    records += record(0x43, para_text(p3))

    header = bytearray(256)
    sig = b"HWP Document File"
    header[: len(sig)] = sig
    header[36] = 0x01  # compressed flag
    header[32:36] = (5, 0, 0, 1)  # major/minor/patch/extra 버전

    (FIX / "_hwp_FileHeader.bin").write_bytes(bytes(header))
    (FIX / "_hwp_BodyText_Section0.bin").write_bytes(zlib.compress(records, level=6, wbits=-15))


def hwp_primitives_gold() -> dict:
    """_iter_records/_decode_para_text 합성 벡터 — 0xFFF 확장 사이즈 포함."""
    from ko_pii.io_.hwp import _decode_para_text, _iter_records

    big = b"A" * 0x1200
    header = (0x43 & 0x3FF) | (0 & 0x3FF << 0) | (0xFFF << 20)
    stream = struct.pack("<I", header) + struct.pack("<I", len(big)) + big
    records = [
        {"tag": tag, "level": level, "size": len(body)}
        for tag, level, body in _iter_records(stream)
    ]
    decode_cases = [
        {"body_hex": bytes([0x48, 0x00, 0x69, 0x00]).hex(), "text": None},
        {"body_hex": bytes([0x0D, 0x00, 0x41, 0x00]).hex(), "text": None},
        {"body_hex": bytes([0x09, 0x00] + [0x00] * 14 + [0x41, 0x00]).hex(), "text": None},
        {"body_hex": bytes([0x05, 0x00] + [0x00] * 14 + [0x41, 0x00]).hex(), "text": None},
        {"body_hex": bytes([0x00, 0x00, 0x42, 0x00]).hex(), "text": None},
    ]
    for c in decode_cases:
        c["text"] = _decode_para_text(bytes.fromhex(c["body_hex"]))
    return {"extended_size_stream": {"hex": stream.hex(), "records": records}, "decode_cases": decode_cases}


def main() -> int:
    FIX.mkdir(parents=True, exist_ok=True)
    build_text_fixtures()
    build_docx()
    build_hwpx()
    build_xlsx()
    build_pdf()
    build_hwp_parts()

    # HWP OLE 조립은 Node(cfb) 도구가 담당
    subprocess.run(
        ["node", str(ROOT / "tools" / "build-hwp-fixture.mjs")], check=True,
        cwd=ROOT,
    )

    from ko_pii.io_.dispatcher import read_records, read_text
    from ko_pii.io_ import csv_reader, docx, hwpx, hwp, plain, pdf, xlsx

    entries = []

    def record(file: str, fmt: str, raw: str, records=None) -> None:
        entry = {"file": file, "format": fmt, "raw_text": raw, "read_text": read_text(str(FIX / file))}
        if records is not None:
            entry["read_records"] = records
        entries.append(entry)

    record("sample.txt", "plain", plain.read_text(str(FIX / "sample.txt")))
    record("sample_bom.txt", "plain", plain.read_text(str(FIX / "sample_bom.txt")))
    record("sample_euckr.txt", "plain", plain.read_text(str(FIX / "sample_euckr.txt")))
    record("sample.csv", "csv", csv_reader.read_text(str(FIX / "sample.csv")),
           csv_reader.read_records(str(FIX / "sample.csv")))
    record("sample.tsv", "tsv", csv_reader.read_text(str(FIX / "sample.tsv")),
           csv_reader.read_records(str(FIX / "sample.tsv")))
    record("sample.docx", "docx", docx.read_text(str(FIX / "sample.docx")))
    record("sample.hwpx", "hwpx", hwpx.read_text(str(FIX / "sample.hwpx")))
    record("sample.xlsx", "xlsx", xlsx.read_text(str(FIX / "sample.xlsx")),
           xlsx.read_records(str(FIX / "sample.xlsx")))
    record("sample.pdf", "pdf", pdf.read_text(str(FIX / "sample.pdf")))
    record("sample.hwp", "hwp", hwp.read_text(str(FIX / "sample.hwp")))

    payload = {
        "generator": "tools/gen-io-gold.py",
        "fixtures": entries,
        "hwp_primitives": hwp_primitives_gold(),
    }
    (OUT / "io.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    print(f"fixtures: {len(list(FIX.iterdir()))} files, gold entries: {len(entries)}")
    print(f"-> {OUT / 'io.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
