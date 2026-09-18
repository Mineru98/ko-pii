/**
 * Python↔TS 동등성 회귀 — 차등 실행으로 발견된 불일치의 고정.
 *
 * 기대값은 모두 Python ko-pii(진실 원천)의 실측 출력이다. 오프셋은 UTF-16 코드 유닛으로
 * 환산한 값이다. 테스트를 고쳐 통과시키지 말 것 — 구현이 Python 에 맞춰진다.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectFiles, processPaths } from "../../src/batch.js";
import { pyFloatRepr, pyFormatFixed } from "../../src/core/pyFormat.js";
import { normalizeUnicode } from "../../src/core/unicodeNorm.js";
import { detectAll } from "../../src/detect.js";
import { isLegalDong, legalDongs } from "../../src/dictionaries/legalDongs.js";
import { readRecords } from "../../src/io/dispatcher.js";
import { recordEntries, recordKeys, setField } from "../../src/io/recordOrder.js";
import { redact } from "../../src/modes/redact.js";
import { ReviewQueue } from "../../src/review/queue.js";
import { anonymizeRecords, anonymizeValue, classifySchemaColumns } from "../../src/tabular.js";
import { pyIsoUtc, ReversibleVault } from "../../src/vault/reversible.js";

const cp = (...points: number[]): string => String.fromCodePoint(...points);
/** ASCII 숫자열을 수학 볼드 숫자(U+1D7CE~, 아스트랄)로 치환. */
const mathBold = (s: string): string => s.replace(/[0-9]/g, (d) => cp(0x1d7ce + Number(d)));
const labels = (text: string, inc?: string[] | null, exc?: string[] | null): string[] =>
  detectAll(text, inc, exc).map((d) => d.label);

describe("detectAll include/exclude (Python 의미론)", () => {
  const text = "홍길동 010-1234-5678 hong@example.com";

  it("include 와 exclude 를 둘 다 적용한다", () => {
    expect(labels(text, ["PHONE", "EMAIL"], ["EMAIL"])).toEqual(["PHONE"]);
  });
  it("빈 include 는 필터 없음이다", () => {
    expect(labels(text, [])).toEqual(["PERSON", "PHONE", "EMAIL"]);
  });
  it("exclude 단독", () => {
    expect(labels(text, null, ["PHONE"])).toEqual(["PERSON", "EMAIL"]);
  });
});

describe("법정동 가제티어 (번들 데이터)", () => {
  it("사전이 비어 있지 않다 — 로드 실패를 빈 집합으로 삼키던 회귀 방지", () => {
    expect(legalDongs().size).toBe(10368); // Python len(legal_dongs()) — 10372줄 중 주석 4줄
    expect(isLegalDong("갈월동")).toBe(true);
  });
  it("주거 anchor 가 있는 단독 법정동을 ADDRESS 로 검출한다", () => {
    const dets = detectAll("갈월동으로 이사했어");
    expect(dets.map((d) => [d.label, d.start, d.end])).toEqual([["ADDRESS", 0, 3]]);
  });
});

describe("아스트랄 문자 정규화 (검출 우회 차단)", () => {
  it("수학 숫자를 ASCII 로 폴딩하고 offset 맵이 출력 유닛 수와 같다", () => {
    const src = mathBold("900101-1234567");
    const [norm, omap] = normalizeUnicode(src);
    expect(norm).toBe("900101-1234567");
    expect(omap.length).toBe(norm.length);
    expect(omap[1]).toBe(2); // 두 번째 숫자는 원본 UTF-16 위치 2 (서로게이트 쌍 폭)
  });
  it("수학 숫자 RRN 을 검출하고 원본 span 으로 역매핑한다", () => {
    const text = `주민 ${mathBold("900101-1234567")} 확인`;
    const dets = detectAll(text);
    expect(dets.map((d) => [d.label, d.start, d.end])).toEqual([["RRN", 3, 30]]);
    expect(dets[0]?.text).toBe(mathBold("900101-1234567"));
  });
  it("이모지와 섞여도 span 이 어긋나지 않는다", () => {
    const text = `연락처 ${mathBold("900101-1234567")} / 담당자 김철수${cp(0x1f468, 0x200d, 0x1f469)} 010-9876-5432`;
    expect(detectAll(text).map((d) => [d.label, d.start, d.end])).toEqual([
      ["RRN", 4, 31],
      ["PERSON", 38, 41],
      ["PHONE", 47, 60],
    ]);
  });
  it("redact asterisk 는 코드 포인트 수만큼 채운다", () => {
    const text = `주민 ${mathBold("900101-1234567")} 확인`;
    expect(redact(text, detectAll(text), "asterisk")).toBe(`주민 ${"*".repeat(14)} 확인`);
  });
});

describe("Python 숫자 포맷", () => {
  it("f'{x:.nf}' — 정확한 중간값은 half-even", () => {
    expect(pyFormatFixed(0.125, 2)).toBe("0.12");
    expect(pyFormatFixed(0.625, 2)).toBe("0.62");
    expect(pyFormatFixed(6.25, 1)).toBe("6.2");
    expect(pyFormatFixed(31.25, 1)).toBe("31.2");
    expect(pyFormatFixed(18.75, 1)).toBe("18.8");
    expect(pyFormatFixed(-0.25, 1)).toBe("-0.2");
  });
  it("중간값처럼 보이지만 아닌 값은 그대로 (8.345 는 tie 가 아니다)", () => {
    expect(pyFormatFixed(8.345, 2)).toBe("8.35");
    expect(pyFormatFixed(1.005, 2)).toBe("1.00");
    expect(pyFormatFixed(2.675, 2)).toBe("2.67");
  });
  it("큰 수의 tie 도 정밀도 손실 없이 처리한다", () => {
    expect(pyFormatFixed(872805598677135.25, 1)).toBe("872805598677135.2");
  });
  it("repr(float)", () => {
    expect(pyFloatRepr(1)).toBe("1.0");
    expect(pyFloatRepr(0.1)).toBe("0.1");
    expect(pyFloatRepr(1e-7)).toBe("1e-07");
    expect(pyFloatRepr(1.5e-7)).toBe("1.5e-07");
    expect(pyFloatRepr(0.0001)).toBe("0.0001");
    expect(pyFloatRepr(1e15)).toBe("1000000000000000.0");
    expect(pyFloatRepr(1e16)).toBe("1e+16");
    expect(pyFloatRepr(-0)).toBe("-0.0");
  });
  it("isoformat 은 마이크로초 6자리 (0 이면 소수부 생략)", () => {
    expect(pyIsoUtc(new Date(Date.UTC(2026, 8, 18, 12, 13, 46, 637)))).toBe(
      "2026-09-18T12:13:46.637000+00:00",
    );
    expect(pyIsoUtc(new Date(Date.UTC(2026, 8, 18, 12, 13, 46, 0)))).toBe(
      "2026-09-18T12:13:46+00:00",
    );
  });
});

describe("tabular", () => {
  const vault = () => new ReversibleVault({ salt: "00".repeat(16), secretKey: "k" });

  it("프로토타입 체인 이름의 헤더가 값을 파괴하지 않는다", () => {
    const rec = JSON.parse(
      '{"constructor":"abc","toString":"def","__proto__":"ghi","성명":"홍길동"}',
    );
    const [out] = anonymizeRecords([rec], { vault: vault() });
    expect(Object.entries(out[0] ?? {})).toEqual([
      ["constructor", "abc"],
      ["toString", "def"],
      ["__proto__", "ghi"],
      ["성명", "<PERSON_1>"],
    ]);
  });
  it("asterisk 길이는 코드 포인트 수", () => {
    const [masked] = anonymizeValue(`${cp(0x20bb7)}田太郎`, "PERSON", {
      strategy: "asterisk",
      vault: vault(),
    });
    expect(masked).toBe("****");
  });
  it("헤더 공백 판정은 Python str.isspace 집합", () => {
    const classified = (h: string) => Object.keys(classifySchemaColumns([h])).length;
    expect(classified(`${cp(0x1f)}성명`)).toBe(1);
    expect(classified(`${cp(0x85)} 성명`)).toBe(1);
    expect(classified(" 성 명 ")).toBe(1);
    expect(classified(`${cp(0xfeff)}성명`)).toBe(0); // U+FEFF 는 Python 공백이 아니다
  });
});

describe("batch 파일 수집·실행", () => {
  const roots: string[] = [];
  const cwd = process.cwd();
  afterEach(() => {
    process.chdir(cwd);
    for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
  });

  function fixture(): string {
    const root = mkdtempSync(join(tmpdir(), "ko-pii-parity-"));
    roots.push(root);
    mkdirSync(join(root, "in", "sub"), { recursive: true });
    mkdirSync(join(root, "in", ".hid"));
    mkdirSync(join(root, "target"));
    mkdirSync(join(root, "empty"));
    writeFileSync(join(root, "in", "a.txt"), "연락처 010-1234-5678\n");
    writeFileSync(join(root, "in", "sub", "b.txt"), "메일 hong@example.com\n");
    writeFileSync(join(root, "in", ".hid", "h.txt"), "숨김 010-9999-8888\n");
    writeFileSync(join(root, "target", "real.txt"), "주민 880101-1234568\n");
    symlinkSync("../target/real.txt", join(root, "in", "link.txt"));
    process.chdir(root);
    return root;
  }

  it("경로를 정규화하지 않고 symlink 파일을 포함한다 (os.walk + os.path.join)", () => {
    fixture();
    expect(collectFiles(["./in"])).toEqual([
      "./in/.hid/h.txt",
      "./in/a.txt",
      "./in/link.txt",
      "./in/sub/b.txt",
    ]);
    expect(collectFiles(["in//"])).toEqual([
      "in//.hid/h.txt",
      "in//a.txt",
      "in//link.txt",
      "in//sub/b.txt",
    ]);
    expect(collectFiles(["./in", "in/a.txt"]).length).toBe(5);
  });
  it("glob ** 는 숨김 디렉터리를 제외하고 './' 접두를 보존한다", () => {
    fixture();
    expect(collectFiles(["./in/**/*.txt"])).toEqual([
      "./in/a.txt",
      "./in/link.txt",
      "./in/sub/b.txt",
    ]);
    expect(collectFiles(["in/**"])).toEqual(["in/a.txt", "in/link.txt", "in/sub/b.txt"]);
  });
  it("빈 extensions 는 기본 확장자로 대체된다", () => {
    fixture();
    expect(collectFiles(["in"], true, new Set()).length).toBe(4);
  });
  it("파일 0개 + workers>=2 도 즉시 끝난다", async () => {
    const root = fixture();
    const summary = await processPaths(["empty"], join(root, "out"), {
      workers: 2,
      progress: false,
    });
    expect(summary.totalFiles).toBe(0);
  });
  it("에러 문자열은 Python 예외 클래스명을 쓴다", async () => {
    const root = fixture();
    const summary = await processPaths(["in/a.txt"], join(root, "out"), {
      strategy: "nope",
      progress: false,
    });
    expect(summary.results[0]?.error).toBe("ValueError: Unknown strategy: nope");
  });
});

describe("검수 큐", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
  });
  const tmp = (): string => {
    const root = mkdtempSync(join(tmpdir(), "ko-pii-queue-"));
    roots.push(root);
    return root;
  };

  it("빈 enqueue 도 파일을 만든다", () => {
    const path = join(tmp(), "nested", "q.jsonl");
    new ReviewQueue(path).enqueueReviewRecords([]);
    expect(existsSync(path)).toBe(true);
  });
  it("stats 는 프로토타입 키 verdict 를 집계하지 않는다", () => {
    const path = join(tmp(), "q.jsonl");
    writeFileSync(
      path,
      '{"id":"a","doc":"d","label":"PHONE","text":"x","span":[1,2,3],"confidence":1e-7,"evidence":[],"legal_basis":null,"verdict":"toString","verdict_at":null,"verdict_by":null,"verdict_note":""}\n',
    );
    expect(new ReviewQueue(path).stats()).toEqual({ total: 1, pending: 0, OK: 0, FP: 0, FN: 0 });
  });
  it("객체가 아닌 JSON 라인은 건너뛰지 않고 TypeError", () => {
    const path = join(tmp(), "bad.jsonl");
    writeFileSync(path, "[1, 2]\n");
    expect(() => new ReviewQueue(path).stats()).toThrow(TypeError);
  });
});

describe("레코드 헤더 순서 (Python dict 삽입 순서)", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
  });

  it("정수형·__proto__·중복 헤더 CSV 를 헤더 순서 그대로 읽고 가명화한다", async () => {
    const root = mkdtempSync(join(tmpdir(), "ko-pii-order-"));
    roots.push(root);
    const path = join(root, "t.csv");
    writeFileSync(
      path,
      "성명,2024,2023,1,__proto__,전화번호,10,2024\n홍길동,a,b,c,d,010-1234-5678,e,f\n이영희,m\n",
    );
    const recs = (await readRecords(path)) as Record<string, string | null>[];
    // Python: list(read_records(path)[0].items()) — 중복 헤더 2024 는 첫 자리에 마지막 값
    expect(recordEntries(recs[0] ?? {})).toEqual([
      ["성명", "홍길동"],
      ["2024", "f"],
      ["2023", "b"],
      ["1", "c"],
      ["__proto__", "d"],
      ["전화번호", "010-1234-5678"],
      ["10", "e"],
    ]);
    expect(recordKeys(recs[1] ?? {})).toEqual([
      "성명",
      "2024",
      "2023",
      "1",
      "__proto__",
      "전화번호",
      "10",
    ]);

    const vault = new ReversibleVault({ salt: "00".repeat(16), secretKey: "k" });
    const [out] = anonymizeRecords(recs, { vault });
    expect(recordEntries(out[0] ?? {})).toEqual([
      ["성명", "<PERSON_1>"],
      ["2024", "f"],
      ["2023", "b"],
      ["1", "c"],
      ["__proto__", "d"],
      ["전화번호", "<PHONE_1>"],
      ["10", "e"],
    ]);
  });

  it("setField 는 기존 키의 자리를 지키고, 순서 정보가 없으면 Object.keys 로 폴백한다", () => {
    const rec: Record<string, string> = {};
    setField(rec, "b", "1");
    setField(rec, "2", "x");
    setField(rec, "b", "9");
    expect(recordEntries(rec)).toEqual([
      ["b", "9"],
      ["2", "x"],
    ]);
    expect(Object.keys(rec)).toEqual(["2", "b"]); // JS 열거 순서는 여전히 정수 키 우선
    expect(recordKeys({ z: 1, a: 2 })).toEqual(["z", "a"]);
  });
});

describe("리뷰 지적 회귀 (Python 실측)", () => {
  const roots: string[] = [];
  const cwd = process.cwd();
  afterEach(() => {
    process.chdir(cwd);
    for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
  });

  it("pyFormatFixed: digits=0 tie, -0.0, 1e21 이상, inf/nan", () => {
    expect(pyFormatFixed(0.5, 0)).toBe("0");
    expect(pyFormatFixed(1.5, 0)).toBe("2");
    expect(pyFormatFixed(2.5, 0)).toBe("2");
    expect(pyFormatFixed(-0.5, 0)).toBe("-0");
    expect(pyFormatFixed(-0, 2)).toBe("-0.00");
    expect(pyFormatFixed(-0.001, 2)).toBe("-0.00");
    expect(pyFormatFixed(1e21, 2)).toBe("1000000000000000000000.00");
    expect(pyFormatFixed(-1e21, 0)).toBe("-1000000000000000000000");
    expect(pyFormatFixed(Number.POSITIVE_INFINITY, 2)).toBe("inf");
    expect(pyFormatFixed(Number.NEGATIVE_INFINITY, 2)).toBe("-inf");
    expect(pyFormatFixed(Number.NaN, 2)).toBe("nan");
  });

  it("include truthiness 는 Python 규칙 — 빈 컨테이너는 필터 없음, 빈 제너레이터는 전부 제외", () => {
    const text = "홍길동 010-1234-5678 hong@example.com";
    const lab = (inc: Iterable<string>) => detectAll(text, inc).map((d) => d.label);
    expect(lab([])).toEqual(["PERSON", "PHONE", "EMAIL"]);
    expect(lab(new Set())).toEqual(["PERSON", "PHONE", "EMAIL"]);
    expect(lab((function* (): Generator<string> {})())).toEqual([]);
    expect(
      lab(
        (function* (): Generator<string> {
          yield "PHONE";
        })(),
      ),
    ).toEqual(["PHONE"]);
  });

  it("symlink 루프가 있어도 수집이 예외 없이 끝난다 (os.path.isdir 는 ELOOP 를 False 로)", () => {
    const root = mkdtempSync(join(tmpdir(), "ko-pii-loop-"));
    roots.push(root);
    mkdirSync(join(root, "in", "sub2"), { recursive: true });
    writeFileSync(join(root, "in", "a.txt"), "연락처 010-1234-5678\n");
    writeFileSync(join(root, "in", "sub2", "b.txt"), "x hong@example.com\n");
    symlinkSync("..", join(root, "in", "sub2", "loop"));
    process.chdir(root);
    // Python: len(collect_files(["in/**/*.txt"])) == 66 (루프를 ELOOP 직전까지 따라간다)
    const globbed = collectFiles(["in/**/*.txt"]);
    expect(globbed.length).toBe(66);
    expect(globbed.slice(0, 2)).toEqual(["in/a.txt", "in/sub2/b.txt"]);
    expect(collectFiles(["in"])).toEqual(["in/a.txt", "in/sub2/b.txt"]);
  });

  it("검수 큐는 \\r 줄 구분과 BOM 첫 줄을 Python 처럼 처리한다", () => {
    const root = mkdtempSync(join(tmpdir(), "ko-pii-qbom-"));
    roots.push(root);
    const line = (id: string, verdict: string | null) =>
      JSON.stringify({
        id,
        doc: "d",
        label: "PHONE",
        text: "x",
        span: [1, 2],
        confidence: 0.5,
        evidence: [],
        legal_basis: null,
        verdict,
        verdict_at: null,
        verdict_by: null,
        verdict_note: "",
      });
    const path = join(root, "q.jsonl");
    // BOM 으로 시작하는 첫 줄은 Python strip() 이 BOM 을 남겨 JSONDecodeError 로 버려진다
    writeFileSync(path, `${cp(0xfeff)}${line("a", null)}\r${line("b", "OK")}\r`);
    expect(new ReviewQueue(path).stats()).toEqual({ total: 1, pending: 0, OK: 1, FP: 0, FN: 0 });
  });
});
