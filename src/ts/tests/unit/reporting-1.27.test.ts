/**
 * Reporting 1.27 — Python tests/unit/reporting/test_html_integrity.py, test_certificate.py,
 * test_summary.py 대응 + Python 실측 출력과의 바이트 대조 (reporting-1.27.fixture.json,
 * .venv/bin/python ko_pii 1.27.0 으로 생성; report_id·생성 일시는 자리표시자로 치환).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { type AnonymizationResult, Anonymizer, reviewItems } from "../../src/anonymizer.js";
import { Action, ProcessingMode } from "../../src/core/modes.js";
import { generateCertificate } from "../../src/reporting/certificate.js";
import { generateHtmlReport } from "../../src/reporting/htmlReport.js";
import * as reporting from "../../src/reporting/index.js";
import { formatSummaryText, reviewQueue, summarize } from "../../src/reporting/summary.js";

interface FixtureCase {
  name: string;
  text: string;
  mode: string;
  strategy: string;
  strategies: Record<string, string> | null;
  html_kwargs: { document_id?: string; enable_marking?: boolean };
  html: string;
  certificates: { default: string; all: string; review: string };
  summary_text: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(
  readFileSync(join(here, "reporting-1.27.fixture.json"), "utf8"),
) as FixtureCase[];

const RID = /"report_id": "[0-9a-f]{32}"/g;
const NOW = /생성 일시\(UTC\): .*/g;

function processCase(c: FixtureCase): AnonymizationResult {
  return new Anonymizer(
    c.mode as ProcessingMode,
    c.strategy,
    null,
    null,
    null,
    null,
    "union",
    null,
    null,
    { strategies: c.strategies },
  ).process(c.text);
}

describe("Python 1.27 실측 출력과 바이트 대조", () => {
  for (const c of FIXTURE) {
    it(`HTML 리포트 — ${c.name}`, () => {
      const html = generateHtmlReport(c.text, processCase(c), {
        documentId: c.html_kwargs.document_id,
        enableMarking: c.html_kwargs.enable_marking,
      });
      expect(html.replace(RID, '"report_id": "<RID>"')).toBe(c.html);
    });
    it(`format_summary_text — ${c.name}`, () => {
      expect(formatSummaryText(processCase(c))).toBe(c.summary_text);
    });
    // 증명서의 source_span 은 explain() 의 UTF-16 좌표라 아스트랄 문자 문서에서는 Python 과 다르다.
    if (c.name === "emoji-redact") continue;
    it(`증명서 — ${c.name}`, () => {
      const result = processCase(c);
      const norm = (s: string) => s.replace(NOW, "생성 일시(UTC): <NOW>");
      expect(norm(generateCertificate(result))).toBe(c.certificates.default);
      expect(
        norm(
          generateCertificate(result, "doc-9", true, {
            includeDocumentId: true,
            includeReplacements: true,
          }),
        ),
      ).toBe(c.certificates.all);
      expect(norm(generateCertificate(result, "(unspecified)", true))).toBe(c.certificates.review);
    });
  }
});

// ───────────────────────────── test_html_integrity.py

type Attrs = Record<string, string>;

function unescapeHtml(s: string): string {
  return s
    .replaceAll("&quot;", '"')
    .replaceAll("&#x27;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

interface Page {
  findings: Attrs[];
  metadata: Record<string, unknown> | null;
  script: string;
}

/** Python HTMLParser 기반 Page 대응 — 생성기가 만드는 고정 마크업만 해석한다. */
function parsePage(html: string): Page {
  const findings: Attrs[] = [];
  for (const m of html.matchAll(/<span ([^>]*data-finding-id="[^"]*"[^>]*)>/g)) {
    const attrs: Attrs = {};
    for (const a of (m[1] as string).matchAll(/([\w-]+)="([^"]*)"/g)) {
      attrs[a[1] as string] = unescapeHtml(a[2] as string);
    }
    findings.push(attrs);
  }
  const meta = /<script id="reviewMetadata" type="application\/json">([^<]*)<\/script>/.exec(html);
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1] as string);
  return {
    findings,
    metadata: meta ? (JSON.parse(meta[1] as string) as Record<string, unknown>) : null,
    script: scripts.join(""),
  };
}

const SOURCE = "첫 요청: 880101-1234567 / 두 번째 요청: 880101-1234567";

function reviewPage(): Page {
  const result = new Anonymizer(ProcessingMode.PERMISSIVE).process(SOURCE);
  expect(reviewItems(result)).toHaveLength(2);
  return parsePage(generateHtmlReport(SOURCE, result, { documentId: "sensitive-document-id" }));
}

interface Interaction {
  download: Record<string, unknown> & { items: Record<string, unknown>[] };
  count: string;
  revoked: boolean;
  pressed: string[][];
}

/** Python RUNNER (node -e) 대응 — 생성된 JS 를 vm 에서 실행한다. */
function interact(page: Page, operations: { index: number; verdict: string }[]): Interaction {
  let download: Interaction["download"] | null = null;
  let revoked = false;
  const counter = { textContent: "0" };
  type Button = {
    parentElement: { previousElementSibling: unknown; children: Button[] };
    attributes: Record<string, string>;
    setAttribute(name: string, value: string): void;
  };
  const buttons = page.findings.map((attrs) => {
    const span = {
      dataset: {
        findingId: attrs["data-finding-id"],
        label: attrs["data-label"],
        reviewLabel: attrs["data-review-label"],
        start: attrs["data-start"],
        end: attrs["data-end"],
        token: attrs["data-token"],
      },
      style: {},
    };
    const parent = { previousElementSibling: span, children: [] as Button[] };
    parent.children = ["OK", "FP"].map(() => ({
      parentElement: parent,
      attributes: { "aria-pressed": "false" } as Record<string, string>,
      setAttribute(name: string, value: string) {
        this.attributes[name] = value;
      },
    }));
    return parent.children;
  });
  const context = vm.createContext({
    document: {
      getElementById(id: string) {
        return id === "reviewMetadata" ? { textContent: JSON.stringify(page.metadata) } : counter;
      },
      createElement() {
        return { click() {} };
      },
    },
    Blob: class {
      constructor(parts: string[]) {
        download = JSON.parse(parts.join(""));
      }
    },
    URL: {
      createObjectURL() {
        return "blob:local";
      },
      revokeObjectURL() {
        revoked = true;
      },
    },
    setTimeout(callback: () => void) {
      callback();
    },
  });
  vm.runInContext(page.script, context);
  const ctx = context as unknown as {
    mark(btn: Button, verdict: string): void;
    exportMarks(): void;
  };
  for (const op of operations) {
    const pair = buttons[op.index] as Button[];
    ctx.mark(pair[op.verdict === "FP" ? 1 : 0] as Button, op.verdict);
  }
  ctx.exportMarks();
  return {
    download: download as unknown as Interaction["download"],
    count: counter.textContent,
    revoked,
    pressed: buttons.map((pair) => pair.map((b) => b.attributes["aria-pressed"] as string)),
  };
}

describe("HTML 검토 — 위치별(per-occurrence) 마킹", () => {
  it("반복 값도 위치별 독립 판정을 유지", () => {
    const observed = interact(reviewPage(), [
      { index: 1, verdict: "FP" },
      { index: 0, verdict: "OK" },
    ]);
    const payload = observed.download;
    expect(payload.contract).toBe("ko-pii-html-review-marks-v1");
    expect(payload.schema_version).toBe(1);
    expect(payload.scope).toBe("selected_occurrences_only");
    expect(payload.offset_unit).toBe("python_code_points");
    expect(payload.report_id).toMatch(/^[0-9a-f]{12}4[0-9a-f]{19}$/);
    expect(payload.source_characters).toBe(SOURCE.length);
    expect(payload.items.map((i) => i.verdict)).toEqual(["OK", "FP"]);
    expect(payload.items.map((i) => i.source_span)).toEqual([
      [6, 20],
      [32, 46],
    ]);
    expect(new Set(payload.items.map((i) => i.finding_id)).size).toBe(2);
    expect(observed.count).toBe("2");
    expect(observed.revoked).toBe(true);
    expect(observed.pressed).toEqual([
      ["true", "false"],
      ["false", "true"],
    ]);
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain("880101");
    expect(serialized).not.toContain("sensitive-document-id");
  });

  it("한 위치의 수정이 다른 위치를 바꾸지 않는다", () => {
    const observed = interact(reviewPage(), [
      { index: 0, verdict: "OK" },
      { index: 1, verdict: "OK" },
      { index: 0, verdict: "FP" },
    ]);
    expect(observed.download.items.map((i) => i.verdict)).toEqual(["FP", "OK"]);
    expect(observed.count).toBe("2");
  });

  it("빈/잘못된 마킹은 완료를 주장하지 않는다", () => {
    const observed = interact(reviewPage(), [{ index: 0, verdict: "APPROVED" }]);
    expect(observed.download.items).toEqual([]);
    expect(observed.count).toBe("0");
    expect(observed.download.scope).toBe("selected_occurrences_only");
  });

  it("메타데이터는 리포트별이며 문서 식별자를 담지 않는다", () => {
    const first = reviewPage();
    const second = reviewPage();
    expect(first.metadata?.report_id).not.toBe(second.metadata?.report_id);
    expect(new Set(Object.keys(first.metadata ?? {}))).toEqual(
      new Set([
        "schema_version",
        "contract",
        "report_id",
        "scope",
        "offset_unit",
        "source_characters",
      ]),
    );
  });

  it("사용자 정의 라벨은 값 없는 다운로드에 복사되지 않는다", () => {
    const result = new Anonymizer(ProcessingMode.PERMISSIVE).process(SOURCE);
    (result.detections[0] as { detection: { label: string } }).detection.label =
      "sensitive-user-name";
    const observed = interact(parsePage(generateHtmlReport(SOURCE, result)), [
      { index: 0, verdict: "OK" },
    ]).download;
    expect(observed.items[0]?.label).toBe("UNKNOWN");
    expect(JSON.stringify(observed)).not.toContain("sensitive-user-name");
  });

  it("아스트랄 문자 문서도 data-start/end·source_characters 는 코드 포인트", () => {
    const text = "💡 메일 a@example.com";
    const result = new Anonymizer(ProcessingMode.PERMISSIVE).process(text);
    const page = parsePage(generateHtmlReport(text, result));
    expect(page.metadata?.source_characters).toBe([...text].length);
    const email = page.findings.find((f) => f["data-label"] === "EMAIL");
    expect([email?.["data-start"], email?.["data-end"]]).toEqual(["5", "18"]);
  });
});

describe("HTML 원문 바인딩 — 불일치는 원문 없는 ValueError", () => {
  const changes = [
    "wrong-pii",
    "prefix",
    "suffix",
    "output",
    "missing-trace",
    "reversed-trace",
    "negative",
    "bool",
    "past-source",
    "past-output",
    "wrong-action",
  ];
  for (const change of changes) {
    it(change, () => {
      const text = "연락: 010-2345-6789 / 메일: a@example.com 끝";
      const result = new Anonymizer().process(text);
      let source = text;
      const subs = result.substitutions as unknown as Record<string, unknown>[];
      if (change === "wrong-pii") source = text.replace("2345", "3456");
      else if (change === "prefix") source = text.replace("연락", "안내");
      else if (change === "suffix") source = `${text}!`;
      else if (change === "output") result.text += "!";
      else if (change === "missing-trace") result.substitutions.length = 0;
      else if (change === "reversed-trace") result.substitutions.reverse();
      else if (change === "wrong-action")
        (result.detections[0] as { action: Action }).action = Action.REVIEW;
      else {
        const [key, value] = (
          {
            negative: ["start", -1],
            bool: ["start", true],
            "past-source": ["end", text.length + 1],
            "past-output": ["outputEnd", result.text.length + 1],
          } as Record<string, [string, unknown]>
        )[change] as [string, unknown];
        subs[0] = { ...subs[0], [key]: value };
      }
      let message = "";
      expect(() => {
        try {
          generateHtmlReport(source, result);
        } catch (e) {
          message = String((e as Error).message);
          throw e;
        }
      }).toThrow(/matching source/);
      expect(message).not.toContain("010-2345-6789");
      expect(message).not.toContain("a@example.com");
    });
  }

  for (const mode of Object.values(ProcessingMode)) {
    for (const strategy of ["redact", "tokenize", "asterisk", "partial", "hashed", "fpe"]) {
      it(`일치하는 유니코드 결과는 변형 없이 지원 — ${mode}/${strategy}`, () => {
        const text = "💡 연락처: ０１０-２３４５-６７８９ / 성명: John Smith";
        const result = new Anonymizer(mode, strategy).process(text);
        const before = JSON.stringify([
          result.text,
          result.detections,
          result.substitutions,
          result.summary,
        ]);
        const page = generateHtmlReport(text, result);
        expect(page).toContain("원문 개인정보가 포함");
        expect(
          JSON.stringify([result.text, result.detections, result.substitutions, result.summary]),
        ).toBe(before);
      });
    }
  }

  it("HTML·내보내기는 사용자 마크업을 실행하지 않는다", () => {
    const text = '</script><img src=x onerror="alert(1)"> a@example.com';
    const result = new Anonymizer().process(text);
    result.summary.combined_risk = '"><img src=x onerror="alert(2)">';
    const page = generateHtmlReport(text, result, {
      documentId: "</title><script>alert(3)</script>",
    });
    expect(page).not.toContain("<img src=x");
    expect(page).not.toContain("<script>alert");
    const exported = interact(parsePage(page), []).download;
    expect(JSON.stringify(exported)).not.toContain("alert");
  });

  it("마킹 비활성화와 빈 문서", () => {
    const page = generateHtmlReport("", new Anonymizer().process(""), { enableMarking: false });
    expect(page).not.toContain("<script");
    expect(page).not.toContain("onclick=");
    expect(parsePage(page).metadata).toBeNull();
    expect(page).toContain("원문 개인정보가 포함");
  });
});

// ───────────────────────────── test_certificate.py / test_summary.py

describe("증명서 — 값 없는 기본값", () => {
  it("요약과 차단 항목을 담고 원문은 노출하지 않는다", () => {
    const result = new Anonymizer(ProcessingMode.STRICT, "tokenize").process(
      "신청인 880101-1234568 연락처 010-1234-5678",
    );
    const cert = generateCertificate(result, "doc-001", false, {
      includeDocumentId: true,
      includeReplacements: true,
    });
    expect(cert).toContain("doc-001");
    expect(cert).toContain("처리 증명서");
    expect(cert).toContain("차단/치환 처리 항목");
    expect(cert).not.toContain("880101-1234568");
    expect(cert).not.toContain("010-1234-5678");
    expect(cert.includes("<RRN_1>") || cert.includes("<PHONE_1>")).toBe(true);
  });

  it("검토 블록은 기본적으로 원문 없이 표시", () => {
    const result = new Anonymizer(ProcessingMode.PERMISSIVE).process("주민번호 880101-1234567");
    const cert = generateCertificate(result, "doc-002");
    expect(cert).toContain("검토 대기 항목");
    expect(cert).not.toContain("880101-1234567");
    expect(cert).not.toContain("doc-002");
    expect(cert).not.toContain("주의:");
  });
});

describe("summary", () => {
  const result = () =>
    new Anonymizer(ProcessingMode.STRICT).process("신청인 880101-1234568 연락처 010-1234-5678");
  it("summarize 키", () => {
    const s = summarize(result());
    for (const key of ["total", "by_action", "by_risk", "by_label", "by_legal_basis"]) {
      expect(s).toHaveProperty(key);
    }
  });
  it("format_summary_text 섹션 헤더 + 종류별 전략", () => {
    const out = formatSummaryText(result());
    for (const h of [
      "처리 모드",
      "[조치별 분포]",
      "[위험도별 분포]",
      "[카테고리별 분포]",
      "[법적 근거별 분포]",
    ]) {
      expect(out).toContain(h);
    }
    expect(out).not.toContain("종류별 전략");
    const custom = new Anonymizer(
      ProcessingMode.STRICT,
      "tokenize",
      null,
      null,
      null,
      null,
      "union",
      null,
      null,
      {
        strategies: { PHONE: "partial", EMAIL: "redact" },
      },
    ).process("010-1234-5678");
    expect(formatSummaryText(custom)).toContain(
      "종류별 전략: {'PHONE': 'partial', 'EMAIL': 'redact'}",
    );
  });
  it("review_queue 는 REVIEW 만", () => {
    const r = new Anonymizer(ProcessingMode.PERMISSIVE).process("주민번호 880101-1234567");
    const q = reviewQueue(r.detections);
    expect(q.length).toBeGreaterThanOrEqual(1);
    expect(q.every((item) => "label" in item)).toBe(true);
  });
  it("reporting/index 는 explain 을 재수출", () => {
    expect(typeof reporting.explain).toBe("function");
    expect(reporting.explain(result()).contract).toBe("ko-pii-explanation-v1");
  });
});
