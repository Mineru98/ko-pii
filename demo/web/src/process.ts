/**
 * demo/app.py 의 `_highlight_html` / `process` 를 ko-pii TS 라이브러리 위에 그대로 옮긴 것.
 *
 * DOM 에 의존하지 않는 순수 함수만 둔다 — 브라우저(main.ts)와 패리티 검증(parity/)이
 * 같은 구현을 쓴다. 출력 문자열은 Python 과 바이트 단위로 같아야 한다.
 */
import { Anonymizer } from "../../../src/ts/src/anonymizer.js";
import { ProcessingMode } from "../../../src/ts/src/core/modes.js";
import type { DetectionResult } from "../../../src/ts/src/core/types.js";
import { detectAll } from "../../../src/ts/src/detect.js";

// ── 색상 팔레트 (카테고리별) — app.py COLORS 와 동일 ─────────────
const COLORS: Record<string, string> = {
  RRN: "#e74c3c", FRN: "#e74c3c", PASSPORT: "#e74c3c",
  DRIVER_LICENSE: "#e74c3c",
  PERSON: "#3498db", NATIONALITY: "#1abc9c",
  PHONE: "#e67e22", EMAIL: "#e67e22", FAX: "#e67e22",
  ADDRESS: "#9b59b6",
  CARD: "#c0392b", ACCOUNT: "#c0392b",
  BUSINESS_REG: "#7f8c8d", CORP_REG: "#7f8c8d",
  DT_BIRTH: "#2ecc71", AGE: "#2ecc71",
  HEIGHT: "#16a085", WEIGHT: "#16a085",
  EDUCATION: "#8e44ad", MAJOR: "#8e44ad", POSITION: "#8e44ad",
};
const DEFAULT_COLOR = "#95a5a6";

export const MODES = ["PARANOID", "STRICT", "BALANCED", "PERMISSIVE", "AUDIT"] as const;
export type ModeName = (typeof MODES)[number];

/** Python `html.escape(s)` (quote=True) 대응. */
function pyHtmlEscape(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

/** Python `f"{x:.0f}"` 대응 (half-even). */
export function pyRound0(x: number): string {
  const tie = Number.isInteger(x * 2) && !Number.isInteger(x);
  return tie ? String(2 * Math.round(x / 2)) : x.toFixed(0);
}

/** Python `f"{x:.0%}"` 대응 — CPython 은 double 로 먼저 100 을 곱한 뒤 한 번만 반올림한다. */
export function pyPercent0(x: number): string {
  return `${pyRound0(x * 100)}%`;
}

/** Python `str.strip()` 이 지우는 공백 집합 — JS `trim()` 과 달리 U+FEFF 는 남기고 U+001C~1F·U+0085 는 지운다. */
const PY_WS = "[\\t-\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const PY_STRIP_RE = new RegExp(`^${PY_WS}+|${PY_WS}+$`, "g");

const BOX_STYLE =
  "font-family:monospace;white-space:pre-wrap;padding:12px;" +
  "border:1px solid #ddd;border-radius:8px;background:#fafafa;min-height:100px";

/** 검출 결과를 HTML 하이라이트로 변환 — app.py `_highlight_html` 대응. */
export function highlightHtml(
  text: string,
  detections: Pick<DetectionResult, "label" | "start" | "end" | "confidence">[],
  engine: string,
): string {
  if (detections.length === 0) {
    const escaped = pyHtmlEscape(text).replaceAll("\n", "<br>");
    return `<div style='${BOX_STYLE}'>${escaped}<br><br><b>${engine}:</b> 검출 없음</div>`;
  }

  const dets = [...detections].sort((a, b) => a.start - b.start);
  const parts: string[] = [];
  let last = 0;
  for (const d of dets) {
    if (d.start > last) parts.push(pyHtmlEscape(text.slice(last, d.start)));
    const color = COLORS[d.label] ?? DEFAULT_COLOR;
    const spanText = pyHtmlEscape(text.slice(d.start, d.end));
    parts.push(
      `<span style="background:${color}22;border:1px solid ${color};` +
        `border-radius:3px;padding:1px 4px" title="${d.label} (${pyPercent0(d.confidence)})">` +
        `${spanText}<sup style="color:${color};font-size:0.7em;font-weight:bold">` +
        `${d.label}</sup></span>`,
    );
    last = d.end;
  }
  if (last < text.length) parts.push(pyHtmlEscape(text.slice(last)));

  const body = parts.join("").replaceAll("\n", "<br>");

  // 요약 — Counter.most_common(): 건수 내림차순, 동률은 첫 등장 순(안정 정렬).
  const counts = new Map<string, number>();
  for (const d of dets) counts.set(d.label, (counts.get(d.label) ?? 0) + 1);
  const summary = [...counts]
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `${k}:${v}`)
    .join(" / ");

  return `<div style='${BOX_STYLE}'>${body}<br><br><b>${engine}:</b> ${dets.length}건 (${summary})</div>`;
}

export const note = (msg: string): string => `<div style='padding:12px;color:#999'>${msg}</div>`;

export type ProcessOutput = [kpii: string, openai: string, presidio: string, anon: string];

/**
 * app.py `process` 대응.
 *
 * 이 함수 안에서는 openai/privacy-filter 와 Presidio 를 돌리지 않는다 — app.py 가 해당 패키지
 * 미설치일 때 내는 출력과 같다(패리티 기준). 브라우저의 openai 칸은 main.ts 가 openai.ts(WebGPU)
 * 결과로 따로 채우고, Presidio 는 UI 에서 비활성이다.
 */
export function process(
  text: string,
  mode: ModeName,
  showOpenai: boolean,
  showPresidio: boolean,
  now: () => number = () => performance.now(),
): ProcessOutput {
  if (!text.replace(PY_STRIP_RE, "")) {
    const empty = note("텍스트를 입력하세요");
    return [empty, empty, empty, ""];
  }

  const t0 = now();
  const kpiiDets = detectAll(text);
  const kpiiMs = now() - t0;
  const kpiiHtml = highlightHtml(text, kpiiDets, `ko-pii (${pyRound0(kpiiMs)}ms)`);

  const anonText = new Anonymizer(ProcessingMode[mode]).process(text).text;

  const openaiHtml = showOpenai
    ? note("openai/privacy-filter 미설치 (pip install ko-pii[ml])")
    : note("비활성");
  const presidioHtml = showPresidio
    ? note("Presidio 미설치 (pip install presidio-analyzer spacy)")
    : note("비활성");

  return [kpiiHtml, openaiHtml, presidioHtml, anonText];
}

// ── 예시 텍스트 — app.py EXAMPLES 와 동일 ────────────────────────
export const EXAMPLES: [string, ModeName, boolean, boolean][] = [
  [
    `서울특별시 종로구청 민원실 회신문

(수신) 김민지 귀하 (010-1234-5678, mjkim@seoul.go.kr)
(주민등록번호) 880101-2123456
(주소) 서울특별시 강남구 테헤란로 124
(차량번호) 12가1234

처리 담당자는 종로구청 환경위생과 박철수 주임 (02-2148-1234) 이며
회신 기한은 2024년 3월 15일입니다.`,
    "STRICT", true, true,
  ],
  [
    `환자명: 홍길동 (1990.03.15생, 34세)
주민번호: 900315-1234567
연락처: 010-9876-5432
주소: 경기도 성남시 분당구 판교로 235 102동 1501호
진단: 고혈압 (I10), 당뇨병 (E11)
처방전번호: RX-2024-0315-001`,
    "STRICT", true, true,
  ],
  [
    `거주지국 대한민국 거주지국코드 KR
사업자등록번호 120-81-47521
계좌번호: 110-123-456789 (국민은행)
여권번호 M12345678`,
    "BALANCED", false, false,
  ],
];
