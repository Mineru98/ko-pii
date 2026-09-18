/** app.py 의 Gradio UI 대응 — 입력/모드/체크박스 → process() → 출력 4칸. */
import * as openai from "./openai.js";
import { EXAMPLES, highlightHtml, MODES, type ModeName, note, process, pyRound0 } from "./process.js";

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} 없음`);
  return el as T;
};

const textInput = $<HTMLTextAreaElement>("text-input");
const showOpenai = $<HTMLInputElement>("show-openai");

const modeBox = $("mode");
for (const m of MODES) {
  const label = document.createElement("label");
  const radio = document.createElement("input");
  radio.type = "radio";
  radio.name = "mode";
  radio.value = m;
  radio.checked = m === "STRICT";
  label.append(radio, ` ${m}`);
  modeBox.append(label);
}

const currentMode = (): ModeName =>
  (document.querySelector<HTMLInputElement>('input[name="mode"]:checked')?.value ?? "STRICT") as ModeName;

const errText = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// ── openai/privacy-filter (WebGPU) — 모델 다운로드·삭제 UI ────────
const openaiStatus = $("openai-status");
const openaiDownload = $<HTMLButtonElement>("openai-download");
const openaiDelete = $<HTMLButtonElement>("openai-delete");
let gpuProblem: string | null = null;

async function refreshModelUi(): Promise<void> {
  const bytes = await openai.cachedBytes();
  const size = bytes > 0 ? ` (${pyRound0(bytes / 2 ** 20)}MB)` : "";
  const usable = gpuProblem === null && (openai.isLoaded() || bytes > 0);
  showOpenai.disabled = !usable;
  if (!usable) showOpenai.checked = false;
  openaiDownload.disabled = gpuProblem !== null || openai.isLoaded();
  openaiDownload.textContent = bytes > 0 ? "모델 로드" : "모델 다운로드 (약 900MB)";
  openaiDelete.disabled = bytes === 0 && !openai.isLoaded();
  openaiStatus.textContent =
    gpuProblem !== null ? `${gpuProblem} — 사용 불가`
    : openai.isLoaded() ? `모델 준비됨${size} · WebGPU`
    : bytes > 0 ? `다운로드됨${size} — 검출 시 로드합니다`
    : "WebGPU 사용 가능 — 모델을 다운로드하면 브라우저 안에서 추론합니다";
}

async function loadModel(): Promise<boolean> {
  openaiDownload.disabled = openaiDelete.disabled = true;
  try {
    await openai.loadModel((p) => (openaiStatus.textContent = `모델 받는 중… ${pyRound0(p)}%`));
    await refreshModelUi();
    return true;
  } catch (e) {
    await refreshModelUi();
    openaiStatus.textContent = `모델 로드 실패: ${errText(e)}`;
    return false;
  }
}

openaiDownload.addEventListener("click", () => void loadModel());
openaiDelete.addEventListener("click", async () => {
  openaiDelete.disabled = true;
  await openai.deleteModel();
  await refreshModelUi();
  $("openai-out").innerHTML = note("비활성");
});
void openai.webGpuProblem().then((problem) => {
  gpuProblem = problem;
  return refreshModelUi();
});

let runSeq = 0;

async function run(): Promise<void> {
  const seq = ++runSeq;
  const text = textInput.value;
  let outputs: ReturnType<typeof process>;
  try {
    // openai 칸은 아래에서 WebGPU 추론으로 채우고, Presidio 는 브라우저에 없다.
    outputs = process(text, currentMode(), false, false);
  } catch (e) {
    // Gradio 는 예외를 에러로 표시한다 — 여기서도 무반응으로 두지 않는다.
    $("kpii-out").textContent = `오류: ${errText(e)}`;
    return;
  }
  const [kpii, openaiHtml, presidio, anon] = outputs;
  // process() 가 검출 구간을 전부 escape 한 HTML 을 돌려준다 (Gradio gr.HTML 과 같은 경로).
  $("kpii-out").innerHTML = kpii;
  $("openai-out").innerHTML = openaiHtml;
  $("presidio-out").innerHTML = presidio;
  $<HTMLTextAreaElement>("anon-out").value = anon;

  if (!showOpenai.checked || !text.trim()) return;
  $("openai-out").innerHTML = note("추론 중…");
  let html: string;
  try {
    if (!(await loadModel())) throw new Error(openaiStatus.textContent ?? "모델 로드 실패");
    const t0 = performance.now();
    const spans = await openai.detect(text);
    html = highlightHtml(text, spans, `openai/PF (${pyRound0(performance.now() - t0)}ms)`);
  } catch (e) {
    html = note(`openai/privacy-filter 오류: ${errText(e)}`);
  }
  // 추론 중에 다시 검출을 눌렀으면 오래된 결과로 덮지 않는다.
  if (seq === runSeq) $("openai-out").innerHTML = html;
}

$("run").addEventListener("click", () => void run());
// Gradio 의 여러 줄 Textbox 는 Shift+Enter 로 submit 한다.
textInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.shiftKey) {
    e.preventDefault();
    void run();
  }
});

// gr.Examples — 클릭하면 입력만 채운다 (실행은 하지 않는다).
const examplesBox = $("examples");
for (const [text, mode, wantOpenai] of EXAMPLES) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = text;
  btn.addEventListener("click", () => {
    textInput.value = text;
    const radio = document.querySelector<HTMLInputElement>(`input[name="mode"][value="${mode}"]`);
    if (radio) radio.checked = true;
    // Presidio 는 비활성 고정, openai 는 모델이 준비된 경우에만 켠다.
    showOpenai.checked = wantOpenai && !showOpenai.disabled;
  });
  examplesBox.append(btn);
}
