/** app.py 의 Gradio UI 대응 — 입력/모드/체크박스 → process() → 출력 4칸. */
import { EXAMPLES, MODES, type ModeName, process } from "./process.js";

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} 없음`);
  return el as T;
};

const textInput = $<HTMLTextAreaElement>("text-input");
const showOpenai = $<HTMLInputElement>("show-openai");
const showPresidio = $<HTMLInputElement>("show-presidio");

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

function run(): void {
  let outputs: ReturnType<typeof process>;
  try {
    outputs = process(textInput.value, currentMode(), showOpenai.checked, showPresidio.checked);
  } catch (e) {
    // Gradio 는 예외를 에러로 표시한다 — 여기서도 무반응으로 두지 않는다.
    $("kpii-out").textContent = `오류: ${e instanceof Error ? e.message : String(e)}`;
    return;
  }
  const [kpii, openai, presidio, anon] = outputs;
  // process() 가 검출 구간을 전부 escape 한 HTML 을 돌려준다 (Gradio gr.HTML 과 같은 경로).
  $("kpii-out").innerHTML = kpii;
  $("openai-out").innerHTML = openai;
  $("presidio-out").innerHTML = presidio;
  $<HTMLTextAreaElement>("anon-out").value = anon;
}

$("run").addEventListener("click", run);
// Gradio 의 여러 줄 Textbox 는 Shift+Enter 로 submit 한다.
textInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.shiftKey) {
    e.preventDefault();
    run();
  }
});

// gr.Examples — 클릭하면 입력만 채운다 (실행은 하지 않는다).
const examplesBox = $("examples");
for (const [text, mode, openai, presidio] of EXAMPLES) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = text;
  btn.addEventListener("click", () => {
    textInput.value = text;
    const radio = document.querySelector<HTMLInputElement>(`input[name="mode"][value="${mode}"]`);
    if (radio) radio.checked = true;
    showOpenai.checked = openai;
    showPresidio.checked = presidio;
  });
  examplesBox.append(btn);
}
