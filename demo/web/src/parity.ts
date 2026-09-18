/** 브라우저 번들(shim 포함) 안에서 패리티 대조 — parity.html 이 결과를 그대로 보여 준다. */
import { compare, type Reference } from "../parity/compare.js";
import reference from "../parity/reference.json";

const out = document.getElementById("result");
if (out) {
  try {
    const { total, failures } = compare(reference as unknown as Reference);
    out.dataset.status = failures.length === 0 ? "PASS" : "FAIL";
    out.textContent = [
      `PARITY ${out.dataset.status}: ${total} checks, ${failures.length} failures`,
      ...failures.slice(0, 10),
    ].join("\n");
  } catch (e) {
    // shim 누락 등으로 throw 해도 "running…" 에 멈추지 않고 실패로 표시한다.
    out.dataset.status = "FAIL";
    out.textContent = `PARITY FAIL: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`;
  }
}
