/**
 * Reversible tokenization mode.
 *
 * 각 검출 결과를 ``<LABEL_N>`` 토큰으로 치환하고, Vault 에 원본을 저장한다.
 * 같은 원본 값은 같은 토큰을 받는다 (문서 내 일관성). Vault 가 있으면 원본 복원 가능.
 *
 * Legal basis: 개인정보보호법 제28조의2~5 (가명정보 처리 특례).
 */
import type { DetectionResult } from "../core/types.js";
import { applySubstitutions } from "./apply.js";
import type { ModesVault } from "./vault.js";

/**
 * Replace each detection span with a stable ``<LABEL_N>`` token.
 *
 * Returns ``[replaced_text, vault]``. Python 은 vault 미지정 시 새 vault 를
 * 만들지만, TS 재단에는 vault 구현이 아직 없어 호출자가 반드시 전달해야 한다
 * (Python ``tokenize(text, detections, vault=None)`` 의 기본값 생성은
 * Anonymizer 계층에서 담당).
 */
export function tokenize(
  text: string,
  detections: Iterable<DetectionResult>,
  vault: ModesVault,
): [string, ModesVault] {
  const v = vault;
  const list = [...detections]; // consume iterator once

  const replace = (d: DetectionResult): string =>
    v.store({
      label: d.label,
      original: d.text,
      riskLevel: d.riskLevel,
      legal_basis: d.legal_basis,
      offset: d.start,
      extra: { ...d.extra },
    });

  const replaced = applySubstitutions(text, list, replace);
  return [replaced, v];
}
