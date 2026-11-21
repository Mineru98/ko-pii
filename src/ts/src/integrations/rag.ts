/**
 * 선택적 RAG 어댑터 공용 메타데이터 경계 — Python ko_pii.integrations._rag 대응.
 *
 * Python 의 LangChain/LlamaIndex 어댑터가 쓰는 순수 로직만 옮겼다 (어댑터 자체는 JS 등가물이
 * 없어 Python 에 남는다). TS 에서 프레임워크 메타데이터를 마스킹할 때 직접 쓴다.
 */
import type { Anonymizer } from "../anonymizer.js";
import { ValueError } from "../core/errors.js";
import { anonymizeJson } from "../structured.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * 한도 있는 JSON 문자열 값을 마스킹하고, 마스킹이 필요한 키는 거부한다.
 *
 * 키는 프레임워크의 메타데이터 제외 목록과 맞도록 그대로 둔다. 숫자 식별자는 문자열로
 * 넘겨야 한다. 지원하지 않는 값은 원문을 통과시키지 않고 실패한다.
 */
export function maskMetadata(
  metadata: Record<string, unknown>,
  anon: Anonymizer,
): Record<string, unknown> {
  const result: unknown = anonymizeJson(metadata, { anonymizer: anon }).data;

  const checkKeys = (value: unknown): void => {
    if (isRecord(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (anon.process(key).text !== key) {
          throw new ValueError("RAG metadata keys must not contain values requiring masking");
        }
        checkKeys(child);
      }
    } else if (Array.isArray(value)) {
      for (const child of value) checkKeys(child);
    }
  };

  checkKeys(result);
  if (!isRecord(result)) throw new ValueError("RAG metadata must be a JSON object");
  return result;
}
