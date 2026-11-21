/**
 * 신뢰된 애플리케이션 규칙용 소형 로컬 어댑터 — 샌드박스가 아니다.
 * Python ko_pii.integrations.custom 대응.
 *
 * 정규식은 JS ``RegExp`` 문법·플래그 문자열(예: ``"i"``)을 쓴다 (Python ``re`` 정수 플래그 대신).
 * 오프셋은 UTF-16 코드 유닛, 길이 한도(maxChars 등)는 Python ``len`` 과 같은 코드 포인트 수.
 */

import { ValueError } from "../core/errors.js";
import { codePointLength } from "../core/strUtils.js";
import { type DetectionResult, RiskLevel } from "../core/types.js";
import { validatedDetection } from "../core/validation.js";
import type { SecondaryDetector } from "./base.js";

function validateResult(result: unknown, text: string): DetectionResult {
  // 지원하는 결정 필드만 복사한다. 자유 형식 메타데이터는 사용자 규칙 적용에 필요 없고
  // 무관한 원문 데이터를 실수로 실어 나를 수 있다.
  return validatedDetection(result, text, { preserveMetadata: false });
}

function isPositiveInt(n: unknown): boolean {
  return typeof n === "number" && Number.isInteger(n) && n >= 1;
}

/** {@link CallableDetector} 한도 — 입력·결과 크기만 제한하고 실행 시간은 제한하지 않는다. */
export interface CustomDetectorLimits {
  /** 입력 최대 길이 (코드 포인트). 기본 1_000_000. */
  maxChars?: number;
  /** 최대 결과 수. 기본 10_000. */
  maxMatches?: number;
}

/**
 * 신뢰된 콜백을 감싸고, 한도 안의 출력 전체를 검증한 뒤에 내보낸다.
 *
 * 한도는 입력/결과 크기만 제한하며 실행 시간은 제한하지 않는다. 콜백과 정규식은
 * 같은 프로세스에서 실행되므로 신뢰할 수 없는 사용자에게서 받아서는 안 된다.
 */
export class CallableDetector implements SecondaryDetector {
  name = "custom-callable";
  readonly maxChars: number;
  readonly maxMatches: number;
  private readonly callback: (text: string) => Iterable<DetectionResult>;

  constructor(
    callback: (text: string) => Iterable<DetectionResult>,
    options: CustomDetectorLimits = {},
  ) {
    const maxChars = options.maxChars === undefined ? 1_000_000 : options.maxChars;
    const maxMatches = options.maxMatches === undefined ? 10_000 : options.maxMatches;
    if (typeof callback !== "function") {
      throw new ValueError("custom detector callback must be callable");
    }
    if (![maxChars, maxMatches].every(isPositiveInt)) {
      throw new ValueError("custom detector limits must be positive integers");
    }
    this.callback = callback;
    this.maxChars = maxChars;
    this.maxMatches = maxMatches;
  }

  *detect(text: string): Generator<DetectionResult> {
    if (typeof text !== "string" || codePointLength(text) > this.maxChars) {
      throw new ValueError("custom detector input must be a bounded string");
    }
    const results: DetectionResult[] = [];
    try {
      for (const result of this.callback(text)) {
        if (results.length >= this.maxMatches) {
          throw new ValueError("custom detector exceeded match limit");
        }
        results.push(validateResult(result, text));
      }
    } catch {
      // 콜백 예외는 원문을 담을 수 있다 — 반사하지 않는다.
      throw new ValueError("custom detector failed or returned invalid/beyond-limit results");
    }
    yield* results;
  }
}

/** {@link RegexDetector} 옵션 (Python keyword 인자 대응). */
export interface RegexDetectorOptions extends CustomDetectorLimits {
  /** 기존 ko-pii 라벨. */
  label: string;
  /** 캡처 그룹 번호 또는 이름. 기본 0 (전체 매치). */
  group?: number | string;
  riskLevel?: RiskLevel;
  confidence?: number;
  /** JS RegExp 플래그 문자열 (``g``·``d`` 는 자동 추가). 기본 "". */
  flags?: string;
}

/** 원문에서 기존 라벨을 매칭 — 선택적으로 캡처 그룹 사용. */
export class RegexDetector extends CallableDetector {
  override name = "custom-regex";

  constructor(pattern: string, options: RegexDetectorOptions) {
    const group = options.group === undefined ? 0 : options.group;
    if (typeof pattern !== "string" || !pattern || codePointLength(pattern) > 4096) {
      throw new ValueError("custom regex must be a nonempty pattern of at most 4096 characters");
    }
    let compiled: RegExp;
    let groupCount: number;
    let groupNames: string[];
    try {
      const flags = [...new Set(`${options.flags === undefined ? "" : options.flags}gd`)]
        .filter((f) => f !== "y")
        .join("");
      compiled = new RegExp(pattern, flags);
      // 빈 대안을 붙이면 항상 매치되어 그룹 수·이름을 알 수 있다 (Python compiled.groups/groupindex).
      const probe = new RegExp(`${pattern}|`, flags.replace("g", "")).exec("");
      groupCount = probe ? probe.length - 1 : 0;
      groupNames = probe?.groups ? Object.keys(probe.groups) : [];
    } catch {
      throw new ValueError("invalid custom regex");
    }
    if (
      !(
        (typeof group === "number" &&
          Number.isInteger(group) &&
          group >= 0 &&
          group <= groupCount) ||
        (typeof group === "string" && groupNames.includes(group))
      )
    ) {
      throw new ValueError("custom regex capture group does not exist");
    }
    const template = validateResult(
      {
        label: options.label,
        text: "x",
        start: 0,
        end: 1,
        riskLevel: options.riskLevel === undefined ? RiskLevel.HIGH : options.riskLevel,
        confidence: options.confidence === undefined ? 1.0 : options.confidence,
        evidence: [],
        legal_basis: null,
        extra: {},
      },
      "x",
    );

    function* matches(text: string): Generator<DetectionResult> {
      for (const match of text.matchAll(compiled)) {
        const span =
          typeof group === "number" ? match.indices?.[group] : match.indices?.groups?.[group];
        if (span === undefined) continue; // 선택 그룹이 참여하지 않음.
        const [start, end] = span;
        yield { ...template, start, end, text: text.slice(start, end) };
      }
    }

    super(matches, { maxChars: options.maxChars, maxMatches: options.maxMatches });
  }
}
