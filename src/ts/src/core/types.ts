/** 핵심 데이터 타입 — Python ko_pii.core.types 대응. */

/** 위험도 (Python IntEnum과 동일한 숫자 값 유지 — Vault/JSON 직렬화 호환). */
export enum RiskLevel {
  INFO = 1,
  LOW = 2,
  MEDIUM = 3,
  HIGH = 4,
  CRITICAL = 5,
}

/** 단일 검출 결과. 오프셋은 UTF-16 코드 유닛 기준 (TS 판 정책 — PORTING.md 참조). */
export interface DetectionResult {
  label: string;
  /** 원본 텍스트에서의 매칭 문자열 — 불변식: source.slice(start, end) === text */
  text: string;
  start: number;
  end: number;
  riskLevel: RiskLevel;
  confidence: number;
  evidence: string[];
  legal_basis: string | null;
  extra: Record<string, unknown>;
  /** Python ``rule_id`` — detectAll 이 ``ko-pii.<label>.v1`` 로 채운다 (선택 필드: 기존 리터럴 호환). */
  ruleId?: string | null;
  /** Python ``normalized`` — 정규화 뷰에서 역매핑된 검출이면 true. */
  normalized?: boolean;
  /** Python ``subrule_id`` — 세부 규칙 (예: ``email.ascii.v1``). */
  subruleId?: string | null;
}

/** Python ``DetectionResult.length`` property. */
export function detectionLength(d: DetectionResult): number {
  return d.end - d.start;
}

export function makeDetection(init: {
  label: string;
  text: string;
  start: number;
  end: number;
  riskLevel: RiskLevel;
  confidence?: number;
  evidence?: string[];
  legal_basis?: string | null;
  extra?: Record<string, unknown>;
  ruleId?: string | null;
  normalized?: boolean;
  subruleId?: string | null;
}): DetectionResult {
  const d: DetectionResult = {
    label: init.label,
    text: init.text,
    start: init.start,
    end: init.end,
    riskLevel: init.riskLevel,
    confidence: init.confidence ?? 1.0,
    evidence: init.evidence ?? [],
    legal_basis: init.legal_basis ?? null,
    extra: init.extra ?? {},
  };
  // 선택 메타데이터는 지정된 경우에만 키를 만든다 (기존 객체 리터럴·toEqual 비교 호환).
  if (init.ruleId !== undefined) d.ruleId = init.ruleId;
  if (init.normalized !== undefined) d.normalized = init.normalized;
  if (init.subruleId !== undefined) d.subruleId = init.subruleId;
  return d;
}
