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
}): DetectionResult {
  return {
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
}
