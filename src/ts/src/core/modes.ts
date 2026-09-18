/** 처리 모드 — Python ko_pii.core.modes 대응 (차단 임계값 프로필). */
import { RiskLevel } from "./types.js";

export enum ProcessingMode {
  PARANOID = "PARANOID",
  STRICT = "STRICT",
  BALANCED = "BALANCED",
  PERMISSIVE = "PERMISSIVE",
  AUDIT = "AUDIT",
}

export enum Action {
  BLOCK = "BLOCK",
  REVIEW = "REVIEW",
  ALLOW = "ALLOW",
}

export interface ModePolicy {
  mode: ProcessingMode;
  blockRiskMin: RiskLevel;
  blockConfidenceMin: number;
  reviewRiskMin: RiskLevel;
  reviewConfidenceMin: number;
  decide(risk: RiskLevel, confidence: number): Action;
}

function policy(p: Omit<ModePolicy, "decide">): ModePolicy {
  return {
    ...p,
    decide(risk: RiskLevel, confidence: number): Action {
      if (this.mode === ProcessingMode.AUDIT) return Action.ALLOW;
      if (risk >= this.blockRiskMin && confidence >= this.blockConfidenceMin) {
        return Action.BLOCK;
      }
      if (risk >= this.reviewRiskMin && confidence >= this.reviewConfidenceMin) {
        return Action.REVIEW;
      }
      return Action.ALLOW;
    },
  };
}

const POLICIES: Record<ProcessingMode, ModePolicy> = {
  [ProcessingMode.PARANOID]: policy({
    mode: ProcessingMode.PARANOID,
    blockRiskMin: RiskLevel.LOW,
    blockConfidenceMin: 0.5,
    reviewRiskMin: RiskLevel.INFO,
    reviewConfidenceMin: 0.0,
  }),
  [ProcessingMode.STRICT]: policy({
    mode: ProcessingMode.STRICT,
    blockRiskMin: RiskLevel.MEDIUM,
    blockConfidenceMin: 0.7,
    reviewRiskMin: RiskLevel.LOW,
    reviewConfidenceMin: 0.5,
  }),
  [ProcessingMode.BALANCED]: policy({
    mode: ProcessingMode.BALANCED,
    blockRiskMin: RiskLevel.HIGH,
    blockConfidenceMin: 0.8,
    reviewRiskMin: RiskLevel.MEDIUM,
    reviewConfidenceMin: 0.6,
  }),
  [ProcessingMode.PERMISSIVE]: policy({
    mode: ProcessingMode.PERMISSIVE,
    blockRiskMin: RiskLevel.CRITICAL,
    blockConfidenceMin: 0.95,
    reviewRiskMin: RiskLevel.HIGH,
    reviewConfidenceMin: 0.7,
  }),
  [ProcessingMode.AUDIT]: policy({
    mode: ProcessingMode.AUDIT,
    blockRiskMin: RiskLevel.CRITICAL,
    blockConfidenceMin: 1.01, // never block
    reviewRiskMin: RiskLevel.INFO,
    reviewConfidenceMin: 0.0,
  }),
};

export function policyFor(mode: ProcessingMode): ModePolicy {
  return POLICIES[mode];
}
