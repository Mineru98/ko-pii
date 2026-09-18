/**
 * 통합 Anonymizer — 검출 + 정책 결정 + 처리 (BLOCK / REVIEW / ALLOW).
 * Python ko_pii.anonymizer 대응.
 *
 * Python 처럼 modes 래퍼(tokenize()/hashed()/fpe())가 아니라 applySubstitutions
 * 위에 repl 클로저를 얹어 DetectionRecord.token 을 태깅한다.
 */
import { type CombinedRiskReport, riskLevelName, score_combined_risk } from "./analytics/index.js";
import { Action, type ModePolicy, ProcessingMode, policyFor } from "./core/modes.js";
import { type DetectionResult, RiskLevel } from "./core/types.js";
import { detectAll } from "./detect.js";
import { applySubstitutions } from "./modes/apply.js";
import { FPE_BY_LABEL, fpeDefault } from "./modes/fpe.js";
import { maskValue } from "./modes/partial.js";
import { labelToHangul } from "./modes/redact.js";
import { ReversibleVault } from "./vault/reversible.js";

export interface DetectionRecord {
  detection: DetectionResult;
  action: Action;
  token: string | null;
}

export interface AnonymizationResult {
  text: string;
  detections: DetectionRecord[];
  vault: ReversibleVault | null;
  summary: Record<string, unknown>;
  combined_risk: CombinedRiskReport | null;
}

export function reviewItems(result: AnonymizationResult): DetectionRecord[] {
  return result.detections.filter((r) => r.action === Action.REVIEW);
}

export function blockedItems(result: AnonymizationResult): DetectionRecord[] {
  return result.detections.filter((r) => r.action === Action.BLOCK);
}

const STRATEGIES = new Set(["tokenize", "redact", "asterisk", "hashed", "partial", "fpe"]);

export class Anonymizer {
  readonly mode: ProcessingMode;
  readonly policy: ModePolicy;
  readonly strategy: string;
  readonly vault: ReversibleVault;
  readonly include: string[] | null;
  readonly exclude: string[] | null;

  constructor(
    mode: ProcessingMode = ProcessingMode.STRICT,
    strategy = "tokenize",
    vault?: ReversibleVault,
    include?: Iterable<string> | null,
    exclude?: Iterable<string> | null,
  ) {
    if (!STRATEGIES.has(strategy)) {
      throw new Error(`Unknown strategy: ${strategy}`);
    }
    this.mode = mode;
    this.policy = policyFor(mode);
    this.strategy = strategy;
    this.vault = vault ?? new ReversibleVault();
    this.include = include ? [...include] : null;
    this.exclude = exclude ? [...exclude] : null;
  }

  process(text: string): AnonymizationResult {
    const primary = detectAll(text, this.include, this.exclude);
    const decisions: DetectionRecord[] = primary.map((d) => ({
      detection: d,
      action: this.policy.decide(d.riskLevel, d.confidence),
      token: null,
    }));

    const toBlock = decisions.filter((r) => r.action === Action.BLOCK);
    const replaced = this.apply(text, toBlock);
    const combined = score_combined_risk(primary);
    const summary = this.buildSummary(decisions, combined);
    return {
      text: replaced,
      detections: decisions,
      vault:
        this.strategy === "tokenize" || this.strategy === "hashed" || this.strategy === "fpe"
          ? this.vault
          : null,
      summary,
      combined_risk: combined,
    };
  }

  // ----------------------------------------------------------- internal

  private apply(text: string, toBlock: DetectionRecord[]): string {
    if (toBlock.length === 0) return text;
    const byDetection = new Map(toBlock.map((r) => [r.detection, r] as const));

    if (this.strategy === "tokenize") {
      const repl = (d: DetectionResult): string => {
        const tok = this.vault.store(d.label, d.text, d.riskLevel, d.legal_basis, d.start, {
          ...d.extra,
        });
        const rec = byDetection.get(d);
        if (rec) rec.token = tok;
        return tok;
      };
      return applySubstitutions(
        text,
        toBlock.map((r) => r.detection),
        repl,
      );
    }

    if (this.strategy === "redact") {
      const repl = (d: DetectionResult): string => `[${labelToHangul(d.label)}]`;
      return applySubstitutions(
        text,
        toBlock.map((r) => r.detection),
        repl,
      );
    }

    if (this.strategy === "asterisk") {
      const repl = (d: DetectionResult): string => "*".repeat(Math.max(1, d.end - d.start));
      return applySubstitutions(
        text,
        toBlock.map((r) => r.detection),
        repl,
      );
    }

    if (this.strategy === "hashed") {
      const repl = (d: DetectionResult): string => {
        const fp = this.vault.fingerprint(d.label, d.text);
        const tok = `<${d.label}:${fp.slice(0, 12)}>`;
        const rec = byDetection.get(d);
        if (rec) rec.token = tok;
        return tok;
      };
      return applySubstitutions(
        text,
        toBlock.map((r) => r.detection),
        repl,
      );
    }

    if (this.strategy === "partial") {
      const repl = (d: DetectionResult): string => {
        const masked = maskValue(d.label, d.text);
        const rec = byDetection.get(d);
        if (rec) rec.token = masked;
        return masked;
      };
      return applySubstitutions(
        text,
        toBlock.map((r) => r.detection),
        repl,
      );
    }

    // fpe
    const repl = (d: DetectionResult): string => {
      const fp = this.vault.fingerprint(d.label, d.text);
      const fn = FPE_BY_LABEL.get(d.label) ?? fpeDefault;
      const newValue = fn(d.text, fp);
      this.vault.store(d.label, d.text, d.riskLevel, d.legal_basis, d.start, {
        ...d.extra,
        fpe_value: newValue,
      });
      const rec = byDetection.get(d);
      if (rec) rec.token = newValue;
      return newValue;
    };
    return applySubstitutions(
      text,
      toBlock.map((r) => r.detection),
      repl,
    );
  }

  private buildSummary(
    decisions: DetectionRecord[],
    combined: CombinedRiskReport,
  ): Record<string, unknown> {
    const byAction: Record<string, number> = {};
    const byRisk: Record<string, number> = {};
    const byLabel: Record<string, number> = {};
    const byLegal: Record<string, number> = {};
    for (const r of decisions) {
      byAction[r.action] = (byAction[r.action] ?? 0) + 1;
      const riskName = riskLevelName(r.detection.riskLevel);
      byRisk[riskName] = (byRisk[riskName] ?? 0) + 1;
      byLabel[r.detection.label] = (byLabel[r.detection.label] ?? 0) + 1;
      const lb = r.detection.legal_basis ?? "—";
      byLegal[lb] = (byLegal[lb] ?? 0) + 1;
    }
    return {
      combined_risk: riskLevelName(combined.combined_risk),
      combined_rationale: [...combined.rationale],
      distinct_identifiers: [...combined.distinct_identifiers],
      distinct_quasi_identifiers: [...combined.distinct_quasi],
      sensitive_attributes: [...combined.sensitive_present],
      total: decisions.length,
      mode: this.mode,
      strategy: this.strategy,
      by_action: byAction,
      by_risk: byRisk,
      by_label: byLabel,
      by_legal_basis: byLegal,
    };
  }
}
