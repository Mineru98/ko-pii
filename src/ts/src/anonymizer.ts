/**
 * 통합 Anonymizer — 검출 + 정책 결정 + 처리 (BLOCK / REVIEW / ALLOW).
 * Python ko_pii.anonymizer 대응.
 *
 * Python 처럼 modes 래퍼(tokenize()/hashed()/fpe())가 아니라 applySubstitutions
 * 위에 repl 클로저를 얹어 DetectionRecord.token 을 태깅한다.
 */

import { type CombinedRiskReport, riskLevelName, score_combined_risk } from "./analytics/index.js";
import { ValueError } from "./core/errors.js";
import { Action, type ModePolicy, ProcessingMode, policyFor } from "./core/modes.js";
import { type DetectionResult, RiskLevel } from "./core/types.js";
import { detectAll } from "./detect.js";
import type { SecondaryDetector } from "./integrations/base.js";
import { mergeDetections, toMergeMode } from "./integrations/hybrid.js";
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
  /** Optional secondary detector (ML 어댑터 등) — 있으면 process() 가 결과를 병합한다. */
  readonly secondaryDetector: SecondaryDetector | null;
  readonly mergeMode: string;
  /** role_split 모드에서 secondary 가 담당할 라벨 (null=기본 퍼지 10종). */
  readonly roleSplitLabels: ReadonlySet<string> | null;

  constructor(
    mode: ProcessingMode = ProcessingMode.STRICT,
    strategy = "tokenize",
    vault?: ReversibleVault,
    include?: Iterable<string> | null,
    exclude?: Iterable<string> | null,
    secondaryDetector: SecondaryDetector | null = null,
    mergeMode = "union",
    roleSplitLabels: Iterable<string> | null = null,
  ) {
    if (!STRATEGIES.has(strategy)) {
      throw new ValueError(`Unknown strategy: ${strategy}`);
    }
    this.mode = mode;
    this.policy = policyFor(mode);
    this.strategy = strategy;
    this.vault = vault ?? new ReversibleVault();
    // Python: `list(include) if include else None` — 빈 컬렉션도 None 이 된다.
    const includeList = include ? [...include] : [];
    const excludeList = exclude ? [...exclude] : [];
    this.include = includeList.length > 0 ? includeList : null;
    this.exclude = excludeList.length > 0 ? excludeList : null;
    this.secondaryDetector = secondaryDetector;
    this.mergeMode = mergeMode;
    this.roleSplitLabels = roleSplitLabels !== null ? new Set(roleSplitLabels) : null;
  }

  process(text: string): AnonymizationResult {
    const primary = detectAll(text, this.include, this.exclude);
    // Optional secondary detector (ML 어댑터 등) 가 있으면 결과 병합
    let detections = primary;
    if (this.secondaryDetector !== null) {
      let secondary = [...this.secondaryDetector.detect(text)];
      // Python: `if self.include:` — 빈 리스트는 생성자에서 이미 null 이 된다.
      const { include, exclude } = this;
      if (include) secondary = secondary.filter((s) => include.includes(s.label));
      if (exclude) secondary = secondary.filter((s) => !exclude.includes(s.label));
      detections = mergeDetections(
        primary,
        secondary,
        toMergeMode(this.mergeMode),
        this.roleSplitLabels,
      );
    }
    const decisions: DetectionRecord[] = detections.map((d) => ({
      detection: d,
      action: this.policy.decide(d.riskLevel, d.confidence),
      token: null,
    }));

    const toBlock = decisions.filter((r) => r.action === Action.BLOCK);
    const replaced = this.apply(text, toBlock);
    const combined = score_combined_risk(detections);
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
      // Python `"*" * max(1, d.end - d.start)` 의 오프셋은 코드 포인트 — 아스트랄 문자가 든
      // span 은 UTF-16 길이로 세면 별표가 2배가 되므로 코드 포인트 수로 센다.
      const repl = (d: DetectionResult): string =>
        "*".repeat(Math.max(1, [...text.slice(d.start, d.end)].length));
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
      const lb = r.detection.legal_basis || "—"; // Python `or` — 빈 문자열도 "—"
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
