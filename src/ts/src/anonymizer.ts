/**
 * 통합 Anonymizer — 검출 + 정책 결정 + 처리 (BLOCK / REVIEW / ALLOW).
 * Python ko_pii.anonymizer 대응.
 *
 * Python 처럼 modes 래퍼(tokenize()/hashed()/fpe())가 아니라 applySubstitutions
 * 위에 repl 클로저를 얹어 DetectionRecord.token 을 태깅한다.
 */

import { type CombinedRiskReport, riskLevelName, score_combined_risk } from "./analytics/index.js";
import { protectionRemainders } from "./core/coverage.js";
import { ValueError } from "./core/errors.js";
import { Action, type ModePolicy, ProcessingMode, policyFor } from "./core/modes.js";
import { resolveOverlaps } from "./core/overlap.js";
import { OverlapTrace, validateTraceLimit } from "./core/trace.js";
import type { DetectionResult } from "./core/types.js";
import { validatedDetection } from "./core/validation.js";
import { detectCandidates } from "./detect.js";
import type { SecondaryDetector } from "./integrations/base.js";
import { mergeCandidates, validateMergeConfig } from "./integrations/hybrid.js";
import { validateLabelFilter } from "./labels.js";
import { type AppliedSpan, applySubstitutions } from "./modes/apply.js";
import { pseudonymizeValue } from "./modes/fpe.js";
import { maskValue } from "./modes/partial.js";
import { labelToHangul } from "./modes/redact.js";
import { isPersonExcluded, normalizeExclusions } from "./patterns/person.js";
import { codePointCompare, policyDigest, validateStrategies } from "./policy.js";
import { ReversibleVault } from "./vault/reversible.js";

export interface DetectionRecord {
  detection: DetectionResult;
  action: Action;
  token: string | null;
  /** 이 검출에 적용(요청)된 변환 전략 (Python ``strategy``). */
  strategy: string | null;
}

export interface AnonymizationResult {
  text: string;
  detections: DetectionRecord[];
  vault: ReversibleVault | null;
  summary: Record<string, unknown>;
  combined_risk: CombinedRiskReport | null;
  /** 실제로 내보낸 치환의 원문/출력 좌표 (Python ``substitutions``). */
  substitutions: AppliedSpan[];
  /** ``traceLimit > 0`` 일 때 수집된 값 없는 겹침 해소 메타데이터 (Python ``overlap_trace``). */
  overlap_trace: OverlapTrace | null;
}

export function reviewItems(result: AnonymizationResult): DetectionRecord[] {
  return result.detections.filter((r) => r.action === Action.REVIEW);
}

export function blockedItems(result: AnonymizationResult): DetectionRecord[] {
  return result.detections.filter((r) => r.action === Action.BLOCK);
}

/** Python keyword-only 인자 (``strategies`` / ``trace_limit``). */
export interface AnonymizerOptions {
  /** 라벨별 ``strategy`` 재정의. 임계값은 계속 ``mode`` 를 따른다 (REVIEW/ALLOW 를 BLOCK 으로 바꾸지 않음). */
  strategies?: Readonly<Record<string, string>> | ReadonlyMap<string, string> | null;
  /** 호출당 최대 이만큼의 값 없는 공통 겹침 이벤트 수집. 0(기본)=비활성, 최대 1000. */
  traceLimit?: number;
}

const VAULT_STRATEGIES: ReadonlySet<string> = new Set(["tokenize", "hashed", "fpe"]);

function sortedLabels(values: readonly string[]): string[] {
  return [...values].sort(codePointCompare);
}

export class Anonymizer {
  readonly mode: ProcessingMode;
  readonly policy: ModePolicy;
  readonly strategy: string;
  /** 라벨별 전략 재정의 (불변 사본). */
  readonly strategies: Readonly<Record<string, string>>;
  readonly traceLimit: number;
  readonly vault: ReversibleVault;
  readonly include: readonly string[] | null;
  readonly exclude: readonly string[] | null;
  /** Optional secondary detector (ML 어댑터 등) — 있으면 process() 가 결과를 병합한다. */
  readonly secondaryDetector: SecondaryDetector | null;
  readonly mergeMode: string;
  /** role_split 모드에서 secondary 가 담당할 라벨 (null=기본 퍼지 10종). */
  readonly roleSplitLabels: ReadonlySet<string> | null;
  /** 이 인스턴스에서 PERSON 검출만 억제할 도메인 용어 (정규화됨). */
  readonly personExclusions: ReadonlySet<string>;

  constructor(
    mode: ProcessingMode = ProcessingMode.STRICT,
    strategy = "tokenize",
    vault?: ReversibleVault | null,
    include?: Iterable<string> | null,
    exclude?: Iterable<string> | null,
    secondaryDetector: SecondaryDetector | null = null,
    mergeMode = "union",
    roleSplitLabels: Iterable<string> | null = null,
    personExclusions: Iterable<string> | null = null,
    options: AnonymizerOptions = {},
  ) {
    const traceLimit = options.traceLimit ?? 0;
    validateTraceLimit(traceLimit);
    const [selectedMode, delegated] = validateMergeConfig(mergeMode, roleSplitLabels);
    if (
      secondaryDetector !== null &&
      secondaryDetector !== undefined &&
      typeof (secondaryDetector as { detect?: unknown }).detect !== "function"
    ) {
      throw new ValueError("secondary_detector must provide a callable detect method");
    }
    this.traceLimit = traceLimit;
    this.strategies = Object.freeze(validateStrategies(strategy, options.strategies));
    this.mode = mode;
    this.policy = policyFor(mode);
    this.strategy = strategy;
    this.vault = vault ?? new ReversibleVault();
    this.include = validateLabelFilter(include, "include");
    this.exclude = validateLabelFilter(exclude, "exclude");
    this.secondaryDetector = secondaryDetector ?? null;
    this.mergeMode = selectedMode;
    this.roleSplitLabels = delegated;
    this.personExclusions = normalizeExclusions(personExclusions);
  }

  // ------------------------------------------------------------ public

  process(text: string): AnonymizationResult {
    return this.processWithExclusions(text, this.personExclusions);
  }

  /** @internal 구조화 필드가 호출 범위 합집합을 넘긴다 — 공유 정책은 바꾸지 않는다. */
  processWithExclusions(text: string, exclusions: ReadonlySet<string>): AnonymizationResult {
    const [mode, delegated] = validateMergeConfig(this.mergeMode, this.roleSplitLabels);
    const trace = this.traceLimit ? new OverlapTrace(this.traceLimit) : null;
    // 병합 확신도·위임·출력 정책이 정해질 때까지 경쟁 라벨을 유지한다. REVIEW 후보가
    // BLOCK 을 가리면 안 된다.
    const primary = detectCandidates(text, this.include, this.exclude, {
      personExclusions: exclusions,
    });
    let candidates: DetectionResult[];
    let stage: "primary" | "hybrid";
    // Optional secondary detector (ML 어댑터 등) 가 있으면 결과 병합
    if (this.secondaryDetector !== null) {
      let secondary: DetectionResult[] = [];
      try {
        for (const detection of this.secondaryDetector.detect(text)) {
          secondary.push(validatedDetection(detection, text));
        }
      } catch {
        // 어댑터 예외는 입력을 되울릴 수 있다. 아직 치환·Vault 쓰기는 없었다.
        throw new ValueError("secondary detector failed or returned invalid source-bound results");
      }
      const { include, exclude } = this;
      if (include) secondary = secondary.filter((s) => include.includes(s.label));
      if (exclude && exclude.length > 0) {
        secondary = secondary.filter((s) => !exclude.includes(s.label));
      }
      if (exclusions.size > 0) {
        // 겹침 해소 전에 거른다 — 제외된 PERSON 이 겹치는 primary ADDRESS·식별자를 밀어내면 안 된다.
        secondary = secondary.filter(
          (d) => !(d.label === "PERSON" && isPersonExcluded(d.text, exclusions)),
        );
      }
      candidates = mergeCandidates(primary, secondary, mode, delegated, { policy: this.policy });
      stage = "hybrid";
    } else {
      candidates = primary;
      stage = "primary";
    }
    let detections = resolveOverlaps(candidates, { trace, stage, policy: this.policy });
    const remainders = protectionRemainders(text, candidates, detections, this.policy, (label) =>
      this.strategyFor(label),
    );
    if (remainders.length > 0) {
      detections = resolveOverlaps([...detections, ...remainders], {
        trace,
        stage: "protection",
        policy: this.policy,
      });
    }
    const result = this.processDetections(text, detections);
    result.summary.overlap_resolution = "block_risk_confidence_length_start";
    if (remainders.length > 0) {
      result.summary.overlap_resolution += ";complete_replacement_remainders";
      result.summary.overlap_protection = { fragments: remainders.length };
    }
    result.overlap_trace = trace;
    return result;
  }

  /** 설정된 변환 전략 — 모드 임계값은 바꾸지 않는다. */
  strategyFor(label: string): string {
    return Object.hasOwn(this.strategies, label)
      ? (this.strategies[label] as string)
      : this.strategy;
  }

  /** @internal ``asserted`` 이면 AUDIT 외 모드에서 모든 검출을 BLOCK 으로 단언한다 (구조화 필드). */
  processDetections(
    text: string,
    detections: DetectionResult[],
    options: { asserted?: boolean } = {},
  ): AnonymizationResult {
    const asserted = options.asserted ?? false;
    const decisions: DetectionRecord[] = detections.map((d) => ({
      detection: d,
      action:
        asserted && this.mode !== ProcessingMode.AUDIT
          ? Action.BLOCK
          : this.policy.decide(d.riskLevel, d.confidence),
      token: null,
      strategy: this.strategyFor(d.label),
    }));

    const toBlock = decisions.filter((r) => r.action === Action.BLOCK);
    const substitutions: AppliedSpan[] = [];
    const replaced = this.apply(text, toBlock, substitutions);
    const combined = score_combined_risk(detections);
    const summary = this.buildSummary(decisions, combined);
    summary.detection_scope = {
      input_empty: !text,
      asserted_field: asserted,
      include: this.include !== null ? sortedLabels(this.include) : null,
      exclude: this.exclude !== null ? sortedLabels(this.exclude) : [],
      combined_risk_basis: "observed_labels_heuristic_not_anonymity_assessment",
    };
    const used = [this.strategy, ...Object.values(this.strategies)];
    return {
      text: replaced,
      detections: decisions,
      vault: used.some((s) => VAULT_STRATEGIES.has(s)) ? this.vault : null,
      summary,
      combined_risk: combined,
      substitutions,
      overlap_trace: null,
    };
  }

  // ----------------------------------------------------------- internal

  private apply(text: string, toBlock: DetectionRecord[], trace: AppliedSpan[]): string {
    if (toBlock.length === 0) return text;
    // Python ``{id(rec.detection): rec for rec in reversed(to_block)}`` — 같은 객체면 첫 레코드.
    const byDetection = new Map<DetectionResult, DetectionRecord>();
    for (const rec of [...toBlock].reverse()) byDetection.set(rec.detection, rec);

    const repl = (d: DetectionResult): string => {
      const record = byDetection.get(d) as DetectionRecord;
      const strategy = this.strategyFor(d.label);
      if (strategy === "tokenize") {
        const tok = this.vault.store(d.label, d.text, d.riskLevel, d.legal_basis, d.start, {
          ...d.extra,
        });
        record.token = tok;
        return tok;
      }
      if (strategy === "redact") return `[${labelToHangul(d.label)}]`;
      if (strategy === "asterisk") {
        // Python `"*" * max(1, d.end - d.start)` 의 오프셋은 코드 포인트 — 아스트랄 문자가 든
        // span 은 UTF-16 길이로 세면 별표가 2배가 되므로 코드 포인트 수로 센다.
        return "*".repeat(Math.max(1, [...text.slice(d.start, d.end)].length));
      }
      if (strategy === "hashed") {
        const fp = this.vault.fingerprint(d.label, d.text);
        const tok = `<${d.label}:${fp.slice(0, 12)}>`;
        record.token = tok;
        return tok;
      }
      if (strategy === "partial") {
        const masked = maskValue(d.label, d.text);
        record.token = masked;
        return masked;
      }
      // fpe
      const fp = this.vault.fingerprint(d.label, d.text);
      const newValue = pseudonymizeValue(d.label, d.text, fp);
      this.vault.store(d.label, d.text, d.riskLevel, d.legal_basis, d.start, {
        ...d.extra,
        fpe_value: newValue,
      });
      record.token = newValue;
      return newValue;
    };
    return applySubstitutions(
      text,
      toBlock.map((r) => r.detection),
      repl,
      { trace },
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
      strategies: { ...this.strategies },
      transformation_policy_sha256: policyDigest(this.mode, this.strategy, this.strategies),
      by_action: byAction,
      by_risk: byRisk,
      by_label: byLabel,
      by_legal_basis: byLegal,
    };
  }
}
