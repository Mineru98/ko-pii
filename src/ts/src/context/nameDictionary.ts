/** 문서 내 누적 이름 사전. Python ko_pii.context.name_dictionary 대응.
 *
 * 한 번 강한 단서(직책·필드 라벨·결정적 PII 인접 등) 로 확정된 이름은
 * 이후 약한 단서로 등장해도 다시 인식할 수 있도록 누적한다.
 *
 * 설계 원칙 #6 "컨텍스트 누적 식별" 구현.
 */

/** (start, end) 스팬 — UTF-16 코드 유닛 기준. */
export type NameSpan = [number, number];

/** Python NameRecord dataclass 대응. */
export interface NameRecord {
  name: string;
  confidence: number;
  occurrences: NameSpan[];
  evidence: string[];
}

/** NameRecord 팩토리 — Python dataclass 기본값 (occurrences/evidence = []) 대응. */
export function makeNameRecord(init: {
  name: string;
  confidence: number;
  occurrences?: NameSpan[];
  evidence?: string[];
}): NameRecord {
  return {
    name: init.name,
    confidence: init.confidence,
    occurrences: init.occurrences ?? [],
    evidence: init.evidence ?? [],
  };
}

/** 문서 단위 누적 이름 사전 (Python NameDictionary 클래스 대응). */
export class NameDictionary {
  private readonly _names: Map<string, NameRecord> = new Map();

  add(name: string, confidence: number, span: NameSpan, evidence?: string[] | null): NameRecord {
    const rec = this._names.get(name);
    if (rec === undefined) {
      const created = makeNameRecord({
        name,
        confidence,
        occurrences: [span],
        evidence: evidence ? [...evidence] : [],
      });
      this._names.set(name, created);
      return created;
    }
    rec.occurrences.push(span);
    // Max-confidence wins — once we've confirmed a name with strong
    // cues, weaker re-occurrences should not lower it.
    if (confidence > rec.confidence) {
      rec.confidence = confidence;
    }
    for (const e of evidence ?? []) {
      if (!rec.evidence.includes(e)) {
        rec.evidence.push(e);
      }
    }
    return rec;
  }

  boostFor(name: string): number {
    const rec = this._names.get(name);
    if (rec === undefined) {
      return 0.0;
    }
    // Already-confirmed names get a strong boost when scoring later
    // candidates. Capped so a single weak occurrence cannot escalate
    // the doc-level score.
    return Math.min(0.4, rec.confidence);
  }

  known(name: string): boolean {
    return this._names.has(name);
  }

  names(): NameRecord[] {
    return [...this._names.values()];
  }

  /** Python __len__ 대응. */
  get size(): number {
    return this._names.size;
  }
}
