/**
 * openai/privacy-filter 를 브라우저에서 transformers.js(WebGPU) 로 돌린다 — app.py `_openai_detect` 대응.
 *
 * 모델은 HF 에서 받아 브라우저 Cache Storage 에 남는다(transformers.js 기본 동작).
 * import 시점에 DOM·네트워크를 건드리지 않는다 — groupSpans 는 Node 에서도 검증한다.
 */

// demo/web 에는 node_modules 가 없다 — 라이브러리는 버전 고정 CDN 에서 동적 import 한다.
const TRANSFORMERS_URL = "https://cdn.jsdelivr.net/npm/@huggingface/transformers@4.3.0";
export const MODEL_ID = "openai/privacy-filter";
/** 모델 README 가 WebGPU 용으로 안내하는 양자화 (onnx/model_q4.onnx + data ≈ 900MiB). */
const DTYPE = "q4";
/** transformers.js 의 env.cacheKey 기본값. */
const CACHE_NAME = "transformers-cache";

// ── 라벨 매핑 — ko_pii.eval.model_comparison.OPENAI_TO_KPII 와 동일 ──
export const OPENAI_TO_KPII: Record<string, string> = {
  private_person: "PERSON",
  private_email: "EMAIL",
  private_phone: "PHONE",
  private_address: "ADDRESS",
  private_date: "DT_BIRTH",
  private_url: "URL",
  account_number: "ACCOUNT",
};

export interface Span {
  label: string;
  start: number;
  end: number;
  confidence: number;
}

/** transformers.js token-classification (aggregation_strategy: "none") 의 토큰 한 개. */
export interface TokenTag {
  entity: string;
  score: number;
  index: number;
}

/** WebGPU 를 쓸 수 없으면 사유를, 쓸 수 있으면 null 을 돌려준다. */
export async function webGpuProblem(): Promise<string | null> {
  const gpu = (navigator as { gpu?: { requestAdapter(): Promise<unknown> } }).gpu;
  if (!gpu) return "이 브라우저는 WebGPU 를 지원하지 않습니다";
  try {
    if (!(await gpu.requestAdapter())) return "사용 가능한 GPU 어댑터가 없습니다";
  } catch (e) {
    return `GPU 확인 실패: ${e instanceof Error ? e.message : String(e)}`;
  }
  return null;
}

/**
 * BIOES 토큰 태그를 문자 구간으로 묶는다.
 *
 * transformers.js 는 토큰의 문자 오프셋을 주지 않는다 — byte-level BPE 는 decode(ids) === text 이므로
 * 접두 디코드 길이로 경계를 복원한다. `prefix(n)` 은 앞 n 개 토큰을 디코드한 문자열.
 * 한글 한 글자가 토큰 둘로 쪼개지면 접두 끝이 U+FFFD 가 되므로 그 글자를 포함하는 쪽으로 경계를 민다.
 */
export function groupSpans(tokens: TokenTag[], text: string, prefix: (n: number) => string): Span[] {
  const partial = (n: number): boolean => prefix(n).endsWith("\uFFFD");
  const boundary = (n: number, step: 1 | -1): number => {
    while (partial(n)) n += step;
    return prefix(n).length;
  };

  const groups: { type: string; first: number; last: number; scores: number[] }[] = [];
  for (const t of tokens) {
    const tagged = /^[BIES]-/.test(t.entity);
    const pos = tagged ? t.entity[0] : "I";
    const type = tagged ? t.entity.slice(2) : t.entity;
    const cur = groups.at(-1);
    if (cur && cur.type === type && cur.last === t.index - 1 && pos !== "B" && pos !== "S") {
      cur.last = t.index;
      cur.scores.push(t.score);
    } else {
      groups.push({ type, first: t.index, last: t.index, scores: [t.score] });
    }
  }

  const spans: Span[] = [];
  for (const g of groups) {
    let start = boundary(g.first, -1);
    let end = boundary(g.last + 1, 1);
    // 토큰은 앞 공백을 품는다(" 김") — app.py 의 .strip() 처럼 구간에서 공백을 뺀다.
    while (start < end && /\s/.test(text[start] ?? "")) start++;
    while (end > start && /\s/.test(text[end - 1] ?? "")) end--;
    if (start === end) continue;
    spans.push({
      label: OPENAI_TO_KPII[g.type] ?? g.type,
      start,
      end,
      confidence: g.scores.reduce((a, b) => a + b, 0) / g.scores.length,
    });
  }
  return spans;
}

// ── 모델 로드 / 추론 ─────────────────────────────────────────────
interface Classifier {
  (text: string, opts: { aggregation_strategy: "none" }): Promise<TokenTag[]>;
  tokenizer: {
    (text: string, opts: { truncation: boolean }): { input_ids: { tolist(): bigint[][] } };
    decode(ids: bigint[], opts: { skip_special_tokens: boolean; clean_up_tokenization_spaces: boolean }): string;
  };
  dispose(): Promise<unknown>;
}

let classifier: Classifier | null = null;
let loading: Promise<void> | null = null;

export const isLoaded = (): boolean => classifier !== null;

/** 모델을 받아(또는 캐시에서 읽어) WebGPU 세션을 만든다. `onProgress` 는 0~100. */
export function loadModel(onProgress: (percent: number) => void): Promise<void> {
  if (classifier) return Promise.resolve();
  loading ??= (async () => {
    try {
      const { pipeline } = await import(/* @vite-ignore */ TRANSFORMERS_URL);
      classifier = (await pipeline("token-classification", MODEL_ID, {
        device: "webgpu",
        dtype: DTYPE,
        progress_callback: (p: { status: string; progress?: number }) => {
          if (p.status === "progress_total") onProgress(p.progress ?? 0);
        },
      })) as Classifier;
    } finally {
      loading = null;
    }
  })();
  return loading;
}

export async function detect(text: string): Promise<Span[]> {
  if (!classifier) throw new Error("모델이 로드되지 않았다");
  const { tokenizer } = classifier;
  const tokens = await classifier(text, { aggregation_strategy: "none" });
  const ids = tokenizer(text, { truncation: true }).input_ids.tolist()[0] ?? [];
  const memo = new Map<number, string>();
  const prefix = (n: number): string => {
    if (n <= 0) return "";
    let s = memo.get(n);
    if (s === undefined) {
      s = tokenizer.decode(ids.slice(0, n), { skip_special_tokens: true, clean_up_tokenization_spaces: false });
      memo.set(n, s);
    }
    return s;
  };
  if (prefix(ids.length) !== text) throw new Error("토크나이저 왕복 불일치 — 문자 오프셋을 복원할 수 없다");
  return groupSpans(tokens, text, prefix);
}

// ── 다운로드된 모델 관리 (Cache Storage) ─────────────────────────
async function modelEntries(): Promise<{ cache: Cache; keys: Request[] } | null> {
  // 비보안 컨텍스트(http, localhost 제외)에는 caches 가 없다.
  if (typeof caches === "undefined" || !(await caches.has(CACHE_NAME))) return null;
  const cache = await caches.open(CACHE_NAME);
  const keys = (await cache.keys()).filter((r) => r.url.includes(`/${MODEL_ID}/`));
  return { cache, keys };
}

/** 캐시에 남아 있는 모델 파일 크기 합(byte). 없으면 0. */
export async function cachedBytes(): Promise<number> {
  const entries = await modelEntries();
  if (!entries) return 0;
  let total = 0;
  for (const key of entries.keys) {
    total += Number((await entries.cache.match(key))?.headers.get("content-length") ?? 0);
  }
  return total;
}

/** GPU 세션을 해제하고 다운로드된 모델 파일을 지운다. 지운 파일 수를 돌려준다. */
export async function deleteModel(): Promise<number> {
  await loading?.catch(() => {});
  await classifier?.dispose();
  classifier = null;
  const entries = await modelEntries();
  if (!entries) return 0;
  await Promise.all(entries.keys.map((k) => entries.cache.delete(k)));
  return entries.keys.length;
}
