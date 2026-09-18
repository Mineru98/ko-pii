/**
 * CSV / TSV 텍스트 추출 — 헤더 인식 + 레코드 반환.
 * Python `ko_pii.io_.csv_reader` 1:1 포트.
 *
 * JS 에는 `csv.Sniffer` / `csv.DictReader` 가 없으므로 CPython 3.12 Lib/csv.py 의
 * 알고리즘을 그대로 재현한다:
 * - `Sniffer.sniff`: quoted-section 패턴 4종(수동 스캔 — Python 정규식의 소유적
 *   수량자 `*+` 를 상태 스캔으로 동등 구현) + 문자 빈도 일관성 휴리스틱.
 * - 레코드 파서: CPython `_csv.c` 상태 머신 (START_RECORD / START_FIELD / IN_FIELD /
 *   IN_QUOTED_FIELD / QUOTE_IN_QUOTED_FIELD / EAT_CRNL). escapechar 는 excel /
 *   excel_tab / sniffed 어느 쪽도 사용하지 않으므로 생략한다.
 * - `DictReader`: 첫 행 = 헤더, 짧은 행 restval(null), 긴 행 restkey(Python None →
 *   TS 에서는 빈 문자열 키 "" 로 표현) 버킷.
 */
import { readText as plainReadText } from "./plain.js";

/** Python csv.Error 대응. */
export class CsvError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CsvError";
  }
}

/** Python csv.Dialect 의 파서 관련 필드. */
export interface CsvDialect {
  delimiter: string;
  quotechar: string;
  doublequote: boolean;
  skipinitialspace: boolean;
}

/** Python csv.excel 대응. */
export const EXCEL: CsvDialect = {
  delimiter: ",",
  quotechar: '"',
  doublequote: true,
  skipinitialspace: false,
};

/** Python csv.excel_tab 대응. */
export const EXCEL_TAB: CsvDialect = {
  delimiter: "\t",
  quotechar: '"',
  doublequote: true,
  skipinitialspace: false,
};

/** DictReader restkey (Python 은 None 키 사용 — TS 객체 표현은 "" 로 대응). */
export const RESTKEY = "";
/** 셀 값 — 긴 행의 초과 셀은 restkey 버킷에 문자열 배열로 담긴다. */
export type CsvCell = string | string[] | null;
export type CsvRecord = Record<string, CsvCell>;

/** 전체 내용을 평문으로 반환 (헤더 포함) — plain 에 위임. */
export function readText(path: string): string {
  return plainReadText(path);
}

/** 첫 행을 헤더로 인식, 이후를 레코드(dict) 리스트로 반환.
 *
 * 정적 타입은 Python `dispatcher.read_records -> list[dict[str, str]]` 어노테이션과
 * 동일하게 본다 (restkey/restval 셀은 런타임에 그대로 유지 — 정형 셀만 쓰는
 * dispatcher 계약이므로). 세밀한 CsvRecord 타입이 필요하면 readRecordsFromText 사용.
 */
export function readRecords(path: string): Record<string, string>[] {
  const raw = plainReadText(path);
  return readRecordsFromText(raw) as unknown as Record<string, string>[];
}

/** 디코드된 텍스트로부터 readRecords 본체 (테스트/재사용용). */
export function readRecordsFromText(raw: string): CsvRecord[] {
  if (!raw.trim()) return [];
  // Sniff delimiter — Python: csv.Sniffer().sniff(raw[:8192], delimiters=",\t;|")
  let dialect: CsvDialect;
  try {
    dialect = sniff(cpSlice(raw, 8192), ",\t;|");
  } catch (error) {
    if (!(error instanceof CsvError)) throw error;
    // Fallback to comma or tab heuristic
    dialect = cpSlice(raw, 1024).includes("\t") ? EXCEL_TAB : EXCEL;
  }
  const rows = parseCsvRows(raw, dialect);
  return dictReaderRecords(rows);
}

// ---------------------------------------------------------------------------
// 문자열 보조
// ---------------------------------------------------------------------------

/** Python `s[:n]` (코드 포인트 기준) 대응 — BMP 문자열에서는 UTF-16 슬라이스와 동일. */
function cpSlice(s: string, n: number): string {
  if (s.length <= n) return s;
  return Array.from(s).slice(0, n).join("");
}

function countChar(s: string, ch: string): number {
  let count = 0;
  for (const c of s) if (c === ch) count += 1;
  return count;
}

/**
 * Python 정규식 `[^\w\n"']` 대응 문자 판정. Python `\w` 는 유니코드 문자를
 * 포함하므로(한글 등) ASCII 단어 문자 + 모든 non-ASCII 를 단어 문자로 근사한다.
 */
function isPythonWordChar(ch: string): boolean {
  return /[0-9A-Za-z_]/.test(ch) || ch.charCodeAt(0) > 0x7f;
}

function isDelimiterCandidateChar(ch: string): boolean {
  return !isPythonWordChar(ch) && ch !== "\n" && ch !== '"' && ch !== "'";
}

// ---------------------------------------------------------------------------
// csv.Sniffer 재현
// ---------------------------------------------------------------------------

/** Sniffer.preferred (CPython Lib/csv.py). */
const PREFERRED = [",", "\t", ";", " ", ":"];

interface QuoteMatch {
  quote: string;
  /** P4 는 delim/space 그룹이 없다 → undefined. */
  delim?: string;
  space?: string;
  /** 다음 스캔 시작 위치 (finditer 비중첩 대응). */
  end: number;
}

/**
 * Returns a dialect (or throws CsvError) corresponding to the sample.
 * Python `Sniffer.sniff` 재현.
 */
export function sniff(sample: string, delimiters: string | null = null): CsvDialect {
  const normalized = sample.replaceAll("\r\n", "\n").replaceAll("\r", "\n");

  let [quotechar, doublequote, delimiter, skipinitialspace] = guessQuoteAndDelimiter(
    normalized,
    delimiters,
  );
  if (!delimiter) {
    [delimiter, skipinitialspace] = guessDelimiter(normalized, delimiters);
  }
  if (!delimiter) throw new CsvError("Could not determine delimiter");

  return {
    delimiter,
    quotechar: quotechar || '"', // _csv.reader won't accept a quotechar of ''
    doublequote,
    skipinitialspace,
  };
}

/**
 * quoted 필드 주변의 동일 문자 패턴에서 quotechar/delimiter를 추정한다.
 * Python `Sniffer._guess_quote_and_delimiter` 재현 (패턴 4종을 순서대로 시도).
 */
function guessQuoteAndDelimiter(
  data: string,
  delimiters: string | null,
): [quotechar: string, doublequote: boolean, delim: string | null, skipinitialspace: boolean] {
  const patterns: Array<(data: string) => QuoteMatch[]> = [
    // 1: ,"..." ,  — delim + space? + quote + body + quote + 같은 delim
    (d) => scanQuotedPattern(d, "delim-quoted-delim"),
    // 2: \n"..." ,  — 행 시작 quote + body + quote + delim + space?
    (d) => scanQuotedPattern(d, "start-quote-delim"),
    // 3: ,"..."\n   — delim + space? + quote + body + quote + EOL
    (d) => scanQuotedPattern(d, "delim-quoted-eol"),
    // 4: \n"..."\n  — 행 시작 quote + body + quote + EOL (delim 없음)
    (d) => scanQuotedPattern(d, "start-quote-eol"),
  ];

  let matches: QuoteMatch[] = [];
  for (const scan of patterns) {
    matches = scan(data);
    if (matches.length > 0) break;
  }

  if (matches.length === 0) {
    // (quotechar, doublequote, delimiter, skipinitialspace)
    return ["", false, null, false];
  }
  const quotes = new Map<string, number>();
  const delims = new Map<string, number>();
  let spaces = 0;
  for (const m of matches) {
    const q = m.quote;
    if (q) quotes.set(q, (quotes.get(q) ?? 0) + 1);
    if (m.delim === undefined) continue; // pattern 4: delim 그룹 없음
    const d = m.delim;
    if (d && (delimiters === null || delimiters.includes(d))) {
      delims.set(d, (delims.get(d) ?? 0) + 1);
    }
    if (m.space === undefined) continue;
    if (m.space) spaces += 1;
  }

  // Python max(dict, key=dict.get) — 최댓값 동률 시 삽입 순서상 첫 항목
  const quotechar = maxKeyByValue(quotes);
  let delim: string;
  let skipinitialspace: boolean;
  if (delims.size > 0) {
    delim = maxKeyByValue(delims);
    skipinitialspace = delims.get(delim) === spaces;
    if (delim === "\n") delim = ""; // most likely a file with a single column
  } else {
    // there is *no* delimiter, it's a single column of quoted data
    delim = "";
    skipinitialspace = false;
  }

  // A doubled quote character inside a quoted field means a double quoted format.
  let doublequote = false;
  if (delim) {
    doublequote = detectDoubleQuote(data, delim, quotechar);
  }
  return [quotechar, doublequote, delim, skipinitialspace];
}

/** Map 에서 값이 최대인 키 (동률 시 삽입 순서 첫 항목 — Python max 시맨틱). */
function maxKeyByValue(map: Map<string, number>): string {
  let bestKey = "";
  let bestValue = -1;
  for (const [key, value] of map) {
    if (value > bestValue) {
      bestKey = key;
      bestValue = value;
    }
  }
  return bestKey;
}

/**
 * 소유적 수량자 body `(?:(?P=q){2}|(?!(?P=q)).)*+` 의 스캔 —
 * body 는 " doubled 가 아닌 첫 quote" 에서 끝난다. 끝 위치를 반환한다.
 */
function scanPossessiveBody(data: string, start: number, quote: string): number {
  let j = start;
  const n = data.length;
  while (j < n) {
    if (data[j] === quote) {
      if (j + 1 < n && data[j + 1] === quote)
        j += 2; // doubled quote
      else break; // unpaired quote → body 끝
    } else {
      j += 1;
    }
  }
  return j;
}

/** Python 정규식 패턴 4종의 수동 스캔 (finditer 비중첩 시맨틱 포함). */
function scanQuotedPattern(data: string, kind: string): QuoteMatch[] {
  const matches: QuoteMatch[] = [];
  const n = data.length;
  let i = 0;
  while (i < n) {
    const m =
      kind === "delim-quoted-delim"
        ? matchDelimQuotedDelim(data, i)
        : kind === "start-quote-delim"
          ? matchStartQuotedDelim(data, i)
          : kind === "delim-quoted-eol"
            ? matchDelimQuotedEol(data, i)
            : matchStartQuotedEol(data, i);
    if (m === null) {
      i += 1;
      continue;
    }
    matches.push(m);
    i = m.end;
  }
  return matches;
}

/** P1: `(?P<delim>[^\w\n"'])(?P<space> ?)(?P<quote>["\'])body(?P=quote)(?P=delim)` */
function matchDelimQuotedDelim(data: string, i: number): QuoteMatch | null {
  const delim = data[i];
  if (delim === undefined || !isDelimiterCandidateChar(delim)) return null;
  let quoteAt = i + 1;
  let space = "";
  if (data[quoteAt] === " ") {
    space = " ";
    quoteAt += 1;
  }
  const quote = data[quoteAt];
  if (quote !== '"' && quote !== "'") return null;
  const bodyEnd = scanPossessiveBody(data, quoteAt + 1, quote);
  if (data[bodyEnd] !== quote) return null;
  if (data[bodyEnd + 1] !== delim) return null;
  return { quote, delim, space, end: bodyEnd + 2 };
}

/** P2: `(?:^|\n)(?P<quote>["\'])body(?P=quote)(?P<delim>[^\w\n"'])(?P<space> ?)` */
function matchStartQuotedDelim(data: string, i: number): QuoteMatch | null {
  // (?:^|\n) — i 가 0 이면 zero-width ^, 아니면 \n 소비 (backtrack 순서 동일)
  const attempts: Array<{ quoteAt: number }> = [];
  if (i === 0) attempts.push({ quoteAt: 0 });
  if (data[i] === "\n") attempts.push({ quoteAt: i + 1 });
  for (const { quoteAt } of attempts) {
    const quote = data[quoteAt];
    if (quote !== '"' && quote !== "'") continue;
    const bodyEnd = scanPossessiveBody(data, quoteAt + 1, quote);
    if (data[bodyEnd] !== quote) continue;
    const delim = data[bodyEnd + 1];
    if (delim === undefined || !isDelimiterCandidateChar(delim)) continue;
    let end = bodyEnd + 2;
    let space = "";
    if (data[end] === " ") {
      space = " ";
      end += 1;
    }
    return { quote, delim, space, end };
  }
  return null;
}

/** P3: `(?P<delim>[^\w\n"'])(?P<space> ?)(?P<quote>["\'])body(?P=quote)(?:$|\n)` */
function matchDelimQuotedEol(data: string, i: number): QuoteMatch | null {
  const delim = data[i];
  if (delim === undefined || !isDelimiterCandidateChar(delim)) return null;
  let quoteAt = i + 1;
  let space = "";
  if (data[quoteAt] === " ") {
    space = " ";
    quoteAt += 1;
  }
  const quote = data[quoteAt];
  if (quote !== '"' && quote !== "'") return null;
  const bodyEnd = scanPossessiveBody(data, quoteAt + 1, quote);
  if (data[bodyEnd] !== quote) return null;
  // MULTILINE $ — 문자열 끝 또는 \n 앞 (zero-width, \n 미소비)
  const after = data[bodyEnd + 1];
  if (after !== undefined && after !== "\n") return null;
  return { quote, delim, space, end: bodyEnd + 1 };
}

/** P4: `(?:^|\n)(?P<quote>["\'])body(?P=quote)(?:$|\n)` — delim/space 그룹 없음 */
function matchStartQuotedEol(data: string, i: number): QuoteMatch | null {
  const attempts: Array<{ quoteAt: number }> = [];
  if (i === 0) attempts.push({ quoteAt: 0 });
  if (data[i] === "\n") attempts.push({ quoteAt: i + 1 });
  for (const { quoteAt } of attempts) {
    const quote = data[quoteAt];
    if (quote !== '"' && quote !== "'") continue;
    const bodyEnd = scanPossessiveBody(data, quoteAt + 1, quote);
    if (data[bodyEnd] !== quote) continue;
    const after = data[bodyEnd + 1];
    if (after !== undefined && after !== "\n") continue;
    return { quote, end: bodyEnd + 1 };
  }
  return null;
}

/**
 * doublequote 포맷 판정 — Python dq_regexp 재현:
 * `(?:(?<=delim)|^) *quote((?:qq|[^q])*+)quote(?:delim|$)` (MULTILINE)
 * body 안에 quote 2연속이 있으면 doublequote.
 */
function detectDoubleQuote(data: string, delim: string, quotechar: string): boolean {
  const n = data.length;
  const spacePattern = delim !== " ";
  let i = 0;
  while (i < n) {
    // (?:(?<=%(delim)s)|^) — MULTILINE ^: 문자열 시작 또는 \n 다음
    const atBoundary = i === 0 || data[i - 1] === delim || data[i - 1] === "\n";
    let matched = false;
    if (atBoundary) {
      let s = i;
      if (spacePattern) {
        while (data[s] === " ") s += 1; // ' *+' (소유적이지만 공백 uniform이라 greedy와 동치)
      }
      if (data[s] === quotechar) {
        const bodyEnd = scanPossessiveBody(data, s + 1, quotechar);
        if (data[bodyEnd] === quotechar) {
          const after = data[bodyEnd + 1];
          if (after === delim || after === undefined || after === "\n") {
            const body = data.slice(s + 1, bodyEnd);
            if (body.includes(quotechar + quotechar)) return true;
            i = bodyEnd + 1; // finditer 비중첩
            matched = true;
          }
        }
      }
    }
    if (!matched) i += 1;
  }
  return false;
}

/**
 * delimiter 빈도 일관성 휴리스틱 — Python `Sniffer._guess_delimiter` 재현.
 * 각 행에서 문자 빈도 → 빈도의 빈도(메타 빈도) mode → mode 를 만족하는 행 비율
 * (consistency) 이 임계값(0.9) 이상인 ASCII 문자를 delimiter 로 고른다.
 */
function guessDelimiter(
  data: string,
  delimiters: string | null,
): [delim: string, skipinitialspace: boolean] {
  const lines = data.split("\n").filter((line) => line !== "");
  const ascii: string[] = [];
  for (let c = 0; c < 127; c++) ascii.push(String.fromCharCode(c)); // 7-bit ASCII

  // build frequency tables
  const chunkLength = Math.min(10, lines.length);
  let iteration = 0;
  const charFrequency = new Map<string, Map<number, number>>();
  const modes = new Map<string, [freq: number, adjusted: number]>();
  const delims = new Map<string, [freq: number, adjusted: number]>();
  let start = 0;
  let end = chunkLength;
  while (start < lines.length) {
    iteration += 1;
    for (const line of lines.slice(start, end)) {
      for (const char of ascii) {
        let metaFrequency = charFrequency.get(char);
        if (metaFrequency === undefined) {
          metaFrequency = new Map<number, number>();
          charFrequency.set(char, metaFrequency);
        }
        // must count even if frequency is 0
        const freq = countChar(line, char);
        metaFrequency.set(freq, (metaFrequency.get(freq) ?? 0) + 1);
      }
    }

    for (const [char, metaFrequency] of charFrequency) {
      const items: Array<[freq: number, count: number]> = [...metaFrequency.entries()];
      if (items.length === 1 && items[0]![0] === 0) continue;
      // get the mode of the frequencies
      if (items.length > 1) {
        let maxItem = items[0]!;
        for (const item of items) if (item[1] > maxItem[1]) maxItem = item;
        // adjust the mode - subtract the sum of all other frequencies
        let restSum = 0;
        for (const item of items) if (item !== maxItem) restSum += item[1];
        modes.set(char, [maxItem[0], maxItem[1] - restSum]);
      } else {
        modes.set(char, items[0]!);
      }
    }

    // build a list of possible delimiters
    const modeList = [...modes.entries()];
    const total = Math.min(chunkLength * iteration, lines.length);
    // (rows of consistent data) / (number of rows) = 100%
    let consistency = 1.0;
    // minimum consistency threshold
    const threshold = 0.9;
    while (delims.size === 0 && consistency >= threshold) {
      for (const [k, v] of modeList) {
        if (v[0] > 0 && v[1] > 0) {
          if (v[1] / total >= consistency && (delimiters === null || delimiters.includes(k))) {
            delims.set(k, v);
          }
        }
      }
      consistency -= 0.01;
    }

    if (delims.size === 1) {
      const delim = [...delims.keys()][0]!;
      const skipinitialspace = countChar(lines[0]!, delim) === countChar(lines[0]!, `${delim} `);
      return [delim, skipinitialspace];
    }

    // analyze another chunkLength lines
    start = end;
    end += chunkLength;
  }

  if (delims.size === 0) return ["", false];

  // if there's more than one, fall back to a 'preferred' list
  if (delims.size > 1) {
    for (const d of PREFERRED) {
      if (delims.has(d)) {
        const skipinitialspace = countChar(lines[0]!, d) === countChar(lines[0]!, `${d} `);
        return [d, skipinitialspace];
      }
    }
  }

  // nothing else indicates a preference, pick the character that dominates(?)
  const items: Array<[[number, number], string]> = [...delims.entries()].map(([k, v]) => [v, k]);
  items.sort(
    (a, b) => a[0][0] - b[0][0] || a[0][1] - b[0][1] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0),
  );
  const delim = items[items.length - 1]![1];
  const skipinitialspace = countChar(lines[0]!, delim) === countChar(lines[0]!, `${delim} `);
  return [delim, skipinitialspace];
}

// ---------------------------------------------------------------------------
// csv reader (CPython _csv.c 상태 머신) + DictReader
// ---------------------------------------------------------------------------

enum ParserState {
  START_RECORD,
  START_FIELD,
  IN_FIELD,
  IN_QUOTED_FIELD,
  QUOTE_IN_QUOTED_FIELD,
  EAT_CRNL,
}

/** Python `csv.reader(StringIO(raw), dialect)` 재현 — 행별('\n' 유지) 처리 + EOF 규칙. */
export function parseCsvRows(raw: string, d: CsvDialect): string[][] {
  const records: string[][] = [];
  let fields: string[] = [];
  let cur = "";
  let state = ParserState.START_RECORD;
  const saveField = (): void => {
    fields.push(cur);
    cur = "";
  };
  const finishRecord = (): void => {
    records.push(fields);
    fields = [];
  };

  const lines = iterLines(raw);
  for (const line of lines) {
    let done = false;
    for (let i = 0; i <= line.length && !done; i++) {
      const c = i < line.length ? line[i]! : "\0";
      const isEol = c === "\n" || c === "\r";
      switch (state) {
        case ParserState.START_RECORD: {
          if (c === "\0") {
            // empty line — record returned with accumulated (empty) fields
            done = true;
            finishRecord();
            break;
          }
          if (isEol) {
            state = ParserState.EAT_CRNL;
            break;
          }
          state = ParserState.START_FIELD;
          i -= 1; // fallthrough — 같은 문자를 START_FIELD 에서 재처리
          break;
        }
        case ParserState.START_FIELD: {
          if (isEol || c === "\0") {
            // save empty field - return [fields]
            saveField();
            if (c === "\0") {
              finishRecord();
              state = ParserState.START_RECORD;
              done = true;
            } else {
              state = ParserState.EAT_CRNL;
            }
            break;
          }
          if (d.quotechar !== "" && c === d.quotechar) {
            // start quoted section
            state = ParserState.IN_QUOTED_FIELD;
            break;
          }
          if (c === d.delimiter) {
            // save empty field
            saveField();
            break;
          }
          if (c === " " && d.skipinitialspace) {
            // ignore space at start of field
            break;
          }
          cur += c;
          state = ParserState.IN_FIELD;
          break;
        }
        case ParserState.IN_FIELD: {
          if (isEol || c === "\0") {
            // end of line - return [fields]
            saveField();
            if (c === "\0") {
              finishRecord();
              state = ParserState.START_RECORD;
              done = true;
            } else {
              state = ParserState.EAT_CRNL;
            }
            break;
          }
          if (c === d.delimiter) {
            saveField();
            state = ParserState.START_FIELD;
            break;
          }
          cur += c;
          break;
        }
        case ParserState.IN_QUOTED_FIELD: {
          if (c === "\0") {
            // 줄 경계 통과 — 다음 줄에서 계속 (multiline quoted cell)
            break;
          }
          if (d.quotechar !== "" && c === d.quotechar) {
            state = d.doublequote ? ParserState.QUOTE_IN_QUOTED_FIELD : ParserState.IN_FIELD;
            break;
          }
          cur += c;
          break;
        }
        case ParserState.QUOTE_IN_QUOTED_FIELD: {
          if (isEol || c === "\0") {
            // end of line - return [fields]
            saveField();
            if (c === "\0") {
              finishRecord();
              state = ParserState.START_RECORD;
              done = true;
            } else {
              state = ParserState.EAT_CRNL;
            }
            break;
          }
          if (d.quotechar !== "" && c === d.quotechar) {
            // double quotes - copy quoted char
            cur += d.quotechar;
            state = ParserState.IN_QUOTED_FIELD;
            break;
          }
          if (c === d.delimiter) {
            // end of field - return [fields]
            saveField();
            state = ParserState.START_FIELD;
            break;
          }
          // strict=False: illegal character - add to field
          cur += c;
          state = ParserState.IN_FIELD;
          break;
        }
        case ParserState.EAT_CRNL: {
          if (isEol) {
            break;
          }
          if (c === "\0") {
            finishRecord();
            state = ParserState.START_RECORD;
            done = true;
            break;
          }
          throw new CsvError(
            "new-line character seen in unquoted field - do you need to open the file with newline=''?",
          );
        }
      }
    }
  }
  // EOF 규칙 (CPython Reader_iternext): field_len != 0 or state == IN_QUOTED_FIELD
  if (fields.length !== 0 || state === ParserState.IN_QUOTED_FIELD) {
    saveField();
    finishRecord();
  }
  return records;
}

/** StringIO(initial, newline="\n") 줄 이터레이션 재현 — "\n" 을 행 끝에 유지. */
function iterLines(raw: string): string[] {
  if (raw === "") return [];
  const parts = raw.split("\n");
  const lines: string[] = [];
  for (let i = 0; i < parts.length - 1; i++) lines.push(`${parts[i]!}\n`);
  const last = parts[parts.length - 1]!;
  if (last !== "") lines.push(last);
  return lines;
}

/** Python csv.DictReader: `while row == []` skip + zip(fieldnames, row) + restkey/restval. */
function dictReaderRecords(rows: string[][]): CsvRecord[] {
  if (rows.length === 0) return [];
  const fieldnames = rows[0]!;
  const out: CsvRecord[] = [];
  for (const row of rows.slice(1)) {
    if (row.length === 0) continue; // 빈 행 스킵
    const record: CsvRecord = {};
    const common = Math.min(fieldnames.length, row.length);
    for (let i = 0; i < common; i++) record[fieldnames[i]!] = row[i]!;
    if (fieldnames.length < row.length) {
      record[RESTKEY] = row.slice(fieldnames.length);
    } else if (fieldnames.length > row.length) {
      for (let i = row.length; i < fieldnames.length; i++) record[fieldnames[i]!] = null;
    }
    // Python `any(row.values())` — None/""/빈 배열은 거짓
    const any = Object.values(record).some((v) =>
      Array.isArray(v) ? v.length > 0 : v !== null && v !== "",
    );
    if (any) out.push(record);
  }
  return out;
}
