/**
 * argparse-lite — Python 3.12 `argparse` 의 ko-pii cli.py 가 사용하는 기능만
 * 재현한 서브셋. 외부 의존성 없음 (라이브러리 코어 "의존성 0" 유지).
 *
 * 지원: positional (nargs="?" / "*"), long/short 옵션, `--flag=value` /
 * `--flag value` / `-fVALUE` 결합, choices, type=int, store_true,
 * nargs="?" const, action="version", -h/--help, 약어 매칭(--lab → --labels),
 * `--` 구분자, 음수 positional.
 *
 * stdout/stderr/종료 코드 1:1 목표로 CPython 3.12.14 실측에 맞춰 포맷한다:
 * - 오류: stderr 에 `usage: ...\nko-pii: error: <msg>\n` 후 코드 2
 *   (usage 블록과 error 줄 사이 빈 줄 없음 — 실측)
 * - help: stdout 에 usage + 설명 + positional arguments + options, 코드 0
 * - version: stdout 에 `<version>\n`, 코드 0
 *
 * textwrap 은 CPython 3.12 TextWrapper(break_long_words=True,
 * break_on_hyphens=True, drop_whitespace=True) 의 wordsep_re 를 포함해 이식했다.
 */
// ─────────────────────────────────────────────────────────────────────
// Python str 유틸
// ─────────────────────────────────────────────────────────────────────

/** Python repr() — 문자열 따옴표 규칙(작은따옴표 기본, ' 포함 시 큰따옴표) 재현. */
export function pyRepr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  const body = s
    .replaceAll("\\", "\\\\")
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\r")
    .replaceAll("\t", "\\t")
    .replaceAll(quote === "'" ? "'" : '"', quote === "'" ? "\\'" : '\\"');
  return `${quote}${body}${quote}`;
}

/** Python int("...") — 주변 공백 허용, 자리 사이 언더스코어 허용. 실패 시 null. */
export function pyInt(s: string): number | null {
  const t = s.trim();
  if (!/^[+-]?[0-9](_?[0-9])*$/.test(t)) return null;
  return Number(t.replaceAll("_", ""));
}

/** Python str 비교 — 코드 포인트 순 (JS 기본은 UTF-16 코드 유닛). */
export function pyStrCompare(a: string, b: string): number {
  const ca = [...a];
  const cb = [...b];
  const n = Math.min(ca.length, cb.length);
  for (let i = 0; i < n; i++) {
    const x = ca[i]!.codePointAt(0)!;
    const y = cb[i]!.codePointAt(0)!;
    if (x !== y) return x < y ? -1 : 1;
  }
  return ca.length - cb.length;
}

// ─────────────────────────────────────────────────────────────────────
// textwrap 포트 (wrap/fill)
// ─────────────────────────────────────────────────────────────────────

// CPython textwrap.wordsep_re 의 문자 클래스.
// Python \w 는 유니코드 인식 — JS \p{...}(u 플래그)으로 대응한다.
const WC = "[\\p{Alphabetic}\\p{M}\\p{Nd}\\p{Pc}\\u200c\\u200d]"; // Python \w
const WP = `[${WC.slice(1, -1)}!"'&.,?]`; // word_punct = [\w!"\'&.,?]
const LT = "[\\p{Alphabetic}\\p{M}\\p{Pc}\\u200c\\u200d]"; // letter = [^\d\W]
const WS = "[ \\t\\n\\v\\f\\r]";
const NWS = "[^ \\t\\n\\v\\f\\r]";

/** wordsep_re — 공백 / 단어(하이픈 경계에서 분리) 토큰화. */
const WORDSEP = new RegExp(
  `(${WS}+` +
    `|(?<=${WP})-{2,}(?=\\w)` +
    `|${NWS}+?(?:` +
    `-(?:(?<=${LT}{2}-)|(?<=${LT}-${LT}-))(?=${LT}-?${LT})` +
    `|(?=${WS}|$)` +
    `|(?<=${WP})(?=-{2,}\\w)` +
    `))`,
  "u",
);

/** argparse HelpFormatter._whitespace_matcher (ASCII \s+) — 공백 정규화. */
function collapseWs(s: string): string {
  return s.replace(/[ \t\n\v\f\r]+/g, " ").trim();
}

/** TextWrapper._split — 공백 치환 + 토큰화. */
function splitWords(text: string): string[] {
  const munged = text.replace(/[\t\n\v\f\r]/g, " ");
  return munged.split(WORDSEP).filter((c) => c !== "");
}

/** TextWrapper._handle_long_word. */
function handleLongWord(chunks: string[], curLine: string[], curLen: number, width: number): void {
  const spaceLeft = width < 1 ? 1 : width - curLen;
  const chunk = chunks[chunks.length - 1]!;
  let end = spaceLeft;
  if (chunk.length > spaceLeft) {
    // rfind('-', 0, space_left) — 하이픈 뒤에서 자름 (앞에 비하이픈 문자가 있을 때만)
    const hyphen = chunk.lastIndexOf("-", spaceLeft - 1);
    if (
      hyphen > 0 &&
      chunk
        .slice(0, hyphen)
        .split("")
        .some((c) => c !== "-")
    ) {
      end = hyphen + 1;
    }
  }
  curLine.push(chunk.slice(0, end));
  chunks[chunks.length - 1] = chunk.slice(end);
}

/** TextWrapper._wrap_chunks (max_lines=None, drop_whitespace=True). */
function wrapChunks(chunksIn: string[], width: number, indents: [string, string]): string[] {
  const lines: string[] = [];
  const chunks = [...chunksIn].reverse();
  while (chunks.length > 0) {
    const curLine: string[] = [];
    let curLen = 0;
    const indent = lines.length === 0 ? indents[0] : indents[1];
    const lineWidth = width - indent.length;
    if (chunks[chunks.length - 1]!.trim() === "" && lines.length > 0) chunks.pop();
    while (chunks.length > 0) {
      const l = chunks[chunks.length - 1]!.length;
      if (curLen + l <= lineWidth) {
        curLine.push(chunks.pop()!);
        curLen += l;
      } else {
        break;
      }
    }
    if (chunks.length > 0 && chunks[chunks.length - 1]!.length > lineWidth) {
      handleLongWord(chunks, curLine, curLen, lineWidth);
      curLen = curLine.reduce((s, c) => s + c.length, 0);
    }
    if (curLine.length > 0 && curLine[curLine.length - 1]!.trim() === "") {
      curLen -= curLine[curLine.length - 1]!.length;
      curLine.pop();
    }
    if (curLine.length > 0) lines.push(indent + curLine.join(""));
  }
  return lines;
}

/** Python textwrap.wrap(text, width) — 기본 옵션. */
export function pyWrap(text: string, width: number): string[] {
  return wrapChunks(splitWords(text), width, ["", ""]);
}

/** Python textwrap.fill(text, width, initial_indent=i, subsequent_indent=i). */
export function pyFill(text: string, width: number, indent: string): string {
  return wrapChunks(splitWords(text), width, [indent, indent]).join("\n");
}

// ─────────────────────────────────────────────────────────────────────
// 터미널 폭 — shutil.get_terminal_size().columns - 2
// ─────────────────────────────────────────────────────────────────────

function terminalWidth(): number {
  const env = process.env.COLUMNS;
  if (env !== undefined && env !== "") {
    const n = Number(env);
    if (Number.isInteger(n) && n > 0) return n - 2;
  }
  const cols = (process.stdout as unknown as { columns?: number }).columns;
  // 파이프/파일 출력 시 columns 가 undefined → Python 의 fallback (80, 24)
  return (typeof cols === "number" && cols > 0 ? cols : 80) - 2;
}

// ─────────────────────────────────────────────────────────────────────
// 파서
// ─────────────────────────────────────────────────────────────────────

/** parseArgs 가 즉시 출력+종료를 요구할 때 (help/version/error). */
export class ParseExit extends Error {
  readonly stream: "stdout" | "stderr";
  readonly code: number;
  readonly text: string;

  constructor(text: string, code: number, stream: "stdout" | "stderr") {
    super("ParseExit");
    this.text = text;
    this.code = code;
    this.stream = stream;
  }
}

export type Nargs = "opt" | "star";

export interface ArgSpec {
  /** 네임스페이스 키 — Python dest (예: "json_summary"). */
  dest: string;
  /** 옵션 문자열들 (첫 번째가 usage/help 대표). 없으면 positional. */
  optionStrings?: string[];
  nargs?: Nargs;
  /** store_true 플래그 (nargs 0). */
  isFlag?: boolean;
  /** nargs="opt" 이고 값이 없을 때 채워지는 값 (Python const). */
  const?: string;
  def?: unknown;
  choices?: readonly string[];
  isInt?: boolean;
  /** action="version" — 지정 시 해당 옵션이 출력할 문자열. */
  versionText?: string;
  help?: string;
}

interface Action extends ArgSpec {
  positional: boolean;
}

/** argparse error 를 Python 형식으로 렌더링하는 파서. */
export class ArgumentParser {
  readonly prog: string;
  description?: string;
  private readonly actions: Action[] = [];
  private readonly optionStrings = new Map<string, Action>(); // 등록 순서 유지

  constructor(prog: string, description?: string) {
    this.prog = prog;
    this.description = description;
    // Python argparse 는 -h/--help 를 가장 먼저 자동 등록한다.
    this.addArgument({
      dest: "help",
      optionStrings: ["-h", "--help"],
      isFlag: true,
      help: "show this help message and exit",
    });
  }

  addArgument(spec: ArgSpec): void {
    const action: Action = { ...spec, positional: spec.optionStrings === undefined };
    this.actions.push(action);
    if (action.optionStrings !== undefined) {
      for (const os of action.optionStrings) this.optionStrings.set(os, action);
    }
  }

  // -------------------------------------------------------------- 포맷

  /** 옵션 하나의 usage 토큰 (예: `[-m {A,B}]`, `[--labels]`). */
  private optionalPart(a: Action): string {
    if (a.isFlag || a.versionText !== undefined) return `[${a.optionStrings![0]!}]`;
    const argsString = this.metavarString(a, a.dest.toUpperCase());
    return `[${a.optionStrings![0]!} ${argsString}]`;
  }

  /** positional 하나의 usage 토큰 (예: `[input]`, `[extra_inputs ...]`). */
  private positionalPart(a: Action): string {
    if (a.nargs === "opt") return `[${a.dest}]`;
    if (a.nargs === "star") return `[${a.dest} ...]`;
    return a.dest;
  }

  /** help/usage 메타변수 — choices 면 `{...}`, nargs="opt" 면 `[M]`, 아니면 M. */
  private metavarString(a: Action, metavar: string): string {
    if (a.choices !== undefined) return `{${a.choices.join(",")}}`;
    if (a.nargs === "opt") return `[${metavar}]`;
    return metavar;
  }

  /** Python _format_usage → 줄(또는 한 줄) 배열 (prog 포함, 후행 개행 없음). */
  private usageLines(width: number): string[] {
    const prefix = "usage: ";
    const optParts = this.actions.filter((a) => !a.positional).map((a) => this.optionalPart(a));
    const posParts = this.actions.filter((a) => a.positional).map((a) => this.positionalPart(a));

    const usage = [this.prog, ...optParts, ...posParts].join(" ");
    if (prefix.length + usage.length <= width) return [usage];

    const getLines = (parts: string[], indent: string, pre: string | null): string[] => {
      const lines: string[] = [];
      let line: string[] = [];
      const indentLength = indent.length;
      let lineLen = pre !== null ? pre.length - 1 : indentLength - 1;
      for (const part of parts) {
        if (lineLen + 1 + part.length > width && line.length > 0) {
          lines.push(indent + line.join(" "));
          line = [];
          lineLen = indentLength - 1;
        }
        line.push(part);
        lineLen += part.length + 1;
      }
      if (line.length > 0) lines.push(indent + line.join(" "));
      if (pre !== null) lines[0] = lines[0]!.slice(indentLength);
      return lines;
    };

    if (prefix.length + this.prog.length <= 0.75 * width) {
      const indent = " ".repeat(prefix.length + this.prog.length + 1);
      const lines = getLines([this.prog, ...optParts], indent, prefix);
      lines.push(...getLines(posParts, indent, null));
      return lines;
    }
    const indent = " ".repeat(prefix.length);
    const lines = getLines([...optParts, ...posParts], indent, null);
    return [this.prog, ...lines];
  }

  /** help 항목 왼쪽 열 (예: `-m {A,B}, --mode {A,B}`). */
  private invocation(a: Action): string {
    if (a.positional) return a.dest;
    if (a.isFlag || a.versionText !== undefined) return a.optionStrings!.join(", ");
    const argsString = this.metavarString(a, a.dest.toUpperCase());
    return a.optionStrings!.map((os) => `${os} ${argsString}`).join(", ");
  }

  /**
   * Python HelpFormatter._format_action 한 블록.
   * 액션은 항상 섹션(start_section → _indent) 안에서 렌더링되므로
   * current_indent 는 2 — 좌측 마진 2칸, action_width = help_position - 4.
   */
  private formatActionHelp(a: Action, width: number, helpPosition: number): string {
    const helpWidth = Math.max(width - helpPosition, 11);
    const actionWidth = helpPosition - 4;
    const header = this.invocation(a);
    const margin = "  ";
    const parts: string[] = [];
    if (a.help === undefined) {
      parts.push(`${margin}${header}\n`);
      return parts.join("");
    }
    if (header.length <= actionWidth) {
      parts.push(`${margin}${header.padEnd(actionWidth)}  `);
      const lines = pyWrap(collapseWs(a.help), helpWidth);
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i]!;
        parts.push(i === 0 ? `${l}\n` : `${" ".repeat(helpPosition)}${l}\n`);
      }
    } else {
      parts.push(`${margin}${header}\n`);
      const lines = pyWrap(collapseWs(a.help), helpWidth);
      for (const l of lines) parts.push(`${" ".repeat(helpPosition)}${l}\n`);
    }
    return parts.join("");
  }

  /** --help 출력 전체. */
  formatHelp(): string {
    const width = terminalWidth();
    const maxHelpPosition = Math.min(24, Math.max(width - 20, 4));
    // action_max_length: help 가 있는 액션의 (invocation 길이 + indent 2) 최댓값
    let actionMaxLength = 0;
    for (const a of this.actions) {
      if (a.help !== undefined) {
        actionMaxLength = Math.max(actionMaxLength, this.invocation(a).length + 2);
      }
    }
    const helpPosition = Math.min(actionMaxLength + 2, maxHelpPosition);

    const out: string[] = [];
    out.push(`usage: ${this.usageLines(width).join("\n")}\n\n`);
    if (this.description) out.push(`${pyFill(this.description, width, "")}\n\n`);
    const positionals = this.actions.filter((a) => a.positional);
    const optionals = this.actions.filter((a) => !a.positional);
    if (positionals.length > 0) {
      out.push("positional arguments:\n");
      for (const a of positionals) out.push(this.formatActionHelp(a, width, helpPosition));
    }
    if (optionals.length > 0) {
      out.push("\noptions:\n");
      for (const a of optionals) out.push(this.formatActionHelp(a, width, helpPosition));
    }
    return out.join("");
  }

  // -------------------------------------------------------------- 파싱

  /** parser.error(message) — usage + `prog: error: <msg>` 를 stderr 로 ParseExit. */
  errorExit(message: string): never {
    this.error(message);
  }

  private error(message: string): never {
    const width = terminalWidth();
    // 실측(CPython 3.12.14): 오류 시 usage 블록은 한 줄 개행으로 끝나고
    // `prog: error: <msg>` 앞에 빈 줄이 없다.
    throw new ParseExit(
      `usage: ${this.usageLines(width).join("\n")}\n${this.prog}: error: ${message}\n`,
      2,
      "stderr",
    );
  }

  private actionName(a: Action): string {
    if (a.positional) return a.dest;
    return a.optionStrings!.join("/");
  }

  /** _parse_optional — 옵션 후보 해석 (약어/첨부값 포함). */
  private parseOptional(
    arg: string,
  ): Array<[Action | null, string, string | null, string | null]> | null {
    if (arg === "") return null;
    if (!arg.startsWith("-")) return null;
    const exact = this.optionStrings.get(arg);
    if (exact !== undefined) return [[exact, arg, null, null]];
    if (arg.length === 1) return null;
    const eq = arg.indexOf("=");
    if (eq > 0) {
      const os = arg.slice(0, eq);
      const found = this.optionStrings.get(os);
      if (found !== undefined) return [[found, os, "=", arg.slice(eq + 1)]];
    }
    // 약어 / 첨부값 탐색 (_get_option_tuples)
    const tuples: Array<[Action, string, string | null, string | null]> = [];
    const eqPos = eq > 0 ? eq : -1;
    const prefix = eqPos > 0 ? arg.slice(0, eqPos) : arg;
    const sep = eqPos > 0 ? "=" : null;
    const explicit = eqPos > 0 ? arg.slice(eqPos + 1) : null;
    if (arg.startsWith("--")) {
      for (const [os, action] of this.optionStrings) {
        if (os.startsWith(prefix)) tuples.push([action, os, sep, explicit]);
      }
    } else {
      const shortPrefix = arg.slice(0, 2);
      const shortExplicit = arg.slice(2);
      for (const [os, action] of this.optionStrings) {
        if (os === shortPrefix) tuples.push([action, os, "", shortExplicit]);
        else if (os.startsWith(prefix)) tuples.push([action, os, sep, explicit]);
      }
    }
    if (tuples.length > 0) return tuples;
    // 음수는 positional
    if (/^-\d+$|^-\d*\.\d+$/.test(arg)) return null;
    if (arg.includes(" ")) return null;
    return [[null, arg, null, null]];
  }

  /** _match_argument — 옵션 컨텍스트 패턴 (nargs 별). */
  private matchArgument(a: Action, pattern: string): number {
    const re =
      a.isFlag || a.versionText !== undefined ? /([-*-]*)/ : a.nargs === "opt" ? /(A?)/ : /([A])/;
    const m = new RegExp(re.source).exec(pattern);
    if (m === null) {
      const msg = a.nargs === "opt" ? "expected at most one argument" : "expected one argument";
      this.error(`argument ${this.actionName(a)}: ${msg}`);
    }
    return m![1]!.length;
  }

  private convertAndCheck(a: Action, arg: string): unknown {
    let value: unknown = arg;
    if (a.isInt) {
      const n = pyInt(arg);
      if (n === null) {
        this.error(`argument ${this.actionName(a)}: invalid int value: ${pyRepr(arg)}`);
      }
      value = n;
    }
    if (a.choices !== undefined && !a.choices.includes(value as string)) {
      this.error(
        `argument ${this.actionName(a)}: invalid choice: ${pyRepr(String(value))} (choose from ${a.choices.join(", ")})`,
      );
    }
    return value;
  }

  private getValues(a: Action, argStrings: string[]): unknown {
    // OPTIONAL (값 없음) → const (옵션) 또는 default (positional)
    if (argStrings.length === 0 && a.nargs === "opt") {
      const value = a.positional ? (a.def !== undefined ? a.def : null) : a.const;
      return typeof value === "string" ? this.convertAndCheck(a, value) : value;
    }
    // '*' positional (값 없음) → default 또는 []
    if (argStrings.length === 0 && a.nargs === "star" && a.positional) {
      return a.def !== undefined && a.def !== null ? a.def : [];
    }
    if (argStrings.length === 1 && (a.nargs === undefined || a.nargs === "opt")) {
      return this.convertAndCheck(a, argStrings[0]!);
    }
    return argStrings.map((s) => this.convertAndCheck(a, s));
  }

  parseArgs(argv?: string[]): Record<string, unknown> {
    const args = argv ?? process.argv.slice(2);
    const ns: Record<string, unknown> = {};
    for (const a of this.actions) ns[a.dest] = a.def !== undefined ? a.def : null;

    // 패턴 구성: 'O'=옵션, 'A'=인자, '-'='--' 구분자(이후 전부 'A')
    const optionIndices = new Map<
      number,
      Array<[Action | null, string, string | null, string | null]>
    >();
    const pattern: string[] = [];
    {
      let i = 0;
      while (i < args.length) {
        const arg = args[i]!;
        if (arg === "--") {
          pattern.push("-");
          i++;
          while (i < args.length) {
            pattern.push("A");
            i++;
          }
          break;
        }
        const opt = this.parseOptional(arg);
        if (opt === null) {
          pattern.push("A");
        } else {
          optionIndices.set(i, opt);
          pattern.push("O");
        }
        i++;
      }
    }
    const patternStr = pattern.join("");

    const extras: string[] = [];
    let positionals = this.actions.filter((a) => a.positional);

    const takeAction = (a: Action, values: string[], optionString?: string): void => {
      if (a.dest === "help") throw new ParseExit(this.formatHelp(), 0, "stdout");
      if (a.versionText !== undefined) throw new ParseExit(`${a.versionText}\n`, 0, "stdout");
      ns[a.dest] = a.isFlag ? true : this.getValues(a, values);
      void optionString;
    };

    const consumePositionals = (start: number): number => {
      const argCounts = this.matchArgumentsPartial(positionals, patternStr.slice(start));
      let idx = start;
      for (let k = 0; k < argCounts.length; k++) {
        const a = positionals[k]!;
        const count = argCounts[k]!;
        const values = args.slice(idx, idx + count);
        // '--' 제거 (선택 구간 패턴에 '-' 가 있을 때)
        if (patternStr.slice(idx, idx + count).includes("-")) {
          const at = values.indexOf("--");
          if (at >= 0) values.splice(at, 1);
        }
        idx += count;
        takeAction(a, values);
      }
      positionals = positionals.slice(argCounts.length);
      return idx;
    };

    const consumeOptional = (start: number): number => {
      const tuples = optionIndices.get(start)!;
      if (tuples.length > 1) {
        const matches = tuples.map(([, os]) => os).join(", ");
        this.error(`ambiguous option: ${args[start]} could match ${matches}`);
      }
      const [action0, optionString, sep, explicitArg] = tuples[0]!;
      if (action0 === null) {
        extras.push(args[start]!);
        return start + 1;
      }
      let action = action0;
      let os = optionString;
      let sep2 = sep;
      let explicit = explicitArg;
      for (;;) {
        if (explicit !== null) {
          const argCount = this.matchArgument(action, "A");
          if (argCount === 0 && os[1] !== undefined && os[1] !== "-" && explicit !== "") {
            if (sep2 !== null || explicit.startsWith("-")) {
              this.error(
                `argument ${this.actionName(action)}: ignored explicit argument ${pyRepr(explicit)}`,
              );
            }
            // 단일 대시 플래그 결합 (예: -hx → -h -x)
            takeAction(action, [], os);
            const next = `${os[0]}${explicit[0]}`;
            const nextAction = this.optionStrings.get(next);
            if (nextAction !== undefined) {
              action = nextAction;
              os = next;
              explicit = explicit.slice(1);
              if (explicit === "") sep2 = null;
              else if (explicit.startsWith("=")) {
                sep2 = "=";
                explicit = explicit.slice(1);
              } else sep2 = "";
              continue;
            }
            extras.push(`${os[0]}${explicit}`);
            return start + 1;
          }
          if (argCount === 1) {
            takeAction(action, [explicit], os);
            return start + 1;
          }
          this.error(
            `argument ${this.actionName(action)}: ignored explicit argument ${pyRepr(explicit)}`,
          );
        }
        const begin = start + 1;
        const argCount = this.matchArgument(action, patternStr.slice(begin));
        const stop = begin + argCount;
        takeAction(action, args.slice(begin, stop), os);
        return stop;
      }
    };

    const optionIndexList = [...optionIndices.keys()];
    const maxOptionIndex = optionIndexList.length > 0 ? Math.max(...optionIndexList) : -1;
    let start = 0;
    while (start <= maxOptionIndex) {
      const nextOption = Math.min(...optionIndexList.filter((i) => i >= start));
      if (start !== nextOption) {
        start = consumePositionals(start);
      }
      if (!optionIndices.has(start)) {
        for (let i = start; i < nextOption; i++) extras.push(args[i]!);
        start = nextOption;
      }
      start = consumeOptional(start);
    }
    const stop = consumePositionals(start);
    for (let i = stop; i < args.length; i++) extras.push(args[i]!);

    if (extras.length > 0) {
      this.error(`unrecognized arguments: ${extras.join(" ")}`);
    }
    return ns;
  }

  /** _match_arguments_partial — 남은 positional 들에 대한 탐욕 매칭. */
  private matchArgumentsPartial(actions: Action[], pattern: string): number[] {
    const nargsPattern = (a: Action): string => {
      const isOption = !a.positional;
      if (a.isFlag || a.versionText !== undefined) return isOption ? "([-*-]*)" : "(-*-*)";
      if (a.nargs === undefined) return isOption ? "([A])" : "(-*A-*)";
      if (a.nargs === "opt") return isOption ? "(A?)" : "(-*A?-*)";
      return isOption ? "(A*)" : "(-*[A-]*)"; // star
    };
    for (let i = actions.length; i > 0; i--) {
      const slice = actions.slice(0, i);
      const pat = slice.map((a) => nargsPattern(a)).join("");
      const m = new RegExp(pat).exec(pattern);
      if (m !== null && m.index === 0) {
        const result = m.slice(1).map((g) => (g ?? "").length);
        if (m[0]!.length < pattern.length && pattern[m[0]!.length] === "O") {
          while (result.length > 0 && result[result.length - 1] === 0) result.pop();
        }
        return result;
      }
    }
    return [];
  }
}
