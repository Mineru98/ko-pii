#!/usr/bin/env bash
# eval/blueteam.py 와 eval/blueteam.ts 실행 환경을 맞추고, 출력이 같은지 대조한다.
# usage: eval/script.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PATH="/opt/homebrew/opt/python@3.12/libexec/bin:/opt/homebrew/bin:/usr/local/opt/python@3.12/libexec/bin:/usr/local/bin:$PATH"
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8

fail() { printf '%s\n' "$*" >&2; exit 2; }

find_python() {
  local c
  for c in python3 python python3.13 python3.12 python3.11 python3.10; do
    command -v "$c" >/dev/null 2>&1 || continue
    if "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  return 1
}

find_node() {
  command -v node >/dev/null 2>&1 || return 1
  local ver major
  ver=$(node -v 2>/dev/null) || return 1
  ver=${ver#v}
  major=${ver%%.*}
  case "$major" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$major" -ge 20 ] || return 1
  command -v node
}

ensure_python() {
  if py=$(find_python); then
    PYTHON=$py
    return 0
  fi
  command -v brew >/dev/null 2>&1 || fail "python >= 3.10 이 필요합니다. python3 를 설치한 뒤 다시 실행하세요."
  printf '[install] brew install python@3.12\n'
  brew install python@3.12
  PATH="/opt/homebrew/opt/python@3.12/libexec/bin:/opt/homebrew/bin:/usr/local/opt/python@3.12/libexec/bin:/usr/local/bin:$PATH"
  hash -r
  py=$(find_python) || fail "python >= 3.10 설치 후에도 찾지 못했습니다."
  PYTHON=$py
}

ensure_node() {
  if nd=$(find_node); then
    NODE=$nd
    return 0
  fi
  command -v brew >/dev/null 2>&1 || fail "node >= 20 이 필요합니다. Node.js 를 설치한 뒤 다시 실행하세요."
  printf '[install] brew install node\n'
  brew install node
  PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
  hash -r
  nd=$(find_node) || fail "node >= 20 설치 후에도 찾지 못했습니다."
  NODE=$nd
}

ensure_tsx() {
  TSX_CLI="$ROOT/src/ts/node_modules/tsx/dist/cli.mjs"
  if [ -f "$TSX_CLI" ]; then
    return 0
  fi
  command -v npm >/dev/null 2>&1 || fail "npm 이 없습니다. Node.js 설치를 확인하세요."
  printf '[install] npm --prefix src/ts install\n'
  npm --prefix "$ROOT/src/ts" install --no-fund --no-audit
  [ -f "$TSX_CLI" ] || fail "tsx 설치 실패: $TSX_CLI 가 없습니다."
}

ensure_python
ensure_node
ensure_tsx

py_ver=$("$PYTHON" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
node_ver=$("$NODE" -v)
printf '== 환경 ==\n'
printf 'python  %s  (%s)\n' "$py_ver" "$PYTHON"
printf 'node    %s  (%s)\n' "$node_ver" "$NODE"
printf 'tsx     %s\n' "$TSX_CLI"

if ! "$PYTHON" -c "import sys; sys.path.insert(0, r'''$ROOT/src/python'''); from ko_pii import detect_all" >/dev/null 2>&1; then
  fail "ko_pii 를 import 할 수 없습니다. src/python 트리를 확인하세요."
fi
printf 'ko_pii  %s/src/python\n' "$ROOT"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
py_out=$tmpdir/python.txt
ts_out=$tmpdir/ts.txt
py_norm=$tmpdir/python.norm
ts_norm=$tmpdir/ts.norm

printf '\n== 실행 ==\n'
printf 'python  eval/blueteam.py\n'
"$PYTHON" "$ROOT/eval/blueteam.py" >"$py_out"
printf 'tsx     eval/blueteam.ts\n'
"$NODE" "$TSX_CLI" "$ROOT/eval/blueteam.ts" >"$ts_out"

tr -d '\r' <"$py_out" >"$py_norm"
tr -d '\r' <"$ts_out" >"$ts_norm"

printf '\n== 결과 ==\n'
if cmp -s "$py_norm" "$ts_norm"; then
  printf 'IDENTICAL\n\n'
  cat "$py_norm"
  exit 0
fi

printf 'MISMATCH\n\n'
diff -u -L python -L typescript "$py_norm" "$ts_norm" || true
exit 1
