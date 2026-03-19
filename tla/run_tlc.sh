#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLA_DIR="$ROOT_DIR/tla"
JAR="$TLA_DIR/tla2tools.jar"

if [[ ! -f "$JAR" ]]; then
  echo "Missing $JAR"
  echo "Download it (example):"
  echo "  curl -L --fail -o tla/tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
  exit 1
fi

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <spec.tla> <config.cfg> [extra tlc args...]"
  echo "Example: $0 tla/DSM.tla tla/DSM_small.cfg -coverage 1"
  exit 2
fi

resolve_path() {
  local input="$1"
  if [[ ! -f "$input" ]]; then
    echo "File not found: $input" >&2
    exit 3
  fi

  local dir
  dir="$(cd "$(dirname "$input")" && pwd)"
  echo "$dir/$(basename "$input")"
}

SPEC_PATH="$(resolve_path "$1")"
CFG_PATH="$(resolve_path "$2")"
shift 2

# Put TLC working dir under tla/states/run_<sequence> without wall-clock time.
RUN_SEQ="$(ls -1 "$TLA_DIR/states" 2>/dev/null | wc -l | tr -d ' ')"
RUN_ID="run_${RUN_SEQ}"
WORKDIR="$TLA_DIR/states/$RUN_ID"
mkdir -p "$WORKDIR"

# TLC uses the current working directory to resolve relative module paths.
cd "$TLA_DIR"

echo "== TLC run =="
echo "spec:   $SPEC_PATH"
echo "config: $CFG_PATH"
echo "workdir:$WORKDIR"

# -workers auto uses all cores; keep deterministic scheduling *out* of TLC itself.
java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
  -workers auto \
  -checkpoint 0 \
  -metadir "$WORKDIR" \
  -config "$CFG_PATH" \
  "$SPEC_PATH" \
  "$@"
