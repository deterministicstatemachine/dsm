#!/bin/bash
# Deterministic vector flake guard (CI opt-in)
# Runs vector suites repeatedly under concurrency to surface shared-state issues.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOOPS="${DSM_VECTOR_FLAKE_LOOPS:-100}"
THREADS="${DSM_VECTOR_FLAKE_THREADS:-16}"

TESTS=(
  "cargo test -p dsm --test vector_tests -- --test-threads=${THREADS}"
  "cargo test -p dsm_sdk --test vector_tests -- --test-threads=${THREADS}"
  "cargo test -p dsm_sdk --test external_commit_v2_vectors -- --test-threads=${THREADS}"
)

printf "🔁 Vector flake guard: loops=%s threads=%s\n" "$LOOPS" "$THREADS"

for i in $(seq 1 "$LOOPS"); do
  printf "\n== Loop %s/%s ==\n" "$i" "$LOOPS"
  for cmd in "${TESTS[@]}"; do
    echo "→ $cmd"
    eval "$cmd"
  done
done

printf "\n✅ Vector flake guard complete (%s loops).\n" "$LOOPS"
