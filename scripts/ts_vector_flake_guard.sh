#!/bin/bash
# Deterministic TS vector flake guard (CI opt-in)
# Runs TS vector suites repeatedly under concurrency to surface shared-state issues.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOOPS="${DSM_TS_VECTOR_FLAKE_LOOPS:-100}"
THREADS="${DSM_TS_VECTOR_FLAKE_THREADS:-8}"

TESTS=(
  "dsm_client/new_frontend/src/dsm/__tests__/externalCommitV2Vectors.test.ts"
  "dsm_client/new_frontend/src/dsm/__tests__/vectorsV1Assets.test.ts"
)

printf "🔁 TS vector flake guard: loops=%s threads=%s\n" "$LOOPS" "$THREADS"

for i in $(seq 1 "$LOOPS"); do
  printf "\n== Loop %s/%s ==\n" "$i" "$LOOPS"
  pnpm -w --filter dsm-wallet run test -- --runTestsByPath "${TESTS[@]}" --maxWorkers="${THREADS}"
done

printf "\n✅ TS vector flake guard complete (%s loops).\n" "$LOOPS"
