#!/usr/bin/env bash
set -euo pipefail

# CI gate: every production path that reads this device's admitted economic
# predecessor is either FENCED or explicitly classified as not creating a
# descendant.
#
# WHY THIS IS STATIC AND NOT A TEST. `descendant_fence` cannot fire today:
# `record_admitted_with_conn` writes `claim_kind = 0` unconditionally because
# F ingress is dark, so `predecessor_claim()` only ever answers `SingleRoot`.
# Deleting both production fence calls turns NO test red — verified by
# mutation. A descendant path added without the fence would therefore be
# invisible now and become a live hole the day E2/E3 starts writing conditional
# rows. Only a static check can hold that line in the meantime.
#
# THE CLASSIFICATION IS THE POINT. A reader lands in exactly one bucket, and a
# new reader lands in neither until someone rules on it.

echo "=== admitted predecessor: every descendant-producing reader is fenced ==="

core=dsm_client/deterministic_state_machine
fence='descendant_fence'
reader='rehydrate_from_admitted_store'

# Readers that create the next economic position. Each MUST cross the fence.
FENCED_READERS=(
  "$core/dsm_sdk/src/sdk/core_sdk.rs"
  "$core/dsm_sdk/src/sdk/sofi_advance.rs"
)

# Readers that legitimately do NOT create a descendant, with the reason each
# is exempt. Adding to this list is a deliberate act, not a default.
declare -a EXEMPT=(
  "$core/dsm_sdk/src/sdk/economic_admission_flow.rs|sources the predecessor root rather than checking a supplied one; also names a (position, root) pair for a foreign verifier, and re-derives nothing"
  "$core/dsm/src/economic/peer_lineage.rs|builds a SingleRoot from this verifier's own settled memo, never from the admitted store"
  "$core/dsm/src/economic/lineage.rs|DEFINES the reader; the only production mention is its own doc"
  "$core/dsm_sdk/src/sdk/sofi_reads.rs|answers the verifier's read of the claim this lineage accepted at a setup's position (SoFi Amendment S9, SetupValid evidence); it creates no position, and an unresolved position yields no claim because the rehydration refuses it"
)

[[ -d "$core" ]] || { echo "[FAIL] $core not found"; exit 1; }

# 1. The fence still exists and still decides the two conditional cases.
echo "[1/4] the fence exists and decides both conditional cases..."
fdef="$core/dsm/src/sofi/lineage.rs"
# PRODUCTION lines only. The tests mention every arm several times, so grepping
# the whole file would stay green with the real match arm deleted.
prod=$(python3 ci/production_text.py "$fdef")
for arm in ConditionalUnresolved ConditionalResolved; do
  if ! grep -c "PredecessorClaim::$arm" <<<"$prod" >/dev/null 2>&1; then
    echo "[FAIL] $fdef no longer decides PredecessorClaim::$arm"
    echo "       E2/E3 needs both arms intact when it starts writing"
    echo "       conditional admitted rows."
    exit 1
  fi
done
echo "  ✓ unresolved refuses, resolved requires the selected root"

# 2. There is still no terminal arm. A terminal resolution selects no root and
#    is never admitted, so a terminal predecessor cannot exist to be refused.
echo "[2/4] no terminal arm crept back in..."
# Comments discuss the absent arm on purpose; only CODE reintroducing it fails.
terminal_hits=$(grep -vE '^\s*(//|///|\*)' "$fdef" | grep -cE 'ConditionalTerminal|PredecessorIsTerminal' || true)
if [[ "${terminal_hits:-0}" -gt 0 ]]; then
  echo "[FAIL] a terminal arm is back in $fdef. A resolution ending Invalid"
  echo "       selects no root, so it is never admitted and no"
  echo "       PredecessorClaim describes it. Persist terminal outcomes in the"
  echo "       resolution domain, not the admitted economic lineage."
  exit 1
fi
echo "  ✓ terminal is not a predecessor state"

# 3. Every declared fenced reader actually fences, near each read.
echo "[3/4] descendant-producing readers cross the fence..."
for f in "${FENCED_READERS[@]}"; do
  [[ -f "$f" ]] || { echo "[FAIL] declared fenced reader $f does not exist"; exit 1; }
  reads=$(grep -n "$reader" "$f" | cut -d: -f1 || true)
  [[ -n "$reads" ]] || { echo "[FAIL] $f no longer reads the admitted predecessor"; exit 1; }
  for n in $reads; do
    window=$(sed -n "$((n > 45 ? n - 45 : 1)),${n}p" "$f")
    if ! grep -q "$fence" <<<"$window"; then
      echo "[FAIL] $f:$n reads the admitted predecessor and creates a"
      echo "       descendant without crossing $fence."
      exit 1
    fi
  done
  echo "  ✓ $(basename "$f") ($(wc -w <<<"$reads" | tr -d ' ') read(s))"
done

# 4. No UNCLASSIFIED production reader exists. This is the check that catches
#    a new path: it is in neither list, so it fails until someone rules.
#
#    "Production" means OUTSIDE the file's own `#[cfg(test)]` items
#    (ci/production_text.py). Several files read the predecessor only to
#    build fixtures, and a name-based allow-list for those would rot silently
#    the first time one of them grew a real caller — so the module boundary is
#    detected, not assumed.
echo "[4/4] no unclassified production reader..."
declared=$(printf '%s\n' "${FENCED_READERS[@]}"; printf '%s\n' "${EXEMPT[@]%%|*}")
unknown=$(python3 - "$core" "$reader" <<'PYEOF'
import importlib.util, pathlib, sys
core, reader = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("production_text", "ci/production_text.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for f in sorted(pathlib.Path(core).glob('*/src/**/*.rs')):
    # Whole-file fixtures: `*_tests.rs` and test_support modules.
    if f.name.endswith('_tests.rs') or 'test_support' in f.parts:
        continue
    try:
        prod = mod.production_text(str(f))
    except OSError:
        continue
    if reader in prod:
        print(f)
PYEOF
)
missing=""
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  grep -qxF "$f" <<<"$declared" || missing="$missing$f"$'\n'
done <<<"$unknown"
if [[ -n "${missing// /}" ]]; then
  echo "[FAIL] these files read the admitted predecessor in PRODUCTION code and"
  echo "       are in neither list:"
  echo "$missing"
  echo "       Rule on each: does it create the next economic position? If so"
  echo "       it must cross $fence and join FENCED_READERS. If not, add it to"
  echo "       EXEMPT with the reason. Defaulting to 'probably fine' is how a"
  echo "       fence that cannot fire yet gets quietly bypassed."
  exit 1
fi
echo "  ✓ every production reader is classified ($(grep -c . <<<"$unknown") total)"

echo "✓ the descendant fence cannot be bypassed before E2/E3 makes it live"
