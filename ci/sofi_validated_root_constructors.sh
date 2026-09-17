#!/usr/bin/env bash
set -euo pipefail

# CI gate: `ValidatedEconomicRoot` has no constructor a caller can reach by
# accident.
#
# The type's whole value is that a root is VERIFIER-DERIVED: no network event
# declares one and no peer can send one. Two punctures exist deliberately —
# `rehydrate_from_admitted_store`, for this device resuming its own admitted
# coordinate, and `from_resolved_sofi_position`, for the SoFi conjunction in
# `sofi::lineage::advance_resolved`. Each is a place where the conjunction that
# earns a validated root is stated; a second caller would be a second,
# unreviewed definition of "validated", which is exactly the fabrication the
# private fields exist to prevent.

echo "=== ValidatedEconomicRoot: constructors stay where their proofs are ==="

core=dsm_client/deterministic_state_machine
lineage="$core/dsm/src/economic/lineage.rs"
sofi_lineage="$core/dsm/src/sofi/lineage.rs"

[[ -f "$lineage" && -f "$sofi_lineage" ]] || {
  echo "[FAIL] the lineage modules are not where this gate expects them"
  exit 1
}

# 1. The struct's fields stay private: a literal would bypass every check.
body=$(awk '/^pub struct ValidatedEconomicRoot \{/{f=1} f{print} f&&/^\}/{exit}' "$lineage")
if grep -qE '^\s+pub(\(| )' <<<"$body"; then
  echo "[FAIL] ValidatedEconomicRoot has a public field — a caller could build one directly:"
  grep -nE '^\s+pub(\(| )' <<<"$body"
  exit 1
fi
echo "  ✓ fields are private"

# 2. The SoFi puncture is crate-private and called from exactly one place.
if ! grep -q 'pub(crate) fn from_resolved_sofi_position' "$lineage"; then
  echo "[FAIL] from_resolved_sofi_position is not pub(crate) in $lineage"
  exit 1
fi
callers=$(grep -rln 'from_resolved_sofi_position' "$core/dsm/src" | grep -v "economic/lineage.rs" || true)
if [[ "$callers" != "$sofi_lineage" ]]; then
  echo "[FAIL] from_resolved_sofi_position must be called only from $sofi_lineage"
  echo "       callers found: ${callers:-none}"
  exit 1
fi
count=$(grep -c 'from_resolved_sofi_position' "$sofi_lineage")
if [[ "$count" -ne 1 ]]; then
  echo "[FAIL] $sofi_lineage references the constructor $count times; exactly one call earns it"
  exit 1
fi
echo "  ✓ one caller, inside advance_resolved"

echo "✓ a validated root is still verifier-derived"
