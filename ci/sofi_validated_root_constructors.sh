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

# 3. `RegisteredEconomicRoot` has no public field either, and exactly one
#    constructor — one that takes a VERIFIED claim.
#
#    Public fields made the claim union's refusal worthless: a caller could
#    read `realize_root` off a conditional `C_q`, assemble the struct by hand,
#    and hand the result to `advance_validated`. The union refuses to flatten;
#    this is what stops a caller doing the flattening itself.
register="$core/dsm/src/economic/register.rs"
[[ -f "$register" ]] || {
  echo "[FAIL] the register module is not where this gate expects it"
  exit 1
}
body=$(awk '/^pub struct RegisteredEconomicRoot \{/{f=1} f{print} f&&/^\}/{exit}' "$register")
if grep -qE '^\s+pub(\(| )' <<<"$body"; then
  echo "[FAIL] RegisteredEconomicRoot has a public field — a caller could flatten a"
  echo "       conditional claim into one by hand:"
  grep -nE '^\s+pub(\(| )' <<<"$body"
  exit 1
fi
echo "  ✓ registered-root fields are private"

if ! grep -q 'pub fn from_verified_single_root' "$register"; then
  echo "[FAIL] from_verified_single_root is missing: the one constructor must take a"
  echo "       VerifiedEconomicRootClaim, not loose fields"
  exit 1
fi
# Any other `-> Self` in that impl would be a second way in.
ctors=$(awk '/^impl RegisteredEconomicRoot \{/{f=1} f&&/-> Self/{print} f&&/^\}/{exit}' "$register" | wc -l | tr -d ' ')
if [[ "$ctors" -ne 1 ]]; then
  echo "[FAIL] RegisteredEconomicRoot has $ctors constructors; exactly one projects a verified claim"
  exit 1
fi
echo "  ✓ one constructor, from a verified single-root claim"

echo "✓ a validated root is still verifier-derived, and a registered one is a projection"
