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

# 4. The FIRST arrow: `VerifiedEconomicRootClaim` is itself unforgeable.
#
#    Gate 3 makes a registered root a projection of a verified claim, and
#    `from_verified_single_root` re-runs no signature check — the argument's
#    existence IS the verification. That is worth nothing if the argument can
#    be written as a struct literal, which is how the hole moved up one type
#    the first time. The chain this gate protects is both arrows:
#
#        raw envelope -> opaque VerifiedEconomicRootClaim -> opaque RegisteredEconomicRoot
#
envelope="$core/dsm/src/economic/claim_envelope.rs"
[[ -f "$envelope" ]] || {
  echo "[FAIL] the claim-envelope module is not where this gate expects it"
  exit 1
}
body=$(awk '/^pub struct VerifiedEconomicRootClaim \{/{f=1} f{print} f&&/^\}/{exit}' "$envelope")
if grep -qE '^\s+pub(\(| )' <<<"$body"; then
  echo "[FAIL] VerifiedEconomicRootClaim has a public field — the 'already verified'"
  echo "       capability could be fabricated from arbitrary bytes:"
  grep -nE '^\s+pub(\(| )' <<<"$body"
  exit 1
fi
echo "  ✓ verified-claim fields are private"

# Exactly one place constructs it, and it is the decode-and-verify path.
literals=$(grep -E 'VerifiedEconomicRootClaim \{' "$envelope" \
  | grep -vE '^(pub struct|impl) ' | wc -l | tr -d ' ')
if [[ "$literals" -ne 1 ]]; then
  echo "[FAIL] expected exactly ONE struct literal of VerifiedEconomicRootClaim in"
  echo "       $envelope; found $literals"
  exit 1
fi
others=$(grep -rln 'VerifiedEconomicRootClaim {' "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src 2>/dev/null | grep -v "economic/claim_envelope.rs" || true)
if [[ -n "$others" ]]; then
  echo "[FAIL] VerifiedEconomicRootClaim is constructed outside its own module:"
  echo "$others"
  exit 1
fi
if ! awk '/fn decode_and_verify_economic_root_claim/{f=1} f&&/Ok\(VerifiedEconomicRootClaim \{/{found=1} f&&/^\}/{exit} END{exit !found}' "$envelope"; then
  echo "[FAIL] the one constructor is not inside decode_and_verify_economic_root_claim"
  exit 1
fi
echo "  ✓ one construction path, inside decode-and-verify"

echo "✓ raw envelope -> verified claim -> registered root: every arrow is opaque"
