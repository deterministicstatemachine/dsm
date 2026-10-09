#!/usr/bin/env bash
set -euo pipefail

# CI gate: a peer transition's LINEAGE is authoritative, and only an ordinary
# single-root lineage can cross into an eligible peer debit (P15-9).
#
# The discriminant is worthless if a caller can attach it themselves. Rust
# gives an enum's variant fields the visibility of the enum, so
# `ValidatedPeerTransition`'s arms wrap one opaque payload instead of carrying
# named fields — a change that alters NO runtime behaviour and therefore cannot
# be caught by any runtime test. Neither can a second walk-constructor, a
# production reference to a test-only constructor, or a consumer path that
# reimplements the sender conjuncts instead of sharing them.
#
# Six source checks.

echo "=== peer debit: lineage is authoritative, not asserted ==="

core=dsm_client/deterministic_state_machine
prov="$core/dsm/src/economic/provenance.rs"
walk="$core/dsm/src/economic/peer_lineage.rs"

[[ -f "$prov" ]] || { echo "[FAIL] $prov not found"; exit 1; }
[[ -f "$walk" ]] || { echo "[FAIL] $walk not found"; exit 1; }

# 1. The payload carrying the provenance has no public field. A public field
#    would let a caller build a payload and wrap it in whichever arm they like.
echo "[1/6] PeerTransitionFacts has no public field..."
body=$(awk '/^pub struct PeerTransitionFacts \{/{f=1} f{print} f&&/^\}/{exit}' "$prov")
[[ -n "$body" ]] || { echo "[FAIL] 'pub struct PeerTransitionFacts' not found in $prov"; exit 1; }
if grep -qE '^\s+pub(\(| )' <<<"$body"; then
  echo "[FAIL] PeerTransitionFacts has a public field — a caller could then"
  echo "       assemble a payload and label it with any lineage:"
  grep -nE '^\s+pub(\(| )' <<<"$body"
  exit 1
fi
echo "  ✓ the payload cannot be assembled outside its module"

# 2. Nothing constructs the SoFi arm. The walk refuses every conditional
#    claim, so no path produces a SoFi-kind transition; the refusal in
#    prevalidate_sender_debit is in place for when one does. A construction
#    site appearing here is that change, and it must bring the refusal's
#    test (one that performs the forbidden debit) with it.
echo "[2/6] nothing constructs ResolvedSofi..."
sofi_ctors=$(grep -n 'Self::ResolvedSofi(PeerTransitionFacts {' "$prov" || true)
if [[ -n "$sofi_ctors" ]]; then
  echo "[FAIL] ResolvedSofi is constructed:"
  echo "$sofi_ctors"
  echo "       A SoFi-kind transition now exists; P15-9's refusal must be"
  echo "       exercised by a test that attempts the debit, and this gate updated."
  exit 1
fi
echo "  ✓ no construction site"

# 3. No constructor assembles a transition outside the walk. dsm has no
#    `testing` feature, so no gate can put one in any artifact.
echo "[3/6] no test-only constructor, and no testing feature..."
if grep -nE 'fn [a-z_]+_for_test\(' "$prov"; then
  echo "[FAIL] a test-only constructor is declared in $prov — it would assert"
  echo "       a lineage instead of establishing one."
  exit 1
fi
if grep -nE '^testing *=' "$core/dsm/Cargo.toml"; then
  echo "[FAIL] dsm declares a testing feature again."
  exit 1
fi
echo "  ✓ only the walk assembles a peer transition"

# 4. The walk's constructor has exactly one caller, and it is the walk. A
#    second caller would be asserting a lineage instead of establishing one.
echo "[4/6] single_root_from_walk has one caller, inside the walk..."
callers=$(grep -rn 'single_root_from_walk(' --include='*.rs' "$core" \
  | grep -v "fn single_root_from_walk" \
  | grep -v "Self::single_root_from_walk" || true)
count=$( [[ -z "$callers" ]] && echo 0 || grep -c . <<<"$callers" )
if [[ "$count" -ne 1 ]] || ! grep -q 'economic/peer_lineage.rs' <<<"$callers"; then
  echo "[FAIL] expected exactly one caller in economic/peer_lineage.rs, found $count:"
  echo "${callers:-  (none)}"
  echo "       Only the walk has proven that every position it traversed"
  echo "       decoded as a single-root claim."
  exit 1
fi
echo "  ✓ only the walk labels a lineage single-root"

# 5. The refusal exists, and both consumer paths still share the one seam.
#    A path that reimplemented the sender conjuncts would inherit no refusal.
echo "[5/6] the refusal is at the shared seam, and both paths use it..."
grep -q 'ProvenanceError::SofiLineageNotEligible' "$prov" || {
  echo "[FAIL] prevalidate_sender_debit no longer refuses a SoFi lineage (P15-9)"; exit 1; }
seam_callers=$(grep -rln 'prevalidate_sender_debit(' --include='*.rs' "$core"/*/src | sort || true)
expected="$core/dsm/src/economic/provenance.rs
$core/dsm_sdk/src/sdk/economic_admission_flow.rs"
if [[ "$seam_callers" != "$expected" ]]; then
  echo "[FAIL] the set of files calling prevalidate_sender_debit changed."
  echo "       expected (the verifier's credit arm and the recipient's"
  echo "       pre-accept prevalidation, correction 8's split):"
  echo "$expected"
  echo "       found:"
  echo "$seam_callers"
  echo "       A new consumer is fine — but it must funnel through this seam,"
  echo "       and this list must be updated deliberately."
  exit 1
fi
echo "  ✓ one seam, both consumer paths"

# 6. No source anywhere in dsm or dsm_sdk gates code on a `testing` feature:
#    a helper behind one is a real method on the type, shipped to whoever
#    enables it.
echo "[6/6] nothing is gated on a testing feature..."
gated=$(grep -rn 'feature = "testing"' "$core/dsm/src" "$core/dsm_sdk/src" || true)
if [[ -n "$gated" ]]; then
  echo "[FAIL] code gated on a testing feature:"
  echo "$gated"
  exit 1
fi
echo "  ✓ none"

echo "✓ only an ordinary single-root lineage can become an eligible peer debit"
