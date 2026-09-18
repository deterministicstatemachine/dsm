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
# Five source checks and one artifact check. The artifact check is the
# load-bearing one, because it asks the compiler rather than the text.

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

# 2. The SoFi arm is constructed in exactly ONE place, and that place is
#    test-gated. This is what makes "no production path produces a SoFi-kind
#    transition" a fact about the build rather than a claim in a comment.
echo "[2/6] ResolvedSofi is constructed once, under the testing feature..."
sofi_ctors=$(grep -n 'Self::ResolvedSofi(PeerTransitionFacts {' "$prov" || true)
n=$(grep -c . <<<"${sofi_ctors:-}" || true)
[[ -n "$sofi_ctors" ]] || { echo "[FAIL] nothing constructs ResolvedSofi; this gate has lost its subject"; exit 1; }
if [[ "$n" -ne 1 ]]; then
  echo "[FAIL] ResolvedSofi is constructed in $n places; exactly one is allowed"
  echo "$sofi_ctors"
  exit 1
fi
echo "  ✓ one construction site"

# 3. Both test-only constructors carry the testing gate. `testing` is enabled
#    only through a dev-dependency in dsm and dsm_sdk, so it never reaches a
#    production artifact (check 6 proves that rather than trusting it).
echo "[3/6] the test-only constructors are feature-gated..."
for ctor in single_root_for_test resolved_sofi_for_test; do
  grep -q "fn $ctor" "$prov" || { echo "[FAIL] $ctor is not declared in $prov"; exit 1; }
  while IFS=: read -r line _; do
    window=$(sed -n "$((line > 4 ? line - 4 : 1)),$((line - 1))p" "$prov")
    if ! grep -q 'cfg(feature = "testing")' <<<"$window"; then
      echo "[FAIL] $prov:$line declares $ctor without #[cfg(feature = \"testing\")]"
      echo "       above it. A fixture constructor compiled into production"
      echo "       would let any caller forge a lineage."
      exit 1
    fi
  done < <(grep -n "fn $ctor" "$prov")
  echo "  ✓ $ctor"
done

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

# 6. No production artifact contains either fixture constructor. A default
#    `cargo build` resolves no dev-dependencies, so `testing` is off and the
#    public items' names are absent from the rlib's metadata.
echo "[6/6] the default-feature rlib contains neither fixture constructor..."
command -v cargo &>/dev/null || { echo "[FAIL] cargo unavailable; cannot prove the artifact"; exit 1; }
rlibs=$(cd "$core" && cargo build -p dsm --message-format=json 2>/dev/null |
  python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("target", {}).get("name") == "dsm":
        for f in m.get("filenames", []):
            if f.endswith(".rlib"):
                print(f)
')
[[ -n "$rlibs" ]] || { echo "[FAIL] no dsm rlib reported by cargo; cannot prove the artifact"; exit 1; }
for rlib in $rlibs; do
  for ctor in single_root_for_test resolved_sofi_for_test; do
    if grep -aq "$ctor" "$rlib"; then
      echo "[FAIL] $ctor is present in a default-feature artifact: $rlib"
      echo "       production can forge a peer-transition lineage"
      exit 1
    fi
  done
done
echo "  ✓ absent from $(wc -w <<<"$rlibs" | tr -d ' ') default-feature artifact(s)"

echo "✓ only an ordinary single-root lineage can become an eligible peer debit"
