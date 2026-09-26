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
# private fields exist to prevent. The peer lineage walker's memo start,
# `from_verifier_memo`, is a third, for a coordinate this verifier validated.

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
for ty in ValidatedEconomicRoot AcceptedClaim; do
  count=$(grep -c "${ty}::from_resolved_sofi_position" "$sofi_lineage")
  if [[ "$count" -ne 1 ]]; then
    echo "[FAIL] $sofi_lineage calls ${ty}::from_resolved_sofi_position $count times; exactly one call earns it"
    exit 1
  fi
done
count=$(grep -c 'from_resolved_sofi_position' "$sofi_lineage")
if [[ "$count" -ne 2 ]]; then
  echo "[FAIL] $sofi_lineage references the SoFi constructors $count times; one per type earns them"
  exit 1
fi
echo "  ✓ one caller per type, inside advance_resolved"

# 2a. The peer-memo puncture is crate-private and called from exactly one
#     place: the peer lineage walker, as the start of a walk.
peer_lineage="$core/dsm/src/economic/peer_lineage.rs"
if ! grep -q 'pub(crate) fn from_verifier_memo' "$lineage"; then
  echo "[FAIL] from_verifier_memo is not pub(crate) in $lineage"
  exit 1
fi
callers=$(grep -rln 'from_verifier_memo' "$core/dsm/src" | grep -v "economic/lineage.rs" || true)
if [[ "$callers" != "$peer_lineage" ]]; then
  echo "[FAIL] from_verifier_memo must be called only from $peer_lineage"
  echo "       callers found: ${callers:-none}"
  exit 1
fi
count=$(grep -c 'from_verifier_memo' "$peer_lineage")
if [[ "$count" -ne 1 ]]; then
  echo "[FAIL] $peer_lineage calls from_verifier_memo $count times; the walk's start is one call"
  exit 1
fi
echo "  ✓ one caller of the memo start, inside the peer walk"

# 2c. The resume puncture, `rehydrate_from_admitted_store`, is public — this
#     device resuming its OWN admitted coordinate needs it from the SDK — so
#     its callers are enumerated rather than counted. Each is a place that
#     rebuilds the local device's own coordinate from its own admitted store;
#     a new caller fails here until it is ruled to be one too. (A caller that
#     labels the local claim as another trader's is not one; see
#     CONFORMANCE_GAPS §6.22.)
echo "[2c] rehydrate_from_admitted_store is called only where this device resumes itself..."
known_rehydrate_callers=(
  "$core/dsm/src/sofi/lineage.rs"                       # advance_resolved: the resolved predecessor, own device
  "$core/dsm/src/economic/lineage.rs"                   # its own definition and the store-backed rehydration tests
  "$core/dsm_sdk/src/sdk/core_sdk.rs"                   # the head's validated root from the admitted store
  "$core/dsm_sdk/src/sdk/economic_admission_flow.rs"    # the validated predecessor of a pending admission
  "$core/dsm_sdk/src/sdk/sofi_advance.rs"               # the pending SoFi position's validated predecessor
  "$core/dsm_sdk/src/sdk/sofi_reads.rs"                 # accepted_claim_at: the accepted claim at a setup's position, answered to the verifier
)
rehydrate_callers=$(grep -rl 'rehydrate_from_admitted_store' "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src 2>/dev/null \
  | grep -v '_tests\.rs$' | grep -v '/test_support/' | sort)
unknown=""
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  prod=$(python3 ci/production_text.py "$f")
  grep -q 'rehydrate_from_admitted_store' <<<"$prod" || continue
  printf '%s\n' "${known_rehydrate_callers[@]}" | grep -qxF "$f" || unknown="$unknown$f"$'\n'
done <<<"$rehydrate_callers"
if [[ -n "${unknown// /}" ]]; then
  echo "[FAIL] rehydrate_from_admitted_store has a caller this gate has not ruled on:"
  echo "$unknown"
  echo "       A validated root is verifier-derived; rehydration is for THIS device"
  echo "       resuming its own admitted coordinate. Rule on the caller and add it."
  exit 1
fi
echo "  ✓ every caller of the resume puncture is a ruled one"

# 2b. `AcceptedClaim` (SoFi Amendment S9) is verifier-derived on the same
#     terms: private fields, so a caller cannot name a claim it never accepted.
body=$(awk '/^pub struct AcceptedClaim \{/{f=1} f{print} f&&/^\}/{exit}' "$lineage")
[[ -n "$body" ]] || {
  echo "[FAIL] AcceptedClaim is not where this gate expects it"
  exit 1
}
if grep -qE '^\s+pub(\(| )' <<<"$body"; then
  echo "[FAIL] AcceptedClaim has a public field — a caller could build one directly:"
  grep -nE '^\s+pub(\(| )' <<<"$body"
  exit 1
fi
if ! grep -q 'pub(crate) fn from_resolved_sofi_position' <(awk '/^impl AcceptedClaim \{/{f=1} f{print} f&&/^\}/{exit}' "$lineage"); then
  echo "[FAIL] AcceptedClaim::from_resolved_sofi_position is not pub(crate)"
  exit 1
fi
echo "  ✓ accepted-claim fields are private"

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
# Any other constructor in that impl — `-> Self`, `-> Result<Self, …>`,
# `-> Option<Self>` — would be a second way in.
ctors=$(awk '/^impl RegisteredEconomicRoot \{/{f=1} f&&/-> (Self|Result<Self|Option<Self)/{print} f&&/^\}/{exit}' "$register" | wc -l | tr -d ' ')
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

# 5. The facts a SoFi resolution stands on are Core's, on the same terms.
#
#    `advance_resolved` installs a root on the ladder's answer over
#    `EstablishedFacts`, which `facts::establish` builds from reads Core
#    evaluated: a registration read bound to its position, an attempt-cell
#    read bound to its key, a walk bound to its chain, a vault chain grown
#    from an accepted genesis by Core-recomputed post states. None of these
#    has a field visible outside the crate (`pub(crate)` is allowed: the
#    ladder's own tests state facts), and the advance takes no `Resolution`
#    argument — a caller cannot name the verdict. The chain's one memo
#    puncture, `VaultChain::from_recorded_generations`, is this device's own
#    earlier conclusion read back, and has exactly one caller: the chain
#    walker's start.
echo "[5] SoFi facts: Core-built, and the advance derives the verdict..."
resolution="$core/dsm/src/sofi/resolution.rs"
facts="$core/dsm/src/sofi/facts.rs"
exercise="$core/dsm/src/sofi/exercise.rs"
registration="$core/dsm/src/sofi/registration.rs"
validation="$core/dsm/src/sofi/validation.rs"
for f in "$resolution" "$facts" "$exercise" "$registration" "$validation"; do
  [[ -f "$f" ]] || { echo "[FAIL] $f is not where this gate expects it"; exit 1; }
done
check_no_pub_field() {
  local ty="$1" file="$2"
  local body
  body=$(awk -v ty="$ty" '$0 ~ "^pub struct " ty "[ <]" {f=1} f{print} f&&/^\}/{exit}' "$file")
  [[ -n "$body" ]] || { echo "[FAIL] $ty is not defined in $file"; exit 1; }
  if grep -qE '^\s+pub [a-z_]+:' <<<"$body"; then
    echo "[FAIL] $ty has a public field — a caller outside the crate could state a fact:"
    grep -nE '^\s+pub [a-z_]+:' <<<"$body"
    exit 1
  fi
}
check_no_pub_field RouteFacts "$resolution"
check_no_pub_field LegFacts "$resolution"
check_no_pub_field VaultChain "$resolution"
check_no_pub_field KeyFacts "$resolution"
check_no_pub_field AttemptWalk "$resolution"
check_no_pub_field EstablishedFacts "$facts"
check_no_pub_field RefutedPosition "$facts"
check_no_pub_field InHandRefutation "$facts"
check_no_pub_field AttemptCellRead "$exercise"
check_no_pub_field RegistrationRead "$registration"
check_no_pub_field VaultPostState "$validation"
echo "  ✓ no fact type has a field visible outside the crate"

sig=$(awk '/^pub fn advance_resolved\(/{f=1} f{print} f&&/\) -> /{exit}' "$sofi_lineage")
if grep -qE 'Resolution' <<<"$sig"; then
  echo "[FAIL] advance_resolved takes a Resolution: the verdict must be derived inside it, never named by a caller"
  echo "$sig"
  exit 1
fi
if ! grep -qE 'established: &Established' <<<"$sig"; then
  echo "[FAIL] advance_resolved does not take the established facts"
  echo "$sig"
  exit 1
fi
if ! grep -qE '^\s*resolve_position\(' <(awk '/^pub fn advance_resolved\(/{f=1} f{print} f&&/^\}/{exit}' "$sofi_lineage") \
   && ! grep -qE 'resolve_position\(' <(awk '/^pub fn advance_resolved\(/{f=1} f{print} f&&/^\}/{exit}' "$sofi_lineage"); then
  echo "[FAIL] advance_resolved does not run the ladder (resolve_position) itself"
  exit 1
fi
if ! grep -q 'pub(crate) fn resolve_position' "$resolution"; then
  echo "[FAIL] resolve_position is not pub(crate): the ladder is the advance's to run"
  exit 1
fi
echo "  ✓ advance_resolved runs the ladder over the established facts and takes no verdict"

# The memo constructor has exactly one production caller: the verifier's
# chain walk (`dsm/src/sofi/resolve.rs`), which anchors the recorded rows at
# the genesis it accepted and checks their links before it stands on them.
# Test text (ci/production_text.py) may state a chain for a fixture.
memo_callers=""
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  prod=$(python3 ci/production_text.py "$f")
  grep -q 'from_recorded(' <<<"$prod" && memo_callers="$memo_callers$f"$'\n'
done < <(grep -rln 'from_recorded(' "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src 2>/dev/null \
  | grep -v "sofi/resolution.rs" | sort)
memo_callers=${memo_callers%$'\n'}
expected_memo="$core/dsm/src/sofi/resolve.rs"
if [[ "$memo_callers" != "$expected_memo" ]]; then
  echo "[FAIL] VaultChain::from_recorded must be called only from $expected_memo"
  echo "       production callers found: ${memo_callers:-none}"
  exit 1
fi
count=$(python3 ci/production_text.py "$expected_memo" | grep -c 'from_recorded(')
if [[ "$count" -ne 1 ]]; then
  echo "[FAIL] $expected_memo references from_recorded $count times; the chain's start is one call"
  exit 1
fi
if grep -rn 'from_recorded_generations' "$core/dsm/src" "$core/dsm_sdk/src" >/dev/null 2>&1; then
  echo "[FAIL] the unchecked memo constructor from_recorded_generations is back"
  exit 1
fi
literals=$(grep -rn 'EstablishedFacts {' "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src 2>/dev/null \
  | grep -v '^\S*facts\.rs:' | grep -vE '(_tests\.rs|/tests/)' || true)
while IFS= read -r hit; do
  [[ -z "$hit" ]] && continue
  file=${hit%%:*}
  prod=$(python3 ci/production_text.py "$file")
  if grep -q 'EstablishedFacts {' <<<"$prod"; then
    echo "[FAIL] EstablishedFacts is stated as a literal outside its builder, in production code:"
    echo "       $hit"
    exit 1
  fi
done <<<"$literals"
echo "  ✓ one caller of the anchored, linked chain memo, at the walk's start; facts are built by establish only"

echo "✓ raw envelope -> verified claim -> registered root: every arrow is opaque"
