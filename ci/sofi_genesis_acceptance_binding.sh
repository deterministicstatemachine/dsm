#!/usr/bin/env bash
# A vault genesis is accepted only from the owner transition the verifier
# itself validated — never from a PRESENTED creation operation.
#
# The R14 predicate took a creation operation and an owner root. It could
# never acquire a production caller: `VaultCreation` carries no asset
# commitments, so a presented creation establishes the AMOUNTS and never
# which balances were debited, and a caller could hand in an A/B-shaped
# sibling of an operation that actually debited X/Y. R14 deleted it (#955).
#
# The specification corpus (SoFi §19.8, §28 step 5) states the sound form:
# `genesis_accepted` binds the genesis bytes to the ACCEPTED owner transition
# at p_create. That transition is a `ValidatedPeerTransition`, which only
# `validate_peer_lineage` constructs (ci/peer_debit_lineage_authoritative.sh):
# the owner's operation, position and debits are the ones the verifier's own
# walk validated, so the accepted creation is derived, never asserted
# (F10). This gate holds that form:
#
#   1. `genesis_accepted` takes the owner as a `ValidatedPeerTransition`,
#      exactly once, and takes no `Operation` of its own;
#   2. no creation-funding carrier stands in for the validated transition;
#   3. the formal statement stays where it lives.
set -euo pipefail
echo "=== genesis acceptance: from the validated owner transition only ==="

core=dsm_client/deterministic_state_machine
lineage=$core/dsm/src/sofi/lineage.rs

# 1. The signature: an owner that only the walk can produce, and no operation
#    a caller could present.
sig=$(awk '/^pub fn genesis_accepted\(/{f=1} f{print} f&&/\) -> /{exit}' "$lineage")
if [[ -z "$sig" ]]; then
  echo "[FAIL] $lineage no longer defines \`pub fn genesis_accepted(\` — the"
  echo "       specification (SoFi §28 step 5) names it as the acceptance."
  exit 1
fi
if ! grep -qE 'owner: &crate::economic::provenance::ValidatedPeerTransition,' <<<"$sig"; then
  echo "[FAIL] genesis_accepted must take the owner as the walk's"
  echo "       ValidatedPeerTransition; anything else is a presented creation."
  echo "$sig"
  exit 1
fi
if grep -qE 'Operation|VaultCreation|CreationFunding' <<<"$sig"; then
  echo "[FAIL] genesis_accepted takes a creation the caller presents:"
  echo "$sig"
  exit 1
fi
defs=$(grep -rn 'fn genesis_accepted' "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src \
  | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(//|///|\*)' || true)
if [[ $(grep -c . <<<"$defs") -ne 1 ]]; then
  echo "[FAIL] exactly one genesis_accepted may exist:"
  echo "$defs"
  exit 1
fi
echo "  ✓ genesis_accepted binds the owner transition the walk validated"

# 2. No carrier of creation funding stands in for the validated transition.
hits=$(grep -rn 'CreationFunding' "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src 2>/dev/null \
  | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(//|///|\*)' || true)
if [[ -n "$hits" ]]; then
  echo "[FAIL] a creation-funding carrier asserts what the walk derives:"
  echo "$hits"
  exit 1
fi
echo "  ✓ no presented creation funding"

# 3. The statement did not go with the code. The formal layer still carries
#    it, so what R14 deleted was one unsound realization and not the rule.
lean=lean4/DSMSofiAtomicity.lean
tla=tla/DSM_SofiFulfillment.tla
# The DEFINITION, not a mention of it. A first draft of this check grepped for
# the bare name and passed while the definition had been renamed away, because
# a use site still spelled it — the same spelling-for-substance mistake G1 made
# for the whole rebuild.
for pair in "$lean|def GenesisAccepted" "$lean|theorem genesis_requires_validated_creation" \
            "$tla|GenesisCanonicalOnlyIfCreationValid ==" ; do
  f="${pair%%|*}"
  name="${pair#*|}"
  if ! grep -qF "$name" "$f" 2>/dev/null; then
    echo "[FAIL] $f no longer DEFINES \`$name\`. Deleting the Rust predicate"
    echo "       moved the rule to the formal layer; deleting it there too"
    echo "       would remove the rule itself."
    exit 1
  fi
done
echo "  ✓ the rule is still stated where it now lives"
