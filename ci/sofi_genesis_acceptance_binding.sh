#!/usr/bin/env bash
# A vault genesis is not acceptable from a PRESENTED creation operation, and
# no Rust predicate claims otherwise.
#
# `genesis_accepted` was a twelve-conjunct predicate that took a creation
# operation and an owner root and returned a vault id. It could never acquire
# a production caller: `VaultCreation` carries no asset commitments, so
# proving the creation leaf establishes the AMOUNTS and never which balances
# were debited, and a caller could hand in an A/B-shaped sibling of an
# operation that actually debited X/Y. This gate used to hold that line by
# failing on the first caller.
#
# Owner ruling, spec §44.4: the standalone production predicate was the stale
# piece, not the gate. Genesis validity is established by the vault genesis
# constructor and recognizer with the accepted genesis root; the predicate
# survives as the FORMAL definition and is gone from Rust. So this gate now
# keeps it gone, and keeps the formal statement present — a deletion that
# quietly took the statement with it would be the same hole by another route.
set -euo pipefail
echo "=== genesis acceptance: formal only, and still stated ==="

core=dsm_client/deterministic_state_machine

# 1. No Rust predicate, anywhere, production or test. Re-introducing one needs
#    F10's VerifiedVaultCreation first, which is a design, not an edit.
hits=$(grep -rn 'genesis_accepted\|CreationFunding' \
  "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src 2>/dev/null \
  | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(//|///|\*)' || true)
if [[ -n "$hits" ]]; then
  echo "[FAIL] a vault-genesis acceptance predicate is back in Rust."
  echo "       VaultCreation carries no asset commitments, so a PRESENTED"
  echo "       creation establishes amounts and never which balances were"
  echo "       debited. F10 owes an opaque VerifiedVaultCreation bound to the"
  echo "       exact accepted owner transition at p_create; until it exists"
  echo "       this predicate has no sound production form."
  echo "$hits"
  exit 1
fi
echo "  ✓ no Rust predicate accepts a genesis from a presented creation"

# 2. The statement did not go with the code. The formal layer still carries
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
