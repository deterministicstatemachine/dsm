#!/usr/bin/env bash
set -euo pipefail

# CI gate: a vault genesis cannot become consumable from a PRESENTED creation
# operation.
#
# `genesis_accepted` takes a `CreationFunding`, which is the funding pair AN
# operation states — read off a signed `SofiVaultCreate`. It is deliberately
# NOT proof that the operation is THE one whose verified write set produced
# the accepted owner transition holding this vault's `VaultCreation` leaf.
#
# The evidence gap is real and not closable by inspection: `VaultCreation`
# carries `vault_id`, `genesis_root`, `amount_a`, `amount_b` and no asset
# commits, so the leaf and its inclusion proof are byte-identical whichever
# assets the creation debited. A verifier that accepted a presented operation
# would take a vault funded from `X/Y` as one funded from the `A/B` its policy
# names — an asset-provenance and conservation failure, not a broken vault.
#
# So until F10 has an opaque `VerifiedVaultCreation` whose sole constructor
# establishes the accepted transition, `genesis_accepted` gets NO production
# caller. This gate holds that: the only references outside its own module are
# doc comments, and the only calls are in its own test block.
#
# When E2 lands the capability, this gate changes shape with it — it does not
# get deleted.

echo "=== genesis acceptance: no naive production caller ==="

core=dsm_client/deterministic_state_machine
lineage="$core/dsm/src/sofi/lineage.rs"

[[ -f "$lineage" ]] || {
  echo "[FAIL] the sofi lineage module is not where this gate expects it"
  exit 1
}

# 1. `CreationFunding` states, it does not prove: one constructor, so named.
if ! grep -q 'pub fn stated_by' "$lineage"; then
  echo "[FAIL] CreationFunding::stated_by is missing — the funding pair must be"
  echo "       READ OFF a signed operation, and the name must say it is only"
  echo "       what an operation states"
  exit 1
fi
ctors=$(awk '/^impl CreationFunding \{/{f=1} f&&/-> Option<Self>|-> Self/{print} f&&/^\}/{exit}' \
  "$lineage" | wc -l | tr -d ' ')
if [[ "$ctors" -ne 1 ]]; then
  echo "[FAIL] CreationFunding has $ctors constructors; exactly one reads the pair"
  echo "       off a signed operation"
  exit 1
fi
echo "  ✓ the funding pair is stated by an operation, never asserted"

# 2. No production caller of `genesis_accepted` anywhere in the workspace.
callers=$(grep -rn 'genesis_accepted(' \
  "$core/dsm/src" "$core/dsm_sdk/src" dsm_storage_node/src 2>/dev/null \
  | grep -v "^$lineage:" || true)
if [[ -n "$callers" ]]; then
  echo "[FAIL] genesis_accepted has a caller outside its own module. A vault"
  echo "       genesis must not be acceptable from a PRESENTED creation"
  echo "       operation — F10 must derive the funding pair from the exact"
  echo "       verified creation transition (an opaque VerifiedVaultCreation)."
  echo "$callers"
  exit 1
fi

# And inside the module, only its own tests call it.
first_test=$(grep -n '^#\[cfg(test)\]' "$lineage" | head -1 | cut -d: -f1)
if [[ -z "$first_test" ]]; then
  echo "[FAIL] no test module in $lineage; this gate cannot tell tests from production"
  exit 1
fi
prod_calls=$( { awk -v t="$first_test" 'NR<t && /genesis_accepted\(/ && !/^\s*\/\//' "$lineage" \
  | grep -v 'pub fn genesis_accepted' || true; } | wc -l | tr -d ' ')
if [[ "$prod_calls" -ne 0 ]]; then
  echo "[FAIL] genesis_accepted is called $prod_calls time(s) before the test module"
  exit 1
fi
echo "  ✓ no production caller; the acceptance binding is still owed by F10"

echo "✓ a genesis is not consumable from a presented creation operation"
