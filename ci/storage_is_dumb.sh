#!/usr/bin/env bash
# CI gate: the storage node holds bytes and knows nothing about SoFi.
set -euo pipefail
root="dsm_storage_node/src"
banned=( 'dsm::sofi' 'SOFI_' 'ConditionalSofi' 'SofiResolutionClaim' 'TraderPrecommit'
         'TraderFulfillment' 'DlvPolicyFulfillment' 'FulfillmentRegistered' 'RouteValidation'
         'ConsumedRoute' 'verify_signed_object' 'check_fulfillment_against_precommit'
         'canonical_legs' 'recompute_e' 'resolution_claim' '/api/v2/sofi' )
fail=0
for tok in "${banned[@]}"; do
  if hits=$(git grep -n -F -- "$tok" -- "$root"); then
    echo "[FAIL] storage node references '$tok':"; echo "$hits"; fail=1
  fi
done
if hits=$(git grep -n -i -- 'sofi' -- "$root"); then
  echo "[FAIL] storage node mentions SoFi:"; echo "$hits"; fail=1
fi
[[ $fail -eq 0 ]] && echo "[OK] the storage node is application blind"
exit $fail
