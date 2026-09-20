#!/usr/bin/env bash
# CI gate: the root register accepts only single root claims signed by the caller.
set -euo pipefail
node=dsm_storage_node/src/api/economic/root_register.rs
h=$(awk '/^pub async fn post_claim\(/{f=1} f{print} f&&/^\}/{exit}' "$node")
[[ -n "$h" ]] || { echo "[FAIL] post_claim not found"; exit 1; }
grep -q 'decode_and_verify_economic_root_claim' <<<"$h" \
  || { echo "[FAIL] post_claim no longer uses the signed single root decoder"; exit 1; }
if grep -q 'decode_registered_economic_claim' <<<"$h"; then
  echo "[FAIL] post_claim decodes a claim kind that carries no caller signature"; exit 1
fi
grep -q 'verify_claim_attribution' "$node" || { echo "[FAIL] attribution check missing"; exit 1; }
echo "[OK] the root register accepts only caller signed single root claims"
