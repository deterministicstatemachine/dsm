#!/usr/bin/env bash
set -euo pipefail

# CI gate: a conditional SoFi resolution claim `C_q` cannot be POSTED to the
# root register. It is derived by the member in the transaction that accepts
# `F`, and `F`'s signature is the attribution.
#
# WHY THIS NEEDS A GATE RATHER THAN A TEST. The endpoint refuses these bytes
# today whatever happens, because the single-root decoder cannot parse them —
# the right outcome for the wrong reason. E2's task list says to make this
# endpoint handle "every claim kind", and the obvious way to do that is to swap
# in `decode_registered_economic_claim`. That swap opens the door, and no
# existing test would notice:
#
#   - `SofiResolutionClaim` carries no signature and no claimant public key, so
#     `verify_claim_attribution` is INAPPLICABLE, not merely skipped;
#   - `K_root` is publicly derivable, which is why attribution is two-part;
#   - the cell is write-once, so a victim can never place their real claim;
#   - the fabricated conditional names no real `F`, never resolves, and the
#     descendant fence then refuses every descendant forever.
#
# Permanent, unrecoverable denial of an arbitrary trader's economic position by
# any authenticated caller.

echo "=== root register: a conditional claim is member-derived, never posted ==="

node=dsm_storage_node/src/api/economic/root_register.rs
wire=dsm_client/deterministic_state_machine/dsm/src/sofi/wire/objects.rs

[[ -f "$node" ]] || { echo "[FAIL] $node not found"; exit 1; }
[[ -f "$wire" ]] || { echo "[FAIL] $wire not found"; exit 1; }

# 1. The refusal exists, and it is inside the POST handler rather than beside it.
echo "[1/3] post_claim refuses the conditional class..."
handler=$(awk '/^pub async fn post_claim\(/{f=1} f{print} f&&/^\}/{exit}' "$node")
[[ -n "$handler" ]] || { echo "[FAIL] could not find post_claim in $node"; exit 1; }
if ! grep -q 'is_conditional_claim_class' <<<"$handler"; then
  echo "[FAIL] post_claim no longer refuses a posted conditional claim."
  echo "       C_q is member-derived: it is written only by the transaction"
  echo "       that accepts F. Accepting it from a caller lets any"
  echo "       authenticated party burn an arbitrary trader's position"
  echo "       permanently — the cell is write-once and the claim never"
  echo "       resolves, so the descendant fence blocks the lineage forever."
  exit 1
fi
echo "  ✓ refused by class, before any decode"

# 2. The refusal is reported BY NAME. "malformed" would read as a caller typo.
echo "[2/3] the refusal names itself..."
if ! grep -q 'conditional-claim-is-member-derived' "$node"; then
  echo "[FAIL] the refusal no longer has its own outcome name. A generic"
  echo "       'malformed' hides a rejected attack behind a client error."
  exit 1
fi
echo "  ✓ named"

# 3. THE PREMISE. The argument above rests on a conditional claim having no
#    signature and no claimant key, so attribution cannot be applied to it. If
#    that ever changes, the rule deserves a fresh ruling rather than inertia.
echo "[3/3] a conditional claim still carries no signature and no claimant key..."
body=$(awk '/^pub struct SofiResolutionClaim \{/{f=1} f{print} f&&/^\}/{exit}' "$wire")
[[ -n "$body" ]] || { echo "[FAIL] could not find SofiResolutionClaim in $wire"; exit 1; }
if grep -qE 'signature|claimant|public_key' <<<"$body"; then
  echo "[FAIL] SofiResolutionClaim grew a signature or claimant key:"
  grep -nE 'signature|claimant|public_key' <<<"$body"
  echo "       The refusal above is justified by attribution being INAPPLICABLE"
  echo "       to this claim. If it now carries an attributable key, re-rule"
  echo "       the boundary deliberately instead of leaving this gate to pass."
  exit 1
fi
echo "  ✓ attribution is inapplicable, which is why posting it is refused"

echo "✓ C_q reaches the register only from the transaction that accepts F"
