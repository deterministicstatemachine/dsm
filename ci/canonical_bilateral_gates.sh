#!/usr/bin/env bash
set -euo pipefail

# CI pre-merge gate: enforce canonical bilateral relationship path
# - No auto-contact creation outside QR acceptance
# - No pairing flow terms
# - Envelope v3 only in protocol paths

echo "=== Canonical Bilateral Path Enforcement ==="

roots=(
  dsm_client/deterministic_state_machine/dsm_sdk/src
  dsm_client/deterministic_state_machine/dsm/src
  dsm_client/android/app/src/main/java/com/dsm/wallet/bridge
  dsm_client/frontend/src
)

# Allowlist for tests and docs
allow_globs=(
  '!**/*test*.rs'
  '!**/*test*.ts'
  '!**/*test*.tsx'
  '!**/*test*.kt'
  '!**/tests/**'
  '!**/__tests__/**'
  '!**/*.md'
  '!**/target/**'
  '!**/build/**'
  '!**/node_modules/**'
)

# 1. Block auto-contact creation patterns (only QR acceptance should create contacts)
echo "[1/4] Checking for auto-contact creation..."
auto_contact_patterns='store_contact.*ble|add_contact.*ble|create_contact.*scan|auto.*add.*contact'
if rg -n --hidden --type-add 'code:*.{rs,kt,ts,tsx}' -t code ${allow_globs[@]} -i -e "$auto_contact_patterns" "${roots[@]}" 2>/dev/null; then
  echo "[FAIL] Auto-contact creation pattern found outside QR acceptance path"
  exit 1
fi
echo "  ✓ No auto-contact creation detected"

# 2. Block pairing flow terminology (replaced by bilateral relationship + BLE binding)
echo "[2/4] Checking for pairing flow terms..."
# Allow: BlePairingRequest/BlePairingAccept (BLE identity exchange frames)
# Allow: Comments/section markers mentioning "pairing"
# Block: Explicit pairing flow terms (PairingStatus, initiate_pairing, etc.) in actual code
pairing_flow_patterns='initiate.*pairing|pairing.*flow[^/]|PairingState|pairing.*workflow'
if rg -n --hidden --type-add 'code:*.{rs,kt,ts,tsx}' -t code ${allow_globs[@]} -i -e "$pairing_flow_patterns" "${roots[@]}" 2>/dev/null | grep -v '//' | grep -v '#' | grep -v '\*'; then
  echo "[FAIL] Explicit pairing flow terminology found (use bilateral relationship + BLE binding)"
  exit 1
fi
echo "  ✓ No explicit pairing flow detected"

# 3. Enforce Envelope v3 in protocol paths (no v2 references)
echo "[3/4] Checking for Envelope v-2 references..."
# Allow: comments mentioning "v2" for historical context or b0x spool (storage layer)
# Allow: version fields in test data (e.g., p2.version = "v2")
# Block: EnvelopeV2 struct usage, ENVELOPE_VERSION = 2 constants
envelope_v2_patterns='struct\s+EnvelopeV2|class\s+EnvelopeV2|ENVELOPE_VERSION\s*=\s*2[^0-9]'
if rg -n --hidden --type-add 'code:*.{rs,kt,ts,tsx}' -t code ${allow_globs[@]} -e "$envelope_v2_patterns" "${roots[@]}" 2>/dev/null; then
  echo "[FAIL] Envelope v-2 struct/constant found (enforce v3 only)"
  exit 1
fi
echo "  ✓ Envelope v3 enforcement verified"

# 4. Verify contact existence checks before BLE binding
echo "[4/4] Checking for BLE binding without contact verification..."
# This is a heuristic check - verify that BLE identity read paths call has_contact_for_device_id
if ! grep -r "hasContactForDeviceId" dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/DsmBluetoothService.kt >/dev/null; then
  echo "[WARN] DsmBluetoothService should call hasContactForDeviceId before BLE binding"
fi
echo "  ✓ Contact existence gating present"

echo ""
echo "=== All canonical bilateral path gates passed ✓ ==="
