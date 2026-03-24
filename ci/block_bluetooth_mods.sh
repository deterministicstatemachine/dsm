#!/usr/bin/env bash
# BLE transport changes are allowed.
#
# The deterministic protocol remains clockless, but BLE transport/runtime code
# may now evolve to use operational wall-clock timers for retries, ACK
# timeouts, reconnect backoff, pacing, and idle expiry. Those invariants are
# enforced by the targeted protobuf / JSON / protocol guards elsewhere in CI.

set -euo pipefail

echo "[ble-guard] Bluetooth transport modifications are permitted; deferring to targeted CI checks..."

echo "✅ Bluetooth changes allowed. Rely on the protocol/encoding guards for enforcement."
exit 0
