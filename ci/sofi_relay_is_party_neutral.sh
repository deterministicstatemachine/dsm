#!/usr/bin/env bash
# Any device may carry immutable signed protocol objects to storage. Only the
# owning device may touch its own admission, fence, lineage and leaf cache
# (owner ruling, spec §44.4). Those are two operations, and this gate keeps
# them two: the relay may not acquire device state, and the owner-local half
# may not lose it.
#
# The doc comment on `complete_pending_fulfillment` used to claim that any
# device may run it while its own signature read this device's head. A
# comment cannot hold that line; this does.
set -euo pipefail
echo "=== sofi relay: party neutral, and the owner-local half stays owner local ==="

core=dsm_client/deterministic_state_machine
relay="$core/dsm_sdk/src/sdk/sofi_relay.rs"
advance="$core/dsm_sdk/src/sdk/sofi_advance.rs"
[[ -f "$relay" && -f "$advance" ]] || {
  echo "[FAIL] the relay and advance modules are not where this gate expects them"
  exit 1
}

# 1. The relay holds no device state. PRODUCTION CODE only: everything before
#    the first #[cfg(test)], with comment lines stripped — this file explains
#    what it may not hold, and prose naming a thing is not holding it. That is
#    the same mistake G1 made for the whole rebuild.
prod=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' "$relay" | grep -vE '^[[:space:]]*(//|/\*|\*)')
declare -a FORBIDDEN=(
  "CoreSDK|a relay that holds the SDK can reach the head, the admission and the lineage"
  "device_head|the relay must not read this device's head"
  "pending_economic_admission|an admission is the owning device's, never a carrier's"
  "client_db|the relay writes nothing local"
  "economic_lineage|the lineage is the owning device's"
)
for entry in "${FORBIDDEN[@]}"; do
  name="${entry%%|*}"
  why="${entry#*|}"
  if grep -qE "\\b${name}\\b" <<<"$prod"; then
    echo "[FAIL] $relay names \`$name\` in production: $why"
    grep -nE "\\b${name}\\b" <<<"$prod" | head -3
    exit 1
  fi
done
echo "  ✓ the relay holds no device state"

# 2. The relay's entry points take a set and public coordinates, nothing more:
#    a fulfillment's content address, or the vault key an exercise holds
#    (SoFi Amendment S20: the exercise carries everything its pair needs).
relay_entry() {
  local fn="$1" what="$2"; shift 2
  local sig
  sig=$(awk "/pub async fn ${fn}\\(/{f=1} f{print} f&&/-> Result/{exit}" "$relay")
  [[ -n "$sig" ]] || { echo "[FAIL] $relay no longer defines $fn"; exit 1; }
  for param in 'set: &StorageSet' "$@"; do
    if ! grep -qF "$param" <<<"$sig"; then
      echo "[FAIL] $fn no longer takes exactly ($what):"
      echo "$sig"
      exit 1
    fi
  done
  if [[ $(grep -c ':' <<<"$(sed -n '/(/,/)/p' <<<"$sig" | grep -vE 'pub async fn')") -ne $(( $# + 1 )) ]]; then
    echo "[FAIL] $fn takes more than ($what):"
    echo "$sig"
    exit 1
  fi
}
relay_entry relay_fulfillment "committed set, fulfillment id" 'fulfillment_id: &D32'
relay_entry relay_exercise "committed set, vault key" 'vault_id: &D32' 'parent_root: &D32' 'attempt: u64'
echo "  ✓ a relay is reached with a committed set and public coordinates"

# 3. The owner-local half still requires the owning device. A relay-shaped
#    signature here would be the same conflation wearing the other face.
for fn in complete_pending_fulfillment resolve_pending_position; do
  sig=$(awk "/pub async fn ${fn}\\(/{f=1} f{print} f&&/-> Result/{exit}" "$advance")
  [[ -n "$sig" ]] || { echo "[FAIL] $advance no longer defines $fn"; exit 1; }
  if ! grep -q 'core: &CoreSDK' <<<"$sig"; then
    echo "[FAIL] $fn no longer takes the owning device:"
    echo "$sig"
    exit 1
  fi
done
echo "  ✓ the owner-local half still takes the owning device"
