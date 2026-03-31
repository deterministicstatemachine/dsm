#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"

echo "[qr-guard] Checking QR path for oversized payload fields…"

# Prefer ripgrep if available
if command -v rg >/dev/null 2>&1; then
  if rg -n --hidden -S 'ContactCardV1.*sig_card' "$root_dir/dsm_client/frontend/src/ui" | grep -vE 'copy|link|share-string' ; then
    echo "Refusing commit: sig_card in QR path. Keep QR minimal (genesis_hash + device_id)."
    exit 1
  fi
else
  # Fallback to grep
  if grep -R "ContactCardV1.*sig_card" -n "$root_dir/dsm_client/frontend/src/ui" 2>/dev/null | grep -vE 'copy|link|share-string' ; then
    echo "Refusing commit: sig_card in QR path. Keep QR minimal (genesis_hash + device_id)."
    exit 1
  fi
fi

echo "[qr-guard] OK"
