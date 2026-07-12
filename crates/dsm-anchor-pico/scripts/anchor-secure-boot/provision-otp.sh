#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# IRREVERSIBLE RP2350 OTP provisioning for the DSM anchor. Dry-run by default; every burn requires
# --commit AND typing YES. See RUNBOOK.md. Do a full dry run on a sacrificial board first.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET_JSON="$HERE/host-secret.json"
# page 48, row 0 — MUST equal HOST_SECRET_ROW in ../../src/secure_boot.rs
PAGE=48
ROW_BASE=$(( PAGE * 64 ))

COMMIT=0; CMD=""
for a in "$@"; do case "$a" in --commit) COMMIT=1 ;; --*) CMD="$a" ;; esac; done

run() { if [ "$COMMIT" = 1 ]; then echo "+ $*"; "$@"; else echo "[dry-run] $*"; fi; }
confirm() {
  [ "$COMMIT" = 1 ] || return 0
  read -r -p "IRREVERSIBLE OTP BURN. Board correct + backed up? Type YES to proceed: " x
  [ "$x" = "YES" ] || { echo "aborted"; exit 1; }
}

case "$CMD" in
  --gen-secret)
    [ -f "$SECRET_JSON" ] && { echo "ERROR: $SECRET_JSON exists — refusing to regenerate a provisioned secret"; exit 1; }
    python3 - "$SECRET_JSON" "$ROW_BASE" <<'PY'
import os, sys, json
path, base = sys.argv[1], int(sys.argv[2])
b = os.urandom(32)  # the 256-bit sealed host-key secret
rows = { str(base + i): (b[2*i] | (b[2*i+1] << 8)) for i in range(16) }
json.dump({"otp": rows}, open(path, "w"), indent=2)
print(f"wrote {path}: 16 rows @ base {base}. THIS FILE IS THE HOST SECRET — guard it like the key.")
PY
    ;;
  --write-secret)
    [ -f "$SECRET_JSON" ] || { echo "ERROR: run '$0 --gen-secret' first"; exit 1; }
    confirm
    run picotool otp load "$SECRET_JSON" ;;
  --lock-secret)
    # Lock OTP page $PAGE to secure-read only, so ONLY secure-state (enrolled) firmware reads the
    # host secret. This script will NOT guess the permission encoding — write perms.json per the
    # RP2350 datasheet §13 + 'picotool otp permissions' schema, then:
    echo "Create $HERE/perms.json setting page $PAGE = secure-read-only (datasheet §13), then run:"
    confirm
    run picotool otp permissions "$HERE/perms.json" ;;
  --lockdown)
    # DO LAST. SECURE_BOOT_ENABLE + DEBUG_DISABLE + boot-key-valid + alt-boot-disable in the CRIT
    # OTP register. This script deliberately does NOT emit a hard-coded CRIT selector/value — a wrong
    # CRIT burn bricks the board. Read the exact rows from RP2350 datasheet §13 (HAL reads CRIT bit0
    # = secure_boot_enabled, bit2 = debug_disabled) and 'picotool otp list', then run the explicit
    # 'picotool otp set <CRIT selector> <value>' commands yourself.
    echo "LOCKDOWN is manual by design. After Steps 3-4 pass validation:"
    echo "  picotool otp set <SECURE_BOOT_ENABLE row> ...   # datasheet §13"
    echo "  picotool otp set <DEBUG_DISABLE row> ..."
    echo "Then re-read: picotool otp dump | diff otp-before.json - "
    exit 0 ;;
  *)
    echo "usage: $0 [--gen-secret | --write-secret | --lock-secret | --lockdown] [--commit]"; exit 2 ;;
esac
