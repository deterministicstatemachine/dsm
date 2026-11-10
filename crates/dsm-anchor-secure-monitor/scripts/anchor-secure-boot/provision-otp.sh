#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# IRREVERSIBLE RP2350 OTP provisioning for the DSM anchor. Dry-run by default; every burn requires
# --commit AND typing YES. See RUNBOOK.md. Rehearse on a spent board before a new one.
set -euo pipefail
# Everything this script writes is the operator's alone.
umask 077
# The sealed secret is the board's identity root: it lives outside the repository, in a directory
# only its owner can open, one directory per board.
SECRET_DIR="${DSM_ANCHOR_SECRET_DIR:-$HOME/.dsm-anchor-secure-boot}"
BUILD_DIR="$SECRET_DIR/build"
# page 48, row 0 — MUST equal SEALED_SECRET_ROW in ../../src/sealed.rs
SECRET_ROW=$(( 48 * 64 ))
# page 46, row 0 — MUST equal MU_ROW in ../../src/main.rs
DIGEST_ROW=$(( 46 * 64 ))
# PAGEn_LOCK1 = 0xf80 + 2n + 1. Each row holds its low byte three times over, and that byte is
# LOCK_S in bits 0-1, LOCK_NS in bits 2-3 and LOCK_BL in bits 4-5 (`picotool otp list -f PAGE48_LOCK1`).
# A row's value is built from its fields, never written out.
lock_row_value() { # LOCK_S LOCK_NS LOCK_BL
  local byte=$(( $1 | ($2 << 2) | ($3 << 4) ))
  printf '0x%06x' $(( byte * 0x010101 ))
}
LOCK_READ_WRITE=0
LOCK_READ_ONLY=1
LOCK_INACCESSIBLE=3
# Secure reads and nothing writes; Non-secure has no access. The USB bootloader never serves the
# secret, and may read back the digest, which is public.
SECRET_LOCK_ROW=$(( 0xf80 + 2 * 48 + 1 ))
SECRET_LOCK=$(lock_row_value "$LOCK_READ_ONLY" "$LOCK_INACCESSIBLE" "$LOCK_INACCESSIBLE")
DIGEST_LOCK_ROW=$(( 0xf80 + 2 * 46 + 1 ))
DIGEST_LOCK=$(lock_row_value "$LOCK_READ_ONLY" "$LOCK_INACCESSIBLE" "$LOCK_READ_ONLY")
# The boot configuration (page 1: CRIT1, BOOT_FLAGS) and the boot key hashes (page 2): everyone reads,
# nothing writes. Until these lock, the USB bootloader could set more bits in them, KEY_INVALID on the
# one valid key among them, and no signed image would ever boot again.
BOOT_CONFIG_LOCK_ROW=$(( 0xf80 + 2 * 1 + 1 ))
BOOT_KEYS_LOCK_ROW=$(( 0xf80 + 2 * 2 + 1 ))
BOOT_PAGES_LOCK=$(lock_row_value "$LOCK_READ_ONLY" "$LOCK_READ_ONLY" "$LOCK_READ_ONLY")
# Page 44, rows 0-2, MUST equal ROLLBACK_ROW in sign.sh: the rollback version. The bootrom, running
# Secure, goes on writing it. A USB host in the bootloader must not, which would retire every image.
ROLLBACK_ROW=$(( 44 * 64 ))
ROLLBACK_LOCK_ROW=$(( 0xf80 + 2 * 44 + 1 ))
ROLLBACK_LOCK=$(lock_row_value "$LOCK_READ_WRITE" "$LOCK_READ_ONLY" "$LOCK_READ_ONLY")

COMMIT=0; CMD=""; BOARD=""
while [ $# -gt 0 ]; do
  case "$1" in
    --commit) COMMIT=1 ;;
    --board) shift; BOARD="${1:-}" ;;
    --*) CMD="$1" ;;
    *) echo "ERROR: unexpected argument $1"; exit 2 ;;
  esac
  shift
done

usage() {
  echo "usage: $0 --board <name> [--check-blank | --gen-secret | --write-secret | --write-digest |"
  echo "                           --lock-pages | --write-bootkey | --lockdown |"
  echo "                           --lock-boot-pages] [--commit]"
  exit 2
}
[ -n "$CMD" ] || usage
[ -n "$BOARD" ] || { echo "ERROR: --board names the board: every board has its own secret"; usage; }
case "$BOARD" in *[!A-Za-z0-9_-]*) echo "ERROR: a board name is letters, digits, - and _"; exit 2 ;; esac
BOARD_DIR="$SECRET_DIR/boards/$BOARD"
mkdir -p "$BOARD_DIR"
chmod 700 "$SECRET_DIR" "$SECRET_DIR/boards" "$BOARD_DIR"
SECRET_BIN="$BOARD_DIR/host-secret.bin"
MU_BIN="$BUILD_DIR/mu-enrolled.bin"
OTP_JSON="$BUILD_DIR/bootkey-otp.json"

run() { if [ "$COMMIT" = 1 ]; then echo "+ $*"; "$@"; else echo "[dry-run] $*"; fi; }
# What the board's secret page holds, read fresh (READ-ONLY): `blank`, or `sealed` when an earlier
# procedure burned a secret there and locked the page exactly as this one does. A board of the second
# kind goes on with that secret, which production reads through the same rows: OTP is never rewritten,
# and the board holds the only copy. Anything else is a page this procedure did not write, and it stops.
secret_page() {
  local dump="$BOARD_DIR/otp-read.bin"
  picotool otp dump -r --output "$dump" >/dev/null
  python3 - "$dump" "$SECRET_ROW" "$SECRET_LOCK_ROW" "$SECRET_LOCK" <<'PAGE'
import struct, sys
data = open(sys.argv[1], "rb").read()
rows = [word & 0xffffff for (word,) in struct.iter_unpack("<I", data)]
if len(rows) != 4096:
    sys.exit(f"ERROR: the dump holds {len(rows)} rows, not 4096")
secret, lock_row, lock = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4], 16)
written = [hex(r) for r in range(secret, secret + 16) if rows[r] != 0]
if not written and rows[lock_row] == 0:
    print("blank")
elif len(written) == 16 and rows[lock_row] == lock:
    print("sealed")
else:
    sys.exit(f"ERROR: the secret page is neither blank nor sealed as this procedure seals it: "
             f"rows written {written}, lock row {hex(rows[lock_row])} (expected 0 or {hex(lock)}). "
             "Another procedure wrote this board; nothing here goes on with it.")
PAGE
}
confirm() {
  [ "$COMMIT" = 1 ] || return 0
  picotool info -d || true
  read -r -p "IRREVERSIBLE OTP BURN on board '$BOARD'. Is that this board? Type YES to proceed: " x
  [ "$x" = "YES" ] || { echo "aborted"; exit 1; }
}
need() { [ -f "$1" ] || { echo "ERROR: no $1 — $2"; exit 1; }; }

case "$CMD" in
  --check-blank)
    # READ-ONLY. Every row this procedure writes must still be zero, except a secret page an earlier
    # procedure sealed as this one seals it: that board keeps its secret, and Step 4 and the secret
    # half of Step 6 are already done on it.
    page="$(secret_page)"
    dump="$BOARD_DIR/otp-before.bin"
    picotool otp dump -r --output "$dump"
    python3 - "$dump" "$SECRET_ROW" "$DIGEST_ROW" "$ROLLBACK_ROW" "$page" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
rows = [word & 0xffffff for (word,) in struct.iter_unpack("<I", data)]
if len(rows) != 4096:
    sys.exit(f"ERROR: the dump holds {len(rows)} rows, not 4096")
secret, digest, rollback, page = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
watched = {"digest": range(digest, digest + 16),
           "boot key 0": range(0x80, 0x90), "CRIT1": range(0x40, 0x48), "BOOT_FLAGS1": range(0x4b, 0x4e),
           "digest page lock": range(0xf80 + 92, 0xf80 + 94),
           "boot page locks": range(0xf80 + 2, 0xf80 + 6), "rollback version": range(rollback, rollback + 3),
           "rollback page lock": range(0xf80 + 88, 0xf80 + 90), "BOOT_FLAGS0": range(0x48, 0x4b)}
if page == "blank":
    watched["sealed secret"] = range(secret, secret + 16)
    watched["secret page lock"] = range(0xf80 + 96, 0xf80 + 98)
used = {name: [hex(r) for r in span if rows[r] != 0] for name, span in watched.items()}
used = {name: found for name, found in used.items() if found}
if used:
    sys.exit(f"ERROR: this board is not blank where the procedure writes: {used}")
if page == "sealed":
    print("blank where the procedure writes, except its sealed secret: an earlier procedure burned and "
          "locked it as this one does, so this board keeps it. Skip Step 4; Step 6 locks the digest page alone.")
else:
    print("blank where the procedure writes")
PY
    ;;
  --gen-secret)
    [ -f "$SECRET_BIN" ] && { echo "ERROR: $SECRET_BIN exists — refusing to regenerate a provisioned secret"; exit 1; }
    [ "$(secret_page)" = blank ] || { echo "ERROR: this board already holds its sealed secret; it needs none generated"; exit 1; }
    python3 - "$SECRET_BIN" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(os.urandom(32))
print(f"wrote {sys.argv[1]}: this board's 256-bit sealed secret. Guard it like the key.")
PY
    ;;
  --write-secret)
    need "$SECRET_BIN" "run --gen-secret for this board first"
    [ "$(secret_page)" = blank ] || { echo "ERROR: this board already holds its sealed secret, and goes on with it: nothing to write"; exit 1; }
    confirm
    run picotool otp load -e -s "$SECRET_ROW" "$SECRET_BIN" -t bin ;;
  --write-digest)
    need "$MU_BIN" "run sign.sh --sign first"
    confirm
    run picotool otp load -e -s "$DIGEST_ROW" "$MU_BIN" -t bin ;;
  --lock-pages)
    page="$(secret_page)"
    confirm
    if [ "$page" = sealed ]; then
      echo "the secret page is already locked as this procedure locks it: only the digest page is locked"
    else
      run picotool otp set -r "$SECRET_LOCK_ROW" "$SECRET_LOCK"
    fi
    run picotool otp set -r "$DIGEST_LOCK_ROW" "$DIGEST_LOCK"
    # Nothing reads this copy again. It could restore no board, since the chip's key does not leave
    # the chip, and all it can still do is leak.
    if [ "$COMMIT" = 1 ]; then
      rm -f "$SECRET_BIN"
      echo "removed $SECRET_BIN: the board holds the only copy"
    fi ;;
  --write-bootkey)
    # The key's hash alone, so it can be read back before anything depends on it. sign.sh's OTP
    # file also holds KEY_VALID and SECURE_BOOT_ENABLE, which --lockdown burns.
    need "$OTP_JSON" "run sign.sh --sign first"
    key_json="$BOARD_DIR/bootkey-only.json"
    python3 - "$OTP_JSON" "$key_json" <<'PY'
import json, sys
json.dump({"bootkey0": json.load(open(sys.argv[1]))["bootkey0"]}, open(sys.argv[2], "w"))
PY
    confirm
    run picotool otp load "$key_json" ;;
  --lockdown)
    # After this the board boots only images signed by the key, with debug off. Boot key slots 1-3
    # are marked invalid so no other key can be installed later. The USB bootloader stays on, which is
    # how a signed monitor update is loaded; --lock-boot-pages is all that remains after this.
    need "$OTP_JSON" "run sign.sh --sign first"
    lock_json="$BOARD_DIR/lockdown.json"
    python3 - "$lock_json" <<'PY'
import json, sys
json.dump({"boot_flags1": {"key_valid": 1, "key_invalid": 14},
           "crit1": {"secure_boot_enable": 1, "debug_disable": 1}}, open(sys.argv[1], "w"))
PY
    confirm
    run picotool otp load "$lock_json" ;;
  --lock-boot-pages)
    # DO LAST, after the board has booted its signed image once. That boot sets ROLLBACK_REQUIRED in
    # BOOT_FLAGS0, on page 1, and the bootrom cannot boot an image whose version it could not record.
    confirm
    run picotool otp set -r "$BOOT_CONFIG_LOCK_ROW" "$BOOT_PAGES_LOCK"
    run picotool otp set -r "$BOOT_KEYS_LOCK_ROW" "$BOOT_PAGES_LOCK"
    run picotool otp set -r "$ROLLBACK_LOCK_ROW" "$ROLLBACK_LOCK" ;;
  *)
    usage ;;
esac
