#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# IRREVERSIBLE RP2350 OTP provisioning for the DSM anchor. Dry-run by default; every burn requires
# --commit AND typing YES. See RUNBOOK.md. Rehearse on a spent board before a new one.
set -euo pipefail
# Everything this script writes is the operator's alone.
umask 077
# The board's sealed secret is its identity root, and the board makes it itself at its first signed
# boot (DSM Amendment A38): nothing here draws, holds or writes it. This directory keeps only what
# the procedure records of each board (its chip id), outside the repository, one directory per board.
SECRET_DIR="${DSM_ANCHOR_SECRET_DIR:-$HOME/.dsm-anchor-secure-boot}"
BUILD_DIR="$SECRET_DIR/build"
# page 49, row 0 — MUST equal SEALED_SECRET_PAGE in ../../src/sealed.rs. Page 48 held a secret drawn on
# a computer by an earlier procedure; nothing reads it.
SECRET_PAGE=49
SECRET_ROW=$(( SECRET_PAGE * 64 ))
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
# The board's own seal, written by its signed image and never here: begun (Secure still writing,
# Non-secure and the bootloader barred), then done (Secure reads, nothing writes). The USB bootloader
# never serves the secret, and may read back the digest, which is public.
SECRET_LOCK_ROW=$(( 0xf80 + 2 * SECRET_PAGE + 1 ))
SEAL_BEGUN=$(lock_row_value "$LOCK_READ_WRITE" "$LOCK_INACCESSIBLE" "$LOCK_INACCESSIBLE")
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

COMMIT=0; CMD=""; BOARD=""; SER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --commit) COMMIT=1 ;;
    --board) shift; BOARD="${1:-}" ;;
    --ser) shift; SER="${1:-}" ;;
    --*) CMD="$1" ;;
    *) echo "ERROR: unexpected argument $1"; exit 2 ;;
  esac
  shift
done

usage() {
  echo "usage: $0 --board <name> --ser <chip id> [--check-blank | --write-digest | --lock-pages |"
  echo "                           --write-bootkey | --lockdown | --lock-boot-pages] [--commit]"
  echo "  <chip id> is the board's RP2350 chip id as BOOTSEL reports it (picotool info -d: chipid),"
  echo "  16 hexadecimal digits. Every picotool call names it, so nothing reaches another board."
  exit 2
}
[ -n "$CMD" ] || usage
[ -n "$BOARD" ] || { echo "ERROR: --board names the board: every board is recorded by its chip id"; usage; }
case "$BOARD" in *[!A-Za-z0-9_-]*) echo "ERROR: a board name is letters, digits, - and _"; exit 2 ;; esac
# The chip id as the USB bootloader gives it for its serial number: upper case, no 0x.
SER="$(printf '%s' "$SER" | tr '[:lower:]' '[:upper:]')"
SER="${SER#0X}"
case "$SER" in
  [0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]) ;;
  *) echo "ERROR: --ser names the board's chip id, 16 hexadecimal digits"; usage ;;
esac
BOARD_DIR="$SECRET_DIR/boards/$BOARD"
mkdir -p "$BOARD_DIR"
chmod 700 "$SECRET_DIR" "$SECRET_DIR/boards" "$BOARD_DIR"
# A board's name stands for one chip for good: the first run records its chip id, and any later run
# under that name for another chip stops before it reads or writes anything.
if [ -f "$BOARD_DIR/chip-id" ]; then
  [ "$(cat "$BOARD_DIR/chip-id")" = "$SER" ] || {
    echo "ERROR: board '$BOARD' is chip $(cat "$BOARD_DIR/chip-id"), not $SER"; exit 1; }
else
  printf '%s\n' "$SER" > "$BOARD_DIR/chip-id"
fi
MU_BIN="$BUILD_DIR/mu-enrolled.bin"
OTP_JSON="$BUILD_DIR/bootkey-otp.json"

# picotool, always at this one board: the device selection goes last on every command.
pt() { picotool "$@" --ser "$SER"; }
run() { # pt <args>: printed as the picotool command it is
  shift
  if [ "$COMMIT" = 1 ]; then echo "+ picotool $* --ser $SER"; pt "$@"; else echo "[dry-run] picotool $* --ser $SER"; fi
}
# What the board's secret page holds, read fresh (READ-ONLY): `blank` before the signed image's first
# boot; `begun` or `sealed` once the board has begun or finished sealing its own secret there. Anything
# else is a page someone else wrote, and it stops. The lock row decides: once the board has begun its
# seal the USB bootloader has no access to the page, so the rows themselves read as nothing here. The
# dump is a private temporary file, gone when this returns.
secret_page() {
  local dump
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN
  pt otp dump -r --output "$dump" >/dev/null
  python3 - "$dump" "$SECRET_ROW" "$SECRET_LOCK_ROW" "$SECRET_LOCK" "$SEAL_BEGUN" <<'PAGE'
import struct, sys
data = open(sys.argv[1], "rb").read()
rows = [word & 0xffffff for (word,) in struct.iter_unpack("<I", data)]
if len(rows) != 4096:
    sys.exit(f"ERROR: the dump holds {len(rows)} rows, not 4096")
secret, lock_row = int(sys.argv[2]), int(sys.argv[3])
sealed, begun = int(sys.argv[4], 16), int(sys.argv[5], 16)
written = [hex(r) for r in range(secret, secret + 16) if rows[r] != 0]
if rows[lock_row] == sealed:
    print("sealed")
elif rows[lock_row] == begun:
    print("begun")
elif not written and rows[lock_row] == 0:
    print("blank")
else:
    sys.exit(f"ERROR: the secret page is neither blank nor sealed as the board seals it: "
             f"rows written {written}, lock row {hex(rows[lock_row])} (expected 0, {hex(begun)} or {hex(sealed)}). "
             "Someone other than the board wrote it; nothing here goes on with it.")
PAGE
}
confirm() {
  [ "$COMMIT" = 1 ] || return 0
  pt info -d || true
  read -r -p "IRREVERSIBLE OTP BURN on board '$BOARD', chip $SER. Is that this board? Type YES to proceed: " x
  [ "$x" = "YES" ] || { echo "aborted"; exit 1; }
}
need() { [ -f "$1" ] || { echo "ERROR: no $1 — $2"; exit 1; }; }

case "$CMD" in
  --check-blank)
    # READ-ONLY. Every row this procedure writes must still be zero, and the secret's page blank, with
    # no access key, for the board to seal its own secret at its first boot (DSM Amendment A38). The
    # kept dump holds no secret: none is on the board yet.
    page="$(secret_page)"
    [ "$page" = blank ] || { echo "ERROR: page $SECRET_PAGE, where the board seals its own secret, is not blank before anything is burned ($page): someone else wrote it"; exit 1; }
    dump="$BOARD_DIR/otp-before.bin"
    pt otp dump -r --output "$dump"
    python3 - "$dump" "$SECRET_ROW" "$DIGEST_ROW" "$ROLLBACK_ROW" "$page" \
      "$SECRET_LOCK" "$DIGEST_LOCK" "$ROLLBACK_LOCK" "$BOOT_PAGES_LOCK" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
rows = [word & 0xffffff for (word,) in struct.iter_unpack("<I", data)]
if len(rows) != 4096:
    sys.exit(f"ERROR: the dump holds {len(rows)} rows, not 4096")
secret, digest, rollback, page = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
secret_lock, digest_lock, rollback_lock, boot_lock = (int(v, 16) for v in sys.argv[6:10])
def lock0(page_no): return 0xf80 + 2 * page_no
def lock1(page_no): return 0xf80 + 2 * page_no + 1
# Rows this procedure writes data into: they must hold nothing.
watched = {"digest": range(digest, digest + 16),
           "boot key 0": range(0x80, 0x90), "CRIT1": range(0x40, 0x48), "BOOT_FLAGS1": range(0x4b, 0x4e),
           "rollback version": range(rollback, rollback + 3), "BOOT_FLAGS0": range(0x48, 0x4b),
           # The pages' access keys, which this procedure never sets.
           "page locks' access keys": [lock0(1), lock0(2), lock0(44), lock0(46), lock0(secret // 64)],
           "the board's own secret": range(secret, secret + 16)}
# Lock rows this procedure burns, with what it burns: one may already hold bits, as long as each of
# them is among those (OTP only sets bits, so such a row still takes the burn and ends as intended).
locks = {"boot configuration page lock": (lock1(1), boot_lock), "boot key page lock": (lock1(2), boot_lock),
         "rollback page lock": (lock1(44), rollback_lock), "digest page lock": (lock1(46), digest_lock)}
used = {name: [hex(r) for r in span if rows[r] != 0] for name, span in watched.items()}
used = {name: found for name, found in used.items() if found}
for name, (row, burned) in locks.items():
    if rows[row] & ~burned & 0xffffff:
        used[name] = [f"{hex(row)} holds {hex(rows[row])}, bits outside the {hex(burned)} this procedure burns"]
if used:
    sys.exit(f"ERROR: this board is not blank where the procedure writes: {used}")
for name, (row, burned) in locks.items():
    if rows[row]:
        print(f"{name} already holds {hex(rows[row])}, all of it within the {hex(burned)} this procedure burns there")
print("blank where the procedure writes, the secret's page blank for the board to seal its own")
PY
    ;;
  --write-digest)
    need "$MU_BIN" "run sign.sh --sign first"
    confirm
    run pt otp load -e -s "$DIGEST_ROW" "$MU_BIN" -t bin ;;
  --lock-pages)
    # The digest page alone: the secret's page is the board's to lock, at its first boot.
    confirm
    run pt otp set -r "$DIGEST_LOCK_ROW" "$DIGEST_LOCK" ;;
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
    run pt otp load "$key_json" ;;
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
    run pt otp load "$lock_json" ;;
  --lock-boot-pages)
    # DO LAST, after the board has booted its signed image once. That boot sets ROLLBACK_REQUIRED in
    # BOOT_FLAGS0, on page 1, and the bootrom cannot boot an image whose version it could not record.
    confirm
    run pt otp set -r "$BOOT_CONFIG_LOCK_ROW" "$BOOT_PAGES_LOCK"
    run pt otp set -r "$BOOT_KEYS_LOCK_ROW" "$BOOT_PAGES_LOCK"
    run pt otp set -r "$ROLLBACK_LOCK_ROW" "$ROLLBACK_LOCK" ;;
  *)
    usage ;;
esac
