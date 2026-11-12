#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The production release a phone burns boards toward (owner, 2026-11-11: a board's one-time burns are
# done from the phone). Copies the signing's public outputs into the wallet's assets, where the board
# setup reads them, before the APK is built. Nothing secret moves: the signed image, its Non-secure app,
# that app's digest and the boot key's hash. The boot key never leaves ~/.dsm-anchor-secure-boot.
#
# usage: scripts/anchor-release-into-app.sh [the signing's build directory]
#        (also builds the lock image, crates/dsm-anchor-lock-pages, for the boards that need it)
#        (default ~/.dsm-anchor-secure-boot/build, where sign.sh --sign writes)
set -euo pipefail
BUILD="${1:-$HOME/.dsm-anchor-secure-boot/build}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/dsm_client/android/app/src/main/assets/anchor-release"
for f in signed.elf ns_app.bin mu-enrolled.bin bootkey-otp.json; do
  [ -f "$BUILD/$f" ] || { echo "ERROR: no $BUILD/$f: run sign.sh --sign first"; exit 1; }
done
mkdir -p "$OUT"
cp "$BUILD/signed.elf" "$BUILD/ns_app.bin" "$BUILD/mu-enrolled.bin" "$OUT/"
# picotool's OTP file names the boot key's hash `bootkey0`, 32 bytes; the app takes those bytes alone,
# so no JSON reaches the phone.
python3 - "$BUILD/bootkey-otp.json" "$OUT/bootkey0.bin" <<'PY'
import json, sys
key = json.load(open(sys.argv[1]))["bootkey0"]
if len(key) != 32:
    sys.exit(f"ERROR: bootkey0 is {len(key)} bytes, not 32")
open(sys.argv[2], "wb").write(bytes(key))
PY
# The lock image (crates/dsm-anchor-lock-pages): for a board whose USB bootloader may not write the
# page locks its Secure code may (an RP2350 A2 with page 63 closed to the bootloader), the phone loads
# and starts it once after the digest. Built here from this checkout; never signed, and it runs only
# before the lockdown.
LOCK_CRATE="$(cd "$(dirname "$0")/.." && pwd)/crates/dsm-anchor-lock-pages"
(cd "$LOCK_CRATE" && cargo build --release --locked)
cp "$LOCK_CRATE/target/thumbv8m.main-none-eabihf/release/dsm-anchor-lock-pages" "$OUT/lock-pages.elf"
echo "the app carries the release: $(cd "$OUT" && ls | tr '\n' ' ')"
