#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The production release a phone burns boards toward (owner, 2026-11-11: a board's one-time burns are
# done from the phone). Copies the signing's public outputs into the wallet's assets, where the board
# setup reads them, before the APK is built. Nothing secret moves: the signed image, its Non-secure app,
# that app's digest and the boot key's hash. The boot key never leaves ~/.dsm-anchor-secure-boot.
#
# usage: scripts/anchor-release-into-app.sh [the signing's build directory]
#        (default ~/.dsm-anchor-secure-boot/build, where sign.sh --sign writes)
#        (also builds the images the phone starts before and during the burns: the lock image,
#        crates/dsm-anchor-lock-pages, and the prepare and trial images, crates/dsm-anchor-secure-monitor)
set -euo pipefail
# Absolute, as the image builds below run from their own crates.
BUILD="$(cd "${1:-$HOME/.dsm-anchor-secure-boot/build}" && pwd)"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/dsm_client/android/app/src/main/assets/anchor-release"
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
LOCK_CRATE="$REPO/crates/dsm-anchor-lock-pages"
(cd "$LOCK_CRATE" && cargo build --release --locked)
cp "$LOCK_CRATE/target/thumbv8m.main-none-eabihf/release/dsm-anchor-lock-pages" "$OUT/lock-pages.elf"
# The prepare and the trial image (the secure monitor built with `prepare_chip`, and with
# `bench_self_enroll` alone): the phone loads and starts them before a board's first burn, the prepare
# image on a test part whose PTRNG Tropic Square left unconfigured, and the trial image for the try-run
# on that very board. Built here from this checkout around the signing's own Non-secure app, so the
# try-run goes through the app the board is burned for. Never signed: neither runs once the board is
# locked down, and the trial image refuses once its digest is burned. Both build to one path, so each
# is copied straight after its build.
MONITOR="$REPO/crates/dsm-anchor-secure-monitor"
MONITOR_ELF="$MONITOR/target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor"
(cd "$MONITOR" && DSM_ANCHOR_NS_BIN="$BUILD/ns_app.bin" cargo build --release --locked --features bench_self_enroll,prepare_chip)
cp "$MONITOR_ELF" "$OUT/prepare-chip.elf"
(cd "$MONITOR" && DSM_ANCHOR_NS_BIN="$BUILD/ns_app.bin" cargo build --release --locked --features bench_self_enroll)
cp "$MONITOR_ELF" "$OUT/trial.elf"
echo "the app carries the release: $(cd "$OUT" && ls | tr '\n' ' ')"
