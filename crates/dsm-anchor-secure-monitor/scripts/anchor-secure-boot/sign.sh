#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Generate the RP2350 secure-boot signing key, sign the enrolled anchor firmware, and write the
# digest of the Non-secure image that firmware measures. See RUNBOOK.md. The signing private key
# never goes on an appliance or in git.
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELF="${ELF:-$HERE/../../target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor}"
SECRET_DIR="${DSM_ANCHOR_SECRET_DIR:-$HOME/.dsm-anchor-secure-boot}"
KEY="${KEY:-$SECRET_DIR/bootkey.pem}"
BUILD_DIR="$SECRET_DIR/build"
mkdir -p "$BUILD_DIR"
chmod 700 "$SECRET_DIR"
SIGNED="$BUILD_DIR/signed.elf"
OTP_JSON="$BUILD_DIR/bootkey-otp.json"
MU_BIN="$BUILD_DIR/mu-enrolled.bin"
# The Non-secure image as signed. Its digest goes into OTP, so a later monitor update must carry these
# very bytes: build it with DSM_ANCHOR_NS_BIN naming a kept copy of this file.
NS_BIN="$BUILD_DIR/ns_app.bin"
# DSM_BOOTKEY_PASSIN names where openssl takes the passphrase from (openssl-passphrase-options), for a
# run with nobody at it. Unset, this script asks.
PASSIN="${DSM_BOOTKEY_PASSIN:-}"
# The image's version, covered by its signature. The bootrom refuses any image whose rollback version is
# below what this board has already booted, and records it at each boot of a higher one. An image with
# a real defect is retired by signing its successor with the next version. Starts at 1: version 0 does
# not set ROLLBACK_REQUIRED (RP2350 datasheet, "Rollback versions and bootloaders").
IMAGE_MAJOR=1
IMAGE_MINOR=0
ROLLBACK_VERSION=1
# Page 44, rows 0-2: the bootrom keeps it in three raw rows, majority-voted, which hold versions up to
# 23. Off the boot configuration's page, which --lock-boot-pages closes to Secure writes: a later
# version could not be recorded there and the image would not boot. MUST equal ROLLBACK_ROW in
# provision-otp.sh, and an image with more versions than these lists further groups after them.
# picotool reads a row number as hex, written with or without its 0x.
ROLLBACK_ROW="$(printf '0x%x' $(( 44 * 64 )))"

# The passphrase, read here and handed to openssl through the environment of this one process.
ask_passphrase() { # [new]
  [ -z "$PASSIN" ] || return 0
  IFS= read -rsp "Boot key passphrase: " DSM_BOOTKEY_PASSPHRASE; echo
  if [ "${1:-}" = new ]; then
    IFS= read -rsp "Again: " again; echo
    [ "$DSM_BOOTKEY_PASSPHRASE" = "$again" ] || { echo "ERROR: they differ"; exit 1; }
    [ "${#DSM_BOOTKEY_PASSPHRASE}" -ge 16 ] || { echo "ERROR: 16 characters at least"; exit 1; }
  fi
  export DSM_BOOTKEY_PASSPHRASE
  PASSIN="env:DSM_BOOTKEY_PASSPHRASE"
}

case "${1:-}" in
  --genkey)
    [ -f "$KEY" ] && { echo "ERROR: $KEY exists — refusing to overwrite the enrolled signing key"; exit 1; }
    # RP2350 secure boot verifies a secp256k1 signature (RP2350 datasheet §5).
    # Encrypted from its first byte: the key is never on disk without its passphrase. A leaked file is then not a leaked key, and a lost passphrase is a lost key.
    ask_passphrase new
    # The key arrives whole or not at all: a file left behind by a failure would pass for one.
    openssl ecparam -name secp256k1 -genkey -noout | openssl ec -aes256 -out "$KEY.new" -passout "$PASSIN" 2>/dev/null
    mv "$KEY.new" "$KEY"
    chmod 600 "$KEY"
    echo "wrote $KEY, encrypted — keep a copy and its passphrase offline, apart; NEVER commit it or copy it to an appliance" ;;
  --sign)
    [ -f "$KEY" ]  || { echo "ERROR: no $KEY — run '$0 --genkey' or supply KEY=…"; exit 1; }
    grep -q ENCRYPTED "$KEY" || { echo "ERROR: $KEY is not encrypted — a signing key is never kept in the clear"; exit 1; }
    [ -f "$ELF" ]  || { echo "ERROR: no firmware ELF at $ELF — build --release --features production first"; exit 1; }
    # Only a production image is ever signed: the trial image and the production one build to one path.
    symbols="$(arm-none-eabi-nm "$ELF")"
    grep -q ' DSM_ANCHOR_PRODUCTION_IMAGE$' <<<"$symbols" || {
      echo "ERROR: $ELF is not a production image — build --release --features production first"; exit 1; }
    # An existing OTP file would be edited in place: every signing starts from nothing. The kept
    # Non-secure image is another matter: a burned board's digest is of those bytes.
    rm -f "$SIGNED" "$OTP_JSON" "$MU_BIN"
    # seal --sign: signs $ELF into $SIGNED and writes the key-fingerprint OTP rows, the key's valid
    # flag and SECURE_BOOT_ENABLE into $OTP_JSON. provision-otp.sh splits those apart.
    # picotool reads the key in the clear, so it gets a copy that lives only as long as this signing.
    CLEAR_DIR="$(mktemp -d)"
    trap 'rm -rf "$CLEAR_DIR"' EXIT
    ask_passphrase
    opened=0; openssl ec -in "$KEY" -out "$CLEAR_DIR/key.pem" -passin "$PASSIN" </dev/null 2>/dev/null || opened=$?
    [ "$opened" = 0 ] || { echo "ERROR: $KEY did not open: is that its passphrase?"; exit 1; }
    picotool seal --sign "$ELF" -t elf "$SIGNED" "$CLEAR_DIR/key.pem" "$OTP_JSON" --major "$IMAGE_MAJOR" --minor "$IMAGE_MINOR" --rollback "$ROLLBACK_VERSION" "$ROLLBACK_ROW"
    rm -rf "$CLEAR_DIR"
    # The digest the monitor compares before every authority op (main.rs `measurement_ok`): BLAKE3
    # over the bytes from __ns_rx_start to __ns_rx_end, which is the head of the .ns_app image.
    python3 - "$ELF" "$SIGNED" "$MU_BIN" "$NS_BIN" <<'PY'
import subprocess, sys, tempfile, os
elf, signed, out, ns_out = sys.argv[1:]
symbols = {}
for line in subprocess.check_output(["arm-none-eabi-nm", elf], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        symbols[fields[2]] = int(fields[0], 16)
start, end = symbols["__ns_rx_start"], symbols["__ns_rx_end"]
if symbols["__ns_app_vector_table"] != start:
    sys.exit(f"ERROR: the Non-secure image does not start at the measured window")
with tempfile.TemporaryDirectory() as scratch:
    image_path = os.path.join(scratch, "ns_app.bin")
    subprocess.check_call(["arm-none-eabi-objcopy", "-O", "binary", "--only-section=.ns_app", elf, image_path])
    image = open(image_path, "rb").read()
window = end - start
if len(image) < window:
    sys.exit(f"ERROR: the Non-secure image is {len(image)} bytes and the measured window {window}: "
             "bytes the loader does not copy would be measured")
measured = image[:window]
if measured not in open(signed, "rb").read():
    sys.exit("ERROR: the signed image does not hold the measured bytes")
if os.path.exists(ns_out) and open(ns_out, "rb").read() != image:
    os.remove(signed)
    sys.exit(f"ERROR: this image's Non-secure app is not the one kept at {ns_out}, and a burned board "
             "refuses any other. Build with DSM_ANCHOR_NS_BIN naming that file. If no board was ever "
             "burned with it, move it aside and sign again.")
digest = subprocess.run(["b3sum", "--raw"], input=measured, capture_output=True, check=True).stdout
if len(digest) != 32:
    sys.exit(f"ERROR: the digest is {len(digest)} bytes")
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(digest)
if not os.path.exists(ns_out):
    with open(ns_out, "wb") as f:
        f.write(image)
print(f"wrote {out}: the digest of the {window}-byte measured window")
print(f"holding {ns_out}: the image it is the digest of. Keep it with bootkey.pem")
PY
    echo "wrote $SIGNED + $OTP_JSON" ;;
  *)
    echo "usage: $0 --genkey | --sign"; exit 2 ;;
esac
