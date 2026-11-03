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

case "${1:-}" in
  --genkey)
    [ -f "$KEY" ] && { echo "ERROR: $KEY exists — refusing to overwrite the enrolled signing key"; exit 1; }
    # RP2350 secure boot verifies a secp256k1 signature (RP2350 datasheet §5).
    openssl ecparam -name secp256k1 -genkey -noout -out "$KEY"
    chmod 600 "$KEY"
    echo "wrote $KEY — keep a copy offline; NEVER commit it or copy it to an appliance" ;;
  --sign)
    [ -f "$KEY" ]  || { echo "ERROR: no $KEY — run '$0 --genkey' or supply KEY=…"; exit 1; }
    [ -f "$ELF" ]  || { echo "ERROR: no firmware ELF at $ELF — build --release --features production first"; exit 1; }
    # An existing OTP file would be edited in place: every signing starts from nothing.
    rm -f "$SIGNED" "$OTP_JSON" "$MU_BIN"
    # seal --sign: signs $ELF into $SIGNED and writes the key-fingerprint OTP rows, the key's valid
    # flag and SECURE_BOOT_ENABLE into $OTP_JSON. provision-otp.sh splits those apart.
    picotool seal --sign "$ELF" -t elf "$SIGNED" "$KEY" "$OTP_JSON"
    # The digest the monitor compares before every authority op (main.rs `measurement_ok`): BLAKE3
    # over the bytes from __ns_rx_start to __ns_rx_end, which is the head of the .ns_app image.
    python3 - "$ELF" "$SIGNED" "$MU_BIN" <<'PY'
import subprocess, sys, tempfile, os
elf, signed, out = sys.argv[1:]
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
digest = subprocess.run(["b3sum", "--raw"], input=measured, capture_output=True, check=True).stdout
if len(digest) != 32:
    sys.exit(f"ERROR: the digest is {len(digest)} bytes")
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(digest)
print(f"wrote {out}: the digest of the {window}-byte measured window")
PY
    echo "wrote $SIGNED + $OTP_JSON" ;;
  *)
    echo "usage: $0 --genkey | --sign"; exit 2 ;;
esac
