#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Generate the RP2350 secure-boot signing key and sign the enrolled anchor firmware.
# See RUNBOOK.md. The signing private key must live OFFLINE/HSM — never on the appliance or in git.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELF="${ELF:-$HERE/../../target/thumbv8m.main-none-eabihf/release/dsm-anchor-pico}"
KEY="${KEY:-$HERE/bootkey.pem}"
SIGNED="$HERE/signed.elf"
OTP_JSON="$HERE/bootkey-otp.json"

case "${1:-}" in
  --genkey)
    [ -f "$KEY" ] && { echo "ERROR: $KEY exists — refusing to overwrite the enrolled signing key"; exit 1; }
    # RP2350 secure boot verifies a secp256k1 signature (RP2350 datasheet §5). Confirm the curve
    # your picotool/silicon expects before committing to it.
    openssl ecparam -name secp256k1 -genkey -noout -out "$KEY"
    chmod 600 "$KEY"
    echo "wrote $KEY — move to offline/HSM storage; NEVER commit it or copy it to the appliance" ;;
  --sign)
    [ -f "$KEY" ]  || { echo "ERROR: no $KEY — run '$0 --genkey' or supply KEY=…"; exit 1; }
    [ -f "$ELF" ]  || { echo "ERROR: no firmware ELF at $ELF — build --release --features secure-boot first"; exit 1; }
    # seal --sign: signs $ELF into $SIGNED and writes the key-fingerprint OTP rows into $OTP_JSON
    # (programmed later via 'picotool otp load bootkey-otp.json' — RUNBOOK step 4).
    picotool seal --sign "$ELF" "$SIGNED" "$KEY" "$OTP_JSON"
    echo "wrote $SIGNED (the ONLY image this device will run after lockdown) + $OTP_JSON" ;;
  *)
    echo "usage: $0 --genkey | --sign"; exit 2 ;;
esac
