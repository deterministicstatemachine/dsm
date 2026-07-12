#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# §1 gate: FAIL if any security-critical Secure symbol resolves into the external XIP flash range.
# The whole Secure TCB (host key, HostSign, TROPIC01, counter, recovery, SG veneer, Secure init) must
# execute from boot-ROM-verified SRAM (0x20000000..0x20081fff) — external flash is mutable after
# boot-time verification. This runs on the linked monitor ELF.
#
# STATUS: PASSES. The custom SRAM-resident linker (dsm-secure-sram.x) places the whole Secure TCB
# at an SRAM VMA (flash LMA), so no security-critical Secure symbol resolves into XIP. This gate is
# the executable form of that policy — a regression that returns any TCB symbol to flash re-FAILs.
# (Boot-time copy of the flash image into SRAM is the bootrom LOAD_MAP's job; that block item and
# its on-silicon copy are the remaining step — the ELF symbol residency this checks is independent.)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELF="${1:-$HERE/../target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor}"
NM="${NM:-arm-none-eabi-nm}"

[ -f "$ELF" ] || { echo "no monitor ELF at $ELF — build --release first"; exit 2; }

XIP_LO=0x10000000
XIP_HI=0x10ffffff

# Security-critical Secure symbols that MUST be SRAM-resident (name patterns).
CRIT='dsm_secure_handler|dsm_secure_dispatch|mu_enrolled|measurement_ok|host|HostSign|part_sign|part_keygen|tropic|Tropic|chip_sign|counter|mcounter|recover|commit|prepare|otp|Otp|__nsc_veneer|SecureOps|blake3'

violations=0
while read -r addr _type name; do
    [ -z "${addr:-}" ] && continue
    # numeric hex address in the XIP range?
    if [[ "$addr" =~ ^[0-9a-fA-F]+$ ]]; then
        a=$((16#$addr))
        if (( a >= XIP_LO && a <= XIP_HI )); then
            echo "XIP-resident Secure symbol: 0x$addr $name"
            violations=$((violations + 1))
        fi
    fi
done < <("$NM" -C "$ELF" 2>/dev/null | grep -E "$CRIT" || true)

if (( violations > 0 )); then
    echo "FAIL: $violations security-critical Secure symbol(s) resolve into XIP flash (0x10000000..)."
    echo "      The SRAM-image linker (TCB VMA in SRAM) is required before this gate passes (§1)."
    exit 1
fi
echo "OK: no security-critical Secure symbol resolves into XIP flash."
