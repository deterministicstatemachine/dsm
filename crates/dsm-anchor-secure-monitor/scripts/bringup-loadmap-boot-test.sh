#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# LOAD_MAP boot test on an UNLOCKED RP2350 dev board — proves the immutable bootrom executes the
# boot-block LOAD_MAP exactly as encoded (copies the flash payload into SRAM, clears Secure BSS,
# sets VTOR/MSP/MSPLIM, enters at the SRAM reset vector).
#
# THIS SCRIPT PERFORMS NO OTP WRITES. It only reads OTP (dump = read-only) to snapshot the
# unlocked state, flashes the test UF2 (fully reversible on an unlocked board), and reads back the
# Secure heartbeat. Keep the other two boards untouched as known-good references.
#
# Evidence model (no SWD probe needed): the reset code exists at its runtime VMA ONLY in SRAM.
# The vector-table + entry-point items send the bootrom to 0x20000000/0x200000f9 (SRAM). If the
# LOAD_MAP copy did not happen, that SRAM is garbage and nothing runs. The BSS-clear entry zeroes
# the heartbeat words themselves, so a sentinel + nonzero beat counter afterwards can only have
# been written by monitor code executing from Secure SRAM. Sentinel word0 = 0x44534D31 ("DSM1"),
# word1 = beat counter (>= 1).
#
# Usage:
#   1. Hold BOOTSEL, plug the chosen dev board in, release.        ./bringup-loadmap-boot-test.sh flash
#   2. Let it run ~5 s. Re-enter BOOTSEL WITHOUT losing power:
#      hold BOOTSEL and momentarily short RUN -> GND (power-cycling clears SRAM and destroys the
#      evidence).                                                   ./bringup-loadmap-boot-test.sh read
#
# NOTE: flashing overwrites whatever firmware the chosen board carried (e.g. the Pico anchor fw).
# Restore afterwards by rebuilding dsm-anchor-pico --release and flashing it back.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$HERE/.."
ELF="$CRATE/target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor"
OUT="${BRINGUP_OUT:-$CRATE/target/bringup}"     # never committed (target/ is gitignored)
HEARTBEAT_ADDR=0x200032A0                        # arm-none-eabi-nm <ELF> | grep DSM_SECURE_HEARTBEAT
SENTINEL="31 4d 53 44"                           # 0x44534D31 ("DSM1") little-endian byte order

mkdir -p "$OUT"

case "${1:-}" in
flash)
    [ -f "$ELF" ] || { echo "no monitor ELF — build --release first"; exit 2; }
    # Keep the heartbeat address pinned to the actual ELF (fails loudly if the layout moved).
    ACTUAL=$(arm-none-eabi-nm "$ELF" | awk '/DSM_SECURE_HEARTBEAT/{print "0x" $1}' | tr 'a-f' 'A-F')
    WANT=$(printf '%s' "$HEARTBEAT_ADDR" | tr 'a-fx' 'A-FX' | sed 's/0X/0x/')
    [ "$(printf '%s' "$ACTUAL" | sed 's/0X/0x/')" = "$WANT" ] || {
        echo "FAIL: DSM_SECURE_HEARTBEAT moved ($ACTUAL != $HEARTBEAT_ADDR) — update this script"; exit 1; }

    echo "== read-only OTP snapshot (unlocked-state reference; NO writes) =="
    picotool otp dump > "$OUT/otp-before-boot-test.txt"
    echo "   saved $OUT/otp-before-boot-test.txt"

    echo "== convert + flash (verify) + execute =="
    picotool uf2 convert "$ELF" -t elf "$OUT/loadmap-test.uf2"
    picotool info -a "$OUT/loadmap-test.uf2" | grep -E "load map|vector table|entry point" | head -5
    picotool load -v -x "$OUT/loadmap-test.uf2"
    echo ""
    echo "Monitor should now be running from SRAM. Wait ~5 s, then re-enter BOOTSEL WITHOUT"
    echo "power loss (hold BOOTSEL, short RUN->GND momentarily), then: $0 read"
    ;;
read)
    echo "== reading Secure heartbeat @ $HEARTBEAT_ADDR (SRAM survives reset, not power-off) =="
    HB="$OUT/heartbeat.bin"
    picotool save -r "$HEARTBEAT_ADDR" 0x200032A8 "$HB" -t bin
    xxd "$HB"
    W0=$(xxd -p -l4 "$HB")
    W1=$(xxd -p -s4 -l4 "$HB")
    if [ "$W0" = "314d5344" ] && [ "$W1" != "00000000" ]; then
        echo "PASS: sentinel DSM1 + beat counter present — the bootrom executed the LOAD_MAP"
        echo "      (copied flash->SRAM, cleared BSS, entered the SRAM monitor)."
    else
        echo "FAIL/INCONCLUSIVE: expected word0=$SENTINEL (DSM1) + word1!=0."
        echo "  - word0 zero/garbage + power was cut: SRAM lost — redo without power-cycling."
        echo "  - word0 zero, power kept: copy or entry did not happen — inspect with"
        echo "    'picotool info -a' on the flashed image and re-check the block encoding."
        exit 1
    fi
    ;;
*)
    echo "usage: $0 flash | read"; exit 2 ;;
esac
