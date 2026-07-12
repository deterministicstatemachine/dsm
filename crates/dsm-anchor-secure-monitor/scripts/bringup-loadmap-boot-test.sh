#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# LOAD_MAP boot test on an UNLOCKED RP2350 dev board — proves the immutable bootrom executes the
# boot-block LOAD_MAP exactly as encoded (copies the flash payload into SRAM, sets MSP/MSPLIM,
# enters at the SRAM reset vector).
#
# THIS SCRIPT PERFORMS NO OTP WRITES. It only reads OTP (dump = read-only) to snapshot the
# unlocked state, and flashes the test UF2 (fully reversible on an unlocked board).
#
# Evidence model — self-reboot, NOT SRAM readback:
#   The RP2350 bootrom CLEARS main SRAM on BOOTSEL entry (proven empirically 2026-07-12 on chip
#   0x430ed6d919933c8e: a marker written in BOOTSEL was gone after a BOOTSEL->BOOTSEL reboot with
#   no app run in between). Post-hoc SRAM reads are therefore an INVALID evidence channel here.
#   Instead, the monitor's bringup diagnostic self-reboots into BOOTSEL after ~10 beats (~30 s).
#   The monitor's code exists only at its SRAM VMA — if the LOAD_MAP copy had not run, the entry
#   point is garbage and the chip locks up (the fault handlers are SRAM-resident too, so there is
#   no false path into BOOTSEL). ROM *rejection* of the image re-enters BOOTSEL in <2 s, which the
#   pass window excludes. The device re-appearing in BOOTSEL by itself after a delay therefore
#   proves the boot path executed from Secure SRAM.
#
# FIRST SILICON PASS: 2026-07-12, chip 0x430ed6d919933c8e (secure boot: 0, debug: 1) — self-reboot
# after 28 s.
#
# Usage: hold BOOTSEL, plug the board in, release, then:   ./bringup-loadmap-boot-test.sh test
#
# NOTE: flashing overwrites whatever firmware the board carried (e.g. the Pico anchor fw).
# Restore afterwards by rebuilding dsm-anchor-pico --release and flashing it back.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$HERE/.."
ELF="$CRATE/target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor"
OUT="${BRINGUP_OUT:-$CRATE/target/bringup}"     # never committed (target/ is gitignored)

[ "${1:-}" = "test" ] || { echo "usage: $0 test"; exit 2; }
[ -f "$ELF" ] || { echo "no monitor ELF — build --release first"; exit 2; }
mkdir -p "$OUT"

echo "== read-only OTP snapshot (unlocked-state reference; NO writes) =="
picotool otp dump > "$OUT/otp-before-boot-test.txt"
echo "   saved $OUT/otp-before-boot-test.txt"

echo "== convert + flash (verify) + execute =="
picotool uf2 convert "$ELF" -t elf "$OUT/loadmap-test.uf2"
picotool info -a "$OUT/loadmap-test.uf2" | grep -E "load map|vector table|entry point" | head -5
picotool load -v -x "$OUT/loadmap-test.uf2"

echo "== timing the self-reboot to classify the boundary outcome =="
# The monitor encodes the outcome in the reboot delay (SRAM readback is dead on BOOTSEL entry):
#   < 4 s  ......... TOO FAST : ROM rejected the block / faulted before anything ran
#   ~11 s (4..30) .. DENIED   : an NS access trapped to the Secure fault handler
#   ~50 s (30..90) . SG-PATH  : NS reached the Secure Gateway with no fault (access ALLOWED)
#   never .......... TIMEOUT  : NS launch / SG did not complete
# The caller decides PASS/FAIL: a denial-probe build wants DENIED; a plain round-trip wants SG-PATH.
START=$(date +%s)
sleep 4
if picotool info -d >/dev/null 2>&1; then
    echo "RESULT: TOO-FAST ($(( $(date +%s) - START )) s) — ROM rejected the block or an early fault."
    exit 2
fi
for _ in $(seq 1 45); do
    if picotool info -d >/dev/null 2>&1; then
        T=$(( $(date +%s) - START ))
        if [ "$T" -lt 30 ]; then
            echo "RESULT: DENIED (self-reboot at ${T} s ~ the Secure-fault delay) — the Non-secure"
            echo "        access faulted into the Secure fault handler. Boundary blocked it."
        else
            echo "RESULT: SG-PATH (self-reboot at ${T} s ~ the Secure-Gateway delay) — NS reached the"
            echo "        gateway with no fault (a denial probe reaching here means ACCESS ALLOWED)."
        fi
        exit 0
    fi
    sleep 2
done
echo "RESULT: TIMEOUT (no reboot within ~94 s) — NS launch or the SG transition did not complete."
exit 1
