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

echo "== timing the self-reboot (the Secure handler delays ~13 s before rebooting) =="
# Outcome map for the NS-launch build:
#   in BOOTSEL at 6 s        -> TOO FAST: ROM rejected the block or an early fault (FAIL)
#   BOOTSEL appears ~8..60 s -> PASS: the Secure handler ran (NS launched + crossed the SG)
#   never                    -> TIMEOUT: NS launch / SG failed, handler never reached (FAIL)
START=$(date +%s)
sleep 6
if picotool info -d >/dev/null 2>&1; then
    echo "FAIL (too fast, $(( $(date +%s) - START )) s): in BOOTSEL before the ~13 s handler delay —"
    echo "     the ROM rejected the block or the monitor faulted before the NS launch. Check"
    echo "     'picotool info -a' block decode and the linker map."
    exit 1
fi
for _ in $(seq 1 30); do
    if picotool info -d >/dev/null 2>&1; then
        NOW=$(date +%s)
        echo "PASS: self-reboot at $((NOW - START)) s (matches the ~13 s handler delay) —"
        echo "      the Non-secure app launched, crossed the NSC sg veneer into Secure, and the"
        echo "      Secure handler read the NS mailbox (state/seq/opcode) and rebooted."
        picotool info -d 2>&1 | grep -E "chipid|secure boot|debug"
        exit 0
    fi
    sleep 2
done
echo "FAIL (timeout): no reboot within ~66 s. NS launch or the SG transition did not complete"
echo "     (bad BXNS / SAU attribution / veneer), so the handler was never reached."
exit 1
