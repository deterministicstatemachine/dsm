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

echo "== polling for self-entry into BOOTSEL (pass window 4..180 s) =="
START=$(date +%s)
sleep 4     # exclude the <2 s ROM-rejection window
for _ in $(seq 1 88); do
    if picotool info -d >/dev/null 2>&1; then
        NOW=$(date +%s)
        echo "PASS: device re-entered BOOTSEL BY ITSELF after $((NOW - START)) s —"
        echo "      the bootrom performed the LOAD_MAP copy and entered the SRAM monitor."
        picotool info -d 2>&1 | grep -E "chipid|secure boot|debug"
        exit 0
    fi
    sleep 2
done
echo "FAIL: no self-reboot within 180 s — the monitor never reached the reboot call."
echo "      (Chip likely locked up: copy or SRAM entry did not happen. Re-check the block"
echo "      encoding with 'picotool info -a' and the linker map.)"
exit 1
