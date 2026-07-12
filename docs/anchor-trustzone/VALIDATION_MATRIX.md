# DSM anchor RP2350 — validation matrix (§11)

The measurement boundary is **not** complete because the firmware builds. It is complete only when
every row below passes — the host-automatable ones in CI, the hardware-boundary ones on a
provisioned silicon board. Until then the property is **"implemented, activation and silicon
validation pending,"** never "proven" or "deployed."

Legend — **Where:** `host` = automatable off-device (unit/integration test); `silicon` = requires a
provisioned RP2350 board.

| # | Test | Expected | Where | Status |
|---|---|---|---|---|
| 0 | bootrom executes the boot-block LOAD_MAP (flash→SRAM copy, MSP/MSPLIM, SRAM entry) | monitor runs from Secure SRAM | silicon | **PASS 2026-07-12** (unlocked board, unsigned image) |
| 1 | Correct monitor + exact app | boot succeeds; committed `HostSign` succeeds | silicon | pending |
| 2 | One app byte changed | `measurement_ok=false`; `HostSign` unavailable | silicon (host: measure fn) | pending |
| 3 | Different app signed by the same signing infra | measurement still fails | silicon | pending |
| 4 | Non-secure OTP read | denied (hardware permission) | silicon | pending |
| 5 | Non-secure TROPIC SPI access | denied (SAU/ACCESSCTRL) | silicon | pending |
| 6 | Non-secure DMA → protected SRAM/SPI | denied | silicon | pending |
| 7 | Arbitrary Secure Gateway signing request | rejected (no oracle) | host (API) + silicon | pending |
| 8 | `sg_prepare` | no chip or host signature; no counter move | host + silicon | pending |
| 9 | prepare / abort / re-prepare | no signatures produced | host + silicon | pending |
| 10 | one `sg_commit` | exactly one counter decrement + one committed message | silicon | pending |
| 11 | second distinct commit from same origin | rejected | host + silicon | pending |
| 12 | power loss BEFORE decrement | safe cancel OR exact completion | silicon | pending |
| 13 | power loss AFTER decrement, BEFORE signatures | only the committed message is signed | silicon | pending |
| 14 | power loss AFTER signatures, BEFORE export | same package re-emitted | silicon | pending |
| 15 | external flash modified after app loaded | running SRAM image + measurement unaffected | silicon | pending |
| 16 | debug access after provisioning | denied | silicon | pending |
| 17 | unsigned monitor | rejected by bootrom | silicon | pending |
| 18 | device with different OTP secret | cannot reproduce the same host key | silicon (host: HKDF determinism) | pending |
| 19 | bench build | cannot create a production-compatible enrollment bundle | host (domain-tag separation) | pending |
| 20 | any fallback exposing HostSign when measurement fails | none exists | host (code audit) + silicon | pending |

## Silicon results so far

**Row 0 — 2026-07-12, chip `0x430ed6d919933c8e` (unlocked: secure boot 0, debug 1), unsigned image.**
Method: the monitor's bringup diagnostic self-reboots into BOOTSEL after ~10 beats; its code exists
only at the SRAM VMA, so self-entry into BOOTSEL after 28 s (vs <2 s for ROM rejection; lockup for a
failed copy — the fault handlers are SRAM-resident too) proves the ROM accepted the hand-encoded
PICOBIN block, performed the LOAD_MAP copy, and entered at the SRAM entry point with a working
MSPLIM. See `crates/dsm-anchor-secure-monitor/scripts/bringup-loadmap-boot-test.sh`.

Discovered en route (binding for all future rows): **the RP2350 bootrom clears main SRAM on BOOTSEL
entry** — a marker written in BOOTSEL vanished across a BOOTSEL→BOOTSEL reboot with no app run in
between. Post-hoc SRAM readback is an invalid evidence channel; use self-reboot, GPIO, or SWD.

Row 0 does NOT yet prove: the VECTOR_TABLE item's VTOR took effect (no exception fired), the NSC
veneer copy executed correctly (nothing calls it until the step-5 NS launch), the hashed/sealed
image path, or any secure-boot behavior. Those remain with their own rows.

**Row 0a (SAU enable) — 2026-07-12, same chip.** The monitor programs SAU (region 0 = NSC veneer
[0x20040000,0x20041000); region 1 = NS SRAM [0x20041000,0x20080000); ALLNS=0 so the Secure monitor,
flash, OTP, peripherals stay Secure) and enables it, then continues. Self-reboot still fired at 29 s,
proving `sau.enable()` from Secure SRAM does NOT fault the running Secure world (no Secure region
mis-marked NS). Does NOT yet prove NS/DMA denial (rows 4/5/6) — that needs the Non-secure launch to
attempt the accesses. `src/boundary.rs::configure_sau`; core 1 remains unlaunched (contained).

**Row 0b (Non-secure launch + live SG round trip = step 5b + step 6) — 2026-07-12, same chip.**
After SAU, the monitor sets `MSP_NS` + `VTOR_NS` from the NS vector table and `BXNS` into the NS
reset vector. A bring-up NS stub (LOAD_MAP entry 3 → NS SRAM 0x20041000) runs Non-secure, publishes
a STATUS request into the fixed mailbox, and calls the NSC `sg` veneer; the Secure handler validates
slot/state/seq, reads `opcode` from the NS mailbox, and (bring-up flag) reboots after a distinctive
~13 s delay. Observed self-reboot at 14 s — a time neither ROM rejection (<2 s) nor an NS/SG failure
(never reboots) can produce. Proves: NS launch, the NS→S `sg` transition through the single NSC
veneer, and Secure reading the NS data plane, all on silicon. Does NOT prove the handler's authority
logic (it reboots before it), the response path back to NS, or NS/DMA *denial* of Secure resources.

**Row 0c (NS code → Secure SRAM DENIED) — 2026-07-12, same chip.** Denial-observability channel:
the monitor's Secure fault handler reboots after a ~11 s delay, distinct from the ~50 s SG-success
delay, so reboot time classifies the outcome. The NS bring-up stub attempts `ldr` of Secure SRAM
`0x20000000` (SAU-Secure) before the SG path. Result: DENIED, self-reboot at 12 s (the fault path).
Control (same build, probe off): SG-PATH, self-reboot at 42 s — proving the two paths are cleanly
separated and 12 s is unambiguously the trap. So an NS access to Secure SRAM faults to Secure rather
than returning data — the SAU boundary *blocks*, not just transitions. Reproduce: set `DENIAL_TARGET`
in `veneer/dsm_ns_stub.S`. Still reversible (no lock, no OTP).

**NS-code peripheral denials (rows 4/5 CPU side) — 2026-07-12, same chip.** Same probe, retargeted:
- NS read of OTP_DATA `0x40130000`: DENIED, self-reboot at 13 s.
- NS read of SPI0 (TROPIC01 transport) `0x40080000`: DENIED, self-reboot at 12 s.
Both fault to Secure: the SAU marks everything outside the two NS-SRAM/NSC regions Secure, so NS-core
reads of OTP and the TROPIC SPI trap rather than returning data. (This is the CPU side; the DMA-master
side of rows 4/5/6 is separate — ACCESSCTRL SRAM0–9 default to fully-open, so a DMA could reach Secure
SRAM until ACCESSCTRL locks it. That + the config lock are the remaining rows.)

## Host-automatable now (no board)

These become unit/integration tests in the monitor crate as the split lands:
- #2 (measurement fn: flip a byte → `constant_time_equal` false),
- #7/#8/#9/#11 (gateway state machine: no signature except through commit; second-commit refusal),
- #18 (HKDF: distinct `k_host_root` → distinct `k_host`),
- #19 (bench vs production bundle domain-tag separation),
- #20 (code audit: no HostSign path bypasses `measurement_ok`).

## Definition of done (spec)

- Secure/Non-secure split implemented; exact app SRAM-loaded and measured; `mu_enrolled` +
  `k_host_root` OTP-protected; host signer + TROPIC path Secure-only; no generic signing oracle;
  production OTP sequence run on a sacrificial board; modified-app AND signed-alternate-app attacks
  both fail on silicon; all power-loss cases preserve single-message emission; the final production
  board passes this entire matrix.
