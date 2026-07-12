# DSM anchor RP2350 — memory map & SRAM feasibility (§4 gate, TCB-SRAM-resident)

**Corrected threat model (supersedes the XIP-monitor draft):** external QSPI flash is mutable
*after* boot-time signature verification, so **no** security-critical code may run from flash XIP.
Every byte that can read/derive the host key, invoke `HostSign`, touch TROPIC01, move/inspect the
physical counter, mutate durable prepare/commit/recovery state, configure SAU/ACCESSCTRL, or service
the Secure Gateway MUST execute from **boot-ROM-verified SRAM**. The RP2350 bootrom supports a
SRAM-resident signed image (`secure-monitor.sram.bin`): the bootrom copies + verifies it into SRAM
and runs it there — SRAM cannot be rewritten by an external flash-tampering attacker.

This document re-proves the budget with the **complete Secure TCB SRAM-resident** and the Non-secure
app SRAM-loaded + measured. First-order from measured sizes; re-measured post-split (below).

## Hardware (Pico 2 W, RP2350)

| Region | Origin | Size |
|---|---|---|
| SRAM banks 0–7 (striped) | `0x20000000` | 512 KiB |
| SRAM8 / SRAM9 (direct) | `0x20080000` / `0x20081000` | 4 KiB each |
| **Total on-chip SRAM** | | **520 KiB** |
| External QSPI flash (XIP) | `0x10000000` | 4 MiB — holds signed images only; **no TCB code runs from here** |

## Measured baseline (current unified firmware, release)

`.text = 142 KiB`, `.rodata = 11 KiB` → **code+rodata = 153 KiB**. `.bss = 256 KiB`, of which
`HEAP_MEM = 256 KiB` (the fixed `embedded-alloc` arena, `HEAP_SIZE = 256*1024`) is essentially all of
it. So the **real** static footprint is ~153 KiB code + a **right-sizeable** heap arena. Actual peak
allocation = SPX128f release (~17–37 KiB) + SPHINCS+ signing working set + protobuf staging — far
below 256 KiB. The 256 KiB arena is oversized (spec remediation #1: reduce it).

Even unchanged, `153 + 256 = 409 KiB < 520 KiB` fully SRAM-resident, with **111 KiB margin**.

## Budget with the complete TCB SRAM-resident (separate S / NS heaps)

Isolation forbids a shared arena: the Secure monitor and Non-secure app get **separate** heaps that
are **simultaneously resident** (no double-counting — spec's lifetime rule).

| Consumer | Domain | Est. | Basis |
|---|---|---|---|
| Secure monitor `.text`+`.rodata` (SRAM-resident) | S | ~100–120 KiB | libtropic + BLAKE3-SPHINCS+ SPX128f + anchor-core appliance/birth/root_advance + x25519 L3 + OTP + measurement + SAU + gateway handler |
| Secure data + stacks | S | ~8–12 KiB | monitor statics, Secure stack, SRAM8 dedicated stack |
| Secure heap / SPHINCS working set / TROPIC buffers / durable staging | S | ~64–96 KiB | right-sized (SPX128f working set is the swing factor; preallocate/stream per remediation #3) |
| NSC veneer region | S↔NS | < 1 KiB | the `SG` entry + `dsm_secure_dispatch` veneer |
| Non-secure app `.text`+`.rodata` (SRAM-loaded, measured, RX-locked) | NS | ~35–55 KiB | USB-CDC + usbd-serial + protobuf framing + transport dispatch + candidate/proof construction (BLAKE3 only; no SPHINCS+/libtropic) |
| Non-secure heap + USB rings + protobuf/transport buffers + one mailbox slot | NS | ~48–80 KiB | right-sized app arena + `MAX_RX_FRAME`(16 KiB) + fixed request/response slot |
| Non-secure stack | NS | ~8 KiB | |
| Crash + guard bands (SAU region alignment) | S/NS | ~8–16 KiB | region granularity + poison bands |
| **Total** | | **~271–390 KiB** | **fits in 520 KiB with 130–249 KiB margin** |

**Verdict: FEASIBLE with the entire Secure TCB SRAM-resident.** No critical code stays in XIP. The
256 KiB arena is right-sized into two smaller domain heaps; even without right-sizing the current
409 KiB footprint fits. If the post-split measurement exceeds 520 KiB, apply in order (spec §):
(1) reduce the app heap; (2) eliminate large dynamic allocations; (3) preallocate/stream the SPHINCS
working set; (4) reduce the Secure TCB (e.g., drop receiver-side `accept` code — not needed on the
appliance); (5) reconsider the host-signature implementation; (6) change hardware (internal-flash
RP2350 variant). **Never retain the signer/counter/TROPIC code in XIP.**

## Static map (TCB-SRAM-resident)

```
Flash 0x10000000  signed images only (secure-monitor.signed.bin + nonsecure-app package + manifest).
                  NO TCB code executes from flash XIP.
SRAM 0x20000000  ┌─────────────────────────────────────────────┐  bootrom copies+verifies here:
                 │ [S]  monitor .text/.rodata (SRAM-resident RX) │  boot-ROM-verified, never XIP
                 │ [S]  monitor .data/.bss, host-key SRAM        │  Secure-only, zeroized after use
                 │ [S]  Secure heap / SPHINCS+ / TROPIC / state  │
                 │ [S]  Secure stack                             │
                 ├─────────────────────────────────────────────┤  NSC region (SAU):
                 │ [NSC] SG veneer: dsm_secure_dispatch          │  starts at a valid SG; branches to S handler
                 ├─────────────────────────────────────────────┤  SAU S/NS boundary
                 │ [NS] app measured image .text/.rodata (RX)    │  read-only + non-writable BEFORE launch
                 │ [NS] app .data/.bss / heap / USB / protobuf   │  RW
                 │ [NS] one fixed request/response mailbox slot  │  NS RW + S RW (data plane only)
                 │ [NS] Non-secure stack                         │
                 └─────────────────────────────────────────────┘
     0x20080000  SRAM8 = Secure core0 stack ; SRAM9 = reserved/guard
```

The Secure and Non-secure linker scripts + the measurement tool MUST agree on: the NSC region
`[nsc_start, nsc_end)`; the SAU S/NS boundary; and the app's canonical measured range
`[app_load, app_load+app_len)` (the exact bytes hashed to `mu_enrolled`).

## Map-file proof obligations (checked from `secure-monitor.map` + `nonsecure-app.map`)
- [ ] every NSC veneer lies entirely inside the NSC region;
- [ ] no Secure secret (`k_host*`, `mu_enrolled` copy, host key) resides in Non-secure memory;
- [ ] the Non-secure executable region cannot write Secure memory (SAU/ACCESSCTRL);
- [ ] the measured Non-secure executable SRAM is read-only before launch;
- [ ] the Secure monitor executes **no** security-critical code from unverified XIP (all TCB `.text`
      in the SRAM-resident, bootrom-verified image).

## Open items before the SRAM-load code (spec step 1 → step 7)
- [x] Budget fits with the complete TCB SRAM-resident (above).
- [ ] Post-split: real monitor/app section sizes + heap peaks; confirm margin ≥ 0 and update this table.
- [ ] Confirm SPX128f peak working set on-target (swing factor); preallocate if needed.
- [ ] Confirm the RP2350 SRAM-image secure-boot flow (`secure-monitor.sram.bin`) against datasheet §5.
