# DSM anchor RP2350 — memory map & SRAM-load feasibility (§4 gate)

Per the measurement-seal spec §4: **prove the split fits before writing the SRAM-load code**, and
never fall back to measured XIP. This document is that proof. It is a first-order budget from the
current combined firmware; the actual per-image sizes are re-measured once the split lands and this
file is updated with real monitor/app section sizes (the budget must still hold).

## Hardware (Pico 2 W, RP2350)

| Region | Origin | Size |
|---|---|---|
| SRAM (banks 0–7, striped) | `0x20000000` | 512 KiB |
| SRAM8 (direct) | `0x20080000` | 4 KiB |
| SRAM9 (direct) | `0x20081000` | 4 KiB |
| **Total on-chip SRAM** | | **520 KiB** |
| External QSPI flash (XIP) | `0x10000000` | 4 MiB |

Measured combined firmware today (`size -A`, release, unified image):
`.text = 145,848 B (142 KiB)`, `.rodata = 11,712 B (11 KiB)`, `.data = 0`, `.bss = 262,176 B (256 KiB)`.

## The load model (why SRAM-load is feasible here)

Two images, two very different placements:

- **Secure monitor** — runs from **flash XIP**, verified by the RP2350 bootrom against the enrolled
  monitor boot key (secure boot). Its large code (libtropic TROPIC01 stack, BLAKE3-SPHINCS+ SPX128f
  `σ^host`, anchor-core appliance state machine, OTP, measurement, HKDF) stays in flash — it does
  **not** consume SRAM for code. Only its working set (`.bss`/stack) lives in **Secure SRAM**.
- **Non-secure app** — the monitor copies its canonical bytes from flash into **Non-secure SRAM**,
  BLAKE3-measures them against `mu_enrolled`, marks the region non-writable + executable, then
  launches it. The app is small: USB-CDC, protobuf framing, transport dispatch, and construction of
  candidate transitions + SMT inclusion proofs (BLAKE3 only). It contains **no** SPHINCS+ and **no**
  libtropic — those are Secure-only. So the SRAM-resident measured image is small.

This inverts the naive worry: the heavy crypto is in flash (secure-boot-verified, not measured-in-SRAM);
only the light, high-attack-surface parser is SRAM-measured. TCB minimization here is about
**untrusted-input handling** (protobuf/USB stay Non-secure), not raw code size.

## SRAM budget (first-order)

| Consumer | Region | Est. | Basis |
|---|---|---|---|
| Non-secure app code+rodata (measured, SRAM-loaded) | NS SRAM | ~48–72 KiB | app share of current 153 KiB code+rodata (USB+protobuf+dispatch), monitor libs excluded |
| Non-secure app heap + transport buffers | NS SRAM | ~120–160 KiB | release package staging (~37 KiB) + protobuf + USB rings; app share of the 256 KiB `.bss` |
| Secure monitor working set (`.bss`/stack) | S SRAM | ~120–180 KiB | SPHINCS+ SPX128f signing working set (the swing factor) + libtropic L3 session + durable prepare/commit buffers |
| Secure/Non-secure stacks + guard bands | S/NS SRAM | ~16–24 KiB | core0 stacks; SRAM8/9 reserved for dedicated stacks |
| **Total** | | **~304–436 KiB** | **fits in 520 KiB with 84–216 KiB margin** |

**Verdict: FEASIBLE.** The single risk is the SPHINCS+ SPX128f signing working set inside the
monitor; it is bounded (SPX128f, no_std `dsm-sphincs`) and re-measured post-split. If, after the
split, the total exceeds 520 KiB: (1) shrink the app (drop non-essential dispatch/log paths); (2)
bound the SPHINCS+ working set / stream the signature; (3) per spec §4, move production hardware to
an internal-flash RP2350 variant sized for the boundary — **never** silently revert to measured XIP.

## Proposed static map

```
Flash 0x10000000 ┌───────────────────────────────────────────────┐
                 │ .start_block + monitor IMAGE_DEF (signed)     │  secure-boot verified
                 │ Secure monitor .text/.rodata (XIP)            │  runs in place, Secure
                 │ Non-secure app package (bytes + manifest)     │  copied to NS SRAM, measured
                 └───────────────────────────────────────────────┘
SRAM  0x20000000 ┌───────────────────────────────────────────────┐  SAU/ACCESSCTRL split below:
                 │ [S]  monitor .bss / host-key SRAM / state      │  Secure-only
                 │ [S]  Secure stack                              │
                 ├───────────────────────────────────────────────┤  SAU region boundary
                 │ [NS] app measured image (.text/.rodata) RX     │  non-writable after measure
                 │ [NS] app .bss / heap / transport buffers RW    │
                 │ [NS] Non-secure stack                          │
                 └───────────────────────────────────────────────┘
      0x20080000 │ SRAM8 (S core0 stack)  SRAM9 (reserved)       │
                 └───────────────────────────────────────────────┘
```

The exact split addresses (the SAU region boundary) are fixed in the monitor+app linker scripts once
the split lands; both linker scripts and the measurement tool MUST agree on the app's canonical
`[load_addr, load_addr+len)` byte range (the range hashed to `mu`). See `MEMORY_MAP` update on split.

## Open items resolved before the SRAM-load code
- [x] Total SRAM budget fits (above).
- [ ] Post-split: measure real monitor vs app section sizes; update this table; confirm margin ≥ 0.
- [ ] Confirm SPHINCS+ SPX128f peak working-set on-target (the swing factor).
