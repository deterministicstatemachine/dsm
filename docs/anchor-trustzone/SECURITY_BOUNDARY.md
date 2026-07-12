# DSM anchor RP2350 — Secure / Non-secure boundary (§5)

The monitor initializes SAU + RP2350 ACCESSCTRL **before** launching the Non-secure app, and locks
the configuration where lock bits exist. Non-secure code and Non-secure DMA must never reach
TROPIC01, OTP, host-key memory, or Secure state.

## Required security property (spec)

`HostSign(message)` is available only when ALL hold:
1. RP2350 secure boot enabled;
2. hardware debug disabled;
3. the Secure monitor is authentic (bootrom-verified against the enrolled monitor key);
4. the exact loaded Non-secure app bytes hash to `mu_enrolled` (`measurement_ok == true`);
5. the appliance is in a valid prepare/commit/recovery state;
6. the requested message is the single canonical DSM root-advance message fixed by that state.

`secure_boot_enabled()` proves a signer, NOT the exact app. The monitor performs the measurement
comparison itself (§4/§7).

## Resource assignment

| Resource | Domain | Notes |
|---|---|---|
| OTP controller + protected pages (`mu_enrolled`, `k_host_root`, policy) | **Secure only** | Non-secure/DMA/debug reads must fail via hardware permissions |
| Secure monitor code (flash XIP) + `.bss`/data SRAM | **Secure only** | |
| Host-key SRAM (`k_host`, HKDF temporaries) | **Secure only** | zeroized after use; never leaves Secure SRAM |
| TROPIC01 SPI peripheral + CS GPIO + SPI DMA | **Secure only** | libtropic runs Secure; NS cannot toggle CS or drive SPI |
| Physical monotonic-counter operations | **Secure only** | |
| Committed-record durable storage interface | **Secure only** | |
| Secure Gateway (`sg_*`) entry points | **Secure only** | the ONLY NS→S transition surface |
| USB CDC | Non-secure | high attack surface (host bytes) |
| BLE / Wi-Fi (CYW43), if used | Non-secure | (appliance is USB-CDC in v1; NS regardless) |
| Protobuf decode, host transport, transport buffers | Non-secure | untrusted parsing stays out of the TCB |
| UI / logging / app-owned GPIOs | Non-secure | |
| DSM SDK integration; candidate transition + SMT proof construction | Non-secure | BLAKE3 only; hands candidates to `sg_prepare` |
| App SRAM / heap / stacks | Non-secure | |

## Multicore

Core 1 is **disabled** (or forced Non-secure) in v1 — no Secure multicore design is in scope. The
monitor runs core 0 Secure; the app runs core 0 Non-secure after launch.

## Non-secure → Secure interface (the ONLY gateway; §6)

No generic `host_sign(digest)` oracle exists. The gateway is a narrow state machine:

```
sg_status()                 -> SecureStatus            // measurement_ok, appliance state, u_i, H0
sg_prepare(candidate)       -> PreparedId | Err        // no signature, no counter move
sg_commit(prepared_id)      -> CommittedId | Err       // exactly one counter decrement; signs internally
sg_emit(committed_id)       -> ReleasePackage | Err    // export the committed release bytes
sg_finalize(committed_id)   -> () | Err
sg_recover()                -> RecoverOutcome           // re-emit committed | complete witness | downgrade
```

Every entry point re-checks `measurement_ok` (§7). `candidate` carries the DSM-level inputs
(parent root, frontier, counter coordinate, policy, recipient, challenge, transition digest inputs)
from which the monitor **recomputes** the canonical root-advance message internally — it never signs
a caller-supplied digest.

## What Non-secure can and cannot do

- CAN: parse protobuf, run the DSM SDK, build a candidate `Δ` + SMT proofs, call the six gateway
  functions, read the returned release bytes, transport them over USB.
- CANNOT: read OTP, drive TROPIC01 SPI/CS, move the counter, read/derive the host key, read Secure
  SRAM, request an arbitrary signature, or modify the measured app image after launch (RX, non-writable).

## Lockdown

After `AccessCtrl`/SAU init the monitor sets the RP2350 access-control lock bits so Non-secure code
cannot re-open Secure resources. Debug is disabled in OTP (provisioning). SPI DMA channels, if used,
are assigned Secure so a Non-secure DMA program cannot reach TROPIC01 or Secure SRAM.
