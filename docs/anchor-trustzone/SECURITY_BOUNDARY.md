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

## Core configuration & init order (before launching Non-secure)

v1 uses **core 0 for both Secure and Non-secure** execution; **core 1 is disabled** (or all its bus
accesses forced Non-secure) — no reviewed Secure multicore design is in scope. Before the monitor
transfers control to the Non-secure reset vector it initializes, in order:

1. **SAU** — Secure vs Non-secure vs NSC region attribution (the boundary in `MEMORY_MAP.md`).
2. **MPU** (Secure) and, for the app, the Non-secure MPU mappings; the measured NS executable region
   is marked RX (non-writable) before launch.
3. **DMA MPU / ACCESSCTRL for DMA** — Non-secure DMA cannot target Secure SRAM, OTP, or the TROPIC01
   SPI/CS; SPI DMA channels (if any) are Secure.
4. **NVIC target state** — interrupts routed to the correct security state (TROPIC/SPI/counter IRQs
   Secure; USB IRQ Non-secure).
5. **ACCESSCTRL** — peripheral ownership per the table above; the NSC veneer region assigned
   explicitly; the mailbox slot is NS RW **and** S RW (data plane); all other Secure monitor memory
   inaccessible to Non-secure code and DMA.
6. **Lock** the access-control + SAU configuration where RP2350 provides lock bits, so Non-secure
   code cannot re-open Secure resources. Debug is disabled in OTP at provisioning.

## TCB placement (corrected)

The entire Secure TCB is **SRAM-resident, boot-ROM-verified** (`secure-monitor.sram.bin`) — no
security-critical code runs from mutable flash XIP (external flash can be altered after boot-time
verification). See `MEMORY_MAP.md`.

## Non-secure → Secure interface — Option C: NSC `SG` veneer + fixed-slot data plane (§6)

The security-state transition is a minimal **Non-Secure-Callable (NSC) veneer**, not a mailbox. A
shared-memory mailbox is a *data plane*, not an authority boundary: with core 1 disabled the RP2350
SIO mailbox does not by itself cause a same-core NS→S transition, so a pure mailbox would need Secure
polling / an NS-triggerable Secure interrupt / a Secure service core — all adding DoS, race, and
lifecycle complexity. The synchronous `SG` veneer is the correct authority boundary; the fixed-slot
mailbox sits **behind** it only to carry bulk protobuf/certificate bytes that don't fit in registers.

The veneer (a tiny C file built with `-mcmse`, or a small reviewed asm veneer) lives in a
linker-defined NSC region, begins at a valid `SG` instruction, and exports exactly one function:

```
dsm_secure_dispatch(slot_index: u32, sequence_number: u32) -> status: u32
```

It immediately branches to a private Secure Rust handler. It exposes **no** arbitrary signing
function, **no** raw pointers into Secure memory, and **no** `HostSign(digest)` API.

**Non-secure app flow:** (1) canonically encode a bounded request into ONE fixed mailbox slot in NS
SRAM; (2) publish its length, opcode, and sequence number; (3) call `dsm_secure_dispatch`; (4) wait
for return; (5) read the bounded response from the same slot.

**Secure handler (behind the veneer):**
1. validate the slot number and sequence number;
2. reject oversized / misaligned / unknown requests;
3. copy the COMPLETE request into Secure SRAM before interpreting it;
4. re-read NO attacker-controlled field after the copy (TOCTOU-safe);
5. validate the canonical encoding from the Secure copy;
6. execute only one of `status` / `prepare` / `commit` / `emit` / `finalize` / `recover`;
7. copy a bounded response back to the NS slot;
8. zeroize the Secure request copy + sensitive temporaries.

Fixed-slot is deliberate: **no** arbitrary Non-secure pointers are accepted (a correct CMSE
range-checking layer would be required first). Every op re-checks `measurement_ok` (§7). The opcodes
map to the narrow state machine:

```
status    -> SecureStatus     // measurement_ok, appliance state, u_i, H0  (no signature)
prepare   -> PreparedId       // no signature, no counter move; recomputes M internally from the copy
commit    -> CommittedId      // re-pin H0-H==prev_u; exactly ONE counter decrement; signs internally
emit      -> ReleasePackage   // export the committed release bytes from the durable record
finalize  -> ()
recover   -> RecoverOutcome    // re-emit committed | complete the one fixed witness | downgrade online
```

The request for `prepare` carries DSM-level inputs (parent root, frontier, counter coordinate,
policy, recipient, challenge, transition-digest inputs) from which the monitor **recomputes** the
canonical root-advance message internally — it never signs a caller-supplied digest. `commit` signs
only the message stored in the committed record and refuses any second distinct commit from the same
origin. `recover` never accepts a new recipient / challenge / successor root / transition digest for
an already-consumed counter step.

## What Non-secure can and cannot do

- CAN: parse protobuf, run the DSM SDK, build a candidate `Δ` + SMT proofs, call the six gateway
  functions, read the returned release bytes, transport them over USB.
- CANNOT: read OTP, drive TROPIC01 SPI/CS, move the counter, read/derive the host key, read Secure
  SRAM, request an arbitrary signature, or modify the measured app image after launch (RX, non-writable).

## Lockdown

After `AccessCtrl`/SAU init the monitor sets the RP2350 access-control lock bits so Non-secure code
cannot re-open Secure resources. Debug is disabled in OTP (provisioning). SPI DMA channels, if used,
are assigned Secure so a Non-secure DMA program cannot reach TROPIC01 or Secure SRAM.
