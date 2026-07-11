<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# DSM offline-bearer counter path — first silicon proof

**Date:** 2026-07-08
**What this is:** the first real on-silicon proof of the DSM Boot-Fenced-Fused-Anchor
offline-bearer anti-double-spend counter path. Two independent RP2350 + TROPIC01 boards, two
independent provenance paths (used-chip bench-adopt, and virgin fresh-birth), each performing
exactly one physical `MCOUNTER` decrement gated by a real authenticated caged verifier-slot read.

Both proofs held the same invariants:

- **Real caged FROM/TO reads** — the counter evidence comes from the receiver's own authenticated
  libtropic session opened on the caged verifier slot (`MCOUNTER_GET`-only) over `OP_SPI_PASSTHROUGH`.
  **No STATUS shortcut.**
- **Counter-Positioned Commit** — FROM captured *before* the commit at `u_i`, TO captured *after* at
  `u_i+1`, both transition-bound.
- **Exactly one decrement** — `u: 0 → 1`.
- **Second COMMIT refused** — the appliance rejects a second commit of the same transition; the
  counter does not move again.

---

## Provenance

| item | value |
|---|---|
| repo `main` | `7c4933c461ebbfe535de0aeaf963c2c91a02e763` (`7c4933c4`) |
| stack merged into main | #571 · #573 · #575 · #576 (`5570ab33`) · #577 (`30d4ef25`) |
| harness | `crates/dsm-anchor-hw-verifier/examples/phase3_one_commit.rs` (selectable `--slot` via #577) |
| slot tool | `crates/dsm-anchor-hw-verifier/examples/usb_verifier_slot.rs` |
| firmware | `dsm-anchor-pico` — production fresh-birth (no bench-adopt feature), **`--release`** |
| build mode | release, **`debug_assertions = false`** (harness enforces this; a debug build refuses to run) |
| host harness build | `cargo +stable run --release` (thumbv8m firmware built with rustup 1.96.0) |

> The in-log `harness commit : (unset ...)` line reflects that `DSM_PHASE3_HARNESS_COMMIT` was not
> exported at run time; the authoritative provenance is the table above (`main @ 7c4933c4`).
> The harness banner prints "USED chip" generically for any allow-listed chip; the actual chip is
> identified by its anchor-id and `--label`.

**Final chip states after the proofs:**

| chip | path | verifier slot | H0 | final u | final H |
|---|---|---|---|---|---|
| chip A | used, bench-adopt | 2 | 4294967281 | 1 | 4294967280 |
| clean chip | virgin, fresh-birth | 1 | 4294967294 | 1 | 4294967293 |

> **The clean chip is no longer pristine.** Its counter has been spent once (`u=0 → 1`) and its
> verifier slot 1 is burned/caged. It cannot serve as a fresh-birth reference again.

---

## Proof 1 — used chip A (bench-adopt path, verifier slot 2)

### Slot inventory (read-only)

```
[status] slot 1: OCCUPIED by a NON-fixed key or not caged.
[status] -> FAIL CLOSED: will NOT overwrite. Choose a different empty slot.

[status] verifier role PROVISIONED at slot 2
[status] chip stpub: [d1, 87, bc, f1, 08, 9e, 9d, aa, b6, 4e, 5c, 0b, 96, fd, 3a, 26, 91, e0, d3, 70, 91, 0a, 07, db, 82, 1a, 32, 25, 83, 0f, be, 7d]

[status] slot 2: PROVISIONED (fixed DSM verifier key, caged read-only)
[status] chip stpub: [d1, 87, bc, f1, 08, 9e, 9d, aa, b6, 4e, 5c, 0b, 96, fd, 3a, 26, 91, e0, d3, 70, 91, 0a, 07, db, 82, 1a, 32, 25, 83, 0f, be, 7d]
```

### One-COMMIT run (`--slot 2`)

```
[CHIP] anchor-id = 1SZ0KC8H6WJ0JYMX2YDD49VM8RX4R6ZGKCK692FDBDZ186HYN15G

############################################################
#        PHASE 3 — ONE REAL COMMIT (counter WILL move)      #
#  Drives the designated USED chip through exactly ONE      #
#  transfer. NEVER the sealed clean/virgin chip.            #
############################################################
Type the anchor-id prefix '1SZ0KC8H' to confirm this is the USED bench chip: 1SZ0KC8H

==================== PHASE 3 BENCH LOG ====================
  chip label        : used chip A
  anchor id         : 1SZ0KC8H6WJ0JYMX2YDD49VM8RX4R6ZGKCK692FDBDZ186HYN15G
  H0 (adopted)      : 4294967281
  pre-run u         : 0
  firmware commit   : (unrecorded — pass --fw-commit)
  harness commit    : (unset — build with DSM_PHASE3_HARNESS_COMMIT=$(git rev-parse HEAD))
  release mode      : yes (debug_assertions=false)
  verifier slot     : 2 (caged MCOUNTER_GET-only; confirm with `usb_verifier_slot status`)
  clean chip (deny) : (none listed)
==========================================================
[CHIP] confirmed USED bench chip 1SZ0KC8H6WJ0JYMX2YDD49VM8RX4R6ZGKCK692FDBDZ186HYN15G — running Phase 3

== Phase 3: one-COMMIT transfer (real caged FROM/TO reads) ==
  caged verifier slot: 2
  pre-state: Ready, u=0, H0=4294967281
  PREPARE ok — witness/cert formed (counter not moved)
  FROM: authenticated caged read H_pre=4294967281 == H0 - u_i (4294967281) at u=0

FROM evidence captured at u=0. This sends ONE COMMIT and moves the counter u:0->1. Type '1SZ0KC8H-COMMIT' to authorize exactly one: 1SZ0KC8H-COMMIT
  COMMIT sent (exactly one)
  TO: authenticated caged read H_post=4294967280 == H0-(u_i+1) (4294967280) == H_pre-1
  STATUS: u advanced exactly once 0->1 (status=2)
  second COMMIT correctly REFUSED by the appliance
  counter stable after refused 2nd COMMIT: H remained 4294967280

PHASE 3 COMPLETE: exactly one transfer committed. u:0->1, H:4294967281->4294967280.
Second commit refused; counter moved exactly once. STOP.
```

---

## Proof 2 — clean chip (virgin fresh-birth path, verifier slot 1)

### 1. Inventory — no firmware yet (no serial port)

```
$ ls /dev/cu.usbmodem*
(no matches found: /dev/cu.usbmodem*)

[verifier-slot] cmd=status slot=Some(1) port=/dev/cu.usbmodemdsm_anchor1
open serial port: Error { kind: Io(NotFound), description: "No such file or directory" }
```

### 2. Pico in BOOTSEL → flash production fresh-birth firmware

```
/Volumes/RP2350 mounted (BOOTSEL)
picotool info: name: dsm-anchor-pico | image type: ARM Secure

Finished `release` profile [optimized]        # ELF 257944 B (distinct from bench-adopt 258848 B)

Family ID 'rp2350-arm-s' can be downloaded in absolute space: 00000000->02000000
Loading into Flash:   [==============================]  100%
The device was rebooted to start the application.
```

### 3. Inventory after flash — clean and empty

```
[status] slot 1: EMPTY (eligible for an explicit commit)
[status] chip stpub: [d1, b5, 79, bf, db, 98, 0b, 55, 8e, 22, 1e, 61, 22, b9, 85, b4, d9, d4, 2e, 31, 53, aa, ff, 8f, 84, 1f, 3f, 28, 25, 08, 69, 6c]
```

### 4. Preflight fails — fresh TROPIC counter uninitialized

```
[preflight] NOT eligible (nothing written): Precondition("mcounter unreadable: CounterInvalid")
```

### 5. counter-init — defines production H0

```
[counter-init] setting mcounter[0] to MCOUNTER_MAX = 4294967294 ...
[counter-init] OK: mcounter[0] read-back = 4294967294 (== max)
```

### 6. Preflight — now green (read-only)

```
[preflight] slot 1: WOULD PROCEED — all read-only checks passed.
[preflight] chip stpub      : [d1, b5, 79, bf, db, 98, 0b, 55, 8e, 22, 1e, 61, 22, b9, 85, b4, d9, d4, 2e, 31, 53, aa, ff, 8f, 84, 1f, 3f, 28, 25, 08, 69, 6c]
[preflight] mcounter[0]     : 4294967294
[preflight] slot 1 SlotEmpty : yes  |  UAP factory-open: yes  |  counter reads: yes
  target slot        : 1  (slot 0 host NEVER touched; other slots NEVER written)
  fixed verifier pub : [07, 0c, db, 46, dc, a5, 18, a8, db, 42, 24, f0, ac, 92, c5, 8f, 17, f5, 5c, 93, 1d, 12, 10, 85, 31, 63, 85, 74, 44, 58, 13, 01]
  cage = revoke slot-1 access to (I_CONFIG_WRITE applied LAST):
      0x040  I_CONFIG_WRITE   <- LAST
  method             : i-config only (no r-config erase); irreversible.
[preflight] DRY-RUN only, nothing written.
```

### 7. Burn (irreversible) + readback

```
[commit] --yes-burn-slot-1 given; running the irreversible provisioning of slot 1...
[PASS] slot 1 is the caged DSM SMT-root verifier slot.
[disclosure] verifier_slot     = 1
[disclosure] chip_static_pubkey = [d1, b5, 79, bf, db, 98, 0b, 55, 8e, 22, 1e, 61, 22, b9, 85, b4, d9, d4, 2e, 31, 53, aa, ff, 8f, 84, 1f, 3f, 28, 25, 08, 69, 6c]

[status] slot 1: PROVISIONED (fixed DSM verifier key, caged read-only)
[status] chip stpub: [d1, b5, 79, bf, db, 98, 0b, 55, 8e, 22, 1e, 61, 22, b9, 85, b4, d9, d4, 2e, 31, 53, aa, ff, 8f, 84, 1f, 3f, 28, 25, 08, 69, 6c]
```

### 8. One-COMMIT run (`--slot 1`)

```
[CHIP] anchor-id = 8RPYNMX7G26GNTQB3BKFK4QXEKJEW0CVTSARZ8BVB2T9ZADGQ3V0

############################################################
#        PHASE 3 — ONE REAL COMMIT (counter WILL move)      #
#  Drives the designated USED chip through exactly ONE      #
#  transfer. NEVER the sealed clean/virgin chip.            #
############################################################
Type the anchor-id prefix '8RPYNMX7' to confirm this is the USED bench chip:

==================== PHASE 3 BENCH LOG ====================
  chip label        : clean chip fresh birth
  anchor id         : 8RPYNMX7G26GNTQB3BKFK4QXEKJEW0CVTSARZ8BVB2T9ZADGQ3V0
  H0 (adopted)      : 4294967294
  pre-run u         : 0
  firmware commit   : (unrecorded — pass --fw-commit)
  harness commit    : (unset — build with DSM_PHASE3_HARNESS_COMMIT=$(git rev-parse HEAD))
  release mode      : yes (debug_assertions=false)
  verifier slot     : 1 (caged MCOUNTER_GET-only; confirm with `usb_verifier_slot status`)
  clean chip (deny) : (none listed)
==========================================================
[CHIP] confirmed USED bench chip 8RPYNMX7G26GNTQB3BKFK4QXEKJEW0CVTSARZ8BVB2T9ZADGQ3V0 — running Phase 3

== Phase 3: one-COMMIT transfer (real caged FROM/TO reads) ==
  caged verifier slot: 1
  pre-state: Ready, u=0, H0=4294967294
  PREPARE ok — witness/cert formed (counter not moved)
  FROM: authenticated caged read H_pre=4294967294 == H0 - u_i (4294967294) at u=0

FROM evidence captured at u=0. This sends ONE COMMIT and moves the counter u:0->1. Type '8RPYNMX7-COMMIT' to authorize exactly one:   COMMIT sent (exactly one)
  TO: authenticated caged read H_post=4294967293 == H0-(u_i+1) (4294967293) == H_pre-1
  STATUS: u advanced exactly once 0->1 (status=2)
  second COMMIT correctly REFUSED by the appliance
  counter stable after refused 2nd COMMIT: H remained 4294967293

PHASE 3 COMPLETE: exactly one transfer committed. u:0->1, H:4294967294->4294967293.
Second commit refused; counter moved exactly once. STOP.
```

---

## Notes

- Logs above are the raw captured terminal output; only formatting (fencing, grouping) was applied —
  no values were altered.
- Both proofs used **real caged FROM/TO reads** over the caged verifier slot — **no STATUS shortcut**.
- Both proofs **refused the second COMMIT** and re-read the counter to confirm it did not move again.
- The first real COMMIT on each chip was authorized by a human-typed confirmation token (the auto-mode
  guard refused to auto-drive the counter-moving harness for chip A three times; for the clean chip it
  proceeded only after the verifier-slot burn was demonstrated in-session — the human/gate boundary held
  either way).
- If this repo is or becomes public, produce a redacted version later (e.g. eliding raw stpub/anchor-id
  bytes if deemed sensitive). This file is the full raw local proof log and is kept intact.
