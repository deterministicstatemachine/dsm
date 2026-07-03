<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# DSM SMT-root verifier slot — bench burn runbook

An **explicit operator-run** checklist to provision one caged DSM SMT-root verifier slot on a
TROPIC01. This is the ONLY sanctioned way to perform the irreversible burn.

> **Hard rules (do not violate):**
> - No burn happens from app boot. No burn happens from a transfer confirm. The burn is a bench
>   action only (this CLI); there is no on-device burn path.
> - **One verifier ROLE.** Its INDEX is chosen explicitly with `--slot N`. Slot 0 (host) is never a
>   verifier slot. Choosing slot 2 on a dev chip whose slot 1 is spent is a deliberate operator
>   choice, NOT a silent fallback.
> - No overwrite of an occupied slot (an old demo / per-relationship key fails closed).
> - The confirm flag must **name the same slot** as `--slot` (`--slot 2` needs `--yes-burn-slot-2`);
>   a mismatch is refused.
> - The burn is IRREVERSIBLE (a written pairing slot is spent; cage bits clear `1 -> 0` permanently).

The commit runs the SAME reviewed `provisioner` code the on-device read uses, over a USB-CDC relay
to the Pico. It reads the chip's own `stpub` (no hardcoded chip identity) — **you** confirm the
target chip (step 2).

```sh
CRATE=crates/dsm-anchor-hw-verifier/Cargo.toml
PORT=/dev/cu.usbmodemdsm_anchor1        # adjust to your Pico's serial port
SLOT=2                                    # this dev chip: slot 1 is spent, so the role goes in slot 2
run() { ~/.cargo/bin/cargo +stable run --manifest-path "$CRATE" --example "$@"; }
```

---

## 1. Confirm main is synced

```sh
git checkout main && git pull --ff-only     # must include the slot-configurable provisioner + preflight
```

## 2. Confirm target chip identity

```sh
run usb_uap_probe     -- "$PORT"                 # full chip dump: chip-id, stpub, slot map, UAP
run usb_verifier_slot -- status "$PORT"          # scans 1..=3: reports where (if anywhere) the role lives
```

Record and confirm the chip's **`stpub`** and current **`mcounter[0]`**. If it is not the chip you
intend, **stop**. (On this dev chip you should see slot 1 already OCCUPIED by the old demo key.)

## 3. Confirm slot 2 is empty

```sh
run usb_verifier_slot -- status --slot "$SLOT" "$PORT"
```

| status output | action |
|---|---|
| `EMPTY` | eligible — go to step 4 |
| `PROVISIONED` | already done (idempotent) — no burn |
| `OCCUPIED` | **stop.** Do NOT overwrite. Pick another empty candidate index and re-confirm. |

## 3b. Set the counter budget to max (SEPARATE slot-0 setup, BEFORE the slot burn)

The monotonic counter is the device's lifetime offline-bearer budget (`H0`). It must be initialized
to the hardware max, not the `1000` bring-up placeholder. This is a distinct operation from the
verifier-slot burn — do it first so the enrolled `H0` is the real max.

```sh
run usb_verifier_slot -- counter-status "$PORT"      # prints current mcounter[0] vs intended max
```

Only if it is not already at max, and after fresh approval:

```sh
run usb_verifier_slot -- counter-init --yes-init-counter-max "$PORT"   # slot-0 write; sets + reads back
```

It refuses without `--yes-init-counter-max`. On success it prints the read-back value; **confirm it
equals `MCOUNTER_MAX` (4294967294)** before continuing. Re-run `counter-status` to double-check.
From here on, every diagnostic reads whatever the chip reports as `H0` — never assume `1000`.

## 4. Read-only preflight against the actual chip (the key protection)

```sh
run usb_verifier_slot -- preflight --slot "$SLOT" "$PORT"
```

This writes **nothing**. It runs the burn's ENTIRE gate on the real chip and must report:
- slot 2 reads back `SlotEmpty`;
- `mcounter[0]` reads (prints the value);
- every deny/allow UAP register is factory-open;
- then prints **exactly what a commit would burn** (fixed verifier pubkey, deny list with
  `I_CONFIG_WRITE` marked LAST, allowlist).

**If the preflight is anything but a clean "WOULD PROCEED", stop and investigate — do not commit.**
(That is the trigger to reach for the emulator; otherwise the emulator is unnecessary.)

## 5. Explicit commit — ONLY after fresh approval

Only if step 3 said `EMPTY`, step 4 was a clean `WOULD PROCEED`, and you give fresh approval:

```sh
run usb_verifier_slot -- commit --slot "$SLOT" --yes-burn-slot-"$SLOT" "$PORT"
```

Without `--yes-burn-slot-2` (or with a flag naming a different slot) the tool refuses and writes
nothing. The commit: write the fixed verifier pubkey into slot 2 -> verify read-back -> revoke slot-2
access to every deny register (`I_CONFIG_WRITE` last) -> TROPIC reboot-latch -> reopen -> verify the
caged surface. It refuses to overwrite a slot that became non-empty; nothing partial is trusted.

## 6. Final proof

On success the commit prints `[PASS] slot 2 is the caged DSM SMT-root verifier slot` + the
`verifier_slot` + `chip_static_pubkey (stpub)` disclosure values. Its internal post-reboot
verification already proved: slot 2 opens with the fixed key; `mcounter_get(0)` succeeds;
`mcounter_init` / `pairing_key_write` / `i_config_write` are denied; slot 0 still reads the counter.

Re-confirm non-destructively and record the disclosure values:

```sh
run usb_verifier_slot -- status "$PORT"          # must report: role PROVISIONED at slot 2, same stpub as step 2
```

---

**After a successful burn**, the chip serves Path-B counter reads: plug it into the sender phone, and
the read-only on-device seam scans + discloses `(slot 2, stpub)` on a first-transfer enroll. Proceed
to the 2-phone BLE transfer test. The live flip remains a separate, explicit owner decision.
