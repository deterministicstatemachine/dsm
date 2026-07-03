<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# DSM SMT-root verifier slot — bench burn runbook

An **explicit operator-run** checklist to provision slot 1 of a TROPIC01 into the caged DSM SMT-root
verifier slot. This is the ONLY sanctioned way to perform the irreversible burn.

> **Hard rules (do not violate):**
> - No burn happens from app boot. No burn happens from a transfer confirm.
> - No fallback to slot 2 or slot 3. Slot 1 only. Slot 0 (host) is never touched.
> - No overwrite of an occupied slot (an old demo / per-relationship key fails closed).
> - No irreversible action without a fresh, explicit bench gate (`--yes-burn-slot-1`).
>
> The burn is IRREVERSIBLE: a written pairing slot is spent, and the i-config cage bits clear
> `1 -> 0` permanently. Run against **a fresh chip or an explicitly approved bench chip only.**

The commit path runs the SAME reviewed `provisioner` code the on-device `SeSlotWriter` uses, over a
USB-CDC relay to the Pico. It reads the chip's own `stpub` (no hardcoded chip identity) — **you** are
responsible for confirming the target chip (step 2).

Toolchain: host build with the rustup toolchain (Homebrew's rust has no cross std is irrelevant here,
but keep it consistent). All commands use `--manifest-path` because the crate is workspace-excluded:

```sh
CRATE=crates/dsm-anchor-hw-verifier/Cargo.toml
PORT=/dev/cu.usbmodemdsm_anchor1        # adjust to your Pico's serial port
run() { ~/.cargo/bin/cargo +stable run --manifest-path "$CRATE" --example "$@"; }
```

---

## 1. Confirm PR #547 is merged and main is synced

```sh
git fetch origin && git log origin/main --oneline -1     # must include the SeSlotWriter / provisioner
git checkout main && git pull --ff-only
```

Do not proceed on a branch that predates the reviewed provisioner (the two confirmed review fixes:
`SlotEmpty`-only emptiness classification, and the `.is_err()` cage-verify gate).

## 2. Confirm target chip identity

```sh
run usb_uap_probe    -- "$PORT"      # full chip dump: chip-id, stpub, slot map, UAP registers
run usb_verifier_slot -- status "$PORT"
```

Record and confirm, **out loud / against your notes**:
- the chip's **`stpub`** (Noise static public key) — this is the chip's identity;
- the chip info / chip-id;
- the current **`mcounter[0]`** value (from `usb_uap_probe`).

If this is not the chip you intend to provision, **stop**.

## 3. Confirm slot 1 state (`status` classifies it for you)

`usb_verifier_slot -- status` prints exactly one of:

| status output | meaning | action |
|---|---|---|
| `PROVISIONED` | slot 1 already holds the fixed DSM key + correct cage | **no burn** — already done (idempotent) |
| `EMPTY` | slot 1 unwritten | eligible for an explicit commit (step 4-5) |
| `OCCUPIED` | slot 1 holds a non-fixed key (e.g. an old demo key) or is not caged | **FAIL CLOSED — stop.** Do NOT overwrite. Do NOT fall back to slot 2/3. Use a different (fresh) chip. |

## 4. Dry-run (no writes)

```sh
run usb_verifier_slot -- plan "$PORT"
```

Confirm the printed plan:
- **fixed verifier pubkey** is the DSM constant (same every device);
- **exact deny register list** is printed, and **`0x040 I_CONFIG_WRITE` is marked `<- LAST`**;
- **allowlist** leaves `MCOUNTER_GET (0x154)` + harmless reads factory-open;
- `slot 0 host NEVER touched; slots 2/3 NEVER written`.

## 5. Explicit commit — ONLY after fresh approval

Only if step 3 said `EMPTY` and steps 2/4 checked out, and you give fresh explicit approval:

```sh
run usb_verifier_slot -- commit "$PORT" --yes-burn-slot-1
```

Without `--yes-burn-slot-1` the tool refuses and exits (no writes). The commit performs, in order:
write the fixed verifier pubkey into slot 1 -> verify read-back -> revoke SH1 access to every deny
register (**I_CONFIG_WRITE last**) -> TROPIC reboot-latch -> reopen -> verify the caged surface. It
aborts (writing nothing further) on any precondition failure and **refuses to overwrite** a slot that
became non-empty. Nothing partial is trusted.

## 6. Final proof

On success the commit prints `[PASS] slot 1 is the caged DSM SMT-root verifier slot` plus the
`verifier_slot` + `chip_static_pubkey (stpub)` disclosure values. The commit's internal verification
already proved, post-reboot:
- slot 1 opens with the fixed verifier key;
- `mcounter_get(0)` succeeds;
- `mcounter_init`, `pairing_key_write`, `i_config_write` are all **denied**;
- slot 0 still reads the counter (host access intact).

Independently re-confirm (non-destructive), and record the disclosure values:

```sh
run usb_verifier_slot -- status "$PORT"        # must print PROVISIONED + the same stpub as step 2
```

- `PROVISIONED` (fixed key present + cage read back via `i_config_read`);
- `stpub` matches the value recorded in step 2;
- the disclosure pair `(verifier_slot=1, chip_static_pubkey=stpub)` is what a receiver pins.

---

**After a successful burn**, the chip is ready to serve Path-B counter reads: plug it back into the
sender phone, and the read-only on-device `SeSlotWriter` will disclose `(slot 1, stpub)` on a
first-transfer enroll. Proceed to the 2-phone BLE transfer test. The live flip remains a separate,
explicit owner decision.
