# DSM anchor — RP2350 secure-boot provisioning runbook

Realizes the paper's measurement-gated σ^host: only the enrolled signed firmware boots, and the
host-signing secret lives in OTP readable only by Secure firmware.

> ⚠️ **THE BURNS HERE ARE IRREVERSIBLE.** OTP is One-Time-Programmable: fuses only ever go 0→1. A
> wrong value permanently bricks the board or locks you out. Provisioning the anchor afterwards
> also burns the TROPIC01 (below). New boards are limited: **this procedure has not yet run on a
> chip.** Rehearse it on a spent board first, then stop and look after the first new one.

Requires: `picotool` v2.2+, `openssl`, `b3sum`, `arm-none-eabi-nm`, `arm-none-eabi-objcopy`, `clang`,
the built firmware ELF, and the board in BOOTSEL. The TROPIC01 driver is pinned by commit in the
manifests. Build from `crates/dsm-anchor-secure-monitor` with the pinned toolchain on the path:

```
cd crates/dsm-anchor-secure-monitor
export PATH="$HOME/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin:$PATH"
export RUSTC="$HOME/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin/rustc"
```

The trial image and the production image build to one path, so build the one you mean just before
you use it. A build must name one of them, and `sign.sh` signs only a production image.

## What has run without a chip

`crates/dsm-anchor-chip/tests` runs the firmware's chip code against Tropic Square's TROPIC01 model
(`ci/tropic01_model.sh` installs it): a birth, the cage, spends, and a power cut at every SPI
transaction of a birth outside its try-run, at every seventh of a spend and at every 61st of a try-run.
The model enforces access privileges and
latches them at a reboot. It does not model timing, tear a write, or stand for a production chip's
factory configuration, and nothing about the RP2350 runs there: secure boot, the OTP locks, the
boundary, the measured window and USB are this runbook's to prove, on silicon.

## The try-run, on this very board, before anything is burned

**Every board goes through this first, a new one included. It is part of installing, not a test of the
procedure.** The trial image goes through an install on the real RP2350 and the real TROPIC01 with the
permanent parts substituted, and tells you what an install would make permanent. It burns no OTP, and it
writes no pairing key and no access rule. Its first boot does generate the chip's resident key, which
stays and which a later install uses, and it sets the counter to its start:

```
cargo build --release --features bench_self_enroll
picotool load -v -x -t elf target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor
used-chip-bench --port <serial> --check
used-chip-bench --port <serial> --try-run
```

What it goes through, for real: both images boot, the TRNG passes its health tests, the boundary holds,
the Secure Gateway and USB framing work; the chip opens a session; the anchor's identity derives and its
first record is written; the chip and the board sign a payment and both signatures verify; the counter
moves with the records around it; the release is held and an answer as long as it comes through whole;
the account advances; the anchor restores from its record and boot recovery accepts it; then all of it is
erased, the counter set back, the record's own slots tried, and the chip reboots and opens a session
again. All the records go to slots no boot ever reads. Unplug and replug partway to see a power cut cost
nothing, and leave it idle to see it outlast its watchdog. `--try-run` reports how long it took: that is
this board's real signing and memory time, which nothing else measures, and it should be well inside the
phone's ~5 minute wait.

What is substituted, because it cannot be undone: OTP is not burned, so the sealed secret is fresh each
boot and held nowhere and the digest is measured at boot; the board's key is not written to the chip's
pairing slot, the factory slot is not invalidated and the cage is not closed. Each of those is instead
checked to be what the chip would take. The image refuses every provisioning, so it cannot make an
install, and it holds no secret anything could be bound to.

**Do not go on unless every step says `ok`.** The steps below are the only irreversible ones, and the
wallet goes through a try-run again before it provisions.

## What a burn freezes

Freeze the firmware before the first burn.

- **Any byte of the Non-secure app.** Its digest is in OTP. A later change fails the digest check
  on that board for good: it refuses Provision, Prepare, Commit, Emit, Finalize and Recover. A monitor
  update must carry the same bytes: keep `build/ns_app.bin` with the signing key, and build the update
  with `DSM_ANCHOR_NS_BIN` naming it. `sign.sh` refuses an image whose Non-secure app differs from it.
- **On the monitor:** the key labels in `ChipIdentity::derive`, `SEALED_SECRET_ROW`, `MU_ROW` and
  the R-memory record format. The monitor can be re-signed and loaded only while `bootkey.pem`
  survives. A changed pairing label can never open slot 1 again, and slot 0 is gone by then.
- **On the TROPIC01,** at the first `OP_PROVISION`: the board's pairing key in slot 1, slot 0
  invalidated, the cage (`dsm-anchor-chip`), the counter's start and the resident key. A chip whose slot 0
  was caged by the old process, or that holds another key in slot 1, refuses this birth.

## Two choices this procedure makes

Change them here before the first burn, not after.

- **The USB bootloader stays on,** which is how a signed monitor update is loaded. Unsigned images
  still do not boot. Reaching it takes the BOOTSEL button: no fault, watchdog reset or USB host sends a
  board there. Step 8b locks the boot configuration against what it could otherwise burn.
- **The glitch detectors stay off,** because their effect on a working board has not been measured.

## Step 0 — check the board is blank (READ-ONLY)

Name each board. Its secret and records live under `~/.dsm-anchor-secure-boot/boards/<name>/`.

```
./provision-otp.sh --board <name> --check-blank
```
It refuses when any row this procedure writes already holds a value.

## Step 1 — create the boot signing key, once

```
./sign.sh --genkey     # ~/.dsm-anchor-secure-boot/bootkey.pem (secp256k1)
```
Keep a copy offline. It MUST NOT go on an appliance or in the repo. Losing it means no monitor
update can ever reach a locked board; leaking it defeats secure boot.

## Step 2 — build the production image and sign it

```
cargo build --release --features production
./sign.sh --sign
```
This writes `build/signed.elf`, `build/bootkey-otp.json`, `build/mu-enrolled.bin`, the digest of the
Non-secure window, and `build/ns_app.bin`, the image itself. It refuses an image shorter than the
window, because bytes the loader does not copy would be measured, and a signed file that does not hold
the measured bytes.

## Step 3 — load the signed image

```
picotool load -v ~/.dsm-anchor-secure-boot/build/signed.elf
```
Stay in BOOTSEL. Until Step 8 is done production firmware does nothing to its chip and answers every
request `NOT_UP`, naming what is missing (`secure boot is not enabled in OTP`).

## Step 4 — burn the board's secret  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --board <name> --gen-secret
./provision-otp.sh --board <name> --write-secret            # DRY RUN: prints the command
./provision-otp.sh --board <name> --write-secret --commit   # page 48
```

## Step 5 — burn the firmware digest  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --board <name> --write-digest
./provision-otp.sh --board <name> --write-digest --commit   # page 46
```

## Step 6 — lock both pages  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --board <name> --lock-pages
./provision-otp.sh --board <name> --lock-pages --commit
```
Secure firmware reads both; Non-secure reads neither; nothing writes either. The USB bootloader
reads the digest and never the secret.

## Step 7 — burn the boot key's hash  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --board <name> --write-bootkey
./provision-otp.sh --board <name> --write-bootkey --commit
```
`picotool otp load` reads back what it wrote and fails on a mismatch. Do not go on after a failure:
a boot key with uncorrectable faults leaves a secure-boot board unbootable.

`bootkey-otp.json` also holds `SECURE_BOOT_ENABLE` and `KEY_VALID`, so never load that file whole.
This step takes the hash from it and Step 8 burns the flags.

## Step 8 — lock down  ⚠️ IRREVERSIBLE, LAST

```
./provision-otp.sh --board <name> --lockdown
./provision-otp.sh --board <name> --lockdown --commit
```
This marks boot key 0 valid and keys 1-3 invalid, then sets `SECURE_BOOT_ENABLE` and
`DEBUG_DISABLE`. The board now boots only images signed by the key, with debug off.

## Step 8b — lock the boot pages  ⚠️ IRREVERSIBLE, LAST

```
./provision-otp.sh --board <name> --lock-boot-pages
./provision-otp.sh --board <name> --lock-boot-pages --commit
```
Pages 1 and 2, the boot configuration and the boot key hashes, become read-only for everyone. Do this
after Step 8: nothing writes them again.

## Step 9 — boot and validate (no pairing key, access rule or OTP is written)

```
picotool reboot
used-chip-bench --port <serial> --check
```
With debug disabled this is how a board is read: every refusal is an answer over USB, with its reason.
A board that says nothing and resets over and over has panicked or faulted before it could answer, and a
board that says nothing and stays silent has refused to launch with its boundary unconfirmed. Its boot
generates the chip's resident key if there is none and sets the counter to its start, and nothing has
bound it yet. Stop and look if any line is not as stated.

1. **Unsigned firmware refused:** load an UNSIGNED build; the bootrom must not run it. Load
   `signed.elf` again.
2. **Secure context and sealed secret:** `the anchor is up and not provisioned`. A board missing either
   says `the anchor did NOT come up` with the reason.
3. **A chip that cannot take a birth is refused here,** with nothing written to it: a counter away from
   its start is reset while the chip is uncaged, but another board's key in slot 1 or a cage already
   begun comes up as `NOT_UP`.
4. **Digest checked at op time, after the Non-secure app has run:** `measurement gate passed`. A signed
   image with a different Non-secure app says `measurement gate REFUSED`, as error 200, and a
   provisioning is refused the same way, before the chip is bound.

## Step 10 — install, from the wallet  ⚠️ IRREVERSIBLE

**Connecting an anchor does nothing permanent.** The wallet reports it as not provisioned, runs the
try-run on the production image when asked, shows every step and what an install would make permanent,
and installs only when told to. The firmware goes through the try-run once more itself and refuses,
with nothing written, unless it passes.

**Installing binds the board to one wallet, for good.** The anchor is bound to the device id, online key
and genesis of the wallet that provisions it, and it is provisioned once. Install only from a wallet that
will be kept: a wallet wiped or created anew afterward cannot use this anchor.

5. **Birth closed:** after `OP_PROVISION`, and again at every boot, the firmware serves only once the
   chip reports each revocation and refuses `mcounter_init`, `pairing_key_write`, `ecc_key_generate`
   and `i_config_write` as unauthorized.
6. **Serves again after a power cycle:** unplug and replug, and `--check` says it serves. This is the
   first thing that would fail on a chip whose behaviour departs from the model.

## What this does and does not prove

- **Does:** rogue or modified firmware is unsigned, so the bootrom won't run it, and it cannot read
  the secret. Combined with the non-exportable TROPIC01 chip key (σ^chip) and the seed-derived
  σ^DSM, the three-factor release is three independent factors on a provisioned device.
- **Does not (by itself):** defend against physical OTP extraction or fault injection on the
  RP2350 (an MCU, not a certified SE); the paper's residual (Thm 8 exposure bound) still applies.
- **Has not been observed on silicon:** the TRNG path, the Non-secure MPU, the grants dropped at the first
  crossing and the reset after a fault are each read and built, not run. The trial image runs the first
  three on a real board at no cost. A fault's reset can be seen by making the Non-secure side touch a
  revoked peripheral in a throwaway trial build.
  `secure_exe()` is only an Arm Secure-state marker; the enforcement is the burns above.
