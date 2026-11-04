# DSM anchor — RP2350 secure-boot provisioning runbook

Realizes the paper's measurement-gated σ^host: only the enrolled signed firmware boots, and the
host-signing secret lives in OTP readable only by Secure firmware.

> ⚠️ **THE BURNS HERE ARE IRREVERSIBLE.** OTP is One-Time-Programmable: fuses only ever go 0→1. A
> wrong value permanently bricks the board or locks you out. Provisioning the anchor afterwards
> also burns the TROPIC01 (below). New boards are limited: **this procedure has not yet run on a
> chip.** Rehearse it on a spent board first, then stop and look after the first new one.

Requires: `picotool` v2.2+, `openssl`, `b3sum`, `arm-none-eabi-nm`, `arm-none-eabi-objcopy`, the
built firmware ELF, and the board in BOOTSEL. The build reads the TROPIC01 driver from outside the
repository: `libtropic-rs` (github.com/tropicsquare/libtropic-rs) beside the checkout's parent, at
commit `0cacb5ed94e5df491bfbb39e8702cc47598f7d63`. Build with the production profile:

```
cd crates/dsm-anchor-secure-monitor
PATH="$HOME/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin:$PATH" \
RUSTC="$HOME/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin/rustc" \
  cargo build --release --features production
```

## What a burn freezes

Freeze the firmware before the first burn.

- **Any byte of the Non-secure app.** Its digest is in OTP. A later change fails the digest check
  on that board for good: it refuses Prepare, Commit, Emit, Finalize and Recover.
- **On the monitor:** the key labels in `ChipIdentity::derive`, `SEALED_SECRET_ROW`, `MU_ROW` and
  the R-memory record format. The monitor can be re-signed and loaded only while `bootkey.pem`
  survives. A changed pairing label can never open slot 1 again, and slot 0 is gone by then.
- **On the TROPIC01,** at the first `OP_PROVISION`: the board's pairing key in slot 1, slot 0
  invalidated, the cage (`chip.rs`), the counter's start and the resident key. A chip whose slot 0
  was caged by the old process, or that holds another key in slot 1, refuses this birth.

## Two choices this procedure makes

Change them here before the first burn, not after.

- **The USB bootloader stays on,** which is how a signed monitor update is loaded. Unsigned images
  still do not boot.
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

## Step 2 — sign the enrolled firmware

```
./sign.sh --sign
```
This writes `build/signed.elf`, `build/bootkey-otp.json` and `build/mu-enrolled.bin`, the digest of
the Non-secure window. It refuses an image shorter than the window, because bytes the loader does
not copy would be measured, and a signed file that does not hold the measured bytes.

## Step 3 — load the signed image

```
picotool load -v ~/.dsm-anchor-secure-boot/build/signed.elf
```
Stay in BOOTSEL. Production firmware halts until Step 8 is done (`secure boot is not enabled`).

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

## Step 9 — boot and validate

```
picotool reboot
```
The firmware reaches `[T1] chip identity: OK` and answers over USB, not provisioned. Then:

1. **Unsigned firmware refused:** load an UNSIGNED build; the bootrom must not run it. Load
   `signed.elf` again.
2. **Secure context asserted:** production firmware halts if secure boot or debug-disable is off;
   verified by it NOT halting.
3. **Sealed secret read:** verified by it NOT halting with `sealed host secret FAIL`.
4. **Digest checked at op time, after the Non-secure app has run:** a `Prepare` passes the gate. A
   signed image with a different Non-secure app gets error 200 on the same `Prepare`.
5. **Birth closed:** after `OP_PROVISION`, the firmware serves only once `close_birth` has proven
   that the chip refuses `mcounter_init`, `pairing_key_write`, `ecc_key_generate` and
   `i_config_write`.

## What this does and does not prove

- **Does:** rogue or modified firmware is unsigned, so the bootrom won't run it, and it cannot read
  the secret. Combined with the non-exportable TROPIC01 chip key (σ^chip) and the seed-derived
  σ^DSM, the three-factor release is three independent factors on a provisioned device.
- **Does not (by itself):** defend against physical OTP extraction or fault injection on the
  RP2350 (an MCU, not a certified SE); the paper's residual (Thm 8 exposure bound) still applies.
  `secure_exe()` is only an Arm Secure-state marker; the enforcement is the burns above.
