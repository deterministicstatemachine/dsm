# DSM anchor — RP2350 secure-boot provisioning runbook

Realizes the paper's measurement-gated σ^host: only the enrolled signed firmware boots, and the
host-signing secret lives in OTP readable only by that firmware. This makes
`finding_host_signer_not_measurement_gated` (the reproducible "honest label" host key) a
non-issue **for a device provisioned by this runbook**.

> ⚠️ **EVERY STEP HERE IS IRREVERSIBLE.** OTP is One-Time-Programmable: fuses only ever go 0→1.
> `SECURE_BOOT_ENABLE`, debug-disable, and the boot-key fingerprint **cannot be undone** — a wrong
> value **permanently bricks the board** or locks you out. Do a full dry run first, on a
> **sacrificial RP2350**, and read RP2350 datasheet §5 (secure boot) + §13 (OTP) before committing.
> None of this can run off-device; the CI/host build only proves the firmware compiles.

Requires: `picotool` v2.2+ (`picotool version`), `openssl`, the built firmware ELF, and the board in
BOOTSEL. The firmware must be built with the production profile:

```
cd crates/dsm-anchor-pico
PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH" \
RUSTC="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc" \
  cargo build --release --features secure-boot
```

## Step 0 — inspect the factory OTP map (READ-ONLY)

```
picotool otp list                 # human map of pages/rows
picotool otp dump  > otp-before.json
```
Confirm the DSM host-secret page (`HOST_SECRET_ROW` = **page 48**, see `src/secure_boot.rs`) is
**blank and free** — not claimed by the bootrom, white-label, or any factory field. If page 48 is
taken on your silicon, change `HOST_SECRET_ROW` in `src/secure_boot.rs` to a confirmed-free page and
rebuild. Never overwrite a populated system page.

## Step 1 — create the boot signing key (keep OFF the appliance)

```
./sign.sh --genkey                # writes bootkey.pem (secp256k1) if absent — store it in an HSM/offline
```
The firmware-signing private key MUST NOT live on the appliance or in the repo. Losing it means you
can never ship a firmware update to a secure-boot-locked device; leaking it defeats secure boot.

## Step 2 — sign the enrolled firmware (produces the image + the key-fingerprint OTP JSON)

```
./sign.sh --sign                  # picotool seal --sign … → signed.elf + bootkey-otp.json
```
`signed.elf` is the ONLY image this device will ever run after Step 5. Sign **exactly** the enrolled
build — "sign only the enrolled firmware" is what makes secure-boot's publisher check equal an
exact-firmware measurement.

## Step 3 — generate + program the OTP-sealed host secret  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --gen-secret            # 32 random bytes → host-secret.json (rows for page 48)
./provision-otp.sh --write-secret          # DRY RUN: prints the picotool otp commands
./provision-otp.sh --write-secret --commit # BURNS the host secret into OTP page 48
```
Then lock the page to **secure-read** so only secure-state (enrolled) firmware reads it:
```
./provision-otp.sh --lock-secret           # DRY RUN
./provision-otp.sh --lock-secret --commit  # BURNS the read permission (secure-read only)
```

## Step 4 — program the boot-key fingerprint  ⚠️ IRREVERSIBLE

```
picotool otp load bootkey-otp.json                 # DRY RUN first: picotool otp load --dry-run …
picotool otp load bootkey-otp.json                 # BURNS the secp256k1 key fingerprint rows
```

## Step 5 — enable secure boot + disable debug/alt-boot  ⚠️ IRREVERSIBLE, DO LAST

Confirm the exact CRIT rows/flags against RP2350 datasheet §13 + `picotool otp list` for your
silicon, then:
```
./provision-otp.sh --lockdown                 # DRY RUN: SECURE_BOOT_ENABLE + DEBUG_DISABLE + boot-path disable
./provision-otp.sh --lockdown --commit        # BURNS the lockdown — the board now runs ONLY signed.elf
```
After this the device boots only Step-2's signed image, with debug off. There is no going back.

## Step 6 — flash the signed firmware + validate

```
picotool load -v -x signed.elf
```
On the serial console the firmware must print neither `[SEC] secure context FAIL` nor
`[SEC] sealed host secret FAIL`; it reaches `[T1] chip identity: OK`. Validation matrix (run each):

1. **Unsigned firmware refused:** try `picotool load` of an UNSIGNED build → the bootrom must refuse it.
2. **Secure context asserted:** the production firmware halts if `secure_boot_enabled()` /
   `debug_disabled()` are false (they are true now) — verified by it NOT halting.
3. **Host secret sealed:** a build with a wrong `HOST_SECRET_ROW`, or reading before provisioning,
   halts with `sealed host secret FAIL` — verified by the provisioned build NOT halting.
4. **Different signed image ⇒ different bundle B:** a modified-but-signed image cannot reproduce the
   enrolled bundle unless it reads the same OTP secret AND is the enrolled measurement — confirm B is
   stable only for the exact enrolled image.

## What this does and does not prove

- **Does:** rogue/modified firmware is unsigned → the bootrom won't run it; it cannot read the
  secure-read OTP host secret → cannot derive σ^host. Combined with the non-exportable TROPIC01 chip
  key (σ^chip) and the seed-derived σ^DSM, the three-factor release is genuinely three independent
  factors on a provisioned device.
- **Does not (by itself):** defend against physical OTP extraction / fault injection on the RP2350
  (an MCU, not a certified SE) — the glitch detector (`glitch_detector_enabled`) raises the bar; the
  paper's residual (Thm 8 exposure bound) still applies. And `secure_exe()` ≠ this — it is only an
  Arm Secure-state marker; the enforcement is the Step-1–5 OTP burns above.
