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
(`ci/tropic01_model.sh` installs it), set up with the factory configuration Tropic Square's catalog
list gives for the part: a birth, the cage, spends, and a power cut at every state a birth, a spend and
a try-run can leave on the chip, found from the model's own log of what it stores. The model enforces
access privileges and latches them at a reboot. It does not model timing or tear a write (`rmem`'s own
tests do), it answers as firmware 2.0.0, and nothing about the RP2350 runs there: secure boot, the OTP
locks, the boundary, the measured window and USB are this runbook's to prove, on silicon.

`scripts/stack-bound.py` walks the production image's call graph, and CI holds the 64 KiB Secure stack to
it. It gives about 53 KiB at the heaviest, with a fault on top.

## Which chip this is, before anything is written to it

**What is on a board is not known until the chip says.** Tropic Square programs its parts differently
(catalog list, section 5), and a Secure Tropic Click's part is not on its label. Every image reads the part
number, silicon revision and firmware versions first, and gives a chip nothing if it fails either check. A
refusal is an answer over USB, and `used-chip-bench --check` prints it.

**Read a board first with the identify image.** It writes nothing, to the chip or to OTP, and needs no
sealed secret, so it runs on any board, burned or blank. It reports the part, its firmware, its
configuration and access rules, its pairing slots, counter, resident key slot and R-memory, the RP2350's
stepping and whether OTP holds a sealed secret, and it saves the chip's four certificates:

```
cargo build --release --features bench_self_enroll,identify_chip
picotool load -v -x -t elf target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor
used-chip-bench --port <serial> --identify --certs <dir>
# The chain, against Tropic Square's root (libtropic examples/linux/spi/full_chain_verification):
for f in t01_ese_cert t01_xxxx_ca_cert t01_ca_cert; do
  openssl x509 -inform DER -in <dir>/$f.der -out <dir>/$f.pem
done
cat <dir>/t01_xxxx_ca_cert.pem <dir>/t01_ca_cert.pem > <dir>/untrusted.pem
openssl verify -CAfile tropicsquare_root_ca_certificate_sn_301.pem -untrusted <dir>/untrusted.pem \
  <dir>/t01_ese_cert.pem
```

The first board read this way (2026-11-06) carried a TR01-C2P-T103 on chip firmware 0.3.1, with
`CFG_START_UP` at `0xFFFFFFFF` (the PTRNG untested, as the table below says of a T103), its chain verifying
to Tropic Square Root CA v1 (revocation lists not fetched), on an RP2350 A2.

The parts:

| Part | Factory configuration | What this firmware does |
|---|---|---|
| T2XX, T3XX | PTRNG tested at start-up, sensors on | Serves. These are the production parts. |
| T101, T103 | Sensors on. `CFG_START_UP[RNGTEST_DIS]` left at 1, so the PTRNG is never configured and what the chip generates may not be random (erratum OI_TR01_ERR_2026090100). Tropic Square calls these test chips, not production devices. | Refused until prepared, below. |
| T005 | I-config and R-config empty, tamper sensors off, engineering-sample key | Refused. Nothing here repairs one. |

**Preparing a test part, only if the owner has decided to use one.** It clears that one bit, for good, which is
Tropic Square's own correction, and erases any key the chip generated before it. Like the trial image it runs on
any board not locked for production, whatever its secret page holds, under a secret of that boot held nowhere:
it writes the chip and never the board (one image prepares every board: owner, 2026-11-08). The chip reboots
and latches the change, so the trial image's `--try-run` after it is the proof that it took:

```
cargo build --release --features bench_self_enroll,prepare_chip
picotool load -v -x -t elf target/thumbv8m.main-none-eabihf/release/dsm-anchor-secure-monitor
used-chip-bench --port <serial> --check     # says what the chip now is and how it went
```

**The RP2350, a note and not a rule (owner, 2026-11-06).** Below A4 a physical glitch at boot can run
unsigned code, with no workaround (RP2350-E24, and on A2 also E16, E20, E21). Nothing refuses a board for
its stepping. The try-run's first line says which stepping the board is: the bootrom's version byte.

**The chip's own firmware.** Below 2.0.0 the chip does not verify its writes (OI_TR01_ERR_2025120100), so the
board reads back each one it depends on. Tropic Square recommends 2.1.0 or later in both banks, then disabling
maintenance mode (ODN_TR01_app_007, advisory ODR_TR01_SA_2026012900). This firmware reports the version and
does not update it. A try-run's first line says which it is.

## The try-run, on this very board, before anything is burned

**Every board goes through this first, a new one included. It is part of installing, not a test of the
procedure.** The trial image goes through an install on the real RP2350 and the real TROPIC01 with the
permanent parts substituted, and tells you what an install would make permanent. It burns no OTP, and it
writes no pairing key and no access rule. Its first boot does generate the chip's resident key, which
stays and which a later install uses, and it sets the counter to its start, and those two are all it
changes (`a_first_boot_writes_only_the_resident_key_and_the_counter`). Everything else the chip can report
is left as found. The counter's set-back is `MCounter_Init`, which Tropic Square's firmware does by erasing
the counter's two sectors and writing the start again: that works until the cage revokes the command, and
then never. What a try-run spends and the chip does not report is wear, a few hundred erases out of the
100,000 cycles the datasheet gives as typical:

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
- **The rollback version's rows,** page 44, rows 0 to 2. An image is signed naming them.
- **On the monitor:** the key labels in `ChipIdentity::derive`, `SEALED_SECRET_ROW`, `MU_ROW` and
  the R-memory record format. The monitor can be re-signed and loaded only while `bootkey.pem`
  survives. A changed pairing label can never open slot 1 again, and slot 0 is gone by then.
- **On the TROPIC01,** at the first `OP_PROVISION`: the board's pairing key in slot 1, slot 0
  invalidated, the cage (`dsm-anchor-chip`), the counter's start and the resident key. A chip whose slot 0
  was caged by the old process, or that holds another key in slot 1, refuses this birth.

## Two choices this procedure makes

Change them here before the first burn, not after.

- **The USB bootloader stays on,** which is how a signed monitor update is loaded. Unsigned images
  still do not boot. Reaching it takes the BOOTSEL button, or a flash with no valid image: no fault,
  watchdog reset or USB host sends a board there. Step 9b locks the boot configuration against what it
  could otherwise burn. A host in the bootloader can still read and write flash and RAM, reads whatever OTP
  its lock leaves it, and has no way to run an image, since the RP2350 does not support `EXEC`.
- **The boot key signs every board.** One leak reaches all of them, and each board holds its own digest and
  secret regardless.
- **The glitch detectors stay off,** because their effect on a working board has not been measured.

## From the phone: the procedure for everyone

Owner, 2026-11-11: "Not everyone has a Mac. It has to be doable from the phone." The wallet does
Steps 3 to 9b itself, through the board's own USB bootloader, with the board plugged into the phone
in BOOTSEL. It speaks the bootloader's protocol as picotool does and applies `provision-otp.sh`'s
checks row for row (`crates/dsm-android-anchor`: `picoboot`, `otp_burn`, `board_setup`). Signing
(Steps 1 and 2) stays the vendor's one-time step on a computer, with the owner's passphrase; the
phone carries only its public outputs.

1. **The release into the app**, once per signing, before the APK is built:
   `scripts/anchor-release-into-app.sh` copies `signed.elf`, `ns_app.bin`, `mu-enrolled.bin` and
   the boot key's hash into the app's assets. Before writing anything the phone checks that the
   digest is the firmware's own measurement of the Non-secure app and that the image holds that app.
2. **Plug the board into the phone with BOOTSEL held.** Appliance → Production setup → Read the board.
   The panel names the chip, lists the steps below in order, marks each done, next or later from
   the board's own OTP (never from anything the phone remembers), and shows what Step 0's check
   found.
3. **Each step is the board's next or it is refused**, and runs only on the board whose chip id the
   person types back (its last four characters). Every write is read back before the step is done.
4. **After "Start the signed image once"** the board leaves BOOTSEL and records its rollback version.
   Once it has started, unplug it, hold BOOTSEL, and plug it in again for the last step: the phone
   locks the boot pages only once `ROLLBACK_REQUIRED` is set.
5. **Then plug it in normally** and install it from the wallet that will keep it (Step 10).

What the phone does differently: a blank secret page is written and locked in one step (Steps 4 and
the secret half of 6), so no page stands written and unlocked between steps, and every write is
read back, the rows picotool's JSON load writes included. Not yet on the phone: Step 9's check that
an unsigned image is refused.

The commands below are the same procedure from a computer with picotool.

## Step 0 — check the board is blank (READ-ONLY)

Name each board. Its secret and records live under `~/.dsm-anchor-secure-boot/boards/<name>/`.
Every command also names the board's RP2350 chip id, as `picotool info -d` gives it in BOOTSEL (`chipid`,
16 hexadecimal digits), and every picotool call goes to that chip alone: with two boards in BOOTSEL, nothing
reaches the other. The first run records the chip id under the board's name, and a later run under that name
for another chip stops.

```
./provision-otp.sh --board <name> --ser <chip id> --check-blank
```
It refuses when any row this procedure writes data into already holds a value, or when a lock row it burns
holds a bit outside what it burns there. A lock row already holding some of those bits is fine and is named:
on the boards read on 2026-11-11 the boot configuration and boot key pages' lock rows hold `0x040404`
(Non-secure read-only), within the `0x151515` Step 9b burns. One exception it also names: a secret
page an earlier procedure burned and locked exactly as Step 4 and Step 6 do (the lock row says so; the
bootloader cannot read the rows of a locked page). Such a board keeps that secret,
which production reads through the same rows (OTP is never rewritten, and the board holds its only copy):
skip Step 4 on it, and Step 6 locks the digest page alone. A secret page in any other state stops the procedure.

## Step 1 — create the boot signing key, once

```
./sign.sh --genkey     # ~/.dsm-anchor-secure-boot/bootkey.pem (secp256k1)
```
It asks for a passphrase of 16 characters or more and keeps the key encrypted, and each signing decrypts
it only for as long as picotool reads it. Keep a copy and the passphrase offline, apart. It MUST NOT go on an appliance or in the
repo. Losing it means no monitor update can ever reach a locked board; leaking it defeats secure boot.

## Step 2 — build the production image and sign it

```
cargo build --release --features production
./sign.sh --sign
```
The image carries version 1.0 with rollback version 1, under its signature. A board refuses any image below
the highest rollback version it has booted, so an image with a real defect is retired by signing its
successor one higher (RP2350 datasheet, "Rollback versions and bootloaders").

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
./provision-otp.sh --board <name> --ser <chip id> --gen-secret
./provision-otp.sh --board <name> --ser <chip id> --write-secret            # DRY RUN: prints the command
./provision-otp.sh --board <name> --ser <chip id> --write-secret --commit   # page 48
```
On a board whose secret page Step 0 found sealed, both refuse: it already holds its secret and goes on with it.

## Step 5 — burn the firmware digest  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --board <name> --ser <chip id> --write-digest
./provision-otp.sh --board <name> --ser <chip id> --write-digest --commit   # page 46
```

## Step 6 — lock both pages  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --board <name> --ser <chip id> --lock-pages
./provision-otp.sh --board <name> --ser <chip id> --lock-pages --commit
```
Secure firmware reads both; Non-secure reads neither; nothing writes either. The USB bootloader
reads the digest and never the secret. With `--commit` this removes `host-secret.bin`: nothing reads it
again, and it could restore no board, since the chip's key does not leave the chip. On a board whose secret
page Step 0 found sealed, only the digest page is locked here; its secret page is already as this leaves it.

## Step 7 — burn the boot key's hash  ⚠️ IRREVERSIBLE

```
./provision-otp.sh --board <name> --ser <chip id> --write-bootkey
./provision-otp.sh --board <name> --ser <chip id> --write-bootkey --commit
```
`picotool otp load` reads back what it wrote and fails on a mismatch. Do not go on after a failure:
a boot key with uncorrectable faults leaves a secure-boot board unbootable.

`bootkey-otp.json` also holds `SECURE_BOOT_ENABLE` and `KEY_VALID`, so never load that file whole.
This step takes the hash from it and Step 8 burns the flags.

## Step 8 — lock down  ⚠️ IRREVERSIBLE, LAST

```
./provision-otp.sh --board <name> --ser <chip id> --lockdown
./provision-otp.sh --board <name> --ser <chip id> --lockdown --commit
```
This marks boot key 0 valid and keys 1-3 invalid, then sets `SECURE_BOOT_ENABLE` and
`DEBUG_DISABLE`. The board now boots only images signed by the key, with debug off.

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

## Step 9b — lock the boot pages  ⚠️ IRREVERSIBLE, AFTER THE FIRST BOOT

```
./provision-otp.sh --board <name> --ser <chip id> --lock-boot-pages
./provision-otp.sh --board <name> --ser <chip id> --lock-boot-pages --commit
```
Pages 1 and 2, the boot configuration and the boot key hashes, become read-only for everyone, and page 44,
the rollback version, read-only for the USB bootloader. Not before Step 9: that first boot of the signed
image records its rollback version and sets `ROLLBACK_REQUIRED` on page 1, and the bootrom will not launch
an image whose version it could not record.

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
  crossing, the reset after a fault, the chip check, the prepare image and the rollback version are each
  read and built, not run. The stack bound is read from the image, not measured. The trial image runs the first
  three on a real board at no cost. A fault's reset can be seen by making the Non-secure side touch a
  revoked peripheral in a throwaway trial build.
  `secure_exe()` is only an Arm Secure-state marker; the enforcement is the burns above.
