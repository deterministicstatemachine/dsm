# dsm-anchor-pico

RP2350 (Raspberry Pi Pico 2 W) firmware for the DSM **Boot Fenced Fused Anchor**
offline-bearer authority, driving a **TROPIC01** secure element (MIKROE *Secure
Tropic Click*) over SPI at 3.3 V.

It wires the hardware-free protocol core [`dsm-anchor-core`](../dsm-anchor-core)
to real silicon:

- **`Tropic`** → libtropic-rs over an authenticated L3 session, with two MACANDD
  slots: `q_boot` (boot fence) and `q_tx` (transfer witness), plus the monotonic
  down-counter (`u = H₀ − H`).
- **`WitnessSig`** → WOTS-over-BLAKE3 (`dsm_anchor_core::sig::WotsBlake3`), the
  per-transfer TROPIC-keyed hardware witness.
- **`PartitionSig`** → BLAKE3-SPHINCS+ SPX128f ([`dsm-sphincs`](../dsm-sphincs)),
  the RP2350 secure-partition certificate scheme — byte-compatible with the DSM
  receiver's verifier (`DSM/sphincs-kdf`).

On boot it enrolls (one-way birth fuse → bundle `B`, fused head `A₀`, boot head
`J₀`, partition keypair), runs the boot fence, executes a self-test
(boot→prepare→commit→emit→finalize, then verifies the release under the §22
acceptance predicate), and serves the appliance over USB-CDC.

The design is the spec `dsm_anticlone.instructions.md` (the paper *Boot Fenced
Fused Anchor Authority for DSM Offline Bearer State*).

## Build & flash

This crate is **excluded** from the host workspace (it is a thumbv8m-only
binary). Build it from inside this directory with the rustup toolchain (Homebrew's
rust has no cross std), and with `libtropic-rs` checked out as a sibling of the
DSM repo (`../../../../libtropic-rs`):

```sh
export PATH="$HOME/.rustup/toolchains/stable-<host>/bin:$PATH"
cd crates/dsm-anchor-pico
cargo build                                       # ARM thumbv8m.main-none-eabihf (default)
# RISC-V: cargo build --target riscv32imac-unknown-none-elf
```

Flash via **picotool** (writes the correct RP2350 family id). Hold BOOTSEL +
replug, then:

```sh
picotool load -v -x -t elf target/thumbv8m.main-none-eabihf/debug/dsm-anchor-pico
```

Read the USB-CDC log from `/dev/cu.usbmodem*`, then drive a full root advance:

```sh
python3 tools/anchor_host_test.py     # STATUS → PREPARE → COMMIT → EMIT → FINALIZE → STATUS
```

> **Bring-up notes.** `Active` (and the partition ratchet) are kept in RAM and
> re-enrolled each boot — production persists them to TROPIC01 R-memory so an
> interrupted transfer completes across a power loss. SPX128f partition signatures
> are 17 KiB; the heap is sized at 256 KiB accordingly.

## Wiring (SPI0)

| Signal | TROPIC01 / Click | Pico 2 W |
|---|---|---|
| SCK | SCK | GP18 (pin 24) |
| MOSI (SDI) | SDI | GP19 (pin 25) |
| MISO (SDO) | SDO | GP16 (pin 21) |
| CS (manual) | CS | GP17 (pin 22) |
| Power | 3V3 | 3V3 (pin 36) |
| Ground | GND | GND (pin 23 / 38) |

Third-party notices (libtropic-rs, Clear BSD): see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
