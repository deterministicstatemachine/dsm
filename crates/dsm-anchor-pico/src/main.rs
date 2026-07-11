//! DSM anchor firmware — Software-Authority / Hardware-Identity appliance + USB transport.
//!
//! Ladder:
//!   T1: raw SPI probe -> L2 GET_INFO chip id + device-cert `stpub` (the pinned identity root).
//!   T2: X25519 handshake (PROD0 pairing key, slot 0) -> encrypted L3 channel.
//!   T3: the resident non-exportable Ed25519 chip key (`σ^chip`) + the monotonic counter (a
//!       non-rewind floor). The chip key is generated ONCE on the die (ECC slot) and persists;
//!       its private half never leaves the chip.
//!   T4: enrollment (one-way birth fuse -> bundle `B` binding `stpub`, `pk_chip`, `pk_host`,
//!       `H(pk_on)`, `H0`, ... + the genesis frontier `h_0`).
//!   T6: a NON-SECURE USB receive loop that frames protobuf requests over USB-CDC into the
//!       secure core and frames responses back — the transport the DSM backend uses to drive
//!       the appliance (prepare -> commit -> emit -> finalize -> status).
//!
//! Authority model: Software Authority, Hardware Identity. Transfer uniqueness is a software
//! property of the DSM device SMT; the firmware is NOT the transfer authority. It provides two
//! identity witnesses over the one DSM root-advance message `M_{i+1}` and nothing else:
//!   - `σ^chip` — the resident non-exportable Ed25519 key inside TROPIC01 (`eddsa_sign`),
//!   - `σ^host` — BLAKE3-SPHINCS+ SPX128f, the RP2350 secure-partition key (`dsm_sphincs`),
//!     byte-compatible with the DSM receiver's verifier (`DSM/sphincs-kdf`).
//! There is no boot fence, no MAC-and-destroy witness, and no on-device counter-read / verify
//! path — the counter is moved only as a local floor at commit and is never read by a receiver.
//!
//! Mediation: the TROPIC01 session, partition key, and `Appliance` live inside [`SecureCore`],
//! whose only public method is `handle(frame) -> frame`.
//!
//! Durable recovery: §26 recovery reads the durable `Active` at boot. This bring-up build keeps
//! `Active` in RAM and re-enrolls each boot from the SAME deterministic chip-rooted identity and
//! the SAME persistent resident chip key, so identity and `B` are stable across reboots.
//! Production persists `Active` to TROPIC01 R-memory.
//!
//! Wiring (SPI0): SCK=GP18(p24), MOSI/SDI=GP19(p25), MISO/SDO=GP16(p21),
//! CS=GP17(p22), 3V3=p36, GND=p23.

#![no_std]
#![no_main]

extern crate alloc;

use panic_halt as _;

use rp235x_hal as hal;

use hal::clocks::Clock;
use hal::fugit::RateExtU32;
use hal::pac;
use hal::rosc::RingOscillator;

use embedded_alloc::LlffHeap as Heap;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiDevice;
use embedded_hal_bus::spi::ExclusiveDevice;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{ActiveSession, EccCurve, MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

use alloc::vec::Vec;
use anchor_core::appliance::{Appliance, RecoverOutcome};
use anchor_core::enrollment::{birth, Birth, BirthInputs};
use anchor_core::service;
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};
use dsm_sphincs::SphincsVariant;

use usb_device::class_prelude::UsbBusAllocator;
use usb_device::prelude::*;
use usb_device::UsbError;
use usbd_serial::SerialPort;

#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[global_allocator]
static HEAP: Heap = Heap::empty();

// Release-only. A debug firmware pins the CPU on SPHINCS+ (the self-test alone can wedge USB enumeration)
// and invalidates BLE / FROM->TO counter-order timing — it must not exist. Building without --release
// turns `debug_assertions` on and fails the build here, before any chip is touched.
#[cfg(debug_assertions)]
compile_error!(
    "dsm-anchor-pico must be built with --release: debug SPHINCS+ is too slow (pins the CPU) and \
     invalidates BLE / FROM->TO timing. Build with `cargo build --release`."
);

const XTAL_HZ: u32 = 12_000_000;
const COUNTER: MCounterIndex = MCounterIndex::Index0;
/// ECC key slot holding the resident non-exportable Ed25519 identity key (`σ^chip`). Generated
/// once on the die and persistent across reboots, so `pk_chip` — and therefore `B` — is stable.
const CHIP_KEY_SLOT: u16 = 0;
// Enrollment counter H0 = the value the monotonic counter was PROVISIONED to (bench CLI:
// `MCOUNTER_MAX`), NOT a bring-up placeholder. It is a FIXED constant so the birth ceremony is
// deterministic across reboots (stable bundle/identity); the LIVE counter (`mcounter_get`) gives the
// current H and the appliance derives u = H0 − H. The firmware ADOPTS the provisioned counter — it
// must NOT re-init it (that would reset the counter and defeat the anti-double-spend floor).
// Unused in a bench-adopt build (H0 = the live counter there); never removed from production.
#[cfg(not(feature = "bench-adopt-existing-chip"))]
const ENROLL_H0: u32 = 0xFFFF_FFFE; // tropic01 MCOUNTER_VALUE_MAX (4_294_967_294)

/// The partition (`σ^host`) scheme: BLAKE3-SPHINCS+ SPX128f (fast sign, 17,088 B signature,
/// 64 B pk). The receiver verifies with the same scheme.
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;

// The device identity (anchor_id, device_id, partition_device_id, partition-key seed, birth
// entropy) is NOT a compile-time constant. It is derived at runtime from the real TROPIC01 —
// its fused device-cert public key (`stpub`) and `chip_id` — so the SAME chip yields the SAME
// identity across reboots and a DIFFERENT chip yields a DIFFERENT identity. No per-boot RP2350
// randomness enters anything the receiver pins as long-term identity. See `ChipIdentity`. The
// load-bearing anti-clone root is `stpub` + the resident chip key + the software DSM predicate;
// the partition co-signer key is an HONEST LABEL (deterministic, chip-unique, NOT a silicon
// secret), attesting firmware authenticity.
const GENESIS: [u8; 32] = [0x00; 32]; // DSM genesis state root that seeds the offline frontier h_0

/// The well-known offline-bearer policy id, computed identically to the host's
/// `canonical_offline_bearer_policy().policy_id` =
/// `domain_hash_bytes("DSM/offline-bearer/policy-id/well-known/v1", &[])` = `BLAKE3(tag ‖ 0x00)`.
/// Baked into the anchor bundle so `B` commits the real policy.
const POLICY_ID_DOMAIN: &str = "DSM/offline-bearer/policy-id/well-known/v1";

/// Deterministic, chip-rooted anchor identity. Every field is derived from the TROPIC01's fused
/// identity (`stpub` from device cert 0 + `chip_id`). Same chip ⇒ same identity across reboots.
struct ChipIdentity {
    anchor_id: [u8; 32],
    device_id: [u8; 32],
    partition_device_id: [u8; 32],
    /// Partition-key birth seed — an HONEST LABEL (deterministic + chip-unique, NOT a silicon
    /// secret). The partition co-signer attests firmware authenticity, not anti-clone.
    partition_key_seed: [u8; 32],
    /// Deterministic stand-ins for the birth entropy inputs so `s_birth` → `B` is stable across
    /// reboots. Chip-rooted, not per-boot RP2350 RNG.
    birth_entropy: [u8; 32],
    birth_host_nonce: [u8; 32],
    birth_witness: [u8; 32],
    /// Online-identity commitment stand-in bound into `B` as `H(pk_on)`. The real `pk_on` binding
    /// is installed by the dual-identity upgrade ceremony (Stage 5); until then this is a
    /// deterministic chip-rooted label so `B` is well-formed.
    online_id_label: [u8; 32],
}
impl ChipIdentity {
    /// Derive from the chip's fused `stpub` (device-cert public key) and a 32-byte digest of `chip_id`.
    fn derive(stpub: &[u8; 32], chip_id_hash: &[u8; 32]) -> Self {
        use anchor_core::hash::h;
        let root = h("DSM/anchor/chip-root/v1", &[stpub, chip_id_hash]);
        Self {
            anchor_id: h("DSM/anchor/anchor-id/v1", &[&root]),
            device_id: h("DSM/anchor/device-id/v1", &[&root]),
            partition_device_id: h("DSM/anchor/partition-device-id/v1", &[&root]),
            partition_key_seed: h("DSM/anchor/partition-seed-label/v1", &[&root]),
            birth_entropy: h("DSM/anchor/birth-entropy/v1", &[&root]),
            birth_host_nonce: h("DSM/anchor/birth-host-nonce/v1", &[&root]),
            birth_witness: h("DSM/anchor/birth-witness/v1", &[&root]),
            online_id_label: h("DSM/anchor/online-id-label/v1", &[&root]),
        }
    }
}

/// Receive-edge frame cap. Requests are small (a transition + device roots); the large release
/// (~37 KiB with SPX128f certs) flows the other way.
const MAX_RX_FRAME: usize = 16 * 1024;

type Serial<'a> = SerialPort<'a, hal::usb::UsbBus>;
type UsbDev<'a> = UsbDevice<'a, hal::usb::UsbBus>;

fn put(serial: &mut Serial, msg: &[u8]) {
    let _ = serial.write(msg);
}

/// Write all bytes to USB-CDC, polling the device and retrying on a full buffer.
fn write_all(serial: &mut Serial, usb_dev: &mut UsbDev, data: &[u8]) {
    let mut sent = 0;
    while sent < data.len() {
        usb_dev.poll(&mut [serial]);
        match serial.write(&data[sent..]) {
            Ok(n) => sent += n,
            Err(UsbError::WouldBlock) => {}
            Err(_) => return,
        }
    }
}

/// BLAKE3-SPHINCS+ SPX128f as the partition (`σ^host`) signature scheme (PartitionSig).
struct SphincsPart;
impl PartitionSig for SphincsPart {
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        match dsm_sphincs::generate_keypair_from_seed(PART_VARIANT, seed) {
            Ok(kp) => (kp.secret_key.clone(), kp.public_key.clone()),
            Err(_) => (Vec::new(), Vec::new()),
        }
    }
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        dsm_sphincs::sign(PART_VARIANT, sk, digest).unwrap_or_default()
    }
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        dsm_sphincs::verify(PART_VARIANT, pk, digest, sig).unwrap_or(false)
    }
}

/// Bridge anchor-core's `Tropic` trait to a libtropic-rs active session: the monotonic counter
/// (a non-rewind floor + offline exposure cap) and the resident non-exportable Ed25519 chip key
/// (`σ^chip`). Signing happens on the die (`eddsa_sign`); the private half never leaves the chip.
struct ChipTropic<'a, SPI: SpiDevice, CS: OutputPin> {
    sess: &'a mut Tropic01<SPI, CS, ActiveSession>,
}
impl<SPI: SpiDevice, CS: OutputPin> Tropic for ChipTropic<'_, SPI, CS> {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        self.sess.mcounter_get(COUNTER).map_err(|_| TropicError::Comm)
    }
    fn counter_update(&mut self) -> Result<(), TropicError> {
        self.sess
            .mcounter_update(COUNTER)
            .map_err(|_| TropicError::CounterExhausted)
    }
    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        // On-die EdDSA over the 32-byte root-advance message M. The resident key never leaves.
        let sig = self
            .sess
            .eddsa_sign(CHIP_KEY_SLOT.into(), &message[..])
            .map_err(|_| TropicError::Comm)?;
        Ok(sig.to_vec())
    }
}

/// The secure core: owns the appliance (chip session, partition key) and exposes ONLY the
/// protobuf request/response boundary.
struct SecureCore<'a, SPI: SpiDevice, CS: OutputPin> {
    app: Appliance<ChipTropic<'a, SPI, CS>, SphincsPart>,
}
impl<SPI: SpiDevice, CS: OutputPin> SecureCore<'_, SPI, CS> {
    fn handle(&mut self, frame: &[u8]) -> Vec<u8> {
        service::handle(&mut self.app, frame)
    }
}

/// Ensure the resident non-exportable Ed25519 chip key exists in `CHIP_KEY_SLOT` and return its
/// public half `pk_chip`. Generated once on the die (persists across reboots), so the pinned
/// `pk_chip` and the bundle `B` are stable. The private half is never exported.
fn ensure_chip_key<SPI: SpiDevice, CS: OutputPin>(
    sess: &mut Tropic01<SPI, CS, ActiveSession>,
) -> Result<Vec<u8>, &'static str> {
    // GATE (Stage-7 hardware proof, BLOCKING): generate-once relies on `ecc_key_read`
    // returning Err on an EMPTY slot. If an unprovisioned slot instead returns Ok with a
    // zero/garbage pubkey, generation is skipped and a bogus pk_chip is pinned into B —
    // poisoning enrollment. This MUST be verified on silicon before the offline identity path
    // is production-ready; deliberately NOT papered over here (a guard would hide the very
    // behavior under test — fix it as a diagnostic if the read does not fail cleanly).
    if let Ok(res) = sess.ecc_key_read(CHIP_KEY_SLOT.into()) {
        return Ok(res.pub_key().to_vec());
    }
    sess.ecc_key_generate(CHIP_KEY_SLOT.into(), EccCurve::Ed25519)
        .map_err(|_| "ecc_key_generate")?;
    let res = sess.ecc_key_read(CHIP_KEY_SLOT.into()).map_err(|_| "ecc_key_read")?;
    Ok(res.pub_key().to_vec())
}

/// Enroll: adopt the provisioned counter, ensure the resident chip key, and run the one-way birth
/// fuse to produce the immutable bundle `B` (binding `stpub`, `pk_chip`, `pk_host`, `H(pk_on)`,
/// `H0`, ...) and the genesis frontier `h_0`. Returns `(H0, Birth)`.
fn enroll<SPI: SpiDevice, CS: OutputPin>(
    sess: &mut Tropic01<SPI, CS, ActiveSession>,
    ident: &ChipIdentity,
    policy_hash: &[u8; 32],
) -> Result<(u32, Birth), &'static str> {
    // ADOPT the counter — do NOT `mcounter_init` (re-init resets the physical counter and would
    // let a rebooted device re-spend already-consumed steps). The live read is always the real
    // chip's authenticated MCOUNTER value: never host-supplied, never faked, never software.
    // Production: hard-require a readable counter (a provisioned chip must have an initialized
    // counter; never init here — re-init resets the anti-double-spend floor). bench-adopt: if the
    // used chip's counter is unreadable (cleared / re-provisioned by earlier bench work), INITIALIZE
    // it to MCOUNTER_VALUE_MAX so the bench anchor starts fresh at u = H0 - live = 0. This is the
    // bench profile's whole purpose (domain-separated bundle, proves transport/read-order/commit —
    // NOT fresh birth or clone exclusion). If init ALSO fails, the counter slot's UAP denies this
    // session and needs re-provisioning (distinct error surfaced).
    #[cfg(not(feature = "bench-adopt-existing-chip"))]
    let live = sess.mcounter_get(COUNTER).map_err(|_| "mcounter_get")?;
    #[cfg(feature = "bench-adopt-existing-chip")]
    let live = match sess.mcounter_get(COUNTER) {
        Ok(v) => v,
        Err(_) => {
            sess.mcounter_init(COUNTER, 0xFFFF_FFFE)
                .map_err(|_| "mcounter_init (counter unreadable; UAP lock?)")?;
            sess.mcounter_get(COUNTER)
                .map_err(|_| "mcounter_get after init")?
        }
    };

    // H0 selection.
    //   * Production (default): `H0` is the FIXED provisioning constant `ENROLL_H0` and the live read
    //     is only a sanity floor (a healthy provisioned virgin chip reads at or below H0). Birth is
    //     deterministic over `ENROLL_H0`, so identity is stable across reboots.
    //   * `bench-adopt-existing-chip`: `H0` is the CURRENT live counter, so an ALREADY-USED chip
    //     becomes a fresh bench anchor at u = H0 − live = 0 without pretending to be virgin. The
    //     bundle is domain-separated so a bench profile can NEVER collide with a production anchor
    //     (even if a fresh chip, live == ENROLL_H0, were mistakenly run in this mode). This proves
    //     transport/read-order/commit/cancel — NOT fresh birth or clone exclusion (module header).
    #[cfg(not(feature = "bench-adopt-existing-chip"))]
    let (enroll_h0, partition_trng): (u32, [u8; 32]) = {
        if live > ENROLL_H0 {
            return Err("counter above enrollment H0 (unprovisioned/mis-provisioned chip)");
        }
        (ENROLL_H0, ident.birth_entropy)
    };
    #[cfg(feature = "bench-adopt-existing-chip")]
    let (enroll_h0, partition_trng): (u32, [u8; 32]) = {
        if live == 0 {
            return Err("bench-adopt: chip counter exhausted (no step left to transfer)");
        }
        (
            live,
            anchor_core::hash::h(
                "DSM/anchor/bench-adopted-existing-chip/v1",
                &[&ident.birth_entropy],
            ),
        )
    };

    // The resident non-exportable Ed25519 chip key (σ^chip): pk_chip is pinned into B.
    let chip_pk = ensure_chip_key(sess)?;
    let b = birth::<SphincsPart>(&BirthInputs {
        partition_trng: &partition_trng,
        chip_birth_witness: &ident.birth_witness,
        host_nonce: &ident.birth_host_nonce,
        device_id: &ident.device_id,
        policy_hash,
        partition_device_id: &ident.partition_device_id,
        anchor_id: &ident.anchor_id,
        chip_pk: &chip_pk,
        online_id_pk: &ident.online_id_label,
        partition_key_seed: &ident.partition_key_seed,
        enrolled_counter: enroll_h0,
        genesis_root: &GENESIS,
    });
    // The appliance derives u = H0 − live. Production: H0 = ENROLL_H0 (virgin chip → u = 0).
    // bench-adopt: H0 = live (used chip → u = 0). Real FROM/TO reads apply from here.
    Ok((enroll_h0, b))
}

/// Serve the appliance over USB-CDC forever: read LE32-length-prefixed protobuf request frames,
/// dispatch through the secure core, write framed responses.
fn serve_forever<SPI: SpiDevice, CS: OutputPin>(
    mut core: SecureCore<'_, SPI, CS>,
    serial: &mut Serial,
    usb_dev: &mut UsbDev,
) -> ! {
    let mut rx: Vec<u8> = Vec::new();
    loop {
        usb_dev.poll(&mut [serial]);
        let mut chunk = [0u8; 64];
        if let Ok(n) = serial.read(&mut chunk) {
            if n > 0 {
                if rx.len() + n > MAX_RX_FRAME + 4 {
                    rx.clear();
                } else {
                    rx.extend_from_slice(&chunk[..n]);
                }
                while rx.len() >= 4 {
                    let len = u32::from_le_bytes([rx[0], rx[1], rx[2], rx[3]]) as usize;
                    if len > MAX_RX_FRAME {
                        rx.clear();
                        break;
                    }
                    if rx.len() < 4 + len {
                        break;
                    }
                    let frame: Vec<u8> = rx[4..4 + len].to_vec();
                    let resp = core.handle(&frame);
                    write_all(serial, usb_dev, &(resp.len() as u32).to_le_bytes());
                    write_all(serial, usb_dev, &resp);
                    rx.drain(0..4 + len);
                }
            }
        }
    }
}

#[hal::entry]
fn main() -> ! {
    {
        use core::mem::MaybeUninit;
        // SPX128f signatures are 17 KiB; the release + encoding allocate well above 64 KiB.
        // 256 KiB leaves ample headroom on the RP2350's 512 KiB.
        const HEAP_SIZE: usize = 256 * 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }

    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    // One TRNG draw: the secure-session handshake ephemeral (randomness is correct here). The
    // anchor birth entropy is deterministic + chip-rooted (see `ChipIdentity`) — never per-boot RNG.
    let rosc = RingOscillator::new(pac.ROSC).initialize();
    let draw = || {
        let mut b = [0u8; 32];
        for byte in b.iter_mut() {
            let mut acc = 0u8;
            for _ in 0..8 {
                acc = (acc << 1) | (rosc.get_random_bit() as u8);
            }
            *byte = acc;
        }
        b
    };
    let eh = draw();

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    let sck = pins.gpio18.into_function::<hal::gpio::FunctionSpi>();
    let mosi = pins.gpio19.into_function::<hal::gpio::FunctionSpi>();
    let miso = pins.gpio16.into_function::<hal::gpio::FunctionSpi>();
    let cs = pins.gpio17.into_push_pull_output();
    let spi_bus = hal::spi::Spi::<_, _, _, 8>::new(pac.SPI0, (mosi, miso, sck)).init(
        &mut pac.RESETS,
        clocks.peripheral_clock.freq(),
        1_000_000u32.Hz(),
        embedded_hal::spi::MODE_0,
    );
    let mut spi_dev = ExclusiveDevice::new(spi_bus, cs, timer).unwrap();

    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));
    let mut serial = SerialPort::new(&usb_bus);
    let mut usb_dev = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0x1209, 0xd5a1))
        .strings(&[StringDescriptors::default()
            .manufacturer("DSM")
            .product("DSM Anchor")
            .serial_number("dsm-anchor")])
        .unwrap()
        .max_packet_size_0(64)
        .unwrap()
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    // ---- Phase 1: raw link probe ~3s while USB enumerates ----
    let probe_until = timer.get_counter().ticks() + 3_000_000;
    let mut last = timer.get_counter();
    while timer.get_counter().ticks() < probe_until {
        usb_dev.poll(&mut [&mut serial]);
        if (timer.get_counter() - last).to_millis() >= 1000 {
            last = timer.get_counter();
            let mut rx = [0u8; 4];
            let tx = [0xAAu8, 0, 0, 0];
            let _ = spi_dev.transfer(&mut rx, &tx);
            let _ = serial.flush();
        }
    }

    // ---- Phase 2: read the REAL chip identity (chip_id + device-cert stpub) ----
    // These L2 getters are only callable BEFORE `session_start` consumes the NoSession handle.
    // The pinned anchor identity is rooted here, in silicon: same chip ⇒ same identity across
    // reboots. Fail closed (halt) if the chip will not disclose a real identity.
    usb_dev.poll(&mut [&mut serial]);
    let mut tropic = Tropic01::new(spi_dev);
    let chip_id_hash = match tropic.get_info_chip_id() {
        Ok(id) => anchor_core::hash::h("DSM/anchor/chip-id/v1", &[id]),
        Err(_) => {
            put(
                &mut serial,
                b"[T1] chip id: FAIL (no real identity; halting)\r\n",
            );
            let _ = serial.flush();
            loop {
                usb_dev.poll(&mut [&mut serial]);
            }
        }
    };
    let stpub: [u8; 32] = match tropic.get_info_cert_store() {
        Ok(cs) => match cs.public_key() {
            Ok(k) => *k,
            Err(_) => {
                put(
                    &mut serial,
                    b"[T1] cert stpub: FAIL (no real identity; halting)\r\n",
                );
                let _ = serial.flush();
                loop {
                    usb_dev.poll(&mut [&mut serial]);
                }
            }
        },
        Err(_) => {
            put(
                &mut serial,
                b"[T1] cert store: FAIL (no real identity; halting)\r\n",
            );
            let _ = serial.flush();
            loop {
                usb_dev.poll(&mut [&mut serial]);
            }
        }
    };
    // Deterministic, chip-rooted identity + the well-known canonical policy id.
    let ident = ChipIdentity::derive(&stpub, &chip_id_hash);
    let policy_hash = anchor_core::hash::h(POLICY_ID_DOMAIN, &[&[0u8][..]]);
    put(
        &mut serial,
        b"[T1] chip identity: OK (stpub-rooted, deterministic across reboot)\r\n",
    );
    let _ = serial.flush();
    usb_dev.poll(&mut [&mut serial]);

    // ---- Phase 3: T2 secure session (PROD0) ----
    put(&mut serial, b"[T2] handshake (PROD0, slot 0)...\r\n");
    let _ = serial.flush();
    usb_dev.poll(&mut [&mut serial]);

    let ehpriv = StaticSecret::from(eh);
    let ehpub = PublicKey::from(&ehpriv);
    let mut sess = match tropic.session_start(
        &X25519Dalek,
        PublicKey::from(SH0PUB_PROD0),
        StaticSecret::from(SH0PRIV_PROD0),
        ehpub,
        ehpriv,
        0,
    ) {
        Ok(s) => s,
        Err((_t, _e)) => loop {
            usb_dev.poll(&mut [&mut serial]);
            put(&mut serial, b"[T2] session FAIL\r\n");
            let _ = serial.flush();
            let mut wait = timer.get_counter();
            while (timer.get_counter() - wait).to_millis() < 2000 {
                usb_dev.poll(&mut [&mut serial]);
            }
            let _ = &mut wait;
        },
    };
    put(&mut serial, b"[T2] session=OK\r\n");
    let _ = serial.flush();

    // ---- Phase 4: enroll (resident chip key + birth fuse -> bundle B, frontier h_0) ----
    put(
        &mut serial,
        b"[T4] enroll: resident Ed25519 chip key + bundle B...\r\n",
    );
    let _ = serial.flush();
    usb_dev.poll(&mut [&mut serial]);
    let (h0, b) = match enroll(&mut sess, &ident, &policy_hash) {
        Ok(v) => v,
        Err(_) => {
            put(&mut serial, b"[T4] enroll FAIL (halting; no fallback identity)\r\n");
            let _ = serial.flush();
            loop {
                usb_dev.poll(&mut [&mut serial]);
            }
        }
    };

    // ---- Phase 5: T6 serve the appliance over USB-CDC for an external host ----
    put(
        &mut serial,
        b"[T6] serving software-authority appliance over USB-CDC (LE32-len-prefixed protobuf)\r\n",
    );
    let _ = serial.flush();
    // Build-mode banner. A debug build fails to compile (module-level `compile_error!`), so if this
    // line runs the firmware is a release build. Confirms the exact profile before any chip work.
    // Enrollment above is FAIL-CLOSED for ALL profiles: any enroll failure (including a failed live
    // authenticated counter read in bench-adopt) halts — never a fallback identity, never ENROLL_H0
    // adopted by a bench build.
    put(
        &mut serial,
        b"[BUILD] mode=release debug_assertions=false sphincs+=on hw=production\r\n",
    );
    #[cfg(feature = "bench-adopt-existing-chip")]
    put(
        &mut serial,
        b"[BUILD] bench-adopt-existing-chip=ENABLED (used-chip adopt: H0=live, u=0)\r\n",
    );
    #[cfg(not(feature = "bench-adopt-existing-chip"))]
    put(
        &mut serial,
        b"[BUILD] bench-adopt-existing-chip=disabled (production fresh-birth)\r\n",
    );
    let _ = serial.flush();
    #[cfg(feature = "bench-adopt-existing-chip")]
    {
        // Profile marker: this build ADOPTED the chip's live authenticated counter as H0 (u=0). The
        // anchor is a fresh, domain-separated BENCH anchor on an already-used chip — it proves real
        // transport / read-order / commit-decrement / cancel-recover, NOT fresh birth or clone
        // exclusion. Read the adopted H0 back over STATUS.
        put(
            &mut serial,
            b"[T6][BENCH] existing-chip / bench-adopted: H0 = live MCOUNTER (u=0), domain-separated bundle. NOT a fresh-birth proof.\r\n",
        );
        let _ = serial.flush();
    }
    let mut core = SecureCore {
        app: Appliance::<_, SphincsPart>::new(
            ChipTropic { sess: &mut sess },
            h0,
            ident.anchor_id,
            ident.partition_device_id,
            b,
        ),
    };
    // §26 recovery before serving (no boot fence — offline is enabled once born).
    let rec = core.app.recover();
    put(
        &mut serial,
        match rec {
            RecoverOutcome::Accept(_) => b"[T6] recover: Accept (ready)\r\n".as_slice(),
            RecoverOutcome::ReemitCommitted(_) => b"[T6] recover: ReemitCommitted\r\n".as_slice(),
            RecoverOutcome::DowngradeOnline => b"[T6] recover: DowngradeOnline\r\n".as_slice(),
            RecoverOutcome::FailClosed => b"[T6] recover: FailClosed\r\n".as_slice(),
            RecoverOutcome::ExhaustedOnlineOnly => {
                b"[T6] recover: ExhaustedOnlineOnly\r\n".as_slice()
            }
            RecoverOutcome::AcceptPreparedCanComplete => {
                b"[T6] recover: PreparedCanComplete\r\n".as_slice()
            }
            RecoverOutcome::OnlineCancelOrResolve => {
                b"[T6] recover: OnlineCancelOrResolve\r\n".as_slice()
            }
        },
    );
    let _ = serial.flush();
    serve_forever(core, &mut serial, &mut usb_dev)
}

/// Program metadata for `picotool info`.
#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [hal::binary_info::EntryAddr; 3] = [
    hal::binary_info::rp_cargo_bin_name!(),
    hal::binary_info::rp_program_description!(
        c"DSM anchor (software-authority / hardware-identity appliance + USB transport)"
    ),
    hal::binary_info::rp_program_build_attribute!(),
];
