// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real appliance integration for the Secure monitor.
//!
//! This is the ONLY place the monitor touches the DSM protocol, and it does so by REUSING
//! `dsm-anchor-core` — it does NOT reimplement prepare/commit/root-advance/counter logic. The chip
//! (`σ^chip`) and partition (`σ^host`) leaf crypto are bound via the same `Tropic` / `PartitionSig`
//! traits the proven `dsm-anchor-pico` binary uses; the state machine is `anchor_core::appliance`
//! driven through `anchor_core::service::dispatch`.
//!
//! The difference from the pico is ownership, not protocol: the pico keeps the appliance on the
//! stack of a `serve_forever` loop and reaches the chip session by borrow. The monitor's request
//! entry is the NSC `sg` veneer — a hardware `bxns`, not a call it can thread state into — so the
//! appliance must live in a `'static` slot of a nameable type. The concrete TROPIC01 session type
//! is unnameable, so the chip is erased behind `Box<dyn Tropic>` (heap-resident; the Secure heap is
//! separate from the NS heap). Everything else mirrors the pico's bench (`host_secret = None`)
//! profile: deterministic chip-rooted identity, resident Ed25519 chip key, one-way birth fuse.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use anchor_core::appliance::Appliance;
use anchor_core::enrollment::{birth, Birth, BirthInputs};
use anchor_core::hash::h;
use anchor_core::proto::{decode_request, encode_response, pb};
use anchor_core::service::dispatch;
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};
use dsm_sphincs::SphincsVariant;

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiDevice;
use embedded_hal_bus::spi::ExclusiveDevice;
use hal::fugit::RateExtU32;
use hal::Clock;
use rp235x_hal as hal;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{ActiveSession, EccCurve, MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{SG_ERR_ENCODING, SG_ERR_INTERNAL, SG_ERR_MEASUREMENT};

const XTAL_HZ: u32 = 12_000_000;
const COUNTER: MCounterIndex = MCounterIndex::Index0;
const CHIP_KEY_SLOT: u16 = 0;
/// σ^host scheme — MUST match the pico anchor + the receiver (byte-compatible SPX128f).
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;
/// FIXED provisioning constant = tropic01 `MCOUNTER_VALUE_MAX`, so birth is deterministic over H0
/// and identity is stable across reboots (same as the pico's non-bench-adopt default).
const ENROLL_H0: u32 = 0xFFFF_FFFE;
/// DSM genesis state root that seeds the offline frontier `h_0`.
const GENESIS: [u8; 32] = [0x00; 32];
/// Well-known offline-bearer policy id domain (identical to the host's canonical policy).
const POLICY_ID_DOMAIN: &str = "DSM/offline-bearer/policy-id/well-known/v1";

/// The live appliance, driven by the SG handler. `'static` slot: the SG entry is a `bxns`, so the
/// handler reaches the appliance here rather than by argument. Single-threaded Secure context (no
/// interrupt or second core touches it — core1 is contained), so `static mut` access through
/// `addr_of_mut!` is sound, matching the existing `LAST_SEQ` / mailbox pattern in `main`.
static mut MONITOR_APP: Option<Appliance<Box<dyn Tropic>, SphincsPart>> = None;

/// BLAKE3-SPHINCS+ SPX128f as the partition (`σ^host`) signature scheme — the SAME crate + contract
/// as the pico anchor, so an anchor born here verifies on the same receiver.
pub struct SphincsPart;
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

/// Bridge anchor-core's `Tropic` to a libtropic-rs active session, OWNING the session by value (the
/// pico borrows it; the monitor owns it so the appliance is `'static`). The monotonic counter is a
/// non-rewind floor; the resident Ed25519 key signs on the die (`σ^chip`) and never leaves it.
struct RealChip<SPI: SpiDevice, CS: OutputPin> {
    sess: Tropic01<SPI, CS, ActiveSession>,
}
impl<SPI: SpiDevice, CS: OutputPin> Tropic for RealChip<SPI, CS> {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        self.sess.mcounter_get(COUNTER).map_err(|_| TropicError::Comm)
    }
    fn counter_update(&mut self) -> Result<(), TropicError> {
        self.sess
            .mcounter_update(COUNTER)
            .map_err(|_| TropicError::CounterExhausted)
    }
    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        let sig = self
            .sess
            .eddsa_sign(CHIP_KEY_SLOT.into(), &message[..])
            .map_err(|_| TropicError::Comm)?;
        Ok(sig.to_vec())
    }
}

/// Deterministic, chip-rooted anchor identity (bench profile). Every field derives from the
/// TROPIC01's fused `stpub` (device cert 0) + `chip_id`, so the same chip yields the same identity
/// across reboots. Mirrors the pico's `ChipIdentity` (bench/`host_secret = None` branch).
struct ChipIdentity {
    anchor_id: [u8; 32],
    device_id: [u8; 32],
    partition_device_id: [u8; 32],
    partition_key_seed: [u8; 32],
    birth_entropy: [u8; 32],
    birth_host_nonce: [u8; 32],
    birth_witness: [u8; 32],
    online_id_label: [u8; 32],
}
impl ChipIdentity {
    fn derive(stpub: &[u8; 32], chip_id_hash: &[u8; 32]) -> Self {
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

/// Ensure the resident non-exportable Ed25519 chip key exists in `CHIP_KEY_SLOT` and return its
/// public half `pk_chip` (generate-once; persists across reboots). GATE (Stage-7, on silicon):
/// generate-once relies on `ecc_key_read` returning Err on an EMPTY slot — deliberately NOT papered
/// over so a bad read is diagnosable rather than pinning a bogus `pk_chip`.
fn ensure_chip_key<SPI: SpiDevice, CS: OutputPin>(
    sess: &mut Tropic01<SPI, CS, ActiveSession>,
) -> Result<Vec<u8>, ()> {
    if let Ok(res) = sess.ecc_key_read(CHIP_KEY_SLOT.into()) {
        return Ok(res.pub_key().to_vec());
    }
    sess.ecc_key_generate(CHIP_KEY_SLOT.into(), EccCurve::Ed25519)
        .map_err(|_| ())?;
    let res = sess.ecc_key_read(CHIP_KEY_SLOT.into()).map_err(|_| ())?;
    Ok(res.pub_key().to_vec())
}

/// Enroll: ADOPT the live counter (never `mcounter_init` — re-init would reset the anti-double-spend
/// floor), ensure the resident chip key, run the one-way birth fuse to the bundle `B` + genesis
/// frontier `h_0`. Bench/fresh-birth profile: `H0 = ENROLL_H0`, `u = H0 − live`.
fn enroll<SPI: SpiDevice, CS: OutputPin>(
    sess: &mut Tropic01<SPI, CS, ActiveSession>,
    ident: &ChipIdentity,
    policy_hash: &[u8; 32],
) -> Result<(u32, Birth), ()> {
    let live = sess.mcounter_get(COUNTER).map_err(|_| ())?;
    if live > ENROLL_H0 {
        return Err(()); // counter above enrollment H0 (unprovisioned/mis-provisioned chip)
    }
    let chip_pk = ensure_chip_key(sess)?;
    let b = birth::<SphincsPart>(&BirthInputs {
        partition_trng: &ident.birth_entropy,
        chip_birth_witness: &ident.birth_witness,
        host_nonce: &ident.birth_host_nonce,
        device_id: &ident.device_id,
        policy_hash,
        partition_device_id: &ident.partition_device_id,
        anchor_id: &ident.anchor_id,
        chip_pk: &chip_pk,
        online_id_pk: &ident.online_id_label,
        partition_key_seed: &ident.partition_key_seed,
        enrolled_counter: ENROLL_H0,
        genesis_root: &GENESIS,
    });
    Ok((ENROLL_H0, b))
}

/// Bring up the TROPIC01 from Secure and build the live appliance, storing it in `MONITOR_APP`.
/// Returns `true` on success. Fail-closed: any chip/session/enroll error leaves `MONITOR_APP =
/// None` and the SG handler refuses every authority op (`SG_ERR_INTERNAL`). Steals the peripherals
/// it needs (CLOCKS/PLL/XOSC/ROSC/TIMER0/SPI0 + GP16-19); `main` must not re-init clocks after.
///
/// SAFETY: single-threaded reset context, called once from `main` before the Non-secure launch.
pub unsafe fn init() -> bool {
    let mut pac = hal::pac::Peripherals::steal();
    let mut watchdog = hal::watchdog::Watchdog::new(pac.WATCHDOG);
    let clocks = match hal::clocks::init_clocks_and_plls(
        XTAL_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    ) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Let the TROPIC01 settle after cold power-up before the first SPI transaction (~1 s @150 MHz).
    cortex_m::asm::delay(150_000_000);

    // Ephemeral X25519 keypair for the L3 handshake (ROSC entropy).
    let rosc = hal::rosc::RingOscillator::new(pac.ROSC).initialize();
    let mut eh = [0u8; 32];
    for byte in eh.iter_mut() {
        let mut acc = 0u8;
        for _ in 0..8 {
            acc = (acc << 1) | (rosc.get_random_bit() as u8);
        }
        *byte = acc;
    }

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(pac.IO_BANK0, pac.PADS_BANK0, sio.gpio_bank0, &mut pac.RESETS);
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
    let spi_dev = match ExclusiveDevice::new(spi_bus, cs, timer) {
        Ok(d) => d,
        Err(_) => return false,
    };

    // Phase 2: read the REAL chip identity (chip_id + device-cert stpub) BEFORE session_start
    // consumes the NoSession handle. Fail closed if the chip will not disclose a real identity.
    let mut tropic = Tropic01::new(spi_dev);
    let chip_id_hash = match tropic.get_info_chip_id() {
        Ok(id) => h("DSM/anchor/chip-id/v1", &[id]),
        Err(_) => return false,
    };
    let stpub: [u8; 32] = match tropic.get_info_cert_store() {
        Ok(cs) => match cs.public_key() {
            Ok(k) => *k,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    let ident = ChipIdentity::derive(&stpub, &chip_id_hash);

    // Phase 3: authenticated L3 session (PROD0 SH0 keys).
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
        Err(_) => return false,
    };

    // Phase 4: enroll (resident chip key + birth fuse -> bundle B, frontier h_0).
    let policy_hash = h(POLICY_ID_DOMAIN, &[&[0u8][..]]);
    let (h0, b) = match enroll(&mut sess, &ident, &policy_hash) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Erase the concrete session behind `Box<dyn Tropic>` and construct the appliance.
    let chip: Box<dyn Tropic> = Box::new(RealChip { sess });
    let mut app = Appliance::<Box<dyn Tropic>, SphincsPart>::new(
        chip,
        h0,
        ident.anchor_id,
        ident.partition_device_id,
        b,
    );
    // §26 recovery before serving (no boot fence — offline is enabled once born).
    let _ = app.recover();

    let slot = &mut *core::ptr::addr_of_mut!(MONITOR_APP);
    *slot = Some(app);
    true
}

/// Authority ops (`σ`-minting / counter-moving / frontier-advancing) that the §2 measurement seal
/// must gate; STATUS and CANCEL do not change authority state and need no fresh measurement.
fn op_requires_measurement(op: i32) -> bool {
    matches!(
        pb::Op::try_from(op),
        Ok(pb::Op::Prepare | pb::Op::Commit | pb::Op::Emit | pb::Op::Finalize)
    )
}

/// Decode the Secure request copy, apply the §2 measurement gate to the DECODED op (never the
/// untrusted mailbox opcode hint), and dispatch through the REAL appliance. Returns the encoded
/// `ApplianceResponse` frame, or an `SG_ERR_*` status on a gate/decode/uninitialized failure.
///
/// SAFETY: single-threaded Secure context; the SG handler is the only caller.
pub unsafe fn service_request(frame: &[u8], measurement_ok: bool) -> Result<Vec<u8>, u32> {
    let req = decode_request(frame).map_err(|_| SG_ERR_ENCODING)?;
    if op_requires_measurement(req.op) && !measurement_ok {
        // §7.12 measurement failure => no counter movement, no TROPIC/host signature.
        return Err(SG_ERR_MEASUREMENT);
    }
    let app = (*core::ptr::addr_of_mut!(MONITOR_APP))
        .as_mut()
        .ok_or(SG_ERR_INTERNAL)?;
    Ok(encode_response(&dispatch(app, &req)))
}
