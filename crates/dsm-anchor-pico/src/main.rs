//! DSM anchor firmware — Boot Fenced Fused Anchor appliance + USB transport.
//!
//! Ladder:
//!   T1: raw SPI probe -> L2 GET_INFO chip id.
//!   T2: X25519 handshake (PROD0 pairing key, slot 0) -> encrypted L3 channel.
//!   T3 / T3b: monotonic down-counter + MAC-and-destroy primitives (two slots).
//!   T4: enrollment (one-way birth fuse -> bundle B, fused head A0, boot head J0,
//!       partition keypair) + the boot fence on the chip (anchor-core).
//!   T5: the fused flow over the prost WIRE PROTOCOL through the secure-core seam
//!       (boot -> prepare -> commit -> emit -> finalize -> status), then the
//!       emitted release is checked with the §22 receiver acceptance predicate.
//!   T6: a NON-SECURE USB receive loop that frames protobuf requests over USB-CDC
//!       into the secure core and frames responses back — the transport an
//!       external host (the DSM backend) uses to drive the appliance.
//!
//! Two signature schemes back the fused construction (anchor-core traits):
//!   - WitnessSig  = WOTS-over-BLAKE3 (`anchor_core::sig::WotsBlake3`) — the
//!     TROPIC01-keyed per-transfer hardware witness.
//!   - PartitionSig = BLAKE3-SPHINCS+ SPX128f (`dsm_sphincs`) — the RP2350 secure
//!     partition certificate (boot cert + per-transfer final cert). Same scheme
//!     the DSM receiver verifies with (byte-compatible `DSM/sphincs-kdf`).
//!
//! Mediation: the TROPIC01 session, partition key, ratchet, and `Appliance` live
//! inside [`SecureCore`], whose only public method is `handle(frame) -> frame`.
//!
//! Durable recovery: §27 recovery reads the durable `Active` at boot and re-emits
//! an interrupted committed release. This bring-up build keeps `Active` in RAM and
//! re-enrolls each boot, so the boot `recover()` here is a Ready no-op once booted.
//! Production persists `Active` (and the partition ratchet) to TROPIC01 R-memory.
//!
//! Wiring (SPI0): SCK=GP18(p24), MOSI/SDI=GP19(p25), MISO/SDO=GP16(p21),
//! CS=GP17(p22), 3V3=p36, GND=p23.

#![no_std]
#![no_main]

extern crate alloc;

use panic_halt as _;

use core::fmt::Write as _;

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
use tropic01::{ActiveSession, MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

use alloc::vec::Vec;
use anchor_core::accept::{accept_offline, CounterVerifier, DsmVerifier, VerifierContext};
use anchor_core::appliance::{Appliance, RecoverOutcome};
use anchor_core::boot::BootTicket;
use anchor_core::enrollment::{birth, Birth, BirthInputs};
use anchor_core::proto::{decode_request, decode_response, encode_request, encode_response, pb};
use anchor_core::root_advance::{CounterEvidence, Transition};
use anchor_core::service;
use anchor_core::sig::WotsBlake3;
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

const XTAL_HZ: u32 = 12_000_000;
const Q_BOOT: u16 = 5; // MACANDD boot-fence slot
const Q_TX: u16 = 6; // MACANDD transfer-witness slot
const COUNTER: MCounterIndex = MCounterIndex::Index0;
// Enrollment counter H0 = the value the monotonic counter was PROVISIONED to (bench CLI:
// `MCOUNTER_MAX`), NOT a bring-up placeholder. It is a FIXED constant so the birth ceremony is
// deterministic across reboots (stable bundle/identity); the LIVE counter (`mcounter_get`) gives the
// current H and the appliance derives u = H0 − H. The firmware ADOPTS the provisioned counter — it
// must NOT re-init it (that would reset the counter and defeat the anti-double-spend guarantee).
// NOTE (D2 reconciliation): `COUNTER` must be the SAME physical MCOUNTER index the CLI initialized AND
// the caged verifier slot the receiver reads over the relay — confirm on hardware.
const ENROLL_H0: u32 = 0xFFFF_FFFE; // tropic01 MCOUNTER_VALUE_MAX (4_294_967_294)

/// The partition certificate scheme: BLAKE3-SPHINCS+ SPX128f (fast sign, 17,088 B
/// signature, 64 B pk). The receiver verifies with the same scheme.
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;

// Enrollment / appliance / test parameters.
//
// The device identity (anchor_id, device_id, partition_device_id, partition-key
// seed, and the birth entropy inputs) is NOT a compile-time constant. It is
// derived at runtime from the real TROPIC01 — its fused device-cert public key
// (`stpub`) and `chip_id`, both read once before the secure session — so the
// SAME chip yields the SAME identity across reboots and a DIFFERENT chip yields a
// DIFFERENT identity. No per-boot RP2350 randomness enters anything the receiver
// pins as long-term identity. See `ChipIdentity`. The load-bearing anti-clone
// root is `stpub` + the live monotonic counter + the receiver pin + the DSM
// predicate; the partition co-signer key derived here is an HONEST LABEL
// (deterministic, chip-unique, NOT a silicon secret), attesting firmware
// authenticity, not chip uniqueness.
const GENESIS: [u8; 32] = [0x00; 32]; // active root hᵢ at counter 0 (genesis SMT root; host adopts A₀ via STATUS)
const NEXT_ROOT: [u8; 32] = [0x11; 32]; // self-test successor root hᵢ₊₁
const ARM0: [u8; 32] = [0xAA; 32]; // MAC-and-destroy boot-fence arming input
const RCHAL: [u8; 32] = [0x55; 32]; // self-test receiver challenge r_R
const FW: [u8; 32] = [0xF0; 32]; // firmware measurement (boot-fence input; deterministic build label)

/// The well-known offline-bearer policy id, computed identically to the host's
/// `canonical_offline_bearer_policy().policy_id` =
/// `domain_hash_bytes("DSM/offline-bearer/policy-id/well-known/v1", &[])` =
/// `BLAKE3(tag ‖ 0x00)`. Baked into the anchor bundle so `B` commits the real
/// policy. (On-chip PREPARE is policy-agnostic; the receiver enforces the
/// canonical value fail-closed. This keeps the bundle honest.)
const POLICY_ID_DOMAIN: &str = "DSM/offline-bearer/policy-id/well-known/v1";

/// Deterministic, chip-rooted anchor identity. Every field is derived from the
/// TROPIC01's fused identity (`stpub` from device cert 0 + `chip_id`). Same chip
/// ⇒ same identity across reboots; different chip ⇒ different identity.
struct ChipIdentity {
    anchor_id: [u8; 32],
    device_id: [u8; 32],
    partition_device_id: [u8; 32],
    /// Partition-key birth seed — an HONEST LABEL (deterministic + chip-unique,
    /// NOT a silicon secret; derivable from the public `stpub`/`chip_id`). The
    /// partition co-signer attests firmware authenticity, not anti-clone.
    partition_key_seed: [u8; 32],
    /// Deterministic stand-in for the birth entropy inputs (`partition_trng`,
    /// `host_nonce`) so `s_birth` → `B` is stable across reboots. Chip-rooted,
    /// not per-boot RP2350 RNG.
    birth_entropy: [u8; 32],
    birth_host_nonce: [u8; 32],
    /// Deterministic chip-rooted birth witness. The LIVE per-boot MACANDD witness
    /// stays in the boot fence (`Appliance::boot`); it must not enter the pinned
    /// identity, which has to be stable across reboots.
    birth_witness: [u8; 32],
}
impl ChipIdentity {
    /// Derive from the chip's fused `stpub` (device-cert public key) and a
    /// 32-byte digest of its `chip_id`.
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
        }
    }
}
const T_REL: [u8; 32] = [1; 32];
const T_OBJ: [u8; 32] = [2; 32];
const T_SND: [u8; 32] = [3; 32];
const T_RCV: [u8; 32] = [4; 32];
const T_PAY: [u8; 32] = [9; 32];
const T_AF: [u8; 2] = [0xAA, 0xBB];
const LEAF_OLD: [u8; 40] = [0xAB; 40]; // self-test DSM SMT proofs (verifier is trivial)
const LEAF_NEW: [u8; 40] = [0xCD; 40];

/// Receive-edge frame cap. Requests are small (a transition + slots); the large
/// release (~37 KiB with SPX128f certs) flows the other way.
const MAX_RX_FRAME: usize = 16 * 1024;

struct BufW {
    buf: [u8; 256],
    len: usize,
}
impl core::fmt::Write for BufW {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

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

/// BLAKE3-SPHINCS+ SPX128f as the partition signature scheme (PartitionSig).
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

/// Bridge anchor-core's `Tropic` trait to a libtropic-rs active session. The same
/// session serves both MACANDD slots (`q_boot`, `q_tx`) and the counter.
struct ChipTropic<'a, SPI: SpiDevice, CS: OutputPin> {
    sess: &'a mut Tropic01<SPI, CS, ActiveSession>,
}
impl<SPI: SpiDevice, CS: OutputPin> Tropic for ChipTropic<'_, SPI, CS> {
    fn mac_and_destroy(&mut self, q: u16, x: &[u8; 32]) -> Result<[u8; 32], TropicError> {
        self.sess
            .mac_and_destroy(q.into(), x)
            .map(|w| *w)
            .map_err(|_| TropicError::Comm)
    }
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        self.sess
            .mcounter_get(COUNTER)
            .map_err(|_| TropicError::Comm)
    }
    fn counter_update(&mut self) -> Result<(), TropicError> {
        self.sess
            .mcounter_update(COUNTER)
            .map_err(|_| TropicError::CounterExhausted)
    }
}
impl<SPI: SpiDevice, CS: OutputPin> ChipTropic<'_, SPI, CS> {
    /// Transparent raw-SPI relay bridge (Path-B counter read): clock `buf` to TROPIC01 and read the
    /// MISO back in place. The bytes are NOT interpreted — a remote receiver drives its own
    /// libtropic session through these opaque transactions; this device is only the SPI bridge.
    fn passthrough(&mut self, buf: &mut [u8]) -> Result<(), TropicError> {
        self.sess.l1_passthrough(buf).map_err(|_| TropicError::Comm)
    }
}

/// The secure core: owns the appliance (chip session, partition key, ratchet) and
/// exposes ONLY the protobuf request/response boundary.
struct SecureCore<'a, SPI: SpiDevice, CS: OutputPin> {
    app: Appliance<ChipTropic<'a, SPI, CS>, WotsBlake3, SphincsPart>,
}
impl<SPI: SpiDevice, CS: OutputPin> SecureCore<'_, SPI, CS> {
    fn handle(&mut self, frame: &[u8]) -> Vec<u8> {
        // OP_SPI_PASSTHROUGH is a transparent raw-SPI relay bridge, not an appliance op: clock the
        // caller's bytes straight to the chip and return the MISO. Handled here (not in the generic
        // service) because it reaches the concrete chip backend directly via `tropic_mut`.
        if let Ok(req) = decode_request(frame) {
            if req.op == pb::Op::SpiPassthrough as i32 {
                let mut buf = req.spi_payload;
                let resp = match self.app.tropic_mut().passthrough(&mut buf) {
                    Ok(()) => pb::ApplianceResponse {
                        op: req.op,
                        ok: true,
                        spi_response: buf,
                        ..Default::default()
                    },
                    Err(_) => pb::ApplianceResponse {
                        op: req.op,
                        ok: false,
                        error: 8, // TROPIC comm
                        ..Default::default()
                    },
                };
                return encode_response(&resp);
            }
        }
        service::handle(&mut self.app, frame)
    }
}

/// On-device self-test receiver. The boot-chain and partition-certificate checks
/// are real (BLAKE3-SPHINCS+ under the pinned partition pubkey); the DSM SMT
/// checks are trivial here (the firmware is the producer). A real receiver backs
/// them with the DSM state.
struct FwDsm {
    part_pk: Vec<u8>,
}
impl DsmVerifier for FwDsm {
    fn prev_root_commits_anchor_state(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: u64,
    ) -> bool {
        true
    }
    fn verify_boot_chain(
        &self,
        bundle: &[u8; 32],
        anchor_head: &[u8; 32],
        committed_boot_head: &[u8; 32],
        current_boot_head: &[u8; 32],
        boot_chain: &[BootTicket],
    ) -> bool {
        let mut prev = *committed_boot_head;
        for tk in boot_chain {
            if &tk.anchor_bundle != bundle
                || &tk.anchor_head != anchor_head
                || tk.prev_boot_head != prev
            {
                return false;
            }
            if !SphincsPart::part_verify(
                &self.part_pk,
                &tk.cert_message(),
                &tk.partition_boot_signature,
            ) {
                return false;
            }
            prev = tk.next_boot_head;
        }
        &prev == current_boot_head
    }
    fn verify_partition_certificate(&self, m_p: &[u8; 32], sigma_partition: &[u8]) -> bool {
        SphincsPart::part_verify(&self.part_pk, m_p, sigma_partition)
    }
    fn verify_transition(&self, _: &Transition) -> bool {
        true
    }
    fn delivers_to_receiver(&self, _: &Transition) -> bool {
        true
    }
    fn next_root_commits_anchor_state(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: u64,
    ) -> bool {
        true
    }
}

/// Self-test counter verifier: models a faithful chip read attesting the claimed
/// value. A real receiver opens its own authenticated L3 verifier session.
struct SelfCounter;
impl CounterVerifier for SelfCounter {
    fn read_authentic_counter(&self, _anchor: &[u8; 32], ev: &CounterEvidence) -> Option<u64> {
        Some(ev.live_counter_claim)
    }
}

/// One protocol round trip through the secure seam: encode -> handle -> decode.
fn rt<SPI: SpiDevice, CS: OutputPin>(
    core: &mut SecureCore<'_, SPI, CS>,
    req: &pb::ApplianceRequest,
) -> Result<pb::ApplianceResponse, &'static str> {
    decode_response(&core.handle(&encode_request(req))).map_err(|_| "decode_response")
}

/// Enroll: init the counter, arm both MACANDD slots, and run the one-way birth
/// fuse to produce the immutable bundle and initial fused/boot heads + partition
/// keypair. Returns `(H0, Birth)`. The boot slot's arming output seeds the TROPIC
/// birth witness.
fn enroll<SPI: SpiDevice, CS: OutputPin>(
    sess: &mut Tropic01<SPI, CS, ActiveSession>,
    ident: &ChipIdentity,
    policy_hash: &[u8; 32],
) -> Result<(u32, Birth), &'static str> {
    // ADOPT the provisioned counter — do NOT `mcounter_init` (re-init resets the physical counter and
    // would let a rebooted device re-spend already-consumed offline-bearer steps). `H0` is the fixed
    // provisioning constant `ENROLL_H0`; the live read is only a sanity floor (a healthy provisioned
    // chip reads at or below H0). Birth is deterministic over `ENROLL_H0`, so identity is stable.
    let live = sess.mcounter_get(COUNTER).map_err(|_| "mcounter_get")?;
    if live > ENROLL_H0 {
        return Err("counter above enrollment H0 (unprovisioned/mis-provisioned chip)");
    }
    // Exercise the boot-fence MACANDD slots (preserves the provisioned arming
    // interaction). The birth witness is now deterministic + chip-rooted
    // (`ident.birth_witness`), NOT this per-boot MACANDD output — so the pinned
    // bundle `B` is stable across reboots. The live per-boot MACANDD witness
    // still gates the boot fence inside `Appliance::boot`.
    sess.mac_and_destroy(Q_BOOT.into(), &ARM0)
        .map_err(|_| "arm q_boot")?;
    sess.mac_and_destroy(Q_TX.into(), &ARM0)
        .map_err(|_| "arm q_tx")?;
    let b = birth::<SphincsPart>(&BirthInputs {
        partition_trng: &ident.birth_entropy,
        tropic_birth_witness: &ident.birth_witness,
        host_nonce: &ident.birth_host_nonce,
        device_id: &ident.device_id,
        policy_hash,
        partition_device_id: &ident.partition_device_id,
        tropic_anchor_id: &ident.anchor_id,
        partition_key_seed: &ident.partition_key_seed,
        enrolled_counter: ENROLL_H0,
        q_boot: Q_BOOT,
        q_tx: Q_TX,
        genesis_root: &GENESIS,
    });
    // Return the FIXED enrollment H0 (not the live read): the appliance derives u = H0 − live.
    Ok((ENROLL_H0, b))
}

fn prepare_request(policy_hash: &[u8; 32]) -> pb::ApplianceRequest {
    pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(pb::TransitionPackage {
            relationship_id: T_REL.to_vec(),
            object_id: T_OBJ.to_vec(),
            sender_device_id: T_SND.to_vec(),
            recipient_device_id: T_RCV.to_vec(),
            prev_root: GENESIS.to_vec(),
            next_root: NEXT_ROOT.to_vec(),
            anchor_counter: 0,
            next_anchor_counter: 1,
            action_type: 0,
            action_fields: T_AF.to_vec(),
            payload_hash: T_PAY.to_vec(),
            old_leaf_proof: LEAF_OLD.to_vec(),
            new_leaf_proof: LEAF_NEW.to_vec(),
            authority_policy_hash: policy_hash.to_vec(),
        }),
        receiver_challenge: RCHAL.to_vec(),
        ..Default::default()
    }
}

struct SelfTest {
    ops_ok: bool,
    pk_len: usize,
    sig_tropic_len: usize,
    sig_partition_len: usize,
    st_counter: u64,
    st_status: u32,
    verify_ok: bool,
    root_match: bool,
}

/// Drive boot→prepare→commit→emit→finalize→status through the secure seam, then
/// verify the wire-carried release with the §22 acceptance predicate.
fn self_test<SPI: SpiDevice, CS: OutputPin>(
    core: &mut SecureCore<'_, SPI, CS>,
    part_pk: &[u8],
    anchor_id: &[u8; 32],
    policy_hash: &[u8; 32],
) -> Result<SelfTest, &'static str> {
    let bundle = core.app.bundle;
    let mut ok_all = true;
    // Boot is device-internal: establish the fence with the device-authoritative
    // measurement directly (the host wire path has no boot op), as serve_forever does.
    ok_all &= core.app.boot(1, &FW).is_ok();
    ok_all &= rt(core, &prepare_request(policy_hash))?.ok;
    ok_all &= rt(
        core,
        &pb::ApplianceRequest {
            op: pb::Op::Commit as i32,
            ..Default::default()
        },
    )?
    .ok;
    let emitr = rt(
        core,
        &pb::ApplianceRequest {
            op: pb::Op::Emit as i32,
            ..Default::default()
        },
    )?;
    ok_all &= emitr.ok;
    let relpb = emitr.release.clone();
    let (pk_len, sig_tropic_len, sig_partition_len) = relpb
        .as_ref()
        .and_then(|r| r.cert.as_ref())
        .map(|c| (c.pk_hw.len(), c.sigma_tropic.len(), c.sigma_partition.len()))
        .unwrap_or((0, 0, 0));
    let fin = rt(
        core,
        &pb::ApplianceRequest {
            op: pb::Op::Finalize as i32,
            ..Default::default()
        },
    )?;
    ok_all &= fin.ok;
    let mut fin_root = [0u8; 32];
    if fin.active_root.len() == 32 {
        fin_root.copy_from_slice(&fin.active_root);
    }
    let st = rt(
        core,
        &pb::ApplianceRequest {
            op: pb::Op::Status as i32,
            ..Default::default()
        },
    )?;
    ok_all &= st.ok;

    let verify_ok = match relpb.as_ref().and_then(|r| r.to_release().ok()) {
        Some(rel) => {
            let ctx = VerifierContext {
                accepted_prev_root: &GENESIS,
                pinned_bundle: &bundle,
                pinned_anchor_id: anchor_id,
                expected_receiver_challenge: &RCHAL,
                expected_policy_hash: policy_hash,
                enrolled_counter: ENROLL_H0 as u64,
                anchor_uncompromised: true,
            };
            let dsm = FwDsm {
                part_pk: part_pk.to_vec(),
            };
            accept_offline::<WotsBlake3, _, _>(&rel, &ctx, &dsm, &SelfCounter).is_ok()
        }
        None => false,
    };

    Ok(SelfTest {
        ops_ok: ok_all,
        pk_len,
        sig_tropic_len,
        sig_partition_len,
        st_counter: st.active_anchor_counter,
        st_status: st.status,
        verify_ok,
        root_match: fin_root == NEXT_ROOT,
    })
}

/// Serve the appliance over USB-CDC forever: read LE32-length-prefixed protobuf
/// request frames, dispatch through the secure core, write framed responses.
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
        // SPX128f signatures are 17 KiB; the release + encoding allocate well above
        // the old 64 KiB. 256 KiB leaves ample headroom on the RP2350's 512 KiB.
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

    // Three TRNG draws: handshake ephemeral, partition birth entropy, host nonce.
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
    // One TRNG draw: the secure-session handshake ephemeral (randomness is correct
    // here). The anchor birth entropy is deterministic + chip-rooted (see
    // `ChipIdentity`) — never per-boot RNG, so the pinned identity is stable.
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
    // These L2 getters are only callable BEFORE `session_start` consumes the
    // NoSession handle. The pinned anchor identity is rooted here, in silicon:
    // same chip ⇒ same identity across reboots. Fail closed (halt) if the chip
    // will not disclose a real identity — never fall back to a fake one.
    usb_dev.poll(&mut [&mut serial]);
    let mut tropic = Tropic01::new(spi_dev);
    let chip_id_hash = match tropic.get_info_chip_id() {
        Ok(id) => anchor_core::hash::h("DSM/anchor/chip-id/v1", &[id]),
        Err(_) => {
            put(&mut serial, b"[T1] chip id: FAIL (no real identity; halting)\r\n");
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
                put(&mut serial, b"[T1] cert stpub: FAIL (no real identity; halting)\r\n");
                let _ = serial.flush();
                loop {
                    usb_dev.poll(&mut [&mut serial]);
                }
            }
        },
        Err(_) => {
            put(&mut serial, b"[T1] cert store: FAIL (no real identity; halting)\r\n");
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

    // ---- Phase 4: T5 self-test (own appliance), reported briefly ----
    put(
        &mut serial,
        b"[T5] self-test (boot-fenced fused protocol, secure-core seam)...\r\n",
    );
    let _ = serial.flush();
    usb_dev.poll(&mut [&mut serial]);
    let st = match enroll(&mut sess, &ident, &policy_hash) {
        Ok((h0, b)) => {
            let part_pk = b.partition_pk.clone();
            let mut core = SecureCore {
                app: Appliance::<_, WotsBlake3, SphincsPart>::new(
                    ChipTropic { sess: &mut sess },
                    h0,
                    ident.anchor_id,
                    Q_BOOT,
                    Q_TX,
                    ident.partition_device_id,
                    GENESIS,
                    b,
                ),
            };
            self_test(&mut core, &part_pk, &ident.anchor_id, &policy_hash)
        }
        Err(e) => Err(e),
    };
    {
        let mut w = BufW {
            buf: [0u8; 256],
            len: 0,
        };
        match &st {
            Ok(r) => {
                let pass = r.ops_ok
                    && r.pk_len == 32
                    && r.sig_tropic_len == 67 * 32
                    && r.sig_partition_len == dsm_sphincs::signature_bytes(PART_VARIANT)
                    && r.st_counter == 1
                    && r.st_status == 0 // Ready
                    && r.verify_ok
                    && r.root_match;
                let _ = write!(
                    w,
                    "[T5] {}  ops_ok={} pk={}B sigT={}B sigP={}B status(u={},st={}) verify={}({})\r\n",
                    if pass { "PASS" } else { "FAIL" },
                    r.ops_ok,
                    r.pk_len,
                    r.sig_tropic_len,
                    r.sig_partition_len,
                    r.st_counter,
                    r.st_status,
                    if r.verify_ok { "accepted" } else { "REJECTED" },
                    if r.root_match { "root ok" } else { "root MISMATCH" },
                );
            }
            Err(e) => {
                let _ = write!(w, "[T5] FAIL at step: {}\r\n", e);
            }
        }
        let report_until = timer.get_counter().ticks() + 4_000_000;
        let mut last = timer.get_counter();
        put(&mut serial, &w.buf[..w.len]);
        let _ = serial.flush();
        while timer.get_counter().ticks() < report_until {
            usb_dev.poll(&mut [&mut serial]);
            if (timer.get_counter() - last).to_millis() >= 2000 {
                last = timer.get_counter();
                put(&mut serial, &w.buf[..w.len]);
                let _ = serial.flush();
            }
        }
    }

    // ---- Phase 5: T6 serve the appliance over USB-CDC for an external host ----
    put(
        &mut serial,
        b"[T6] serving boot-fenced fused appliance over USB-CDC (LE32-len-prefixed protobuf)\r\n",
    );
    let _ = serial.flush();
    let (h0, b) = enroll(&mut sess, &ident, &policy_hash).unwrap_or_else(|_| {
        // Re-enrollment should not fail after a good session; fall back to a birth
        // from the SAME deterministic chip-rooted identity so the device still
        // serves the same anchor (never a fresh/fake one).
        let b = birth::<SphincsPart>(&BirthInputs {
            partition_trng: &ident.birth_entropy,
            tropic_birth_witness: &ident.birth_witness,
            host_nonce: &ident.birth_host_nonce,
            device_id: &ident.device_id,
            policy_hash: &policy_hash,
            partition_device_id: &ident.partition_device_id,
            tropic_anchor_id: &ident.anchor_id,
            partition_key_seed: &ident.partition_key_seed,
            enrolled_counter: ENROLL_H0,
            q_boot: Q_BOOT,
            q_tx: Q_TX,
            genesis_root: &GENESIS,
        });
        (ENROLL_H0, b)
    });
    let mut core = SecureCore {
        app: Appliance::<_, WotsBlake3, SphincsPart>::new(
            ChipTropic { sess: &mut sess },
            h0,
            ident.anchor_id,
            Q_BOOT,
            Q_TX,
            ident.partition_device_id,
            GENESIS,
            b,
        ),
    };
    // Boot fence: advance the boot head once this power cycle so offline mode is
    // enabled, then run §27 recovery before serving.
    let _ = core.app.boot(1, &FW);
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
        c"DSM anchor (boot-fenced fused appliance + USB transport)"
    ),
    hal::binary_info::rp_program_build_attribute!(),
];
