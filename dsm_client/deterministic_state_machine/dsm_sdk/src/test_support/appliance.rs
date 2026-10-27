// SPDX-License-Identifier: Apache-2.0

//! The anchor appliance on the host, for tests (owner ruling 2026-09-27): the
//! real anchor-core appliance — PREPARE, COMMIT, EMIT, FINALIZE, its counter
//! floor, its three-signature release, its durable record and its
//! provisioning — on a board in software, installed through the production
//! seam ([`crate::bridge::install_anchor_appliance_factory`]).
//!
//! The board is the only part in software, and it is a whole board: a
//! TROPIC01 with a down-counter that refuses past zero and a resident Ed25519
//! key that signs the root-advance message and never leaves the chip value,
//! and the R-memory the appliance keeps its durable record in. Both sit on one
//! supply, which a test can cut at a numbered record write — before it lands
//! or just after — to reach every crash point of the flow; a reboot births the
//! appliance again from its chip and the provisioning its record holds, and
//! runs §26 boot recovery before it serves. The partition key is the RP2350
//! scheme the receiver verifies with (BLAKE3-SPHINCS+ SPX128f,
//! `bluetooth::anchor_accept`), generated at birth from the partition's seed.
//!
//! A physical chip draws its birth entropy from its TRNG and its resident key
//! from its die; this one expands its seed with BLAKE3's key derivation, one
//! context per input. The seed is the only typed-in value.

use std::sync::{Arc, Mutex, MutexGuard};

use anchor_core::appliance::RecoverOutcome;
use anchor_core::durable::{ActiveStore, DurableAppliance, DurableBootRefusal, StoreError};
use anchor_core::enrollment::{ChipBirth, Provisioning};
use anchor_core::root_advance::Transition;
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};
use ed25519_dalek::{Signer, SigningKey};

use crate::anchor::{AnchorAppliance, AnchorPin, ApplianceStatus};
use crate::test_support::two_device::TestDevice;
use dsm::types::error::DsmError;

/// The partition scheme the receiver verifies `σ^host` with.
const PARTITION_VARIANT: dsm::crypto::sphincs::SphincsVariant =
    dsm::crypto::sphincs::SphincsVariant::SPX128f;

/// The value behind `m`, whether or not a test panicked while holding it.
fn held<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The board's one supply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Power {
    On,
    Off,
}

/// Where a test cuts the supply, counted in record writes since the cut was set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cut {
    Never,
    /// The power goes off as write `n` starts: it does not land.
    AtWrite(u32),
    /// Write `n` lands, then the power goes off.
    AfterWrite(u32),
}

struct Supply {
    power: Power,
    cut: Cut,
    writes: u32,
}

#[derive(Clone)]
struct Board(Arc<Mutex<Supply>>);

impl Board {
    fn powered(&self) -> Result<(), TropicError> {
        match held(&self.0).power {
            Power::On => Ok(()),
            Power::Off => Err(TropicError::Comm),
        }
    }

    fn write_starts(&self) -> Result<(), StoreError> {
        let mut s = held(&self.0);
        if s.power == Power::Off {
            return Err(StoreError::Unavailable);
        }
        s.writes += 1;
        if s.cut == Cut::AtWrite(s.writes) {
            s.power = Power::Off;
            return Err(StoreError::Unavailable);
        }
        Ok(())
    }

    fn write_landed(&self) {
        let mut s = held(&self.0);
        if s.cut == Cut::AfterWrite(s.writes) {
            s.power = Power::Off;
        }
    }
}

/// A TROPIC01 in software: its monotonic down-counter `H`, which lives on the die across reboots,
/// and its resident Ed25519 key.
pub struct SoftwareTropic {
    board: Board,
    counter: Arc<Mutex<u32>>,
    resident: SigningKey,
}

impl Tropic for SoftwareTropic {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        self.board.powered()?;
        Ok(*held(&self.counter))
    }

    fn counter_update(&mut self) -> Result<(), TropicError> {
        self.board.powered()?;
        let mut h = held(&self.counter);
        *h = h.checked_sub(1).ok_or(TropicError::CounterExhausted)?;
        Ok(())
    }

    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        self.board.powered()?;
        Ok(self.resident.sign(message).to_bytes().to_vec())
    }
}

/// The R-memory slot the appliance keeps its durable record in, on the board's supply.
#[derive(Clone)]
pub struct SoftwareRMemory {
    board: Board,
    slot: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ActiveStore for SoftwareRMemory {
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        self.board.write_starts()?;
        *held(&self.slot) = Some(record.to_vec());
        self.board.write_landed();
        Ok(())
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        match held(&self.board.0).power {
            Power::On => Ok(held(&self.slot).clone()),
            Power::Off => Err(StoreError::Unavailable),
        }
    }
}

/// The RP2350 partition scheme: BLAKE3-SPHINCS+ SPX128f, as the receiver
/// verifies it.
pub struct SphincsPartition;

impl PartitionSig for SphincsPartition {
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        match dsm::crypto::sphincs::generate_keypair_from_seed(PARTITION_VARIANT, seed) {
            Ok(kp) => (kp.secret_key.clone(), kp.public_key.clone()),
            Err(e) => panic!("the partition keypair from its seed: {e}"),
        }
    }

    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        match dsm::crypto::sphincs::sign(PARTITION_VARIANT, sk, digest) {
            Ok(sig) => sig,
            Err(e) => panic!("the partition signs: {e}"),
        }
    }

    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        matches!(
            dsm::crypto::sphincs::verify(PARTITION_VARIANT, pk, digest, sig),
            Ok(valid) if valid
        )
    }
}

type Durable = DurableAppliance<SoftwareTropic, SphincsPartition, SoftwareRMemory>;

/// What the appliance is between power-ups: never provisioned, serving, or refusing to serve
/// after boot recovery refused it.
enum Served {
    Unprovisioned,
    Serving(Box<Durable>),
    Refused(DurableBootRefusal),
}

struct Anchor {
    board: Board,
    counter: Arc<Mutex<u32>>,
    rmemory: SoftwareRMemory,
    chip_seed: [u8; 32],
    enrolled_counter: u32,
    served: Served,
}

impl Anchor {
    fn derive(&self, input: &str) -> [u8; 32] {
        blake3::derive_key(
            &format!("DSM test software TROPIC01 2026-09-27 {input}"),
            &self.chip_seed,
        )
    }

    fn resident(&self) -> SigningKey {
        SigningKey::from_bytes(&self.derive("resident key"))
    }

    fn chip(&self) -> SoftwareTropic {
        SoftwareTropic {
            board: self.board.clone(),
            counter: self.counter.clone(),
            resident: self.resident(),
        }
    }

    fn chip_birth(&self) -> ChipBirth {
        ChipBirth {
            anchor_id: self.derive("static identity"),
            partition_device_id: self.derive("partition device id"),
            chip_pk: self.resident().verifying_key().to_bytes().to_vec(),
            enrolled_counter: self.enrolled_counter,
            partition_trng: self.derive("partition trng"),
            chip_birth_witness: self.derive("chip birth witness"),
            host_nonce: self.derive("host nonce"),
            partition_key_seed: self.derive("partition key seed"),
        }
    }

    fn serving(&mut self) -> Result<&mut Durable, DsmError> {
        match &mut self.served {
            Served::Serving(d) => Ok(d),
            Served::Unprovisioned => Err(DsmError::invalid_operation(
                "anchor appliance: not provisioned",
            )),
            Served::Refused(why) => Err(DsmError::invalid_operation(format!(
                "anchor appliance: boot recovery refused to serve: {why:?}"
            ))),
        }
    }
}

/// One appliance, held as a chip is held: every attach reaches the same one,
/// so its counter and its frontier are the ones every transfer sees.
#[derive(Clone)]
pub struct HostAppliance {
    anchor: Arc<Mutex<Anchor>>,
}

fn appliance_error(what: &str, e: impl std::fmt::Debug) -> DsmError {
    DsmError::invalid_operation(format!("anchor appliance {what}: {e:?}"))
}

/// What `device` provisions an anchor with: its device id, its online key,
/// the offline-bearer policy and its genesis — what `CoreSDK` provisions with.
pub fn provisioning_of(device: &TestDevice) -> Provisioning {
    Provisioning {
        device_id: device.device_id,
        online_id_pk: device.ak_pk.clone(),
        policy_hash: dsm::types::operations::canonical_offline_bearer_policy().policy_id,
        genesis_root: device.genesis,
    }
}

impl HostAppliance {
    /// A chip as it leaves the factory: seeded with `chip_seed`, enrolled
    /// with `enrolled_counter` counter steps, never provisioned.
    pub fn unprovisioned(chip_seed: [u8; 32], enrolled_counter: u32) -> Self {
        let board = Board(Arc::new(Mutex::new(Supply {
            power: Power::On,
            cut: Cut::Never,
            writes: 0,
        })));
        Self {
            anchor: Arc::new(Mutex::new(Anchor {
                rmemory: SoftwareRMemory {
                    board: board.clone(),
                    slot: Arc::new(Mutex::new(None)),
                },
                board,
                counter: Arc::new(Mutex::new(enrolled_counter)),
                chip_seed,
                enrolled_counter,
                served: Served::Unprovisioned,
            })),
        }
    }

    /// The appliance provisioned for `device`, its chip seeded with
    /// `chip_seed` and enrolled with `enrolled_counter` counter steps.
    pub fn birth(device: &TestDevice, chip_seed: [u8; 32], enrolled_counter: u32) -> Self {
        let mut appliance = Self::unprovisioned(chip_seed, enrolled_counter);
        if let Err(e) = appliance.provision(&provisioning_of(device)) {
            panic!("the appliance provisions for its device: {e}");
        }
        appliance
    }

    /// Install this appliance as the process's anchor appliance: every
    /// `CoreSDK` that attaches one attaches this one, until the returned
    /// handle drops and the process has none again.
    #[must_use = "the appliance stays installed only while the handle lives"]
    pub fn install(self) -> InstalledAppliance {
        let appliance = self.clone();
        crate::bridge::install_anchor_appliance_factory(Arc::new(move || {
            Ok(Box::new(appliance.clone()) as Box<dyn AnchorAppliance + Send>)
        }));
        InstalledAppliance { appliance: self }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Durable) -> Result<R, DsmError>) -> Result<R, DsmError> {
        f(held(&self.anchor).serving()?)
    }

    /// Cut the supply at a record write counted from now.
    pub fn cut(&self, cut: Cut) {
        let anchor = held(&self.anchor);
        let mut s = held(&anchor.board.0);
        s.cut = cut;
        s.writes = 0;
    }

    /// Whether the supply is on.
    pub fn power(&self) -> Power {
        held(&held(&self.anchor).board.0).power
    }

    /// Power restored: the appliance born again from its chip and the
    /// provisioning its R-memory holds, its state the record's, and §26 boot
    /// recovery deciding whether it serves — what the firmware does at boot.
    pub fn reboot(&self) {
        let mut anchor = held(&self.anchor);
        {
            let mut s = held(&anchor.board.0);
            s.power = Power::On;
            s.cut = Cut::Never;
            s.writes = 0;
        }
        let restored =
            DurableAppliance::restore(&anchor.chip_birth(), anchor.chip(), anchor.rmemory.clone());
        anchor.served = match restored {
            Ok(mut d) => match d.recover_at_boot() {
                Ok(()) => Served::Serving(Box::new(d)),
                Err(why) => Served::Refused(why),
            },
            Err(anchor_core::durable::DurableError::NotProvisioned) => Served::Unprovisioned,
            Err(e) => panic!("the record restores: {e:?}"),
        };
    }

    /// The chip's counter `H`.
    pub fn chip_counter(&self) -> u32 {
        *held(&held(&self.anchor).counter)
    }

    /// The pin of the provisioned appliance.
    pub fn pin(&self) -> AnchorPin {
        match self.clone().provisioned_pin() {
            Ok(Some(pin)) => pin,
            other => panic!("the appliance is provisioned and serving: {other:?}"),
        }
    }
}

/// An appliance installed as the process's anchor appliance; dropping it
/// uninstalls it. An installation that outlived its test leaked into every
/// later test in the process: the offline-cash gate tests, which assert what a
/// device with no appliance is refused, found this one attached.
pub struct InstalledAppliance {
    appliance: HostAppliance,
}

impl std::ops::Deref for InstalledAppliance {
    type Target = HostAppliance;
    fn deref(&self) -> &HostAppliance {
        &self.appliance
    }
}

impl Drop for InstalledAppliance {
    fn drop(&mut self) {
        crate::bridge::uninstall_anchor_appliance_factory();
    }
}

impl AnchorAppliance for HostAppliance {
    fn status(&mut self) -> Result<ApplianceStatus, DsmError> {
        self.with(|d| {
            let a = d.appliance();
            Ok(ApplianceStatus {
                root: a.active.root,
                anchor_counter: a.active.anchor_counter,
            })
        })
    }

    fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), DsmError> {
        self.with(|d| {
            d.prepare(
                t,
                receiver_challenge,
                sender_device_root_before,
                sender_device_root_after,
            )
            .map_err(|e| appliance_error("prepare", e))
        })
    }

    fn commit(&mut self) -> Result<(), DsmError> {
        self.with(|d| d.commit().map_err(|e| appliance_error("commit", e)))
    }

    fn emit(&mut self) -> Result<Vec<u8>, DsmError> {
        self.with(|d| {
            d.emit()
                .map(|release| anchor_core::proto::encode_release(&release.to_pb()))
                .map_err(|e| appliance_error("emit", e))
        })
    }

    fn finalize(&mut self) -> Result<[u8; 32], DsmError> {
        self.with(|d| d.finalize().map_err(|e| appliance_error("finalize", e)))
    }

    fn cancel(&mut self) -> Result<(), DsmError> {
        self.with(|d| d.cancel().map_err(|e| appliance_error("cancel", e)))
    }

    fn provisioned_pin(&mut self) -> Result<Option<AnchorPin>, DsmError> {
        let mut anchor = held(&self.anchor);
        if matches!(anchor.served, Served::Unprovisioned) {
            return Ok(None);
        }
        let a = anchor.serving()?.appliance();
        Ok(Some(AnchorPin {
            bundle: a.bundle,
            anchor_id: a.anchor_id,
            enrolled_counter: u64::from(a.h0),
            partition_pk: a.partition_pk.clone(),
            pk_chip: a.chip_pk.clone(),
            birth_commitment: a.birth_commitment,
        }))
    }

    fn provision(&mut self, provisioning: &Provisioning) -> Result<AnchorPin, DsmError> {
        {
            let mut anchor = held(&self.anchor);
            if !matches!(anchor.served, Served::Unprovisioned) {
                return Err(appliance_error(
                    "provision",
                    anchor_core::durable::DurableError::AlreadyProvisioned,
                ));
            }
            let d = DurableAppliance::provision(
                &anchor.chip_birth(),
                anchor.chip(),
                anchor.rmemory.clone(),
                provisioning.clone(),
            )
            .map_err(|e| appliance_error("provision", e))?;
            anchor.served = Served::Serving(Box::new(d));
        }
        self.provisioned_pin()?
            .ok_or_else(|| DsmError::invalid_operation("anchor appliance: provisioned, yet no pin"))
    }

    fn recover(&mut self) -> Result<RecoverOutcome, DsmError> {
        self.with(|d| Ok(d.recover()))
    }
}
