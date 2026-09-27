// SPDX-License-Identifier: Apache-2.0

//! The anchor appliance on the host, for tests (owner ruling 2026-09-27): the
//! real anchor-core [`Appliance`] — PREPARE, COMMIT, EMIT, FINALIZE, its counter
//! floor and its three-signature release — over a TROPIC01 in software,
//! installed through the production seam
//! ([`crate::bridge::install_anchor_appliance_factory`]).
//!
//! The chip is the only part in software, and it is a whole chip: a
//! down-counter that refuses past zero, and a resident Ed25519 key that signs
//! the root-advance message and never leaves the chip value. The partition key
//! is the RP2350 scheme the receiver verifies with (BLAKE3-SPHINCS+ SPX128f,
//! `bluetooth::anchor_accept`), generated at birth from the partition's seed.
//! The birth itself is anchor-core's own ceremony over the device's identity:
//! its device id, its AK, its genesis root and the offline-bearer policy.
//!
//! A physical chip draws its birth entropy from its TRNG and its resident key
//! from its die; this one expands its seed with BLAKE3's key derivation, one
//! context per input. The seed is the only typed-in value.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use anchor_core::appliance::{Appliance, RecoverOutcome};
use anchor_core::enrollment::{birth, BirthInputs};
use anchor_core::root_advance::Transition;
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};
use ed25519_dalek::{Signer, SigningKey};

use crate::anchor::{AnchorAppliance, AnchorPin, ApplianceStatus};
use crate::test_support::two_device::TestDevice;
use dsm::types::error::DsmError;

/// The partition scheme the receiver verifies `σ^host` with.
const PARTITION_VARIANT: dsm::crypto::sphincs::SphincsVariant =
    dsm::crypto::sphincs::SphincsVariant::SPX128f;

/// A TROPIC01 in software: its monotonic down-counter `H` and its resident
/// Ed25519 key.
pub struct SoftwareTropic {
    counter: u32,
    resident: SigningKey,
}

impl Tropic for SoftwareTropic {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        Ok(self.counter)
    }

    fn counter_update(&mut self) -> Result<(), TropicError> {
        self.counter = self
            .counter
            .checked_sub(1)
            .ok_or(TropicError::CounterExhausted)?;
        Ok(())
    }

    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        Ok(self.resident.sign(message).to_bytes().to_vec())
    }
}

/// The RP2350 partition scheme: BLAKE3-SPHINCS+ SPX128f, as the receiver
/// verifies it.
pub struct SphincsPartition;

impl PartitionSig for SphincsPartition {
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let kp = dsm::crypto::sphincs::generate_keypair_from_seed(PARTITION_VARIANT, seed)
            .expect("the partition keypair from its seed");
        (kp.secret_key.clone(), kp.public_key.clone())
    }

    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        dsm::crypto::sphincs::sign(PARTITION_VARIANT, sk, digest).expect("the partition signs")
    }

    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        dsm::crypto::sphincs::verify(PARTITION_VARIANT, pk, digest, sig).unwrap_or(false)
    }
}

/// One appliance, held as a chip is held: every attach reaches the same one,
/// so its counter and its frontier are the ones every transfer sees.
#[derive(Clone)]
pub struct HostAppliance {
    inner: Arc<Mutex<Appliance<SoftwareTropic, SphincsPartition>>>,
    enrolled_counter: u32,
}

fn appliance_error(what: &str, e: impl std::fmt::Debug) -> DsmError {
    DsmError::invalid_operation(format!("anchor appliance {what}: {e:?}"))
}

impl HostAppliance {
    /// The appliance born for `device`, its chip seeded with `chip_seed` and
    /// enrolled with `enrolled_counter` counter steps.
    pub fn birth(device: &TestDevice, chip_seed: [u8; 32], enrolled_counter: u32) -> Self {
        let derive = |input: &str| {
            blake3::derive_key(
                &format!("DSM test software TROPIC01 2026-09-27 {input}"),
                &chip_seed,
            )
        };
        let resident = SigningKey::from_bytes(&derive("resident key"));
        let chip_pk = resident.verifying_key().to_bytes().to_vec();
        let anchor_id = derive("static identity");
        let partition_device_id = derive("partition device id");
        let policy_hash = dsm::types::operations::canonical_offline_bearer_policy().policy_id;
        let born = birth::<SphincsPartition>(&BirthInputs {
            partition_trng: &derive("partition trng"),
            chip_birth_witness: &derive("chip birth witness"),
            host_nonce: &derive("host nonce"),
            device_id: &device.device_id,
            policy_hash: &policy_hash,
            partition_device_id: &partition_device_id,
            anchor_id: &anchor_id,
            chip_pk: &chip_pk,
            online_id_pk: &device.ak_pk,
            partition_key_seed: &derive("partition key seed"),
            enrolled_counter,
            genesis_root: &device.smt_root,
        });
        let appliance = Appliance::new(
            SoftwareTropic {
                counter: enrolled_counter,
                resident,
            },
            enrolled_counter,
            anchor_id,
            partition_device_id,
            born,
        );
        Self {
            inner: Arc::new(Mutex::new(appliance)),
            enrolled_counter,
        }
    }

    /// Install this appliance as the process's anchor appliance: every
    /// `CoreSDK` that attaches one from now on attaches this one.
    pub fn install(&self) {
        let appliance = self.clone();
        crate::bridge::install_anchor_appliance_factory(Arc::new(move || {
            Ok(Box::new(appliance.clone()) as Box<dyn AnchorAppliance + Send>)
        }));
    }

    fn with<R>(&self, f: impl FnOnce(&mut Appliance<SoftwareTropic, SphincsPartition>) -> R) -> R {
        f(&mut self.inner.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

impl AnchorAppliance for HostAppliance {
    fn status(&mut self) -> Result<ApplianceStatus, DsmError> {
        Ok(self.with(|a| ApplianceStatus {
            root: a.active.root,
            anchor_counter: a.active.anchor_counter,
        }))
    }

    fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), DsmError> {
        self.with(|a| {
            a.prepare(
                t,
                receiver_challenge,
                sender_device_root_before,
                sender_device_root_after,
            )
        })
        .map_err(|e| appliance_error("prepare", e))
    }

    fn commit(&mut self) -> Result<(), DsmError> {
        self.with(|a| a.commit())
            .map_err(|e| appliance_error("commit", e))
    }

    fn emit(&mut self) -> Result<Vec<u8>, DsmError> {
        self.with(|a| {
            a.emit()
                .map(|release| anchor_core::proto::encode_release(&release.to_pb()))
        })
        .map_err(|e| appliance_error("emit", e))
    }

    fn finalize(&mut self) -> Result<[u8; 32], DsmError> {
        self.with(|a| a.finalize())
            .map_err(|e| appliance_error("finalize", e))
    }

    fn cancel(&mut self) -> Result<(), DsmError> {
        self.with(|a| a.cancel())
            .map_err(|e| appliance_error("cancel", e))
    }

    fn pin(&self) -> AnchorPin {
        self.with(|a| AnchorPin {
            bundle: a.bundle,
            anchor_id: a.anchor_id,
            enrolled_counter: u64::from(self.enrolled_counter),
            partition_pk: a.partition_pk.clone(),
            pk_chip: a.chip_pk.clone(),
        })
    }

    fn recover(&mut self) -> Result<RecoverOutcome, DsmError> {
        Ok(self.with(|a| a.recover()))
    }
}
