// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery bundle (spec §0.5, Phase C) — the transmitted succession artifacts.
//!
//! A [`RecoveryBundle`] carries the genesis-anchored recovery authority pubkey
//! (`K_A_pub`), the tombstone/succession pair, and the [`RecoveryActivationSeal`]. It is
//! deliberately LIGHT: it does NOT inline per-counterparty
//! [`crate::recovery::CrossRelationshipSuccessionEvidence`].
//!
//! Why no inlined evidence: per the §0.5 posted-state authority, each counterparty's
//! succession evidence is **re-derived and re-verified from that counterparty's OWN
//! posted, genesis-authenticated state** — its PDSMT head + relationship state history,
//! fetched from storage, not bundled. (Adversarial review confirmed this: with both
//! endpoints pinned — the capsule floor `h_cap` and `t_old_current` in C's signed head —
//! and DSM being deterministic + collision-resistant, the forward-only walk is unique, so
//! the verifier reconstructs the evidence rather than trusting a transmitted copy.) The
//! seal's `evidence_root` commits the verified per-C outcomes; the bundle carries the
//! authorization (tombstone/succession), the authority to check it against the anchor,
//! and the committed seal.
//!
//! Wire: a protobuf container of nested canonical sub-object encodings (each via its own
//! codec). Protobuf-only, fail-closed decode.

use crate::recovery::activation::RecoveryActivationSeal;
use crate::recovery::tombstone::{SuccessionReceipt, TombstoneReceipt};
use crate::types::error::DsmError;
use crate::types::proto::{Message as _, RecoveryBundleV1};

/// The transmitted recovery succession artifacts (§0.5 Phase C).
#[derive(Clone, Debug)]
pub struct RecoveryBundle {
    /// The genesis-anchored recovery authority public key (`K_A_pub`). The verifier binds
    /// it to the device's [`crate::recovery::RecoveryAuthorityAnchor`] before trusting the
    /// tombstone/succession signatures.
    pub authority_pubkey: Vec<u8>,
    pub tombstone: TombstoneReceipt,
    pub succession: SuccessionReceipt,
    pub activation_seal: RecoveryActivationSeal,
}

impl RecoveryBundle {
    /// Serialize to canonical protobuf bytes (nested sub-object encodings).
    pub fn to_bytes(&self) -> Vec<u8> {
        RecoveryBundleV1 {
            authority_pubkey: self.authority_pubkey.clone(),
            tombstone: self.tombstone.to_bytes(),
            succession: self.succession.to_bytes(),
            activation_seal: self.activation_seal.to_bytes(),
        }
        .encode_to_vec()
    }

    /// Deserialize from protobuf bytes (fail-closed: every nested sub-object must decode).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = RecoveryBundleV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("RecoveryBundle::from_bytes: {e}"),
                "RecoveryBundle",
                None::<String>,
                Some(e),
            )
        })?;
        if p.authority_pubkey.is_empty() {
            return Err(DsmError::verification(
                "RecoveryBundle: empty authority_pubkey",
            ));
        }
        Ok(Self {
            authority_pubkey: p.authority_pubkey,
            tombstone: TombstoneReceipt::from_bytes(&p.tombstone)?,
            succession: SuccessionReceipt::from_bytes(&p.succession)?,
            activation_seal: RecoveryActivationSeal::from_bytes(&p.activation_seal)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::recovery::tombstone::{create_succession, create_tombstone};
    use std::collections::BTreeSet;

    fn sample_bundle() -> (RecoveryBundle, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("kp");
        let device_id = "DEV_BUNDLE";
        let tombstone =
            create_tombstone(&[0x01; 32], 0, &[0x02; 32], device_id, &kp.secret_key).expect("t");
        let succession = create_succession(
            &tombstone.tombstone_hash,
            &[0xAA; 32].to_vec(),
            device_id,
            &kp.secret_key,
        )
        .expect("s");

        let members: BTreeSet<[u8; 32]> = [[0xC1; 32], [0xC2; 32]].into_iter().collect();
        let seal = RecoveryActivationSeal {
            genesis_id: [0x6E; 32],
            old_device_id: [0xA0; 32],
            new_device_id: [0xA1; 32],
            recovery_intent_digest: [0x03; 32],
            tombstone_proposal_digest: [0x04; 32],
            contact_set_commit: crate::recovery::capsule::contact_set_commit_from_device_ids(
                &members,
            ),
            evidence_root: [0xEE; 32],
            synced_contact_count: members.len() as u64,
            final_per_device_smt_root: [0x05; 32],
            final_receipt_roll: [0x06; 32],
        };

        let bundle = RecoveryBundle {
            authority_pubkey: kp.public_key.clone(),
            tombstone,
            succession,
            activation_seal: seal,
        };
        (bundle, kp.public_key.clone())
    }

    #[test]
    fn bundle_round_trips() {
        let (bundle, _pk) = sample_bundle();
        let decoded = RecoveryBundle::from_bytes(&bundle.to_bytes()).expect("decode");
        // Sub-objects survive (field-equality; receipts/seal compared by their fields).
        assert_eq!(decoded.authority_pubkey, bundle.authority_pubkey);
        assert_eq!(
            decoded.tombstone.tombstone_hash,
            bundle.tombstone.tombstone_hash
        );
        assert_eq!(decoded.tombstone.signature, bundle.tombstone.signature);
        assert_eq!(
            decoded.succession.succession_hash,
            bundle.succession.succession_hash
        );
        assert_eq!(decoded.activation_seal, bundle.activation_seal);
        // Re-encode is byte-identical (canonical).
        assert_eq!(bundle.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn bundle_rejects_empty_authority_pubkey() {
        let (bundle, _pk) = sample_bundle();
        let mut p = RecoveryBundleV1::decode(bundle.to_bytes().as_slice()).unwrap();
        p.authority_pubkey.clear();
        assert!(RecoveryBundle::from_bytes(&p.encode_to_vec()).is_err());
    }

    #[test]
    fn bundle_rejects_corrupt_nested_seal() {
        let (bundle, _pk) = sample_bundle();
        let mut p = RecoveryBundleV1::decode(bundle.to_bytes().as_slice()).unwrap();
        p.activation_seal = vec![0xFF; 8]; // not a valid RecoveryActivationSealProto
        assert!(RecoveryBundle::from_bytes(&p.encode_to_vec()).is_err());
    }
}
