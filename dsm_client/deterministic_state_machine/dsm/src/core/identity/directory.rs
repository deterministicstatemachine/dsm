// SPDX-License-Identifier: MIT OR Apache-2.0

//! The device directory: each device's own, self-signed entry (owner,
//! 2026-09-23).
//!
//! A device writes its own entry — its genesis, its device id, its authority
//! key AK, its birth attestation AttA, its Kyber key, a counter and its P0–P6
//! authority evidence at a transition it names — signed with AK, to a keyed
//! cell every member of the set holds. A node stores every entry it is given
//! and checks nothing: it has no authority over whose entry is whose. A sender
//! reads the cell and keeps the entry that proves itself:
//!
//! 1. `DevID = H("DSM/devid" ‖ AK ‖ AttA)` equals the device id the entry names,
//!    so the AK is the one the device id commits;
//! 2. the signature verifies under that AK;
//! 3. P0–P6, run on the entry's evidence at the transition it names with
//!    nothing fetched, prove that AK as the owner authority of the device
//!    under the genesis the entry names (DSM Amendment A18): the genesis
//!    recomputes from its parameters and commits the GRK, the delegation and
//!    transition chain authenticates under it, and the device is a leaf of
//!    the tree at that transition;
//! 4. among entries that pass, the highest counter wins, so a device can
//!    update its own entry.
//!
//! Knowing a device id is not enough to write a valid entry for it: that takes
//! an AK hashing to the id and a signature by it. Naming a genesis is not
//! enough to be one of its devices: only that genesis's GRK delegates its
//! tree. A squatter's junk fails the check and is ignored, and no one can lock
//! a device out.

use prost::Message;

use crate::common::domain_tags::{TAG_DSM_DEVICE_DIRECTORY_ENTRY, TAG_DSM_DEVICE_DIRECTORY_KEY};
use crate::core::identity::genesis_v2::derive_devid;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::economic::authority_evidence::verify_authority_evidence;
use crate::crypto::sphincs;
use crate::types::proto;

/// The cell namespace every directory entry is written under.
pub const DIRECTORY_NAMESPACE: &[u8] = b"DSM/device-directory/v1";

/// An AK public key (SPHINCS+ SPX256f).
pub const AK_PUBLIC_KEY_LEN: usize = 64;

/// A Kyber (ML-KEM-768) public key.
pub const KYBER_PUBLIC_KEY_LEN: usize = 1184;

/// The cell a device's entries live in: one per (genesis, device).
pub fn directory_cell_key(genesis: &[u8; 32], device_id: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_DEVICE_DIRECTORY_KEY);
    h.update(genesis);
    h.update(device_id);
    *h.finalize().as_bytes()
}

/// What an entry states about its device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntryBody {
    pub genesis: [u8; 32],
    pub device_id: [u8; 32],
    pub ak_public_key: Vec<u8>,
    pub att_a: [u8; 32],
    pub kyber_public_key: Vec<u8>,
    /// Higher replaces lower. Only the device can sign one.
    pub counter: u64,
    /// The transition `t` the evidence's chain reaches: the position P0–P6
    /// prove the device's authority at (descent at `t`, not currency).
    pub authority_position: [u8; 32],
    /// The device's P0–P6 authority evidence, the exact bytes of an
    /// `AuthorityEvidenceV1`: the genesis parameters, the GRK delegation and
    /// device-tree transition chain to `authority_position`, and the device's
    /// inclusion proof under that transition's tree root.
    pub authority_evidence: Vec<u8>,
}

impl DirectoryEntryBody {
    pub fn to_proto(&self) -> proto::DeviceDirectoryEntryBodyV1 {
        proto::DeviceDirectoryEntryBodyV1 {
            genesis: self.genesis.to_vec(),
            device_id: self.device_id.to_vec(),
            ak_public_key: self.ak_public_key.clone(),
            att_a: self.att_a.to_vec(),
            kyber_public_key: self.kyber_public_key.clone(),
            counter: self.counter,
            authority_position: self.authority_position.to_vec(),
            authority_evidence: self.authority_evidence.clone(),
        }
    }

    /// The digest AK signs: `H(DSM/device-directory-entry/v1 ‖ 0x00 ‖ body bytes)`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_DEVICE_DIRECTORY_ENTRY);
        h.update(&self.to_proto().encode_to_vec());
        *h.finalize().as_bytes()
    }
}

/// A body and its AK signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub body: DirectoryEntryBody,
    pub signature: Vec<u8>,
}

/// Why an entry does not prove itself. None of these is a node's decision:
/// every reader reaches the same one from the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// Not the one canonical encoding of an entry: why.
    Malformed(String),
    /// A key has the wrong length.
    KeyLength,
    /// `H(AK ‖ AttA)` is not the device id the entry names.
    NotThisDevicesKey,
    /// The signature does not verify under the entry's AK.
    SignatureDoesNotVerify,
    /// The evidence does not prove, by P0–P6, the entry's AK as the owner
    /// authority of its device under the genesis it names: why.
    GenesisNotProven(String),
}

impl core::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "directory entry is malformed: {why}"),
            Self::KeyLength => write!(f, "directory entry key has the wrong length"),
            Self::NotThisDevicesKey => write!(f, "directory entry's AK is not the device's"),
            Self::SignatureDoesNotVerify => write!(f, "directory entry signature does not verify"),
            Self::GenesisNotProven(why) => write!(
                f,
                "directory entry's evidence does not prove the device under its genesis: {why}"
            ),
        }
    }
}

impl std::error::Error for DirectoryError {}

impl DirectoryEntry {
    /// Sign `body` with the device's AK secret key.
    pub fn sign(
        body: DirectoryEntryBody,
        ak_secret_key: &[u8],
    ) -> Result<Self, crate::types::error::DsmError> {
        let signature = sphincs::sphincs_sign(ak_secret_key, &body.signing_digest())?;
        Ok(Self { body, signature })
    }

    /// The exact bytes written to the cell.
    pub fn encode(&self) -> Vec<u8> {
        proto::DeviceDirectoryEntryV1 {
            body: Some(self.body.to_proto()),
            signature: self.signature.clone(),
        }
        .encode_to_vec()
    }

    /// Decode cell bytes: only the one canonical encoding of an entry.
    pub fn decode(bytes: &[u8]) -> Result<Self, DirectoryError> {
        let p = proto::DeviceDirectoryEntryV1::decode(bytes)
            .map_err(|e| DirectoryError::Malformed(e.to_string()))?;
        if p.encode_to_vec() != bytes {
            return Err(DirectoryError::Malformed(
                "not the canonical encoding".to_string(),
            ));
        }
        let b = p
            .body
            .ok_or_else(|| DirectoryError::Malformed("no body".to_string()))?;
        let d32 = |v: &[u8]| {
            <[u8; 32]>::try_from(v).map_err(|e| DirectoryError::Malformed(e.to_string()))
        };
        Ok(Self {
            body: DirectoryEntryBody {
                genesis: d32(&b.genesis)?,
                device_id: d32(&b.device_id)?,
                ak_public_key: b.ak_public_key,
                att_a: d32(&b.att_a)?,
                kyber_public_key: b.kyber_public_key,
                counter: b.counter,
                authority_position: d32(&b.authority_position)?,
                authority_evidence: b.authority_evidence,
            },
            signature: p.signature,
        })
    }

    /// Whether the entry's signature verifies under the AK it names.
    fn signature_verifies(&self) -> Result<(), DirectoryError> {
        let b = &self.body;
        match sphincs::sphincs_verify(&b.ak_public_key, &b.signing_digest(), &self.signature) {
            Ok(true) => Ok(()),
            Ok(false) | Err(..) => Err(DirectoryError::SignatureDoesNotVerify),
        }
    }

    /// Whether the entry proves itself: its AK is the one its device id
    /// commits, its signature verifies under that AK, and its evidence proves
    /// that AK, by P0–P6, as the owner authority of the device under the
    /// genesis the entry names (DSM Amendment A18).
    pub fn verify(&self) -> Result<(), DirectoryError> {
        let b = &self.body;
        if b.ak_public_key.len() != AK_PUBLIC_KEY_LEN
            || b.kyber_public_key.len() != KYBER_PUBLIC_KEY_LEN
        {
            return Err(DirectoryError::KeyLength);
        }
        if derive_devid(&b.ak_public_key, &b.att_a) != b.device_id {
            return Err(DirectoryError::NotThisDevicesKey);
        }
        self.signature_verifies()?;
        let proven = verify_authority_evidence(
            &b.authority_evidence,
            &b.genesis,
            &b.device_id,
            &b.authority_position,
        )
        .map_err(|e| DirectoryError::GenesisNotProven(e.to_string()))?;
        if proven.proven_ak != b.ak_public_key {
            return Err(DirectoryError::GenesisNotProven(
                "the evidence proves another key than the entry's AK".to_string(),
            ));
        }
        Ok(())
    }
}

/// Whether `bytes` are a directory entry naming `genesis` and `device_id`: a
/// candidate [`select_entry`] ranks. Whether it proves itself is decided
/// there, best first, never here.
pub fn names_directory_entry(genesis: &[u8; 32], device_id: &[u8; 32], bytes: &[u8]) -> bool {
    DirectoryEntry::decode(bytes)
        .is_ok_and(|entry| &entry.body.genesis == genesis && &entry.body.device_id == device_id)
}

/// From everything read at a device's cell, across every member, the entry to
/// use: one that names this genesis and device and proves itself, with the
/// highest counter. Ties (only the device itself could sign two) go to the
/// smallest encoding, so every reader picks the same one. `None` when nothing
/// proves itself.
pub fn select_entry<'a>(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Option<DirectoryEntry> {
    select_proven(genesis, device_id, values, DirectoryEntry::verify).0
}

/// [`select_entry`] with `proves` as the entry's proof of itself: what it
/// chose, and why each candidate ranked above the choice did not prove
/// itself, best first. The
/// candidates are ordered as the choice orders them — highest counter, then
/// smallest encoding — and each distinct encoding is proven once, best
/// first, until one proves itself: every member returns the same entry, and
/// proving every copy read, and every junk value, before comparing counters
/// let one member force hundreds of SPHINCS+ verifications per read (SA-142).
fn select_proven<'a, E>(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    values: impl IntoIterator<Item = &'a [u8]>,
    proves: impl Fn(&DirectoryEntry) -> Result<(), E>,
) -> (Option<DirectoryEntry>, Vec<E>) {
    let mut candidates: Vec<(DirectoryEntry, &'a [u8])> = Vec::new();
    for bytes in values {
        if candidates.iter().any(|(_, held)| *held == bytes) {
            continue;
        }
        let Ok(entry) = DirectoryEntry::decode(bytes) else {
            continue;
        };
        if &entry.body.genesis != genesis || &entry.body.device_id != device_id {
            continue;
        }
        candidates.push((entry, bytes));
    }
    candidates.sort_by(|(a, a_bytes), (b, b_bytes)| {
        b.body
            .counter
            .cmp(&a.body.counter)
            .then_with(|| a_bytes.cmp(b_bytes))
    });
    let mut refused = Vec::new();
    for (entry, _) in candidates {
        match proves(&entry) {
            Ok(()) => return (Some(entry), refused),
            Err(why) => refused.push(why),
        }
    }
    (None, refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccb::{
        delegation_genesis_sentinel, role, sigalg, transition_genesis_sentinel,
        DeviceTreeRootTransition, GenesisParamsV3, RootProgressionDelegation,
    };
    use crate::common::device_tree::DeviceTree;
    use crate::core::identity::genesis_v2::{derive_atta, genesis_authority_policy_hash};
    use crate::core::identity::genesis_v3::derive_genesis_v3_self_attested;

    const NETWORK: &[u8] = b"dsm-testnet";

    /// A real identity from wallet seed `[seed; 64]` and its own entry body at
    /// `counter`, with the P0–P6 evidence a wallet publishes: the GRK
    /// delegates root progression to the AK (`D_0`), the AK installs the
    /// single-device tree (`T_0`), and the device's leaf is proved under it.
    /// Returns the body and the AK secret key.
    fn identity(seed: u8, counter: u64) -> (DirectoryEntryBody, Vec<u8>) {
        let wallet_seed = [seed; 64];
        let genesis = derive_genesis_v3_self_attested(
            &wallet_seed,
            NETWORK,
            0,
            0,
            3,
            &genesis_authority_policy_hash(),
        )
        .expect("genesis");
        let params = GenesisParamsV3::new(
            genesis.genesis_nonce,
            NETWORK,
            3,
            sigalg::SPHINCS_PLUS_SPX256F,
            &genesis.grk_public,
        )
        .expect("params");
        let d0 = RootProgressionDelegation {
            genesis_id: genesis.g,
            role: role::DEVICE_TREE_ROOT_PROGRESSION,
            role_version: role::BETA_ROLE_VERSION,
            delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
            delegated_pk: genesis.ak_public.clone(),
            delegation_number: 0,
            parent_delegation_digest: delegation_genesis_sentinel(),
            activation_transition_digest: transition_genesis_sentinel(),
        };
        let d0_signature = sphincs::sphincs_sign(
            &genesis.grk_secret,
            &d0.signing_digest().expect("D_0 digest"),
        )
        .expect("GRK signs D_0");
        let tree = DeviceTree::single(genesis.devid);
        let t0 = DeviceTreeRootTransition {
            genesis_id: genesis.g,
            predecessor_transition_digest: transition_genesis_sentinel(),
            new_root: tree.root(),
            version_number: 0,
            delegation_digest: d0.digest().expect("D_0"),
        };
        let t0_signature =
            sphincs::sphincs_sign(&genesis.ak_secret, &t0.signing_digest()).expect("AK signs T_0");
        let att_a = derive_atta(&wallet_seed, &genesis.g, 0);
        let evidence = proto::AuthorityEvidenceV1 {
            genesis_params_ccb: params.encode().expect("params"),
            delegations: vec![proto::SignedAuthorityObjectV1 {
                ccb: d0.encode().expect("D_0"),
                signature: d0_signature,
            }],
            transitions: vec![proto::SignedAuthorityObjectV1 {
                ccb: t0.encode(),
                signature: t0_signature,
            }],
            inclusion_proof: tree.proof(&genesis.devid).expect("own leaf").to_bytes(),
            ak_public_key: genesis.ak_public.clone(),
            atta: att_a.to_vec(),
        };
        let body = DirectoryEntryBody {
            genesis: genesis.g,
            device_id: genesis.devid,
            ak_public_key: genesis.ak_public.clone(),
            att_a,
            kyber_public_key: vec![counter as u8; KYBER_PUBLIC_KEY_LEN],
            counter,
            authority_position: t0.digest(),
            authority_evidence: evidence.encode_to_vec(),
        };
        (body, genesis.ak_secret.clone())
    }

    #[test]
    fn the_devices_own_entry_is_chosen_and_a_squatters_is_ignored() {
        let (body, sk) = identity(1, 1);
        let (g, id) = (body.genesis, body.device_id);
        let own = DirectoryEntry::sign(body.clone(), &sk).unwrap();
        assert_eq!(own.verify(), Ok(()));
        // Evidence included, an entry is a value a node's cell takes.
        assert!(own.encode().len() <= crate::route_chain::MAX_VALUE_LEN);

        // A squatter knows the device id, and even the AK, AttA and evidence,
        // but signs with its own key: the signature does not verify.
        let (squatter, squatter_sk) = identity(2, 99);
        let squat = DirectoryEntry::sign(
            DirectoryEntryBody {
                counter: 99,
                ..body.clone()
            },
            &squatter_sk,
        )
        .unwrap();
        assert_eq!(squat.verify(), Err(DirectoryError::SignatureDoesNotVerify));

        // A squatter with its own AK cannot make it hash to this device id.
        let foreign = DirectoryEntry::sign(
            DirectoryEntryBody {
                device_id: id,
                ..squatter
            },
            &squatter_sk,
        )
        .unwrap();
        assert_eq!(foreign.verify(), Err(DirectoryError::NotThisDevicesKey));

        let values = [
            squat.encode(),
            foreign.encode(),
            b"junk".to_vec(),
            own.encode(),
        ];
        let chosen = select_entry(&g, &id, values.iter().map(Vec::as_slice));
        assert_eq!(chosen, Some(own));
    }

    /// DSM Amendment A18. A device names another account's genesis beside
    /// its own key, AttA and evidence, at that account's cell: everything it
    /// signs is its own, so the genesis it names is its one lie. P0–P6 recompute
    /// the evidence's genesis, which is the device's own, so the entry does
    /// not prove itself and the reader never takes the device for one of the
    /// account's.
    ///
    /// MUTATION CONTROL: delete the evidence check in `verify` and the entry
    /// claiming the other account is chosen.
    #[test]
    fn naming_another_accounts_genesis_is_not_membership_in_it() {
        let (victim, ..) = identity(7, 1);
        let (intruder, intruder_sk) = identity(8, 1);
        let claim = DirectoryEntry::sign(
            DirectoryEntryBody {
                genesis: victim.genesis,
                ..intruder.clone()
            },
            &intruder_sk,
        )
        .unwrap();
        assert!(
            matches!(claim.verify(), Err(DirectoryError::GenesisNotProven(..))),
            "{:?}",
            claim.verify()
        );
        let values = [claim.encode()];
        assert_eq!(
            select_entry(
                &victim.genesis,
                &intruder.device_id,
                values.iter().map(Vec::as_slice)
            ),
            None
        );
    }

    /// The evidence must prove the entry's own AK: another identity's
    /// evidence, or evidence named at a transition its chain does not reach,
    /// proves nothing for this entry.
    #[test]
    fn evidence_for_another_identity_or_position_proves_nothing() {
        let (body, sk) = identity(9, 1);
        let (other, ..) = identity(10, 1);
        let borrowed = DirectoryEntry::sign(
            DirectoryEntryBody {
                authority_evidence: other.authority_evidence.clone(),
                authority_position: other.authority_position,
                ..body.clone()
            },
            &sk,
        )
        .unwrap();
        assert!(matches!(
            borrowed.verify(),
            Err(DirectoryError::GenesisNotProven(..))
        ));
        let elsewhere = DirectoryEntry::sign(
            DirectoryEntryBody {
                authority_position: [0x5Au8; 32],
                ..body
            },
            &sk,
        )
        .unwrap();
        assert!(matches!(
            elsewhere.verify(),
            Err(DirectoryError::GenesisNotProven(..))
        ));
    }

    /// SA-142. Every member returns the same entry, and a hostile member
    /// adds entries naming the device with higher counters that do not prove
    /// themselves. Each distinct encoding is proven once, best first, and the
    /// choice stops at the first that proves itself: three forgeries and one
    /// of the five copies of the device's own entry, four proofs where every
    /// value read was proven before.
    /// MUTATION CONTROL: proving every value read before the choice, as the
    /// selection did, makes eight proofs and turns this red.
    #[test]
    fn each_distinct_entry_is_proven_once_and_the_best_that_proves_itself_stops_the_choice() {
        let (body, sk) = identity(11, 1);
        let (_, forger_sk) = identity(12, 1);
        let (g, id) = (body.genesis, body.device_id);
        let own = DirectoryEntry::sign(body.clone(), &sk).unwrap();
        let mut values = vec![own.encode(); 5];
        for counter in [7, 8, 9] {
            let forged = DirectoryEntry::sign(
                DirectoryEntryBody {
                    counter,
                    ..body.clone()
                },
                &forger_sk,
            )
            .unwrap();
            values.push(forged.encode());
        }
        let proofs = std::cell::Cell::new(0usize);
        let (chosen, refused) = select_proven(&g, &id, values.iter().map(Vec::as_slice), |entry| {
            proofs.set(proofs.get() + 1);
            entry.verify()
        });
        assert_eq!(chosen, Some(own));
        assert_eq!(refused, vec![DirectoryError::SignatureDoesNotVerify; 3]);
        assert_eq!(proofs.get(), 4);
    }

    #[test]
    fn a_higher_counter_replaces_a_lower_one() {
        let (first_body, sk) = identity(4, 1);
        let (g, id) = (first_body.genesis, first_body.device_id);
        let first = DirectoryEntry::sign(first_body.clone(), &sk).unwrap();
        let second = DirectoryEntry::sign(
            DirectoryEntryBody {
                counter: 2,
                ..first_body
            },
            &sk,
        )
        .unwrap();
        let values = [second.encode(), first.encode()];
        let chosen = select_entry(&g, &id, values.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(chosen.body.counter, 2);
    }

    #[test]
    fn an_entry_for_another_device_or_genesis_is_not_chosen() {
        let (body, sk) = identity(5, 1);
        let (g, id) = (body.genesis, body.device_id);
        let entry = DirectoryEntry::sign(body, &sk).unwrap();
        let bytes = [entry.encode()];
        assert!(select_entry(&[8u8; 32], &id, bytes.iter().map(Vec::as_slice)).is_none());
        assert!(select_entry(&g, &[0x6Bu8; 32], bytes.iter().map(Vec::as_slice)).is_none());
    }

    #[test]
    fn only_the_canonical_encoding_decodes() {
        let (body, sk) = identity(6, 1);
        let mut bytes = DirectoryEntry::sign(body, &sk).unwrap().encode();
        bytes.extend_from_slice(&[0x10, 0x01]); // a repeated field appended
        assert!(matches!(
            DirectoryEntry::decode(&bytes),
            Err(DirectoryError::Malformed(..))
        ));
    }
}
