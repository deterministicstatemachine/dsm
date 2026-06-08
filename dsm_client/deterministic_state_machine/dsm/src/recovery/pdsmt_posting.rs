// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated Enumerable Per-Device SMT posting (spec §0.5, gap 13).
//!
//! Recovery gate-set enumeration must be rooted in A_old's online-posted,
//! genesis-authenticated, ENUMERABLE, value-capable Per-Device SMT (PDSMT) leaf set
//! at the recovery snapshot. The raw posted PDSMT (tips head + encrypted leaves) is
//! not enumerable, not per-leaf classifiable, and not genesis-authenticated, so this
//! module defines the authenticated, enumerable posting that sits on top of it.
//!
//! ## Dual keying (MANDATORY) — device for state location, genesis for authority
//!
//! The PDSMT belongs to a specific device and `rel_key` is device-pair-derived
//! (`H("DSM/smt-key\0" || min(DevID_A,DevID_C) || max(DevID_A,DevID_C))`), so the
//! posting is addressed/enumerated by `device_id = A_old` — genesis-only would blur
//! multiple devices and break the SMT-key model. But every signed head/leaf record
//! ALSO carries `genesis_id = G_A`, and the head is signed by the genesis-anchored
//! recovery authority (`authority_pubkey_commit == H(K_A_pub)`, bound via
//! [`crate::recovery::RecoveryAuthorityAnchor`]). **Device selects the PDSMT; genesis
//! authenticates that the device/PDSMT belongs to G_A; the signing authority chains
//! back to `genesis_id`.**
//!
//! ## Scope of THIS module (verification primitives only)
//!
//! - wire codec for the head + leaf records (protobuf-only, fail-closed lengths);
//! - the head signing digest + [`PostedPdsmtHead::verify`] (signature under the
//!   candidate authority pubkey + binding that pubkey to the committed authority);
//! - the per-leaf committed digest (the value committed under `leaf_index_root`),
//!   so callers can verify a leaf record's inclusion against the head.
//!
//! What is NOT here (caller / integration layer): proving the candidate authority
//! pubkey is the genesis-anchored one (compose with `fetch_and_verify_authority_anchor`
//! / the [`RecoveryAuthorityAnchor`]), proving `A_old ∈ G_A`'s Device Tree (device-tree
//! quorum), SMT-inclusion of `rel_key → current_tip` against `pd_smt_root`, and the
//! leaf-index inclusion against `leaf_index_root`. The R4 ANTI-SHRINK guarantee (the
//! authority holder must not be able to post a SHRUNK value-capable set) is an open
//! design point recorded in §0.2 gap 13 and is NOT resolved by this module.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::sphincs_verify;
use crate::recovery::authority_anchor::compute_authority_pubkey_commit;
use crate::types::error::DsmError;
use crate::types::proto::{Message as _, PostedPdsmtHeadV1, PostedPdsmtLeafRecordV1};

const PDSMT_HEAD_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_PDSMT_HEAD;
const PDSMT_LEAF_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_PDSMT_LEAF;

/// Fail-closed `Vec<u8>` → `[u8; 32]` (proto `dsm_fixed_len` is a hint, not enforced).
fn fixed32(b: &[u8], field: &str) -> Result<[u8; 32], DsmError> {
    <[u8; 32]>::try_from(b).map_err(|_| {
        DsmError::verification(format!(
            "pdsmt-posting: field `{field}` is {} bytes, expected 32",
            b.len()
        ))
    })
}

/// The genesis-head parent sentinel: the first head in a chain links to all-zeros.
pub const GENESIS_PARENT_HEAD_HASH: [u8; 32] = [0u8; 32];

/// The signed head of a posted PDSMT snapshot (dual-keyed, append-only chained).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostedPdsmtHead {
    pub genesis_id: [u8; 32],
    pub device_id: [u8; 32],
    pub pd_smt_root: [u8; 32],
    pub leaf_index_root: [u8; 32],
    pub snapshot_id: [u8; 32],
    /// `H(K_A_pub)` of the genesis-anchored recovery authority.
    pub authority_pubkey_commit: [u8; 32],
    /// Hash of the predecessor head (`GENESIS_PARENT_HEAD_HASH` for the first), R4 layer 1.
    pub parent_head_hash: [u8; 32],
    /// Monotone chain position (0 for the genesis head).
    pub head_number: u64,
    /// SPHINCS+ signature by `K_A` over [`PostedPdsmtHead::digest`].
    pub signature: Vec<u8>,
}

impl PostedPdsmtHead {
    /// The digest the head signature covers: every field except the signature. This is
    /// also the head's identity in the append-only chain (see [`PostedPdsmtHead::head_hash`]).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(PDSMT_HEAD_DOMAIN);
        h.update(&self.genesis_id);
        h.update(&self.device_id);
        h.update(&self.pd_smt_root);
        h.update(&self.leaf_index_root);
        h.update(&self.snapshot_id);
        h.update(&self.authority_pubkey_commit);
        h.update(&self.parent_head_hash);
        h.update(&self.head_number.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// The head's hash for chain linking — a child head's `parent_head_hash` must equal
    /// this. Equals [`PostedPdsmtHead::digest`] (the signed identity), so a child cannot
    /// link to an unsigned/forged predecessor.
    pub fn head_hash(&self) -> [u8; 32] {
        self.digest()
    }

    /// True iff this is the first head of a chain (links to the genesis sentinel at 0).
    pub fn is_genesis_head(&self) -> bool {
        self.head_number == 0 && self.parent_head_hash == GENESIS_PARENT_HEAD_HASH
    }

    /// Verify the head is signed by `candidate_authority_pubkey` AND that pubkey is the
    /// one committed in the head (`H(candidate) == authority_pubkey_commit`).
    ///
    /// The caller MUST independently establish that `candidate_authority_pubkey` is the
    /// genesis-anchored authority for `(genesis_id, device_id)` (via the
    /// [`RecoveryAuthorityAnchor`]) and that `device_id ∈ genesis_id`'s Device Tree.
    /// This method only proves head authenticity under that authority, fail-closed.
    pub fn verify(&self, candidate_authority_pubkey: &[u8]) -> Result<(), DsmError> {
        if self.authority_pubkey_commit != compute_authority_pubkey_commit(candidate_authority_pubkey)
        {
            return Err(DsmError::verification(
                "pdsmt-posting: candidate authority pubkey does not match the head's committed authority",
            ));
        }
        if !sphincs_verify(candidate_authority_pubkey, &self.digest(), &self.signature)? {
            return Err(DsmError::verification(
                "pdsmt-posting: head signature invalid under the candidate authority",
            ));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        PostedPdsmtHeadV1 {
            genesis_id: self.genesis_id.to_vec(),
            device_id: self.device_id.to_vec(),
            pd_smt_root: self.pd_smt_root.to_vec(),
            leaf_index_root: self.leaf_index_root.to_vec(),
            snapshot_id: self.snapshot_id.to_vec(),
            authority_pubkey_commit: self.authority_pubkey_commit.to_vec(),
            parent_head_hash: self.parent_head_hash.to_vec(),
            head_number: self.head_number,
            signature: self.signature.clone(),
        }
        .encode_to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = PostedPdsmtHeadV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("PostedPdsmtHead::from_bytes: {e}"),
                "PostedPdsmtHead",
                None::<String>,
                Some(e),
            )
        })?;
        Ok(Self {
            genesis_id: fixed32(&p.genesis_id, "genesis_id")?,
            device_id: fixed32(&p.device_id, "device_id")?,
            pd_smt_root: fixed32(&p.pd_smt_root, "pd_smt_root")?,
            leaf_index_root: fixed32(&p.leaf_index_root, "leaf_index_root")?,
            snapshot_id: fixed32(&p.snapshot_id, "snapshot_id")?,
            authority_pubkey_commit: fixed32(&p.authority_pubkey_commit, "authority_pubkey_commit")?,
            parent_head_hash: fixed32(&p.parent_head_hash, "parent_head_hash")?,
            head_number: p.head_number,
            signature: p.signature,
        })
    }
}

/// One enumerable, committed leaf/index record of a posted PDSMT snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostedPdsmtLeafRecord {
    pub genesis_id: [u8; 32],
    pub owner_device_id: [u8; 32],
    pub rel_key: [u8; 32],
    pub counterparty_device_id: [u8; 32],
    /// Optional context — `None` if unknown. Cannot compute `rel_key` (device-pair),
    /// but useful once C's device membership under its own genesis is verified.
    pub counterparty_genesis_id: Option<[u8; 32]>,
    pub current_tip: [u8; 32],
    pub value_capable: bool,
    pub value_capable_reason: String,
    pub inclusion_proof_to_pd_smt_root: Vec<u8>,
    pub inclusion_proof_to_leaf_index_root: Vec<u8>,
}

impl PostedPdsmtLeafRecord {
    /// The committed digest of this leaf record — the value committed under the head's
    /// `leaf_index_root` (so the leaf set is enumerable + tamper-evident). Covers the
    /// identity + tip + the `value_capable` flag/reason (the flag is authoritative
    /// because it is committed here, never server metadata). EXCLUDES the inclusion
    /// proofs (which are paths TO this committed value, not part of it).
    pub fn committed_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(PDSMT_LEAF_DOMAIN);
        h.update(&self.genesis_id);
        h.update(&self.owner_device_id);
        h.update(&self.rel_key);
        h.update(&self.counterparty_device_id);
        match &self.counterparty_genesis_id {
            Some(g) => {
                h.update(&[1u8]);
                h.update(g);
            }
            None => {
                h.update(&[0u8]);
            }
        }
        h.update(&self.current_tip);
        h.update(&[self.value_capable as u8]);
        let reason = self.value_capable_reason.as_bytes();
        h.update(&(reason.len() as u32).to_le_bytes());
        h.update(reason);
        *h.finalize().as_bytes()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        PostedPdsmtLeafRecordV1 {
            genesis_id: self.genesis_id.to_vec(),
            owner_device_id: self.owner_device_id.to_vec(),
            rel_key: self.rel_key.to_vec(),
            counterparty_device_id: self.counterparty_device_id.to_vec(),
            counterparty_genesis_id: self
                .counterparty_genesis_id
                .map(|g| g.to_vec())
                .unwrap_or_default(),
            current_tip: self.current_tip.to_vec(),
            value_capable: self.value_capable,
            value_capable_reason: self.value_capable_reason.clone(),
            inclusion_proof_to_pd_smt_root: self.inclusion_proof_to_pd_smt_root.clone(),
            inclusion_proof_to_leaf_index_root: self.inclusion_proof_to_leaf_index_root.clone(),
        }
        .encode_to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = PostedPdsmtLeafRecordV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("PostedPdsmtLeafRecord::from_bytes: {e}"),
                "PostedPdsmtLeafRecord",
                None::<String>,
                Some(e),
            )
        })?;
        let counterparty_genesis_id = if p.counterparty_genesis_id.is_empty() {
            None
        } else {
            Some(fixed32(&p.counterparty_genesis_id, "counterparty_genesis_id")?)
        };
        Ok(Self {
            genesis_id: fixed32(&p.genesis_id, "genesis_id")?,
            owner_device_id: fixed32(&p.owner_device_id, "owner_device_id")?,
            rel_key: fixed32(&p.rel_key, "rel_key")?,
            counterparty_device_id: fixed32(&p.counterparty_device_id, "counterparty_device_id")?,
            counterparty_genesis_id,
            current_tip: fixed32(&p.current_tip, "current_tip")?,
            value_capable: p.value_capable,
            value_capable_reason: p.value_capable_reason,
            inclusion_proof_to_pd_smt_root: p.inclusion_proof_to_pd_smt_root,
            inclusion_proof_to_leaf_index_root: p.inclusion_proof_to_leaf_index_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsVariant};

    const G: [u8; 32] = [0x6E; 32];
    const A: [u8; 32] = [0xA0; 32];

    fn signed_head() -> (PostedPdsmtHead, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("kp");
        let mut head = PostedPdsmtHead {
            genesis_id: G,
            device_id: A,
            pd_smt_root: [0x11; 32],
            leaf_index_root: [0x22; 32],
            snapshot_id: [0x33; 32],
            authority_pubkey_commit: compute_authority_pubkey_commit(&kp.public_key),
            parent_head_hash: GENESIS_PARENT_HEAD_HASH,
            head_number: 0,
            signature: Vec::new(),
        };
        head.signature = sphincs_sign(&kp.secret_key, &head.digest()).expect("sign");
        (head, kp.public_key.clone())
    }

    fn leaf(value_capable: bool) -> PostedPdsmtLeafRecord {
        PostedPdsmtLeafRecord {
            genesis_id: G,
            owner_device_id: A,
            rel_key: [0x55; 32],
            counterparty_device_id: [0xC0; 32],
            counterparty_genesis_id: Some([0xC9; 32]),
            current_tip: [0x77; 32],
            value_capable,
            value_capable_reason: "accepted token transfer".into(),
            inclusion_proof_to_pd_smt_root: vec![1, 2, 3],
            inclusion_proof_to_leaf_index_root: vec![4, 5, 6],
        }
    }

    #[test]
    fn head_round_trip_and_verify() {
        let (head, pk) = signed_head();
        let decoded = PostedPdsmtHead::from_bytes(&head.to_bytes()).expect("decode");
        assert_eq!(head, decoded);
        decoded.verify(&pk).expect("verify after round-trip");
        assert_eq!(head.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn head_chain_fields_are_signed_and_genesis_detected() {
        let (head, pk) = signed_head();
        assert!(head.is_genesis_head());
        // head_hash == digest (the signed identity a child links to).
        assert_eq!(head.head_hash(), head.digest());
        // parent_head_hash and head_number are covered by the signature.
        let mut tampered_parent = head.clone();
        tampered_parent.parent_head_hash[0] ^= 0x01;
        assert!(tampered_parent.verify(&pk).is_err());
        let mut tampered_number = head.clone();
        tampered_number.head_number = 1;
        assert!(tampered_number.verify(&pk).is_err());
    }

    #[test]
    fn head_verify_rejects_wrong_authority() {
        let (head, _pk) = signed_head();
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).expect("kp");
        assert!(head.verify(&other.public_key).is_err());
    }

    #[test]
    fn head_verify_rejects_tampered_root() {
        let (mut head, pk) = signed_head();
        head.pd_smt_root[0] ^= 0x01; // digest changes → signature no longer valid
        assert!(head.verify(&pk).is_err());
    }

    #[test]
    fn head_from_bytes_rejects_wrong_length() {
        let (head, _pk) = signed_head();
        let mut p = PostedPdsmtHeadV1::decode(head.to_bytes().as_slice()).unwrap();
        p.genesis_id.truncate(31);
        assert!(PostedPdsmtHead::from_bytes(&p.encode_to_vec()).is_err());
    }

    #[test]
    fn leaf_round_trip_with_and_without_counterparty_genesis() {
        let mut l = leaf(true);
        assert_eq!(l, PostedPdsmtLeafRecord::from_bytes(&l.to_bytes()).unwrap());
        l.counterparty_genesis_id = None;
        let decoded = PostedPdsmtLeafRecord::from_bytes(&l.to_bytes()).unwrap();
        assert_eq!(l, decoded);
        assert_eq!(decoded.counterparty_genesis_id, None);
    }

    #[test]
    fn leaf_committed_digest_binds_value_capable_flag_and_reason() {
        let yes = leaf(true);
        let no = leaf(false);
        // Flipping the authoritative value_capable flag changes the committed digest.
        assert_ne!(yes.committed_digest(), no.committed_digest());
        // Changing the reason also changes the digest.
        let mut other_reason = leaf(true);
        other_reason.value_capable_reason = "dlv collateral lock".into();
        assert_ne!(yes.committed_digest(), other_reason.committed_digest());
        // Deterministic.
        assert_eq!(yes.committed_digest(), leaf(true).committed_digest());
        // Inclusion proofs are NOT part of the committed value.
        let mut diff_proof = leaf(true);
        diff_proof.inclusion_proof_to_pd_smt_root = vec![9, 9, 9];
        assert_eq!(yes.committed_digest(), diff_proof.committed_digest());
    }
}
