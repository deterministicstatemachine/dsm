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
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};
use crate::recovery::authority_anchor::compute_authority_pubkey_commit;
use crate::types::device_state::ValueCapability;
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

/// Verify a single `SparseMerkleTree` inclusion: the `proof_bytes` must decode, be for
/// exactly `key`, carry exactly `Some(value)`, and recompute `root`. Both the PDSMT
/// (`pd_smt_root`) and the leaf index (`leaf_index_root`) are `SparseMerkleTree`s, so
/// both use this verifier (format: `SmtInclusionProof::to_bytes`). NOTE: this is a
/// distinct proof system from `verification::proof_primitives::verify_smt_inclusion_proof_bytes`
/// (protobuf `SmtProof`, used for cross-device receipt proofs); the two are not
/// interchangeable. We pin to `SparseMerkleTree` here because `pd_smt_root` IS a
/// `SparseMerkleTree` root (`device_state.rs`).
fn verify_smt_leaf(
    root: &[u8; 32],
    key: &[u8; 32],
    value: &[u8; 32],
    proof_bytes: &[u8],
    what: &str,
) -> Result<(), DsmError> {
    let proof = SmtInclusionProof::from_bytes(proof_bytes)
        .ok_or_else(|| DsmError::verification(format!("pdsmt leaf: malformed {what} proof")))?;
    if &proof.key != key {
        return Err(DsmError::verification(format!(
            "pdsmt leaf: {what} proof key != rel_key"
        )));
    }
    if proof.value != Some(*value) {
        return Err(DsmError::verification(format!(
            "pdsmt leaf: {what} proof value mismatch"
        )));
    }
    if !SparseMerkleTree::verify_proof_against_root(&proof, root) {
        return Err(DsmError::verification(format!(
            "pdsmt leaf: {what} inclusion does not recompute the committed root"
        )));
    }
    Ok(())
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
    /// Canonical value-capability (R4). `Yes`/`Unknown` include in the gate; only `No`
    /// excludes. Committed into `leaf_index_root` (authoritative, not server metadata).
    pub value_capability: ValueCapability,
    pub value_capability_reason: String,
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
        h.update(&[self.value_capability.commit_tag()]);
        let reason = self.value_capability_reason.as_bytes();
        h.update(&(reason.len() as u32).to_le_bytes());
        h.update(reason);
        *h.finalize().as_bytes()
    }

    /// Verify this leaf is genuinely part of a posted PDSMT snapshot (R4 layer 2,
    /// completeness): `rel_key → current_tip` is included under `pd_smt_root` AND
    /// `rel_key → committed_digest()` is included under `leaf_index_root`. The second
    /// inclusion is what makes the committed `value_capable` flag authoritative — it is
    /// committed in the head's `leaf_index_root`, never trusted as server metadata.
    /// Fail-closed on any malformed proof, key/value mismatch, or root mismatch.
    pub fn verify_inclusion(
        &self,
        pd_smt_root: &[u8; 32],
        leaf_index_root: &[u8; 32],
    ) -> Result<(), DsmError> {
        verify_smt_leaf(
            pd_smt_root,
            &self.rel_key,
            &self.current_tip,
            &self.inclusion_proof_to_pd_smt_root,
            "pd_smt_root",
        )?;
        verify_smt_leaf(
            leaf_index_root,
            &self.rel_key,
            &self.committed_digest(),
            &self.inclusion_proof_to_leaf_index_root,
            "leaf_index_root",
        )?;
        Ok(())
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
            value_capability: self.value_capability.to_wire(),
            value_capability_reason: self.value_capability_reason.clone(),
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
            value_capability: ValueCapability::from_wire(p.value_capability).ok_or_else(|| {
                DsmError::verification(format!(
                    "pdsmt leaf: value_capability invalid wire value {} (UNSPECIFIED/unknown is \
                     rejected, never read as No)",
                    p.value_capability
                ))
            })?,
            value_capability_reason: p.value_capability_reason,
            inclusion_proof_to_pd_smt_root: p.inclusion_proof_to_pd_smt_root,
            inclusion_proof_to_leaf_index_root: p.inclusion_proof_to_leaf_index_root,
        })
    }
}

/// Verify a posted PDSMT snapshot head together with its enumerated leaf records
/// (R4 layers 1+2, the completeness check). Accepts iff:
/// - the head signature is valid under `candidate_authority_pubkey`, which must equal
///   the head's committed authority (`PostedPdsmtHead::verify`); AND
/// - every leaf record is bound to this head (`genesis_id`/`owner_device_id` match) and
///   is included under both `pd_smt_root` and `leaf_index_root` (`verify_inclusion`).
///
/// The caller MUST independently establish that `candidate_authority_pubkey` is the
/// genesis-anchored authority for `(head.genesis_id, head.device_id)` (via the
/// `RecoveryAuthorityAnchor`) and that `head.device_id ∈ head.genesis_id`'s Device Tree,
/// and that this head is the latest valid head at/before the recovery snapshot (the
/// append-only chain, R4 layer 1). This function does NOT prove the head enumerates
/// EVERY value-capable leaf — that residual completeness gap is closed by the
/// counterparty-union backstop (R4 layer 3, gate-set construction).
pub fn verify_head_with_leaves(
    head: &PostedPdsmtHead,
    candidate_authority_pubkey: &[u8],
    leaves: &[PostedPdsmtLeafRecord],
) -> Result<(), DsmError> {
    head.verify(candidate_authority_pubkey)?;
    for leaf in leaves {
        if leaf.genesis_id != head.genesis_id {
            return Err(DsmError::verification(
                "pdsmt snapshot: leaf genesis_id != head genesis_id",
            ));
        }
        if leaf.owner_device_id != head.device_id {
            return Err(DsmError::verification(
                "pdsmt snapshot: leaf owner_device_id != head device_id",
            ));
        }
        leaf.verify_inclusion(&head.pd_smt_root, &head.leaf_index_root)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsVariant};
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;

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

    fn leaf(vc: ValueCapability) -> PostedPdsmtLeafRecord {
        PostedPdsmtLeafRecord {
            genesis_id: G,
            owner_device_id: A,
            rel_key: [0x55; 32],
            counterparty_device_id: [0xC0; 32],
            counterparty_genesis_id: Some([0xC9; 32]),
            current_tip: [0x77; 32],
            value_capability: vc,
            value_capability_reason: "accepted token transfer".into(),
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
        let mut l = leaf(ValueCapability::Yes);
        assert_eq!(l, PostedPdsmtLeafRecord::from_bytes(&l.to_bytes()).unwrap());
        l.counterparty_genesis_id = None;
        let decoded = PostedPdsmtLeafRecord::from_bytes(&l.to_bytes()).unwrap();
        assert_eq!(l, decoded);
        assert_eq!(decoded.counterparty_genesis_id, None);
    }

    fn signed_head_with_roots(
        pd_smt_root: [u8; 32],
        leaf_index_root: [u8; 32],
    ) -> (PostedPdsmtHead, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("kp");
        let mut head = PostedPdsmtHead {
            genesis_id: G,
            device_id: A,
            pd_smt_root,
            leaf_index_root,
            snapshot_id: [0x33; 32],
            authority_pubkey_commit: compute_authority_pubkey_commit(&kp.public_key),
            parent_head_hash: GENESIS_PARENT_HEAD_HASH,
            head_number: 0,
            signature: Vec::new(),
        };
        head.signature = sphincs_sign(&kp.secret_key, &head.digest()).expect("sign");
        (head, kp.public_key.clone())
    }

    /// Build a leaf record with REAL inclusion proofs against freshly-built SMTs:
    /// `pd_smt` holds `rel_key → current_tip`, `leaf_index` holds
    /// `rel_key → committed_digest`. Returns (leaf, pd_smt_root, leaf_index_root).
    fn leaf_with_real_proofs() -> (PostedPdsmtLeafRecord, [u8; 32], [u8; 32]) {
        let mut l = leaf(ValueCapability::Yes);
        let mut pd = SparseMerkleTree::new(256);
        pd.update_leaf(&l.rel_key, &l.current_tip).unwrap();
        let pd_root = *pd.root();
        let tip_proof = pd.get_inclusion_proof(&l.rel_key, 256).unwrap().to_bytes();

        let cd = l.committed_digest();
        let mut idx = SparseMerkleTree::new(256);
        idx.update_leaf(&l.rel_key, &cd).unwrap();
        let idx_root = *idx.root();
        let idx_proof = idx.get_inclusion_proof(&l.rel_key, 256).unwrap().to_bytes();

        l.inclusion_proof_to_pd_smt_root = tip_proof;
        l.inclusion_proof_to_leaf_index_root = idx_proof;
        (l, pd_root, idx_root)
    }

    #[test]
    fn leaf_verify_inclusion_passes_and_rejects_tamper() {
        let (l, pd_root, idx_root) = leaf_with_real_proofs();
        l.verify_inclusion(&pd_root, &idx_root).expect("valid inclusion");
        // Wrong roots fail.
        assert!(l.verify_inclusion(&[0u8; 32], &idx_root).is_err());
        assert!(l.verify_inclusion(&pd_root, &[0u8; 32]).is_err());
        // Tampered tip: proof value no longer matches the record's current_tip.
        let mut t = l.clone();
        t.current_tip[0] ^= 0x01;
        assert!(t.verify_inclusion(&pd_root, &idx_root).is_err());
        // Tampered value_capability: committed_digest changes → leaf-index inclusion fails.
        let mut v = l.clone();
        v.value_capability = ValueCapability::No;
        assert!(v.verify_inclusion(&pd_root, &idx_root).is_err());
    }

    #[test]
    fn verify_head_with_leaves_passes_end_to_end() {
        let (l, pd_root, idx_root) = leaf_with_real_proofs();
        let (head, pk) = signed_head_with_roots(pd_root, idx_root);
        verify_head_with_leaves(&head, &pk, &[l]).expect("valid snapshot");
    }

    #[test]
    fn verify_head_with_leaves_rejects_leaf_binding_and_injection() {
        let (l, pd_root, idx_root) = leaf_with_real_proofs();
        let (head, pk) = signed_head_with_roots(pd_root, idx_root);
        // Leaf bound to a different genesis is rejected.
        let mut wrong_genesis = l.clone();
        wrong_genesis.genesis_id = [0xAA; 32];
        assert!(verify_head_with_leaves(&head, &pk, &[wrong_genesis]).is_err());
        // Leaf not committed under the head's leaf_index_root (different rel_key, stale
        // proofs) is rejected — cannot inject an extra leaf.
        let mut rogue = l.clone();
        rogue.rel_key = [0x66; 32];
        assert!(verify_head_with_leaves(&head, &pk, &[rogue]).is_err());
        // Wrong authority pubkey is rejected at the head.
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).unwrap();
        assert!(verify_head_with_leaves(&head, &other.public_key, &[l]).is_err());
    }

    #[test]
    fn leaf_committed_digest_binds_value_capable_flag_and_reason() {
        let yes = leaf(ValueCapability::Yes);
        let no = leaf(ValueCapability::No);
        // Flipping the authoritative value_capability changes the committed digest.
        assert_ne!(yes.committed_digest(), no.committed_digest());
        // Changing the reason also changes the digest.
        let mut other_reason = leaf(ValueCapability::Yes);
        other_reason.value_capability_reason = "dlv collateral lock".into();
        assert_ne!(yes.committed_digest(), other_reason.committed_digest());
        // Deterministic.
        assert_eq!(yes.committed_digest(), leaf(ValueCapability::Yes).committed_digest());
        // Inclusion proofs are NOT part of the committed value.
        let mut diff_proof = leaf(ValueCapability::Yes);
        diff_proof.inclusion_proof_to_pd_smt_root = vec![9, 9, 9];
        assert_eq!(yes.committed_digest(), diff_proof.committed_digest());
    }
}
