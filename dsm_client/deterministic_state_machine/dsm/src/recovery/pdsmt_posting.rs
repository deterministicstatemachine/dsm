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
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};
use crate::recovery::authority_anchor::compute_authority_pubkey_commit;
use crate::types::device_state::ValueCapability;
use crate::types::error::DsmError;
use crate::types::proto::{
    Message as _, PostedPdsmtHeadV1, PostedPdsmtLeafRecordV1, PostedPdsmtLeafSetV1,
};

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
///
/// `pub(crate)` so the recovery-evidence path
/// ([`crate::recovery::succession_binding::CrossRelationshipSuccessionEvidence::verify`])
/// checks `(old|new)_rel_key → tip` against C's `counterparty_root` (== C's `pd_smt_root`)
/// with the SAME verifier — the proofs it consumes are C's posted PDSMT leaf proofs, so the
/// verifier MUST match the SparseMerkleTree root they were produced against.
pub(crate) fn verify_smt_leaf(
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
    /// The raw recovery-authority pubkey (`K_A_pub`) that produced `signature`. Carried so a
    /// third party (a recovering device fetching a counterparty's head) can verify the head
    /// WITHOUT a separate pubkey source. It is NOT trusted by mere presence: [`Self::verify`]
    /// requires `H(authority_pubkey) == authority_pubkey_commit` AND that commit equals the
    /// genesis-anchored commit — trust flows from the bind-once anchor, the head only reveals
    /// the preimage needed to check the signature. Pinned by the signed `authority_pubkey_commit`
    /// (preimage resistance), so it is NOT separately included in [`Self::digest`].
    pub authority_pubkey: Vec<u8>,
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

    /// Verify the head end-to-end against a GENESIS-ANCHORED authority commitment, using the
    /// `authority_pubkey` the head itself carries:
    ///
    /// 1. `H(self.authority_pubkey) == self.authority_pubkey_commit` — the carried pubkey is
    ///    the one the head commits to (pinned by preimage resistance);
    /// 2. `self.authority_pubkey_commit == anchored_authority_commit` — that commit is the
    ///    one bound to the genesis via the [`RecoveryAuthorityAnchor`] (caller supplies it
    ///    from the anchor + device-tree quorum) — trust flows from the bind-once anchor, NOT
    ///    from the pubkey merely appearing in the head;
    /// 3. the signature verifies under `self.authority_pubkey` over [`Self::digest`].
    ///
    /// The caller MUST still independently establish `device_id ∈ genesis_id`'s Device Tree.
    /// Fail-closed at every step.
    pub fn verify(&self, anchored_authority_commit: &[u8; 32]) -> Result<(), DsmError> {
        if self.authority_pubkey.is_empty() {
            return Err(DsmError::verification(
                "pdsmt-posting: head carries no authority_pubkey",
            ));
        }
        // 1. carried pubkey ↔ head's own commit.
        if compute_authority_pubkey_commit(&self.authority_pubkey) != self.authority_pubkey_commit {
            return Err(DsmError::verification(
                "pdsmt-posting: head authority_pubkey does not hash to its authority_pubkey_commit",
            ));
        }
        // 2. head's commit ↔ the genesis-anchored commit (the actual trust root).
        if &self.authority_pubkey_commit != anchored_authority_commit {
            return Err(DsmError::verification(
                "pdsmt-posting: head authority_pubkey_commit != genesis-anchored authority commit",
            ));
        }
        // 3. signature under the (now anchored) authority pubkey.
        if !sphincs_verify(&self.authority_pubkey, &self.digest(), &self.signature)? {
            return Err(DsmError::verification(
                "pdsmt-posting: head signature invalid under the anchored authority",
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
            authority_pubkey: self.authority_pubkey.clone(),
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
            authority_pubkey: p.authority_pubkey,
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

    pub(crate) fn to_proto(&self) -> PostedPdsmtLeafRecordV1 {
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
    }

    pub(crate) fn from_proto(p: PostedPdsmtLeafRecordV1) -> Result<Self, DsmError> {
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

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
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
        Self::from_proto(p)
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
    anchored_authority_commit: &[u8; 32],
    leaves: &[PostedPdsmtLeafRecord],
) -> Result<(), DsmError> {
    head.verify(anchored_authority_commit)?;
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

/// Build a posted PDSMT snapshot (signed head + leaf records) for `device_state`,
/// signed by the genesis-anchored recovery authority `K_A` (publish-side, R4).
///
/// Pure + deterministic: enumerates the device's relationship leaves, carries each
/// leaf's canonical `value_capability` STRAIGHT from `RelChainTip` (no re-derivation —
/// the sticky flag is the source of truth), builds the `leaf_index` SMT over
/// `rel_key → committed_digest`, and attests each leaf with inclusion proofs against
/// both `pd_smt_root` (the live device SMT, which may also hold vault leaves) and
/// `leaf_index_root`. The result passes [`verify_head_with_leaves`] under
/// `authority_pubkey` and feeds `gate_set::build_gate_set`.
///
/// `parent_head_hash`/`head_number` chain this head onto the device's append-only head
/// chain (`GENESIS_PARENT_HEAD_HASH`/`0` for the first). `counterparty_genesis` supplies
/// `C`'s genesis when locally known (else `None`).
pub fn build_pdsmt_snapshot(
    device_state: &crate::types::device_state::DeviceState,
    authority_pubkey: &[u8],
    authority_sk: &[u8],
    parent_head_hash: [u8; 32],
    head_number: u64,
    counterparty_genesis: impl Fn(&[u8; 32]) -> Option<[u8; 32]>,
) -> Result<(PostedPdsmtHead, Vec<PostedPdsmtLeafRecord>), DsmError> {
    let genesis_id = device_state.genesis_digest();
    let owner_device_id = device_state.devid();
    let pd_smt_root = device_state.root();

    // 1. Build leaf records (proofs filled once both roots exist) + the leaf index.
    let rel_keys = device_state.relationship_keys();
    let mut index = SparseMerkleTree::new(rel_keys.len().max(1));
    let mut leaves: Vec<PostedPdsmtLeafRecord> = Vec::with_capacity(rel_keys.len());
    for rel_key in &rel_keys {
        let tip = device_state.rel_chain_tip(rel_key).ok_or_else(|| {
            DsmError::verification("pdsmt snapshot: enumerated rel_key has no tip")
        })?;
        let value_capability = tip.value_capability;
        let value_capability_reason = match value_capability {
            ValueCapability::Yes => "value-bearing".to_string(),
            ValueCapability::No => String::new(),
            ValueCapability::Unknown => "unknown-unbackfilled".to_string(),
        };
        let leaf = PostedPdsmtLeafRecord {
            genesis_id,
            owner_device_id,
            rel_key: *rel_key,
            counterparty_device_id: tip.counterparty_devid,
            counterparty_genesis_id: counterparty_genesis(&tip.counterparty_devid),
            current_tip: tip.chain_tip,
            value_capability,
            value_capability_reason,
            inclusion_proof_to_pd_smt_root: Vec::new(),
            inclusion_proof_to_leaf_index_root: Vec::new(),
        };
        index.update_leaf(rel_key, &leaf.committed_digest()).map_err(|e| {
            DsmError::invalid_operation(format!("pdsmt snapshot: leaf index update: {e}"))
        })?;
        leaves.push(leaf);
    }
    let leaf_index_root = *index.root();

    // 2. Attach inclusion proofs: rel_key→current_tip against the LIVE device SMT, and
    //    rel_key→committed_digest against the leaf index.
    for leaf in &mut leaves {
        leaf.inclusion_proof_to_pd_smt_root =
            device_state.rel_inclusion_proof(&leaf.rel_key)?.to_bytes();
        leaf.inclusion_proof_to_leaf_index_root = index
            .get_inclusion_proof(&leaf.rel_key, 256)
            .map_err(|e| {
                DsmError::invalid_operation(format!("pdsmt snapshot: leaf index proof: {e}"))
            })?
            .to_bytes();
    }

    // 3. Build + sign the head.
    let snapshot_id = {
        let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_PDSMT_SNAPSHOT);
        h.update(&pd_smt_root);
        h.update(&head_number.to_le_bytes());
        *h.finalize().as_bytes()
    };
    let mut head = PostedPdsmtHead {
        genesis_id,
        device_id: owner_device_id,
        pd_smt_root,
        leaf_index_root,
        snapshot_id,
        authority_pubkey_commit: compute_authority_pubkey_commit(authority_pubkey),
        parent_head_hash,
        head_number,
        signature: Vec::new(),
        authority_pubkey: authority_pubkey.to_vec(),
    };
    head.signature = sphincs_sign(authority_sk, &head.digest())?;
    Ok((head, leaves))
}

/// Serialize an enumerable leaf set to canonical protobuf bytes (availability-only blob;
/// authority is the head's signed `leaf_index_root`).
pub fn encode_leaf_set(leaves: &[PostedPdsmtLeafRecord]) -> Vec<u8> {
    PostedPdsmtLeafSetV1 {
        leaves: leaves.iter().map(|l| l.to_proto()).collect(),
    }
    .encode_to_vec()
}

/// Deserialize an enumerable leaf set (fail-closed per leaf via `from_proto`).
pub fn decode_leaf_set(bytes: &[u8]) -> Result<Vec<PostedPdsmtLeafRecord>, DsmError> {
    let set = PostedPdsmtLeafSetV1::decode(bytes).map_err(|e| {
        DsmError::serialization_error(
            format!("PostedPdsmtLeafSet::decode: {e}"),
            "PostedPdsmtLeafSet",
            None::<String>,
            Some(e),
        )
    })?;
    set.leaves
        .into_iter()
        .map(PostedPdsmtLeafRecord::from_proto)
        .collect()
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
            authority_pubkey: kp.public_key.clone(),
        };
        head.signature = sphincs_sign(&kp.secret_key, &head.digest()).expect("sign");
        (head, kp.public_key.clone())
    }

    /// The genesis-anchored authority commit for a pubkey (what `verify` now takes).
    fn anchored(pk: &[u8]) -> [u8; 32] {
        compute_authority_pubkey_commit(pk)
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
        decoded.verify(&anchored(&pk)).expect("verify after round-trip");
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
        assert!(tampered_parent.verify(&anchored(&pk)).is_err());
        let mut tampered_number = head.clone();
        tampered_number.head_number = 1;
        assert!(tampered_number.verify(&anchored(&pk)).is_err());
    }

    #[test]
    fn head_verify_rejects_wrong_authority() {
        let (head, _pk) = signed_head();
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).expect("kp");
        // A different anchored commit than the head's own commit → rejected at step 2.
        assert!(head.verify(&anchored(&other.public_key)).is_err());
    }

    #[test]
    fn head_verify_rejects_carried_pubkey_not_matching_commit() {
        // Swap the carried pubkey to one whose hash != the (signed) commit → step 1 fails.
        let (mut head, pk) = signed_head();
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).expect("kp");
        head.authority_pubkey = other.public_key.clone();
        assert!(head.verify(&anchored(&pk)).is_err());
    }

    #[test]
    fn head_verify_rejects_tampered_root() {
        let (mut head, pk) = signed_head();
        head.pd_smt_root[0] ^= 0x01; // digest changes → signature no longer valid
        assert!(head.verify(&anchored(&pk)).is_err());
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
            authority_pubkey: kp.public_key.clone(),
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
        verify_head_with_leaves(&head, &anchored(&pk), &[l]).expect("valid snapshot");
    }

    #[test]
    fn verify_head_with_leaves_rejects_leaf_binding_and_injection() {
        let (l, pd_root, idx_root) = leaf_with_real_proofs();
        let (head, pk) = signed_head_with_roots(pd_root, idx_root);
        // Leaf bound to a different genesis is rejected.
        let mut wrong_genesis = l.clone();
        wrong_genesis.genesis_id = [0xAA; 32];
        assert!(verify_head_with_leaves(&head, &anchored(&pk), &[wrong_genesis]).is_err());
        // Leaf not committed under the head's leaf_index_root (different rel_key, stale
        // proofs) is rejected — cannot inject an extra leaf.
        let mut rogue = l.clone();
        rogue.rel_key = [0x66; 32];
        assert!(verify_head_with_leaves(&head, &anchored(&pk), &[rogue]).is_err());
        // Wrong anchored commit (different authority) is rejected at the head.
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).unwrap();
        assert!(verify_head_with_leaves(&head, &anchored(&other.public_key), &[l]).is_err());
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

    #[test]
    fn leaf_set_codec_round_trips() {
        let set = vec![
            leaf(ValueCapability::Yes),
            {
                let mut l = leaf(ValueCapability::No);
                l.rel_key = [0x56; 32];
                l.counterparty_genesis_id = None;
                l
            },
            {
                let mut l = leaf(ValueCapability::Unknown);
                l.rel_key = [0x57; 32];
                l
            },
        ];
        let decoded = decode_leaf_set(&encode_leaf_set(&set)).expect("decode leaf set");
        assert_eq!(decoded, set);
        // Empty set round-trips too.
        assert!(decode_leaf_set(&encode_leaf_set(&[])).unwrap().is_empty());
    }

    #[test]
    fn build_pdsmt_snapshot_from_real_device_state_end_to_end() {
        use crate::core::bilateral_transaction_manager::{
            compute_smt_key, initial_chain_tip_from_device_ids,
        };
        use crate::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};
        use crate::types::operations::Operation;
        use crate::types::token_types::Balance;

        let genesis = [0x6E; 32];
        let owner = [0xA0; 32];
        let dev = DeviceState::new(genesis, owner, vec![0xAA; 64], 1024);

        // A value relationship (Mint → Yes).
        let c_yes = [0xC1; 32];
        let rk_yes = compute_smt_key(&owner, &c_yes);
        let dev = dev
            .advance(
                rk_yes,
                c_yes,
                Operation::Mint {
                    amount: Balance::from_state(10, [0u8; 32]),
                    token_id: b"ERA".to_vec(),
                    authorized_by: vec![],
                    proof_of_authorization: vec![],
                    message: String::new(),
                },
                vec![1; 32],
                None,
                &[BalanceDelta {
                    policy_commit: [0xF1; 32],
                    direction: BalanceDirection::Credit,
                    amount: 10,
                }],
                Some(initial_chain_tip_from_device_ids(&owner, &c_yes)),
                None,
            )
            .expect("value advance")
            .new_device_state;

        // A non-value relationship (Generic → No).
        let c_no = [0xC2; 32];
        let rk_no = compute_smt_key(&owner, &c_no);
        let dev = dev
            .advance(
                rk_no,
                c_no,
                Operation::Generic {
                    operation_type: b"t".to_vec(),
                    data: vec![],
                    message: "t".into(),
                    signature: vec![],
                },
                vec![2; 32],
                None,
                &[],
                Some(initial_chain_tip_from_device_ids(&owner, &c_no)),
                None,
            )
            .expect("non-value advance")
            .new_device_state;

        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).unwrap();
        let (head, leaves) = build_pdsmt_snapshot(
            &dev,
            &kp.public_key,
            &kp.secret_key,
            GENESIS_PARENT_HEAD_HASH,
            0,
            |_| None,
        )
        .expect("build snapshot");

        // The produced snapshot is self-consistent + signed. The head now carries its own
        // authority pubkey; verify against the genesis-anchored commit H(K_A_pub).
        let anchored = compute_authority_pubkey_commit(&kp.public_key);
        verify_head_with_leaves(&head, &anchored, &leaves).expect("verify snapshot");
        assert_eq!(head.authority_pubkey, kp.public_key);
        assert_eq!(head.device_id, owner);
        assert_eq!(head.genesis_id, genesis);
        assert_eq!(head.pd_smt_root, dev.root());
        assert!(head.is_genesis_head());
        assert_eq!(leaves.len(), 2);

        // Gate-set: the value relationship is included, the proven-No one excluded.
        let gs = crate::recovery::gate_set::build_gate_set(&owner, &head, &anchored, &leaves, &[])
            .expect("gate set");
        assert!(gs.members.contains(&c_yes));
        assert!(!gs.members.contains(&c_no));
        // The included leaf's rel_key matches the symmetric derivation.
        assert_eq!(gs.rel_keys.get(&c_yes), Some(&rk_yes));
        let _ = rk_no;
    }
}
