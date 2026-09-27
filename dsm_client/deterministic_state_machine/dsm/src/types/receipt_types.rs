// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical Receipt Types
//!
//! This module implements the stitched receipt structures as specified in the
//! DSM whitepaper. Receipts are the fundamental cryptographic commitment objects
//! that bind state transitions, Merkle proofs, and signatures together.
//!
//! Key invariants:
//! - Canonical Protobuf encoding (deterministic, per whitepaper Sec. 4.2.1)
//! - Domain-separated BLAKE3 hashing
//! - Dual SPHINCS+ signatures (both parties)
//! - The step's write set: every leaf the step writes, with its path against
//!   the pre-state root, folding to the post-state root; and the device binding
//! - Per-step receipt response through EK derivation and cert chaining

use crate::common::domain_tags::TAG_RECEIPT_COMMIT;
use crate::types::error::DsmError;
use std::collections::HashMap;

/// Canonical Stitched Receipt V2
///
/// Fields of the canonical commit form (the `ReceiptCommit` field numbers):
/// 1. genesis (32B)
/// 2. devid_a (32B)
/// 3. devid_b (32B)
/// 4. parent_tip (32B)
/// 5. child_tip (32B)
/// 6. parent_root (32B)
/// 7. child_root (32B)
/// 10. dev_proof (variable bstr)
/// 21. transition_entropy (32B)
/// 22. step_writes (`StepWriteSet`): every leaf the step writes
///
/// Fields 8, 9 and 11 are reserved: 8 was one relationship path, which could
/// not prove a step that writes more than the relationship leaf; 9 and 11 were
/// second encodings of it.
#[derive(Clone, Debug)]
pub struct StitchedReceiptV2 {
    /// Genesis hash (32 bytes)
    pub genesis: [u8; 32],

    /// Device ID of party A (32 bytes)
    pub devid_a: [u8; 32],

    /// Device ID of party B (32 bytes)
    pub devid_b: [u8; 32],

    /// Parent relationship tip hash (h_n, 32 bytes)
    pub parent_tip: [u8; 32],

    /// Child relationship tip hash (h_{n+1}, 32 bytes)
    pub child_tip: [u8; 32],

    /// Parent Per-Device SMT root (r_A, 32 bytes)
    pub parent_root: [u8; 32],

    /// Child Per-Device SMT root (r_A', 32 bytes)
    pub child_root: [u8; 32],

    /// The sender's transition entropy `e_{n+1}` (32 bytes): the one value
    /// Core derived inside `DeviceState::advance` for this step (Part VII,
    /// §39.3). It is part of the CANONICAL commit form, so `sig_a` binds it,
    /// and it is what the recipient feeds into `C_pre` and the symmetric
    /// tip — the recipient cannot derive it, because `e_n` is the sender's
    /// own tip entropy. With it the recipient can also recompute
    /// `child_tip = relationship_chain_tip_v2(k, parent_tip, DevID_B, op, e)`
    /// and refuse a receipt whose child is not the successor its own fields
    /// name. Wire field 21, exactly 32 bytes, required.
    pub transition_entropy: [u8; 32],

    /// Every leaf the step writes, ordered by derived key, each with its path
    /// against `parent_root` in the one canonical encoding. The verifier
    /// derives each leaf's key and values; folded together they move
    /// `parent_root` to `child_root`. Wire field 22, required.
    pub step_writes: Vec<ReceiptWrite>,

    /// Inclusion proof for devid_a in Device Tree root R_G (variable length)
    pub dev_proof: Vec<u8>,

    /// SPHINCS+ response from party A for this receipt challenge.
    ///
    /// The challenge is the proposed transition context. The signer answers
    /// with the fresh EK key derived from h_n, C_pre, k_step (keyed under Smaster).
    pub sig_a: Vec<u8>,

    /// SPHINCS+ response from party B for this receipt challenge.
    pub sig_b: Vec<u8>,

    /// Ephemeral-key certificate for party A's per-step EK (whitepaper §11.1).
    ///
    /// `cert_{n+1} = Sign_{SK_n}( BLAKE3("DSM/ek-cert\0" || EK_pk_{n+1} || h_n) )`
    ///
    /// Where `SK_n` is the prior signer's secret key (AK at n=0, else EK_n).
    /// Carried in the receipt envelope (NOT in canonical commit form per §4.2.1).
    /// Verifier walks the cert chain back to AK_pk to establish AK-rooted
    /// authorization for the per-step EK that signed `sig_a`.
    pub ek_cert_a: Vec<u8>,

    /// Ephemeral-key certificate for party B's per-step EK.
    pub ek_cert_b: Vec<u8>,

    /// Per-step ephemeral SPHINCS+ public key for party A (whitepaper §11.1).
    ///
    /// `EK_pk_{n+1} = SPHINCS+.KeyGen(E_{n+1})`, where
    /// `E_{n+1} = HKDF_Smaster("DSM/ek\0" || h_n || C_pre || k_step)`.
    ///
    /// Carried in the envelope alongside `sig_a` so verifiers don't need
    /// the per-step EK out-of-band. NOT in canonical commit form (§4.2.1).
    /// Required for accepted offline bilateral receipts.
    /// The key changes each transition and is linked to the previous key by
    /// `ek_cert_a`, so copied public receipt state is not spend authority.
    pub ek_pk_a: Vec<u8>,

    /// Per-step ephemeral SPHINCS+ public key for party B.
    /// Same semantics as `ek_pk_a`.
    pub ek_pk_b: Vec<u8>,

    /// Per-step Kyber/ML-KEM ciphertext for party A's contribution to
    /// `k_step` (whitepaper §11). The sender encapsulates with deterministic
    /// coins against the recipient's Kyber pubkey; the resulting ct travels
    /// here. Recipient decapsulates with their Kyber sk to recover `ss`
    /// and derive `k_step = BLAKE3("DSM/kyber-ss\0" || ss)`.
    pub kyber_ct_a: Vec<u8>,

    /// Per-step Kyber ciphertext for party B's contribution.
    /// Mirrors `kyber_ct_a` but encapsulated by B against A's Kyber pubkey.
    pub kyber_ct_b: Vec<u8>,
}

/// Which leaf one of a receipt's writes is, and the one witness a verifier
/// cannot derive: the offline allocation's pre-state preimage (its leaf is an
/// opaque hash of `(amount, sequence)`). Every other key and value is derived
/// from inputs the verifier validated independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptLeaf {
    /// The relationship leaf: `parent_tip` before, `child_tip` after.
    Relationship,
    /// The anchor-state leaf of the pinned bundle: before and after from the
    /// release's signed counter pair and frontiers.
    AnchorState,
    /// The offline allocation leaf, as it stood before the step.
    OfflineAllocation { pre_amount: u64, pre_sequence: u64 },
}

/// One leaf a receipt's step writes: which leaf, and its path against the
/// receipt's `parent_root` in the one canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptWrite {
    pub leaf: ReceiptLeaf,
    pub path: crate::merkle::smt_path::EncodedPath,
}

impl ReceiptWrite {
    fn to_proto(&self) -> crate::types::proto::StepWrite {
        use crate::types::proto::{
            step_write::Leaf, StepWriteAnchorState, StepWriteOfflineAllocation,
            StepWriteRelationship,
        };
        crate::types::proto::StepWrite {
            leaf: Some(match self.leaf {
                ReceiptLeaf::Relationship => Leaf::Relationship(StepWriteRelationship {}),
                ReceiptLeaf::AnchorState => Leaf::AnchorState(StepWriteAnchorState {}),
                ReceiptLeaf::OfflineAllocation {
                    pre_amount,
                    pre_sequence,
                } => Leaf::OfflineAllocation(StepWriteOfflineAllocation {
                    pre_amount,
                    pre_sequence,
                }),
            }),
            path_heights: self.path.explicit_heights.to_vec(),
            path_siblings: self.path.siblings.clone(),
        }
    }

    fn from_proto(w: crate::types::proto::StepWrite) -> Result<Self, DsmError> {
        use crate::merkle::smt_path::{decode, EncodedPath};
        use crate::merkle::sparse_merkle_tree::DeviceSmtHashes;
        use crate::types::proto::step_write::Leaf;
        let leaf = match w.leaf {
            None => return Err(DsmError::invalid_operation("a receipt write names no leaf")),
            Some(Leaf::Relationship(_)) => ReceiptLeaf::Relationship,
            Some(Leaf::AnchorState(_)) => ReceiptLeaf::AnchorState,
            Some(Leaf::OfflineAllocation(a)) => ReceiptLeaf::OfflineAllocation {
                pre_amount: a.pre_amount,
                pre_sequence: a.pre_sequence,
            },
        };
        // Only the one canonical encoding of a device-tree path is a path.
        decode::<DeviceSmtHashes>(&w.path_heights, &w.path_siblings)
            .map_err(|e| DsmError::invalid_operation(format!("a receipt write's path: {e}")))?;
        let explicit_heights = w.path_heights.as_slice().try_into().map_err(|_| {
            DsmError::invalid_operation("a receipt write's path height set is not 32 bytes")
        })?;
        Ok(Self {
            leaf,
            path: EncodedPath {
                explicit_heights,
                siblings: w.path_siblings,
            },
        })
    }
}

/// Per-field bound for a strict length-delimited wire message.
#[derive(Clone, Copy)]
enum FieldLimit {
    /// The field must be exactly this many bytes.
    Fixed(usize),
    /// The field may be at most this many bytes.
    Max(usize),
}

fn receipt_commit_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1..=7 => Some(FieldLimit::Fixed(32)),
        10 => Some(FieldLimit::Max(128 * 1024)),
        12..=17 => Some(FieldLimit::Max(65_535)),
        18..=19 => Some(FieldLimit::Max(2_048)),
        21 => Some(FieldLimit::Fixed(32)),
        22 => Some(FieldLimit::Max(128 * 1024)),
        _ => None,
    }
}

/// `ReceiptCountersignB` (ADR 0003 return leg): the four B-side receipt
/// fields, two 32-byte references, and the recipient's authenticated
/// canonical pair (`b_parent_tip`, `b_child_tip`). Fields 1-8 are required;
/// field 9 (3.5b PR4: the recipient economic RELEASE content address) is
/// OPTIONAL at the wire layer — an acceptance BUNDLE's countersign carries
/// none (provenance never carries finalization authority), while the sender
/// separately REFUSES a finalize delta without it.
const RECEIPT_COUNTERSIGN_B_TAGS: u32 = 9;

fn receipt_countersign_b_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1..=2 => Some(FieldLimit::Fixed(32)),
        3..=5 => Some(FieldLimit::Max(65_535)),
        6 => Some(FieldLimit::Max(2_048)),
        7..=9 => Some(FieldLimit::Fixed(32)),
        _ => None,
    }
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

fn read_canonical_varint(
    bytes: &[u8],
    offset: &mut usize,
    wire: &str,
    what: &str,
) -> Result<u64, DsmError> {
    let start = *offset;
    let mut value = 0u64;
    let mut shift = 0u32;

    for _ in 0..10 {
        if *offset >= bytes.len() {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: truncated {what} varint"
            )));
        }
        let byte = bytes[*offset];
        *offset += 1;

        let low = (byte & 0x7f) as u64;
        if shift >= 64 || (shift == 63 && low > 1) {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: {what} varint overflow"
            )));
        }
        value |= low << shift;

        if byte & 0x80 == 0 {
            let encoded = encode_varint(value);
            if encoded.as_slice() != &bytes[start..*offset] {
                return Err(DsmError::invalid_operation(format!(
                    "{wire}: non-canonical {what} varint"
                )));
            }
            return Ok(value);
        }

        shift += 7;
    }

    Err(DsmError::invalid_operation(format!(
        "{wire}: {what} varint too long"
    )))
}

/// Strict validation of a length-delimited-only protobuf message BEFORE prost
/// sees it: canonical varints, wire type 2 everywhere, no unknown tags, no
/// duplicates, per-field fixed/max lengths, and every `required` tag present.
/// `wire` names the message in error strings ("receipt wire", "countersign
/// wire") so callers can pin the reason.
fn validate_length_delimited_wire(
    bytes: &[u8],
    wire: &str,
    max_tag: u32,
    limit_for: impl Fn(u32) -> Option<FieldLimit>,
    required: impl Fn(u32) -> bool,
) -> Result<(), DsmError> {
    let mut offset = 0usize;
    let mut seen = vec![false; max_tag as usize + 1];

    while offset < bytes.len() {
        let key = read_canonical_varint(bytes, &mut offset, wire, "field key")?;
        let tag = (key >> 3) as u32;
        let wire_type = (key & 0x07) as u8;

        if wire_type != 2 {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: field {tag} has wire type {wire_type}, expected length-delimited"
            )));
        }

        let Some(limit) = limit_for(tag) else {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: unknown field {tag}"
            )));
        };

        let seen_idx = tag as usize;
        if seen[seen_idx] {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: duplicate field {tag}"
            )));
        }
        seen[seen_idx] = true;

        let len = read_canonical_varint(bytes, &mut offset, wire, "field length")? as usize;
        let Some(end) = offset.checked_add(len) else {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: field {tag} length exceeds remaining input"
            )));
        };
        if end > bytes.len() {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: field {tag} length exceeds remaining input"
            )));
        }

        match limit {
            FieldLimit::Fixed(exact) if len != exact => {
                return Err(DsmError::invalid_operation(format!(
                    "{wire}: field {tag} must be {exact} bytes, got {len}"
                )));
            }
            FieldLimit::Max(max) if len > max => {
                return Err(DsmError::invalid_operation(format!(
                    "{wire}: field {tag} exceeds max length {max}, got {len}"
                )));
            }
            _ => {}
        }

        offset = end;
    }

    for tag in 1..=max_tag {
        if required(tag) && !seen[tag as usize] {
            return Err(DsmError::invalid_operation(format!(
                "{wire}: missing required field {tag}"
            )));
        }
    }

    Ok(())
}

fn validate_receipt_commit_wire(bytes: &[u8]) -> Result<(), DsmError> {
    validate_length_delimited_wire(
        bytes,
        "receipt wire",
        22,
        receipt_commit_field_limit,
        |tag| (1..=7).contains(&tag) || tag == 21 || tag == 22,
    )
}

/// Strict wire validation for `ReceiptCountersignB`: tags 1-8 only, all
/// present, 1-2 and 7-8 exactly 32 bytes, 3-5 at most 65,535, 6 at most
/// 2,048. A full `ReceiptCommit` body fed here fails on its first tag above 8
/// (or, before that, on tag 8 not being exactly 32 bytes).
fn validate_receipt_countersign_b_wire(bytes: &[u8]) -> Result<(), DsmError> {
    validate_length_delimited_wire(
        bytes,
        "countersign wire",
        RECEIPT_COUNTERSIGN_B_TAGS,
        receipt_countersign_b_field_limit,
        |tag| tag != 9,
    )
}

/// Decode a `ReceiptCountersignB` from wire bytes: strict validation, prost
/// decode, and re-encode equality (so the bytes are the canonical encoding
/// and can be digested deterministically).
pub fn decode_receipt_countersign_b_wire(
    bytes: &[u8],
) -> Result<crate::types::proto::ReceiptCountersignB, DsmError> {
    use prost::Message;
    validate_receipt_countersign_b_wire(bytes)?;
    let delta = crate::types::proto::ReceiptCountersignB::decode(bytes)
        .map_err(|e| DsmError::invalid_operation(format!("countersign decode: {e}")))?;
    if delta.encode_to_vec() != bytes {
        return Err(DsmError::invalid_operation(
            "countersign wire: non-canonical field ordering or encoding",
        ));
    }
    Ok(delta)
}

/// `RelationshipFinalizedV1` (finality barrier): seven 32-byte fields plus the
/// sender's per-step EK signature. Every field is required.
const RELATIONSHIP_FINALIZED_TAGS: u32 = 8;

fn relationship_finalized_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1..=7 => Some(FieldLimit::Fixed(32)),
        8 => Some(FieldLimit::Max(65_535)),
        _ => None,
    }
}

/// Strict wire validation + prost decode + re-encode equality for a
/// `RelationshipFinalizedV1` certificate: tags 1-8 only, all present, 1-7
/// exactly 32 bytes, 8 at most 65,535, no unknown or duplicate fields.
pub fn decode_relationship_finalized_wire(
    bytes: &[u8],
) -> Result<crate::types::proto::RelationshipFinalizedV1, DsmError> {
    use prost::Message;
    validate_length_delimited_wire(
        bytes,
        "relationship-finalized wire",
        RELATIONSHIP_FINALIZED_TAGS,
        relationship_finalized_field_limit,
        |_| true,
    )?;
    let cert = crate::types::proto::RelationshipFinalizedV1::decode(bytes)
        .map_err(|e| DsmError::invalid_operation(format!("relationship-finalized decode: {e}")))?;
    if cert.encode_to_vec() != bytes {
        return Err(DsmError::invalid_operation(
            "relationship-finalized wire: non-canonical field ordering or encoding",
        ));
    }
    Ok(cert)
}

/// The signing target of a `RelationshipFinalizedV1`: BLAKE3 under
/// `DSM/relationship-finalized/v1` over the canonical concatenation of its
/// seven 32-byte fields, in tag order. Computed identically by the issuing
/// sender and the verifying recipient; the signature field is not an input.
pub fn relationship_finalized_signing_target(
    cert: &crate::types::proto::RelationshipFinalizedV1,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(7 * 32);
    for field in [
        &cert.relationship_key,
        &cert.transition_commitment,
        &cert.sender_device_id,
        &cert.recipient_device_id,
        &cert.sender_child_tip_a,
        &cert.recipient_parent_tip_b,
        &cert.recipient_child_tip_b,
    ] {
        input.extend_from_slice(field);
    }
    crate::crypto::blake3::domain_hash_bytes(
        crate::common::domain_tags::TAG_DSM_RELATIONSHIP_FINALIZED,
        &input,
    )
}

/// The B-side receipt fields the recipient adds at acceptance (ADR 0003
/// return leg): exactly what the sender lacks after authoring the A side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountersignB {
    pub sig_b: Vec<u8>,
    pub ek_cert_b: Vec<u8>,
    pub ek_pk_b: Vec<u8>,
    pub kyber_ct_b: Vec<u8>,
}

impl CountersignB {
    pub fn from_wire(delta: &crate::types::proto::ReceiptCountersignB) -> Self {
        Self {
            sig_b: delta.sig_b.clone(),
            ek_cert_b: delta.ek_cert_b.clone(),
            ek_pk_b: delta.ek_pk_b.clone(),
            kyber_ct_b: delta.kyber_ct_b.clone(),
        }
    }

    fn is_complete(&self) -> bool {
        !self.sig_b.is_empty()
            && !self.ek_cert_b.is_empty()
            && !self.ek_pk_b.is_empty()
            && !self.kyber_ct_b.is_empty()
    }
}

/// The session-bound receipt response target (§4.2.1):
/// `BLAKE3(DSM/receipt-bind-session, commitment ‖ session_binding)`.
/// Online paths bind `session_binding == commitment`.
pub fn compute_receipt_challenge_response_target(
    receipt_commitment: &[u8; 32],
    session_binding: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(receipt_commitment);
    input.extend_from_slice(session_binding);
    crate::crypto::blake3::domain_hash_bytes(
        crate::common::domain_tags::TAG_DSM_RECEIPT_BIND_SESSION,
        &input,
    )
}

/// The ONLINE recipient's B-side response target:
/// `BLAKE3(DSM/receipt-b-canonical/v1, standard ‖ b_parent ‖ b_child)` —
/// `sig_b` over this authenticates the recipient's own canonical pair.
pub fn compute_receipt_b_canonical_target(
    receipt_commitment: &[u8; 32],
    session_binding: &[u8; 32],
    b_parent_tip: &[u8; 32],
    b_child_tip: &[u8; 32],
) -> [u8; 32] {
    let standard = compute_receipt_challenge_response_target(receipt_commitment, session_binding);
    let mut input = Vec::with_capacity(96);
    input.extend_from_slice(&standard);
    input.extend_from_slice(b_parent_tip);
    input.extend_from_slice(b_child_tip);
    crate::crypto::blake3::domain_hash_bytes(
        crate::common::domain_tags::TAG_DSM_RECEIPT_B_CANONICAL,
        &input,
    )
}

impl StitchedReceiptV2 {
    /// Create a new receipt with all required fields
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis: [u8; 32],
        devid_a: [u8; 32],
        devid_b: [u8; 32],
        parent_tip: [u8; 32],
        child_tip: [u8; 32],
        parent_root: [u8; 32],
        child_root: [u8; 32],
        transition_entropy: [u8; 32],
        step_writes: Vec<ReceiptWrite>,
        dev_proof: Vec<u8>,
    ) -> Self {
        Self {
            genesis,
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            parent_root,
            child_root,
            transition_entropy,
            step_writes,
            dev_proof,
            sig_a: Vec::new(),
            sig_b: Vec::new(),
            ek_cert_a: Vec::new(),
            ek_cert_b: Vec::new(),
            ek_pk_a: Vec::new(),
            ek_pk_b: Vec::new(),
            kyber_ct_a: Vec::new(),
            kyber_ct_b: Vec::new(),
        }
    }

    /// The receipt of one step, from the advance that made it — the one
    /// producer. It proves the step's whole write set: every leaf the advance
    /// wrote, each with its path against the step's pre-root
    /// ([`AdvanceOutcome::transition`]). `bearer` is present exactly for the
    /// author's own offline-bearer spend: its anchor-state leaves under its
    /// pinned bundle, as the step's release names them.
    ///
    /// Refused when the step writes a leaf no receipt names, or when the
    /// receipt fails
    /// [`verify_receipt_state`](crate::verification::receipt_verification::verify_receipt_state)
    /// against `device_tree_commitment`, the author's authenticated `R_G`: an
    /// author checks the state rules before anything is signed or sent.
    ///
    /// [`AdvanceOutcome::transition`]: crate::types::device_state::AdvanceOutcome::transition
    pub fn of_step(
        genesis: [u8; 32],
        devid_a: [u8; 32],
        devid_b: [u8; 32],
        outcome: &crate::types::device_state::AdvanceOutcome,
        bearer: Option<crate::verification::receipt_verification::BearerLeaves>,
        device_tree_commitment: &DeviceTreeAcceptanceCommitment,
    ) -> Result<Self, DsmError> {
        use crate::core::bilateral_transaction_manager::{anchor_state_leaf_key, compute_smt_key};

        let relationship_key = compute_smt_key(&devid_a, &devid_b);
        let anchor_key = bearer.map(|b| anchor_state_leaf_key(&b.bundle));
        let step_writes = outcome
            .transition
            .receipt_writes(&relationship_key, anchor_key.as_ref())?;
        let (parent_tip, child_tip) = outcome.relationship_pair();
        let dev_proof = crate::common::device_tree::DeviceTree::single(devid_a)
            .proof(&devid_a)
            .ok_or_else(|| {
                DsmError::invalid_operation(
                    "receipt: the single-device tree has no path for the author",
                )
            })?;
        let receipt = Self::new(
            genesis,
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            outcome.transition.pre_root(),
            outcome.transition.post_root(),
            outcome.transition_entropy(),
            step_writes,
            dev_proof.to_bytes(),
        );
        crate::verification::receipt_verification::verify_receipt_state(
            &receipt,
            &crate::verification::receipt_verification::ReceiptStateContext {
                device_tree_commitment,
                author_genesis: genesis,
                operation: &outcome.new_chain_state.operation,
                bearer,
            },
        )?;
        Ok(receipt)
    }

    /// Convert to prost-generated `ReceiptCommit` (canonical form, no sigs):
    /// fields 1–7, 10, 21 and 22. Signatures (12, 13), ephemeral-key certs
    /// (14, 15), EK pubkeys (16, 17), Kyber cts (18, 19) and the fork-aware
    /// finalization witness (20) live in the envelope only and are explicitly
    /// absent here.
    fn to_proto_canonical(&self) -> crate::types::proto::ReceiptCommit {
        crate::types::proto::ReceiptCommit {
            genesis: self.genesis.to_vec(),
            devid_a: self.devid_a.to_vec(),
            devid_b: self.devid_b.to_vec(),
            parent_tip: self.parent_tip.to_vec(),
            child_tip: self.child_tip.to_vec(),
            parent_root: self.parent_root.to_vec(),
            child_root: self.child_root.to_vec(),
            transition_entropy: self.transition_entropy.to_vec(),
            step_writes: Some(crate::types::proto::StepWriteSet {
                writes: self
                    .step_writes
                    .iter()
                    .map(ReceiptWrite::to_proto)
                    .collect(),
            }),
            dev_proof: self.dev_proof.clone(),
            sig_a: vec![],
            sig_b: vec![],
            ek_cert_a: vec![],
            ek_cert_b: vec![],
            ek_pk_a: vec![],
            ek_pk_b: vec![],
            kyber_ct_a: vec![],
            kyber_ct_b: vec![],
        }
    }

    /// Convert to prost-generated `ReceiptCommit` (full form, with sigs + certs + EK pks + Kyber ct).
    fn to_proto_full(&self) -> crate::types::proto::ReceiptCommit {
        let mut proto = self.to_proto_canonical();
        proto.sig_a.clone_from(&self.sig_a);
        proto.sig_b.clone_from(&self.sig_b);
        proto.ek_cert_a.clone_from(&self.ek_cert_a);
        proto.ek_cert_b.clone_from(&self.ek_cert_b);
        proto.ek_pk_a.clone_from(&self.ek_pk_a);
        proto.ek_pk_b.clone_from(&self.ek_pk_b);
        proto.kyber_ct_a.clone_from(&self.kyber_ct_a);
        proto.kyber_ct_b.clone_from(&self.kyber_ct_b);
        proto
    }

    /// Construct from prost-generated `ReceiptCommit`.
    fn from_proto(rc: crate::types::proto::ReceiptCommit) -> Result<Self, DsmError> {
        let copy32 = |src: &[u8], name: &str| -> Result<[u8; 32], DsmError> {
            <[u8; 32]>::try_from(src).map_err(|_| {
                DsmError::invalid_operation(format!(
                    "receipt field {name}: expected 32 bytes, got {}",
                    src.len()
                ))
            })
        };
        let step_writes = rc
            .step_writes
            .ok_or_else(|| DsmError::invalid_operation("receipt field step_writes is absent"))?
            .writes
            .into_iter()
            .map(ReceiptWrite::from_proto)
            .collect::<Result<Vec<_>, _>>()?;

        let mut receipt = Self::new(
            copy32(&rc.genesis, "genesis")?,
            copy32(&rc.devid_a, "devid_a")?,
            copy32(&rc.devid_b, "devid_b")?,
            copy32(&rc.parent_tip, "parent_tip")?,
            copy32(&rc.child_tip, "child_tip")?,
            copy32(&rc.parent_root, "parent_root")?,
            copy32(&rc.child_root, "child_root")?,
            copy32(&rc.transition_entropy, "transition_entropy")?,
            step_writes,
            rc.dev_proof,
        );
        if !rc.sig_a.is_empty() {
            receipt.add_sig_a(rc.sig_a);
        }
        if !rc.sig_b.is_empty() {
            receipt.add_sig_b(rc.sig_b);
        }
        if !rc.ek_cert_a.is_empty() {
            receipt.set_ek_cert_a(rc.ek_cert_a);
        }
        if !rc.ek_cert_b.is_empty() {
            receipt.set_ek_cert_b(rc.ek_cert_b);
        }
        if !rc.ek_pk_a.is_empty() {
            receipt.set_ek_pk_a(rc.ek_pk_a);
        }
        if !rc.ek_pk_b.is_empty() {
            receipt.set_ek_pk_b(rc.ek_pk_b);
        }
        if !rc.kyber_ct_a.is_empty() {
            receipt.set_kyber_ct_a(rc.kyber_ct_a);
        }
        if !rc.kyber_ct_b.is_empty() {
            receipt.set_kyber_ct_b(rc.kyber_ct_b);
        }
        Ok(receipt)
    }

    /// Decode a `StitchedReceiptV2` from protobuf bytes (canonical or full).
    ///
    /// Runs raw protobuf validation before prost decoding. Accepts canonical
    /// fields 1-11 and the defined wire-only receipt authorization fields,
    /// but rejects unknown fields, duplicate fields, wrong fixed lengths, and
    /// non-canonical encodings.
    pub fn from_canonical_protobuf(bytes: &[u8]) -> Result<Self, DsmError> {
        use prost::Message;
        validate_receipt_commit_wire(bytes)?;
        let rc = crate::types::proto::ReceiptCommit::decode(bytes)
            .map_err(|e| DsmError::invalid_operation(format!("receipt decode: {e}")))?;
        let receipt = Self::from_proto(rc)?;
        let reencoded = receipt.to_full_protobuf()?;
        if reencoded != bytes {
            return Err(DsmError::invalid_operation(
                "receipt wire: non-canonical field ordering or encoding",
            ));
        }
        Ok(receipt)
    }

    /// Returns the canonical protobuf bytes for hashing/signing.
    ///
    /// Encodes the canonical fields only (no signatures) via prost `ReceiptCommit`.
    /// Proto3 omits empty bytes fields, so sig_a/sig_b are excluded.
    /// Format: ReceiptCommit message as specified in whitepaper Sec. 4.2.1
    pub fn to_canonical_protobuf(&self) -> Result<Vec<u8>, DsmError> {
        use prost::Message;
        Ok(self.to_proto_canonical().encode_to_vec())
    }

    /// Returns the full wire protobuf bytes including signatures.
    ///
    /// The canonical fields are identical to `to_canonical_protobuf()` (the commitment
    /// preimage). Fields 12 (sig_a) and 13 (sig_b) are included when non-empty.
    /// Use this for transport; use `to_canonical_protobuf()` for commitment hashing.
    pub fn to_full_protobuf(&self) -> Result<Vec<u8>, DsmError> {
        use prost::Message;
        Ok(self.to_proto_full().encode_to_vec())
    }

    /// Compute the canonical commitment hash
    ///
    /// Per whitepaper: BLAKE3("DSM/receipt-commit\0" || canonical_protobuf_bytes)
    pub fn compute_commitment(&self) -> Result<[u8; 32], DsmError> {
        let protobuf_bytes = self.to_canonical_protobuf()?;

        // Domain-separated BLAKE3-256: BLAKE3("DSM/receipt-commit\0" || canonical_protobuf_bytes)
        let hash = crate::crypto::blake3::domain_hash(TAG_RECEIPT_COMMIT, &protobuf_bytes);
        Ok(*hash.as_bytes())
    }

    /// Add signature from party A
    pub fn add_sig_a(&mut self, sig: Vec<u8>) {
        self.sig_a = sig;
    }

    /// Add signature from party B
    pub fn add_sig_b(&mut self, sig: Vec<u8>) {
        self.sig_b = sig;
    }

    /// Set party A's per-step ephemeral-key certificate.
    /// See whitepaper §11.1 ephemeral certification.
    pub fn set_ek_cert_a(&mut self, cert: Vec<u8>) {
        self.ek_cert_a = cert;
    }

    /// Set party B's per-step ephemeral-key certificate (counterparty).
    pub fn set_ek_cert_b(&mut self, cert: Vec<u8>) {
        self.ek_cert_b = cert;
    }

    /// Set party A's per-step ephemeral SPHINCS+ public key.
    /// See whitepaper §11.1.
    pub fn set_ek_pk_a(&mut self, pk: Vec<u8>) {
        self.ek_pk_a = pk;
    }

    /// Set party B's per-step ephemeral SPHINCS+ public key.
    pub fn set_ek_pk_b(&mut self, pk: Vec<u8>) {
        self.ek_pk_b = pk;
    }

    /// Set party A's per-step Kyber ciphertext (whitepaper §11).
    pub fn set_kyber_ct_a(&mut self, ct: Vec<u8>) {
        self.kyber_ct_a = ct;
    }

    /// Set party B's per-step Kyber ciphertext (counterparty's contribution).
    pub fn set_kyber_ct_b(&mut self, ct: Vec<u8>) {
        self.kyber_ct_b = ct;
    }

    /// Split a countersigned receipt into the A-side receipt (fields 1-11 plus
    /// the A-side authorization material) and the B-side `CountersignB` the
    /// recipient added at acceptance. Errors if any B field is absent: a receipt
    /// that was never countersigned has no delta to return.
    ///
    /// `split.0.to_full_protobuf()` is byte-identical to the A-side bytes the
    /// receipt was built from — `to_full_protobuf` is a pure function of the
    /// fields — which is what lets the recipient derive the digest binding the
    /// sender will check against its retained artifact.
    pub fn split_countersign_b(&self) -> Result<(Self, CountersignB), DsmError> {
        let b = CountersignB {
            sig_b: self.sig_b.clone(),
            ek_cert_b: self.ek_cert_b.clone(),
            ek_pk_b: self.ek_pk_b.clone(),
            kyber_ct_b: self.kyber_ct_b.clone(),
        };
        if !b.is_complete() {
            return Err(DsmError::invalid_operation(
                "split_countersign_b: receipt carries no complete B-side countersignature",
            ));
        }
        let mut a_side = self.clone();
        a_side.sig_b.clear();
        a_side.ek_cert_b.clear();
        a_side.ek_pk_b.clear();
        a_side.kyber_ct_b.clear();
        Ok((a_side, b))
    }

    /// Overlay a B-side `CountersignB` onto an A-side receipt, producing the
    /// countersigned receipt the recipient holds. Errors if `self` already
    /// carries any B field (a delta is never applied twice, and never onto a
    /// receipt that was not the sender's own A side) or if the delta is
    /// incomplete.
    pub fn with_countersign_b(&self, b: CountersignB) -> Result<Self, DsmError> {
        if !self.sig_b.is_empty()
            || !self.ek_cert_b.is_empty()
            || !self.ek_pk_b.is_empty()
            || !self.kyber_ct_b.is_empty()
        {
            return Err(DsmError::invalid_operation(
                "with_countersign_b: receipt already carries B-side material",
            ));
        }
        if !b.is_complete() {
            return Err(DsmError::invalid_operation(
                "with_countersign_b: incomplete B-side countersignature",
            ));
        }
        let mut full = self.clone();
        full.set_ek_pk_b(b.ek_pk_b);
        full.set_ek_cert_b(b.ek_cert_b);
        full.set_kyber_ct_b(b.kyber_ct_b);
        full.add_sig_b(b.sig_b);
        Ok(full)
    }

    /// Check if both signatures are present
    pub fn is_fully_signed(&self) -> bool {
        !self.sig_a.is_empty() && !self.sig_b.is_empty()
    }

    /// Total serialized size (canonical protobuf + signatures). A receipt that
    /// does not encode has no size: an error, never 0 (which would pass any cap).
    pub fn serialized_size(&self) -> Result<usize, DsmError> {
        let pb_size = self.to_canonical_protobuf()?.len();
        Ok(pb_size + self.sig_a.len() + self.sig_b.len())
    }

    /// Validate size cap (≤128 KiB per whitepaper)
    pub fn validate_size_cap(&self) -> Result<(), DsmError> {
        const MAX_SIZE: usize = 128 * 1024; // 128 KiB
        let size = self.serialized_size()?;
        if size > MAX_SIZE {
            return Err(DsmError::InvalidOperation(format!(
                "Receipt exceeds size cap: {} > {} bytes",
                size, MAX_SIZE
            )));
        }
        Ok(())
    }

    /// Get canonical commitment (alias for compute_commitment)
    pub fn canonical_commit(&self) -> Result<[u8; 32], DsmError> {
        self.compute_commitment()
    }

    /// Get device ID A
    pub fn id_a(&self) -> &[u8; 32] {
        &self.devid_a
    }

    /// Get device ID B
    pub fn id_b(&self) -> &[u8; 32] {
        &self.devid_b
    }
}

/// Receipt verification context
///
/// Holds all data needed to verify a stitched receipt against acceptance predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTreeAcceptanceCommitment {
    /// Concrete authenticated commitment used to validate `π_dev: DevID ∈ R_G`.
    ///
    /// Today this is the canonical 32-byte Device Tree root `R_G` itself. The
    /// wrapper keeps the acceptance path explicit about requiring an authenticated
    /// locally persisted commitment, while allowing equivalent authenticated
    /// persisted artifacts to be represented in the future without changing the
    /// strict-fail receipt predicate.
    root: [u8; 32],
}

impl DeviceTreeAcceptanceCommitment {
    pub fn from_root(root: [u8; 32]) -> Self {
        Self { root }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }
}

impl From<[u8; 32]> for DeviceTreeAcceptanceCommitment {
    fn from(root: [u8; 32]) -> Self {
        Self::from_root(root)
    }
}

pub struct ReceiptVerificationContext {
    /// Authenticated local commitment used to validate `π_dev: DevID ∈ R_G`.
    pub device_tree_commitment: DeviceTreeAcceptanceCommitment,

    /// The sender's pre-state root this verifier expects the step to start
    /// from; a receipt over any other root is not this step.
    pub expected_parent_root: [u8; 32],

    /// SPHINCS+ public key for party A (the per-step EK_pk for this receipt).
    pub pubkey_a: Vec<u8>,

    /// SPHINCS+ public key for party B (counterparty's per-step EK_pk).
    pub pubkey_b: Vec<u8>,

    /// Per-relationship cert chain head for party A.
    ///
    /// This is the SPHINCS+ public key that authorized the current `pubkey_a`
    /// via the ek-cert chain (whitepaper §11.1):
    ///   - At step n=0: AK_pk (the device-attested long-term key).
    ///   - At step n>0: the previous step's `EK_pk_n` (which signed cert_{n+1}).
    ///
    /// `Some(pk)` means the receipt must carry a valid `ek_cert_a` that verifies
    /// against `pk`. `None` is fail-closed for receipt acceptance because
    /// parent/root inclusion alone is not spend authority.
    pub chain_head_pubkey_a: Option<Vec<u8>>,

    /// Per-relationship cert chain head for party B.
    /// Same semantics as `chain_head_pubkey_a`.
    pub chain_head_pubkey_b: Option<Vec<u8>>,

    /// The genesis the receipt's author (`devid_a`) is pinned under.
    pub author_genesis: [u8; 32],

    /// The operation the step carries: it decides which leaves the step
    /// writes, and the child tip is recomputed from it.
    pub operation: crate::types::operations::Operation,

    /// For the author's own offline-bearer spend, its anchor-state leaves.
    pub bearer: Option<crate::verification::receipt_verification::BearerLeaves>,
}

impl ReceiptVerificationContext {
    pub fn new<T: Into<DeviceTreeAcceptanceCommitment>>(
        device_tree_commitment: T,
        expected_parent_root: [u8; 32],
        pubkey_a: Vec<u8>,
        pubkey_b: Vec<u8>,
        author_genesis: [u8; 32],
        operation: crate::types::operations::Operation,
    ) -> Self {
        Self {
            device_tree_commitment: device_tree_commitment.into(),
            expected_parent_root,
            pubkey_a,
            pubkey_b,
            chain_head_pubkey_a: None,
            chain_head_pubkey_b: None,
            author_genesis,
            operation,
            bearer: None,
        }
    }

    /// Builder: set the cert chain head for party A.
    /// Once set, the receipt MUST carry a valid `ek_cert_a` (whitepaper §11.1).
    pub fn with_chain_head_a(mut self, pubkey: Vec<u8>) -> Self {
        self.chain_head_pubkey_a = Some(pubkey);
        self
    }

    /// Builder: set the cert chain head for party B.
    pub fn with_chain_head_b(mut self, pubkey: Vec<u8>) -> Self {
        self.chain_head_pubkey_b = Some(pubkey);
        self
    }
}

/// Receipt acceptance result
#[derive(Debug, Clone)]
pub struct ReceiptAcceptance {
    /// Whether the receipt is valid
    pub valid: bool,

    /// Detailed reason if invalid
    pub reason: Option<String>,

    /// Computed commitment hash
    pub commitment: Option<[u8; 32]>,
}

impl ReceiptAcceptance {
    pub fn accept(commitment: [u8; 32]) -> Self {
        Self {
            valid: true,
            reason: None,
            commitment: Some(commitment),
        }
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: Some(reason.into()),
            commitment: None,
        }
    }
}

/// Parent consumption tracker
///
/// Tracks which parent tips have been consumed to enforce uniqueness
/// and detect fork attempts.
#[derive(Default)]
pub struct ParentConsumptionTracker {
    /// Map: parent_tip -> child_tip
    consumed: HashMap<[u8; 32], [u8; 32]>,
}

impl ParentConsumptionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(_capacity: usize) -> Self {
        Self::new()
    }

    /// Try to consume a parent tip
    ///
    /// Returns Ok(()) if parent is fresh, Err if already consumed.
    pub fn try_consume(
        &mut self,
        parent_tip: [u8; 32],
        child_tip: [u8; 32],
    ) -> Result<(), DsmError> {
        if let Some(existing_child) = self.consumed.get(&parent_tip) {
            if existing_child == &child_tip {
                // Idempotent: same transition attempted twice (replay)
                return Err(DsmError::InvalidOperation(
                    "Parent already consumed (replay detected)".to_string(),
                ));
            } else {
                // Fork: different children for same parent
                return Err(DsmError::InvalidOperation(format!(
                    "Fork detected: parent {:?} has conflicting children",
                    &parent_tip[..8]
                )));
            }
        }

        // Fresh parent: mark as consumed
        self.consumed.insert(parent_tip, child_tip);
        Ok(())
    }

    /// Check if parent is consumed (read-only)
    pub fn is_consumed(&self, parent_tip: &[u8; 32]) -> bool {
        self.consumed.contains_key(parent_tip)
    }

    /// Get the child for a consumed parent (if any)
    pub fn get_child(&self, parent_tip: &[u8; 32]) -> Option<&[u8; 32]> {
        self.consumed.get(parent_tip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::step_fixture::{credit_step, transfer_step, Party, Step};

    /// TRANSPORT USES `to_full_protobuf`. COMMITMENT USES `to_canonical_protobuf`.
    ///
    /// These two are not interchangeable and the failure mode is silent, so the
    /// difference is pinned here rather than left to the method names.
    ///
    /// `to_canonical_protobuf` emits the commitment PREIMAGE — fields 1-11 —
    /// and therefore erases the countersignature evidence in fields 12-20. Bytes
    /// produced that way still decode cleanly, and `compute_commitment()` over
    /// them is UNCHANGED, because the commitment is defined over exactly that
    /// preimage. Nothing at the decode boundary objects either:
    /// `from_canonical_protobuf` accepts canonical OR full bytes by design.
    ///
    /// So a caller that ships canonical bytes as transport hands the far side a
    /// receipt whose `sig_b` is simply gone. That receipt fails verification for
    /// a signature it never lost on the wire, and — on the acceptance path — the
    /// sender's step can never finalize, because reaching `finalized` requires
    /// the very reply that just failed to verify.
    ///
    /// Any code putting the A-side evidence on the wire must use
    /// `to_full_protobuf`; the B side never ships a whole receipt at all — only
    /// its `CountersignB` delta, which the sender overlays onto the retained A
    /// bytes (`with_countersign_b`).
    #[test]
    fn canonical_encoding_erases_countersignature_evidence_that_full_encoding_keeps() {
        let receipt = a_side()
            .with_countersign_b(countersign_b().0)
            .expect("the receiver countersigns");

        let canonical = receipt.to_canonical_protobuf().expect("canonical");
        let full = receipt.to_full_protobuf().expect("full");
        assert_ne!(
            canonical, full,
            "the two encoders must not be aliases; if they ever become equal, \
             this whole hazard is gone and this test should be deleted"
        );

        // Full bytes preserve every countersignature field.
        let from_full = StitchedReceiptV2::from_canonical_protobuf(&full).expect("decode full");
        assert_eq!(from_full.ek_pk_b, receipt.ek_pk_b);
        assert_eq!(from_full.ek_cert_b, receipt.ek_cert_b);
        assert_eq!(from_full.sig_b, receipt.sig_b);
        assert_eq!(from_full.kyber_ct_b, receipt.kyber_ct_b);

        // Canonical bytes decode WITHOUT COMPLAINT and silently drop them all.
        let from_canonical =
            StitchedReceiptV2::from_canonical_protobuf(&canonical).expect("decode canonical");
        assert!(from_canonical.ek_pk_b.is_empty());
        assert!(from_canonical.ek_cert_b.is_empty());
        assert!(
            from_canonical.sig_b.is_empty(),
            "this is the trap: the countersignature is gone and nothing errored"
        );
        assert!(from_canonical.kyber_ct_b.is_empty());

        // And the commitment is identical across both, so a commitment check
        // cannot be what catches the mistake.
        assert_eq!(
            from_canonical.compute_commitment().expect("c1"),
            from_full.compute_commitment().expect("c2"),
            "the commitment covers only the canonical fields, so it is blind to the loss"
        );
    }

    /// Two wallets, the sender's first transfer to the receiver, the
    /// receiver's credit of it, and a second transfer from the sender's same
    /// head (a fork of the first). Derived once: SPHINCS+ keygen and signing
    /// are slow.
    struct World {
        sender: Party,
        receiver: Party,
        transfer: Step,
        credit: Step,
        fork: Step,
    }

    fn world() -> &'static World {
        static WORLD: std::sync::OnceLock<World> = std::sync::OnceLock::new();
        WORLD.get_or_init(|| {
            let sender = Party::from_seed(b"receipt codec sender wallet seed");
            let receiver = Party::from_seed(b"receipt codec receiver wallet seed");
            let transfer = transfer_step(&sender, &receiver, 7);
            let credit = credit_step(&receiver, &sender, &transfer.operation);
            let fork = transfer_step(&sender, &receiver, 8);
            World {
                sender,
                receiver,
                transfer,
                credit,
                fork,
            }
        })
    }

    /// The transfer's receipt as the online sender ships it: answered with
    /// its per-step EK, bound to the receipt's own commitment.
    fn a_side() -> StitchedReceiptV2 {
        let w = world();
        let mut receipt = w.transfer.receipt.clone();
        let commitment = receipt.compute_commitment().expect("commitment");
        let a = w.sender.answer(
            &w.receiver,
            &receipt.parent_tip,
            &w.transfer.c_pre,
            &compute_receipt_challenge_response_target(&commitment, &commitment),
        );
        receipt.add_sig_a(a.sig);
        receipt.set_ek_cert_a(a.ek_cert);
        receipt.set_ek_pk_a(a.ek_pk);
        receipt.set_kyber_ct_a(a.kyber_ct);
        receipt
    }

    /// The receiver's countersignature of the transfer's receipt over its
    /// own canonical pair (its credit step's tips), and that pair.
    fn countersign_b() -> (CountersignB, ([u8; 32], [u8; 32])) {
        let w = world();
        let commitment = w.transfer.receipt.compute_commitment().expect("commitment");
        let (b_parent, b_child) = w.credit.outcome.relationship_pair();
        let b = w.receiver.answer(
            &w.sender,
            &b_parent,
            &w.transfer.c_pre,
            &compute_receipt_b_canonical_target(&commitment, &commitment, &b_parent, &b_child),
        );
        (
            CountersignB {
                sig_b: b.sig,
                ek_cert_b: b.ek_cert,
                ek_pk_b: b.ek_pk,
                kyber_ct_b: b.kyber_ct,
            },
            (b_parent, b_child),
        )
    }

    /// The A side's evidence digest: its role-separated content address.
    fn evidence_digest_a(a: &StitchedReceiptV2) -> [u8; 32] {
        crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
            &a.to_full_protobuf().expect("encode"),
        )
    }

    /// The receiver's countersign delta on the wire: the A side's commitment
    /// and evidence digest, the countersignature, and the receiver's pair.
    fn delta_wire() -> Vec<u8> {
        use prost::Message;
        let a = a_side();
        let (b, (b_parent_tip, b_child_tip)) = countersign_b();
        crate::types::proto::ReceiptCountersignB {
            commitment: a.compute_commitment().expect("commitment").to_vec(),
            receipt_evidence_digest_a: evidence_digest_a(&a).to_vec(),
            sig_b: b.sig_b,
            ek_cert_b: b.ek_cert_b,
            ek_pk_b: b.ek_pk_b,
            kyber_ct_b: b.kyber_ct_b,
            b_parent_tip: b_parent_tip.to_vec(),
            b_child_tip: b_child_tip.to_vec(),
            recipient_economic_release_addr: Vec::new(),
        }
        .encode_to_vec()
    }

    /// A receipt's commitment is a function of the receipt: the same receipt
    /// commits the same, another step commits otherwise.
    #[test]
    fn test_commitment_hash() {
        let w = world();
        let commitment = w.transfer.receipt.compute_commitment().unwrap();
        assert_eq!(commitment, w.transfer.receipt.compute_commitment().unwrap());
        assert_ne!(commitment, w.fork.receipt.compute_commitment().unwrap());
    }

    #[test]
    fn test_prost_canonical_roundtrip() {
        let receipt = &world().transfer.receipt;

        let canonical = receipt.to_canonical_protobuf().unwrap();
        let decoded = StitchedReceiptV2::from_canonical_protobuf(&canonical).unwrap();
        assert_eq!(decoded.genesis, receipt.genesis);
        assert_eq!(decoded.devid_a, receipt.devid_a);
        assert_eq!(decoded.devid_b, receipt.devid_b);
        assert_eq!(decoded.parent_tip, receipt.parent_tip);
        assert_eq!(decoded.child_tip, receipt.child_tip);
        assert_eq!(decoded.parent_root, receipt.parent_root);
        assert_eq!(decoded.child_root, receipt.child_root);
        assert_eq!(decoded.transition_entropy, receipt.transition_entropy);
        assert_eq!(decoded.step_writes, receipt.step_writes);
        assert_eq!(decoded.dev_proof, receipt.dev_proof);
        assert!(decoded.sig_a.is_empty());
        assert!(decoded.sig_b.is_empty());
        assert_eq!(decoded.to_canonical_protobuf().unwrap(), canonical);

        // Commitment stability: encode → decode → re-encode must match
        let commit1 = receipt.compute_commitment().unwrap();
        let commit2 = decoded.compute_commitment().unwrap();
        assert_eq!(commit1, commit2);
    }

    #[test]
    fn test_prost_full_roundtrip_with_sigs() {
        let receipt = a_side()
            .with_countersign_b(countersign_b().0)
            .expect("the receiver countersigns");

        let full = receipt.to_full_protobuf().unwrap();
        let decoded = StitchedReceiptV2::from_canonical_protobuf(&full).unwrap();
        assert_eq!(decoded.sig_a, receipt.sig_a);
        assert_eq!(decoded.sig_b, receipt.sig_b);

        // Canonical bytes should NOT include sigs
        let canonical = receipt.to_canonical_protobuf().unwrap();
        assert!(canonical.len() < full.len());

        // Canonical commitment must be the same regardless of sigs
        let commit_unsigned = StitchedReceiptV2::from_canonical_protobuf(&canonical)
            .unwrap()
            .compute_commitment()
            .unwrap();
        let commit_signed = decoded.compute_commitment().unwrap();
        assert_eq!(commit_unsigned, commit_signed);
    }

    #[test]
    fn receipt_decode_rejects_unknown_field() {
        let mut bytes = world().transfer.receipt.to_canonical_protobuf().unwrap();
        bytes.extend_from_slice(&[0xA2, 0x01, 0x01, 0x00]); // tag 20, len 1

        let err = StitchedReceiptV2::from_canonical_protobuf(&bytes).unwrap_err();
        assert!(err.to_string().contains("unknown field 20"), "{err}");
    }

    #[test]
    fn receipt_decode_rejects_duplicate_field() {
        let receipt = &world().transfer.receipt;
        let mut bytes = receipt.to_canonical_protobuf().unwrap();
        bytes.push(0x0A); // tag 1
        bytes.push(0x20); // len 32
        bytes.extend_from_slice(&receipt.devid_b);

        let err = StitchedReceiptV2::from_canonical_protobuf(&bytes).unwrap_err();
        assert!(err.to_string().contains("duplicate field 1"), "{err}");
    }

    #[test]
    fn receipt_decode_rejects_bad_fixed_length() {
        let mut bytes = vec![0x0A, 0x1F];
        bytes.extend_from_slice(&world().transfer.receipt.genesis[..31]);

        let err = StitchedReceiptV2::from_canonical_protobuf(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("field 1 must be 32 bytes"),
            "{err}"
        );
    }

    #[test]
    fn receipt_decode_rejects_non_canonical_varint() {
        let mut bytes = world().transfer.receipt.to_canonical_protobuf().unwrap();
        bytes[1] = 0xA0;
        bytes.insert(2, 0x00);

        let err = StitchedReceiptV2::from_canonical_protobuf(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("non-canonical field length"),
            "{err}"
        );
    }

    #[test]
    fn receipt_decode_rejects_out_of_order_fields() {
        let bytes = world().transfer.receipt.to_canonical_protobuf().unwrap();
        let mut reordered = bytes[34..].to_vec();
        reordered.extend_from_slice(&bytes[..34]);

        let err = StitchedReceiptV2::from_canonical_protobuf(&reordered).unwrap_err();
        assert!(
            err.to_string()
                .contains("non-canonical field ordering or encoding"),
            "{err}"
        );
    }

    #[test]
    fn test_prost_encoding_tag_format() {
        let receipt = &world().transfer.receipt;
        let bytes = receipt.to_canonical_protobuf().unwrap();
        // Tag 1, wire type 2 (length-delimited) = (1 << 3) | 2 = 0x0A
        assert_eq!(bytes[0], 0x0A);
        // Length 32 = 0x20
        assert_eq!(bytes[1], 0x20);
        // Content: the author's genesis
        assert_eq!(&bytes[2..34], &receipt.genesis);
    }

    #[test]
    fn test_size_cap_enforcement() {
        let receipt = a_side()
            .with_countersign_b(countersign_b().0)
            .expect("the receiver countersigns");
        receipt
            .validate_size_cap()
            .expect("a countersigned receipt is under the cap");

        // A hostile device proof past the cap.
        let mut oversized = receipt;
        oversized.dev_proof = vec![0u8; 128 * 1024];
        assert!(oversized.validate_size_cap().is_err());
    }

    #[test]
    fn receipt_is_fully_signed_only_with_both_answers() {
        assert!(!world().transfer.receipt.is_fully_signed());
        let a = a_side();
        assert!(!a.is_fully_signed());
        let full = a
            .with_countersign_b(countersign_b().0)
            .expect("the receiver countersigns");
        assert!(full.is_fully_signed());
    }

    #[test]
    fn receipt_id_accessors() {
        let w = world();
        assert_eq!(w.transfer.receipt.id_a(), &w.sender.device_id());
        assert_eq!(w.transfer.receipt.id_b(), &w.receiver.device_id());
    }

    #[test]
    fn receipt_serialized_size_grows_with_sigs() {
        let w = world();
        let base_size = w
            .transfer
            .receipt
            .serialized_size()
            .expect("the receipt encodes");
        let full = a_side()
            .with_countersign_b(countersign_b().0)
            .expect("the receiver countersigns");
        assert_eq!(
            full.serialized_size().expect("the receipt encodes"),
            base_size + full.sig_a.len() + full.sig_b.len()
        );
    }

    #[test]
    fn receipt_canonical_commit_alias() {
        let receipt = &world().transfer.receipt;
        let a = receipt.compute_commitment().unwrap();
        let b = receipt.canonical_commit().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn receipt_different_steps_produce_different_commitments() {
        let w = world();
        let transfer = w.transfer.receipt.compute_commitment().unwrap();
        assert_ne!(transfer, w.fork.receipt.compute_commitment().unwrap());
        assert_ne!(transfer, w.credit.receipt.compute_commitment().unwrap());
    }

    // --- DeviceTreeAcceptanceCommitment ---

    #[test]
    fn device_tree_acceptance_from_root() {
        let root =
            crate::common::device_tree::DeviceTree::single(world().sender.device_id()).root();
        let c = DeviceTreeAcceptanceCommitment::from_root(root);
        assert_eq!(c.root(), root);
        let from_array: DeviceTreeAcceptanceCommitment = root.into();
        assert_eq!(from_array, c);
        let copied = c;
        assert_eq!(copied, c);
    }

    // --- ReceiptAcceptance ---

    #[test]
    fn receipt_acceptance_accept() {
        let commitment = world().transfer.receipt.compute_commitment().unwrap();
        let acc = ReceiptAcceptance::accept(commitment);
        assert!(acc.valid);
        assert!(acc.reason.is_none());
        assert_eq!(acc.commitment, Some(commitment));
    }

    #[test]
    fn receipt_acceptance_reject() {
        let acc = ReceiptAcceptance::reject("bad signature");
        assert!(!acc.valid);
        assert_eq!(acc.reason.as_deref(), Some("bad signature"));
        assert!(acc.commitment.is_none());
    }

    // --- ADR 0003 return leg: CountersignB split / overlay / wire codec ---

    /// The whole return-leg contract in one assertion chain: the recipient's
    /// split gives back EXACTLY the A bytes it received, and the sender's
    /// overlay of that delta onto its own A bytes gives back EXACTLY the
    /// recipient's full receipt. Both directions byte-identical, so a digest
    /// over either side is a digest over the same object.
    #[test]
    fn split_then_overlay_reproduces_the_full_wire_bytes_exactly() {
        let a_side = a_side();
        let a_bytes = a_side.to_full_protobuf().unwrap();
        // The A side is what the sender ships and retains: two SPHINCS+
        // objects of 49,856 bytes (σ_A and the EK certificate), the 64-byte
        // EK, the 1,088-byte ML-KEM ciphertext, and the step's fields with
        // its one compressed relationship path — 101 KB class, against the
        // 109 KB of the uncompressed path.
        assert!(
            (101_000..102_000).contains(&a_bytes.len()),
            "{}",
            a_bytes.len()
        );

        // Recipient: countersign, encode, store.
        let (b, _) = countersign_b();
        let full = a_side.with_countersign_b(b.clone()).unwrap();
        let full_bytes = full.to_full_protobuf().unwrap();
        // The countersignature adds exactly its four fields (σ_B 13, its EK
        // certificate 15, the EK 17, the ML-KEM ciphertext 19), each with its
        // field header, and nothing else.
        let b_fields: usize = [
            (13, &b.sig_b),
            (15, &b.ek_cert_b),
            (17, &b.ek_pk_b),
            (19, &b.kyber_ct_b),
        ]
        .into_iter()
        .map(|(tag, value)| prost::encoding::bytes::encoded_len(tag, value))
        .sum();
        assert_eq!(
            full_bytes.len(),
            a_bytes.len() + b_fields,
            "full countersigned receipt size"
        );

        // Recipient at reply time: decode its stored bytes and split.
        let decoded = StitchedReceiptV2::from_canonical_protobuf(&full_bytes).unwrap();
        let (a_again, b_again) = decoded.split_countersign_b().unwrap();
        assert_eq!(
            a_again.to_full_protobuf().unwrap(),
            a_bytes,
            "split A side must re-encode to the exact bytes the recipient received"
        );
        assert_eq!(b_again, b);

        // Sender: overlay the delta onto its retained A bytes.
        let reconstructed = StitchedReceiptV2::from_canonical_protobuf(&a_bytes)
            .unwrap()
            .with_countersign_b(b_again)
            .unwrap();
        assert_eq!(
            reconstructed.to_full_protobuf().unwrap(),
            full_bytes,
            "overlay must reproduce the recipient's countersigned receipt byte for byte"
        );
        assert_eq!(
            reconstructed.compute_commitment().unwrap(),
            a_side.compute_commitment().unwrap(),
            "commitment is blind to B fields"
        );
    }

    #[test]
    fn split_refuses_a_receipt_without_a_countersignature() {
        let a_side = a_side();
        let err = a_side.split_countersign_b().unwrap_err();
        assert!(
            format!("{err}").contains("no complete B-side countersignature"),
            "{err}"
        );

        // Partial B material is not a countersignature either.
        let mut half = a_side.clone();
        half.add_sig_b(countersign_b().0.sig_b);
        assert!(half.split_countersign_b().is_err());
    }

    #[test]
    fn overlay_refuses_an_already_countersigned_receipt_and_an_incomplete_delta() {
        let (b, _) = countersign_b();
        let full = a_side().with_countersign_b(b.clone()).unwrap();
        let err = full.with_countersign_b(b.clone()).unwrap_err();
        assert!(
            format!("{err}").contains("already carries B-side material"),
            "{err}"
        );

        let mut incomplete = b;
        incomplete.kyber_ct_b.clear();
        let err = a_side().with_countersign_b(incomplete).unwrap_err();
        assert!(format!("{err}").contains("incomplete"), "{err}");
    }

    #[test]
    fn countersign_wire_accepts_the_canonical_encoding_and_reencodes_identically() {
        use prost::Message;
        let a = a_side();
        let (b, (b_parent_tip, b_child_tip)) = countersign_b();
        let wire = delta_wire();
        let decoded = decode_receipt_countersign_b_wire(&wire).unwrap();
        assert_eq!(decoded.commitment, a.compute_commitment().unwrap().to_vec());
        assert_eq!(
            decoded.receipt_evidence_digest_a,
            evidence_digest_a(&a).to_vec()
        );
        assert_eq!(decoded.b_parent_tip, b_parent_tip.to_vec());
        assert_eq!(decoded.b_child_tip, b_child_tip.to_vec());
        // The pair is delta-only metadata: it never enters the receipt, so the
        // split/overlay byte identity above is untouched by it.
        assert_eq!(CountersignB::from_wire(&decoded), b);
        assert_eq!(decoded.encode_to_vec(), wire);
        // Two SPHINCS objects plus ~1.3 KB of everything else: the normative
        // budget class (ADR 0003), well under the 131,072-byte node cap even
        // before the transport wrapper.
        assert!(
            wire.len() > 100_000 && wire.len() < 102_000,
            "{}",
            wire.len()
        );
    }

    /// A full countersigned receipt fed to the delta decoder is refused — the
    /// sender can never mistake a whole receipt for a delta, so no legacy
    /// full-receipt reply can be consumed by accident. Tags 1–7 of a receipt
    /// are 32-byte fields the delta's first seven tags admit; the first
    /// divergence is `ReceiptCommit` tag 10, the device proof, which the delta
    /// does not have.
    #[test]
    fn countersign_wire_refuses_a_full_receipt_commit_body() {
        let full_bytes = a_side()
            .with_countersign_b(countersign_b().0)
            .unwrap()
            .to_full_protobuf()
            .unwrap();
        let err = decode_receipt_countersign_b_wire(&full_bytes).unwrap_err();
        assert!(
            format!("{err}").contains("countersign wire: unknown field 10"),
            "{err}"
        );
    }

    /// The recipient's canonical pair is REQUIRED and fixed-width: a delta
    /// without it (the pre-barrier shape) or with a truncated tip is refused at
    /// the wire, before any signature is examined.
    #[test]
    fn countersign_wire_requires_the_recipient_canonical_pair() {
        use prost::Message;
        let good = delta_wire();

        let mut no_pair = crate::types::proto::ReceiptCountersignB::decode(&good[..]).unwrap();
        no_pair.b_parent_tip.clear();
        no_pair.b_child_tip.clear();
        let err = decode_receipt_countersign_b_wire(&no_pair.encode_to_vec()).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field 7"),
            "{err}"
        );

        let mut short_child = crate::types::proto::ReceiptCountersignB::decode(&good[..]).unwrap();
        short_child.b_child_tip.truncate(31);
        let err = decode_receipt_countersign_b_wire(&short_child.encode_to_vec()).unwrap_err();
        assert!(
            format!("{err}").contains("field 8 must be 32 bytes"),
            "{err}"
        );

        decode_receipt_countersign_b_wire(&good).unwrap();
    }

    #[test]
    fn countersign_wire_refuses_missing_duplicate_and_oversized_fields() {
        use prost::Message;
        let good = delta_wire();

        // Missing kyber_ct_b (field 6): the live gate is structural, so the
        // wire must not let it through silently.
        let mut no_ct = crate::types::proto::ReceiptCountersignB::decode(&good[..]).unwrap();
        no_ct.kyber_ct_b.clear();
        let err = decode_receipt_countersign_b_wire(&no_ct.encode_to_vec()).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field 6"),
            "{err}"
        );

        // Wrong fixed length on the digest binding.
        let mut short_digest = crate::types::proto::ReceiptCountersignB::decode(&good[..]).unwrap();
        short_digest.receipt_evidence_digest_a.truncate(31);
        let err = decode_receipt_countersign_b_wire(&short_digest.encode_to_vec()).unwrap_err();
        assert!(
            format!("{err}").contains("field 2 must be 32 bytes"),
            "{err}"
        );

        // Duplicate field: a hostile second field-1 appended to the canonical
        // bytes.
        let mut dup = good.clone();
        let mut extra = crate::types::proto::ReceiptCountersignB {
            commitment: world().fork.receipt.compute_commitment().unwrap().to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        dup.append(&mut extra);
        let err = decode_receipt_countersign_b_wire(&dup).unwrap_err();
        assert!(format!("{err}").contains("duplicate field 1"), "{err}");

        // A hostile kyber_ct_b past its cap (2,048).
        let mut fat = crate::types::proto::ReceiptCountersignB::decode(&good[..]).unwrap();
        fat.kyber_ct_b = vec![0u8; 2_049];
        let err = decode_receipt_countersign_b_wire(&fat.encode_to_vec()).unwrap_err();
        assert!(
            format!("{err}").contains("field 6 exceeds max length 2048"),
            "{err}"
        );

        // Positive control in the same shape: the untouched bytes decode.
        decode_receipt_countersign_b_wire(&good).unwrap();
    }

    // --- Finality barrier: RelationshipFinalizedV1 wire codec ---

    fn production_shaped_certificate() -> crate::types::proto::RelationshipFinalizedV1 {
        crate::types::proto::RelationshipFinalizedV1 {
            relationship_key: vec![0x01; 32],
            transition_commitment: vec![0x02; 32],
            sender_device_id: vec![0x03; 32],
            recipient_device_id: vec![0x04; 32],
            sender_child_tip_a: vec![0x05; 32],
            recipient_parent_tip_b: vec![0x06; 32],
            recipient_child_tip_b: vec![0x07; 32],
            signature_a: vec![0xAA; 49_856],
        }
    }

    /// One SPHINCS+ signature plus seven tips: well under the node cap, and
    /// the strict codec accepts exactly the canonical encoding.
    #[test]
    fn relationship_finalized_wire_accepts_canonical_encoding_under_the_cap() {
        use prost::Message;
        let cert = production_shaped_certificate();
        let wire = cert.encode_to_vec();
        assert!(wire.len() < 131_072, "{}", wire.len());
        assert!(wire.len() > 49_856, "{}", wire.len());
        let decoded = decode_relationship_finalized_wire(&wire).unwrap();
        assert_eq!(decoded, cert);
        assert_eq!(
            relationship_finalized_signing_target(&decoded),
            relationship_finalized_signing_target(&cert)
        );
    }

    #[test]
    fn relationship_finalized_wire_refuses_missing_short_unknown_and_duplicate_fields() {
        use prost::Message;
        let good = production_shaped_certificate().encode_to_vec();

        let mut no_sig = production_shaped_certificate();
        no_sig.signature_a.clear();
        let err = decode_relationship_finalized_wire(&no_sig.encode_to_vec()).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field 8"),
            "{err}"
        );

        let mut short = production_shaped_certificate();
        short.recipient_child_tip_b.truncate(31);
        let err = decode_relationship_finalized_wire(&short.encode_to_vec()).unwrap_err();
        assert!(
            format!("{err}").contains("field 7 must be 32 bytes"),
            "{err}"
        );

        // A countersign delta on the certificate method: refused at the wire
        // (its tag 3 is a signature, not a 32-byte tip).
        let delta = delta_wire();
        let err = decode_relationship_finalized_wire(&delta).unwrap_err();
        assert!(
            format!("{err}").contains("field 3 must be 32 bytes"),
            "{err}"
        );

        let mut dup = good.clone();
        let mut extra = crate::types::proto::RelationshipFinalizedV1 {
            relationship_key: vec![0x33; 32],
            ..Default::default()
        }
        .encode_to_vec();
        dup.append(&mut extra);
        let err = decode_relationship_finalized_wire(&dup).unwrap_err();
        assert!(format!("{err}").contains("duplicate field 1"), "{err}");

        decode_relationship_finalized_wire(&good).unwrap();
    }

    /// The signing target covers every tip field and never the signature.
    #[test]
    fn relationship_finalized_signing_target_binds_every_field_but_the_signature() {
        let base = production_shaped_certificate();
        let t0 = relationship_finalized_signing_target(&base);
        let mut sig_only = base.clone();
        sig_only.signature_a = vec![0xBB; 49_856];
        assert_eq!(relationship_finalized_signing_target(&sig_only), t0);
        for i in 0..7 {
            let mut c = base.clone();
            let f: &mut Vec<u8> = match i {
                0 => &mut c.relationship_key,
                1 => &mut c.transition_commitment,
                2 => &mut c.sender_device_id,
                3 => &mut c.recipient_device_id,
                4 => &mut c.sender_child_tip_a,
                5 => &mut c.recipient_parent_tip_b,
                _ => &mut c.recipient_child_tip_b,
            };
            f[0] ^= 0x01;
            assert_ne!(relationship_finalized_signing_target(&c), t0, "field {i}");
        }
    }

    // --- ParentConsumptionTracker ---

    #[test]
    fn tracker_fresh_parent_not_consumed() {
        let tracker = ParentConsumptionTracker::new();
        assert!(!tracker.is_consumed(&[0; 32]));
        assert!(tracker.get_child(&[0; 32]).is_none());
    }

    #[test]
    fn tracker_with_capacity_behaves_like_new() {
        let tracker = ParentConsumptionTracker::with_capacity(100);
        assert!(!tracker.is_consumed(&[0xFF; 32]));
    }

    #[test]
    fn tracker_multiple_distinct_parents() {
        let mut tracker = ParentConsumptionTracker::new();
        let p1 = [1u8; 32];
        let p2 = [2u8; 32];
        let c1 = [0xA0; 32];
        let c2 = [0xB0; 32];

        tracker.try_consume(p1, c1).unwrap();
        tracker.try_consume(p2, c2).unwrap();

        assert_eq!(tracker.get_child(&p1), Some(&c1));
        assert_eq!(tracker.get_child(&p2), Some(&c2));
    }

    #[test]
    fn tracker_replay_same_child_is_error() {
        let mut tracker = ParentConsumptionTracker::new();
        let parent = [0x10; 32];
        let child = [0x20; 32];
        tracker.try_consume(parent, child).unwrap();
        let err = tracker.try_consume(parent, child).unwrap_err();
        assert!(format!("{err}").contains("replay"));
    }
}
