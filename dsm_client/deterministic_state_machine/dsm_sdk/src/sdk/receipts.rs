//! # Receipt Primitives for Offline Bilateral Flows
//!
//! Re-exports canonical receipt types and verification from `dsm::core`,
//! adding SDK-level helpers for relationship key derivation and monotonic
//! counter checking on stitched receipts.

use dsm::types::error::DsmError;

// Re-export canonical types from dsm core
pub use dsm::types::receipt_types::{
    DeviceTreeAcceptanceCommitment, ParentConsumptionTracker as ReceiptGuard, ReceiptAcceptance,
    ReceiptVerificationContext, StitchedReceiptV2,
};

/// Derive relationship key from counterparty public key.
/// Domain-separated to prevent collision with other hash contexts.
pub fn derive_relationship_key(counterparty_pk: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes("DSM/relationship-key", counterparty_pk)
}

/// Verify a stitched receipt with signatures.
///
/// Delegates to the canonical core verifier. Replay protection is enforced
/// by the `ParentConsumptionTracker` (one-time parent-tip lock per relationship),
/// NOT by sequence numbers — the protocol is clockless (§4.3).
#[allow(clippy::too_many_arguments)]
pub fn verify_stitched_receipt(
    receipt: &StitchedReceiptV2,
    sig_a: &[u8],
    sig_b: &[u8],
    pk_a: &[u8],
    pk_b: &[u8],
    device_tree_commitment: DeviceTreeAcceptanceCommitment,
    guard: Option<&mut ReceiptGuard>,
) -> Result<(), DsmError> {
    // Create verification context
    let ctx = ReceiptVerificationContext::new(
        device_tree_commitment,
        receipt.parent_root,
        pk_a.to_vec(),
        pk_b.to_vec(),
    );

    // Prepare signatures on the receipt
    let mut receipt_with_sigs = receipt.clone();
    receipt_with_sigs.add_sig_a(sig_a.to_vec());
    receipt_with_sigs.add_sig_b(sig_b.to_vec());

    // Use canonical verification
    let mut local_tracker;
    let tracker = if let Some(g) = guard {
        g
    } else {
        local_tracker = ReceiptGuard::new();
        &mut local_tracker
    };

    let result = dsm::verification::receipt_verification::verify_stitched_receipt(
        &receipt_with_sigs,
        &ctx,
        tracker,
    )?;

    if result.valid {
        Ok(())
    } else {
        Err(DsmError::invalid_operation(format!(
            "Receipt verification failed: {}",
            result.reason.unwrap_or_else(|| "unknown".to_string())
        )))
    }
}

/// Build a complete `StitchedReceiptV2` struct with real cryptographic material.
///
/// **This is the SINGLE authoritative receipt constructor for the entire SDK.**
/// All receipt construction — bilateral, unilateral, faucet, BLE, online —
/// MUST go through this function. It computes:
/// - Real genesis hash from `AppState`
/// - Stub parent/child SMT roots via `hash_smt_leaf()` (zero-depth, leaf=root)
/// - Parseable `SerializableMerkleProof` envelopes for relation proofs
/// - Canonical `DevTreeProof` for device binding
/// - Zero-depth SMT replace witness (verified against tripwire)
///
/// Returns `None` only if strict verification of the computed artifacts fails.
pub fn build_receipt_struct(
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> Option<StitchedReceiptV2> {
    use dsm::common::device_tree;
    use dsm::verification::smt_replace_witness::{
        compute_smt_key, hash_smt_leaf, verify_tripwire_smt_replace,
    };

    // 1. Real genesis hash from AppState.
    let genesis = {
        let mut g = [0u8; 32];
        if let Some(gh) = crate::sdk::app_state::AppState::get_genesis_hash() {
            if gh.len() >= 32 {
                g.copy_from_slice(&gh[..32]);
            }
        }
        if g == [0u8; 32] {
            log::warn!(
                "[receipts] genesis hash unavailable from AppState — receipt will be unverifiable"
            );
            return None;
        }
        g
    };

    // 2. STUB: Compute degenerate single-leaf SMT roots (leaf hash = root).
    //    This creates a zero-depth tree where the leaf IS the root, with no
    //    siblings. The BLE offline path uses `build_bilateral_receipt_with_smt()`
    //    with real SparseMerkleTree roots instead. This stub path is for online receipts
    //    that don't yet track the full Per-Device SMT.
    let smt_key = compute_smt_key(&devid_a, &devid_b);
    let parent_root = hash_smt_leaf(&parent_tip);
    let child_root = hash_smt_leaf(&child_tip);

    // 3. Build parseable relation proofs in SmtInclusionProof format
    //    (zero-depth SMT: rel_key is the key, tip is the value, no siblings).
    let rel_proof_parent =
        serialize_inclusion_proof(&dsm::merkle::sparse_merkle_tree::SmtInclusionProof {
            key: smt_key,
            value: Some(parent_tip),
            siblings: Vec::new(),
        });
    let rel_proof_child =
        serialize_inclusion_proof(&dsm::merkle::sparse_merkle_tree::SmtInclusionProof {
            key: smt_key,
            value: Some(child_tip),
            siblings: Vec::new(),
        });

    // 4. Build device tree proof via DeviceTree builder (§2.3).
    //    The authenticated commitment used for `π_dev` MUST be supplied explicitly
    //    by the caller. Today that commitment is the concrete root `R_G`.
    let device_tree_commitment = match device_tree_commitment {
        Some(commitment) => commitment,
        None => {
            log::error!(
                "[receipts] build_receipt_struct: authenticated device-tree commitment is required; refusing to derive a synthetic R_G"
            );
            return None;
        }
    };
    let r_g = device_tree_commitment.root();
    let dev_tree = device_tree::DeviceTree::single(devid_a);
    let dev_proof_obj = dev_tree
        .proof(&devid_a)
        .unwrap_or(device_tree::DevTreeProof {
            siblings: Vec::new(),
            path_bits: Vec::new(),
            leaf_to_root: true,
        });
    let dev_proof = dev_proof_obj.to_bytes();

    // 5. Zero-depth replace witness.
    let witness: Vec<u8> = 0u32.to_le_bytes().to_vec();

    // 6. Strict verification: proofs must parse and tripwire must pass.
    if deserialize_inclusion_proof(&rel_proof_parent).is_err()
        || deserialize_inclusion_proof(&rel_proof_child).is_err()
    {
        log::warn!("[receipts] Failed to build parseable relation proofs");
        return None;
    }

    let parsed_dev = device_tree::DevTreeProof::from_bytes(&dev_proof)?;
    if !parsed_dev.verify(&devid_a, &r_g) {
        log::warn!("[receipts] Device proof verification failed against R_G");
        return None;
    }

    if !verify_tripwire_smt_replace(&parent_root, &child_root, &parent_tip, &child_tip, &witness)
        .ok()?
    {
        log::warn!("[receipts] Tripwire SMT replace witness verification failed");
        return None;
    }

    // 7. Assemble receipt.
    let mut receipt = StitchedReceiptV2::new(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        parent_root,
        child_root,
        rel_proof_parent,
        rel_proof_child,
        dev_proof,
    );
    receipt.set_rel_replace_witness(witness);
    Some(receipt)
}

/// Convenience wrapper: build receipt and serialize to canonical protobuf bytes.
///
/// Delegates entirely to `build_receipt_struct()` for all crypto, then serializes.
pub fn build_bilateral_receipt(
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> Option<Vec<u8>> {
    build_receipt_struct(
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        device_tree_commitment,
    )?
    .to_canonical_protobuf()
    .ok()
}

/// Build receipt with **real** Per-Device SMT roots and inclusion proofs (§4.2).
///
/// Unlike `build_bilateral_receipt()` which computes single-leaf stub proofs,
/// this function accepts the actual SMT roots and serialized inclusion proofs
/// produced by `SparseMerkleTree` after an `update_leaf()` call. Use this when the
/// caller has already performed the SMT-Replace and collected the proofs.
#[allow(clippy::too_many_arguments)]
pub fn build_bilateral_receipt_with_smt(
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    parent_root: [u8; 32],
    child_root: [u8; 32],
    rel_proof_parent: Vec<u8>,
    rel_proof_child: Vec<u8>,
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> Option<Vec<u8>> {
    use dsm::common::device_tree;

    // 1. Real genesis hash from AppState.
    let genesis = {
        let mut g = [0u8; 32];
        if let Some(gh) = crate::sdk::app_state::AppState::get_genesis_hash() {
            if gh.len() >= 32 {
                g.copy_from_slice(&gh[..32]);
            }
        }
        if g == [0u8; 32] {
            log::warn!(
                "[receipts] genesis hash unavailable from AppState — receipt will be unverifiable"
            );
            return None;
        }
        g
    };

    // 2. Build device tree proof via DeviceTree builder (§2.3).
    //    The authenticated commitment used for `π_dev` MUST be supplied explicitly
    //    by the caller. Today that commitment is the concrete root `R_G`.
    let device_tree_commitment = match device_tree_commitment {
        Some(commitment) => commitment,
        None => {
            log::error!(
                "[receipts] build_bilateral_receipt_with_smt: authenticated device-tree commitment is required; refusing to derive a synthetic R_G"
            );
            return None;
        }
    };
    let r_g = device_tree_commitment.root();
    let dev_tree = device_tree::DeviceTree::single(devid_a);
    let dev_proof_obj = dev_tree
        .proof(&devid_a)
        .unwrap_or(device_tree::DevTreeProof {
            siblings: Vec::new(),
            path_bits: Vec::new(),
            leaf_to_root: true,
        });
    let dev_proof = dev_proof_obj.to_bytes();

    // 3. Zero-depth replace witness (tripwire).
    let witness: Vec<u8> = 0u32.to_le_bytes().to_vec();

    // 4. Verify device proof against R_G before assembly.
    let parsed_dev = device_tree::DevTreeProof::from_bytes(&dev_proof)?;
    if !parsed_dev.verify(&devid_a, &r_g) {
        log::warn!("[receipts] Device proof verification failed against R_G");
        return None;
    }

    // 5. Assemble receipt with real SMT roots and proofs.
    let mut receipt = StitchedReceiptV2::new(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        parent_root,
        child_root,
        rel_proof_parent,
        rel_proof_child,
        dev_proof,
    );
    receipt.set_rel_replace_witness(witness);
    receipt.to_canonical_protobuf().ok()
}

/// Verify a stitched receipt from its canonical protobuf bytes (§4.3).
///
/// Both counterparties share an **identical chain tip** h_n for C_{A↔B}.
/// Implements the normative verification rules from §4.3:
///
/// 1. Protobuf decodes the receipt
/// 2. All 32-byte fixed fields (genesis, devids, tips, roots) must be non-zero
/// 3. §4.3#2: π_rel proves h_n ∈ r_A and π'_rel proves h_{n+1} ∈ r'_A
///    (SmtInclusionProof deserialization + root reconstruction)
/// 4. §4.3#4: Leaf-replace recomputation — replacing h_n with h_{n+1} using
///    the same sibling path must yield r'_A byte-exactly
/// 5. §4.3#3: π_dev proves DevID_A ∈ R_G (Device Tree inclusion)
///
/// `device_tree_commitment`: explicit authenticated commitment for the sender's
/// Device Tree path. `None` is rejected.
/// Returns `true` only if all checks pass.
pub fn verify_receipt_bytes(
    receipt_bytes: &[u8],
    device_tree_commitment: Option<DeviceTreeAcceptanceCommitment>,
) -> bool {
    use dsm::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};
    use dsm::common::device_tree;
    use dsm::verification::smt_replace_witness::compute_smt_key;

    // 1. Decode the canonical protobuf into a StitchedReceiptV2.
    let receipt = match StitchedReceiptV2::from_canonical_protobuf(receipt_bytes) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // 2. Non-zero fixed fields.
    let is_zero = |b: &[u8; 32]| b.iter().all(|&v| v == 0);
    if is_zero(&receipt.genesis)
        || is_zero(&receipt.devid_a)
        || is_zero(&receipt.devid_b)
        || is_zero(&receipt.parent_tip)
        || is_zero(&receipt.child_tip)
        || is_zero(&receipt.parent_root)
        || is_zero(&receipt.child_root)
    {
        return false;
    }

    // 3–4. §4.3#2+#4: Both counterparties share an IDENTICAL chain tip.
    //   π_rel proves h_n ∈ r_A, π'_rel proves h_{n+1} ∈ r'_A.
    //   Leaf-replace recomputation (same siblings, swap h_n→h_{n+1}) must yield r'_A.
    let smt_key = compute_smt_key(&receipt.devid_a, &receipt.devid_b);

    let parent_proof = deserialize_inclusion_proof(&receipt.rel_proof_parent).ok();
    let child_proof = match deserialize_inclusion_proof(&receipt.rel_proof_child) {
        Ok(p) => p,
        Err(_) => return false, // child proof must always exist (post-update)
    };

    // §4.3#2: π'_rel proves h_{n+1} ∈ r'_A
    if child_proof.key != smt_key {
        return false;
    }
    if child_proof.value != Some(receipt.child_tip) {
        return false;
    }
    if !SparseMerkleTree::verify_proof_against_root(&child_proof, &receipt.child_root) {
        return false;
    }

    if let Some(pp) = parent_proof {
        // Full verification: parent proof exists.
        if pp.key != smt_key {
            return false;
        }
        // §4.3#2: π_rel MUST prove inclusion of h_n in r_A.
        // Fail closed: the proof value must be present and must equal parent_tip.
        // A non-inclusion proof (value=None) or value mismatch both reject.
        match pp.value {
            Some(v) if v == receipt.parent_tip => { /* inclusion of correct tip */ }
            _ => return false,
        }

        // §4.3#2: π_rel proves h_n ∈ r_A
        if !SparseMerkleTree::verify_proof_against_root(&pp, &receipt.parent_root) {
            return false;
        }

        // §4.3#4: Leaf-replace recomputation.
        // Single leaf change ⇒ sibling path is identical.
        // Replace h_n with h_{n+1} using parent's siblings → must yield r'_A.
        let replace_proof = SmtInclusionProof {
            key: smt_key,
            value: Some(receipt.child_tip),
            siblings: pp.siblings,
        };
        if !SparseMerkleTree::verify_proof_against_root(&replace_proof, &receipt.child_root) {
            return false;
        }
    }
    // If parent proof absent: first tx for this relationship (leaf was ZERO_LEAF).
    // Child proof already verified above.

    // 5. §4.3#3: Device proof must parse and verify against the authenticated
    //    local commitment used for `π_dev`.
    //    Today this is the raw root `R_G`, supplied by the caller from a trusted
    //    external source (§2.3 commit path). If None, reject: acceptance predicates
    //    must never derive `R_G` from the receipt itself.
    let r_g = match device_tree_commitment {
        Some(commitment) => commitment.root(),
        None => {
            log::error!(
                "[receipts] §4.3#3 FATAL: authenticated device-tree commitment not provided — \
                 R_G or an equivalent authenticated persisted commitment must be externally supplied, never derived from the receipt itself."
            );
            return false;
        }
    };
    match device_tree::DevTreeProof::from_bytes(&receipt.dev_proof) {
        Some(parsed) => {
            if !parsed.verify(&receipt.devid_a, &r_g) {
                return false;
            }
        }
        None => return false,
    }

    true
}

/// Serialize a `SmtInclusionProof` to bytes for wire transport.
///
/// Format: [32-byte key][1-byte has_value][optional 32-byte value][4-byte LE sibling count][32-byte siblings...]
pub fn serialize_inclusion_proof(
    proof: &dsm::merkle::sparse_merkle_tree::SmtInclusionProof,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 1 + 32 + 4 + proof.siblings.len() * 32);
    buf.extend_from_slice(&proof.key);
    buf.push(proof.value.is_some() as u8);
    if let Some(v) = &proof.value {
        buf.extend_from_slice(v);
    }
    buf.extend_from_slice(&(proof.siblings.len() as u32).to_le_bytes());
    for s in &proof.siblings {
        buf.extend_from_slice(s);
    }
    buf
}

/// Deserialize a `SmtInclusionProof` from bytes.
pub fn deserialize_inclusion_proof(
    data: &[u8],
) -> Result<dsm::merkle::sparse_merkle_tree::SmtInclusionProof, DsmError> {
    if data.len() < 33 {
        return Err(DsmError::invalid_operation(
            "inclusion proof too short: need at least 33 bytes",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let has_value = data[32] != 0;
    let mut offset = 33;
    let value = if has_value {
        if data.len() < offset + 32 {
            return Err(DsmError::invalid_operation(
                "inclusion proof truncated at value",
            ));
        }
        let mut v = [0u8; 32];
        v.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        Some(v)
    } else {
        None
    };
    if data.len() < offset + 4 {
        return Err(DsmError::invalid_operation(
            "inclusion proof truncated at sibling count",
        ));
    }
    let count =
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or_default()) as usize;
    offset += 4;
    if data.len() < offset + count * 32 {
        return Err(DsmError::invalid_operation(
            "inclusion proof truncated at siblings",
        ));
    }
    let mut siblings = Vec::with_capacity(count);
    for i in 0..count {
        let mut s = [0u8; 32];
        s.copy_from_slice(&data[offset + i * 32..offset + (i + 1) * 32]);
        siblings.push(s);
    }
    Ok(dsm::merkle::sparse_merkle_tree::SmtInclusionProof {
        key,
        value,
        siblings,
    })
}

/// Deterministically derive a stitched receipt sigma from canonical input parts.
///
/// This uses the DSM receipt commitment domain tag and length-prefixes each input
/// part to prevent ambiguity:
/// `BLAKE3("DSM/receipt-commit\0" || len(part_0)||part_0 || ... )`.
///
/// Callers should prefer a true `StitchedReceiptV2::compute_commitment()` when
/// available. This helper mirrors the same domain and deterministic framing.
pub fn derive_stitched_receipt_sigma(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/receipt-commit");
    for part in parts {
        hasher.update(&(part.len() as u32).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Deterministically encode a protocol-only transition payload.
///
/// This is used for sovereign DLV/faucet/bitcoin transitions that need a stable
/// commitment domain but are not bilateral stitched receipts.
pub fn encode_protocol_transition_payload(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(label.len() as u32).to_le_bytes());
    out.extend_from_slice(label);
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Deterministically derive a protocol-transition commitment.
///
/// This must be used for sovereign protocol actors instead of the bilateral
/// `DSM/receipt-commit` domain.
pub fn compute_protocol_transition_commitment(payload_bytes: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes("DSM/protocol-transition", payload_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::merkle::sparse_merkle_tree::SmtInclusionProof;

    // ── derive_relationship_key ──

    #[test]
    fn derive_relationship_key_deterministic() {
        let pk = [0xABu8; 32];
        let a = derive_relationship_key(&pk);
        let b = derive_relationship_key(&pk);
        assert_eq!(a, b, "same input must yield identical key");
    }

    #[test]
    fn derive_relationship_key_varies_with_input() {
        let k1 = derive_relationship_key(&[1u8; 32]);
        let k2 = derive_relationship_key(&[2u8; 32]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_relationship_key_nonzero() {
        let k = derive_relationship_key(b"any-counterparty-pk");
        assert_ne!(k, [0u8; 32]);
    }

    // ── serialize / deserialize inclusion proof round-trip ──

    fn sample_proof(with_value: bool, siblings: usize) -> SmtInclusionProof {
        SmtInclusionProof {
            key: [0x11u8; 32],
            value: if with_value { Some([0x22u8; 32]) } else { None },
            siblings: (0..siblings)
                .map(|i| [(i as u8).wrapping_add(0x30); 32])
                .collect(),
        }
    }

    #[test]
    fn roundtrip_proof_with_value_no_siblings() {
        let proof = sample_proof(true, 0);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.key, proof.key);
        assert_eq!(decoded.value, proof.value);
        assert!(decoded.siblings.is_empty());
    }

    #[test]
    fn roundtrip_proof_without_value_no_siblings() {
        let proof = sample_proof(false, 0);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.key, proof.key);
        assert_eq!(decoded.value, None);
        assert!(decoded.siblings.is_empty());
    }

    #[test]
    fn roundtrip_proof_with_value_and_siblings() {
        let proof = sample_proof(true, 4);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.key, proof.key);
        assert_eq!(decoded.value, proof.value);
        assert_eq!(decoded.siblings.len(), 4);
        assert_eq!(decoded.siblings, proof.siblings);
    }

    #[test]
    fn roundtrip_proof_without_value_with_siblings() {
        let proof = sample_proof(false, 3);
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.value, None);
        assert_eq!(decoded.siblings.len(), 3);
    }

    #[test]
    fn serialize_proof_expected_length_with_value() {
        let proof = sample_proof(true, 2);
        let bytes = serialize_inclusion_proof(&proof);
        // 32 (key) + 1 (has_value) + 32 (value) + 4 (count) + 2*32 (siblings)
        assert_eq!(bytes.len(), 32 + 1 + 32 + 4 + 64);
    }

    #[test]
    fn serialize_proof_expected_length_without_value() {
        let proof = sample_proof(false, 2);
        let bytes = serialize_inclusion_proof(&proof);
        // 32 (key) + 1 (has_value) + 4 (count) + 2*32 (siblings)
        assert_eq!(bytes.len(), 32 + 1 + 4 + 64);
    }

    // ── deserialize error cases ──

    #[test]
    fn deserialize_too_short() {
        let short = vec![0u8; 10];
        assert!(deserialize_inclusion_proof(&short).is_err());
    }

    #[test]
    fn deserialize_truncated_at_value() {
        // 32 key + has_value=1, but no value bytes
        let mut data = vec![0u8; 33];
        data[32] = 1; // has_value = true
        assert!(deserialize_inclusion_proof(&data).is_err());
    }

    #[test]
    fn deserialize_truncated_at_sibling_count() {
        // 32 key + has_value=0, missing sibling count bytes
        let data = vec![0u8; 33]; // has_value=0, no count
        assert!(deserialize_inclusion_proof(&data).is_err());
    }

    #[test]
    fn deserialize_truncated_siblings() {
        // valid header + count=2, but only 1 sibling worth of bytes
        let proof = sample_proof(false, 2);
        let bytes = serialize_inclusion_proof(&proof);
        let truncated = &bytes[..bytes.len() - 16]; // remove half of second sibling
        assert!(deserialize_inclusion_proof(truncated).is_err());
    }

    #[test]
    fn deserialize_empty_is_err() {
        assert!(deserialize_inclusion_proof(&[]).is_err());
    }

    // ── derive_stitched_receipt_sigma ──

    #[test]
    fn sigma_deterministic() {
        let parts: Vec<&[u8]> = vec![b"hello", b"world"];
        let a = derive_stitched_receipt_sigma(&parts);
        let b = derive_stitched_receipt_sigma(&parts);
        assert_eq!(a, b);
    }

    #[test]
    fn sigma_varies_with_different_parts() {
        let s1 = derive_stitched_receipt_sigma(&[b"a", b"b"]);
        let s2 = derive_stitched_receipt_sigma(&[b"a", b"c"]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn sigma_order_matters() {
        let s1 = derive_stitched_receipt_sigma(&[b"first", b"second"]);
        let s2 = derive_stitched_receipt_sigma(&[b"second", b"first"]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn sigma_empty_parts() {
        let s = derive_stitched_receipt_sigma(&[]);
        assert_ne!(s, [0u8; 32]);
    }

    #[test]
    fn sigma_nonzero() {
        let s = derive_stitched_receipt_sigma(&[b"test"]);
        assert_ne!(s, [0u8; 32]);
    }

    #[test]
    fn sigma_length_prefixing_prevents_ambiguity() {
        // "ab" + "cd" vs "abc" + "d" should differ due to length prefixes
        let s1 = derive_stitched_receipt_sigma(&[b"ab", b"cd"]);
        let s2 = derive_stitched_receipt_sigma(&[b"abc", b"d"]);
        assert_ne!(s1, s2);
    }

    // ── encode_protocol_transition_payload ──

    #[test]
    fn encode_protocol_transition_basic() {
        let encoded = encode_protocol_transition_payload(b"FAUCET", &[b"part1", b"part2"]);
        // label len (4) + label (6) + part1 len (4) + part1 (5) + part2 len (4) + part2 (5) = 28
        assert_eq!(encoded.len(), 4 + 6 + 4 + 5 + 4 + 5);
    }

    #[test]
    fn encode_protocol_transition_deterministic() {
        let a = encode_protocol_transition_payload(b"LABEL", &[b"data"]);
        let b = encode_protocol_transition_payload(b"LABEL", &[b"data"]);
        assert_eq!(a, b);
    }

    #[test]
    fn encode_protocol_transition_empty_parts() {
        let encoded = encode_protocol_transition_payload(b"LABEL", &[]);
        // just label length-prefix + label = 4 + 5
        assert_eq!(encoded.len(), 4 + 5);
    }

    #[test]
    fn encode_protocol_transition_empty_label() {
        let encoded = encode_protocol_transition_payload(b"", &[b"data"]);
        // label_len(4) + label(0) + data_len(4) + data(4) = 12
        assert_eq!(encoded.len(), 4 + 4 + 4);
    }

    #[test]
    fn encode_protocol_transition_label_at_offset_zero() {
        let encoded = encode_protocol_transition_payload(b"LBL", &[b"X"]);
        // First 4 bytes = label length (3)
        let label_len = u32::from_le_bytes(encoded[0..4].try_into().unwrap());
        assert_eq!(label_len, 3);
        assert_eq!(&encoded[4..7], b"LBL");
    }

    #[test]
    fn encode_protocol_transition_parts_are_length_prefixed() {
        let encoded = encode_protocol_transition_payload(b"L", &[b"AB", b"CDE"]);
        // After label: offset = 4+1=5
        // Part0: len(4)=2, data(2)="AB" → offset 5..11
        let p0_len = u32::from_le_bytes(encoded[5..9].try_into().unwrap());
        assert_eq!(p0_len, 2);
        assert_eq!(&encoded[9..11], b"AB");
        // Part1: len(4)=3, data(3)="CDE" → offset 11..18
        let p1_len = u32::from_le_bytes(encoded[11..15].try_into().unwrap());
        assert_eq!(p1_len, 3);
        assert_eq!(&encoded[15..18], b"CDE");
    }

    // ── compute_protocol_transition_commitment ──

    #[test]
    fn protocol_commitment_deterministic() {
        let a = compute_protocol_transition_commitment(b"payload");
        let b = compute_protocol_transition_commitment(b"payload");
        assert_eq!(a, b);
    }

    #[test]
    fn protocol_commitment_varies() {
        let a = compute_protocol_transition_commitment(b"payload_a");
        let b = compute_protocol_transition_commitment(b"payload_b");
        assert_ne!(a, b);
    }

    #[test]
    fn protocol_commitment_nonzero() {
        let c = compute_protocol_transition_commitment(b"data");
        assert_ne!(c, [0u8; 32]);
    }

    #[test]
    fn protocol_commitment_empty_input() {
        let c = compute_protocol_transition_commitment(b"");
        assert_ne!(c, [0u8; 32]);
    }

    // ── serialize/deserialize: additional edge cases ──

    #[test]
    fn roundtrip_proof_many_siblings() {
        let proof = SmtInclusionProof {
            key: [0xFF; 32],
            value: Some([0xEE; 32]),
            siblings: (0..256).map(|i| [(i as u8); 32]).collect(),
        };
        let bytes = serialize_inclusion_proof(&proof);
        let decoded = deserialize_inclusion_proof(&bytes).unwrap();
        assert_eq!(decoded.siblings.len(), 256);
        assert_eq!(decoded.key, [0xFF; 32]);
        assert_eq!(decoded.value, Some([0xEE; 32]));
        for (i, sib) in decoded.siblings.iter().enumerate() {
            assert_eq!(*sib, [(i as u8); 32]);
        }
    }

    #[test]
    fn serialize_proof_key_is_first_32_bytes() {
        let proof = SmtInclusionProof {
            key: [0xAB; 32],
            value: None,
            siblings: vec![],
        };
        let bytes = serialize_inclusion_proof(&proof);
        assert_eq!(&bytes[..32], &[0xAB; 32]);
    }

    #[test]
    fn serialize_has_value_byte_zero_when_none() {
        let proof = SmtInclusionProof {
            key: [0; 32],
            value: None,
            siblings: vec![],
        };
        let bytes = serialize_inclusion_proof(&proof);
        assert_eq!(bytes[32], 0);
    }

    #[test]
    fn serialize_has_value_byte_one_when_some() {
        let proof = SmtInclusionProof {
            key: [0; 32],
            value: Some([0; 32]),
            siblings: vec![],
        };
        let bytes = serialize_inclusion_proof(&proof);
        assert_eq!(bytes[32], 1);
    }

    #[test]
    fn deserialize_exact_minimum_no_value() {
        // 32 key + 1 has_value(0) + 4 count(0) = 37 bytes
        let mut data = vec![0u8; 37];
        data[32] = 0; // has_value = false
                      // count bytes already zero (0 siblings)
        let proof = deserialize_inclusion_proof(&data).unwrap();
        assert_eq!(proof.key, [0u8; 32]);
        assert_eq!(proof.value, None);
        assert!(proof.siblings.is_empty());
    }

    #[test]
    fn deserialize_exact_minimum_with_value() {
        // 32 key + 1 has_value(1) + 32 value + 4 count(0) = 69 bytes
        let mut data = vec![0u8; 69];
        data[32] = 1; // has_value = true
        data[33..65].copy_from_slice(&[0xCC; 32]); // value
                                                   // count bytes at 65..69 already zero
        let proof = deserialize_inclusion_proof(&data).unwrap();
        assert_eq!(proof.value, Some([0xCC; 32]));
        assert!(proof.siblings.is_empty());
    }

    #[test]
    fn deserialize_sibling_count_as_le_u32() {
        let proof = sample_proof(false, 1);
        let bytes = serialize_inclusion_proof(&proof);
        // After key(32) + has_value(1) byte, count is at offset 33..37
        let count = u32::from_le_bytes(bytes[33..37].try_into().unwrap());
        assert_eq!(count, 1);
    }

    // ── sigma: additional edge cases ──

    #[test]
    fn sigma_single_empty_part_differs_from_no_parts() {
        let s_empty = derive_stitched_receipt_sigma(&[]);
        let s_one_empty = derive_stitched_receipt_sigma(&[b""]);
        assert_ne!(s_empty, s_one_empty);
    }

    #[test]
    fn sigma_large_input() {
        let big = vec![0x42u8; 10_000];
        let s = derive_stitched_receipt_sigma(&[&big]);
        assert_ne!(s, [0u8; 32]);
    }

    // ── encode_protocol_transition_payload: additional ──

    #[test]
    fn encode_protocol_transition_order_matters() {
        let a = encode_protocol_transition_payload(b"L", &[b"X", b"Y"]);
        let b = encode_protocol_transition_payload(b"L", &[b"Y", b"X"]);
        assert_ne!(a, b);
    }

    #[test]
    fn encode_protocol_transition_different_labels_differ() {
        let a = encode_protocol_transition_payload(b"FAUCET", &[b"data"]);
        let b = encode_protocol_transition_payload(b"DLV", &[b"data"]);
        assert_ne!(a, b);
    }

    // ── derive_relationship_key: additional ──

    #[test]
    fn derive_relationship_key_empty_input() {
        let k = derive_relationship_key(&[]);
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn derive_relationship_key_large_input() {
        let big = vec![0xCC; 1024];
        let k = derive_relationship_key(&big);
        assert_ne!(k, [0u8; 32]);
    }

    // ── compute_protocol_transition_commitment ──

    #[test]
    fn protocol_commitment_uses_different_domain_from_sigma() {
        let data = b"same-payload";
        let sigma = derive_stitched_receipt_sigma(&[data.as_slice()]);
        let proto = compute_protocol_transition_commitment(data);
        assert_ne!(sigma, proto);
    }

    // ── encode + commit roundtrip ──

    #[test]
    fn encode_then_commit_deterministic() {
        let payload = encode_protocol_transition_payload(b"TEST", &[b"a", b"b"]);
        let c1 = compute_protocol_transition_commitment(&payload);
        let c2 = compute_protocol_transition_commitment(&payload);
        assert_eq!(c1, c2);
    }

    #[test]
    fn encode_different_payloads_produce_different_commitments() {
        let p1 = encode_protocol_transition_payload(b"A", &[b"x"]);
        let p2 = encode_protocol_transition_payload(b"B", &[b"x"]);
        let c1 = compute_protocol_transition_commitment(&p1);
        let c2 = compute_protocol_transition_commitment(&p2);
        assert_ne!(c1, c2);
    }
}
