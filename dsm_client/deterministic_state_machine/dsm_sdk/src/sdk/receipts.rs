//! # Receipt Primitives for Offline Bilateral Flows
//!
//! Re-exports canonical receipt types and verification from `dsm::core`,
//! adding SDK-level helpers for relationship key derivation and monotonic
//! counter checking on stitched receipts.

use dsm::types::error::DsmError;

// Re-export canonical types from dsm core
pub use dsm::types::receipt_types::{
    ParentConsumptionTracker as ReceiptGuard, ReceiptAcceptance, ReceiptVerificationContext,
    StitchedReceiptV2,
};

/// Derive relationship key from counterparty public key.
/// Domain-separated to prevent collision with other hash contexts.
pub fn derive_relationship_key(counterparty_pk: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes("DSM/relationship-key", counterparty_pk)
}

/// Verify a stitched receipt with signatures
/// Wrapper around the canonical verification that adds monotonic counter checking
#[allow(clippy::too_many_arguments)]
pub fn verify_stitched_receipt(
    receipt: &StitchedReceiptV2,
    sig_a: &[u8],
    sig_b: &[u8],
    pk_a: &[u8],
    pk_b: &[u8],
    t_local: u64,
    guard: Option<&mut ReceiptGuard>,
) -> Result<(), DsmError> {
    // Monotonic counter check (application-level logic)
    // Note: The receipt's child_tip encodes the sequence number
    // For bilateral flows, we extract and verify monotonic progression
    // This prevents replay attacks at the application layer
    let receipt_seq = extract_sequence_from_tip(&receipt.child_tip);
    if receipt_seq <= t_local {
        return Err(DsmError::invalid_operation(
            "Non-incrementing receipt counter",
        ));
    }

    // Create verification context
    let ctx = ReceiptVerificationContext::new(
        receipt.genesis,
        [0; 32], // device_tree_root - would be provided by state
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

/// Extract sequence number from tip hash
/// In practice, tips encode transaction data including sequence numbers
/// For now, we use a simple extraction (would be replaced with proper decoding)
fn extract_sequence_from_tip(tip: &[u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&tip[0..8]);
    u64::from_le_bytes(bytes)
}

/// Build a complete `StitchedReceiptV2` struct with real cryptographic material.
///
/// **This is the SINGLE authoritative receipt constructor for the entire SDK.**
/// All receipt construction — bilateral, unilateral, faucet, BLE, online —
/// MUST go through this function. It computes:
/// - Real genesis hash from `AppState`
/// - Real parent/child SMT roots via `hash_smt_leaf()`
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
    device_tree_root: Option<[u8; 32]>,
) -> Option<StitchedReceiptV2> {
    use dsm::common::device_tree;
    use dsm::verification::smt_replace_witness::{
        compute_relationship_key, hash_smt_leaf, verify_tripwire_smt_replace,
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

    // 2. Compute SMT roots from relationship key + tips.
    let rel_key = compute_relationship_key(&devid_a, &devid_b);
    let parent_root = hash_smt_leaf(&rel_key, &parent_tip);
    let child_root = hash_smt_leaf(&rel_key, &child_tip);

    // 3. Build parseable relation proofs in BoundedInclusionProof format
    //    (zero-depth SMT: rel_key is the key, tip is the value, no siblings).
    let rel_proof_parent =
        serialize_inclusion_proof(&crate::security::bounded_smt::BoundedInclusionProof {
            key: rel_key,
            value: Some(parent_tip),
            siblings: Vec::new(),
        });
    let rel_proof_child =
        serialize_inclusion_proof(&crate::security::bounded_smt::BoundedInclusionProof {
            key: rel_key,
            value: Some(child_tip),
            siblings: Vec::new(),
        });

    // 4. Build device tree proof via DeviceTree builder (§2.3).
    //    R_G MUST be supplied explicitly by the caller.
    let r_g = match device_tree_root {
        Some(root) => root,
        None => {
            log::error!(
                "[receipts] build_receipt_struct: device_tree_root is required; refusing to derive a synthetic R_G"
            );
            return None;
        }
    };
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

    if !verify_tripwire_smt_replace(
        &parent_root,
        &child_root,
        &parent_tip,
        &child_tip,
        &devid_a,
        &devid_b,
        &witness,
    )
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
    device_tree_root: Option<[u8; 32]>,
) -> Option<Vec<u8>> {
    build_receipt_struct(devid_a, devid_b, parent_tip, child_tip, device_tree_root)?
        .to_canonical_protobuf()
        .ok()
}

/// Build receipt with **real** Per-Device SMT roots and inclusion proofs (§4.2).
///
/// Unlike `build_bilateral_receipt()` which computes single-leaf stub proofs,
/// this function accepts the actual SMT roots and serialized inclusion proofs
/// produced by `BoundedSmt` after an `update_leaf()` call. Use this when the
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
    device_tree_root: Option<[u8; 32]>,
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
    //    R_G MUST be supplied explicitly by the caller.
    let r_g = match device_tree_root {
        Some(root) => root,
        None => {
            log::error!(
                "[receipts] build_bilateral_receipt_with_smt: device_tree_root is required; refusing to derive a synthetic R_G"
            );
            return None;
        }
    };
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
///    (BoundedInclusionProof deserialization + root reconstruction)
/// 4. §4.3#4: Leaf-replace recomputation — replacing h_n with h_{n+1} using
///    the same sibling path must yield r'_A byte-exactly
/// 5. §4.3#3: π_dev proves DevID_A ∈ R_G (Device Tree inclusion)
///
/// `device_tree_root`: explicit R_G for sender. `None` is rejected.
/// Returns `true` only if all checks pass.
pub fn verify_receipt_bytes(receipt_bytes: &[u8], device_tree_root: Option<[u8; 32]>) -> bool {
    use crate::security::bounded_smt::{BoundedInclusionProof, BoundedSmt};
    use dsm::common::device_tree;
    use dsm::verification::smt_replace_witness::compute_relationship_key;

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
    let rel_key = compute_relationship_key(&receipt.devid_a, &receipt.devid_b);

    let parent_proof = deserialize_inclusion_proof(&receipt.rel_proof_parent).ok();
    let child_proof = match deserialize_inclusion_proof(&receipt.rel_proof_child) {
        Ok(p) => p,
        Err(_) => return false, // child proof must always exist (post-update)
    };

    // §4.3#2: π'_rel proves h_{n+1} ∈ r'_A
    if child_proof.key != rel_key {
        return false;
    }
    if child_proof.value != Some(receipt.child_tip) {
        return false;
    }
    if !BoundedSmt::verify_proof_against_root(&child_proof, &receipt.child_root) {
        return false;
    }

    if let Some(pp) = parent_proof {
        // Full verification: parent proof exists.
        if pp.key != rel_key {
            return false;
        }
        if pp.value != Some(receipt.parent_tip) {
            return false;
        }

        // §4.3#2: π_rel proves h_n ∈ r_A
        if !BoundedSmt::verify_proof_against_root(&pp, &receipt.parent_root) {
            return false;
        }

        // §4.3#4: Leaf-replace recomputation.
        // Single leaf change ⇒ sibling path is identical.
        // Replace h_n with h_{n+1} using parent's siblings → must yield r'_A.
        let replace_proof = BoundedInclusionProof {
            key: rel_key,
            value: Some(receipt.child_tip),
            siblings: pp.siblings,
        };
        if !BoundedSmt::verify_proof_against_root(&replace_proof, &receipt.child_root) {
            return false;
        }
    }
    // If parent proof absent: first tx for this relationship (leaf was ZERO_LEAF).
    // Child proof already verified above.

    // 5. §4.3#3: Device proof must parse and verify against R_G.
    //    R_G MUST be supplied by the caller from a trusted external source (§2.3 commit path).
    //    If None, reject: acceptance predicates must never derive R_G from the receipt itself.
    let r_g = match device_tree_root {
        Some(root) => root,
        None => {
            log::error!(
                "[receipts] §4.3#3 FATAL: device_tree_root not provided — \
                 R_G must be externally supplied, never derived from the receipt itself."
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

/// Serialize a `BoundedInclusionProof` to bytes for wire transport.
///
/// Format: [32-byte key][1-byte has_value][optional 32-byte value][4-byte LE sibling count][32-byte siblings...]
pub fn serialize_inclusion_proof(
    proof: &crate::security::bounded_smt::BoundedInclusionProof,
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

/// Deserialize a `BoundedInclusionProof` from bytes.
pub fn deserialize_inclusion_proof(
    data: &[u8],
) -> Result<crate::security::bounded_smt::BoundedInclusionProof, DsmError> {
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
    let count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
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
    Ok(crate::security::bounded_smt::BoundedInclusionProof {
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
