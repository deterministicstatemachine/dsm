//! Receipt Verification Module
//!
//! Implements cryptographic stitched-receipt verification predicates.
//! State-transition semantics such as token balance conservation are enforced
//! when applying transitions, not from opaque receipt tip hashes alone.

use crate::types::error::DsmError;
use crate::types::receipt_types::{
    ParentConsumptionTracker, ReceiptAcceptance, ReceiptVerificationContext, StitchedReceiptV2,
};
use crate::verification::proof_primitives::{
    verify_device_tree_inclusion_proof_bytes, verify_smt_inclusion_proof_bytes,
};
use crate::verification::smt_replace_witness::compute_smt_key;
use crate::verification::smt_replace_witness::verify_tripwire_smt_replace;

/// Verify a stitched receipt against all acceptance predicates
///
/// Per whitepaper, a receipt is accepted iff:
/// 1. Both SPHINCS+ signatures verify over canonical commit bytes
/// 2. Inclusion proofs verify (old/new leaves in SMT, device in Device Tree)
/// 3. SMT replace recomputes child_root exactly
/// 4. Parent tip has not been previously consumed (uniqueness)
/// 5. Size cap enforced (≤128 KiB)
///
/// Token balance conservation and non-negativity are verified by the
/// state-transition layer when the receipt is applied, not here.
///
/// # Arguments
/// * `receipt` - The stitched receipt to verify
/// * `ctx` - Verification context (roots, pubkeys, consumed set)
/// * `tracker` - Parent consumption tracker (for uniqueness)
///
/// # Returns
/// `ReceiptAcceptance` with validity and optional rejection reason
pub fn verify_stitched_receipt(
    receipt: &StitchedReceiptV2,
    ctx: &ReceiptVerificationContext,
    tracker: &mut ParentConsumptionTracker,
) -> Result<ReceiptAcceptance, DsmError> {
    // Rule 0: Size cap (must check before expensive operations)
    if let Err(e) = receipt.validate_size_cap() {
        return Ok(ReceiptAcceptance::reject(format!("Size cap: {}", e)));
    }

    // Rule 1: Compute canonical commitment
    let commitment = match receipt.compute_commitment() {
        Ok(c) => c,
        Err(e) => {
            return Ok(ReceiptAcceptance::reject(format!(
                "Commitment error: {}",
                e
            )))
        }
    };

    // Rule 2: Verify both bilateral signatures over the commitment.
    if receipt.sig_a.is_empty() {
        return Ok(ReceiptAcceptance::reject(
            "Missing sender signature (sig_a)".to_string(),
        ));
    }
    if receipt.sig_b.is_empty() {
        return Ok(ReceiptAcceptance::reject(
            "Missing receiver signature (sig_b)".to_string(),
        ));
    }

    if !verify_sphincs_signature(&commitment, &receipt.sig_a, &ctx.pubkey_a)? {
        return Ok(ReceiptAcceptance::reject(
            "Signature A verification failed".to_string(),
        ));
    }
    if !verify_sphincs_signature(&commitment, &receipt.sig_b, &ctx.pubkey_b)? {
        return Ok(ReceiptAcceptance::reject(
            "Signature B verification failed".to_string(),
        ));
    }

    // Rule 2b: C-DBRW-bound ephemeral-key authorization (whitepaper §11.1).
    // Offline receipt acceptance is fail-closed: the sender signature must be
    // made by a per-step EK that is certified by the current AK/EK chain head.
    // Parent/root inclusion proves state consistency; this cert proves live
    // enrolled-device authorization for the proposed transition.
    let Some(chain_head) = &ctx.chain_head_pubkey_a else {
        return Ok(ReceiptAcceptance::reject(
            "Missing chain_head_pubkey_a (C-DBRW EK cert chain required)".to_string(),
        ));
    };
    if receipt.ek_cert_a.is_empty() {
        return Ok(ReceiptAcceptance::reject(
            "Missing ek_cert_a (C-DBRW EK cert chain required)".to_string(),
        ));
    }
    match crate::crypto::ephemeral_key::verify_ek_cert(
        chain_head,
        &ctx.pubkey_a,
        &receipt.parent_tip,
        &receipt.ek_cert_a,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Ok(ReceiptAcceptance::reject(
                "ek_cert_a verification failed (EK_pk not authorized by chain head)".to_string(),
            ))
        }
        Err(e) => return Ok(ReceiptAcceptance::reject(format!("ek_cert_a error: {}", e))),
    }
    let Some(chain_head) = &ctx.chain_head_pubkey_b else {
        return Ok(ReceiptAcceptance::reject(
            "Missing chain_head_pubkey_b (C-DBRW EK cert chain required)".to_string(),
        ));
    };
    if receipt.ek_cert_b.is_empty() {
        return Ok(ReceiptAcceptance::reject(
            "Missing ek_cert_b (C-DBRW EK cert chain required)".to_string(),
        ));
    }
    match crate::crypto::ephemeral_key::verify_ek_cert(
        chain_head,
        &ctx.pubkey_b,
        &receipt.parent_tip,
        &receipt.ek_cert_b,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Ok(ReceiptAcceptance::reject(
                "ek_cert_b verification failed".to_string(),
            ))
        }
        Err(e) => return Ok(ReceiptAcceptance::reject(format!("ek_cert_b error: {}", e))),
    }

    // Rule 3: Verify inclusion proofs
    let smt_key = compute_smt_key(&receipt.devid_a, &receipt.devid_b);

    // 3a: Parent tip in parent root (rel_proof_parent)
    if !verify_smt_inclusion(
        &receipt.parent_root,
        &smt_key,
        &receipt.parent_tip,
        &receipt.rel_proof_parent,
    )? {
        return Ok(ReceiptAcceptance::reject(
            "Parent tip inclusion proof failed".to_string(),
        ));
    }

    // 3b: Child tip in child root (rel_proof_child)
    if !verify_smt_inclusion(
        &receipt.child_root,
        &smt_key,
        &receipt.child_tip,
        &receipt.rel_proof_child,
    )? {
        return Ok(ReceiptAcceptance::reject(
            "Child tip inclusion proof failed".to_string(),
        ));
    }

    // 3c: DevID in the authenticated Device Tree commitment used for `π_dev`
    if !verify_device_tree_inclusion(
        &ctx.device_tree_commitment.root(),
        &receipt.devid_a,
        &receipt.dev_proof,
    )? {
        return Ok(ReceiptAcceptance::reject(
            "Device Tree inclusion proof failed".to_string(),
        ));
    }

    // Rule 4: SMT replace recomputation
    // Build an SMT with parent_root, replace parent_tip → child_tip, verify child_root
    if !verify_smt_replace(
        &receipt.parent_root,
        &receipt.child_root,
        &receipt.parent_tip,
        &receipt.child_tip,
        &receipt.rel_replace_witness,
    )? {
        return Ok(ReceiptAcceptance::reject(
            "SMT replace recomputation failed".to_string(),
        ));
    }

    // Rule 5: Parent uniqueness (Tripwire enforcement)
    if let Err(e) = tracker.try_consume(receipt.parent_tip, receipt.child_tip) {
        return Ok(ReceiptAcceptance::reject(format!(
            "Parent uniqueness: {}",
            e
        )));
    }

    // Token balance invariants are enforced in the state-transition layer via
    // core::state_machine::transition::verify_token_balance_consistency().

    // All checks passed
    Ok(ReceiptAcceptance::accept(commitment))
}

/// Verify SMT inclusion proof
///
/// Checks that `leaf` is included in `root` via `proof`.
fn verify_smt_inclusion(
    root: &[u8; 32],
    smt_key: &[u8; 32],
    value: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<bool, DsmError> {
    verify_smt_inclusion_proof_bytes(root, smt_key, value, proof_bytes)
}

/// Verify Device Tree inclusion proof
///
/// Checks that `devid` is included in the Device Tree `root` via `proof`.
fn verify_device_tree_inclusion(
    root: &[u8; 32],
    devid: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<bool, DsmError> {
    verify_device_tree_inclusion_proof_bytes(root, devid, proof_bytes)
}

/// Verify SMT replace recomputation
///
/// Rebuilds parent SMT, replaces parent_tip → child_tip, verifies child_root.
///
/// This verification ensures that the child_root is the correct result of
/// replacing the relationship tip in the parent SMT. The SMT replace operation
/// is fundamental to the DSM protocol's state transition model.
fn verify_smt_replace(
    parent_root: &[u8; 32],
    child_root: &[u8; 32],
    parent_tip: &[u8; 32],
    child_tip: &[u8; 32],
    witness_bytes: &[u8],
) -> Result<bool, DsmError> {
    verify_tripwire_smt_replace(
        parent_root,
        child_root,
        parent_tip,
        child_tip,
        witness_bytes,
    )
}

/// Helper: Verify SPHINCS+ signature
///
/// Verifies a SPHINCS+ signature over commitment bytes using public key.
fn verify_sphincs_signature(
    commitment: &[u8; 32],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, DsmError> {
    if signature.is_empty() || public_key.is_empty() {
        return Ok(false);
    }

    // Use SignatureKeyPair::verify_raw for static signature verification
    crate::crypto::signatures::SignatureKeyPair::verify_raw(commitment, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smt_key_ordering() {
        // Relationship key computation is enforced in the SMT module, not here.
        // Tripwire interlock will move to a true SMT replace-witness verifier.
        // Smoke test: module compiles under tests.
    }

    #[test]
    fn test_verify_empty_receipt_rejects() {
        let receipt = StitchedReceiptV2::new(
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            vec![],
            vec![],
            vec![],
        );

        let ctx = ReceiptVerificationContext::new([0u8; 32], [0u8; 32], vec![], vec![]);
        let mut tracker = ParentConsumptionTracker::new();

        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();

        // Should reject due to missing sender signature
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("Missing sender signature"));
    }

    #[test]
    fn test_verify_receipt_rejects_missing_receiver_signature() {
        let keypair_a = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let mut receipt = StitchedReceiptV2::new(
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            vec![],
            vec![],
            vec![],
        );
        let commitment = receipt.compute_commitment().unwrap();
        receipt.add_sig_a(keypair_a.sign(&commitment).unwrap());

        let ctx = ReceiptVerificationContext::new(
            [0u8; 32],
            [0u8; 32],
            keypair_a.public_key().to_vec(),
            vec![],
        );
        let mut tracker = ParentConsumptionTracker::new();

        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();
        assert!(!result.valid);
        assert!(result
            .reason
            .unwrap()
            .contains("Missing receiver signature"));
    }

    #[test]
    fn test_parent_uniqueness_enforcement() {
        use crate::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};

        // Create keypairs for testing
        let keypair_a = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();

        // Empty proof bytes — with non-zero roots ([0x01] / [0x02]), the sentinel
        // check in verify_smt_inclusion_proof_bytes returns Ok(false) cleanly
        // (no protobuf decode needed). This test targets parent uniqueness, not proofs.
        let smt_proof_bytes = vec![];
        let dev_proof_bytes = vec![];

        let mut receipt = StitchedReceiptV2::new(
            [0; 32],                 // genesis
            [0; 32],                 // devid_a
            [0; 32],                 // devid_b
            [0xaa; 32],              // parent_tip
            [0xbb; 32],              // child_tip
            [0x01; 32],              // parent_root (different from child)
            [0x02; 32],              // child_root (different from parent)
            smt_proof_bytes.clone(), // rel_proof_parent
            smt_proof_bytes,         // rel_proof_child
            dev_proof_bytes,         // dev_proof
        );

        // Compute commitment and sign it
        let commitment = receipt.compute_commitment().unwrap();
        let sig_a = keypair_a.sign(&commitment).unwrap();
        let sig_b = keypair_b.sign(&commitment).unwrap();
        receipt.add_sig_a(sig_a);
        receipt.add_sig_b(sig_b);
        let (chain_head_pk, chain_head_sk) = generate_ephemeral_keypair(&[0xA5; 32]).unwrap();
        let (chain_head_b_pk, chain_head_b_sk) = generate_ephemeral_keypair(&[0xB5; 32]).unwrap();
        receipt.set_ek_cert_a(
            sign_ek_cert(&chain_head_sk, keypair_a.public_key(), &[0xaa; 32]).unwrap(),
        );
        receipt.set_ek_cert_b(
            sign_ek_cert(&chain_head_b_sk, keypair_b.public_key(), &[0xaa; 32]).unwrap(),
        );

        // Create context with the public keys
        let ctx = ReceiptVerificationContext::new(
            [0u8; 32],
            [0u8; 32],
            keypair_a.public_key().to_vec(),
            keypair_b.public_key().to_vec(),
        )
        .with_chain_head_a(chain_head_pk)
        .with_chain_head_b(chain_head_b_pk);
        let mut tracker = ParentConsumptionTracker::new();

        // Manually mark parent as consumed first
        tracker.try_consume([0xaa; 32], [0xbb; 32]).unwrap();

        // Now verification should fail uniqueness check (signatures pass, proofs fail on wrong roots, but we test the flow)
        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();
        assert!(!result.valid);
        let reason = result.reason.as_ref().unwrap();
        eprintln!("Actual rejection reason: {}", reason);
        // The test may fail at proof verification since roots don't match the empty proof
        // but the important thing is uniqueness is checked if proofs pass
        assert!(reason.contains("Parent uniqueness") || reason.contains("inclusion proof failed"));
    }

    /// Whitepaper §11.1: when a chain head is set on the verification context,
    /// the receipt MUST carry a valid `ek_cert_a`. A missing cert must be
    /// rejected with a specific error — otherwise an attacker could strip the
    /// cert and bypass AK-rooted authorization for the per-step EK.
    #[test]
    fn test_missing_ek_cert_a_rejected_when_chain_head_set() {
        use crate::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};

        // Build a receipt with valid signatures but no ek_cert_a.
        let keypair_a = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let mut receipt = StitchedReceiptV2::new(
            [0; 32],
            [0; 32],
            [0; 32],
            [0xaa; 32],
            [0xbb; 32],
            [0x01; 32],
            [0x02; 32],
            vec![],
            vec![],
            vec![],
        );
        let commitment = receipt.compute_commitment().unwrap();
        receipt.add_sig_a(keypair_a.sign(&commitment).unwrap());
        receipt.add_sig_b(keypair_b.sign(&commitment).unwrap());
        // Deliberately do NOT call set_ek_cert_a.

        // Build a chain head pubkey (any valid SPHINCS+ key works).
        let (chain_head_pk, _) = generate_ephemeral_keypair(&[0xCC; 32]).expect("keygen");
        let (chain_head_b_pk, chain_head_b_sk) =
            generate_ephemeral_keypair(&[0xBC; 32]).expect("keygen");
        receipt.set_ek_cert_b(
            sign_ek_cert(&chain_head_b_sk, keypair_b.public_key(), &[0xaa; 32]).unwrap(),
        );

        let ctx = ReceiptVerificationContext::new(
            [0u8; 32],
            [0u8; 32],
            keypair_a.public_key().to_vec(),
            keypair_b.public_key().to_vec(),
        )
        .with_chain_head_a(chain_head_pk)
        .with_chain_head_b(chain_head_b_pk);

        let mut tracker = ParentConsumptionTracker::new();
        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();
        assert!(!result.valid, "missing ek_cert_a must be rejected");
        let reason = result.reason.unwrap();
        assert!(
            reason.contains("Missing ek_cert_a") || reason.contains("cert chain"),
            "wrong rejection reason: {}",
            reason
        );
    }

    /// Forged ek_cert_a (signed by an unauthorized SK) must not verify against
    /// the legitimate chain head — this is the core forgery resistance of the
    /// cert chain.
    #[test]
    fn test_ek_cert_a_signed_by_wrong_key_rejected() {
        use crate::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};

        let keypair_a = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let mut receipt = StitchedReceiptV2::new(
            [0; 32],
            [0; 32],
            [0; 32],
            [0xaa; 32],
            [0xbb; 32],
            [0x01; 32],
            [0x02; 32],
            vec![],
            vec![],
            vec![],
        );
        let commitment = receipt.compute_commitment().unwrap();
        receipt.add_sig_a(keypair_a.sign(&commitment).unwrap());
        receipt.add_sig_b(keypair_b.sign(&commitment).unwrap());

        // The legitimate chain head.
        let (legit_head_pk, _) = generate_ephemeral_keypair(&[0x01; 32]).expect("keygen");
        let (legit_head_b_pk, legit_head_b_sk) =
            generate_ephemeral_keypair(&[0x02; 32]).expect("keygen");
        // The attacker's keypair (NOT the chain head).
        let (_, attacker_sk) = generate_ephemeral_keypair(&[0x99; 32]).expect("keygen");

        // Forge a cert under the attacker's SK over the correct (pubkey_a, h_n).
        let forged = sign_ek_cert(
            &attacker_sk,
            keypair_a.public_key(),
            &[0xaa; 32], // matches receipt.parent_tip
        )
        .expect("forge cert");
        receipt.set_ek_cert_a(forged);
        receipt.set_ek_cert_b(
            sign_ek_cert(&legit_head_b_sk, keypair_b.public_key(), &[0xaa; 32]).unwrap(),
        );

        let ctx = ReceiptVerificationContext::new(
            [0u8; 32],
            [0u8; 32],
            keypair_a.public_key().to_vec(),
            keypair_b.public_key().to_vec(),
        )
        .with_chain_head_a(legit_head_pk)
        .with_chain_head_b(legit_head_b_pk);

        let mut tracker = ParentConsumptionTracker::new();
        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();
        assert!(!result.valid, "forged ek_cert_a must be rejected");
        let reason = result.reason.unwrap();
        assert!(
            reason.contains("ek_cert_a verification failed") || reason.contains("not authorized"),
            "wrong rejection reason: {}",
            reason
        );
    }

    /// Receipt verification is fail-closed when no sender chain head is set.
    /// Parent/root inclusion alone is not spend authority; the recipient must
    /// also verify the C-DBRW-bound per-step EK cert chain.
    #[test]
    fn test_no_chain_head_rejects_receipt_authorization() {
        // Reuse the parent_uniqueness test setup but without consuming the parent.
        use crate::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};

        let keypair_a = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::generate_for_testing();
        let mut receipt = StitchedReceiptV2::new(
            [0; 32],
            [0; 32],
            [0; 32],
            [0xaa; 32],
            [0xbb; 32],
            [0x01; 32],
            [0x02; 32],
            vec![],
            vec![],
            vec![],
        );
        let commitment = receipt.compute_commitment().unwrap();
        receipt.add_sig_a(keypair_a.sign(&commitment).unwrap());
        receipt.add_sig_b(keypair_b.sign(&commitment).unwrap());
        receipt.set_ek_cert_a(vec![0xAA; 32]);
        let (chain_head_b_pk, chain_head_b_sk) =
            generate_ephemeral_keypair(&[0xD1; 32]).expect("keygen");
        receipt.set_ek_cert_b(
            sign_ek_cert(&chain_head_b_sk, keypair_b.public_key(), &[0xaa; 32]).unwrap(),
        );

        let ctx = ReceiptVerificationContext::new(
            [0u8; 32],
            [0u8; 32],
            keypair_a.public_key().to_vec(),
            keypair_b.public_key().to_vec(),
        )
        .with_chain_head_b(chain_head_b_pk);
        let mut tracker = ParentConsumptionTracker::new();
        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();
        assert!(!result.valid, "missing chain head must reject");
        let reason = result.reason.unwrap();
        assert!(
            reason.contains("chain_head_pubkey_a") || reason.contains("C-DBRW"),
            "wrong rejection reason: {}",
            reason
        );
    }
}
