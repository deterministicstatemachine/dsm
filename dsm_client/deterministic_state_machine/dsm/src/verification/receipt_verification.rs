// SPDX-License-Identifier: MIT OR Apache-2.0

//! Receipt Verification Module
//!
//! Implements cryptographic stitched-receipt verification predicates.
//! State-transition semantics such as token balance conservation are enforced
//! when applying transitions, not from opaque receipt tip hashes alone.

use crate::common::device_tree::DevTreeProof;
use crate::core::bilateral_transaction_manager::compute_smt_key;
use crate::merkle::sparse_merkle_tree::{verify_smt_replace, SmtInclusionProof};
use crate::types::error::DsmError;
use crate::types::receipt_types::{
    DeviceTreeAcceptanceCommitment, ParentConsumptionTracker, ReceiptAcceptance,
    ReceiptVerificationContext, StitchedReceiptV2,
};

/// Verify a stitched receipt against all acceptance predicates
///
/// Per whitepaper, a receipt is accepted iff:
/// 1. Both SPHINCS+ signatures verify over canonical commit bytes
/// 2. The receipt's state rules hold ([`verify_receipt_state`]): the one
///    relationship path authenticates the parent tip and folds the child tip
///    to `child_root`; the device proof verifies
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

    // Rule 2b: EK-cert-chain ephemeral-key authorization (whitepaper §11.1).
    // Offline receipt acceptance is fail-closed: the sender signature must be
    // made by a per-step EK that is certified by the current AK/EK chain head.
    // Parent/root inclusion proves state consistency; this cert proves live
    // enrolled-device authorization for the proposed transition.
    let Some(chain_head) = &ctx.chain_head_pubkey_a else {
        return Ok(ReceiptAcceptance::reject(
            "Missing chain_head_pubkey_a (EK cert chain required)".to_string(),
        ));
    };
    if receipt.ek_cert_a.is_empty() {
        return Ok(ReceiptAcceptance::reject(
            "Missing ek_cert_a (EK cert chain required)".to_string(),
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
            "Missing chain_head_pubkey_b (EK cert chain required)".to_string(),
        ));
    };
    if receipt.ek_cert_b.is_empty() {
        return Ok(ReceiptAcceptance::reject(
            "Missing ek_cert_b (EK cert chain required)".to_string(),
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

    // Rule 2c: the step starts from the root this verifier expects.
    if receipt.parent_root != ctx.expected_parent_root {
        return Ok(ReceiptAcceptance::reject(
            "the receipt's parent root is not the root this verifier expects".to_string(),
        ));
    }

    // Rules 3–4: the receipt's state — one relationship path authenticates the
    // parent tip and folds the child tip to the claimed post-state root, and
    // the device proof puts the sender under the authenticated Device Tree.
    if let Err(e) = verify_receipt_state(receipt, &ctx.device_tree_commitment) {
        return Ok(ReceiptAcceptance::reject(e.to_string()));
    }

    // Rule 5: Parent uniqueness (Tripwire enforcement)
    if let Err(e) = tracker.try_consume(receipt.parent_tip, receipt.child_tip) {
        return Ok(ReceiptAcceptance::reject(format!(
            "Parent uniqueness: {}",
            e
        )));
    }

    // All checks passed
    Ok(ReceiptAcceptance::accept(commitment))
}

/// The state rules of a receipt, whoever checks it: the sender before it signs,
/// the recipient before it accepts, and [`verify_stitched_receipt`] as its
/// rules 3–4. There is one implementation, over one relationship path.
///
/// - Every fixed field names something: a zero genesis, device, tip, root or
///   transition entropy is not a field of any transition.
/// - The relationship path (`rel_proof_parent`, the tree's own encoding) is at
///   `compute_smt_key(devid_a, devid_b)` and carries `parent_tip`; through
///   [`verify_smt_replace`] it authenticates `parent_tip` under `parent_root`,
///   and the same siblings folded with `child_tip` must be `child_root`.
/// - The device proof puts `devid_a` under the authenticated Device Tree
///   commitment the caller supplies — never one derived from the receipt.
pub fn verify_receipt_state(
    receipt: &StitchedReceiptV2,
    device_tree_commitment: &DeviceTreeAcceptanceCommitment,
) -> Result<(), DsmError> {
    let named = |b: &[u8; 32]| b.iter().any(|&v| v != 0);
    for (field, value) in [
        ("genesis", &receipt.genesis),
        ("devid_a", &receipt.devid_a),
        ("devid_b", &receipt.devid_b),
        ("parent_tip", &receipt.parent_tip),
        ("child_tip", &receipt.child_tip),
        ("parent_root", &receipt.parent_root),
        ("child_root", &receipt.child_root),
        ("transition_entropy", &receipt.transition_entropy),
    ] {
        if !named(value) {
            return Err(DsmError::invalid_operation(format!(
                "receipt field {field} is zero"
            )));
        }
    }

    let smt_key = compute_smt_key(&receipt.devid_a, &receipt.devid_b);
    let path = SmtInclusionProof::from_bytes(&receipt.rel_proof_parent)
        .ok_or_else(|| DsmError::invalid_operation("the relationship path does not decode"))?;
    if path.key != smt_key {
        return Err(DsmError::invalid_operation(
            "the relationship path is not at the relationship key",
        ));
    }
    if path.value != Some(receipt.parent_tip) {
        return Err(DsmError::invalid_operation(
            "the relationship path does not carry the parent tip",
        ));
    }
    let post_root = verify_smt_replace(
        &receipt.parent_root,
        &smt_key,
        &receipt.parent_tip,
        &receipt.child_tip,
        &path.siblings,
    )?;
    if post_root != receipt.child_root {
        return Err(DsmError::invalid_operation(
            "the child tip folded through the relationship path is not the child root",
        ));
    }

    let dev_proof = DevTreeProof::from_bytes(&receipt.dev_proof)
        .ok_or_else(|| DsmError::invalid_operation("the device proof does not decode"))?;
    if !dev_proof.verify(&receipt.devid_a, &device_tree_commitment.root()) {
        return Err(DsmError::invalid_operation(
            "the device proof does not put the sender under the Device Tree commitment",
        ));
    }
    Ok(())
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

/// The side of a stitched receipt: its sender (A) or its receiver (B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BilateralSide {
    /// The sender, which initiates the step.
    A,
    /// The receiver, which counter-signs it.
    B,
}

/// One side's per-step EK artifacts on `receipt` (§11.1) answer the standard
/// session-bound response target of the receipt's commitment. See
/// [`verify_per_step_ek_signing_target`].
pub fn verify_per_step_ek_signing(
    receipt: &StitchedReceiptV2,
    side: BilateralSide,
    expected_prev_pk: &[u8],
    h_n: &[u8; 32],
    session_binding: &[u8; 32],
) -> Result<(), DsmError> {
    let commitment = receipt.compute_commitment()?;
    let signing_target = crate::types::receipt_types::compute_receipt_challenge_response_target(
        &commitment,
        session_binding,
    );
    verify_per_step_ek_signing_target(receipt, side, expected_prev_pk, h_n, &signing_target)
}

/// One side's per-step EK artifacts on `receipt` (§11.1), against an explicit
/// response target:
///
/// 1. `ek_cert_{side}` is `expected_prev_pk`'s signature over
///    `ek_pk_{side} ‖ h_n` — `expected_prev_pk` is the side's AK at the
///    relationship's first step, else its previous EK;
/// 2. `sig_{side}` verifies under `ek_pk_{side}` over `signing_target`.
///
/// Missing artifacts are refused.
pub fn verify_per_step_ek_signing_target(
    receipt: &StitchedReceiptV2,
    side: BilateralSide,
    expected_prev_pk: &[u8],
    h_n: &[u8; 32],
    signing_target: &[u8; 32],
) -> Result<(), DsmError> {
    use crate::crypto::ephemeral_key::verify_ek_cert;
    use crate::crypto::sphincs::sphincs_verify;
    let (ek_pk, ek_cert, sig, label) = match side {
        BilateralSide::A => (&receipt.ek_pk_a, &receipt.ek_cert_a, &receipt.sig_a, "A"),
        BilateralSide::B => (&receipt.ek_pk_b, &receipt.ek_cert_b, &receipt.sig_b, "B"),
    };
    if ek_pk.is_empty() || ek_cert.is_empty() || sig.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "receipt carries no §11.1 per-step EK {label}-side artifacts \
             (ek_pk_{label} / ek_cert_{label} / sig_{label}); rejecting"
        )));
    }
    if expected_prev_pk.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: expected_prev_pk for {label}-side is empty — the \
             caller supplies the AK at the first step or the prior chain-head EK"
        )));
    }
    let cert_ok = verify_ek_cert(expected_prev_pk, ek_pk, h_n, ek_cert).map_err(|e| {
        DsmError::crypto(
            format!("verify_per_step_ek_signing: cert chain verify error ({label}-side): {e}"),
            None::<std::io::Error>,
        )
    })?;
    if !cert_ok {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: ek_cert_{label} does NOT chain ek_pk_{label} \
             back to expected_prev_pk over h_n — sig_{label} cannot be trusted"
        )));
    }
    let sig_ok = sphincs_verify(ek_pk, signing_target, sig).map_err(|e| {
        DsmError::crypto(
            format!("verify_per_step_ek_signing: sig verify error ({label}-side): {e}"),
            None::<std::io::Error>,
        )
    })?;
    if !sig_ok {
        return Err(DsmError::invalid_operation(format!(
            "verify_per_step_ek_signing: sig_{label} does NOT verify under ek_pk_{label} \
             over receipt challenge-response target — check that signer used the same \
             commitment_hash"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let keypair_a = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
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

    /// An unsigned receipt over real material, with the Device Tree
    /// commitment it verifies against: the relationship leaf moves from
    /// `0xaa..` to `0xbb..` in a tree that also keeps another relationship.
    fn real_state_receipt() -> (StitchedReceiptV2, DeviceTreeAcceptanceCommitment) {
        use crate::common::device_tree::DeviceTree;
        use crate::merkle::sparse_merkle_tree::SparseMerkleTree;

        let devid = |label: &[u8]| {
            crate::crypto::blake3::domain_hash_bytes(
                crate::common::domain_tags::TAG_DEVICE_ID,
                label,
            )
        };
        let (devid_a, devid_b) = (devid(b"state-a"), devid(b"state-b"));
        let key = compute_smt_key(&devid_a, &devid_b);
        let mut tree = SparseMerkleTree::new();
        tree.update_leaf(&compute_smt_key(&devid_a, &devid(b"state-c")), &[0x5E; 32]);
        tree.update_leaf(&key, &[0xaa; 32]);
        let replace = tree.smt_replace(&key, &[0xbb; 32]).expect("replace");
        let device_tree = DeviceTree::single(devid_a);
        let mut receipt = StitchedReceiptV2::new(
            [0x0E; 32],
            devid_a,
            devid_b,
            [0xaa; 32],
            [0xbb; 32],
            replace.pre_root,
            replace.post_root,
            replace.parent_proof.to_bytes(),
            device_tree.proof(&devid_a).expect("device path").to_bytes(),
        );
        receipt.set_transition_entropy([0x21; 32]);
        (
            receipt,
            DeviceTreeAcceptanceCommitment::from_root(device_tree.root()),
        )
    }

    /// The state rules hold for a receipt over real material and refuse each
    /// thing that would let a receipt claim a state its one path does not
    /// prove: a post-state root the child does not fold to, a pre-state root
    /// the path does not authenticate the parent under, a changed sibling, a
    /// path at another key or carrying another tip, a zero field, and a
    /// device proof for another device.
    #[test]
    fn the_state_rules_hold_only_for_what_the_one_path_proves() {
        use crate::merkle::sparse_merkle_tree::SmtInclusionProof;

        let (receipt, commitment) = real_state_receipt();
        verify_receipt_state(&receipt, &commitment).expect("a real receipt holds");

        let refused = |mutate: &dyn Fn(&mut StitchedReceiptV2)| {
            let mut r = receipt.clone();
            mutate(&mut r);
            verify_receipt_state(&r, &commitment).is_err()
        };
        fn with_path(r: &mut StitchedReceiptV2, f: impl Fn(&mut SmtInclusionProof)) {
            let mut p = SmtInclusionProof::from_bytes(&r.rel_proof_parent).expect("path");
            f(&mut p);
            r.rel_proof_parent = p.to_bytes();
        }

        assert!(
            refused(&|r| r.child_root[0] ^= 1),
            "a post-state root the child does not fold to"
        );
        assert!(
            refused(&|r| r.parent_root[0] ^= 1),
            "a pre-state root the path does not authenticate"
        );
        assert!(
            refused(&|r| with_path(r, |p| p.siblings[200][3] ^= 1)),
            "a changed sibling"
        );
        assert!(
            refused(&|r| with_path(r, |p| p.key[0] ^= 1)),
            "a path at another key"
        );
        assert!(
            refused(&|r| with_path(r, |p| p.value = Some([0xab; 32]))),
            "a path carrying another tip"
        );
        assert!(
            refused(&|r| with_path(r, |p| {
                p.siblings.pop();
            })),
            "a path of another height"
        );
        assert!(refused(&|r| r.transition_entropy = [0; 32]), "a zero field");
        assert!(
            refused(&|r| r.devid_a[0] ^= 1),
            "a device proof for another device"
        );
    }

    /// A receipt over real material — a real per-device tree, the device's
    /// own Device Tree path, both signatures and EK certs — with the context
    /// a verifier expecting its step would hold.
    fn signed_receipt_and_context() -> (StitchedReceiptV2, ReceiptVerificationContext) {
        use crate::common::device_tree::DeviceTree;
        use crate::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};
        use crate::merkle::sparse_merkle_tree::SparseMerkleTree;

        let keypair_a = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
        let devid_a = crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DEVICE_ID,
            b"uniqueness-a",
        );
        let devid_b = crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DEVICE_ID,
            b"uniqueness-b",
        );
        let parent_tip = [0xaa; 32];
        let child_tip = [0xbb; 32];

        let key = compute_smt_key(&devid_a, &devid_b);
        let mut tree = SparseMerkleTree::new();
        tree.update_leaf(&key, &parent_tip);
        let replace = tree.smt_replace(&key, &child_tip).expect("replace");
        let device_tree = DeviceTree::single(devid_a);
        let dev_proof = device_tree.proof(&devid_a).expect("device path").to_bytes();

        let mut receipt = StitchedReceiptV2::new(
            [0x0E; 32],
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            replace.pre_root,
            replace.post_root,
            replace.parent_proof.to_bytes(),
            dev_proof,
        );
        receipt.set_transition_entropy([0x21; 32]);
        let commitment = receipt.compute_commitment().unwrap();
        receipt.add_sig_a(keypair_a.sign(&commitment).unwrap());
        receipt.add_sig_b(keypair_b.sign(&commitment).unwrap());
        let (chain_head_pk, chain_head_sk) = generate_ephemeral_keypair(&[0xA5; 32]).unwrap();
        let (chain_head_b_pk, chain_head_b_sk) = generate_ephemeral_keypair(&[0xB5; 32]).unwrap();
        receipt.set_ek_cert_a(
            sign_ek_cert(&chain_head_sk, keypair_a.public_key(), &parent_tip).unwrap(),
        );
        receipt.set_ek_cert_b(
            sign_ek_cert(&chain_head_b_sk, keypair_b.public_key(), &parent_tip).unwrap(),
        );

        let ctx = ReceiptVerificationContext::new(
            DeviceTreeAcceptanceCommitment::from_root(device_tree.root()),
            replace.pre_root,
            keypair_a.public_key().to_vec(),
            keypair_b.public_key().to_vec(),
        )
        .with_chain_head_a(chain_head_pk)
        .with_chain_head_b(chain_head_b_pk);
        (receipt, ctx)
    }

    /// The real receipt is accepted on a fresh parent; once that parent is
    /// consumed the same receipt is refused for parent uniqueness, and for
    /// nothing else.
    #[test]
    fn test_parent_uniqueness_enforcement() {
        let (receipt, ctx) = signed_receipt_and_context();
        let accepted =
            verify_stitched_receipt(&receipt, &ctx, &mut ParentConsumptionTracker::new()).unwrap();
        assert!(accepted.valid, "{:?}", accepted.reason);

        let mut tracker = ParentConsumptionTracker::new();
        tracker.try_consume(receipt.parent_tip, [0xcc; 32]).unwrap();
        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();
        assert!(!result.valid);
        let reason = result.reason.unwrap_or_default();
        assert!(reason.contains("Parent uniqueness"), "got: {reason}");
    }

    /// A verifier that expects the step to start from one root refuses a
    /// receipt — fully signed, its path authentic — over any other root:
    /// that receipt is a different step.
    #[test]
    fn a_receipt_over_a_root_the_verifier_does_not_expect_is_refused() {
        let (receipt, ctx) = signed_receipt_and_context();
        let accepted =
            verify_stitched_receipt(&receipt, &ctx, &mut ParentConsumptionTracker::new()).unwrap();
        assert!(accepted.valid, "{:?}", accepted.reason);

        let mut elsewhere = ctx;
        elsewhere.expected_parent_root = receipt.child_root;
        let mut tracker = ParentConsumptionTracker::new();
        let refused = verify_stitched_receipt(&receipt, &elsewhere, &mut tracker).unwrap();
        assert!(!refused.valid);
        let reason = refused.reason.unwrap_or_default();
        assert!(
            reason.contains("is not the root this verifier expects"),
            "got: {reason}"
        );
        assert!(
            tracker
                .try_consume(receipt.parent_tip, receipt.child_tip)
                .is_ok(),
            "a refused receipt consumes no parent"
        );
    }

    /// Whitepaper §11.1: when a chain head is set on the verification context,
    /// the receipt MUST carry a valid `ek_cert_a`. A missing cert must be
    /// rejected with a specific error — otherwise an attacker could strip the
    /// cert and bypass AK-rooted authorization for the per-step EK.
    #[test]
    fn test_missing_ek_cert_a_rejected_when_chain_head_set() {
        use crate::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};

        // Build a receipt with valid signatures but no ek_cert_a.
        let keypair_a = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
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

        let keypair_a = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
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
    /// also verify the per-step EK cert chain.
    #[test]
    fn test_no_chain_head_rejects_receipt_authorization() {
        // Reuse the parent_uniqueness test setup but without consuming the parent.
        use crate::crypto::ephemeral_key::{generate_ephemeral_keypair, sign_ek_cert};

        let keypair_a = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
        let keypair_b = crate::crypto::signatures::SignatureKeyPair::new().expect("keygen");
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
            reason.contains("chain_head_pubkey_a") || reason.contains("EK cert chain"),
            "wrong rejection reason: {}",
            reason
        );
    }
}
