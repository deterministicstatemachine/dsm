// SPDX-License-Identifier: MIT OR Apache-2.0

//! Receipt Verification Module
//!
//! Implements cryptographic stitched-receipt verification predicates.
//! State-transition semantics such as token balance conservation are enforced
//! when applying transitions, not from opaque receipt tip hashes alone.

use crate::common::device_tree::DevTreeProof;
use crate::core::bilateral_transaction_manager::{
    anchor_state_leaf_key, compute_smt_key, operation_requires_offline_bearer,
};
use crate::merkle::batch_fold::{verify_batch, FoldEntry};
use crate::merkle::smt_path;
use crate::merkle::sparse_merkle_tree::DeviceSmtHashes;
use crate::types::device_state::relationship_chain_tip_v2;
use crate::types::error::DsmError;
use crate::types::offline_allocation_leaf::{offline_allocation_key, offline_allocation_value};
use crate::types::operations::Operation;
use crate::types::receipt_types::{
    DeviceTreeAcceptanceCommitment, ParentConsumptionTracker, ReceiptAcceptance, ReceiptLeaf,
    ReceiptVerificationContext, StitchedReceiptV2,
};

/// Verify a stitched receipt against all acceptance predicates
///
/// Per whitepaper, a receipt is accepted iff:
/// 1. Both SPHINCS+ signatures verify over canonical commit bytes
/// 2. The receipt's state rules hold ([`verify_receipt_state`]): the step's
///    writes are exactly the ones its operation implies, and they fold from
///    `parent_root` to `child_root`; the device proof verifies
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

    // Rules 3–4: the receipt's state — the step's writes are the ones its
    // operation implies and fold from the pre-state root to the post-state
    // root, and the device proof puts the sender under the authenticated
    // Device Tree.
    let state = ReceiptStateContext {
        device_tree_commitment: &ctx.device_tree_commitment,
        author_genesis: ctx.author_genesis,
        operation: &ctx.operation,
        bearer: ctx.bearer,
    };
    if let Err(e) = verify_receipt_state(receipt, &state) {
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

/// The anchor-state leaf of the author's own offline-bearer spend, before and
/// after, as the verifier derived them under the pinned bundle from the
/// release's signed counter pair and frontiers — never read from the receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BearerLeaves {
    /// The author's pinned anchor bundle `B`.
    pub bundle: [u8; 32],
    /// `anchor_state_leaf(B, h_i, u_i)`.
    pub anchor_before: [u8; 32],
    /// `anchor_state_leaf(B, h_{i+1}, u_i+1)`.
    pub anchor_after: [u8; 32],
}

/// What a verifier holds, independently of the receipt, to derive every leaf
/// the receipt's step writes.
#[derive(Clone, Copy, Debug)]
pub struct ReceiptStateContext<'a> {
    /// The authenticated Device Tree commitment the author's device proof is
    /// checked against — never one derived from the receipt.
    pub device_tree_commitment: &'a DeviceTreeAcceptanceCommitment,
    /// The genesis the receipt's author (`devid_a`) is pinned under.
    pub author_genesis: [u8; 32],
    /// The operation the step carries.
    pub operation: &'a Operation,
    /// Present exactly for the author's own offline-bearer spend.
    pub bearer: Option<BearerLeaves>,
}

/// The state rules of a receipt, whoever checks it: the sender before it signs
/// anything, the recipient before it accepts, and [`verify_stitched_receipt`]
/// as its rules 3–4. There is one implementation.
///
/// - Every fixed field names something: a zero genesis, device, tip, root or
///   transition entropy is not a field of any transition; and the genesis is
///   the author's pinned genesis.
/// - `child_tip` is the successor its own fields name:
///   `relationship_chain_tip_v2(k, parent_tip, devid_b, op, e)`.
/// - The step's writes are exactly the leaves its operation implies, each
///   once, ordered by key: the relationship leaf; and for the author's own
///   offline-bearer spend also the anchor-state leaf of the pinned bundle and
///   the offline allocation it drew from. Every key and value is derived here
///   — the relationship's from the tips, the anchor's from [`BearerLeaves`],
///   the allocation's after-state from its before-state and the operation's
///   amount. Only the allocation's before-state is a witness, because its leaf
///   is an opaque hash; it is bound by the fold like every other value.
/// - Folded together against `parent_root`, the writes are `child_root`: the
///   receipt proves the whole move of the author's root, so no leaf it names
///   can move differently and no leaf it does not name can move at all.
/// - The device proof puts `devid_a` under the Device Tree commitment the
///   caller supplies.
pub fn verify_receipt_state(
    receipt: &StitchedReceiptV2,
    ctx: &ReceiptStateContext<'_>,
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
    if receipt.genesis != ctx.author_genesis {
        return Err(DsmError::invalid_operation(
            "the receipt's genesis is not its author's pinned genesis",
        ));
    }

    let rel_key = compute_smt_key(&receipt.devid_a, &receipt.devid_b);
    let op_bytes = ctx.operation.to_bytes();
    if relationship_chain_tip_v2(
        &rel_key,
        &receipt.parent_tip,
        &receipt.devid_b,
        &op_bytes,
        &receipt.transition_entropy,
        None,
    ) != receipt.child_tip
    {
        return Err(DsmError::invalid_operation(
            "the receipt's child tip is not the successor of its parent tip under its operation and entropy",
        ));
    }

    // The leaves the step writes follow from its operation: a spend the author
    // makes offline also moves its anchor counter and its allocation.
    let offline_spend = match ctx.operation {
        Operation::Transfer {
            to_device_id,
            amount,
            policy_commit,
            ..
        } if operation_requires_offline_bearer(ctx.operation)
            && to_device_id.as_slice() == receipt.devid_b =>
        {
            Some((amount.value(), *policy_commit))
        }
        _ => None,
    };
    let bearer = match (offline_spend, ctx.bearer) {
        (Some(spend), Some(leaves)) => Some((spend, leaves)),
        (None, None) => None,
        (Some(_), None) => {
            return Err(DsmError::invalid_operation(
                "an offline-bearer spend is verified against its anchor-state leaves",
            ))
        }
        (None, Some(_)) => {
            return Err(DsmError::invalid_operation(
                "only the author's own offline-bearer spend writes its anchor-state leaf",
            ))
        }
    };
    let expected_count = if bearer.is_some() { 3 } else { 1 };
    if receipt.step_writes.len() != expected_count {
        return Err(DsmError::invalid_operation(format!(
            "the step writes {expected_count} leaves; the receipt proves {}",
            receipt.step_writes.len()
        )));
    }

    let mut entries: Vec<FoldEntry> = Vec::with_capacity(expected_count);
    let (mut relationship, mut anchor, mut allocation) = (false, false, false);
    for write in &receipt.step_writes {
        let (key, pre, post) = match (write.leaf, &bearer) {
            (ReceiptLeaf::Relationship, _) if !relationship => {
                relationship = true;
                (rel_key, receipt.parent_tip, receipt.child_tip)
            }
            (ReceiptLeaf::AnchorState, Some((_, leaves))) if !anchor => {
                anchor = true;
                if leaves.anchor_before == leaves.anchor_after {
                    return Err(DsmError::invalid_operation(
                        "an offline-bearer spend moves its anchor-state leaf",
                    ));
                }
                (
                    anchor_state_leaf_key(&leaves.bundle),
                    leaves.anchor_before,
                    leaves.anchor_after,
                )
            }
            (
                ReceiptLeaf::OfflineAllocation {
                    pre_amount,
                    pre_sequence,
                },
                Some(((amount, asset), leaves)),
            ) if !allocation => {
                allocation = true;
                let post_amount = pre_amount.checked_sub(*amount).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "the offline allocation holds less than the operation spends",
                    )
                })?;
                let post_sequence = pre_sequence.checked_add(1).ok_or_else(|| {
                    DsmError::invalid_operation("the offline allocation's sequence overflows")
                })?;
                (
                    offline_allocation_key(
                        &ctx.author_genesis,
                        &receipt.devid_a,
                        &leaves.bundle,
                        asset,
                    ),
                    offline_allocation_value(pre_amount, pre_sequence),
                    offline_allocation_value(post_amount, post_sequence),
                )
            }
            (leaf, _) => {
                return Err(DsmError::invalid_operation(format!(
                    "the receipt proves a write the step does not make: {leaf:?}"
                )))
            }
        };
        let path =
            smt_path::decode::<DeviceSmtHashes>(&write.path.explicit_heights, &write.path.siblings)
                .map_err(|e| DsmError::invalid_operation(format!("a receipt write's path: {e}")))?;
        entries.push(FoldEntry {
            key,
            pre: Some(pre),
            post: Some(post),
            path,
        });
    }
    if entries.windows(2).any(|w| w[0].key >= w[1].key) {
        return Err(DsmError::invalid_operation(
            "the receipt's writes are not in the order of their keys",
        ));
    }
    let post_root = verify_batch::<DeviceSmtHashes>(&receipt.parent_root, &entries)
        .map_err(|e| DsmError::invalid_operation(format!("the receipt's writes: {e}")))?;
    if post_root != receipt.child_root {
        return Err(DsmError::invalid_operation(
            "the receipt's writes do not fold from its parent root to its child root",
        ));
    }

    let dev_proof = DevTreeProof::from_bytes(&receipt.dev_proof)
        .ok_or_else(|| DsmError::invalid_operation("the device proof does not decode"))?;
    if !dev_proof.verify(&receipt.devid_a, &ctx.device_tree_commitment.root()) {
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
    use crate::merkle::smt_path::EncodedPath;
    use crate::types::step_fixture::{transfer_step, Party, Step};

    /// Two wallets, the sender's first transfer to the receiver, and a second
    /// transfer from the sender's same head (a fork of the first). Derived
    /// once: SPHINCS+ keygen and signing are slow.
    struct World {
        sender: Party,
        receiver: Party,
        transfer: Step,
        fork: Step,
    }

    fn world() -> &'static World {
        static WORLD: std::sync::OnceLock<World> = std::sync::OnceLock::new();
        WORLD.get_or_init(|| {
            let sender = Party::from_seed(b"receipt verification sender wallet seed");
            let receiver = Party::from_seed(b"receipt verification receiver wallet seed");
            let transfer = transfer_step(&sender, &receiver, 7);
            let fork = transfer_step(&sender, &receiver, 8);
            World {
                sender,
                receiver,
                transfer,
                fork,
            }
        })
    }

    /// The transfer's receipt signed as [`verify_stitched_receipt`] checks
    /// it: each side's per-step EK, certified by that side's AK at the
    /// receipt's parent tip, signs the receipt's commitment. With the context
    /// a verifier expecting the step holds.
    fn signed_receipt_and_context() -> (StitchedReceiptV2, ReceiptVerificationContext) {
        let w = world();
        let mut receipt = w.transfer.receipt.clone();
        let commitment = receipt.compute_commitment().unwrap();
        let a = w.sender.answer(
            &w.receiver,
            &receipt.parent_tip,
            &w.transfer.c_pre,
            &commitment,
        );
        let b = w.receiver.answer(
            &w.sender,
            &receipt.parent_tip,
            &w.transfer.c_pre,
            &commitment,
        );
        receipt.add_sig_a(a.sig);
        receipt.set_ek_cert_a(a.ek_cert);
        receipt.set_ek_pk_a(a.ek_pk.clone());
        receipt.add_sig_b(b.sig);
        receipt.set_ek_cert_b(b.ek_cert);
        receipt.set_ek_pk_b(b.ek_pk.clone());
        let ctx = ReceiptVerificationContext::new(
            w.sender.device_tree_commitment(),
            receipt.parent_root,
            a.ek_pk,
            b.ek_pk,
            w.sender.genesis(),
            w.transfer.operation.clone(),
        )
        .with_chain_head_a(w.sender.signing_public_key().to_vec())
        .with_chain_head_b(w.receiver.signing_public_key().to_vec());
        (receipt, ctx)
    }

    #[test]
    fn test_verify_empty_receipt_rejects() {
        let (_, ctx) = signed_receipt_and_context();
        let receipt = world().transfer.receipt.clone();
        let result =
            verify_stitched_receipt(&receipt, &ctx, &mut ParentConsumptionTracker::new()).unwrap();
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("Missing sender signature"));
    }

    #[test]
    fn test_verify_receipt_rejects_missing_receiver_signature() {
        let (signed, ctx) = signed_receipt_and_context();
        let mut receipt = world().transfer.receipt.clone();
        receipt.add_sig_a(signed.sig_a.clone());
        let result =
            verify_stitched_receipt(&receipt, &ctx, &mut ParentConsumptionTracker::new()).unwrap();
        assert!(!result.valid);
        assert!(result
            .reason
            .unwrap()
            .contains("Missing receiver signature"));
    }

    /// The state rules hold for the receipt of a real step and refuse each
    /// thing that would let a receipt claim a move its writes do not prove:
    /// another post-state root, another pre-state root, a changed sibling, a
    /// write naming another leaf, a write too many or none, a zero field, a
    /// genesis that is not the author's, another operation, anchor-state
    /// leaves for a step that moves none, a device proof for another device,
    /// and another Device Tree.
    ///
    /// MUTATION CONTROLS (run 2026-09-27): deleting the genesis check, the
    /// child-tip recompute, the fold-to-`child_root` check, the device-proof
    /// check or the refusal of anchor-state leaves for a step that moves none
    /// each turns one named assertion here red. The write-count check is not
    /// load-bearing for a one-write step (a repeated leaf and an empty set are
    /// refused without it); it carries the three-write bearer step.
    #[test]
    fn the_state_rules_hold_only_for_the_move_the_writes_prove() {
        let w = world();
        let receipt = &w.transfer.receipt;
        let commitment = w.sender.device_tree_commitment();
        let context = ReceiptStateContext {
            device_tree_commitment: &commitment,
            author_genesis: w.sender.genesis(),
            operation: &w.transfer.operation,
            bearer: None,
        };
        verify_receipt_state(receipt, &context).expect("the receipt of a real step holds");

        let refused = |why: &str, mutate: &dyn Fn(&mut StitchedReceiptV2)| {
            let mut r = receipt.clone();
            mutate(&mut r);
            assert_ne!(
                r.to_canonical_protobuf().unwrap(),
                receipt.to_canonical_protobuf().unwrap(),
                "the mutation changes the receipt: {why}"
            );
            assert!(verify_receipt_state(&r, &context).is_err(), "{why}");
        };
        refused("another post-state root", &|r| {
            r.child_root = w.fork.receipt.child_root
        });
        refused("another pre-state root", &|r| {
            r.parent_root = w.fork.receipt.child_root
        });
        assert!(
            !receipt.step_writes[0].path.siblings.is_empty(),
            "the relationship leaf shares its tree with the faucet's self-loop"
        );
        refused("a changed sibling", &|r| {
            r.step_writes[0].path.siblings[0] ^= 1
        });
        refused("a sibling the path does not name", &|r| {
            let path = &r.step_writes[0].path;
            let mut heights = path.explicit_heights;
            let free = (0..256)
                .find(|h| heights[h / 8] & (0x80 >> (h % 8)) == 0)
                .expect("a height the path carries no sibling at");
            heights[free / 8] |= 0x80 >> (free % 8);
            let mut siblings = path.siblings.clone();
            siblings.extend_from_slice(&w.fork.receipt.child_tip);
            r.step_writes[0].path = EncodedPath {
                explicit_heights: heights,
                siblings,
            };
        });
        refused("a write naming another leaf", &|r| {
            r.step_writes[0].leaf = ReceiptLeaf::AnchorState
        });
        refused("a write too many", &|r| {
            let again = r.step_writes[0].clone();
            r.step_writes.push(again)
        });
        refused("no writes", &|r| r.step_writes.clear());
        refused("a zero field", &|r| r.transition_entropy = [0; 32]);
        refused("a device proof for another device", &|r| {
            r.dev_proof = crate::common::device_tree::DeviceTree::new(vec![
                w.sender.device_id(),
                w.receiver.device_id(),
            ])
            .proof(&w.receiver.device_id())
            .expect("the receiver's device path")
            .to_bytes()
        });

        let with = |context: ReceiptStateContext<'_>| verify_receipt_state(receipt, &context);
        assert!(
            with(ReceiptStateContext {
                author_genesis: w.receiver.genesis(),
                ..context
            })
            .is_err(),
            "a genesis that is not the author's"
        );
        assert!(
            with(ReceiptStateContext {
                operation: &w.fork.operation,
                ..context
            })
            .is_err(),
            "another operation"
        );
        assert!(
            with(ReceiptStateContext {
                bearer: Some(BearerLeaves {
                    bundle: w.fork.receipt.child_root,
                    anchor_before: w.fork.receipt.parent_tip,
                    anchor_after: w.fork.receipt.child_tip,
                }),
                ..context
            })
            .is_err(),
            "anchor-state leaves for a step that moves none"
        );
        let other_tree = w.receiver.device_tree_commitment();
        assert!(
            with(ReceiptStateContext {
                device_tree_commitment: &other_tree,
                ..context
            })
            .is_err(),
            "another Device Tree"
        );
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

        let fork = &world().fork.receipt;
        assert_eq!(
            fork.parent_tip, receipt.parent_tip,
            "the fork shares the parent"
        );
        let mut tracker = ParentConsumptionTracker::new();
        tracker
            .try_consume(fork.parent_tip, fork.child_tip)
            .unwrap();
        let result = verify_stitched_receipt(&receipt, &ctx, &mut tracker).unwrap();
        assert!(!result.valid);
        let reason = result.reason.unwrap_or_default();
        assert!(reason.contains("Parent uniqueness"), "got: {reason}");
    }

    /// A verifier that expects the step to start from one root refuses a
    /// receipt — fully signed, its writes authentic — over any other root:
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
        let (mut receipt, ctx) = signed_receipt_and_context();
        receipt.ek_cert_a.clear();
        let result =
            verify_stitched_receipt(&receipt, &ctx, &mut ParentConsumptionTracker::new()).unwrap();
        assert!(!result.valid, "missing ek_cert_a must be rejected");
        let reason = result.reason.unwrap();
        assert!(
            reason.contains("Missing ek_cert_a"),
            "wrong rejection reason: {reason}"
        );
    }

    /// An ek_cert_a signed by a key that is not the chain head — here the
    /// receiver's AK certifying the sender's EK — must not verify against the
    /// legitimate head: the core forgery resistance of the cert chain.
    #[test]
    fn test_ek_cert_a_signed_by_wrong_key_rejected() {
        let w = world();
        let (mut receipt, ctx) = signed_receipt_and_context();
        receipt.ek_cert_a = crate::crypto::ephemeral_key::sign_ek_cert(
            w.receiver.signing_secret_key(),
            &ctx.pubkey_a,
            &receipt.parent_tip,
        )
        .expect("the receiver's AK signs a cert");
        let result =
            verify_stitched_receipt(&receipt, &ctx, &mut ParentConsumptionTracker::new()).unwrap();
        assert!(!result.valid, "forged ek_cert_a must be rejected");
        let reason = result.reason.unwrap();
        assert!(
            reason.contains("ek_cert_a verification failed"),
            "wrong rejection reason: {reason}"
        );
    }

    /// Receipt verification is fail-closed when no sender chain head is set.
    /// Parent/root inclusion alone is not spend authority; the recipient must
    /// also verify the per-step EK cert chain.
    #[test]
    fn test_no_chain_head_rejects_receipt_authorization() {
        let (receipt, ctx) = signed_receipt_and_context();
        let headless = ReceiptVerificationContext {
            chain_head_pubkey_a: None,
            ..ctx
        };
        let result =
            verify_stitched_receipt(&receipt, &headless, &mut ParentConsumptionTracker::new())
                .unwrap();
        assert!(!result.valid, "missing chain head must reject");
        let reason = result.reason.unwrap();
        assert!(
            reason.contains("chain_head_pubkey_a"),
            "wrong rejection reason: {reason}"
        );
    }
}
