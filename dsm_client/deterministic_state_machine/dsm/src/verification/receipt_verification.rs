// SPDX-License-Identifier: MIT OR Apache-2.0

//! Receipt Verification Module
//!
//! Implements cryptographic stitched-receipt verification predicates.
//! State-transition semantics such as token balance conservation are enforced
//! when applying transitions, not from opaque receipt tip hashes alone.

use crate::common::device_tree::DevTreeProof;
use crate::core::bilateral_transaction_manager::{compute_smt_key, operation_requires_offline_bearer};
use crate::merkle::batch_fold::{verify_batch, FoldEntry};
use crate::merkle::smt_path;
use crate::merkle::sparse_merkle_tree::DeviceSmtHashes;
use crate::types::device_state::relationship_chain_tip_v2;
use crate::types::error::DsmError;
use crate::types::offline_account::offline_account_leaf_key;
use crate::types::operations::Operation;
use crate::types::receipt_types::{DeviceTreeAcceptanceCommitment, ReceiptLeaf, StitchedReceiptV2};

/// What the verifier holds of the author's own offline-bearer spend from the
/// release it verified, never from the receipt: the pinned bundle, and the
/// release's signed counter and frontiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BearerLeaves {
    /// The author's pinned anchor bundle `B`.
    pub bundle: [u8; 32],
    /// The software counter `u_i` the spend started from.
    pub counter: u64,
    /// The frontier `h_i` the spend started from.
    pub frontier: [u8; 32],
    /// The frontier `h_{i+1}` the spend advanced to.
    pub next_frontier: [u8; 32],
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
/// anything, and the recipient before it accepts (`bilateral::offline`'s
/// `decide_confirm` and `decide_commit_ack`). There is one implementation.
///
/// - Every fixed field names something: a zero genesis, device, tip, root or
///   transition entropy is not a field of any transition; and the genesis is
///   the author's pinned genesis.
/// - `child_tip` is the successor its own fields name:
///   `relationship_chain_tip_v2(k, parent_tip, devid_b, op, e)`.
/// - The step's writes are exactly the leaves its operation implies, each
///   once, ordered by key: the relationship leaf; and for the author's own
///   offline-bearer spend also the leaf of the offline account of the pinned
///   bundle. Every key and value is derived here — the relationship's from the
///   tips, the account's after-root by folding the spend (the allocation
///   debit, the counter step and the frontier's advance) from the account the
///   receipt states it started from, whose counter and frontiers must be the
///   release's ([`BearerLeaves`]). Only that starting account is a witness;
///   it is bound by both folds like every other value.
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
                "an offline-bearer spend is verified against the release it advances",
            ))
        }
        (None, Some(_)) => {
            return Err(DsmError::invalid_operation(
                "only the author's own offline-bearer spend writes its offline account",
            ))
        }
    };
    let expected_count = if bearer.is_some() { 2 } else { 1 };
    if receipt.step_writes.len() != expected_count {
        return Err(DsmError::invalid_operation(format!(
            "the step writes {expected_count} leaves; the receipt proves {}",
            receipt.step_writes.len()
        )));
    }

    // A leaf named twice derives one key twice, which the key-order check
    // below refuses.
    let mut entries: Vec<FoldEntry> = Vec::with_capacity(expected_count);
    for write in &receipt.step_writes {
        let (key, pre, post) = match (&write.leaf, &bearer) {
            (ReceiptLeaf::Relationship, _) => (rel_key, receipt.parent_tip, receipt.child_tip),
            (ReceiptLeaf::OfflineAccount(witness), Some(((amount, asset), release))) => {
                // The account the spend started from is the release's: its
                // counter and both frontiers are the ones the release signed.
                if witness.pre_counter != release.counter
                    || witness.pre_frontier != release.frontier
                    || witness.next_frontier != release.next_frontier
                {
                    return Err(DsmError::invalid_operation(
                        "the receipt's offline account is not the one its release advances",
                    ));
                }
                (
                    offline_account_leaf_key(&release.bundle),
                    witness.pre_account_root,
                    witness.post_account_root(asset, *amount)?,
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

/// The side of a stitched receipt: its sender (A) or its receiver (B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BilateralSide {
    /// The sender, which initiates the step.
    A,
    /// The receiver, which counter-signs it.
    B,
}

/// Which key a side's next `ek_cert` chains to (§11.1), as the key of that
/// kind the caller holds: a public key to verify the certificate, a secret
/// key to sign it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EkPredecessor<K> {
    /// The side's EK head on the relationship.
    ChainHead(K),
    /// The side's AK, at the relationship's first step, before it has an EK
    /// head.
    RootAk(K),
}

impl<K> EkPredecessor<K> {
    /// The key itself.
    pub fn key(self) -> K {
        match self {
            Self::ChainHead(key) | Self::RootAk(key) => key,
        }
    }

    /// Whether the chain starts at the AK, the relationship's first step.
    pub fn is_root_ak(&self) -> bool {
        matches!(self, Self::RootAk(_))
    }
}

/// The predecessor rule of the per-step EK chain (§11.1), the one rule its
/// signer and every verifier use: a side's EK head on the relationship, or, at
/// the relationship's first step, where the side has no EK head yet, its AK.
/// A head the caller could not read is not "no head": it is the caller's to
/// report, never to pass here as `None`.
pub fn per_step_ek_predecessor<K>(chain_head: Option<K>, root_ak: K) -> EkPredecessor<K> {
    match chain_head {
        Some(head) => EkPredecessor::ChainHead(head),
        None => EkPredecessor::RootAk(root_ak),
    }
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

/// The sender's verdict on a recipient acceptance receipt (§16.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerifyOutcome {
    /// The receipt binds the exact step the sender proposed and its per-step
    /// EK countersignature (`sig_b`) verifies. `commitment` is the receipt
    /// commitment the finalization records for idempotent replay.
    Verified { commitment: [u8; 32] },
    /// The receipt names another step (party, parent, child or roots), or its
    /// countersignature does not verify. The sender's gate is retained.
    Rejected { reason: String },
}

fn rejected(reason: &str) -> ReceiptVerifyOutcome {
    ReceiptVerifyOutcome::Rejected {
        reason: reason.to_string(),
    }
}

/// The sender's online finality predicate (§16.6): a recipient acceptance
/// receipt finalizes the sender's step only when, in order,
///
///  1. `receipt.devid_a` is `sender_device_id` and `receipt.devid_b` is
///     `counterparty_device_id`;
///  2. its parent and child tips are `canonical_pair`, the step's pair in the
///     ASYMMETRIC canonical space (a symmetric routing pair is another formula
///     space, and comparing across the two rejects valid countersignatures);
///  3. its commitment is `commitment`. The commitment covers the receipt's
///     parent and child roots, so a receipt naming other roots fails here;
///  4. `ek_cert_b` chains `ek_pk_b` to `expected_prev_pk_b` over the parent tip
///     ([`per_step_ek_predecessor`] of the recipient's head and AK), and
///     `sig_b` verifies under `ek_pk_b` over the B-canonical target: the
///     session-bound target of the commitment extended with `b_pair`, the
///     recipient's canonical pair. A pair the recipient did not sign fails
///     here, so the pair the sender pins as the peer's head is authenticated.
///
/// `Err` means the receipt's commitment could not be computed. A validly
/// signed receipt naming another step is `Rejected`.
pub fn verify_acceptance_receipt(
    sender_device_id: &[u8; 32],
    counterparty_device_id: &[u8; 32],
    receipt: &StitchedReceiptV2,
    canonical_pair: ([u8; 32], [u8; 32]),
    commitment: &[u8; 32],
    expected_prev_pk_b: &[u8],
    b_pair: ([u8; 32], [u8; 32]),
) -> Result<ReceiptVerifyOutcome, DsmError> {
    if &receipt.devid_a != sender_device_id {
        return Ok(rejected("receipt devid_a is not this sender"));
    }
    if &receipt.devid_b != counterparty_device_id {
        return Ok(rejected("receipt devid_b is not the proposal counterparty"));
    }
    if receipt.parent_tip != canonical_pair.0 {
        return Ok(rejected(
            "receipt parent_tip != proposal canonical_parent (A-space)",
        ));
    }
    if receipt.child_tip != canonical_pair.1 {
        return Ok(rejected(
            "receipt child_tip != proposal canonical_child (A-space)",
        ));
    }
    let receipt_commitment = receipt.compute_commitment()?;
    if &receipt_commitment != commitment {
        return Ok(rejected("receipt commitment != proposal commitment"));
    }
    let b_target = crate::types::receipt_types::compute_receipt_b_canonical_target(
        &receipt_commitment,
        &receipt_commitment,
        &b_pair.0,
        &b_pair.1,
    );
    if let Err(e) = verify_per_step_ek_signing_target(
        receipt,
        BilateralSide::B,
        expected_prev_pk_b,
        &receipt.parent_tip,
        &b_target,
    ) {
        return Ok(rejected(&format!(
            "recipient per-step EK countersignature (sig_b) failed verification: {e}"
        )));
    }
    Ok(ReceiptVerifyOutcome::Verified {
        commitment: receipt_commitment,
    })
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
            r.step_writes[0].leaf =
                ReceiptLeaf::OfflineAccount(Box::new(crate::types::offline_account::SpendWitness {
                    pre_account_root: w.fork.receipt.parent_root,
                    pre_allocation: 1,
                    pre_counter: 0,
                    pre_frontier: w.fork.receipt.parent_tip,
                    next_frontier: w.fork.receipt.child_tip,
                    account_paths: Vec::new(),
                }))
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
                    counter: 0,
                    frontier: w.fork.receipt.parent_tip,
                    next_frontier: w.fork.receipt.child_tip,
                }),
                ..context
            })
            .is_err(),
            "an offline account for a step that moves none"
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

    /// The predecessor is the side's EK head once it has one, and its AK only
    /// before, for a public key as for a secret one.
    #[test]
    fn the_predecessor_is_the_head_and_the_ak_only_before_one_exists() {
        let (head, ak) = ([0xE1u8; 64], [0xA1u8; 64]);
        let chosen = per_step_ek_predecessor(Some(&head[..]), &ak[..]);
        assert_eq!(chosen, EkPredecessor::ChainHead(&head[..]));
        assert_eq!(chosen.key(), &head[..]);
        let first = per_step_ek_predecessor(None, &ak[..]);
        assert_eq!(first, EkPredecessor::RootAk(&ak[..]));
        assert_eq!(first.key(), &ak[..]);
        assert!(!chosen.is_root_ak());
        assert!(first.is_root_ak());
        assert_eq!(
            per_step_ek_predecessor(Some(vec![0xE2u8; 128]), vec![0xA2u8; 128]),
            EkPredecessor::ChainHead(vec![0xE2u8; 128])
        );
    }

    /// Everything the sender's finality predicate is handed, as the sender of
    /// the world's transfer holds it after the receiver's honest countersign:
    /// the receiver's per-step EK answer over the B-canonical target of the
    /// transfer's commitment and the receiver's own pair (its credit of the
    /// transfer), certified by the receiver's AK at the relationship's first
    /// step.
    #[derive(Clone)]
    struct Judged {
        sender: [u8; 32],
        counterparty: [u8; 32],
        receipt: StitchedReceiptV2,
        canonical_pair: ([u8; 32], [u8; 32]),
        commitment: [u8; 32],
        predecessor: Vec<u8>,
        b_pair: ([u8; 32], [u8; 32]),
    }

    impl Judged {
        fn verdict(&self) -> ReceiptVerifyOutcome {
            verify_acceptance_receipt(
                &self.sender,
                &self.counterparty,
                &self.receipt,
                self.canonical_pair,
                &self.commitment,
                &self.predecessor,
                self.b_pair,
            )
            .expect("the receipt's commitment computes")
        }

        /// Rejected, for a reason naming `why`.
        fn rejected_for(&self, why: &str) {
            match self.verdict() {
                ReceiptVerifyOutcome::Rejected { reason } => {
                    assert!(reason.contains(why), "expected {why}, got: {reason}")
                }
                verified => panic!("expected a rejection naming {why}, got {verified:?}"),
            }
        }
    }

    fn countersigned() -> &'static Judged {
        static HONEST: std::sync::OnceLock<Judged> = std::sync::OnceLock::new();
        HONEST.get_or_init(|| {
            let w = world();
            let mut receipt = w.transfer.receipt.clone();
            let commitment = receipt.compute_commitment().expect("the commitment");
            let credit = crate::types::step_fixture::credit_step(
                &w.receiver,
                &w.sender,
                &w.transfer.operation,
            );
            let b_pair = (credit.receipt.parent_tip, credit.receipt.child_tip);
            let answer = w.receiver.answer(
                &w.sender,
                &receipt.parent_tip,
                &w.transfer.c_pre,
                &crate::types::receipt_types::compute_receipt_b_canonical_target(
                    &commitment,
                    &commitment,
                    &b_pair.0,
                    &b_pair.1,
                ),
            );
            receipt.set_ek_pk_b(answer.ek_pk);
            receipt.set_ek_cert_b(answer.ek_cert);
            receipt.add_sig_b(answer.sig);
            Judged {
                sender: w.sender.device_id(),
                counterparty: w.receiver.device_id(),
                canonical_pair: (receipt.parent_tip, receipt.child_tip),
                commitment,
                predecessor: per_step_ek_predecessor(None, w.receiver.signing_public_key())
                    .key()
                    .to_vec(),
                b_pair,
                receipt,
            }
        })
    }

    #[test]
    fn an_honest_countersign_verifies_and_names_its_commitment() {
        let honest = countersigned();
        assert_eq!(
            honest.verdict(),
            ReceiptVerifyOutcome::Verified {
                commitment: honest.commitment
            }
        );
    }

    /// The honest countersign, judged by a device that is not its sender.
    #[test]
    fn rejects_receipt_naming_a_different_sender() {
        Judged {
            sender: world().receiver.device_id(),
            ..countersigned().clone()
        }
        .rejected_for("devid_a");
    }

    /// The honest countersign, judged against a proposal to another device.
    #[test]
    fn rejects_receipt_naming_a_different_counterparty() {
        Judged {
            counterparty: world().sender.device_id(),
            ..countersigned().clone()
        }
        .rejected_for("devid_b");
    }

    /// The honest countersign, judged against a proposal whose canonical
    /// parent or child is another step's, though its commitment is this one's.
    #[test]
    fn rejects_receipt_with_different_parent_or_child() {
        let honest = countersigned();
        let other = &world().fork.receipt;
        Judged {
            canonical_pair: (other.child_tip, honest.canonical_pair.1),
            ..honest.clone()
        }
        .rejected_for("parent_tip");
        Judged {
            canonical_pair: (honest.canonical_pair.0, other.child_tip),
            ..honest.clone()
        }
        .rejected_for("child_tip");
    }

    /// A receipt whose child tip is forged, with the commitment recomputed
    /// over the forgery, is refused at the child tip: retargeting the check
    /// onto the proposal's canonical pair tightened it.
    #[test]
    fn forged_canonical_child_is_rejected() {
        let mut forged = countersigned().clone();
        forged.receipt.child_tip = world().fork.receipt.child_tip;
        forged.commitment = forged.receipt.compute_commitment().expect("the commitment");
        forged.rejected_for("child_tip");
    }

    /// The commitment covers the receipt's roots: a receipt naming other roots
    /// is refused at the commitment, and so is the honest countersign judged
    /// against another step's commitment.
    #[test]
    fn a_receipt_naming_other_roots_than_the_committed_ones_is_rejected() {
        let other = &world().fork.receipt;
        let mutations: [fn(&mut StitchedReceiptV2, &StitchedReceiptV2); 2] = [
            |r, other| r.parent_root = other.child_root,
            |r, other| r.child_root = other.child_root,
        ];
        for mutate in mutations {
            let mut forged = countersigned().clone();
            mutate(&mut forged.receipt, other);
            forged.rejected_for("commitment");
        }
        Judged {
            commitment: other.compute_commitment().expect("the fork's commitment"),
            ..countersigned().clone()
        }
        .rejected_for("commitment");
    }

    /// A raw `sig_b` with no per-step EK and no certificate is a static-key
    /// signature, not finalization evidence.
    #[test]
    fn rejects_static_key_receipt_without_per_step_ek_artifacts() {
        let mut bare = countersigned().clone();
        bare.receipt.set_ek_pk_b(Vec::new());
        bare.receipt.set_ek_cert_b(Vec::new());
        bare.rejected_for("per-step EK");
    }

    /// The honest countersign answers for the receiver's pair from the
    /// receiver's chain: judged over another pair, or as chained from the
    /// sender's AK, `sig_b` does not verify.
    #[test]
    fn a_countersign_over_another_pair_or_from_another_chain_is_rejected() {
        let honest = countersigned();
        Judged {
            b_pair: (honest.b_pair.1, honest.b_pair.0),
            ..honest.clone()
        }
        .rejected_for("sig_b");
        Judged {
            predecessor: world().sender.signing_public_key().to_vec(),
            ..honest.clone()
        }
        .rejected_for("sig_b");
    }
}
