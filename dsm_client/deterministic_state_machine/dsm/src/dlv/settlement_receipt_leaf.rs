// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trader settlement receipt — proof that a settlement actually committed.
//!
//! WHY THIS EXISTS. A pending pointer says "I am about to settle against this
//! vault at this sequence". Folding that claim into effective reserves is what
//! made liquidity griefing free: a trader publishes a well-formed pointer, never
//! advances its own chain, pays nothing, takes nothing, and the vault's quotable
//! liquidity drops for everyone else — indefinitely, at the cost of one storage
//! write. Every check the composer ran (pointer signature, X published,
//! RouteCommit valid, AMM math exact) is satisfied by that trader, because all
//! of them describe an *intent* and none of them witness an *advance*.
//!
//! A receipt is the missing witness. It proves the trader's own `DlvSettle`
//! advance committed: the settlement is bound into a leaf of the trader's device
//! SMT, and the receipt carries that leaf's inclusion path against the trader's
//! post-advance root, signed by the trader. So a pointer is inert until its
//! receipt is produced and verified — the griefer cannot manufacture one without
//! actually paying the input.
//!
//! Shape is cloned from [`crate::dlv::vault_smt_leaf`] (signature over the
//! committed tuple, then a 256-sibling SMT path re-verified from a recomputed
//! leaf) and [`crate::dlv::vault_reserve_leaf`] (per-`(device, subject)` keying
//! outside `balances`). Both are proven; a third mechanism for the same shape is
//! how the three would drift.
//!
//! KEYED BY RECEIPT ID, which gives replay protection structurally rather than
//! by bookkeeping. Recording the same receipt twice writes the same key with the
//! same value — idempotent by construction, no dedup table consulted. A
//! *different* settlement claiming the same receipt id writes a different value
//! at that same key, so the conflict is visible as a value mismatch rather than
//! silently overwriting.
//!
//! Verification is stateless: a third party runs it against published bytes with
//! no access to the trader's device. All hashing is domain-separated BLAKE3,
//! signatures are SPHINCS+. No JSON, no hex, no wall-clock.

use crate::common::domain_tags::{
    TAG_SETTLEMENT_RECEIPT_COMMIT, TAG_SETTLEMENT_RECEIPT_ID, TAG_SETTLEMENT_RECEIPT_LEAF,
    TAG_SETTLEMENT_RECEIPT_SIGN, TAG_SETTLEMENT_RECEIPT_STATE,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};

/// 256-bit SMT key of a settlement receipt leaf:
/// `H("DSM/settlement-receipt/v1" ‖ genesis_id ‖ device_id ‖ vault_id ‖ receipt_id)`.
///
/// Keyed by `vault_id` as well as `receipt_id` so a receipt can never be
/// re-pointed at a different vault: the key itself would move.
pub fn settlement_receipt_key(
    genesis_id: &[u8; 32],
    device_id: &[u8; 32],
    vault_id: &[u8; 32],
    receipt_id: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_SETTLEMENT_RECEIPT_LEAF);
    h.update(genesis_id);
    h.update(device_id);
    h.update(vault_id);
    h.update(receipt_id);
    *h.finalize().as_bytes()
}

/// The settled trade, in the exact terms the owner must reproduce.
///
/// This is the *whole* trade, not a reference to it. The owner folds these
/// numbers directly into its reserves, so anything omitted here would be
/// something the owner had to take on trust from elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettledTrade {
    /// The external commitment the trader published for this settlement. Ties
    /// the receipt to exactly one pending pointer.
    pub x: [u8; 32],
    /// Vault sequence this settlement consumed, and the one it produced.
    pub parent_sequence: u64,
    pub new_sequence: u64,
    /// The asset the trader paid, and how much of it (base units).
    pub input_policy_commit: [u8; 32],
    pub input_amount: u64,
    /// The asset the trader took, and how much of it (base units).
    pub output_policy_commit: [u8; 32],
    pub output_amount: u64,
}

/// 256-bit receipt-leaf VALUE committing the settled trade.
///
/// Every field of the trade is folded in, so a receipt cannot be re-pointed at
/// different amounts, a different asset pair, or a different sequence step while
/// keeping its leaf position.
pub fn settlement_receipt_value(trade: &SettledTrade) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_SETTLEMENT_RECEIPT_STATE);
    h.update(&trade.x);
    h.update(&trade.parent_sequence.to_be_bytes());
    h.update(&trade.new_sequence.to_be_bytes());
    h.update(&trade.input_policy_commit);
    h.update(&trade.input_amount.to_be_bytes());
    h.update(&trade.output_policy_commit);
    h.update(&trade.output_amount.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Signed canonical form of a trader settlement receipt. Wire-encoded as
/// `TraderSettlementReceiptV1`.
#[derive(Debug, Clone)]
pub struct SignedTraderSettlementReceipt {
    pub vault_id: [u8; 32],
    pub receipt_id: [u8; 32],
    pub trade: SettledTrade,
    /// The trader's own identity — whose chain this receipt witnesses.
    pub trader_genesis: [u8; 32],
    pub trader_devid: [u8; 32],
    /// The trader's device SMT root AFTER the settling advance committed.
    pub post_root: [u8; 32],
    /// 256 sibling hashes, leaf-to-root, for the receipt leaf under `post_root`.
    pub smt_siblings: Vec<[u8; 32]>,
    pub trader_public_key: Vec<u8>,
    pub trader_signature: Vec<u8>,
}

/// Errors from settlement-receipt signing / verification.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiptError {
    /// SPHINCS+ signature verification failed: bad signature, wrong key, or a
    /// tampered field inside the signed tuple.
    SignatureInvalid,
    /// Underlying SPHINCS+ sign call failed.
    SignFailed(String),
    /// The SMT path does not carry the recomputed receipt leaf up to
    /// `post_root`. The trader signed a settlement its own chain does not
    /// commit — which is exactly the unbacked claim this type exists to reject.
    InclusionProofRejected,
    /// Sibling vector length is not exactly 256.
    BadSiblingCount { expected: usize, actual: usize },
    /// `new_sequence != parent_sequence + 1`, or the parent cannot be advanced.
    /// Matches the pointer's unit-step rule; a receipt that skipped sequences
    /// could fold a vault forward past states nobody witnessed.
    NonUnitStep {
        parent_sequence: u64,
        new_sequence: u64,
    },
    /// A settlement must name two distinct assets and move a non-zero amount of
    /// each. Rejected here as well as at the core chokepoint, because this
    /// verifier runs on a device that never saw the trader's advance.
    DegenerateTrade,
}

impl core::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReceiptError::SignatureInvalid => write!(f, "receipt signature verification failed"),
            ReceiptError::SignFailed(msg) => write!(f, "sphincs sign failed: {msg}"),
            ReceiptError::InclusionProofRejected => write!(
                f,
                "receipt leaf is not committed in the trader's post-advance root",
            ),
            ReceiptError::BadSiblingCount { expected, actual } => {
                write!(f, "SMT siblings must have length {expected}, got {actual}")
            }
            ReceiptError::NonUnitStep {
                parent_sequence,
                new_sequence,
            } => write!(
                f,
                "receipt must advance sequence by exactly 1 (parent={parent_sequence}, new={new_sequence})",
            ),
            ReceiptError::DegenerateTrade => write!(
                f,
                "receipt must name two distinct assets and move a non-zero amount of each",
            ),
        }
    }
}

impl std::error::Error for ReceiptError {}

/// Canonical signing payload:
/// `H("DSM/settlement-receipt-sign" ‖ vault_id ‖ receipt_id ‖ leaf_value ‖
///    trader_genesis ‖ trader_devid ‖ post_root)`.
///
/// The trade enters through `leaf_value`, so the signature covers every settled
/// quantity without restating them — and covers exactly what the SMT path is
/// checked against, so signature and inclusion cannot describe different trades.
pub fn receipt_sign_payload(
    vault_id: &[u8; 32],
    receipt_id: &[u8; 32],
    trade: &SettledTrade,
    trader_genesis: &[u8; 32],
    trader_devid: &[u8; 32],
    post_root: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_SETTLEMENT_RECEIPT_SIGN);
    h.update(vault_id);
    h.update(receipt_id);
    h.update(&settlement_receipt_value(trade));
    h.update(trader_genesis);
    h.update(trader_devid);
    h.update(post_root);
    *h.finalize().as_bytes()
}

/// Deterministic receipt id for the settlement committed by `x` against `vault_id`.
///
/// Derived rather than chosen so the pointer publisher and the settling advance
/// arrive at the same id with no coordination between them — they run at
/// different times, and a trader that picked an id freely could publish a
/// pointer naming one id and then settle under another, leaving the pointer
/// permanently inert and the slot permanently claimed.
pub fn derive_receipt_id(vault_id: &[u8; 32], x: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_SETTLEMENT_RECEIPT_ID);
    h.update(vault_id);
    h.update(x);
    *h.finalize().as_bytes()
}

/// The commitment a pending pointer carries, naming the ONE receipt that can
/// activate it: `H(tag ‖ vault_id ‖ receipt_id ‖ leaf_value)`.
///
/// DELIBERATELY EXCLUDES `post_root`, and that exclusion is forced by the
/// publish ordering. The pointer goes out BEFORE the trader advances — that is
/// what claims the `(parent_sequence, X)` slot and makes the first-writer race
/// decidable — so at pointer-signing time the trader does not yet have a
/// post-advance root to commit to. Everything about the *trade* is known then,
/// and that is what this covers.
///
/// Nothing is lost by the exclusion. The pointer pins which trade may activate
/// it; the receipt independently proves that trade is committed under a root
/// the trader signed. A griefer can match this commitment trivially — it is
/// derived from their own published pointer — but cannot produce the inclusion
/// path without actually settling.
pub fn receipt_commitment(
    vault_id: &[u8; 32],
    receipt_id: &[u8; 32],
    trade: &SettledTrade,
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_SETTLEMENT_RECEIPT_COMMIT);
    h.update(vault_id);
    h.update(receipt_id);
    h.update(&settlement_receipt_value(trade));
    *h.finalize().as_bytes()
}

/// The commitment for an already-assembled receipt.
pub fn receipt_commitment_of(receipt: &SignedTraderSettlementReceipt) -> [u8; 32] {
    receipt_commitment(&receipt.vault_id, &receipt.receipt_id, &receipt.trade)
}

fn check_trade_shape(trade: &SettledTrade) -> Result<(), ReceiptError> {
    if trade.input_policy_commit == trade.output_policy_commit
        || trade.input_amount == 0
        || trade.output_amount == 0
    {
        return Err(ReceiptError::DegenerateTrade);
    }
    let expected = trade
        .parent_sequence
        .checked_add(1)
        .ok_or(ReceiptError::NonUnitStep {
            parent_sequence: trade.parent_sequence,
            new_sequence: trade.new_sequence,
        })?;
    if trade.new_sequence != expected {
        return Err(ReceiptError::NonUnitStep {
            parent_sequence: trade.parent_sequence,
            new_sequence: trade.new_sequence,
        });
    }
    Ok(())
}

/// Sign a settlement receipt with the trader's SPHINCS+ secret key.
///
/// The caller supplies the sibling path already pulled from its own post-advance
/// SMT; this function consults no tree state. It refuses to sign a degenerate or
/// non-unit-step trade, so a malformed receipt cannot be produced in the first
/// place rather than only being caught downstream.
#[allow(clippy::too_many_arguments)]
pub fn sign_trader_settlement_receipt(
    vault_id: &[u8; 32],
    receipt_id: &[u8; 32],
    trade: SettledTrade,
    trader_genesis: &[u8; 32],
    trader_devid: &[u8; 32],
    post_root: &[u8; 32],
    smt_siblings: Vec<[u8; 32]>,
    trader_public_key: &[u8],
    trader_secret_key: &[u8],
) -> Result<SignedTraderSettlementReceipt, ReceiptError> {
    check_trade_shape(&trade)?;
    if smt_siblings.len() != 256 {
        return Err(ReceiptError::BadSiblingCount {
            expected: 256,
            actual: smt_siblings.len(),
        });
    }
    let payload = receipt_sign_payload(
        vault_id,
        receipt_id,
        &trade,
        trader_genesis,
        trader_devid,
        post_root,
    );
    let signature = crate::crypto::sphincs::sphincs_sign(trader_secret_key, &payload)
        .map_err(|e| ReceiptError::SignFailed(format!("{e:?}")))?;
    Ok(SignedTraderSettlementReceipt {
        vault_id: *vault_id,
        receipt_id: *receipt_id,
        trade,
        trader_genesis: *trader_genesis,
        trader_devid: *trader_devid,
        post_root: *post_root,
        smt_siblings,
        trader_public_key: trader_public_key.to_vec(),
        trader_signature: signature,
    })
}

/// Verify a settlement receipt end-to-end: trade shape, then the trader's
/// signature, then SMT inclusion of the recomputed leaf under `post_root`.
///
/// Passing means the trader's own device root commits this exact settlement —
/// the input was paid and the output taken on a chain the trader signed. That is
/// the fact a pointer needs before it may consume anyone's liquidity.
///
/// Stateless and fail-closed. Note what it does NOT establish: that `post_root`
/// is the trader's *current* root. It does not need to — a committed settlement
/// stays committed, and a trader cannot un-pay an input by advancing further.
pub fn verify_trader_settlement_receipt(
    receipt: &SignedTraderSettlementReceipt,
) -> Result<(), ReceiptError> {
    check_trade_shape(&receipt.trade)?;
    if receipt.smt_siblings.len() != 256 {
        return Err(ReceiptError::BadSiblingCount {
            expected: 256,
            actual: receipt.smt_siblings.len(),
        });
    }
    let payload = receipt_sign_payload(
        &receipt.vault_id,
        &receipt.receipt_id,
        &receipt.trade,
        &receipt.trader_genesis,
        &receipt.trader_devid,
        &receipt.post_root,
    );
    let ok = crate::crypto::sphincs::sphincs_verify(
        &receipt.trader_public_key,
        &payload,
        &receipt.trader_signature,
    )
    .map_err(|_| ReceiptError::SignatureInvalid)?;
    if !ok {
        return Err(ReceiptError::SignatureInvalid);
    }

    let key = settlement_receipt_key(
        &receipt.trader_genesis,
        &receipt.trader_devid,
        &receipt.vault_id,
        &receipt.receipt_id,
    );
    let value = settlement_receipt_value(&receipt.trade);
    let proof = SmtInclusionProof {
        key,
        value: Some(value),
        siblings: receipt.smt_siblings.clone(),
    };
    if SparseMerkleTree::verify_proof_against_root(&proof, &receipt.post_root) {
        Ok(())
    } else {
        Err(ReceiptError::InclusionProofRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::generate_sphincs_keypair;

    fn ids() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32])
    }

    fn trade() -> SettledTrade {
        SettledTrade {
            x: [0x55; 32],
            parent_sequence: 7,
            new_sequence: 8,
            input_policy_commit: [0xE0; 32],
            input_amount: 1_000,
            output_policy_commit: [0xF0; 32],
            output_amount: 970,
        }
    }

    /// Build a real 256-sibling proof for the receipt leaf.
    fn fixture(
        genesis: &[u8; 32],
        devid: &[u8; 32],
        vault: &[u8; 32],
        receipt_id: &[u8; 32],
        trade: &SettledTrade,
    ) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut tree = SparseMerkleTree::new(64);
        let key = settlement_receipt_key(genesis, devid, vault, receipt_id);
        let value = settlement_receipt_value(trade);
        tree.update_leaf(&key, &value).expect("update_leaf");
        let proof = tree.get_inclusion_proof(&key, 256).expect("proof");
        (*tree.root(), proof.siblings)
    }

    fn signed() -> (SignedTraderSettlementReceipt, Vec<u8>) {
        let (genesis, devid, vault, receipt_id) = ids();
        let t = trade();
        let (root, sibs) = fixture(&genesis, &devid, &vault, &receipt_id, &t);
        let (pk, sk) = generate_sphincs_keypair().expect("keypair");
        let r = sign_trader_settlement_receipt(
            &vault,
            &receipt_id,
            t,
            &genesis,
            &devid,
            &root,
            sibs,
            &pk,
            &sk,
        )
        .expect("sign");
        (r, sk)
    }

    #[test]
    fn a_real_settlement_verifies() {
        let (r, _) = signed();
        verify_trader_settlement_receipt(&r).expect("a committed settlement must verify");
    }

    /// THE GRIEFING CASE. A receipt whose settlement is not actually in the
    /// trader's root must fail — that is the entire point of the type. Signature
    /// alone is not enough: the griefer holds their own key and can sign
    /// anything.
    #[test]
    fn a_signature_over_a_settlement_the_chain_does_not_commit_is_rejected() {
        let (genesis, devid, vault, receipt_id) = ids();
        let t = trade();
        let (real_root, sibs) = fixture(&genesis, &devid, &vault, &receipt_id, &t);
        let (pk, sk) = generate_sphincs_keypair().expect("keypair");

        // Claim a root that this leaf does not belong to, and sign it honestly.
        let mut fake_root = real_root;
        fake_root[0] ^= 0xff;
        let forged = sign_trader_settlement_receipt(
            &vault,
            &receipt_id,
            t,
            &genesis,
            &devid,
            &fake_root,
            sibs,
            &pk,
            &sk,
        )
        .expect("signing a lie succeeds; verifying it must not");

        assert_eq!(
            verify_trader_settlement_receipt(&forged),
            Err(ReceiptError::InclusionProofRejected),
            "an unbacked settlement must not verify even with a valid signature"
        );
    }

    /// Every settled quantity is covered. Moving any of them must break the
    /// receipt — otherwise a trader could publish a pointer for one trade and
    /// activate it with a receipt for a cheaper one.
    #[test]
    fn every_settled_quantity_is_covered() {
        let (r, _) = signed();
        /// One named tamper: a label for the failure message, and the mutation
        /// that corrupts exactly one field.
        type ReceiptTamper = (
            &'static str,
            Box<dyn Fn(&mut SignedTraderSettlementReceipt)>,
        );

        let mutations: Vec<ReceiptTamper> = vec![
            (
                "x",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.trade.x[0] ^= 0xff),
            ),
            (
                "input amount",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.trade.input_amount -= 1),
            ),
            (
                "output amount",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.trade.output_amount += 1),
            ),
            (
                "input asset",
                Box::new(|r: &mut SignedTraderSettlementReceipt| {
                    r.trade.input_policy_commit[0] ^= 0xff
                }),
            ),
            (
                "output asset",
                Box::new(|r: &mut SignedTraderSettlementReceipt| {
                    r.trade.output_policy_commit[0] ^= 0xff
                }),
            ),
            (
                "vault id",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.vault_id[0] ^= 0xff),
            ),
            (
                "receipt id",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.receipt_id[0] ^= 0xff),
            ),
            (
                "trader devid",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.trader_devid[0] ^= 0xff),
            ),
            (
                "trader genesis",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.trader_genesis[0] ^= 0xff),
            ),
            (
                "post root",
                Box::new(|r: &mut SignedTraderSettlementReceipt| r.post_root[0] ^= 0xff),
            ),
        ];
        for (what, mutate) in mutations {
            let mut tampered = r.clone();
            mutate(&mut tampered);
            assert!(
                verify_trader_settlement_receipt(&tampered).is_err(),
                "tampering the {what} must invalidate the receipt"
            );
        }
    }

    /// The sequence pair moves together, so tampering it breaks the signature
    /// rather than tripping the shape check — either way it must reject.
    #[test]
    fn the_sequence_step_is_covered_and_must_be_a_unit_step() {
        let (r, _) = signed();
        let mut shifted = r.clone();
        shifted.trade.parent_sequence = 8;
        shifted.trade.new_sequence = 9;
        assert!(
            verify_trader_settlement_receipt(&shifted).is_err(),
            "a re-sequenced receipt must not verify"
        );

        let mut skipped = r.clone();
        skipped.trade.new_sequence = 10;
        assert!(matches!(
            verify_trader_settlement_receipt(&skipped),
            Err(ReceiptError::NonUnitStep { .. })
        ));
    }

    #[test]
    fn a_degenerate_trade_cannot_be_signed_or_verified() {
        let (genesis, devid, vault, receipt_id) = ids();
        let (pk, sk) = generate_sphincs_keypair().expect("keypair");
        for bad in [
            SettledTrade {
                output_policy_commit: [0xE0; 32], // same asset both legs
                ..trade()
            },
            SettledTrade {
                input_amount: 0,
                ..trade()
            },
            SettledTrade {
                output_amount: 0,
                ..trade()
            },
        ] {
            let (root, sibs) = fixture(&genesis, &devid, &vault, &receipt_id, &bad);
            assert_eq!(
                sign_trader_settlement_receipt(
                    &vault,
                    &receipt_id,
                    bad,
                    &genesis,
                    &devid,
                    &root,
                    sibs,
                    &pk,
                    &sk,
                )
                .err(),
                Some(ReceiptError::DegenerateTrade),
            );
        }
    }

    #[test]
    fn another_key_cannot_sign_for_this_trader() {
        let (mut r, _) = signed();
        let (other_pk, _) = generate_sphincs_keypair().expect("keypair");
        r.trader_public_key = other_pk;
        assert_eq!(
            verify_trader_settlement_receipt(&r),
            Err(ReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn a_short_or_absent_path_fails_closed() {
        let (mut r, _) = signed();
        r.smt_siblings.truncate(255);
        assert!(matches!(
            verify_trader_settlement_receipt(&r),
            Err(ReceiptError::BadSiblingCount { .. })
        ));
        r.smt_siblings.clear();
        assert!(matches!(
            verify_trader_settlement_receipt(&r),
            Err(ReceiptError::BadSiblingCount { .. })
        ));
    }

    /// The pointer's commitment must name exactly one receipt. Two receipts
    /// differing in any settled quantity must not share a hash, or a pointer for
    /// an expensive trade could be activated by a cheap one.
    #[test]
    fn the_pointer_commitment_names_exactly_one_receipt() {
        let (r, _) = signed();
        let h = receipt_commitment_of(&r);
        assert_eq!(h, receipt_commitment_of(&r.clone()), "deterministic");

        let mut cheaper = r.clone();
        cheaper.trade.input_amount = 1;
        assert_ne!(
            h,
            receipt_commitment_of(&cheaper),
            "a cheaper trade must not satisfy this pointer's commitment"
        );

        let mut other_vault = r.clone();
        other_vault.vault_id[0] ^= 0xff;
        assert_ne!(h, receipt_commitment_of(&other_vault));

        // Derivable from the trade ALONE — no post_root. That is what lets the
        // pointer be published before the advance that produces the receipt.
        assert_eq!(
            h,
            receipt_commitment(&r.vault_id, &r.receipt_id, &r.trade),
            "the commitment must be computable before the advance"
        );
    }

    /// Recording the same receipt twice is the same key AND the same value, so
    /// replay is a no-op structurally — there is no dedup table to consult and
    /// therefore none to get wrong.
    #[test]
    fn replay_is_idempotent_and_a_conflicting_reuse_is_visible() {
        let (genesis, devid, vault, receipt_id) = ids();
        let t = trade();
        let k1 = settlement_receipt_key(&genesis, &devid, &vault, &receipt_id);
        let k2 = settlement_receipt_key(&genesis, &devid, &vault, &receipt_id);
        assert_eq!(k1, k2);
        assert_eq!(settlement_receipt_value(&t), settlement_receipt_value(&t));

        // Same receipt id, different settlement: same slot, different value.
        // The conflict surfaces as a value mismatch instead of silently
        // overwriting the earlier settlement.
        let conflicting = SettledTrade {
            output_amount: 971,
            ..t
        };
        assert_eq!(
            k1,
            settlement_receipt_key(&genesis, &devid, &vault, &receipt_id)
        );
        assert_ne!(
            settlement_receipt_value(&t),
            settlement_receipt_value(&conflicting),
            "the same receipt id claiming a different trade must be detectable"
        );
    }

    #[test]
    fn key_is_field_sensitive_and_domain_separated() {
        let (g, d, v, r) = ids();
        let base = settlement_receipt_key(&g, &d, &v, &r);
        for i in 0..4 {
            let mut f = [g, d, v, r];
            f[i][0] ^= 0xff;
            assert_ne!(
                base,
                settlement_receipt_key(&f[0], &f[1], &f[2], &f[3]),
                "field {i} must move the leaf"
            );
        }
        // Disjoint from every other leaf family sharing the device SMT.
        assert_ne!(
            base,
            crate::dlv::vault_reserve_leaf::vault_reserve_key(&g, &d, &v, &r),
            "vs the vault-reserve leaf"
        );
        assert_ne!(
            base,
            crate::types::offline_allocation_leaf::offline_allocation_key(&g, &d, &v, &r),
            "vs the offline-cash allocation leaf"
        );
        assert_ne!(
            base,
            crate::dlv::vault_smt_leaf::compute_vault_smt_key(&v),
            "vs the vault-state leaf"
        );
        assert_ne!(
            base,
            crate::core::bilateral_transaction_manager::anchor_state_leaf_key(&v),
            "vs the anchor-state leaf"
        );
        assert_ne!(
            base,
            crate::core::bilateral_transaction_manager::compute_smt_key(&d, &d),
            "vs a relationship-tip leaf"
        );
    }
}
