// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sender-side VERIFICATION of a recipient acceptance receipt for online
//! transition finalization (§16.6).
//!
//! Protocol boundary: a DSM online transition finalizes on the sender only when
//! the sender verifies a recipient-produced acceptance receipt that binds the
//! exact transition and carries the recipient's per-step EK countersignature
//! (`sig_b`), cert-chained to the recipient's stored counterparty cert head.
//! Storage-node ACK / message deletion is transport housekeeping and is DEMOTED
//! to best-effort garbage collection — it MUST NOT determine finalization.
//!
//! This module performs VERIFICATION ONLY. The atomic finalization commit
//! (relationship tip advance, pending-gate deletion, Local cert-head promotion,
//! Counterparty cert-head advance to `ek_pk_b`, receipt persistence, and the
//! finalized marker, as ONE recoverable state transition) is intentionally NOT
//! done here — "clear the gate, then persist evidence" is the wrong crash
//! ordering. The commit is a durable-journal-first operation implemented
//! separately so a crash cannot leave a transfer "finalized" with its cert heads
//! or evidence missing.
//!
//! `sig_b` is a PER-STEP EK SPHINCS+ signature (with `ek_pk_b` / `ek_cert_b` /
//! `kyber_ct_b`), NOT a static contact-key signature. It is verified the way the
//! recipient produces it — mirroring [`verify_inbound_receipt_sig_a`] but B-side:
//! `ek_cert_b` chains `ek_pk_b` back to the sender's stored Counterparty (=
//! recipient) cert head over `h_n`, then `sig_b` verifies under `ek_pk_b` over
//! the receipt challenge-response target. `genesis` is a genesis hash, not a
//! relationship id; the relationship is identified by `compute_smt_key(devid_a,
//! devid_b)` and matched to the pending gate by counterparty device id.

use crate::sdk::receipts::{verify_per_step_ek_signing, BilateralSide};
use crate::storage::client_db::sender_proposal::SenderOnlineProposal;
use crate::storage::client_db::{load_cert_chain_head_pubkey, CertChainSide};
use anyhow::{anyhow, Result};
use dsm::types::receipt_types::StitchedReceiptV2;

/// Outcome of [`verify_acceptance_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerifyOutcome {
    /// The receipt binds THIS exact pending transition and its per-step EK
    /// countersignature (`sig_b`) verifies. `commitment` is the receipt
    /// commitment the atomic finalization commit records for idempotent replay.
    Verified { commitment: [u8; 32] },
    /// The receipt does not correspond to this pending gate (wrong
    /// party/parent/child/root) or its countersignature is invalid. The gate
    /// MUST be retained.
    Rejected { reason: String },
}

/// Verify a recipient acceptance receipt against a pending online gate, COMPLETELY,
/// before any finalization commit.
///
/// Checks, in order:
///  1. `receipt.devid_a` is this sender and `receipt.devid_b` is the gate
///     counterparty (recipient);
///  2. `receipt.parent_tip == proposal.canonical_parent`, `receipt.child_tip ==
///     proposal.canonical_child`, and the recomputed receipt commitment equals
///     `proposal.commitment` — all in the ASYMMETRIC canonical space. The gate's
///     SYMMETRIC projection pair is deliberately NOT used: cross-space comparison
///     rejects valid countersignatures;
///  3. `expected_parent_root` / `expected_child_root`, when known from the
///     sender's stored proposal, equal the receipt's roots (pass `None` to skip
///     until proposal storage lands — a `Some` mismatch is a hard reject);
///  4. B-side per-step EK: `ek_cert_b` chains `ek_pk_b` back to the sender's
///     stored Counterparty (recipient) cert head over `h_n` (or `recipient_ak_pk`
///     at relationship genesis), then `sig_b` verifies under `ek_pk_b`;
///  5. Kyber consistency: `ek_pk_b` present ⇒ `kyber_ct_b` present.
///
/// `proposal` is the sender's ONE persisted proposal for this canonical step —
/// the single artifact carrying both the canonical and projection pairs.
///
/// `recipient_ak_pk` MUST be the recipient's already-authenticated contact
/// signing key (AK, the cert-chain genesis root) from the sender's contact book —
/// used only as the genesis predecessor when no Counterparty cert head exists yet.
/// It is NEVER used to verify `sig_b` directly.
///
/// This function does NOT mutate any state. A validly-signed receipt naming a
/// different transition is `Rejected`.
pub fn verify_acceptance_receipt(
    self_device_id: &[u8; 32],
    counterparty_device_id: &[u8; 32],
    receipt: &StitchedReceiptV2,
    proposal: &SenderOnlineProposal,
    recipient_ak_pk: &[u8],
    expected_parent_root: Option<&[u8; 32]>,
    expected_child_root: Option<&[u8; 32]>,
) -> Result<ReceiptVerifyOutcome> {
    // ---- 1-2. Structural binding: the receipt must name THIS exact transition ----
    //
    // FORMULA SPACE MATTERS HERE. The receipt's parent/child are ASYMMETRIC
    // canonical tips (DeviceState-embedded). The pending GATE stores the
    // SYMMETRIC projection pair used for routing and b0x addressing. Comparing
    // the receipt against the gate compares two different spaces and rejects a
    // perfectly valid countersignature — the exact failure that stranded
    // AWYPCNK8. The persisted proposal is the single artifact holding BOTH
    // pairs, so the canonical comparison is made against it.
    if &receipt.devid_a != self_device_id {
        return Ok(reject("receipt devid_a is not this sender"));
    }
    if &receipt.devid_b != counterparty_device_id {
        return Ok(reject("receipt devid_b is not the proposal counterparty"));
    }
    if receipt.parent_tip != proposal.canonical_parent {
        return Ok(reject(
            "receipt parent_tip != proposal canonical_parent (A-space)",
        ));
    }
    if receipt.child_tip != proposal.canonical_child {
        return Ok(reject(
            "receipt child_tip != proposal canonical_child (A-space)",
        ));
    }
    if receipt
        .compute_commitment()
        .map_err(|e| anyhow!("receipt commitment failed: {e}"))?
        != proposal.commitment
    {
        return Ok(reject("receipt commitment != proposal commitment"));
    }

    // ---- 3. Root binding against the sender's stored proposal (when known) ----
    if let Some(expected) = expected_parent_root {
        if &receipt.parent_root != expected {
            return Ok(reject("receipt parent_root != stored proposal parent_root"));
        }
    }
    if let Some(expected) = expected_child_root {
        if &receipt.child_root != expected {
            return Ok(reject("receipt child_root != stored proposal child_root"));
        }
    }

    // ---- 5. Kyber consistency (structural) ----
    if !receipt.ek_pk_b.is_empty() && receipt.kyber_ct_b.is_empty() {
        return Ok(reject(
            "receipt ek_pk_b set but kyber_ct_b missing — per-step EK derivation \
             requires both halves of the Kyber context",
        ));
    }

    // ---- 4. B-side per-step EK countersignature ----
    // From the SENDER's viewpoint the recipient (B) is the Counterparty. At
    // relationship genesis (no Counterparty head yet) ek_cert_b chains back to
    // the recipient's AK — its legitimate predecessor.
    let rel_key =
        dsm::verification::smt_replace_witness::compute_smt_key(&receipt.devid_a, &receipt.devid_b);
    let expected_prev_pk_b = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
        .ok()
        .flatten()
        .unwrap_or_else(|| recipient_ak_pk.to_vec());

    let commitment = receipt
        .compute_commitment()
        .map_err(|e| anyhow!("receipt commitment failed: {e}"))?;

    if let Err(e) = verify_per_step_ek_signing(
        receipt,
        BilateralSide::B,
        &expected_prev_pk_b,
        &receipt.parent_tip,
        &commitment,
    ) {
        return Ok(reject(&format!(
            "recipient per-step EK countersignature (sig_b) failed verification: {e}"
        )));
    }

    Ok(ReceiptVerifyOutcome::Verified { commitment })
}

fn reject(reason: &str) -> ReceiptVerifyOutcome {
    ReceiptVerifyOutcome::Rejected {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_receipt(
        a: [u8; 32],
        b: [u8; 32],
        parent: [u8; 32],
        child: [u8; 32],
    ) -> StitchedReceiptV2 {
        StitchedReceiptV2::new(
            [0u8; 32], // genesis
            a,
            b,
            parent,
            child,
            [0u8; 32], // parent_root
            [0u8; 32], // child_root
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// A proposal whose CANONICAL pair is the transition under test, and whose
    /// PROJECTION pair is deliberately DIFFERENT. Any check that reads the
    /// projection values where it should read canonical ones fails these tests —
    /// which is exactly the cross-space bug that stranded AWYPCNK8 in production.
    fn proposal(cp: [u8; 32], parent: [u8; 32], child: [u8; 32]) -> SenderOnlineProposal {
        proposal_with_commitment(cp, parent, child, [0u8; 32])
    }

    fn proposal_with_commitment(
        cp: [u8; 32],
        parent: [u8; 32],
        child: [u8; 32],
        commitment: [u8; 32],
    ) -> SenderOnlineProposal {
        SenderOnlineProposal {
            relationship_key: dsm::verification::smt_replace_witness::compute_smt_key(
                &[0x11u8; 32],
                &cp,
            ),
            canonical_parent: parent,
            canonical_child: child,
            // Divergent on purpose (symmetric routing space).
            projection_parent: [0xAAu8; 32],
            projection_target: [0xBBu8; 32],
            commitment,
            operation_digest: [0u8; 32],
            nonce_hash: [0u8; 32],
            message_id: Some("MSG-TEST".to_string()),
            tx_id: "TX-TEST".to_string(),
            counterparty_device_id: cp,
            amount: 0,
            token_id: "ERA".to_string(),
            status: "submitted".to_string(),
            created_at: 0,
        }
    }

    #[test]
    fn rejects_receipt_naming_a_different_sender() {
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let receipt = base_receipt([0x99u8; 32], b, parent, child);
        let g = proposal(b, parent, child);
        let out = verify_acceptance_receipt(&a, &b, &receipt, &g, &[0u8; 32], None, None).unwrap();
        assert!(matches!(out, ReceiptVerifyOutcome::Rejected { .. }));
    }

    #[test]
    fn rejects_receipt_with_different_parent_or_child() {
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let g = proposal(b, parent, child);
        let r1 = base_receipt(a, b, [0xEEu8; 32], child);
        assert!(matches!(
            verify_acceptance_receipt(&a, &b, &r1, &g, &[0u8; 32], None, None).unwrap(),
            ReceiptVerifyOutcome::Rejected { .. }
        ));
        let r2 = base_receipt(a, b, parent, [0xEEu8; 32]);
        assert!(matches!(
            verify_acceptance_receipt(&a, &b, &r2, &g, &[0u8; 32], None, None).unwrap(),
            ReceiptVerifyOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn rejects_receipt_with_mismatched_stored_root() {
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let receipt = base_receipt(a, b, parent, child); // roots are [0u8;32]
        let g = proposal(b, parent, child);
        let expected_parent_root = [0x77u8; 32];
        assert!(matches!(
            verify_acceptance_receipt(
                &a,
                &b,
                &receipt,
                &g,
                &[0u8; 32],
                Some(&expected_parent_root),
                None,
            )
            .unwrap(),
            ReceiptVerifyOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn rejects_static_key_receipt_without_per_step_ek_artifacts() {
        // The shape today's recipient produces: a raw sig_b with NO ek_pk_b /
        // ek_cert_b. The B-side per-step EK verifier MUST reject it — a static
        // contact-key signature is not acceptable finalization evidence.
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let mut receipt = base_receipt(a, b, parent, child);
        receipt.sig_b = vec![0xADu8; 64]; // present but no ek_pk_b/ek_cert_b
        let g = proposal(b, parent, child);
        let out =
            verify_acceptance_receipt(&a, &b, &receipt, &g, &[0x55u8; 32], None, None).unwrap();
        assert!(matches!(out, ReceiptVerifyOutcome::Rejected { .. }));
    }

    /// LIVE REGRESSION (AWYPCNK8, 2026-07-19).
    ///
    /// A structurally valid receipt whose CANONICAL pair matches the proposal
    /// must never be rejected for a tip/space reason, even though the gate's
    /// SYMMETRIC projection pair diverges wildly from it. The production bug
    /// compared the receipt's A-space tips against the gate's projection tips
    /// and fail-closed a transfer that was entirely correct.
    ///
    /// This receipt still fails later (it carries no per-step EK material), so
    /// the assertion is specifically that the rejection is NOT about parent,
    /// child, or commitment — i.e. it survived the structural binding stage.
    #[test]
    fn divergent_projection_does_not_reject_a_valid_canonical_pair() {
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let receipt = base_receipt(a, b, parent, child);
        let commitment = receipt.compute_commitment().expect("commitment");
        let p = proposal_with_commitment(b, parent, child, commitment);

        // Sanity: the proposal's projection pair is deliberately NOT the
        // canonical pair — the exact live condition.
        assert_ne!(p.projection_parent, p.canonical_parent);
        assert_ne!(p.projection_target, p.canonical_child);

        let out =
            verify_acceptance_receipt(&a, &b, &receipt, &p, &[0x55u8; 32], None, None).unwrap();
        match out {
            ReceiptVerifyOutcome::Rejected { reason } => {
                assert!(
                    !reason.contains("parent_tip")
                        && !reason.contains("child_tip")
                        && !reason.contains("commitment"),
                    "valid canonical pair must clear structural binding; \
                     rejected instead with: {reason}"
                );
            }
            ReceiptVerifyOutcome::Verified { .. } => {}
        }
    }

    /// A forged canonical child must still fail closed — retargeting the check
    /// onto the proposal tightened the comparison, it did not relax it.
    #[test]
    fn forged_canonical_child_is_rejected() {
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let receipt = base_receipt(a, b, parent, [0xEEu8; 32]);
        let commitment = receipt.compute_commitment().expect("commitment");
        let p = proposal_with_commitment(b, parent, child, commitment);
        let out =
            verify_acceptance_receipt(&a, &b, &receipt, &p, &[0x55u8; 32], None, None).unwrap();
        match out {
            ReceiptVerifyOutcome::Rejected { reason } => {
                assert!(reason.contains("child_tip"), "unexpected reason: {reason}");
            }
            ReceiptVerifyOutcome::Verified { .. } => {
                panic!("a forged canonical child must never verify")
            }
        }
    }
}
