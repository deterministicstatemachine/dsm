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
use crate::storage::client_db::types::PendingOnlineOutboxRecord;
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
///  2. `receipt.parent_tip == gate.parent_tip` and `receipt.child_tip == gate.next_tip`;
///  3. `expected_parent_root` / `expected_child_root`, when known from the
///     sender's stored proposal, equal the receipt's roots (pass `None` to skip
///     until proposal storage lands — a `Some` mismatch is a hard reject);
///  4. B-side per-step EK: `ek_cert_b` chains `ek_pk_b` back to the sender's
///     stored Counterparty (recipient) cert head over `h_n` (or `recipient_ak_pk`
///     at relationship genesis), then `sig_b` verifies under `ek_pk_b`;
///  5. Kyber consistency: `ek_pk_b` present ⇒ `kyber_ct_b` present.
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
    gate: &PendingOnlineOutboxRecord,
    recipient_ak_pk: &[u8],
    expected_parent_root: Option<&[u8; 32]>,
    expected_child_root: Option<&[u8; 32]>,
) -> Result<ReceiptVerifyOutcome> {
    // ---- 1-2. Structural binding: the receipt must name THIS exact transition ----
    let gate_parent: [u8; 32] = gate
        .parent_tip
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("gate parent_tip is not 32 bytes"))?;
    let gate_next: [u8; 32] = gate
        .next_tip
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("gate next_tip is not 32 bytes"))?;

    if &receipt.devid_a != self_device_id {
        return Ok(reject("receipt devid_a is not this sender"));
    }
    if &receipt.devid_b != counterparty_device_id {
        return Ok(reject("receipt devid_b is not the gate counterparty"));
    }
    if receipt.parent_tip != gate_parent {
        return Ok(reject("receipt parent_tip != gate parent_tip"));
    }
    if receipt.child_tip != gate_next {
        return Ok(reject("receipt child_tip != gate next_tip"));
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
    use crate::storage::client_db::types::PendingOnlineOutboxRecord;

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

    fn gate(cp: [u8; 32], parent: [u8; 32], next: [u8; 32]) -> PendingOnlineOutboxRecord {
        PendingOnlineOutboxRecord {
            counterparty_device_id: cp.to_vec(),
            message_id: "MSG-TEST".to_string(),
            parent_tip: parent.to_vec(),
            next_tip: next.to_vec(),
            created_at: 0,
        }
    }

    #[test]
    fn rejects_receipt_naming_a_different_sender() {
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let receipt = base_receipt([0x99u8; 32], b, parent, child);
        let g = gate(b, parent, child);
        let out = verify_acceptance_receipt(&a, &b, &receipt, &g, &[0u8; 32], None, None).unwrap();
        assert!(matches!(out, ReceiptVerifyOutcome::Rejected { .. }));
    }

    #[test]
    fn rejects_receipt_with_different_parent_or_child() {
        let (a, b, parent, child) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);
        let g = gate(b, parent, child);
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
        let g = gate(b, parent, child);
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
        let g = gate(b, parent, child);
        let out =
            verify_acceptance_receipt(&a, &b, &receipt, &g, &[0x55u8; 32], None, None).unwrap();
        assert!(matches!(out, ReceiptVerifyOutcome::Rejected { .. }));
    }
}
