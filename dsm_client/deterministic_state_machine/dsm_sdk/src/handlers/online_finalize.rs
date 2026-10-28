// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sender-side online transition finalization (§16.6): the recipient's
//! countersign, bound to the A side the sender retained.
//!
//! Protocol boundary: a DSM online transition finalizes on the sender only when
//! the sender verifies a recipient-produced acceptance receipt that binds the
//! exact transition and carries the recipient's per-step EK countersignature
//! (`sig_b`), cert-chained to the recipient's stored counterparty cert head.
//! Storage-node ACK / message deletion is transport housekeeping and is DEMOTED
//! to garbage collection — it MUST NOT determine finalization.
//!
//! That predicate is Core's,
//! [`verify_acceptance_receipt`](dsm::verification::receipt_verification::verify_acceptance_receipt),
//! judged against the predecessor this device reads with
//! [`counterparty_ek_predecessor`](crate::handlers::storage_routes::counterparty_ek_predecessor).
//! This module rebuilds the receipt it judges from the sender's own retained
//! A side and the recipient's delta. The atomic finalization commit
//! (relationship tip advance, pending-gate deletion, Local cert-head promotion,
//! Counterparty cert-head advance to `ek_pk_b`, receipt persistence, and the
//! finalized marker, as ONE recoverable state transition) is a durable-journal-
//! first operation implemented separately, so a crash cannot leave a transfer
//! "finalized" with its cert heads or evidence missing.

use crate::storage::client_db::sender_proposal::SenderOnlineProposal;
use anyhow::{anyhow, Result};
use dsm::types::receipt_types::StitchedReceiptV2;

// ============================================================================
// ADR 0003 return leg — reconstruct the countersigned receipt from what the
// sender ALREADY holds plus the recipient's B-side delta.
//
// The recipient never ships the whole receipt back (218 KB, over the node
// cap). It ships `ReceiptCountersignB`: the four B-side fields plus two
// references. The sender overlays those onto the A-side receipt it authored
// and froze at send time (`sender_outbox_artifacts`, role `evidence_a`) and
// then runs Core's acceptance verifier on it. That reconstruction is the
// load-bearing binding: B material is only ever judged against the A side the
// sender itself produced, so no delta can be accepted "for" foreign A bytes.
// The delta's `receipt_evidence_digest_a` is advisory consistency evidence
// (nothing B signs covers it); a mismatch parks the step, it authenticates
// nothing.
// ============================================================================

/// The A-side evidence the sender froze at send time — the exact bytes the
/// recipient countersigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedEvidenceA {
    /// `ReceiptEvidenceA.full_receipt_bytes` as frozen in the outbox artifact.
    pub full_receipt_bytes: Vec<u8>,
    /// `sender_outbox_artifacts.content_digest` for that row — role-separated
    /// BLAKE3 over `full_receipt_bytes`, computed at send time.
    pub content_digest: [u8; 32],
}

/// Load the proposal's frozen A-side evidence from `sender_outbox_artifacts`.
///
/// `Ok(None)` means the proposal has NO evidence_a row. On a clean install
/// that cannot happen — the artifact is committed in the same transaction as
/// the proposal — so callers treat it as an invariant violation, not a
/// transient: nothing will ever create that row later, and without it the
/// step can never finalize.
pub fn load_retained_evidence_a(
    proposal: &SenderOnlineProposal,
) -> Result<Option<RetainedEvidenceA>> {
    use crate::storage::client_db::sender_outbox::{load_sender_outbox_artifacts, ArtifactRole};
    use prost::Message;

    let artifacts = load_sender_outbox_artifacts(
        &proposal.relationship_key,
        &proposal.canonical_parent,
        &proposal.nonce_hash,
    )?;
    let Some(row) = artifacts
        .into_iter()
        .find(|a| a.role == ArtifactRole::EvidenceA)
    else {
        return Ok(None);
    };
    let env = dsm::types::proto::Envelope::decode(row.envelope_bytes.as_slice())
        .map_err(|e| anyhow!("retained evidence_a envelope does not decode: {e}"))?;
    let Some(evidence) = crate::sdk::b0x_sdk::B0xSDK::decode_receipt_evidence_a(&env) else {
        return Err(anyhow!(
            "retained evidence_a envelope carries no receipt.evidence.a invoke"
        ));
    };
    Ok(Some(RetainedEvidenceA {
        full_receipt_bytes: evidence.full_receipt_bytes,
        content_digest: row.content_digest,
    }))
}

/// The reconstructed countersigned receipt plus the delta-only metadata the
/// verifier needs: the recipient's canonical pair, authenticated by `sig_b`.
#[derive(Debug, Clone)]
pub struct BoundCountersignDelta {
    pub receipt: StitchedReceiptV2,
    pub b_parent_tip: [u8; 32],
    pub b_child_tip: [u8; 32],
}

impl BoundCountersignDelta {
    pub fn b_pair(&self) -> ([u8; 32], [u8; 32]) {
        (self.b_parent_tip, self.b_child_tip)
    }
}

/// Result of overlaying a delta onto the retained A side.
#[derive(Debug)]
pub enum DeltaBinding {
    /// The reconstructed countersigned receipt (+ pair), ready for the verifier.
    Bound(Box<BoundCountersignDelta>),
    /// The delta names A bytes other than the ones this sender retained. The
    /// step is parked exactly like a verifier rejection: this artifact proved
    /// nothing, and an honest one for the same commitment can still arrive.
    Rejected { reason: String },
}

/// Overlay `delta` onto `retained`. `Err` means the SENDER's own state is
/// unusable (its retained bytes do not match their stored digest, or are not
/// an A-side receipt) — that is local corruption, and nothing is written.
pub fn bind_countersign_delta(
    retained: &RetainedEvidenceA,
    delta: &dsm::types::proto::ReceiptCountersignB,
) -> Result<DeltaBinding> {
    use crate::storage::client_db::sender_outbox::{evidence_content_digest, ArtifactRole};
    use dsm::types::receipt_types::CountersignB;

    let recomputed = evidence_content_digest(ArtifactRole::EvidenceA, &retained.full_receipt_bytes);
    if recomputed != retained.content_digest {
        return Err(anyhow!(
            "retained evidence_a bytes ({} B) do not match their stored digest ({} vs {}) — \
             local artifact corruption",
            retained.full_receipt_bytes.len(),
            crate::util::text_id::encode_base32_crockford(&recomputed),
            crate::util::text_id::encode_base32_crockford(&retained.content_digest),
        ));
    }
    if delta.receipt_evidence_digest_a.as_slice() != recomputed.as_slice() {
        return Ok(DeltaBinding::Rejected {
            reason: format!(
                "delta names A-side evidence {} but this sender retained {} ({} B)",
                crate::util::text_id::encode_base32_crockford(&delta.receipt_evidence_digest_a),
                crate::util::text_id::encode_base32_crockford(&recomputed),
                retained.full_receipt_bytes.len(),
            ),
        });
    }
    let a_side = StitchedReceiptV2::from_canonical_protobuf(&retained.full_receipt_bytes)
        .map_err(|e| anyhow!("retained evidence_a is not a decodable receipt: {e}"))?;
    let full = a_side
        .with_countersign_b(CountersignB::from_wire(delta))
        .map_err(|e| anyhow!("retained evidence_a cannot take a countersign overlay: {e}"))?;
    // The strict wire decoder already required both tips at exactly 32 bytes;
    // this conversion is the type boundary, not a second validation.
    let b_parent_tip: [u8; 32] = delta
        .b_parent_tip
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("delta b_parent_tip is not 32 bytes"))?;
    let b_child_tip: [u8; 32] = delta
        .b_child_tip
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("delta b_child_tip is not 32 bytes"))?;
    Ok(DeltaBinding::Bound(Box::new(BoundCountersignDelta {
        receipt: full,
        b_parent_tip,
        b_child_tip,
    })))
}

#[cfg(test)]
mod tests {
    /// A readable, empty client store.
    fn with_a_store() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
    }

    /// The counterparty head table, out of reach until dropped: every read of
    /// a head fails while it is held.
    struct HeadsUnreadable;
    impl HeadsUnreadable {
        fn hide() -> Self {
            crate::storage::client_db::get_connection()
                .expect("the store")
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .execute_batch("ALTER TABLE cert_chain_heads RENAME TO cert_chain_heads_unreadable")
                .expect("hide the head table");
            Self
        }
    }
    impl Drop for HeadsUnreadable {
        fn drop(&mut self) {
            let restored = crate::storage::client_db::get_connection().and_then(|conn| {
                conn.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .execute_batch(
                        "ALTER TABLE cert_chain_heads_unreadable RENAME TO cert_chain_heads",
                    )
                    .map_err(anyhow::Error::from)
            });
            if let Err(e) = restored {
                eprintln!("the head table was not restored; later tests will fail on it: {e}");
            }
        }
    }

    /// The key the counterparty's next `ek_cert` must chain to, as this device
    /// reads it: the counterparty's AK while no head is stored for the
    /// relationship, and the stored head once there is one, whatever AK is
    /// offered.
    #[test]
    #[serial_test::serial]
    fn the_counterparty_predecessor_is_its_stored_head_and_its_ak_only_before_one() {
        with_a_store();
        let (rel_key, ak, head) = ([0x5Cu8; 32], [0x55u8; 64], [0xE1u8; 64]);
        let predecessor = || {
            crate::handlers::storage_routes::counterparty_ek_predecessor(&rel_key, &ak)
                .expect("a readable store answers")
        };
        assert_eq!(predecessor(), ak.to_vec(), "no head stored: the AK");
        crate::storage::client_db::cas_advance_counterparty_cert_chain_head(&rel_key, None, &head)
            .expect("the head is stored");
        assert_eq!(predecessor(), head.to_vec(), "a head stored: the head");
    }

    /// Storage spec §4: a counterparty cert-chain head that could not be READ
    /// is not "no head yet". Neither verifier judges the chain against the
    /// root AK: the sender's read of the predecessor it checks the
    /// recipient's countersignature against is an error (the delta is
    /// retried), never the AK; the recipient's check of the sender's
    /// signature names the unreadable head. With the store readable again and
    /// no head stored, the predecessor is the AK, and the same inputs reach
    /// the chain check itself.
    #[test]
    #[serial_test::serial]
    fn an_unreadable_counterparty_head_is_never_read_as_genesis() {
        use crate::test_support::receipts::{transfer_step, Party};
        with_a_store();
        let receipt = transfer_step(&Party::from_seed(0x31), &Party::from_seed(0x32), 7).receipt;
        let commitment = receipt.compute_commitment().expect("commitment");
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &receipt.devid_a,
            &receipt.devid_b,
        );
        let ak = [0x55u8; 64];
        let predecessor =
            || crate::handlers::storage_routes::counterparty_ek_predecessor(&rel_key, &ak);
        let sig_a = || {
            crate::handlers::storage_routes::verify_inbound_receipt_sig_a(
                &receipt,
                &commitment,
                &ak,
            )
        };
        {
            let _hidden = HeadsUnreadable::hide();
            let err = predecessor().expect_err("an unreadable head is not a verdict");
            assert!(err.contains("could not be read"), "{err}");
            let err = sig_a().expect_err("an unreadable head is not a verdict");
            assert!(err.contains("could not be read"), "{err}");
        }
        assert_eq!(
            predecessor().expect("readable again"),
            ak.to_vec(),
            "with no head stored, the predecessor is the AK"
        );
        let err = sig_a()
            .expect("readable again: the check can be made")
            .expect_err("no per-step EK material in this receipt");
        assert!(!err.contains("could not be read"), "{err}");
    }
}
