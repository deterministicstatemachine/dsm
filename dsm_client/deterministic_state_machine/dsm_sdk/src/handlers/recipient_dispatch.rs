// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR 0003 step 3c: dispatch polled halves into recipient staging.
//!
//! Fetch and decode happen in `b0x_sdk` (explicit invoke methods, never a
//! trial-decode). This module owns the decision of what is allowed to OCCUPY a
//! staging slot, and it enforces one rule that is not obvious:
//!
//! # Verify BEFORE the bytes take the slot
//!
//! [`recipient_staging::stage_transfer_half`] is first-writer-wins on the
//! correlation key: the first bytes to arrive own the slot, a divergent copy is
//! refused, and `TerminalReject` is sticky. That is the correct invariant — one
//! correlation key names one commitment — but it makes ARRIVAL ORDER decide the
//! outcome if unverified bytes are allowed to stage.
//!
//! That matters now specifically because the cross-endpoint merge deliberately
//! stopped collapsing divergent copies of one message id (it was
//! first-responder-wins, which let a single replica shadow honest copies on
//! every poll, forever). Divergent copies now BOTH arrive, by design. If a
//! tampered copy could stage first, it would take the slot, permanently refuse
//! the honest copy sitting in the same batch, fail verification, and stick at
//! terminal reject — reproducing on the recipient exactly the wedge that was
//! just removed from the sender.
//!
//! So each half is authenticated on its own, against the LOCALLY TRUSTED sender
//! AK, before it is offered to staging:
//!
//! - transfer half — SIG A over `canonical_operation_bytes`;
//! - evidence half — the receipt's own SIG A over its commitment.
//!
//! Neither check needs the other half, and neither trusts the unsigned digest
//! reference. A tampered copy is discarded as a CANDIDATE and never becomes
//! staging state, so the honest copy stages normally regardless of order.

use crate::handlers::recipient_accept::{verify_and_accept, Acceptance};
use crate::sdk::apply_outcome::ApplyOutcome;
use crate::storage::client_db::recipient_staging::{
    self, stage_evidence_half, stage_transfer_half, StagingState,
};
use dsm::types::receipt_types::StitchedReceiptV2;
use prost::Message;

/// What a polled half did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Authenticated and staged; the pair is not complete yet.
    Staged(StagingState),
    /// Both halves present, verified, and canonically applied.
    Accepted(Acceptance),
    /// The candidate failed its OWN signature check and was discarded without
    /// touching staging. Deliberately not a terminal reject: no slot was taken,
    /// so an honest copy of the same half can still arrive and stage.
    DiscardedCandidate(String),
}

/// Authenticate a candidate transfer half, then stage it.
///
/// `sender_ak_pk` MUST come from the locally stored contact — never from the
/// wire artifact.
pub fn dispatch_transfer_half(
    correlation_key: &str,
    transfer_bytes: &[u8],
    sender_ak_pk: &[u8],
) -> Result<DispatchOutcome, String> {
    let req = match dsm::types::proto::OnlineTransferRequest::decode(transfer_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Ok(DispatchOutcome::DiscardedCandidate(format!(
                "transfer half for {correlation_key} does not decode: {e}"
            )))
        }
    };
    if req.canonical_operation_bytes.is_empty() {
        return Ok(DispatchOutcome::DiscardedCandidate(format!(
            "transfer half for {correlation_key} carries no canonical_operation_bytes"
        )));
    }
    // The candidate gate. A copy that cannot prove itself never reaches storage.
    if let Err(e) = dsm::types::operations::Operation::decode_and_bind_signed(
        &req.canonical_operation_bytes,
        &req.signature,
        sender_ak_pk,
    ) {
        return Ok(DispatchOutcome::DiscardedCandidate(format!(
            "transfer half for {correlation_key} failed SIG A: {e}"
        )));
    }

    let digest: [u8; 32] = req
        .receipt_evidence_digest
        .as_slice()
        .try_into()
        .map_err(|_| {
            format!("transfer half for {correlation_key} has a malformed evidence reference")
        })?;

    let state = stage_transfer_half(correlation_key, transfer_bytes, &digest)
        .map_err(|e| format!("staging the transfer half for {correlation_key} failed: {e}"))?;
    Ok(DispatchOutcome::Staged(state))
}

/// Authenticate a candidate evidence half, then stage it.
///
/// The artifact's self-declared digest is NOT trusted as authentication — an
/// attacker who rewrites the bytes can rewrite that field too. What cannot be
/// forged without the sender's AK is the receipt's own SIG A, so that is the
/// gate. The digest BINDING to the transfer half is re-checked later, by
/// `verify_staged_transfer`, against the frozen bytes.
pub fn dispatch_evidence_half(
    evidence: &dsm::types::proto::ReceiptEvidenceA,
    sender_ak_pk: &[u8],
) -> Result<DispatchOutcome, String> {
    let correlation_key = evidence.transfer_submission_id.as_str();
    if correlation_key.is_empty() {
        return Ok(DispatchOutcome::DiscardedCandidate(
            "evidence half names no transfer submission id".to_string(),
        ));
    }

    let receipt = match StitchedReceiptV2::from_canonical_protobuf(&evidence.full_receipt_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Ok(DispatchOutcome::DiscardedCandidate(format!(
                "evidence half for {correlation_key} does not decode: {e}"
            )))
        }
    };
    let commitment = match receipt.compute_commitment() {
        Ok(c) => c,
        Err(e) => {
            return Ok(DispatchOutcome::DiscardedCandidate(format!(
                "evidence half for {correlation_key}: commitment failed: {e}"
            )))
        }
    };
    if let Err(e) =
        super::storage_routes::verify_inbound_receipt_sig_a(&receipt, &commitment, sender_ak_pk)
    {
        return Ok(DispatchOutcome::DiscardedCandidate(format!(
            "evidence half for {correlation_key} failed the receipt chain: {e}"
        )));
    }

    let state = stage_evidence_half(correlation_key, &evidence.full_receipt_bytes)
        .map_err(|e| format!("staging the evidence half for {correlation_key} failed: {e}"))?;
    Ok(DispatchOutcome::Staged(state))
}

/// Complete a pair that has both halves: verify, canonically apply, accept.
///
/// Returns `None` when the pair is not `ready_to_verify`, so the caller can keep
/// polling without treating an incomplete pair as an error.
pub fn try_complete<F>(
    correlation_key: &str,
    sender_ak_pk: &[u8],
    apply: F,
) -> Result<Option<Acceptance>, String>
where
    F: FnOnce(&crate::handlers::recipient_accept::VerifiedTransfer) -> Result<ApplyOutcome, String>,
{
    let state = recipient_staging::staging_state(correlation_key)
        .map_err(|e| format!("staging state load failed for {correlation_key}: {e}"))?;
    if state != StagingState::ReadyToVerify {
        return Ok(None);
    }
    let (_verified, acceptance) = verify_and_accept(correlation_key, sender_ak_pk, apply)?;
    Ok(Some(acceptance))
}

/// Whether a completed pair may be acknowledged on the wire.
///
/// The ACK decision is deliberately NOT `outcome.is_ok()`. Only a pair that
/// reached `Accepted` in durable staging may be acknowledged, and the
/// fresh/duplicate distinction is carried through so the caller cannot collapse
/// a converged retry into a second value-bearing acknowledgement by accident.
pub fn may_ack(correlation_key: &str) -> Result<bool, String> {
    recipient_staging::staging_state(correlation_key)
        .map(|s| s.may_ack())
        .map_err(|e| format!("staging state load failed for {correlation_key}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::recipient_accept::tests::{setup, signed_receipt_bytes, signed_transfer_bytes};
    use crate::storage::client_db::{evidence_content_digest, ArtifactRole};
    use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
    use serial_test::serial;

    /// Build an honest pair plus a TAMPERED copy of each half.
    /// Returns `(ak_pk, transfer, evidence, tampered_transfer, tampered_evidence)`.
    #[allow(clippy::type_complexity)]
    fn pair() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        setup();
        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC4; 32]).expect("ak");
        let evidence = signed_receipt_bytes(&ak_pk, &ak_sk);
        let digest = evidence_content_digest(ArtifactRole::EvidenceA, &evidence);
        let transfer = signed_transfer_bytes(&ak_sk, &digest);

        // A middlebox flips bytes in each half. Neither can be re-signed without
        // the sender's AK, which is exactly what the candidate gate tests.
        let mut bad_transfer = transfer.clone();
        let n = bad_transfer.len();
        bad_transfer[n / 2] ^= 0xFF;
        let mut bad_evidence = evidence.clone();
        let m = bad_evidence.len();
        bad_evidence[m / 2] ^= 0xFF;

        (ak_pk, transfer, evidence, bad_transfer, bad_evidence)
    }

    fn evidence_artifact(key: &str, bytes: &[u8]) -> dsm::types::proto::ReceiptEvidenceA {
        dsm::types::proto::ReceiptEvidenceA {
            transfer_submission_id: key.to_string(),
            receipt_evidence_digest: evidence_content_digest(ArtifactRole::EvidenceA, bytes)
                .to_vec(),
            full_receipt_bytes: bytes.to_vec(),
        }
    }

    /// THE ARRIVAL-ORDER PROOF.
    ///
    /// Staging is first-writer-wins and terminal rejection is sticky, so if an
    /// unverified copy could stage, whichever copy arrived first would decide the
    /// outcome. Divergent copies now BOTH arrive by design (the cross-endpoint
    /// merge stopped collapsing them). A tampered copy arriving FIRST must not be
    /// able to take the slot and lock out the honest copy behind it.
    #[test]
    #[serial]
    fn a_tampered_transfer_arriving_first_cannot_lock_out_the_honest_copy() {
        let key = "DISP-ORDER-T";
        let (ak_pk, transfer, evidence, bad_transfer, _) = pair();

        // Tampered copy arrives FIRST.
        let out = dispatch_transfer_half(key, &bad_transfer, &ak_pk).expect("dispatch");
        assert!(
            matches!(out, DispatchOutcome::DiscardedCandidate(ref r) if r.contains("SIG A")
                || r.contains("does not decode")),
            "a copy that cannot prove itself must be discarded, got {out:?}"
        );
        assert_eq!(
            recipient_staging::staging_state(key).expect("state"),
            StagingState::Absent,
            "a discarded candidate must leave NO staging state -- not even a rejection"
        );

        // The honest copy, right behind it in the same batch, still stages.
        assert!(matches!(
            dispatch_transfer_half(key, &transfer, &ak_pk).expect("dispatch"),
            DispatchOutcome::Staged(_)
        ));
        assert!(matches!(
            dispatch_evidence_half(&evidence_artifact(key, &evidence), &ak_pk).expect("dispatch"),
            DispatchOutcome::Staged(StagingState::ReadyToVerify)
        ));
    }

    /// Same property for the evidence half, whose gate is the receipt's own SIG A
    /// rather than the artifact's self-declared digest (an attacker who rewrites
    /// the bytes rewrites that field too, so it authenticates nothing).
    #[test]
    #[serial]
    fn a_tampered_evidence_arriving_first_cannot_lock_out_the_honest_copy() {
        let key = "DISP-ORDER-E";
        let (ak_pk, transfer, evidence, _, bad_evidence) = pair();

        let out =
            dispatch_evidence_half(&evidence_artifact(key, &bad_evidence), &ak_pk).expect("d");
        assert!(
            matches!(out, DispatchOutcome::DiscardedCandidate(_)),
            "a tampered evidence copy must be discarded, got {out:?}"
        );
        assert_eq!(
            recipient_staging::staging_state(key).expect("state"),
            StagingState::Absent
        );

        assert!(matches!(
            dispatch_evidence_half(&evidence_artifact(key, &evidence), &ak_pk).expect("d"),
            DispatchOutcome::Staged(_)
        ));
        assert!(matches!(
            dispatch_transfer_half(key, &transfer, &ak_pk).expect("d"),
            DispatchOutcome::Staged(StagingState::ReadyToVerify)
        ));
    }

    /// The happy path end to end through dispatch, and the ACK gate.
    #[test]
    #[serial]
    fn an_honest_pair_dispatches_verifies_and_becomes_ack_able() {
        let key = "DISP-OK";
        let (ak_pk, transfer, evidence, _, _) = pair();

        dispatch_transfer_half(key, &transfer, &ak_pk).expect("t");
        dispatch_evidence_half(&evidence_artifact(key, &evidence), &ak_pk).expect("e");

        assert!(
            !may_ack(key).expect("ack gate"),
            "not ACK-able before accept"
        );

        let acceptance = try_complete(key, &ak_pk, |_| {
            Ok(ApplyOutcome::AlreadyAppliedSameOperation {
                record: crate::storage::client_db::CanonicalApplyRecord {
                    relationship_key: [0x01; 32],
                    parent_tip: [0x02; 32],
                    child_tip: [0x03; 32],
                    precommit_digest: [0x04; 32],
                    operation_digest: [0x05; 32],
                    sender_device: [0x06; 32],
                    recipient_device: [0x07; 32],
                    nonce_hash: [0x08; 32],
                    applied_parent_root_b: [0x09; 32],
                    applied_child_root_b: [0x0A; 32],
                },
            })
        })
        .expect("complete")
        .expect("ready");
        assert_eq!(acceptance, Acceptance::AcceptedDuplicate);
        assert!(
            may_ack(key).expect("ack gate"),
            "ACK-able only after accept"
        );
    }

    /// A single half never completes and never becomes ACK-able.
    #[test]
    #[serial]
    fn one_half_never_completes_and_never_acks() {
        let key = "DISP-HALF";
        let (ak_pk, transfer, _, _, _) = pair();
        dispatch_transfer_half(key, &transfer, &ak_pk).expect("t");
        assert_eq!(
            try_complete(key, &ak_pk, |_| panic!("apply must never run")).expect("complete"),
            None
        );
        assert!(!may_ack(key).expect("ack gate"));
    }
}
