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
//! refused, and a half that does not bind the staged one is not staged. That
//! is the correct invariant — one
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
/// wire artifact. `route` is the b0x inbox address this half was polled from;
/// it is retained on the staging row so the partner half — replayed by the
/// sender under the same frozen route — is still received after the
/// relationship tip advances. Both halves must arrive on the same route.
pub fn dispatch_transfer_half(
    correlation_key: &str,
    transfer_bytes: &[u8],
    sender_ak_pk: &[u8],
    route: &str,
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

    let state = stage_transfer_half(correlation_key, transfer_bytes, &digest, route)
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
    route: &str,
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

    let state = stage_evidence_half(correlation_key, &evidence.full_receipt_bytes, route)
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
    let acceptance = verify_and_accept(correlation_key, sender_ak_pk, apply)?.1;
    Ok(Some(acceptance))
}

/// What the poll loop is allowed to do with a pair.
///
/// The live handler must not decide this inline. Every "never ACKs" rule in the
/// design is a property of this one value, so it is computed in one place and
/// unit-tested against real durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckDecision {
    /// The pair reached `Accepted`. The acceptance kind is carried, NOT collapsed:
    /// `AcceptedFresh` is the semantic finality path, `AcceptedDuplicate` is the
    /// idempotent convergence path and must never mint a second value result.
    Ack(Acceptance),
    /// Not ACK-able, with the reason. Covers every non-accepted state — a single
    /// half, and `ready_to_verify` before apply.
    DoNotAck(String),
}

/// The whole per-pair decision: complete the pair if it is ready, then report
/// whether (and how) it may be acknowledged.
///
/// A failing apply is propagated as `Err`, deliberately distinct from
/// `DoNotAck`: the pair stays retryable and un-ACK-able, and the caller should
/// log it rather than treat it as a decision about the transfer.
pub fn decide_ack<F>(
    correlation_key: &str,
    sender_ak_pk: &[u8],
    apply: F,
) -> Result<AckDecision, String>
where
    F: FnOnce(&crate::handlers::recipient_accept::VerifiedTransfer) -> Result<ApplyOutcome, String>,
{
    let state = recipient_staging::staging_state(correlation_key)
        .map_err(|e| format!("staging state load failed for {correlation_key}: {e}"))?;

    // ALREADY ACCEPTED. This is the crash-after-apply-before-ACK window: the
    // canonical apply committed durably but the acknowledgement never went out.
    // The pair must re-ACK so the sender converges, and it must NOT re-apply —
    // so it reports Duplicate, which is exactly what a fresh apply attempt would
    // have returned anyway (the canonical apply is keyed on authenticated
    // material, not on this delivery).
    if state == StagingState::Accepted {
        return Ok(AckDecision::Ack(Acceptance::AcceptedDuplicate));
    }

    match try_complete(correlation_key, sender_ak_pk, apply)? {
        Some(acceptance) => {
            // Belt and braces: the ACK is gated on DURABLE state, never on the
            // fact that a call returned Ok.
            if !may_ack(correlation_key)? {
                return Ok(AckDecision::DoNotAck(format!(
                    "{correlation_key} reported acceptance but durable state is not Accepted"
                )));
            }
            Ok(AckDecision::Ack(acceptance))
        }
        None => Ok(AckDecision::DoNotAck(format!(
            "{correlation_key} is {} — not ACK-able",
            state.as_str()
        ))),
    }
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
    use crate::test_support::arrivals::{the_one_transfer, OneTransfer};
    use crate::test_support::two_device::Pair;
    use serial_test::serial;

    /// A sends B 10; B has not polled. The transfer's halves as B's poll
    /// reads them, with B entered.
    async fn sent() -> (Pair, OneTransfer) {
        let p = Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let one = the_one_transfer(&p.b, &p.fleet).await;
        p.b.enter();
        (p, one)
    }

    fn flipped(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let middle = out.len() / 2;
        out[middle] ^= 0xFF;
        out
    }

    fn state(key: &str) -> StagingState {
        recipient_staging::staging_state(key).expect("staging state")
    }

    /// THE ARRIVAL-ORDER PROOF. Staging is first-writer-wins and terminal
    /// rejection is sticky, so if an unverified copy could stage, whichever
    /// copy arrived first would decide the outcome. A tampered copy of the
    /// transfer arriving FIRST cannot take the slot: it is discarded and
    /// leaves no staging state, and the honest copy behind it stages and
    /// applies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_tampered_transfer_arriving_first_cannot_lock_out_the_honest_copy() {
        let (p, one) = sent().await;
        let out = dispatch_transfer_half(
            &one.key,
            &flipped(&one.transfer_bytes),
            &p.a.ak_pk,
            &one.route,
        )
        .expect("dispatch");
        assert!(
            matches!(out, DispatchOutcome::DiscardedCandidate(_)),
            "a copy that cannot prove itself is discarded, got {out:?}"
        );
        assert_eq!(
            state(&one.key),
            StagingState::Absent,
            "not even a rejection is recorded"
        );

        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        assert_eq!(p.b.era_balance(), 10, "the honest copy staged and applied");
    }

    /// The same for the evidence half, whose gate is the receipt's own SIG A
    /// — never the artifact's self-declared digest, which an attacker who
    /// rewrites the bytes rewrites too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_tampered_evidence_arriving_first_cannot_lock_out_the_honest_copy() {
        let (p, one) = sent().await;
        let out = dispatch_evidence_half(
            &one.evidence_with(flipped(&one.evidence.full_receipt_bytes)),
            &p.a.ak_pk,
            &one.evidence_route,
        )
        .expect("dispatch");
        assert!(
            matches!(out, DispatchOutcome::DiscardedCandidate(_)),
            "a tampered evidence copy is discarded, got {out:?}"
        );
        assert_eq!(state(&one.key), StagingState::Absent);

        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        assert_eq!(p.b.era_balance(), 10, "the honest copy staged and applied");
    }

    /// RAW-BYTE FREEZE: staging holds byte-for-byte what the dispatcher was
    /// handed, a re-read returns the same bytes, and that frozen pair is what
    /// verification and the apply consume.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn staging_freezes_the_exact_bytes_and_the_frozen_pair_is_what_applies() {
        let (p, one) = sent().await;
        assert!(matches!(
            dispatch_transfer_half(&one.key, &one.transfer_bytes, &p.a.ak_pk, &one.route)
                .expect("transfer"),
            DispatchOutcome::Staged(StagingState::StagedTransfer)
        ));
        assert!(matches!(
            dispatch_evidence_half(&one.evidence, &p.a.ak_pk, &one.evidence_route)
                .expect("evidence"),
            DispatchOutcome::Staged(StagingState::ReadyToVerify)
        ));
        let row = recipient_staging::get_staging(&one.key)
            .expect("load")
            .expect("row");
        assert_eq!(
            row.transfer_bytes.as_deref(),
            Some(one.transfer_bytes.as_slice()),
            "the EXACT bytes, not a re-encode"
        );
        assert_eq!(
            row.evidence_bytes.as_deref(),
            Some(one.evidence.full_receipt_bytes.as_slice())
        );
        assert_eq!(row.state, StagingState::ReadyToVerify);

        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        assert_eq!(p.b.era_balance(), 10);
        p.b.enter();
        assert_eq!(state(&one.key), StagingState::Accepted);
    }

    /// A single half never completes, and evidence the transfer does not name
    /// is not staged: neither pair can reach the apply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_single_half_or_an_unbound_half_never_completes() {
        let (p, one) = sent().await;
        assert!(matches!(
            dispatch_transfer_half(&one.key, &one.transfer_bytes, &p.a.ak_pk, &one.route)
                .expect("transfer"),
            DispatchOutcome::Staged(StagingState::StagedTransfer)
        ));
        assert_eq!(
            try_complete(&one.key, &p.a.ak_pk, |_| panic!("apply must never run"))
                .expect("complete"),
            None
        );
        assert!(!may_ack(&one.key).expect("gate"));

        // Evidence bytes the transfer does not name: the digest the transfer
        // commits to is over other bytes.
        let unbound = dispatch_evidence_half(
            &one.evidence_with(flipped(&one.evidence.full_receipt_bytes)),
            &p.a.ak_pk,
            &one.evidence_route,
        );
        assert!(
            !matches!(
                unbound,
                Ok(DispatchOutcome::Staged(StagingState::ReadyToVerify))
            ),
            "evidence the transfer does not name never completes the pair, got {unbound:?}"
        );
        assert_eq!(
            state(&one.key),
            StagingState::StagedTransfer,
            "nothing negative recorded"
        );
        assert!(matches!(
            decide_ack(&one.key, &p.a.ak_pk, |_| panic!("apply must never run")).expect("decide"),
            AckDecision::DoNotAck(_)
        ));
    }

    /// Order independence: evidence-first and transfer-first both reach
    /// ready_to_verify, and so does a poisoned transfer replica arriving
    /// ahead of the honest pair. Each order starts from an empty staging
    /// table on the same honest halves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn every_arrival_order_converges() {
        let (p, one) = sent().await;
        let clear = || {
            let binding = crate::storage::client_db::get_connection().expect("conn");
            let conn = binding
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            conn.execute("DELETE FROM recipient_staging", [])
                .expect("empty the staging table");
        };
        let transfer = || {
            let out = dispatch_transfer_half(&one.key, &one.transfer_bytes, &p.a.ak_pk, &one.route)
                .expect("transfer");
            assert!(matches!(out, DispatchOutcome::Staged(_)), "{out:?}");
        };
        let evidence = || {
            let out = dispatch_evidence_half(&one.evidence, &p.a.ak_pk, &one.evidence_route)
                .expect("evidence");
            assert!(matches!(out, DispatchOutcome::Staged(_)), "{out:?}");
        };

        transfer();
        evidence();
        assert_eq!(
            state(&one.key),
            StagingState::ReadyToVerify,
            "transfer first"
        );

        clear();
        evidence();
        transfer();
        assert_eq!(
            state(&one.key),
            StagingState::ReadyToVerify,
            "evidence first"
        );

        clear();
        assert!(matches!(
            dispatch_transfer_half(
                &one.key,
                &flipped(&one.transfer_bytes),
                &p.a.ak_pk,
                &one.route
            )
            .expect("poisoned"),
            DispatchOutcome::DiscardedCandidate(_)
        ));
        transfer();
        evidence();
        assert_eq!(
            state(&one.key),
            StagingState::ReadyToVerify,
            "a poisoned replica arriving first does not block convergence"
        );
    }
}
