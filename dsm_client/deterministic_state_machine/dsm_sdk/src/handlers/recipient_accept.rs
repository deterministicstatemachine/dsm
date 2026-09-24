// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR 0003 step 3b: verification and canonical apply for a staged split
//! transfer.
//!
//! The load-bearing invariant, in order:
//!
//! ```text
//! ready_to_verify
//!   -> digest binds the FROZEN evidence bytes
//!   -> SIG A verifies the FROZEN canonical_operation_bytes
//!   -> SIG B / SIG C receipt chain verifies the FROZEN receipt evidence
//!   -> canonical apply succeeds
//!   -> accepted committed
//!   -> may_ack() == true
//! ```
//!
//! If any step fails the transfer must never partially apply and must never
//! become ACK-able. Failure leaves the row in `ready_to_verify` and records
//! nothing (DSM Amendment A1, MR-DSM-0018): a transient apply failure can
//! succeed later, and a digest or signature that does not bind never will.
//!
//! **What the staged halves are.** The `transfer` half is the
//! `OnlineTransferRequest` bytes and the `evidence` half is the full
//! `ReceiptCommit` wire bytes — the *semantic* artifacts, not their transport
//! envelopes. That is deliberate: the sender's digest is computed over
//! `receipt_commit_bytes`, so staging the receipt makes the digest bind exactly
//! the bytes whose signatures are verified here. Unwrapping the envelopes is 3c's
//! job.
//!
//! **Parsing frozen bytes is fine; substituting them is not.** Verification must
//! decode the staged bytes to reach the fields it checks. What must never happen
//! is verifying a re-encoded replacement and treating that as equivalent to what
//! arrived — the whole point of freezing the bytes in 3a.
//!
//! Retrieval, polling, method dispatch and the B-side return transport are 3c.

use dsm::types::operations::Operation;
use dsm::types::receipt_types::StitchedReceiptV2;
use prost::Message;

use crate::storage::client_db::recipient_staging::{self, StagingRecord, StagingState};

/// What verification established. Every field here is derived from FROZEN
/// staged bytes.
#[derive(Debug, Clone)]
pub struct VerifiedTransfer {
    pub correlation_key: String,
    /// The ONLY trusted operation. Sourced from `decode_and_bind_signed`, never
    /// from the reconstructed protobuf fields.
    pub signed_op: Operation,
    /// The exact signed bytes `signed_op` was bound from. Carried so the
    /// canonical apply — which hashes them into the apply identity — receives
    /// the bytes that were verified, not a re-read of staging.
    pub canonical_operation_bytes: Vec<u8>,
    /// The receipt whose `sig_a` / `ek_cert_a` chain verified.
    pub receipt: StitchedReceiptV2,
}

/// How a staged transfer was accepted. A successful apply has TWO semantically
/// different outcomes and they must not collapse into one.
///
/// ```text
/// Fresh                        -> canonical apply executed      -> AcceptedFresh
/// AlreadyAppliedSameOperation  -> NO re-execution, converged     -> AcceptedDuplicate
/// Conflict                     -> fail closed                    -> not accepted
/// ```
///
/// `AcceptedDuplicate` is NOT an error: a legitimate retry after a lost ACK has
/// to converge. It is also NOT permission to manufacture a second value-bearing
/// result keyed only by the new correlation id. 3c decides what an ACK for each
/// looks like; this type exists so that decision cannot be made by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// The canonical apply executed for the first time.
    AcceptedFresh,
    /// The exact operation identity was already applied. Converged from the
    /// stored canonical record; nothing re-executed and nothing re-credited.
    AcceptedDuplicate,
}

/// Verify a staged transfer, run the caller's canonical apply, and only then
/// transition to `accepted`.
///
/// The apply returns an [`ApplyOutcome`], not `()`. That is deliberate: the
/// canonical apply is keyed on AUTHENTICATED material — `canonical_apply_id`
/// hashes the relationship, tips, precommit and operation digests, both device
/// ids and the nonce, none of which is transport metadata — so replaying the
/// same signed operation under a fresh correlation id returns
/// `AlreadyAppliedSameOperation` rather than applying twice. If this boundary
/// were `Result<(), _>`, that outcome would be indistinguishable from a fresh
/// apply and 3c could mint a second finality object for one semantic transfer.
///
/// Ordering: `mark_accepted` runs only after the apply reports success. A
/// failing apply or a `Conflict` leaves the row `ready_to_verify` —
/// un-ACK-able, and recorded nowhere.
pub fn verify_and_accept<F>(
    correlation_key: &str,
    sender_ak_pk: &[u8],
    apply: F,
) -> Result<(VerifiedTransfer, Acceptance), String>
where
    F: FnOnce(&VerifiedTransfer) -> Result<crate::sdk::apply_outcome::ApplyOutcome, String>,
{
    let verified = verify_staged_transfer(correlation_key, sender_ak_pk)?;

    let outcome = apply(&verified).map_err(|e| {
        // The cryptography held, so this is a local failure to apply. The row
        // stays `ready_to_verify`: retryable and un-ACK-able.
        format!("canonical apply failed for {correlation_key} (not accepted, retryable): {e}")
    })?;

    let acceptance = match outcome {
        crate::sdk::apply_outcome::ApplyOutcome::Applied { .. } => Acceptance::AcceptedFresh,
        crate::sdk::apply_outcome::ApplyOutcome::AlreadyAppliedSameOperation { .. } => {
            Acceptance::AcceptedDuplicate
        }
        // A conflicting identity reusing this (relationship, parent) or nonce
        // cannot become valid by being retried; it stays unaccepted.
        crate::sdk::apply_outcome::ApplyOutcome::Conflict { reason } => {
            return Err(refused(
                correlation_key,
                format!("canonical apply conflict: {reason}"),
            ));
        }
    };

    recipient_staging::mark_accepted(correlation_key)
        .map_err(|e| format!("accept transition failed for {correlation_key}: {e}"))?;

    Ok((verified, acceptance))
}

/// The verification half, with no apply and no state transition.
///
/// A failure — a digest or signature that does not bind, or an inability to
/// proceed — is returned and recorded nowhere: the state is left alone.
pub fn verify_staged_transfer(
    correlation_key: &str,
    sender_ak_pk: &[u8],
) -> Result<VerifiedTransfer, String> {
    let rec = recipient_staging::get_staging(correlation_key)
        .map_err(|e| format!("staging load failed for {correlation_key}: {e}"))?
        .ok_or_else(|| format!("no staged transfer for {correlation_key}"))?;

    if rec.state != StagingState::ReadyToVerify {
        return Err(format!(
            "refusing to verify {correlation_key} from state {}; both halves must be \
             present and digest-bound first",
            rec.state.as_str()
        ));
    }

    let (transfer_bytes, evidence_bytes) = frozen_halves(&rec)?;

    // ---- 1. the digest must bind the FROZEN evidence bytes ----
    //
    // 3a already bound this when the second half landed. Re-checking here is
    // not redundant: it means verification never trusts a state transition that
    // happened earlier, only the bytes in front of it.
    let expected = rec.expected_evidence_digest.ok_or_else(|| {
        format!("{correlation_key} is ready_to_verify without an evidence reference")
    })?;
    let actual = crate::storage::client_db::evidence_content_digest(
        crate::storage::client_db::ArtifactRole::EvidenceA,
        evidence_bytes,
    );
    if actual != expected {
        return Err(refused(
            correlation_key,
            format!(
                "evidence digest does not bind the frozen bytes: expected {}, got {}",
                crate::util::text_id::encode_base32_crockford(&expected),
                crate::util::text_id::encode_base32_crockford(&actual)
            ),
        ));
    }

    // ---- 2. SIG A over the FROZEN canonical operation bytes ----
    let req = dsm::types::proto::OnlineTransferRequest::decode(transfer_bytes).map_err(|e| {
        refused(
            correlation_key,
            format!("transfer half does not decode: {e}"),
        )
    })?;

    if req.canonical_operation_bytes.is_empty() {
        return Err(refused(
            correlation_key,
            "transfer carries no canonical_operation_bytes; there is nothing SIG A could bind"
                .to_string(),
        ));
    }
    // The reconstructed protobuf fields are UNTRUSTED. `signed_op` is the only
    // operation any downstream credit may be sourced from.
    let signed_op = Operation::decode_and_bind_signed(
        &req.canonical_operation_bytes,
        &req.signature,
        sender_ak_pk,
    )
    .map_err(|e| refused(correlation_key, format!("SIG A does not verify: {e}")))?;

    // ---- 3. the receipt chain over the FROZEN evidence bytes ----
    let receipt = StitchedReceiptV2::from_canonical_protobuf(evidence_bytes)
        .map_err(|e| refused(correlation_key, format!("evidence does not decode: {e}")))?;
    let commitment = receipt
        .compute_commitment()
        .map_err(|e| refused(correlation_key, format!("receipt commitment failed: {e}")))?;
    super::storage_routes::verify_inbound_receipt_sig_a(&receipt, &commitment, sender_ak_pk)
        .map_err(|e| {
            refused(
                correlation_key,
                format!("receipt chain does not verify: {e}"),
            )
        })?;

    Ok(VerifiedTransfer {
        correlation_key: correlation_key.to_string(),
        signed_op,
        canonical_operation_bytes: req.canonical_operation_bytes,
        receipt,
    })
}

/// Borrow both frozen halves, or explain which is missing.
fn frozen_halves(rec: &StagingRecord) -> Result<(&[u8], &[u8]), String> {
    let t = rec.transfer_bytes.as_deref().ok_or_else(|| {
        format!(
            "{} is ready_to_verify without a transfer half",
            rec.correlation_key
        )
    })?;
    let e = rec.evidence_bytes.as_deref().ok_or_else(|| {
        format!(
            "{} is ready_to_verify without an evidence half",
            rec.correlation_key
        )
    })?;
    Ok((t, e))
}

/// The message for a pair that does not verify or apply. Nothing is recorded
/// (DSM Amendment A1, MR-DSM-0018): the halves stay staged as raw material,
/// and a pair whose digest or signatures do not bind stays unaccepted however
/// often it is verified again.
fn refused(correlation_key: &str, reason: String) -> String {
    format!("{correlation_key}: {reason}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::recipient_staging::{stage_evidence_half, stage_transfer_half};
    use crate::test_support::arrivals::{the_one_transfer, OneTransfer};
    use crate::test_support::two_device::Pair;
    use prost::Message;
    use serial_test::serial;

    /// A sends B 10; B has not polled. The transfer's halves as B's poll
    /// reads them, with B entered. The tests stage halves directly, past the
    /// dispatcher's gate, so each refusal proves verification's own check.
    async fn sent() -> (Pair, OneTransfer) {
        let p = Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let one = the_one_transfer(&p.b, &p.fleet).await;
        p.b.enter();
        (p, one)
    }

    fn evidence_digest(bytes: &[u8]) -> [u8; 32] {
        crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            bytes,
        )
    }

    fn never_applies(
        verified: &VerifiedTransfer,
    ) -> Result<crate::sdk::apply_outcome::ApplyOutcome, String> {
        panic!("apply must never run for {verified:?}")
    }

    /// A transfer whose SIG A does not verify under the sender's stored AK is
    /// refused; the pair stays ready_to_verify, recorded nowhere.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_bad_sig_a_is_refused_and_never_accepts() {
        let (p, one) = sent().await;
        let mut transfer =
            dsm::types::proto::OnlineTransferRequest::decode(one.transfer_bytes.as_slice())
                .expect("the transfer request");
        transfer.signature[0] ^= 0xFF;
        let digest = evidence_digest(&one.evidence.full_receipt_bytes);
        stage_transfer_half(&one.key, &transfer.encode_to_vec(), &digest, &one.route)
            .expect("stage the transfer");
        stage_evidence_half(&one.key, &one.evidence.full_receipt_bytes, &one.route)
            .expect("stage the evidence");

        let err = verify_and_accept(&one.key, &p.a.ak_pk, never_applies)
            .expect_err("a bad SIG A must be refused");
        assert!(err.contains("SIG A does not verify"), "{err}");
        let state = recipient_staging::staging_state(&one.key).expect("state");
        assert_eq!(
            state,
            StagingState::ReadyToVerify,
            "nothing negative is recorded"
        );
        assert!(!state.may_ack());
    }

    /// A receipt whose `sig_a` does not verify is refused even when the
    /// transfer names its exact bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_bad_receipt_sig_is_refused_and_never_accepts() {
        let (p, one) = sent().await;
        let mut receipt =
            StitchedReceiptV2::from_canonical_protobuf(&one.evidence.full_receipt_bytes)
                .expect("the receipt");
        receipt.sig_a[0] ^= 0xFF;
        let tampered = receipt.to_full_protobuf().expect("re-encode");
        let mut transfer =
            dsm::types::proto::OnlineTransferRequest::decode(one.transfer_bytes.as_slice())
                .expect("the transfer request");
        let digest = evidence_digest(&tampered);
        transfer.receipt_evidence_digest = digest.to_vec();
        stage_transfer_half(&one.key, &transfer.encode_to_vec(), &digest, &one.route)
            .expect("stage the transfer");
        stage_evidence_half(&one.key, &tampered, &one.route).expect("stage the evidence");

        let err = verify_and_accept(&one.key, &p.a.ak_pk, never_applies)
            .expect_err("a tampered receipt must be refused");
        assert!(err.contains("does not verify"), "{err}");
        let state = recipient_staging::staging_state(&one.key).expect("state");
        assert_eq!(
            state,
            StagingState::ReadyToVerify,
            "nothing negative is recorded"
        );
        assert!(!state.may_ack());
    }

    /// Verification refuses any state but ready_to_verify: a single half never
    /// reaches the apply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn verification_is_unreachable_from_a_single_half() {
        let (p, one) = sent().await;
        stage_transfer_half(
            &one.key,
            &one.transfer_bytes,
            &evidence_digest(&one.evidence.full_receipt_bytes),
            &one.route,
        )
        .expect("stage the transfer");
        let err = verify_and_accept(&one.key, &p.a.ak_pk, never_applies)
            .expect_err("a single half must not verify");
        assert!(err.contains("both halves must be present"), "{err}");
        assert!(!recipient_staging::staging_state(&one.key)
            .expect("state")
            .may_ack());
    }
}
