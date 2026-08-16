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
//! become ACK-able. Failure leaves the row in `ready_to_verify` (retryable, e.g.
//! a transient apply failure) or drives it to `terminal_reject` (a decision, e.g.
//! a digest or signature that does not bind), and neither is ACK-able.
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
/// Conflict                     -> fail closed                    -> terminal_reject
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
/// failing apply leaves the row `ready_to_verify` — retryable, un-ACK-able. A
/// `Conflict` is a decision about the transfer and is terminal.
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
        // Deliberately NOT a terminal reject: the cryptography held, so this is
        // a local failure to apply, not a decision about the transfer. Leaving
        // it `ready_to_verify` keeps it retryable and un-ACK-able.
        format!("canonical apply failed for {correlation_key} (not accepted, retryable): {e}")
    })?;

    let acceptance = match outcome {
        crate::sdk::apply_outcome::ApplyOutcome::Applied { .. } => Acceptance::AcceptedFresh,
        crate::sdk::apply_outcome::ApplyOutcome::AlreadyAppliedSameOperation { .. } => {
            Acceptance::AcceptedDuplicate
        }
        // A conflicting identity reusing this (relationship, parent) or nonce is
        // a DECISION about the transfer, not a transient failure: it cannot
        // become valid by being retried.
        crate::sdk::apply_outcome::ApplyOutcome::Conflict { reason } => {
            return Err(reject(
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
/// A failure that is a DECISION about the artifacts (digest or signature does
/// not bind) drives the row to `terminal_reject`. A failure that is merely an
/// inability to proceed leaves the state alone.
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
        return Err(reject(
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
        reject(
            correlation_key,
            format!("transfer half does not decode: {e}"),
        )
    })?;

    if req.canonical_operation_bytes.is_empty() {
        return Err(reject(
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
    .map_err(|e| reject(correlation_key, format!("SIG A does not verify: {e}")))?;

    // ---- 3. the receipt chain over the FROZEN evidence bytes ----
    let receipt = StitchedReceiptV2::from_canonical_protobuf(evidence_bytes)
        .map_err(|e| reject(correlation_key, format!("evidence does not decode: {e}")))?;
    let commitment = receipt
        .compute_commitment()
        .map_err(|e| reject(correlation_key, format!("receipt commitment failed: {e}")))?;
    super::storage_routes::verify_inbound_receipt_sig_a(&receipt, &commitment, sender_ak_pk)
        .map_err(|e| {
            reject(
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

/// Record a terminal rejection and return the message.
///
/// Used only for failures that are DECISIONS about the artifacts. A transfer
/// whose digest or signatures do not bind cannot become valid by being retried,
/// so leaving it retryable would mean retrying until something eventually
/// matched.
fn reject(correlation_key: &str, reason: String) -> String {
    if let Err(e) = recipient_staging::mark_rejected(correlation_key, &reason) {
        return format!("{reason} (additionally, recording the rejection failed: {e})");
    }
    reason
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sdk::receipts::{sign_receipt_with_per_step_ek, PerStepSigningInputs};
    use crate::storage::client_db::recipient_staging::{stage_evidence_half, stage_transfer_half};
    use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
    use serial_test::serial;

    pub(crate) fn setup() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        let _ =
            crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        crate::sdk::app_state::AppState::reset_for_testing();
        crate::sdk::app_state::AppState::set_identity_info(
            vec![0x11; 32],
            vec![0xAB; 32],
            vec![0x22; 32],
            vec![0u8; 32],
        );
        crate::sdk::recovery_sdk::RecoverySDK::set_cached_wallet_seed_for_testing(vec![0x9C; 64]);
    }

    /// A valid A-side receipt signed under `ak`, returned as its CANONICAL
    /// protobuf bytes -- exactly what the sender digests and what staging holds.
    pub(crate) fn signed_receipt_bytes(ak_pk: &[u8], ak_sk: &[u8]) -> Vec<u8> {
        let kyber_kp = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber");
        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            [0xAA; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x08; 16],
            vec![0x09; 16],
        );
        let commitment = receipt.compute_commitment().expect("commitment");
        let out = sign_receipt_with_per_step_ek(&PerStepSigningInputs {
            commitment: &commitment,
            h_n: [0xAA; 32],
            c_pre: [0xBB; 32],
            devid_sender: [0x11; 32],
            relationship_key: [0xE7; 32],
            root_ak_keypair: Some((ak_pk, ak_sk)),
            recipient_kyber_pk: &kyber_kp.public_key,
            // Production passes the commitment here (app_router_impl.rs) -- the
            // degenerate H(C || C) binding ADR 0003 notes as the natural home for
            // the operation digest later. The fixture must match production, not
            // an arbitrary value, or it would verify a chain production never
            // produces.
            session_binding: &commitment,
        })
        .expect("sign receipt");
        receipt.set_ek_pk_a(out.ek_pk);
        receipt.set_ek_cert_a(out.ek_cert);
        receipt.set_kyber_ct_a(out.kyber_ct);
        receipt.add_sig_a(out.sig);
        receipt.to_full_protobuf().expect("encode receipt")
    }

    /// An `OnlineTransferRequest` whose SIG A verifies under `ak`.
    pub(crate) fn signed_transfer_bytes(ak_sk: &[u8], evidence_digest: &[u8; 32]) -> Vec<u8> {
        let op = Operation::Noop;
        let canonical = op.to_bytes();
        let signature =
            dsm::crypto::sphincs::sphincs_sign(ak_sk, &canonical).expect("sign operation");
        let req = dsm::types::proto::OnlineTransferRequest {
            token_id: "ERA".to_string(),
            to_device_id: vec![0x03; 32],
            amount: 100,
            memo: String::new(),
            signature,
            nonce: vec![0x7E; 32],
            from_device_id: vec![0x02; 32],
            chain_tip: vec![0xAA; 32],
            seq: 1,
            receipt_commit: Vec::new(),
            canonical_operation_bytes: canonical,
            receipt_evidence_digest: evidence_digest.to_vec(),
        };
        let mut out = Vec::with_capacity(req.encoded_len());
        req.encode(&mut out).expect("encode transfer");
        out
    }

    /// Stage a fully valid pair. Returns `(key, ak_pk, evidence_bytes)`.
    fn stage_valid_pair(key: &str) -> (Vec<u8>, Vec<u8>) {
        setup();
        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC4; 32]).expect("ak");
        let evidence = signed_receipt_bytes(&ak_pk, &ak_sk);
        let digest = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &evidence,
        );
        let transfer = signed_transfer_bytes(&ak_sk, &digest);
        stage_transfer_half(key, &transfer, &digest, "TESTROUTE").expect("stage transfer");
        stage_evidence_half(key, &evidence, "TESTROUTE").expect("stage evidence");
        assert_eq!(
            recipient_staging::staging_state(key).expect("state"),
            StagingState::ReadyToVerify
        );
        (ak_pk, evidence)
    }

    /// A real `AdvanceOutcome` from a trivial advance. Constructing one by hand
    /// is not possible without duplicating the SMT machinery, and a real one is
    /// closer to what production hands back anyway.
    pub(crate) fn stub_advance() -> dsm::types::device_state::AdvanceOutcome {
        use dsm::core::bilateral_transaction_manager::{
            compute_smt_key, initial_chain_tip_from_device_ids,
        };
        let me = [0x21u8; 32];
        let head = dsm::types::device_state::DeviceState::new(me, me, vec![0xAB; 64], 64);
        head.advance(
            compute_smt_key(&me, &me),
            me,
            dsm::types::operations::Operation::Noop,
            vec![0x33; 32],
            None,
            &[],
            Some(initial_chain_tip_from_device_ids(&me, &me)),
            None,
            None,
            None,
        )
        .expect("stub advance")
    }

    fn stub_record() -> crate::storage::client_db::CanonicalApplyRecord {
        crate::storage::client_db::CanonicalApplyRecord {
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
        }
    }

    /// The whole chain holds, apply runs, and ONLY then is the transfer ACK-able.
    #[test]
    #[serial]
    fn a_valid_pair_verifies_applies_and_becomes_ack_able() {
        let key = "ACC-1";
        let (ak_pk, _) = stage_valid_pair(key);

        assert!(
            !recipient_staging::staging_state(key)
                .expect("state")
                .may_ack(),
            "ready_to_verify must not be ACK-able"
        );

        let applied = std::cell::Cell::new(false);
        let (_v, acceptance) = verify_and_accept(key, &ak_pk, |_v| {
            applied.set(true);
            Ok(
                crate::sdk::apply_outcome::ApplyOutcome::AlreadyAppliedSameOperation {
                    record: stub_record(),
                },
            )
        })
        .expect("verify + accept");

        assert!(applied.get(), "the canonical apply must have run");
        assert_eq!(
            acceptance,
            Acceptance::AcceptedDuplicate,
            "an AlreadyAppliedSameOperation must NOT be reported as a fresh acceptance"
        );
        let st = recipient_staging::staging_state(key).expect("state");
        assert_eq!(st, StagingState::Accepted);
        assert!(st.may_ack(), "only a completed acceptance is ACK-able");
    }

    /// A FRESH apply is classified as fresh, and a duplicate as duplicate. These
    /// must not collapse: 3c decides what an ACK looks like for each, and a
    /// duplicate must never mint a second value-bearing result keyed only by the
    /// new correlation id.
    #[test]
    #[serial]
    fn fresh_and_duplicate_applies_are_classified_distinctly() {
        let key = "ACC-FRESH";
        let (ak_pk, _) = stage_valid_pair(key);

        let (_v, acceptance) = verify_and_accept(key, &ak_pk, |_| {
            Ok(crate::sdk::apply_outcome::ApplyOutcome::Applied {
                record: stub_record(),
                advance: Box::new(stub_advance()),
            })
        })
        .expect("fresh accept");
        assert_eq!(acceptance, Acceptance::AcceptedFresh);
    }

    /// A canonical-apply Conflict is a DECISION about the transfer -- a different
    /// operation identity already consumed this (relationship, parent) or nonce.
    /// It cannot become valid by being retried, so it is terminal, not retryable.
    #[test]
    #[serial]
    fn an_apply_conflict_is_terminal_not_retryable() {
        let key = "ACC-CONFLICT";
        let (ak_pk, _) = stage_valid_pair(key);

        let err = verify_and_accept(key, &ak_pk, |_| {
            Ok(crate::sdk::apply_outcome::ApplyOutcome::Conflict {
                reason: "nonce already consumed by a different identity".to_string(),
            })
        })
        .expect_err("a conflict must not accept");
        assert!(err.contains("canonical apply conflict"), "{err}");

        let st = recipient_staging::staging_state(key).expect("state");
        assert_eq!(
            st,
            StagingState::TerminalReject,
            "a conflicting identity is a decision, not a transient failure"
        );
        assert!(!st.may_ack());
    }

    /// Valid crypto, but the canonical apply fails: nothing is accepted, nothing
    /// is ACK-able, and the transfer stays retryable rather than being rejected
    /// -- the cryptography held, so this is not a decision about the transfer.
    #[test]
    #[serial]
    fn a_failing_canonical_apply_never_accepts_and_never_acks() {
        let key = "ACC-2";
        let (ak_pk, _) = stage_valid_pair(key);

        let err = verify_and_accept(key, &ak_pk, |_v| {
            Err::<crate::sdk::apply_outcome::ApplyOutcome, _>("disk on fire".to_string())
        })
        .expect_err("a failing apply must not accept");
        assert!(err.contains("canonical apply failed"), "{err}");

        let st = recipient_staging::staging_state(key).expect("state");
        assert_eq!(
            st,
            StagingState::ReadyToVerify,
            "a failed apply must stay retryable, not become terminal"
        );
        assert!(!st.may_ack(), "a failed apply must never be ACK-able");
    }

    /// Valid digest, tampered SIG A -> terminal reject, never ACK-able.
    #[test]
    #[serial]
    fn a_bad_sig_a_rejects_terminally() {
        let key = "ACC-3";
        setup();
        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC4; 32]).expect("ak");
        let evidence = signed_receipt_bytes(&ak_pk, &ak_sk);
        let digest = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &evidence,
        );

        // Sign with the WRONG key: the digest still binds, SIG A does not.
        let (_, other_sk) = generate_ephemeral_keypair(&[0xD5; 32]).expect("other");
        let transfer = signed_transfer_bytes(&other_sk, &digest);
        stage_transfer_half(key, &transfer, &digest, "TESTROUTE").expect("stage transfer");
        stage_evidence_half(key, &evidence, "TESTROUTE").expect("stage evidence");

        let err = verify_and_accept(
            key,
            &ak_pk,
            |_| -> Result<crate::sdk::apply_outcome::ApplyOutcome, String> {
                panic!("apply must never run")
            },
        )
        .expect_err("a bad SIG A must be refused");
        assert!(err.contains("SIG A does not verify"), "{err}");

        let st = recipient_staging::staging_state(key).expect("state");
        assert_eq!(st, StagingState::TerminalReject);
        assert!(!st.may_ack());
    }

    /// Valid SIG A, tampered receipt `sig_a` -> terminal reject.
    #[test]
    #[serial]
    fn a_bad_receipt_sig_rejects_terminally() {
        let key = "ACC-4";
        setup();
        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC4; 32]).expect("ak");
        let good = signed_receipt_bytes(&ak_pk, &ak_sk);

        // Replace sig_a with a signature over the WRONG target, then re-derive
        // the digest so the DIGEST still binds and ONLY the receipt signature is
        // wrong. Flipping a trailing byte is not sufficient: `compute_commitment`
        // hard-zeroes fields 12-20, so a byte in e.g. `kyber_ct_a` is covered by
        // no signature on this path and verification legitimately passes.
        let mut receipt =
            StitchedReceiptV2::from_canonical_protobuf(&good).expect("decode good receipt");
        let bogus = dsm::crypto::sphincs::sphincs_sign(&ak_sk, b"not the receipt target")
            .expect("bogus signature");
        receipt.sig_a = bogus;
        let tampered = receipt.to_full_protobuf().expect("re-encode tampered");
        let digest = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &tampered,
        );
        let transfer = signed_transfer_bytes(&ak_sk, &digest);
        stage_transfer_half(key, &transfer, &digest, "TESTROUTE").expect("stage transfer");
        stage_evidence_half(key, &tampered, "TESTROUTE").expect("stage evidence");

        let err = verify_and_accept(
            key,
            &ak_pk,
            |_| -> Result<crate::sdk::apply_outcome::ApplyOutcome, String> {
                panic!("apply must never run")
            },
        )
        .expect_err("a tampered receipt must be refused");
        assert!(
            err.contains("receipt chain does not verify") || err.contains("does not decode"),
            "{err}"
        );
        assert_eq!(
            recipient_staging::staging_state(key).expect("state"),
            StagingState::TerminalReject
        );
    }

    /// Verification refuses any state other than ready_to_verify, so a single
    /// half can never reach the apply path.
    #[test]
    #[serial]
    fn verification_is_unreachable_from_a_single_half() {
        let key = "ACC-5";
        setup();
        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC4; 32]).expect("ak");
        let evidence = signed_receipt_bytes(&ak_pk, &ak_sk);
        let digest = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &evidence,
        );
        stage_transfer_half(
            key,
            &signed_transfer_bytes(&ak_sk, &digest),
            &digest,
            "TESTROUTE",
        )
        .expect("stage transfer");

        let err = verify_and_accept(
            key,
            &ak_pk,
            |_| -> Result<crate::sdk::apply_outcome::ApplyOutcome, String> {
                panic!("apply must never run")
            },
        )
        .expect_err("a single half must not verify");
        assert!(err.contains("both halves must be present"), "{err}");
        assert!(!recipient_staging::staging_state(key)
            .expect("state")
            .may_ack());
    }
}
