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
    /// The receipt whose `sig_a` / `ek_cert_a` chain verified.
    pub receipt: StitchedReceiptV2,
}

/// Verify a staged transfer, run the caller's canonical apply, and only then
/// transition to `accepted`.
///
/// `apply` is injected rather than called directly so that this slice stays
/// verification + transition, and so a test can force the apply to fail at
/// exactly the boundary where partial application would be most damaging.
///
/// Ordering is the point: `mark_accepted` runs only after `apply` returns `Ok`.
/// A failing apply leaves the row `ready_to_verify` — retryable, and not
/// ACK-able.
pub fn verify_and_accept<F>(
    correlation_key: &str,
    sender_ak_pk: &[u8],
    apply: F,
) -> Result<VerifiedTransfer, String>
where
    F: FnOnce(&VerifiedTransfer) -> Result<(), String>,
{
    let verified = verify_staged_transfer(correlation_key, sender_ak_pk)?;

    apply(&verified).map_err(|e| {
        // Deliberately NOT a terminal reject: the cryptography held, so this is
        // a local failure to apply, not a decision about the transfer. Leaving
        // it `ready_to_verify` keeps it retryable and un-ACK-able.
        format!("canonical apply failed for {correlation_key} (not accepted, retryable): {e}")
    })?;

    recipient_staging::mark_accepted(correlation_key)
        .map_err(|e| format!("accept transition failed for {correlation_key}: {e}"))?;

    Ok(verified)
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
mod tests {
    use super::*;
    use crate::sdk::receipts::{sign_receipt_with_per_step_ek, PerStepSigningInputs};
    use crate::storage::client_db::recipient_staging::{stage_evidence_half, stage_transfer_half};
    use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
    use serial_test::serial;

    fn setup() {
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
    fn signed_receipt_bytes(ak_pk: &[u8], ak_sk: &[u8]) -> Vec<u8> {
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
    fn signed_transfer_bytes(ak_sk: &[u8], evidence_digest: &[u8; 32]) -> Vec<u8> {
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
        stage_transfer_half(key, &transfer, &digest).expect("stage transfer");
        stage_evidence_half(key, &evidence).expect("stage evidence");
        assert_eq!(
            recipient_staging::staging_state(key).expect("state"),
            StagingState::ReadyToVerify
        );
        (ak_pk, evidence)
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
        verify_and_accept(key, &ak_pk, |_v| {
            applied.set(true);
            Ok(())
        })
        .expect("verify + accept");

        assert!(applied.get(), "the canonical apply must have run");
        let st = recipient_staging::staging_state(key).expect("state");
        assert_eq!(st, StagingState::Accepted);
        assert!(st.may_ack(), "only a completed acceptance is ACK-able");
    }

    /// Valid crypto, but the canonical apply fails: nothing is accepted, nothing
    /// is ACK-able, and the transfer stays retryable rather than being rejected
    /// -- the cryptography held, so this is not a decision about the transfer.
    #[test]
    #[serial]
    fn a_failing_canonical_apply_never_accepts_and_never_acks() {
        let key = "ACC-2";
        let (ak_pk, _) = stage_valid_pair(key);

        let err = verify_and_accept(key, &ak_pk, |_v| Err("disk on fire".to_string()))
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
        stage_transfer_half(key, &transfer, &digest).expect("stage transfer");
        stage_evidence_half(key, &evidence).expect("stage evidence");

        let err = verify_and_accept(key, &ak_pk, |_| panic!("apply must never run"))
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
        stage_transfer_half(key, &transfer, &digest).expect("stage transfer");
        stage_evidence_half(key, &tampered).expect("stage evidence");

        let err = verify_and_accept(key, &ak_pk, |_| panic!("apply must never run"))
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
        stage_transfer_half(key, &signed_transfer_bytes(&ak_sk, &digest), &digest)
            .expect("stage transfer");

        let err = verify_and_accept(key, &ak_pk, |_| panic!("apply must never run"))
            .expect_err("a single half must not verify");
        assert!(err.contains("both halves must be present"), "{err}");
        assert!(!recipient_staging::staging_state(key)
            .expect("state")
            .may_ack());
    }
}
