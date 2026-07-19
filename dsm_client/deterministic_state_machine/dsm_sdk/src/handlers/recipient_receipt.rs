// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recipient B-side acceptance-receipt orchestrator (§16.6).
//!
//! The single authoritative recipient countersigning path, in three phases under
//! one ASYNC relationship exclusion (see design doc): generate + persist BEFORE
//! apply; authorize convergence only AFTER the durable `CanonicalApplyRecord`
//! exists; never sign in recovery.
//!
//! Live sequence (accept path holds the tokio guard across all of it):
//!   prepare_bside_acceptance_receipt_locked(...)      // before apply
//!   CoreSDK::apply_incoming_transfer_full_state(...)  // single full-state tx
//!   converge_accepted_locked(journal, record, ...)    // projection sync + marker
//!                                                     // → promote → complete
//!
//! Startup / on-access recovery drives the SAME convergence from the durable
//! `CanonicalApplyRecord` — redelivery is a valid trigger but never the only one.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use crate::storage::client_db::bilateral_tip_sync::{
    sync_tip_projection_and_record_acceptance_atomic, TipSyncOutcome, TipSyncRequest,
};
use crate::storage::client_db::{
    complete_applied_acceptance, get_acceptance_journal, get_canonical_apply_identity,
    get_incomplete_acceptance_journals, get_outbound_reply_bytes,
    insert_prepared_acceptance_journal, promote_prepared_to_applied, AcceptancePhaseOutcome,
    AcceptedTransition, CanonicalApplyRecord, PromoteOutcome, RecipientAcceptanceJournal,
    STATUS_APPLIED, STATUS_COMPLETE, STATUS_PREPARED,
};

/// Per-relationship ASYNC exclusion. The keyed registry's std mutex is held only
/// briefly to get-or-insert the per-key `Arc<tokio::sync::Mutex<()>>` — never
/// across `.await`. Callers hold the tokio guard (owned, `Send + 'static`)
/// across the whole acceptance sequence. The durable journal PK + the DB UNIQUE
/// constraints remain the cross-process/crash authority; this lock only
/// serializes in-process callers.
static RELATIONSHIP_LOCKS: Lazy<StdMutex<HashMap<[u8; 32], Arc<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

/// Get the per-relationship async lock. Acquire with
/// `relationship_lock(&rel).lock_owned().await` and hold the guard across the
/// entire acceptance sequence.
pub fn relationship_lock(relationship_key: &[u8; 32]) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = RELATIONSHIP_LOCKS.lock().unwrap_or_else(|p| p.into_inner());
    map.entry(*relationship_key)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Fully-constructed, locally-verified B-side artifacts ready to journal.
pub struct GeneratedBArtifacts {
    /// Exact canonical `to_full_protobuf` bytes (with `sig_b`).
    pub receipt_bytes: Vec<u8>,
    pub commitment: [u8; 32],
    pub child_tip: [u8; 32],
    pub counterparty_device_id: [u8; 32],
    /// Party A's roots as claimed by the inbound receipt.
    pub receipt_parent_root_a: [u8; 32],
    pub receipt_child_root_a: [u8; 32],
    /// Canonical pre-commit digest (`C_pre`).
    pub precommit_digest: [u8; 32],
    /// `acceptance_artifact_hash(exact persisted full receipt bytes)`.
    pub prepared_receipt_artifact_hash: [u8; 32],
    /// Pre-step local B head captured once (`None` at genesis).
    pub expected_local_b_head: Option<Vec<u8>>,
    /// New local B head (`ek_pk_b`).
    pub new_local_b_head: Vec<u8>,
    /// `ek_sk_b`, ALREADY encrypted (plaintext never leaves the generator).
    pub new_local_b_sk_enc: Vec<u8>,
    /// Pre-step counterparty (A) head captured once (`None` at genesis).
    pub expected_counterparty_a_head: Option<Vec<u8>>,
    /// New counterparty (A) head (`ek_pk_a` from the inbound receipt).
    pub new_counterparty_a_head: Vec<u8>,
}

/// PHASE 1 (before apply) — SYNC, caller holds the relationship guard.
/// Generate + self-verify the B receipt once and persist it PREPARED. Re-entry
/// returns the exact stored bytes and NEVER re-signs. Advances nothing.
pub fn prepare_bside_acceptance_receipt_locked<G>(
    relationship_key: [u8; 32],
    parent_tip: [u8; 32],
    generate: G,
) -> Result<Vec<u8>>
where
    G: FnOnce() -> Result<GeneratedBArtifacts>,
{
    if let Some(existing) = get_acceptance_journal(&relationship_key, &parent_tip)? {
        return Ok(existing.receipt_bytes);
    }

    let artifacts = generate()?;
    let rec = RecipientAcceptanceJournal {
        relationship_key,
        parent_tip,
        child_tip: artifacts.child_tip,
        counterparty_device_id: artifacts.counterparty_device_id,
        commitment: artifacts.commitment,
        receipt_parent_root_a: artifacts.receipt_parent_root_a,
        receipt_child_root_a: artifacts.receipt_child_root_a,
        precommit_digest: artifacts.precommit_digest,
        prepared_receipt_artifact_hash: artifacts.prepared_receipt_artifact_hash,
        expected_local_b_head: artifacts.expected_local_b_head,
        new_local_b_head: artifacts.new_local_b_head,
        new_local_b_sk_enc: Some(artifacts.new_local_b_sk_enc),
        expected_counterparty_a_head: artifacts.expected_counterparty_a_head,
        new_counterparty_a_head: artifacts.new_counterparty_a_head,
        receipt_bytes: artifacts.receipt_bytes.clone(),
        status: STATUS_PREPARED.to_string(),
        created_at: 0,
    };
    match insert_prepared_acceptance_journal(&rec) {
        Ok(()) => Ok(rec.receipt_bytes),
        Err(e) => {
            // Journal PK is the uniqueness point: a winner that escaped the
            // in-process lock arbitrates.
            if let Some(winner) = get_acceptance_journal(&relationship_key, &parent_tip)? {
                return Ok(winner.receipt_bytes);
            }
            Err(e)
        }
    }
}

/// PHASE 2 — SYNC, caller holds the relationship guard. Promote the prepared
/// journal to Applied on the full field-for-field marker match.
pub fn mark_recipient_acceptance_applied_locked(
    relationship_key: [u8; 32],
    parent_tip: [u8; 32],
) -> Result<PromoteOutcome> {
    promote_prepared_to_applied(&relationship_key, &parent_tip)
}

/// PHASE 3 — SYNC, caller holds the relationship guard. Complete an Applied
/// journal (CAS both cert heads, install outbox, mark complete, wipe secret).
/// Returns the persisted receipt bytes on convergence; `None` if not yet Applied.
pub fn resume_acceptance_phases_locked(
    relationship_key: [u8; 32],
    parent_tip: [u8; 32],
    wrap_key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let rec = match get_acceptance_journal(&relationship_key, &parent_tip)? {
        Some(r) => r,
        None => return Ok(None),
    };
    match complete_applied_acceptance(&rec, wrap_key)? {
        AcceptancePhaseOutcome::Converged { .. } => {
            read_persisted_bytes(&relationship_key, &parent_tip, &rec.commitment).map(Some)
        }
        AcceptancePhaseOutcome::NotYetApplied => Ok(None),
        AcceptancePhaseOutcome::Conflict { reason } => {
            Err(anyhow!("acceptance completion failed closed: {reason}"))
        }
    }
}

/// Convergence for an accepted transition — SYNC, caller holds the relationship
/// guard. Driven by the durable `CanonicalApplyRecord` (from `Applied` /
/// `AlreadyAppliedSameOperation` or from recovery's lookup):
///  1. journal ↔ record identity match on {rel, parent, child, precommit,
///     sender, recipient} — roots are NOT cross-matched (different domains);
///  2. atomic { contacts.chain_tip PROJECTION sync + immutable acceptance
///     marker } — the marker binds BOTH root pairs (A from the journal/receipt,
///     B from the record);
///  3. promote Prepared → Applied (full marker compare);
///  4. complete (CAS A + B heads, outbox, wipe secret);
///  5. return the exact persisted receipt bytes.
pub fn converge_accepted_locked(
    journal: &RecipientAcceptanceJournal,
    record: &CanonicalApplyRecord,
    wrap_key: &[u8; 32],
) -> Result<Vec<u8>> {
    // 1. Identity match (fail closed on any divergence).
    if record.relationship_key != journal.relationship_key
        || record.parent_tip != journal.parent_tip
        || record.child_tip != journal.child_tip
        || record.precommit_digest != journal.precommit_digest
        || record.sender_device != journal.counterparty_device_id
    {
        return Err(anyhow!(
            "canonical apply record does not match the prepared journal identity — fail closed"
        ));
    }
    if let Some(local) = crate::sdk::app_state::AppState::get_device_id() {
        if local.len() == 32 && record.recipient_device.as_slice() != local.as_slice() {
            return Err(anyhow!(
                "canonical apply record names a different recipient — fail closed"
            ));
        }
    }

    // 2. Projection sync + marker, one client-db tx. All values from durable
    // records — never derived from the projection.
    let marker = AcceptedTransition {
        relationship_key: journal.relationship_key,
        parent_tip: journal.parent_tip,
        child_tip: journal.child_tip,
        receipt_parent_root_a: journal.receipt_parent_root_a,
        receipt_child_root_a: journal.receipt_child_root_a,
        applied_parent_root_b: record.applied_parent_root_b,
        applied_child_root_b: record.applied_child_root_b,
        precommit_digest: journal.precommit_digest,
        prepared_receipt_commitment: journal.commitment,
        prepared_receipt_artifact_hash: journal.prepared_receipt_artifact_hash,
        sender_device: record.sender_device,
        recipient_device: record.recipient_device,
    };
    let request = TipSyncRequest {
        counterparty_device_id: journal.counterparty_device_id,
        expected_parent_tip: journal.parent_tip,
        target_tip: journal.child_tip,
        observed_gate: None,
        clear_gate_on_success: false,
    };
    match sync_tip_projection_and_record_acceptance_atomic(&request, &marker)? {
        TipSyncOutcome::Advanced { .. }
        | TipSyncOutcome::RepairedAtTarget { .. }
        | TipSyncOutcome::AlreadyAtTarget { .. } => {}
        other => {
            return Err(anyhow!(
                "projection sync failed closed ({other:?}) — reconciliation required"
            ));
        }
    }

    // 3-4. Promote on the full marker compare, then complete.
    match promote_prepared_to_applied(&journal.relationship_key, &journal.parent_tip)? {
        PromoteOutcome::Applied => {}
        PromoteOutcome::NotYetApplied => {
            return Err(anyhow!(
                "promotion refused after marker write — inconsistent acceptance state"
            ));
        }
        PromoteOutcome::Rejected => {
            return Err(anyhow!("journal is rejected — refusing to converge"));
        }
    }
    match resume_acceptance_phases_locked(journal.relationship_key, journal.parent_tip, wrap_key)? {
        Some(bytes) => Ok(bytes),
        None => Err(anyhow!(
            "completion returned NotYetApplied after promotion — inconsistent acceptance state"
        )),
    }
}

/// Startup + on-access recovery: finish applied-but-incomplete journals from the
/// durable `CanonicalApplyRecord` WITHOUT waiting for redelivery. A `prepared`
/// journal with NO apply record is left intact (the transition never committed;
/// redelivery may still apply it). A conflicting record fails closed (logged,
/// journal left for inspection). Runs only after DB + wallet keys exist — the
/// caller derives `wrap_key` and skips (fail closed) when the wallet is locked.
pub async fn recover_incomplete_acceptances(wrap_key: &[u8; 32]) -> Result<()> {
    for j in get_incomplete_acceptance_journals()? {
        let lock = relationship_lock(&j.relationship_key);
        let _guard = lock.lock_owned().await;

        // Re-read under the lock (state may have moved).
        let journal = match get_acceptance_journal(&j.relationship_key, &j.parent_tip)? {
            Some(cur) if cur.status == STATUS_PREPARED || cur.status == STATUS_APPLIED => cur,
            _ => continue,
        };

        if journal.status == STATUS_APPLIED || journal.status == STATUS_COMPLETE {
            // Marker already present (promotion happened) — just complete.
            let _ = resume_acceptance_phases_locked(
                journal.relationship_key,
                journal.parent_tip,
                wrap_key,
            )?;
            continue;
        }

        match get_canonical_apply_identity(&journal.relationship_key, &journal.parent_tip)? {
            None => {
                // Transition never committed — leave Prepared.
                continue;
            }
            Some(record) => {
                match converge_accepted_locked(&journal, &record, wrap_key) {
                    Ok(_) => {
                        log::info!(
                            "[acceptance-recovery] converged journal for parent {:02x}{:02x}.. without redelivery",
                            journal.parent_tip[0],
                            journal.parent_tip[1],
                        );
                    }
                    Err(e) => {
                        // Fail closed: no projection sync, no receipt completion.
                        log::error!(
                            "[acceptance-recovery] FAIL CLOSED for parent {:02x}{:02x}..: {e}",
                            journal.parent_tip[0],
                            journal.parent_tip[1],
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// The authoritative return is the persisted outbound-reply bytes; fall back to
/// the journal's stored bytes (identical exact canonical bytes).
fn read_persisted_bytes(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
    commitment: &[u8; 32],
) -> Result<Vec<u8>> {
    if let Some(bytes) = get_outbound_reply_bytes(commitment)? {
        return Ok(bytes);
    }
    match get_acceptance_journal(relationship_key, parent_tip)? {
        Some(j) => Ok(j.receipt_bytes),
        None => Err(anyhow!(
            "acceptance receipt bytes not found in storage after fold"
        )),
    }
}

/// Produce the recipient's B-side per-step EK artifacts from the inbound accepted
/// receipt (production generator; the symmetric signer yields the LOCAL/B side).
/// Captures BOTH pre-step heads once, self-verifies before returning. The
/// `ek_sk_b` plaintext is encrypted here and never returned in clear.
pub fn generate_b_artifacts_from_inbound(
    inbound_receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    c_pre: &[u8; 32],
    sender_kyber_pk: &[u8],
    recipient_ak_pk: &[u8],
    recipient_ak_sk: &[u8],
    wrap_key: &[u8; 32],
) -> Result<GeneratedBArtifacts> {
    use crate::sdk::receipts::{
        sign_receipt_with_per_step_ek, verify_per_step_ek_signing, BilateralSide,
        PerStepSigningInputs,
    };
    use crate::storage::client_db::cert_chain::{
        encrypt_chain_sk, load_cert_chain_head_pubkey, CertChainSide,
    };
    use dsm::types::receipt_types::StitchedReceiptV2;
    use dsm::verification::smt_replace_witness::compute_smt_key;

    let rel_key = compute_smt_key(&inbound_receipt.devid_a, &inbound_receipt.devid_b);
    let commitment = inbound_receipt
        .compute_commitment()
        .map_err(|e| anyhow!("commitment: {e}"))?;

    // Capture BOTH pre-step heads exactly once.
    let pre_step_b = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Local)?;
    let pre_step_a = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)?;

    let out = sign_receipt_with_per_step_ek(&PerStepSigningInputs {
        commitment: &commitment,
        h_n: inbound_receipt.parent_tip,
        c_pre: *c_pre,
        devid_sender: inbound_receipt.devid_b,
        relationship_key: rel_key,
        root_ak_keypair: Some((recipient_ak_pk, recipient_ak_sk)),
        recipient_kyber_pk: sender_kyber_pk,
        session_binding: &commitment,
    })
    .map_err(|e| anyhow!("B-side per-step EK signing: {e}"))?;

    if pre_step_b.is_none() != out.used_root_ak {
        return Err(anyhow!("pre-step B head / used_root_ak inconsistency"));
    }

    let mut receipt = inbound_receipt.clone();
    receipt.set_ek_pk_b(out.ek_pk.clone());
    receipt.set_ek_cert_b(out.ek_cert.clone());
    receipt.set_kyber_ct_b(out.kyber_ct.clone());
    receipt.add_sig_b(out.sig.clone());

    // Verify before journaling.
    if receipt.sig_b.is_empty()
        || receipt.ek_pk_b.is_empty()
        || receipt.ek_cert_b.is_empty()
        || receipt.kyber_ct_b.is_empty()
    {
        return Err(anyhow!(
            "constructed B-side receipt has an empty EK artifact"
        ));
    }
    if inbound_receipt.ek_pk_a.is_empty() {
        return Err(anyhow!(
            "inbound receipt missing ek_pk_a (cannot advance A head)"
        ));
    }
    let bytes = receipt
        .to_full_protobuf()
        .map_err(|e| anyhow!("to_full_protobuf: {e}"))?;
    let reparsed = StitchedReceiptV2::from_canonical_protobuf(&bytes)
        .map_err(|e| anyhow!("reparse persisted bytes: {e}"))?;
    if reparsed.compute_commitment().map_err(|e| anyhow!("{e}"))? != commitment {
        return Err(anyhow!(
            "serialization drift: commitment mismatch after full serialize"
        ));
    }
    let expected_prev_pk = pre_step_b
        .clone()
        .unwrap_or_else(|| recipient_ak_pk.to_vec());
    verify_per_step_ek_signing(
        &receipt,
        BilateralSide::B,
        &expected_prev_pk,
        &receipt.parent_tip,
        &commitment,
    )
    .map_err(|e| anyhow!("B-side EK self-verification failed before mutation: {e}"))?;

    let new_local_b_sk_enc = encrypt_chain_sk(&out.ek_sk, wrap_key)?;
    // Bind the EXACT persisted bytes before moving them into the struct.
    let prepared_receipt_artifact_hash =
        crate::storage::client_db::acceptance_artifact_hash(&bytes);

    Ok(GeneratedBArtifacts {
        receipt_bytes: bytes,
        commitment,
        child_tip: inbound_receipt.child_tip,
        counterparty_device_id: inbound_receipt.devid_a,
        receipt_parent_root_a: inbound_receipt.parent_root,
        receipt_child_root_a: inbound_receipt.child_root,
        precommit_digest: *c_pre,
        prepared_receipt_artifact_hash,
        expected_local_b_head: pre_step_b,
        new_local_b_head: out.ek_pk,
        new_local_b_sk_enc,
        expected_counterparty_a_head: pre_step_a,
        new_counterparty_a_head: inbound_receipt.ek_pk_a.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::cert_chain::{
        encrypt_chain_sk, load_cert_chain_head_pubkey, CertChainSide,
    };
    use crate::storage::client_db::{outbound_reply_exists, store_contact, ContactRecord};
    use serial_test::serial;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const WRAP: [u8; 32] = [0x42u8; 32];

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        // Pin the global AppState identity to this module's fixture recipient
        // ([0x0F;32], used by make_record) so converge's recipient check is
        // deterministic regardless of which #[serial] test ran before us.
        crate::sdk::app_state::AppState::set_identity_info(
            vec![0x0Fu8; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            vec![0x04; 32],
        );
    }

    fn make_artifacts(child: [u8; 32], commitment: [u8; 32], bytes: &[u8]) -> GeneratedBArtifacts {
        GeneratedBArtifacts {
            receipt_bytes: bytes.to_vec(),
            commitment,
            child_tip: child,
            counterparty_device_id: [0x0Au8; 32],
            receipt_parent_root_a: [0x0Bu8; 32],
            receipt_child_root_a: [0x0Cu8; 32],
            precommit_digest: [0x0Du8; 32],
            prepared_receipt_artifact_hash: crate::storage::client_db::acceptance_artifact_hash(
                bytes,
            ),
            expected_local_b_head: None,
            new_local_b_head: vec![0xBBu8; 40],
            new_local_b_sk_enc: encrypt_chain_sk(&[0xCCu8; 64], &WRAP).unwrap(),
            expected_counterparty_a_head: None,
            new_counterparty_a_head: vec![0xAAu8; 40],
        }
    }

    /// A canonical apply record matching `make_artifacts` (as the full-state
    /// apply would durably record it, with authoritative B roots).
    fn make_record(rel: [u8; 32], parent: [u8; 32], child: [u8; 32]) -> CanonicalApplyRecord {
        CanonicalApplyRecord {
            relationship_key: rel,
            parent_tip: parent,
            child_tip: child,
            precommit_digest: [0x0Du8; 32],
            operation_digest: [0x0Eu8; 32],
            sender_device: [0x0Au8; 32],
            recipient_device: [0x0Fu8; 32],
            nonce_hash: [0x10u8; 32],
            applied_parent_root_b: [0x1Bu8; 32],
            applied_child_root_b: [0x1Cu8; 32],
        }
    }

    /// The projection-sync needs a contact row for the counterparty.
    fn seed_contact(cp: &[u8; 32], tip: &[u8; 32]) {
        let c = ContactRecord {
            contact_id: "t".to_string(),
            device_id: cp.to_vec(),
            alias: "t".to_string(),
            genesis_hash: vec![0u8; 32],
            public_key: Vec::new(),
            kyber_public_key: Vec::new(),
            current_chain_tip: Some(tip.to_vec()),
            added_at: 0,
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "active".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        };
        store_contact(&c).unwrap();
        // Force chain_tip (store_contact's COALESCE keeps existing/NULL).
        let binding = crate::storage::client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "UPDATE contacts SET chain_tip = ?2 WHERE device_id = ?1",
            rusqlite::params![cp.as_slice(), tip.as_slice()],
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn prepare_persists_prepared_but_advances_nothing() {
        init_test_db();
        let rel = [0x51u8; 32];
        let parent = [0x52u8; 32];
        let bytes = prepare_bside_acceptance_receipt_locked(rel, parent, || {
            Ok(make_artifacts(
                [0x53u8; 32],
                [0x54u8; 32],
                b"PREPARED-BYTES",
            ))
        })
        .unwrap();
        assert_eq!(bytes, b"PREPARED-BYTES");
        assert!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local)
            .unwrap()
            .is_none());
        assert!(!outbound_reply_exists(&[0x54u8; 32]).unwrap());
        assert!(resume_acceptance_phases_locked(rel, parent, &WRAP)
            .unwrap()
            .is_none());
    }

    #[test]
    #[serial]
    fn full_convergence_via_record_and_reentry_byte_identical() {
        init_test_db();
        let rel = [0x61u8; 32];
        let parent = [0x62u8; 32];
        let child = [0x63u8; 32];
        let calls = AtomicUsize::new(0);
        let first = prepare_bside_acceptance_receipt_locked(rel, parent, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(make_artifacts(child, [0x64u8; 32], b"BYTES-3PHASE"))
        })
        .unwrap();
        // Simulate the durable apply record + the counterparty projection at parent.
        seed_contact(&[0x0Au8; 32], &parent);
        let record = make_record(rel, parent, child);
        let journal = get_acceptance_journal(&rel, &parent).unwrap().unwrap();
        let done = converge_accepted_locked(&journal, &record, &WRAP).unwrap();
        assert_eq!(done, b"BYTES-3PHASE");
        assert_eq!(
            load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap(),
            Some(vec![0xBBu8; 40])
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&rel, CertChainSide::Counterparty).unwrap(),
            Some(vec![0xAAu8; 40])
        );
        assert!(outbound_reply_exists(&[0x64u8; 32]).unwrap());
        // Projection synchronized parent -> child.
        assert_eq!(
            crate::storage::client_db::get_contact_chain_tip_raw(&[0x0Au8; 32]),
            Some(child)
        );
        // Re-entry to prepare returns identical bytes; generator NOT called again.
        let again = prepare_bside_acceptance_receipt_locked(rel, parent, || {
            panic!("must not regenerate");
        })
        .unwrap();
        assert_eq!(first, again);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[serial]
    fn converge_rejects_mismatched_record_identity() {
        init_test_db();
        let rel = [0x71u8; 32];
        let parent = [0x72u8; 32];
        let child = [0x73u8; 32];
        prepare_bside_acceptance_receipt_locked(rel, parent, || {
            Ok(make_artifacts(child, [0x74u8; 32], b"BYTES-MM"))
        })
        .unwrap();
        seed_contact(&[0x0Au8; 32], &parent);
        let journal = get_acceptance_journal(&rel, &parent).unwrap().unwrap();
        // Record with a DIFFERENT precommit — identity mismatch must fail closed.
        let mut record = make_record(rel, parent, child);
        record.precommit_digest = [0xEEu8; 32];
        let err = converge_accepted_locked(&journal, &record, &WRAP).unwrap_err();
        assert!(err.to_string().contains("does not match"));
        // Nothing advanced.
        assert!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local)
            .unwrap()
            .is_none());
        assert!(!outbound_reply_exists(&[0x74u8; 32]).unwrap());
    }

    #[test]
    #[serial]
    fn recovery_without_redelivery_converges_prepared_journal() {
        init_test_db();
        let rel = [0x81u8; 32];
        let parent = [0x82u8; 32];
        let child = [0x83u8; 32];
        prepare_bside_acceptance_receipt_locked(rel, parent, || {
            Ok(make_artifacts(child, [0x84u8; 32], b"BYTES-RECOVER"))
        })
        .unwrap();
        seed_contact(&[0x0Au8; 32], &parent);
        // Durably record the apply (as the single full-state tx would).
        {
            let binding = crate::storage::client_db::get_connection().unwrap();
            let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let tx = conn.transaction().unwrap();
            let record = make_record(rel, parent, child);
            let out =
                crate::storage::client_db::insert_canonical_apply_identity_with_conn(&tx, &record)
                    .unwrap();
            assert_eq!(
                out,
                crate::storage::client_db::CanonicalApplyInsertOutcome::Inserted
            );
            tx.commit().unwrap();
        }
        // NO redelivery: recovery alone converges.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(recover_incomplete_acceptances(&WRAP)).unwrap();
        assert_eq!(
            get_acceptance_journal(&rel, &parent)
                .unwrap()
                .unwrap()
                .status,
            STATUS_COMPLETE
        );
        assert!(outbound_reply_exists(&[0x84u8; 32]).unwrap());
        assert_eq!(
            load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap(),
            Some(vec![0xBBu8; 40])
        );
        // And a prepared journal with NO record stays prepared:
        let rel2 = [0x91u8; 32];
        let parent2 = [0x92u8; 32];
        prepare_bside_acceptance_receipt_locked(rel2, parent2, || {
            Ok(make_artifacts([0x93u8; 32], [0x94u8; 32], b"BYTES-NOREC"))
        })
        .unwrap();
        rt.block_on(recover_incomplete_acceptances(&WRAP)).unwrap();
        assert_eq!(
            get_acceptance_journal(&rel2, &parent2)
                .unwrap()
                .unwrap()
                .status,
            STATUS_PREPARED
        );
    }

    #[test]
    #[serial]
    fn concurrent_prepare_generates_once_async_lock() {
        init_test_db();
        let rel = [0xA1u8; 32];
        let parent = [0xA2u8; 32];
        let calls = Arc::new(AtomicUsize::new(0));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut handles = Vec::new();
            for _ in 0..4 {
                let calls = calls.clone();
                handles.push(tokio::spawn(async move {
                    let lock = relationship_lock(&rel);
                    let _guard = lock.lock_owned().await;
                    prepare_bside_acceptance_receipt_locked(rel, parent, || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(make_artifacts([0xA3u8; 32], [0xA4u8; 32], b"BYTES-CONC"))
                    })
                    .unwrap()
                }));
            }
            for h in handles {
                assert_eq!(h.await.unwrap(), b"BYTES-CONC");
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
