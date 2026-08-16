// SPDX-License-Identifier: MIT OR Apache-2.0
//! Storage route handlers for AppRouterImpl.
//!
//! Handles `storage.status` and `storage.sync` query paths.

use dsm::types::proto as generated;
use dsm::types::identifiers::TransactionId;
use prost::Message;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};
use super::transfer_helpers::build_online_receipt_with_smt;
use super::app_router_impl::{
    collect_tagged_inbox_addresses, ensure_inbox_recipient_targets_local, InboxBatchState,
    RouteFreshness,
};
#[cfg(feature = "dev-discovery")]
use crate::sdk::network_detection::get_network_gate;

fn decode_canonical_b32_32(label: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = crate::util::text_id::decode_base32_crockford(value)
        .ok_or_else(|| format!("{label} is not valid base32"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{label} must decode to exactly 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// Prefer the receiver-local archival receipt when we can build it, but never
// leave the UI empty if the incoming receipt was already cryptographically verified.
fn select_history_receipt_bytes(
    rebuilt_receipt: Option<Vec<u8>>,
    verified_receipt_commit: &[u8],
) -> Option<Vec<u8>> {
    rebuilt_receipt.or_else(|| {
        if verified_receipt_commit.is_empty() {
            None
        } else {
            Some(verified_receipt_commit.to_vec())
        }
    })
}

#[cfg(all(target_os = "android", feature = "jni"))]
fn emit_authoritative_wallet_refresh() {
    if let Err(e) = crate::jni::event_dispatch::post_event_to_webview("dsm-wallet-refresh", &[]) {
        log::debug!("[storage.sync] wallet refresh dispatch skipped: {e}");
    }
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn emit_authoritative_wallet_refresh() {}

fn mark_contact_needs_online_reconcile_and_refresh(device_id: &[u8]) {
    match crate::storage::client_db::mark_contact_needs_online_reconcile(device_id) {
        Ok(()) => emit_authoritative_wallet_refresh(),
        Err(e) => {
            log::warn!(
                "[storage.sync] failed to mark relationship blocked for {} bytes of device id: {}",
                device_id.len(),
                e
            );
        }
    }
}

/// Non-authoritative history/UI residue after a split transfer is accepted.
///
/// The balance is already materialized by the full-state apply; the acceptance
/// reply is already enqueued by convergence. This only writes the local
/// transaction row the History tab reads and refreshes the in-memory caches.
/// Every failure is non-fatal and logged — none of this is protocol state.
fn record_accepted_split_history(
    correlation_key: &str,
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    sender_b32: &str,
    self_b32: &str,
    amount: u64,
    token_id: String,
) {
    use crate::storage::codecs::hash_blake3_bytes;

    let tx_hash = crate::util::text_id::encode_base32_crockford(&hash_blake3_bytes(
        correlation_key.as_bytes(),
    ));
    let mut meta: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    meta.insert("token_id".to_string(), token_id.into_bytes());
    meta.insert("adr0003_split".to_string(), b"true".to_vec());
    let rec = crate::storage::client_db::TransactionRecord {
        tx_id: correlation_key.to_string(),
        tx_hash,
        from_device: sender_b32.to_string(),
        to_device: self_b32.to_string(),
        amount,
        tx_type: "online".to_string(),
        status: "confirmed".to_string(),
        chain_height: 0,
        step_index: 0,
        commitment_hash: None,
        proof_data: receipt.to_full_protobuf().ok(),
        metadata: meta,
        created_at: 0,
    };
    if let Err(e) = crate::storage::client_db::store_transaction(&rec) {
        log::warn!("[storage.sync] ADR 0003 store_transaction failed for {correlation_key}: {e} (non-fatal)");
    }
    if let Some(router) = crate::bridge::app_router() {
        router.sync_balance_cache();
    }
    emit_authoritative_wallet_refresh();
}

fn record_observed_remote_tip_and_refresh(device_id: &[u8], observed_tip: &[u8; 32]) {
    match crate::storage::client_db::record_observed_remote_chain_tip(
        device_id,
        observed_tip,
        crate::storage::client_db::ObservedRemoteTipSource::DeferredInbox,
    ) {
        Ok(()) => emit_authoritative_wallet_refresh(),
        Err(e) => {
            log::warn!(
                "[storage.sync] failed to record observed remote relationship tip for {} bytes of device id: {}",
                device_id.len(),
                e
            );
        }
    }
}

/// Verify an inbound stitched receipt's sender authorization (`sig_a`) the way
/// the sender actually produces it (§11.1 per-step EK).
///
/// The online `wallet.send` path signs `sig_a` with a freshly-derived per-step
/// EK (`receipt.ek_pk_a`, cert-chained to the sender's AK via `ek_cert_a`) over
/// the receipt challenge-response target — NOT with the sender's static signing
/// key over the raw commitment. The genesis cert-chain root is the sender's
/// AK_pk, which equals the static signing key published as
/// `sender_signing_public_key` (`ak_pk_genesis` here). `session_binding` for the
/// online path is the receipt commitment itself (`app_router_impl` passes
/// `session_binding: &commitment`).
///
/// VERIFY ONLY — this does NOT mutate the Counterparty cert-chain head. The head
/// is advanced by the acceptance fold's completion phase (CAS, §16.6) only after
/// the transition is durably applied and the acceptance marker is written, so a
/// receipt that verifies but fails to apply never advances the receiver's chain
/// (lockstep: a failed acceptance leaves both chains where they were).
/// Resolve the SPHINCS+ key an inbound online entry is verified against.
///
/// TRUST ROOT: the sender's AK comes from the LOCALLY STORED contact, never
/// from the wire artifact.
///
/// This drain previously preferred `entry.sender_signing_public_key` and then
/// verified that entry's own signature against it, so an attacker who could
/// place an inbox entry supplied both the key and a signature made with the
/// matching secret — SIG A verified against the attacker's own root. Ordinary
/// transfer verification must not bootstrap trust from the same message it is
/// authenticating; establishing an AK for an unknown sender needs its own
/// authenticated identity rule.
///
/// A wire-embedded key that disagrees with the stored AK is a signal, not a
/// tiebreak: it is reported and ignored, and verification stays rooted in the
/// stored value.
///
/// Extracted so the property is unit-testable rather than buried in the drain.
pub(crate) fn resolve_trusted_sender_ak(
    sender_device_id: &str,
    wire_supplied: &[u8],
) -> Result<Vec<u8>, String> {
    let trusted = crate::storage::client_db::get_contact_public_key_by_device_id(sender_device_id)
        .ok_or_else(|| {
            format!(
                "no locally trusted sender AK for {sender_device_id}; wire-supplied keys are \
                 never trusted"
            )
        })?;
    if !wire_supplied.is_empty() && wire_supplied != trusted.as_slice() {
        log::warn!(
            "[storage.sync] ⚠️ entry from {sender_device_id} embeds a sender key that differs \
             from the stored AK; IGNORING the wire value"
        );
    }
    Ok(trusted)
}

pub(crate) fn verify_inbound_receipt_sig_a(
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    commitment: &[u8; 32],
    ak_pk_genesis: &[u8],
) -> Result<(), String> {
    use crate::storage::client_db::{load_cert_chain_head_pubkey, CertChainSide};

    let rel_key =
        dsm::verification::smt_replace_witness::compute_smt_key(&receipt.devid_a, &receipt.devid_b);
    // From the receiver's viewpoint the SENDER (A-side) is the Counterparty.
    // At relationship genesis (no Counterparty head yet) the sender's ek_cert_a
    // chains back to the sender's AK — the legitimate predecessor.
    let expected_prev_pk = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
        .ok()
        .flatten()
        .unwrap_or_else(|| ak_pk_genesis.to_vec());

    crate::sdk::receipts::verify_per_step_ek_signing(
        receipt,
        crate::sdk::receipts::BilateralSide::A,
        &expected_prev_pk,
        &receipt.parent_tip,
        commitment,
    )
    .map_err(|e| e.to_string())
}

/// AUTHENTICATED CAPABILITY HYDRATION (§16.6) — not migration residue.
///
/// A valid relationship can exist locally while its cached ML-KEM capability is
/// absent; the B-side receipt encapsulates `kyber_ct_b` to the sender's key, so
/// that gap fail-closes every inbound acceptance. This hydrates the missing
/// capability from the registry under strict rules:
///
///   * runs ONLY when the local key is missing (caller-enforced, re-asserted here);
///   * NEVER replaces a nonempty locally-bound key — persist is first-write-wins;
///   * verifies the registry binding against the STORED pairing AK, device id,
///     and genesis (never wire evidence, never the registry record itself);
///   * conflicting or ambiguous registry data fails closed;
///   * a registry failure returns an error and NEVER degrades into an insecure
///     fallback — the acceptance simply stays fail-closed and retries later.
///
/// Nothing is persisted on any error path.
async fn hydrate_missing_sender_kyber_capability(
    storage_endpoints: &[String],
    sender_device_id: [u8; 32],
    contact: &crate::storage::client_db::ContactRecord,
) -> Result<Vec<u8>, String> {
    // Re-assert the precondition at the boundary: hydration is only ever for an
    // ABSENT capability. A present key is authoritative and is returned as-is.
    if !contact.kyber_public_key.is_empty() {
        return Ok(contact.kyber_public_key.clone());
    }
    if contact.public_key.is_empty() {
        return Err(
            "contact has no pairing-established AK to verify the Kyber binding".to_string(),
        );
    }
    let contact_genesis: [u8; 32] = contact
        .genesis_hash
        .as_slice()
        .try_into()
        .map_err(|_| "contact genesis_hash is not 32 bytes".to_string())?;

    // Quorum lookup: a single equivocating node cannot decide this. Any transport
    // or agreement failure propagates as an error (no fallback).
    let identity = crate::handlers::app_router_impl::fetch_quorum_device_identity(
        storage_endpoints,
        sender_device_id,
    )
    .await?;
    if identity.device_id != sender_device_id {
        return Err("registry device_id diverges from the relationship counterparty".to_string());
    }
    if identity.genesis_hash != contact_genesis {
        return Err("registry genesis diverges from the pairing-established genesis".to_string());
    }
    crate::sdk::kyber_identity::verify_kyber_identity_binding(
        &sender_device_id,
        &contact_genesis,
        &identity.kyber_public_key,
        &identity.kyber_binding_sig,
        &contact.public_key,
    )
    .map_err(|e| format!("sender Kyber identity binding invalid: {e}"))?;

    // First-write-wins. Losing the race means another path bound a key
    // concurrently; that stored key is authoritative and is used instead.
    let bound = crate::storage::client_db::bind_contact_kyber_key_if_absent(
        &sender_device_id,
        &identity.kyber_public_key,
    )
    .map_err(|e| format!("failed to persist verified sender Kyber key: {e}"))?;
    if bound {
        return Ok(identity.kyber_public_key);
    }
    match crate::storage::client_db::get_contact_by_device_id(&sender_device_id) {
        Ok(Some(c)) if !c.kyber_public_key.is_empty() => Ok(c.kyber_public_key),
        _ => Err("Kyber capability vanished between bind and read — failing closed".to_string()),
    }
}

/// §16.6 SENDER FINALIZATION on cryptographic proof.
///
/// An online transition finalizes here — on a verified recipient countersignature —
/// and NEVER on storage-node message deletion, which is best-effort GC. The
/// returned receipt is matched to the sender's ONE persisted proposal by
/// commitment, verified against that proposal's CANONICAL pair (the gate holds
/// projection values and must never be used for this comparison), and only then
/// is the gate released and the proposal terminally finalized.
///
/// Every failure path leaves the gate intact: an unmatched, stale, or invalid
/// artifact must never release a pending transition. Idempotent — a redelivered
/// reply finds the proposal already finalized and does nothing.
/// Glue for one polled ADR 0003 transfer half.
///
/// FAILS CLOSED on missing raw bytes. There is deliberately no re-encode
/// fallback: staging freezes what it is handed, and SIG A is later checked
/// against that frozen copy, so reconstructing the request from decoded fields
/// would mean verifying bytes the sender never signed. An entry that reached
/// here without its originals is a bug in the fetch path, and the only safe
/// response is to refuse it and say so.
fn stage_polled_transfer_half(entry: &crate::sdk::b0x_sdk::B0xEntry) {
    use crate::handlers::recipient_dispatch::{dispatch_transfer_half, DispatchOutcome};

    let key = entry.transaction_id.as_str();
    // The route this half was polled from. `inbox_key` is set to the b0x
    // address by `retrieve_from_b0x_v2`; it is empty only for locally-built
    // entries, which never reach this path. Retained on the staging row so
    // the partner half — replayed under the same frozen route — is still
    // received after the relationship tip advances.
    let route = entry.inbox_key.as_str();
    if route.is_empty() {
        log::error!(
            "[storage.sync] ❌ REJECTING split transfer {key}: no inbox route recorded on the              polled entry; a half with no route cannot anchor its partner"
        );
        return;
    }
    if entry.transfer_wire_bytes.is_empty() {
        log::error!(
            "[storage.sync] ❌ REJECTING split transfer {key}: the original \
             OnlineTransferRequest bytes were not retained. Refusing to reconstruct them — \
             staging freezes what it is given and SIG A is verified against that copy."
        );
        return;
    }
    let ak = match resolve_trusted_sender_ak(
        &entry.sender_device_id,
        &entry.sender_signing_public_key,
    ) {
        Ok(k) => k,
        Err(e) => {
            log::warn!("[storage.sync] ❌ REJECTING split transfer {key}: {e}");
            return;
        }
    };
    match dispatch_transfer_half(key, &entry.transfer_wire_bytes, &ak, route) {
        Ok(DispatchOutcome::Staged(state)) => {
            log::info!(
                "[storage.sync] ADR 0003 transfer {key} staged → {}",
                state.as_str()
            )
        }
        Ok(DispatchOutcome::DiscardedCandidate(why)) => {
            log::warn!("[storage.sync] ADR 0003 transfer {key} discarded: {why}")
        }
        Ok(other) => log::warn!("[storage.sync] ADR 0003 transfer {key}: unexpected {other:?}"),
        Err(e) => log::error!("[storage.sync] ADR 0003 transfer {key} dispatch failed: {e}"),
    }
}

/// Glue for one polled ADR 0003 evidence half.
///
/// The sender identity comes from the receipt's own `devid_a`, and the AK from
/// the STORED contact for that device — never from the artifact. Everything
/// after that is the dispatcher's decision, including whether the bytes are
/// allowed to occupy a staging slot at all.
fn stage_polled_evidence_half(evidence: &dsm::types::proto::ReceiptEvidenceA, route: &str) {
    use crate::handlers::recipient_dispatch::{dispatch_evidence_half, DispatchOutcome};

    let key = evidence.transfer_submission_id.as_str();
    // Read devid_a only to name the trust root. The bytes are re-decoded and
    // fully verified inside the dispatcher against that root.
    let sender = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &evidence.full_receipt_bytes,
    ) {
        Ok(r) => crate::util::text_id::encode_base32_crockford(&r.devid_a),
        Err(e) => {
            log::warn!("[storage.sync] ADR 0003 evidence {key}: receipt does not decode: {e}");
            return;
        }
    };
    let ak = match resolve_trusted_sender_ak(&sender, &[]) {
        Ok(k) => k,
        Err(e) => {
            log::warn!("[storage.sync] ADR 0003 evidence {key}: {e}");
            return;
        }
    };
    match dispatch_evidence_half(evidence, &ak, route) {
        Ok(DispatchOutcome::Staged(state)) => {
            log::info!(
                "[storage.sync] ADR 0003 evidence {key} staged → {}",
                state.as_str()
            )
        }
        Ok(DispatchOutcome::DiscardedCandidate(why)) => {
            // No slot was taken, so an honest copy of this half can still arrive.
            log::warn!("[storage.sync] ADR 0003 evidence {key} discarded: {why}")
        }
        Ok(other) => log::warn!("[storage.sync] ADR 0003 evidence {key}: unexpected {other:?}"),
        Err(e) => log::error!("[storage.sync] ADR 0003 evidence {key} dispatch failed: {e}"),
    }
}

/// What one B-side countersign delta did on the sender. Every arm is a
/// distinct, testable fact — "nothing changed" is never the whole answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CountersignOutcome {
    /// The body is not a canonical `ReceiptCountersignB` (a whole receipt on
    /// this method lands here: "unknown field 7").
    WireRejected(String),
    /// No proposal for that commitment — not ours; nothing written.
    NoProposal,
    /// Already finalized — idempotent no-op.
    AlreadyFinalized,
    /// The proposal has NO frozen evidence_a row. On a clean install this
    /// cannot happen (the artifact commits with the proposal); it is an
    /// invariant violation, not a transient, and the step cannot finalize.
    NoRetainedEvidence,
    /// The sender's own retained A bytes are unusable (digest mismatch with
    /// their stored digest, or not an A-side receipt). Nothing written.
    LocalEvidenceCorrupt(String),
    /// The delta names A bytes other than the ones this sender retained; the
    /// step is parked awaiting a valid replacement, like a verifier rejection.
    DigestMismatch(String),
    /// Local identity / recipient AK unavailable; nothing written.
    Unverifiable(String),
    /// The reconstructed receipt failed the acceptance verifier; parked.
    Rejected(String),
    /// Verified and finalized atomically.
    Finalized,
    /// Verified, but the atomic commit failed; retried on the next poll.
    FinalizeFailed(String),
}

/// Sender-side finalization from an ADR 0003 B-side countersign delta.
///
/// The recipient never ships the whole countersigned receipt (218 KB, over the
/// node cap). It ships `ReceiptCountersignB`; this overlays it onto the A-side
/// receipt the sender froze at send time and runs the UNCHANGED acceptance
/// verifier and the UNCHANGED atomic finalization. That reconstruction is the
/// load-bearing binding — B material is only ever judged against the A side the
/// sender itself authored.
async fn finalize_from_countersign_delta(
    delta: &crate::sdk::b0x_sdk::CountersignDelta,
) -> CountersignOutcome {
    use crate::handlers::online_finalize::{
        bind_countersign_delta, load_retained_evidence_a, DeltaBinding,
    };
    use crate::storage::client_db::sender_outbox::{
        derive_artifact_submission_id, evidence_content_digest, ArtifactRole, SenderOutboxArtifact,
    };
    use crate::storage::client_db::sender_proposal::{
        get_sender_proposal_by_commitment, PROPOSAL_FINALIZED,
    };

    let wire = match dsm::types::receipt_types::decode_receipt_countersign_b_wire(&delta.body) {
        Ok(w) => w,
        Err(e) => {
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta {} refused at the wire: {e}",
                delta.message_id
            );
            return CountersignOutcome::WireRejected(e.to_string());
        }
    };
    let commitment: [u8; 32] = match wire.commitment.as_slice().try_into() {
        Ok(c) => c,
        Err(_) => {
            return CountersignOutcome::WireRejected("commitment is not 32 bytes".to_string())
        }
    };
    let short = crate::util::text_id::encode_base32_crockford(&commitment[..4]);

    let proposal = match get_sender_proposal_by_commitment(&commitment) {
        Ok(Some(p)) => p,
        Ok(None) => {
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta ignored: no proposal for commitment \
                 {short}.. (not ours) — gate retained"
            );
            return CountersignOutcome::NoProposal;
        }
        Err(e) => {
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta lookup failed for {short}..: {e}"
            );
            return CountersignOutcome::Unverifiable(format!("proposal lookup: {e}"));
        }
    };

    if proposal.status == PROPOSAL_FINALIZED {
        log::info!(
            "[storage.sync] ADR 0003 countersign delta {short}.. already finalized — idempotent no-op"
        );
        return CountersignOutcome::AlreadyFinalized;
    }

    let retained = match load_retained_evidence_a(&proposal) {
        Ok(Some(r)) => r,
        Ok(None) => {
            log::error!(
                "[storage.sync] ADR 0003 countersign delta {short}..: proposal has NO retained \
                 evidence_a artifact — invariant violated (the artifact commits with the \
                 proposal); this step cannot finalize"
            );
            return CountersignOutcome::NoRetainedEvidence;
        }
        Err(e) => {
            log::error!(
                "[storage.sync] ADR 0003 countersign delta {short}..: retained evidence_a \
                 unusable: {e}"
            );
            return CountersignOutcome::LocalEvidenceCorrupt(e.to_string());
        }
    };

    // Reconstruct the countersigned receipt from OUR A bytes + the delta.
    let receipt = match bind_countersign_delta(&retained, &wire) {
        Ok(DeltaBinding::Bound(r)) => *r,
        Ok(DeltaBinding::Rejected { reason }) => {
            park_awaiting_valid_reply(&proposal, &short, &reason);
            return CountersignOutcome::DigestMismatch(reason);
        }
        Err(e) => {
            log::error!(
                "[storage.sync] ADR 0003 countersign delta {short}..: retained evidence_a \
                 unusable: {e}"
            );
            return CountersignOutcome::LocalEvidenceCorrupt(e.to_string());
        }
    };

    let self_device_id: [u8; 32] = match crate::sdk::app_state::AppState::get_device_id()
        .and_then(|d| <[u8; 32]>::try_from(d.as_slice()).ok())
    {
        Some(d) => d,
        None => {
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta {short}..: local device_id unavailable"
            );
            return CountersignOutcome::Unverifiable("local device_id unavailable".to_string());
        }
    };

    // The recipient's AK from the STORED contact — the cert-chain genesis root.
    // Never taken from the wire.
    let recipient_ak_pk = match crate::storage::client_db::get_contact_public_key_by_device_id(
        &crate::util::text_id::encode_base32_crockford(&proposal.counterparty_device_id),
    ) {
        Some(pk) => pk,
        None => {
            match crate::storage::client_db::get_contact_by_device_id(
                &proposal.counterparty_device_id,
            ) {
                Ok(Some(c)) if !c.public_key.is_empty() => c.public_key,
                _ => {
                    log::warn!(
                        "[storage.sync] ADR 0003 countersign delta {short}..: no stored AK for \
                         the recipient — cannot verify sig_b, gate retained"
                    );
                    return CountersignOutcome::Unverifiable(
                        "no stored AK for the recipient".to_string(),
                    );
                }
            }
        }
    };

    match crate::handlers::online_finalize::verify_acceptance_receipt(
        &self_device_id,
        &proposal.counterparty_device_id,
        &receipt,
        &proposal,
        &recipient_ak_pk,
        None,
        None,
    ) {
        Ok(crate::handlers::online_finalize::ReceiptVerifyOutcome::Verified { .. }) => {}
        Ok(crate::handlers::online_finalize::ReceiptVerifyOutcome::Rejected { reason }) => {
            // The gate is retained (correct — this artifact proved nothing), but
            // the step must NOT be left stranded at `submitted` with no exit.
            // Receipt fields 12-20 are outside every signature, so a middlebox or
            // a single malicious replica can produce a delta that passes the
            // strict decode yet trips a check here. Without this transition, one
            // such artifact pins the proposal at `submitted` forever: `finalized`
            // is the only other reachable state and it needs the very reply that
            // was just refused.
            //
            // This is NOT a rollback. The recipient may already have applied and
            // credited the transfer, so nothing is un-spent or reverted; the step
            // is simply marked as awaiting a VALID replacement artifact for the
            // same commitment, which can still finalize it.
            park_awaiting_valid_reply(&proposal, &short, &reason);
            return CountersignOutcome::Rejected(reason);
        }
        Err(e) => {
            log::error!(
                "[storage.sync] ADR 0003 countersign delta {short}.. verification errored: {e}"
            );
            return CountersignOutcome::Unverifiable(format!("verification errored: {e}"));
        }
    }

    // ====================================================================
    // §16.6 DEFECT 1 — ONE ATOMIC FINALIZATION.
    //
    // Verified. Everything this acceptance proof authorises now commits in a
    // SINGLE transaction: projection tip advance, Local EK-head promotion,
    // Counterparty EK-head advance, proposal finalization, gate release, the
    // outbox moving to `gc_pending`, and the delta persisted as the sender's
    // countersign_b artifact.
    //
    // The previous code finalized the proposal and deleted the gate HERE, and
    // left the tip advance and head promotion to the §5.4 ACK sweep — which
    // iterates the very gate this had just deleted, making them unreachable.
    // That is why every SECOND transfer on a relationship failed ("divergent
    // local bilateral chain tip") and re-chained from the root AK
    // (`used_root_ak=true`). Splitting this sequence is the defect, so it is
    // not split.
    // ====================================================================
    let expected_counterparty_head = match crate::storage::client_db::load_cert_chain_head_pubkey(
        &proposal.relationship_key,
        crate::storage::client_db::CertChainSide::Counterparty,
    ) {
        Ok(head) => head,
        Err(e) => {
            log::error!(
                "[storage.sync] §16.6 could not read counterparty head for {short}.. — \
                 refusing to finalize (retry from the durable outbox): {e}"
            );
            return CountersignOutcome::FinalizeFailed(format!("counterparty head read: {e}"));
        }
    };

    let content_digest = evidence_content_digest(ArtifactRole::CountersignB, &delta.body);
    let countersign_artifact = SenderOutboxArtifact {
        relationship_key: proposal.relationship_key,
        canonical_parent: proposal.canonical_parent,
        proposal_nonce: proposal.nonce_hash,
        role: ArtifactRole::CountersignB,
        submission_id: derive_artifact_submission_id(&content_digest),
        envelope_bytes: delta.envelope_bytes.clone(),
        content_digest,
    };

    match crate::storage::client_db::finalize_on_acceptance_atomically(
        &proposal.relationship_key,
        &proposal.canonical_parent,
        &proposal.nonce_hash,
        &proposal.commitment,
        &proposal.counterparty_device_id,
        &proposal.projection_parent,
        &proposal.projection_target,
        expected_counterparty_head.as_deref(),
        &receipt.ek_pk_b,
        &countersign_artifact,
    ) {
        Ok(()) => {
            log::info!(
                "[storage.sync] §16.6 FINALIZED atomically on acceptance proof: \
                 commitment={short}.. tx={} (tip advanced, both cert heads promoted, \
                 gate released, outbox gc_pending, countersign_b retained)",
                proposal.tx_id
            );
            // The retired §5.4 sweep emitted this on tip advance; the tip now
            // advances here, so the refresh belongs here.
            emit_authoritative_wallet_refresh();
            CountersignOutcome::Finalized
        }
        Err(e) => {
            log::error!(
                "[storage.sync] §16.6 atomic finalization failed for {short}.. — NOTHING \
                 committed, retries from the durable outbox row: {e}"
            );
            CountersignOutcome::FinalizeFailed(e.to_string())
        }
    }
}

/// Park a step whose delta proved nothing: awaiting a VALID replacement
/// artifact for the same commitment. Not a rollback — see the caller.
fn park_awaiting_valid_reply(
    proposal: &crate::storage::client_db::sender_proposal::SenderOnlineProposal,
    short: &str,
    reason: &str,
) {
    match crate::storage::client_db::mark_sender_proposal_awaiting_valid_reply(
        &proposal.relationship_key,
        &proposal.canonical_parent,
    ) {
        Ok(true) => log::error!(
            "[storage.sync] ADR 0003 countersign delta {short}.. REJECTED: {reason} — gate \
             retained, step now awaiting a valid replacement artifact"
        ),
        Ok(false) => log::error!(
            "[storage.sync] ADR 0003 countersign delta {short}.. REJECTED: {reason} — gate \
             retained; proposal status unchanged (already finalized, or never submitted)"
        ),
        Err(e) => log::error!(
            "[storage.sync] ADR 0003 countersign delta {short}.. REJECTED: {reason} — gate \
             retained, but recording the awaiting-valid-reply state FAILED: {e}"
        ),
    }
}

/// §16.6 reply-window delivery sweep.
///
/// Hands every durably-countersigned-but-undelivered acceptance receipt back to
/// its original sender. Each reply is addressed to the tip the SENDER polls (the
/// projection parent captured at PREPARE, carried in the journal) — NOT to this
/// device's own projection, which has already advanced past it by the time the
/// fold completes.
///
/// The sender's identity comes from the STORED contact (genesis + device id),
/// never from wire material. A reply whose counterparty contact is missing is
/// skipped and retried next sweep rather than guessed at.
async fn deliver_pending_acceptance_replies(
    storage_endpoints: &[String],
    core_sdk: std::sync::Arc<crate::sdk::core_sdk::CoreSDK>,
) -> Result<(), String> {
    use crate::storage::client_db::{mark_reply_submitted, pending_outbound_replies};

    let pending = pending_outbound_replies().map_err(|e| e.to_string())?;
    if pending.is_empty() {
        return Ok(());
    }
    log::info!(
        "[storage.sync] §16.6 reply window: {} undelivered acceptance repl{}",
        pending.len(),
        if pending.len() == 1 { "y" } else { "ies" }
    );

    let local_device_b32 = match crate::sdk::app_state::AppState::get_device_id() {
        Some(d) if d.len() == 32 => crate::util::text_id::encode_base32_crockford(&d),
        _ => return Err("local device_id unavailable for reply delivery".to_string()),
    };

    for reply in pending {
        let contact = match crate::storage::client_db::get_contact_by_device_id(
            &reply.counterparty_device_id,
        ) {
            Ok(Some(c)) => c,
            _ => {
                log::warn!(
                    "[storage.sync] §16.6 reply skipped: no contact for counterparty {}.. (retry next sweep)",
                    crate::util::text_id::encode_base32_crockford(&reply.counterparty_device_id[..4]),
                );
                continue;
            }
        };
        let sender_genesis: [u8; 32] = match contact.genesis_hash.as_slice().try_into() {
            Ok(g) => g,
            Err(_) => {
                log::warn!("[storage.sync] §16.6 reply skipped: contact genesis not 32 bytes");
                continue;
            }
        };

        // NOTE: the envelope is built from `dsm::types::proto`, which is a SEPARATE
        // prost generation from `crate::generated` — same schema, distinct Rust types.
        let mut b0x = match crate::sdk::b0x_sdk::B0xSDK::new(
            local_device_b32.clone(),
            core_sdk.clone(),
            storage_endpoints.to_vec(),
        ) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[storage.sync] §16.6 reply skipped: B0xSDK init failed: {e}");
                continue;
            }
        };
        // The stored row keeps the FULL countersigned receipt; only the B-side
        // delta derived from it goes on the wire (ADR 0003 return leg). A row
        // the builder refuses is a local defect, not a transport condition — it
        // is logged at error and left unmarked so it stays visible.
        match b0x
            .submit_acceptance_reply(
                &sender_genesis,
                &reply.counterparty_device_id,
                &reply.projection_parent_tip,
                &reply.commitment,
                &reply.receipt_bytes,
            )
            .await
        {
            Ok(msg_id) => {
                mark_reply_submitted(&reply.commitment).map_err(|e| e.to_string())?;
                log::info!(
                    "[storage.sync] §16.6 countersign delta delivered msg={}.. commitment={}..",
                    &msg_id[..8.min(msg_id.len())],
                    crate::util::text_id::encode_base32_crockford(&reply.commitment[..4]),
                );
            }
            Err(e) if matches!(e, dsm::types::error::DsmError::Network { .. }) => {
                // Left unmarked on purpose — retried on the next sweep.
                log::warn!("[storage.sync] §16.6 reply delivery failed (will retry): {e}");
            }
            Err(e) => {
                log::error!(
                    "[storage.sync] §16.6 reply for commitment {}.. could not be built from the                      stored receipt ({} bytes) — local defect, left unmarked: {e}",
                    crate::util::text_id::encode_base32_crockford(&reply.commitment[..4]),
                    reply.receipt_bytes.len(),
                );
            }
        }
    }
    Ok(())
}

/// Upper bound on frozen sends re-driven per poll, so a dead network cannot pin
/// the poller for minutes replaying a backlog. Anything past the bound waits for
/// the next poll; ordering by `created_at` keeps cross-transfer causality.
const OUTBOX_RESUBMIT_ROWS_PER_POLL: usize = 8;

impl AppRouterImpl {
    /// §16.6 liveness — replay every unsettled frozen send through the shared
    /// delivery primitive. Returns how many logical sends reached full quorum
    /// on this pass.
    ///
    /// Selection is `unsettled_sender_outbox()`: `pending_submit`, `submitting`
    /// and `submission_uncertain`. All three mean "may or may not have entered
    /// the network"; replay is idempotent by id, so they are treated alike. Rows
    /// this process is already delivering (first attempt still on the wire) are
    /// skipped — that is traffic suppression, not a correctness guard.
    ///
    /// Per row: load the frozen artifacts, deliver the whole set, and only on
    /// complete success CAS the row to `submitted`. A partial or failed delivery
    /// leaves the row exactly as it was; the next sweep replays the whole
    /// frozen set again. There is deliberately no half-delivered state.
    pub(crate) async fn resubmit_unsettled_sender_outbox(
        &self,
        device_id_b32: &str,
        storage_endpoints: &[String],
    ) -> Result<u32, String> {
        use crate::storage::client_db::{
            advance_sender_outbox_status_if, bind_sender_outbox_message_ids,
            load_sender_outbox_artifacts, mark_sender_proposal_submitted_if_proposed,
            unsettled_sender_outbox, DeliveryInFlight, OUTBOX_PENDING_SUBMIT,
            OUTBOX_SUBMISSION_UNCERTAIN, OUTBOX_SUBMITTED, OUTBOX_SUBMITTING,
        };

        let rows =
            unsettled_sender_outbox().map_err(|e| format!("unsettled_sender_outbox: {e}"))?;
        if rows.is_empty() {
            return Ok(0);
        }
        if storage_endpoints.is_empty() {
            return Err("no storage endpoints configured; cannot resubmit".to_string());
        }

        let mut b0x = crate::sdk::b0x_sdk::B0xSDK::new(
            device_id_b32.to_string(),
            self.core_sdk.clone(),
            storage_endpoints.to_vec(),
        )
        .map_err(|e| format!("B0xSDK init for resubmit: {e}"))?;
        let retry = crate::sdk::b0x_sdk::B0xRetryConfig::default();

        let mut delivered = 0u32;
        let total = rows.len();
        for row in rows.into_iter().take(OUTBOX_RESUBMIT_ROWS_PER_POLL) {
            let Some(_slot) = DeliveryInFlight::claim(
                &row.relationship_key,
                &row.canonical_parent,
                &row.proposal_nonce,
            ) else {
                log::debug!(
                    "[storage.sync] outbox resubmit: {} in flight in this process; skipping",
                    row.submission_id
                );
                continue;
            };

            let artifacts = match load_sender_outbox_artifacts(
                &row.relationship_key,
                &row.canonical_parent,
                &row.proposal_nonce,
            ) {
                Ok(a) => a,
                Err(e) => {
                    log::warn!(
                        "[storage.sync] outbox resubmit: {} artifacts unreadable; leaving \
                         {} for the next sweep: {e}",
                        row.submission_id,
                        row.status
                    );
                    continue;
                }
            };

            log::info!(
                "[storage.sync] outbox resubmit: replaying {} ({} bytes, {} artifact(s), \
                 was {}) to frozen route {}..",
                row.submission_id,
                row.envelope_bytes.len(),
                artifacts.len(),
                row.status,
                &row.routing_address[..row.routing_address.len().min(12)]
            );

            match b0x
                .deliver_frozen_logical_send(&row, &artifacts, &retry)
                .await
            {
                Ok(_) => {
                    // The row may have moved on while we were on the wire
                    // (recipient replied fast, another sync finalized it). CAS
                    // from the unsettled states only; anything else is left.
                    match advance_sender_outbox_status_if(
                        &row.relationship_key,
                        &row.canonical_parent,
                        &row.proposal_nonce,
                        &[
                            OUTBOX_PENDING_SUBMIT,
                            OUTBOX_SUBMITTING,
                            OUTBOX_SUBMISSION_UNCERTAIN,
                        ],
                        OUTBOX_SUBMITTED,
                    ) {
                        Ok(true) => {
                            delivered += 1;
                            log::info!(
                                "[storage.sync] ✅ outbox resubmit: {} now submitted",
                                row.submission_id
                            );
                        }
                        Ok(false) => log::info!(
                            "[storage.sync] outbox resubmit: {} delivered but the row already \
                             progressed past the unsettled states; leaving it",
                            row.submission_id
                        ),
                        Err(e) => log::warn!(
                            "[storage.sync] outbox resubmit: {} delivered but status CAS failed: {e}",
                            row.submission_id
                        ),
                    }
                    // Metadata binds. Guarded / non-authoritative; failure here
                    // never un-delivers anything.
                    if let Err(e) = mark_sender_proposal_submitted_if_proposed(
                        &row.relationship_key,
                        &row.canonical_parent,
                        &row.submission_id,
                    ) {
                        log::warn!(
                            "[storage.sync] outbox resubmit: {} proposal bind skipped: {e}",
                            row.submission_id
                        );
                    }
                    if row.message_ids.is_none() {
                        let _ = bind_sender_outbox_message_ids(
                            &row.relationship_key,
                            &row.canonical_parent,
                            &row.proposal_nonce,
                            &row.submission_id,
                        );
                    }
                }
                Err(e) => {
                    // Not proof of non-delivery. Row stays exactly as it was —
                    // no status write at all — and the whole frozen set is
                    // replayed on the next sweep.
                    log::warn!(
                        "[storage.sync] outbox resubmit: {} not fully delivered (row unchanged, \
                         will retry): {e}",
                        row.submission_id
                    );
                }
            }
        }

        if total > OUTBOX_RESUBMIT_ROWS_PER_POLL {
            log::info!(
                "[storage.sync] outbox resubmit: {} of {} unsettled rows attempted this poll; \
                 remainder next poll",
                OUTBOX_RESUBMIT_ROWS_PER_POLL,
                total
            );
        }
        Ok(delivered)
    }

    /// ADR 0003 — drive every complete-but-unfinished split pair through the
    /// EXISTING acceptance machinery, and hand back the ACK coordinates for
    /// every pair that reached durable `accepted`.
    ///
    /// Selection is `staging_rows_needing_completion()`: `ready_to_verify`
    /// (needs verify + apply) and `accepted` with a retained route (applied,
    /// ACK not yet proven; a released route means finished). Read
    /// from the database every poll — a process that died after both halves
    /// landed, or after apply but before ACK, is driven forward by what is
    /// durably true, never by which keys an earlier invocation happened to
    /// touch. The `Accepted` branch of `decide_ack` is the crash-after-apply
    /// re-ACK path, and enumerating durable rows is what makes it reachable
    /// across restart.
    ///
    /// Per pair the sequence is the legacy inline one, unchanged in order:
    ///
    ///   PREPARE (persist the exact B countersignature, BEFORE apply)
    ///   → APPLY (one atomic full-state tx, lookup-before-execute)
    ///   → CONVERGE (projection sync, CAS both heads, enqueue reply)
    ///   → history/UI
    ///   → ACK both halves, then release the retained route.
    ///
    /// PREPARE runs INSIDE the apply closure `decide_ack` hands us, so it is
    /// guaranteed to precede apply. If it ran after and the process died
    /// between them there would be no journal; `recover_incomplete_acceptances`
    /// iterates journals only, and once staging is `accepted` `decide_ack`
    /// short-circuits without ever yielding a `VerifiedTransfer` again — the
    /// pair would be credited on this side and unfinalizable on the sender's.
    ///
    /// Nothing here duplicates acceptance logic: verification, apply outcome
    /// classification, terminal reject and `mark_accepted` all live in
    /// `decide_ack → try_complete → verify_and_accept`. This is glue.
    ///
    /// Returns `(route, message_id)` pairs to ACK — two per accepted key, one
    /// for each half — plus the keys whose route should be released once those
    /// ACKs succeed.
    pub(crate) async fn complete_ready_split_transfers(
        &self,
        storage_endpoints: &[String],
    ) -> (Vec<(String, String)>, Vec<String>) {
        use crate::handlers::recipient_dispatch::{decide_ack, AckDecision};
        use crate::handlers::recipient_receipt as rr;
        use crate::storage::client_db::recipient_staging::{
            staging_rows_needing_completion, StagingState,
        };

        let mut acks: Vec<(String, String)> = Vec::new();
        let mut release_after_ack: Vec<String> = Vec::new();

        let rows = match staging_rows_needing_completion() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[storage.sync] ADR 0003 completion: staging read failed: {e}");
                return (acks, release_after_ack);
            }
        };
        if rows.is_empty() {
            return (acks, release_after_ack);
        }

        let Some(self_device_vec) = crate::sdk::app_state::AppState::get_device_id() else {
            log::warn!("[storage.sync] ADR 0003 completion: local device id unavailable");
            return (acks, release_after_ack);
        };
        let Ok(self_device) = <[u8; 32]>::try_from(self_device_vec.as_slice()) else {
            log::warn!("[storage.sync] ADR 0003 completion: local device id is not 32 bytes");
            return (acks, release_after_ack);
        };
        let self_device_b32 = crate::util::text_id::encode_base32_crockford(&self_device);

        for row in rows {
            let key = row.correlation_key.clone();

            // The evidence half carries the sender's identity and the trusted
            // receipt; without it there is nothing to verify against.
            let Some(evidence_bytes) = row.evidence_bytes.as_deref() else {
                continue;
            };
            let Ok(evidence_receipt) =
                dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                    evidence_bytes,
                )
            else {
                log::warn!(
                    "[storage.sync] ADR 0003 completion: {key} evidence does not decode; skipping"
                );
                continue;
            };
            let sender_device: [u8; 32] = evidence_receipt.devid_a;
            let sender_b32 = crate::util::text_id::encode_base32_crockford(&sender_device);
            if evidence_receipt.devid_b != self_device {
                log::warn!(
                    "[storage.sync] ADR 0003 completion: {key} names a different recipient; skipping"
                );
                continue;
            }

            // Trust root: the STORED contact AK, never the artifact.
            let sender_ak = match resolve_trusted_sender_ak(&sender_b32, &[]) {
                Ok(k) => k,
                Err(e) => {
                    log::warn!("[storage.sync] ADR 0003 completion: {key}: {e}");
                    continue;
                }
            };

            // Already applied: no prepare, no apply — just re-ACK from durable
            // state. `decide_ack` returns `Ack(AcceptedDuplicate)` here without
            // invoking the closure, which is why the closure below may assume
            // it is running for a genuinely `ready_to_verify` pair.
            if row.state != StagingState::Accepted {
                // ---- async prerequisites, resolved BEFORE the sync closure ----
                let rel_key = dsm::verification::smt_replace_witness::compute_smt_key(
                    &sender_device,
                    &self_device,
                );
                let (ak_pk, ak_sk) = match self.wallet.ak_keypair_for_cert_chain() {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("[storage.sync] ADR 0003 completion: {key}: AK keypair unavailable: {e}");
                        continue;
                    }
                };
                let sender_kyber_pk = match crate::storage::client_db::get_contact_by_device_id(
                    &sender_device,
                ) {
                    Ok(Some(c)) if !c.kyber_public_key.is_empty() => c.kyber_public_key,
                    Ok(Some(c)) => {
                        match hydrate_missing_sender_kyber_capability(
                            storage_endpoints,
                            sender_device,
                            &c,
                        )
                        .await
                        {
                            Ok(k) => k,
                            Err(e) => {
                                log::error!("[storage.sync] ADR 0003 completion: {key}: sender Kyber capability missing and hydration failed: {e} — fail closed");
                                continue;
                            }
                        }
                    }
                    _ => {
                        log::error!("[storage.sync] ADR 0003 completion: {key}: no contact for sender — fail closed");
                        continue;
                    }
                };
                let wrap_key = match crate::init::current_chain_head_at_rest_key() {
                    Ok(k) => k,
                    Err(e) => {
                        log::error!("[storage.sync] ADR 0003 completion: {key}: wrap key unavailable (wallet locked?): {e}");
                        continue;
                    }
                };
                let core_sdk = self.core_sdk.clone();

                // Relationship exclusion across prepare → apply → converge.
                let rel_lock = rr::relationship_lock(&rel_key);
                let _rel_guard = rel_lock.lock_owned().await;

                let sender_b32_for_apply = sender_b32.clone();
                let key_for_apply = key.clone();
                let decision = decide_ack(&key, &sender_ak, |v| {
                    // Everything derives from the VERIFIED transfer, exactly as
                    // the legacy path derives it from the verified entry.
                    let signed_parent = v.receipt.parent_tip;
                    let signed_child = v.receipt.child_tip;
                    let nonce: Vec<u8> = match &v.signed_op {
                        dsm::types::operations::Operation::Transfer { nonce, .. } => nonce.clone(),
                        _ => return Err("split transfer is not a Transfer op".to_string()),
                    };
                    let signed_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                        &signed_parent,
                        &v.canonical_operation_bytes,
                        &nonce,
                    );
                    let projection_parent: [u8; 32] =
                        match crate::storage::client_db::get_contact_chain_tip_raw(&sender_device) {
                            Some(t) if t != [0u8; 32] => t,
                            _ => dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                                &self_device,
                                &sender_device,
                            ),
                        };
                    let projection_target: [u8; 32] = {
                        let sigma_sym = dsm::core::bilateral_transaction_manager::compute_precommit(
                            &projection_parent,
                            &v.canonical_operation_bytes,
                            &nonce,
                        );
                        dsm::core::bilateral_transaction_manager::compute_successor_tip(
                            &projection_parent,
                            &v.canonical_operation_bytes,
                            &nonce,
                            &sigma_sym,
                        )
                    };

                    // PREPARE — BEFORE apply, idempotent, never re-signs.
                    rr::prepare_bside_acceptance_receipt_locked(
                        rel_key,
                        signed_parent,
                        (projection_parent, projection_target),
                        || {
                            rr::generate_b_artifacts_from_inbound(
                                &v.receipt,
                                &signed_sigma,
                                &sender_kyber_pk,
                                &ak_pk,
                                &ak_sk,
                                &wrap_key,
                            )
                        },
                    )
                    .map_err(|e| format!("prepare failed for {key_for_apply}: {e}"))?;

                    // APPLY — the one production canonical apply.
                    let tx_id =
                        crate::types::identifiers::TransactionId::new(key_for_apply.clone());
                    core_sdk
                        .apply_incoming_transfer_full_state(
                            v.signed_op.clone(),
                            &tx_id,
                            &sender_b32_for_apply,
                            &v.canonical_operation_bytes,
                            signed_parent,
                            signed_child,
                        )
                        .map_err(|e| format!("apply failed for {key_for_apply}: {e}"))
                });

                match decision {
                    Ok(AckDecision::Ack(acceptance)) => {
                        log::info!("[storage.sync] ADR 0003 completion: {key} {acceptance:?}");
                        // CONVERGE from durable state — tip sync, CAS both
                        // heads, enqueue the B reply. Idempotent when already
                        // complete. On failure the pair stays `accepted` and
                        // `recover_incomplete_acceptances` converges it next
                        // poll from the journal + apply record.
                        let parent = evidence_receipt.parent_tip;
                        let converged = match (
                            crate::storage::client_db::get_acceptance_journal(&rel_key, &parent),
                            crate::storage::client_db::get_canonical_apply_identity(
                                &rel_key, &parent,
                            ),
                        ) {
                            (Ok(Some(journal)), Ok(Some(record))) => {
                                rr::converge_accepted_locked(&journal, &record, &wrap_key)
                                    .map(|_| ())
                                    .map_err(|e| e.to_string())
                            }
                            (j, r) => Err(format!(
                                "journal/apply-record missing after accept (journal={} record={})",
                                j.map(|x| x.is_some()).unwrap_or(false),
                                r.map(|x| x.is_some()).unwrap_or(false)
                            )),
                        };
                        if let Err(e) = converged {
                            log::warn!("[storage.sync] ADR 0003 completion: {key} accepted but convergence deferred: {e}");
                            mark_contact_needs_online_reconcile_and_refresh(&sender_device);
                            // Do NOT ACK yet — the reply is not enqueued.
                            continue;
                        }
                        // Amount/token from the FROZEN transfer half (SIG A already verified
                        // over its canonical bytes by `verify_staged_transfer`).
                        let (amount, token_id) = row
                            .transfer_bytes
                            .as_deref()
                            .and_then(|b| {
                                <dsm::types::proto::OnlineTransferRequest as prost::Message>::decode(b).ok()
                            })
                            .map(|r| (r.amount, r.token_id))
                            .unwrap_or((0, "ERA".to_string()));
                        record_accepted_split_history(
                            &key,
                            &evidence_receipt,
                            &sender_b32,
                            &self_device_b32,
                            amount,
                            token_id,
                        );
                    }
                    Ok(AckDecision::DoNotAck(why)) => {
                        log::info!("[storage.sync] ADR 0003 completion: {key} not ACK-able: {why}");
                        continue;
                    }
                    Err(e) => {
                        log::warn!("[storage.sync] ADR 0003 completion: {key} failed: {e}");
                        continue;
                    }
                }
            } else {
                // Durably accepted already; `decide_ack` re-ACKs without apply.
                match decide_ack(&key, &sender_ak, |_| {
                    Err("apply must not run for an already-accepted pair".to_string())
                }) {
                    Ok(AckDecision::Ack(_)) => {}
                    other => {
                        log::warn!("[storage.sync] ADR 0003 completion: {key} accepted row did not re-ACK: {other:?}");
                        continue;
                    }
                }
            }

            // ACK BOTH HALVES on the retained route. The transfer's id is the
            // correlation key; the evidence's id is derived from its digest the
            // same way the sender derived it.
            // The route is set with the FIRST staged half and released only after
            // both ACKs succeed, and released rows are not selected — so an
            // accepted row without a route here is an invariant violation, not a
            // recoverable state.
            let Some(route) = row.retained_route.clone() else {
                log::error!(
                    "[storage.sync] ADR 0003 completion: {key} is accepted with no retained \
                     route — invariant violated; cannot ACK by route"
                );
                continue;
            };
            acks.push((route.clone(), key.clone()));
            if let Some(d) = row.evidence_digest {
                acks.push((
                    route,
                    crate::storage::client_db::derive_artifact_submission_id(&d),
                ));
            }
            release_after_ack.push(key);
        }

        (acks, release_after_ack)
    }

    pub(crate) async fn run_storage_sync_request(
        &self,
        req: generated::StorageSyncRequest,
    ) -> Result<generated::StorageSyncResponse, String> {
        let pack = generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: req.encode_to_vec(),
            ..Default::default()
        };

        let result = self
            .handle_storage_query(AppQuery {
                path: "storage.sync".to_string(),
                params: pack.encode_to_vec(),
            })
            .await;

        if !result.success {
            return Err(result
                .error_message
                .unwrap_or_else(|| "storage.sync failed".to_string()));
        }

        let payload = result
            .data
            .strip_prefix(&[0x03])
            .ok_or_else(|| "storage.sync missing envelope v3 framing".to_string())?;
        let env = dsm::envelope::from_canonical_bytes(payload)
            .map_err(|e| format!("storage.sync envelope decode failed: {e}"))?;
        match env.payload {
            Some(generated::envelope::Payload::StorageSyncResponse(resp)) => Ok(resp),
            Some(generated::envelope::Payload::Error(err_payload)) => Err(err_payload.message),
            _ => Err("storage.sync returned unexpected payload".to_string()),
        }
    }

    /// Dispatch handler for `storage.status` and `storage.sync` query routes.
    pub(crate) async fn handle_storage_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "storage.status" => {
                log::info!("[DSM_SDK] storage.status called");

                // Decode request (optional, but good for validation)
                if let Ok(pack) = generated::ArgPack::decode(&*q.params) {
                    if pack.codec == generated::Codec::Proto as i32 {
                        let _ = generated::StorageStatusRequest::decode(&*pack.body);
                    }
                }

                let endpoints = self._config.storage_endpoints.clone();
                let total_nodes = endpoints.len() as u32;

                // Real connectivity check — probe /api/v2/health on each node concurrently
                let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
                let mut connected_nodes = 0u32;
                let mut handles = Vec::new();
                for ep in &endpoints {
                    let c = client.clone();
                    let url = format!("{ep}/api/v2/health");
                    handles.push(tokio::spawn(async move {
                        matches!(tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            c.get(&url).send(),
                        ).await, Ok(Ok(resp)) if resp.status().is_success())
                    }));
                }
                for handle in handles {
                    if let Ok(true) = handle.await {
                        connected_nodes += 1;
                    }
                }

                // Get DB size
                let data_size = match crate::storage::client_db::get_db_size() {
                    Ok(size) => {
                        if size > 1024 * 1024 {
                            format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
                        } else {
                            format!("{:.1} KB", size as f64 / 1024.0)
                        }
                    }
                    Err(_) => "Unknown".to_string(),
                };

                // Real sync counter from transaction history
                let last_sync_iter =
                    crate::storage::client_db::get_transaction_count().unwrap_or(0);

                // Real backup status from NFC recovery SDK
                let backup_status = {
                    let rs = crate::sdk::recovery_sdk::RecoverySDK::get_recovery_status();
                    if !rs.enabled {
                        "Not configured".to_string()
                    } else if rs.pending_capsule {
                        format!("Armed (capsule #{})", rs.last_capsule_index)
                    } else if rs.capsule_count > 0 {
                        format!(
                            "Written (#{}, {} total)",
                            rs.last_capsule_index, rs.capsule_count
                        )
                    } else {
                        "Enabled (no capsule)".to_string()
                    }
                };

                let resp = generated::StorageStatusResponse {
                    total_nodes,
                    connected_nodes,
                    last_sync_iter,
                    data_size,
                    backup_status,
                };
                // NEW: Return as Envelope.storageStatusResponse (field 47)
                pack_envelope_ok(generated::envelope::Payload::StorageStatusResponse(resp))
            }

            // -------- storage.sync (QueryOp) --------
            "storage.sync" => {
                log::info!("[DSM_SDK] storage.sync called");

                // Registry-visibility heal (detached, best-effort, latched on success): wallets
                // created offline — and pre-fix Genesis v2 wallets that never published — become
                // verifiable by counterparties on the first sync with reachable storage nodes.
                crate::sdk::storage_node_sdk::StorageNodeSDK::spawn_ensure_genesis_registry_published(
                    "storage.sync",
                );

                // Check network connectivity before attempting sync
                #[cfg(feature = "dev-discovery")]
                let network_gate = get_network_gate();
                #[cfg(feature = "dev-discovery")]
                if network_gate.should_disable_network_features() {
                    log::warn!("[DSM_SDK] storage.sync: Network features disabled due to repeated failures");
                    return err("Network connectivity disabled due to repeated failures. Please restart the app.".into());
                }

                // Decode StorageSyncRequest
                let (pull_inbox, push_pending, limit) = match generated::ArgPack::decode(&*q.params)
                {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageSyncRequest::decode(&*pack.body) {
                            Ok(req) => (
                                req.pull_inbox,
                                req.push_pending,
                                req.limit.clamp(1, 200) as usize,
                            ),
                            Err(_) => (true, true, 100), // default: do everything
                        }
                    }
                    _ => (true, true, 100), // default
                };

                let mut pulled = 0u32;
                let mut processed = 0u32;
                #[allow(unused_mut)]
                let mut pushed = 0u32;
                let mut errors: Vec<String> = Vec::new();

                // Get storage endpoints
                let storage_endpoints =
                    match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
                        Ok(cfg) => cfg.node_urls,
                        Err(e) => {
                            let resp = generated::StorageSyncResponse {
                                success: false,
                                pulled: 0,
                                processed: 0,
                                pushed: 0,
                                errors: vec![format!("No storage node config available: {}", e)],
                            };
                            // NEW: Return as Envelope.storageSyncResponse (field 35)
                            return pack_envelope_ok(
                                generated::envelope::Payload::StorageSyncResponse(resp),
                            );
                        }
                    };
                if storage_endpoints.is_empty() {
                    let resp = generated::StorageSyncResponse {
                        success: false,
                        pulled: 0,
                        processed: 0,
                        pushed: 0,
                        errors: vec!["No storage endpoints configured".to_string()],
                    };
                    // NEW: Return as Envelope.storageSyncResponse (field 35)
                    return pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(
                        resp,
                    ));
                }

                let device_id_b32 =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                // Canonical textual device id for auth/storage keys is base32(32 bytes).
                // (Older code used dotted-decimal in some paths; never use that for auth.)
                log::info!(
                    "[DSM_SDK] storage.sync device_id: prefix={}..., len={}, base32_32={}",
                    &device_id_b32[..8.min(device_id_b32.len())],
                    device_id_b32.len(),
                    crate::util::text_id::decode_base32_crockford(&device_id_b32)
                        .map(|b| b.len() == 32)
                        .unwrap_or(false)
                );

                // Pull from inbox if requested
                if pull_inbox {
                    match crate::sdk::b0x_sdk::B0xSDK::new(
                        device_id_b32.clone(),
                        self.core_sdk.clone(),
                        storage_endpoints.clone(),
                    ) {
                        Ok(mut b0x_sdk) => {
                            // Proactively register this device on all storage endpoints to ensure valid tokens
                            // before attempting any inbox retrieval. This avoids 401/InboxTokenInvalid cases
                            // when storage nodes have been reset or tokens have expired.
                            let reg_res = if let Ok(handle) = tokio::runtime::Handle::try_current()
                            {
                                tokio::task::block_in_place(|| {
                                    handle.block_on(b0x_sdk.register_device())
                                })
                            } else if let Ok(rt) = tokio::runtime::Runtime::new() {
                                rt.block_on(b0x_sdk.register_device())
                            } else {
                                Err(dsm::types::error::DsmError::internal(
                                    "runtime failed",
                                    None::<std::io::Error>,
                                ))
                            };
                            match reg_res {
                                Ok(_) => log::info!("[DSM_SDK] storage.sync: device registration succeeded on storage endpoints"),
                                Err(e) => log::warn!("[DSM_SDK] storage.sync: device registration failed (continuing): {}", e),
                            }

                            // §16.4: Compute per-contact rotated b0x addresses for inbox polling.
                            // Each contact uses a tip-scoped routing key derived from
                            // domain-separated genesis/device/tip components.
                            let my_genesis = match self.core_sdk.local_genesis_hash().await {
                                Ok(genesis) if genesis.len() == 32 => {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&genesis);
                                    arr
                                }
                                Ok(genesis) => {
                                    let resp = generated::StorageSyncResponse {
                                        success: false,
                                        pulled: 0,
                                        processed: 0,
                                        pushed: 0,
                                        errors: vec![format!(
                                            "storage.sync: local genesis must be 32 bytes, got {}",
                                            genesis.len()
                                        )],
                                    };
                                    return pack_envelope_ok(
                                        generated::envelope::Payload::StorageSyncResponse(resp),
                                    );
                                }
                                Err(e) => {
                                    let resp = generated::StorageSyncResponse {
                                        success: false,
                                        pulled: 0,
                                        processed: 0,
                                        pushed: 0,
                                        errors: vec![format!(
                                            "storage.sync: missing local genesis for rotated inbox routing: {e}"
                                        )],
                                    };
                                    return pack_envelope_ok(
                                        generated::envelope::Payload::StorageSyncResponse(resp),
                                    );
                                }
                            };

                            let contacts =
                                crate::storage::client_db::get_all_contacts().unwrap_or_default();
                            // §5.2: Use tagged addresses to distinguish current vs stale-route items.
                            let tagged_addresses = collect_tagged_inbox_addresses(
                                my_genesis,
                                self.device_id_bytes,
                                &contacts,
                            );

                            let mut all_items = Vec::new();
                            // Already-accepted stale-route duplicates (see §5.2) collected for a
                            // DIRECT ACK: they must not re-enter the verify+apply pipeline (their
                            // sig_a no longer chains back to our advanced cert head), but they must
                            // still be ACKed to release the sender's pending online gate.
                            let mut stale_dup_acks: Vec<(String, String)> = Vec::new();
                            for tagged_addr in tagged_addresses {
                                if all_items.len() >= limit {
                                    break;
                                }
                                let remaining = limit - all_items.len();

                                log::info!(
                                    "[storage.sync] polling addr={}.. freshness={:?}",
                                    &tagged_addr.address[..16.min(tagged_addr.address.len())],
                                    tagged_addr.freshness,
                                );
                                let entries_res =
                                    match tokio::runtime::Handle::try_current() {
                                        Ok(handle) => tokio::task::block_in_place(|| {
                                            handle.block_on(b0x_sdk.retrieve_from_b0x_v2(
                                                &tagged_addr.address,
                                                remaining,
                                            ))
                                        }),
                                        Err(_) => {
                                            if let Ok(rt) = tokio::runtime::Runtime::new() {
                                                rt.block_on(b0x_sdk.retrieve_from_b0x_v2(
                                                    &tagged_addr.address,
                                                    remaining,
                                                ))
                                            } else {
                                                Err(dsm::types::error::DsmError::internal(
                                                    "runtime failed",
                                                    None::<std::io::Error>,
                                                ))
                                            }
                                        }
                                    };
                                // §16.6 SENDER FINALIZATION: drain any acceptance artifacts
                                // this poll decoded. They ride the same spool as forward
                                // transfers but are a distinct payload variant, so they are
                                // discriminated structurally rather than trial-decoded.
                                // Draining happens regardless of `entries_res` — a poll that
                                // yields no forward transfers can still carry the reply that
                                // releases this device's pending gate.
                                for delta in b0x_sdk.take_countersign_deltas() {
                                    let outcome = finalize_from_countersign_delta(&delta).await;
                                    log::info!(
                                        "[storage.sync] ADR 0003 countersign delta {} -> {:?}",
                                        delta.message_id,
                                        outcome
                                    );
                                }
                                // ADR 0003 evidence halves ride the same spool under their
                                // own explicit method. Glue only: resolve the trust root,
                                // hand the artifact to the dispatcher, log. No verification
                                // or acceptance logic lives here.
                                for evidence in b0x_sdk.take_evidence_artifacts() {
                                    stage_polled_evidence_half(&evidence, &tagged_addr.address);
                                }
                                // Cert-resync control messages ride the same spool,
                                // discriminated by their explicit method. Dispatch each
                                // to the matching leg; errors are logged, never fatal to
                                // the poll (a malformed/foreign message must not wedge sync).
                                for (method, rbody) in b0x_sdk.take_cert_resync_messages() {
                                    let outcome = if method
                                        == crate::storage::client_db::CERT_RESYNC_REQUEST_METHOD
                                    {
                                        self.handle_cert_resync_request(
                                            &rbody,
                                            storage_endpoints.clone(),
                                        )
                                        .await
                                    } else {
                                        self.handle_cert_resync_ack(&rbody).await
                                    };
                                    if let Err(e) = outcome {
                                        log::warn!("[cert-resync] {method} handling errored: {e}");
                                    }
                                }

                                // Auto-initiate: any relationship the send-gate marked
                                // REQUIRED gets its resync request sent here (which moves
                                // it to PENDING, so it is not re-sent every poll). This is
                                // what turns a blocked send into an actual recovery.
                                if let Ok(rels) =
                                    crate::storage::client_db::relationships_requiring_resync()
                                {
                                    for rel in rels {
                                        match crate::handlers::cert_resync_flow::peer_device_for_relationship(
                                            &self.device_id_bytes,
                                            &rel,
                                        ) {
                                            Some(peer) => {
                                                if let Err(e) = self
                                                    .initiate_cert_resync(peer, storage_endpoints.clone())
                                                    .await
                                                {
                                                    log::warn!("[cert-resync] auto-initiate failed: {e}");
                                                }
                                            }
                                            None => log::warn!(
                                                "[cert-resync] REQUIRED relationship has no resolvable peer"
                                            ),
                                        }
                                    }
                                }

                                match entries_res {
                                    Ok(items) => {
                                        // §5.2: Items from PreviousTip addresses that are non-adjacent
                                        // must NOT enter the mutating apply pipeline. Filter them here
                                        // so Tripwire is defense-in-depth, not the primary gate.
                                        if tagged_addr.freshness == RouteFreshness::PreviousTip {
                                            for item in items {
                                                let chain_tip_opt =
                                                    crate::util::text_id::decode_base32_crockford(
                                                        &item.sender_chain_tip,
                                                    );
                                                let from_device_opt =
                                                    crate::util::text_id::decode_base32_crockford(
                                                        &item.sender_device_id,
                                                    );
                                                let is_adjacent = match (
                                                    chain_tip_opt,
                                                    from_device_opt,
                                                ) {
                                                    (Some(ct), Some(fd))
                                                        if ct.len() == 32 && fd.len() >= 32 =>
                                                    {
                                                        let mut chain_tip_arr = [0u8; 32];
                                                        chain_tip_arr.copy_from_slice(&ct);
                                                        match crate::storage::client_db::get_contact_chain_tip_raw(
                                                            &fd[..32],
                                                        ) {
                                                            Some(stored) if stored != [0u8; 32] => stored == chain_tip_arr,
                                                            _ => true, // No stored tip or zero tip — allow
                                                        }
                                                    }
                                                    _ => true, // Decode failure — let apply pipeline handle it
                                                };
                                                if is_adjacent {
                                                    all_items.push(item);
                                                } else if crate::storage::client_db::transaction_exists(&item.transaction_id) {
                                                    // Already-accepted duplicate re-delivered on a stale
                                                    // (previous-tip) route: non-adjacent only because our
                                                    // tip already advanced PAST it, but we DID accept it
                                                    // (a transaction row exists). It must NOT re-enter the
                                                    // verify+apply pipeline: accepting it already advanced
                                                    // our Counterparty cert-chain head, so its per-step-EK
                                                    // sig_a no longer chains back to expected_prev_pk over
                                                    // h_n and verification REJECTS it WITHOUT an ACK, which
                                                    // re-strands the sender forever ("delivered but already
                                                    // accepted, won't refresh"). Since the stored
                                                    // transaction row proves acceptance, ACK it DIRECTLY
                                                    // (delete from the storage node) so the sender's pending
                                                    // online gate finalizes. Idempotent.
                                                    log::info!(
                                                        "[storage.sync] §5.2: stale-route item {} is an already-accepted duplicate; ACKing directly to release sender gate",
                                                        item.transaction_id,
                                                    );
                                                    stale_dup_acks.push((
                                                        item.inbox_key.clone(),
                                                        item.transaction_id.clone(),
                                                    ));
                                                } else {
                                                    log::info!(
                                                        "[storage.sync] §5.2: stale-route item {} skipped pre-apply (non-adjacent, from previous-tip address)",
                                                        item.transaction_id,
                                                    );
                                                }
                                            }
                                        } else {
                                            all_items.extend(items);
                                        }
                                    }
                                    Err(e) => {
                                        // Record network failure for connectivity monitoring
                                        #[cfg(feature = "dev-discovery")]
                                        network_gate.record_network_failure();

                                        // Use centralized mapping for inbox errors so all code paths
                                        // produce consistent, actionable messages.
                                        let formatted = self.format_inbox_error(&e);
                                        log::warn!("[storage.sync] Error encountered: {:?} -> Formatted: {}", e, formatted);
                                        errors.push(format!("inbox pull failed: {}", formatted));
                                    }
                                }
                            }

                            // Enter the apply+ACK block when there are items to apply OR
                            // already-accepted stale-route duplicates to ACK directly (§5.2). The
                            // latter carry no apply work — the loop below is a no-op for an empty
                            // `all_items` — but their direct ACK (further down) MUST run, else a
                            // cycle that pulled only a stale duplicate would skip the ACK and leave
                            // the sender's gate stranded forever.
                            if !all_items.is_empty() || !stale_dup_acks.is_empty() {
                                let items = all_items;
                                pulled = items.len() as u32;
                                let batch_state = Arc::new(Mutex::new(InboxBatchState::default()));
                                let core_sdk = self.core_sdk.clone();
                                let device_id_bytes = self.device_id_bytes;

                                for entry in items.iter().cloned() {
                                    {
                                        let state_guard = batch_state.lock().await;
                                        if state_guard.fatal_error.is_some() {
                                            break;
                                        }
                                    }

                                    // §4.2.1 (issue #446): `entry.transaction` is a field-by-field
                                    // reconstruction from UNTRUSTED protobuf and is used here ONLY as
                                    // a routing hint. Every value-bearing read below derives from the
                                    // signed canonical operation — decoded from `canonical_operation_bytes`
                                    // and bound to the verified signature — never from the structured
                                    // fields a relay could tamper while leaving the signature intact.
                                    // ADR 0003 SPLIT TRANSFER. A non-empty evidence reference
                                    // means the receipt travels as its own artifact, so this
                                    // entry is only one half and MUST NOT take the legacy
                                    // inline path. Glue only: require the retained wire bytes,
                                    // resolve the trust root, hand off. The dispatcher decides
                                    // everything else.
                                    if !entry.receipt_evidence_digest.is_empty() {
                                        stage_polled_transfer_half(&entry);
                                        continue;
                                    }

                                    if let dsm::types::operations::Operation::Transfer { .. } =
                                        &entry.transaction
                                    {
                                        // The signed canonical preimage is mandatory (strict-fail).
                                        if entry.canonical_operation_bytes.is_empty() {
                                            log::error!(
                                                "[storage.sync] ❌ REJECTING tx {}: missing canonical_operation_bytes (§4.2.1 strict-fail)",
                                                entry.transaction_id
                                            );
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push(format!(
                                                "missing canonical_operation_bytes for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }
                                        let signing_bytes = entry.canonical_operation_bytes.clone();

                                        // TRUST ROOT: the stored contact, never the wire. See
                                        // `resolve_trusted_sender_ak`.
                                        let pk = match resolve_trusted_sender_ak(
                                            &entry.sender_device_id,
                                            &entry.sender_signing_public_key,
                                        ) {
                                            Ok(k) => k,
                                            Err(e) => {
                                                log::warn!(
                                                    "[storage.sync] ❌ REJECTING tx {}: {e}",
                                                    entry.transaction_id
                                                );
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                    "{e} (tx {})",
                                                    entry.transaction_id
                                                ));
                                                continue;
                                            }
                                        };
                                        let pk_source = "stored_contact";
                                        let pk_hash = dsm::crypto::blake3::domain_hash(
                                            dsm::common::domain_tags::TAG_DSM_PK_HASH,
                                            &pk,
                                        );
                                        log::info!("[storage.sync] 🔑 signer pk hash(first8)={:?} source={} tx={}", &pk_hash.as_bytes()[..8], pk_source, entry.transaction_id);

                                        // §4.2.1 authoritative binding: verify SPHINCS+ over the
                                        // canonical bytes, decode the SIGNED operation, enforce
                                        // canonical re-serialization equality, and re-attach the
                                        // verified signature. `signed_op` is the ONLY trusted
                                        // operation for this entry.
                                        let signed_op = match dsm::types::operations::Operation::decode_and_bind_signed(
                                            &signing_bytes,
                                            &entry.signature,
                                            &pk,
                                        ) {
                                            Ok(op) => op,
                                            Err(e) => {
                                                log::warn!(
                                                    "[storage.sync] inbox.pull: signed-operation binding failed for tx {} ({}) — skipping poisoned entry, continuing batch",
                                                    entry.transaction_id, e
                                                );
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                    "inbox.pull: signed-operation binding failed for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };

                                        // Authoritative transfer fields come ONLY from signed_op.
                                        let (to_device_id, amount_val, token_id, nonce, memo) =
                                            match &signed_op {
                                                dsm::types::operations::Operation::Transfer {
                                                    to_device_id,
                                                    amount,
                                                    token_id,
                                                    nonce,
                                                    message,
                                                    ..
                                                } => (
                                                    to_device_id.clone(),
                                                    amount.value(),
                                                    token_id.clone(),
                                                    nonce.clone(),
                                                    message.clone(),
                                                ),
                                                _ => {
                                                    log::warn!("[storage.sync] Skipping tx {}: signed operation is not a Transfer", entry.transaction_id);
                                                    let mut state_guard = batch_state.lock().await;
                                                    state_guard.errors.push(format!(
                                                        "signed op not a Transfer for tx {}",
                                                        entry.transaction_id
                                                    ));
                                                    continue;
                                                }
                                            };

                                        if amount_val == 0 {
                                            log::warn!(
                                                "[storage.sync] Skipping zero-amount transfer"
                                            );
                                            continue;
                                        }

                                        // Guardrail: ensure this inbox item is actually targeted to the local device.
                                        if let Err(msg) = ensure_inbox_recipient_targets_local(
                                            &entry.recipient_device_id,
                                            &to_device_id,
                                            &device_id_bytes,
                                        ) {
                                            log::warn!(
                                                "[storage.sync] Skipping tx {}: {}",
                                                entry.transaction_id,
                                                msg
                                            );
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push(format!(
                                                "inbox.pull: recipient mismatch for {}: {}",
                                                entry.transaction_id, msg
                                            ));
                                            continue;
                                        }

                                        // Get signing context from envelope (sender identity + relationship state)
                                        let from_device_id = match decode_canonical_b32_32(
                                            "sender_device_id",
                                            &entry.sender_device_id,
                                        ) {
                                            Ok(value) => value,
                                            Err(msg) => {
                                                log::warn!(
                                                    "[storage.sync] Skipping tx {}: {}",
                                                    entry.transaction_id,
                                                    msg
                                                );
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                            "inbox.pull: malformed sender identity for {}: {}",
                                                            entry.transaction_id, msg
                                                        ));
                                                continue;
                                            }
                                        };
                                        let chain_tip_arr = match decode_canonical_b32_32(
                                            "sender_chain_tip",
                                            &entry.sender_chain_tip,
                                        ) {
                                            Ok(value) => value,
                                            Err(msg) => {
                                                log::warn!(
                                                    "[storage.sync] Skipping tx {}: {}",
                                                    entry.transaction_id,
                                                    msg
                                                );
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                            "inbox.pull: malformed sender chain tip for {}: {}",
                                                            entry.transaction_id, msg
                                                        ));
                                                continue;
                                            }
                                        };
                                        let to_device_id_arr: [u8; 32] = match to_device_id
                                            .as_slice()
                                            .try_into()
                                        {
                                            Ok(value) => value,
                                            Err(_) => {
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                                "inbox.pull: tx {} has invalid operation.to_device_id length {}",
                                                                entry.transaction_id,
                                                                to_device_id.len()
                                                            ));
                                                continue;
                                            }
                                        };

                                        // =====================================================================
                                        // DIAGNOSTIC: Log all signing context fields for debugging mismatches
                                        // =====================================================================
                                        log::info!(
                                                    "[storage.sync] 📥 Verifying tx={}: from_first8={:02x}{:02x}{:02x}{:02x}... to_first8={:02x}{:02x}{:02x}{:02x}... chain_tip_first8={:02x}{:02x}{:02x}{:02x}...",
                                                    entry.transaction_id,
                                                    from_device_id[0], from_device_id[1], from_device_id[2], from_device_id[3],
                                                    to_device_id_arr[0], to_device_id_arr[1], to_device_id_arr[2], to_device_id_arr[3],
                                                    chain_tip_arr[0], chain_tip_arr[1], chain_tip_arr[2], chain_tip_arr[3],
                                                );
                                        log::info!(
                                                    "[storage.sync] 📥 tx={}: amount={} token={} nonce_len={} memo_len={} seq={}",
                                                    entry.transaction_id, amount_val, String::from_utf8_lossy(&token_id), nonce.len(), memo.len(), entry.seq
                                                );

                                        // GUARDRAIL: Check if to_device_id matches chain_tip (indicates sender bug)
                                        if to_device_id_arr == chain_tip_arr
                                            && chain_tip_arr != [0u8; 32]
                                        {
                                            log::error!(
                                                        "[storage.sync] ❌ SENDER BUG DETECTED: to_device_id == chain_tip! Sender passed chain_tip as recipient."
                                                    );
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push("inbox.pull: sender passed chain_tip as to_device_id".into());
                                            continue;
                                        }

                                        // Apply the authoritative signed operation (decoded and bound
                                        // above from the canonical signed bytes — never the untrusted
                                        // reconstructed `entry.transaction`).
                                        let op = signed_op;
                                        let tx_id: TransactionId =
                                            TransactionId::new(entry.transaction_id.clone());
                                        // §S1: receipt_commit is mandatory — §4.3 items 2/3/4 all depend on it.
                                        if entry.receipt_commit.is_empty() {
                                            log::error!("[storage.sync] §4.3 REJECTING tx {}: receipt_commit absent (mandatory per §4.3)", entry.transaction_id);
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push(format!(
                                                "§4.3 missing receipt_commit for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }
                                        // §S4/§6 Tripwire: bricked-contact check BEFORE state mutation.
                                        if crate::storage::client_db::is_contact_bricked(
                                            &from_device_id,
                                        ) {
                                            log::error!("[storage.sync] §6 REJECTING tx {} from BRICKED contact {} (pre-apply)", entry.transaction_id, entry.sender_device_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!(
                                                "§6 bricked contact for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }
                                        // ═══════════════════════════════════════════════════════
                                        // Strict replay drain (§4.3 + §5.4): when a nonce is already
                                        // spent the balance was credited on a prior sync. We MAY only
                                        // ACK the stale entry if four invariants still hold:
                                        //   1. Sender's receipt re-verifies (same transaction body,
                                        //      not a forged nonce reuse).
                                        //   2. `receipt.child_tip == recomputed expected_h_next`.
                                        //   3. `receipt.sig_a` still verifies under the sender PK.
                                        //   4. Local `contacts.chain_tip` equals `expected_h_next`,
                                        //      or can be atomically advanced to it in this cycle.
                                        // A bare nonce-match ACK is unsafe: it lets the sender advance
                                        // while the receiver stays at h_n, producing permanent
                                        // contacts.chain_tip divergence and subsequent b0x routing
                                        // misses. Failure at any step → no ACK, storage node keeps
                                        // the entry for retry.
                                        // ═══════════════════════════════════════════════════════
                                        {
                                            // Authoritative nonce from the signed op (issue #446).
                                            let nonce_bytes: Option<&[u8]> = if nonce.is_empty() {
                                                None
                                            } else {
                                                Some(nonce.as_slice())
                                            };
                                            if let Some(nb) = nonce_bytes {
                                                if let Ok(true) =
                                                    crate::storage::client_db::is_nonce_spent(nb)
                                                {
                                                    let op_bytes_for_tip = signing_bytes.clone();
                                                    let receipt_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                                                        &chain_tip_arr,
                                                        &op_bytes_for_tip,
                                                        &nonce,
                                                    );
                                                    let expected_h_next = dsm::core::bilateral_transaction_manager::compute_successor_tip(
                                                        &chain_tip_arr,
                                                        &op_bytes_for_tip,
                                                        &nonce,
                                                        &receipt_sigma,
                                                    );

                                                    let sender_device_tree_commitment = crate::storage::client_db::get_contact_device_tree_commitment(&from_device_id);
                                                    if !crate::sdk::receipts::verify_receipt_bytes(
                                                        &entry.receipt_commit,
                                                        sender_device_tree_commitment,
                                                    ) {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: receipt re-verify failed", entry.transaction_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!("replay drain receipt re-verify failed for tx {}", entry.transaction_id));
                                                        continue;
                                                    }

                                                    let receipt = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&entry.receipt_commit) {
                                                        Ok(r) => r,
                                                        Err(e) => {
                                                            log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: receipt parse failed: {}", entry.transaction_id, e);
                                                            let mut sg = batch_state.lock().await;
                                                            sg.errors.push(format!("replay drain receipt parse failed for tx {}: {}", entry.transaction_id, e));
                                                            continue;
                                                        }
                                                    };

                                                    // Receipt carries A-side asymmetric tips (what
                                                    // sender's T_A stores + what inclusion proofs prove).
                                                    // Symmetric §16.6 h_{n+1} equivalence is enforced at
                                                    // envelope-level `next_chain_tip` vs `expected_h_next`
                                                    // and via the contacts.chain_tip CAS — no per-receipt
                                                    // comparison required here.

                                                    if receipt.sig_a.is_empty() {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: sig_a absent", entry.transaction_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!(
                                                            "replay drain sig_a absent for tx {}",
                                                            entry.transaction_id
                                                        ));
                                                        continue;
                                                    }

                                                    let commitment = match receipt
                                                        .compute_commitment()
                                                    {
                                                        Ok(c) => c,
                                                        Err(e) => {
                                                            log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: commitment error: {}", entry.transaction_id, e);
                                                            let mut sg = batch_state.lock().await;
                                                            sg.errors.push(format!("replay drain commitment error for tx {}: {}", entry.transaction_id, e));
                                                            continue;
                                                        }
                                                    };

                                                    // §11.1 per-step EK verify (see main site) — sig_a
                                                    // verifies under receipt.ek_pk_a over the challenge
                                                    // target, not as a raw SPHINCS+ under the static key.
                                                    if let Err(e) = verify_inbound_receipt_sig_a(
                                                        &receipt,
                                                        &commitment,
                                                        &pk,
                                                    ) {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: sig_a invalid: {}", entry.transaction_id, e);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!(
                                                            "replay drain sig_a invalid for tx {}",
                                                            entry.transaction_id
                                                        ));
                                                        continue;
                                                    }

                                                    // Ensure local contacts.chain_tip is at expected_h_next.
                                                    let tip_converged = match crate::storage::client_db::get_contact_chain_tip_raw(&from_device_id) {
                                                        Some(t) if t == expected_h_next => true,
                                                        _ => {
                                                            let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                                                                counterparty_device_id: from_device_id,
                                                                expected_parent_tip: chain_tip_arr,
                                                                target_tip: expected_h_next,
                                                                observed_gate: None,
                                                                clear_gate_on_success: false,
                                                            };
                                                            matches!(
                                                                crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request),
                                                                Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. })
                                                                | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. })
                                                                | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. })
                                                            )
                                                        }
                                                    };

                                                    if !tip_converged {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: local contacts.chain_tip could not converge to h_{{n+1}}", entry.transaction_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!("replay drain tip convergence failed for tx {}", entry.transaction_id));
                                                        continue;
                                                    }

                                                    // Canonical §2.2 SMT advance is owned by the
                                                    // §16.6 full-state apply
                                                    // (`apply_incoming_transfer_full_state` →
                                                    // `execute_on_relationship_guarded`). Idempotency
                                                    // for already-consumed nonces is decided by the
                                                    // canonical apply identity, not on any shadow SMT.

                                                    log::info!("[storage.sync] Strict replay drain ACK for tx {} (receipt verified, tip converged)", entry.transaction_id);
                                                    emit_authoritative_wallet_refresh();
                                                    let mut sg = batch_state.lock().await;
                                                    sg.processed_entries.push((
                                                        entry.inbox_key.clone(),
                                                        entry.transaction_id.clone(),
                                                    ));
                                                    sg.processed = sg.processed.saturating_add(1);
                                                    continue;
                                                }
                                            }
                                        }
                                        // §S4/§4.3#5: Parent-tip mismatch check BEFORE state mutation.
                                        // NOTE: For online unilateral delivery, inbox order can be non-adjacent
                                        // (stale or ahead-of-local-tip entries). A mismatch here is not by itself
                                        // cryptographic proof of equivocation, so do NOT permanently brick.
                                        // Instead, mark relationship for reconciliation and skip this entry.
                                        {
                                            let stored_tip_pre = crate::storage::client_db::get_contact_chain_tip_raw(&from_device_id);
                                            if let Some(stored) = stored_tip_pre {
                                                if stored != [0u8; 32] && stored != chain_tip_arr {
                                                    // §5.4 ACK-advancement: if we have a pending online outbox
                                                    // for this counterparty whose next_tip matches the claimed
                                                    // parent, the gap is exactly one pending-online step.
                                                    // Try ACK-based advancement before rejecting.
                                                    let mut gap_closed = false;
                                                    if let Ok(Some(pending)) = crate::storage::client_db::get_pending_online_outbox(&from_device_id) {
                                                        let pending_next: Option<[u8; 32]> = pending.next_tip.as_slice().try_into().ok();
                                                        if pending_next == Some(chain_tip_arr) {
                                                            log::info!(
                                                                "[storage.sync] Parent-tip mismatch for tx {} but pending outbox next_tip matches claimed parent; trying ACK advancement",
                                                                entry.transaction_id
                                                            );
                                                            match b0x_sdk.is_message_acknowledged(&pending.message_id).await {
                                                                Ok(true) => {
                                                                    let pending_parent: [u8; 32] = pending.parent_tip.as_slice().try_into().unwrap_or([0u8; 32]);
                                                                    let cp_arr: [u8; 32] = pending.counterparty_device_id.as_slice().try_into().unwrap_or([0u8; 32]);
                                                                    let observed_gate = crate::storage::client_db::bilateral_tip_sync::ObservedPendingGate {
                                                                        counterparty_device_id: cp_arr,
                                                                        parent_tip: pending_parent,
                                                                        next_tip: chain_tip_arr,
                                                                    };
                                                                    let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                                                                        counterparty_device_id: cp_arr,
                                                                        expected_parent_tip: pending_parent,
                                                                        target_tip: chain_tip_arr,
                                                                        observed_gate: Some(observed_gate),
                                                                        clear_gate_on_success: true,
                                                                    };
                                                                    match crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request) {
                                                                        Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. })
                                                                        | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. })
                                                                        | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. }) => {
                                                                            log::info!(
                                                                                "[storage.sync] §5.4 ACK-advancement succeeded for tx {}; canonical tip now matches claimed parent",
                                                                                entry.transaction_id
                                                                            );
                                                                            gap_closed = true;
                                                                        }
                                                                        Ok(other) => {
                                                                            log::warn!(
                                                                                "[storage.sync] §5.4 ACK-advancement tip sync returned {:?} for tx {}; deferring",
                                                                                other, entry.transaction_id
                                                                            );
                                                                        }
                                                                        Err(e) => {
                                                                            log::warn!(
                                                                                "[storage.sync] §5.4 ACK-advancement tip sync failed for tx {}: {}; deferring",
                                                                                entry.transaction_id, e
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                                Ok(false) => {
                                                                    log::info!(
                                                                        "[storage.sync] Pending online send not yet ACKed for tx {}; deferring inbound",
                                                                        entry.transaction_id
                                                                    );
                                                                }
                                                                Err(e) => {
                                                                    log::warn!(
                                                                        "[storage.sync] ACK check failed for tx {}: {}; deferring",
                                                                        entry.transaction_id, e
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if !gap_closed {
                                                        log::warn!("[storage.sync] Parent-tip mismatch pre-apply for tx {}: stored={:02x?}.. claimed={:02x?}.. recording observed remote tip and marking reconcile", entry.transaction_id, &stored[..4], &chain_tip_arr[..4]);
                                                        record_observed_remote_tip_and_refresh(
                                                            &from_device_id,
                                                            &chain_tip_arr,
                                                        );
                                                        mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!(
                                                            "parent-tip mismatch pre-apply for tx {}",
                                                            entry.transaction_id
                                                        ));
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                        // §5.4: Do not race an inbound online apply against a local pending online projection.
                                        {
                                            let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                                                        &from_device_id,
                                                        &to_device_id_arr,
                                                    );
                                            if crate::security::modal_sync_lock::is_pending_online(
                                                &smt_key,
                                            ) {
                                                log::warn!(
                                                            "[storage.sync] Deferring tx {} because relationship {} has a pending local online projection",
                                                            entry.transaction_id,
                                                            entry.sender_device_id
                                                        );
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "pending local online projection for tx {}",
                                                    entry.transaction_id
                                                ));
                                                continue;
                                            }
                                        }
                                        // ═══════════════════════════════════════════════════════
                                        // §4.3 Pre-flight verification — ALL cryptographic checks
                                        // run BEFORE any state mutation. Failure at any step →
                                        // `continue` without ACK so the storage node retains the
                                        // entry. This preserves spec-mandated acceptance order
                                        // (sigs → inclusion proofs → byte-exact SMT replace →
                                        // parent-tip) and rules out the gate-continue divergence
                                        // where balance was credited but contacts.chain_tip
                                        // stayed at h_n.
                                        // ═══════════════════════════════════════════════════════
                                        let op_bytes_for_tip = signing_bytes.clone();
                                        let receipt_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                                            &chain_tip_arr,
                                            &op_bytes_for_tip,
                                            &nonce,
                                        );
                                        let expected_h_next = dsm::core::bilateral_transaction_manager::compute_successor_tip(
                                            &chain_tip_arr,
                                            &op_bytes_for_tip,
                                            &nonce,
                                            &receipt_sigma,
                                        );

                                        // Envelope's claimed next_chain_tip must match recomputation (§4.3#6).
                                        if let Some(claimed_tip) =
                                            crate::util::text_id::decode_base32_crockford(
                                                &entry.next_chain_tip,
                                            )
                                            .filter(|b| b.len() == 32)
                                        {
                                            let mut claimed_arr = [0u8; 32];
                                            claimed_arr.copy_from_slice(&claimed_tip);
                                            if claimed_arr != expected_h_next {
                                                // Routing/diagnostic ONLY (§16.6 authority sourcing):
                                                // envelope tips are unsigned metadata and must never
                                                // invalidate an otherwise-valid signed receipt.
                                                log::warn!("[storage.sync] envelope next_chain_tip diverges from recomputed symmetric h_{{n+1}} for tx {} — diagnostic only, proceeding on the signed receipt", entry.transaction_id);
                                            }
                                        }

                                        // §4.3 items 2+4: full receipt verification (SMT-Replace, device proof, relation proofs).
                                        let sender_device_tree_commitment = crate::storage::client_db::get_contact_device_tree_commitment(&from_device_id);
                                        if !crate::sdk::receipts::verify_receipt_bytes(
                                            &entry.receipt_commit,
                                            sender_device_tree_commitment,
                                        ) {
                                            log::error!("[storage.sync] §4.3#2+4 ReceiptCommit verification FAILED for tx {} — rejecting without ACK", entry.transaction_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!("§4.3#2+4 ReceiptCommit verification failed for tx {}", entry.transaction_id));
                                            continue;
                                        }

                                        // Parse receipt, verify child_tip matches recomputed h_{n+1} (§4.3),
                                        // and verify sig_a (§4.2 mandatory sender non-repudiation).
                                        let receipt = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&entry.receipt_commit) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                log::error!("[storage.sync] §4.3 StitchedReceiptV2 parse FAILED for tx {}: {} — rejecting without ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("§4.3 receipt parse failed for tx {}: {}", entry.transaction_id, e));
                                                continue;
                                            }
                                        };

                                        // Receipt carries A-side asymmetric tips (what sender's T_A
                                        // stores + what the inclusion proofs prove). Symmetric
                                        // §16.6 h_{n+1} equivalence is enforced earlier against
                                        // `envelope.next_chain_tip` (line ~999) and later via the
                                        // contacts.chain_tip CAS — no per-receipt comparison here.

                                        if receipt.sig_a.is_empty() {
                                            log::error!("[storage.sync] §4.2 REJECTING tx {}: receipt.sig_a absent (mandatory)", entry.transaction_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!(
                                                "§4.2 sig_a absent for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }

                                        let receipt_commitment = match receipt.compute_commitment()
                                        {
                                            Ok(c) => c,
                                            Err(e) => {
                                                log::error!("[storage.sync] §4.2 receipt commitment failed for tx {}: {} — rejecting without ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "§4.2 commitment failed for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };

                                        // §11.1 sender authorization: sig_a is a per-step EK
                                        // signature (receipt.ek_pk_a, cert-chained to the sender's
                                        // AK) over the receipt challenge-response target — verify it
                                        // the way the sender signs it, NOT as a raw SPHINCS+ over
                                        // the commitment under the static signing key. `pk` is the
                                        // sender's static signing key, which is also the AK_pk that
                                        // roots the cert chain at relationship genesis.
                                        match verify_inbound_receipt_sig_a(
                                            &receipt,
                                            &receipt_commitment,
                                            &pk,
                                        ) {
                                            Ok(()) => {
                                                log::info!(
                                                    "[storage.sync] §11.1 sig_a verified (per-step EK) for tx {}",
                                                    entry.transaction_id
                                                );
                                            }
                                            Err(e) => {
                                                log::error!("[storage.sync] §11.1 FATAL: sig_a invalid for tx {}: {} — rejecting without ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "§4.2 sig_a invalid for tx {}",
                                                    entry.transaction_id
                                                ));
                                                continue;
                                            }
                                        }

                                        // ═══════════════════════════════════════════════════════
                                        // §16.6 AUTHORITY SOURCING: the VERIFIED SIGNED receipt is
                                        // the sole authority for the canonical transition this
                                        // entry proposes. Its parent/child are ASYMMETRIC-space
                                        // canonical tips. `entry.sender_chain_tip` /
                                        // `entry.next_chain_tip` are unsigned routing metadata —
                                        // logged on divergence, never validation inputs.
                                        // ═══════════════════════════════════════════════════════
                                        let signed_parent: [u8; 32] = receipt.parent_tip;
                                        let signed_child: [u8; 32] = receipt.child_tip;
                                        if signed_parent != chain_tip_arr {
                                            log::warn!(
                                                "[storage.sync] routing metadata parent ({}..) diverges from SIGNED receipt parent ({}..) for tx {} — proceeding on the signed value",
                                                crate::util::text_id::encode_base32_crockford(&chain_tip_arr[..4]),
                                                crate::util::text_id::encode_base32_crockford(&signed_parent[..4]),
                                                entry.transaction_id
                                            );
                                        }
                                        // C_pre bound to the SIGNED parent + SIGNED operation bytes.
                                        let signed_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                                            &signed_parent,
                                            &op_bytes_for_tip,
                                            &nonce,
                                        );
                                        // SYMMETRIC projection pair for the contacts CAS, captured
                                        // BEFORE any mutation from the LOCAL stored symmetric tip
                                        // (genesis-init when absent) + the signed operation — the
                                        // wire metadata plays no part.
                                        let projection_parent: [u8; 32] = match crate::storage::client_db::get_contact_chain_tip_raw(&from_device_id) {
                                            Some(t) if t != [0u8; 32] => t,
                                            _ => dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                                                &to_device_id_arr,
                                                &from_device_id,
                                            ),
                                        };
                                        let projection_target: [u8; 32] = {
                                            let sigma_sym = dsm::core::bilateral_transaction_manager::compute_precommit(
                                                &projection_parent,
                                                &op_bytes_for_tip,
                                                &nonce,
                                            );
                                            dsm::core::bilateral_transaction_manager::compute_successor_tip(
                                                &projection_parent,
                                                &op_bytes_for_tip,
                                                &nonce,
                                                &sigma_sym,
                                            )
                                        };

                                        // ═══════════════════════════════════════════════════════
                                        // §16.6 SINGLE AUTHORITATIVE COUNTERSIGNING PATH (the fold).
                                        //   prepare (persist exact B receipt, BEFORE apply)
                                        //   → atomic full-state apply (DeviceState successor + BCR +
                                        //     head + balances + nonce + recovery index +
                                        //     CanonicalApplyRecord, ONE tx, lookup-before-execute)
                                        //   → convergence (projection sync + immutable marker →
                                        //     promote → CAS both cert heads → outbox → Complete)
                                        //   → ACK only after Complete.
                                        // A duplicate delivery returns
                                        // AlreadyAppliedSameOperation(record) and re-enters the SAME
                                        // convergence — never a re-ACK short-circuit.
                                        // ═══════════════════════════════════════════════════════
                                        let rel_key =
                                            dsm::verification::smt_replace_witness::compute_smt_key(
                                                &from_device_id,
                                                &to_device_id_arr,
                                            );
                                        let (ak_pk, ak_sk) = match self
                                            .wallet
                                            .ak_keypair_for_cert_chain()
                                        {
                                            Ok(p) => p,
                                            Err(e) => {
                                                log::error!("[storage.sync] §16.6 AK keypair unavailable for tx {}: {} — no ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "AK keypair unavailable for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };
                                        let sender_kyber_pk = match crate::storage::client_db::get_contact_by_device_id(&from_device_id) {
                                            Ok(Some(c)) if !c.kyber_public_key.is_empty() => c.kyber_public_key,
                                            Ok(Some(c)) => {
                                                match hydrate_missing_sender_kyber_capability(
                                                    &storage_endpoints,
                                                    from_device_id,
                                                    &c,
                                                )
                                                .await
                                                {
                                                    Ok(k) => {
                                                        log::info!("[storage.sync] §16.6 sender Kyber capability hydrated from registry (AK binding verified) for tx {}", entry.transaction_id);
                                                        k
                                                    }
                                                    Err(e) => {
                                                        log::error!("[storage.sync] §16.6 sender contact missing Kyber capability for tx {} and registry hydration failed: {} — fail closed, no ACK", entry.transaction_id, e);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!("sender Kyber capability missing for tx {} (hydration: {})", entry.transaction_id, e));
                                                        continue;
                                                    }
                                                }
                                            }
                                            _ => {
                                                log::error!("[storage.sync] §16.6 no contact for sender of tx {} — fail closed, no ACK (establish the contact)", entry.transaction_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("sender contact missing for tx {}", entry.transaction_id));
                                                continue;
                                            }
                                        };
                                        let wrap_key =
                                            match crate::init::current_chain_head_at_rest_key() {
                                                Ok(k) => k,
                                                Err(e) => {
                                                    log::error!("[storage.sync] §16.6 wrap key unavailable for tx {} (wallet locked?): {} — no ACK", entry.transaction_id, e);
                                                    let mut sg = batch_state.lock().await;
                                                    sg.errors.push(format!(
                                                        "wrap key unavailable for tx {}: {}",
                                                        entry.transaction_id, e
                                                    ));
                                                    continue;
                                                }
                                            };

                                        // Async relationship exclusion, held across prepare →
                                        // apply → convergence for this entry.
                                        let rel_lock =
                                            crate::handlers::recipient_receipt::relationship_lock(
                                                &rel_key,
                                            );
                                        let _rel_guard = rel_lock.lock_owned().await;

                                        // PHASE 1 — prepare + persist the exact countersigned
                                        // receipt BEFORE apply. Idempotent: a re-delivery returns
                                        // the same stored bytes, never re-signs.
                                        let prepared_bytes = match crate::handlers::recipient_receipt::prepare_bside_acceptance_receipt_locked(
                                            rel_key,
                                            signed_parent,
                                            (projection_parent, projection_target),
                                            || crate::handlers::recipient_receipt::generate_b_artifacts_from_inbound(
                                                &receipt,
                                                &signed_sigma,
                                                &sender_kyber_pk,
                                                &ak_pk,
                                                &ak_sk,
                                                &wrap_key,
                                            ),
                                        ) {
                                            Ok(b) => b,
                                            Err(e) => {
                                                log::error!("[storage.sync] §16.6 PREPARE failed for tx {}: {} — no apply, no ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("acceptance prepare failed for tx {}: {}", entry.transaction_id, e));
                                                continue;
                                            }
                                        };

                                        // ATOMIC FULL-STATE APPLY (lookup-before-execute).
                                        let apply_outcome = match core_sdk
                                            .apply_incoming_transfer_full_state(
                                                op,
                                                &tx_id,
                                                &entry.sender_device_id,
                                                &op_bytes_for_tip,
                                                signed_parent,
                                                signed_child,
                                            ) {
                                            Ok(o) => o,
                                            Err(e) => {
                                                log::warn!("[storage.sync] §16.6 full-state apply errored for tx {}: {} — no ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "full-state apply failed for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };
                                        let (apply_record, advance_opt) = match apply_outcome {
                                            crate::sdk::apply_outcome::ApplyOutcome::Applied { record, advance } => (record, Some(advance)),
                                            crate::sdk::apply_outcome::ApplyOutcome::AlreadyAppliedSameOperation { record } => {
                                                log::info!("[storage.sync] §16.6 duplicate delivery of already-applied tx {} — converging from the stored record (no re-execution)", entry.transaction_id);
                                                (record, None)
                                            }
                                            crate::sdk::apply_outcome::ApplyOutcome::Conflict { reason } => {
                                                log::error!("[storage.sync] §16.6 apply CONFLICT for tx {}: {} — fail closed, no ACK", entry.transaction_id, reason);
                                                mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("apply conflict for tx {}: {}", entry.transaction_id, reason));
                                                continue;
                                            }
                                        };

                                        // CONVERGENCE — projection sync + immutable acceptance
                                        // marker (one client-db tx) → promote → CAS A + B cert
                                        // heads → outbox → Complete → wipe secret. Driven by the
                                        // durable CanonicalApplyRecord on BOTH fresh and duplicate
                                        // paths. Failure: reconcile-flag + no ACK (recovery sweep
                                        // converges later; the canonical commit is never reversed).
                                        let journal =
                                            match crate::storage::client_db::get_acceptance_journal(
                                                &rel_key,
                                                &signed_parent,
                                            ) {
                                                Ok(Some(j)) => j,
                                                _ => {
                                                    log::error!("[storage.sync] §16.6 prepared journal missing after apply for tx {} — reconcile, no ACK", entry.transaction_id);
                                                    mark_contact_needs_online_reconcile_and_refresh(
                                                        &from_device_id,
                                                    );
                                                    let mut sg = batch_state.lock().await;
                                                    sg.errors.push(format!(
                                                        "prepared journal missing for tx {}",
                                                        entry.transaction_id
                                                    ));
                                                    continue;
                                                }
                                            };
                                        if let Err(e) = crate::handlers::recipient_receipt::converge_accepted_locked(
                                            &journal,
                                            &apply_record,
                                            &wrap_key,
                                        ) {
                                            log::error!("[storage.sync] §16.6 convergence failed for tx {}: {} — reconcile, no ACK (recovery sweep will retry)", entry.transaction_id, e);
                                            mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!("acceptance convergence failed for tx {}: {}", entry.transaction_id, e));
                                            continue;
                                        }
                                        log::info!("[storage.sync] §16.6 acceptance CONVERGED for tx {} (marker + both heads + outbox)", entry.transaction_id);

                                        // Post-commit history/UI persistence (best-effort projections;
                                        // NEVER invalidates the committed canonical transition).
                                        // Fresh applies only — a duplicate's rows were written by the
                                        // first delivery, and its authoritative evidence lives in the
                                        // fold's journal/outbox regardless.
                                        if let Some(advance_outcome) = &advance_opt {
                                            let to_device_b32 =
                                                crate::util::text_id::encode_base32_crockford(
                                                    &to_device_id,
                                                );
                                            let tx_hash = {
                                                let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                                                    dsm::tagged_domain!(b"DSM/tx-record-hash"),
                                                );
                                                h.update(entry.transaction_id.as_bytes());
                                                h.update(entry.sender_device_id.as_bytes());
                                                crate::util::text_id::encode_base32_crockford(
                                                    &h.finalize().as_bytes()[..32],
                                                )
                                            };
                                            let mut meta = std::collections::HashMap::new();
                                            meta.insert("token_id".to_string(), token_id.clone());
                                            meta.insert(
                                                "memo".to_string(),
                                                memo.as_bytes().to_vec(),
                                            );

                                            let recv_smt_pre = advance_outcome.parent_r_a;
                                            let recv_smt_post = advance_outcome.child_r_a;
                                            let recv_parent_bytes =
                                                advance_outcome.smt_proofs.parent_proof.to_bytes();
                                            let recv_child_bytes =
                                                advance_outcome.smt_proofs.child_proof.to_bytes();

                                            // Source BOTH signatures from the fold's persisted
                                            // countersigned artifact — ONE in-memory instance parsed
                                            // from the exact stored bytes, never a separately-signed
                                            // sig_b (the static-key path is deleted).
                                            let countersigned = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&prepared_bytes) {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    log::warn!("[storage.sync] §4.2 countersigned artifact parse failed for tx {} (history row skipped): {}", entry.transaction_id, e);
                                                    dsm::types::receipt_types::StitchedReceiptV2::new(
                                                        [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
                                                        [0u8; 32], [0u8; 32], Vec::new(), Vec::new(), Vec::new(),
                                                    )
                                                }
                                            };
                                            if !countersigned.sig_a.is_empty()
                                                && !countersigned.sig_b.is_empty()
                                            {
                                                let dual =
                                                    crate::storage::client_db::StitchedReceipt {
                                                        tx_hash: receipt_commitment,
                                                        h_n: projection_parent,
                                                        h_n1: projection_target,
                                                        device_id_a: from_device_id,
                                                        device_id_b: to_device_id_arr,
                                                        sig_a: countersigned.sig_a.clone(),
                                                        sig_b: countersigned.sig_b.clone(),
                                                        receipt_commit: entry
                                                            .receipt_commit
                                                            .clone(),
                                                        smt_root_pre: Some(recv_smt_pre),
                                                        smt_root_post: Some(recv_smt_post),
                                                    };
                                                if let Err(e) =
                                                    crate::storage::client_db::store_stitched_receipt(&dual)
                                                {
                                                    log::warn!("[storage.sync] §4.2 store_stitched_receipt failed for tx {}: {} (non-fatal)", entry.transaction_id, e);
                                                } else {
                                                    log::info!("[storage.sync] §4.2 Dual-signed receipt persisted with SMT roots for tx {}", entry.transaction_id);
                                                }
                                            }

                                            let recv_device_tree_commitment =
                                                crate::storage::client_db::get_contact_device_tree_commitment(&from_device_id);
                                            let rebuilt = build_online_receipt_with_smt(
                                                &from_device_id,
                                                &to_device_id_arr,
                                                projection_parent,
                                                projection_target,
                                                recv_smt_pre,
                                                recv_smt_post,
                                                recv_parent_bytes,
                                                recv_child_bytes,
                                                recv_device_tree_commitment,
                                            );
                                            let history_proof_bytes: Option<Vec<u8>> =
                                                select_history_receipt_bytes(
                                                    rebuilt,
                                                    &entry.receipt_commit,
                                                );

                                            let rec =
                                                crate::storage::client_db::TransactionRecord {
                                                    tx_id: entry.transaction_id.clone(),
                                                    tx_hash,
                                                    from_device: entry.sender_device_id.clone(),
                                                    to_device: to_device_b32,
                                                    amount: amount_val,
                                                    tx_type: "online".to_string(),
                                                    status: "confirmed".to_string(),
                                                    chain_height: entry.seq,
                                                    step_index: entry.seq,
                                                    commitment_hash: None,
                                                    proof_data: history_proof_bytes,
                                                    metadata: meta,
                                                    created_at: 0,
                                                };
                                            if let Err(e) =
                                                crate::storage::client_db::store_transaction(&rec)
                                            {
                                                log::warn!("[storage.sync] store_transaction failed for tx {}: {} (non-fatal)", entry.transaction_id, e);
                                            } else {
                                                log::info!("[storage.sync] Recorded incoming tx {} (from={}, amount={})", entry.transaction_id, entry.sender_device_id, amount_val);
                                            }
                                        }

                                        // §11.1 balance already materialized by the full-state apply.
                                        // Refresh in-memory caches + notify WebView.
                                        if let Some(router) = crate::bridge::app_router() {
                                            router.sync_balance_cache();
                                        }
                                        emit_authoritative_wallet_refresh();

                                        {
                                            let mut sg = batch_state.lock().await;
                                            sg.processed_entries.push((
                                                entry.inbox_key.clone(),
                                                entry.transaction_id.clone(),
                                            ));
                                            sg.processed = sg.processed.saturating_add(1);
                                        }
                                    } else {
                                        log::warn!(
                                            "[storage.sync] Unexpected transaction type: {:?}",
                                            entry.transaction
                                        );
                                    }
                                }

                                let (processed_entries, fatal_error) = {
                                    let final_state = batch_state.lock().await;
                                    processed = final_state.processed;
                                    errors.extend(final_state.errors.clone());
                                    (
                                        final_state.processed_entries.clone(),
                                        final_state.fatal_error.clone(),
                                    )
                                };

                                if let Some(fatal) = fatal_error {
                                    return err(fatal);
                                }

                                // Gate acknowledgements: ACK entries that were validated and
                                // processed this cycle, PLUS already-accepted stale-route duplicates
                                // (see §5.2) that must be ACKed directly to release a stranded sender
                                // gate without re-running now-invalid per-step-EK verification.
                                if !processed_entries.is_empty() || !stale_dup_acks.is_empty() {
                                    let mut ack_groups: std::collections::BTreeMap<
                                        String,
                                        Vec<String>,
                                    > = std::collections::BTreeMap::new();
                                    for (inbox_key, tx_id) in processed_entries.clone() {
                                        ack_groups.entry(inbox_key).or_default().push(tx_id);
                                    }
                                    for (inbox_key, tx_id) in stale_dup_acks.clone() {
                                        ack_groups.entry(inbox_key).or_default().push(tx_id);
                                    }

                                    let mut acked_total = 0usize;
                                    for (inbox_key, tx_ids) in ack_groups {
                                        let ack_res =
                                            match tokio::runtime::Handle::try_current() {
                                                Ok(handle) => tokio::task::block_in_place(|| {
                                                    handle.block_on(b0x_sdk.acknowledge_b0x_v2(
                                                        &inbox_key,
                                                        tx_ids.clone(),
                                                    ))
                                                }),
                                                Err(_) => {
                                                    if let Ok(rt) = tokio::runtime::Runtime::new() {
                                                        rt.block_on(b0x_sdk.acknowledge_b0x_v2(
                                                            &inbox_key,
                                                            tx_ids.clone(),
                                                        ))
                                                    } else {
                                                        Err(dsm::types::error::DsmError::internal(
                                                            "runtime failed",
                                                            None::<std::io::Error>,
                                                        ))
                                                    }
                                                }
                                            };

                                        match ack_res {
                                            Ok(_) => {
                                                acked_total += tx_ids.len();
                                            }
                                            Err(e) => {
                                                #[cfg(feature = "dev-discovery")]
                                                network_gate.record_network_failure();

                                                log::warn!(
                                                    "[storage.sync] ⚠️ Ack failed for {}: {}",
                                                    inbox_key,
                                                    e
                                                );
                                                errors.push(format!(
                                                    "acknowledge failed for {}: {}",
                                                    inbox_key, e
                                                ));
                                            }
                                        }
                                    }
                                    if acked_total > 0 {
                                        log::info!(
                                            "[storage.sync] ✅ Acknowledged {} inbox entries",
                                            acked_total
                                        );
                                    }
                                }

                                // NOTE: Post-batch chain tip update loop REMOVED.
                                // The per-entry §4.3 finalize path that CAS-advances the
                                // canonical bilateral tip with independently recomputed expected_h_next
                                // is authoritative. The old loop
                                // overwrote the correct relationship tip h_{n+1} with the state-machine entity
                                // hash (entry.sender_chain_tip), breaking fork-exclusion detection.

                                // §5.4 outbox sweep runs unconditionally below the
                                // if/else — see post-else block.

                                // Auto-push any pending bilateral messages if enabled
                                if push_pending {
                                    let push_res = crate::sdk::b0x_sdk::B0xSDK::push_pending_bilateral_messages(
                                        device_id_b32.clone(),
                                        self.core_sdk.clone(),
                                        storage_endpoints.clone(),
                                    ).await;
                                    match push_res {
                                        Ok(count) => {
                                            pushed = count as u32;
                                            log::info!(
                                                "[DSM_SDK] ✅ Pushed {} pending bilateral messages",
                                                count
                                            );
                                        }
                                        Err(e) => {
                                            // Record network failure for connectivity monitoring
                                            #[cfg(feature = "dev-discovery")]
                                            network_gate.record_network_failure();

                                            log::warn!(
                                                "[DSM_SDK] ⚠️ Failed to push pending messages: {}",
                                                e
                                            );
                                            errors.push(format!(
                                                "push pending messages failed: {}",
                                                e
                                            ));
                                        }
                                    }
                                }
                            } else {
                                log::info!("[DSM_SDK] No new inbox items to process");
                            }

                            // ═══════════════════════════════════════════════════════════
                            // ADR 0003 SPLIT-TRANSFER COMPLETION — every poll, from durable
                            // staging rows, regardless of whether anything was pulled above.
                            //
                            // Deliberately OUTSIDE the `if !all_items.is_empty()` block: a
                            // pair whose halves both landed on earlier polls, or a pair that
                            // was applied but died before its ACK, needs driving forward on
                            // a poll that pulls nothing. The database says what is unfinished;
                            // this invocation's item list does not.
                            //
                            // ACKs for BOTH halves go out on the retained route, and the
                            // route is released ONLY after the ACK succeeded — an ACK failure
                            // leaves it in place for the next pass to re-ACK.
                            // ═══════════════════════════════════════════════════════════
                            {
                                let (split_acks, release_keys) = self
                                    .complete_ready_split_transfers(&storage_endpoints)
                                    .await;
                                if !split_acks.is_empty() {
                                    let mut groups: std::collections::BTreeMap<
                                        String,
                                        Vec<String>,
                                    > = std::collections::BTreeMap::new();
                                    for (route, id) in &split_acks {
                                        groups.entry(route.clone()).or_default().push(id.clone());
                                    }
                                    let mut all_acked = true;
                                    for (route, ids) in groups {
                                        match b0x_sdk.acknowledge_b0x_v2(&route, ids.clone()).await {
                                            Ok(_) => log::info!(
                                                "[storage.sync] ADR 0003 ACKed {} id(s) on retained route {}..",
                                                ids.len(),
                                                &route[..route.len().min(12)]
                                            ),
                                            Err(e) => {
                                                all_acked = false;
                                                log::warn!(
                                                    "[storage.sync] ADR 0003 ACK failed on {}.. (route retained, will re-ACK): {e}",
                                                    &route[..route.len().min(12)]
                                                );
                                                errors.push(format!("ADR 0003 ack failed: {e}"));
                                            }
                                        }
                                    }
                                    // Release only when every ACK for this pass landed. A
                                    // partial failure keeps every route: re-ACKing an
                                    // already-acked id is idempotent at the node, and a
                                    // released route on an un-ACKed id is a stranded sender.
                                    if all_acked {
                                        for key in release_keys {
                                            match crate::storage::client_db::recipient_staging::release_retained_route(&key) {
                                                Ok(true) => log::info!("[storage.sync] ADR 0003 released retained route for {key}"),
                                                Ok(false) => {}
                                                Err(e) => log::warn!("[storage.sync] ADR 0003 route release failed for {key}: {e}"),
                                            }
                                        }
                                    }
                                }
                            }

                            // §16.6 ON-ACCESS acceptance recovery: once per poll, finish any
                            // applied-but-incomplete acceptance journals from the durable
                            // CanonicalApplyRecord — no redelivery required. Fail-closed skip
                            // when the wallet is locked (wrap key underivable).
                            match crate::init::current_chain_head_at_rest_key() {
                                Ok(wrap_key) => {
                                    if let Err(e) =
                                        crate::handlers::recipient_receipt::recover_incomplete_acceptances(&wrap_key).await
                                    {
                                        log::warn!("[storage.sync] §16.6 acceptance recovery sweep errored (non-fatal): {e}");
                                    }
                                }
                                Err(_) => {
                                    log::debug!("[storage.sync] §16.6 acceptance recovery skipped (wallet locked)");
                                }
                            }

                            // §16.6 REPLY WINDOW: deliver every countersigned acceptance
                            // receipt that is durably persisted but not yet handed to the
                            // sender. Store-before-send + repost-until-delivered: the row
                            // survives crashes and an offline sender, and the bytes are
                            // byte-identical on every attempt (signed once, at prepare).
                            if let Err(e) = deliver_pending_acceptance_replies(
                                &storage_endpoints,
                                self.core_sdk.clone(),
                            )
                            .await
                            {
                                log::warn!("[storage.sync] §16.6 reply delivery sweep errored (non-fatal): {e}");
                            }

                            // §5.4 RETIRED AS PROTOCOL AUTHORITY — TRANSPORT GC ONLY.
                            //
                            // This sweep used to advance the projection tip, promote the
                            // Local cert head, finalize the proposal and release the gate,
                            // all keyed off a storage-node ACK. It no longer touches any of
                            // them. The verified countersigned acceptance artifact is the
                            // sole finalization authority and commits that whole sequence in
                            // ONE transaction (`finalize_on_acceptance_atomically`).
                            //
                            // An ACK is a TRANSPORT fact: a node observed the recipient
                            // consume its spooled copy. It carries no evidence the recipient
                            // ACCEPTED the transfer, so it may never mutate canonical,
                            // projection, proposal, gate, or certificate state. What remains
                            // is collection: outbox rows the finalizer already moved to
                            // `gc_pending`, whose wire copies are now consumed.
                            if let Ok(collectable) =
                                crate::storage::client_db::gc_pending_sender_outbox()
                            {
                                for row in &collectable {
                                    // The wire id IS the deterministic submission id;
                                    // `message_ids` is a redundant bind that can be
                                    // missing when the process died between
                                    // `submitted` and the bind. Fall back rather than
                                    // skipping the row forever.
                                    let message_id = row
                                        .message_ids
                                        .as_deref()
                                        .unwrap_or(row.submission_id.as_str());
                                    match b0x_sdk.is_message_acknowledged(message_id).await {
                                        Ok(true) => match crate::storage::client_db::set_sender_outbox_status(
                                            &row.relationship_key,
                                            &row.canonical_parent,
                                            &row.proposal_nonce,
                                            crate::storage::client_db::OUTBOX_COMPLETE,
                                        ) {
                                            Ok(_) => log::info!(
                                                "[storage.sync] §5.4 GC: {message_id} consumed by the recipient; outbox row complete"
                                            ),
                                            Err(e) => log::warn!(
                                                "[storage.sync] §5.4 GC: could not mark {message_id} complete: {e}"
                                            ),
                                        },
                                        Ok(false) => log::debug!(
                                            "[storage.sync] §5.4 GC: {message_id} still spooled; retaining the outbox row"
                                        ),
                                        Err(e) => log::debug!(
                                            "[storage.sync] §5.4 GC: ACK check failed for {message_id}: {e}"
                                        ),
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Record network failure for connectivity monitoring
                            #[cfg(feature = "dev-discovery")]
                            network_gate.record_network_failure();

                            log::warn!("[DSM_SDK] inbox.pull: B0xSDK retrieve failed: {}", e);
                            return err(format!("inbox.pull: B0xSDK retrieve failed: {}", e));
                        }
                    }
                }

                // =============================================================
                // §16.6 / ADR 0003 — SENDER OUTBOX RESUBMIT SWEEP.
                //
                // The liveness half of the durable outbox. A send that entered
                // the network with an unknown outcome is retained as
                // `submission_uncertain` with its exact wire bytes and every
                // frozen artifact, and the user is told it "will be retried
                // automatically". This is that retry.
                //
                // Placement is deliberate: OUTSIDE `if pull_inbox`, gated only on
                // `push_pending`. An idle sender pulls nothing, and the recovery
                // gate test drives `push_pending` alone; a sweep nested in the
                // inbox branch would silently never run for either.
                //
                // Every row is re-driven through the SAME primitive the first
                // attempt used, over the same frozen bytes, ids and route, so
                // recovery cannot drift from delivery. All-or-nothing per row.
                // =============================================================
                if push_pending {
                    match self
                        .resubmit_unsettled_sender_outbox(&device_id_b32, &storage_endpoints)
                        .await
                    {
                        Ok(n) => pushed += n,
                        Err(e) => {
                            log::warn!("[storage.sync] outbox resubmit sweep errored: {e}");
                            errors.push(format!("outbox resubmit sweep failed: {e}"));
                        }
                    }
                }

                // Record network success for connectivity monitoring
                #[cfg(feature = "dev-discovery")]
                network_gate.record_network_success();

                let resp = generated::StorageSyncResponse {
                    success: true,
                    pulled,
                    processed,
                    pushed,
                    errors,
                };
                // NEW: Return as Envelope.storageSyncResponse (field 35)
                pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(resp))
            }

            // -------- storage.nodeHealth --------
            // Queries each configured storage node for health + Prometheus metrics.
            // Returns StorageNodeStatsResponse via Envelope.
            "storage.nodeHealth" => {
                log::info!("[DSM_SDK] storage.nodeHealth called");

                // Get endpoints from request or fall back to configured ones
                let endpoints = match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageNodeStatsRequest::decode(&*pack.body) {
                            Ok(req) if !req.endpoints.is_empty() => req.endpoints,
                            _ => crate::network::list_storage_endpoints().unwrap_or_default(),
                        }
                    }
                    _ => crate::network::list_storage_endpoints().unwrap_or_default(),
                };

                let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
                let mut node_stats = Vec::with_capacity(endpoints.len());
                let mut healthy_count = 0u32;

                // Query each endpoint concurrently
                let mut handles = Vec::new();
                for ep in &endpoints {
                    let c = client.clone();
                    let ep_owned = ep.clone();
                    handles.push(tokio::spawn(async move {
                        check_single_node_stats(&c, &ep_owned).await
                    }));
                }

                for handle in handles {
                    match handle.await {
                        Ok(stats) => {
                            if stats.status == "healthy" {
                                healthy_count += 1;
                            }
                            node_stats.push(stats);
                        }
                        Err(e) => {
                            log::warn!("[storage.nodeHealth] task join error: {}", e);
                        }
                    }
                }

                let resp = generated::StorageNodeStatsResponse {
                    nodes: node_stats,
                    total_nodes: endpoints.len() as u32,
                    healthy_nodes: healthy_count,
                };
                pack_envelope_ok(generated::envelope::Payload::StorageNodeStatsResponse(resp))
            }

            // -------- storage.connectivity --------
            // Diagnostic route: tests TLS handshake + device registration against each
            // configured storage node. Reports CA cert status, per-node reachability,
            // and auth token validity. Use to diagnose why online transfers fail.
            "storage.connectivity" => {
                log::info!("[DSM_SDK] storage.connectivity called");

                let ca_certs = crate::sdk::storage_node_sdk::ca_certs_loaded_count();
                let endpoints = crate::network::list_storage_endpoints().unwrap_or_default();
                let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
                let device_id_b32 =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);

                let mut node_stats = Vec::with_capacity(endpoints.len());
                let mut healthy_count = 0u32;

                for ep in &endpoints {
                    let start = std::time::Instant::now();
                    let health_url = format!("{ep}/api/v2/health");
                    let (tls_ok, http_status, tls_error) =
                        match client.get(&health_url).send().await {
                            Ok(resp) => {
                                let code = resp.status().as_u16();
                                (true, code.to_string(), String::new())
                            }
                            Err(e) => {
                                let msg = format!("{e}");
                                let is_tls = msg.contains("certificate")
                                    || msg.contains("ssl")
                                    || msg.contains("tls")
                                    || msg.contains("InvalidCertificate")
                                    || msg.contains("UnknownIssuer");
                                let label = if is_tls {
                                    "TLS_CERT_REJECTED"
                                } else if msg.contains("connect") || msg.contains("timeout") {
                                    "NETWORK_UNREACHABLE"
                                } else {
                                    "REQUEST_FAILED"
                                };
                                (false, label.to_string(), msg)
                            }
                        };
                    let latency_ms = start.elapsed().as_millis() as u32;

                    // Try device registration if TLS passed
                    let reg_status = if tls_ok {
                        match crate::sdk::b0x_sdk::B0xSDK::new(
                            device_id_b32.clone(),
                            self.core_sdk.clone(),
                            vec![ep.clone()],
                        ) {
                            Ok(sdk) => match sdk.register_device().await {
                                Ok(_) => "AUTH_OK".to_string(),
                                Err(e) => format!("AUTH_FAIL:{e}"),
                            },
                            Err(e) => format!("SDK_INIT_FAIL:{e}"),
                        }
                    } else {
                        "SKIPPED_TLS_FAIL".to_string()
                    };

                    let status = if tls_ok
                        && http_status.parse::<u16>().map(|c| c < 500).unwrap_or(false)
                        && reg_status == "AUTH_OK"
                    {
                        healthy_count += 1;
                        "healthy".to_string()
                    } else {
                        "down".to_string()
                    };

                    // Encode diagnostic details into last_error as a structured string.
                    let diag = format!(
                        "tls={} http={} auth={} ca_certs={}{}",
                        if tls_ok { "OK" } else { "FAIL" },
                        http_status,
                        reg_status,
                        ca_certs,
                        if tls_error.is_empty() {
                            String::new()
                        } else {
                            format!(" err={}", tls_error)
                        }
                    );

                    let (name, region) = name_and_region_from_endpoint(ep);

                    node_stats.push(generated::StorageNodeStats {
                        url: ep.clone(),
                        name,
                        region,
                        status,
                        latency_ms,
                        last_error: diag,
                        ..Default::default()
                    });
                }

                log::info!(
                    "[storage.connectivity] ca_certs={} nodes={} healthy={}/{}",
                    ca_certs,
                    endpoints.len(),
                    healthy_count,
                    endpoints.len()
                );

                let resp = generated::StorageNodeStatsResponse {
                    nodes: node_stats,
                    total_nodes: endpoints.len() as u32,
                    healthy_nodes: healthy_count,
                };
                pack_envelope_ok(generated::envelope::Payload::StorageNodeStatsResponse(resp))
            }

            // -------- storage.addNode --------
            "storage.addNode" => {
                log::info!("[DSM_SDK] storage.addNode called");
                match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageNodeManageRequest::decode(&*pack.body) {
                            Ok(req) if req.auto_assign => {
                                // Protocol enforcement: node assignment is decided by keyed
                                // Fisher-Yates over the known pool (dsm_env_config.toml minus
                                // active nodes). The caller does not choose which node is added.
                                match crate::network::auto_assign_storage_node(
                                    &self.device_id_bytes,
                                ) {
                                    Ok(assigned_url) => {
                                        let current = crate::network::list_storage_endpoints()
                                            .unwrap_or_default();
                                        let resp = generated::StorageNodeManageResponse {
                                            success: true,
                                            error: String::new(),
                                            current_endpoints: current,
                                            assigned_url,
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                    Err(e) => {
                                        let resp = generated::StorageNodeManageResponse {
                                            success: false,
                                            error: format!("{}", e),
                                            current_endpoints: vec![],
                                            assigned_url: String::new(),
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                }
                            }
                            Ok(_) => {
                                // Reject manual URL selection — node assignment must be
                                // determined by Fisher-Yates for security and even distribution.
                                err("storage.addNode: direct node selection is not permitted; set auto_assign = true".into())
                            }
                            Err(_) => err("storage.addNode: failed to decode request".into()),
                        }
                    }
                    _ => err("storage.addNode: invalid request encoding".into()),
                }
            }

            // -------- storage.removeNode --------
            "storage.removeNode" => {
                log::info!("[DSM_SDK] storage.removeNode called");
                match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageNodeManageRequest::decode(&*pack.body) {
                            Ok(req) if !req.url.is_empty() => {
                                match crate::network::remove_storage_endpoint(&req.url) {
                                    Ok(()) => {
                                        let current = crate::network::list_storage_endpoints()
                                            .unwrap_or_default();
                                        let resp = generated::StorageNodeManageResponse {
                                            success: true,
                                            error: String::new(),
                                            current_endpoints: current,
                                            assigned_url: String::new(),
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                    Err(e) => {
                                        let resp = generated::StorageNodeManageResponse {
                                            success: false,
                                            error: format!("{}", e),
                                            current_endpoints: vec![],
                                            assigned_url: String::new(),
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                }
                            }
                            _ => err("storage.removeNode: missing or invalid url".into()),
                        }
                    }
                    _ => err("storage.removeNode: invalid request encoding".into()),
                }
            }

            other => err(format!("unknown storage query: {other}")),
        }
    }

    /// `diagnostics.metrics` — return a plain-text metrics snapshot.
    ///
    /// Snapshot format: newline-delimited `key=value` lines (no JSON/hex/base64).
    /// Appends `db_bytes=N` from SQLite before returning so callers have storage
    /// context without embedding DB logic in the pure `dsm` crate.
    pub(crate) async fn handle_diagnostics_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "diagnostics.metrics" => {
                let mut snapshot = dsm::telemetry::get_global_metrics_snapshot();
                let db_bytes = crate::storage::client_db::get_db_size().unwrap_or(0);
                snapshot.extend_from_slice(format!("db_bytes={db_bytes}\n").as_bytes());

                // Encode snapshot as UTF-8 string in AppStateResponse.value so
                // the frontend can read it without a new proto field.
                let text = String::from_utf8_lossy(&snapshot).into_owned();
                let resp = generated::AppStateResponse {
                    key: "diagnostics.metrics".to_string(),
                    value: Some(text),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            other => err(format!("diagnostics: unknown route '{other}'")),
        }
    }
}

/// Check a single storage node's health and scrape its Prometheus metrics.
/// Uses `Instant::now()` for display-only latency measurement (permitted for
/// non-authoritative operational purposes per Hard Invariant §4).
async fn check_single_node_stats(
    client: &reqwest::Client,
    endpoint: &str,
) -> dsm::types::proto::StorageNodeStats {
    use dsm::types::proto::StorageNodeStats;
    use std::collections::HashMap;

    let start = std::time::Instant::now();
    let health_url = format!("{endpoint}/api/v2/health");

    // 1. Health check
    let (status, last_error) = match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => ("healthy".to_string(), String::new()),
        Ok(resp) => {
            let code = resp.status();
            ("degraded".to_string(), format!("HTTP {code}"))
        }
        Err(e) => ("down".to_string(), format!("{e}")),
    };
    let latency_ms = start.elapsed().as_millis() as u32;

    // 2. Prometheus metrics (best-effort, skip if node is down)
    let prom = if status != "down" {
        let metrics_url = format!("{endpoint}/metrics");
        match client.get(&metrics_url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(text) => parse_prometheus_text(&text),
                Err(_) => HashMap::new(),
            },
            _ => HashMap::new(),
        }
    } else {
        HashMap::new()
    };

    // 3. Derive name/region from endpoint heuristic (IP-to-region mapping)
    let (name, region) = name_and_region_from_endpoint(endpoint);

    StorageNodeStats {
        url: endpoint.to_string(),
        name,
        region,
        status,
        latency_ms,
        last_error,
        objects_put_total: prom_u64(&prom, "dsm_storage_objects_put_total"),
        objects_get_total: prom_u64(&prom, "dsm_storage_objects_get_total"),
        bytes_written_total: prom_u64(&prom, "dsm_storage_bytes_written_total"),
        bytes_read_total: prom_u64(&prom, "dsm_storage_bytes_read_total"),
        cleanup_runs_total: prom_u64(&prom, "dsm_storage_cleanup_runs_total"),
        replication_failures: prom_u64(&prom, "dsm_replication_outbox_failures_total"),
    }
}

/// Parse Prometheus exposition text format into metric_name → value map.
/// Handles simple gauge/counter lines: `metric_name value [unix_ts]`.
/// This is display-only operational data — not protocol.
fn parse_prometheus_text(text: &str) -> std::collections::HashMap<String, f64> {
    let mut metrics = std::collections::HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Handle optional label sets: e.g. metric_name{label="val"} 42
        let metric_part = if let Some(brace_idx) = trimmed.find('{') {
            if let Some(close_idx) = trimmed.find('}') {
                // metric_name{...} value
                let name = &trimmed[..brace_idx];
                let rest = trimmed[close_idx + 1..].trim();
                if let Some(val_str) = rest.split_whitespace().next() {
                    if let Ok(val) = val_str.parse::<f64>() {
                        metrics.insert(name.to_string(), val);
                    }
                }
                continue;
            }
            trimmed
        } else {
            trimmed
        };
        let mut parts = metric_part.split_whitespace();
        if let (Some(name), Some(val_str)) = (parts.next(), parts.next()) {
            if let Ok(val) = val_str.parse::<f64>() {
                metrics.insert(name.to_string(), val);
            }
        }
    }
    metrics
}

/// Extract a u64 from Prometheus metrics map (display-only).
fn prom_u64(prom: &std::collections::HashMap<String, f64>, key: &str) -> u64 {
    prom.get(key).copied().unwrap_or(0.0) as u64
}

/// Derive human-readable name and region from a storage node endpoint URL.
/// Uses the hardcoded production IP→region mapping.
fn name_and_region_from_endpoint(endpoint: &str) -> (String, String) {
    // GCP 6-node production cluster (must match dsm_env_config.toml)
    let ip_region_map: &[(&str, &str, &str)] = &[
        ("34.73.141.32", "us-east1-a", "us-east1"),
        ("35.243.157.151", "us-east1-b", "us-east1"),
        ("35.205.9.157", "europe-west1-a", "europe-west1"),
        ("34.53.251.120", "europe-west1-b", "europe-west1"),
        ("34.21.157.56", "asia-southeast1-a", "asia-southeast1"),
        ("34.87.93.29", "asia-southeast1-b", "asia-southeast1"),
    ];
    for &(ip, name, region) in ip_region_map {
        if endpoint.contains(ip) {
            return (name.to_string(), region.to_string());
        }
    }
    // Unknown node — derive a short name from the URL
    let short = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or(endpoint);
    (
        format!("node-{}", &short[..short.len().min(12)]),
        String::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::resolve_trusted_sender_ak;
    use super::select_history_receipt_bytes;

    #[test]
    fn select_history_receipt_bytes_prefers_rebuilt_receipt() {
        let rebuilt = Some(vec![1u8, 2, 3]);
        let fallback = vec![9u8, 9, 9];

        let selected = select_history_receipt_bytes(rebuilt, &fallback);

        assert_eq!(selected, Some(vec![1u8, 2, 3]));
    }

    #[test]
    fn select_history_receipt_bytes_falls_back_to_verified_receipt_commit() {
        let selected = select_history_receipt_bytes(None, &[7u8, 8, 9]);

        assert_eq!(selected, Some(vec![7u8, 8, 9]));
    }

    // =====================================================================
    // TRUST ROOT (issue #656): the online inbox must not verify an entry
    // against a key that entry supplied.
    //
    // The drain previously preferred `entry.sender_signing_public_key` over
    // the contact book and then passed it to `decode_and_bind_signed`. An
    // attacker who could place an inbox entry therefore supplied BOTH the key
    // and a signature made with the matching secret, and SIG A verified
    // against the attacker's own root.
    // =====================================================================

    fn trust_root_test_db() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        let _ =
            crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn seed_sender_contact(devid: [u8; 32], ak: Vec<u8>) -> String {
        let c = crate::storage::client_db::ContactRecord {
            contact_id: "cid-trust-root".to_string(),
            device_id: devid.to_vec(),
            alias: "sender".to_string(),
            genesis_hash: [0xAAu8; 32].to_vec(),
            public_key: ak,
            kyber_public_key: vec![0xCCu8; 1184],
            current_chain_tip: None,
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        };
        crate::storage::client_db::store_contact(&c).expect("seed contact");
        crate::util::text_id::encode_base32_crockford(&devid)
    }

    /// 1. Stored AK present, no wire key -> the stored AK is used.
    #[test]
    #[serial_test::serial]
    fn stored_ak_is_used_when_no_wire_key_is_embedded() {
        trust_root_test_db();
        let stored = vec![0xBBu8; 64];
        let dev = seed_sender_contact([0x51u8; 32], stored.clone());

        let resolved = resolve_trusted_sender_ak(&dev, &[]).expect("stored AK must resolve");
        assert_eq!(resolved, stored);
    }

    /// 2. THE ATTACK. An attacker embeds their own key; verification must NOT
    ///    root in it. Before the fix this returned the attacker's key, so a
    ///    signature made with the attacker's secret verified.
    #[test]
    #[serial_test::serial]
    fn an_attacker_supplied_wire_key_is_never_trusted() {
        trust_root_test_db();
        let stored = vec![0xBBu8; 64];
        let dev = seed_sender_contact([0x52u8; 32], stored.clone());

        let attacker = vec![0xEEu8; 64];
        let resolved = resolve_trusted_sender_ak(&dev, &attacker).expect("resolve");
        assert_eq!(
            resolved, stored,
            "verification must root in the STORED AK, never the wire-supplied key"
        );
        assert_ne!(
            resolved, attacker,
            "the attacker's key must never become the verification root"
        );
    }

    /// 3. Wire key disagrees with the stored AK -> the wire value is ignored and
    ///    verification still roots in the stored one.
    #[test]
    #[serial_test::serial]
    fn a_disagreeing_wire_key_is_ignored_not_preferred() {
        trust_root_test_db();
        let stored = vec![0x01u8; 64];
        let dev = seed_sender_contact([0x53u8; 32], stored.clone());

        let resolved = resolve_trusted_sender_ak(&dev, &[0x02u8; 64]).expect("resolve");
        assert_eq!(resolved, stored);
    }

    /// 4. No stored AK -> FAIL CLOSED. Never fall back to the wire value.
    ///    Establishing an AK for an unknown sender needs its own authenticated
    ///    identity rule; transfer verification must not bootstrap trust from the
    ///    message it is authenticating.
    #[test]
    #[serial_test::serial]
    fn no_stored_ak_fails_closed_and_never_falls_back_to_the_wire() {
        trust_root_test_db();
        let unknown = crate::util::text_id::encode_base32_crockford(&[0x54u8; 32]);

        let err = resolve_trusted_sender_ak(&unknown, &[0xEEu8; 64])
            .expect_err("an unknown sender must fail closed");
        assert!(
            err.contains("no locally trusted sender AK"),
            "unexpected error: {err}"
        );
    }

    // =====================================================================
    // #658 RECOVERY E2E — poisoned reply -> awaiting_valid_reply -> honest
    // copy for the same step -> finalized.
    //
    // WHY THIS TEST EXISTS AND WHY IT DRIVES THE HANDLER.
    //
    // `sender_proposal.rs` already proves the DB state machine ALLOWS this
    // path, but it does so by calling `mark_sender_proposal_awaiting_valid_
    // reply` and `mark_sender_proposal_finalized_by_canonical` directly. That
    // test stays green even if `finalize_from_acceptance_artifact` never makes
    // the transition at all — it measures the storage layer, not the decision.
    //
    // The defect being guarded is a stranded sender: `finalized` is the only
    // other state reachable from `submitted`, and reaching it requires the very
    // reply that was just refused. One bad artifact therefore pinned the step
    // forever. That is a property of the HANDLER, so the handler is what runs
    // here.
    //
    // The poisoning is the real attack shape, not a synthetic one. Receipt
    // fields 12-20 sit outside every signature, and the delta's `commitment`
    // is an unsigned reference the handler uses for proposal lookup. So a
    // middlebox can address a delta at a genuine proposal while carrying B
    // material minted over a different receipt. The poisoned delta below does
    // exactly that: the honest commitment and A digest, and B fields whose
    // per-step EK countersignature genuinely verifies — over a forged child.
    // =====================================================================

    /// Mint a B-side receipt whose per-step EK artifacts genuinely verify, with
    /// `b_ak_sk` acting as the relationship-genesis predecessor.
    ///
    /// Ordering matters: everything the commitment covers is set BEFORE the
    /// commitment is computed, and `sig_b` — which signs a target derived from
    /// that commitment — is attached last.
    fn signed_b_receipt(
        a: [u8; 32],
        b: [u8; 32],
        parent: [u8; 32],
        child: [u8; 32],
        b_ak_sk: &[u8],
    ) -> dsm::types::receipt_types::StitchedReceiptV2 {
        use crate::sdk::receipts::compute_receipt_challenge_response_target;
        use dsm::crypto::ephemeral_key::sign_ek_cert;
        use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};

        let mut r = dsm::types::receipt_types::StitchedReceiptV2::new(
            [0u8; 32],
            a,
            b,
            parent,
            child,
            [0u8; 32],
            [0u8; 32],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let (ek_pk_b, ek_sk_b) = generate_sphincs_keypair().expect("per-step EK keypair");
        r.ek_pk_b = ek_pk_b.clone();
        // Structural rule: ek_pk_b present => kyber_ct_b present.
        r.kyber_ct_b = vec![0x5Au8; 1088];
        // h_n is the receipt's own parent_tip, matching the verifier.
        r.ek_cert_b = sign_ek_cert(b_ak_sk, &ek_pk_b, &parent).expect("ek_cert_b");

        let commitment = r.compute_commitment().expect("commitment");
        let target = compute_receipt_challenge_response_target(&commitment, &commitment);
        r.sig_b = sphincs_sign(&ek_sk_b, &target).expect("sig_b");
        r
    }

    /// Freeze the sender's A-side evidence for `proposal` exactly as `wallet.send`
    /// does: the A-only receipt bytes wrapped by the REAL evidence builder,
    /// committed atomically with the proposal, outbox row, gate and EK head.
    /// Returns the evidence content digest — what an honest delta names.
    fn seed_frozen_send_with_evidence_a(
        a_side: &dsm::types::receipt_types::StitchedReceiptV2,
        proposal: &crate::storage::client_db::sender_proposal::SenderOnlineProposal,
        sender_b32: &str,
        recipient_b32: &str,
    ) -> [u8; 32] {
        use crate::storage::client_db::{
            commit_send_prerequisites_atomically, evidence_content_digest, ArtifactRole,
            SenderOutboxArtifact, SenderOutboxRecord, OUTBOX_PENDING_SUBMIT,
        };
        use std::sync::Arc;

        let a_bytes = a_side.to_full_protobuf().expect("A-side bytes");
        let digest_a = evidence_content_digest(ArtifactRole::EvidenceA, &a_bytes);
        let evidence_sid = crate::storage::client_db::derive_artifact_submission_id(&digest_a);
        let transfer_sid = crate::storage::client_db::derive_submission_id(&proposal.commitment);

        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().expect("CoreSDK"));
        let sdk =
            crate::sdk::b0x_sdk::B0xSDK::new(sender_b32.to_string(), core, vec![]).expect("B0xSDK");
        let built = sdk
            .build_evidence_envelope(
                recipient_b32,
                &crate::util::text_id::encode_base32_crockford(&[0xAAu8; 32]),
                &transfer_sid,
                &evidence_sid,
                &digest_a,
                &a_bytes,
            )
            .expect("real evidence envelope");

        let outbox = SenderOutboxRecord {
            relationship_key: proposal.relationship_key,
            canonical_parent: proposal.canonical_parent,
            proposal_nonce: proposal.nonce_hash,
            canonical_child: proposal.canonical_child,
            commitment: proposal.commitment,
            projection_parent: proposal.projection_parent,
            projection_target: proposal.projection_target,
            routing_address: "TESTROUTINGADDRESS".to_string(),
            submission_id: transfer_sid,
            envelope_bytes: vec![0xC1u8; 512],
            local_expected_prev: None,
            is_first_ek_step: true,
            status: OUTBOX_PENDING_SUBMIT.to_string(),
            message_ids: None,
            created_at: 0,
        };
        let evidence = SenderOutboxArtifact {
            relationship_key: proposal.relationship_key,
            canonical_parent: proposal.canonical_parent,
            proposal_nonce: proposal.nonce_hash,
            role: ArtifactRole::EvidenceA,
            submission_id: evidence_sid,
            envelope_bytes: built.bytes,
            content_digest: digest_a,
        };
        commit_send_prerequisites_atomically(
            proposal,
            &outbox,
            "GATE-658",
            &[0xD1u8; 64],
            &[0xD2u8; 64],
            &[0x42u8; 32],
            true,
            std::slice::from_ref(&evidence),
        )
        .expect("seed frozen send");
        digest_a
    }

    /// The recipient's delta for a countersigned receipt, as the sender's poll
    /// hands it to the handler: the four B fields plus the two references.
    /// `envelope_bytes` is what the sender persists on finalization; only the
    /// body is decoded here, so a placeholder envelope keeps this fixture
    /// honest about what it exercises.
    fn delta_for(
        receipt_with_b: &dsm::types::receipt_types::StitchedReceiptV2,
        commitment: [u8; 32],
        digest_a: [u8; 32],
    ) -> crate::sdk::b0x_sdk::CountersignDelta {
        use prost::Message;
        let (_, b) = receipt_with_b
            .split_countersign_b()
            .expect("receipt carries a countersignature");
        let body = dsm::types::proto::ReceiptCountersignB {
            commitment: commitment.to_vec(),
            receipt_evidence_digest_a: digest_a.to_vec(),
            sig_b: b.sig_b,
            ek_cert_b: b.ek_cert_b,
            ek_pk_b: b.ek_pk_b,
            kyber_ct_b: b.kyber_ct_b,
        }
        .encode_to_vec();
        crate::sdk::b0x_sdk::CountersignDelta {
            message_id: "TESTDELTA000000000000000000".to_string(),
            envelope_bytes: vec![0xEDu8; 64],
            body,
        }
    }

    struct SeededStep {
        a: [u8; 32],
        b: [u8; 32],
        b_ak_pk: Vec<u8>,
        b_ak_sk: Vec<u8>,
        parent: [u8; 32],
        honest: dsm::types::receipt_types::StitchedReceiptV2,
        commitment: [u8; 32],
        digest_a: [u8; 32],
        rel_key: [u8; 32],
        proposal: crate::storage::client_db::sender_proposal::SenderOnlineProposal,
    }

    /// One submitted step on the sender with its frozen A-side evidence, and
    /// the honest countersigned receipt the recipient would hold for it.
    fn seed_submitted_step() -> SeededStep {
        use crate::storage::client_db::sender_proposal::{
            mark_sender_proposal_submitted, SenderOnlineProposal, PROPOSAL_PROPOSED,
        };

        trust_root_test_db();
        let (a, b) = ([0x0Au8; 32], [0x0Bu8; 32]);
        let (parent, child) = ([0x31u8; 32], [0x32u8; 32]);

        // The recipient's AK is the cert-chain genesis root, and it comes from
        // the contact book — never from the wire.
        let (b_ak_pk, b_ak_sk) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("recipient AK");
        seed_sender_contact(b, b_ak_pk.clone());

        crate::sdk::app_state::AppState::set_identity_info(
            a.to_vec(),
            vec![0x01u8; 32],
            vec![0xAAu8; 32],
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);

        // The honest reply defines the commitment this step is bound to; its A
        // side is what the sender authored and froze.
        let honest = signed_b_receipt(a, b, parent, child, &b_ak_sk);
        let commitment = honest.compute_commitment().expect("commitment");
        let (a_side, _) = honest.split_countersign_b().expect("split");

        let rel_key = dsm::verification::smt_replace_witness::compute_smt_key(&a, &b);
        let proposal = SenderOnlineProposal {
            relationship_key: rel_key,
            canonical_parent: parent,
            canonical_child: child,
            // Genesis projection tip: a fresh relationship reads back an
            // all-zero chain_tip, so this is the real first-transfer shape.
            // Still deliberately DIVERGENT from the canonical pair — the two
            // formula spaces must not be conflated, and any check that reads
            // projection values where it should read canonical ones fails here.
            projection_parent: [0u8; 32],
            projection_target: [0xBBu8; 32],
            commitment,
            operation_digest: [0u8; 32],
            nonce_hash: [0x88u8; 32],
            message_id: None,
            tx_id: "TX-658".to_string(),
            counterparty_device_id: b,
            amount: 7,
            token_id: "ERA".to_string(),
            status: PROPOSAL_PROPOSED.to_string(),
            created_at: 0,
        };
        let digest_a = seed_frozen_send_with_evidence_a(
            &a_side,
            &proposal,
            &crate::util::text_id::encode_base32_crockford(&a),
            &crate::util::text_id::encode_base32_crockford(&b),
        );
        mark_sender_proposal_submitted(&rel_key, &parent, "MSG-658").expect("submit");

        SeededStep {
            a,
            b,
            b_ak_pk,
            b_ak_sk,
            parent,
            honest,
            commitment,
            digest_a,
            rel_key,
            proposal,
        }
    }

    fn proposal_status(commitment: &[u8; 32]) -> String {
        crate::storage::client_db::sender_proposal::get_sender_proposal_by_commitment(commitment)
            .expect("load")
            .expect("proposal still present")
            .status
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn a_poisoned_delta_parks_the_step_and_an_honest_delta_still_finalizes() {
        use super::CountersignOutcome;
        use crate::storage::client_db::sender_proposal::{
            get_sender_proposal_by_commitment, PROPOSAL_AWAITING_VALID_REPLY, PROPOSAL_FINALIZED,
            PROPOSAL_ROLLED_BACK,
        };
        let st = seed_submitted_step();

        // ---- 1. A poisoned delta arrives, addressed at the real proposal ----
        // B material minted over a receipt with a FORGED canonical child, then
        // carried in a delta naming the honest commitment and the honest A
        // digest. Its ek_cert_b genuinely verifies (same h_n); its sig_b was
        // signed over the forged commitment, so it cannot verify once overlaid
        // onto the sender's OWN A side.
        let poisoned_receipt = signed_b_receipt(st.a, st.b, st.parent, [0xEEu8; 32], &st.b_ak_sk);
        let poisoned = delta_for(&poisoned_receipt, st.commitment, st.digest_a);
        let outcome = super::finalize_from_countersign_delta(&poisoned).await;
        match &outcome {
            CountersignOutcome::Rejected(reason) => assert!(
                reason.contains("sig_b"),
                "the forgery must be refused on the countersignature, got: {reason}"
            ),
            other => panic!("poisoned delta must be Rejected by the verifier, got {other:?}"),
        }

        let after_poison = get_sender_proposal_by_commitment(&st.commitment)
            .expect("load")
            .expect("proposal still present");
        assert_eq!(
            after_poison.status, PROPOSAL_AWAITING_VALID_REPLY,
            "a rejected artifact must park the step in a state it can leave; \
             the handler itself must make this transition, not just the DB layer"
        );
        assert_ne!(
            after_poison.status, PROPOSAL_ROLLED_BACK,
            "NOT a rollback — the recipient may already have applied and credited"
        );
        assert_eq!(
            after_poison.message_id.as_deref(),
            Some("MSG-658"),
            "the step keeps its deterministic message id, so the honest copy \
             addresses the same submitted step rather than a new one"
        );

        // ---- 2. The honest delta for the SAME step finalizes it ----
        //
        // Pin the positive case first: if the "honest" receipt did not actually
        // verify, the finalize assertion below would be measuring the wrong
        // thing — a second rejection looks identical to a step that simply
        // never left `awaiting_valid_reply`.
        match crate::handlers::online_finalize::verify_acceptance_receipt(
            &st.a,
            &st.b,
            &st.honest,
            &after_poison,
            &st.b_ak_pk,
            None,
            None,
        )
        .expect("verification must not error")
        {
            crate::handlers::online_finalize::ReceiptVerifyOutcome::Verified { .. } => {}
            crate::handlers::online_finalize::ReceiptVerifyOutcome::Rejected { reason } => {
                panic!("the honest replacement must verify, but was rejected: {reason}")
            }
        }

        let good = delta_for(&st.honest, st.commitment, st.digest_a);
        assert_eq!(
            super::finalize_from_countersign_delta(&good).await,
            CountersignOutcome::Finalized
        );
        assert_eq!(
            proposal_status(&st.commitment),
            PROPOSAL_FINALIZED,
            "recovery is only real if a valid replacement for the same \
             commitment still finalizes the step through the live handler"
        );
        let outbox = crate::storage::client_db::get_sender_outbox_by_commitment(&st.commitment)
            .expect("outbox")
            .expect("present");
        assert_eq!(outbox.status, crate::storage::client_db::OUTBOX_GC_PENDING);
        let retained = crate::storage::client_db::load_sender_outbox_artifacts(
            &st.rel_key,
            &st.parent,
            &st.proposal.nonce_hash,
        )
        .expect("artifacts");
        assert!(
            retained.iter().any(|a| a.role
                == crate::storage::client_db::ArtifactRole::CountersignB
                && a.envelope_bytes == good.envelope_bytes),
            "the delta the sender finalized on is retained beside its evidence_a"
        );

        // A redelivered honest delta is an idempotent no-op.
        assert_eq!(
            super::finalize_from_countersign_delta(&good).await,
            CountersignOutcome::AlreadyFinalized
        );
    }

    /// Anti-vacuity: the poisoned B material must be refused for the RIGHT
    /// reason. Without this, the test above would still pass if the delta were
    /// rejected for something incidental — an unparseable body, a missing
    /// field — and it would then prove nothing about a well-formed forgery.
    #[test]
    #[serial_test::serial]
    fn the_poisoned_b_material_is_well_formed_and_fails_only_once_overlaid_on_the_honest_a_side() {
        trust_root_test_db();

        let (a, b) = ([0x0Au8; 32], [0x0Bu8; 32]);
        let (parent, child) = ([0x31u8; 32], [0x32u8; 32]);
        let (b_ak_pk, b_ak_sk) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("recipient AK");

        let poisoned = signed_b_receipt(a, b, parent, [0xEEu8; 32], &b_ak_sk);

        // Its per-step EK countersignature is genuinely valid over the receipt
        // it was minted for ...
        crate::sdk::receipts::verify_per_step_ek_signing(
            &poisoned,
            crate::sdk::receipts::BilateralSide::B,
            &b_ak_pk,
            &poisoned.parent_tip,
            &poisoned.compute_commitment().expect("commitment"),
        )
        .expect("the poisoned receipt must carry a genuinely valid sig_b");

        // ... and its delta survives the exact wire codec the handler uses,
        // countersignature intact.
        let (_, poisoned_b) = poisoned.split_countersign_b().expect("split");
        let delta = delta_for(&poisoned, [0x00u8; 32], [0x00u8; 32]);
        let decoded = dsm::types::receipt_types::decode_receipt_countersign_b_wire(&delta.body)
            .expect("the poisoned delta must pass the wire codec");
        assert_eq!(
            dsm::types::receipt_types::CountersignB::from_wire(&decoded),
            poisoned_b,
            "the countersignature must survive the wire round-trip"
        );

        // Overlaid onto the HONEST A side, the same material fails on sig_b
        // and nothing else: ek_cert_b still verifies (same h_n), the shape is
        // complete, only the countersignature target differs.
        let honest = signed_b_receipt(a, b, parent, child, &b_ak_sk);
        let (honest_a, _) = honest.split_countersign_b().expect("split");
        let reconstructed = honest_a
            .with_countersign_b(poisoned_b)
            .expect("overlay is structurally fine");
        let err = crate::sdk::receipts::verify_per_step_ek_signing(
            &reconstructed,
            crate::sdk::receipts::BilateralSide::B,
            &b_ak_pk,
            &reconstructed.parent_tip,
            &reconstructed.compute_commitment().expect("commitment"),
        )
        .expect_err("poisoned B material over the honest A side must not verify");
        assert!(
            format!("{err}").to_ascii_lowercase().contains("sig_b"),
            "{err}"
        );
        assert_ne!(
            poisoned.child_tip, child,
            "the forgery under test is the canonical child, nothing else"
        );
    }

    /// The delta's A-digest is advisory, but a delta naming A bytes this sender
    /// never retained is refused BEFORE any signature work and parks the step.
    /// Positive control in the same fixture: the true digest finalizes.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_delta_whose_digest_does_not_name_the_retained_evidence_is_rejected() {
        use super::CountersignOutcome;
        use crate::storage::client_db::sender_proposal::{
            PROPOSAL_AWAITING_VALID_REPLY, PROPOSAL_FINALIZED,
        };
        let st = seed_submitted_step();

        let mut wrong_digest = st.digest_a;
        wrong_digest[0] ^= 0x01;
        let mismatched = delta_for(&st.honest, st.commitment, wrong_digest);
        match super::finalize_from_countersign_delta(&mismatched).await {
            CountersignOutcome::DigestMismatch(reason) => {
                assert!(reason.contains("this sender retained"), "{reason}")
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        assert_eq!(
            proposal_status(&st.commitment),
            PROPOSAL_AWAITING_VALID_REPLY
        );

        let good = delta_for(&st.honest, st.commitment, st.digest_a);
        assert_eq!(
            super::finalize_from_countersign_delta(&good).await,
            CountersignOutcome::Finalized
        );
        assert_eq!(proposal_status(&st.commitment), PROPOSAL_FINALIZED);
    }

    /// A whole countersigned receipt on the countersign method is refused at
    /// the wire ("unknown field 7") and changes nothing; the same fixture then
    /// finalizes on the honest delta, so "nothing changed" is not vacuous.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_full_receipt_on_the_countersign_method_is_refused_at_the_wire() {
        use super::CountersignOutcome;
        use crate::storage::client_db::sender_proposal::{PROPOSAL_FINALIZED, PROPOSAL_SUBMITTED};
        let st = seed_submitted_step();

        let full_receipt = crate::sdk::b0x_sdk::CountersignDelta {
            message_id: "TESTFULL0000000000000000000".to_string(),
            envelope_bytes: vec![0xEDu8; 64],
            body: st.honest.to_full_protobuf().expect("full receipt"),
        };
        match super::finalize_from_countersign_delta(&full_receipt).await {
            CountersignOutcome::WireRejected(reason) => {
                assert!(reason.contains("unknown field 7"), "{reason}")
            }
            other => panic!("expected WireRejected, got {other:?}"),
        }
        assert_eq!(proposal_status(&st.commitment), PROPOSAL_SUBMITTED);

        let good = delta_for(&st.honest, st.commitment, st.digest_a);
        assert_eq!(
            super::finalize_from_countersign_delta(&good).await,
            CountersignOutcome::Finalized
        );
        assert_eq!(proposal_status(&st.commitment), PROPOSAL_FINALIZED);
    }

    /// Producer -> consumer with REAL per-step EK material: the recipient's
    /// real builder over its stored full receipt, decoded by the sender's real
    /// discriminator, finalized by the live handler. What the fixture-built
    /// deltas above cannot prove — that the two ends agree byte for byte.
    #[tokio::test]
    #[serial_test::serial]
    async fn the_real_delta_builder_output_finalizes_the_sender_through_the_live_handler() {
        use super::CountersignOutcome;
        use crate::storage::client_db::sender_proposal::PROPOSAL_FINALIZED;
        use prost::Message;
        use std::sync::Arc;
        let st = seed_submitted_step();

        // Recipient side: identity b, its stored full countersigned receipt.
        let full_bytes = st.honest.to_full_protobuf().expect("full receipt");
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().expect("CoreSDK"));
        let recipient_sdk = crate::sdk::b0x_sdk::B0xSDK::new(
            crate::util::text_id::encode_base32_crockford(&st.b),
            core,
            vec![],
        )
        .expect("B0xSDK");
        let built = recipient_sdk
            .build_countersign_reply_envelope(
                &[0xB6u8; 32],
                &st.proposal.projection_parent,
                &st.commitment,
                &full_bytes,
            )
            .expect("real delta");
        assert!(built.bytes.len() < 131_072, "{}", built.bytes.len());
        assert!(
            built.bytes.len() > 100_000,
            "two real SPHINCS objects: {}",
            built.bytes.len()
        );

        // Sender side: exactly what the poll does with the spooled envelope.
        let env = dsm::types::proto::Envelope::decode(&*built.bytes).expect("Envelope");
        let body = crate::sdk::b0x_sdk::B0xSDK::decode_countersign_b(&env)
            .expect("discriminated by method");
        let delta = crate::sdk::b0x_sdk::CountersignDelta {
            message_id: built.message_id_b32.clone(),
            envelope_bytes: built.bytes.clone(),
            body,
        };
        assert_eq!(
            super::finalize_from_countersign_delta(&delta).await,
            CountersignOutcome::Finalized
        );
        assert_eq!(proposal_status(&st.commitment), PROPOSAL_FINALIZED);
        let retained = crate::storage::client_db::load_sender_outbox_artifacts(
            &st.rel_key,
            &st.parent,
            &st.proposal.nonce_hash,
        )
        .expect("artifacts");
        let kept = retained
            .iter()
            .find(|a| a.role == crate::storage::client_db::ArtifactRole::CountersignB)
            .expect("countersign_b retained");
        assert_eq!(
            kept.envelope_bytes, built.bytes,
            "the exact envelope it finalized on"
        );
    }

    /// A step with no frozen evidence_a cannot finalize under any delta — that
    /// is a terminal invariant violation, reported as such, never a retry.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_delta_for_a_step_with_no_retained_evidence_is_a_terminal_invariant_violation() {
        use super::CountersignOutcome;
        use crate::storage::client_db::sender_proposal::PROPOSAL_SUBMITTED;
        let st = seed_submitted_step();

        // Pin the precondition, then remove the row the design depends on.
        assert!(
            crate::handlers::online_finalize::load_retained_evidence_a(&st.proposal)
                .expect("load")
                .is_some(),
            "fixture must start WITH the evidence row"
        );
        {
            let binding = crate::storage::client_db::get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "DELETE FROM sender_outbox_artifacts WHERE role = 'evidence_a'",
                [],
            )
            .expect("delete evidence_a");
        }
        assert!(
            crate::handlers::online_finalize::load_retained_evidence_a(&st.proposal)
                .expect("load")
                .is_none()
        );

        let good = delta_for(&st.honest, st.commitment, st.digest_a);
        assert_eq!(
            super::finalize_from_countersign_delta(&good).await,
            CountersignOutcome::NoRetainedEvidence
        );
        assert_eq!(proposal_status(&st.commitment), PROPOSAL_SUBMITTED);
    }

    // =====================================================================
    // RUNTIME RECOVERY OF AN UNCERTAIN SEND
    //
    // The durable outbox promises two things. It keeps the SAFETY half today:
    // a failed send is committed as `submission_uncertain`, the exact wire
    // bytes are frozen, and a restart neither rebuilds them nor debits again.
    // Hardware confirmed all of that.
    //
    // It also promises LIVENESS — the user is told the send "will be retried
    // automatically", `unsettled_sender_outbox()` documents itself as driving
    // "the startup/periodic resubmit sweep", and `StorageSyncRequest` carries
    // a `push_pending` field commented "submit local pending transactions".
    //
    // This test drives the REAL periodic hook — `run_storage_sync_request`,
    // the same call production makes from three sites — against a seeded
    // uncertain row. It deliberately does NOT call `unsettled_sender_outbox()`
    // itself: proving the query returns rows would pass today and would test
    // the wrong layer entirely. What must be observed is a network submission.
    //
    // The recorders are intentionally dumb. They authenticate nothing, parse
    // no protobuf, and verify no signature — every one of those would give the
    // test a way to fail for reasons unrelated to the missing wiring.
    // =====================================================================

    #[derive(Debug, Clone)]
    struct RecordedPost {
        endpoint: String,
        path: String,
        body: Vec<u8>,
        /// `x-dsm-recipient` — the route the caller submitted under.
        recipient: String,
        /// `x-dsm-message-id` — the deterministic id the caller submitted under.
        message_id: String,
    }

    /// Per-message-id HTTP status the recorder should answer with instead of
    /// 204. Lets a test make ONE artifact fail while the other succeeds.
    type StatusOverrides = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u16>>>;

    /// A loopback listener that records `POST /api/v2/b0x/submit` and answers
    /// `204 No Content`. Returns its `http://127.0.0.1:PORT` base URL.
    fn spawn_recorder(
        log: std::sync::Arc<std::sync::Mutex<Vec<RecordedPost>>>,
    ) -> std::io::Result<String> {
        spawn_recorder_with_overrides(log, StatusOverrides::default())
    }

    fn spawn_recorder_with_overrides(
        log: std::sync::Arc<std::sync::Mutex<Vec<RecordedPost>>>,
        overrides: StatusOverrides,
    ) -> std::io::Result<String> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let mine = endpoint.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                // Read headers, then exactly Content-Length bytes of body.
                let (mut head_end, mut content_len) = (None, 0usize);
                while head_end.is_none() {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                head_end = Some(p + 4);
                                let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                                for line in head.lines() {
                                    if let Some(v) = line.strip_prefix("content-length:") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let Some(hs) = head_end else { continue };
                while buf.len() < hs + content_len {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&buf[..hs]).to_string();
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                let header = |name: &str| -> String {
                    head.lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim()
                                .eq_ignore_ascii_case(name)
                                .then(|| v.trim().to_string())
                        })
                        .unwrap_or_default()
                };
                let message_id = header("x-dsm-message-id");
                let status: u16 = overrides
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&message_id)
                    .copied()
                    .unwrap_or(204);
                if head.to_uppercase().starts_with("POST") {
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(RecordedPost {
                            endpoint: mine.clone(),
                            path,
                            body: buf[hs..].to_vec(),
                            recipient: header("x-dsm-recipient"),
                            message_id,
                        });
                }
                let reason = match status {
                    204 => "No Content",
                    503 => "Service Unavailable",
                    500 => "Internal Server Error",
                    _ => "OK",
                };
                let _ = s.write_all(
                    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                );
                let _ = s.flush();
            }
        });
        Ok(endpoint)
    }

    /// Point the runtime's storage-endpoint resolver at the recorders.
    ///
    /// Both `wallet.send` and `storage.sync` resolve endpoints through
    /// `StorageNodeConfig::from_env_config()`, NOT `SdkConfig`. Under
    /// DSM_SDK_TEST_MODE that loader returns a hardcoded localhost set
    /// (:8080-8084) unless DSM_ENV_CONFIG_PATH names a real file — so without
    /// this, the code under test dials ports nothing is listening on and a
    /// missing submission is indistinguishable from the defect.
    fn point_env_config_at(endpoints: &[String]) {
        // ONE fixed path per process, installed through the OnceLock the JNI
        // layer uses in production. The env var is deliberately NOT relied on:
        // other test modules in this binary `remove_var` it from NON-serial
        // setup helpers, so under a full-binary run they can clear it between
        // this call and the sweep's read — the sweep then dials the
        // DSM_SDK_TEST_MODE fallback ports and a wiring test goes red for a
        // fixture reason. The OnceLock is consulted before the env var and
        // cannot be un-set, so it is immune to that race. Each test rewrites
        // the FILE with its own recorders; the loader re-reads it every call.
        let cfg_path = std::env::temp_dir().join(format!(
            "dsm_storage_routes_test_env_{}.toml",
            std::process::id()
        ));
        let mut cfg_toml = String::from(
            "protocol = \"http\"\nlan_ip = \"127.0.0.1\"\nallow_localhost = true\n\
             storage_node_mode = \"remote\"\nports = [8080]\n\
             bitcoin_network = \"signet\"\ndbtc_min_confirmations = 1\n",
        );
        for (i, ep) in endpoints.iter().enumerate() {
            cfg_toml.push_str(&format!(
                "\n[[nodes]]\nname = \"rec-{i}\"\nendpoint = \"{ep}\"\n"
            ));
        }
        std::fs::write(&cfg_path, cfg_toml).expect("write env config");
        crate::network::set_env_config_path(cfg_path.to_string_lossy().into_owned());
        // Belt and braces for any reader that still prefers the env var.
        unsafe {
            std::env::set_var("DSM_ENV_CONFIG_PATH", &cfg_path);
        }
    }

    /// A frozen uncertain send: the transfer envelope plus its ADR 0003
    /// A-side evidence, both already encoded and committed.
    struct FrozenSend {
        transfer_submission_id: String,
        transfer_bytes: Vec<u8>,
        evidence_submission_id: String,
        evidence_bytes: Vec<u8>,
    }

    fn seed_uncertain_send() -> FrozenSend {
        use crate::storage::client_db::{
            commit_send_prerequisites_atomically, set_sender_outbox_status, ArtifactRole,
            SenderOnlineProposal, SenderOutboxArtifact, SenderOutboxRecord, OUTBOX_PENDING_SUBMIT,
            OUTBOX_SUBMISSION_UNCERTAIN,
        };

        // The commit path refuses an unknown counterparty, so the relationship
        // must exist before a send can be frozen against it.
        seed_sender_contact([0x0Bu8; 32], vec![0xA1u8; 64]);

        let rel =
            dsm::verification::smt_replace_witness::compute_smt_key(&[0x0Au8; 32], &[0x0Bu8; 32]);
        let (cp, cc) = ([0x71u8; 32], [0x72u8; 32]);
        let (pp, pt) = ([0u8; 32], [0x74u8; 32]);
        let nonce = [0x75u8; 32];
        let commitment = [0x76u8; 32];

        // Deterministic, byte-exact, and distinguishable from each other.
        let transfer_submission_id = "TESTTRANSFER0000000000000A".to_string();
        let evidence_submission_id = "TESTEVIDENCEA000000000000B".to_string();
        let transfer_bytes = vec![0xC1u8; 4096];
        let evidence_bytes = vec![0xE1u8; 8192];

        let proposal = SenderOnlineProposal {
            relationship_key: rel,
            canonical_parent: cp,
            canonical_child: cc,
            projection_parent: pp,
            projection_target: pt,
            commitment,
            operation_digest: [0x77u8; 32],
            nonce_hash: nonce,
            message_id: None,
            tx_id: "tx:recovery-test".to_string(),
            counterparty_device_id: [0x0Bu8; 32],
            amount: 5,
            token_id: "ERA".to_string(),
            status: "proposed".to_string(),
            created_at: 0,
        };

        let outbox = SenderOutboxRecord {
            relationship_key: rel,
            canonical_parent: cp,
            proposal_nonce: nonce,
            canonical_child: cc,
            commitment,
            projection_parent: pp,
            projection_target: pt,
            routing_address: "TESTROUTINGADDRESS".to_string(),
            submission_id: transfer_submission_id.clone(),
            envelope_bytes: transfer_bytes.clone(),
            local_expected_prev: None,
            is_first_ek_step: true,
            status: OUTBOX_PENDING_SUBMIT.to_string(),
            message_ids: None,
            created_at: 0,
        };

        let evidence = SenderOutboxArtifact {
            relationship_key: rel,
            canonical_parent: cp,
            proposal_nonce: nonce,
            role: ArtifactRole::EvidenceA,
            submission_id: evidence_submission_id.clone(),
            envelope_bytes: evidence_bytes.clone(),
            content_digest: [0x78u8; 32],
        };

        commit_send_prerequisites_atomically(
            &proposal,
            &outbox,
            "GATE-RECOVERY",
            &[0xD1u8; 64],
            &[0xD2u8; 64],
            &[0x42u8; 32],
            true,
            std::slice::from_ref(&evidence),
        )
        .expect("seed frozen send");

        // The send entered the network and the outcome is unknown — exactly
        // the state a 402/timeout leaves behind.
        set_sender_outbox_status(&rel, &cp, &nonce, OUTBOX_SUBMISSION_UNCERTAIN)
            .expect("mark uncertain");

        FrozenSend {
            transfer_submission_id,
            transfer_bytes,
            evidence_submission_id,
            evidence_bytes,
        }
    }

    // Multi-threaded for the same reason as the scaffold above: once the sweep
    // is wired this reaches the submit path, which calls `block_in_place` and
    // panics on a single-threaded runtime. Set BEFORE the wiring so the first
    // post-fix run cannot fail for a fixture reason and be read as the fix
    // failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn submission_uncertain_is_replayed_from_frozen_artifacts_on_runtime_recovery() {
        use crate::storage::client_db::{unsettled_sender_outbox, OUTBOX_SUBMISSION_UNCERTAIN};

        trust_root_test_db();

        // Three recorders, because the production submit path is quorum-shaped;
        // one endpoint could not distinguish "called submit" from "reached K".
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<RecordedPost>::new()));
        let endpoints: Vec<String> = (0..3)
            .map(|_| spawn_recorder(log.clone()).expect("recorder"))
            .collect();
        point_env_config_at(&endpoints);

        let device_id = vec![0x0Au8; 32];
        let genesis_hash = vec![0x31u8; 32];
        let binding_key = vec![0x41u8; 32];
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &device_id,
            &genesis_hash,
            &binding_key,
        )
        .expect("signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id,
            public_key,
            genesis_hash,
            dsm::merkle::sparse_merkle_tree::empty_root(
                dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
            )
            .to_vec(),
        );
        crate::sdk::app_state::AppState::set_has_identity(true);

        let sender_b32 = crate::util::text_id::encode_base32_crockford(&[0x0Au8; 32]);
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(&[0x31u8; 32]);

        // FIXTURE DEBT PAID UP FRONT. Once the sweep is wired this test reaches
        // `submit_stored_envelope`, which calls `ensure_token_for_endpoint` and
        // looks up (endpoint, device_id_b32, base32(local_genesis_hash())).
        // `local_genesis_hash()` reads `genesis_records`, NOT AppState — so the
        // record below is both the routing genesis and the genesis half of the
        // token key. Miss either and the SDK falls through to a live
        // registration handshake the recorders cannot answer.
        crate::storage::client_db::store_genesis_record_with_verification(
            &crate::storage::client_db::GenesisRecord {
                genesis_id: genesis_b32.clone(),
                device_id: sender_b32.clone(),
                mpc_proof: "test".to_string(),
                device_birth_binding: String::new(),
                merkle_root: String::new(),
                participant_count: 3,
                progress_marker: String::new(),
                publication_hash: String::new(),
                storage_nodes: endpoints.clone(),
                entropy_hash: String::new(),
                protocol_version: "v1".to_string(),
                hash_chain_proof: None,
                smt_proof: None,
                verification_step: None,
                genesis_nonce: String::new(),
                genesis_profile: "MnemonicV2".to_string(),
            },
        )
        .expect("seed genesis record");
        for ep in &endpoints {
            crate::storage::client_db::store_auth_token(
                ep,
                &sender_b32,
                &genesis_b32,
                "test-token",
            )
            .expect("seed auth token");
        }

        let frozen = seed_uncertain_send();

        // Precondition: the sweep query can see it. If this ever fails the test
        // is mis-seeded, and the real assertions below would be vacuous.
        assert_eq!(
            unsettled_sender_outbox().expect("query").len(),
            1,
            "fixture must present exactly one unsettled send"
        );

        let router = crate::handlers::app_router_impl::AppRouterImpl::new(crate::init::SdkConfig {
            node_id: "recovery-test".to_string(),
            storage_endpoints: endpoints.clone(),
            enable_offline: false,
        })
        .expect("router init");

        // THE PRODUCTION HOOK. No wallet.send, no manual resubmit helper.
        let _ = router
            .run_storage_sync_request(dsm::types::proto::StorageSyncRequest {
                pull_inbox: false,
                push_pending: true,
                limit: 0,
            })
            .await;

        let posts = log.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let submits: Vec<&RecordedPost> = posts
            .iter()
            .filter(|p| p.path.contains("/api/v2/b0x/submit"))
            .collect();

        // ---- the defect this test exists for ----
        assert!(
            !submits.is_empty(),
            "periodic storage sync with push_pending=true performed ZERO b0x \
             submissions while a submission_uncertain send was durably stored. \
             The durable record survives and the UI promises automatic retry, \
             but nothing re-drives it: unsettled_sender_outbox() has no \
             production caller, and push_pending sweeps bilateral_sessions \
             instead of sender_outbox."
        );

        // ---- exact frozen replay, both halves ----
        let by_bytes = |want: &[u8]| -> Vec<&&RecordedPost> {
            submits.iter().filter(|p| p.body == want).collect()
        };
        assert!(
            !by_bytes(&frozen.transfer_bytes).is_empty(),
            "the transfer half must be replayed BYTE-IDENTICALLY from the frozen \
             envelope ({} bytes), never rebuilt from current state",
            frozen.transfer_bytes.len()
        );
        assert!(
            !by_bytes(&frozen.evidence_bytes).is_empty(),
            "the ADR 0003 A-side evidence must also be replayed byte-identically \
             ({} bytes). Replaying only the transfer resurrects a send the \
             recipient can never complete",
            frozen.evidence_bytes.len()
        );

        // Each half must reach the same quorum shape production requires.
        for (label, want) in [
            ("transfer", &frozen.transfer_bytes),
            ("evidence_a", &frozen.evidence_bytes),
        ] {
            let reached: std::collections::BTreeSet<&str> = submits
                .iter()
                .filter(|p| p.body == *want)
                .map(|p| p.endpoint.as_str())
                .collect();
            assert_eq!(
                reached.len(),
                endpoints.len(),
                "{label} must reach all {} nodes; reached {:?}",
                endpoints.len(),
                reached
            );
        }

        // ---- nothing was rebuilt, nothing was charged twice ----
        let rows = unsettled_sender_outbox().expect("query");
        assert!(
            rows.len() <= 1,
            "recovery must not create a second outbox row: {} present",
            rows.len()
        );
        assert_eq!(
            crate::storage::client_db::get_sender_proposal_by_commitment(&[0x76u8; 32])
                .expect("load")
                .expect("proposal")
                .amount,
            5,
            "recovery must not rebuild or re-price the proposal"
        );
        assert!(
            frozen.transfer_submission_id != frozen.evidence_submission_id,
            "fixture sanity: the two artifacts must carry distinct ids"
        );

        // ---- lifecycle moves forward only when everything landed ----
        let still_uncertain = unsettled_sender_outbox()
            .expect("query")
            .iter()
            .any(|r| r.status == OUTBOX_SUBMISSION_UNCERTAIN);
        assert!(
            !still_uncertain,
            "once every frozen artifact reached quorum the logical send must \
             leave submission_uncertain; leaving it there would replay forever"
        );

        // ---- the route invariant, observed on the wire ----
        // Every half rides the OWNING outbox's frozen route, under its own
        // frozen id. A replay under any other recipient would be silently
        // discarded by the node's message-id dedup while returning success —
        // so the route on the wire is what proves no relocation happened.
        for p in &submits {
            assert_eq!(
                p.recipient, "TESTROUTINGADDRESS",
                "every submission must carry the frozen routing_address as x-dsm-recipient; \
                 got {:?} for message {}",
                p.recipient, p.message_id
            );
        }
        let ids: std::collections::BTreeSet<&str> =
            submits.iter().map(|p| p.message_id.as_str()).collect();
        assert!(
            ids.contains(frozen.transfer_submission_id.as_str())
                && ids.contains(frozen.evidence_submission_id.as_str()),
            "both frozen ids must appear on the wire verbatim; saw {ids:?}"
        );
    }

    /// Partial delivery is NOT delivery. If the transfer reaches quorum but the
    /// evidence does not, the logical send stays `submission_uncertain`, no
    /// status advances, and the next sweep replays the WHOLE frozen set — a
    /// second debit never happens because nothing is rebuilt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_half_delivered_send_stays_uncertain_and_the_next_sweep_replays_everything() {
        use crate::storage::client_db::{
            unsettled_sender_outbox, OUTBOX_SUBMISSION_UNCERTAIN, OUTBOX_SUBMITTED,
        };

        trust_root_test_db();

        let overrides: StatusOverrides = StatusOverrides::default();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<RecordedPost>::new()));
        let endpoints: Vec<String> = (0..3)
            .map(|_| {
                spawn_recorder_with_overrides(log.clone(), overrides.clone()).expect("recorder")
            })
            .collect();
        point_env_config_at(&endpoints);

        let device_id = vec![0x0Au8; 32];
        let genesis_hash = vec![0x31u8; 32];
        let binding_key = vec![0x41u8; 32];
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &device_id,
            &genesis_hash,
            &binding_key,
        )
        .expect("signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id,
            public_key,
            genesis_hash,
            dsm::merkle::sparse_merkle_tree::empty_root(
                dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
            )
            .to_vec(),
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        let sender_b32 = crate::util::text_id::encode_base32_crockford(&[0x0Au8; 32]);
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(&[0x31u8; 32]);
        crate::storage::client_db::store_genesis_record_with_verification(
            &crate::storage::client_db::GenesisRecord {
                genesis_id: genesis_b32.clone(),
                device_id: sender_b32.clone(),
                mpc_proof: "test".to_string(),
                device_birth_binding: String::new(),
                merkle_root: String::new(),
                participant_count: 3,
                progress_marker: String::new(),
                publication_hash: String::new(),
                storage_nodes: endpoints.clone(),
                entropy_hash: String::new(),
                protocol_version: "v1".to_string(),
                hash_chain_proof: None,
                smt_proof: None,
                verification_step: None,
                genesis_nonce: String::new(),
                genesis_profile: "MnemonicV2".to_string(),
            },
        )
        .expect("seed genesis record");
        for ep in &endpoints {
            crate::storage::client_db::store_auth_token(
                ep,
                &sender_b32,
                &genesis_b32,
                "test-token",
            )
            .expect("seed auth token");
        }

        let frozen = seed_uncertain_send();
        let proposal_before =
            crate::storage::client_db::get_sender_proposal_by_commitment(&[0x76u8; 32])
                .expect("load")
                .expect("proposal");

        // The EVIDENCE fails everywhere; the transfer succeeds.
        overrides
            .lock()
            .unwrap()
            .insert(frozen.evidence_submission_id.clone(), 503);

        let router = crate::handlers::app_router_impl::AppRouterImpl::new(crate::init::SdkConfig {
            node_id: "partial-test".to_string(),
            storage_endpoints: endpoints.clone(),
            enable_offline: false,
        })
        .expect("router init");
        async fn sync(r: &crate::handlers::app_router_impl::AppRouterImpl) {
            let _ = r
                .run_storage_sync_request(dsm::types::proto::StorageSyncRequest {
                    pull_inbox: false,
                    push_pending: true,
                    limit: 0,
                })
                .await;
        }

        sync(&router).await;

        // The transfer went out; the evidence was tried and refused. Neither
        // is a delivery.
        let posts = log.lock().unwrap().clone();
        assert!(posts
            .iter()
            .any(|p| p.message_id == frozen.transfer_submission_id));
        assert!(posts
            .iter()
            .any(|p| p.message_id == frozen.evidence_submission_id));

        let rows = unsettled_sender_outbox().expect("query");
        assert_eq!(
            rows.len(),
            1,
            "exactly one row, no duplicate created on partial delivery"
        );
        assert_eq!(
            rows[0].status, OUTBOX_SUBMISSION_UNCERTAIN,
            "a transfer-only quorum must NOT advance the logical send"
        );
        assert_eq!(
            crate::storage::client_db::get_sender_proposal_by_commitment(&[0x76u8; 32])
                .expect("load")
                .expect("proposal")
                .status,
            proposal_before.status,
            "proposal status must not move on partial delivery"
        );

        // Network heals. The next sweep replays BOTH halves — byte-identical,
        // same ids — and only now does the send advance.
        overrides.lock().unwrap().clear();
        log.lock().unwrap().clear();
        sync(&router).await;

        let posts = log.lock().unwrap().clone();
        let replayed_transfer = posts
            .iter()
            .filter(|p| p.body == frozen.transfer_bytes)
            .count();
        let replayed_evidence = posts
            .iter()
            .filter(|p| p.body == frozen.evidence_bytes)
            .count();
        assert!(
            replayed_transfer >= 3 && replayed_evidence >= 3,
            "the whole frozen set is replayed to full quorum, not just the missing half \
             (transfer x{replayed_transfer}, evidence x{replayed_evidence})"
        );
        let rows = unsettled_sender_outbox().expect("query");
        assert!(
            rows.is_empty(),
            "after full delivery the row leaves the unsettled set; got {:?}",
            rows.iter().map(|r| r.status.as_str()).collect::<Vec<_>>()
        );
        // And it moved to `submitted`, not somewhere else.
        let all: Vec<String> = {
            let binding = crate::storage::client_db::get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let mut st = conn
                .prepare("SELECT status FROM sender_outbox")
                .expect("prep");
            st.query_map([], |r| r.get::<_, String>(0))
                .expect("q")
                .collect::<Result<Vec<_>, _>>()
                .expect("rows")
        };
        assert_eq!(all, vec![OUTBOX_SUBMITTED.to_string()]);
    }

    /// Settled rows are never replayed. `submitted`, `gc_pending` and
    /// `complete` produce ZERO submissions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn settled_outbox_rows_are_never_resubmitted() {
        use crate::storage::client_db::{
            set_sender_outbox_status, OUTBOX_COMPLETE, OUTBOX_GC_PENDING, OUTBOX_SUBMITTED,
        };

        trust_root_test_db();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<RecordedPost>::new()));
        let endpoints: Vec<String> = (0..3)
            .map(|_| spawn_recorder(log.clone()).expect("recorder"))
            .collect();
        point_env_config_at(&endpoints);
        let device_id = vec![0x0Au8; 32];
        crate::sdk::app_state::AppState::set_identity_info(
            device_id,
            vec![0x01u8; 32],
            vec![0x31u8; 32],
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        crate::sdk::recovery_sdk::RecoverySDK::set_cached_wallet_seed_for_testing(vec![0x9Cu8; 64]);

        let _frozen = seed_uncertain_send();
        let rel =
            dsm::verification::smt_replace_witness::compute_smt_key(&[0x0Au8; 32], &[0x0Bu8; 32]);
        let (cp, nonce) = ([0x71u8; 32], [0x75u8; 32]);

        let router = crate::handlers::app_router_impl::AppRouterImpl::new(crate::init::SdkConfig {
            node_id: "settled-test".to_string(),
            storage_endpoints: endpoints.clone(),
            enable_offline: false,
        })
        .expect("router init");

        for settled in [OUTBOX_SUBMITTED, OUTBOX_GC_PENDING, OUTBOX_COMPLETE] {
            set_sender_outbox_status(&rel, &cp, &nonce, settled).expect("set");
            log.lock().unwrap().clear();
            let _ = router
                .run_storage_sync_request(dsm::types::proto::StorageSyncRequest {
                    pull_inbox: false,
                    push_pending: true,
                    limit: 0,
                })
                .await;
            let submits = log
                .lock()
                .unwrap()
                .iter()
                .filter(|p| p.path.contains("/api/v2/b0x/submit"))
                .count();
            assert_eq!(
                submits, 0,
                "a `{settled}` row must never be replayed; the sweep replayed it {submits} time(s)"
            );
        }
    }

    // =====================================================================
    // INITIAL-SEND DELIVERY COMPLETENESS
    //
    // A SEPARATE defect from the recovery gate above, on a separate production
    // path. `wallet.send` builds BOTH halves of an ADR 0003 split send and
    // commits both durably in one transaction — `sender_outbox` for the
    // transfer, `sender_outbox_artifacts` for the A-side evidence. It then
    // submits only the transfer: `app_router_impl.rs` destructures
    // `extra_artifacts: _` and `submit_stored_envelope` is called once, with
    // the transfer envelope alone.
    //
    // The recipient side is complete and waiting — `recipient_accept` and
    // `recipient_dispatch` stage and pair both halves — so a send that
    // delivers only the transfer leaves the recipient holding one half of a
    // pair whose partner was never sent.
    //
    // THE RULE UNDER TEST, stated as the contract rather than as a POST count:
    //
    //   wallet.send MUST NOT report success unless the transfer envelope AND
    //   every frozen A-side artifact have reached quorum.
    //
    // Asserting only "two POSTs happened" would pass a future best-effort
    // implementation that fires the evidence and reports success without
    // waiting for it. Premature success is the defect, not merely a missing
    // request.
    // =====================================================================

    /// Serves the two endpoint families a first-time send touches, and records
    /// every submission. Deliberately dumb: it authenticates nothing and
    /// validates no protobuf, so this gate cannot fail for reasons unrelated
    /// to delivery completeness.
    fn spawn_send_recorder(
        log: std::sync::Arc<std::sync::Mutex<Vec<RecordedPost>>>,
        identity_bytes: std::sync::Arc<Vec<u8>>,
    ) -> std::io::Result<String> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let mine = endpoint.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (mut head_end, mut content_len) = (None, 0usize);
                while head_end.is_none() {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                head_end = Some(p + 4);
                                let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                                for line in head.lines() {
                                    if let Some(v) = line.strip_prefix("content-length:") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let Some(hs) = head_end else { continue };
                while buf.len() < hs + content_len {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&buf[..hs]).to_string();
                let mut parts = head.lines().next().unwrap_or("").split_whitespace();
                let method = parts.next().unwrap_or("").to_uppercase();
                let path = parts.next().unwrap_or("").to_string();

                let resp: Vec<u8> = if method == "POST" {
                    let header = |name: &str| -> String {
                        head.lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.trim()
                                    .eq_ignore_ascii_case(name)
                                    .then(|| v.trim().to_string())
                            })
                            .unwrap_or_default()
                    };
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(RecordedPost {
                            endpoint: mine.clone(),
                            path: path.clone(),
                            body: buf[hs..].to_vec(),
                            recipient: header("x-dsm-recipient"),
                            message_id: header("x-dsm-message-id"),
                        });
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec()
                } else if path.contains("/api/v2/device/") {
                    // Quorum identity lookup. Failure here is FATAL inside
                    // wallet.send, so it must answer.
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        identity_bytes.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(&identity_bytes);
                    r
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
                };
                let _ = s.write_all(&resp);
                let _ = s.flush();
            }
        });
        Ok(endpoint)
    }

    // SCAFFOLD — NOT EVIDENCE YET. Ignored on purpose.
    //
    // This does NOT currently prove defect #1. It halts one assertion early, at
    // its own anti-vacuity guard, because the fixture cannot yet establish the
    // in-memory bilateral state a first-time send requires: the
    // BilateralTransactionManager Tripwire rejects with `ParentConsumed`
    // (`anchor.chain_tip != pre.local_chain_tip_at_creation`), which is
    // contact_manager state rather than a seedable row.
    //
    // Six real production dependencies ARE resolved here and are worth keeping:
    // genesis via `genesis_records` (NOT AppState); endpoints via
    // `DSM_ENV_CONFIG_PATH` (`SdkConfig.storage_endpoints` is ignored by
    // wallet.send); the auth-token triple; the identity GET; a non-empty served
    // pubkey matching the contact AK byte-for-byte; and a multi-threaded runtime
    // for `block_in_place`.
    //
    // Do not un-ignore this to "see it fail" — a red here means fixture
    // incompleteness, not the defect. It should be re-sited around the smallest
    // production orchestration boundary that can prove the contract without
    // rebuilding the bilateral state machine by hand.
    //
    // Multi-threaded on purpose: the send path calls `block_in_place`, which
    // panics on the single-threaded runtime. Production runs multi-threaded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    #[ignore = "scaffold: fixture cannot yet reach ADR 0003 split composition; not evidence for defect #1"]
    async fn wallet_send_submits_transfer_and_frozen_evidence_a_before_reporting_delivery_success()
    {
        use crate::storage::client_db::{load_sender_outbox_artifacts, unsettled_sender_outbox};
        use prost::Message;

        trust_root_test_db();

        let sender_device = [0x0Au8; 32];
        let recipient_device = [0x0Bu8; 32];
        let genesis = [0x31u8; 32];
        let recipient_kyber = vec![0x9Au8; 1184];

        // The served identity must MATCH the stored contact exactly so
        // `repair_contact_decision` short-circuits to `Unchanged` and no
        // SPHINCS+ binding signature has to be minted for this fixture.
        // `pubkey` cannot be empty: `fetch_quorum_device_identity` rejects an
        // empty pubkey before `authoritative_ak_permits_repair` is ever
        // consulted, so the contact AK below is set to this same value.
        let recipient_ak = vec![0xA1u8; 32];
        let identity = dsm::types::proto::RegisterDeviceRequest {
            device_id: recipient_device.to_vec(),
            pubkey: recipient_ak.clone(),
            genesis_hash: genesis.to_vec(),
            kyber_public_key: recipient_kyber.clone(),
            kyber_binding_sig: vec![0x5Au8; 64],
        };
        let identity_bytes = std::sync::Arc::new(identity.encode_to_vec());

        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<RecordedPost>::new()));
        let endpoints: Vec<String> = (0..3)
            .map(|_| spawn_send_recorder(log.clone(), identity_bytes.clone()).expect("recorder"))
            .collect();

        point_env_config_at(&endpoints);

        let binding_key = vec![0x41u8; 32];
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &sender_device,
            &genesis,
            &binding_key,
        )
        .expect("signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            sender_device.to_vec(),
            public_key.clone(),
            genesis.to_vec(),
            dsm::merkle::sparse_merkle_tree::empty_root(
                dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
            )
            .to_vec(),
        );
        crate::sdk::app_state::AppState::set_has_identity(true);

        let sender_b32 = crate::util::text_id::encode_base32_crockford(&sender_device);
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(&genesis);

        // `wallet.send` routes on `core_sdk.local_genesis_hash()`, which reads
        // `genesis_records` — NOT AppState. It is also the genesis half of the
        // auth-token key, so both must come from this one record or the token
        // lookup misses and falls through to live registration.
        crate::storage::client_db::store_genesis_record_with_verification(
            &crate::storage::client_db::GenesisRecord {
                genesis_id: genesis_b32.clone(),
                device_id: sender_b32.clone(),
                mpc_proof: "test".to_string(),
                device_birth_binding: String::new(),
                merkle_root: String::new(),
                participant_count: 3,
                progress_marker: String::new(),
                publication_hash: String::new(),
                storage_nodes: endpoints.clone(),
                entropy_hash: String::new(),
                protocol_version: "v1".to_string(),
                hash_chain_proof: None,
                smt_proof: None,
                verification_step: None,
                genesis_nonce: String::new(),
                genesis_profile: "MnemonicV2".to_string(),
            },
        )
        .expect("seed genesis record");

        // FIXTURE GUARD: `ensure_token_for_endpoint` looks up
        // (endpoint, self.device_id, base32(core_sdk.local_genesis_hash())).
        // Miss it and the SDK falls through to a live registration handshake
        // this recorder cannot satisfy — a setup failure that would look
        // exactly like the defect.
        for ep in &endpoints {
            crate::storage::client_db::store_auth_token(
                ep,
                &sender_b32,
                &genesis_b32,
                "test-token",
            )
            .expect("seed auth token");
        }

        // Recipient contact, matching the served identity exactly.
        let mut contact = crate::storage::client_db::ContactRecord {
            contact_id: "c-gate2".to_string(),
            device_id: recipient_device.to_vec(),
            alias: "recipient".to_string(),
            genesis_hash: genesis.to_vec(),
            public_key: recipient_ak.clone(),
            kyber_public_key: recipient_kyber,
            current_chain_tip: None,
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "BleCapable".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        };
        contact.verified = true;
        crate::storage::client_db::store_contact(&contact).expect("seed contact");

        crate::storage::client_db::upsert_balance_projection(
            &crate::storage::client_db::BalanceProjectionRecord {
                balance_key: format!("{sender_b32}:ERA"),
                device_id: sender_b32.clone(),
                token_id: "ERA".to_string(),
                policy_commit: crate::util::text_id::encode_base32_crockford(&[0x0Fu8; 32]),
                available: 1000,
                locked: 0,
                source_state_hash: String::new(),
                updated_at: 0,
            },
        )
        .expect("seed balance");

        let router = crate::handlers::app_router_impl::AppRouterImpl::new(crate::init::SdkConfig {
            node_id: "gate2".to_string(),
            storage_endpoints: endpoints.clone(),
            enable_offline: false,
        })
        .expect("router init");

        let body = dsm::types::proto::OnlineTransferRequest {
            token_id: "ERA".to_string(),
            to_device_id: recipient_device.to_vec(),
            amount: 5,
            from_device_id: sender_device.to_vec(),
            seq: 1,
            nonce: vec![0x7Eu8; 32],
            ..Default::default()
        };
        let args = dsm::types::proto::ArgPack {
            codec: dsm::types::proto::Codec::Proto as i32,
            body: body.encode_to_vec(),
            ..Default::default()
        };

        // THE PRODUCTION PATH. An ordinary first-time send.
        use crate::bridge::AppRouter;
        let result = router
            .invoke(crate::bridge::AppInvoke {
                method: "wallet.send".to_string(),
                args: args.encode_to_vec(),
            })
            .await;

        // What the send FROZE is the ground truth for what it owed the wire.
        let frozen_artifacts: Vec<_> = unsettled_sender_outbox()
            .expect("outbox")
            .into_iter()
            .flat_map(|r| {
                load_sender_outbox_artifacts(
                    &r.relationship_key,
                    &r.canonical_parent,
                    &r.proposal_nonce,
                )
                .unwrap_or_default()
            })
            .collect();

        let posts = log.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let submits: Vec<&RecordedPost> = posts
            .iter()
            .filter(|p| p.path.contains("/api/v2/b0x/submit"))
            .collect();

        // Anti-vacuity: if the send never got as far as freezing an evidence
        // artifact, this test is measuring the wrong thing and must say so
        // rather than passing quietly.
        assert!(
            !frozen_artifacts.is_empty(),
            "fixture did not reach ADR 0003 split composition — no A-side \
             artifact was frozen, so delivery completeness cannot be judged. \
             wallet.send returned success={} error={:?}",
            result.success,
            result.error_message
        );

        for art in &frozen_artifacts {
            let reached: std::collections::BTreeSet<&str> = submits
                .iter()
                .filter(|p| p.body == art.envelope_bytes)
                .map(|p| p.endpoint.as_str())
                .collect();

            // THE CONTRACT. Reporting success while a frozen artifact never
            // reached quorum is the defect — whether it was never sent, or
            // sent best-effort without waiting.
            assert!(
                !(result.success && reached.len() < endpoints.len()),
                "wallet.send reported success=true while the frozen {:?} \
                 artifact ({} bytes, submission_id={}) reached only {}/{} \
                 nodes. A split send whose A-side evidence never reaches \
                 quorum leaves the recipient holding one half of a pair whose \
                 partner was never delivered.",
                art.role,
                art.envelope_bytes.len(),
                art.submission_id,
                reached.len(),
                endpoints.len()
            );
        }
    }

    // =====================================================================
    // RECIPIENT COMPLETION IS DRIVEN BY DURABLE STATE, NOT BY THIS POLL.
    //
    // The crash-after-apply-before-ACK window: a pair reached durable
    // `accepted`, and the process died before its ACKs went out. On the next
    // poll NOTHING is pulled that names this pair — the sender is not
    // re-sending, and this device's in-memory "touched keys" from the last
    // invocation are gone. If completion depended on either, the sender's gate
    // would stay stranded forever. So the pass must find the row in the
    // database and produce both ACK coordinates from it alone.
    // =====================================================================

    /// A durably `accepted` split pair with a retained route, and nothing
    /// polled this invocation, must still yield ACKs for BOTH halves on that
    /// route — and its route must be released only when told the ACKs landed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn an_accepted_but_unacked_pair_is_re_acked_from_the_database_alone() {
        use crate::storage::client_db::recipient_staging::{
            get_staging, mark_accepted, release_retained_route, retained_routes_for_polling,
            stage_evidence_half, stage_transfer_half, StagingState,
        };

        trust_root_test_db();

        let sender_device = [0x0Au8; 32];
        let self_device = [0x0Bu8; 32];
        crate::sdk::app_state::AppState::set_identity_info(
            self_device.to_vec(),
            vec![0x01u8; 32],
            vec![0x31u8; 32],
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        // `AppRouterImpl::new` derives signing authority from the cached seed.
        crate::sdk::recovery_sdk::RecoverySDK::set_cached_wallet_seed_for_testing(vec![0x9Cu8; 64]);
        // The trust root the pass resolves the sender through.
        seed_sender_contact(sender_device, vec![0xA1u8; 64]);

        // A receipt naming (sender -> self). Signature validity is not what this
        // test is about — the pair is already `accepted`, so `decide_ack`
        // short-circuits without verifying — but the receipt must decode and
        // must name this device as devid_b, because the pass reads both.
        let receipt = dsm::types::receipt_types::StitchedReceiptV2::new(
            [0u8; 32],
            sender_device,
            self_device,
            [0x41u8; 32],
            [0x42u8; 32],
            [0u8; 32],
            [0u8; 32],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let evidence_bytes = receipt.to_full_protobuf().expect("encode");
        let evidence_digest = crate::storage::client_db::evidence_content_digest(
            crate::storage::client_db::ArtifactRole::EvidenceA,
            &evidence_bytes,
        );

        let key = "SPLITKEY0000000000000000A1";
        let route = "RETAINEDROUTEXYZ";
        // Reach ready_to_verify, then accepted — the state a crash after apply
        // but before ACK leaves behind.
        assert_eq!(
            stage_transfer_half(key, b"transfer-half-bytes", &evidence_digest, route)
                .expect("stage transfer"),
            StagingState::StagedTransfer
        );
        assert_eq!(
            stage_evidence_half(key, &evidence_bytes, route).expect("stage evidence"),
            StagingState::ReadyToVerify
        );
        mark_accepted(key).expect("accepted");
        assert_eq!(
            get_staging(key)
                .expect("load")
                .expect("row")
                .retained_route
                .as_deref(),
            Some(route)
        );

        let router = crate::handlers::app_router_impl::AppRouterImpl::new(crate::init::SdkConfig {
            node_id: "completion-test".to_string(),
            storage_endpoints: vec!["http://127.0.0.1:1".to_string()],
            enable_offline: false,
        })
        .expect("router init");

        // THE PASS, with nothing polled and no touched-key hint. It must find
        // the row itself.
        let (acks, release_keys) = router
            .complete_ready_split_transfers(&["http://127.0.0.1:1".to_string()])
            .await;

        // Both halves, both on the retained route, ids as the sender derives them.
        let expected_evidence_id =
            crate::storage::client_db::derive_artifact_submission_id(&evidence_digest);
        let mut got = acks.clone();
        got.sort();
        let mut want = vec![
            (route.to_string(), key.to_string()),
            (route.to_string(), expected_evidence_id.clone()),
        ];
        want.sort();
        assert_eq!(
            got, want,
            "an accepted pair must be re-ACKed for BOTH halves on its retained route, from \
             durable state alone"
        );
        assert_eq!(release_keys, vec![key.to_string()]);

        // The pass does NOT release the route itself — the caller does, and only
        // after the ACKs succeed. Until then the route stays polled.
        assert!(retained_routes_for_polling()
            .expect("routes")
            .contains(&route.to_string()));

        // Simulate the caller's "all ACKs succeeded" step.
        assert!(release_retained_route(key).expect("release"));
        assert!(!retained_routes_for_polling()
            .expect("routes")
            .contains(&route.to_string()));

        // Idempotent re-entry: the row is still `accepted`; running the pass
        // again re-derives the same ACKs (re-ACKing is free at the node) and
        // never touches apply. Route is now None, so the caller would skip.
        let (acks2, _) = router
            .complete_ready_split_transfers(&["http://127.0.0.1:1".to_string()])
            .await;
        assert!(
            acks2.is_empty(),
            "with the route released there is nothing to ACK by route; got {acks2:?}"
        );
        assert_eq!(
            crate::storage::client_db::recipient_staging::staging_state(key).expect("state"),
            StagingState::Accepted,
            "re-entry must not disturb the durable acceptance"
        );
    }
}
