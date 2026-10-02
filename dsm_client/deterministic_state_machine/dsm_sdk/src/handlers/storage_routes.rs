// SPDX-License-Identifier: MIT OR Apache-2.0
//! Storage route handlers for AppRouterImpl.
//!
//! Handles `storage.status` and `storage.sync` query paths.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};
use super::app_router_impl::{collect_tagged_inbox_addresses, RouteFreshness};

#[cfg(all(target_os = "android", feature = "jni"))]
fn emit_authoritative_wallet_refresh() {
    if let Err(e) = crate::jni::event_dispatch::post_event_to_webview("dsm-wallet-refresh", &[]) {
        log::debug!("[storage.sync] wallet refresh dispatch skipped: {e}");
    }
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn emit_authoritative_wallet_refresh() {}

/// Block the relationship with `device_id` until it is reconciled online.
fn mark_contact_needs_online_reconcile_and_refresh(device_id: &[u8]) -> Result<(), String> {
    crate::storage::client_db::mark_contact_needs_online_reconcile(device_id)
        .map_err(|e| format!("failed to mark a relationship blocked for reconcile: {e}"))?;
    emit_authoritative_wallet_refresh();
    Ok(())
}

/// The received transfer's history row, written from the VERIFIED operation
/// and named by the transfer's recomputed submission id.
///
/// Derived from accepted state rather than written once as a side effect: a
/// pass that deferred after the apply (convergence, the economic admission, a
/// failed write) leaves the row to the next pass, which writes it before the
/// pair is released. None of it is protocol state; the balance is already
/// materialized by the apply.
fn ensure_received_history(
    wallet: &crate::sdk::wallet_sdk::WalletSDK,
    v: &crate::handlers::recipient_accept::VerifiedTransfer,
    sender_b32: &str,
    self_b32: &str,
) -> Result<(), String> {
    use crate::storage::codecs::hash_blake3_bytes;

    let name = v.transfer_name();
    if crate::storage::client_db::transaction_exists(&name)
        .map_err(|e| format!("{name}: history unreadable: {e}"))?
    {
        return Ok(());
    }
    let terms = crate::handlers::recipient_accept::transfer_terms(&v.signed_op)?;
    let mut meta: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    meta.insert("token_id".to_string(), terms.token_id.into_bytes());
    // The operation the receipt's tip binds, so the history can check the
    // receipt again and read the figures from it.
    meta.insert(
        crate::storage::client_db::HISTORY_OPERATION_KEY.to_string(),
        v.signed_op.to_bytes(),
    );
    let proof_data = v
        .receipt
        .to_full_protobuf()
        .map_err(|e| format!("{name}: the receipt does not encode: {e}"))?;
    let rec = crate::storage::client_db::TransactionRecord {
        tx_hash: crate::util::text_id::encode_base32_crockford(&hash_blake3_bytes(name.as_bytes())),
        tx_id: name.clone(),
        from_device: sender_b32.to_string(),
        to_device: self_b32.to_string(),
        amount: terms.amount,
        tx_type: "online".to_string(),
        status: "confirmed".to_string(),
        commitment_hash: None,
        proof_data: Some(proof_data),
        metadata: meta,
    };
    crate::storage::client_db::store_transaction(&rec)
        .map_err(|e| format!("{name}: history row not stored: {e}"))?;
    wallet
        .reload_balance_cache_for_self()
        .map_err(|e| format!("{name}: balance cache not reloaded: {e}"))?;
    emit_authoritative_wallet_refresh();
    Ok(())
}

/// Resolve the SPHINCS+ key an inbound half is verified against.
///
/// TRUST ROOT: the sender's AK comes from the LOCALLY STORED contact, never
/// from the wire. A half names a contact (its envelope header, or its receipt's
/// `devid_a`); that name only chooses which stored key is tried, and the
/// signature decides whether the half is that contact's. Ordinary transfer
/// verification never bootstraps trust from the message it authenticates;
/// establishing an AK for an unknown sender needs its own authenticated
/// identity rule.
pub(crate) fn resolve_trusted_sender_ak(sender_device_id: &str) -> Result<Vec<u8>, String> {
    stored_sender_ak(sender_device_id)?
        .ok_or_else(|| format!("no locally trusted sender AK for {sender_device_id}"))
}

/// The key this device stored for `sender_device_id`: `None` when it holds no
/// such contact — a fact about the name, not a failure — and `Err` only when
/// the store cannot be read.
pub(crate) fn stored_sender_ak(sender_device_id: &str) -> Result<Option<Vec<u8>>, String> {
    crate::storage::client_db::get_contact_public_key_by_device_id(sender_device_id)
        .map_err(|e| format!("the trusted sender AK for {sender_device_id} is unreadable: {e}"))
}

/// Verify an inbound stitched receipt's sender authorization (`sig_a`) the way
/// the sender actually produces it (§11.1 per-step EK).
///
/// The online send path signs `sig_a` with a freshly-derived per-step EK
/// (`receipt.ek_pk_a`, cert-chained to the sender's AK via `ek_cert_a`) over
/// the receipt challenge-response target — NOT with the sender's static signing
/// key over the raw commitment. The genesis cert-chain root is the sender's
/// AK_pk (`ak_pk_genesis` here), the key this device stored for the contact.
/// `session_binding` for the online path is the receipt commitment itself.
///
/// VERIFY ONLY — this does NOT mutate the Counterparty cert-chain head. The head
/// is advanced by the acceptance fold's completion phase (CAS, §16.6) only after
/// the transition is durably applied and the acceptance marker is written, so a
/// receipt that verifies but fails to apply never advances the receiver's chain
/// (lockstep: a failed acceptance leaves both chains where they were).
///
/// Two kinds of answer: the outer `Err` is this device unable to decide (the
/// counterparty's cert-chain head could not be read); the inner `Err` is the
/// verdict that `sig_a` does not verify.
pub(crate) fn verify_inbound_receipt_sig_a(
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    commitment: &[u8; 32],
    ak_pk_genesis: &[u8],
) -> Result<Result<(), String>, String> {
    let expected_prev_pk = expected_counterparty_ek_root(receipt, ak_pk_genesis)?;
    Ok(
        dsm::verification::receipt_verification::verify_per_step_ek_signing(
            receipt,
            dsm::verification::receipt_verification::BilateralSide::A,
            &expected_prev_pk,
            &receipt.parent_tip,
            commitment,
        )
        .map_err(|e| e.to_string()),
    )
}

/// The key an inbound receipt's `ek_cert_a` must chain to. From the receiver's
/// viewpoint the SENDER (A-side) is the Counterparty; at relationship genesis
/// (no Counterparty head yet) the sender's `ek_cert_a` chains back to the
/// sender's AK — the legitimate predecessor. A head that could not be READ is
/// not "no head": the check cannot be made, and that is an error.
fn expected_counterparty_ek_root(
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    ak_pk_genesis: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::storage::client_db::{load_cert_chain_head_pubkey, CertChainSide};

    let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
        &receipt.devid_a,
        &receipt.devid_b,
    );
    match load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty) {
        Ok(Some(head)) => Ok(head),
        Ok(None) => Ok(ak_pk_genesis.to_vec()),
        Err(e) => Err(format!(
            "the counterparty's cert-chain head could not be read: {e}"
        )),
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
    let bound = match bind_countersign_delta(&retained, &wire) {
        Ok(DeltaBinding::Bound(b)) => *b,
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
        Ok(Some(pk)) => pk,
        Ok(None) => {
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta {short}..: the recipient is not a \
                 contact — cannot verify sig_b, gate retained"
            );
            return CountersignOutcome::Unverifiable("the recipient is not a contact".to_string());
        }
        Err(e) => {
            return CountersignOutcome::Unverifiable(format!(
                "the recipient's stored AK is unreadable: {e}"
            ));
        }
    };

    let receipt = &bound.receipt;
    match crate::handlers::online_finalize::verify_acceptance_receipt(
        &self_device_id,
        &proposal.counterparty_device_id,
        receipt,
        &proposal,
        &recipient_ak_pk,
        bound.b_pair(),
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
    // THE RELEASE GATE (3.5b PR4). `sig_b` above is acceptance PROVENANCE —
    // it is published inside the recipient's admission evidence before
    // ECON_ADMITTED and proves acceptance, not admission. Finalization
    // authority is the recipient-signed RecipientEconomicReleaseV1, bound to
    // this exact commitment and recipient identity, and then checked
    // INDEPENDENTLY against the recipient's registered economic root — a
    // hostile recipient's private "admitted" flag is never trusted.
    // ====================================================================
    if wire.recipient_economic_release_addr.is_empty() {
        let reason = "countersign delta carries no recipient economic release — bare sig_b \
                      cannot finalize the sender"
            .to_string();
        park_awaiting_valid_reply(&proposal, &short, &reason);
        return CountersignOutcome::Rejected(reason);
    }
    let Ok(release_addr) = <[u8; 32]>::try_from(wire.recipient_economic_release_addr.as_slice())
    else {
        let reason = "recipient economic release addr is not 32 bytes".to_string();
        park_awaiting_valid_reply(&proposal, &short, &reason);
        return CountersignOutcome::Rejected(reason);
    };
    // Fetch the exact release bytes by content address (re-hash verified by
    // the fetch boundary). Not-yet-published is an outage shape, not an
    // attack: the recipient's post-admit publish may still be in flight.
    let set = match crate::sdk::economic_admission_flow::committed_network_id()
        .and_then(|network| crate::sdk::storage_set::canonical_set(&network))
    {
        Ok(set) => set,
        Err(e) => return CountersignOutcome::Unverifiable(format!("no pinned storage set: {e}")),
    };
    let release_bytes = match crate::sdk::storage_io::fetch_immutable(
        &set,
        dsm::common::domain_tags::TAG_DSM_RECIPIENT_ECONOMIC_RELEASE,
        &release_addr,
    )
    .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta {short}..: release object not yet \
                 fetchable — finalize deferred"
            );
            return CountersignOutcome::Unverifiable("release object not yet fetchable".into());
        }
        Err(e) => {
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta {short}..: release fetch failed \
                 ({e}) — finalize deferred"
            );
            return CountersignOutcome::Unverifiable(format!("release fetch: {e}"));
        }
    };
    let release = match dsm::economic::release::verify_recipient_economic_release(
        &release_bytes,
        &recipient_ak_pk,
    ) {
        Ok(f) => f,
        Err(e) => {
            let reason = format!("recipient economic release refused: {e}");
            park_awaiting_valid_reply(&proposal, &short, &reason);
            return CountersignOutcome::Rejected(reason);
        }
    };
    if release.receipt_commitment != commitment
        || release.recipient_devid != proposal.counterparty_device_id
    {
        let reason = "recipient economic release is bound to a different transition or recipient"
            .to_string();
        park_awaiting_valid_reply(&proposal, &short, &reason);
        return CountersignOutcome::Rejected(reason);
    }
    // The release's genesis must be the PINNED contact identity — otherwise a
    // hostile recipient could point the register check at an accomplice's
    // cell under a different genesis.
    match crate::storage::client_db::get_contact_by_device_id(&proposal.counterparty_device_id) {
        Ok(Some(c)) if c.genesis_hash.as_slice() == release.recipient_genesis.as_slice() => {}
        Ok(Some(..)) | Ok(None) => {
            let reason =
                "recipient economic release names a genesis that is not the pinned contact's"
                    .to_string();
            park_awaiting_valid_reply(&proposal, &short, &reason);
            return CountersignOutcome::Rejected(reason);
        }
        Err(e) => {
            return CountersignOutcome::Unverifiable(format!("contact lookup failed: {e}"));
        }
    }
    match crate::sdk::economic_admission_flow::verify_release_against_register(&release).await {
        Ok(()) => {}
        Err(crate::sdk::economic_admission_flow::ReleaseRegisterCheck::Unavailable(m)) => {
            // An outage is never an attack: gate retained, retried next poll.
            log::warn!(
                "[storage.sync] ADR 0003 countersign delta {short}..: release register read \
                 unavailable ({m}) — finalize deferred"
            );
            return CountersignOutcome::Unverifiable(format!("release register read: {m}"));
        }
        Err(crate::sdk::economic_admission_flow::ReleaseRegisterCheck::Mismatch(m)) => {
            let reason = format!("release does not match the registered economic root: {m}");
            park_awaiting_valid_reply(&proposal, &short, &reason);
            return CountersignOutcome::Rejected(reason);
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

    // Pre-tx sanity on the peer's canonical head: the delta's `b_parent_tip`
    // must be the head this sender pins for the recipient (the genesis seed
    // when nothing has been learned yet). A mismatch means the recipient
    // applied this step under a lineage this sender does not know — the
    // artifact proves nothing for THIS relationship state; park it. The
    // in-tx CAS below stays authoritative for the race.
    let genesis_seed = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
        &self_device_id,
        &proposal.counterparty_device_id,
    );
    match crate::storage::client_db::load_counterparty_canonical_head(&proposal.relationship_key) {
        Ok(pinned) => {
            let pinned = pinned.unwrap_or(genesis_seed);
            if pinned != bound.b_parent_tip {
                let reason = format!(
                    "peer canonical head mismatch: delta parent {}.. but this sender pins {}..",
                    crate::util::text_id::encode_base32_crockford(&bound.b_parent_tip[..4]),
                    crate::util::text_id::encode_base32_crockford(&pinned[..4]),
                );
                park_awaiting_valid_reply(&proposal, &short, &reason);
                return CountersignOutcome::Rejected(reason);
            }
        }
        Err(e) => {
            log::error!(
                "[storage.sync] §16.6 could not read the peer canonical head for {short}.. — \
                 refusing to finalize (retry from the durable outbox): {e}"
            );
            return CountersignOutcome::FinalizeFailed(format!("peer canonical head read: {e}"));
        }
    }

    let content_digest = evidence_content_digest(ArtifactRole::CountersignB, &delta.body);
    let countersign_artifact = SenderOutboxArtifact {
        relationship_key: proposal.relationship_key,
        canonical_parent: proposal.canonical_parent,
        proposal_nonce: proposal.nonce_hash,
        role: ArtifactRole::CountersignB,
        submission_id: derive_artifact_submission_id(&content_digest),
        envelope_bytes: delta.envelope_bytes.clone(),
        content_digest,
        routing_address: None,
    };

    // ====================================================================
    // FINALITY CERTIFICATE (finality barrier). Built and signed HERE, before
    // the finalize transaction, with the PENDING A per-step EK for this
    // commitment — the key the recipient chained `ek_pk_a` for and will verify
    // under (its journal's `new_counterparty_a_head`). The transaction below
    // promotes and deletes that pending row, so the signer must be read first.
    // The exact envelope bytes are frozen with their own route (the recipient's,
    // at the projection target it converged to); the checkpoint sweep replays
    // them until quorum, and only THEN is the sender's gate released.
    // ====================================================================
    let finalized_artifact = match build_relationship_finalized_artifact(
        &proposal,
        &self_device_id,
        bound.b_pair(),
        &receipt.ek_pk_a,
    ) {
        Ok(a) => a,
        Err(e) => {
            log::error!(
                "[storage.sync] finality certificate for {short}.. could not be built — \
                 refusing to finalize (retry from the durable outbox): {e}"
            );
            return CountersignOutcome::FinalizeFailed(format!("finality certificate: {e}"));
        }
    };

    // Both signers' EK step objects for THIS step (3.5b PR4) — byte-identical
    // to the recipient's derivation (same deterministic inputs), so both
    // devices' tracking tables converge on the same content addresses. The
    // recipient freezes and publishes the objects with its admission; the
    // sender only needs the rows.
    let ek_steps = {
        use prost::Message as _;
        let a_prior = match crate::storage::client_db::economic_lineage::latest_ek_step(
            &proposal.relationship_key,
            &self_device_id,
        ) {
            Ok(v) => v.map(|(_, addr, _)| addr),
            Err(e) => {
                return CountersignOutcome::FinalizeFailed(format!("ek step chain (A): {e}"));
            }
        };
        let b_prior = match crate::storage::client_db::economic_lineage::latest_ek_step(
            &proposal.relationship_key,
            &proposal.counterparty_device_id,
        ) {
            Ok(v) => v.map(|(_, addr, _)| addr),
            Err(e) => {
                return CountersignOutcome::FinalizeFailed(format!("ek step chain (B): {e}"));
            }
        };
        let a_step_bytes = dsm::types::proto::EkCertStepV1 {
            ek_pk: receipt.ek_pk_a.clone(),
            ek_cert: receipt.ek_cert_a.clone(),
            h_n: receipt.parent_tip.to_vec(),
            prior_step_addr: a_prior.map(|a| a.to_vec()),
        }
        .encode_to_vec();
        let b_step_bytes = dsm::types::proto::EkCertStepV1 {
            ek_pk: receipt.ek_pk_b.clone(),
            ek_cert: receipt.ek_cert_b.clone(),
            h_n: receipt.parent_tip.to_vec(),
            prior_step_addr: b_prior.map(|a| a.to_vec()),
        }
        .encode_to_vec();
        vec![
            (
                self_device_id,
                dsm::economic::peer_acceptance::ek_cert_step_addr(&a_step_bytes),
                receipt.ek_pk_a.clone(),
                a_step_bytes,
            ),
            (
                proposal.counterparty_device_id,
                dsm::economic::peer_acceptance::ek_cert_step_addr(&b_step_bytes),
                receipt.ek_pk_b.clone(),
                b_step_bytes,
            ),
        ]
    };

    match crate::storage::client_db::finalize_on_acceptance_atomically(
        &crate::storage::client_db::AcceptanceFinalization {
            relationship_key: &proposal.relationship_key,
            canonical_parent: &proposal.canonical_parent,
            proposal_nonce: &proposal.nonce_hash,
            commitment: &proposal.commitment,
            counterparty_device_id: &proposal.counterparty_device_id,
            projection_parent: &proposal.projection_parent,
            projection_target: &proposal.projection_target,
            expected_counterparty_head: expected_counterparty_head.as_deref(),
            new_counterparty_head: &receipt.ek_pk_b,
            peer_pair: bound.b_pair(),
            genesis_seed,
            countersign_b: &countersign_artifact,
            finalized: &finalized_artifact,
            ek_steps: &ek_steps,
        },
    ) {
        Ok(()) => {
            log::info!(
                "[storage.sync] §16.6 FINALIZED atomically on acceptance proof: \
                 commitment={short}.. tx={} (tip advanced, both cert heads promoted, peer \
                 head pinned, certificate frozen, outbox finalization_checkpoint_pending; \
                 gate retained until the checkpoint reaches quorum)",
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

/// Build and sign the `RelationshipFinalizedV1` for a verified acceptance,
/// frozen as an outbox artifact with its own route. PURE apart from DB reads:
/// the pending A EK (signer), the recipient's genesis (route), the local
/// genesis (envelope headers). Refuses if the pending EK's public key is not
/// the `ek_pk_a` the recipient chained — that is the key it will verify under.
fn build_relationship_finalized_artifact(
    proposal: &crate::storage::client_db::sender_proposal::SenderOnlineProposal,
    self_device_id: &[u8; 32],
    b_pair: ([u8; 32], [u8; 32]),
    receipt_ek_pk_a: &[u8],
) -> Result<crate::storage::client_db::SenderOutboxArtifact, String> {
    use crate::storage::client_db::sender_outbox::{
        derive_artifact_submission_id, evidence_content_digest, ArtifactRole, SenderOutboxArtifact,
    };
    use prost::Message;

    let wrap_key = crate::init::current_chain_head_at_rest_key()
        .map_err(|e| format!("chain-head key unavailable (wallet locked?): {e}"))?;
    let (ek_pk_a, ek_sk_a) = crate::storage::client_db::pending_local_head_signer(
        &proposal.relationship_key,
        &proposal.commitment,
        &wrap_key,
    )
    .map_err(|e| format!("pending Local EK head read: {e}"))?
    .ok_or_else(|| "no pending Local EK head for this commitment".to_string())?;
    if ek_pk_a != receipt_ek_pk_a {
        return Err(
            "pending Local EK head is not the ek_pk_a the recipient chained — refusing to sign \
             a certificate the recipient could not verify"
                .to_string(),
        );
    }
    let mut cert = dsm::types::proto::RelationshipFinalizedV1 {
        relationship_key: proposal.relationship_key.to_vec(),
        transition_commitment: proposal.commitment.to_vec(),
        sender_device_id: self_device_id.to_vec(),
        recipient_device_id: proposal.counterparty_device_id.to_vec(),
        sender_child_tip_a: proposal.canonical_child.to_vec(),
        recipient_parent_tip_b: b_pair.0.to_vec(),
        recipient_child_tip_b: b_pair.1.to_vec(),
        signature_a: Vec::new(),
    };
    let target = dsm::types::receipt_types::relationship_finalized_signing_target(&cert);
    cert.signature_a = dsm::crypto::sphincs::sphincs_sign(&ek_sk_a, &target)
        .map_err(|e| format!("certificate signing: {e}"))?;
    let wire = cert.encode_to_vec();
    // Self-check through the strict codec the recipient will apply.
    dsm::types::receipt_types::decode_relationship_finalized_wire(&wire)
        .map_err(|e| format!("certificate fails its own wire codec: {e}"))?;

    let content_digest = evidence_content_digest(ArtifactRole::RelationshipFinalized, &wire);
    let submission_id = derive_artifact_submission_id(&content_digest);

    // Frozen route: the recipient polls at the tip it converged to — the
    // proposal's projection target — under ITS genesis and device.
    let recipient_genesis: [u8; 32] =
        match crate::storage::client_db::get_contact_by_device_id(&proposal.counterparty_device_id)
        {
            Ok(Some(c)) => c
                .genesis_hash
                .as_slice()
                .try_into()
                .map_err(|_| "recipient contact genesis is not 32 bytes".to_string())?,
            Ok(None) => return Err("no contact for the recipient".to_string()),
            Err(e) => return Err(format!("recipient contact lookup: {e}")),
        };
    let route = crate::sdk::b0x_sdk::B0xSDK::compute_b0x_address(
        &recipient_genesis,
        &proposal.counterparty_device_id,
        &proposal.projection_target,
    )
    .map_err(|e| format!("certificate route: {e}"))?;
    let local_genesis: [u8; 32] = crate::sdk::app_state::AppState::get_genesis_hash()
        .and_then(|g| <[u8; 32]>::try_from(g.as_slice()).ok())
        .ok_or_else(|| "local genesis unavailable".to_string())?;
    let built = crate::sdk::b0x_sdk::B0xSDK::build_relationship_finalized_envelope(
        self_device_id,
        &local_genesis,
        &wire,
        &content_digest,
        &submission_id,
    )
    .map_err(|e| format!("certificate envelope: {e}"))?;
    // DSM Amendment A7: the spool carries it sealed to the recipient, sealed
    // once here and kept, so every delivery sends the same bytes.
    crate::sdk::b0x_sdk::seal_for(
        &proposal.counterparty_device_id,
        &submission_id,
        &built.bytes,
    )
    .map_err(|e| format!("certificate seal: {e}"))?;

    Ok(SenderOutboxArtifact {
        relationship_key: proposal.relationship_key,
        canonical_parent: proposal.canonical_parent,
        proposal_nonce: proposal.nonce_hash,
        role: ArtifactRole::RelationshipFinalized,
        submission_id,
        envelope_bytes: built.bytes,
        content_digest,
        routing_address: Some(route),
    })
}

/// Finality-barrier checkpoint sweep: replay every frozen
/// `RelationshipFinalizedV1` whose outbox row is `finalization_checkpoint_pending`
/// under its own frozen route and deterministic id until it reaches storage
/// quorum, then — the ONE deleter — release the sender's gate and move the row
/// to `gc_pending` in one transaction. Failure leaves the row for the next
/// sweep; nothing is rebuilt.
async fn deliver_pending_finalization_checkpoints(
    storage_endpoints: &[String],
    core_sdk: std::sync::Arc<crate::sdk::core_sdk::CoreSDK>,
) -> Result<u32, String> {
    use crate::storage::client_db::{
        finalization_checkpoint_pending_sender_outbox, get_sender_proposal_by_commitment,
        load_sender_outbox_artifacts, release_gate_on_finalization_checkpoint_atomically,
        ArtifactRole,
    };

    let rows = finalization_checkpoint_pending_sender_outbox().map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Ok(0);
    }
    let local_device_b32 = match crate::sdk::app_state::AppState::get_device_id() {
        Some(d) if d.len() == 32 => crate::util::text_id::encode_base32_crockford(&d),
        _ => return Err("local device_id unavailable for the checkpoint sweep".to_string()),
    };
    let mut b0x =
        crate::sdk::b0x_sdk::B0xSDK::new(local_device_b32, core_sdk, storage_endpoints.to_vec())
            .map_err(|e| format!("B0xSDK init: {e}"))?;
    let retry = crate::sdk::b0x_sdk::B0xRetryConfig::default();

    let mut released = 0u32;
    for row in rows {
        let artifacts = match load_sender_outbox_artifacts(
            &row.relationship_key,
            &row.canonical_parent,
            &row.proposal_nonce,
        ) {
            Ok(a) => a,
            Err(e) => {
                log::warn!(
                    "[storage.sync] checkpoint sweep: {} artifacts unreadable; retry next sweep: {e}",
                    row.submission_id
                );
                continue;
            }
        };
        let Some(checkpoint) = artifacts
            .into_iter()
            .find(|a| a.role == ArtifactRole::RelationshipFinalized)
        else {
            log::error!(
                "[storage.sync] checkpoint sweep: {} is finalization_checkpoint_pending with NO \
                 frozen certificate — invariant violated; leaving for inspection",
                row.submission_id
            );
            continue;
        };
        let Some(route) = checkpoint.routing_address.as_deref() else {
            log::error!(
                "[storage.sync] checkpoint sweep: certificate {} has no frozen route — invariant \
                 violated; leaving for inspection",
                checkpoint.submission_id
            );
            continue;
        };
        let proposal = match get_sender_proposal_by_commitment(&row.commitment) {
            Ok(Some(p)) => p,
            Ok(None) => {
                log::error!(
                    "[storage.sync] checkpoint sweep: no proposal for {} — leaving for inspection",
                    row.submission_id
                );
                continue;
            }
            Err(e) => {
                log::warn!(
                    "[storage.sync] checkpoint sweep: proposal lookup for {} failed; retry next \
                     sweep: {e}",
                    row.submission_id
                );
                continue;
            }
        };
        match b0x
            .submit_stored_envelope_with_retry(route, &checkpoint.submission_id, &retry)
            .await
        {
            Ok(()) => {}
            Err(e) => {
                log::warn!(
                    "[storage.sync] checkpoint sweep: certificate {} below quorum (will retry): {e}",
                    checkpoint.submission_id
                );
                continue;
            }
        }
        match release_gate_on_finalization_checkpoint_atomically(
            &row.relationship_key,
            &row.canonical_parent,
            &row.proposal_nonce,
            &proposal.counterparty_device_id,
            &row.projection_parent,
            &row.projection_target,
        ) {
            Ok(true) => {
                released += 1;
                log::info!(
                    "[storage.sync] finality checkpoint {} at quorum — gate released, outbox gc_pending",
                    checkpoint.submission_id
                );
                emit_authoritative_wallet_refresh();
            }
            Ok(false) => {}
            Err(e) => log::error!(
                "[storage.sync] checkpoint sweep: release after quorum FAILED for {}: {e}",
                checkpoint.submission_id
            ),
        }
    }
    Ok(released)
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

        // The post-admission RELEASE (3.5b PR4): the sweep only sees promoted
        // rows, so a row carries its release by construction. A row without one
        // is a local defect — the sender refuses a bare delta — and stays
        // unmarked and visible rather than going out with an empty release.
        let Some(release_bytes) = reply.release_bytes.as_deref() else {
            log::error!(
                "[storage.sync] §16.6 reply for commitment {}.. has no post-admission release — \
                 local defect, left unmarked",
                crate::util::text_id::encode_base32_crockford(&reply.commitment[..4]),
            );
            continue;
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
                (reply.applied_parent_tip_b, reply.applied_child_tip_b),
                release_bytes,
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
                    "[storage.sync] §16.6 reply for commitment {}.. could not be built from the \
                     stored receipt ({} bytes) — local defect, left unmarked: {e}",
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

            // Only the INITIAL-send artifacts are replayed here (the A-side
            // evidence). The finality certificate has its own frozen route and
            // sweep; a received delta is never re-sent. An unsettled row cannot
            // hold either yet, but the resubmit sweep can race a finalize — so
            // it must never see non-initial roles.
            let artifacts: Vec<_> = match load_sender_outbox_artifacts(
                &row.relationship_key,
                &row.canonical_parent,
                &row.proposal_nonce,
            ) {
                Ok(a) => a
                    .into_iter()
                    .filter(|a| a.role.is_initial_send_artifact())
                    .collect(),
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
                        if let Err(e) = bind_sender_outbox_message_ids(
                            &row.relationship_key,
                            &row.canonical_parent,
                            &row.proposal_nonce,
                            &row.submission_id,
                        ) {
                            log::warn!(
                                "[storage.sync] outbox resubmit: {} message-id bind failed \
                                 (spool cleanup metadata only): {e}",
                                row.submission_id
                            );
                        }
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

    /// ADR 0003 — drive every staged pair still in flight.
    ///
    /// Selection is `pairs_in_flight()`, read from the store every poll, so a
    /// process that died anywhere between binding and release is driven forward
    /// by what the store durably holds. A BOUND pair goes through the acceptance
    /// sequence, unchanged in order:
    ///
    ///   PREPARE (persist the exact B countersignature, BEFORE apply)
    ///   → APPLY (one atomic full-state tx, lookup-before-execute; the pair is
    ///     marked accepted inside that transaction)
    ///   → CONVERGE (projection sync, CAS both heads, enqueue reply)
    ///   → FINISH the economic admission
    ///
    /// PREPARE runs INSIDE the apply closure, so it is guaranteed to precede
    /// apply; `recover_incomplete_acceptances` iterates journals only.
    ///
    /// Every ACCEPTED pair — accepted in this pass or an earlier one — is then
    /// finished: its history row is written from the verified operation if it
    /// is not there yet, and the observed id of every copy of both halves is
    /// returned to be marked consumed. The pair is released only once those
    /// markers land.
    ///
    /// Returns the `(address, message_id)` pairs to mark consumed, the pairs to
    /// release once they are, and every failure the pass met.
    pub(crate) async fn complete_staged_pairs(
        &self,
    ) -> (
        Vec<(String, String)>,
        Vec<crate::storage::client_db::recipient_staging::StagedPair>,
        Vec<String>,
    ) {
        use crate::handlers::recipient_accept::{accept_bound_pair, verified_pair};
        use crate::handlers::recipient_receipt as rr;
        use crate::storage::client_db::recipient_staging::{self, PairState, StagedPair};

        let mut consumed: Vec<(String, String)> = Vec::new();
        let mut release: Vec<StagedPair> = Vec::new();
        let mut failures: Vec<String> = Vec::new();

        let pairs = match recipient_staging::pairs_in_flight() {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("split-transfer staging is unreadable: {e}"));
                return (consumed, release, failures);
            }
        };
        if pairs.is_empty() {
            return (consumed, release, failures);
        }

        let self_device = match crate::handlers::recipient_dispatch::this_device() {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("split-transfer completion: {e}"));
                return (consumed, release, failures);
            }
        };
        let self_device_b32 = crate::util::text_id::encode_base32_crockford(&self_device);

        // ── Step 0 (3.5b PR4): a pending economic admission is DEVICE-global
        // — resume it before any pair. Still pending afterwards means our own
        // quorum is unreachable; every apply would be fenced, so hold the
        // whole pass (pairs stay bound, retried next poll).
        if let Some(pending) = self
            .core_sdk
            .device_head()
            .and_then(|h| h.pending_economic_admission().cloned())
        {
            let resumed = match crate::sdk::economic_admission_flow::committed_network_id() {
                Ok(net) => crate::sdk::economic_admission_flow::resume_pending_admission(
                    &self.core_sdk,
                    &net,
                    pending,
                )
                .await
                .map(|_| ()),
                Err(e) => Err(e),
            };
            if let Err(e) = resumed {
                failures.push(format!(
                    "a pending economic admission could not be finished ({e}); every pair is \
                     held for resume"
                ));
                return (consumed, release, failures);
            }
        }

        for mut pair in pairs {
            // Everything below reads the pair's meaning from the staged
            // signed material, re-derived now — never from a copy's wrapper.
            let v = match verified_pair(&pair) {
                Ok(v) => v,
                Err(e) => {
                    failures.push(format!("split transfer: {e}"));
                    continue;
                }
            };
            let name = v.transfer_name();
            let sender_device: [u8; 32] = v.sender;
            let sender_b32 = crate::util::text_id::encode_base32_crockford(&sender_device);
            let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                &sender_device,
                &self_device,
            );

            if pair.state == PairState::Bound {
                // FINALITY BARRIER — reordering hold. A next-generation transfer
                // may be TRANSPORTED before this device has processed the
                // sender's certificate for the predecessor it applied, but it
                // may not be canonically APPLIED until then: while any accepted
                // journal on this relationship still has `peer_finalized = 0`,
                // the pair stays bound (no apply, nothing consumed; its routes
                // stay polled). This pass re-runs every poll and certificates
                // are drained BEFORE it, so once the certificate lands the same
                // pair proceeds through the normal pin.
                match crate::storage::client_db::relationship_awaits_peer_finalization(&rel_key) {
                    Ok(awaiting) => {
                        if awaiting {
                            log::info!(
                                "[storage.sync] ADR 0003 completion: {name} HELD — a prior \
                                 acceptance on this relationship awaits the peer's finality \
                                 certificate"
                            );
                            continue;
                        }
                    }
                    Err(e) => {
                        failures.push(format!("split transfer {name}: barrier read failed: {e}"));
                        continue;
                    }
                }

                let sender_ak = match resolve_trusted_sender_ak(&sender_b32) {
                    Ok(k) => k,
                    Err(e) => {
                        failures.push(format!("split transfer {name}: {e}"));
                        continue;
                    }
                };
                let (ak_pk, ak_sk) = match self.wallet.ak_keypair_for_cert_chain() {
                    Ok(p) => p,
                    Err(e) => {
                        failures.push(format!(
                            "split transfer {name}: AK keypair unavailable: {e}"
                        ));
                        continue;
                    }
                };
                let (sender_kyber_pk, sender_genesis) =
                    match crate::storage::client_db::get_contact_by_device_id(&sender_device) {
                        Ok(Some(c)) => {
                            let genesis: [u8; 32] = match c.genesis_hash.as_slice().try_into() {
                                Ok(g) => g,
                                Err(e) => {
                                    failures.push(format!(
                                        "split transfer {name}: the sender contact's genesis is \
                                         not 32 bytes: {e}"
                                    ));
                                    continue;
                                }
                            };
                            (c.kyber_public_key.clone(), genesis)
                        }
                        Ok(None) => {
                            failures.push(format!(
                                "split transfer {name}: the sender is no longer a contact"
                            ));
                            continue;
                        }
                        Err(e) => {
                            failures.push(format!(
                                "split transfer {name}: sender contact unreadable: {e}"
                            ));
                            continue;
                        }
                    };

                // ── IN HAND, BEFORE ANY READ (MR-DSM-0029, G13) ──────────────
                // The token's committed policy is state this device holds, so a
                // transfer the policy does not permit is refused here, before
                // prevalidation reads the sender's register. The apply checks it
                // again, under the state-machine lock.
                if let Err(e) = self.core_sdk.enforce_policy_for_operation(&v.signed_op) {
                    failures.push(format!("split transfer {name}: {e}"));
                    continue;
                }

                // ── PREVALIDATION (3.5b PR4, corrections 3+5+8): every foreign
                // dependency that CAN be established before local acceptance IS
                // established here — the sender's validated debit, the binding
                // of the signed bytes to it, EK portability, and the Stored
                // evidence closure — async, BEFORE the relationship lock,
                // before any durable econ state. The debit is located by the
                // hints the copies carried; a hint that does not resolve is not
                // a verdict on the transfer, and another copy's hint may.
                let hints = match recipient_staging::locator_hints(&pair.op_id) {
                    Ok(h) => h,
                    Err(e) => {
                        failures.push(format!("split transfer {name}: locator hints: {e}"));
                        continue;
                    }
                };
                let mut resolved = None;
                for hint in hints {
                    let incoming = crate::sdk::economic_admission_flow::IncomingTransfer {
                        canonical_operation_bytes: &v.canonical_operation_bytes,
                        signature: &v.signature,
                        hint,
                        evidence_bytes: &v.evidence_bytes,
                    };
                    match crate::sdk::economic_admission_flow::prevalidate_incoming_transfer_admission(
                        &self.core_sdk,
                        &sender_genesis,
                        &sender_device,
                        &sender_ak,
                        &incoming,
                        &rel_key,
                    )
                    .await
                    {
                        Ok(p) => {
                            resolved = Some((p, hint));
                            break;
                        }
                        Err(refusal) => {
                            use crate::sdk::economic_admission_flow::PrevalidationRefusal as PR;
                            match &refusal {
                                PR::Terminal(m) | PR::Quarantined(m) => log::warn!(
                                    "[storage.sync] ADR 0003 completion: {name} not admissible \
                                     at locator {hint:?} — economic prevalidation: {m}"
                                ),
                                PR::Incomplete(m) => log::info!(
                                    "[storage.sync] ADR 0003 completion: {name} held at locator \
                                     {hint:?} — {m}"
                                ),
                            }
                        }
                    }
                }
                let Some((prereqs, admitted_hint)) = resolved else {
                    continue;
                };
                let wrap_key = match crate::init::current_chain_head_at_rest_key() {
                    Ok(k) => k,
                    Err(e) => {
                        failures.push(format!("split transfer {name}: wrap key unavailable: {e}"));
                        continue;
                    }
                };
                let core_sdk = self.core_sdk.clone();
                let (econ_genesis, econ_devid) = match core_sdk.device_head() {
                    Some(h) => (h.genesis_digest(), h.devid()),
                    None => {
                        failures.push(format!("split transfer {name}: no device head"));
                        continue;
                    }
                };
                let mut prereqs = prereqs;
                let econ_tree = std::cell::RefCell::new(std::mem::replace(
                    &mut prereqs.tree,
                    dsm::economic::tree::EconomicSmt::new(),
                ));
                let admission_build: std::cell::RefCell<
                    Option<crate::sdk::economic_admission_flow::RecipientAdmissionBuild>,
                > = std::cell::RefCell::new(None);
                let signed_op_stash: std::cell::RefCell<Option<dsm::types::operations::Operation>> =
                    std::cell::RefCell::new(None);
                let mut accepted_admission: Option<
                    dsm::economic::admission::PendingEconomicAdmission,
                > = None;

                // Relationship exclusion across prepare → apply → converge.
                let rel_lock = rr::relationship_lock(&rel_key);
                let _rel_guard = rel_lock.lock_owned().await;

                let sender_b32_for_apply = sender_b32.clone();
                let decision = accept_bound_pair(&v, |v| {
                    // The verified transfer must be byte-identical to what
                    // prevalidation validated.
                    if v.canonical_operation_bytes != prereqs.pinned_canonical_bytes {
                        return Err(
                            "verified transfer differs from the prevalidated bytes".to_string()
                        );
                    }
                    // Everything derives from the VERIFIED transfer. The
                    // transition entropy is the receipt's canonical field 21 —
                    // the one value Core derived inside the sender's advance
                    // (Part VII step 3) — and it is what BOTH receipt hashes
                    // take here (§39.3); the transfer nonce stays inside the
                    // operation bytes (§39.4).
                    let signed_parent = v.receipt.parent_tip;
                    let signed_child = v.receipt.child_tip;
                    let transition_entropy = v.receipt.transition_entropy;
                    let signed_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                        &signed_parent,
                        &v.canonical_operation_bytes,
                        &transition_entropy,
                    );
                    let projection_parent: [u8; 32] =
                        crate::storage::client_db::get_contact_chain_tip(&sender_device)
                            .map_err(|e| {
                                format!("the sender's relationship tip is unreadable: {e}")
                            })?
                            .ok_or_else(|| "the sender is not a contact".to_string())?;
                    let projection_target: [u8; 32] = {
                        let sigma_sym = dsm::core::bilateral_transaction_manager::compute_precommit(
                            &projection_parent,
                            &v.canonical_operation_bytes,
                            &transition_entropy,
                        );
                        dsm::core::bilateral_transaction_manager::compute_successor_tip(
                            &projection_parent,
                            &v.canonical_operation_bytes,
                            &transition_entropy,
                            &sigma_sym,
                        )
                    };

                    // APPLY — the one production canonical apply, STAGED: the
                    // B artifacts are generated in the pre-write window from the
                    // exact AdvanceOutcome (its relationship pair is what sig_b
                    // authenticates); the journal, the EK steps and the pair's
                    // acceptance are written INSIDE the apply transaction with
                    // the nonce and the canonical record.
                    let tx_id = crate::types::identifiers::TransactionId::new(v.transfer_name());
                    let receipt = &v.receipt;
                    let op_id = v.pair.op_id;
                    core_sdk
                        .apply_incoming_transfer_staged(
                            v.signed_op.clone(),
                            &tx_id,
                            &sender_b32_for_apply,
                            &v.canonical_operation_bytes,
                            signed_parent,
                            signed_child,
                            transition_entropy,
                            |outcome, b_pair| {
                                let b_art = rr::generate_b_artifacts_from_inbound(
                                    receipt,
                                    &signed_sigma,
                                    &sender_kyber_pk,
                                    &ak_pk,
                                    &ak_sk,
                                    &wrap_key,
                                    b_pair,
                                )
                                .map_err(|e| {
                                    dsm::types::error::DsmError::invalid_operation(format!(
                                        "B-side acceptance artifacts: {e}"
                                    ))
                                })?;
                                // The recipient's admission, from the EXACT
                                // prepared successor: countersign wire bytes →
                                // EK steps → acceptance bundle → PeerDebit
                                // facts (the addr an OUTPUT) → witness/manifest
                                // → the signed release. All frozen with the
                                // accept transaction below.
                                let built =
                                    crate::sdk::economic_admission_flow::build_recipient_admission(
                                        &prereqs,
                                        &mut econ_tree.borrow_mut(),
                                        &econ_genesis,
                                        &econ_devid,
                                        &outcome.new_chain_state,
                                        &v.signed_op,
                                        &b_art,
                                        &crate::sdk::economic_admission_flow::IncomingTransfer {
                                            canonical_operation_bytes: &v.canonical_operation_bytes,
                                            signature: &v.signature,
                                            hint: admitted_hint,
                                            evidence_bytes: &v.evidence_bytes,
                                        },
                                        &rel_key,
                                    )?;
                                *admission_build.borrow_mut() = Some(built);
                                *signed_op_stash.borrow_mut() = Some(v.signed_op.clone());
                                Ok(b_art)
                            },
                            |tx, _outcome, artifacts| {
                                let build_ref = admission_build.borrow();
                                let built = build_ref.as_ref().ok_or_else(|| {
                                    dsm::types::error::DsmError::internal(
                                        "recipient admission missing at write",
                                        None::<std::convert::Infallible>,
                                    )
                                })?;
                                crate::storage::client_db::insert_prepared_acceptance_journal_with_conn(
                                    tx,
                                    &rr::journal_row(
                                        artifacts,
                                        rel_key,
                                        signed_parent,
                                        (projection_parent, projection_target),
                                        Some(built.release_bytes.clone()),
                                    ),
                                )
                                .map_err(|e| {
                                    dsm::types::error::DsmError::internal(
                                        format!("in-tx acceptance journal insert failed: {e}"),
                                        None::<std::convert::Infallible>,
                                    )
                                })?;
                                // The signer-chain steps become part of the SAME
                                // atomic acceptance — without them the NEXT
                                // acceptance bundle's ancestry is unwalkable.
                                for (signer, addr, pk) in &built.ek_step_rows {
                                    crate::storage::client_db::economic_lineage::append_ek_step_with_conn(
                                        tx, &rel_key, signer, addr, pk,
                                    )
                                    .map_err(|e| {
                                        dsm::types::error::DsmError::internal(
                                            format!("in-tx EK step append failed: {e}"),
                                            None::<std::convert::Infallible>,
                                        )
                                    })?;
                                }
                                // The pair is accepted in the SAME transaction:
                                // the apply and its acceptance commit together,
                                // so no crash leaves an applied pair unaccepted.
                                recipient_staging::mark_pair_accepted_with_conn(tx, &op_id)
                                    .map_err(|e| {
                                        dsm::types::error::DsmError::internal(
                                            format!("in-tx pair acceptance failed: {e}"),
                                            None::<std::convert::Infallible>,
                                        )
                                    })?;
                                // The sender's coordinate this acceptance
                                // verified is this device's frontier for it
                                // from now on (DSM Amendment A8), and so is
                                // each coordinate its credits' sources
                                // reached, every one at the end of a segment
                                // that passed whole: recorded with the
                                // acceptance and never before it.
                                for frontier in std::iter::once(&prereqs.sender_frontier)
                                    .chain(&prereqs.source_frontiers)
                                {
                                    crate::storage::client_db::economic_lineage::record_frontier_in_tx(
                                        tx, frontier,
                                    )
                                    .map_err(|e| {
                                        dsm::types::error::DsmError::internal(
                                            format!("in-tx peer frontier failed: {e}"),
                                            None::<std::convert::Infallible>,
                                        )
                                    })?;
                                }
                                Ok(())
                            },
                            Some(crate::sdk::core_sdk::AdmissionPlan {
                                prepared: prereqs.prepared.clone(),
                                storage_set_id: prereqs.set.id(),
                                build: Box::new(|_o| {
                                    let built = admission_build.borrow();
                                    let built = built.as_ref().ok_or_else(|| {
                                        dsm::types::error::DsmError::internal(
                                            "admission parts missing at commit",
                                            None::<std::convert::Infallible>,
                                        )
                                    })?;
                                    Ok((built.parts.coords, built.parts.artifacts.clone()))
                                }),
                                accepted_out: &mut accepted_admission,
                            }),
                        )
                        .map_err(|e| format!("apply failed: {e}"))
                });

                let acceptance = match decision {
                    Ok((acceptance, stored)) => {
                        pair = stored;
                        acceptance
                    }
                    Err(e) => {
                        failures.push(format!("split transfer {name}: {e}"));
                        continue;
                    }
                };
                log::info!("[storage.sync] ADR 0003 completion: {name} {acceptance:?}");
                // CONVERGE from durable state — tip sync, CAS both heads,
                // enqueue the B reply. Idempotent when already complete. On
                // failure the pair stays accepted and
                // `recover_incomplete_acceptances` converges it next poll from
                // the journal + apply record.
                let parent = v.receipt.parent_tip;
                let converged = match (
                    crate::storage::client_db::get_acceptance_journal(&rel_key, &parent),
                    crate::storage::client_db::get_canonical_apply_identity(&rel_key, &parent),
                ) {
                    (Ok(Some(journal)), Ok(Some(record))) => {
                        rr::converge_accepted_locked(&journal, &record, &wrap_key)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    }
                    (journal, record) => Err(format!(
                        "journal/apply-record missing after accept (journal {}, record {})",
                        presence(&journal),
                        presence(&record)
                    )),
                };
                if let Err(e) = converged {
                    log::warn!(
                        "[storage.sync] ADR 0003 completion: {name} accepted but convergence \
                         deferred: {e}"
                    );
                    if let Err(e) = mark_contact_needs_online_reconcile_and_refresh(&sender_device)
                    {
                        failures.push(e);
                    }
                    continue;
                }
                // ── FINISH the admission (3.5b PR4): publish → register →
                // validate → admit. Runs with the relationship lock still held
                // but needs no lock semantics of its own; the terminal admission
                // transaction promotes the HELD reply (the release) to
                // deliverable. On failure: accepted-but-held; the poll-level
                // resume (Step 0) finishes the SAME admission next pass.
                if let Some(pending) = accepted_admission.take() {
                    let built = admission_build.borrow_mut().take();
                    let signed_op = signed_op_stash.borrow_mut().take();
                    let (Some(built), Some(signed_op)) = (built, signed_op) else {
                        failures.push(format!(
                            "split transfer {name}: admission accepted with no build \
                             (invariant violated); held for resume"
                        ));
                        continue;
                    };
                    if let Err(e) = crate::sdk::economic_admission_flow::finish_admission(
                        &self.core_sdk,
                        &prereqs.network_id,
                        &prereqs.set,
                        &prereqs.validated,
                        built.parts.witness,
                        built.parts.manifest,
                        signed_op,
                        pending,
                        // The RELEASE object: frozen only in the admit
                        // transaction, published right after.
                        vec![(
                            crate::sdk::economic_registers::immutable_object_key(
                                dsm::common::domain_tags::TAG_DSM_RECIPIENT_ECONOMIC_RELEASE,
                                &built.release_bytes,
                            ),
                            built.release_bytes.clone(),
                            "recipient-economic-release",
                        )],
                    )
                    .await
                    {
                        log::warn!(
                            "[storage.sync] ADR 0003 completion: {name} accepted; economic \
                             admission HELD for resume ({e}) — release undelivered"
                        );
                        if let Err(e) =
                            mark_contact_needs_online_reconcile_and_refresh(&sender_device)
                        {
                            failures.push(e);
                        }
                        continue;
                    }
                }
            }

            // ACCEPTED — in this pass or an earlier one. The history row, from
            // the verified operation, before anything is released.
            if let Err(e) = ensure_received_history(&self.wallet, &v, &sender_b32, &self_device_b32)
            {
                failures.push(format!("split transfer {name} history: {e}"));
                continue;
            }
            match recipient_staging::observed_ids_of_pair(&pair) {
                Ok(ids) => consumed.extend(ids),
                Err(e) => {
                    failures.push(format!(
                        "split transfer {name}: observations unreadable: {e}"
                    ));
                    continue;
                }
            }
            release.push(pair);
        }

        (consumed, release, failures)
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

        let env = super::response_helpers::decode_local_envelope(&result.data)
            .map_err(|e| format!("storage.sync answer: {e}"))?;
        match env.payload {
            Some(generated::envelope::Payload::StorageSyncResponse(resp)) => Ok(resp),
            Some(generated::envelope::Payload::Error(err_payload)) => Err(err_payload.message),
            _ => Err("storage.sync returned unexpected payload".to_string()),
        }
    }

    /// Dispatch handler for the `storage.status` and `storage.sync` query routes.
    pub(crate) async fn handle_storage_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "storage.status" => {
                if let Err(e) = decode_proto_request::<generated::StorageStatusRequest>(
                    &q.params,
                    "storage.status",
                ) {
                    return err(e);
                }
                match storage_status().await {
                    Ok(resp) => {
                        pack_envelope_ok(generated::envelope::Payload::StorageStatusResponse(resp))
                    }
                    Err(e) => err(format!("storage.status: {e}")),
                }
            }

            // -------- storage.sync (QueryOp) --------
            "storage.sync" => {
                let request = match decode_storage_sync_request(&q.params) {
                    Ok(request) => request,
                    Err(e) => return err(e),
                };
                let response = match self.storage_sync(request).await {
                    Ok(report) => generated::StorageSyncResponse {
                        success: true,
                        pulled: report.pulled,
                        processed: report.processed,
                        pushed: report.pushed,
                        errors: report.errors,
                        more_pending: report.more_pending,
                    },
                    Err(failure) => generated::StorageSyncResponse {
                        success: false,
                        pulled: failure.report.pulled,
                        processed: failure.report.processed,
                        pushed: failure.report.pushed,
                        errors: failure.report.errors,
                        more_pending: failure.report.more_pending,
                    },
                };
                pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(response))
            }

            other => err(format!("unknown storage query: {other}")),
        }
    }
}

/// `StorageSyncRequest.limit` when the request leaves it 0 (the wire
/// contract's default): the most entries one sync reads from each route.
const STORAGE_SYNC_DEFAULT_LIMIT: usize = 100;
/// The largest per-route budget a request may ask for.
const STORAGE_SYNC_MAX_LIMIT: u32 = 200;

/// A decoded `storage.sync` request.
struct StorageSyncRequestV {
    pull_inbox: bool,
    push_pending: bool,
    limit: usize,
}

fn decode_storage_sync_request(params: &[u8]) -> Result<StorageSyncRequestV, String> {
    let pack = generated::ArgPack::decode(params)
        .map_err(|e| format!("storage.sync: decode ArgPack failed: {e}"))?;
    if pack.codec != generated::Codec::Proto as i32 {
        return Err("storage.sync: ArgPack.codec must be PROTO".to_string());
    }
    let request = generated::StorageSyncRequest::decode(&*pack.body)
        .map_err(|e| format!("storage.sync: decode StorageSyncRequest failed: {e}"))?;
    let limit = match request.limit {
        0 => STORAGE_SYNC_DEFAULT_LIMIT,
        n if n <= STORAGE_SYNC_MAX_LIMIT => n as usize,
        n => {
            return Err(format!(
                "storage.sync: limit {n} exceeds {STORAGE_SYNC_MAX_LIMIT}"
            ))
        }
    };
    Ok(StorageSyncRequestV {
        pull_inbox: request.pull_inbox,
        push_pending: request.push_pending,
        limit,
    })
}

/// What one sync did: items pulled from the spool, items processed to a
/// durable outcome (transfers completed, deltas finalized on, checkpoints
/// applied), objects pushed, and what failed along the way.
struct StorageSyncReport {
    pulled: u32,
    processed: u32,
    pushed: u32,
    errors: Vec<String>,
    /// Why the inbox read did not cover every delivery, if it did not: a
    /// route no member answered for, or one read from too few members. What
    /// was read is processed; the run is not complete (storage spec §4).
    inbox_incomplete: Option<String>,
    /// The routes whose budget this sync spent with entries still unread: a
    /// status, never an error. The next sync resumes each where it stopped.
    more_pending: Vec<String>,
}

/// A sync that could not run to its end, with what it did before it stopped.
struct StorageSyncFailure {
    report: StorageSyncReport,
}

impl StorageSyncReport {
    fn stop(mut self, why: String) -> StorageSyncFailure {
        self.errors.push(why);
        StorageSyncFailure { report: self }
    }
}

fn short_route(route: &str) -> &str {
    &route[..route.len().min(12)]
}

/// What the ingestion boundary made of one copy: ingested on a current route,
/// or classified on a previous-tip route.
enum StaleOrIngested {
    Ingested(crate::handlers::recipient_dispatch::IngestOutcome),
    Stale(crate::handlers::recipient_dispatch::StaleCopy),
}

/// Act on what the boundary made of one copy read at `address` under
/// `message_id`. A copy of an object the canonical apply has decided is
/// consumed, under the id the spool holds it by; a copy that is not recognized
/// is left unconsumed and recorded nowhere.
fn take_in_copy(
    copy: Result<StaleOrIngested, String>,
    address: &str,
    message_id: &str,
    consume_now: &mut std::collections::BTreeMap<String, Vec<String>>,
    report: &mut StorageSyncReport,
) {
    use crate::handlers::recipient_dispatch::{Ingested, StaleCopy};
    let ingested = match copy {
        Ok(StaleOrIngested::Ingested(outcome)) => {
            for unreadable in outcome.unreadable_candidates {
                report.errors.push(format!(
                    "a staged object could not be read back while ingesting {message_id}: \
                     {unreadable}"
                ));
            }
            for unbound in outcome.unbound {
                report.errors.push(match unbound {
                    crate::handlers::recipient_dispatch::Unbound::Refused(why) => {
                        format!("a receipt did not bind while ingesting {message_id}: {why}")
                    }
                    crate::handlers::recipient_dispatch::Unbound::Pending(why) => {
                        format!("a transfer waits while ingesting {message_id}: {why}")
                    }
                });
            }
            outcome.ingested
        }
        Ok(StaleOrIngested::Stale(StaleCopy::Decided)) => Ingested::Decided,
        Ok(StaleOrIngested::Stale(StaleCopy::Undecided)) => {
            log::info!(
                "[storage.sync] §5.2: previous-tip copy {message_id} is not decided; left in place"
            );
            return;
        }
        Ok(StaleOrIngested::Stale(StaleCopy::NotRecognized(why))) => Ingested::NotRecognized(why),
        Err(e) => {
            report.errors.push(format!(
                "copy {message_id} on {}..: {e}",
                short_route(address)
            ));
            return;
        }
    };
    match ingested {
        Ingested::Staged => {}
        Ingested::Decided => consume_now
            .entry(address.to_string())
            .or_default()
            .push(message_id.to_string()),
        // A copy on this route that is not a transfer or receipt this device
        // can take never will be: a route is one contact's, whose key this
        // device holds. Consumed on this device only (owner ruling,
        // 2026-10-01, pre-audit item 11: junk classified terminally is not
        // charged forever); the spool keeps it as raw material (Amendment
        // A1), and nothing is recorded about it beyond this device's read.
        Ingested::NotRecognized(why) => {
            log::info!(
                "[storage.sync] copy {message_id} on {}.. is not recognized: {why}",
                short_route(address)
            );
            consume_now
                .entry(address.to_string())
                .or_default()
                .push(message_id.to_string());
        }
    }
}

/// Whether a durable row was found, for a message: present, absent, or why it
/// could not be read.
fn presence<T, E: std::fmt::Display>(read: &Result<Option<T>, E>) -> String {
    match read {
        Ok(Some(_)) => "present".to_string(),
        Ok(None) => "absent".to_string(),
        Err(e) => format!("unreadable: {e}"),
    }
}

impl AppRouterImpl {
    /// One `storage.sync`: pull and process the inbox, then push what is
    /// owed. A completed run is counted.
    async fn storage_sync(
        &self,
        request: StorageSyncRequestV,
    ) -> Result<StorageSyncReport, StorageSyncFailure> {
        let mut report = StorageSyncReport {
            pulled: 0,
            processed: 0,
            pushed: 0,
            errors: Vec::new(),
            inbox_incomplete: None,
            more_pending: Vec::new(),
        };
        let storage_endpoints = match crate::sdk::storage_set::pinned_endpoints() {
            Ok(endpoints) => endpoints,
            Err(e) => return Err(report.stop(format!("no pinned storage set: {e}"))),
        };
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        if request.pull_inbox {
            report = self
                .pull_and_process_inbox(report, &storage_endpoints, &device_id_b32, request.limit)
                .await?;
        }
        if request.push_pending {
            self.push_owed(&mut report, &storage_endpoints, &device_id_b32)
                .await;
        }
        if let Some(why) = report.inbox_incomplete.take() {
            return Err(report.stop(why));
        }
        if let Err(e) = crate::storage::client_db::storage_sync_runs::record_completed() {
            return Err(report.stop(format!("could not count the completed sync: {e}")));
        }
        Ok(report)
    }

    /// Pull every rotated inbox route, process what arrived, and drive the
    /// durable completion passes that do not depend on this pull.
    ///
    /// `limit` is each route's budget (owner ruling, 2026-10-01, pre-audit
    /// item 11): a route reads at most `limit` entries per sync, and one
    /// whose budget runs out with entries left is reported `more_pending`, a
    /// status and not an error; the next sync resumes it. No route can spend
    /// another's budget, so junk on one route never keeps another unread. An
    /// entry classified terminally (a request that is not what its method
    /// names, or a copy this device can never take) is consumed on this
    /// device, so it is charged once and never again.
    async fn pull_and_process_inbox(
        &self,
        mut report: StorageSyncReport,
        storage_endpoints: &[String],
        device_id_b32: &str,
        limit: usize,
    ) -> Result<StorageSyncReport, StorageSyncFailure> {
        let mut b0x_sdk = match crate::sdk::b0x_sdk::B0xSDK::new(
            device_id_b32.to_string(),
            self.core_sdk.clone(),
            storage_endpoints.to_vec(),
        ) {
            Ok(sdk) => sdk,
            Err(e) => return Err(report.stop(format!("b0x init failed: {e}"))),
        };
        // §16.4: the per-contact rotated routes, tagged current or previous tip.
        let my_genesis = match self.core_sdk.local_genesis_hash().await {
            Ok(genesis) => match <[u8; 32]>::try_from(genesis.as_slice()) {
                Ok(genesis) => genesis,
                Err(e) => return Err(report.stop(format!("local genesis is not 32 bytes: {e}"))),
            },
            Err(e) => return Err(report.stop(format!("local genesis unavailable: {e}"))),
        };
        let contacts = match crate::storage::client_db::get_all_contacts() {
            Ok(contacts) => contacts,
            Err(e) => return Err(report.stop(format!("load contacts failed: {e}"))),
        };
        let tagged_addresses =
            match collect_tagged_inbox_addresses(my_genesis, self.device_id_bytes, &contacts) {
                Ok(addresses) => addresses,
                Err(e) => return Err(report.stop(e)),
            };

        // Copies whose object the canonical apply has already decided, by the
        // address and message id they were read under: consumed directly.
        let mut consume_now: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut pulled = 0usize;
        // Routes read to full coverage, routes read partially, and routes no
        // member answered for. Only the first kind says "nothing more there".
        let (mut routes_read, mut routes_partial, mut routes_unread) = (0usize, 0usize, 0usize);
        for tagged in tagged_addresses {
            let retrieved = b0x_sdk.retrieve_from_b0x_v2(&tagged.address).await;
            // Replies ride the same spool as forward transfers, as distinct
            // payloads; they are drained whether or not this route yielded
            // transfers, since a reply alone can release a pending gate.
            self.process_countersign_deltas(&mut b0x_sdk, &tagged.address, &mut report)
                .await;
            self.process_finality_checkpoints(&mut b0x_sdk, &tagged.address, &mut report)
                .await;
            // §5.2: the route fixes the tip an item was composed on — the
            // inbox address hashes the relationship's tip (storage node spec
            // §8). Every item on a previous-tip route steps from a tip this
            // device has already advanced past: nothing on it is staged. A copy
            // of an object the canonical apply has decided is consumed; any
            // other is left where it is.
            let stale = tagged.freshness == RouteFreshness::PreviousTip;
            for artifact in b0x_sdk.take_evidence_artifacts() {
                let copy = if stale {
                    crate::handlers::recipient_dispatch::classify_stale_receipt_copy(
                        &artifact.evidence.full_receipt_bytes,
                    )
                    .map(StaleOrIngested::Stale)
                } else {
                    crate::handlers::recipient_dispatch::ingest_evidence_half(
                        &artifact.evidence.full_receipt_bytes,
                        &tagged.address,
                        &artifact.message_id,
                    )
                    .map(StaleOrIngested::Ingested)
                };
                take_in_copy(
                    copy,
                    &tagged.address,
                    &artifact.message_id,
                    &mut consume_now,
                    &mut report,
                );
            }
            for (method, body) in b0x_sdk.take_cert_resync_messages() {
                let outcome = if method == crate::storage::client_db::CERT_RESYNC_REQUEST_METHOD {
                    self.handle_cert_resync_request(&body, storage_endpoints.to_vec())
                        .await
                } else {
                    self.handle_cert_resync_ack(&body).await
                };
                if let Err(e) = outcome {
                    report.errors.push(format!("cert resync {method}: {e}"));
                }
            }
            self.initiate_required_cert_resyncs(storage_endpoints, &mut report)
                .await;

            let polled = match retrieved {
                Ok(outcome) => {
                    if let crate::sdk::b0x_sdk::SpoolCoverage::Partial { responded, needed } =
                        outcome.coverage
                    {
                        routes_partial += 1;
                        report.errors.push(format!(
                            "inbox read partial on {}..: {responded} of {} members answered, \
                             {needed} needed to meet every delivery",
                            short_route(&tagged.address),
                            outcome.members
                        ));
                    } else {
                        routes_read += 1;
                    }
                    outcome.entries
                }
                Err(e) => {
                    routes_unread += 1;
                    report.errors.push(format!(
                        "inbox pull failed on {}..: {e}",
                        short_route(&tagged.address)
                    ));
                    continue;
                }
            };
            if polled.len() > limit {
                report
                    .more_pending
                    .push(format!("{}..", short_route(&tagged.address)));
            }
            for entry in polled.into_iter().take(limit) {
                pulled += 1;
                // Only transfers are the transfer pipeline's business; the
                // boundary reads every value-bearing field from the signed
                // operation it verifies itself. A request whose body is not
                // what its method names never will be: consumed here, so it
                // is not charged to this route's budget again.
                if entry.kind != crate::sdk::b0x_sdk::B0xEntryKind::Transfer {
                    consume_now
                        .entry(tagged.address.clone())
                        .or_default()
                        .push(entry.transaction_id.clone());
                    continue;
                }
                let copy = if stale {
                    crate::handlers::recipient_dispatch::classify_stale_transfer_copy(
                        &entry.transfer_wire_bytes,
                        &entry.sender_device_id,
                    )
                    .map(StaleOrIngested::Stale)
                } else {
                    crate::handlers::recipient_dispatch::ingest_transfer_half(
                        &entry.transfer_wire_bytes,
                        &entry.sender_device_id,
                        &entry.inbox_key,
                        &entry.transaction_id,
                    )
                    .map(StaleOrIngested::Ingested)
                };
                take_in_copy(
                    copy,
                    &entry.inbox_key,
                    &entry.transaction_id,
                    &mut consume_now,
                    &mut report,
                );
            }
        }
        // At most `limit` per route, which the request bounds by
        // STORAGE_SYNC_MAX_LIMIT, over the few routes this device's contacts
        // give it: far below u32::MAX.
        report.pulled = pulled as u32;
        for (route, ids) in consume_now {
            if let Err(e) = b0x_sdk.record_consumed_b0x(&route, ids).await {
                report.errors.push(format!(
                    "consume decided copies on {}..: {e}",
                    short_route(&route)
                ));
            }
        }

        self.complete_split_transfers(&mut b0x_sdk, &mut report)
            .await;

        // §16.6 on-access acceptance recovery, from the durable apply record.
        match crate::init::current_chain_head_at_rest_key() {
            Ok(wrap_key) => {
                if let Err(e) =
                    crate::handlers::recipient_receipt::recover_incomplete_acceptances(&wrap_key)
                        .await
                {
                    report.errors.push(format!("acceptance recovery: {e}"));
                }
            }
            Err(locked) => log::info!(
                "[storage.sync] §16.6 acceptance recovery waits for the wallet: {locked}"
            ),
        }
        // §16.6 reply window: every countersigned receipt persisted but not
        // yet delivered to its sender.
        if let Err(e) =
            deliver_pending_acceptance_replies(storage_endpoints, self.core_sdk.clone()).await
        {
            report
                .errors
                .push(format!("acceptance reply delivery: {e}"));
        }
        // §5.4: a row reaches gc_pending only once the recipient's verified
        // countersigned acceptance finalized it; nothing is asked of a node.
        match crate::storage::client_db::gc_pending_sender_outbox() {
            Ok(collectable) => {
                for row in &collectable {
                    if let Err(e) = crate::storage::client_db::set_sender_outbox_status(
                        &row.relationship_key,
                        &row.canonical_parent,
                        &row.proposal_nonce,
                        crate::storage::client_db::OUTBOX_COMPLETE,
                    ) {
                        report.errors.push(format!(
                            "outbox row {} not marked complete: {e}",
                            row.submission_id
                        ));
                    }
                }
            }
            Err(e) => report.errors.push(format!("outbox collection: {e}")),
        }
        if routes_partial > 0 || routes_unread > 0 {
            report.inbox_incomplete = Some(format!(
                "inbox read incomplete: {routes_read} route(s) fully read, {routes_partial} \
                 partially, {routes_unread} not at all; what was read is processed, and nothing \
                 unread is reported as absent"
            ));
        }
        Ok(report)
    }

    /// §16.6 sender finalization from the countersign deltas this poll
    /// decoded. A delta finalized on (now or earlier) is consumed.
    async fn process_countersign_deltas(
        &self,
        b0x_sdk: &mut crate::sdk::b0x_sdk::B0xSDK,
        route: &str,
        report: &mut StorageSyncReport,
    ) {
        let mut consumed = Vec::new();
        for delta in b0x_sdk.take_countersign_deltas() {
            let outcome = finalize_from_countersign_delta(&delta).await;
            log::info!(
                "[storage.sync] ADR 0003 countersign delta {} -> {:?}",
                delta.message_id,
                outcome
            );
            match outcome {
                CountersignOutcome::Finalized => {
                    report.processed += 1;
                    consumed.push(delta.message_id.clone());
                }
                CountersignOutcome::AlreadyFinalized => consumed.push(delta.message_id.clone()),
                other => report
                    .errors
                    .push(format!("countersign delta {}: {other:?}", delta.message_id)),
            }
        }
        if !consumed.is_empty() {
            if let Err(e) = b0x_sdk.record_consumed_b0x(route, consumed).await {
                report.errors.push(format!(
                    "consume countersign deltas on {}..: {e}",
                    short_route(route)
                ));
            }
        }
    }

    /// Finality certificates (the finality barrier), before split-transfer
    /// completion so a pair held behind one proceeds in the same pass.
    async fn process_finality_checkpoints(
        &self,
        b0x_sdk: &mut crate::sdk::b0x_sdk::B0xSDK,
        route: &str,
        report: &mut StorageSyncReport,
    ) {
        use crate::handlers::relationship_finalized::RelationshipFinalizedOutcome as O;
        let mut consumed = Vec::new();
        for checkpoint in b0x_sdk.take_relationship_finalized() {
            let outcome = crate::handlers::relationship_finalized::apply_relationship_finalized(
                &checkpoint.body,
            )
            .await;
            log::info!(
                "[storage.sync] finality checkpoint {} -> {:?}",
                checkpoint.message_id,
                outcome
            );
            match outcome {
                O::Applied => {
                    report.processed += 1;
                    consumed.push(checkpoint.message_id.clone());
                }
                O::AlreadyFinalized | O::NoJournal => consumed.push(checkpoint.message_id.clone()),
                other => report.errors.push(format!(
                    "finality checkpoint {}: {other:?}",
                    checkpoint.message_id
                )),
            }
        }
        if !consumed.is_empty() {
            if let Err(e) = b0x_sdk.record_consumed_b0x(route, consumed).await {
                report.errors.push(format!(
                    "consume finality checkpoints on {}..: {e}",
                    short_route(route)
                ));
            }
        }
    }

    /// Every relationship the send gate marked REQUIRED gets its resync
    /// request sent (which moves it to PENDING).
    async fn initiate_required_cert_resyncs(
        &self,
        storage_endpoints: &[String],
        report: &mut StorageSyncReport,
    ) {
        let relationships = match crate::storage::client_db::relationships_requiring_resync() {
            Ok(relationships) => relationships,
            Err(e) => {
                report.errors.push(format!("cert resync lookup: {e}"));
                return;
            }
        };
        for relationship in relationships {
            match crate::handlers::cert_resync_flow::peer_device_for_relationship(
                &self.device_id_bytes,
                &relationship,
            ) {
                Ok(Some(peer)) => {
                    if let Err(e) = self
                        .initiate_cert_resync(peer, storage_endpoints.to_vec())
                        .await
                    {
                        report.errors.push(format!("cert resync initiate: {e}"));
                    }
                }
                Ok(None) => report
                    .errors
                    .push("a relationship requiring resync has no resolvable peer".to_string()),
                Err(e) => report.errors.push(format!("cert resync peer lookup: {e}")),
            }
        }
    }

    /// ADR 0003 split-transfer completion, every sync, from the durable staged
    /// pairs. Every copy of both halves of an accepted pair is marked consumed
    /// under the id the spool holds it by, and the pair is released only once
    /// every marker of the pass landed.
    async fn complete_split_transfers(
        &self,
        b0x_sdk: &mut crate::sdk::b0x_sdk::B0xSDK,
        report: &mut StorageSyncReport,
    ) {
        let (observed, release, failures) = self.complete_staged_pairs().await;
        report.errors.extend(failures);
        let mut groups: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for (address, id) in observed {
            groups.entry(address).or_default().push(id);
        }
        let mut unconsumed = 0usize;
        for (address, ids) in groups {
            if let Err(e) = b0x_sdk.record_consumed_b0x(&address, ids).await {
                unconsumed += 1;
                report.errors.push(format!(
                    "ADR 0003 consume on {}.. failed (pairs kept): {e}",
                    short_route(&address)
                ));
            }
        }
        if unconsumed > 0 {
            return;
        }
        for pair in release {
            match crate::storage::client_db::recipient_staging::release_pair(&pair) {
                // Each released pair is one transfer this device finished.
                Ok(()) => report.processed += 1,
                Err(e) => report
                    .errors
                    .push(format!("ADR 0003 release of a finished pair failed: {e}")),
            }
        }
    }

    /// The liveness sweeps: resubmit uncertain sends, replay frozen
    /// certificates and publication artifacts, and finish an economic
    /// admission a crash stranded.
    async fn push_owed(
        &self,
        report: &mut StorageSyncReport,
        storage_endpoints: &[String],
        device_id_b32: &str,
    ) {
        match self
            .resubmit_unsettled_sender_outbox(device_id_b32, storage_endpoints)
            .await
        {
            Ok(n) => report.pushed += n,
            Err(e) => report
                .errors
                .push(format!("outbox resubmit sweep failed: {e}")),
        }
        match deliver_pending_finalization_checkpoints(storage_endpoints, self.core_sdk.clone())
            .await
        {
            Ok(n) => report.pushed += n,
            Err(e) => report.errors.push(format!("checkpoint sweep failed: {e}")),
        }
        match crate::handlers::artifact_republish::republish_unpublished_artifacts().await {
            Ok(n) => report.pushed += n,
            Err(e) => report
                .errors
                .push(format!("artifact republish sweep failed: {e}")),
        }
        if let Err(e) = crate::handlers::artifact_republish::continue_route_writes().await {
            report.errors.push(e);
        }
        // An admission the head already carried when this process restored
        // it; one created after startup belongs to the handler that created it.
        let stranded = self
            .core_sdk
            .device_head()
            .and_then(|head| head.pending_economic_admission().cloned())
            .filter(|pending| self.core_sdk.admission_predates_startup(pending));
        if let Some(pending) = stranded {
            let position = pending.economic_position;
            let resumed = match crate::sdk::economic_admission_flow::committed_network_id() {
                Ok(network) => {
                    crate::sdk::economic_admission_flow::resume_pending_admission(
                        &self.core_sdk,
                        &network,
                        pending,
                    )
                    .await
                }
                Err(e) => Err(e),
            };
            match resumed {
                Ok(..) => report.pushed += 1,
                Err(e) => report.errors.push(format!(
                    "stranded admission at position {position} not finished: {e}"
                )),
            }
        }
    }
}

/// Decode a proto request carried in a PROTO ArgPack.
fn decode_proto_request<M: Message + Default>(params: &[u8], route: &str) -> Result<M, String> {
    let pack = generated::ArgPack::decode(params)
        .map_err(|e| format!("{route}: decode ArgPack failed: {e}"))?;
    if pack.codec != generated::Codec::Proto as i32 {
        return Err(format!("{route}: ArgPack.codec must be PROTO"));
    }
    M::decode(&*pack.body).map_err(|e| format!("{route}: decode request failed: {e}"))
}

/// `storage.status`: the pinned set of this device's committed network, what
/// each member answered for its latest ByteCommit, and this device's own sync
/// count and database size. A member's answer is an observation, never a
/// verdict (storage spec §4).
async fn storage_status() -> Result<generated::StorageStatusResponse, String> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| format!("no committed network: {e}"))?;
    let set = crate::sdk::storage_set::canonical_set(&network)
        .map_err(|e| format!("no pinned storage set: {e}"))?;
    let client = crate::sdk::storage_node_sdk::SetClient::new(&set)
        .map_err(|e| format!("storage client: {e}"))?;
    let reads = futures::future::join_all(
        client
            .members()
            .iter()
            .map(|member| member.latest_bytecommit()),
    )
    .await;
    let members = set
        .members()
        .iter()
        .zip(reads)
        .map(|(member, read)| member_status(member, read))
        .collect();
    let completed_syncs = crate::storage::client_db::storage_sync_runs::completed()
        .map_err(|e| format!("sync count: {e}"))?;
    let database_bytes =
        crate::storage::client_db::get_db_size().map_err(|e| format!("database size: {e}"))?;
    Ok(generated::StorageStatusResponse {
        network_id: String::from_utf8(network)
            .map_err(|e| format!("the committed network id is not text: {e}"))?,
        storage_set_id: set.id().to_vec(),
        members,
        completed_syncs,
        database_bytes,
    })
}

/// One member of the pinned set and its answer, as `storage.status` reports
/// them.
fn member_status(
    member: &crate::sdk::storage_set::StorageMember,
    read: crate::sdk::storage_node_sdk::LatestByteCommitRead,
) -> generated::StorageMemberStatus {
    use crate::sdk::storage_node_sdk::LatestByteCommit;
    use generated::storage_member_status::Answer;
    let answer = match read.answer {
        LatestByteCommit::Stated(commit) => Answer::Latest(generated::StorageMemberByteCommit {
            digest: commit.digest().to_vec(),
            commit: Some(commit.to_proto()),
        }),
        LatestByteCommit::NoCycle => Answer::NoCycle(generated::StorageMemberNoCycle {}),
        LatestByteCommit::Unanswered(why) => Answer::Unanswered(why),
    };
    generated::StorageMemberStatus {
        member_id: member.member_id.as_bytes().to_vec(),
        register_incarnation_id: member.register_incarnation_id.to_vec(),
        endpoint: member.endpoint.clone(),
        answer: Some(answer),
        answered_as: read.answered_as,
    }
}

#[cfg(test)]
mod tests {
    use super::{finalize_from_countersign_delta, CountersignOutcome};
    use super::resolve_trusted_sender_ak;
    use crate::sdk::b0x_sdk::CountersignDelta;
    use crate::storage::client_db;
    use crate::storage::client_db::sender_proposal::{
        get_sender_proposal_by_commitment, PROPOSAL_AWAITING_VALID_REPLY, PROPOSAL_FINALIZED,
        PROPOSAL_SUBMITTED,
    };
    use crate::test_support::two_device::Pair;
    use prost::Message;

    // =====================================================================
    // TRUST ROOT (issue #656): an inbound half is verified against the key
    // the contact book holds for the contact it names, never a key the wire
    // carries — the wire carries none.
    // =====================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn the_sender_ak_is_the_one_the_contact_book_holds() {
        let p = Pair::boot(0, 0).await;
        p.b.enter();
        let a_b32 = crate::util::text_id::encode_base32_crockford(&p.a.device_id);
        assert_eq!(
            resolve_trusted_sender_ak(&a_b32).expect("the stored AK resolves"),
            p.a.ak_pk,
            "the key B stored for A"
        );
        let unknown = crate::util::text_id::encode_base32_crockford(&p.b.device_id);
        let err = resolve_trusted_sender_ak(&unknown)
            .expect_err("a sender with no stored AK fails closed");
        assert!(err.contains("no locally trusted sender AK"), "{err}");
    }

    // =====================================================================
    // SENDER FINALIZATION FROM A RECIPIENT'S DELTA (#658, R5, 3.5b PR4).
    //
    // Every step is a real send from A to B on the nodes. B's real delta is
    // read from the members exactly as A's poll reads it; hostile variants
    // are that delta with fields a middlebox or a malicious recipient can
    // change, handed to the handler A's poll hands deltas to. Receipt fields
    // 12-20 sit outside every signature and the delta's commitment is an
    // unsigned lookup reference, so each of these is a delta that arrives.
    // =====================================================================

    /// A sends `amount` to B and B applies and replies: B's delta for the
    /// step, read from the members, and the step's commitment.
    async fn step_with_reply(p: &Pair, amount: u64) -> (CountersignDelta, [u8; 32]) {
        let sent = p.a.send(&p.b, amount).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        let delta = crate::test_support::arrivals::arrivals_for(&p.a, &p.fleet)
            .await
            .deltas
            .pop()
            .expect("B's delta is on the members");
        let commitment: [u8; 32] = wire(&delta)
            .commitment
            .as_slice()
            .try_into()
            .expect("a 32-byte commitment");
        (delta, commitment)
    }

    fn wire(delta: &CountersignDelta) -> dsm::types::proto::ReceiptCountersignB {
        dsm::types::proto::ReceiptCountersignB::decode(delta.body.as_slice())
            .expect("the delta body")
    }

    /// `delta` with its body edited.
    fn tampered(
        delta: &CountersignDelta,
        edit: impl FnOnce(&mut dsm::types::proto::ReceiptCountersignB),
    ) -> CountersignDelta {
        let mut body = wire(delta);
        edit(&mut body);
        CountersignDelta {
            message_id: delta.message_id.clone(),
            envelope_bytes: delta.envelope_bytes.clone(),
            body: body.encode_to_vec(),
        }
    }

    fn status(commitment: &[u8; 32]) -> String {
        get_sender_proposal_by_commitment(commitment)
            .expect("load proposal")
            .expect("A holds the proposal")
            .status
    }

    /// A poisoned delta — B's countersignature over a DIFFERENT recipient
    /// pair (R5), or naming A bytes this sender never retained, or carrying
    /// no release — is refused and PARKS the step in a state it can leave;
    /// the honest delta for the same step then finalizes it, and a
    /// redelivered honest delta is an idempotent no-op.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_poisoned_delta_parks_the_step_and_the_honest_delta_still_finalizes() {
        let p = Pair::boot(100, 0).await;
        let (honest, commitment) = step_with_reply(&p, 10).await;
        p.a.enter();
        assert_eq!(status(&commitment), PROPOSAL_SUBMITTED);

        // R5: the recipient pair substituted — sig_b covers the pair it
        // signed, so it cannot verify over another.
        let substituted = tampered(&honest, |w| w.b_child_tip = w.b_parent_tip.clone());
        match finalize_from_countersign_delta(&substituted).await {
            CountersignOutcome::Rejected(reason) => {
                assert!(
                    reason.contains("sig_b"),
                    "refused on the countersignature: {reason}"
                )
            }
            other => panic!("a substituted pair must be Rejected, got {other:?}"),
        }
        assert_eq!(
            status(&commitment),
            PROPOSAL_AWAITING_VALID_REPLY,
            "a rejected artifact parks the step; it is not a rollback"
        );

        // A-bytes this sender never retained: refused before any signature
        // work.
        let foreign_digest = tampered(&honest, |w| {
            w.receipt_evidence_digest_a = dsm::crypto::blake3::domain_hash_bytes(
                dsm::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
                &w.commitment,
            )
            .to_vec()
        });
        assert!(matches!(
            finalize_from_countersign_delta(&foreign_digest).await,
            CountersignOutcome::DigestMismatch(..)
        ));
        assert_eq!(status(&commitment), PROPOSAL_AWAITING_VALID_REPLY);

        // sig_b is acceptance provenance only: a delta with no recipient
        // economic release cannot finalize the sender.
        let no_release = tampered(&honest, |w| w.recipient_economic_release_addr.clear());
        match finalize_from_countersign_delta(&no_release).await {
            CountersignOutcome::Rejected(reason) => {
                assert!(reason.contains("no recipient economic release"), "{reason}")
            }
            other => panic!("a delta without a release must be Rejected, got {other:?}"),
        }
        assert_eq!(status(&commitment), PROPOSAL_AWAITING_VALID_REPLY);

        // The honest delta for the SAME step finalizes it.
        assert_eq!(
            finalize_from_countersign_delta(&honest).await,
            CountersignOutcome::Finalized
        );
        assert_eq!(status(&commitment), PROPOSAL_FINALIZED);
        assert_eq!(
            client_db::get_sender_outbox_by_commitment(&commitment)
                .expect("outbox")
                .expect("present")
                .status,
            client_db::OUTBOX_FINALIZATION_CHECKPOINT_PENDING,
            "finalized locally; the certificate still has to reach quorum"
        );
        assert_eq!(
            finalize_from_countersign_delta(&honest).await,
            CountersignOutcome::AlreadyFinalized,
            "a redelivered honest delta is an idempotent no-op"
        );
    }

    /// A replayed release — B's real, signed release of an EARLIER step —
    /// carried in the delta of a later step is bound to a different
    /// transition and cannot finalize it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_release_of_another_step_cannot_finalize_this_one() {
        let p = Pair::boot(100, 0).await;
        let (first, first_commitment) = step_with_reply(&p, 10).await;
        p.a.enter();
        assert_eq!(
            finalize_from_countersign_delta(&first).await,
            CountersignOutcome::Finalized
        );
        assert_eq!(status(&first_commitment), PROPOSAL_FINALIZED);
        let shipped = p.a.sync().await;
        assert!(shipped.success, "{:?}", shipped.errors);
        let released = p.b.sync().await;
        assert!(released.success, "{:?}", released.errors);

        let (second, second_commitment) = step_with_reply(&p, 5).await;
        let old_release = wire(&first).recipient_economic_release_addr;
        let replayed = tampered(&second, |w| w.recipient_economic_release_addr = old_release);
        p.a.enter();
        match finalize_from_countersign_delta(&replayed).await {
            CountersignOutcome::Rejected(reason) => assert!(
                reason.contains("different transition"),
                "the release is bound to its own step: {reason}"
            ),
            other => panic!("a replayed release must be Rejected, got {other:?}"),
        }
        assert_eq!(status(&second_commitment), PROPOSAL_AWAITING_VALID_REPLY);
        assert_eq!(
            finalize_from_countersign_delta(&second).await,
            CountersignOutcome::Finalized
        );
    }

    /// A whole receipt carried on the countersign method is refused at the
    /// wire: the method's body is a `ReceiptCountersignB`, never a receipt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_full_receipt_on_the_countersign_method_is_refused_at_the_wire() {
        let p = Pair::boot(100, 0).await;
        let (honest, commitment) = step_with_reply(&p, 10).await;
        p.a.enter();
        let proposal = get_sender_proposal_by_commitment(&commitment)
            .expect("load")
            .expect("A holds the proposal");
        let full_receipt = crate::handlers::online_finalize::load_retained_evidence_a(&proposal)
            .expect("load")
            .expect("A retained its evidence")
            .full_receipt_bytes;
        let whole = CountersignDelta {
            message_id: honest.message_id.clone(),
            envelope_bytes: honest.envelope_bytes.clone(),
            body: full_receipt,
        };
        assert!(matches!(
            finalize_from_countersign_delta(&whole).await,
            CountersignOutcome::WireRejected(..)
        ));
        assert_eq!(status(&commitment), PROPOSAL_SUBMITTED, "nothing written");
    }

    /// A step whose frozen evidence_a is gone cannot finalize under any
    /// delta: a terminal invariant violation, reported as such, never a
    /// retry. The evidence goes the way it can go on a device — the row is
    /// lost from its database.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_delta_for_a_step_with_no_retained_evidence_is_a_terminal_invariant_violation() {
        let p = Pair::boot(100, 0).await;
        let (honest, commitment) = step_with_reply(&p, 10).await;
        p.a.enter();
        {
            let binding = client_db::get_connection().expect("conn");
            let conn = binding
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let removed = conn
                .execute(
                    "DELETE FROM sender_outbox_artifacts WHERE role = 'evidence_a'",
                    [],
                )
                .expect("lose the evidence row");
            assert_eq!(removed, 1, "the step had its evidence");
        }
        assert_eq!(
            finalize_from_countersign_delta(&honest).await,
            CountersignOutcome::NoRetainedEvidence
        );
        assert_eq!(status(&commitment), PROPOSAL_SUBMITTED);
    }

    /// A settled outbox row is never resubmitted: once the generation is
    /// final on both sides, further syncs put no new copy of the transfer on
    /// any member.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn settled_outbox_rows_are_never_resubmitted() {
        let p = Pair::boot(100, 0).await;
        let commitment = step_with_reply(&p, 10).await.1;
        let finalized = p.a.sync().await;
        assert!(finalized.success, "{:?}", finalized.errors);
        p.a.enter();
        assert_eq!(status(&commitment), PROPOSAL_FINALIZED);
        let transfer_id = client_db::get_sender_outbox_by_commitment(&commitment)
            .expect("outbox")
            .expect("present")
            .submission_id;
        let holders = p.holders_of(&transfer_id).await;
        let copies = |spools: Vec<Vec<crate::test_support::nodes::Spooled>>| {
            spools
                .iter()
                .flatten()
                .filter(|s| s.message_id.as_deref() == Some(transfer_id.as_str()))
                .count()
        };
        let mut before = Vec::new();
        for node in &p.nodes.nodes {
            before.push(node.spool().await);
        }
        let before = copies(before);

        for pass in 0..2 {
            let again = p.a.sync().await;
            assert!(again.success, "pass {pass}: {:?}", again.errors);
        }
        let mut after = Vec::new();
        for node in &p.nodes.nodes {
            after.push(node.spool().await);
        }
        assert_eq!(copies(after), before, "no resubmission");
        assert_eq!(p.holders_of(&transfer_id).await, holders);
    }

    /// `storage.status` through the router, as the app asks it.
    async fn storage_status_of(
        router: &crate::handlers::app_router_impl::AppRouterImpl,
    ) -> dsm::types::proto::StorageStatusResponse {
        let pack = dsm::types::proto::ArgPack {
            codec: dsm::types::proto::Codec::Proto as i32,
            body: dsm::types::proto::StorageStatusRequest {}.encode_to_vec(),
            ..Default::default()
        };
        let answer = router
            .handle_storage_query(crate::bridge::AppQuery {
                path: "storage.status".to_string(),
                params: pack.encode_to_vec(),
            })
            .await;
        assert!(answer.success, "storage.status: {:?}", answer.error_message);
        let env = crate::handlers::response_helpers::decode_local_envelope(&answer.data)
            .expect("a local envelope");
        match env.payload {
            Some(dsm::types::proto::envelope::Payload::StorageStatusResponse(status)) => status,
            other => panic!("storage.status answered {other:?}"),
        }
    }

    /// `storage.status` reports the set this device's traffic uses — its
    /// committed network's pinned set, by the id every provisioned member
    /// logged — and each member's own answer, as that member gave it: the
    /// ByteCommit it closed (with Core's digest of it), or its statement that
    /// it has closed none. A member that stops serving is reported as not
    /// answering, with the reason, while the others still answer. Real
    /// nodes, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn storage_status_reports_the_pinned_set_and_each_members_own_answer() {
        use dsm::types::proto::storage_member_status::Answer;

        let mut device = crate::test_support::one_device::Device::start(0x5A).await;
        let members = device.nodes.members();
        let first = members[0].0.clone();
        let closer = crate::sdk::storage_node_sdk::MemberClient::new(&first, &members[0].1)
            .expect("a client for the first member");
        closer
            .put_cells(&[(
                b"DSM/test/storage-status".to_vec(),
                [0x5A; 32],
                b"value".to_vec(),
            )])
            .await
            .expect("the entry is taken");
        let closed = closer.close_cycle().await.expect("the cycle closes");

        let status = storage_status_of(&device.router).await;
        let profile = dsm::economic::register::resolve_root_register_profile(b"dsm-testnet")
            .expect("the beta network is provisioned");
        assert_eq!(status.network_id, "dsm-testnet");
        assert_eq!(status.storage_set_id, profile.storage_set_id.to_vec());
        assert_eq!(status.members.len(), members.len());
        assert!(status.database_bytes > 0, "the device database exists");
        assert!(
            status
                .members
                .windows(2)
                .all(|w| w[0].member_id < w[1].member_id),
            "in the set's member order"
        );
        for reported in &status.members {
            let (member_id, endpoint, incarnation) = members
                .iter()
                .find(|(id, _, _)| id.as_bytes() == reported.member_id.as_slice())
                .expect("every reported member is a member of the set");
            assert_eq!(reported.endpoint, *endpoint);
            assert_eq!(reported.register_incarnation_id, incarnation.to_vec());
            assert_eq!(
                reported.answered_as.as_deref(),
                Some(member_id.as_bytes()),
                "{member_id} answered as itself"
            );
            match reported
                .answer
                .as_ref()
                .expect("every member has an answer")
            {
                Answer::Latest(latest) => {
                    let commit = dsm::storage_cell::ByteCommit::from_proto(
                        latest.commit.as_ref().expect("the ByteCommit"),
                    )
                    .expect("a ByteCommit");
                    assert_eq!(commit.member_id, member_id.as_bytes());
                    assert_eq!(latest.digest, commit.digest().to_vec(), "Core's digest");
                    if *member_id == first {
                        assert_eq!(commit.cycle_index, closed, "the cycle it closed");
                    }
                }
                Answer::NoCycle(_) => assert_ne!(
                    *member_id, first,
                    "the member that closed a cycle states its ByteCommit"
                ),
                Answer::Unanswered(why) => panic!("{member_id} did not answer: {why}"),
            }
        }

        let down = members[1].0.clone();
        device.nodes.take_down(std::slice::from_ref(&down)).await;
        let status = storage_status_of(&device.router).await;
        for reported in &status.members {
            let answer = reported
                .answer
                .as_ref()
                .expect("every member has an answer");
            if reported.member_id == down.as_bytes() {
                assert!(
                    matches!(answer, Answer::Unanswered(why) if why.starts_with("transport: ")),
                    "the member that stopped serving did not answer: {answer:?}"
                );
                assert_eq!(reported.answered_as, None, "no node answered for it");
            } else {
                assert!(
                    !matches!(answer, Answer::Unanswered(_)),
                    "the members still serving answer: {answer:?}"
                );
            }
        }
    }
}
