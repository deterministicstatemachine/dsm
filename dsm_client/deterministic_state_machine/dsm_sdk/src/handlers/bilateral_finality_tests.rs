// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral finality barrier — protocol tests over the two-device harness.
//!
//! Every test drives PRODUCTION code end to end: the real `wallet.send`, the
//! real `storage.sync` on each side, a dumb spooling fleet in between. See
//! `test_support::two_device` for the harness contract (strictly serialized;
//! one device active at a time — every assertion helper below reads the
//! database of whichever device is currently entered).
//!
//! # The R-tests
//!
//! Each `rN_…` test states one rule of the finality barrier and was written
//! RED before the commit that made it green (the named mutation turns it red
//! again): R1 role reversal, R2a/R2b the recipient gate and its release by
//! the certificate, R3 the sender gate until checkpoint quorum, R4 ACK ≠
//! release, R7 byte-identical checkpoint replay, R11 one deleter for the gate.
//! R5/R6 live beside the code they pin (`storage_routes` / `core_sdk`).

use crate::storage::client_db as cdb;
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::types::proto as generated;
use prost::Message;
use serial_test::serial;

/// `SELECT COUNT(*) FROM {table} WHERE relationship_key = ?` on the ENTERED
/// device's database.
fn rows_for_relationship(table: &str, rel: &[u8; 32]) -> i64 {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE relationship_key = ?1"),
        rusqlite::params![rel.as_slice()],
        |r| r.get::<_, i64>(0),
    )
    .expect("count")
}

/// Every sender proposal status for `rel` on the ENTERED device, in
/// insertion order.
fn proposal_statuses(rel: &[u8; 32]) -> Vec<String> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare(
            "SELECT status FROM sender_online_proposal WHERE relationship_key = ?1 ORDER BY rowid",
        )
        .expect("prepare");
    stmt.query_map(rusqlite::params![rel.as_slice()], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// Every sender proposal's canonical CHILD for `rel` on the ENTERED device,
/// in insertion order — the heads this device signed its sends under.
fn proposal_children(rel: &[u8; 32]) -> Vec<[u8; 32]> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare(
            "SELECT canonical_child FROM sender_online_proposal WHERE relationship_key = ?1 \
             ORDER BY rowid",
        )
        .expect("prepare");
    stmt.query_map(rusqlite::params![rel.as_slice()], |r| {
        let v: Vec<u8> = r.get(0)?;
        Ok(<[u8; 32]>::try_from(v.as_slice()).expect("32"))
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

/// The signed A-side PARENT of every canonical apply on `rel` on the ENTERED
/// device — the head the sender signed under, as the recipient pinned it.
fn applied_signed_parents(rel: &[u8; 32]) -> Vec<[u8; 32]> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare(
            "SELECT parent_tip FROM canonical_apply_identity WHERE relationship_key = ?1 \
             ORDER BY rowid",
        )
        .expect("prepare");
    stmt.query_map(rusqlite::params![rel.as_slice()], |r| {
        let v: Vec<u8> = r.get(0)?;
        Ok(<[u8; 32]>::try_from(v.as_slice()).expect("32"))
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

/// Every sender outbox status for `rel` on the ENTERED device.
fn outbox_statuses(rel: &[u8; 32]) -> Vec<String> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare("SELECT status FROM sender_outbox WHERE relationship_key = ?1 ORDER BY rowid")
        .expect("prepare");
    stmt.query_map(rusqlite::params![rel.as_slice()], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// Every recipient staging state on the ENTERED device.
fn staging_states() -> Vec<String> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare("SELECT state FROM recipient_staging ORDER BY rowid")
        .expect("prepare");
    stmt.query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// Whether the ENTERED device holds a pending online gate toward `peer`.
fn gate_present(peer: &TestDevice) -> bool {
    cdb::get_pending_online_outbox(&peer.device_id)
        .expect("gate")
        .is_some()
}

/// The ENTERED device's send-status authority for `peer`.
fn send_status(peer: &TestDevice) -> generated::RelationshipSendStatus {
    crate::handlers::relationship_status::derive_local_send_status_for_device_id(&peer.device_id)
}

fn pending_catchup() -> i32 {
    generated::RelationshipSendBlockReason::PendingCatchup as i32
}

/// One complete generation `from → to`: the real send, the recipient's sync
/// (stage → verify → apply → converge → ACK → delta) and the sender's sync
/// (finalize on the delta). Asserts each step so a later failure is never
/// mistaken for a fixture that never got this far.
async fn generation(from: &TestDevice, to: &TestDevice, amount: u64) {
    let rel = from.rel_key_with(to);
    let from_before = from.era_balance();
    let to_before = to.era_balance();
    let applied_before = {
        to.enter();
        rows_for_relationship("canonical_apply_identity", &rel)
    };
    let proposals_before = {
        from.enter();
        proposal_statuses(&rel).len()
    };

    let sent = from.send(to, amount).await;
    assert!(
        sent.success,
        "{}->{} wallet.send failed: {:?}",
        from.slot, to.slot, sent.error_message
    );
    assert_eq!(
        from.era_balance(),
        from_before - amount,
        "{} debited once",
        from.slot
    );
    assert!(
        gate_present(to),
        "{}'s gate is armed after the send",
        from.slot
    );

    let to_sync = to.sync().await;
    assert!(to_sync.success, "{:?}", to_sync.errors);
    assert_eq!(
        to.era_balance(),
        to_before + amount,
        "{} credited once",
        to.slot
    );
    assert_eq!(
        rows_for_relationship("canonical_apply_identity", &rel),
        applied_before + 1,
        "exactly one new canonical apply on {}",
        to.slot
    );

    let from_sync = from.sync().await;
    assert!(from_sync.success, "{:?}", from_sync.errors);
    let statuses = proposal_statuses(&rel);
    assert_eq!(statuses.len(), proposals_before + 1);
    assert_eq!(
        statuses.last().map(String::as_str),
        Some(cdb::PROPOSAL_FINALIZED),
        "{}'s proposal finalized on the recipient's countersignature",
        from.slot
    );
    // The same sync shipped the finality certificate to quorum: the sender's
    // gate is released and the outbox is collecting.
    assert!(
        !gate_present(to),
        "{}'s gate released once the checkpoint reached quorum",
        from.slot
    );
    assert_eq!(
        outbox_statuses(&rel).last().map(String::as_str),
        Some(cdb::OUTBOX_GC_PENDING)
    );

    // The recipient absorbs the certificate on its next poll and is released.
    let to_sync = to.sync().await;
    assert!(to_sync.success, "{:?}", to_sync.errors);
    assert!(
        !cdb::relationship_awaits_peer_finalization(&rel).expect("await"),
        "{} verified the certificate; its barrier is resolved",
        to.slot
    );
}

/// The harness itself must carry a full A→B generation through the shipped
/// pipeline. Every other test builds on this loop, so it is pinned first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn harness_carries_one_generation_a_to_b_through_production_code() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    generation(&p.a, &p.b, 10).await;
    p.b.enter();
    assert_eq!(
        rows_for_relationship("acceptance_fold_journal", &rel),
        1,
        "B journaled its acceptance"
    );
}

// =====================================================================
// R1 — ROLE REVERSAL. A→B, A→B, then B→A on the SAME relationship.
//
// The hardware failure this stack exists for: A's pin for B's head used to be
// derived from what A had APPLIED (nothing), so it fell back to the genesis
// seed while B's local lineage had advanced B0→B1→B2 by applying A's two
// transfers — B signed parent=B2, A saw Conflict, B's 5 ERA were stuck. Now
// the peer's head is ONE authority (`counterparty_canonical_heads`) advanced
// from both roles: A learns B1 and B2 from B's sig_b-authenticated deltas.
// =====================================================================

/// The ENTERED device's pinned canonical head for its peer on `rel`.
fn peer_head(rel: &[u8; 32]) -> Option<[u8; 32]> {
    cdb::load_counterparty_canonical_head(rel).expect("head")
}

/// The ENTERED device's journaled B pair for its most recent apply on `rel`.
fn last_applied_pair(rel: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.query_row(
        "SELECT applied_parent_tip_b, applied_child_tip_b FROM acceptance_fold_journal \
         WHERE relationship_key = ?1 ORDER BY rowid DESC LIMIT 1",
        rusqlite::params![rel.as_slice()],
        |r| {
            let p: Vec<u8> = r.get(0)?;
            let c: Vec<u8> = r.get(1)?;
            Ok((
                <[u8; 32]>::try_from(p.as_slice()).expect("32"),
                <[u8; 32]>::try_from(c.as_slice()).expect("32"),
            ))
        },
    )
    .expect("journal pair")
}

/// R1: the peer's canonical head is authenticated on every generation, so
/// B→A after A→B ×2 applies exactly once on A and finalizes on B. Mutation M1
/// (skip the peer-pair CAS in the sender's finalize) turns this red: A would
/// still pin the genesis seed for B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r1_role_reversal_applies_once_on_a_and_finalizes_on_b() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    generation(&p.a, &p.b, 10).await;
    generation(&p.a, &p.b, 10).await;
    assert_eq!(p.b.era_balance(), 20);

    // A pins B's head at exactly the child B journaled on its second apply —
    // learned from B's delta, authenticated by sig_b — and that is the parent
    // B will sign under.
    let b_pair_2 = {
        p.b.enter();
        last_applied_pair(&rel)
    };
    p.a.enter();
    assert_eq!(
        peer_head(&rel),
        Some(b_pair_2.1),
        "A's pinned head for B == B's applied_child_tip_b of apply #2"
    );
    // And B pins A's head at A's signed child of send #2 (learned on apply).
    let a_child_2 = {
        p.a.enter();
        proposal_children(&rel)
            .last()
            .copied()
            .expect("A's proposals")
    };
    p.b.enter();
    assert_eq!(
        peer_head(&rel),
        Some(a_child_2),
        "B pins A's second signed child"
    );

    generation(&p.b, &p.a, 5).await;

    assert_eq!(p.a.era_balance(), 985, "A credited exactly once");
    assert_eq!(p.b.era_balance(), 15);
    p.a.enter();
    assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 1);
    assert_eq!(staging_states(), vec!["accepted".to_string()]);
    assert_eq!(
        applied_signed_parents(&rel),
        vec![b_pair_2.1],
        "B signed the reverse leg under exactly the head A pinned"
    );
    p.b.enter();
    assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 2);
    assert_eq!(
        proposal_statuses(&rel),
        vec![cdb::PROPOSAL_FINALIZED.to_string()]
    );
    // And the relationship keeps working in BOTH directions afterwards.
    generation(&p.a, &p.b, 1).await;
    generation(&p.b, &p.a, 1).await;
}

// =====================================================================
// R2 — REVERSE BEFORE PEER FINALITY. B applied A's transfer and posted its
// delta, but A has NOT finalized (no certificate). B may not originate.
// =====================================================================

/// Commit 4: `relationship_status` blocks PendingCatchup while an accepted
/// journal on this side has `peer_finalized = 0`, and `wallet.send` consults
/// the authority and refuses before any mutation. Mutations M5 (flip
/// peer_finalized on delta submit) / M7 (bypass the authority) → red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r2a_recipient_cannot_originate_before_the_peer_finalized() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(p.b.era_balance(), 10, "B applied");
    // A deliberately does NOT sync: no finalize, no certificate.

    p.b.enter();
    let status = send_status(&p.a);
    assert!(!status.send_ready, "B must not be send-ready: {status:?}");
    assert_eq!(status.send_block_reason, pending_catchup());

    let refused = p.b.send(&p.a, 5).await;
    assert!(!refused.success, "B's reverse send must be refused");
    // Refused by the AUTHORITY, before any mutation was attempted — not by
    // the in-tx defense in depth (which also holds; see below).
    assert!(
        refused
            .error_message
            .as_deref()
            .unwrap_or("")
            .contains("not send-ready"),
        "refusal must come from the send-ready authority: {:?}",
        refused.error_message
    );
    assert_eq!(p.b.era_balance(), 10, "zero balance change");
    p.b.enter();
    assert_eq!(proposal_statuses(&rel).len(), 0, "zero proposal change");
    assert_eq!(outbox_statuses(&rel).len(), 0, "zero outbox change");
    assert!(!gate_present(&p.a), "no gate armed on B");
    assert_eq!(
        rows_for_relationship("canonical_apply_identity", &rel),
        1,
        "zero canonical change"
    );
}

/// Commit 5: once A's `RelationshipFinalizedV1` reaches quorum and B verifies
/// it (`peer_finalized = 1`), B is send-ready and its reverse send applies on A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r2b_the_certificate_releases_the_recipient() {
    let p = Pair::boot(1_000, 0).await;
    generation(&p.a, &p.b, 10).await;
    // A's finalize sync above also ships the checkpoint; B absorbs it here.
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    p.b.enter();
    let status = send_status(&p.a);
    assert!(
        status.send_ready,
        "B released by the certificate: {status:?}"
    );
    generation(&p.b, &p.a, 5).await;
    assert_eq!(p.a.era_balance(), 995);
}

// =====================================================================
// R3 — SAME DIRECTION UNTIL CHECKPOINT QUORUM. A finalized on B's delta but
// its certificate has not reached storage quorum: A's gate stays armed and
// a second A→B is refused. Once the fleet accepts (204×K) the sweep clears
// the gate in ONE tx and the outbox moves to gc_pending.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r3_sender_stays_gated_until_the_checkpoint_reaches_quorum() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);

    // The fleet is down for writes: A finalizes locally, cannot ship the
    // checkpoint. (Mutation M3 — clear the gate in the local finalize → red.)
    p.override_all_submits(Some(503));
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert_eq!(
        proposal_statuses(&rel),
        vec![cdb::PROPOSAL_FINALIZED.to_string()]
    );
    assert!(
        gate_present(&p.b),
        "gate stays armed while the checkpoint is unsent"
    );
    let status = send_status(&p.b);
    assert!(!status.send_ready);
    assert_eq!(status.send_block_reason, pending_catchup());
    let refused = p.a.send(&p.b, 1).await;
    assert!(!refused.success, "second A->B must be refused");
    assert_eq!(p.a.era_balance(), 990, "no second debit");

    // Fleet back: the sweep replays the exact certificate, quorum, release.
    p.override_all_submits(None);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert!(
        !gate_present(&p.b),
        "gate cleared by the post-quorum release"
    );
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_GC_PENDING.to_string()]
    );
    assert!(send_status(&p.b).send_ready);
    let ok = p.a.send(&p.b, 1).await;
    assert!(ok.success, "{:?}", ok.error_message);
}

// =====================================================================
// R4 — A STORAGE ACK IS NOT A RELEASE. B consumed (ACKed) both halves on
// every node; A observes "acked" through the calibration route. Today that
// route clears the gate; the barrier keeps it armed — only a verified
// countersignature and a quorum'd certificate release it.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r4_a_storage_ack_cannot_release_the_sender_gate() {
    let p = Pair::boot(1_000, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    // Positive control on the fixture: the node reports the transfer acked.
    let transfer_id = p
        .submits()
        .first()
        .map(|s| s.message_id.clone())
        .expect("a submit");
    assert_eq!(p.acked_count(&transfer_id), 3, "B ACKed on every node");

    p.a.enter();
    let calibrated =
        p.a.router()
            .calibrate_local_relationship_send_status(&p.b.device_id)
            .await;
    assert!(gate_present(&p.b), "an ACK alone must not clear the gate");
    assert!(!calibrated.send_ready, "{calibrated:?}");
    assert_eq!(calibrated.send_block_reason, pending_catchup());
    // Calibrating again changes nothing: it is read-only now.
    p.a.router()
        .calibrate_local_relationship_send_status(&p.b.device_id)
        .await;
    assert!(gate_present(&p.b));

    // Positive, and the anti-vacuity: the delta B spooled finalizes A on its
    // next sync, the certificate reaches quorum, and ONLY THEN is the gate
    // gone — with the certificate on the wire to prove which event did it.
    let rel = p.a.rel_key_with(&p.b);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert_eq!(
        proposal_statuses(&rel),
        vec![cdb::PROPOSAL_FINALIZED.to_string()]
    );
    assert!(!gate_present(&p.b));
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_GC_PENDING.to_string()]
    );
    let certificates: Vec<_> = p
        .submits()
        .into_iter()
        .filter(|s| {
            dsm::types::proto::Envelope::decode(s.body.as_slice())
                .ok()
                .and_then(|env| crate::sdk::b0x_sdk::B0xSDK::decode_relationship_finalized(&env))
                .is_some()
        })
        .collect();
    assert_eq!(
        certificates.len(),
        3,
        "exactly one certificate per node (deterministic id, quorum 3)"
    );
    assert!(
        certificates
            .iter()
            .all(|c| c.message_id == certificates[0].message_id),
        "the same deterministic id everywhere"
    );
}

// =====================================================================
// R11 — ONLY THE POST-QUORUM SWEEP DELETES THE SENDER GATE. With the
// certificate unshipped, none of the other historical clearers may touch it.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r11_only_the_checkpoint_sweep_clears_the_gate() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    p.override_all_submits(Some(503));
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert_eq!(
        proposal_statuses(&rel),
        vec![cdb::PROPOSAL_FINALIZED.to_string()]
    );
    assert!(gate_present(&p.b));

    // Every historical clearer, in turn: none may delete the row.
    let calibrated =
        p.a.router()
            .calibrate_local_relationship_send_status(&p.b.device_id)
            .await;
    assert!(gate_present(&p.b), "calibrate must not clear it");
    assert_eq!(calibrated.send_block_reason, pending_catchup());
    let stale = cdb::clear_stale_pending_online_gate(&p.b.device_id).expect("stale check");
    assert!(
        matches!(stale, cdb::StaleGateOutcome::StillPending),
        "clear_stale_pending_online_gate must report StillPending, got {stale:?}"
    );
    assert!(gate_present(&p.b), "the stale-gate check must not clear it");
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert!(
        gate_present(&p.b),
        "a sync that cannot ship the checkpoint must not clear it"
    );
    assert!(!send_status(&p.b).send_ready);

    // Then the ONE deleter: fleet up, sweep replays, one tx clears + gc_pending.
    p.override_all_submits(None);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert!(!gate_present(&p.b));
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_GC_PENDING.to_string()]
    );
}

// =====================================================================
// R7 — CRASH AFTER FINALIZE, BEFORE THE CHECKPOINT REACHED QUORUM. The
// certificate is frozen in the finalize transaction; nothing rebuilds it.
// When the fleet is back, the sweep replays the EXACT bytes under the SAME
// deterministic id and route, releases the gate once, and no second debit or
// proposal appears. The signing key is gone from the pending table the moment
// the finalize committed, so a re-sign is impossible, not merely avoided.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r7_a_frozen_checkpoint_is_replayed_byte_identically_after_the_fleet_returns() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);

    p.override_all_submits(Some(503));
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert_eq!(
        proposal_statuses(&rel),
        vec![cdb::PROPOSAL_FINALIZED.to_string()]
    );
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_FINALIZATION_CHECKPOINT_PENDING.to_string()]
    );
    let (frozen_bytes, frozen_id, frozen_route): (Vec<u8>, String, String) = {
        let binding = cdb::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT envelope_bytes, submission_id, routing_address FROM sender_outbox_artifacts \
             WHERE relationship_key = ?1 AND role = 'relationship_finalized'",
            rusqlite::params![rel.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("frozen certificate")
    };
    let pending_heads: i64 = {
        let binding = cdb::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM pending_local_cert_heads WHERE relationship_key = ?1",
            rusqlite::params![rel.as_slice()],
            |r| r.get(0),
        )
        .expect("count")
    };
    assert_eq!(
        pending_heads, 0,
        "the certificate's signing key was promoted and deleted"
    );
    let submits_before = p.submits().len();

    // The fleet returns; the sweep replays.
    p.override_all_submits(None);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert!(
        !gate_present(&p.b),
        "released once the replay reached quorum"
    );
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_GC_PENDING.to_string()]
    );
    assert_eq!(proposal_statuses(&rel).len(), 1, "no second proposal");
    assert_eq!(p.a.era_balance(), 990, "no second debit");
    let replayed: Vec<_> = p
        .submits()
        .into_iter()
        .skip(submits_before)
        .filter(|s| s.message_id == frozen_id)
        .collect();
    assert_eq!(replayed.len(), 3, "one replay per node under the frozen id");
    for r in &replayed {
        assert_eq!(
            r.body, frozen_bytes,
            "byte-identical to the frozen envelope"
        );
        assert_eq!(r.recipient, frozen_route, "under the frozen route");
    }
    // And B absorbs it and is released.
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    p.b.enter();
    assert!(!cdb::relationship_awaits_peer_finalization(&rel).unwrap());
}

// =====================================================================
// R8 — REORDERED NEXT GENERATION. A's certificate for transfer #1 reached
// quorum (A is free) but B has not seen it yet; A's transfer #2 arrives at B
// first. B stages #2 and HOLDS it at ready_to_verify — not applied, not
// ACKed, not rejected — until the certificate lands; then the SAME row
// applies exactly once. The intended reordering behaviour.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r8_a_next_generation_transfer_is_held_until_the_certificate_lands() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert!(!gate_present(&p.b), "certificate #1 at quorum: A is free");
    // Certificate #1 is delayed in transit for B.
    let cert_id: String = {
        let binding = cdb::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT submission_id FROM sender_outbox_artifacts \
             WHERE relationship_key = ?1 AND role = 'relationship_finalized'",
            rusqlite::params![rel.as_slice()],
            |r| r.get(0),
        )
        .expect("certificate id")
    };
    p.hold_message(&cert_id);

    // A's second transfer arrives at B before the certificate.
    let sent2 = p.a.send(&p.b, 7).await;
    assert!(sent2.success, "{:?}", sent2.error_message);
    let transfer2_id = p
        .submits()
        .last()
        .map(|s| s.message_id.clone())
        .expect("a submit");
    for _pass in 0..2 {
        let b_sync = p.b.sync().await;
        assert!(b_sync.success, "{:?}", b_sync.errors);
        assert_eq!(p.b.era_balance(), 10, "held: not applied");
        p.b.enter();
        assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 1);
        assert_eq!(
            staging_states(),
            vec!["accepted".to_string(), "ready_to_verify".to_string()],
            "held at ready_to_verify — not rejected, not accepted"
        );
        assert!(cdb::relationship_awaits_peer_finalization(&rel).unwrap());
    }
    assert_eq!(p.acked_count(&transfer2_id), 0, "held: not ACKed");
    p.a.enter();
    assert!(
        gate_present(&p.b),
        "A's gate #2 is still armed (no delta yet)"
    );

    // The certificate lands: the SAME row proceeds and applies exactly once.
    p.release_message(&cert_id);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(p.b.era_balance(), 17, "applied once after the certificate");
    p.b.enter();
    assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 2);
    assert_eq!(
        staging_states(),
        vec!["accepted".to_string(), "accepted".to_string()]
    );
    assert_eq!(p.acked_count(&transfer2_id), 3);
    // And generation #2 finalizes normally on both sides.
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert_eq!(
        proposal_statuses(&rel),
        vec![
            cdb::PROPOSAL_FINALIZED.to_string(),
            cdb::PROPOSAL_FINALIZED.to_string()
        ]
    );
    assert!(!gate_present(&p.b));
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    p.b.enter();
    assert!(!cdb::relationship_awaits_peer_finalization(&rel).unwrap());
}
