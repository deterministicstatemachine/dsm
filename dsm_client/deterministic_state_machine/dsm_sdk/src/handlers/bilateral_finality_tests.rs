// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral finality barrier — protocol tests over the two-device harness.
//!
//! Every test drives PRODUCTION code end to end: the real `wallet.send`, the
//! real `storage.sync` on each side, the network's pinned set of storage
//! nodes in between; every fault is a node that stops serving. See
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

use crate::economic_fixtures::whole_era;
use crate::storage::client_db as cdb;
use crate::test_support::two_device::{assert_incomplete, Pair, TestDevice};
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

/// The state of every staged pair still in flight on the ENTERED device. A
/// finished pair is released, so it is not listed.
fn staging_states() -> Vec<String> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare("SELECT state FROM recipient_pair ORDER BY rowid")
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

/// The id of the finality certificate the ENTERED sender froze for `rel`.
fn frozen_certificate_id(rel: &[u8; 32]) -> String {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.query_row(
        "SELECT submission_id FROM sender_outbox_artifacts \
         WHERE relationship_key = ?1 AND role = 'relationship_finalized'",
        rusqlite::params![rel.as_slice()],
        |r| r.get(0),
    )
    .expect("certificate id")
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

    // Locator honesty (3.5b correction C): the frozen envelope's economic
    // locators are OUTPUTS of the sender's built admission — the wire must
    // name exactly the position the sender's lineage admitted for this debit,
    // and THE debit mutation index of a pure-debit write set.
    p.a.enter();
    let (admitted_pos, _) = cdb::economic_lineage::get_admitted_coordinate()
        .expect("admitted read")
        .expect("the send admission is terminal before delivery");
    let envelope_bytes: Vec<u8> = {
        let binding = cdb::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT envelope_bytes FROM sender_outbox \
             WHERE relationship_key = ?1 ORDER BY rowid DESC LIMIT 1",
            rusqlite::params![rel.as_slice()],
            |r| r.get(0),
        )
        .expect("outbox envelope")
    };
    // The outbox holds the full b0x envelope: Envelope → UniversalTx →
    // Invoke → ArgPack.body IS the OnlineTransferRequest.
    let outer = dsm::types::proto::Envelope::decode(envelope_bytes.as_slice())
        .expect("outbox envelope decodes");
    let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = outer.payload else {
        panic!("expected a UniversalTx payload");
    };
    let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) =
        tx.ops.first().and_then(|op| op.kind.clone())
    else {
        panic!("expected an Invoke op");
    };
    let body = invoke.args.expect("arg pack").body;
    let env = dsm::types::proto::OnlineTransferRequest::decode(body.as_slice())
        .expect("transfer decodes");
    assert_eq!(
        env.sender_economic_position, admitted_pos,
        "the wire locator names the admitted position of THIS debit"
    );
    assert_eq!(
        env.sender_debit_mutation_index, 0,
        "a pure-debit write set has exactly one mutation — index 0 is a builder fact"
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
    // B originates on the reverse leg, and under 3.5b a send debits the
    // sender's ADMITTED economic balance — received-but-unadmitted credits
    // cannot fund it until PR4 lands recipient admission. So B boots with its
    // own faucet-funded 100 to send from; the received 20 rides on the head.
    let p = Pair::boot(1_000, 100).await;
    let rel = p.a.rel_key_with(&p.b);
    generation(&p.a, &p.b, 10).await;
    generation(&p.a, &p.b, 10).await;
    assert_eq!(p.b.era_balance(), whole_era(100) + 20);

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

    assert_eq!(
        p.a.era_balance(),
        whole_era(1_000) - 20 + 5,
        "A credited exactly once"
    );
    assert_eq!(p.b.era_balance(), whole_era(100) + 20 - 5);
    p.a.enter();
    assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 1);
    assert_eq!(
        staging_states(),
        Vec::<String>::new(),
        "the applied pair was finished and released in the same pass"
    );
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
    // B's reverse send needs its own admitted funding (see r1).
    let p = Pair::boot(1_000, 100).await;
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
    assert_eq!(p.a.era_balance(), whole_era(1_000) - 10 + 5);
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

    // Three members' spools fail. A reads B's delta from the two whose spools
    // serve and finalizes — every cell it reads to verify the release still
    // serves — but the checkpoint reaches only two spools, below quorum.
    // (Mutation M3 — clear the gate in the local finalize → red.)
    let down = crate::economic_fixtures::members_to_break_quorum();
    p.nodes.fail_spools(&down).await;
    let a_sync = p.a.sync().await;
    assert_incomplete(&a_sync);
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
    assert_eq!(p.a.era_balance(), whole_era(1_000) - 10, "no second debit");

    // Fleet back: the sweep replays the exact certificate, quorum, release.
    p.nodes.restore_spools(&down).await;
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

/// A step in flight is not a lost head. A's first transfer is signed with a
/// per-step EK that waits, pending, for the step's finalization; until then A
/// has no Local head for the relationship. A second send in that window is
/// refused by the catch-up gate — and the relationship is never marked as
/// needing a cert-chain resync, which would block it until a joint resync.
/// Once the step finalizes, A sends again. (Mutation: drop the pending-head
/// term from wallet.send's head-loss check → the second send marks a resync
/// and this goes red.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_send_before_the_previous_step_finalizes_is_gated_never_marked_for_resync() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);

    let early = p.a.send(&p.b, 1).await;
    assert!(
        !early.success,
        "the second send waits for the first to finalize"
    );
    let msg = early.error_message.unwrap_or_default();
    assert!(
        !msg.contains("resync"),
        "a pending step is not a lost head: {msg}"
    );
    p.a.enter();
    assert!(
        !cdb::cert_resync_blocks_send(&rel).expect("resync state"),
        "the relationship is not marked for resync"
    );
    assert_eq!(p.a.era_balance(), whole_era(1_000) - 10, "no second debit");

    // The step finalizes; the relationship sends again.
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    let released = p.b.sync().await;
    assert!(released.success, "{:?}", released.errors);
    let again = p.a.send(&p.b, 1).await;
    assert!(again.success, "{:?}", again.error_message);
}

// =====================================================================
// R4 — CALIBRATION IS NOT A RELEASE. B applied the transfer; A asks the
// calibration route what it can observe. Only a verified countersignature
// and a certificate at quorum release the gate.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r4_calibration_cannot_release_the_sender_gate() {
    let p = Pair::boot(1_000, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(p.b.era_balance(), 10, "B applied the transfer");

    p.a.enter();
    let calibrated =
        p.a.router()
            .calibrate_local_relationship_send_status(&p.b.device_id)
            .await;
    assert!(
        gate_present(&p.b),
        "calibration alone must not clear the gate"
    );
    assert!(!calibrated.send_ready, "{calibrated:?}");
    assert_eq!(calibrated.send_block_reason, pending_catchup());
    // Calibrating again changes nothing: it is read-only.
    p.a.router()
        .calibrate_local_relationship_send_status(&p.b.device_id)
        .await;
    assert!(gate_present(&p.b));

    // Positive, and the anti-vacuity: the delta B spooled finalizes A on its
    // next sync, the certificate reaches quorum, and ONLY THEN is the gate
    // gone — with the certificate on the members to prove which event did it.
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
    let certificate = frozen_certificate_id(&rel);
    assert_eq!(
        p.holders_of(&certificate).await,
        crate::economic_fixtures::delivery_quorum(),
        "the certificate is held by exactly the delivery quorum, under one id"
    );
}

// =====================================================================
// THE HARNESS HOLDS THE BACKGROUND POLLER OFF. R4 failed on CI when the
// process's background poller — started by an earlier test's send, woken by
// the calibration's `resume_poller` — ran a sync of A between A's own sync and
// the read of the state it left, and collected A's outbox row
// (gc_pending → complete).
// =====================================================================
/// While a pair lives, a wake of the background poller starts no sync: the
/// send's wake and a wake inside the window after A's sync are deferred, and
/// the state A's sync left is the state read. Released, the deferred start
/// runs: the poller's first cycle syncs the entered device and collects the
/// row — the wake was deferred, not lost.
/// MUTATION CONTROL: letting `start_poller` run while the hold stands turns
/// this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_harness_defers_the_background_poller_while_a_pair_lives() {
    use crate::sdk::inbox_poller::{
        poller_running, poller_start_deferred, resume_poller, stop_poller, POLLER_CYCLE_DONE,
    };
    let mut p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    assert!(
        !poller_running() && poller_start_deferred(),
        "the send's wake started a poller while the pair lives"
    );
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_GC_PENDING.to_string()]
    );

    // The wake a calibration issues, in the window between A's sync and the
    // read of the state it left.
    resume_poller();
    assert!(!poller_running(), "a poller started inside the window");
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_GC_PENDING.to_string()],
        "a sync entered the window"
    );

    // Released, the deferred start runs; its first cycle syncs A (entered)
    // and collects the row.
    let cycle = POLLER_CYCLE_DONE.notified();
    tokio::pin!(cycle);
    cycle.as_mut().enable();
    p.release_background_poller();
    assert!(poller_running(), "the deferred start was lost");
    tokio::time::timeout(std::time::Duration::from_secs(60), cycle)
        .await
        .expect("the released poller's first cycle");
    stop_poller();
    p.a.enter();
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_COMPLETE.to_string()],
        "the released poller's sync did not collect the row"
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
    let down = crate::economic_fixtures::members_to_break_quorum();
    p.nodes.fail_spools(&down).await;
    let a_sync = p.a.sync().await;
    assert_incomplete(&a_sync);
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
    assert_incomplete(&a_sync);
    p.a.enter();
    assert!(
        gate_present(&p.b),
        "a sync that cannot ship the checkpoint must not clear it"
    );
    assert!(!send_status(&p.b).send_ready);

    // Then the ONE deleter: fleet up, sweep replays, one tx clears + gc_pending.
    p.nodes.restore_spools(&down).await;
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

    let down = crate::economic_fixtures::members_to_break_quorum();
    p.nodes.fail_spools(&down).await;
    let a_sync = p.a.sync().await;
    assert_incomplete(&a_sync);
    p.a.enter();
    assert_eq!(
        proposal_statuses(&rel),
        vec![cdb::PROPOSAL_FINALIZED.to_string()]
    );
    assert_eq!(
        outbox_statuses(&rel),
        vec![cdb::OUTBOX_FINALIZATION_CHECKPOINT_PENDING.to_string()]
    );
    let (frozen_id, frozen_route): (String, String) = {
        let binding = cdb::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT submission_id, routing_address FROM sender_outbox_artifacts \
             WHERE relationship_key = ?1 AND role = 'relationship_finalized'",
            rusqlite::params![rel.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("frozen certificate")
    };
    // The sealed bytes the finalize froze for delivery.
    let frozen_seal = crate::sdk::b0x_sdk::kept_seal(&frozen_id).expect("the certificate's seal");
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

    // The fleet returns; the sweep replays.
    p.nodes.restore_spools(&down).await;
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
    assert_eq!(p.a.era_balance(), whole_era(1_000) - 10, "no second debit");
    // The replay re-posts to members that already held the first delivery;
    // a node deduplicates nothing (storage spec §8), so those hold it twice.
    // What matters is that every copy anywhere is the frozen envelope under
    // the frozen route, and that the delivery quorum holds it.
    let mut holders = 0;
    for node in &p.nodes.nodes {
        let mut held = false;
        for spooled in node.spool().await {
            if spooled.message_id.as_deref() == Some(frozen_id.as_str()) {
                held = true;
                assert_eq!(
                    spooled.envelope, frozen_seal,
                    "byte-identical to the frozen envelope"
                );
                assert_eq!(spooled.address, frozen_route, "under the frozen route");
            }
        }
        holders += usize::from(held);
    }
    assert_eq!(
        holders,
        crate::economic_fixtures::delivery_quorum(),
        "the delivery quorum holds the frozen certificate"
    );
    // And B absorbs it and is released.
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    p.b.enter();
    assert!(!cdb::relationship_awaits_peer_finalization(&rel).expect("await"));
}

// =====================================================================
// R8 — REORDERED NEXT GENERATION. A's certificate for transfer #1 reached
// quorum (A is free) but B has not seen it yet; A's transfer #2 reaches B
// first. B stages #2 and HOLDS it at ready_to_verify — not applied, not
// rejected — until the certificate lands; then the SAME row applies exactly
// once. The reordering comes from failing spools: the certificate went out
// while the first members' spools had failed, so it sits on the others;
// transfer #2 went out with every spool serving, so it sits on the first
// ones; B then reads only the first ones.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r8_a_next_generation_transfer_is_held_until_the_certificate_lands() {
    let p = Pair::boot(1_000, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let members = crate::economic_fixtures::canonical_member_ids();
    let quorum = crate::economic_fixtures::delivery_quorum();
    let (first, rest) = members.split_at(members.len() - quorum);
    let (first, rest) = (first.to_vec(), rest.to_vec());

    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);

    // Certificate #1 goes out while the first members' spools have failed.
    p.nodes.fail_spools(&first).await;
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    p.a.enter();
    assert!(!gate_present(&p.b), "certificate #1 at quorum: A is free");
    let certificate = frozen_certificate_id(&rel);
    p.nodes.restore_spools(&first).await;
    assert_eq!(p.holders_of(&certificate).await, quorum);

    // A's second transfer, with every member serving.
    let sent2 = p.a.send(&p.b, 7).await;
    assert!(sent2.success, "{:?}", sent2.error_message);

    // The other members' spools fail: B reads only the first members, so
    // transfer #2 reaches it and the certificate does not.
    p.nodes.fail_spools(&rest).await;
    for pass in 0..2 {
        let b_sync = p.b.sync().await;
        assert_incomplete(&b_sync);
        assert!(
            b_sync
                .errors
                .iter()
                .any(|e| e.contains("awaits the peer's finality certificate")),
            "pass {pass}: the hold is reported: {:?}",
            b_sync.errors
        );
        assert_eq!(p.b.era_balance(), 10, "pass {pass}: held, not applied");
        p.b.enter();
        assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 1);
        assert_eq!(
            staging_states(),
            vec!["bound".to_string()],
            "generation #1 finished and released; #2 held bound — not rejected, not accepted"
        );
        assert!(cdb::relationship_awaits_peer_finalization(&rel).expect("await"));
    }
    p.a.enter();
    assert!(
        gate_present(&p.b),
        "A's gate #2 is still armed (no delta yet)"
    );

    // The certificate lands: the SAME row proceeds and applies exactly once.
    p.nodes.restore_spools(&rest).await;
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(p.b.era_balance(), 17, "applied once after the certificate");
    p.b.enter();
    assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 2);
    assert_eq!(
        staging_states(),
        Vec::<String>::new(),
        "both generations finished and released"
    );
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
    assert!(!cdb::relationship_awaits_peer_finalization(&rel).expect("await"));
}

// =====================================================================
// R9 — RELATIONSHIP-LOCAL, NEVER WALLET-GLOBAL. A↔B pending on BOTH sides
// (A's gate armed, B awaiting A's certificate) must not touch A↔C or B↔C.
// Mutation M7' (make either barrier condition wallet-global) turns this red.
// =====================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn r9_the_barrier_is_relationship_local() {
    let p = Pair::boot(1_000, 500).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    for (x, y) in [(&p.a, &c), (&p.b, &c)] {
        x.add_contact(y).await;
        y.add_contact(x).await;
    }
    let c_sync = c.sync().await;
    assert!(c_sync.success, "{:?}", c_sync.errors);

    // A↔B pending both ways: A sent, B applied, A has NOT finalized.
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    p.a.enter();
    assert!(gate_present(&p.b), "A's gate toward B is armed");
    p.b.enter();
    assert!(!send_status(&p.a).send_ready, "B is blocked toward A");

    // A→C and B→C are free.
    p.a.enter();
    assert!(send_status(&c).send_ready, "A is free toward C");
    p.b.enter();
    assert!(send_status(&c).send_ready, "B is free toward C");
    generation(&p.a, &c, 3).await;
    generation(&p.b, &c, 2).await;
    assert_eq!(c.era_balance(), 5);

    // A↔B settled along the way (A's syncs inside the generations consumed
    // B's delta and shipped the certificate; B's synced too).
    p.a.enter();
    assert!(!gate_present(&p.b));
    p.b.enter();
    assert!(send_status(&p.a).send_ready);
}

/// Two online sends that cross both settle (owner ruling, 2026-10-29: "both
/// settle"). A sends to B and B sends to A, each before either device sees
/// the other's transfer: every spool has failed, so neither preflight pulls
/// anything and each send's delivery is left to the re-drive. Each transfer
/// consumes its own sender's parent. Once the spools serve again, both
/// transfers apply, both senders finalize on the countersignatures made
/// after their counterparties' own sends, both certificates are verified and
/// both gates release; each balance moved by both amounts, both devices hold
/// one relationship tip, and the relationship takes the next transfer in
/// each direction. (The defect this pins: both transfers applied and every
/// finalization was refused on every sync, so neither gate released and the
/// relationship took no further step, online or offline.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn two_online_sends_that_cross_both_settle_and_the_relationship_moves_on() {
    let p = Pair::boot(1_000, 1_000).await;
    let rel = p.a.rel_key_with(&p.b);
    let members = crate::economic_fixtures::canonical_member_ids();
    let (a0, b0) = (p.a.era_balance(), p.b.era_balance());

    p.nodes.fail_spools(&members).await;
    for (from, to, amount) in [(&p.a, &p.b, 10), (&p.b, &p.a, 7)] {
        let sent = from.send(to, amount).await;
        assert!(
            sent.error_message
                .as_deref()
                .is_some_and(|e| e.contains("delivery outcome unknown")),
            "{}: debited, its delivery left to the re-drive: {:?}",
            from.slot,
            sent.error_message
        );
    }
    p.nodes.restore_spools(&members).await;

    let mut rounds = 0;
    loop {
        let a_sync = p.a.sync().await;
        let b_sync = p.b.sync().await;
        let settled = [(&p.a, &p.b), (&p.b, &p.a)].iter().all(|(me, peer)| {
            me.enter();
            !gate_present(peer) && !cdb::relationship_awaits_peer_finalization(&rel).expect("await")
        });
        if settled {
            break;
        }
        rounds += 1;
        assert!(
            rounds < 6,
            "the crossing did not settle: A {:?}; B {:?}",
            a_sync.errors,
            b_sync.errors
        );
    }

    assert_eq!(p.a.era_balance(), a0 - 10 + 7, "A paid 10 and was paid 7");
    assert_eq!(p.b.era_balance(), b0 + 10 - 7, "B was paid 10 and paid 7");
    let mut tips = Vec::new();
    for (me, peer) in [(&p.a, &p.b), (&p.b, &p.a)] {
        me.enter();
        assert_eq!(
            proposal_statuses(&rel),
            vec![cdb::PROPOSAL_FINALIZED.to_string()],
            "{}'s send finalized",
            me.slot
        );
        assert_eq!(
            rows_for_relationship("canonical_apply_identity", &rel),
            1,
            "{} applied the crossing transfer once",
            me.slot
        );
        assert!(send_status(peer).send_ready, "{} is send-ready", me.slot);
        tips.push(
            cdb::get_contact_chain_tip(&peer.device_id)
                .expect("read the tip")
                .expect("the peer is a contact"),
        );
    }
    assert_eq!(tips[0], tips[1], "both devices hold one relationship tip");

    generation(&p.a, &p.b, 5).await;
    generation(&p.b, &p.a, 3).await;
}

// =====================================================================
// CROSSING SENDS (owner ruling, 2026-10-29: "both settle") — adversarial.
// Each test crosses two online sends as the permanent crossing test does,
// then disturbs the settlement one way, and requires both to settle exactly
// once.
// =====================================================================

/// A sends `a_amount` to B and B sends `b_amount` to A while every spool has
/// failed, so neither preflight sees the other's transfer; the spools serve
/// again on return.
async fn crossed(p: &Pair, a_amount: u64, b_amount: u64) {
    let members = crate::economic_fixtures::canonical_member_ids();
    p.nodes.fail_spools(&members).await;
    for (from, to, amount) in [(&p.a, &p.b, a_amount), (&p.b, &p.a, b_amount)] {
        let sent = from.send(to, amount).await;
        assert!(
            sent.error_message
                .as_deref()
                .is_some_and(|e| e.contains("delivery outcome unknown")),
            "{}: debited, its delivery left to the re-drive: {:?}",
            from.slot,
            sent.error_message
        );
    }
    p.nodes.restore_spools(&members).await;
}

/// Whether both of the crossing's gates are released and both barriers
/// resolved.
fn crossing_settled(p: &Pair, rel: &[u8; 32]) -> bool {
    [(&p.a, &p.b), (&p.b, &p.a)].iter().all(|(me, peer)| {
        me.enter();
        !gate_present(peer) && !cdb::relationship_awaits_peer_finalization(rel).expect("await")
    })
}

/// Syncs `first` then `second`, round after round, until the crossing settles.
async fn settle(p: &Pair, rel: &[u8; 32], first: &TestDevice, second: &TestDevice) {
    for round in 0..8 {
        let one = first.sync().await;
        let two = second.sync().await;
        if crossing_settled(p, rel) {
            return;
        }
        assert!(
            round < 7,
            "the crossing did not settle: {} {:?}; {} {:?}",
            first.slot,
            one.errors,
            second.slot,
            two.errors
        );
    }
}

/// Both sends settled exactly once: each balance moved by both amounts, each
/// device holds one finalized send and one applied transfer, both hold one
/// relationship tip, and both are send-ready.
fn assert_crossing_settled(p: &Pair, rel: &[u8; 32], before: (u64, u64), amounts: (u64, u64)) {
    assert_eq!(
        p.a.era_balance(),
        before.0 - amounts.0 + amounts.1,
        "A's balance"
    );
    assert_eq!(
        p.b.era_balance(),
        before.1 + amounts.0 - amounts.1,
        "B's balance"
    );
    let mut tips = Vec::new();
    for (me, peer) in [(&p.a, &p.b), (&p.b, &p.a)] {
        me.enter();
        assert_eq!(
            proposal_statuses(rel),
            vec![cdb::PROPOSAL_FINALIZED.to_string()],
            "{}'s send finalized once",
            me.slot
        );
        assert_eq!(
            rows_for_relationship("canonical_apply_identity", rel),
            1,
            "{} applied the crossing transfer once",
            me.slot
        );
        assert!(send_status(peer).send_ready, "{} is send-ready", me.slot);
        tips.push(
            cdb::get_contact_chain_tip(&peer.device_id)
                .expect("read the tip")
                .expect("the peer is a contact"),
        );
    }
    assert_eq!(tips[0], tips[1], "both devices hold one relationship tip");
}

/// Every copy of a transfer half, an evidence half and a certificate one
/// device's polls have read, each kept once by the id the spool holds it by.
#[derive(Default)]
struct Copies {
    transfers: Vec<crate::sdk::b0x_sdk::B0xEntry>,
    evidence: Vec<(crate::sdk::b0x_sdk::EvidenceArtifact, String)>,
    certificates: Vec<crate::sdk::b0x_sdk::RelationshipFinalizedMessage>,
}

impl Copies {
    /// Keep what `me`'s poll would read now.
    async fn read(&mut self, me: &TestDevice, p: &Pair) {
        let arrived = crate::test_support::arrivals::arrivals_for(me, &p.fleet).await;
        for transfer in arrived.transfers {
            if self
                .transfers
                .iter()
                .all(|kept| kept.transaction_id != transfer.transaction_id)
            {
                self.transfers.push(transfer);
            }
        }
        for (artifact, route) in arrived.evidence {
            if self
                .evidence
                .iter()
                .all(|(kept, _)| kept.message_id != artifact.message_id)
            {
                self.evidence.push((artifact, route));
            }
        }
        for certificate in arrived.certificates {
            if self
                .certificates
                .iter()
                .all(|kept| kept.message_id != certificate.message_id)
            {
                self.certificates.push(certificate);
            }
        }
    }

    /// Deliver every kept copy to `me` again through its own boundary — each
    /// half into its ingestion, each certificate into its handler — as a
    /// network that repeats itself does.
    async fn deliver_again(&self, me: &TestDevice) {
        use crate::handlers::recipient_dispatch::{ingest_evidence_half, ingest_transfer_half};
        use crate::handlers::relationship_finalized::{
            apply_relationship_finalized, RelationshipFinalizedOutcome,
        };
        me.enter();
        for transfer in &self.transfers {
            if let Err(e) = ingest_transfer_half(
                &transfer.transfer_wire_bytes,
                &transfer.sender_device_id,
                &transfer.inbox_key,
                &transfer.transaction_id,
            ) {
                panic!("{}: a transfer copy failed the device: {e}", me.slot);
            }
        }
        for (artifact, route) in &self.evidence {
            if let Err(e) = ingest_evidence_half(
                &artifact.evidence.full_receipt_bytes,
                route,
                &artifact.message_id,
            ) {
                panic!("{}: an evidence copy failed the device: {e}", me.slot);
            }
        }
        for certificate in &self.certificates {
            let outcome = apply_relationship_finalized(&certificate.body).await;
            assert!(
                matches!(
                    outcome,
                    RelationshipFinalizedOutcome::Applied
                        | RelationshipFinalizedOutcome::AlreadyFinalized
                ),
                "{}: a certificate copy: {outcome:?}",
                me.slot
            );
        }
    }
}

/// Reversed delivery order and copies: B, not A, syncs first in every round,
/// so each device meets the other's transfer, acknowledgment and certificate
/// in the other order. Before each sync the device's arrivals are kept, and
/// after it every copy kept so far is delivered to it again — mid-settlement,
/// while its reconciliation is under way — and once more after the crossing
/// settles, followed by two more rounds of syncs. Nothing moves twice: each
/// balance moves by both amounts once, each device applies one transfer and
/// finalizes one send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn crossing_sends_settle_in_the_reversed_order_and_their_copies_change_nothing() {
    let p = Pair::boot(1_000, 1_000).await;
    let rel = p.a.rel_key_with(&p.b);
    let before = (p.a.era_balance(), p.b.era_balance());
    crossed(&p, 10, 7).await;
    let mut copies = [Copies::default(), Copies::default()];
    for round in 0..8 {
        let mut errors = Vec::new();
        for (kept, me) in copies.iter_mut().zip([&p.b, &p.a]) {
            kept.read(me, &p).await;
            let synced = me.sync().await;
            errors.push((me.slot, synced.errors));
            kept.deliver_again(me).await;
        }
        if crossing_settled(&p, &rel) {
            break;
        }
        assert!(round < 7, "the crossing did not settle: {errors:?}");
    }
    assert_crossing_settled(&p, &rel, before, (10, 7));
    for (kept, me) in copies.iter().zip([&p.b, &p.a]) {
        assert!(
            !kept.transfers.is_empty() && !kept.evidence.is_empty(),
            "{}: the peer's transfer halves were read and kept",
            me.slot
        );
        assert!(
            !kept.certificates.is_empty(),
            "{}: the peer's certificate was read and kept",
            me.slot
        );
        kept.deliver_again(me).await;
    }
    for _ in 0..2 {
        let b_sync = p.b.sync().await;
        let a_sync = p.a.sync().await;
        assert!(
            a_sync.success && b_sync.success,
            "{:?} {:?}",
            a_sync.errors,
            b_sync.errors
        );
    }
    assert_crossing_settled(&p, &rel, before, (10, 7));
}

/// Lost acknowledgments: while B applies A's transfer, enough members' spools
/// fail that B's acknowledgment reaches no quorum; while A applies B's, the
/// same. Each acknowledgment is sent again once the members serve, and both
/// sends settle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn crossing_sends_settle_when_their_acknowledgments_are_lost_and_sent_again() {
    let p = Pair::boot(1_000, 1_000).await;
    let rel = p.a.rel_key_with(&p.b);
    let before = (p.a.era_balance(), p.b.era_balance());
    crossed(&p, 10, 7).await;
    // Each device's re-drive delivers its own transfer.
    for device in [&p.a, &p.b] {
        let sync = device.sync().await;
        assert!(sync.success, "{}: {:?}", device.slot, sync.errors);
    }
    let breaking = crate::economic_fixtures::members_to_break_quorum();
    for device in [&p.b, &p.a] {
        p.nodes.fail_spools(&breaking).await;
        // The transfer is read from the members still serving; the
        // acknowledgment reaches no quorum.
        let sync = device.sync().await;
        assert_incomplete(&sync);
        p.nodes.restore_spools(&breaking).await;
        device.enter();
        assert_eq!(
            rows_for_relationship("canonical_apply_identity", &rel),
            1,
            "{} applied the crossing transfer",
            device.slot
        );
    }
    settle(&p, &rel, &p.a, &p.b).await;
    assert_crossing_settled(&p, &rel, before, (10, 7));
}

/// A restart during reconciliation: after B has applied A's transfer and
/// before either send has finalized, B restarts — a new router over its own
/// database — and the settlement goes on from what it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn crossing_sends_settle_across_a_restart_mid_reconciliation() {
    let mut p = Pair::boot(1_000, 1_000).await;
    let rel = p.a.rel_key_with(&p.b);
    let before = (p.a.era_balance(), p.b.era_balance());
    crossed(&p, 10, 7).await;
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    p.b.enter();
    assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 1);
    assert_eq!(
        proposal_statuses(&rel),
        vec![cdb::PROPOSAL_SUBMITTED.to_string()]
    );

    p.b.boot(&p.fleet).await;
    settle(&p, &rel, &p.a, &p.b).await;
    assert_crossing_settled(&p, &rel, before, (10, 7));
    generation(&p.a, &p.b, 5).await;
}

/// A tampered certificate of a crossing step releases nothing: once A has
/// finalized its send, its certificate is read off the members before B's
/// poll, and each field altered, then applied by hand on B — every one is
/// refused and B still awaits A's finality. The certificate as A signed it
/// then releases B, and both sends settle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_tampered_certificate_of_a_crossing_step_releases_nothing() {
    use prost::Message as _;
    let p = Pair::boot(1_000, 1_000).await;
    let rel = p.a.rel_key_with(&p.b);
    let before = (p.a.era_balance(), p.b.era_balance());
    crossed(&p, 10, 7).await;
    let mut certificate = None;
    for _ in 0..6 {
        let a_sync = p.a.sync().await;
        assert!(a_sync.success, "{:?}", a_sync.errors);
        p.a.enter();
        if proposal_statuses(&rel) == vec![cdb::PROPOSAL_FINALIZED.to_string()] {
            certificate = crate::test_support::arrivals::arrivals_for(&p.b, &p.fleet)
                .await
                .certificates
                .pop();
            break;
        }
        let b_sync = p.b.sync().await;
        assert!(b_sync.success, "{:?}", b_sync.errors);
    }
    let Some(certificate) = certificate else {
        panic!("A never finalized its crossing send");
    };
    let good = dsm::types::proto::RelationshipFinalizedV1::decode(certificate.body.as_slice())
        .expect("the certificate");
    p.b.enter();
    for field in 0..4 {
        let mut forged = good.clone();
        match field {
            0 => forged.sender_child_tip_a[0] ^= 1,
            1 => forged.recipient_parent_tip_b[0] ^= 1,
            2 => forged.recipient_child_tip_b[0] ^= 1,
            _ => forged.signature_a[0] ^= 1,
        }
        let out = crate::handlers::relationship_finalized::apply_relationship_finalized(
            &forged.encode_to_vec(),
        )
        .await;
        assert!(
            matches!(
                out,
                crate::handlers::relationship_finalized::RelationshipFinalizedOutcome::Rejected(_)
                    | crate::handlers::relationship_finalized::RelationshipFinalizedOutcome::NoJournal
            ),
            "field {field}: {out:?}"
        );
        assert!(
            cdb::relationship_awaits_peer_finalization(&rel).expect("await"),
            "field {field}: B still awaits A's finality"
        );
    }
    settle(&p, &rel, &p.a, &p.b).await;
    assert_crossing_settled(&p, &rel, before, (10, 7));
}

/// A send `device` froze for `rel` and could not deliver: its transfer
/// request and evidence half as the recipient would read them, with the ids
/// and route they were frozen under, and the parent it consumed.
struct FrozenSend {
    transfer: Vec<u8>,
    route: String,
    message_id: String,
    receipt: Vec<u8>,
    evidence_id: String,
    parent: [u8; 32],
}

/// The latest send `device` froze for `rel`, opened with `recipient`'s key
/// where the frozen bytes are sealed to it.
fn frozen_send(device: &TestDevice, recipient: &TestDevice, rel: &[u8; 32]) -> FrozenSend {
    device.enter();
    let (envelope, route, message_id, parent, evidence_envelope, evidence_id) = {
        let binding = cdb::get_connection().expect("conn");
        let conn = binding.lock().expect("the store lock");
        let (envelope, route, message_id, parent, nonce): (
            Vec<u8>,
            String,
            String,
            Vec<u8>,
            Vec<u8>,
        ) = conn
            .query_row(
                "SELECT envelope_bytes, routing_address, submission_id, canonical_parent, \
                 proposal_nonce FROM sender_outbox WHERE relationship_key = ?1 \
                 ORDER BY rowid DESC LIMIT 1",
                rusqlite::params![rel.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("the frozen send");
        let (evidence_envelope, evidence_id): (Vec<u8>, String) = conn
            .query_row(
                "SELECT envelope_bytes, submission_id FROM sender_outbox_artifacts \
                 WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3 \
                 AND role = 'evidence_a'",
                rusqlite::params![rel.as_slice(), parent, nonce],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("its frozen evidence half");
        (
            envelope,
            route,
            message_id,
            parent,
            evidence_envelope,
            evidence_id,
        )
    };
    recipient.enter();
    let body = |bytes: &[u8]| -> Vec<u8> {
        let outer = dsm::envelope::from_canonical_bytes(bytes).expect("a frozen envelope");
        let inner = match outer.payload {
            Some(generated::envelope::Payload::Sealed(_)) => crate::sdk::b0x_sdk::open_sealed(
                &crate::sdk::b0x_sdk::local_kyber_secret().expect("the recipient's key"),
                &outer,
            )
            .expect("the recipient opens it"),
            _ => outer,
        };
        let Some(generated::envelope::Payload::UniversalTx(tx)) = inner.payload else {
            panic!("a frozen send carries a UniversalTx");
        };
        tx.ops
            .into_iter()
            .find_map(|op| match op.kind {
                Some(generated::universal_op::Kind::Invoke(invoke)) => {
                    invoke.args.map(|args| args.body)
                }
                _ => None,
            })
            .expect("an invoke with its request")
    };
    let receipt = generated::ReceiptEvidenceA::decode(body(&evidence_envelope).as_slice())
        .expect("the evidence half")
        .full_receipt_bytes;
    FrozenSend {
        transfer: body(&envelope),
        route,
        message_id,
        receipt,
        evidence_id,
        parent: <[u8; 32]>::try_from(parent.as_slice()).expect("a 32-byte parent"),
    }
}

/// Conflicting transfers from one parent: A's device is copied before it
/// sends, and while A's transfer crosses B's, the copy sends B another
/// transfer from the same parent. The copy's own wallet cannot deliver it —
/// its economic admission finds the position A's send holds — so the copy's
/// frozen transfer and evidence are handed to B's ingestion directly, as a
/// copy running other software can post them. B applies exactly one transfer
/// from that parent — A's — and never the copy's; A's and B's crossing sends
/// settle, and B is credited A's amount once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_second_transfer_from_the_same_parent_never_applies_beside_a_crossing() {
    let p = Pair::boot(1_000, 1_000).await;
    let rel = p.a.rel_key_with(&p.b);
    let before = (p.a.era_balance(), p.b.era_balance());
    let mut copy = p.a.backed_up_into("A_COPY");
    crossed(&p, 10, 7).await;
    // A's transfer reaches the members first.
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    // The copy sends from the parent A sent from, before it can see B's
    // transfer: its spools have failed, as A's had.
    copy.boot(&p.fleet).await;
    let members = crate::economic_fixtures::canonical_member_ids();
    p.nodes.fail_spools(&members).await;
    let forked = copy.send(&p.b, 4).await;
    p.nodes.restore_spools(&members).await;
    assert!(
        forked
            .error_message
            .as_deref()
            .is_some_and(|e| e.contains("held by another root claim")),
        "the copy's admission finds A's position held: {:?}",
        forked.error_message
    );
    let fork = frozen_send(&copy, &p.b, &rel);
    let a_b32 = crate::util::text_id::encode_base32_crockford(&p.a.device_id);
    p.b.enter();
    let transfer = crate::handlers::recipient_dispatch::ingest_transfer_half(
        &fork.transfer,
        &a_b32,
        &fork.route,
        &fork.message_id,
    )
    .expect("B reads the copy's transfer");
    let evidence = crate::handlers::recipient_dispatch::ingest_evidence_half(
        &fork.receipt,
        &fork.route,
        &fork.evidence_id,
    )
    .expect("B reads the copy's evidence");
    // Both halves verify under A's key and are staged; staging executes nothing.
    for (half, outcome) in [("transfer", &transfer), ("evidence", &evidence)] {
        assert!(
            matches!(
                outcome.ingested,
                crate::handlers::recipient_dispatch::Ingested::Staged
            ),
            "the copy's {half} half is staged: {outcome:?}"
        );
    }

    settle(&p, &rel, &p.a, &p.b).await;
    p.b.enter();
    assert_eq!(
        applied_signed_parents(&rel).first(),
        Some(&fork.parent),
        "the copy's transfer consumes the parent A's applied transfer consumed"
    );
    assert_eq!(
        p.a.era_balance(),
        before.0 - 10 + 7,
        "A paid 10 and was paid 7"
    );
    assert_eq!(
        p.b.era_balance(),
        before.1 + 10 - 7,
        "B credited A's amount once, never the copy's"
    );
    p.b.enter();
    assert_eq!(
        applied_signed_parents(&rel).len(),
        1,
        "B applied one transfer from A's parent"
    );
    for me in [&p.a, &p.b] {
        me.enter();
        assert_eq!(
            proposal_statuses(&rel),
            vec![cdb::PROPOSAL_FINALIZED.to_string()],
            "{}'s crossing send finalized",
            me.slot
        );
    }
    // The copy's staged transfer holds nothing: B is send-ready toward A and
    // the relationship carries the next transfer each way.
    p.b.enter();
    assert!(send_status(&p.a).send_ready, "B is send-ready toward A");
    generation(&p.b, &p.a, 3).await;
    generation(&p.a, &p.b, 2).await;
}

/// A lone transfer half from a copy: as above, but the copy posts only its
/// transfer, never the evidence that would bind it to a step. Staged and
/// unbound, it waits on a receipt that will not come; once the crossing has
/// moved B's tip past the one its nonce derives from it can never execute,
/// and it holds nothing: B is send-ready toward A and the relationship
/// carries the next transfer each way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_lone_transfer_half_from_a_copy_holds_nothing_once_it_cannot_execute() {
    let p = Pair::boot(1_000, 1_000).await;
    let rel = p.a.rel_key_with(&p.b);
    let before = (p.a.era_balance(), p.b.era_balance());
    let mut copy = p.a.backed_up_into("A_COPY");
    crossed(&p, 10, 7).await;
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    copy.boot(&p.fleet).await;
    let members = crate::economic_fixtures::canonical_member_ids();
    p.nodes.fail_spools(&members).await;
    let forked = copy.send(&p.b, 4).await;
    p.nodes.restore_spools(&members).await;
    assert!(
        forked
            .error_message
            .as_deref()
            .is_some_and(|e| e.contains("held by another root claim")),
        "the copy's admission finds A's position held: {:?}",
        forked.error_message
    );
    let fork = frozen_send(&copy, &p.b, &rel);
    let a_b32 = crate::util::text_id::encode_base32_crockford(&p.a.device_id);
    p.b.enter();
    let transfer = crate::handlers::recipient_dispatch::ingest_transfer_half(
        &fork.transfer,
        &a_b32,
        &fork.route,
        &fork.message_id,
    )
    .expect("B reads the copy's transfer");
    assert!(
        matches!(
            transfer.ingested,
            crate::handlers::recipient_dispatch::Ingested::Staged
        ),
        "the copy's transfer half is staged: {transfer:?}"
    );

    settle(&p, &rel, &p.a, &p.b).await;
    assert_crossing_settled(&p, &rel, before, (10, 7));
    generation(&p.b, &p.a, 3).await;
    generation(&p.a, &p.b, 2).await;
}

mod model_correspondence;
