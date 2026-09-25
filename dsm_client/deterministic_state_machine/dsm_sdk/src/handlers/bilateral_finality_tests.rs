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
    assert_eq!(p.b.era_balance(), 120);

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
    assert_eq!(p.b.era_balance(), 115);
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
    assert_eq!(p.a.era_balance(), 990, "no second debit");

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
    assert_eq!(p.a.era_balance(), 990, "no second debit");

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
    assert_eq!(p.a.era_balance(), 990, "no second debit");
    let mut copies = 0;
    for node in &p.nodes.nodes {
        for spooled in node.spool().await {
            if spooled.message_id == frozen_id {
                copies += 1;
                assert_eq!(
                    spooled.envelope, frozen_seal,
                    "byte-identical to the frozen envelope"
                );
                assert_eq!(spooled.address, frozen_route, "under the frozen route");
            }
        }
    }
    assert_eq!(
        copies,
        crate::economic_fixtures::delivery_quorum(),
        "the delivery quorum holds the frozen certificate, once each"
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
        assert_eq!(p.b.era_balance(), 10, "pass {pass}: held, not applied");
        p.b.enter();
        assert_eq!(rows_for_relationship("canonical_apply_identity", &rel), 1);
        assert_eq!(
            staging_states(),
            vec!["accepted".to_string(), "ready_to_verify".to_string()],
            "held at ready_to_verify — not rejected, not accepted"
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
        vec!["accepted".to_string(), "accepted".to_string()]
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
