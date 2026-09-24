// SPDX-License-Identifier: Apache-2.0

//! Recipient-side economic admission: the both-sides e2e, the refusal
//! controls (hostile coordinates refused BEFORE any durable state), the
//! same-debit-cannot-fund-twice layer, and the outage-holds-then-recovers
//! path — two devices on the network's pinned set of storage nodes, every
//! fault a node that stops serving.

use serial_test::serial;

use crate::storage::client_db;
use crate::test_support::two_device::{Pair, TestDevice};

/// The transfer halves `B` staged on receipt — its transfer request and A's
/// receipt evidence, exactly as delivered.
fn staged_halves() -> (Vec<u8>, Vec<u8>) {
    let binding = client_db::get_connection().expect("device db");
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    conn.query_row(
        "SELECT transfer_bytes, evidence_bytes FROM recipient_staging
         WHERE transfer_bytes IS NOT NULL AND evidence_bytes IS NOT NULL",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("the staged halves")
}

/// ADOPTION PRECEDES RECEIPT (owner ruling 2026-09-13). A receiver that never
/// ADDED a token is not credited when that token is sent to it — the policy it
/// would validate against is not in its own committed state, and nothing may
/// fetch it on the receiver's behalf at acceptance time. After the receiver
/// adopts through the production route (the leaf lands on its head), the same
/// asset credits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receiver_that_never_added_the_token_is_not_credited_until_it_adopts() {
    use crate::bridge::AppRouter;
    let p = Pair::boot(100, 0).await;
    // A REAL creation on A: fee burned, the whole genesis supply released to
    // A in the same admitted transition.
    p.a.enter();
    let pc = crate::economic_fixtures::create_asset(p.a.router(), "ADPT", 0, 1_000).await;
    let head_balance = |d: &TestDevice| {
        d.enter();
        d.router()
            .core_sdk
            .device_head()
            .expect("a booted device has a head")
            .balance(&pc)
    };
    assert_eq!(head_balance(&p.a), 1_000, "A holds what it issued");
    p.b.enter();
    assert!(
        !p.b.router()
            .core_sdk
            .device_head()
            .expect("B head")
            .has_adopted(&pc),
        "precondition: B never added ADPT"
    );

    p.a.enter();
    let sent = p.a.send_token(&p.b, "ADPT", 100).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let refused_sync = p.b.sync().await;
    assert!(refused_sync.success, "{:?}", refused_sync.errors);
    assert_eq!(
        head_balance(&p.b),
        0,
        "B is not credited a token it never adopted"
    );

    // B adopts through the production route: the adoption leaf is committed
    // to B's head (root moves), no ERA is spent.
    p.b.enter();
    let era_before = p.b.era_balance();
    let root_before = p.b.router().core_sdk.device_head().expect("B head").root();
    let adopted =
        p.b.router()
            .query(crate::bridge::AppQuery {
                path: "tokens.addByAnchor".to_string(),
                params: crate::util::text_id::encode_base32_crockford(&pc).into_bytes(),
            })
            .await;
    assert!(
        adopted.success,
        "B adopts ADPT: {:?}",
        adopted.error_message
    );
    let head = p.b.router().core_sdk.device_head().expect("B head");
    assert!(head.has_adopted(&pc), "the adoption leaf is on B's head");
    assert_ne!(head.root(), root_before, "adoption is a committed advance");
    assert_eq!(p.b.era_balance(), era_before, "adoption costs no ERA");

    // The HELD transfer now applies on B's next sync — a refusal for want of
    // adoption is an outage shape, not a wedge: nothing is resent, the same
    // frozen halves credit once the precondition holds.
    p.b.enter();
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(head_balance(&p.b), 100, "credited once B adopted");
}

/// The full transfer with BOTH admissions, asserted at the economic layer:
/// the sender's debit admitted at its position, the recipient's credit
/// admitted at ITS position with the consumed-source leaf installed, the
/// release row promoted (not held) after admission, and the peer cache
/// carrying the Stored economic watermark.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_transfer_admits_on_both_sides_with_a_register_backed_release() {
    let p = Pair::boot(100, 0).await;
    let rel = p.a.rel_key_with(&p.b);

    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(p.b.era_balance(), 10, "credited once");

    // Recipient side: credit ADMITTED at position 1 (fresh activation),
    // unfenced, with the release promoted to deliverable.
    p.b.enter();
    let (b_pos, _root) = client_db::economic_lineage::get_admitted_coordinate()
        .unwrap()
        .expect("the recipient credit is admitted before anything is deliverable");
    assert_eq!(b_pos, 1);
    assert!(
        p.b.router()
            .core_sdk
            .device_head()
            .unwrap()
            .pending_economic_admission()
            .is_none(),
        "unfenced after admission"
    );
    let (held, release): (i64, Option<Vec<u8>>) = {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT held, release_bytes FROM recipient_outbound_reply
             WHERE relationship_key = ?1",
            rusqlite::params![rel.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(held, 0, "the terminal admission promoted the held reply");
    let release = release.expect("the reply carries the signed release");
    let facts = dsm::economic::release::verify_recipient_economic_release(&release, &p.b.ak_pk)
        .expect("the frozen release verifies under the recipient AK");
    assert_eq!(facts.recipient_economic_position, 1);
    assert_eq!(facts.recipient_devid, p.b.device_id);

    // The economic watermark for the SENDER's walked closure.
    assert!(
        client_db::economic_lineage::peer_closure_stored(
            &p.a.genesis,
            &p.a.device_id,
            facts_sender_position(&p),
        )
        .unwrap(),
        "the walked sender closure is memoized Stored"
    );

    // Sender side: finalized on the release (generation semantics), and its
    // own debit admitted.
    p.a.enter();
    let (a_pos, _) = client_db::economic_lineage::get_admitted_coordinate()
        .unwrap()
        .expect("sender admitted");
    assert_eq!(a_pos, 2, "faucet claim (1) + debit (2)");
}

fn facts_sender_position(p: &Pair) -> u64 {
    p.a.enter();
    let (pos, _) = client_db::economic_lineage::get_admitted_coordinate()
        .unwrap()
        .expect("sender admitted");
    p.b.enter();
    pos
}

/// THE correction-3 control: hostile sender coordinates are refused BEFORE
/// any durable recipient state. A fabricated debit index (the validated
/// position exists; the named mutation is not the operation's debit) is
/// TERMINAL; a nonexistent position (no register winner) is an outage shape
/// and merely holds. Neither leaves a pending admission, a journal row, or
/// an admitted coordinate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn fabricated_sender_coordinates_are_refused_before_any_durable_state() {
    use crate::sdk::economic_admission_flow::{
        prevalidate_incoming_transfer_admission, PrevalidationRefusal,
    };
    use prost::Message;

    let p = Pair::boot(100, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    // A REAL settled generation first: A's debit is registered and walkable.
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);

    // The exact frozen halves as the RECIPIENT staged them — what production
    // prevalidation actually consumes.
    p.b.enter();
    let (wire, evidence_bytes) = staged_halves();

    let durable_state_is_clean = |p: &Pair| {
        p.b.enter();
        assert!(
            p.b.router()
                .core_sdk
                .device_head()
                .unwrap()
                .pending_economic_admission()
                .is_none(),
            "no pending admission may exist"
        );
    };

    p.b.enter();
    let sender_ak = p.a.ak_pk.clone();

    // Fabricated debit index: TERMINAL, nothing durable. (The real transfer
    // already applied, so the admitted coordinate stays at 1 throughout.)
    let mut tampered = dsm::types::proto::OnlineTransferRequest::decode(wire.as_slice()).unwrap();
    tampered.sender_debit_mutation_index = 7;
    let refusal = prevalidate_incoming_transfer_admission(
        &p.b.router().core_sdk,
        &p.a.genesis,
        &p.a.device_id,
        &sender_ak,
        &tampered.encode_to_vec(),
        &evidence_bytes,
        &rel,
    )
    .await
    .map(|_| ())
    .expect_err("a fabricated debit index must refuse");
    assert!(
        matches!(&refusal, PrevalidationRefusal::Terminal(m) if m.contains("debit")),
        "terminal refusal naming the debit, got: {refusal}"
    );
    durable_state_is_clean(&p);

    // Nonexistent position: an outage shape — HELD, never terminal, nothing
    // durable, no permanent fence.
    let mut ghost = dsm::types::proto::OnlineTransferRequest::decode(wire.as_slice()).unwrap();
    ghost.sender_economic_position += 40;
    p.b.enter();
    let refusal = prevalidate_incoming_transfer_admission(
        &p.b.router().core_sdk,
        &p.a.genesis,
        &p.a.device_id,
        &sender_ak,
        &ghost.encode_to_vec(),
        &evidence_bytes,
        &rel,
    )
    .await
    .map(|_| ())
    .expect_err("a nonexistent position cannot prevalidate");
    assert!(
        matches!(refusal, PrevalidationRefusal::Incomplete(_)),
        "absence of a register winner is indistinguishable from an outage — held, got: {refusal}"
    );
    durable_state_is_clean(&p);
}

/// The consumed-source layer: the SAME sender debit cannot fund a second
/// recipient credit. B's credited transfer — the exact signed operation B
/// staged, its sender coordinates, and the acceptance bundle B froze for it —
/// is built again at the write-set builder over B's REAL post-admission tree,
/// past the transport and nonce defenses, so the refusal proves THIS layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_same_sender_debit_cannot_fund_a_second_credit() {
    use prost::Message;
    let p = Pair::boot(100, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(p.b.era_balance(), 10, "credited once");

    p.b.enter();
    let wire = staged_halves().0;
    let transfer = dsm::types::proto::OnlineTransferRequest::decode(wire.as_slice())
        .expect("the staged transfer request");
    let op = dsm::types::operations::Operation::decode_and_bind_signed(
        &transfer.canonical_operation_bytes,
        &transfer.signature,
        &p.a.ak_pk,
    )
    .expect("the staged operation is A's signed transfer");
    let bundle =
        client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
            &format!(
                "immutable::{}::",
                String::from_utf8_lossy(
                    dsm::common::domain_tags::TAG_DSM_PEER_TRANSFER_ACCEPTANCE.source_bytes()
                )
            ),
            "peer-transfer-acceptance",
        )
        .expect("frozen artifacts")
        .expect("B froze the acceptance bundle of the credit");
    let head = p.b.router().core_sdk.device_head().expect("B head");
    let econ_op_id = dsm::economic::admission::dsm_economic_operation_id(
        &p.b.genesis,
        &p.b.device_id,
        &head
            .chain_tip(&rel)
            .expect("B's relationship with A has a tip"),
    );
    let validated = {
        let admitted = client_db::economic_lineage::get_admitted()
            .expect("read admitted")
            .expect("B's credit is admitted");
        dsm::economic::lineage::ValidatedEconomicRoot::rehydrate_from_admitted_store(admitted)
            .expect("an ordinary admitted position")
    };
    let (mut tree, pre_state) =
        crate::sdk::economic_admission_flow::producer_tree_and_pre_state(&validated)
            .expect("B's producer tree");

    let err = dsm::economic::write_set::build_write_set(
        &op,
        &p.b.genesis,
        &p.b.device_id,
        &econ_op_id,
        &pre_state.as_write_set_pre_state(),
        &mut tree,
        &dsm::economic::write_set::CreditSourceFacts::PeerDebit {
            peer_genesis: p.a.genesis,
            peer_devid: p.a.device_id,
            peer_economic_position: transfer.sender_economic_position,
            peer_debit_mutation_index: transfer.sender_debit_mutation_index,
            acceptance_evidence_addr: dsm::economic::peer_acceptance::acceptance_evidence_addr(
                &bundle,
            ),
        },
    )
    .expect_err("the consumed-source leaf is already present — a second credit must refuse");
    assert_eq!(
        err,
        dsm::economic::write_set::WriteSetError::SourceAlreadyConsumed,
        "the refusal is the consumed source"
    );
}

/// An outage during prevalidation HOLDS the transfer with zero durable state
/// (no pending admission, no journal, staging not accepted), and the SAME row
/// completes when the fleet returns — an outage is never an attack and never
/// a wedge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_outage_holds_the_transfer_cleanly_and_it_recovers() {
    let mut p = Pair::boot(100, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);

    // Quorum gone: prevalidation cannot establish the Stored closure.
    let down = crate::economic_fixtures::members_to_break_quorum();
    p.nodes.take_down(&down).await;
    let held_sync = p.b.sync().await;
    assert!(held_sync.success, "{:?}", held_sync.errors);
    assert_eq!(p.b.era_balance(), 0, "nothing credited under the outage");
    p.b.enter();
    assert!(
        p.b.router()
            .core_sdk
            .device_head()
            .unwrap()
            .pending_economic_admission()
            .is_none(),
        "no pending admission during the hold"
    );
    assert_eq!(
        {
            let binding = client_db::get_connection().unwrap();
            let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
            conn.query_row(
                "SELECT COUNT(*) FROM acceptance_fold_journal WHERE relationship_key = ?1",
                rusqlite::params![rel.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
        },
        0,
        "no journal row during the hold"
    );

    // Fleet back: the SAME row proceeds through the full admission.
    p.nodes.bring_up(&down).await;
    let recovered = p.b.sync().await;
    assert!(recovered.success, "{:?}", recovered.errors);
    assert_eq!(p.b.era_balance(), 10, "applied once after recovery");
    p.b.enter();
    assert_eq!(
        client_db::economic_lineage::get_admitted_coordinate()
            .unwrap()
            .unwrap()
            .0,
        1,
        "the credit admitted"
    );
}
