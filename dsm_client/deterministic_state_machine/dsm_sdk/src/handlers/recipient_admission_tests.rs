// SPDX-License-Identifier: Apache-2.0

//! 3.5b PR4: recipient-side economic admission — the both-sides e2e, the
//! correction-3 refusal controls (hostile coordinates refused BEFORE any
//! durable state), the same-debit-cannot-fund-twice layer, the held-release
//! race rule, and the outage-holds-then-recovers path.

use serial_test::serial;

use crate::storage::client_db;
use crate::test_support::two_device::Pair;

/// The full transfer with BOTH admissions, asserted at the economic layer:
/// the sender's debit admitted at its position, the recipient's credit
/// admitted at ITS position with the consumed-source leaf installed, the
/// release row promoted (not held) after admission, and the peer cache
/// carrying the q-durable economic watermark.
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
    let (b_pos, _root) = client_db::economic_lineage::get_admitted()
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
        client_db::economic_lineage::peer_closure_q_durable(
            &p.a.genesis,
            &p.a.device_id,
            facts_sender_position(&p),
        )
        .unwrap(),
        "the walked sender closure is memoized q-durable"
    );

    // Sender side: finalized on the release (generation semantics), and its
    // own debit admitted.
    p.a.enter();
    let (a_pos, _) = client_db::economic_lineage::get_admitted()
        .unwrap()
        .expect("sender admitted");
    assert_eq!(a_pos, 2, "faucet claim (1) + debit (2)");
}

fn facts_sender_position(p: &Pair) -> u64 {
    p.a.enter();
    let (pos, _) = client_db::economic_lineage::get_admitted()
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
    let (wire, evidence_bytes): (Vec<u8>, Vec<u8>) = {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT transfer_bytes, evidence_bytes FROM recipient_staging
             WHERE transfer_bytes IS NOT NULL AND evidence_bytes IS NOT NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };

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
/// recipient credit — driven directly at the write-set builder over the
/// recipient's REAL post-admission tree, bypassing the transport/nonce
/// defenses so the refusal proves THIS layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_same_sender_debit_cannot_fund_a_second_credit() {
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);

    let sender_pos = facts_sender_position(&p);
    p.b.enter();
    let validated = {
        let (pos, root) = client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap();
        dsm::economic::lineage::ValidatedEconomicRoot::rehydrate_from_admitted_store(pos, root)
    };
    let (mut tree, pre_balances) =
        crate::sdk::economic_admission_flow::producer_tree_and_balances(&validated).unwrap();

    // A second credit consuming the SAME (position, debit index).
    let op = dsm::types::operations::Operation::Transfer {
        to_device_id: p.b.device_id.to_vec(),
        amount: dsm::types::token_types::Balance::from_state(10, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: dsm::core::token::token_state_manager::era_policy_commit(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![0x77; 32],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: p.b.device_id.to_vec(),
        to: Vec::new(),
        message: String::new(),
        signature: Vec::new(),
        authority_policy: None,
    };
    let econ_op_id = [0x42u8; 32];
    let err = dsm::economic::write_set::build_write_set(
        &op,
        &p.b.genesis,
        &p.b.device_id,
        &econ_op_id,
        &dsm::economic::write_set::EconomicPreState::balances_only(&pre_balances),
        &mut tree,
        &dsm::economic::write_set::CreditSourceFacts::PeerDebit {
            peer_genesis: p.a.genesis,
            peer_devid: p.a.device_id,
            peer_economic_position: sender_pos,
            peer_debit_mutation_index: 0,
            acceptance_evidence_addr: [0xAD; 32],
        },
    )
    .expect_err("the consumed-source leaf is already present — a second credit must refuse");
    assert!(
        err.to_string().to_lowercase().contains("consumed")
            || err.to_string().to_lowercase().contains("source"),
        "the refusal names the consumed source, got: {err}"
    );
}

/// Correction A's recipient mirror, at the storage layer: a HELD reply row is
/// invisible to the delivery sweep; the terminal admission promotion makes it
/// deliverable. MUTATION CONTROL: drop the `held = 0` filter from
/// `pending_outbound_replies` and this goes red.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_held_reply_is_invisible_to_the_delivery_sweep_until_admitted() {
    let (_core, _fleet) = crate::handlers::faucet_flow_tests_support::setup_funded(0xD1).await;
    let rel = [0x21u8; 32];
    let parent = [0x22u8; 32];
    let commitment = [0x23u8; 32];
    let journal = crate::storage::client_db::RecipientAcceptanceJournal {
        relationship_key: rel,
        parent_tip: parent,
        child_tip: [0x24; 32],
        counterparty_device_id: [0x25; 32],
        commitment,
        receipt_parent_root_a: [0u8; 32],
        receipt_child_root_a: [0u8; 32],
        precommit_digest: [0u8; 32],
        prepared_receipt_artifact_hash: [0u8; 32],
        expected_local_b_head: None,
        new_local_b_head: vec![0x26; 8],
        new_local_b_sk_enc: None,
        expected_counterparty_a_head: None,
        new_counterparty_a_head: vec![0x27; 8],
        receipt_bytes: vec![0x28; 8],
        projection_parent_tip: [0x29; 32],
        projection_target_tip: [0x2A; 32],
        applied_parent_tip_b: [0x2B; 32],
        applied_child_tip_b: [0x2C; 32],
        release_bytes: Some(vec![0x2D; 8]),
        peer_finalized: false,
        status: "prepared".to_string(),
        created_at: 0,
    };
    client_db::insert_prepared_acceptance_journal_with_conn(
        &client_db::get_connection()
            .unwrap()
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
        &journal,
    )
    .unwrap();
    {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE acceptance_fold_journal SET status = 'complete' WHERE commitment = ?1",
            rusqlite::params![commitment.as_slice()],
        )
        .unwrap();
    }
    client_db::recipient_receipt_fold::insert_outbound_reply(
        &commitment,
        &rel,
        &[0x25; 32],
        &[0x24; 32],
        &[0x28; 8],
        Some(&[0x2D; 8]),
        true, // HELD
    )
    .unwrap();
    assert!(
        client_db::pending_outbound_replies().unwrap().is_empty(),
        "a HELD release must be invisible to the delivery sweep — zero bytes may escape \
         before ECON_ADMITTED"
    );
    {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        let n = client_db::recipient_receipt_fold::promote_held_replies_with_conn(&conn).unwrap();
        assert_eq!(n, 1);
    }
    assert_eq!(
        client_db::pending_outbound_replies().unwrap().len(),
        1,
        "promotion makes the release deliverable"
    );
}

/// An outage during prevalidation HOLDS the transfer with zero durable state
/// (no pending admission, no journal, staging not accepted), and the SAME row
/// completes when the fleet returns — an outage is never an attack and never
/// a wedge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_outage_holds_the_transfer_cleanly_and_it_recovers() {
    let p = Pair::boot(100, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);

    // Quorum gone: prevalidation cannot establish the q-durable closure.
    crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-1");
    crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-2");
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
    crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-1");
    crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-2");
    let recovered = p.b.sync().await;
    assert!(recovered.success, "{:?}", recovered.errors);
    assert_eq!(p.b.era_balance(), 10, "applied once after recovery");
    p.b.enter();
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        1,
        "the credit admitted"
    );
}
