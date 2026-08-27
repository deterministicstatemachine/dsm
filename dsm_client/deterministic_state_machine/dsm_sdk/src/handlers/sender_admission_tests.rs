// SPDX-License-Identifier: Apache-2.0

//! 3.5b PR3: the generalized admission seam under ordinary operations —
//! admitted Burn through the self-loop helper, the multi-step foreign walk,
//! the admission serialization (correction B), and the held-outbox rule
//! (correction A).

use serial_test::serial;

use crate::bridge::AppRouter;
use crate::handlers::faucet_flow_tests_support::{setup_funded, NETWORK};
use crate::sdk::economic_admission_flow::admitted_self_loop_operation;
use crate::storage::client_db;

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn burn_op(amount: u64) -> dsm::types::operations::Operation {
    dsm::types::operations::Operation::Burn {
        amount: dsm::types::token_types::Balance::from_state(amount, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: era(),
        proof_of_ownership: Vec::new(),
        message: String::new(),
    }
}

fn burn_delta(amount: u64) -> dsm::types::device_state::BalanceDelta {
    dsm::types::device_state::BalanceDelta {
        policy_commit: era(),
        direction: dsm::types::device_state::BalanceDirection::Debit,
        amount,
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn an_admitted_burn_advances_the_lineage_and_is_foreign_walkable() {
    // Faucet position 1 (+100), then an ADMITTED burn of 40 at position 2 —
    // the first ordinary economic operation through the generalized seam.
    // Then the decisive check: a FOREIGN walk of positions 1..2, crossing a
    // faucet credit AND a pure debit in one lineage.
    let (core, _fleet) = setup_funded(0xC1).await;
    let (outcome, admitted) =
        admitted_self_loop_operation(&core, burn_op(40), burn_delta(40), None)
            .await
            .expect("admitted burn");
    assert_eq!(admitted.economic_position, 2);
    assert_eq!(outcome.new_device_state.balance(&era()), 60);
    let head = core.device_head().expect("head");
    assert!(head.pending_economic_admission().is_none(), "unfenced");
    let (position, admitted_root) = client_db::economic_lineage::get_admitted()
        .unwrap()
        .expect("admitted");
    assert_eq!(position, 2);

    let (genesis, devid) = (head.genesis_digest(), head.devid());
    client_db::economic_lineage::clear_peer_lineage(&genesis, &devid).unwrap();
    let handle = tokio::runtime::Handle::current();
    let peer = tokio::task::spawn_blocking(move || {
        use dsm::economic::provenance::ProvenanceResolver;
        let profile =
            dsm::economic::register::resolve_root_register_profile(NETWORK).expect("profile");
        let set = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .resolve(&profile.storage_set_id)
            .cloned()
            .expect("canonical set");
        let resolver = crate::sdk::economic_registers::LiveRegisterResolver {
            set: &set,
            runtime: handle,
            expected_network_id: NETWORK.to_vec(),
        };
        resolver.validated_peer_transition(&genesis, &devid, 2)
    })
    .await
    .expect("join")
    .expect("a two-step lineage (credit then debit) MUST be foreign-walkable");
    assert_eq!(peer.validated_root.economic_position(), 2);
    assert_eq!(peer.validated_root.economic_root(), admitted_root);
    assert!(matches!(
        peer.verified_operation,
        dsm::types::operations::Operation::Burn { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_stale_admission_snapshot_is_refused_not_committed() {
    // Correction B: the seam CAS-checks the admitted predecessor UNDER the
    // lock. A prepared admission built from a stale coordinate (position 1
    // after position 1 already admitted) must refuse, never overwrite.
    let (core, _fleet) = setup_funded(0xC2).await;
    let head = core.device_head().unwrap();
    let stale = dsm::economic::admission::PendingEconomicAdmission::prepared(
        dsm::economic::admission::PendingAdmissionKind::DsmBacked,
        1, // already admitted
        dsm::economic::tree::empty_economic_root(),
        dsm::economic::faucet::dsm_operation_digest(&burn_op(1).to_bytes()),
    );
    let _ = head;
    let err = core
        .faucet_claim_advance(
            burn_op(1),
            &burn_delta(1),
            stale,
            |_| unreachable!("build must not run for a refused admission"),
            &[0u8; 32],
            None,
        )
        .expect_err("stale predecessor must refuse");
    assert!(
        err.to_string()
            .contains("does not extend the admitted coordinate"),
        "got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_held_outbox_row_is_invisible_to_the_resubmit_sweep_until_admitted() {
    // Correction A's load-bearing rule at the storage layer: a row in
    // `economic_admission_pending` is NOT an unsettled row — the sweep
    // cannot see it, so it cannot deliver it. The terminal admission
    // transaction promotes it; only then is it deliverable.
    let (_core, _fleet) = setup_funded(0xC3).await;
    let held = crate::storage::client_db::SenderOutboxRecord {
        relationship_key: [0x11; 32],
        canonical_parent: [0x22; 32],
        proposal_nonce: [0x33; 32],
        canonical_child: [0x44; 32],
        commitment: [0x55; 32],
        projection_parent: [0x66; 32],
        projection_target: [0x77; 32],
        routing_address: "route".into(),
        submission_id: "held-row-test".into(),
        envelope_bytes: vec![0xEE; 8],
        local_expected_prev: None,
        is_first_ek_step: true,
        status: client_db::OUTBOX_ECONOMIC_ADMISSION_PENDING.to_string(),
        message_ids: None,
        created_at: 0,
    };
    {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        client_db::insert_sender_outbox_with_conn(&conn, &held).unwrap();
    }
    let unsettled = client_db::unsettled_sender_outbox().unwrap();
    assert!(
        unsettled.iter().all(|r| r.submission_id != "held-row-test"),
        "a HELD row must be invisible to the resubmit sweep — zero transfer bytes \
         may be emitted before ECON_ADMITTED"
    );
    // Promotion makes it deliverable.
    {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let n = client_db::sender_outbox::promote_held_outbox_rows_with_conn(&conn).unwrap();
        assert_eq!(n, 1);
    }
    let unsettled = client_db::unsettled_sender_outbox().unwrap();
    assert!(unsettled.iter().any(|r| r.submission_id == "held-row-test"));
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sequential_admissions_stay_monotonic_across_operation_kinds() {
    // Faucet claim, burn, burn — three admissions, three kinds of witness
    // content, one strictly monotonic lineage.
    let (core, _fleet) = setup_funded(0xC4).await;
    let (_o, a2) = admitted_self_loop_operation(&core, burn_op(10), burn_delta(10), None)
        .await
        .expect("burn 1");
    assert_eq!(a2.economic_position, 2);
    let (_o, a3) = admitted_self_loop_operation(&core, burn_op(20), burn_delta(20), None)
        .await
        .expect("burn 2");
    assert_eq!(a3.economic_position, 3);
    assert_eq!(core.device_head().unwrap().balance(&era()), 70);
}

#[test]
fn online_transfer_request_locators_round_trip_on_the_wire() {
    // The tag-31 lesson: every wire change owes its inverse immediately. The
    // 3.5b locator fields (13/14) must survive encode → decode exactly, with
    // values distinctive enough that a dropped field cannot alias a default.
    use prost::Message;
    let req = crate::generated::OnlineTransferRequest {
        token_id: "ERA".to_string(),
        to_device_id: vec![0x11; 32],
        amount: 40,
        memo: String::new(),
        signature: vec![0x22; 8],
        nonce: vec![0x33; 32],
        from_device_id: vec![0x44; 32],
        chain_tip: Vec::new(),
        seq: 7,
        canonical_operation_bytes: vec![0x55; 16],
        receipt_evidence_digest: vec![0x66; 32],
        sender_economic_position: 0x0102_0304_0506_0708,
        sender_debit_mutation_index: 0x0A0B_0C0D,
    };
    let bytes = req.encode_to_vec();
    let back = crate::generated::OnlineTransferRequest::decode(bytes.as_slice())
        .expect("decode must succeed");
    assert_eq!(back, req, "every field must survive the round trip");
    assert_eq!(back.sender_economic_position, 0x0102_0304_0506_0708);
    assert_eq!(back.sender_debit_mutation_index, 0x0A0B_0C0D);
    assert_eq!(
        back.encode_to_vec(),
        bytes,
        "re-encode must be byte-identical"
    );
}

/// The route-level coverage the integration suites lost when creation's fee
/// became an ADMITTED debit (integration tests have no fake fleet): the
/// fee-only creation end to end, its anchor contract, reconciliation, the
/// named creator-supply refusal, and the admitted burn route — one funded
/// device, one lineage, every position accounted for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn token_routes_admit_fee_only_create_and_burn_end_to_end() {
    use prost::Message;
    let p = crate::test_support::two_device::Pair::boot(100, 0).await;
    p.a.enter();
    let router = p.a.router();
    let pack = |body: Vec<u8>| {
        crate::generated::ArgPack {
            schema_hash: Some(crate::generated::Hash32 { v: vec![0u8; 32] }),
            codec: crate::generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    };
    let create_req = |alloc: u128| {
        crate::generated::TokenCreateRequest {
            ticker: "ADMT".into(),
            alias: "Admitted Token".into(),
            // Nonzero decimals so the cap-scaling contract (display cap ->
            // BASE-unit registry cap, scaled exactly once at the boundary)
            // stays pinned now that no integration test can create a token.
            decimals: 2,
            max_supply_u128: 1_000_000u128.to_be_bytes().to_vec(),
            initial_alloc_u128: alloc.to_be_bytes().to_vec(),
            mint_burn_enabled: true,
            transferable: true,
            unlimited_supply: false,
            mint_burn_threshold: 1,
            description: String::new(),
            icon_url: String::new(),
            allowlist_device_ids: Vec::new(),
        }
        .encode_to_vec()
    };
    let fee = dsm::core::token::TOKEN_CREATION_FEE_ERA;
    assert_eq!(
        p.a.era_balance(),
        100,
        "one faucet claim funded the fixture"
    );

    // Creator supply: the named refusal, and NOTHING moved.
    let refused = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.create".into(),
            args: pack(create_req(5)),
        })
        .await;
    assert!(!refused.success, "creator supply must be refused");
    assert!(
        refused
            .error_message
            .unwrap_or_default()
            .contains("initial_supply > 0 cannot enter a validated lineage"),
        "the refusal is the NAMED issuance-predicate error"
    );
    assert_eq!(p.a.era_balance(), 100, "a refused creation burns nothing");
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        1,
        "a refused creation admits nothing"
    );

    // Fee-only creation: ADMITTED end to end (position 2).
    let created = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.create".into(),
            args: pack(create_req(0)),
        })
        .await;
    assert!(created.success, "{:?}", created.error_message);
    let resp = match crate::generated::Envelope::decode(&created.data[1..])
        .expect("envelope")
        .payload
    {
        Some(crate::generated::envelope::Payload::TokenCreateResponse(t)) => t,
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    };
    assert_eq!(p.a.era_balance(), 100 - fee, "exactly the fee, burned");
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        2,
        "the fee debit is an admitted economic position"
    );
    let head = p.a.router().core_sdk.device_head().expect("head");
    assert!(head.pending_economic_admission().is_none(), "unfenced");
    // The anchor contract from the retired integration create: the anchor is
    // the content hash of the policy Rust packed — no node, no client names
    // it. Re-derive from the stored policy bytes and require equality.
    let row = client_db::token_registry::get_token_by_ticker("ADMT")
        .expect("registry read")
        .expect("registry row committed with the advance");
    assert_eq!(
        row.max_supply, 100_000_000,
        "display cap 1,000,000 at 2 decimals is recorded as BASE units"
    );
    assert_eq!(resp.policy_anchor.len(), 32, "anchor is 32 bytes");
    let (stored_anchor, stored_policy) = client_db::token_registry::all_policies()
        .expect("policies")
        .into_iter()
        .find(|(a, _)| a.as_slice() == resp.policy_anchor.as_slice())
        .expect("the created token's policy is stored under its anchor");
    let derived = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_POLICY,
        &stored_policy,
    );
    assert_eq!(
        derived, stored_anchor,
        "stored policy must hash to the anchor the route returned"
    );

    // An identical resubmission reconciles: same id, no second fee, no advance.
    let again = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.create".into(),
            args: pack(create_req(0)),
        })
        .await;
    assert!(again.success, "{:?}", again.error_message);
    let resp2 = match crate::generated::Envelope::decode(&again.data[1..])
        .expect("envelope")
        .payload
    {
        Some(crate::generated::envelope::Payload::TokenCreateResponse(t)) => t,
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    };
    assert_eq!(resp2.token_id, resp.token_id, "one commitment, one token");
    assert_eq!(p.a.era_balance(), 100 - fee, "no second fee");
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        2,
        "a reconciled resubmission admits nothing new"
    );

    // The admitted burn ROUTE (position 3).
    let burned = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.burn".into(),
            args: pack(
                crate::generated::TokenBurnRequest {
                    token_id: "ERA".into(),
                    amount: 25,
                    message: "route burn".into(),
                }
                .encode_to_vec(),
            ),
        })
        .await;
    assert!(burned.success, "{:?}", burned.error_message);
    assert_eq!(p.a.era_balance(), 100 - fee - 25);
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        3,
        "the route burn advanced the lineage"
    );
}

/// Correction A end to end: a send whose admission CANNOT finish (the
/// register fleet is down past quorum) commits the debit forward-only,
/// HOLDS the outbox row, and emits ZERO transfer bytes — even when the
/// resubmit sweep runs in the held window. Recovery then completes the SAME
/// admission from the frozen artifacts, promotes the row, and the transfer
/// delivers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_failed_finish_holds_the_outbox_and_resume_completes_the_same_admission() {
    let p = crate::test_support::two_device::Pair::boot(100, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let submits_before = p.submits().len();

    // Quorum is 2-of-3: two failing members make evidence publication
    // impossible, so finish_admission dies AFTER the staged commit.
    crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-1");
    crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-2");
    let refused = p.a.send(&p.b, 10).await;
    assert!(!refused.success, "the send must not report success");
    let msg = refused.error_message.unwrap_or_default();
    assert!(
        msg.contains("HELD for resume") && msg.contains("nothing was delivered"),
        "the refusal names the held admission, got: {msg}"
    );
    assert_eq!(
        p.a.era_balance(),
        90,
        "forward-only: the committed debit stands"
    );
    assert_eq!(
        p.submits().len(),
        submits_before,
        "zero transfer bytes emitted by the send itself"
    );

    p.a.enter();
    let held_status: String = {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT status FROM sender_outbox WHERE relationship_key = ?1",
            rusqlite::params![rel.as_slice()],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(held_status, client_db::OUTBOX_ECONOMIC_ADMISSION_PENDING);
    let core = p.a.router().core_sdk.clone();
    let pending = core
        .device_head()
        .unwrap()
        .pending_economic_admission()
        .cloned()
        .expect("the admission rides the head for resume");
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        1,
        "nothing admitted"
    );

    // THE RACE (correction A's control): run the resubmit sweep in the held
    // window — it must not see the row, so nothing reaches any node.
    let swept = p.a.sync().await;
    assert!(swept.success, "{:?}", swept.errors);
    assert_eq!(
        p.submits().len(),
        submits_before,
        "the sweep in the held window emits ZERO transfer bytes"
    );

    // Recovery: heal the fleet, finish the SAME admission from frozen state.
    crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-1");
    crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-2");
    crate::sdk::economic_admission_flow::resume_pending_admission(&core, b"dsm-testnet", pending)
        .await
        .expect("resume completes the same admission");
    p.a.enter();
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        2,
        "the SAME admission admitted at position 2"
    );
    assert!(
        p.a.router()
            .core_sdk
            .device_head()
            .unwrap()
            .pending_economic_admission()
            .is_none(),
        "unfenced after resume"
    );
    let promoted: String = {
        let binding = client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT status FROM sender_outbox WHERE relationship_key = ?1",
            rusqlite::params![rel.as_slice()],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_ne!(
        promoted,
        client_db::OUTBOX_ECONOMIC_ADMISSION_PENDING,
        "the terminal admission promoted the held row"
    );

    // And the promoted row now DELIVERS.
    let resent = p.a.sync().await;
    assert!(resent.success, "{:?}", resent.errors);
    assert!(
        p.submits().len() > submits_before,
        "the promoted row is deliverable"
    );
    let applied = p.b.sync().await;
    assert!(applied.success, "{:?}", applied.errors);
    assert_eq!(p.b.era_balance(), 10, "B received the held transfer once");
}
