// SPDX-License-Identifier: Apache-2.0

//! 3.5b PR3: the generalized admission seam under ordinary operations —
//! admitted Burn through the self-loop helper, the multi-step foreign walk,
//! the admission serialization (correction B), and the held-outbox rule
//! (correction A).

use serial_test::serial;

use crate::bridge::AppRouter;
use crate::handlers::faucet_flow_tests_support::{setup_funded, NETWORK};
use crate::sdk::economic_admission_flow::{admitted_self_loop_operation, resume_pending_admission};
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
    let (outcome, admitted) = admitted_self_loop_operation(
        &core,
        burn_op(40),
        burn_delta(40),
        |_| {
            Ok((
                dsm::economic::write_set::CreditSourceFacts::None,
                Vec::new(),
            ))
        },
        None,
    )
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
            .sets()
            .iter()
            .find(|s| {
                crate::sdk::storage_set::as_ccb_members(s)
                    .ok()
                    .and_then(|m| profile.derive_set_id(&m).ok())
                    .is_some()
            })
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
    let (_o, a2) = admitted_self_loop_operation(
        &core,
        burn_op(10),
        burn_delta(10),
        |_| {
            Ok((
                dsm::economic::write_set::CreditSourceFacts::None,
                Vec::new(),
            ))
        },
        None,
    )
    .await
    .expect("burn 1");
    assert_eq!(a2.economic_position, 2);
    let (_o, a3) = admitted_self_loop_operation(
        &core,
        burn_op(20),
        burn_delta(20),
        |_| {
            Ok((
                dsm::economic::write_set::CreditSourceFacts::None,
                Vec::new(),
            ))
        },
        None,
    )
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
            // Decimals stay nonzero so the created token is not accidentally
            // the trivial whole-unit shape. The cap-scaling contract is NOT
            // pinned here any more: a capped creation is refused in beta, so
            // the only creation that reaches the registry carries no cap.
            // `token_decimal_scaling.rs` pins the scaling arithmetic through
            // the capped path's own refusals.
            decimals: 2,
            max_supply_u128: 0u128.to_be_bytes().to_vec(),
            initial_alloc_u128: alloc.to_be_bytes().to_vec(),
            mint_burn_enabled: true,
            transferable: true,
            unlimited_supply: true,
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
        row.max_supply, 0,
        "an uncapped token records no cap — the only creation beta admits"
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

/// THE HONEST AUTHORIZED MINT, END TO END, THEN FOREIGN-WALKED.
///
/// This is the statement the producer cut exists to make true:
///
/// ```text
/// canonical policy -> exact Mint frozen -> transition-bound 1-of-1 0x0029
///   -> 0x0023 AuthorizedIssuance -> economic admission -> positive R_econ
/// ```
///
/// Faucet funds position 1, the fee-bearing create admits position 2 and
/// anchors the policy, the mint admits position 3 — and then a FOREIGN
/// verifier with no local shortcuts walks the lineage and validates the mint
/// through the full 0x0023 arm, fetching the 0x0029 bundle by content
/// address from the fleet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn token_routes_admit_an_authorized_mint_that_is_foreign_walkable() {
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
    let created = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.create".into(),
            args: pack(
                crate::generated::TokenCreateRequest {
                    ticker: "MNTA".into(),
                    alias: "Mintable Token".into(),
                    decimals: 2,
                    max_supply_u128: 0u128.to_be_bytes().to_vec(),
                    initial_alloc_u128: 0u128.to_be_bytes().to_vec(),
                    mint_burn_enabled: true,
                    transferable: true,
                    unlimited_supply: true,
                    mint_burn_threshold: 1,
                    description: String::new(),
                    icon_url: String::new(),
                    allowlist_device_ids: Vec::new(),
                }
                .encode_to_vec(),
            ),
        })
        .await;
    assert!(created.success, "{:?}", created.error_message);
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        2,
        "the creation fee admitted position 2"
    );

    let minted = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.mint".into(),
            args: pack(
                crate::generated::TokenMintRequest {
                    token_id: "MNTA".into(),
                    amount: 500,
                    message: "first authorized issuance".into(),
                }
                .encode_to_vec(),
            ),
        })
        .await;
    assert!(minted.success, "{:?}", minted.error_message);
    let resp = match crate::generated::Envelope::decode(&minted.data[1..])
        .expect("envelope")
        .payload
    {
        Some(crate::generated::envelope::Payload::TokenMintResponse(t)) => t,
        other => panic!("expected TokenMintResponse, got {other:?}"),
    };
    assert_eq!(resp.new_balance, 500, "the credit landed");
    let (position, admitted_root) = client_db::economic_lineage::get_admitted()
        .unwrap()
        .expect("admitted");
    assert_eq!(position, 3, "the mint admitted position 3");
    let head = p.a.router().core_sdk.device_head().expect("head");
    assert!(
        head.pending_economic_admission().is_none(),
        "no fence remains after ECON_ADMITTED"
    );

    // FOREIGN VERIFICATION: no cached shortcuts, live quorum, the real
    // resolver — position 3 must validate as an AuthorizedIssuance-funded
    // Mint from public material alone.
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    client_db::economic_lineage::clear_peer_lineage(&genesis, &devid).unwrap();
    let handle = tokio::runtime::Handle::current();
    let peer = tokio::task::spawn_blocking(move || {
        use dsm::economic::provenance::ProvenanceResolver;
        let profile =
            dsm::economic::register::resolve_root_register_profile(NETWORK).expect("profile");
        let set = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .sets()
            .iter()
            .find(|s| {
                crate::sdk::storage_set::as_ccb_members(s)
                    .ok()
                    .and_then(|m| profile.derive_set_id(&m).ok())
                    .is_some()
            })
            .cloned()
            .expect("canonical set");
        let resolver = crate::sdk::economic_registers::LiveRegisterResolver {
            set: &set,
            runtime: handle,
            expected_network_id: NETWORK.to_vec(),
        };
        resolver.validated_peer_transition(&genesis, &devid, 3)
    })
    .await
    .expect("join")
    .expect("the minted position MUST be foreign-walkable through the 0x0023 arm");
    assert_eq!(peer.validated_root.economic_position(), 3);
    assert_eq!(peer.validated_root.economic_root(), admitted_root);
    assert!(
        matches!(
            peer.verified_operation,
            dsm::types::operations::Operation::Mint { .. }
        ),
        "the walked operation is the Mint itself"
    );
}

/// EVERY UNSUPPORTED POLICY SHAPE REFUSES AT THE PRODUCER, BEFORE ANY
/// MUTATION — the policy's own reason, not a generic failure. One boot, three
/// shapes: mint/burn disabled, an allowlist excluding this device, and the
/// allowlist POSITIVE control proving the refusal is the allowlist rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn mint_preflight_refuses_each_unsupported_policy_shape_by_name() {
    use prost::Message;
    let p = crate::test_support::two_device::Pair::boot(100, 0).await;
    p.a.enter();
    let router = p.a.router();
    let own_devid = router.core_sdk.device_head().expect("head").devid();
    let pack = |body: Vec<u8>| {
        crate::generated::ArgPack {
            schema_hash: Some(crate::generated::Hash32 { v: vec![0u8; 32] }),
            codec: crate::generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    };
    let create = |ticker: &str, mint_burn: bool, allow: Vec<Vec<u8>>| {
        crate::generated::TokenCreateRequest {
            ticker: ticker.into(),
            alias: format!("{ticker} Token"),
            decimals: 0,
            max_supply_u128: 0u128.to_be_bytes().to_vec(),
            initial_alloc_u128: 0u128.to_be_bytes().to_vec(),
            mint_burn_enabled: mint_burn,
            transferable: true,
            unlimited_supply: true,
            mint_burn_threshold: 1,
            description: String::new(),
            icon_url: String::new(),
            allowlist_device_ids: allow,
        }
        .encode_to_vec()
    };
    let mint = |token: &str| {
        crate::generated::TokenMintRequest {
            token_id: token.into(),
            amount: 10,
            message: String::new(),
        }
        .encode_to_vec()
    };

    let admitted_before_mints = {
        // three creates, three fee admissions
        for (ticker, mb, allow) in [
            ("NOMB", false, Vec::new()),
            ("ALLW", true, vec![vec![0x77u8; 32]]),
            ("ALLK", true, vec![own_devid.to_vec()]),
        ] {
            let r = router
                .invoke(crate::bridge::AppInvoke {
                    method: "token.create".into(),
                    args: pack(create(ticker, mb, allow)),
                })
                .await;
            assert!(r.success, "create {ticker}: {:?}", r.error_message);
        }
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0
    };

    let refused = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.mint".into(),
            args: pack(mint("NOMB")),
        })
        .await;
    assert!(!refused.success);
    let msg = refused.error_message.unwrap_or_default();
    assert!(
        msg.contains("disables mint/burn"),
        "the committed policy's own reason, got: {msg}"
    );

    let refused = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.mint".into(),
            args: pack(mint("ALLW")),
        })
        .await;
    assert!(!refused.success);
    let msg = refused.error_message.unwrap_or_default();
    assert!(
        msg.contains("allowlist"),
        "the receiving device is outside the committed allowlist, got: {msg}"
    );

    // POSITIVE CONTROL: the same shape NAMING this device mints — so the two
    // refusals above are the policy rules, not a broken producer.
    let ok = router
        .invoke(crate::bridge::AppInvoke {
            method: "token.mint".into(),
            args: pack(mint("ALLK")),
        })
        .await;
    assert!(ok.success, "{:?}", ok.error_message);
    assert_eq!(
        client_db::economic_lineage::get_admitted()
            .unwrap()
            .unwrap()
            .0,
        admitted_before_mints + 1,
        "exactly the allowlisted mint admitted; the refusals moved nothing"
    );
}

/// ATOMICITY: a failure while building the issuance facts leaves NOTHING —
/// no advance, no fence, no admitted movement, no frozen evidence. The facts
/// closure runs before anything durable, so its error must be a clean no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_failed_issuance_evidence_build_leaves_no_trace() {
    let (core, _fleet) = setup_funded(0xD4).await;
    let head_root_before = core.device_head().expect("head").root();
    let admitted_before = client_db::economic_lineage::get_admitted().unwrap();

    let mint = dsm::types::operations::Operation::Mint {
        amount: dsm::types::token_types::Balance::from_state(25, [0u8; 32]),
        token_id: b"GHST".to_vec(),
        policy_commit: [0x5Cu8; 32],
        message: String::new(),
    };
    let delta = dsm::types::device_state::BalanceDelta {
        policy_commit: [0x5Cu8; 32],
        direction: dsm::types::device_state::BalanceDirection::Credit,
        amount: 25,
    };
    let refused = admitted_self_loop_operation(
        &core,
        mint,
        delta,
        |_| {
            Err(dsm::types::error::DsmError::invalid_operation(
                "TEST: evidence construction failed",
            ))
        },
        None,
    )
    .await;
    assert!(refused.is_err(), "the seam must surface the build failure");

    let head = core.device_head().expect("head");
    assert_eq!(head.root(), head_root_before, "no advance survived");
    assert!(
        head.pending_economic_admission().is_none(),
        "no fence survived"
    );
    assert_eq!(
        client_db::economic_lineage::get_admitted().unwrap(),
        admitted_before,
        "no admitted movement"
    );
    assert!(
        client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
            "immutable::DSM/issuance-authorization-evidence/v1::",
            "issuance-authorization-evidence",
        )
        .unwrap()
        .is_none(),
        "no evidence artifact was frozen"
    );
}

/// A FAILED FINISH HOLDS THE MINT, AND RESUME COMPLETES THE SAME ADMISSION —
/// with the SAME 0x0029 evidence bytes, re-signed by nobody. Quorum dies
/// after the staged commit; the crash invariant is that the mint, its pending
/// admission and its exact evidence all exist durably, and resume finishes
/// from frozen bytes alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_failed_finish_holds_the_mint_and_resume_completes_the_same_admission() {
    let (core, _fleet) = setup_funded(0xD5).await;

    // A real 1-of-1 policy naming THIS wallet's signing key, packed by the
    // sole production packer — the seam-level twin of what token.create
    // anchors. The registry is deliberately not involved: the seam consumes
    // policy BYTES, and only the route resolves tickers.
    let signer_pk = crate::sdk::signing_authority::current_public_key().expect("pk");
    let policy_proto = {
        let packed = crate::handlers::token_routes::build_policy_v3_bytes(
            &crate::handlers::token_routes::ParsedTokenPolicy {
                ticker: "HELD".into(),
                alias: "Held Token".into(),
                decimals: 0,
                max_supply: 0,
                initial_alloc: 0,
                description: Option::None,
                icon_url: Option::None,
                mint_burn_enabled: true,
                transferable: true,
                unlimited_supply: true,
                mint_burn_threshold: 1,
                signers: vec![signer_pk.clone()],
                allowlist_device_ids: Vec::new(),
            },
        )
        .expect("pack");
        use prost::Message;
        crate::generated::TokenPolicyV3 {
            policy_bytes: packed,
        }
        .encode_to_vec()
    };
    let policy_commit = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_POLICY,
        &policy_proto,
    );
    let head = core.device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    // The policy engine on the advance path rehydrates by TOKEN ID from the
    // durable registry, and DEFAULT-DENIES a token it cannot rehydrate — so
    // the fixture anchors both halves exactly as token.create would: the
    // registry row and the verified policy bytes under their own commit.
    client_db::token_registry::upsert_policy(&policy_commit, &policy_proto)
        .expect("anchor policy bytes");
    client_db::token_registry::insert_token(&client_db::token_registry::TokenRegistryRow {
        token_id: "HELD".into(),
        policy_commit,
        ticker: "HELD".into(),
        alias: "Held Token".into(),
        decimals: 0,
        max_supply: 0,
        owner_device_id: devid,
    })
    .expect("registry row");
    // A bare CoreSDK has no policy resolver (the router installs it); wire
    // the SAME resolution the production installer uses, so the advance-path
    // policy engine can rehydrate this token instead of default-denying it.
    core.set_policy_resolver(std::sync::Arc::new(|identifier: &str| {
        let row = client_db::token_registry::get_token(identifier)
            .ok()
            .flatten()
            .or_else(|| {
                client_db::token_registry::get_token_by_ticker(identifier)
                    .ok()
                    .flatten()
            })?;
        let raw = client_db::token_registry::load_policy_verified(&row.policy_commit)
            .ok()
            .flatten()?;
        let parsed = crate::handlers::token_routes::parse_token_policy(&raw)?;
        Some((
            crate::handlers::token_routes::derive_policy_file(&row.ticker, &parsed),
            dsm::types::policy_types::PolicyAnchor::from_bytes(row.policy_commit),
        ))
    }));
    let mint = dsm::types::operations::Operation::Mint {
        amount: dsm::types::token_types::Balance::from_state(25, genesis),
        token_id: b"HELD".to_vec(),
        policy_commit,
        message: String::new(),
    };
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&mint.to_bytes());
    let delta = dsm::types::device_state::BalanceDelta {
        policy_commit,
        direction: dsm::types::device_state::BalanceDirection::Credit,
        amount: 25,
    };
    let facts = move |target_position: u64| {
        use prost::Message;
        let body = dsm::economic::issuance::IssuanceAuthorizationBody {
            policy_commit,
            issuer_genesis: genesis,
            issuer_devid: devid,
            issuer_economic_position: target_position,
            recipient_operation_digest: op_digest,
            amount: 25,
        };
        let body_ccb = body.encode().expect("ccb");
        let digest = body.signing_digest().expect("digest");
        let sk = crate::sdk::signing_authority::current_secret_key()?;
        let sig = dsm::crypto::sphincs::sphincs_sign(&sk, &digest).expect("sign");
        let evidence_bytes = crate::generated::IssuanceAuthorizationEvidenceV1 {
            canonical_policy_bytes: policy_proto.clone(),
            authorization_body_ccb: body_ccb,
            signatures: vec![crate::generated::PolicySignerSignatureV1 {
                signer_public_key: signer_pk.clone(),
                signature: sig,
            }],
        }
        .encode_to_vec();
        let addr = dsm::storage_object::immutable_inner(
            dsm::common::domain_tags::TAG_DSM_ISSUANCE_AUTHORIZATION_EVIDENCE,
            &evidence_bytes,
        );
        let key = crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_ISSUANCE_AUTHORIZATION_EVIDENCE,
            &evidence_bytes,
        );
        Ok((
            dsm::economic::write_set::CreditSourceFacts::AuthorizedIssuance {
                issuance_authorization_addr: addr,
            },
            vec![(key, evidence_bytes, "issuance-authorization-evidence")],
        ))
    };

    // Quorum is 2-of-3: two dead members make evidence publication
    // impossible, so finish dies AFTER the staged commit.
    crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-1");
    crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-2");
    let refused = admitted_self_loop_operation(&core, mint, delta.clone(), facts, None).await;
    let seam_err = refused
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        seam_err.contains("below storage quorum"),
        "finish must fail AT PUBLICATION, not earlier, got: {seam_err}"
    );
    let pending = core
        .device_head()
        .expect("head")
        .pending_economic_admission()
        .cloned()
        .expect("the mint is HELD behind its pending admission");
    assert_eq!(pending.operation_digest, op_digest, "held for THIS mint");
    let frozen =
        client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
            "immutable::DSM/issuance-authorization-evidence/v1::",
            "issuance-authorization-evidence",
        )
        .unwrap()
        .expect("the exact evidence bytes are frozen for resume");

    // Heal the fleet; resume completes the SAME admission from frozen bytes.
    crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-1");
    crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-2");
    resume_pending_admission(&core, NETWORK, pending)
        .await
        .expect("resume completes the held mint admission");
    let (position, _root) = client_db::economic_lineage::get_admitted()
        .unwrap()
        .expect("admitted");
    assert_eq!(position, 2, "the held mint admitted at its signed position");
    assert!(
        core.device_head()
            .expect("head")
            .pending_economic_admission()
            .is_none(),
        "unfenced after resume"
    );
    assert_eq!(
        core.device_head().expect("head").balance(&policy_commit),
        25,
        "the authorized credit stands"
    );
    let frozen_after =
        client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
            "immutable::DSM/issuance-authorization-evidence/v1::",
            "issuance-authorization-evidence",
        )
        .unwrap()
        .expect("still frozen");
    assert_eq!(
        frozen, frozen_after,
        "resume used the SAME evidence bytes — nothing was re-signed"
    );
}

/// THE FUNNEL IS THE GATE, NOT THE ROUTE: a DLV advance driven DIRECTLY
/// through the state-machine funnel — no route, no pre-flight — still refuses
/// a non-transferable market leg. This is the every-caller property the mint
/// gate taught: a route guard alone leaves any future caller free to reopen
/// the hole.
///
/// MUTATION CONTROL: comment out the `enforce_market_leg_policies_local` call
/// in `execute_on_relationship_inner` and this goes red — the refusal
/// (if any) stops naming the market rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_direct_dlv_advance_with_a_non_transferable_leg_is_refused_at_the_funnel() {
    let (core, _fleet) = crate::handlers::faucet_flow_tests_support::setup(0xE6);

    // Root a NON-transferable policy — the funnel reads local rooting only.
    let proto = {
        use prost::Message;
        let packed = crate::handlers::token_routes::build_policy_v3_bytes(
            &crate::handlers::token_routes::ParsedTokenPolicy {
                ticker: "NTFR".into(),
                alias: "No Transfer".into(),
                decimals: 0,
                max_supply: 0,
                initial_alloc: 0,
                description: Option::None,
                icon_url: Option::None,
                mint_burn_enabled: true,
                transferable: false,
                unlimited_supply: true,
                mint_burn_threshold: 1,
                signers: vec![vec![0xE1; 64]],
                allowlist_device_ids: Vec::new(),
            },
        )
        .expect("pack");
        crate::generated::TokenPolicyV3 {
            policy_bytes: packed,
        }
        .encode_to_vec()
    };
    let pc =
        dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &proto);
    client_db::token_registry::upsert_policy(&pc, &proto).expect("root");
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    let (lo, hi) = if era < pc { (era, pc) } else { (pc, era) };

    let dev = core.device_head().expect("head").devid();
    let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev, &dev);
    let tip =
        dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(&dev, &dev);
    let op = core
        .sign_operation_sphincs(dsm::types::operations::Operation::DlvCreateFundedV2 {
            vault_id: vec![0x77; 32],
            creator_public_key: vec![0xE2; 64],
            parameters_hash: vec![0xE3; 32],
            fulfillment_condition: Vec::new(),
            leg_a_policy_commit: lo,
            leg_a_amount: 100,
            leg_b_policy_commit: hi,
            leg_b_amount: 100,
            fee_bps: 30,
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        })
        .expect("sign");
    let refused = core.execute_on_relationship_with_reserve_mutation(
        rel_key,
        dev,
        op,
        &[],
        Some(tip),
        Some(dsm::types::device_state::VaultReserveMutation::Fund {
            vault_id: [0x77; 32],
            legs: vec![(lo, 100), (hi, 100)],
            vault_sequence: 0,
            pair: dsm::types::device_state::VaultStatePair::new(lo, hi, 30).expect("pair"),
        }),
        None,
    );
    let msg = refused
        .err()
        .map(|e| e.to_string())
        .expect("the funnel must refuse a non-transferable market leg");
    assert!(
        msg.contains("non-transferable") && msg.contains("market leg"),
        "the funnel refusal names the market rule, got: {msg}"
    );
}
