// SPDX-License-Identifier: MIT OR Apache-2.0
//! REGISTER CONFORMANCE: the in-process register double against the REAL
//! storage-node endpoints, on identical vectors.
//!
//! `dsm_sdk::sdk::storage_io::fake_registers` stands in for this node's two
//! economic write-once registers in every client-side test. It is allowed to
//! exist on ONE premise: that it is a protocol-faithful implementation of the
//! member, never a source of invented authority. This suite is that premise
//! made executable. Every vector below is submitted to three real members —
//! this crate's routers, built by the SAME library functions the binary
//! serves, behind `device_auth`, echoing their configured identity — and to
//! the double, and the two `ClaimFanout`s are compared.
//!
//! What "compared" means, stated rather than assumed:
//!
//! - `Accepted`, `HeldIdentical`, `Refused { held_digest }`: EXACT equality,
//!   held digest by value.
//! - `Unavailable(text)` for an endpoint or auth refusal (400/401/403/422/503):
//!   EXACT equality — both sides go through the one shared classifier
//!   (`classify_one_shot_response`) on the member's `(status, outcome)`, so
//!   the text is identical by construction.
//! - `Unavailable` for a member that answers NOTHING (down): variant and echo
//!   (`None`) — the live text is reqwest's transport error, the double's is
//!   "injected", and neither reaches the quorum counter, which ignores every
//!   `Unavailable`. The classifier's own vectors pin the live text.
//!
//! What this suite does NOT claim: it drives axum routers in-process
//! (`tower::oneshot`), not reqwest on a socket, so the client's HTTP encoding
//! is exercised only through the shared `one_shot_claim_headers`; and a real
//! fleet's members decide independently under concurrent claims where the
//! double serialises a whole fan-out — proven equivalent PER MEMBER below,
//! and documented as a modelling choice at fleet level.

#![cfg(feature = "local-dev")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use tower::ServiceExt;
use tower_http::limit::RequestBodyLimitLayer;

use dsm::economic::cell_observation::MemberCellRead;
use dsm::economic::claim::EconomicRootClaimBody;
use dsm::economic::claim_envelope::{
    economic_root_claim_envelope_digest, sign_economic_root_claim,
};
use dsm::economic::faucet::{
    era_faucet_id, faucet_claim_evidence_addr, sign_faucet_ticket_claim, FaucetTicketClaimBody,
    ERA_FAUCET_TICKET_COUNT,
};
use dsm::economic::register::{economic_root_register_key, AuthenticatedCaller, MAX_CLAIM_BYTES};
use dsm_sdk::sdk::storage_io::fake_registers::{self, RegisterKind};
use dsm_sdk::sdk::storage_node_sdk::{
    classify_one_shot_response, one_shot_claim_headers, ClaimFanout, MemberClaimOutcome,
    MemberClaimResult, StorageAuthContext,
};
use dsm_sdk::sdk::storage_set::{StorageMember, StorageSet};
use dsm_sdk::util::text_id;
use dsm_storage_node::replication::{ReplicationConfig, ReplicationManager};
use dsm_storage_node::{db, AppState, NodeStorageSet};

const NETWORK: &[u8] = b"dsm-testnet";
const MEMBERS: [&str; 3] = ["dsm-node-1", "dsm-node-2", "dsm-node-3"];

// ── the real side ────────────────────────────────────────────────────────────

/// One real member: its router as the binary would serve it for these
/// registers — writes behind `device_auth`, reads public, body-limited, and
/// echoing the member's RAW configured id on every response.
struct RealMember {
    id: String,
    endpoint: String,
    pool: Arc<db::DBPool>,
    router: Router,
}

async fn real_member(id: &str, set_members: &[&str], network: Option<&[u8]>) -> RealMember {
    let endpoint = format!("http://{id}.local:8080");
    let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
    db::init_db(&pool).await.expect("init db");
    let rm = Arc::new(
        ReplicationManager::new_for_tests(
            ReplicationConfig {
                replication_factor: 3,
                gossip_interval_ticks: 100,
                failure_timeout_ticks: 300,
                gossip_fanout: 3,
                max_concurrent_jobs: 10,
            },
            id.to_string(),
            endpoint.clone(),
        )
        .expect("replication manager"),
    );
    let mut state = AppState::new(id.to_string(), &endpoint, None, pool.clone(), rm);
    if !set_members.is_empty() {
        let ids: Vec<String> = set_members.iter().map(|s| s.to_string()).collect();
        state = state.with_storage_set(NodeStorageSet::new(ids, id).expect("node set"));
    }
    if let Some(n) = network {
        state = state.with_network_id(n.to_vec());
    }
    let state = Arc::new(state);
    let router = dsm_storage_node::economic_register_write_router(state.clone())
        .merge(dsm_storage_node::economic_register_read_router(state))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(dsm_storage_node::node_identity_echo_layer(id));
    RealMember {
        id: id.to_string(),
        endpoint,
        pool,
        router,
    }
}

/// The canonical three-member fleet, every member configured for the same set
/// and network — what a client's catalog names as `dsm-node-1..3`.
async fn fleet() -> Vec<RealMember> {
    let mut v = Vec::new();
    for id in MEMBERS {
        v.push(real_member(id, &MEMBERS, Some(NETWORK)).await);
    }
    v
}

/// The client-side view of the same fleet: the set the double is handed.
fn client_set(members: &[RealMember]) -> StorageSet {
    StorageSet::new(
        members
            .iter()
            .map(|m| StorageMember {
                member_id: m.id.clone(),
                endpoint: m.endpoint.clone(),
            })
            .collect(),
    )
    .expect("client set")
}

// ── devices ──────────────────────────────────────────────────────────────────

/// A device with a real SPHINCS+ keypair, registered at every member with a
/// bearer token exactly as device registration stores it: the member keeps
/// `BLAKE3(raw token)` and the wire carries the raw token in Base32.
struct Device {
    devid: [u8; 32],
    genesis: [u8; 32],
    pk: Vec<u8>,
    sk: Vec<u8>,
    auth: StorageAuthContext,
}

impl Device {
    fn caller(&self) -> AuthenticatedCaller {
        AuthenticatedCaller {
            public_key: self.pk.clone(),
            device_id: self.devid,
        }
    }
}

async fn device(tag: u8, members: &[RealMember]) -> Device {
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
    let devid = [tag; 32];
    let genesis = [tag ^ 0xA5; 32];
    let raw_token = [tag ^ 0x3C; 32];
    let devid_b32 = text_id::encode_base32_crockford(&devid);
    let token_hash = blake3::hash(&raw_token);
    for m in members {
        db::register_device(
            &m.pool,
            &devid_b32,
            &genesis,
            &pk,
            token_hash.as_bytes(),
            &[0u8; 32],
            &[0u8; 32],
        )
        .await
        .expect("register device at member");
    }
    Device {
        devid,
        genesis,
        pk,
        sk,
        auth: StorageAuthContext {
            device_id_b32: devid_b32,
            token_b32: text_id::encode_base32_crockford(&raw_token),
        },
    }
}

// ── driving one register on both sides ───────────────────────────────────────

#[derive(Clone, Copy)]
enum Register {
    Faucet,
    Root,
}

impl Register {
    fn kind(self) -> RegisterKind {
        match self {
            Register::Faucet => RegisterKind::FaucetTicket,
            Register::Root => RegisterKind::EconomicRoot,
        }
    }
    fn path(self) -> &'static str {
        match self {
            Register::Faucet => "/api/v2/faucet-ticket/claim",
            Register::Root => "/api/v2/economic-root/claim",
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Register::Faucet => "x-dsm-faucet-ticket",
            Register::Root => "x-dsm-economic-root",
        }
    }
    fn digest(self, envelope: &[u8]) -> [u8; 32] {
        match self {
            Register::Faucet => faucet_claim_evidence_addr(envelope),
            Register::Root => economic_root_claim_envelope_digest(envelope),
        }
    }
    fn network(self) -> Option<&'static [u8]> {
        match self {
            Register::Faucet => Some(NETWORK),
            Register::Root => None,
        }
    }
}

static MSG_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// One real member's answer, mapped EXACTLY as the live client maps it: the
/// shared request headers on the way in, the shared classifier on the way out.
async fn post_to(
    member: &RealMember,
    register: Register,
    envelope: &[u8],
    auth: Option<&StorageAuthContext>,
) -> MemberClaimOutcome {
    let seq = MSG_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let msg_id = format!("conformance-{seq}");
    let mut req = Request::builder().method("POST").uri(register.path());
    for (name, value) in one_shot_claim_headers(auth, &msg_id) {
        req = req.header(name, value);
    }
    let resp = member
        .router
        .clone()
        .oneshot(req.body(Body::from(envelope.to_vec())).expect("request"))
        .await
        .expect("router answers");
    let echoed = resp
        .headers()
        .get("x-dsm-node-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let outcome = resp
        .headers()
        .get(format!("{}-outcome", register.prefix()).as_str())
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let held = resp
        .headers()
        .get(format!("{}-held-digest", register.prefix()).as_str())
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    MemberClaimOutcome {
        member_id: member.id.clone(),
        endpoint: member.endpoint.clone(),
        result: classify_one_shot_response(resp.status().as_u16(), &outcome, held.as_deref()),
        echoed_node_id: echoed,
    }
}

/// The live client's fan-out over a set, where `members` are the members it
/// has a client for: a set member with no client is `Unavailable` with no
/// echo, exactly as `StorageNodeSDK::submit_one_shot_claim` reports it.
async fn real_fanout(
    set: &StorageSet,
    members: &[RealMember],
    register: Register,
    envelope: &[u8],
    auth: Option<&StorageAuthContext>,
) -> ClaimFanout {
    let mut outcomes = Vec::new();
    for sm in set.members() {
        match members.iter().find(|m| m.id == sm.member_id) {
            Some(m) => outcomes.push(post_to(m, register, envelope, auth).await),
            None => outcomes.push(MemberClaimOutcome {
                member_id: sm.member_id.clone(),
                endpoint: sm.endpoint.clone(),
                result: MemberClaimResult::Unavailable(
                    "no client for this member's endpoint".into(),
                ),
                echoed_node_id: None,
            }),
        }
    }
    ClaimFanout {
        outcomes,
        total: set.len() as u32,
    }
}

fn fake_fanout(
    set: &StorageSet,
    register: Register,
    envelope: &[u8],
    caller: Option<&AuthenticatedCaller>,
) -> ClaimFanout {
    fake_registers::claim(set, register.kind(), envelope, caller, register.network())
}

/// THE COMPARISON RELATION, as documented at the top of the file.
fn assert_conformant(case: &str, real: &ClaimFanout, fake: &ClaimFanout) {
    assert_eq!(real.total, fake.total, "{case}: fan-out total");
    assert_eq!(
        real.outcomes.len(),
        fake.outcomes.len(),
        "{case}: one outcome per member"
    );
    for (r, f) in real.outcomes.iter().zip(fake.outcomes.iter()) {
        assert_eq!(r.member_id, f.member_id, "{case}: member order");
        assert_eq!(
            r.echoed_node_id, f.echoed_node_id,
            "{case}: echo on {}",
            r.member_id
        );
        match (&r.result, &f.result) {
            (MemberClaimResult::Unavailable(rt), MemberClaimResult::Unavailable(ft))
                if r.echoed_node_id.is_none() =>
            {
                // A member that answered nothing: variant + echo, texts differ
                // by transport (reqwest's error vs the double's "injected").
                assert!(
                    !rt.is_empty() && !ft.is_empty(),
                    "{case}: an unanswered member carries a reason on both sides"
                );
            }
            (rr, fr) => assert_eq!(rr, fr, "{case}: result on {}", r.member_id),
        }
    }
}

// ── vectors ──────────────────────────────────────────────────────────────────

fn faucet_body(d: &Device, set_id: [u8; 32], ticket: u64, salt: u8) -> FaucetTicketClaimBody {
    FaucetTicketClaimBody {
        faucet_id: era_faucet_id(NETWORK),
        ticket_index: ticket,
        claimant_genesis: d.genesis,
        claimant_devid: d.devid,
        claimant_economic_position: 1,
        recipient_operation_digest: [salt; 32],
        claimant_public_key: d.pk.clone(),
        storage_set_id: set_id,
    }
}

fn faucet_envelope(d: &Device, body: &FaucetTicketClaimBody) -> Vec<u8> {
    sign_faucet_ticket_claim(body, &d.sk).expect("sign ticket claim")
}

fn root_envelope(d: &Device, set_id: [u8; 32], position: u64, salt: u8) -> Vec<u8> {
    root_envelope_for(d, d.genesis, d.devid, set_id, position, salt)
}

fn root_envelope_for(
    signer: &Device,
    genesis: [u8; 32],
    devid: [u8; 32],
    set_id: [u8; 32],
    position: u64,
    salt: u8,
) -> Vec<u8> {
    let body = EconomicRootClaimBody::new(
        genesis,
        devid,
        position,
        [salt; 32],
        [salt ^ 0xFF; 32],
        set_id,
        dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
        &signer.pk,
    )
    .expect("root claim body");
    sign_economic_root_claim(&body, &signer.sk).expect("sign root claim")
}

/// Two envelopes for the SAME cell with DIFFERENT bytes.
fn conflicting_pair(register: Register, d: &Device, set_id: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    match register {
        Register::Faucet => (
            faucet_envelope(d, &faucet_body(d, set_id, 7, 0x11)),
            faucet_envelope(d, &faucet_body(d, set_id, 7, 0x22)),
        ),
        Register::Root => (
            root_envelope(d, set_id, 1, 0x11),
            root_envelope(d, set_id, 1, 0x22),
        ),
    }
}

fn fresh(register: Register, d: &Device, set_id: [u8; 32], salt: u8) -> Vec<u8> {
    match register {
        Register::Faucet => faucet_envelope(d, &faucet_body(d, set_id, 100 + salt as u64, salt)),
        Register::Root => root_envelope(d, set_id, 10 + position_of(salt), salt),
    }
}

fn position_of(salt: u8) -> u64 {
    salt as u64
}

// ── (1) (2) (3): first claim, identical replay, conflicting digest ───────────

#[tokio::test]
#[serial_test::serial]
async fn first_claim_replay_and_conflict_answer_identically() {
    for register in [Register::Faucet, Register::Root] {
        fake_registers::reset();
        let members = fleet().await;
        let set = client_set(&members);
        let d = device(0x11, &members).await;
        let (a, b) = conflicting_pair(register, &d, set.id());

        // (1) first claim -> Accepted on every member, attributed.
        let real = real_fanout(&set, &members, register, &a, Some(&d.auth)).await;
        let fake = fake_fanout(&set, register, &a, Some(&d.caller()));
        assert_conformant("first claim", &real, &fake);
        for o in &real.outcomes {
            assert_eq!(o.result, MemberClaimResult::Accepted);
            assert_eq!(o.echoed_node_id.as_deref(), Some(o.member_id.as_str()));
        }

        // (2) identical replay -> HeldIdentical.
        let real = real_fanout(&set, &members, register, &a, Some(&d.auth)).await;
        let fake = fake_fanout(&set, register, &a, Some(&d.caller()));
        assert_conformant("identical replay", &real, &fake);
        assert!(real
            .outcomes
            .iter()
            .all(|o| o.result == MemberClaimResult::HeldIdentical));

        // (3) conflicting digest at the held cell -> Refused, naming the
        //     winner's digest BY VALUE.
        let real = real_fanout(&set, &members, register, &b, Some(&d.auth)).await;
        let fake = fake_fanout(&set, register, &b, Some(&d.caller()));
        assert_conformant("conflicting digest", &real, &fake);
        let winner = register.digest(&a).to_vec();
        for o in &real.outcomes {
            assert_eq!(
                o.result,
                MemberClaimResult::Refused {
                    held_digest: Some(winner.clone())
                },
                "the refusal names the winner's digest"
            );
        }
    }
}

// ── (4): member unavailable, claim and read side ─────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn a_member_that_answers_nothing_is_unattributed_on_both_sides() {
    for register in [Register::Faucet, Register::Root] {
        fake_registers::reset();
        let members = fleet().await;
        let set = client_set(&members);
        let d = device(0x12, &members).await;
        let env = fresh(register, &d, set.id(), 0x21);

        // Real: the client has no client for dsm-node-3 (down / unreachable).
        // Double: dsm-node-3 is failed.
        let reachable: Vec<&RealMember> = members.iter().take(2).collect();
        let reachable_owned: Vec<RealMember> = Vec::new();
        let _ = reachable_owned;
        fake_registers::fail_member("dsm-node-3", true);
        let real = {
            let mut outcomes = Vec::new();
            for sm in set.members() {
                match reachable.iter().find(|m| m.id == sm.member_id) {
                    Some(m) => outcomes.push(post_to(m, register, &env, Some(&d.auth)).await),
                    None => outcomes.push(MemberClaimOutcome {
                        member_id: sm.member_id.clone(),
                        endpoint: sm.endpoint.clone(),
                        result: MemberClaimResult::Unavailable(
                            "HTTP request failed: connection refused".into(),
                        ),
                        echoed_node_id: None,
                    }),
                }
            }
            ClaimFanout {
                outcomes,
                total: set.len() as u32,
            }
        };
        let fake = fake_fanout(&set, register, &env, Some(&d.caller()));
        assert_conformant("member unavailable (claim)", &real, &fake);
        assert!(matches!(
            real.outcomes[2].result,
            MemberClaimResult::Unavailable(_)
        ));
        assert_eq!(real.outcomes[2].echoed_node_id, None);

        // READ side: the two live members hold the winner; the down member is
        // an UNATTRIBUTED empty on both sides — never an attributed one, which
        // the quorum reader would count.
        let key = match register {
            Register::Faucet => {
                let v = dsm::economic::faucet::decode_and_verify_faucet_ticket_claim(&env)
                    .expect("vector decodes");
                (
                    format!(
                        "/api/v2/faucet-ticket/{}/{}",
                        text_id::encode_base32_crockford(&v.body.faucet_id),
                        v.body.ticket_index
                    ),
                    fake_registers::ticket_key(&v.body.faucet_id, v.body.ticket_index),
                )
            }
            Register::Root => {
                let v = dsm::economic::claim_envelope::decode_and_verify_economic_root_claim(&env)
                    .expect("vector decodes");
                let k = economic_root_register_key(
                    &v.body.trader_genesis,
                    &v.body.trader_devid,
                    v.body.economic_position,
                );
                (
                    format!(
                        "/api/v2/economic-root/{}",
                        text_id::encode_base32_crockford(&k)
                    ),
                    fake_registers::root_key(&k),
                )
            }
        };
        let mut real_rows = Vec::new();
        for sm in set.members() {
            match reachable.iter().find(|m| m.id == sm.member_id) {
                Some(m) => {
                    let resp = m
                        .router
                        .clone()
                        .oneshot(
                            Request::builder()
                                .method("GET")
                                .uri(key.0.as_str())
                                .body(Body::empty())
                                .expect("request"),
                        )
                        .await
                        .expect("router answers");
                    let echoed = resp
                        .headers()
                        .get("x-dsm-node-id")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    // THE REAL NODE'S THREE ANSWERS, classified exactly as the
                    // client classifies them: 200 carries the row, 404 is this
                    // member ASSERTING there is none, and anything else — plus
                    // any response this reader cannot attribute — answered
                    // nothing at all.
                    let status = resp.status().as_u16();
                    let attributed = echoed.as_deref() == Some(sm.member_id.as_str());
                    let read = if !attributed {
                        MemberCellRead::Unavailable
                    } else if status == 200 {
                        MemberCellRead::Value(
                            axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                                .await
                                .expect("body")
                                .to_vec(),
                        )
                    } else if status == 404 {
                        MemberCellRead::Absent
                    } else {
                        MemberCellRead::Unavailable
                    };
                    real_rows.push(read);
                }
                // A member this reader cannot reach did not answer.
                None => real_rows.push(MemberCellRead::Unavailable),
            }
        }
        let fake_rows = fake_registers::read(&set, register.kind(), &key.1);
        assert_eq!(real_rows, fake_rows, "read rows, down member unattributed");
        assert_eq!(real_rows[0], MemberCellRead::Value(env.clone()));
        // AND A MEMBER THAT DID NOT ANSWER IS NOT AN ABSENCE. `dsm-node-3` is
        // unreachable here; classifying that as "no row" is what let a quorum
        // of broken members manufacture an emptiness, so the real node and the
        // fake must agree that silence is `Unavailable` and nothing else.
        assert_eq!(
            real_rows[2],
            MemberCellRead::Unavailable,
            "an unreachable member answers nothing, never an absence"
        );
        assert!(
            !matches!(real_rows[2], MemberCellRead::Absent),
            "silence must never be counted as an absence"
        );
        fake_registers::fail_member("dsm-node-3", false);
    }
}

// ── (5): malformed ───────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn malformed_requests_are_refused_identically_not_panicked_on() {
    for register in [Register::Faucet, Register::Root] {
        fake_registers::reset();
        let members = fleet().await;
        let set = client_set(&members);
        let d = device(0x13, &members).await;
        let good = fresh(register, &d, set.id(), 0x31);

        let mut oversize = good.clone();
        oversize.resize(MAX_CLAIM_BYTES + 1, 0);
        let mut appended = good.clone();
        appended.extend_from_slice(&[0x18, 0x01]);
        let mut flipped = good.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;

        for (name, vector, expect) in [
            ("empty body", Vec::new(), "status 400 outcome \"malformed\""),
            (
                "oversize body",
                oversize,
                "status 400 outcome \"malformed\"",
            ),
            (
                "trailing bytes",
                appended,
                "status 400 outcome \"malformed\"",
            ),
            (
                "flipped signature byte",
                flipped,
                "status 403 outcome \"signature-invalid\"",
            ),
        ] {
            let real = real_fanout(&set, &members, register, &vector, Some(&d.auth)).await;
            let fake = fake_fanout(&set, register, &vector, Some(&d.caller()));
            assert_conformant(name, &real, &fake);
            for o in &real.outcomes {
                assert_eq!(
                    o.result,
                    MemberClaimResult::Unavailable(expect.into()),
                    "{name}: the member's refusal, as the client classifies it"
                );
                assert_eq!(o.echoed_node_id.as_deref(), Some(o.member_id.as_str()));
            }
        }
        // And nothing was written: the good envelope is still a first claim.
        let real = real_fanout(&set, &members, register, &good, Some(&d.auth)).await;
        assert!(real
            .outcomes
            .iter()
            .all(|o| o.result == MemberClaimResult::Accepted));
    }
}

// ── (6): wrong signer / attribution ──────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn a_claim_in_someone_elses_name_is_refused_identically() {
    for register in [Register::Faucet, Register::Root] {
        fake_registers::reset();
        let members = fleet().await;
        let set = client_set(&members);
        let victim = device(0x14, &members).await;
        let impostor = device(0x15, &members).await;

        // (a) The impostor's own validly-signed envelope, presented from the
        //     VICTIM's authenticated session: claimant key != caller key.
        let impostor_env = fresh(register, &impostor, set.id(), 0x41);
        let real = real_fanout(&set, &members, register, &impostor_env, Some(&victim.auth)).await;
        let fake = fake_fanout(&set, register, &impostor_env, Some(&victim.caller()));
        assert_conformant("claimant is not the caller", &real, &fake);
        for o in &real.outcomes {
            assert_eq!(
                o.result,
                MemberClaimResult::Unavailable("status 403 outcome \"claimant-not-caller\"".into())
            );
        }

        // (b) The caller's own key, but a body naming ANOTHER device.
        let foreign_devid = [0x77u8; 32];
        let wrong_device = match register {
            Register::Faucet => {
                let mut body = faucet_body(&victim, set.id(), 500, 0x42);
                body.claimant_devid = foreign_devid;
                faucet_envelope(&victim, &body)
            }
            Register::Root => {
                root_envelope_for(&victim, victim.genesis, foreign_devid, set.id(), 500, 0x42)
            }
        };
        let real = real_fanout(&set, &members, register, &wrong_device, Some(&victim.auth)).await;
        let fake = fake_fanout(&set, register, &wrong_device, Some(&victim.caller()));
        assert_conformant("device is not the caller", &real, &fake);
        for o in &real.outcomes {
            assert_eq!(
                o.result,
                MemberClaimResult::Unavailable("status 403 outcome \"device-not-caller\"".into())
            );
        }

        // (c) No authenticated device at all.
        let own = fresh(register, &victim, set.id(), 0x43);
        let real = real_fanout(&set, &members, register, &own, None).await;
        let fake = fake_fanout(&set, register, &own, None);
        assert_conformant("unauthenticated", &real, &fake);
        for o in &real.outcomes {
            assert_eq!(
                o.result,
                MemberClaimResult::Unavailable("status 401 outcome \"\"".into())
            );
            assert_eq!(o.echoed_node_id.as_deref(), Some(o.member_id.as_str()));
        }

        // And the victim's cell is untouched by any of it: its own claim lands.
        let real = real_fanout(&set, &members, register, &own, Some(&victim.auth)).await;
        let fake = fake_fanout(&set, register, &own, Some(&victim.caller()));
        assert_conformant("the victim's own claim afterwards", &real, &fake);
        assert!(real
            .outcomes
            .iter()
            .all(|o| o.result == MemberClaimResult::Accepted));
    }
}

// ── (7): wrong network or catalog ────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn a_claim_for_another_set_or_network_is_refused_identically() {
    // A foreign storage set, on both registers.
    for register in [Register::Faucet, Register::Root] {
        fake_registers::reset();
        let members = fleet().await;
        let set = client_set(&members);
        let d = device(0x16, &members).await;
        let foreign_set = [0x77u8; 32];
        let env = match register {
            Register::Faucet => faucet_envelope(&d, &faucet_body(&d, foreign_set, 600, 0x51)),
            Register::Root => root_envelope(&d, foreign_set, 600, 0x51),
        };
        let real = real_fanout(&set, &members, register, &env, Some(&d.auth)).await;
        let fake = fake_fanout(&set, register, &env, Some(&d.caller()));
        assert_conformant("foreign set", &real, &fake);
        for o in &real.outcomes {
            assert_eq!(
                o.result,
                MemberClaimResult::Unavailable("status 422 outcome \"foreign-set\"".into())
            );
        }
    }

    // The faucet register's network-scoped coordinates.
    fake_registers::reset();
    let members = fleet().await;
    let set = client_set(&members);
    let d = device(0x17, &members).await;

    let mut other_net = faucet_body(&d, set.id(), 601, 0x52);
    other_net.faucet_id = era_faucet_id(b"othernet");
    let other_net = faucet_envelope(&d, &other_net);
    let real = real_fanout(&set, &members, Register::Faucet, &other_net, Some(&d.auth)).await;
    let fake = fake_fanout(&set, Register::Faucet, &other_net, Some(&d.caller()));
    assert_conformant("noncanonical faucet", &real, &fake);
    for o in &real.outcomes {
        assert_eq!(
            o.result,
            MemberClaimResult::Unavailable("status 422 outcome \"noncanonical-faucet\"".into())
        );
    }

    let out_of_range = faucet_envelope(
        &d,
        &faucet_body(&d, set.id(), ERA_FAUCET_TICKET_COUNT, 0x53),
    );
    let real = real_fanout(
        &set,
        &members,
        Register::Faucet,
        &out_of_range,
        Some(&d.auth),
    )
    .await;
    let fake = fake_fanout(&set, Register::Faucet, &out_of_range, Some(&d.caller()));
    assert_conformant("ticket out of range", &real, &fake);
    for o in &real.outcomes {
        assert_eq!(
            o.result,
            MemberClaimResult::Unavailable("status 422 outcome \"ticket-out-of-range\"".into())
        );
    }

    // Members that do not know their network refuse every ticket claim —
    // real: state without a network; double: told no network.
    fake_registers::reset();
    let mut blind = Vec::new();
    for id in MEMBERS {
        blind.push(real_member(id, &MEMBERS, None).await);
    }
    let set = client_set(&blind);
    let d = device(0x18, &blind).await;
    let env = faucet_envelope(&d, &faucet_body(&d, set.id(), 602, 0x54));
    let real = real_fanout(&set, &blind, Register::Faucet, &env, Some(&d.auth)).await;
    let fake = fake_registers::claim(
        &set,
        RegisterKind::FaucetTicket,
        &env,
        Some(&d.caller()),
        None,
    );
    assert_conformant("network unconfigured", &real, &fake);
    for o in &real.outcomes {
        assert_eq!(
            o.result,
            MemberClaimResult::Unavailable("status 503 outcome \"no-network\"".into())
        );
    }

    // A member with no storage set at all is a deployment fault the double
    // cannot be handed — its members ARE the set — so it is pinned on the real
    // side only, through the same classifier.
    let unset = real_member("dsm-node-1", &[], Some(NETWORK)).await;
    let d2 = device(0x19, std::slice::from_ref(&unset)).await;
    let env = faucet_envelope(&d2, &faucet_body(&d2, set.id(), 603, 0x55));
    let o = post_to(&unset, Register::Faucet, &env, Some(&d2.auth)).await;
    assert_eq!(
        o.result,
        MemberClaimResult::Unavailable("status 503 outcome \"no-storage-set\"".into())
    );
    let env = root_envelope(&d2, set.id(), 603, 0x55);
    let o = post_to(&unset, Register::Root, &env, Some(&d2.auth)).await;
    assert_eq!(
        o.result,
        MemberClaimResult::Unavailable("status 503 outcome \"no-storage-set\"".into())
    );
}

// ── (8): concurrent conflicting claims ───────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn concurrent_conflicting_claims_have_exactly_one_winner_per_member() {
    const RACERS: usize = 8;
    for register in [Register::Faucet, Register::Root] {
        fake_registers::reset();
        let members = fleet().await;
        let set = client_set(&members);
        let d = device(0x1A, &members).await;
        // Eight DIFFERENT envelopes for the SAME cell.
        let envelopes: Vec<Vec<u8>> = (0..RACERS as u8)
            .map(|i| match register {
                Register::Faucet => faucet_envelope(&d, &faucet_body(&d, set.id(), 900, 0x60 + i)),
                Register::Root => root_envelope(&d, set.id(), 900, 0x60 + i),
            })
            .collect();
        let digests: Vec<[u8; 32]> = envelopes.iter().map(|e| register.digest(e)).collect();

        // REAL, per member: the racers hit one router concurrently.
        for m in &members {
            let mut tasks = Vec::new();
            for env in &envelopes {
                let router = m.router.clone();
                let env = env.clone();
                let auth = d.auth.clone();
                let mid = m.id.clone();
                let ep = m.endpoint.clone();
                tasks.push(tokio::spawn(async move {
                    let member = RealMember {
                        id: mid,
                        endpoint: ep,
                        pool: Arc::new(db::create_pool(":memory:", true).expect("unused pool")),
                        router,
                    };
                    post_to(&member, register, &env, Some(&auth)).await
                }));
            }
            let mut accepted = 0;
            let mut winner: Option<Vec<u8>> = None;
            let mut refused_naming_winner = 0;
            let mut outcomes = Vec::new();
            for t in tasks {
                outcomes.push(t.await.expect("racer"));
            }
            for (o, digest) in outcomes.iter().zip(digests.iter()) {
                match &o.result {
                    MemberClaimResult::Accepted => {
                        accepted += 1;
                        winner = Some(digest.to_vec());
                    }
                    MemberClaimResult::Refused { held_digest } => {
                        assert!(held_digest.is_some());
                        refused_naming_winner += 1;
                    }
                    other => panic!("{}: unexpected racer outcome {other:?}", m.id),
                }
            }
            assert_eq!(accepted, 1, "{}: exactly one winner", m.id);
            assert_eq!(refused_naming_winner, RACERS - 1);
            let winner = winner.expect("a winner");
            for o in &outcomes {
                if let MemberClaimResult::Refused { held_digest } = &o.result {
                    assert_eq!(
                        held_digest.as_deref(),
                        Some(winner.as_slice()),
                        "{}: every loser names the one winner",
                        m.id
                    );
                }
            }
        }

        // DOUBLE: the same eight envelopes raced from eight threads. Per
        // member, exactly one winner and every loser names it — the property
        // proven above. The double additionally makes every member agree on
        // the SAME winner, because it serialises the whole fan-out; a real
        // fleet's members decide independently and may split, which the
        // client reports as Contested / Conflict. That is a documented
        // modelling limit of the double, not an equivalence claim.
        fake_registers::reset();
        let set2 = set.clone();
        let caller = d.caller();
        let handles: Vec<_> = envelopes
            .iter()
            .cloned()
            .map(|env| {
                let set2 = set2.clone();
                let caller = caller.clone();
                std::thread::spawn(move || {
                    fake_registers::claim(
                        &set2,
                        register.kind(),
                        &env,
                        Some(&caller),
                        register.network(),
                    )
                })
            })
            .collect();
        let fanouts: Vec<ClaimFanout> = handles
            .into_iter()
            .map(|h| h.join().expect("racer"))
            .collect();
        for (idx, member) in set.members().iter().enumerate() {
            let per_member: Vec<&MemberClaimResult> =
                fanouts.iter().map(|f| &f.outcomes[idx].result).collect();
            let accepted = per_member
                .iter()
                .filter(|r| ***r == MemberClaimResult::Accepted)
                .count();
            assert_eq!(
                accepted, 1,
                "double, {}: exactly one winner",
                member.member_id
            );
            let winner_digest = fanouts
                .iter()
                .zip(digests.iter())
                .find(|(f, _)| f.outcomes[idx].result == MemberClaimResult::Accepted)
                .map(|(_, d)| d.to_vec())
                .expect("a winner");
            for r in &per_member {
                if let MemberClaimResult::Refused { held_digest } = r {
                    assert_eq!(held_digest.as_deref(), Some(winner_digest.as_slice()));
                }
            }
        }
    }
}
