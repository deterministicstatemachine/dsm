// SPDX-License-Identifier: MIT OR Apache-2.0

//! Escrow vaults end to end on storage nodes (SoFi §19.9, Amendment S21).
//!
//! Two players, A and B, each lock a stake of ERA against one match: the
//! external commitment `X` they agreed on, and one outcome table — A wins and
//! B wins decided by a referee R, a cancel decided by both players, a void
//! decided by R. A's branches pay A for "a-wins", B for "b-wins", and A's own
//! stake back for "cancel" and "void"; B's the same with B's stake. Both
//! vaults derive one verdict cell, and the routes, the producers and Core run
//! as in production against the pinned set's nodes.

use dsm::sofi::escrow::{self, VerdictCell};
use dsm::sofi::resolve::VaultGenesis;
use dsm::sofi::wire::{EscrowSigner, EscrowTerms, EscrowVerdict};
use dsm::types::proto as generated;
use generated::envelope::Payload;
use serial_test::serial;

use super::node_e2e_tests::{
    adopt, args, balance, create_token, entered, era, head_agrees_with_admitted_root, history_rows,
    invoke, payload, pending_position, position_of, realized_through,
};
use crate::bridge::AppResult;
use crate::economic_fixtures::{whole_era, NETWORK};
use crate::sdk::escrow_flow::exercise_release;
use crate::sdk::route_seats::write_recorded;
use crate::sdk::sofi_flow::{PositionState, SIGNATURE_ALG};
use crate::sdk::sofi_reads::VerifierContext;
use crate::sdk::storage_set::{as_ccb_members, canonical_set};
use crate::test_support::two_device::{Pair, TestDevice};

/// One match both players locked a stake against.
struct Match {
    era: [u8; 32],
    stake: u64,
    verdict_cell: [u8; 32],
    a_vault: [u8; 32],
    b_vault: [u8; 32],
}

/// The referee: a third device on the pair's nodes. It holds nothing; it
/// signs and adjudicates.
async fn referee(p: &Pair) -> TestDevice {
    let mut r = TestDevice::create("R", 0x0C);
    r.boot(&p.fleet).await;
    r
}

async fn party(d: &TestDevice) -> generated::EscrowPartyResponse {
    match payload(&invoke(d, "escrow.party", args(&generated::EscrowPartyRequest {})).await) {
        Payload::EscrowPartyResponse(r) => r,
        other => panic!("escrow.party answered {other:?}"),
    }
}

fn signer_of(party: &generated::EscrowPartyResponse) -> generated::EscrowSignerV1 {
    party.signer.clone().expect("a party names its signer")
}

/// `signers` in their canonical order: `alg ‖ |key| ‖ key`.
fn ascending(mut signers: Vec<generated::EscrowSignerV1>) -> Vec<generated::EscrowSignerV1> {
    signers.sort_by(|x, y| {
        (x.signature_alg, x.public_key.len(), &x.public_key).cmp(&(
            y.signature_alg,
            y.public_key.len(),
            &y.public_key,
        ))
    });
    signers
}

fn branch(
    outcome: &[u8],
    signers: Vec<generated::EscrowSignerV1>,
    to: &generated::EscrowPartyResponse,
) -> generated::EscrowBranchV1 {
    generated::EscrowBranchV1 {
        outcome: outcome.to_vec(),
        signers,
        recipient_genesis: to.genesis.clone(),
        recipient_device_id: to.device_id.clone(),
    }
}

/// The match's branches for the stake of `owner`, ascending by outcome.
fn branches(
    a: &generated::EscrowPartyResponse,
    b: &generated::EscrowPartyResponse,
    r: &generated::EscrowPartyResponse,
    owner: &generated::EscrowPartyResponse,
) -> Vec<generated::EscrowBranchV1> {
    let referee = vec![signer_of(r)];
    let players = ascending(vec![signer_of(a), signer_of(b)]);
    vec![
        branch(b"a-wins", referee.clone(), a),
        branch(b"b-wins", referee.clone(), b),
        branch(b"cancel", players, owner),
        branch(b"void", referee, owner),
    ]
}

async fn lock(
    d: &TestDevice,
    external: &[u8],
    stake: u64,
    branches: Vec<generated::EscrowBranchV1>,
    counterpart: Option<[u8; 32]>,
) -> AppResult {
    let era = era();
    invoke(
        d,
        "escrow.create",
        args(&generated::EscrowCreateRequest {
            external: external.to_vec(),
            token_policy_commit: era.to_vec(),
            amount_entered: entered(d, &era, stake),
            branches,
            counterpart_vault_id: match counterpart {
                Some(v) => v.to_vec(),
                None => Vec::new(),
            },
        }),
    )
    .await
}

fn created(r: &AppResult) -> generated::EscrowCreatedResponse {
    match payload(r) {
        Payload::EscrowCreatedResponse(r) => r,
        other => panic!("escrow.create answered {other:?}"),
    }
}

fn d32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

/// A locks 25 ERA for the match `external`, then B locks 25 ERA against A's
/// vault.
async fn open_match(p: &Pair, r: &TestDevice, external: &[u8]) -> Match {
    let (pa, pb, pr) = (party(&p.a).await, party(&p.b).await, party(r).await);
    let stake = whole_era(25);
    let a = created(&lock(&p.a, external, stake, branches(&pa, &pb, &pr, &pa), None).await);
    let b = created(
        &lock(
            &p.b,
            external,
            stake,
            branches(&pa, &pb, &pr, &pb),
            Some(d32(&a.vault_id)),
        )
        .await,
    );
    assert_eq!(
        a.verdict_cell, b.verdict_cell,
        "one commitment and one outcome table derive one verdict cell"
    );
    assert_eq!(a.external_commitment, b.external_commitment);
    assert_ne!(
        a.vault_id, b.vault_id,
        "each player's stake is its own vault"
    );
    Match {
        era: era(),
        stake,
        verdict_cell: d32(&a.verdict_cell),
        a_vault: d32(&a.vault_id),
        b_vault: d32(&b.vault_id),
    }
}

fn outcome_request(vault_id: &[u8; 32], outcome: &[u8]) -> Vec<u8> {
    args(&generated::EscrowOutcomeRequest {
        vault_id: vault_id.to_vec(),
        outcome: outcome.to_vec(),
    })
}

fn verdict_of(r: &AppResult, route: &str) -> generated::EscrowVerdictResponse {
    match payload(r) {
        Payload::EscrowVerdictResponse(r) => r,
        other => panic!("{route} answered {other:?}"),
    }
}

async fn adjudicate(d: &TestDevice, vault_id: &[u8; 32], outcome: &[u8]) -> AppResult {
    invoke(d, "escrow.adjudicate", outcome_request(vault_id, outcome)).await
}

async fn verdict(d: &TestDevice, vault_id: &[u8; 32]) -> generated::EscrowVerdictResponse {
    verdict_of(
        &invoke(
            d,
            "escrow.verdict",
            args(&generated::EscrowVerdictRequest {
                vault_id: vault_id.to_vec(),
            }),
        )
        .await,
        "escrow.verdict",
    )
}

/// The cell's verdict is final on `outcome`.
fn final_on(v: &generated::EscrowVerdictResponse, m: &Match, outcome: &[u8]) {
    assert_eq!(v.verdict_cell, m.verdict_cell.to_vec());
    assert_eq!(
        (v.state, v.outcome.as_slice()),
        (generated::EscrowVerdictState::Final as i32, outcome),
        "the cell's verdict: {v:?}"
    );
}

fn release_request(vault_id: &[u8; 32]) -> Vec<u8> {
    args(&generated::EscrowReleaseRequest {
        vault_id: vault_id.to_vec(),
    })
}

/// `d`'s `escrow.release` of `vault_id` is refused, with `reason`.
async fn refused_release(d: &TestDevice, vault_id: &[u8; 32], reason: &str) {
    let r = invoke(d, "escrow.release", release_request(vault_id)).await;
    assert!(!r.success, "escrow.release on {} was not refused", d.slot);
    let message = r.error_message.expect("a refusal says why");
    assert!(message.contains(reason), "{message}");
}

async fn vaults_of(
    d: &TestDevice,
    route: &str,
    request: Vec<u8>,
) -> generated::EscrowVaultsResponse {
    match payload(&invoke(d, route, request).await) {
        Payload::EscrowVaultsResponse(r) => r,
        other => panic!("{route} answered {other:?}"),
    }
}

async fn locked(d: &TestDevice, m: &Match) -> generated::EscrowVaultsResponse {
    vaults_of(
        d,
        "escrow.locked",
        args(&generated::EscrowLockedRequest {
            verdict_cell: m.verdict_cell.to_vec(),
        }),
    )
    .await
}

/// `(vault id, amount, status)` of each vault listed, by vault id.
fn holdings(r: &generated::EscrowVaultsResponse) -> Vec<(Vec<u8>, u64, i32)> {
    let mut rows: Vec<_> = r
        .vaults
        .iter()
        .map(|v| (v.vault_id.clone(), v.amount, v.status))
        .collect();
    rows.sort();
    rows
}

/// `(vault, amount, status)` of the two vaults, by vault id.
fn both(
    m: &Match,
    a: (u64, generated::SofiVaultStatus),
    b: (u64, generated::SofiVaultStatus),
) -> Vec<(Vec<u8>, u64, i32)> {
    let mut rows = vec![
        (m.a_vault.to_vec(), a.0, a.1 as i32),
        (m.b_vault.to_vec(), b.0, b.1 as i32),
    ];
    rows.sort();
    rows
}

/// How many of `d`'s history rows are of `tx_type`.
async fn rows_of(d: &TestDevice, tx_type: generated::TransactionType) -> usize {
    history_rows(d)
        .await
        .iter()
        .filter(|row| row.tx_type == tx_type as i32)
        .count()
}

/// The escrow terms `vault_id`'s accepted genesis commits, as `d` reads them.
fn terms_of(d: &TestDevice, vault_id: &[u8; 32]) -> EscrowTerms {
    d.enter();
    let set = canonical_set(NETWORK).expect("the pinned set");
    let ctx = VerifierContext::new(&set, Some((d.genesis, d.device_id)), None).expect("a verifier");
    match ctx
        .verifier()
        .vault_genesis(vault_id)
        .expect("the genesis read")
    {
        VaultGenesis::Accepted(accepted) => accepted.escrow().cloned().expect("an escrow vault"),
        VaultGenesis::NotPublished
        | VaultGenesis::OwnerUnresolved(..)
        | VaultGenesis::Refused(..) => panic!("the vault's genesis is not accepted"),
    }
}

/// `d`'s signature over the statement for `outcome` at `verdict_cell`.
fn signed_by(
    d: &TestDevice,
    verdict_cell: &[u8; 32],
    outcome: &[u8],
) -> dsm::sofi::wire::VerdictSignature {
    d.enter();
    let public_key = crate::sdk::signing_authority::current_public_key().expect("the device's key");
    let signer = EscrowSigner::new(SIGNATURE_ALG, &public_key).expect("a declared key");
    let secret_key =
        crate::sdk::signing_authority::current_secret_key().expect("the device's secret key");
    escrow::sign_statement(&signer, &secret_key, verdict_cell, outcome).expect("signs")
}

/// `d` writes `value` to the verdict cell itself, by the cell's route, as
/// any party can: nothing but the value decides whether it is a verdict.
async fn write_to_cell(d: &TestDevice, m: &Match, value: &EscrowVerdict) {
    d.enter();
    let set = canonical_set(NETWORK).expect("the pinned set");
    let cell = VerdictCell::new(
        &m.verdict_cell,
        &as_ccb_members(&set).expect("the set's members"),
        &set.id(),
    )
    .expect("the verdict cell");
    let wrote = write_recorded(&set, cell.routed(), &value.encode())
        .await
        .expect("the write");
    assert!(wrote.reached_leader(), "the cell's leader took the value");
}

/// The match settles A's way: A takes both stakes, once, and B takes nothing.
///
/// - A release before any verdict builds nothing.
/// - B's release of a branch paying A is refused by its producer, and when B
///   builds it past the producer, by Core.
/// - Once the referee's verdict is final, A releases both vaults; a second
///   release of either finds it retired.
/// - Every escrow route answers through its producer, and an `escrow.`
///   method the router does not declare is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_winner_takes_both_stakes_once() {
    let p = Pair::boot(100, 100).await;
    let r = referee(&p).await;
    let m = open_match(&p, &r, b"match 1: A v B, 25 ERA each, referee R").await;
    assert_eq!(balance(&p.a, &m.era), whole_era(100) - m.stake);
    assert_eq!(balance(&p.b, &m.era), whole_era(100) - m.stake);
    let active = generated::SofiVaultStatus::Active;
    let retired = generated::SofiVaultStatus::Retired;
    let listed = locked(&r, &m).await;
    assert_eq!(
        holdings(&listed),
        both(&m, (m.stake, active), (m.stake, active))
    );
    assert_eq!(listed.search, generated::SofiSearch::Complete as i32);

    // No verdict yet: the cell is open, and a release builds nothing.
    let open = verdict(&p.a, &m.a_vault).await;
    assert_eq!(open.state, generated::EscrowVerdictState::None as i32);
    refused_release(&p.a, &m.a_vault, "no verdict holds the cell yet").await;
    assert_eq!(pending_position(&p.a), None);

    // The referee decides; both vaults read the one verdict.
    final_on(
        &verdict_of(
            &adjudicate(&r, &m.a_vault, b"a-wins").await,
            "escrow.adjudicate",
        ),
        &m,
        b"a-wins",
    );
    final_on(&verdict(&p.b, &m.b_vault).await, &m, b"a-wins");

    // The loser cannot take a branch that pays the winner: its producer
    // refuses, and past the producer Core refuses the draft.
    refused_release(&p.b, &m.a_vault, "pays another identity").await;
    p.b.enter();
    let set = canonical_set(NETWORK).expect("the pinned set");
    match exercise_release(&p.b.router().core_sdk, &set, &m.a_vault, b"a-wins".to_vec()).await {
        Err(e) => assert!(e.to_string().contains("NotTheBranchRecipient"), "{e}"),
        Ok(..) => panic!("B's release of A's branch was taken"),
    }
    assert_eq!(pending_position(&p.b), None);
    assert_eq!(balance(&p.b, &m.era), whole_era(100) - m.stake);

    realized_through(&p.a, "escrow.release", release_request(&m.a_vault)).await;
    realized_through(&p.a, "escrow.release", release_request(&m.b_vault)).await;
    assert_eq!(balance(&p.a, &m.era), whole_era(100) + m.stake);
    assert_eq!(balance(&p.b, &m.era), whole_era(100) - m.stake);
    head_agrees_with_admitted_root(&p.a, &[m.era]);

    // Released is retired: there is no second release.
    refused_release(&p.a, &m.a_vault, "already released").await;
    refused_release(&p.a, &m.b_vault, "already released").await;
    assert_eq!(
        holdings(&locked(&p.b, &m).await),
        both(&m, (0, retired), (0, retired))
    );
    let own = vaults_of(
        &p.a,
        "escrow.vaults",
        args(&generated::EscrowVaultsRequest {}),
    )
    .await;
    assert_eq!(
        holdings(&own),
        vec![(m.a_vault.to_vec(), 0, retired as i32)]
    );

    let lock = generated::TransactionType::TxTypeEscrowLock;
    let release = generated::TransactionType::TxTypeEscrowRelease;
    assert_eq!(rows_of(&p.a, lock).await, 1);
    assert_eq!(rows_of(&p.a, release).await, 2);
    assert_eq!(rows_of(&p.b, lock).await, 1);
    assert_eq!(rows_of(&p.b, release).await, 0);

    let unknown = invoke(&p.a, "escrow.close", release_request(&m.a_vault)).await;
    assert!(!unknown.success);
    assert!(
        unknown
            .error_message
            .expect("a refusal says why")
            .contains("unknown invoke method"),
        "the router declares no escrow.close"
    );
}

/// One commitment has one verdict (owner, 2026-10-05). A referee who signs
/// both outcomes settles both vaults on the verdict that reached the cell
/// first: the later one is written, and the cell still holds the first. A
/// release B builds on the later verdict's outcome, past its producer's
/// check, is void at Core — nothing moves — and both stakes still go to A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_referee_who_signs_both_outcomes_settles_both_vaults_on_the_first() {
    let p = Pair::boot(100, 100).await;
    let r = referee(&p).await;
    let m = open_match(&p, &r, b"match 2: A v B, 25 ERA each, referee R").await;

    final_on(
        &verdict_of(
            &adjudicate(&r, &m.a_vault, b"a-wins").await,
            "escrow.adjudicate",
        ),
        &m,
        b"a-wins",
    );
    final_on(
        &verdict_of(
            &adjudicate(&r, &m.b_vault, b"b-wins").await,
            "escrow.adjudicate",
        ),
        &m,
        b"a-wins",
    );
    refused_release(&p.b, &m.b_vault, "pays another identity").await;

    p.b.enter();
    let set = canonical_set(NETWORK).expect("the pinned set");
    let built = exercise_release(&p.b.router().core_sdk, &set, &m.b_vault, b"b-wins".to_vec())
        .await
        .expect("B's release on b-wins is a well-formed position");
    let state = match built.state {
        PositionState::RetriesExhausted => {
            let (position, state) = position_of(
                &invoke(
                    &p.b,
                    "sofi.resolve",
                    args(&generated::SofiResolveRequest {}),
                )
                .await,
                "sofi.resolve",
            );
            assert_eq!(position, built.position);
            state
        }
        PositionState::Realized => generated::SofiPositionState::Realized as i32,
        PositionState::Void => generated::SofiPositionState::Void as i32,
        PositionState::Invalid => generated::SofiPositionState::Invalid as i32,
    };
    assert_eq!(
        state,
        generated::SofiPositionState::Void as i32,
        "a release on the outcome the cell's verdict is not on is void"
    );
    assert_eq!(pending_position(&p.b), None);
    assert_eq!(balance(&p.b, &m.era), whole_era(100) - m.stake);

    realized_through(&p.a, "escrow.release", release_request(&m.b_vault)).await;
    realized_through(&p.a, "escrow.release", release_request(&m.a_vault)).await;
    assert_eq!(balance(&p.a, &m.era), whole_era(100) + m.stake);
    assert_eq!(balance(&p.b, &m.era), whole_era(100) - m.stake);
}

/// Nothing but a verdict that proves its own authority occupies the cell.
/// B writes a "b-wins" signed by its own key — not the outcome's signer —
/// and the referee's genuine "a-wins" made for another match's cell; the
/// cell holds no verdict, each is passed over with its reason, and nothing
/// can be released. The referee's verdict, written after both, is the cell's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_verdict_outside_the_authority_cannot_occupy_the_cell() {
    let p = Pair::boot(100, 100).await;
    let r = referee(&p).await;
    let m = open_match(&p, &r, b"match 3: A v B, 25 ERA each, referee R").await;
    let terms = terms_of(&p.b, &m.a_vault);
    assert_eq!(escrow::verdict_cell_of(&terms), m.verdict_cell);

    let forged = EscrowVerdict::new(
        *terms.external_commitment(),
        terms.outcome_table(),
        b"b-wins",
        vec![signed_by(&p.b, &m.verdict_cell, b"b-wins")],
    )
    .expect("a verdict's bytes");
    write_to_cell(&p.b, &m, &forged).await;

    let elsewhere = EscrowTerms::new(
        *terms.token(),
        escrow::external_commitment(b"match 4"),
        terms.branches().to_vec(),
    )
    .expect("terms");
    let other_cell = escrow::verdict_cell_of(&elsewhere);
    let misplaced = EscrowVerdict::new(
        *elsewhere.external_commitment(),
        elsewhere.outcome_table(),
        b"a-wins",
        vec![signed_by(&r, &other_cell, b"a-wins")],
    )
    .expect("a verdict's bytes");
    write_to_cell(&p.b, &m, &misplaced).await;

    let open = verdict(&p.a, &m.a_vault).await;
    assert_eq!(open.state, generated::EscrowVerdictState::None as i32);
    assert_eq!(open.passed_over.len(), 2, "{:?}", open.passed_over);
    assert!(open.passed_over[0].contains("NotTheOutcomesSigners"));
    assert!(open.passed_over[1].contains("NotThisCell"));
    refused_release(&p.b, &m.b_vault, "no verdict holds the cell yet").await;

    let decided = verdict_of(
        &adjudicate(&r, &m.a_vault, b"a-wins").await,
        "escrow.adjudicate",
    );
    final_on(&decided, &m, b"a-wins");
    assert_eq!(decided.passed_over.len(), 2);
    realized_through(&p.a, "escrow.release", release_request(&m.b_vault)).await;
    assert_eq!(balance(&p.a, &m.era), whole_era(100));
}

/// A cancel is decided by both players and only by both: the referee cannot
/// adjudicate it, and one player's signature does not complete it. Once both
/// sign, the cancel is the cell's verdict, a referee result written after it
/// settles nothing, and each player takes back its own stake only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_joint_cancel_and_a_referee_result_cannot_both_settle() {
    let p = Pair::boot(100, 100).await;
    let r = referee(&p).await;
    let m = open_match(&p, &r, b"match 5: A v B, 25 ERA each, referee R").await;

    let by_referee = adjudicate(&r, &m.a_vault, b"cancel").await;
    assert!(!by_referee.success);
    assert!(by_referee
        .error_message
        .expect("a refusal says why")
        .contains("do not decide"));
    let signed =
        match payload(&invoke(&p.a, "escrow.sign", outcome_request(&m.a_vault, b"cancel")).await) {
            Payload::EscrowSignedResponse(s) => s,
            other => panic!("escrow.sign answered {other:?}"),
        };
    assert_eq!(signed.verdict_cell, m.verdict_cell.to_vec());
    let alone = adjudicate(&p.a, &m.a_vault, b"cancel").await;
    assert!(!alone.success, "one player's signature is no cancel");
    assert_eq!(
        verdict(&r, &m.a_vault).await.state,
        generated::EscrowVerdictState::None as i32,
        "nothing was written for a verdict the signatures do not complete"
    );

    final_on(
        &verdict_of(
            &adjudicate(&p.b, &m.b_vault, b"cancel").await,
            "escrow.adjudicate",
        ),
        &m,
        b"cancel",
    );
    final_on(
        &verdict_of(
            &adjudicate(&r, &m.a_vault, b"a-wins").await,
            "escrow.adjudicate",
        ),
        &m,
        b"cancel",
    );

    refused_release(&p.a, &m.b_vault, "pays another identity").await;
    realized_through(&p.a, "escrow.release", release_request(&m.a_vault)).await;
    realized_through(&p.b, "escrow.release", release_request(&m.b_vault)).await;
    assert_eq!(balance(&p.a, &m.era), whole_era(100));
    assert_eq!(balance(&p.b, &m.era), whole_era(100));
}

/// An escrow vault is not a market: it is not traded through, its owner
/// cannot close it, and it is not among the owner's market vaults. A stake
/// locked against a vault bound to another verdict cell is not locked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_escrow_vault_has_no_market_and_no_owner_close() {
    let p = Pair::boot(100, 100).await;
    let r = referee(&p).await;
    let (pa, pb, pr) = (party(&p.a).await, party(&p.b).await, party(&r).await);
    let stake = whole_era(25);
    let a = created(&lock(&p.a, b"match 6", stake, branches(&pa, &pb, &pr, &pa), None).await);
    let a_vault = d32(&a.vault_id);

    let closed = invoke(
        &p.a,
        "sofi.close",
        args(&generated::SofiCloseRequest {
            vault_id: a_vault.to_vec(),
        }),
    )
    .await;
    assert!(!closed.success);
    assert!(closed
        .error_message
        .expect("a refusal says why")
        .contains("no market"));

    let tkn = create_token(&p.a, "TKN", 1_000).await;
    adopt(&p.b, &tkn).await;
    let era = era();
    let traded = invoke(
        &p.b,
        "sofi.trade",
        args(&generated::SofiTradeRequest {
            vault_id: a_vault.to_vec(),
            token_in_policy_commit: era.to_vec(),
            amount_in_entered: entered(&p.b, &era, whole_era(1)),
            min_amount_out_entered: entered(&p.b, &tkn, 1),
            token_out_policy_commit: tkn.to_vec(),
        }),
    )
    .await;
    assert!(!traded.success);
    let message = traded.error_message.expect("a refusal says why");
    assert!(message.contains("no market"), "{message}");

    let markets =
        match payload(&invoke(&p.a, "sofi.vaults", args(&generated::SofiVaultsRequest {})).await) {
            Payload::SofiVaultsResponse(r) => r.vaults,
            other => panic!("sofi.vaults answered {other:?}"),
        };
    assert!(markets.is_empty(), "an escrow vault is no market vault");
    let own = vaults_of(
        &p.a,
        "escrow.vaults",
        args(&generated::EscrowVaultsRequest {}),
    )
    .await;
    assert_eq!(
        holdings(&own),
        vec![(
            a_vault.to_vec(),
            stake,
            generated::SofiVaultStatus::Active as i32
        )]
    );

    let elsewhere = lock(
        &p.b,
        b"match 7",
        stake,
        branches(&pa, &pb, &pr, &pb),
        Some(a_vault),
    )
    .await;
    assert!(!elsewhere.success);
    assert!(elsewhere
        .error_message
        .expect("a refusal says why")
        .contains("another verdict cell"));
    assert_eq!(balance(&p.b, &era), whole_era(100));
    assert_eq!(pending_position(&p.b), None);
}

// ── escrow.lock: parties named by device id ────────────────────────────────

/// An outcome of `escrow.lock`: its label, who decides it and who it pays,
/// each by device id.
fn named(
    outcome: &[u8],
    decided_by: &[&TestDevice],
    pays: &TestDevice,
) -> generated::EscrowLockOutcomeV1 {
    generated::EscrowLockOutcomeV1 {
        outcome: outcome.to_vec(),
        decided_by: decided_by.iter().map(|d| d.device_id.to_vec()).collect(),
        pays: pays.device_id.to_vec(),
    }
}

async fn lock_named(
    d: &TestDevice,
    external: &[u8],
    stake: u64,
    outcomes: Vec<generated::EscrowLockOutcomeV1>,
) -> AppResult {
    let era = era();
    invoke(
        d,
        "escrow.lock",
        args(&generated::EscrowLockRequest {
            external: external.to_vec(),
            token_policy_commit: era.to_vec(),
            amount_entered: entered(d, &era, stake),
            outcomes,
            counterpart_vault_id: Vec::new(),
        }),
    )
    .await
}

/// What the one vault `r` lists means for the device that listed it: its
/// outcomes in table order, the ones this device decides, and the ones that
/// pay it.
struct ForMe {
    outcomes: Vec<&'static [u8]>,
    decides: Vec<&'static [u8]>,
    paid_by: Vec<&'static [u8]>,
}

fn read_for_me(r: &generated::EscrowVaultsResponse) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let [vault] = r.vaults.as_slice() else {
        panic!("one vault is listed: {:?}", r.vaults.len())
    };
    let labels = |keep: fn(&generated::EscrowVaultOutcomeV1) -> bool| -> Vec<Vec<u8>> {
        vault
            .outcomes
            .iter()
            .filter(|o| keep(o))
            .map(|o| o.outcome.clone())
            .collect()
    };
    (
        vault.outcomes.iter().map(|o| o.outcome.clone()).collect(),
        labels(|o| o.decided_by_this_device),
        labels(|o| o.pays_this_device),
    )
}

fn as_listed(want: ForMe) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let owned = |v: Vec<&[u8]>| v.into_iter().map(<[u8]>::to_vec).collect();
    (
        owned(want.outcomes),
        owned(want.decides),
        owned(want.paid_by),
    )
}

/// `escrow.lock` names each outcome's signers and recipient by device id, in
/// any order, and the stake it locks is exactly the one `escrow.create` locks
/// with those parties' keys in the table's one order: the same terms, so the
/// same verdict cell. A's outcomes are listed out of order, and "b-done"'s
/// signers too (B before A); the committed terms are canonical. Each device's
/// listing says which outcomes it decides and which pay it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_stake_locked_by_naming_its_parties_commits_the_terms_their_keys_would() {
    let p = Pair::boot(100, 0).await;
    let (pa, pb) = (party(&p.a).await, party(&p.b).await);
    let stake = whole_era(10);
    let external = b"delivery 7: B ships to A";
    let made = created(
        &lock_named(
            &p.a,
            external,
            stake,
            vec![
                named(b"b-done", &[&p.b, &p.a], &p.b),
                named(b"a-done", &[&p.a], &p.a),
            ],
        )
        .await,
    );
    assert_eq!(
        balance(&p.a, &era()),
        whole_era(100) - stake,
        "the stake is locked"
    );

    // The terms the vault committed are the canonical ones the parties' own
    // keys give: outcomes ascending, each signer set ascending.
    let key = |party: &generated::EscrowPartyResponse| {
        EscrowSigner::new(SIGNATURE_ALG, &signer_of(party).public_key).expect("a signer")
    };
    let mut both = vec![key(&pa), key(&pb)];
    both.sort_by_key(EscrowSigner::canonical);
    let expected = EscrowTerms::new(
        era(),
        escrow::external_commitment(external),
        vec![
            dsm::sofi::wire::EscrowBranch::new(
                dsm::sofi::wire::EscrowOutcome::new(b"a-done", vec![key(&pa)]).expect("an outcome"),
                d32(&pa.genesis),
                d32(&pa.device_id),
            ),
            dsm::sofi::wire::EscrowBranch::new(
                dsm::sofi::wire::EscrowOutcome::new(b"b-done", both).expect("an outcome"),
                d32(&pb.genesis),
                d32(&pb.device_id),
            ),
        ],
    )
    .expect("canonical terms");
    let vault = d32(&made.vault_id);
    assert_eq!(terms_of(&p.a, &vault), expected);
    assert_eq!(d32(&made.verdict_cell), escrow::verdict_cell_of(&expected));

    // A decides both outcomes and is paid by "a-done"; B, reading the same
    // vault by its cell, decides "b-done" and is paid by it.
    let own = vaults_of(
        &p.a,
        "escrow.vaults",
        args(&generated::EscrowVaultsRequest {}),
    )
    .await;
    assert_eq!(
        read_for_me(&own),
        as_listed(ForMe {
            outcomes: vec![b"a-done", b"b-done"],
            decides: vec![b"a-done", b"b-done"],
            paid_by: vec![b"a-done"],
        })
    );
    let by_cell = vaults_of(
        &p.b,
        "escrow.locked",
        args(&generated::EscrowLockedRequest {
            verdict_cell: made.verdict_cell.clone(),
        }),
    )
    .await;
    assert_eq!(
        read_for_me(&by_cell),
        as_listed(ForMe {
            outcomes: vec![b"a-done", b"b-done"],
            decides: vec![b"b-done"],
            paid_by: vec![b"b-done"],
        })
    );
}

/// `escrow.lock` names only parties this device holds, and refuses a table
/// it could not build before anything is locked: a device that is neither
/// this one nor a contact, a label listed twice, a device listed twice among
/// one outcome's signers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn escrow_lock_refuses_a_party_it_does_not_hold_and_a_repeated_name() {
    let p = Pair::boot(100, 0).await;
    let stranger = referee(&p).await;
    let stake = whole_era(10);
    let cases: [(&str, Vec<generated::EscrowLockOutcomeV1>); 3] = [
        (
            "is neither this device nor a contact",
            vec![named(b"done", &[&stranger], &p.a)],
        ),
        (
            "two outcomes are labelled",
            vec![named(b"done", &[&p.a], &p.a), named(b"done", &[&p.b], &p.b)],
        ),
        (
            "lists one device twice among its signers",
            vec![named(b"done", &[&p.a, &p.b, &p.a], &p.a)],
        ),
    ];
    for (reason, outcomes) in cases {
        let refused = lock_named(&p.a, b"terms", stake, outcomes).await;
        assert!(!refused.success, "{reason}: locked anyway");
        let message = refused.error_message.expect("a refusal says why");
        assert!(message.contains(reason), "{reason}: {message}");
    }
    assert_eq!(balance(&p.a, &era()), whole_era(100), "nothing was locked");
    let own = vaults_of(
        &p.a,
        "escrow.vaults",
        args(&generated::EscrowVaultsRequest {}),
    )
    .await;
    assert!(own.vaults.is_empty(), "no vault was created");
}
