// SPDX-License-Identifier: MIT OR Apache-2.0

//! Computed escrow vaults end to end on storage nodes (SoFi §19.10,
//! Amendment S22): a staked match decided by the registered `wildstate-duel`
//! program from the players' signed transcript, with no referee.
//!
//! Two players, A and B, lock a stake of ERA each in one match: the setup
//! names both, their session keys and the program. Each wallet readies once
//! it verified both vaults, the second writes the Start, and the players then
//! sign their entries through their own wallets with no storage write until
//! the winner settles the whole transcript at the match cell and collects
//! both stakes. Every step runs the wallet's production code against the
//! pinned set's nodes, and Core decides every outcome from the cells.

use dsm::sofi::computed;
use dsm::sofi::wire::{EntryKind, MatchSide, StartKind, TranscriptEntry};
use dsm::types::error::DsmError;
use serial_test::serial;
use wildstate_duel::vectors::DuelVectorSetV1;
use wildstate_duel::creatures::CreatureRecordV1;
use wildstate_duel::{CreatureStateV1, DuelMatchV1, DuelSetupV1, DuelSide, DuelTurnV1};

use super::node_e2e_tests::{balance, era, pending_position};
use crate::economic_fixtures::{whole_era, NETWORK};
use crate::sdk::computed_flow::{self, LockIntent, Locked, MatchView, SignedEntry};
use crate::sdk::sofi_flow::PositionState;
use crate::sdk::storage_set::canonical_set;
use crate::test_support::two_device::{Pair, TestDevice};

type D32 = [u8; 32];

fn set() -> crate::sdk::storage_set::StorageSet {
    canonical_set(NETWORK).expect("the pinned set")
}

/// A frozen match of several turns: its teams, and the moves it was played
/// with.
pub(super) fn frozen() -> (DuelMatchV1, Vec<DuelTurnV1>) {
    let vectors = DuelVectorSetV1::decode(wildstate_duel::VECTORS_V1).expect("the vectors");
    let long = vectors
        .vectors
        .into_iter()
        .max_by_key(|v| v.turns.len())
        .expect("a vector");
    (long.body, long.turns)
}

fn session_key(d: &TestDevice, nonce: &D32) -> Vec<u8> {
    d.enter();
    computed_flow::session_public_key(nonce).expect("a session key")
}

/// `d` issues the creatures of its side of the frozen match, `of`, as its
/// own: for each, a token of supply one `d` creates (`prefix` names its
/// tickers) and holds, and the frozen state under that anchor, published by
/// `d` as the record the creature was issued with. What a wallet locking a
/// stake reads its teams against.
pub(super) async fn issue_team(
    d: &TestDevice,
    of: &DuelSide,
    prefix: &str,
) -> Vec<CreatureStateV1> {
    use crate::bridge::{AppInvoke, AppRouter};
    use prost::Message;
    d.enter();
    let mut team = Vec::new();
    for (i, frozen) in of.team.iter().enumerate() {
        let request = crate::handlers::token_create_tests::request(&format!("{prefix}{i}"), 0, 1);
        let result = d
            .router()
            .invoke(AppInvoke {
                method: "token.create".to_string(),
                args: dsm::types::proto::ArgPack {
                    schema_hash: None,
                    codec: dsm::types::proto::Codec::Proto as i32,
                    body: request.encode_to_vec(),
                }
                .encode_to_vec(),
            })
            .await;
        assert!(result.success, "token.create: {:?}", result.error_message);
        let anchor: D32 =
            match crate::handlers::response_helpers::decode_local_envelope(&result.data)
                .expect("a local answer")
                .payload
            {
                Some(dsm::types::proto::envelope::Payload::TokenCreateResponse(r)) => {
                    r.policy_anchor.as_slice().try_into().expect("an anchor")
                }
                other => panic!("token.create answered {other:?}"),
            };
        let state = CreatureStateV1::new(
            anchor,
            frozen.species(),
            frozen.xp(),
            frozen.hp(),
            frozen.charges().to_vec(),
        )
        .expect("the frozen state under the new anchor");
        // Issued at its birth state (owner ruling 2026-10-06), then played on
        // to the frozen match's state as a successor naming it.
        let birth = CreatureRecordV1 {
            parent: None,
            state: CreatureStateV1::birth(anchor, state.species()).expect("the birth state"),
        };
        let mut records = vec![birth.clone()];
        if birth.state != state {
            records.push(CreatureRecordV1 {
                parent: Some(birth.digest()),
                state: state.clone(),
            });
        }
        for record in records {
            let published =
                crate::sdk::authored_objects::publish(&set(), &anchor, &record.encode())
                    .await
                    .expect("a record of the creature");
            assert!(published.stored, "the record is Stored");
        }
        team.push(state);
    }
    team
}

/// The setup of a match between `a` and `b` fielding `team_a` and `team_b`
/// in the frozen match, each side naming its wallet's identity and its
/// session key, and the tiebreak seed both keys and the nonce derive.
pub(super) fn setup_with_keys(
    a: &TestDevice,
    b: &TestDevice,
    nonce: D32,
    (key_a, team_a): (&[u8], &[CreatureStateV1]),
    (key_b, team_b): (&[u8], &[CreatureStateV1]),
) -> Vec<u8> {
    let (body, _) = frozen();
    let side = |of: &DuelSide, d: &TestDevice, key: &[u8], team: &[CreatureStateV1]| DuelSide {
        genesis: d.genesis,
        device_id: d.device_id,
        session_public_key: key.to_vec(),
        team: team.to_vec(),
        ..of.clone()
    };
    let side_a = side(body.a(), a, key_a, team_a);
    let side_b = side(body.b(), b, key_b, team_b);
    let seed = wildstate_duel::tiebreak_seed(&nonce, key_a, key_b);
    let body = DuelMatchV1::new(nonce, body.turn_cap(), seed, side_a, side_b).expect("a match");
    DuelSetupV1 {
        program: wildstate_duel::program_hash(),
        body,
    }
    .encode()
}

/// Both players' frozen teams, each issued by its own player's wallet.
async fn teams(p: &Pair) -> (Vec<CreatureStateV1>, Vec<CreatureStateV1>) {
    let (body, _) = frozen();
    (
        issue_team(&p.a, body.a(), "CRA").await,
        issue_team(&p.b, body.b(), "CRB").await,
    )
}

fn setup(
    p: &Pair,
    nonce: D32,
    (team_a, team_b): &(Vec<CreatureStateV1>, Vec<CreatureStateV1>),
) -> Vec<u8> {
    let (key_a, key_b) = (session_key(&p.a, &nonce), session_key(&p.b, &nonce));
    setup_with_keys(&p.a, &p.b, nonce, (&key_a, team_a), (&key_b, team_b))
}

/// `d`'s proof that it holds the creatures `setup` fields on `side`, as its
/// own wallet makes it for an opponent's lock.
pub(super) fn holdings_of(
    d: &TestDevice,
    setup: &[u8],
    side: MatchSide,
) -> dsm::types::proto::HoldingsProofV1 {
    let body = DuelSetupV1::decode(setup).expect("a setup").body;
    let team = match side {
        MatchSide::A => &body.a().team,
        MatchSide::B => &body.b().team,
    };
    let anchors: Vec<D32> = team.iter().map(|c| *c.anchor()).collect();
    d.enter();
    crate::sdk::connect::holdings::prove(&d.router().core_sdk, &anchors).expect("a holdings proof")
}

async fn lock(
    d: &TestDevice,
    other: &TestDevice,
    setup: &[u8],
    side: MatchSide,
    stake: u64,
    counterpart: Option<D32>,
) -> Result<Locked, DsmError> {
    let opponent_holdings = holdings_of(other, setup, side.other());
    d.enter();
    computed_flow::create(
        &d.router().core_sdk,
        &set(),
        &LockIntent {
            setup: setup.to_vec(),
            side,
            token: era(),
            amount: stake,
            opponent: (other.genesis, other.device_id),
            counterpart,
            opponent_holdings: Some(prost::Message::encode_to_vec(&opponent_holdings)),
        },
    )
    .await
}

async fn ready(d: &TestDevice, cell: &D32, theirs: Option<&[u8]>) -> computed_flow::Readied {
    d.enter();
    computed_flow::ready(&d.router().core_sdk, &set(), cell, theirs)
        .await
        .expect("ready")
}

fn view(d: &TestDevice, cell: &D32) -> MatchView {
    d.enter();
    computed_flow::view(&d.router().core_sdk, &set(), cell).expect("the match's cells")
}

/// One match both players locked a stake in.
struct Match {
    stake: u64,
    /// Each player's ERA once its creatures were issued, before its lock.
    a_start: u64,
    b_start: u64,
    cell: D32,
    a_vault: D32,
    b_vault: D32,
}

/// Each player issues its team; A locks 25 ERA, then B locks 25 ERA against
/// A's vault.
async fn open_match(p: &Pair, nonce: D32) -> (Match, Vec<u8>) {
    let setup = setup(p, nonce, &teams(p).await);
    let (a_start, b_start) = (balance(&p.a, &era()), balance(&p.b, &era()));
    let stake = whole_era(25);
    let a = lock(&p.a, &p.b, &setup, MatchSide::A, stake, None)
        .await
        .expect("A's lock");
    let b = lock(&p.b, &p.a, &setup, MatchSide::B, stake, Some(a.vault_id))
        .await
        .expect("B's lock");
    assert_eq!(a.match_cell, b.match_cell, "one setup binds one match cell");
    assert_eq!(a.program, wildstate_duel::program_hash());
    assert_ne!(a.vault_id, b.vault_id);
    (
        Match {
            stake,
            a_start,
            b_start,
            cell: a.match_cell,
            a_vault: a.vault_id,
            b_vault: b.vault_id,
        },
        setup,
    )
}

/// A readies first; B readies second with A's ready and writes the Start.
async fn start(p: &Pair, m: &Match) {
    let a = ready(&p.a, &m.cell, None).await;
    assert_eq!(a.view.start, None, "one ready is no Start");
    let b = ready(&p.b, &m.cell, Some(&a.ready_signature)).await;
    assert_eq!(
        b.view.start,
        Some((StartKind::Start, dsm::route_chain::ChainState::Final))
    );
}

/// The transcript as the test's relay carries it between the two wallets.
struct Relay {
    cell: D32,
    entries: Vec<(MatchSide, Vec<u8>, Vec<u8>)>,
    /// How many entries each wallet has applied.
    seen: [usize; 2],
}

fn at(side: MatchSide) -> usize {
    match side {
        MatchSide::A => 0,
        MatchSide::B => 1,
    }
}

impl Relay {
    fn new(cell: D32) -> Self {
        Self {
            cell,
            entries: Vec::new(),
            seen: [0, 0],
        }
    }

    fn next_index(&self) -> u32 {
        self.entries.len() as u32 + 1
    }

    /// The other side's entries `side`'s wallet has not applied.
    fn unseen(&self, side: MatchSide) -> Vec<SignedEntry> {
        self.entries[self.seen[at(side)]..]
            .iter()
            .map(|(_, entry, signature)| SignedEntry {
                entry: entry.clone(),
                signature: signature.clone(),
            })
            .collect()
    }

    /// `d`, playing `side`, signs `entry` after the entries it has not seen.
    fn try_sign(
        &self,
        d: &TestDevice,
        side: MatchSide,
        entry: &[u8],
    ) -> Result<computed_flow::EntrySigned, DsmError> {
        d.enter();
        computed_flow::sign_entry(
            &d.router().core_sdk,
            &set(),
            &self.cell,
            &self.unseen(side),
            entry,
        )
    }

    fn sign(&mut self, d: &TestDevice, side: MatchSide, kind: EntryKind) -> Vec<u8> {
        let entry = TranscriptEntry::new(self.next_index(), side, kind)
            .expect("an entry")
            .encode();
        let signed = self.try_sign(d, side, &entry).expect("the wallet signs");
        assert_eq!(signed.index, self.next_index());
        self.entries.push((side, entry.clone(), signed.signature));
        self.seen[at(side)] = self.entries.len();
        entry
    }
}

pub(super) fn salt(index: u32, side: MatchSide) -> D32 {
    [index as u8 ^ side.byte().wrapping_mul(0x40); 32]
}

/// One turn: both commit, then both reveal.
fn play_turn(p: &Pair, relay: &mut Relay, turn: &DuelTurnV1) {
    let first = relay.next_index();
    let moves = [(MatchSide::A, turn.a), (MatchSide::B, turn.b)];
    for (side, played) in moves {
        let d = if side == MatchSide::A { &p.a } else { &p.b };
        let commitment = computed::move_commitment(&salt(first, side), &played.encode());
        relay.sign(d, side, EntryKind::Commit { commitment });
    }
    for (side, played) in moves {
        let d = if side == MatchSide::A { &p.a } else { &p.b };
        relay.sign(
            d,
            side,
            EntryKind::Reveal {
                salt: salt(first, side),
                played: played.encode(),
            },
        );
    }
}

/// Writes the nodes were asked to take: cells, objects, indexes, envelopes.
fn writes(p: &Pair) -> Vec<String> {
    let written = |r: &String| {
        [
            "POST /api/v2/cell",
            "POST /api/v2/immutable/put",
            "POST /api/v2/index",
            "POST /api/v2/b0x/submit",
        ]
        .iter()
        .any(|w| r.starts_with(w))
    };
    p.nodes
        .nodes
        .iter()
        .flat_map(|n| n.requests())
        .filter(written)
        .collect()
}

fn forget_requests(p: &Pair) {
    for n in &p.nodes.nodes {
        n.forget_requests();
    }
}

async fn settle(d: &TestDevice, cell: &D32, given: &[SignedEntry]) -> Result<MatchView, DsmError> {
    d.enter();
    computed_flow::settle(&d.router().core_sdk, &set(), cell, given).await
}

/// `d` releases `vault`, and the release realizes.
async fn collect(d: &TestDevice, vault: &D32) {
    d.enter();
    let core = &d.router().core_sdk;
    let done = computed_flow::release(core, &set(), vault)
        .await
        .expect("the release");
    if done.state != PositionState::Realized {
        let resolved = crate::sdk::sofi_flow::resolve(core, &set())
            .await
            .expect("the release resolves");
        assert_eq!(
            (resolved.position, resolved.state),
            (done.position, PositionState::Realized)
        );
    }
}

async fn refused_collect(d: &TestDevice, vault: &D32, reason: &str) {
    d.enter();
    match computed_flow::release(&d.router().core_sdk, &set(), vault).await {
        Err(e) => assert!(e.to_string().contains(reason), "{e}"),
        Ok(done) => panic!("{}'s release was built: {done:?}", d.slot),
    }
}

/// The match is played by both wallets' signatures alone and decided by the
/// program: A wins when B resigns after three turns, A's settlement is the
/// match's only write, and A collects both stakes once; B collects nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_winner_by_computation_takes_both_stakes() {
    let p = Pair::boot(100, 100).await;
    let (m, setup) = open_match(&p, [0x31; 32]).await;
    assert_eq!(balance(&p.a, &era()), m.a_start - m.stake);
    assert_eq!(balance(&p.b, &era()), m.b_start - m.stake);

    // Before a Start, no wallet signs an entry.
    let mut relay = Relay::new(m.cell);
    let early = TranscriptEntry::new(
        1,
        MatchSide::A,
        EntryKind::Commit {
            commitment: [7; 32],
        },
    )
    .expect("an entry")
    .encode();
    let refused = relay
        .try_sign(&p.a, MatchSide::A, &early)
        .expect_err("an entry before the Start");
    assert!(
        refused.to_string().contains("no Start is final"),
        "{refused}"
    );
    start(&p, &m).await;

    // Three turns, then B resigns: nothing is written to storage.
    forget_requests(&p);
    let (_, turns) = frozen();
    let mut state = wildstate_duel::start(&setup).expect("the setup");
    for turn in turns.iter().take(3) {
        play_turn(&p, &mut relay, turn);
        state = wildstate_duel::step(&state, turn).expect("a turn of a frozen match");
        assert_eq!(
            state.winner(),
            None,
            "the frozen match lasts past three turns"
        );
    }
    p.a.enter();
    let unfinished = computed_flow::settle(&p.a.router().core_sdk, &set(), &m.cell, &[])
        .await
        .expect_err("a transcript with no end");
    assert!(
        unfinished.to_string().contains("has not ended"),
        "{unfinished}"
    );
    relay.sign(&p.b, MatchSide::B, EntryKind::Resign);
    assert_eq!(
        writes(&p),
        Vec::<String>::new(),
        "no write between Start and settlement"
    );
    assert!(
        p.nodes.nodes.iter().any(|n| !n.requests().is_empty()),
        "the request log records the reads made meanwhile"
    );

    // A settles with B's last entry in hand; the cell computes a-wins.
    let settled = settle(&p.a, &m.cell, &relay.unseen(MatchSide::A))
        .await
        .expect("A settles");
    let (label, kind, state) = settled.occupant.clone().expect("an occupant");
    assert_eq!(
        (label.as_slice(), kind, state),
        (
            dsm::sofi::wire::COMPUTED_LABEL_A_WINS,
            computed_flow::OccupantKind::Transcript,
            dsm::route_chain::ChainState::Final
        )
    );
    assert_eq!(
        view(&p.b, &m.cell).final_outcome(),
        Some(b"a-wins".to_vec())
    );

    // The loser cannot collect; the winner collects both stakes, once.
    refused_collect(&p.b, &m.a_vault, "pays another identity").await;
    refused_collect(&p.b, &m.b_vault, "pays another identity").await;
    assert_eq!(pending_position(&p.b), None);
    collect(&p.a, &m.a_vault).await;
    collect(&p.a, &m.b_vault).await;
    assert_eq!(balance(&p.a, &era()), m.a_start + m.stake);
    assert_eq!(balance(&p.b, &era()), m.b_start - m.stake);
    refused_collect(&p.a, &m.a_vault, "already released").await;
}

/// The wallet signs only canonical entries that are steps of the match, and
/// never two entries at one index. When the other side's key signs two heads
/// at one index, the honest wallet settles the proof of it and collects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn tampered_entries_are_refused_and_an_equivocation_settles_for_the_honest_side() {
    let p = Pair::boot(100, 100).await;
    let (m, setup) = open_match(&p, [0x32; 32]).await;
    start(&p, &m).await;
    let mut relay = Relay::new(m.cell);
    let (_, turns) = frozen();
    let played = turns[0].a.encode();

    // A commits; B's wallet refuses A's entry under a signature that is not
    // over its head, and an entry that is not its canonical encoding.
    let commitment = computed::move_commitment(&salt(1, MatchSide::A), &played);
    relay.sign(&p.a, MatchSide::A, EntryKind::Commit { commitment });
    let b_salt = salt(2, MatchSide::B);
    let b_commitment = computed::move_commitment(&b_salt, &turns[0].b.encode());
    let b_commit = TranscriptEntry::new(
        2,
        MatchSide::B,
        EntryKind::Commit {
            commitment: b_commitment,
        },
    )
    .expect("an entry")
    .encode();
    let mut forged = relay.unseen(MatchSide::B);
    forged[0].signature[0] ^= 1;
    p.b.enter();
    let core_b = &p.b.router().core_sdk;
    let refused = computed_flow::sign_entry(core_b, &set(), &m.cell, &forged, &b_commit)
        .expect_err("a forged signature");
    assert!(refused.to_string().contains("does not verify"), "{refused}");
    let mut longer = b_commit.clone();
    longer.push(0);
    let refused = relay
        .try_sign(&p.b, MatchSide::B, &longer)
        .expect_err("an entry with a byte past its end");
    assert!(refused.to_string().contains("decode"), "{refused}");
    relay.sign(
        &p.b,
        MatchSide::B,
        EntryKind::Commit {
            commitment: b_commitment,
        },
    );

    // A tampered reveal does not open A's commitment.
    let tampered = TranscriptEntry::new(
        3,
        MatchSide::A,
        EntryKind::Reveal {
            salt: salt(9, MatchSide::A),
            played: played.clone(),
        },
    )
    .expect("an entry")
    .encode();
    let refused = relay
        .try_sign(&p.a, MatchSide::A, &tampered)
        .expect_err("a reveal under another salt");
    assert!(refused.to_string().contains("does not open"), "{refused}");

    // A's wallet never signs another entry at index 1.
    let other_commit = TranscriptEntry::new(
        1,
        MatchSide::A,
        EntryKind::Commit {
            commitment: [5; 32],
        },
    )
    .expect("an entry")
    .encode();
    let refused = relay
        .try_sign(&p.a, MatchSide::A, &other_commit)
        .expect_err("a second entry at index 1");
    assert!(refused.to_string().contains("never signs two"), "{refused}");
    let again = relay
        .try_sign(&p.a, MatchSide::A, &relay.entries[0].1)
        .expect("the same entry answers with its signature");
    assert_eq!(again.signature, relay.entries[0].2);

    // A's key signs a second head at index 1 outside its wallet, as a cheater
    // holding the key would. B's wallet catches it and keeps the proof.
    p.a.enter();
    let nonce = DuelSetupV1::decode(&setup).expect("the setup").body;
    let secret = computed_flow::session_keypair(nonce.match_nonce())
        .expect("A's session key")
        .secret_key()
        .to_vec();
    let terms = {
        let read = crate::sdk::outcome_programs::read_setup(&setup).expect("the setup");
        computed_flow::terms_of(&setup, &read, era(), (p.a.genesis, p.a.device_id))
            .expect("A's terms")
    };
    let head = computed::next_head(
        &computed::genesis_head(&m.cell, terms.table().setup_digest()),
        &other_commit,
    );
    let signature = computed::sign_head(
        terms.table().session(MatchSide::A),
        &secret,
        &m.cell,
        1,
        &head,
    )
    .expect("the cheating signature");
    let b_reveal = TranscriptEntry::new(
        3,
        MatchSide::B,
        EntryKind::Reveal {
            salt: b_salt,
            played: turns[0].b.encode(),
        },
    )
    .expect("an entry")
    .encode();
    p.b.enter();
    let caught = computed_flow::sign_entry(
        &p.b.router().core_sdk,
        &set(),
        &m.cell,
        &[SignedEntry {
            entry: other_commit,
            signature,
        }],
        &b_reveal,
    )
    .expect_err("an equivocation");
    assert!(
        caught.to_string().contains("two different entries"),
        "{caught}"
    );

    // B settles the proof: the cell gives b-wins, and B collects both stakes.
    let settled = settle(&p.b, &m.cell, &[]).await.expect("B settles");
    let (label, kind, _) = settled.occupant.expect("an occupant");
    assert_eq!(
        (label.as_slice(), kind),
        (
            dsm::sofi::wire::COMPUTED_LABEL_B_WINS,
            computed_flow::OccupantKind::Equivocation
        )
    );
    refused_collect(&p.a, &m.a_vault, "pays another identity").await;
    collect(&p.b, &m.a_vault).await;
    collect(&p.b, &m.b_vault).await;
    assert_eq!(balance(&p.b, &era()), m.b_start + m.stake);
    assert_eq!(balance(&p.a, &era()), m.a_start - m.stake);
}

/// Withdraw before a Start voids the match: each stake goes back to its own
/// owner, a Start can no longer hold, and no entry is ever signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_withdraw_before_the_start_voids_the_match_and_refunds_both() {
    let p = Pair::boot(100, 100).await;
    let setup = setup(&p, [0x33; 32], &teams(&p).await);
    let (a_start, b_start) = (balance(&p.a, &era()), balance(&p.b, &era()));
    let stake = whole_era(25);
    let a = lock(&p.a, &p.b, &setup, MatchSide::A, stake, None)
        .await
        .expect("A's lock");
    // A wallet readies only once both vaults are verified: B has none yet.
    p.a.enter();
    let alone = computed_flow::ready(&p.a.router().core_sdk, &set(), &a.match_cell, None)
        .await
        .expect_err("a ready with one stake on the match");
    assert!(alone.to_string().contains("mirrors this one"), "{alone}");
    let b = lock(&p.b, &p.a, &setup, MatchSide::B, stake, Some(a.vault_id))
        .await
        .expect("B's lock");
    let m = Match {
        stake,
        a_start,
        b_start,
        cell: a.match_cell,
        a_vault: a.vault_id,
        b_vault: b.vault_id,
    };
    let a_ready = ready(&p.a, &m.cell, None).await;
    p.a.enter();
    let withdrawn = computed_flow::withdraw(&p.a.router().core_sdk, &set(), &m.cell)
        .await
        .expect("A withdraws");
    assert_eq!(withdrawn.final_outcome(), Some(b"void".to_vec()));

    // B's ready no longer starts anything: the Withdraw holds the cell.
    let late = ready(&p.b, &m.cell, Some(&a_ready.ready_signature)).await;
    assert_eq!(
        late.view.start,
        Some((StartKind::Withdraw, dsm::route_chain::ChainState::Final))
    );
    let relay = Relay::new(m.cell);
    let entry = TranscriptEntry::new(1, MatchSide::B, EntryKind::Resign)
        .expect("an entry")
        .encode();
    relay
        .try_sign(&p.b, MatchSide::B, &entry)
        .expect_err("an entry in a withdrawn match");
    p.b.enter();
    computed_flow::withdraw(&p.b.router().core_sdk, &set(), &m.cell)
        .await
        .expect("a second Withdraw is harmless: the first holds");

    // Each player takes its own stake back, and not the other's.
    refused_collect(&p.a, &m.b_vault, "pays another identity").await;
    collect(&p.a, &m.a_vault).await;
    collect(&p.b, &m.b_vault).await;
    assert_eq!(balance(&p.a, &era()), m.a_start);
    assert_eq!(balance(&p.b, &era()), m.b_start);
}

/// A wallet locks a stake only in a setup whose teams are the creatures as
/// their issuers last published them, and only fielding creatures it holds:
/// a modded state, a creature it does not hold, a creature of a token that is
/// not of supply one and a state never published are each refused, and no
/// stake moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_modded_or_unheld_creature_is_refused_at_lock() {
    let p = Pair::boot(100, 100).await;
    let (team_a, team_b) = teams(&p).await;
    let nonce = [0x34; 32];
    let (key_a, key_b) = (session_key(&p.a, &nonce), session_key(&p.b, &nonce));
    let stake = whole_era(25);
    let refused = |setup: Vec<u8>, reason: &'static str| {
        let p = &p;
        async move {
            match lock(&p.a, &p.b, &setup, MatchSide::A, stake, None).await {
                Err(e) => assert!(e.to_string().contains(reason), "{e}"),
                Ok(locked) => panic!("A locked a stake in a refused setup: {locked:?}"),
            }
        }
    };

    // One more XP than A's creature was issued with.
    let c = &team_a[0];
    let modded = CreatureStateV1::new(
        *c.anchor(),
        c.species(),
        c.xp() + 1,
        c.hp(),
        c.charges().to_vec(),
    )
    .expect("a modded state");
    refused(
        setup_with_keys(&p.a, &p.b, nonce, (&key_a, &[modded]), (&key_b, &team_b)),
        "never published as its latest",
    )
    .await;
    // The opponent's creature modded: A's wallet checks both teams.
    let theirs = &team_b[0];
    let modded_b = CreatureStateV1::new(
        *theirs.anchor(),
        theirs.species(),
        theirs.xp(),
        theirs.hp() - 1,
        theirs.charges().to_vec(),
    )
    .expect("a modded state");
    refused(
        setup_with_keys(&p.a, &p.b, nonce, (&key_a, &team_a), (&key_b, &[modded_b])),
        "never published as its latest",
    )
    .await;
    // B's own creature, published by B, fielded on A's side: A does not hold it.
    let swapped = vec![team_b[0].clone()];
    refused(
        setup_with_keys(&p.a, &p.b, nonce, (&key_a, &swapped), (&key_b, &team_a)),
        "does not hold creature",
    )
    .await;
    // A's spare creature, published by A, fielded on B's side: B does not hold
    // it, and the proof B's wallet makes says so.
    let (body, _) = frozen();
    let spare = issue_team(&p.a, body.a(), "CRX").await;
    refused(
        setup_with_keys(&p.a, &p.b, nonce, (&key_a, &team_a), (&key_b, &spare)),
        "the opponent does not hold creature",
    )
    .await;
    // A state under an anchor nobody issued.
    let unissued = CreatureStateV1::new(
        [0x5E; 32],
        c.species(),
        c.xp(),
        c.hp(),
        c.charges().to_vec(),
    )
    .expect("a state");
    let a_start = balance(&p.a, &era());
    refused(
        setup_with_keys(&p.a, &p.b, nonce, (&key_a, &[unissued]), (&key_b, &team_b)),
        "no policy is published under its anchor",
    )
    .await;
    assert_eq!(balance(&p.a, &era()), a_start, "no stake moved");

    // The teams as published lock.
    let setup = setup_with_keys(&p.a, &p.b, nonce, (&key_a, &team_a), (&key_b, &team_b));
    lock(&p.a, &p.b, &setup, MatchSide::A, stake, None)
        .await
        .expect("A's lock on the published teams");
    assert_eq!(balance(&p.a, &era()), a_start - stake);
}
