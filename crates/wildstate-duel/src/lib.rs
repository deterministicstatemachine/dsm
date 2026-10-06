// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Wildstate duel — the outcome program for staked Wildstate matches
//!
//! A staked match is decided by computation, not by a referee: both wallets
//! lock a canonical setup, the players' opened moves form a transcript, and
//! anyone holding the transcript replays it with this program, pinned by its
//! hash `P`. This crate is that program. It lives outside DSM Core; Core only
//! learns "the outcome is what `P` computes".
//!
//! ## Objects and class numbers
//!
//! The classes are the game's own range `0x5700..=0x57FF` (`0x57` is ASCII
//! `W`), disjoint from Core's `0x00xx` classes, so a duel object can never be
//! read as a Core object or the other way round:
//!
//! | Class | Object |
//! |---|---|
//! | `0x5701` | [`CreatureStateV1`] |
//! | `0x5702` | [`DuelMatchV1`] (the setup without the program) |
//! | `0x5703` | [`DuelSetupV1`] |
//! | `0x5704` | [`DuelMoveV1`] |
//! | `0x5705` | [`DuelTurnV1`] |
//! | `0x5706` | [`DuelState`] (`DuelStateV1`) |
//! | `0x5707` | `DuelTablesV1` ([`tables::Tables::encode`]) |
//! | `0x5708` | `OutcomeProgramV1` (the program-hash preimage) |
//! | `0x5709` | [`vectors::DuelVectorV1`] |
//! | `0x570A` | [`vectors::DuelVectorSetV1`] |
//! | `0x570B` | [`DuelOpenedTurnV1`] |
//!
//! Every object uses the house CCB grammar ([`codec`]), schema 1.
//!
//! ## The program hash
//!
//! `P = H(DSM/outcome-program/v1 ‖ 0x00 ‖ CCB(OutcomeProgramV1))` where
//! `OutcomeProgramV1` is `name bytes ‖ rules_version u32 ‖ tables_digest ‖
//! conformance_vectors_digest`. The tables digest covers every table and
//! constant the rules read; the vectors digest covers the frozen vectors
//! (`tests/vectors/v1/vectors.ccb`). The vectors hold [`DuelMatchV1`], not a
//! setup, so `P` is not inside its own preimage.
//!
//! ## Rules
//!
//! An exact port of the game's player-vs-player engine (see [`engine`] for
//! the ordering rules), with integer damage (×4, halves rounded up as
//! `Math.round` does) and these staked-match changes:
//! - a level tie is broken by a bit of `H(tiebreak_seed ‖ turn)`, not the
//!   match id; no rule favours side a;
//! - Resign hands the other side the win; both resigning in one turn is
//!   decided as at the cap;
//! - an opened move the rules cannot play (an unknown index, an empty charge,
//!   an item out of stock or aimed at a fainted creature) plays as a pass, and
//!   so does an opening whose bytes are not a canonical `DuelMoveV1` at all
//!   ([`DuelMoveV1::played`]): a garbled reveal never stops the match from
//!   being decided;
//! - after `turn_cap` (60) turns the side with more total team HP wins, and
//!   equal HP goes to the tiebreak seed's parity. There is never a tie.

pub mod codec;
pub mod engine;
pub mod tables;
pub mod types;
pub mod vectors;

use core::fmt;

pub use codec::DecodeError;
pub use engine::{
    Acted, ActionLog, DuelState, End, Event, EventKind, Fighter, Guard, Phase, Played, Side,
    SideState, Status, TurnLog, Winner,
};
pub use tables::{Tables, TABLES};
pub use types::{
    CreatureStateV1, DuelMatchV1, DuelMoveV1, DuelOpenedTurnV1, DuelSetupV1, DuelSide, DuelTurnV1,
    MAX_OPENED_MOVE_BYTES,
};

use codec::{tagged_hash, Writer};
use vectors::DuelVectorSetV1;

/// The game-owned class range and its members.
pub mod class {
    pub const CREATURE_STATE: u16 = 0x5701;
    pub const DUEL_MATCH: u16 = 0x5702;
    pub const DUEL_SETUP: u16 = 0x5703;
    pub const DUEL_MOVE: u16 = 0x5704;
    pub const DUEL_TURN: u16 = 0x5705;
    pub const DUEL_STATE: u16 = 0x5706;
    pub const DUEL_TABLES: u16 = 0x5707;
    pub const OUTCOME_PROGRAM: u16 = 0x5708;
    pub const DUEL_VECTOR: u16 = 0x5709;
    pub const DUEL_VECTOR_SET: u16 = 0x570A;
    pub const DUEL_OPENED_TURN: u16 = 0x570B;
}

pub const TAG_OUTCOME_PROGRAM: &str = "DSM/outcome-program/v1";
pub const TAG_TABLES: &str = "DSM/wildstate-duel/tables/v1";
pub const TAG_VECTORS: &str = "DSM/wildstate-duel/conformance-vectors/v1";
pub const TAG_SETUP: &str = "DSM/wildstate-duel/setup/v1";
pub const TAG_STATE: &str = "DSM/wildstate-duel/state/v1";
pub const TAG_CREATURE_STATE: &str = "DSM/wildstate-duel/creature-state/v1";
pub const TAG_FIRST_ACTOR: &str = "DSM/wildstate-duel/first-actor/v1";
pub const TAG_VECTOR_TRACE: &str = "DSM/wildstate-duel/vector-trace/v1";
pub const TAG_TIEBREAK: &str = "DSM/wildstate-duel/tiebreak/v1";

pub const PROGRAM_NAME: &str = "wildstate-duel";
pub const RULES_VERSION: u32 = 1;

/// The frozen conformance vectors of rules version 1.
pub const VECTORS_V1: &[u8] = include_bytes!("../tests/vectors/v1/vectors.ccb");

/// Why the program will not compute, or a step was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Bytes that are not the canonical encoding of the object.
    Decode(DecodeError),
    /// The setup pins another program.
    WrongProgram { pinned: [u8; 32], this: [u8; 32] },
    /// A turn after the match was decided.
    MatchOver { turns: u16 },
    /// The transcript ends before the match is decided.
    Unfinished { turns: u16 },
    /// A rule's own precondition does not hold; the state is not one the
    /// rules can reach.
    Invariant { what: &'static str },
    /// A frozen vector does not reproduce.
    Conformance { vector: usize, what: &'static str },
}

impl From<DecodeError> for Refusal {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "not canonical: {e}"),
            Self::WrongProgram { .. } => write!(f, "the setup pins another outcome program"),
            Self::MatchOver { turns } => write!(f, "the match was decided after {turns} turns"),
            Self::Unfinished { turns } => {
                write!(f, "the match is undecided after {turns} turns")
            }
            Self::Invariant { what } => write!(f, "unreachable state: {what}"),
            Self::Conformance { vector, what } => {
                write!(f, "conformance vector {vector} does not reproduce: {what}")
            }
        }
    }
}

impl std::error::Error for Refusal {}

/// The digest of the rules-version-1 tables.
pub fn tables_digest() -> [u8; 32] {
    TABLES.digest()
}

/// `H(DSM/wildstate-duel/conformance-vectors/v1 ‖ 0x00 ‖ CCB(vector set))`.
pub fn conformance_vectors_digest_of(vectors: &[u8]) -> [u8; 32] {
    tagged_hash(TAG_VECTORS, &[vectors])
}

/// `P` for a given table set and vector set.
pub fn program_hash_for(tables: &Tables, vectors: &[u8]) -> [u8; 32] {
    let mut w = Writer::object(class::OUTCOME_PROGRAM);
    w.bytes(PROGRAM_NAME.as_bytes());
    w.u32(RULES_VERSION);
    w.digest(&tables.digest());
    w.digest(&conformance_vectors_digest_of(vectors));
    tagged_hash(TAG_OUTCOME_PROGRAM, &[&w.finish()])
}

/// `P`, this program's hash.
pub fn program_hash() -> [u8; 32] {
    program_hash_for(&TABLES, VECTORS_V1)
}

/// The tiebreak seed a staked match commits: `H(DSM/wildstate-duel/tiebreak/v1
/// ‖ 0x00 ‖ match_nonce ‖ u32be(|key_a|) ‖ key_a ‖ u32be(|key_b|) ‖ key_b)`
/// over both sides' session public keys. Each key is fixed by its own wallet
/// at lock, so neither side alone can grind the seed. Rules never read how
/// a seed was made; a wallet locking a stake checks the setup's seed is this.
pub fn tiebreak_seed(match_nonce: &[u8; 32], session_a: &[u8], session_b: &[u8]) -> [u8; 32] {
    let len = |key: &[u8]| (key.len() as u32).to_be_bytes();
    tagged_hash(
        TAG_TIEBREAK,
        &[
            match_nonce,
            &len(session_a),
            session_a,
            &len(session_b),
            session_b,
        ],
    )
}

/// Runs every frozen vector; the count on success.
pub fn verify_conformance() -> Result<usize, Refusal> {
    let set = DuelVectorSetV1::decode(VECTORS_V1)?;
    for (i, v) in set.vectors.iter().enumerate() {
        v.check()
            .map_err(|what| Refusal::Conformance { vector: i, what })?;
    }
    Ok(set.vectors.len())
}

/// Decodes a setup and checks it pins this program; the state before turn 0.
pub fn start(setup: &[u8]) -> Result<DuelState, Refusal> {
    let s = DuelSetupV1::decode(setup)?;
    let this = program_hash();
    if s.program != this {
        return Err(Refusal::WrongProgram {
            pinned: s.program,
            this,
        });
    }
    Ok(DuelState::start(&s.body))
}

/// One turn on a verified state: O(1) in the match length.
pub fn step(state: &DuelState, turn: &DuelTurnV1) -> Result<DuelState, Refusal> {
    state.step(turn)
}

/// Every turn's log; the transcript may stop before the match is decided,
/// but no turn may follow its end.
pub fn replay(setup: &[u8], turns: &[DuelTurnV1]) -> Result<Vec<TurnLog>, Refusal> {
    let mut state = start(setup)?;
    let mut logs = Vec::with_capacity(turns.len());
    for t in turns {
        let (next, log) = state.step_logged(t)?;
        state = next;
        logs.push(log);
    }
    Ok(logs)
}

/// The decided result of a complete transcript, by full replay.
pub fn outcome(setup: &[u8], turns: &[DuelTurnV1]) -> Result<Winner, Refusal> {
    let mut state = start(setup)?;
    for t in turns {
        state = state.step(t)?;
    }
    state.winner().ok_or(Refusal::Unfinished {
        turns: state.turn(),
    })
}
