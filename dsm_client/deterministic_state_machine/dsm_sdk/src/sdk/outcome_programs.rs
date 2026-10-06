// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outcome programs this SDK runs (SoFi §19.10, Amendment S22; DSM
//! Amendment A13), and the process registry every verifier it builds stands
//! on.
//!
//! Core knows a computed escrow vault only as "the outcome is what the
//! program pinned by `P` computes from the opened entries". The programs
//! themselves live outside Core. This module adapts each to Core's
//! [`OutcomeProgram`] and registers it, once per process, only after the
//! program reproduces its own frozen conformance vectors through the very
//! interface Core calls: a build whose rules drifted is a different program,
//! and it is never registered under the hash it no longer earns.
//!
//! ## `wildstate-duel` v1
//!
//! A match is a sequence of turns. Each turn is both sides' Commit, then both
//! sides' Reveal: neither commitment of a turn may follow a reveal of it, and
//! no commitment of the next turn may precede the last reveal of this one.
//! Each revealed move is a canonical `DuelMoveV1`. A Core `Resign` ends the
//! match at once: the turn it lands in is played with the resigning side
//! resigning and the other side's move of that turn, if it revealed one, or a
//! pass. The program is `Done` exactly when the duel rules decided a winner,
//! `Incomplete` before, and any opened entry after that is a fault. The duel
//! has no draw: its labels are `a-wins` and `b-wins`.

use std::sync::{Arc, OnceLock};

use dsm::sofi::computed::{
    OpenedKind, Opened, OutcomeProgram, ProgramFault, ProgramOutcome, ProgramRegistry,
    RegistryError,
};
use dsm::sofi::wire::{MatchSide, COMPUTED_LABEL_A_WINS, COMPUTED_LABEL_B_WINS};
use wildstate_duel::vectors::DuelVectorSetV1;
use wildstate_duel::{DuelMoveV1, DuelSetupV1, DuelState, DuelTurnV1, Side};

type D32 = [u8; 32];

fn fault(what: impl Into<String>) -> ProgramFault {
    ProgramFault(what.into())
}

fn slot(side: MatchSide) -> usize {
    match side {
        MatchSide::A => 0,
        MatchSide::B => 1,
    }
}

/// The label of `side`'s win.
pub fn win_label(side: Side) -> &'static [u8] {
    match side {
        Side::A => COMPUTED_LABEL_A_WINS,
        Side::B => COMPUTED_LABEL_B_WINS,
    }
}

/// A revealed move of the turn in play, not yet answered by the other side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Revealed {
    committed_at: u32,
    revealed_at: u32,
    played: DuelMoveV1,
}

/// How far a duel has come over the opened entries applied so far: the
/// verified duel state, the turn in play and where the last turn ended. A
/// wallet keeps it durably per match and applies one entry at a time; a
/// settlement verifier folds a whole transcript through it. Both run the one
/// [`DuelProgress::apply`], so the two never disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelProgress {
    state: DuelState,
    pending: [Option<Revealed>; 2],
    /// The index of the last reveal of the last whole turn: every
    /// commitment of the turn in play comes after it.
    turn_floor: u32,
}

impl DuelProgress {
    /// The progress of a match before its first entry: `setup` decoded,
    /// canonical, and pinning this program.
    pub fn start(setup: &[u8]) -> Result<Self, ProgramFault> {
        let decoded = DuelSetupV1::decode(setup).map_err(|e| fault(format!("the setup: {e}")))?;
        if decoded.encode() != setup {
            return Err(fault("the setup is not its canonical encoding"));
        }
        let state = wildstate_duel::start(setup).map_err(|e| fault(format!("the setup: {e}")))?;
        Ok(Self {
            state,
            pending: [None, None],
            turn_floor: 0,
        })
    }

    /// The verified duel state after the last whole turn.
    pub fn state(&self) -> &DuelState {
        &self.state
    }

    /// The side the rules decided won, once they did.
    pub fn winner(&self) -> Option<Side> {
        self.state.winner().map(|w| w.side)
    }

    /// What the program says the match has come to.
    pub fn outcome(&self) -> ProgramOutcome {
        match self.winner() {
            Some(side) => ProgramOutcome::Done(win_label(side).to_vec()),
            None => ProgramOutcome::Incomplete,
        }
    }

    /// Whether a commitment made now can be part of a transcript the
    /// program accepts: only between turns, before either side revealed a
    /// move of the turn it commits to, and never after the match ended.
    /// Core never shows the program a commitment; a wallet asks this before
    /// it signs one.
    pub fn may_commit(&self) -> Result<(), ProgramFault> {
        if self.winner().is_some() {
            return Err(fault("the match has ended"));
        }
        if self.pending.iter().any(Option::is_some) {
            return Err(fault(
                "a move of this turn is already revealed: a commitment now follows it",
            ));
        }
        Ok(())
    }

    /// Apply the next opened entry.
    pub fn apply(&mut self, opened: &Opened) -> Result<(), ProgramFault> {
        if self.winner().is_some() {
            return Err(fault(format!(
                "entry {} follows the end of the match",
                opened.index
            )));
        }
        let at = slot(opened.side);
        match &opened.kind {
            OpenedKind::Move {
                committed_at,
                played,
            } => {
                let decoded = DuelMoveV1::decode(played)
                    .map_err(|e| fault(format!("the move at {}: {e}", opened.index)))?;
                if decoded.encode() != *played {
                    return Err(fault(format!(
                        "the move at {} is not its canonical encoding",
                        opened.index
                    )));
                }
                if *committed_at <= self.turn_floor {
                    return Err(fault(format!(
                        "the move at {} was committed before the last turn was revealed",
                        opened.index
                    )));
                }
                if self.pending[at].is_some() {
                    return Err(fault(format!(
                        "the move at {} is its side's second move of one turn",
                        opened.index
                    )));
                }
                if let Some(other) = &self.pending[1 - at] {
                    if *committed_at > other.revealed_at {
                        return Err(fault(format!(
                            "the move at {} was committed after the other side's reveal",
                            opened.index
                        )));
                    }
                }
                self.pending[at] = Some(Revealed {
                    committed_at: *committed_at,
                    revealed_at: opened.index,
                    played: decoded,
                });
                if let [Some(a), Some(b)] = self.pending {
                    if a.committed_at > b.revealed_at || b.committed_at > a.revealed_at {
                        return Err(fault("a commitment of this turn follows a reveal of it"));
                    }
                    self.play(DuelTurnV1 {
                        a: a.played,
                        b: b.played,
                    })?;
                    self.turn_floor = a.revealed_at.max(b.revealed_at);
                }
            }
            OpenedKind::Resign => {
                let other = match &self.pending[1 - at] {
                    Some(revealed) => revealed.played,
                    None => DuelMoveV1::Pass,
                };
                let turn = match opened.side {
                    MatchSide::A => DuelTurnV1 {
                        a: DuelMoveV1::Resign,
                        b: other,
                    },
                    MatchSide::B => DuelTurnV1 {
                        a: other,
                        b: DuelMoveV1::Resign,
                    },
                };
                self.play(turn)?;
                self.turn_floor = opened.index;
            }
        }
        Ok(())
    }

    fn play(&mut self, turn: DuelTurnV1) -> Result<(), ProgramFault> {
        self.state = wildstate_duel::step(&self.state, &turn)
            .map_err(|e| fault(format!("turn {}: {e}", self.state.turn())))?;
        self.pending = [None, None];
        Ok(())
    }

    /// `u32be(turn_floor) ‖ side A's pending ‖ side B's pending ‖
    /// u32be(|state|) ‖ CCB(DuelStateV1)`, a pending move being `0x00` for
    /// none or `0x01 ‖ u32be(committed_at) ‖ u32be(revealed_at) ‖
    /// u32be(|move|) ‖ CCB(DuelMoveV1)`: what a wallet keeps between turns.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.turn_floor.to_be_bytes());
        for pending in &self.pending {
            match pending {
                None => out.push(0),
                Some(r) => {
                    out.push(1);
                    out.extend(r.committed_at.to_be_bytes());
                    out.extend(r.revealed_at.to_be_bytes());
                    push_part(&mut out, &r.played.encode());
                }
            }
        }
        push_part(&mut out, &self.state.encode());
        out
    }

    /// Exactly what [`Self::encode`] wrote.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut rest = bytes;
        let turn_floor = take_u32(&mut rest)?;
        let mut pending = [None, None];
        for one in &mut pending {
            match take(&mut rest, 1)? {
                [0] => {}
                [1] => {
                    let committed_at = take_u32(&mut rest)?;
                    let revealed_at = take_u32(&mut rest)?;
                    let played = take_part(&mut rest)?;
                    let decoded =
                        DuelMoveV1::decode(played).map_err(|e| format!("a kept move: {e}"))?;
                    *one = Some(Revealed {
                        committed_at,
                        revealed_at,
                        played: decoded,
                    });
                }
                other => return Err(format!("a kept pending marker {other:?}")),
            }
        }
        let state_bytes = take_part(&mut rest)?;
        let state =
            DuelState::decode(state_bytes).map_err(|e| format!("the kept duel state: {e}"))?;
        if !rest.is_empty() {
            return Err("the kept duel progress has trailing bytes".into());
        }
        let progress = Self {
            state,
            pending,
            turn_floor,
        };
        if progress.encode() != bytes {
            return Err("the kept duel progress is not its canonical encoding".into());
        }
        Ok(progress)
    }
}

fn push_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend((part.len() as u32).to_be_bytes());
    out.extend(part);
}

fn take<'b>(bytes: &mut &'b [u8], n: usize) -> Result<&'b [u8], String> {
    let (head, rest) = bytes
        .split_at_checked(n)
        .ok_or_else(|| "the kept duel progress is cut short".to_string())?;
    *bytes = rest;
    Ok(head)
}

fn take_u32(bytes: &mut &[u8]) -> Result<u32, String> {
    let raw: [u8; 4] = take(bytes, 4)?
        .try_into()
        .map_err(|e| format!("a kept number: {e}"))?;
    Ok(u32::from_be_bytes(raw))
}

fn take_part<'b>(bytes: &mut &'b [u8]) -> Result<&'b [u8], String> {
    let len = usize::try_from(take_u32(bytes)?).map_err(|e| format!("a kept length: {e}"))?;
    take(bytes, len)
}

/// One side of a match setup, as a wallet locking a stake reads it: the
/// identity its branch pays and the session key its table commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupSide {
    pub genesis: D32,
    pub device_id: D32,
    pub session_public_key: Vec<u8>,
}

/// What a wallet needs from a match setup to lock a stake in it: the program
/// it pins, the nonce its session keys are derived from, and both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchSetup {
    pub program: D32,
    pub match_nonce: D32,
    pub a: SetupSide,
    pub b: SetupSide,
}

impl MatchSetup {
    pub fn side(&self, side: MatchSide) -> &SetupSide {
        match side {
            MatchSide::A => &self.a,
            MatchSide::B => &self.b,
        }
    }
}

/// `setup` read for a lock: the canonical setup of a program this process
/// registered, whose tiebreak seed is the one its nonce and both session keys
/// derive (`wildstate_duel::tiebreak_seed`), so the application relaying the
/// setup could not have picked it.
pub fn read_setup(setup: &[u8]) -> Result<MatchSetup, String> {
    let decoded = DuelSetupV1::decode(setup).map_err(|e| format!("the setup: {e}"))?;
    if decoded.encode() != setup {
        return Err("the setup is not its canonical encoding".into());
    }
    if decoded.program != WildstateDuel.id() || !is_registered(&decoded.program) {
        return Err(format!(
            "the setup pins program {}, which this wallet does not run",
            dsm::utils::text_id::encode_base32_crockford(&decoded.program)
        ));
    }
    DuelProgress::start(setup).map_err(|e| e.0)?;
    let body = &decoded.body;
    let seed = wildstate_duel::tiebreak_seed(
        body.match_nonce(),
        &body.a().session_public_key,
        &body.b().session_public_key,
    );
    if *body.tiebreak_seed() != seed {
        return Err("the setup's tiebreak seed is not the one its nonce and keys derive".into());
    }
    let side = |s: &wildstate_duel::DuelSide| SetupSide {
        genesis: s.genesis,
        device_id: s.device_id,
        session_public_key: s.session_public_key.clone(),
    };
    Ok(MatchSetup {
        program: decoded.program,
        match_nonce: *body.match_nonce(),
        a: side(body.a()),
        b: side(body.b()),
    })
}

/// `wildstate-duel` v1 as Core's outcome program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WildstateDuel;

impl OutcomeProgram for WildstateDuel {
    fn id(&self) -> D32 {
        wildstate_duel::program_hash()
    }

    fn outcome(&self, setup: &[u8], opened: &[Opened]) -> Result<ProgramOutcome, ProgramFault> {
        let mut progress = DuelProgress::start(setup)?;
        for entry in opened {
            progress.apply(entry)?;
        }
        Ok(progress.outcome())
    }
}

/// An outcome program that can show it is the program its hash pins.
pub trait ConformingProgram: OutcomeProgram {
    /// Reproduce the program's frozen conformance vectors; how many did.
    fn conformance(&self) -> Result<usize, String>;
}

impl ConformingProgram for WildstateDuel {
    /// The duel rules reproduce every frozen vector, and this adapter, as
    /// Core calls it, decides each vector's match exactly as frozen.
    fn conformance(&self) -> Result<usize, String> {
        let rules = wildstate_duel::verify_conformance().map_err(|e| e.to_string())?;
        let adapted = adapter_conformance(self, wildstate_duel::VECTORS_V1)?;
        if rules != adapted {
            return Err(format!(
                "the rules reproduced {rules} vectors and the adapter {adapted}"
            ));
        }
        Ok(adapted)
    }
}

/// The opened entries of `turns` played in order, each turn as both sides'
/// Commit and then both sides' Reveal: side A commits at `4t+1`, side B at
/// `4t+2`, and they reveal at `4t+3` and `4t+4`.
pub fn opened_of_turns(turns: &[DuelTurnV1]) -> Vec<Opened> {
    let mut opened = Vec::with_capacity(turns.len() * 2);
    for (t, turn) in turns.iter().enumerate() {
        let base = 4 * t as u32;
        for (k, (side, played)) in [(MatchSide::A, turn.a), (MatchSide::B, turn.b)]
            .into_iter()
            .enumerate()
        {
            let k = k as u32;
            opened.push(Opened {
                index: base + 3 + k,
                side,
                kind: OpenedKind::Move {
                    committed_at: base + 1 + k,
                    played: played.encode(),
                },
            });
        }
    }
    opened
}

/// Whether `program` decides every match of the vector set `vectors` as it
/// was frozen, under Core's acceptance rule: `Done` with the winner's label
/// on the whole transcript, and `Incomplete` without its last opened entry.
/// The count of vectors on success.
pub fn adapter_conformance(program: &dyn OutcomeProgram, vectors: &[u8]) -> Result<usize, String> {
    let set = DuelVectorSetV1::decode(vectors).map_err(|e| format!("the vectors: {e}"))?;
    for (i, vector) in set.vectors.iter().enumerate() {
        let setup = DuelSetupV1 {
            program: program.id(),
            body: vector.body.clone(),
        }
        .encode();
        let opened = opened_of_turns(&vector.turns);
        let want = win_label(vector.winner);
        match program.outcome(&setup, &opened) {
            Ok(ProgramOutcome::Done(label)) if label == want => {}
            other => {
                return Err(format!(
                    "vector {i}: the whole transcript gives {other:?}, not Done({:?})",
                    String::from_utf8_lossy(want)
                ))
            }
        }
        let without_last = &opened[..opened.len() - 1];
        match program.outcome(&setup, without_last) {
            Ok(ProgramOutcome::Incomplete) => {}
            other => {
                return Err(format!(
                    "vector {i}: without its last entry the transcript gives {other:?}, not \
                     Incomplete"
                ))
            }
        }
    }
    Ok(set.vectors.len())
}

/// A program the registry would not register, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub program: D32,
    pub why: String,
}

/// A registry of the `candidates` that reproduce their own conformance
/// vectors, and why each other one was refused. A refused program is not
/// registered under any hash: a match it pins establishes nothing.
pub fn conforming_registry(
    candidates: Vec<Arc<dyn ConformingProgram>>,
) -> (ProgramRegistry, Vec<Refused>) {
    let mut registry = ProgramRegistry::new();
    let mut refused = Vec::new();
    for candidate in candidates {
        let program = candidate.id();
        if let Err(why) = candidate.conformance() {
            refused.push(Refused { program, why });
            continue;
        }
        let as_program: Arc<dyn OutcomeProgram> = candidate;
        if let Err(RegistryError::AlreadyRegistered { program }) = registry.register(as_program) {
            refused.push(Refused {
                program,
                why: "another program is registered under its hash".into(),
            });
        }
    }
    (registry, refused)
}

/// The programs this SDK ships.
fn shipped() -> Vec<Arc<dyn ConformingProgram>> {
    vec![Arc::new(WildstateDuel)]
}

static PROCESS: OnceLock<(ProgramRegistry, Vec<Refused>)> = OnceLock::new();

fn process() -> &'static (ProgramRegistry, Vec<Refused>) {
    PROCESS.get_or_init(|| conforming_registry(shipped()))
}

/// The registry every verifier this process builds runs: the shipped
/// programs that reproduced their vectors, built once.
pub fn registry() -> &'static ProgramRegistry {
    &process().0
}

/// The shipped programs this process refused to register.
pub fn refused() -> &'static [Refused] {
    &process().1
}

/// Build the process registry now (SDK init), so the conformance runs once
/// at start rather than on the first verifier. The programs refused, each
/// named in the log.
pub fn init() -> &'static [Refused] {
    for r in refused() {
        log::error!(
            "[outcome programs] {} is not registered: {}",
            dsm::utils::text_id::encode_base32_crockford(&r.program),
            r.why
        );
    }
    refused()
}

/// Whether `program` is registered with this process's verifiers.
pub fn is_registered(program: &D32) -> bool {
    registry().get(program).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::sofi::computed::ProgramOutcome::{Done, Incomplete};

    fn vectors() -> DuelVectorSetV1 {
        DuelVectorSetV1::decode(wildstate_duel::VECTORS_V1).expect("the frozen vectors")
    }

    fn setup_of(vector: &wildstate_duel::vectors::DuelVectorV1) -> Vec<u8> {
        DuelSetupV1 {
            program: wildstate_duel::program_hash(),
            body: vector.body.clone(),
        }
        .encode()
    }

    #[test]
    fn the_adapter_decides_every_golden_vector_under_cores_acceptance_rule() {
        let count = WildstateDuel.conformance().expect("conforms");
        assert_eq!(count, vectors().vectors.len());
        assert!(count > 0);
        assert_eq!(WildstateDuel.id(), wildstate_duel::program_hash());
        assert_eq!(
            hex_free(&WildstateDuel.id()),
            hex_free(&[
                0x44, 0x82, 0x48, 0xec, 0x83, 0xd7, 0x08, 0xda, 0x32, 0x8b, 0x0b, 0xb6, 0x89, 0x96,
                0x44, 0xde, 0xef, 0x75, 0xaf, 0x91, 0xf5, 0x61, 0x52, 0x7b, 0xdf, 0x51, 0x95, 0x58,
                0x43, 0x9c, 0xb3, 0x76
            ]),
            "the program the computed vaults pin"
        );
    }

    fn hex_free(d: &D32) -> Vec<u8> {
        d.to_vec()
    }

    /// Stepping one opened entry at a time, with the progress encoded and
    /// decoded between entries as a wallet keeps it, reaches exactly the
    /// state and winner a full replay of the turns reaches.
    #[test]
    fn incremental_progress_through_the_durable_encoding_equals_full_replay() {
        for (i, vector) in vectors().vectors.iter().enumerate() {
            let setup = setup_of(vector);
            let mut progress = DuelProgress::start(&setup).expect("a setup");
            for entry in opened_of_turns(&vector.turns) {
                let kept = progress.encode();
                progress = DuelProgress::decode(&kept).expect("the kept progress");
                assert_eq!(progress.encode(), kept);
                progress.apply(&entry).expect("an entry of a frozen match");
            }
            let replayed = wildstate_duel::outcome(&setup, &vector.turns).expect("decided");
            assert_eq!(progress.winner(), Some(replayed.side), "vector {i}");
            assert_eq!(progress.winner(), Some(vector.winner), "vector {i}");
            assert_eq!(progress.state().digest(), vector.final_state, "vector {i}");
        }
    }

    #[test]
    fn a_resignation_ends_the_match_for_the_other_side_at_once() {
        let set = vectors();
        let vector = set
            .vectors
            .iter()
            .find(|v| v.turns.len() > 1)
            .expect("a frozen match of more than one turn");
        let setup = setup_of(vector);
        // The first turn, which does not decide the match, then B resigns.
        let mut opened = opened_of_turns(&vector.turns[..1]);
        assert_eq!(WildstateDuel.outcome(&setup, &opened), Ok(Incomplete));
        opened.push(Opened {
            index: 5,
            side: MatchSide::B,
            kind: OpenedKind::Resign,
        });
        assert_eq!(
            WildstateDuel.outcome(&setup, &opened),
            Ok(Done(COMPUTED_LABEL_A_WINS.to_vec()))
        );
        opened.push(Opened {
            index: 6,
            side: MatchSide::A,
            kind: OpenedKind::Resign,
        });
        WildstateDuel
            .outcome(&setup, &opened)
            .expect_err("an entry after the end");
        // A resignation as the very first entry: the other side wins.
        let resign_a = [Opened {
            index: 1,
            side: MatchSide::A,
            kind: OpenedKind::Resign,
        }];
        assert_eq!(
            WildstateDuel.outcome(&setup, &resign_a),
            Ok(Done(COMPUTED_LABEL_B_WINS.to_vec()))
        );
        assert_eq!(WildstateDuel.outcome(&setup, &[]), Ok(Incomplete));
    }

    #[test]
    fn a_turn_out_of_order_or_a_move_not_canonical_is_a_fault() {
        let vector = &vectors().vectors[0];
        let setup = setup_of(vector);
        let turn = vector.turns[0];
        let mv = |index, side, committed_at, played: Vec<u8>| Opened {
            index,
            side,
            kind: OpenedKind::Move {
                committed_at,
                played,
            },
        };
        // B commits after A revealed: A 1 commit, A 2 reveal, B 3 commit, B 4 reveal.
        let late_commit = [
            mv(2, MatchSide::A, 1, turn.a.encode()),
            mv(4, MatchSide::B, 3, turn.b.encode()),
        ];
        WildstateDuel
            .outcome(&setup, &late_commit)
            .expect_err("a commitment after the other side's reveal");
        // A moves twice in one turn.
        let twice = [
            mv(3, MatchSide::A, 1, turn.a.encode()),
            mv(5, MatchSide::A, 4, turn.a.encode()),
        ];
        WildstateDuel
            .outcome(&setup, &twice)
            .expect_err("a side's second move of one turn");
        // A move whose bytes are not a canonical DuelMoveV1.
        let mut trailing = turn.a.encode();
        trailing.push(7);
        WildstateDuel
            .outcome(&setup, &[mv(3, MatchSide::A, 1, trailing)])
            .expect_err("a move with trailing bytes");
        // A setup pinning another program.
        let other = DuelSetupV1 {
            program: [0x5A; 32],
            body: vector.body.clone(),
        }
        .encode();
        WildstateDuel
            .outcome(&other, &[])
            .expect_err("a setup pinning another program");
        // The next turn committed before the last turn's last reveal.
        let set = vectors();
        let long = set
            .vectors
            .iter()
            .find(|v| v.turns.len() > 1)
            .expect("a frozen match of more than one turn");
        let long_setup = setup_of(long);
        let early = opened_of_turns(&long.turns[..1]);
        let mut pipelined = opened_of_turns(&long.turns[..2]);
        assert_eq!(
            WildstateDuel.outcome(&long_setup, &pipelined),
            Ok(Incomplete)
        );
        if let Some(Opened {
            kind: OpenedKind::Move { committed_at, .. },
            ..
        }) = pipelined.get_mut(2)
        {
            *committed_at = 4;
        }
        WildstateDuel
            .outcome(&long_setup, &pipelined)
            .expect_err("a commitment before the last turn's last reveal");
        let progress = DuelProgress::start(&long_setup).expect("a setup");
        progress.may_commit().expect("a commitment between turns");
        let mut half = progress.clone();
        half.apply(&early[0]).expect("A's reveal");
        half.may_commit()
            .expect_err("a commitment after a reveal of the turn");
    }

    /// A program whose rules disagree with its own vectors is refused, and a
    /// match it pins establishes nothing.
    #[test]
    fn the_registry_refuses_a_program_that_fails_its_vectors() {
        /// The duel with its labels swapped: every decided match goes to the
        /// other side.
        struct Swapped;
        impl OutcomeProgram for Swapped {
            fn id(&self) -> D32 {
                WildstateDuel.id()
            }
            fn outcome(
                &self,
                setup: &[u8],
                opened: &[Opened],
            ) -> Result<ProgramOutcome, ProgramFault> {
                Ok(match WildstateDuel.outcome(setup, opened)? {
                    Done(label) if label == COMPUTED_LABEL_A_WINS => {
                        Done(COMPUTED_LABEL_B_WINS.to_vec())
                    }
                    Done(..) => Done(COMPUTED_LABEL_A_WINS.to_vec()),
                    Incomplete => Incomplete,
                })
            }
        }
        impl ConformingProgram for Swapped {
            fn conformance(&self) -> Result<usize, String> {
                adapter_conformance(self, wildstate_duel::VECTORS_V1)
            }
        }
        let (registry, refused) = conforming_registry(vec![Arc::new(Swapped)]);
        assert!(registry.get(&WildstateDuel.id()).is_none());
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].program, WildstateDuel.id());

        let (registry, refused) =
            conforming_registry(vec![Arc::new(WildstateDuel), Arc::new(WildstateDuel)]);
        assert!(registry.get(&WildstateDuel.id()).is_some());
        assert_eq!(refused.len(), 1, "one program under one hash");

        assert!(is_registered(&wildstate_duel::program_hash()));
        assert!(init().is_empty());
    }

    #[test]
    fn the_tiebreak_seed_commits_the_nonce_and_both_keys_in_order() {
        let seed = wildstate_duel::tiebreak_seed(&[1; 32], &[2; 64], &[3; 64]);
        assert_ne!(
            seed,
            wildstate_duel::tiebreak_seed(&[1; 32], &[3; 64], &[2; 64])
        );
        assert_ne!(
            seed,
            wildstate_duel::tiebreak_seed(&[4; 32], &[2; 64], &[3; 64])
        );
        assert_ne!(
            seed,
            wildstate_duel::tiebreak_seed(&[1; 32], &[2; 63], &[3; 64])
        );
    }
}
