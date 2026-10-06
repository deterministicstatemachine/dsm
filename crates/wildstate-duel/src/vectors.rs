// SPDX-License-Identifier: MIT OR Apache-2.0

//! The frozen conformance vectors: whole matches with their decided results.
//! Their digest is part of the program hash, so a build whose rules no longer
//! reproduce them is a different program, and `verify_conformance` refuses it.

use crate::class;
use crate::codec::{tagged_hash, DecodeError, Reader, Writer};
use crate::engine::{DuelState, End, Side, Winner};
use crate::tables::TABLES;
use crate::types::{DuelMatchV1, DuelOpenedTurnV1, DuelTurnV1};
use crate::{Refusal, TAG_VECTOR_TRACE};

/// Bound on vectors in one set (an allocation guard, not a target).
pub const MAX_VECTORS: usize = 4096;
/// Bound on a vector's label.
pub const MAX_LABEL_BYTES: usize = 64;

/// `0x5709 DuelVectorV1` — one frozen match.
///
/// 1 `label` bytes, `1..=64`, what the vector exercises · 2 `match` nested
/// `0x5702` · 3 `opened` `seq<0x570B>` (nested), `1..=turn_cap`, each turn's
/// openings exactly as revealed, garbled ones included · 4 `winner`
/// u8 · 5 `end` u8 · 6 `final_state` digest32, the state digest after the
/// last turn · 7 `trace` digest32, the chain over every state the match
/// passed through (`t_0 = H(trace ‖ state_0)`, `t_i = H(trace ‖ t_{i−1} ‖
/// state_i)` over state digests), so a rule change that heals over by the
/// end still fails. The match is decided exactly at its last turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelVectorV1 {
    pub label: Vec<u8>,
    pub body: DuelMatchV1,
    /// Each turn's openings as revealed: what the vector freezes.
    pub opened: Vec<DuelOpenedTurnV1>,
    /// The turns the rules play from `opened` ([`DuelOpenedTurnV1::turn`]).
    /// Derived, never encoded.
    pub turns: Vec<DuelTurnV1>,
    pub winner: Side,
    pub end: End,
    pub final_state: [u8; 32],
    pub trace: [u8; 32],
}

impl DuelVectorV1 {
    pub const CLASS: u16 = class::DUEL_VECTOR;

    /// Freezes a match: plays its openings and records what it decided.
    pub fn freeze(
        label: &str,
        body: DuelMatchV1,
        opened: Vec<DuelOpenedTurnV1>,
    ) -> Result<Self, Refusal> {
        let turns: Vec<DuelTurnV1> = opened.iter().map(DuelOpenedTurnV1::turn).collect();
        let (state, winner, trace) = play(&body, &turns)?;
        Ok(Self {
            label: label.as_bytes().to_vec(),
            body,
            opened,
            turns,
            winner: winner.side,
            end: winner.end,
            final_state: state.digest(),
            trace,
        })
    }

    fn write_body(&self, w: &mut Writer) {
        w.bytes(&self.label);
        w.nested(&self.body.encode());
        w.count(self.opened.len());
        for t in &self.opened {
            w.nested(&t.encode());
        }
        w.u8(self.winner.code());
        w.u8(self.end.code());
        w.digest(&self.final_state);
        w.digest(&self.trace);
    }
    fn read_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let label = r.bytes("vector.label", 1, MAX_LABEL_BYTES)?;
        let body = r.nested(DuelMatchV1::read_body, DuelMatchV1::CLASS)?;
        let n = r.count("vector.opened", 1, usize::from(TABLES.constants.turn_cap))?;
        let mut opened = Vec::with_capacity(n);
        for _ in 0..n {
            opened.push(r.nested(DuelOpenedTurnV1::read_body, DuelOpenedTurnV1::CLASS)?);
        }
        let turns = opened.iter().map(DuelOpenedTurnV1::turn).collect();
        let w = r.u8("vector.winner")?;
        let winner = Side::from_code(w).ok_or(DecodeError::UnknownValue {
            field: "vector.winner",
            value: u32::from(w),
        })?;
        let e = r.u8("vector.end")?;
        let end = End::from_code(e).ok_or(DecodeError::UnknownValue {
            field: "vector.end",
            value: u32::from(e),
        })?;
        let final_state = r.digest("vector.final_state")?;
        let trace = r.digest("vector.trace")?;
        Ok(Self {
            label,
            body,
            opened,
            turns,
            winner,
            end,
            final_state,
            trace,
        })
    }

    /// Plays the vector and compares every recorded result.
    pub fn check(&self) -> Result<(), &'static str> {
        let turns: Vec<DuelTurnV1> = self.opened.iter().map(DuelOpenedTurnV1::turn).collect();
        let (state, winner, trace) = play(&self.body, &turns).map_err(|r| match r {
            Refusal::MatchOver { .. } => "the match was decided before its last turn",
            Refusal::Unfinished { .. } => "the match is not decided at its last turn",
            _ => "a turn was refused",
        })?;
        if winner.side != self.winner {
            return Err("a different side won");
        }
        if winner.end != self.end {
            return Err("the match ended another way");
        }
        if state.digest() != self.final_state {
            return Err("the final state differs");
        }
        if trace != self.trace {
            return Err("a state along the way differs");
        }
        Ok(())
    }
}

/// Plays every turn; the match must be decided exactly at the last one.
fn play(
    body: &DuelMatchV1,
    turns: &[DuelTurnV1],
) -> Result<(DuelState, Winner, [u8; 32]), Refusal> {
    let mut state = DuelState::start(body);
    let mut trace = tagged_hash(TAG_VECTOR_TRACE, &[&state.digest()]);
    for t in turns {
        state = state.step(t)?;
        trace = tagged_hash(TAG_VECTOR_TRACE, &[&trace, &state.digest()]);
    }
    let winner = state.winner().ok_or(Refusal::Unfinished {
        turns: state.turn(),
    })?;
    Ok((state, winner, trace))
}

/// `0x570A DuelVectorSetV1` — 1 `vectors` `seq<0x5709>` (nested), `1..=MAX_VECTORS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelVectorSetV1 {
    pub vectors: Vec<DuelVectorV1>,
}

impl DuelVectorSetV1 {
    pub const CLASS: u16 = class::DUEL_VECTOR_SET;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        w.count(self.vectors.len());
        for v in &self.vectors {
            let mut inner = Writer::object(DuelVectorV1::CLASS);
            v.write_body(&mut inner);
            w.nested(&inner.finish());
        }
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let n = r.count("vector_set.vectors", 1, MAX_VECTORS)?;
        let mut vectors = Vec::with_capacity(n);
        for _ in 0..n {
            vectors.push(r.nested(DuelVectorV1::read_body, DuelVectorV1::CLASS)?);
        }
        r.finish()?;
        Ok(Self { vectors })
    }
}
