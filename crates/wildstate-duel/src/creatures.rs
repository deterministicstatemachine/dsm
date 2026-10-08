// SPDX-License-Identifier: MIT OR Apache-2.0

//! A creature's published states: the chain a match setup's team is read
//! from.
//!
//! The account that issued a creature (the creator of its token, a supply of
//! one) publishes the creature's state as it changes: first the state it was
//! issued in, then each successor naming the record before it. Each record
//! is a content-addressed immutable object, authored and signed by that
//! account, under a locator derived from the creature's anchor. This module
//! decides what the records say: the issuance record, the one chain of
//! successors from it, and the state at its tip. Who authored a record and
//! where it is found are the reader's to check before it hands the records
//! here.
//!
//! A record that is not the canonical encoding of a record of this anchor is
//! no record. Two issuance records, or two successors of one record, are two
//! histories the issuer published for one creature: no state of it can be
//! taken as its latest, and a setup naming it is refused.

use core::fmt;

use crate::class;
use crate::codec::{tagged_hash, DecodeError, Reader, Writer};
use crate::types::CreatureStateV1;
use crate::TAG_CREATURE_RECORD;

/// `0x570C CreatureRecordV1` — one published state of a creature.
///
/// 1 `parent` u8: 0 for the record the creature was issued with, 1 for a
/// successor, then the parent record's digest32 · 2 `state` nested `0x5701`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatureRecordV1 {
    pub parent: Option<[u8; 32]>,
    pub state: CreatureStateV1,
}

impl CreatureRecordV1 {
    pub const CLASS: u16 = class::CREATURE_RECORD;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        match &self.parent {
            None => w.u8(0),
            Some(parent) => {
                w.u8(1);
                w.digest(parent);
            }
        }
        w.nested(&self.state.encode());
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let parent = match r.u8("record.parent")? {
            0 => None,
            1 => Some(r.digest("record.parent")?),
            other => {
                return Err(DecodeError::UnknownValue {
                    field: "record.parent",
                    value: u32::from(other),
                })
            }
        };
        let state = r.nested(CreatureStateV1::read_body, CreatureStateV1::CLASS)?;
        r.finish()?;
        Ok(Self { parent, state })
    }

    /// `H(DSM/wildstate-duel/creature-record/v1 ‖ 0x00 ‖ CCB(record))`: what
    /// a successor names as its parent.
    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(TAG_CREATURE_RECORD, &[&self.encode()])
    }
}

/// Why no state of a creature can be taken as its latest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainRefusal {
    /// No record the creature was issued with.
    NoIssuance,
    /// Two different records the creature was issued with.
    TwoIssuances,
    /// Two different successors of one record.
    Fork { parent: [u8; 32] },
    /// The record it was issued with is not the state every creature is born
    /// in (`CreatureStateV1::birth`): its issuer handed it over at a later
    /// state than level 1.
    NotBorn,
    /// The birth state of the issued record's species cannot be built.
    BirthState(DecodeError),
}

impl fmt::Display for ChainRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoIssuance => write!(f, "no state the creature was issued with is published"),
            Self::TwoIssuances => {
                write!(f, "its issuer published two states it was issued with")
            }
            Self::Fork { .. } => {
                write!(f, "its issuer published two successors of one state")
            }
            Self::BirthState(e) => write!(f, "its birth state cannot be built: {e}"),
            Self::NotBorn => write!(
                f,
                "its issuer published it as issued at a state other than level 1's birth state"
            ),
        }
    }
}

impl std::error::Error for ChainRefusal {}

/// The latest state of the creature `anchor` among `published` (each the
/// bytes of one record its issuer authored), and its record's digest: the tip
/// of the one chain from the record it was issued with. Bytes that are not a
/// canonical record of `anchor` are skipped; one record published twice
/// counts once.
pub fn latest(
    anchor: &[u8; 32],
    published: &[Vec<u8>],
) -> Result<(CreatureStateV1, [u8; 32]), ChainRefusal> {
    let mut records: Vec<(CreatureRecordV1, [u8; 32])> = Vec::new();
    for bytes in published {
        let Ok(record) = CreatureRecordV1::decode(bytes) else {
            continue;
        };
        if record.encode() != *bytes || record.state.anchor() != anchor {
            continue;
        }
        let digest = record.digest();
        if records.iter().all(|(_, d)| *d != digest) {
            records.push((record, digest));
        }
    }
    let mut issued = records.iter().filter(|(r, _)| r.parent.is_none());
    let mut tip = issued.next().ok_or(ChainRefusal::NoIssuance)?;
    if issued.next().is_some() {
        return Err(ChainRefusal::TwoIssuances);
    }
    // Whatever its issuer hands over is born at level 1; only play, or a
    // trade between players, carries a creature past that.
    let born =
        CreatureStateV1::birth(*anchor, tip.0.state.species()).map_err(ChainRefusal::BirthState)?;
    if tip.0.state != born {
        return Err(ChainRefusal::NotBorn);
    }
    // Each step follows the one successor of the record before it. A chain
    // visits each record at most once: a successor names its parent by a
    // digest over its own bytes, so no record can be its own ancestor.
    for _ in 0..records.len() {
        let mut next = records
            .iter()
            .filter(|(r, _)| r.parent.as_ref() == Some(&tip.1));
        let Some(successor) = next.next() else {
            break;
        };
        if next.next().is_some() {
            return Err(ChainRefusal::Fork { parent: tip.1 });
        }
        tip = successor;
    }
    Ok((tip.0.state.clone(), tip.1))
}
