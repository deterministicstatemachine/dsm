// SPDX-License-Identifier: MIT OR Apache-2.0

//! The canonical match objects: a creature's state, the match both wallets
//! lock, the setup that pins the program, and a turn's opened moves.

use crate::class;
use crate::codec::{tagged_hash, DecodeError, Reader, Writer};
use crate::tables::TABLES;

/// The widest session public key a setup carries (SPHINCS+ keys are far smaller).
pub const MAX_SESSION_KEY_BYTES: usize = 4096;

/// `0x5701 CreatureStateV1` — one creature, as its issuing account last
/// published it.
///
/// 1 `anchor` digest32 · 2 `species` u8 (a species-table index) · 3 `xp` u32
/// · 4 `hp` u16, at most the level's maximum · 5 `charges` `u32 count ‖ u8 …`,
/// exactly one per move of the species in table order; a move without
/// charges holds 0 and a charged move at most its maximum for the level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatureStateV1 {
    anchor: [u8; 32],
    species: u8,
    xp: u32,
    hp: u16,
    charges: Vec<u8>,
}

impl CreatureStateV1 {
    pub const CLASS: u16 = class::CREATURE_STATE;

    /// Validates against the tables: a known species, HP within the level's
    /// maximum, one charge count per move, none above its maximum.
    pub fn new(
        anchor: [u8; 32],
        species: u8,
        xp: u32,
        hp: u16,
        charges: Vec<u8>,
    ) -> Result<Self, DecodeError> {
        let def = TABLES
            .species_def(species)
            .ok_or(DecodeError::UnknownValue {
                field: "creature.species",
                value: u32::from(species),
            })?;
        if charges.len() != def.moves.len() {
            return Err(DecodeError::Cardinality {
                field: "creature.charges",
                min: def.moves.len(),
                max: def.moves.len(),
                got: charges.len(),
            });
        }
        if hp > TABLES.max_hp(xp) {
            return Err(DecodeError::Invalid {
                what: "creature.hp exceeds the level's maximum",
            });
        }
        let level = TABLES.level(xp);
        for (m, c) in def.moves.iter().zip(charges.iter()) {
            if *c > TABLES.max_charges(m, level) {
                return Err(DecodeError::Invalid {
                    what: "creature.charges exceed the move's maximum",
                });
            }
        }
        Ok(Self {
            anchor,
            species,
            xp,
            hp,
            charges,
        })
    }

    pub fn anchor(&self) -> &[u8; 32] {
        &self.anchor
    }
    pub fn species(&self) -> u8 {
        self.species
    }
    pub fn xp(&self) -> u32 {
        self.xp
    }
    pub fn hp(&self) -> u16 {
        self.hp
    }
    pub fn charges(&self) -> &[u8] {
        &self.charges
    }
    pub fn level(&self) -> u8 {
        TABLES.level(self.xp)
    }
    /// The species' table entry; the constructor admitted only table species.
    pub fn species_def(&self) -> &'static crate::tables::SpeciesDef {
        &TABLES.species[usize::from(self.species)]
    }
    pub(crate) fn set_hp(&mut self, hp: u16) {
        self.hp = hp;
    }
    pub(crate) fn charges_mut(&mut self) -> &mut [u8] {
        &mut self.charges
    }

    pub(crate) fn write_body(&self, w: &mut Writer) {
        w.digest(&self.anchor);
        w.u8(self.species);
        w.u32(self.xp);
        w.u16(self.hp);
        w.bytes(&self.charges);
    }
    pub(crate) fn read_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let anchor = r.digest("creature.anchor")?;
        let species = r.u8("creature.species")?;
        let xp = r.u32("creature.xp")?;
        let hp = r.u16("creature.hp")?;
        let moves = TABLES
            .species_def(species)
            .ok_or(DecodeError::UnknownValue {
                field: "creature.species",
                value: u32::from(species),
            })?
            .moves
            .len();
        let charges = r.bytes("creature.charges", moves, moves)?;
        Self::new(anchor, species, xp, hp, charges)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        self.write_body(&mut w);
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let v = Self::read_body(&mut r)?;
        r.finish()?;
        Ok(v)
    }
    /// The state commitment: `H(DSM/wildstate-duel/creature-state/v1 ‖ 0x00 ‖ CCB)`.
    pub fn commitment(&self) -> [u8; 32] {
        tagged_hash(crate::TAG_CREATURE_STATE, &[&self.encode()])
    }
}

/// One side of a match, inside `DuelMatchV1`.
///
/// 1 `genesis` digest32 · 2 `device_id` digest32 · 3 `session_public_key`
/// bytes, `1..=MAX_SESSION_KEY_BYTES` · 4 `poultice` u8 · 5 `tonic` u8 ·
/// 6 `team` `seq<CreatureStateV1>` (nested), `1..=team_max`, every creature
/// standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelSide {
    pub genesis: [u8; 32],
    pub device_id: [u8; 32],
    pub session_public_key: Vec<u8>,
    pub poultice: u8,
    pub tonic: u8,
    pub team: Vec<CreatureStateV1>,
}

impl DuelSide {
    fn write(&self, w: &mut Writer) {
        w.digest(&self.genesis);
        w.digest(&self.device_id);
        w.bytes(&self.session_public_key);
        w.u8(self.poultice);
        w.u8(self.tonic);
        w.count(self.team.len());
        for c in &self.team {
            w.nested(&c.encode());
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let genesis = r.digest("side.genesis")?;
        let device_id = r.digest("side.device_id")?;
        let session_public_key = r.bytes("side.session_public_key", 1, MAX_SESSION_KEY_BYTES)?;
        let poultice = r.u8("side.poultice")?;
        let tonic = r.u8("side.tonic")?;
        let n = r.count("side.team", 1, usize::from(TABLES.constants.team_max))?;
        let mut team = Vec::with_capacity(n);
        for _ in 0..n {
            team.push(r.nested(CreatureStateV1::read_body, CreatureStateV1::CLASS)?);
        }
        Ok(Self {
            genesis,
            device_id,
            session_public_key,
            poultice,
            tonic,
            team,
        })
    }
    fn check(&self) -> Result<(), DecodeError> {
        let max = usize::from(TABLES.constants.team_max);
        if self.team.is_empty() || self.team.len() > max {
            return Err(DecodeError::Cardinality {
                field: "side.team",
                min: 1,
                max,
                got: self.team.len(),
            });
        }
        if self.session_public_key.is_empty()
            || self.session_public_key.len() > MAX_SESSION_KEY_BYTES
        {
            return Err(DecodeError::Cardinality {
                field: "side.session_public_key",
                min: 1,
                max: MAX_SESSION_KEY_BYTES,
                got: self.session_public_key.len(),
            });
        }
        if self.team.iter().any(|c| c.hp() == 0) {
            return Err(DecodeError::Invalid {
                what: "a fielded creature has fainted",
            });
        }
        Ok(())
    }
}

/// `0x5702 DuelMatchV1` — what both wallets lock, without the program.
///
/// 1 `match_nonce` digest32 · 2 `turn_cap` u16, the table's cap ·
/// 3 `tiebreak_seed` digest32 · 4 side a · 5 side b. No creature anchor
/// appears twice across both teams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelMatchV1 {
    match_nonce: [u8; 32],
    turn_cap: u16,
    tiebreak_seed: [u8; 32],
    a: DuelSide,
    b: DuelSide,
}

impl DuelMatchV1 {
    pub const CLASS: u16 = class::DUEL_MATCH;

    pub fn new(
        match_nonce: [u8; 32],
        turn_cap: u16,
        tiebreak_seed: [u8; 32],
        a: DuelSide,
        b: DuelSide,
    ) -> Result<Self, DecodeError> {
        if turn_cap != TABLES.constants.turn_cap {
            return Err(DecodeError::UnknownValue {
                field: "match.turn_cap",
                value: u32::from(turn_cap),
            });
        }
        a.check()?;
        b.check()?;
        let mut anchors: Vec<&[u8; 32]> = a
            .team
            .iter()
            .chain(b.team.iter())
            .map(|c| c.anchor())
            .collect();
        anchors.sort();
        if anchors.windows(2).any(|w| w[0] == w[1]) {
            return Err(DecodeError::Invalid {
                what: "a creature anchor is fielded twice",
            });
        }
        Ok(Self {
            match_nonce,
            turn_cap,
            tiebreak_seed,
            a,
            b,
        })
    }
    pub fn match_nonce(&self) -> &[u8; 32] {
        &self.match_nonce
    }
    pub fn turn_cap(&self) -> u16 {
        self.turn_cap
    }
    pub fn tiebreak_seed(&self) -> &[u8; 32] {
        &self.tiebreak_seed
    }
    pub fn a(&self) -> &DuelSide {
        &self.a
    }
    pub fn b(&self) -> &DuelSide {
        &self.b
    }

    pub(crate) fn write_body(&self, w: &mut Writer) {
        w.digest(&self.match_nonce);
        w.u16(self.turn_cap);
        w.digest(&self.tiebreak_seed);
        self.a.write(w);
        self.b.write(w);
    }
    pub(crate) fn read_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let match_nonce = r.digest("match.match_nonce")?;
        let turn_cap = r.u16("match.turn_cap")?;
        let tiebreak_seed = r.digest("match.tiebreak_seed")?;
        let a = DuelSide::read(r)?;
        let b = DuelSide::read(r)?;
        Self::new(match_nonce, turn_cap, tiebreak_seed, a, b)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        self.write_body(&mut w);
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let v = Self::read_body(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

/// `0x5703 DuelSetupV1` — the match pinned to the program that decides it.
///
/// 1 `program` digest32 (`P`) · 2 `match` nested `0x5702`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelSetupV1 {
    pub program: [u8; 32],
    pub body: DuelMatchV1,
}

impl DuelSetupV1 {
    pub const CLASS: u16 = class::DUEL_SETUP;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        w.digest(&self.program);
        w.nested(&self.body.encode());
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let program = r.digest("setup.program")?;
        let body = r.nested(DuelMatchV1::read_body, DuelMatchV1::CLASS)?;
        r.finish()?;
        Ok(Self { program, body })
    }
    /// `H(DSM/wildstate-duel/setup/v1 ‖ 0x00 ‖ CCB(setup))`.
    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(crate::TAG_SETUP, &[&self.encode()])
    }
}

/// `0x5704 DuelMoveV1` — one side's opened move for one turn.
///
/// 1 `kind` u8, then by kind: 0 Move `index u8` (a move of the active
/// creature, in table order) · 1 Item `item u8 ‖ team_index u8` · 2 Pass ·
/// 3 Resign. An index or item the rules cannot use is a legal encoding and
/// plays as a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuelMoveV1 {
    Move { index: u8 },
    Item { item: u8, team_index: u8 },
    Pass,
    Resign,
}

impl DuelMoveV1 {
    pub const CLASS: u16 = class::DUEL_MOVE;

    pub(crate) fn write_body(&self, w: &mut Writer) {
        match *self {
            Self::Move { index } => {
                w.u8(0);
                w.u8(index);
            }
            Self::Item { item, team_index } => {
                w.u8(1);
                w.u8(item);
                w.u8(team_index);
            }
            Self::Pass => w.u8(2),
            Self::Resign => w.u8(3),
        }
    }
    pub(crate) fn read_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8("move.kind")? {
            0 => Ok(Self::Move {
                index: r.u8("move.index")?,
            }),
            1 => Ok(Self::Item {
                item: r.u8("move.item")?,
                team_index: r.u8("move.team_index")?,
            }),
            2 => Ok(Self::Pass),
            3 => Ok(Self::Resign),
            other => Err(DecodeError::UnknownValue {
                field: "move.kind",
                value: u32::from(other),
            }),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        self.write_body(&mut w);
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let v = Self::read_body(&mut r)?;
        r.finish()?;
        Ok(v)
    }

    /// The move a revealed opening plays: the move it is the canonical
    /// encoding of, and a pass for any other bytes. A garbled opening is a
    /// turn its side let go by, never a reason the match cannot be decided:
    /// the opening was committed and signed, so it is the side's own move.
    pub fn played(opened: &[u8]) -> Self {
        match Self::decode(opened) {
            Ok(m) if m.encode() == opened => m,
            _ => Self::Pass,
        }
    }
}

/// The longest move opening a transcript carries (Core's
/// `TRANSCRIPT_MAX_MOVE_BYTES`); a vector holds openings of `1..=` this.
pub const MAX_OPENED_MOVE_BYTES: usize = 64;

/// `0x570B DuelOpenedTurnV1` — both sides' openings of one turn exactly as
/// revealed, before the rules read them.
///
/// 1 `a` bytes `1..=64` · 2 `b` bytes `1..=64`. Each plays as
/// [`DuelMoveV1::played`] reads it, so bytes that are not a canonical move
/// play as a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelOpenedTurnV1 {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}

impl DuelOpenedTurnV1 {
    pub const CLASS: u16 = class::DUEL_OPENED_TURN;

    /// Both sides' canonical moves of `turn`.
    pub fn of(turn: &DuelTurnV1) -> Self {
        Self {
            a: turn.a.encode(),
            b: turn.b.encode(),
        }
    }

    /// The turn the rules play.
    pub fn turn(&self) -> DuelTurnV1 {
        DuelTurnV1 {
            a: DuelMoveV1::played(&self.a),
            b: DuelMoveV1::played(&self.b),
        }
    }

    pub(crate) fn write_body(&self, w: &mut Writer) {
        w.bytes(&self.a);
        w.bytes(&self.b);
    }
    pub(crate) fn read_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let a = r.bytes("opened.a", 1, MAX_OPENED_MOVE_BYTES)?;
        let b = r.bytes("opened.b", 1, MAX_OPENED_MOVE_BYTES)?;
        Ok(Self { a, b })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        self.write_body(&mut w);
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let v = Self::read_body(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

/// `0x5705 DuelTurnV1` — both sides' opened moves for one turn.
///
/// 1 `a` nested `0x5704` · 2 `b` nested `0x5704`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuelTurnV1 {
    pub a: DuelMoveV1,
    pub b: DuelMoveV1,
}

impl DuelTurnV1 {
    pub const CLASS: u16 = class::DUEL_TURN;

    pub(crate) fn write_body(&self, w: &mut Writer) {
        w.nested(&self.a.encode());
        w.nested(&self.b.encode());
    }
    pub(crate) fn read_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let a = r.nested(DuelMoveV1::read_body, DuelMoveV1::CLASS)?;
        let b = r.nested(DuelMoveV1::read_body, DuelMoveV1::CLASS)?;
        Ok(Self { a, b })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        self.write_body(&mut w);
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let v = Self::read_body(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}
