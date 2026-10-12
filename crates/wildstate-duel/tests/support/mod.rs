// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared builders for the duel tests and the vector freezer: a seeded
//! generator (splitmix64, no dependency), creatures at a chosen level, and
//! matches.

use wildstate_duel::{
    CreatureStateV1, DuelMatchV1, DuelMoveV1, DuelSide, DuelState, DuelTurnV1, Side, TABLES,
};

/// A test's result: any refusal fails it with its message.
pub type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// splitmix64: a fixed, seeded sequence.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    /// Uniform in `0..n` for `n <= 256`.
    pub fn byte(&mut self, n: u64) -> u8 {
        (self.below(n.min(256)) & 0xFF) as u8
    }
    pub fn digest(&mut self) -> [u8; 32] {
        core::array::from_fn(|_| self.next().to_be_bytes()[0])
    }
}

/// XP at the start of `level`.
pub fn xp_at(level: u8) -> u32 {
    (u32::from(level) - 1) * TABLES.constants.xp_per_level
}

/// Every charged move at its maximum for the level.
pub fn full_charges(species: u8, level: u8) -> Vec<u8> {
    TABLES.species[usize::from(species)]
        .moves
        .iter()
        .map(|m| TABLES.max_charges(m, level))
        .collect()
}

/// A creature at `level` with full charges and `hp` (full when `None`).
pub fn creature(anchor: u8, species: u8, level: u8, hp: Option<u16>) -> R<CreatureStateV1> {
    let xp = xp_at(level);
    let hp = match hp {
        Some(hp) => hp,
        None => TABLES.max_hp(xp),
    };
    Ok(CreatureStateV1::new(
        [anchor; 32],
        species,
        xp,
        hp,
        full_charges(species, level),
    )?)
}

pub fn side(key: u8, poultice: u8, tonic: u8, team: Vec<CreatureStateV1>) -> DuelSide {
    DuelSide {
        genesis: [key; 32],
        device_id: [key.wrapping_add(1); 32],
        session_public_key: vec![key; 32],
        poultice,
        tonic,
        team,
    }
}

/// A match with the table cap; `seed` sets every tiebreak-seed byte.
pub fn duel(seed: u8, a: DuelSide, b: DuelSide) -> R<DuelMatchV1> {
    Ok(DuelMatchV1::new(
        [0x4E; 32],
        TABLES.constants.turn_cap,
        [seed; 32],
        a,
        b,
    )?)
}

pub fn mv(index: u8) -> DuelMoveV1 {
    DuelMoveV1::Move { index }
}

pub fn turn(a: DuelMoveV1, b: DuelMoveV1) -> DuelTurnV1 {
    DuelTurnV1 { a, b }
}

/// A random creature: any species and level, HP and charges within bounds.
pub fn random_creature(rng: &mut Rng, anchor: [u8; 32]) -> R<CreatureStateV1> {
    let species = rng.byte(TABLES.species.len() as u64);
    let level = 1 + rng.byte(u64::from(TABLES.constants.level_cap));
    let xp = xp_at(level) + u32::from(rng.byte(u64::from(TABLES.constants.xp_per_level)));
    let max = TABLES.max_hp(xp);
    let hp = if rng.below(2) == 0 {
        max
    } else {
        // Below `max`, a u16.
        1 + rng.below(u64::from(max)) as u16
    };
    let level = TABLES.level(xp);
    let charges = TABLES.species[usize::from(species)]
        .moves
        .iter()
        .map(|m| rng.byte(u64::from(TABLES.max_charges(m, level)) + 1))
        .collect();
    Ok(CreatureStateV1::new(anchor, species, xp, hp, charges)?)
}

/// A random match: one to three creatures a side, up to two of each item.
pub fn random_match(rng: &mut Rng) -> R<DuelMatchV1> {
    let mut anchor = 0u8;
    let mut team = |rng: &mut Rng| {
        let n = 1 + rng.below(u64::from(TABLES.constants.team_max));
        (0..n)
            .map(|_| {
                anchor += 1;
                let mut a = rng.digest();
                a[0] = anchor;
                random_creature(rng, a)
            })
            .collect::<R<Vec<_>>>()
    };
    let ta = team(rng)?;
    let tb = team(rng)?;
    let a = DuelSide {
        genesis: rng.digest(),
        device_id: rng.digest(),
        session_public_key: rng.digest().to_vec(),
        poultice: rng.byte(3),
        tonic: rng.byte(3),
        team: ta,
    };
    let b = DuelSide {
        genesis: rng.digest(),
        device_id: rng.digest(),
        session_public_key: rng.digest().to_vec(),
        poultice: rng.byte(3),
        tonic: rng.byte(3),
        team: tb,
    };
    Ok(DuelMatchV1::new(
        rng.digest(),
        TABLES.constants.turn_cap,
        rng.digest(),
        a,
        b,
    )?)
}

/// Which opened moves a random player sends.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Play {
    /// Only moves the rules accept.
    Legal,
    /// Mostly legal, with unusable moves and items mixed in.
    Loose,
}

/// A random opened move for `side`. Never a resignation.
pub fn random_move(rng: &mut Rng, state: &DuelState, side: Side, play: Play) -> DuelMoveV1 {
    let s = state.side(side);
    let active = &s.team()[usize::from(s.active())];
    let moves = active.creature().species_def().moves;
    let roll = rng.below(100);
    if play == Play::Loose && roll < 8 {
        return mv(rng.byte(7));
    }
    if play == Play::Loose && roll < 12 {
        return DuelMoveV1::Pass;
    }
    if roll >= 88 {
        let stocked: Vec<u8> = (0u8..2)
            .filter(|i| s.items()[usize::from(*i)] > 0)
            .collect();
        let standing: Vec<u8> = (0u8..)
            .zip(s.team().iter())
            .filter(|(_, f)| f.hp() > 0)
            .map(|(i, _)| i)
            .collect();
        if play == Play::Loose {
            return DuelMoveV1::Item {
                item: rng.byte(2),
                team_index: rng.byte(4),
            };
        }
        if !stocked.is_empty() {
            return DuelMoveV1::Item {
                item: stocked[rng.below(stocked.len() as u64) as usize],
                team_index: standing[rng.below(standing.len() as u64) as usize],
            };
        }
    }
    let usable: Vec<u8> = (0u8..)
        .zip(moves.iter())
        .filter(|(i, m)| m.max == 0 || active.creature().charges()[usize::from(*i)] > 0)
        .map(|(i, _)| i)
        .collect();
    mv(usable[rng.below(usable.len() as u64) as usize])
}
