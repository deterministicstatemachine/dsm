// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pinned content every rule reads: elements, statuses, species and their
//! moves, items and the numeric constants. These are the game's tables
//! (`dsm-creatures/src/domain/game.ts`) in canonical form; the rules never
//! hold a number of their own, so `tables_digest` covers every value a match
//! outcome depends on.
//!
//! Damage is computed ×4 so it stays an integer: an element multiplier of
//! 1.5 / 1 / 0.5 is 6 / 4 / 2, the soaked penalty of 2 is 8 and its floor of
//! 1 is 4.

use crate::class;
use crate::codec::{tagged_hash, Writer};

/// Status indices the rules name. Their order is the table's order.
pub const STATUS_BURN: u8 = 0;
pub const STATUS_ROOT: u8 = 1;
pub const STATUS_STUN: u8 = 2;
pub const STATUS_SOAKED: u8 = 3;

/// Item indices the rules name, in table order.
pub const ITEM_POULTICE: u8 = 0;
pub const ITEM_TONIC: u8 = 1;

const FIRE: u8 = 0;
const GRASS: u8 = 1;
const WATER: u8 = 2;
const ELECTRIC: u8 = 3;
const NONE: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElementDef {
    pub id: &'static str,
    /// Element indices this element is strong against.
    pub beats: &'static [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusDef {
    pub id: &'static str,
    /// Turns a status lasts once landed.
    pub turns: u8,
}

/// What a move does when its creature acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Damages the target; may land a status.
    Damage { power: u8, status: Option<u8> },
    /// Halves the next damage the user takes.
    Guard,
    /// Restores HP up to the user's maximum.
    Heal { amount: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveDef {
    pub id: &'static str,
    pub element: u8,
    pub effect: Effect,
    /// Base charges; 0 means the move needs none.
    pub max: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeciesDef {
    pub id: &'static str,
    pub element: u8,
    pub moves: &'static [MoveDef],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemEffect {
    /// Restores HP up to the creature's maximum.
    Heal { amount: u16 },
    /// Refills every charged move to its maximum for the creature's level.
    RefillCharges,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemDef {
    pub id: &'static str,
    pub effect: ItemEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constants {
    pub xp_per_level: u32,
    pub level_cap: u8,
    pub base_hp: u16,
    pub hp_per_level: u16,
    /// Each level here grants one extra charge on every charged move once reached.
    pub charge_bonus_levels: &'static [u8],
    pub strong_x4: u16,
    pub neutral_x4: u16,
    pub weak_x4: u16,
    pub soaked_penalty_x4: u16,
    pub soaked_floor_x4: u16,
    pub burn_damage: u16,
    pub turn_cap: u16,
    pub team_max: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tables {
    pub elements: &'static [ElementDef],
    pub statuses: &'static [StatusDef],
    pub species: &'static [SpeciesDef],
    pub items: &'static [ItemDef],
    pub constants: Constants,
}

const fn dmg(id: &'static str, element: u8, power: u8, max: u8) -> MoveDef {
    MoveDef {
        id,
        element,
        effect: Effect::Damage {
            power,
            status: None,
        },
        max,
    }
}
const fn dmg_status(id: &'static str, element: u8, power: u8, max: u8, status: u8) -> MoveDef {
    MoveDef {
        id,
        element,
        effect: Effect::Damage {
            power,
            status: Some(status),
        },
        max,
    }
}
const fn guard(id: &'static str, max: u8) -> MoveDef {
    MoveDef {
        id,
        element: NONE,
        effect: Effect::Guard,
        max,
    }
}
const fn heal(id: &'static str, amount: u8, max: u8) -> MoveDef {
    MoveDef {
        id,
        element: NONE,
        effect: Effect::Heal { amount },
        max,
    }
}

/// The rules-version-1 tables.
pub const TABLES: Tables = Tables {
    elements: &[
        ElementDef {
            id: "fire",
            beats: &[GRASS],
        },
        ElementDef {
            id: "grass",
            beats: &[WATER, ELECTRIC],
        },
        ElementDef {
            id: "water",
            beats: &[FIRE],
        },
        ElementDef {
            id: "electric",
            beats: &[WATER],
        },
        ElementDef {
            id: "none",
            beats: &[],
        },
    ],
    statuses: &[
        StatusDef {
            id: "burn",
            turns: 2,
        },
        StatusDef {
            id: "root",
            turns: 1,
        },
        StatusDef {
            id: "stun",
            turns: 1,
        },
        StatusDef {
            id: "soaked",
            turns: 2,
        },
    ],
    species: &[
        SpeciesDef {
            id: "embercub",
            element: FIRE,
            moves: &[
                dmg("strike", NONE, 8, 0),
                dmg("flare", FIRE, 14, 5),
                dmg_status("ember-bite", FIRE, 9, 3, STATUS_BURN),
                guard("warm-coat", 2),
            ],
        },
        SpeciesDef {
            id: "mossling",
            element: GRASS,
            moves: &[
                dmg("strike", NONE, 8, 0),
                dmg("leaf-cut", GRASS, 12, 5),
                dmg_status("root-bind", GRASS, 6, 3, STATUS_ROOT),
                heal("photosynth", 12, 1),
            ],
        },
        SpeciesDef {
            id: "tidefin",
            element: WATER,
            moves: &[
                dmg("strike", NONE, 8, 0),
                dmg("tide-lash", WATER, 12, 5),
                dmg_status("soak", WATER, 7, 3, STATUS_SOAKED),
                guard("mist-veil", 2),
            ],
        },
        SpeciesDef {
            id: "voltusk",
            element: ELECTRIC,
            moves: &[
                dmg("strike", NONE, 8, 0),
                dmg("volt-charge", ELECTRIC, 12, 5),
                dmg_status("static-tusk", ELECTRIC, 7, 3, STATUS_STUN),
                guard("bristle", 2),
            ],
        },
        SpeciesDef {
            id: "leon",
            element: GRASS,
            moves: &[
                dmg("strike", NONE, 8, 0),
                dmg("tongue-lash", GRASS, 12, 5),
                dmg_status("sticky-snare", GRASS, 6, 3, STATUS_ROOT),
                guard("camouflage", 2),
            ],
        },
        SpeciesDef {
            id: "rattlefin",
            element: WATER,
            moves: &[
                dmg("strike", NONE, 8, 0),
                dmg("chain-whip", WATER, 12, 5),
                dmg_status("lure-flash", WATER, 6, 3, STATUS_STUN),
                guard("rust-hide", 2),
            ],
        },
        SpeciesDef {
            id: "brineback",
            element: WATER,
            moves: &[
                dmg("strike", NONE, 8, 0),
                dmg("brine-jet", WATER, 12, 5),
                dmg_status("barnacle-bash", WATER, 7, 3, STATUS_SOAKED),
                guard("shell-up", 2),
            ],
        },
    ],
    items: &[
        ItemDef {
            id: "poultice",
            effect: ItemEffect::Heal { amount: 15 },
        },
        ItemDef {
            id: "tonic",
            effect: ItemEffect::RefillCharges,
        },
    ],
    constants: Constants {
        xp_per_level: 20,
        level_cap: 10,
        base_hp: 40,
        hp_per_level: 4,
        charge_bonus_levels: &[4, 7],
        strong_x4: 6,
        neutral_x4: 4,
        weak_x4: 2,
        soaked_penalty_x4: 8,
        soaked_floor_x4: 4,
        burn_damage: 3,
        turn_cap: 60,
        team_max: 3,
    },
};

impl Tables {
    /// `min(cap, 1 + ⌊xp / xp_per_level⌋)`.
    pub fn level(&self, xp: u32) -> u8 {
        let raw = 1 + xp / self.constants.xp_per_level;
        let cap = self.constants.level_cap;
        if raw >= u32::from(cap) {
            cap
        } else {
            // Below the cap, so it fits a byte.
            raw as u8
        }
    }
    /// `base + per_level · (level − 1)`.
    pub fn max_hp(&self, xp: u32) -> u16 {
        self.constants.base_hp + self.constants.hp_per_level * (u16::from(self.level(xp)) - 1)
    }
    /// One extra charge for every bonus level reached.
    pub fn charge_bonus(&self, level: u8) -> u8 {
        self.constants
            .charge_bonus_levels
            .iter()
            .filter(|l| level >= **l)
            .fold(0u8, |n, _| n + 1)
    }
    /// A charged move's maximum at `level`; a move without charges has none.
    pub fn max_charges(&self, m: &MoveDef, level: u8) -> u8 {
        if m.max == 0 {
            0
        } else {
            m.max + self.charge_bonus(level)
        }
    }
    /// The element multiplier ×4: strong, weak, else neutral.
    pub fn multiplier_x4(&self, attack: u8, defend: u8) -> u16 {
        let beats = |a: u8, d: u8| {
            self.elements
                .get(usize::from(a))
                .is_some_and(|e| e.beats.contains(&d))
        };
        if beats(attack, defend) {
            self.constants.strong_x4
        } else if beats(defend, attack) {
            self.constants.weak_x4
        } else {
            self.constants.neutral_x4
        }
    }
    pub fn species_def(&self, species: u8) -> Option<&'static SpeciesDef> {
        self.species.get(usize::from(species))
    }

    /// `0x5707 DuelTablesV1`.
    ///
    /// 1 `elements` `seq<(id bytes, beats seq<u8>)>` · 2 `statuses`
    /// `seq<(id bytes, turns u8)>` · 3 `species` `seq<(id bytes, element u8,
    /// moves seq<move>)>`, a move being `id bytes ‖ element u8 ‖ max u8 ‖
    /// effect u8` followed by, for damage (0), `power u8 ‖ status seq<u8>`
    /// (0..=1), for guard (1) nothing, for heal (2) `amount u8` · 4 `items`
    /// `seq<(id bytes, effect u8)>` followed by, for heal (0), `amount u16`,
    /// for refill (1) nothing · 5 constants, in declaration order:
    /// `xp_per_level u32 ‖ level_cap u8 ‖ base_hp u16 ‖ hp_per_level u16 ‖
    /// charge_bonus_levels seq<u8> ‖ strong_x4 u16 ‖ neutral_x4 u16 ‖ weak_x4
    /// u16 ‖ soaked_penalty_x4 u16 ‖ soaked_floor_x4 u16 ‖ burn_damage u16 ‖
    /// turn_cap u16 ‖ team_max u8`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(class::DUEL_TABLES);
        w.count(self.elements.len());
        for e in self.elements {
            w.bytes(e.id.as_bytes());
            w.bytes(e.beats);
        }
        w.count(self.statuses.len());
        for s in self.statuses {
            w.bytes(s.id.as_bytes());
            w.u8(s.turns);
        }
        w.count(self.species.len());
        for sp in self.species {
            w.bytes(sp.id.as_bytes());
            w.u8(sp.element);
            w.count(sp.moves.len());
            for m in sp.moves {
                w.bytes(m.id.as_bytes());
                w.u8(m.element);
                w.u8(m.max);
                match m.effect {
                    Effect::Damage { power, status } => {
                        w.u8(0);
                        w.u8(power);
                        let landed: Vec<u8> = status.into_iter().collect();
                        w.bytes(&landed);
                    }
                    Effect::Guard => w.u8(1),
                    Effect::Heal { amount } => {
                        w.u8(2);
                        w.u8(amount);
                    }
                }
            }
        }
        w.count(self.items.len());
        for it in self.items {
            w.bytes(it.id.as_bytes());
            match it.effect {
                ItemEffect::Heal { amount } => {
                    w.u8(0);
                    w.u16(amount);
                }
                ItemEffect::RefillCharges => w.u8(1),
            }
        }
        let c = &self.constants;
        w.u32(c.xp_per_level);
        w.u8(c.level_cap);
        w.u16(c.base_hp);
        w.u16(c.hp_per_level);
        w.bytes(c.charge_bonus_levels);
        w.u16(c.strong_x4);
        w.u16(c.neutral_x4);
        w.u16(c.weak_x4);
        w.u16(c.soaked_penalty_x4);
        w.u16(c.soaked_floor_x4);
        w.u16(c.burn_damage);
        w.u16(c.turn_cap);
        w.u8(c.team_max);
        w.finish()
    }

    /// `H(DSM/wildstate-duel/tables/v1 ‖ 0x00 ‖ CCB(tables))`.
    pub fn digest(&self) -> [u8; 32] {
        tables_digest_of(&self.encode())
    }
}

/// The tables digest of already-encoded tables bytes.
pub fn tables_digest_of(ccb: &[u8]) -> [u8; 32] {
    tagged_hash(crate::TAG_TABLES, &[ccb])
}
