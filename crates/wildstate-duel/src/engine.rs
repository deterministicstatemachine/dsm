// SPDX-License-Identifier: MIT OR Apache-2.0

//! The battle rules: an exact port of the game's player-vs-player exchange
//! (`duel.ts` `exchange`, `match.ts` `resolve`), with the staked-match
//! changes listed in the crate documentation.
//!
//! Ordering rules kept from the port, each with a named test:
//! 1. The first actor's held status (root or stun) is read when it acts; the
//!    second actor's is read *before* its own statuses tick, so a root or stun
//!    the first actor lands this turn holds the second actor this turn.
//! 2. The second actor's statuses tick after the first actor acts (only while
//!    it stands); the first actor's tick at the end of the turn.
//! 3. A status the second actor lands goes on the first actor only after the
//!    first actor's own tick, and only if it still stands; it is reported
//!    whenever the hit itself left the first actor standing.
//! 4. Items take effect before the exchange, the first actor's side first.
//! 5. The first actor spends a charge without a floor (its move was checked
//!    to have one); the second spends with a floor of zero. A held creature
//!    spends none.
//! 6. A tonic refills each charged move to `max + charge_bonus(level)`.
//! 7. After the exchange the second side's fainted creature is replaced
//!    first, then the first side's, each by its first standing creature in
//!    team order; a side with none left loses.

use crate::class;
use crate::codec::{tagged_hash, DecodeError, Reader, Writer};
use crate::tables::{
    Effect, ItemEffect, MoveDef, ITEM_POULTICE, ITEM_TONIC, STATUS_BURN, STATUS_ROOT,
    STATUS_SOAKED, STATUS_STUN, TABLES,
};
use crate::types::{CreatureStateV1, DuelMatchV1, DuelMoveV1, DuelSide, DuelTurnV1};
use crate::Refusal;

/// A side of the match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    A,
    B,
}

impl Side {
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
    pub fn code(self) -> u8 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::A),
            1 => Some(Self::B),
            _ => None,
        }
    }
}

/// How a finished match was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// Every creature on the losing side fainted.
    Knockouts,
    /// The losing side resigned.
    Resign,
    /// At the turn cap (or when both sides resigned in one turn), more total
    /// team HP.
    Hp,
    /// Equal total team HP there: the tiebreak seed's parity decided.
    Tiebreak,
}

impl End {
    pub fn code(self) -> u8 {
        match self {
            Self::Knockouts => 0,
            Self::Resign => 1,
            Self::Hp => 2,
            Self::Tiebreak => 3,
        }
    }
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Knockouts),
            1 => Some(Self::Resign),
            2 => Some(Self::Hp),
            3 => Some(Self::Tiebreak),
            _ => None,
        }
    }
}

/// The decided result: who won, how, after how many turns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Winner {
    pub side: Side,
    pub end: End,
    pub turns: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Battle,
    Done(Winner),
}

/// Whether a creature's guard is up: the next hit it takes is halved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    Down,
    Up,
}

/// A status on a creature and the turns it has left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub id: u8,
    pub turns: u8,
}

/// A creature in battle: its state plus the battle-only guard and statuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fighter {
    creature: CreatureStateV1,
    guard: Guard,
    statuses: Vec<Status>,
}

impl Fighter {
    fn fresh(creature: CreatureStateV1) -> Self {
        Self {
            creature,
            guard: Guard::Down,
            statuses: Vec::new(),
        }
    }
    pub fn creature(&self) -> &CreatureStateV1 {
        &self.creature
    }
    pub fn guard(&self) -> Guard {
        self.guard
    }
    pub fn statuses(&self) -> &[Status] {
        &self.statuses
    }
    pub fn hp(&self) -> u16 {
        self.creature.hp()
    }
    fn set_hp(&mut self, hp: u16) {
        self.creature.set_hp(hp);
    }
    fn lose_hp(&mut self, n: u16) {
        self.set_hp(self.hp().saturating_sub(n));
    }
    fn max_hp(&self) -> u16 {
        TABLES.max_hp(self.creature.xp())
    }
    fn element(&self) -> u8 {
        self.creature.species_def().element
    }
    fn has(&self, id: u8) -> bool {
        self.statuses.iter().any(|s| s.id == id)
    }
    /// A root or stun costs the creature its action.
    fn held(&self) -> bool {
        self.has(STATUS_ROOT) || self.has(STATUS_STUN)
    }
    /// Ticks every status once; returns the burn damage to apply.
    fn tick(&mut self) -> u16 {
        let mut burn = 0u16;
        for s in &mut self.statuses {
            s.turns = s.turns.saturating_sub(1);
            if s.id == STATUS_BURN {
                burn += TABLES.constants.burn_damage;
            }
        }
        self.statuses.retain(|s| s.turns > 0);
        burn
    }
    /// Lands a status: soaked washes off a burn; a status already held is not renewed.
    fn apply_status(&mut self, id: u8) {
        if id == STATUS_SOAKED {
            self.statuses.retain(|s| s.id != STATUS_BURN);
        }
        if !self.has(id) {
            if let Some(def) = TABLES.statuses.get(usize::from(id)) {
                self.statuses.push(Status {
                    id,
                    turns: def.turns,
                });
            }
        }
    }
    fn heal(&mut self, amount: u16) {
        self.set_hp(self.max_hp().min(self.hp() + amount));
    }
}

/// Damage ×4 before rounding: `(power + level − 1) · M`, then the soaked
/// penalty with its floor, then the guard's exact halving (`D` is even).
pub fn damage_x4(
    power: u8,
    level: u8,
    mult_x4: u16,
    attacker_soaked: bool,
    target_guarded: bool,
) -> u16 {
    let c = &TABLES.constants;
    let mut d = (u16::from(power) + u16::from(level).saturating_sub(1)) * mult_x4;
    if attacker_soaked {
        d = d.saturating_sub(c.soaked_penalty_x4).max(c.soaked_floor_x4);
    }
    if target_guarded {
        d /= 2;
    }
    d
}

/// `round(D / 4)` with halves rounded up, as `Math.round` does.
pub fn round_x4(d: u16) -> u16 {
    (d + 2) / 4
}

/// An even byte picks side a, an odd one side b.
fn parity_side(byte: u8) -> Side {
    if byte.is_multiple_of(2) {
        Side::A
    } else {
        Side::B
    }
}

fn acted(held: bool) -> Acted {
    if held {
        Acted::Held
    } else {
        Acted::Acted
    }
}

/// One hit of `attacker` on `target`; drops the target's guard if it was up.
fn strike(attacker: &Fighter, target: &mut Fighter, power: u8, element: u8) -> (u16, u16) {
    let mult = TABLES.multiplier_x4(element, target.element());
    let guarded = target.guard == Guard::Up;
    let d = damage_x4(
        power,
        attacker.creature.level(),
        mult,
        attacker.has(STATUS_SOAKED),
        guarded,
    );
    if guarded {
        target.guard = Guard::Down;
    }
    (round_x4(d), mult)
}

/// What a side plays this turn once its opened move has been checked.
#[derive(Debug, Clone, Copy)]
enum Act {
    Move { index: u8, def: &'static MoveDef },
    Item { item: u8, team_index: u8 },
    Pass,
}

/// What a side played, as the log reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Played {
    Move { index: u8 },
    Item { item: u8, team_index: u8 },
    Pass,
    Resign,
}

/// Whether the creature acted or a root or stun held it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acted {
    Acted,
    Held,
}

/// One action of a turn, in the order the creatures acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionLog {
    pub side: Side,
    pub played: Played,
    pub dmg: u16,
    /// The element multiplier ×4 of the hit (neutral when nothing hit).
    pub mult_x4: u16,
    /// A status the action landed (or, for the second actor, aimed to land).
    pub status: Option<u8>,
    /// Burn damage the opposing creature took at its tick after this action.
    pub burn: u16,
    pub acted: Acted,
}

impl ActionLog {
    fn new(side: Side, played: Played, acted: Acted) -> Self {
        Self {
            side,
            played,
            dmg: 0,
            mult_x4: TABLES.constants.neutral_x4,
            status: None,
            burn: 0,
            acted,
        }
    }
    fn of(side: Side, act: Act, acted: Acted) -> Self {
        let played = match act {
            Act::Move { index, .. } => Played::Move { index },
            Act::Item { item, team_index } => Played::Item { item, team_index },
            Act::Pass => Played::Pass,
        };
        Self::new(side, played, acted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Faint,
    Switch,
}

/// A creature fainted, or one was sent in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub side: Side,
    pub kind: EventKind,
    pub team_index: u8,
}

/// Everything one turn did, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnLog {
    /// The turn's index, from 0.
    pub turn: u16,
    /// Who acted first; none when a resignation ended the turn.
    pub first: Option<Side>,
    pub actions: Vec<ActionLog>,
    pub events: Vec<Event>,
    pub end: Option<Winner>,
}

/// One exchange, in place on the two active creatures.
fn exchange(
    first: &mut Fighter,
    first_side: Side,
    first_act: Act,
    second: &mut Fighter,
    second_side: Side,
    second_act: Act,
) -> Result<(ActionLog, Option<ActionLog>), Refusal> {
    let mut a = match first_act {
        Act::Move { index, def } => {
            // A root or stun landed last turn costs this action, and no charge.
            let skip = first.held();
            if def.max > 0 && !skip {
                let slot = first
                    .creature
                    .charges_mut()
                    .get_mut(usize::from(index))
                    .ok_or(Refusal::Invariant {
                        what: "a checked move has no charge slot",
                    })?;
                *slot = slot.checked_sub(1).ok_or(Refusal::Invariant {
                    what: "a checked move has no charge left",
                })?;
            }
            let mut a = ActionLog::of(first_side, first_act, acted(skip));
            if !skip {
                match def.effect {
                    Effect::Guard => first.guard = Guard::Up,
                    Effect::Heal { amount } => first.heal(u16::from(amount)),
                    Effect::Damage { power, status } => {
                        let (dmg, mult) = strike(first, second, power, def.element);
                        a.dmg = dmg;
                        a.mult_x4 = mult;
                        second.lose_hp(dmg);
                        if let Some(st) = status {
                            if second.hp() > 0 {
                                second.apply_status(st);
                                a.status = Some(st);
                            }
                        }
                    }
                }
            }
            a
        }
        idle => ActionLog::of(first_side, idle, Acted::Acted),
    };

    // The second's hold is read before its statuses tick.
    let skip_second = second.held();
    let second_burn = if second.hp() > 0 { second.tick() } else { 0 };
    if second_burn > 0 {
        a.burn = second_burn;
        second.lose_hp(second_burn);
    }
    if second.hp() == 0 {
        return Ok((a, None));
    }

    let b = match second_act {
        Act::Move { index, def } => {
            if def.max > 0 && !skip_second {
                if let Some(slot) = second.creature.charges_mut().get_mut(usize::from(index)) {
                    *slot = slot.saturating_sub(1);
                }
            }
            let mut b = ActionLog::of(second_side, second_act, acted(skip_second));
            let mut landed = None;
            if !skip_second {
                match def.effect {
                    Effect::Guard => second.guard = Guard::Up,
                    Effect::Heal { amount } => second.heal(u16::from(amount)),
                    Effect::Damage { power, status } => {
                        let (dmg, mult) = strike(second, first, power, def.element);
                        b.dmg = dmg;
                        b.mult_x4 = mult;
                        if let Some(st) = status {
                            if first.hp() > dmg {
                                landed = Some(st);
                                b.status = Some(st);
                            }
                        }
                        first.lose_hp(dmg);
                    }
                }
            }
            // The first actor's statuses tick at the end of the turn; one
            // landed this turn holds into the next.
            let first_burn = if first.hp() > 0 { first.tick() } else { 0 };
            if first_burn > 0 {
                b.burn = first_burn;
                first.lose_hp(first_burn);
            }
            if let Some(st) = landed {
                if first.hp() > 0 {
                    first.apply_status(st);
                }
            }
            b
        }
        idle => {
            let mut b = ActionLog::of(second_side, idle, Acted::Acted);
            let first_burn = if first.hp() > 0 { first.tick() } else { 0 };
            if first_burn > 0 {
                b.burn = first_burn;
                first.lose_hp(first_burn);
            }
            b
        }
    };
    Ok((a, Some(b)))
}

/// One side's battle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideState {
    /// Bag items left, by item index (poultice, tonic).
    items: [u8; 2],
    active: u8,
    ko: u8,
    team: Vec<Fighter>,
}

impl SideState {
    fn from_side(side: &DuelSide) -> Self {
        Self {
            items: [side.poultice, side.tonic],
            active: 0,
            ko: 0,
            team: side.team.iter().cloned().map(Fighter::fresh).collect(),
        }
    }
    pub fn items(&self) -> [u8; 2] {
        self.items
    }
    pub fn active(&self) -> u8 {
        self.active
    }
    pub fn ko(&self) -> u8 {
        self.ko
    }
    pub fn team(&self) -> &[Fighter] {
        &self.team
    }
    pub fn total_hp(&self) -> u32 {
        self.team.iter().map(|f| u32::from(f.hp())).sum()
    }
    fn active_fighter(&self) -> Result<&Fighter, Refusal> {
        self.team
            .get(usize::from(self.active))
            .ok_or(Refusal::Invariant {
                what: "the active index is outside the team",
            })
    }
    fn active_mut(&mut self) -> Result<&mut Fighter, Refusal> {
        self.team
            .get_mut(usize::from(self.active))
            .ok_or(Refusal::Invariant {
                what: "the active index is outside the team",
            })
    }

    /// The opened move as the rules play it: anything the rules cannot use
    /// this turn plays as a pass.
    fn checked(&self, mv: DuelMoveV1) -> Result<Act, Refusal> {
        Ok(match mv {
            DuelMoveV1::Move { index } => {
                let c = self.active_fighter()?.creature();
                let def = c.species_def().moves.get(usize::from(index));
                match def {
                    Some(def) if def.max == 0 => Act::Move { index, def },
                    Some(def) if c.charges().get(usize::from(index)).is_some_and(|n| *n > 0) => {
                        Act::Move { index, def }
                    }
                    _ => Act::Pass,
                }
            }
            DuelMoveV1::Item { item, team_index } => {
                let stocked = self.items.get(usize::from(item)).is_some_and(|n| *n > 0);
                let standing = self
                    .team
                    .get(usize::from(team_index))
                    .is_some_and(|f| f.hp() > 0);
                if stocked && standing && usize::from(item) < TABLES.items.len() {
                    Act::Item { item, team_index }
                } else {
                    Act::Pass
                }
            }
            DuelMoveV1::Pass | DuelMoveV1::Resign => Act::Pass,
        })
    }

    /// Spends and applies an item; any other act leaves the side as it is.
    fn use_item(&mut self, act: Act) -> Result<(), Refusal> {
        if let Act::Item { item, team_index } = act {
            let left = self
                .items
                .get_mut(usize::from(item))
                .ok_or(Refusal::Invariant {
                    what: "a checked item has no stock slot",
                })?;
            *left = left.checked_sub(1).ok_or(Refusal::Invariant {
                what: "a checked item is out of stock",
            })?;
            let target = self
                .team
                .get_mut(usize::from(team_index))
                .ok_or(Refusal::Invariant {
                    what: "a checked item targets no creature",
                })?;
            let effect = TABLES
                .items
                .get(usize::from(item))
                .ok_or(Refusal::Invariant {
                    what: "a checked item is not in the tables",
                })?
                .effect;
            match effect {
                ItemEffect::Heal { amount } => target.heal(amount),
                ItemEffect::RefillCharges => {
                    let level = target.creature.level();
                    let moves = target.creature.species_def().moves;
                    for (slot, m) in target.creature.charges_mut().iter_mut().zip(moves.iter()) {
                        *slot = TABLES.max_charges(m, level);
                    }
                }
            }
        }
        Ok(())
    }

    /// Replaces a fainted active creature; `None` when the side has none standing.
    fn replace_fainted(&mut self, side: Side, events: &mut Vec<Event>) -> Option<()> {
        if self
            .team
            .get(usize::from(self.active))
            .is_some_and(|f| f.hp() > 0)
        {
            return Some(());
        }
        self.ko += 1;
        events.push(Event {
            side,
            kind: EventKind::Faint,
            team_index: self.active,
        });
        let (next, _) = (0u8..).zip(self.team.iter()).find(|(_, f)| f.hp() > 0)?;
        self.active = next;
        events.push(Event {
            side,
            kind: EventKind::Switch,
            team_index: self.active,
        });
        Some(())
    }
}

/// The verified match state a wallet keeps and steps, one turn at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelState {
    match_nonce: [u8; 32],
    tiebreak_seed: [u8; 32],
    turn_cap: u16,
    turn: u16,
    phase: Phase,
    a: SideState,
    b: SideState,
}

impl DuelState {
    pub const CLASS: u16 = class::DUEL_STATE;

    /// The state before turn 0: snapshots of both teams, guards down, no statuses.
    pub fn start(m: &DuelMatchV1) -> Self {
        Self {
            match_nonce: *m.match_nonce(),
            tiebreak_seed: *m.tiebreak_seed(),
            turn_cap: m.turn_cap(),
            turn: 0,
            phase: Phase::Battle,
            a: SideState::from_side(m.a()),
            b: SideState::from_side(m.b()),
        }
    }
    pub fn match_nonce(&self) -> &[u8; 32] {
        &self.match_nonce
    }
    pub fn turn(&self) -> u16 {
        self.turn
    }
    pub fn turn_cap(&self) -> u16 {
        self.turn_cap
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn winner(&self) -> Option<Winner> {
        match self.phase {
            Phase::Done(w) => Some(w),
            Phase::Battle => None,
        }
    }
    pub fn side(&self, side: Side) -> &SideState {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }
    fn side_mut(&mut self, side: Side) -> &mut SideState {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }
    fn pair_mut(&mut self, first: Side) -> (&mut SideState, &mut SideState) {
        match first {
            Side::A => (&mut self.a, &mut self.b),
            Side::B => (&mut self.b, &mut self.a),
        }
    }

    /// The higher-level active creature acts first; on a level tie, bit 0 of
    /// `H(DSM/wildstate-duel/first-actor/v1 ‖ 0x00 ‖ tiebreak_seed ‖ u16_be(turn))`
    /// (0 → a, 1 → b).
    pub fn first_to_act(&self) -> Result<Side, Refusal> {
        let la = self.a.active_fighter()?.creature().level();
        let lb = self.b.active_fighter()?.creature().level();
        if la != lb {
            return Ok(if la > lb { Side::A } else { Side::B });
        }
        let h = tagged_hash(
            crate::TAG_FIRST_ACTOR,
            &[&self.tiebreak_seed, &self.turn.to_be_bytes()],
        );
        Ok(parity_side(h[0]))
    }

    /// More total team HP wins; equal HP goes to the tiebreak seed's parity
    /// (last byte even → a, odd → b).
    fn decide_by_hp(&self) -> Winner {
        let (ha, hb) = (self.a.total_hp(), self.b.total_hp());
        let (side, end) = if ha > hb {
            (Side::A, End::Hp)
        } else if hb > ha {
            (Side::B, End::Hp)
        } else {
            (parity_side(self.tiebreak_seed[31]), End::Tiebreak)
        };
        Winner {
            side,
            end,
            turns: self.turn,
        }
    }

    /// Plays one turn and reports what happened.
    pub fn step_logged(&self, turn: &DuelTurnV1) -> Result<(Self, TurnLog), Refusal> {
        if let Phase::Done(w) = self.phase {
            return Err(Refusal::MatchOver { turns: w.turns });
        }
        let mut s = self.clone();
        let index = s.turn;
        s.turn = index.checked_add(1).ok_or(Refusal::Invariant {
            what: "the turn counter overflowed",
        })?;
        let mut log = TurnLog {
            turn: index,
            first: None,
            actions: Vec::new(),
            events: Vec::new(),
            end: None,
        };

        let resigned: Vec<Side> = [(Side::A, turn.a), (Side::B, turn.b)]
            .into_iter()
            .filter(|(_, mv)| *mv == DuelMoveV1::Resign)
            .map(|(side, _)| side)
            .collect();
        if !resigned.is_empty() {
            for side in &resigned {
                log.actions
                    .push(ActionLog::new(*side, Played::Resign, Acted::Acted));
            }
            let winner = match resigned.as_slice() {
                [only] => Winner {
                    side: only.other(),
                    end: End::Resign,
                    turns: s.turn,
                },
                _ => s.decide_by_hp(),
            };
            s.phase = Phase::Done(winner);
            log.end = Some(winner);
            return Ok((s, log));
        }

        // Who acts first is read from the state the turn starts in.
        let first = self.first_to_act()?;
        let second = first.other();
        log.first = Some(first);
        let pick = |side: Side| match side {
            Side::A => turn.a,
            Side::B => turn.b,
        };
        let first_act = s.side(first).checked(pick(first))?;
        let second_act = s.side(second).checked(pick(second))?;
        s.side_mut(first).use_item(first_act)?;
        s.side_mut(second).use_item(second_act)?;

        let (fs, ss) = s.pair_mut(first);
        let (ea, eb) = exchange(
            fs.active_mut()?,
            first,
            first_act,
            ss.active_mut()?,
            second,
            second_act,
        )?;
        log.actions.push(ea);
        log.actions.extend(eb);

        // The second actor can only have fainted before acting; the first, at the turn's end.
        for side in [second, first] {
            if s.side_mut(side)
                .replace_fainted(side, &mut log.events)
                .is_none()
            {
                let winner = Winner {
                    side: side.other(),
                    end: End::Knockouts,
                    turns: s.turn,
                };
                s.phase = Phase::Done(winner);
                log.end = Some(winner);
                return Ok((s, log));
            }
        }
        if s.turn >= s.turn_cap {
            let winner = s.decide_by_hp();
            s.phase = Phase::Done(winner);
            log.end = Some(winner);
        }
        Ok((s, log))
    }

    /// Plays one turn.
    pub fn step(&self, turn: &DuelTurnV1) -> Result<Self, Refusal> {
        Ok(self.step_logged(turn)?.0)
    }

    /// `0x5706 DuelStateV1`.
    ///
    /// 1 `match_nonce` digest32 · 2 `tiebreak_seed` digest32 · 3 `turn_cap`
    /// u16 · 4 `turn` u16 · 5 `phase` u8: 0 battle, 1 done followed by
    /// `winner u8 ‖ end u8` · 6 side a · 7 side b. A side is `poultice u8 ‖
    /// tonic u8 ‖ active u8 ‖ ko u8 ‖ team seq<fighter>`; a fighter is
    /// `creature nested 0x5701 ‖ guard u8 (0 down, 1 up) ‖ statuses
    /// seq<(id u8, turns u8)>`, distinct ids in the order they landed.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::object(Self::CLASS);
        w.digest(&self.match_nonce);
        w.digest(&self.tiebreak_seed);
        w.u16(self.turn_cap);
        w.u16(self.turn);
        match self.phase {
            Phase::Battle => w.u8(0),
            Phase::Done(win) => {
                w.u8(1);
                w.u8(win.side.code());
                w.u8(win.end.code());
            }
        }
        for side in [&self.a, &self.b] {
            w.u8(side.items[usize::from(ITEM_POULTICE)]);
            w.u8(side.items[usize::from(ITEM_TONIC)]);
            w.u8(side.active);
            w.u8(side.ko);
            w.count(side.team.len());
            for f in &side.team {
                w.nested(&f.creature.encode());
                w.u8(match f.guard {
                    Guard::Down => 0,
                    Guard::Up => 1,
                });
                w.count(f.statuses.len());
                for st in &f.statuses {
                    w.u8(st.id);
                    w.u8(st.turns);
                }
            }
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::object(bytes, Self::CLASS)?;
        let match_nonce = r.digest("state.match_nonce")?;
        let tiebreak_seed = r.digest("state.tiebreak_seed")?;
        let turn_cap = r.u16("state.turn_cap")?;
        if turn_cap != TABLES.constants.turn_cap {
            return Err(DecodeError::UnknownValue {
                field: "state.turn_cap",
                value: u32::from(turn_cap),
            });
        }
        let turn = r.u16("state.turn")?;
        if turn > turn_cap {
            return Err(DecodeError::Invalid {
                what: "state.turn is past the cap",
            });
        }
        let phase = match r.u8("state.phase")? {
            0 => Phase::Battle,
            1 => {
                let side_code = r.u8("state.winner")?;
                let side = Side::from_code(side_code).ok_or(DecodeError::UnknownValue {
                    field: "state.winner",
                    value: u32::from(side_code),
                })?;
                let end_code = r.u8("state.end")?;
                let end = End::from_code(end_code).ok_or(DecodeError::UnknownValue {
                    field: "state.end",
                    value: u32::from(end_code),
                })?;
                Phase::Done(Winner {
                    side,
                    end,
                    turns: turn,
                })
            }
            other => {
                return Err(DecodeError::UnknownValue {
                    field: "state.phase",
                    value: u32::from(other),
                })
            }
        };
        let a = read_side(&mut r)?;
        let b = read_side(&mut r)?;
        r.finish()?;
        if phase == Phase::Battle {
            if turn >= turn_cap {
                return Err(DecodeError::Invalid {
                    what: "a match at its cap is decided",
                });
            }
            for side in [&a, &b] {
                if side
                    .team
                    .get(usize::from(side.active))
                    .is_none_or(|f| f.hp() == 0)
                {
                    return Err(DecodeError::Invalid {
                        what: "a match in battle has a fainted active creature",
                    });
                }
            }
        }
        Ok(Self {
            match_nonce,
            tiebreak_seed,
            turn_cap,
            turn,
            phase,
            a,
            b,
        })
    }

    /// `H(DSM/wildstate-duel/state/v1 ‖ 0x00 ‖ CCB(state))`.
    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(crate::TAG_STATE, &[&self.encode()])
    }
}

fn read_side(r: &mut Reader<'_>) -> Result<SideState, DecodeError> {
    let poultice = r.u8("state.side.poultice")?;
    let tonic = r.u8("state.side.tonic")?;
    let active = r.u8("state.side.active")?;
    let ko = r.u8("state.side.ko")?;
    let n = r.count("state.side.team", 1, usize::from(TABLES.constants.team_max))?;
    let mut team = Vec::with_capacity(n);
    for _ in 0..n {
        let creature = r.nested(CreatureStateV1::read_body, CreatureStateV1::CLASS)?;
        let guard = match r.u8("state.fighter.guard")? {
            0 => Guard::Down,
            1 => Guard::Up,
            other => {
                return Err(DecodeError::UnknownValue {
                    field: "state.fighter.guard",
                    value: u32::from(other),
                })
            }
        };
        let k = r.count("state.fighter.statuses", 0, TABLES.statuses.len())?;
        let mut statuses: Vec<Status> = Vec::with_capacity(k);
        for _ in 0..k {
            let id = r.u8("state.status.id")?;
            let turns = r.u8("state.status.turns")?;
            let def = TABLES
                .statuses
                .get(usize::from(id))
                .ok_or(DecodeError::UnknownValue {
                    field: "state.status.id",
                    value: u32::from(id),
                })?;
            if turns == 0 || turns > def.turns || statuses.iter().any(|s| s.id == id) {
                return Err(DecodeError::Invalid {
                    what: "a status is repeated or its turns are out of range",
                });
            }
            statuses.push(Status { id, turns });
        }
        team.push(Fighter {
            creature,
            guard,
            statuses,
        });
    }
    if usize::from(active) >= team.len() || usize::from(ko) > team.len() {
        return Err(DecodeError::Invalid {
            what: "state.side.active or ko is outside the team",
        });
    }
    Ok(SideState {
        items: [poultice, tonic],
        active,
        ko,
        team,
    })
}
