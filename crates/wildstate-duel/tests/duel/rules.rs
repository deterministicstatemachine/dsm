// SPDX-License-Identifier: MIT OR Apache-2.0

//! The battle rules. Every expected number is worked out by hand from the
//! game's tables in the comment beside it.

use crate::support::{creature, duel, mv, side, turn, xp_at, R};
use wildstate_duel::engine::{damage_x4, round_x4};
use wildstate_duel::tables::{STATUS_BURN, STATUS_ROOT, STATUS_STUN, TABLES};
use wildstate_duel::{
    Acted, CreatureStateV1, DuelMoveV1, DuelState, End, Event, EventKind, Played, Refusal, Side,
    Status, TurnLog,
};

const EMBERCUB: u8 = 0;
const MOSSLING: u8 = 1;
const TIDEFIN: u8 = 2;
const VOLTUSK: u8 = 3;
const LEON: u8 = 4;

const STRIKE: u8 = 0;
const BIG: u8 = 1;
const STATUS_MOVE: u8 = 2;
const GUARD_OR_HEAL: u8 = 3;

fn play(state: &DuelState, a: DuelMoveV1, b: DuelMoveV1) -> R<(DuelState, TurnLog)> {
    Ok(state.step_logged(&turn(a, b))?)
}
fn hp(state: &DuelState, s: Side, i: usize) -> u16 {
    state.side(s).team()[i].hp()
}
fn statuses(state: &DuelState, s: Side, i: usize) -> Vec<Status> {
    state.side(s).team()[i].statuses().to_vec()
}

/// `round(D/4)` against an f64 model of the TypeScript `damage()` for every
/// power a byte holds, every level, multiplier, soaked and guard case.
#[test]
fn damage_matches_the_f64_reference_exhaustively() -> R {
    let mults = [
        (TABLES.constants.strong_x4, 1.5f64),
        (TABLES.constants.neutral_x4, 1.0),
        (TABLES.constants.weak_x4, 0.5),
    ];
    let mut checked = 0u32;
    for power in 0..=u8::MAX {
        for level in 1..=TABLES.constants.level_cap {
            for (m4, mf) in mults {
                for soaked in [0u8, 1] {
                    for guarded in [0u8, 1] {
                        let mut d = (f64::from(power) + f64::from(level) - 1.0) * mf;
                        if soaked == 1 {
                            d = (d - 2.0).max(1.0);
                        }
                        if guarded == 1 {
                            d /= 2.0;
                        }
                        // Math.round: halves go up.
                        let reference = (d + 0.5).floor().max(0.0);
                        let got = round_x4(damage_x4(power, level, m4, soaked == 1, guarded == 1));
                        assert_eq!(
                            f64::from(got),
                            reference,
                            "power {power} level {level} mult {mf} soaked {soaked} guard {guarded}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 256 * 10 * 3 * 4);
    Ok(())
}

#[test]
fn the_higher_level_acts_first_on_either_side() -> R {
    // a embercub L3 strikes first: (8 + 2) · 4 = 40 → 10. b mossling L1: 32 → 8.
    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, EMBERCUB, 3, None)?]),
        side(2, 0, 0, vec![creature(2, MOSSLING, 1, None)?]),
    )?;
    let (s, log) = play(&DuelState::start(&m), mv(STRIKE), mv(STRIKE))?;
    assert_eq!(log.first, Some(Side::A));
    assert_eq!((log.actions[0].side, log.actions[0].dmg), (Side::A, 10));
    assert_eq!((log.actions[1].side, log.actions[1].dmg), (Side::B, 8));
    assert_eq!((hp(&s, Side::A, 0), hp(&s, Side::B, 0)), (40, 30));

    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, MOSSLING, 1, None)?]),
        side(2, 0, 0, vec![creature(2, EMBERCUB, 3, None)?]),
    )?;
    let (_, log) = play(&DuelState::start(&m), mv(STRIKE), mv(STRIKE))?;
    assert_eq!(log.first, Some(Side::B));
    Ok(())
}

/// On a level tie the first actor is bit 0 of
/// `BLAKE3(DSM/wildstate-duel/first-actor/v1 ‖ 0x00 ‖ seed ‖ u16_be(turn))`,
/// recomputed here independently; both sides get first turns.
#[test]
fn a_level_tie_is_broken_by_the_seeded_hash_without_side_bias() -> R {
    let mut firsts = [0u32; 2];
    for seed in 0u8..48 {
        let m = duel(
            seed,
            side(1, 0, 0, vec![creature(1, VOLTUSK, 4, None)?]),
            side(2, 0, 0, vec![creature(2, VOLTUSK, 4, None)?]),
        )?;
        let mut s = DuelState::start(&m);
        for t in 0u16..3 {
            let mut h = blake3::Hasher::new();
            h.update(b"DSM/wildstate-duel/first-actor/v1");
            h.update(&[0]);
            h.update(&[seed; 32]);
            h.update(&t.to_be_bytes());
            let expected = if h.finalize().as_bytes()[0].is_multiple_of(2) {
                Side::A
            } else {
                Side::B
            };
            let (next, log) = play(&s, DuelMoveV1::Pass, DuelMoveV1::Pass)?;
            assert_eq!(log.first, Some(expected), "seed {seed} turn {t}");
            firsts[usize::from(expected.code())] += 1;
            s = next;
        }
    }
    assert!(firsts[0] > 40 && firsts[1] > 40, "first turns {firsts:?}");
    Ok(())
}

/// Rule 1: the second actor's hold is read before its tick, so a root the
/// first actor lands holds it this very turn (and then ticks away).
#[test]
fn a_root_landed_by_the_first_actor_holds_the_second_this_turn() -> R {
    // a mossling L2 root-bind: (6 + 1) · 2 (fire resists grass) = 14 → 4. b 40 → 36.
    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, MOSSLING, 2, None)?]),
        side(2, 0, 0, vec![creature(2, EMBERCUB, 1, None)?]),
    )?;
    let (s, log) = play(&DuelState::start(&m), mv(STATUS_MOVE), mv(STRIKE))?;
    assert_eq!(
        (log.actions[0].dmg, log.actions[0].status),
        (4, Some(STATUS_ROOT))
    );
    assert_eq!((log.actions[1].acted, log.actions[1].dmg), (Acted::Held, 0));
    assert_eq!((hp(&s, Side::A, 0), hp(&s, Side::B, 0)), (44, 36));
    assert!(statuses(&s, Side::B, 0).is_empty(), "the root ticked away");
    assert_eq!(s.side(Side::A).team()[0].creature().charges()[2], 2);
    // Next turn b acts: 32 → 8.
    let (s, log) = play(&s, mv(STRIKE), mv(STRIKE))?;
    assert_eq!(
        (log.actions[1].acted, hp(&s, Side::A, 0)),
        (Acted::Acted, 36)
    );
    Ok(())
}

/// Rule 2: the second actor's statuses tick right after the first acts; the
/// burn the first lands ticks at once.
#[test]
fn the_second_actor_ticks_after_the_first_acts() -> R {
    // a embercub L2 ember-bite: (9 + 1) · 6 = 60 → 15; b 40 → 25, burn 2 ticks: −3 → 22.
    // b strike: 32 → 8; a 44 → 36.
    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, EMBERCUB, 2, None)?]),
        side(2, 0, 0, vec![creature(2, MOSSLING, 1, None)?]),
    )?;
    let (s, log) = play(&DuelState::start(&m), mv(STATUS_MOVE), mv(STRIKE))?;
    assert_eq!(
        (
            log.actions[0].dmg,
            log.actions[0].burn,
            log.actions[0].status
        ),
        (15, 3, Some(STATUS_BURN))
    );
    assert_eq!((hp(&s, Side::A, 0), hp(&s, Side::B, 0)), (36, 22));
    assert_eq!(
        statuses(&s, Side::B, 0),
        vec![Status {
            id: STATUS_BURN,
            turns: 1
        }]
    );
    // a strike (8 + 1) · 4 = 36 → 9: 22 → 13, last burn tick → 10. b strike → a 28.
    let (s, log) = play(&s, mv(STRIKE), mv(STRIKE))?;
    assert_eq!((log.actions[0].dmg, log.actions[0].burn), (9, 3));
    assert_eq!((hp(&s, Side::A, 0), hp(&s, Side::B, 0)), (28, 10));
    assert!(statuses(&s, Side::B, 0).is_empty());
    Ok(())
}

/// Rule 3: a status the second actor lands goes on after the first actor's
/// tick, so it is still there to hold the first actor next turn.
#[test]
fn the_second_actors_status_lands_after_the_first_actors_tick() -> R {
    // a embercub L3 (48): strike 40 → 10, b 40 → 30. b voltusk static-tusk 28 → 7: a 41, stun lands.
    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, EMBERCUB, 3, None)?]),
        side(2, 0, 0, vec![creature(2, VOLTUSK, 1, None)?]),
    )?;
    let (s, log) = play(&DuelState::start(&m), mv(STRIKE), mv(STATUS_MOVE))?;
    assert_eq!(log.actions[1].status, Some(STATUS_STUN));
    assert_eq!(hp(&s, Side::A, 0), 41);
    assert_eq!(
        statuses(&s, Side::A, 0),
        vec![Status {
            id: STATUS_STUN,
            turns: 1
        }]
    );
    // Turn 2: a is held; b strikes 8; the stun ticks away at the end.
    let (s, log) = play(&s, mv(STRIKE), mv(STRIKE))?;
    assert_eq!((log.actions[0].acted, log.actions[0].dmg), (Acted::Held, 0));
    assert_eq!((hp(&s, Side::A, 0), hp(&s, Side::B, 0)), (33, 30));
    assert!(statuses(&s, Side::A, 0).is_empty());
    Ok(())
}

/// Rule 3, second half: reported when the hit leaves the first actor
/// standing, but not applied when its own burn tick then knocks it out. Also:
/// a first actor whose opponent faints before acting does not tick.
#[test]
fn a_status_is_not_applied_to_a_first_actor_its_burn_knocks_out() -> R {
    let a = side(1, 0, 0, vec![creature(1, EMBERCUB, 3, Some(15))?]);
    let b = side(
        2,
        0,
        0,
        vec![
            creature(2, EMBERCUB, 1, Some(1))?,
            creature(4, VOLTUSK, 1, None)?,
        ],
    );
    let s = DuelState::start(&duel(1, a, b)?);
    // Turn 1: a guards; b ember-bite 36, halved 18 → 5 (4.5 up). a 15 → 10, burn lands after a's tick.
    let (s, log) = play(&s, mv(GUARD_OR_HEAL), mv(STATUS_MOVE))?;
    assert_eq!(
        (log.actions[1].dmg, log.actions[1].status),
        (5, Some(STATUS_BURN))
    );
    assert_eq!(
        statuses(&s, Side::A, 0),
        vec![Status {
            id: STATUS_BURN,
            turns: 2
        }]
    );
    // Turn 2: a knocks out b's embercub before it acts; a does not tick; b sends in its voltusk.
    let (s, log) = play(&s, mv(STRIKE), mv(STRIKE))?;
    assert_eq!(log.actions.len(), 1);
    assert_eq!(
        statuses(&s, Side::A, 0),
        vec![Status {
            id: STATUS_BURN,
            turns: 2
        }]
    );
    assert_eq!(
        log.events,
        vec![
            Event {
                side: Side::B,
                kind: EventKind::Faint,
                team_index: 0
            },
            Event {
                side: Side::B,
                kind: EventKind::Switch,
                team_index: 1
            },
        ]
    );
    // Turn 3: static-tusk 7 leaves a at 3 (stun reported), the burn tick takes the last 3.
    let (s, log) = play(&s, mv(STRIKE), mv(STATUS_MOVE))?;
    assert_eq!(
        (
            log.actions[1].dmg,
            log.actions[1].burn,
            log.actions[1].status
        ),
        (7, 3, Some(STATUS_STUN))
    );
    assert_eq!(hp(&s, Side::A, 0), 0);
    assert!(!statuses(&s, Side::A, 0).iter().any(|x| x.id == STATUS_STUN));
    let w = s.winner().ok_or("decided")?;
    assert_eq!((w.side, w.end, w.turns), (Side::B, End::Knockouts, 3));
    Ok(())
}

/// Rule 4: items take effect before the exchange, for both sides.
#[test]
fn items_apply_before_the_exchange_on_both_sides() -> R {
    // a voltusk L2 at 30 drinks a poultice (→ 44 cap) before b's strike (8): 36, not 37.
    let a = side(1, 1, 0, vec![creature(1, VOLTUSK, 2, Some(30))?]);
    let b = side(2, 1, 0, vec![creature(2, EMBERCUB, 1, None)?]);
    let (s, log) = play(
        &DuelState::start(&duel(1, a, b)?),
        DuelMoveV1::Item {
            item: 0,
            team_index: 0,
        },
        mv(STRIKE),
    )?;
    assert_eq!(
        log.actions[0].played,
        Played::Item {
            item: 0,
            team_index: 0
        }
    );
    assert_eq!(hp(&s, Side::A, 0), 36);
    assert_eq!(s.side(Side::A).items(), [0, 0]);
    // Both sides spend a poultice in one turn.
    let a = side(1, 1, 0, vec![creature(1, VOLTUSK, 1, Some(30))?]);
    let b = side(
        2,
        1,
        0,
        vec![
            creature(2, TIDEFIN, 1, Some(20))?,
            creature(4, LEON, 1, Some(5))?,
        ],
    );
    let (s, _) = play(
        &DuelState::start(&duel(1, a, b)?),
        DuelMoveV1::Item {
            item: 0,
            team_index: 0,
        },
        DuelMoveV1::Item {
            item: 0,
            team_index: 1,
        },
    )?;
    assert_eq!(
        (hp(&s, Side::A, 0), hp(&s, Side::B, 0), hp(&s, Side::B, 1)),
        (40, 20, 20)
    );
    assert_eq!(
        (s.side(Side::A).items(), s.side(Side::B).items()),
        ([0, 0], [0, 0])
    );
    Ok(())
}

/// Rule 5: the actors spend charges; a held creature spends none.
#[test]
fn charges_are_spent_by_acting_creatures_only() -> R {
    // a mossling L4 root-bind (max 3 + 1): 4 → 3. b voltusk is held: volt-charge stays 5.
    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, MOSSLING, 4, None)?]),
        side(2, 0, 0, vec![creature(2, VOLTUSK, 1, None)?]),
    )?;
    let (s, _) = play(&DuelState::start(&m), mv(STATUS_MOVE), mv(BIG))?;
    assert_eq!(s.side(Side::A).team()[0].creature().charges()[2], 3);
    assert_eq!(s.side(Side::B).team()[0].creature().charges()[1], 5);
    let (s, _) = play(&s, mv(STRIKE), mv(BIG))?;
    assert_eq!(s.side(Side::B).team()[0].creature().charges()[1], 4);
    Ok(())
}

/// Rule 6: a tonic refills every charged move to `max + charge_bonus(level)`.
#[test]
fn a_tonic_refills_to_the_levels_maximum() -> R {
    // embercub L7: bonus 2 → flare 7, ember-bite 5, warm-coat 4; strike has none.
    let empty = CreatureStateV1::new([1; 32], EMBERCUB, xp_at(7), 60, vec![0, 0, 0, 0])?;
    let m = duel(
        1,
        side(1, 0, 1, vec![empty]),
        side(2, 0, 0, vec![creature(2, MOSSLING, 1, None)?]),
    )?;
    let (s, _) = play(
        &DuelState::start(&m),
        DuelMoveV1::Item {
            item: 1,
            team_index: 0,
        },
        DuelMoveV1::Pass,
    )?;
    assert_eq!(
        s.side(Side::A).team()[0].creature().charges(),
        &[0, 7, 5, 4]
    );
    assert_eq!(s.side(Side::A).items(), [0, 0]);
    Ok(())
}

/// Rule 7: a fainted creature is replaced by the first standing one in team
/// order; a side with none left loses by knockouts.
#[test]
fn a_fainted_creature_is_replaced_in_team_order() -> R {
    let a = side(1, 0, 0, vec![creature(1, EMBERCUB, 10, None)?]);
    let b = side(
        2,
        0,
        0,
        vec![
            creature(2, MOSSLING, 1, Some(5))?,
            creature(4, TIDEFIN, 1, None)?,
            creature(6, LEON, 1, None)?,
        ],
    );
    // (8 + 9) · 4 = 68 → 17 knocks out the mossling.
    let (mut s, log) = play(&DuelState::start(&duel(1, a, b)?), mv(STRIKE), mv(STRIKE))?;
    assert_eq!(
        log.events,
        vec![
            Event {
                side: Side::B,
                kind: EventKind::Faint,
                team_index: 0
            },
            Event {
                side: Side::B,
                kind: EventKind::Switch,
                team_index: 1
            },
        ]
    );
    assert_eq!((s.side(Side::B).active(), s.side(Side::B).ko()), (1, 1));
    let mut seen = vec![1u8];
    while s.winner().is_none() {
        s = play(&s, mv(STRIKE), mv(STRIKE))?.0;
        seen.push(s.side(Side::B).active());
    }
    seen.dedup();
    assert_eq!(seen, vec![1, 2]);
    let w = s.winner().ok_or("decided")?;
    assert_eq!(
        (w.side, w.end, s.side(Side::B).ko()),
        (Side::A, End::Knockouts, 3)
    );
    Ok(())
}

#[test]
fn resigning_hands_the_other_side_the_win() -> R {
    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, LEON, 2, None)?]),
        side(2, 0, 0, vec![creature(2, TIDEFIN, 2, None)?]),
    )?;
    let s = DuelState::start(&m);
    let (done, log) = play(&s, DuelMoveV1::Resign, mv(BIG))?;
    let w = done.winner().ok_or("decided")?;
    assert_eq!((w.side, w.end, w.turns), (Side::B, End::Resign, 1));
    assert_eq!(log.actions[0].played, Played::Resign);
    assert_eq!(
        hp(&done, Side::A, 0),
        hp(&s, Side::A, 0),
        "a resigned turn plays nothing"
    );
    let (done, _) = play(&s, mv(STRIKE), DuelMoveV1::Resign)?;
    assert_eq!(
        done.winner().map(|w| (w.side, w.end)),
        Some((Side::A, End::Resign))
    );
    assert!(matches!(
        done.step(&turn(mv(STRIKE), mv(STRIKE))),
        Err(Refusal::MatchOver { turns: 1 })
    ));
    Ok(())
}

#[test]
fn both_resigning_is_decided_by_hp_then_the_seed() -> R {
    let m = duel(
        1,
        side(1, 0, 0, vec![creature(1, LEON, 2, Some(30))?]),
        side(2, 0, 0, vec![creature(2, TIDEFIN, 2, None)?]),
    )?;
    let (done, _) = play(
        &DuelState::start(&m),
        DuelMoveV1::Resign,
        DuelMoveV1::Resign,
    )?;
    assert_eq!(
        done.winner().map(|w| (w.side, w.end)),
        Some((Side::B, End::Hp))
    );
    for (seed, expected) in [(0x20u8, Side::A), (0x21, Side::B)] {
        let m = duel(
            seed,
            side(1, 0, 0, vec![creature(1, LEON, 2, None)?]),
            side(2, 0, 0, vec![creature(2, TIDEFIN, 2, None)?]),
        )?;
        let (done, _) = play(
            &DuelState::start(&m),
            DuelMoveV1::Resign,
            DuelMoveV1::Resign,
        )?;
        assert_eq!(
            done.winner().map(|w| (w.side, w.end)),
            Some((expected, End::Tiebreak))
        );
    }
    Ok(())
}

fn pass_to_cap(mut s: DuelState) -> R<DuelState> {
    for t in 0..TABLES.constants.turn_cap {
        assert!(s.winner().is_none(), "decided early at turn {t}");
        s = play(&s, DuelMoveV1::Pass, DuelMoveV1::Pass)?.0;
    }
    Ok(s)
}

#[test]
fn at_the_cap_more_total_hp_wins() -> R {
    // Team totals: a 30 + 20 = 50, b 40 + 9 = 49.
    let a = side(
        1,
        0,
        0,
        vec![
            creature(1, VOLTUSK, 1, Some(30))?,
            creature(3, LEON, 1, Some(20))?,
        ],
    );
    let b = side(
        2,
        0,
        0,
        vec![
            creature(2, VOLTUSK, 1, None)?,
            creature(4, LEON, 1, Some(9))?,
        ],
    );
    let s = pass_to_cap(DuelState::start(&duel(1, a, b)?))?;
    let w = s.winner().ok_or("decided at the cap")?;
    assert_eq!((w.side, w.end, w.turns), (Side::A, End::Hp, 60));
    assert!(matches!(
        s.step(&turn(DuelMoveV1::Pass, DuelMoveV1::Pass)),
        Err(Refusal::MatchOver { turns: 60 })
    ));
    Ok(())
}

#[test]
fn at_the_cap_equal_hp_goes_to_the_seeds_parity() -> R {
    for (seed, expected) in [
        (0x42u8, Side::A),
        (0x43, Side::B),
        (0xFE, Side::A),
        (0xFF, Side::B),
    ] {
        let a = side(1, 0, 0, vec![creature(1, VOLTUSK, 1, Some(33))?]);
        let b = side(2, 0, 0, vec![creature(2, EMBERCUB, 1, Some(33))?]);
        let s = pass_to_cap(DuelState::start(&duel(seed, a, b)?))?;
        let w = s.winner().ok_or("decided at the cap")?;
        assert_eq!(
            (w.side, w.end, w.turns),
            (expected, End::Tiebreak, 60),
            "seed {seed:#x}"
        );
    }
    Ok(())
}

/// An opened move the rules cannot use plays as a pass and changes nothing.
#[test]
fn unusable_moves_play_as_passes() -> R {
    // a embercub L2 with flare empty; b mossling L1 (5 hp) then leon, no items.
    let a = side(
        1,
        0,
        0,
        vec![CreatureStateV1::new(
            [1; 32],
            EMBERCUB,
            xp_at(2),
            44,
            vec![0, 0, 3, 2],
        )?],
    );
    let b = side(
        2,
        0,
        0,
        vec![
            creature(2, MOSSLING, 1, Some(5))?,
            creature(4, LEON, 1, None)?,
        ],
    );
    let s = DuelState::start(&duel(1, a, b)?);
    for (am, bm) in [
        (
            mv(9),
            DuelMoveV1::Item {
                item: 0,
                team_index: 0,
            },
        ),
        (
            mv(BIG),
            DuelMoveV1::Item {
                item: 9,
                team_index: 0,
            },
        ),
        (
            DuelMoveV1::Item {
                item: 1,
                team_index: 0,
            },
            mv(4),
        ),
        (
            DuelMoveV1::Pass,
            DuelMoveV1::Item {
                item: 0,
                team_index: 3,
            },
        ),
    ] {
        let (next, log) = play(&s, am, bm)?;
        assert!(
            log.actions
                .iter()
                .all(|x| x.played == Played::Pass && x.dmg == 0),
            "{log:?}"
        );
        assert_eq!((hp(&next, Side::A, 0), hp(&next, Side::B, 0)), (44, 5));
        assert_eq!(
            next.side(Side::A).team()[0].creature().charges(),
            &[0, 0, 3, 2]
        );
    }
    // A poultice aimed at a fainted creature is a pass and keeps the poultice.
    let a = side(1, 0, 0, vec![creature(1, EMBERCUB, 4, None)?]);
    let b = side(
        2,
        1,
        0,
        vec![
            creature(2, MOSSLING, 1, Some(5))?,
            creature(4, LEON, 1, None)?,
        ],
    );
    let (s, _) = play(&DuelState::start(&duel(1, a, b)?), mv(STRIKE), mv(STRIKE))?;
    assert_eq!(hp(&s, Side::B, 0), 0);
    let (s, log) = play(
        &s,
        DuelMoveV1::Pass,
        DuelMoveV1::Item {
            item: 0,
            team_index: 0,
        },
    )?;
    assert_eq!(log.actions[1].played, Played::Pass);
    assert_eq!(s.side(Side::B).items(), [1, 0]);
    Ok(())
}
