// SPDX-License-Identifier: MIT OR Apache-2.0

//! Freezes the rules-version-1 conformance vectors into
//! `tests/vectors/v1/vectors.ccb`.
//!
//! Run once when a rules version is cut:
//! `cargo run -p wildstate-duel --example freeze_vectors`. The vectors' digest
//! is part of `P`, so re-running it against changed rules makes a different
//! program; the pinned-hash test then fails until the new `P` is pinned on
//! purpose. Every vector also replays through the game's TypeScript engine
//! (`dsm-creatures/test/duel-equivalence.test.ts`), which is the evidence
//! that the frozen results are the game's rules and not only this crate's.

#[path = "../tests/support/mod.rs"]
mod support;

use support::{creature, duel, mv, random_match, random_move, side, turn, Play, Rng, R};
use wildstate_duel::vectors::{DuelVectorSetV1, DuelVectorV1};
use wildstate_duel::{DuelMatchV1, DuelMoveV1, DuelOpenedTurnV1, DuelState, DuelTurnV1, Side};

const EMBERCUB: u8 = 0;
const MOSSLING: u8 = 1;
const TIDEFIN: u8 = 2;
const VOLTUSK: u8 = 3;
const LEON: u8 = 4;
const RATTLEFIN: u8 = 5;
const BRINEBACK: u8 = 6;

/// How the turns after the script are played.
enum Fill {
    /// Both sides strike.
    Strike,
    /// Both sides pass, so the cap decides.
    Pass,
    /// Both sides open bytes that are no move at all, so the cap decides.
    Garbled,
    /// Seeded random play.
    Random(u64, Play),
}

/// Plays the script, then the fill, until the match is decided.
fn scripted(label: &str, m: DuelMatchV1, script: &[DuelTurnV1], fill: Fill) -> R<DuelVectorV1> {
    let opened: Vec<DuelOpenedTurnV1> = script.iter().map(DuelOpenedTurnV1::of).collect();
    opened_scripted(label, m, &opened, fill)
}

/// [`scripted`] over openings exactly as revealed, garbled ones included.
fn opened_scripted(
    label: &str,
    m: DuelMatchV1,
    script: &[DuelOpenedTurnV1],
    fill: Fill,
) -> R<DuelVectorV1> {
    let mut state = DuelState::start(&m);
    let mut turns = Vec::new();
    let mut rng = Rng::new(match fill {
        Fill::Random(seed, _) => seed,
        _ => 1,
    });
    let mut script = script.iter();
    while state.winner().is_none() {
        let t = match (script.next(), &fill) {
            (Some(t), _) => t.clone(),
            (None, Fill::Strike) => DuelOpenedTurnV1::of(&turn(mv(0), mv(0))),
            (None, Fill::Pass) => DuelOpenedTurnV1::of(&turn(DuelMoveV1::Pass, DuelMoveV1::Pass)),
            (None, Fill::Garbled) => DuelOpenedTurnV1 {
                a: vec![0xFF],
                b: vec![0x57, 0x04, 0x00, 0x01, 0x09],
            },
            (None, Fill::Random(_, play)) => DuelOpenedTurnV1::of(&turn(
                random_move(&mut rng, &state, Side::A, *play),
                random_move(&mut rng, &state, Side::B, *play),
            )),
        };
        state = state.step(&t.turn())?;
        turns.push(t);
    }
    Ok(DuelVectorV1::freeze(label, m, turns)?)
}

fn main() -> R {
    let out = match std::env::args().nth(1) {
        Some(path) => path,
        None => format!(
            "{}/tests/vectors/v1/vectors.ccb",
            env!("CARGO_MANIFEST_DIR")
        ),
    };
    let s = |idx: u8| mv(idx);
    let mut vectors = vec![
        scripted(
            "rounding-half-up",
            duel(
                0x10,
                side(1, 0, 0, vec![creature(1, EMBERCUB, 1, None)?]),
                side(2, 0, 0, vec![creature(2, MOSSLING, 1, None)?]),
            )?,
            &[turn(s(2), s(0)), turn(s(2), s(0)), turn(s(2), s(1))],
            Fill::Strike,
        )?,
        scripted(
            "guard-halves-and-clears",
            duel(
                0x11,
                side(1, 0, 0, vec![creature(1, TIDEFIN, 2, None)?]),
                side(2, 0, 0, vec![creature(2, EMBERCUB, 2, None)?]),
            )?,
            &[
                turn(s(3), s(1)),
                turn(s(3), s(1)),
                turn(s(1), s(3)),
                turn(s(1), s(1)),
            ],
            Fill::Strike,
        )?,
        scripted(
            "soaked-weakens-attacker",
            duel(
                0x12,
                side(1, 0, 0, vec![creature(1, BRINEBACK, 3, None)?]),
                side(2, 0, 0, vec![creature(2, LEON, 3, None)?]),
            )?,
            &[turn(s(2), s(1)), turn(s(2), s(1)), turn(s(1), s(2))],
            Fill::Strike,
        )?,
        scripted(
            "root-holds-the-same-turn",
            duel(
                0x13,
                side(1, 0, 0, vec![creature(1, MOSSLING, 4, None)?]),
                side(2, 0, 0, vec![creature(2, VOLTUSK, 2, None)?]),
            )?,
            &[
                turn(s(2), s(1)),
                turn(s(2), s(1)),
                turn(s(3), s(2)),
                turn(s(1), s(2)),
            ],
            Fill::Strike,
        )?,
        scripted(
            "stun-lands-after-the-tick",
            duel(
                0x14,
                side(1, 0, 0, vec![creature(1, EMBERCUB, 3, None)?]),
                side(2, 0, 0, vec![creature(2, VOLTUSK, 1, None)?]),
            )?,
            &[turn(s(0), s(2)), turn(s(2), s(2)), turn(s(1), s(2))],
            Fill::Strike,
        )?,
        scripted(
            "items-poultice-and-tonic",
            duel(
                0x15,
                side(
                    1,
                    2,
                    1,
                    vec![
                        creature(1, VOLTUSK, 5, Some(20))?,
                        creature(3, LEON, 2, None)?,
                    ],
                ),
                side(2, 1, 1, vec![creature(2, TIDEFIN, 5, None)?]),
            )?,
            &[
                turn(
                    DuelMoveV1::Item {
                        item: 0,
                        team_index: 0,
                    },
                    s(1),
                ),
                turn(s(1), s(1)),
                turn(
                    s(1),
                    DuelMoveV1::Item {
                        item: 1,
                        team_index: 0,
                    },
                ),
                turn(
                    DuelMoveV1::Item {
                        item: 1,
                        team_index: 0,
                    },
                    DuelMoveV1::Item {
                        item: 0,
                        team_index: 0,
                    },
                ),
                turn(s(1), s(1)),
            ],
            Fill::Strike,
        )?,
        scripted(
            "faint-and-switch-teams-of-three",
            duel(
                0x16,
                side(
                    1,
                    1,
                    0,
                    vec![
                        creature(1, EMBERCUB, 6, None)?,
                        creature(3, MOSSLING, 2, None)?,
                        creature(5, TIDEFIN, 2, None)?,
                    ],
                ),
                side(
                    2,
                    0,
                    1,
                    vec![
                        creature(2, LEON, 3, None)?,
                        creature(4, RATTLEFIN, 3, None)?,
                        creature(6, BRINEBACK, 3, None)?,
                    ],
                ),
            )?,
            &[],
            Fill::Random(0x5EED_0016, Play::Legal),
        )?,
        scripted(
            "resign-a",
            duel(
                0x17,
                side(1, 0, 0, vec![creature(1, LEON, 2, None)?]),
                side(2, 0, 0, vec![creature(2, RATTLEFIN, 2, None)?]),
            )?,
            &[
                turn(s(1), s(1)),
                turn(s(2), s(2)),
                turn(DuelMoveV1::Resign, s(1)),
            ],
            Fill::Strike,
        )?,
        scripted(
            "resign-b-first-turn",
            duel(
                0x18,
                side(1, 0, 0, vec![creature(1, LEON, 2, None)?]),
                side(2, 0, 0, vec![creature(2, RATTLEFIN, 2, None)?]),
            )?,
            &[turn(s(1), DuelMoveV1::Resign)],
            Fill::Strike,
        )?,
        scripted(
            "both-resign-hp-decides",
            duel(
                0x19,
                side(1, 0, 0, vec![creature(1, MOSSLING, 3, None)?]),
                side(2, 0, 0, vec![creature(2, EMBERCUB, 3, None)?]),
            )?,
            &[
                turn(s(1), s(1)),
                turn(DuelMoveV1::Resign, DuelMoveV1::Resign),
            ],
            Fill::Strike,
        )?,
        scripted(
            "cap-more-hp-wins",
            duel(
                0x1A,
                side(1, 0, 0, vec![creature(1, VOLTUSK, 1, Some(30))?]),
                side(2, 0, 0, vec![creature(2, VOLTUSK, 1, Some(31))?]),
            )?,
            &[],
            Fill::Pass,
        )?,
        scripted(
            "cap-equal-hp-even-seed",
            duel(
                0x42,
                side(
                    1,
                    0,
                    0,
                    vec![
                        creature(1, TIDEFIN, 2, None)?,
                        creature(3, LEON, 1, Some(9))?,
                    ],
                ),
                side(
                    2,
                    0,
                    0,
                    vec![
                        creature(2, TIDEFIN, 2, Some(40))?,
                        creature(4, LEON, 1, Some(13))?,
                    ],
                ),
            )?,
            &[],
            Fill::Pass,
        )?,
        scripted(
            "cap-equal-hp-odd-seed",
            duel(
                0x43,
                side(1, 0, 0, vec![creature(1, BRINEBACK, 4, None)?]),
                side(2, 0, 0, vec![creature(2, RATTLEFIN, 4, None)?]),
            )?,
            &[turn(s(3), s(3))],
            Fill::Pass,
        )?,
        scripted(
            "unusable-moves-play-as-passes",
            duel(
                0x1B,
                side(
                    1,
                    0,
                    1,
                    vec![wildstate_duel::CreatureStateV1::new(
                        [1; 32],
                        EMBERCUB,
                        20,
                        44,
                        vec![0, 0, 3, 2],
                    )?],
                ),
                side(2, 0, 0, vec![creature(2, MOSSLING, 2, None)?]),
            )?,
            &[
                turn(
                    s(9),
                    DuelMoveV1::Item {
                        item: 0,
                        team_index: 0,
                    },
                ),
                turn(
                    s(1),
                    DuelMoveV1::Item {
                        item: 7,
                        team_index: 0,
                    },
                ),
                turn(
                    DuelMoveV1::Item {
                        item: 1,
                        team_index: 4,
                    },
                    s(4),
                ),
                turn(
                    DuelMoveV1::Item {
                        item: 1,
                        team_index: 0,
                    },
                    s(1),
                ),
                turn(s(1), s(1)),
            ],
            Fill::Strike,
        )?,
        scripted(
            "level-tie-order-from-seed",
            duel(
                0x1C,
                side(
                    1,
                    0,
                    0,
                    vec![
                        creature(1, VOLTUSK, 5, None)?,
                        creature(3, EMBERCUB, 5, None)?,
                    ],
                ),
                side(
                    2,
                    0,
                    0,
                    vec![
                        creature(2, TIDEFIN, 5, None)?,
                        creature(4, MOSSLING, 5, None)?,
                    ],
                ),
            )?,
            &[],
            Fill::Random(0x5EED_001C, Play::Legal),
        )?,
    ];
    // Openings that are no canonical move: each plays as a pass.
    let garbled: Vec<Vec<u8>> = vec![
        // A canonical move with a byte after it.
        [mv(0).encode(), vec![0x00]].concat(),
        // A move kind the program does not define.
        vec![0x57, 0x04, 0x00, 0x01, 0x09],
        // A Move cut off before its index.
        vec![0x57, 0x04, 0x00, 0x01, 0x00],
        // A whole turn where one move belongs.
        turn(mv(0), mv(1)).encode(),
        // An unknown schema.
        vec![0x57, 0x04, 0x00, 0x02, 0x02],
        // One stray byte, and the longest opening there is.
        vec![0xFF],
        vec![0xA5; wildstate_duel::MAX_OPENED_MOVE_BYTES],
    ];
    vectors.push(opened_scripted(
        "garbled-openings-play-as-passes",
        duel(
            0x1D,
            side(1, 0, 0, vec![creature(1, TIDEFIN, 3, None)?]),
            side(2, 0, 0, vec![creature(2, EMBERCUB, 3, None)?]),
        )?,
        &garbled
            .iter()
            .map(|bytes| DuelOpenedTurnV1 {
                a: bytes.clone(),
                b: mv(0).encode(),
            })
            .collect::<Vec<_>>(),
        Fill::Strike,
    )?);
    vectors.push(opened_scripted(
        "garbled-openings-b-then-items",
        duel(
            0x1E,
            side(1, 1, 0, vec![creature(1, LEON, 2, Some(15))?]),
            side(2, 0, 0, vec![creature(2, MOSSLING, 2, None)?]),
        )?,
        &[
            DuelOpenedTurnV1 {
                a: DuelMoveV1::Item {
                    item: 0,
                    team_index: 0,
                }
                .encode(),
                b: garbled[0].clone(),
            },
            DuelOpenedTurnV1 {
                a: mv(1).encode(),
                b: garbled[3].clone(),
            },
        ],
        Fill::Strike,
    )?);
    vectors.push(opened_scripted(
        "garbled-both-sides-cap-decides",
        duel(
            0x1F,
            side(1, 0, 0, vec![creature(1, RATTLEFIN, 2, Some(21))?]),
            side(2, 0, 0, vec![creature(2, BRINEBACK, 2, Some(20))?]),
        )?,
        &[],
        Fill::Garbled,
    )?);
    let mut rng = Rng::new(0x0057_1D57_A7E0_0001);
    for i in 0..48 {
        let m = random_match(&mut rng)?;
        let seed = rng.next();
        let play = if i % 2 == 0 { Play::Legal } else { Play::Loose };
        vectors.push(scripted(
            &format!("random-{i:02}"),
            m,
            &[],
            Fill::Random(seed, play),
        )?);
    }
    let set = DuelVectorSetV1 { vectors };
    let bytes = set.encode();
    std::fs::write(&out, &bytes)?;
    println!(
        "{} vectors, {} bytes -> {out}",
        set.vectors.len(),
        bytes.len()
    );
    Ok(())
}
