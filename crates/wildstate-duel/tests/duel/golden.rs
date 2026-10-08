// SPDX-License-Identifier: MIT OR Apache-2.0

//! The frozen vectors, the pinned program hash, incremental stepping against
//! full replay, and termination under random play.

use crate::support::{random_match, random_move, Play, Rng, R};
use wildstate_duel::tables::{Constants, Tables, TABLES};
use wildstate_duel::vectors::DuelVectorSetV1;
use wildstate_duel::{
    conformance_vectors_digest_of, outcome, program_hash, program_hash_for, replay, start, step,
    tables_digest, verify_conformance, DuelMatchV1, DuelMoveV1, DuelSetupV1, DuelState, DuelTurnV1,
    Refusal, Side, VECTORS_V1,
};

/// `P` of rules version 1, pinned. A change to any table, constant or frozen
/// vector changes it, and this test fails until the new value is pinned on
/// purpose.
const PINNED_P: [u8; 32] = [
    164, 207, 112, 198, 252, 193, 147, 108, 96, 192, 4, 97, 109, 196, 107, 205, 239, 194, 0, 137,
    40, 16, 207, 109, 161, 144, 10, 254, 116, 25, 77, 205,
];

fn vectors() -> R<DuelVectorSetV1> {
    Ok(DuelVectorSetV1::decode(VECTORS_V1)?)
}

fn setup_bytes(body: &DuelMatchV1) -> Vec<u8> {
    DuelSetupV1 {
        program: program_hash(),
        body: body.clone(),
    }
    .encode()
}

/// The frozen file is exactly what the rules build today. When it is not,
/// the set built today is written to the test's scratch directory, and
/// copying it over the frozen file is the deliberate act of cutting a rules
/// version.
#[test]
fn the_frozen_vectors_are_what_the_rules_build() -> R {
    let built = crate::freeze::vector_set()?.encode();
    if built != VECTORS_V1 {
        let fresh = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("vectors.ccb");
        std::fs::write(&fresh, &built)?;
        panic!(
            "the rules build vectors other than the frozen ones; the set built today is at {} \
             and replaces tests/vectors/v1/vectors.ccb only when a rules version is cut",
            fresh.display()
        );
    }
    Ok(())
}

#[test]
fn the_program_reproduces_its_frozen_vectors() -> R {
    let n = verify_conformance()?;
    assert_eq!(n, vectors()?.vectors.len());
    assert!(n >= 60, "{n} vectors");
    Ok(())
}

#[test]
fn the_program_hash_is_pinned() -> R {
    assert_eq!(program_hash(), PINNED_P);
    Ok(())
}

#[test]
fn any_table_or_vector_change_changes_the_program_hash() -> R {
    let p = program_hash();
    let burn = Tables {
        constants: Constants {
            burn_damage: TABLES.constants.burn_damage + 1,
            ..TABLES.constants
        },
        ..TABLES
    };
    assert_ne!(burn.digest(), tables_digest());
    assert_ne!(program_hash_for(&burn, VECTORS_V1), p);
    // One move's power, one species further down the table.
    let mut species = TABLES.species.to_vec();
    let mut moves = species[6].moves.to_vec();
    moves[1].max += 1;
    species[6].moves = Box::leak(moves.into_boxed_slice());
    let moved = Tables {
        species: Box::leak(species.into_boxed_slice()),
        ..TABLES
    };
    assert_ne!(program_hash_for(&moved, VECTORS_V1), p);
    // One byte of the vectors.
    let mut v = VECTORS_V1.to_vec();
    let last = v.len() - 1;
    v[last] ^= 1;
    assert_ne!(
        conformance_vectors_digest_of(&v),
        conformance_vectors_digest_of(VECTORS_V1)
    );
    assert_ne!(program_hash_for(&TABLES, &v), p);
    assert_eq!(program_hash_for(&TABLES, VECTORS_V1), p);
    Ok(())
}

/// A wallet keeps the verified state as bytes and steps it one turn at a
/// time; that reaches exactly the full replay's result on every vector.
#[test]
fn incremental_steps_equal_full_replay_on_every_vector() -> R {
    for (i, v) in vectors()?.vectors.iter().enumerate() {
        let setup = setup_bytes(&v.body);
        let full = outcome(&setup, &v.turns)?;
        assert_eq!((full.side, full.end), (v.winner, v.end), "vector {i}");
        let mut kept = start(&setup)?.encode();
        for t in &v.turns {
            let state = DuelState::decode(&kept)?;
            let wire = DuelTurnV1::decode(&t.encode())?;
            kept = step(&state, &wire)?.encode();
        }
        let last = DuelState::decode(&kept)?;
        assert_eq!(last.winner(), Some(full), "vector {i}");
        assert_eq!(last.digest(), v.final_state, "vector {i}");
        let logs = replay(&setup, &v.turns)?;
        assert_eq!(logs.len(), v.turns.len());
        assert_eq!(logs.last().and_then(|l| l.end), Some(full));
    }
    Ok(())
}

#[test]
fn a_transcript_is_judged_only_whole_and_only_under_its_own_program() -> R {
    let set = vectors()?;
    let v = &set.vectors[0];
    let setup = setup_bytes(&v.body);
    let short = &v.turns[..v.turns.len() - 1];
    assert!(matches!(
        outcome(&setup, short),
        Err(Refusal::Unfinished { .. })
    ));
    assert_eq!(replay(&setup, short)?.len(), short.len());
    let mut long = v.turns.clone();
    long.push(v.turns[0]);
    assert!(matches!(
        outcome(&setup, &long),
        Err(Refusal::MatchOver { .. })
    ));
    let mut other = program_hash();
    other[0] ^= 1;
    let foreign = DuelSetupV1 {
        program: other,
        body: v.body.clone(),
    }
    .encode();
    assert!(matches!(
        outcome(&foreign, &v.turns),
        Err(Refusal::WrongProgram { .. })
    ));
    Ok(())
}

/// Seeded random matches, legal and loose play alike, always end with a
/// winner by the cap.
#[test]
fn every_random_match_ends_with_a_winner_by_the_cap() -> R {
    let mut rng = Rng::new(0xD0E1_0000_0000_0001);
    let mut ends = [0u32; 4];
    for i in 0..4000 {
        let m = random_match(&mut rng)?;
        let play = if i % 2 == 0 { Play::Legal } else { Play::Loose };
        // Every fifth match one side stalls, so the cap decides some.
        let stall = i % 5 == 4;
        let mut s = DuelState::start(&m);
        let mut turns = 0u16;
        while s.winner().is_none() {
            let a = random_move(&mut rng, &s, Side::A, play);
            let t = DuelTurnV1 {
                a: if stall { DuelMoveV1::Pass } else { a },
                b: if stall {
                    DuelMoveV1::Pass
                } else {
                    random_move(&mut rng, &s, Side::B, play)
                },
            };
            s = s.step(&t)?;
            turns += 1;
        }
        let w = s.winner().ok_or("decided")?;
        assert!(turns <= TABLES.constants.turn_cap && w.turns == turns);
        ends[usize::from(w.end.code())] += 1;
    }
    assert_eq!(ends.iter().sum::<u32>(), 4000);
    assert!(ends[0] > 0 && ends[2] > 0 && ends[3] > 0, "ends {ends:?}");
    Ok(())
}

/// The frozen vectors hold garbled openings, and each one is decided: the
/// pass rule for bytes that are no move is part of what `P` pins.
#[test]
fn the_frozen_vectors_decide_matches_with_garbled_openings() -> R {
    let set = vectors()?;
    let garbled = set
        .vectors
        .iter()
        .filter(|v| {
            v.opened.iter().any(|t| {
                [&t.a, &t.b]
                    .iter()
                    .any(|o| DuelMoveV1::decode(o).map(|m| m.encode()).as_ref() != Ok(*o))
            })
        })
        .count();
    assert!(garbled >= 3, "{garbled} vectors with garbled openings");
    for v in &set.vectors {
        let setup = setup_bytes(&v.body);
        let turns: Vec<DuelTurnV1> = v.opened.iter().map(|t| t.turn()).collect();
        assert_eq!(turns, v.turns);
        let w = outcome(&setup, &turns)?;
        assert_eq!((w.side, w.end), (v.winner, v.end));
    }
    Ok(())
}
