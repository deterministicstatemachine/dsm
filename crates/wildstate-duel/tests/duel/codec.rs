// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical encoding: exact round trips, and the strict decoders' refusals.

use crate::support::{creature, duel, mv, side, turn, R};
use wildstate_duel::vectors::DuelVectorSetV1;
use wildstate_duel::{
    class, program_hash, CreatureStateV1, DecodeError, DuelMatchV1, DuelMoveV1, DuelSetupV1,
    DuelState, DuelTurnV1, VECTORS_V1,
};

fn sample_match() -> R<DuelMatchV1> {
    duel(
        7,
        side(
            1,
            2,
            1,
            vec![creature(1, 0, 3, Some(20))?, creature(3, 1, 1, None)?],
        ),
        side(2, 0, 2, vec![creature(2, 2, 5, None)?]),
    )
}

/// Encode → decode → encode is the identity on bytes, and refuses any extra byte.
fn round_trips<T: PartialEq + core::fmt::Debug>(
    bytes: Vec<u8>,
    value: &T,
    decode: impl Fn(&[u8]) -> Result<T, DecodeError>,
    encode: impl Fn(&T) -> Vec<u8>,
) -> R {
    let back = decode(&bytes)?;
    assert_eq!(&back, value);
    assert_eq!(encode(&back), bytes);
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        decode(&longer),
        Err(DecodeError::TrailingBytes { extra: 1 })
    );
    let shorter = &bytes[..bytes.len() - 1];
    assert!(matches!(
        decode(shorter),
        Err(DecodeError::Truncated { .. })
    ));
    Ok(())
}

#[test]
fn every_object_round_trips_exactly() -> R {
    let c = creature(9, 3, 6, Some(30))?;
    round_trips(
        c.encode(),
        &c,
        CreatureStateV1::decode,
        CreatureStateV1::encode,
    )?;
    let m = sample_match()?;
    round_trips(m.encode(), &m, DuelMatchV1::decode, DuelMatchV1::encode)?;
    let setup = DuelSetupV1 {
        program: program_hash(),
        body: m.clone(),
    };
    round_trips(
        setup.encode(),
        &setup,
        DuelSetupV1::decode,
        DuelSetupV1::encode,
    )?;
    for mvv in [
        mv(2),
        DuelMoveV1::Item {
            item: 1,
            team_index: 2,
        },
        DuelMoveV1::Pass,
        DuelMoveV1::Resign,
    ] {
        round_trips(mvv.encode(), &mvv, DuelMoveV1::decode, DuelMoveV1::encode)?;
    }
    let t = turn(mv(1), DuelMoveV1::Resign);
    round_trips(t.encode(), &t, DuelTurnV1::decode, DuelTurnV1::encode)?;
    // A state with a guard up, statuses on and an item spent.
    let mut s = DuelState::start(&m);
    for t in [
        turn(mv(3), mv(2)),
        turn(
            DuelMoveV1::Item {
                item: 0,
                team_index: 0,
            },
            mv(1),
        ),
        turn(mv(2), mv(3)),
    ] {
        s = s.step(&t)?;
    }
    assert!(
        s.side(wildstate_duel::Side::A).team()[0].statuses().len()
            + s.side(wildstate_duel::Side::B).team()[0].statuses().len()
            > 0
    );
    round_trips(s.encode(), &s, DuelState::decode, DuelState::encode)?;
    let set = DuelVectorSetV1::decode(VECTORS_V1)?;
    assert_eq!(set.encode(), VECTORS_V1);
    Ok(())
}

#[test]
fn the_move_layout_is_the_documented_bytes() -> R {
    assert_eq!(
        DuelMoveV1::Item {
            item: 1,
            team_index: 2
        }
        .encode(),
        vec![0x57, 0x04, 0x00, 0x01, 1, 1, 2]
    );
    assert_eq!(DuelMoveV1::Resign.encode(), vec![0x57, 0x04, 0x00, 0x01, 3]);
    let t = turn(mv(0), DuelMoveV1::Pass).encode();
    assert_eq!(
        t,
        vec![0x57, 0x05, 0, 1, 0x57, 0x04, 0, 1, 0, 0, 0x57, 0x04, 0, 1, 2]
    );
    Ok(())
}

#[test]
fn a_wrong_class_or_schema_is_refused() -> R {
    let c = creature(9, 3, 6, None)?.encode();
    assert_eq!(
        DuelMoveV1::decode(&c),
        Err(DecodeError::WrongClass {
            expected: class::DUEL_MOVE,
            got: class::CREATURE_STATE
        })
    );
    let mut schema2 = c.clone();
    schema2[3] = 2;
    assert_eq!(
        CreatureStateV1::decode(&schema2),
        Err(DecodeError::UnknownSchema {
            class: class::CREATURE_STATE,
            schema: 2
        })
    );
    // A nested object under the wrong class.
    let mut t = turn(mv(0), mv(0)).encode();
    t[5] = 0x01;
    assert!(matches!(
        DuelTurnV1::decode(&t),
        Err(DecodeError::WrongClass { .. })
    ));
    Ok(())
}

#[test]
fn non_canonical_lengths_and_values_are_refused() -> R {
    // Charges: the count must be the species' move count (4).
    let c = creature(9, 3, 6, None)?.encode();
    let count_at = 4 + 32 + 1 + 4 + 2;
    let mut three = c.clone();
    three[count_at + 3] = 3;
    three.pop();
    assert!(matches!(
        CreatureStateV1::decode(&three),
        Err(DecodeError::Cardinality {
            field: "creature.charges",
            ..
        })
    ));
    // HP above the level's maximum, charges above the move's maximum.
    let mut over = c.clone();
    over[count_at - 1] = 0xFF;
    assert!(matches!(
        CreatureStateV1::decode(&over),
        Err(DecodeError::Invalid { .. })
    ));
    let mut charged = c.clone();
    charged[count_at + 4 + 1] = 99;
    assert!(matches!(
        CreatureStateV1::decode(&charged),
        Err(DecodeError::Invalid { .. })
    ));
    // An unknown species.
    let mut species = c.clone();
    species[4 + 32] = 7;
    assert!(matches!(
        CreatureStateV1::decode(&species),
        Err(DecodeError::UnknownValue { .. })
    ));

    // A session key length that runs past the input, and an empty one.
    let m = sample_match()?.encode();
    let key_len_at = 4 + 32 + 2 + 32 + 32 + 32;
    let mut long = m.clone();
    long[key_len_at..key_len_at + 4].copy_from_slice(&0x0010_0000u32.to_be_bytes());
    assert!(matches!(
        DuelMatchV1::decode(&long),
        Err(DecodeError::Cardinality { .. })
    ));
    let mut past = m.clone();
    past[key_len_at..key_len_at + 4].copy_from_slice(&4000u32.to_be_bytes());
    assert!(matches!(
        DuelMatchV1::decode(&past),
        Err(DecodeError::Truncated { .. })
    ));
    let mut empty = m.clone();
    empty[key_len_at..key_len_at + 4].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        DuelMatchV1::decode(&empty),
        Err(DecodeError::Cardinality { .. })
    ));
    // A team of zero or four.
    let team_at = key_len_at + 4 + 32 + 2;
    for n in [0u32, 4] {
        let mut team = m.clone();
        team[team_at..team_at + 4].copy_from_slice(&n.to_be_bytes());
        assert!(matches!(
            DuelMatchV1::decode(&team),
            Err(DecodeError::Cardinality {
                field: "side.team",
                ..
            })
        ));
    }
    // A turn cap other than the table's.
    let mut cap = m.clone();
    cap[4 + 32 + 1] = 61;
    assert!(matches!(
        DuelMatchV1::decode(&cap),
        Err(DecodeError::UnknownValue {
            field: "match.turn_cap",
            ..
        })
    ));
    // A move kind the table does not define.
    assert!(matches!(
        DuelMoveV1::decode(&[0x57, 0x04, 0, 1, 4]),
        Err(DecodeError::UnknownValue { .. })
    ));
    Ok(())
}

#[test]
fn a_match_refuses_a_fainted_or_duplicated_creature() -> R {
    let fainted = DuelMatchV1::new(
        [1; 32],
        60,
        [2; 32],
        side(1, 0, 0, vec![creature(1, 0, 1, Some(0))?]),
        side(2, 0, 0, vec![creature(2, 0, 1, None)?]),
    );
    assert!(matches!(fainted, Err(DecodeError::Invalid { .. })));
    let twice = DuelMatchV1::new(
        [1; 32],
        60,
        [2; 32],
        side(1, 0, 0, vec![creature(5, 0, 1, None)?]),
        side(2, 0, 0, vec![creature(5, 1, 1, None)?]),
    );
    assert!(matches!(twice, Err(DecodeError::Invalid { .. })));
    Ok(())
}

#[test]
fn a_state_with_an_undefined_guard_or_phase_is_refused() -> R {
    let s = DuelState::start(&sample_match()?).encode();
    // The first fighter's guard byte follows its nested creature.
    let creature_at = 4 + 32 + 32 + 2 + 2 + 1 + 4 + 4;
    let guard_at = creature_at + 4 + 32 + 1 + 4 + 2 + 4 + 4;
    assert_eq!(s[guard_at], 0);
    let mut guard = s.clone();
    guard[guard_at] = 2;
    assert!(matches!(
        DuelState::decode(&guard),
        Err(DecodeError::UnknownValue {
            field: "state.fighter.guard",
            ..
        })
    ));
    let mut phase = s.clone();
    phase[4 + 32 + 32 + 2 + 2] = 9;
    assert!(matches!(
        DuelState::decode(&phase),
        Err(DecodeError::UnknownValue {
            field: "state.phase",
            ..
        })
    ));
    Ok(())
}
