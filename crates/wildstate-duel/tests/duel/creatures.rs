// SPDX-License-Identifier: MIT OR Apache-2.0

//! A creature's published states: the issuance record, the one chain of
//! successors from it, and the state at its tip.

use crate::support::{creature, R};
use wildstate_duel::creatures::{latest, ChainRefusal, CreatureRecordV1};
use wildstate_duel::CreatureStateV1;

const ANCHOR: [u8; 32] = [7; 32];

/// The record a creature is issued with: its birth state at level 1.
fn born() -> R<CreatureRecordV1> {
    let later = creature(7, 2, 3, None)?;
    Ok(CreatureRecordV1 {
        parent: None,
        state: CreatureStateV1::birth(*later.anchor(), later.species())?,
    })
}

fn record(parent: Option<[u8; 32]>, hp: u16) -> R<CreatureRecordV1> {
    Ok(CreatureRecordV1 {
        parent,
        state: creature(7, 2, 3, Some(hp))?,
    })
}

#[test]
fn a_record_round_trips_and_names_its_parent_by_digest() -> R {
    let issued = record(None, 30)?;
    let next = record(Some(issued.digest()), 20)?;
    for r in [&issued, &next] {
        let bytes = r.encode();
        assert_eq!(&CreatureRecordV1::decode(&bytes)?, r);
        let mut longer = bytes.clone();
        longer.push(0);
        CreatureRecordV1::decode(&longer).expect_err("a trailing byte");
    }
    assert_ne!(issued.digest(), next.digest());
    assert_ne!(issued.digest(), record(None, 29)?.digest());
    Ok(())
}

#[test]
fn the_latest_state_is_the_tip_of_the_chain_from_issuance() -> R {
    let issued = born()?;
    let second = record(Some(issued.digest()), 22)?;
    let third = record(Some(second.digest()), 25)?;
    // Published in any order, one of them twice, with bytes that are no
    // record and a record of another creature beside them.
    let other = CreatureRecordV1 {
        parent: None,
        state: CreatureStateV1::birth([8; 32], 2)?,
    };
    let published = vec![
        third.encode(),
        vec![1, 2, 3],
        issued.encode(),
        other.encode(),
        second.encode(),
        third.encode(),
    ];
    let (state, digest) = latest(&ANCHOR, &published)?;
    assert_eq!(state, third.state);
    assert_eq!(digest, third.digest());
    assert_eq!(latest(&ANCHOR, &[issued.encode()])?.0, issued.state);
    // Without the middle record the chain stops at issuance: a successor
    // whose parent is not published is not reached.
    assert_eq!(
        latest(&ANCHOR, &[issued.encode(), third.encode()])?.0,
        issued.state
    );
    Ok(())
}

#[test]
fn two_histories_of_one_creature_give_no_latest_state() -> R {
    let issued = born()?;
    assert_eq!(latest(&ANCHOR, &[]), Err(ChainRefusal::NoIssuance));
    assert_eq!(
        latest(&ANCHOR, &[record(Some(issued.digest()), 9)?.encode()]),
        Err(ChainRefusal::NoIssuance)
    );
    assert_eq!(
        latest(&ANCHOR, &[issued.encode(), record(None, 29)?.encode()]),
        Err(ChainRefusal::TwoIssuances)
    );
    let fork = [
        issued.encode(),
        record(Some(issued.digest()), 10)?.encode(),
        record(Some(issued.digest()), 11)?.encode(),
    ];
    assert_eq!(
        latest(&ANCHOR, &fork),
        Err(ChainRefusal::Fork {
            parent: issued.digest()
        })
    );
    Ok(())
}

/// A modded state is not the tip: any change to a published state's bytes
/// is another state, which the chain does not end in.
#[test]
fn a_modded_state_is_not_the_latest() -> R {
    let issued = born()?;
    let (tip, _) = latest(&ANCHOR, &[issued.encode()])?;
    let modded = CreatureStateV1::new(
        *tip.anchor(),
        tip.species(),
        tip.xp() + 1,
        tip.hp(),
        tip.charges().to_vec(),
    )?;
    assert_ne!(modded, tip);
    assert_ne!(modded.commitment(), tip.commitment());
    Ok(())
}

/// Whatever its issuer hands over is born at level 1 (owner ruling
/// 2026-10-06): a creature issued at any later state has no latest state,
/// and one issued at birth carries on to whatever level it played to.
#[test]
fn a_creature_is_issued_only_at_its_birth_state() -> R {
    let grown = record(None, 30)?;
    assert_ne!(grown.state, born()?.state, "level 3 is not the birth state");
    assert_eq!(
        latest(&ANCHOR, &[grown.encode()]),
        Err(ChainRefusal::NotBorn)
    );
    let issued = born()?;
    let played = record(Some(issued.digest()), 30)?;
    assert_eq!(
        latest(&ANCHOR, &[issued.encode(), played.encode()])?.0,
        played.state
    );
    let birth = CreatureStateV1::birth(ANCHOR, 2)?;
    assert_eq!(birth.xp(), 0);
    assert_eq!(birth.hp(), wildstate_duel::TABLES.max_hp(0));
    Ok(())
}
