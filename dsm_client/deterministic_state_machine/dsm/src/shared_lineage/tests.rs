// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::ccb::decode::DecodeError;

/// A decoder, its result discarded once it decoded.
type Decode = fn(&[u8]) -> Result<(), DecodeError>;

const VAULT_A: D32 = [0xA1; 32];
const VAULT_B: D32 = [0xB1; 32];

fn genesis(id: D32) -> SharedGenesisV1 {
    SharedGenesisV1::new(LineageKind::Vault, id, [0x10; 32], [0x11; 32])
}

/// A chain of `n` generations after the genesis, each root and step derived
/// from its generation number.
fn chain(id: D32, n: u64) -> GenerationChain {
    let mut c = GenerationChain::from_genesis(&genesis(id));
    for g in 1..=n {
        c.push(root(g), vault_step_digest(&[g as u8; 32]))
            .expect("the next generation");
    }
    c
}

fn root(g: u64) -> D32 {
    let mut r = [0x20; 32];
    r[..8].copy_from_slice(&g.to_be_bytes());
    r
}

fn checkpoint_from(c: &GenerationChain, start: u64) -> CheckpointV1 {
    let roots = (start..=start + EPOCH_GENERATIONS)
        .map(|g| c.at(g).expect("an established generation").0)
        .collect();
    CheckpointV1::new(
        LineageKind::Vault,
        VAULT_A,
        start,
        c.at(start).expect("start").1,
        c.at(start + EPOCH_GENERATIONS).expect("end").1,
        roots,
        [0x55; 32],
    )
    .expect("a checkpoint")
}

/// Advance a chain to the head at `generation`.
fn head_at(c: &GenerationChain, generation: u64) -> EstablishedSharedHead {
    let mut prefix = GenerationChain::from_genesis(&genesis(VAULT_A));
    for g in 1..=generation {
        prefix
            .push(root(g), vault_step_digest(&[g as u8; 32]))
            .expect("the next generation");
    }
    assert_eq!(
        prefix.head().generation_digest(),
        &c.at(generation).expect("g").1
    );
    prefix.head()
}

#[test]
fn every_object_round_trips_and_refuses_trailing_bytes() {
    let g = genesis(VAULT_A);
    assert_eq!(SharedGenesisV1::decode(&g.encode()).expect("genesis"), g);

    let gen = SharedGenerationV1::new(LineageKind::Vault, VAULT_A, 3, [1; 32], [2; 32], [3; 32])
        .expect("a generation");
    assert_eq!(
        SharedGenerationV1::decode(&gen.encode()).expect("generation"),
        gen
    );

    let c = chain(VAULT_A, 40);
    let hint =
        GenerationHintV1::of_established(&c, 33, vault_step_digest(&[33; 32])).expect("a hint");
    assert_eq!(
        GenerationHintV1::decode(&hint.encode()).expect("hint"),
        hint
    );

    let cp = checkpoint_from(&c, 0);
    assert_eq!(CheckpointV1::decode(&cp.encode()).expect("checkpoint"), cp);

    let steps = (0..EPOCH_GENERATIONS)
        .map(|i| BundleStep::Vault {
            attempt: i % 2,
            external_commitment: [i as u8; 32],
            trader_genesis: [0x61; 32],
            trader_device_id: [0x62; 32],
            trader_position: 7 + i,
            siblings: vec![([0x71; 32], [0x72; 32])],
        })
        .collect();
    let bundle = TransitionBundleV1::new(LineageKind::Vault, VAULT_A, 0, steps).expect("a bundle");
    assert_eq!(
        TransitionBundleV1::decode(&bundle.encode()).expect("bundle"),
        bundle
    );

    let decoders: [Decode; 5] = [
        |b| SharedGenesisV1::decode(b).map(drop),
        |b| SharedGenerationV1::decode(b).map(drop),
        |b| GenerationHintV1::decode(b).map(drop),
        |b| CheckpointV1::decode(b).map(drop),
        |b| TransitionBundleV1::decode(b).map(drop),
    ];
    let encodings = [
        g.encode(),
        gen.encode(),
        hint.encode(),
        cp.encode(),
        bundle.encode(),
    ];
    for (decode, bytes) in decoders.iter().zip(encodings) {
        let mut longer = bytes.clone();
        longer.push(0);
        decode(&longer).expect_err("trailing bytes are refused");
        decode(&bytes[..bytes.len() - 1]).expect_err("truncated bytes are refused");
    }
}

#[test]
fn no_generation_object_names_the_genesis() {
    assert_eq!(
        SharedGenerationV1::new(LineageKind::Vault, VAULT_A, 0, [1; 32], [2; 32], [3; 32]),
        Err(LineageObjectError::GenerationIsGenesis)
    );
    assert_eq!(
        GenerationHintV1::new(LineageKind::Reserve, VAULT_A, 0, [1; 32], [2; 32], [3; 32]),
        Err(LineageObjectError::GenerationIsGenesis)
    );
}

/// The digest of a generation commits the whole history before it, the
/// lineage and its kind: two chains that differ anywhere differ from there
/// on, and the same steps under another vault, or another kind, are another
/// chain.
#[test]
fn a_generation_digest_binds_its_history_lineage_and_kind() {
    let a = chain(VAULT_A, 10);
    let again = chain(VAULT_A, 10);
    assert_eq!(
        a, again,
        "the chain is a pure function of what was established"
    );

    let mut forked = GenerationChain::from_genesis(&genesis(VAULT_A));
    for g in 1..=10u64 {
        let step = if g == 4 { [0xEE; 32] } else { [g as u8; 32] };
        forked
            .push(root(g), vault_step_digest(&step))
            .expect("next");
    }
    for g in 0..4 {
        assert_eq!(a.at(g), forked.at(g), "generation {g} is before the change");
    }
    for g in 4..=10 {
        assert_ne!(
            a.at(g).expect("a").1,
            forked.at(g).expect("f").1,
            "generation {g}"
        );
    }

    let b = chain(VAULT_B, 10);
    assert_ne!(a.head().generation_digest(), b.head().generation_digest());

    let reserve = SharedGenesisV1::new(LineageKind::Reserve, VAULT_A, [0x10; 32], [0x11; 32]);
    assert_ne!(reserve.digest(), genesis(VAULT_A).digest());
}

#[test]
fn a_checkpoint_must_cover_exactly_one_epoch_and_its_digest_must_recompute() {
    let c = chain(VAULT_A, 64);
    let cp = checkpoint_from(&c, 32);
    let bytes = cp.encode();

    // The digest is the last field; any change to the body breaks it.
    let mut wrong_digest = bytes.clone();
    let last = wrong_digest.len() - 1;
    wrong_digest[last] ^= 1;
    CheckpointV1::decode(&wrong_digest).expect_err("a digest that does not recompute");
    let mut wrong_root = bytes.clone();
    // The first root follows env(4) kind(1) id(32) start(8) end(8) two digests(64) count(4).
    wrong_root[4 + 1 + 32 + 8 + 8 + 64 + 4] ^= 1;
    CheckpointV1::decode(&wrong_root).expect_err("a root the digest does not commit");
    // An end that is not one epoch after the start.
    let mut wrong_end = bytes;
    wrong_end[4 + 1 + 32 + 8 + 7] ^= 1;
    CheckpointV1::decode(&wrong_end).expect_err("an end that is not one epoch on");

    assert_eq!(
        CheckpointV1::new(
            LineageKind::Vault,
            VAULT_A,
            5,
            [1; 32],
            [2; 32],
            vec![[3; 32]; 33],
            [4; 32]
        ),
        Err(LineageObjectError::StartNotOnEpoch { start: 5 })
    );
    assert_eq!(
        CheckpointV1::new(
            LineageKind::Vault,
            VAULT_A,
            0,
            [1; 32],
            [2; 32],
            vec![[3; 32]; 32],
            [4; 32]
        ),
        Err(LineageObjectError::WrongRootCount { got: 32 })
    );
}

/// A checkpoint is read from only at the head a reader established: the same
/// lineage, the head's generation, digest and root. Each mismatch on its own
/// makes it ineligible.
#[test]
fn a_checkpoint_is_eligible_only_at_the_head_the_reader_established() {
    let c = chain(VAULT_A, 64);
    let cp = checkpoint_from(&c, 32);
    let head = head_at(&c, 32);
    assert_eq!(cp.eligible_at(&head), Ok(()));

    let other_vault = chain(VAULT_B, 32).head();
    assert_eq!(
        cp.eligible_at(&other_vault),
        Err(CheckpointIneligible::OtherLineage)
    );

    let earlier = head_at(&c, 31);
    assert!(matches!(
        cp.eligible_at(&earlier),
        Err(CheckpointIneligible::OtherStart {
            start: 32,
            established: 31
        })
    ));

    // The same generation reached through another history.
    let mut forked = GenerationChain::from_genesis(&genesis(VAULT_A));
    for g in 1..=32u64 {
        let step = if g == 9 { [0xEE; 32] } else { [g as u8; 32] };
        forked
            .push(root(g), vault_step_digest(&step))
            .expect("next");
    }
    assert_eq!(
        cp.eligible_at(&forked.head()),
        Err(CheckpointIneligible::StartDigestMismatch)
    );

    // A checkpoint whose first root is not the head's root.
    let mut roots = cp.claimed_roots().to_vec();
    roots[0] = [0x99; 32];
    let lying = CheckpointV1::new(
        LineageKind::Vault,
        VAULT_A,
        32,
        *head.generation_digest(),
        *cp.end_generation_digest(),
        roots,
        [0x55; 32],
    )
    .expect("a checkpoint");
    assert_eq!(
        lying.eligible_at(&head),
        Err(CheckpointIneligible::StartRootMismatch)
    );
}

#[test]
fn a_checkpoint_end_matches_only_the_head_the_walk_reached() {
    let c = chain(VAULT_A, 64);
    let cp = checkpoint_from(&c, 0);
    assert!(cp.end_matches(&head_at(&c, 32)));
    assert!(!cp.end_matches(&head_at(&c, 31)));
    assert!(!cp.end_matches(&chain(VAULT_B, 32).head()));
}

#[test]
fn the_epoch_locator_binds_kind_lineage_and_epoch() {
    let base = epoch_locator(LineageKind::Vault, &VAULT_A, 1);
    assert_ne!(base, epoch_locator(LineageKind::Reserve, &VAULT_A, 1));
    assert_ne!(base, epoch_locator(LineageKind::Vault, &VAULT_B, 1));
    assert_ne!(base, epoch_locator(LineageKind::Vault, &VAULT_A, 2));
    assert_eq!(epoch_of(31), 0);
    assert_eq!(epoch_of(32), 1);
}

#[test]
fn a_bundle_holds_one_step_per_generation_of_its_own_kind() {
    let reserve_steps = |n: u64| {
        (0..n)
            .map(|i| BundleStep::Reserve {
                release_evidence_addr: [i as u8; 32],
            })
            .collect::<Vec<_>>()
    };
    TransitionBundleV1::new(LineageKind::Reserve, VAULT_A, 32, reserve_steps(32))
        .expect("one reserve step per generation");
    assert_eq!(
        TransitionBundleV1::new(LineageKind::Reserve, VAULT_A, 32, reserve_steps(31)),
        Err(LineageObjectError::WrongStepCount { got: 31 })
    );
    assert_eq!(
        TransitionBundleV1::new(LineageKind::Vault, VAULT_A, 32, reserve_steps(32)),
        Err(LineageObjectError::StepKindMismatch)
    );
}

#[test]
fn junk_under_an_epoch_index_is_recognized_as_nothing() {
    for junk in [&b""[..], b"x", &[0x07u8; 64], &[0x00, 0x6E, 0x00, 0x01, 9]] {
        LineageObject::recognize(junk).expect_err("junk is no hint and no checkpoint");
    }
}

/// Discovery carries no authority (DSM Amendment A15): this module names
/// nothing that constructs or records an established vault chain, reserve
/// state, root or memo. A discovered root reaches established state only
/// through the Core walk.
#[test]
fn discovery_code_names_no_constructor_of_established_state() {
    let source = include_str!("mod.rs");
    for forbidden in [
        "VaultChain",
        "from_recorded",
        "record_generation",
        "record_walked",
        "record_final_release",
        "NativeReserveState",
        "ValidatedEconomicRoot",
        "VaultPostState",
    ] {
        assert!(
            !source.contains(forbidden),
            "shared_lineage names {forbidden}"
        );
    }
}
