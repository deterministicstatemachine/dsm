// SPDX-License-Identifier: Apache-2.0

//! Section 17.5, rebuild step R11: the exercise, and what counts at a
//! successor key.
//!
//! The value written to each successor key of a route is one canonical
//! object, [`SofiExercise`], carrying the signed envelope of `F`, the signed
//! envelope of `P`, `P(E)`, every `G_j` and every closure object. At the key
//! `K^(a)` of vault `v` at parent `R_n`, the value that counts is the first
//! exercise at the leader whose `F` names `(v, a)` in its attempts and whose
//! `P` names `(v, R_n)` in its legs — everything else at the key counts as
//! nothing (P1, OnlyExercisesCount). An exercise cannot exist unless the
//! trader exercised, because it carries `F`, which only the trader can sign;
//! everything else in it is bound to `F` by hashed preimages; and it names
//! its own attempt, so it cannot count at another key.
//!
//! Recognition establishes that the bytes ARE an exercise naming the key. It
//! is not validation: whether the route it carries realizes is the ladder's
//! question (rebuild step R12), answered from the same bytes.

use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellReading,
    CompletionProof, Missing, ProofRefusal, RoutedCell,
};
use super::derive;
use super::publication::{
    recognize_policy_fulfillment, recognize_precommit, recognize_fulfillment, Signed,
};
use super::wire::{
    DlvPolicyFulfillmentBody, SettlementPreimage, SofiExercise, TraderFulfillmentBody,
    TraderPrecommitBody,
};

type D32 = [u8; 32];

/// An exercise whose bytes rebuilt into the objects it carries, bound to one
/// another: `F` is `P`'s, `P(E)` recomputes `P`'s `E`, the witnesses are the
/// set `F` commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecognizedExercise {
    pub fulfillment: Signed<TraderFulfillmentBody>,
    pub precommit: Signed<TraderPrecommitBody>,
    pub preimage: SettlementPreimage,
    pub witnesses: Vec<DlvPolicyFulfillmentBody>,
    pub closure: Vec<Vec<u8>>,
    /// `E`, as `P` commits it and `P(E)` recomputes it.
    pub external_commitment: D32,
}

/// Rebuild the objects an exercise carries and check their binding to one
/// another. `None` for bytes that are not one exercise of one operation.
pub fn recognize_exercise(bytes: &[u8]) -> Option<RecognizedExercise> {
    let exercise = SofiExercise::decode(bytes).ok()?;
    let fulfillment = recognize_fulfillment(exercise.fulfillment())?.1;
    let (pid, precommit) = recognize_precommit(exercise.precommit())?;
    if *fulfillment.body.precommit_id() != pid {
        return None;
    }
    let preimage = SettlementPreimage::decode(exercise.preimage()).ok()?;
    let e = derive::recompute_e(&preimage).ok()?;
    if e != *precommit.body.external_commitment() {
        return None;
    }
    // The witnesses are P's own, one per leg in leg order, and together they
    // are exactly the set F commits.
    if exercise.witnesses().len() != precommit.body.legs().len() {
        return None;
    }
    let mut witnesses = Vec::with_capacity(exercise.witnesses().len());
    let mut ids = Vec::with_capacity(exercise.witnesses().len());
    for (leg, w) in precommit.body.legs().iter().zip(exercise.witnesses()) {
        let (id, body) = recognize_policy_fulfillment(w)?;
        if body.precommit_id != pid
            || body.external_commitment != e
            || body.vault_id != leg.vault_id
            || body.parent_root != leg.parent_root
        {
            return None;
        }
        ids.push(id);
        witnesses.push(body);
    }
    ids.sort();
    if fulfillment.body.policy_fulfillment_set() != ids.as_slice() {
        return None;
    }
    if exercise.closure().len() != preimage.settlement().closure().refs().len() {
        return None;
    }
    Some(RecognizedExercise {
        fulfillment,
        precommit,
        preimage,
        witnesses,
        closure: exercise.closure().to_vec(),
        external_commitment: e,
    })
}

/// An object naming the successor key `K^(attempt)` of `vault_id` at
/// `parent_root`: an exercise whose `F` names `(vault_id, attempt)` and
/// whose `P` names `(vault_id, parent_root)`. Anything else at the key is
/// nothing — neither a rival nor a winner, however early it arrived.
pub fn exercise_names_key(
    bytes: &[u8],
    vault_id: &D32,
    parent_root: &D32,
    attempt: u64,
) -> Option<RecognizedExercise> {
    let recognized = recognize_exercise(bytes)?;
    let names_attempt = recognized
        .fulfillment
        .body
        .attempts()
        .iter()
        .any(|a| a.vault_id == *vault_id && a.attempt == attempt);
    let names_parent = recognized
        .precommit
        .body
        .legs()
        .iter()
        .any(|l| l.vault_id == *vault_id && l.parent_root == *parent_root);
    (names_attempt && names_parent).then_some(recognized)
}

/// The successor key `K^(attempt)` of `vault_id` at `parent_root` as Core
/// derives it (Sections 7.2, 17.5): the key, and the route seeded by
/// `storage_seed(v, R_n)` over the set the vault state commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptCell {
    vault_id: D32,
    parent_root: D32,
    attempt: u64,
    cell: RoutedCell,
}

impl AttemptCell {
    /// `members` must re-derive `committed_set_id`, the `storage_set_id` of
    /// the vault state at `parent_root`, which the caller validated.
    pub fn new(
        vault_id: &D32,
        parent_root: &D32,
        attempt: u64,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let cell = RoutedCell::new(
            crate::common::domain_tags::TAG_DSM_SOFI_SUCC_CELL_V2.source_bytes(),
            derive::successor_attempt_key(vault_id, parent_root, attempt),
            &derive::storage_seed(vault_id, parent_root),
            members,
            committed_set_id,
        )?;
        Ok(Self {
            vault_id: *vault_id,
            parent_root: *parent_root,
            attempt,
            cell,
        })
    }

    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }

    pub fn parent_root(&self) -> &D32 {
        &self.parent_root
    }

    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    pub fn routed(&self) -> &RoutedCell {
        &self.cell
    }
}

/// `SuccessorResolution(K)` (Section 23.1) as the ladder reads it: the
/// route-chain reading of an attempt cell over exercises naming its key.
/// What holds the cell is the recognized exercise, identified by its `E`. A
/// cell whose leader holds no exercise naming the key is `Open`; evidence
/// that does not yet decide the cell is [`Missing`], a network status and
/// never an answer. No key is ever dead.
pub fn attempt_resolution(
    cell: &AttemptCell,
    evidence: &CellEvidence,
) -> Result<CellReading<RecognizedExercise>, Missing> {
    evaluate(&cell.cell, evidence, exercise_at(cell))
}

/// The recognizer of an attempt cell: exercises naming its key, identified
/// by their `E`.
fn exercise_at(cell: &AttemptCell) -> impl Fn(&[u8]) -> Option<(D32, RecognizedExercise)> + '_ {
    move |bytes| {
        exercise_names_key(bytes, &cell.vault_id, &cell.parent_root, cell.attempt)
            .map(|x| (x.external_commitment, x))
    }
}

/// The completion proof of the exercise final at an attempt cell (storage
/// spec §9; SoFi Amendment S10), with the exercise; `None` while no chain of
/// the exercise holding the cell has three links.
pub fn attempt_completion(
    cell: &AttemptCell,
    evidence: &CellEvidence,
) -> Result<Option<(RecognizedExercise, CompletionProof)>, Missing> {
    completion_proof(&cell.cell, evidence, exercise_at(cell))
}

/// Check a kept completion proof of an attempt cell against the reads in
/// `evidence`: the exercise it proves final.
pub fn check_attempt_completion(
    cell: &AttemptCell,
    evidence: &CellEvidence,
    proof: &CompletionProof,
) -> Result<RecognizedExercise, ProofRefusal> {
    check_completion_proof(&cell.cell, evidence, proof, exercise_at(cell))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::sofi::conformance::derive_policy_fulfillments;
    use crate::sofi::derive::precommit_id;
    use crate::sofi::publication::Publication;
    use crate::sofi::validation::fixtures::{swap_fixture_n, Fixture};
    use crate::route_chain::fixtures::{committed_set, committed_set_id, Cell};
    use crate::route_chain::{CellFact, ChainState, ROUTE_LEN};
    use crate::sofi::wire::AttemptEntry;

    const KEY: [u8; 64] = [0x31; 64];
    const SIG: [u8; 8] = [0x77; 8];

    /// An exercise with the precommit and fulfillment body it carries.
    struct Built {
        exercise: SofiExercise,
        precommit: TraderPrecommitBody,
        fulfillment: TraderFulfillmentBody,
    }

    /// One operation as an exercise: F over `attempts`, the canonical
    /// witnesses over the shadows P(E) commits, no closure.
    fn exercise(f: &Fixture, attempts: &[u64]) -> Built {
        let p = &f.precommit;
        let canonical = derive::canonical_legs(&f.preimage).unwrap();
        let shadows: Vec<D32> = p
            .legs()
            .iter()
            .map(|leg| {
                canonical
                    .iter()
                    .find(|l| l.vault_id == leg.vault_id)
                    .unwrap()
                    .shadow_core
            })
            .collect();
        let witnesses = derive_policy_fulfillments(p, &shadows).unwrap();
        let mut set: Vec<D32> = witnesses
            .iter()
            .map(derive::policy_fulfillment_id)
            .collect();
        set.sort();
        let fb = TraderFulfillmentBody::new(
            precommit_id(p),
            set,
            p.legs()
                .iter()
                .zip(attempts)
                .map(|(l, a)| AttemptEntry {
                    vault_id: l.vault_id,
                    attempt: *a,
                })
                .collect(),
            p.position() + 1,
            ALG,
            &KEY,
        )
        .unwrap();
        let x = SofiExercise::new(
            Publication::Fulfillment {
                body: &fb,
                signature: &SIG,
            }
            .object_bytes()
            .unwrap(),
            Publication::Precommit {
                body: p,
                signature: &SIG,
            }
            .object_bytes()
            .unwrap(),
            f.preimage.encode().unwrap(),
            witnesses
                .iter()
                .map(DlvPolicyFulfillmentBody::encode)
                .collect(),
            Vec::new(),
        )
        .unwrap();
        Built {
            exercise: x,
            precommit: p.clone(),
            fulfillment: fb,
        }
    }

    #[test]
    fn an_exercise_round_trips_and_rebuilds_into_bound_objects() {
        let f = swap_fixture_n(2);
        let Built {
            exercise: x,
            precommit: p,
            fulfillment: fb,
        } = exercise(&f, &[0, 1]);
        let bytes = x.encode();
        assert_eq!(SofiExercise::decode(&bytes).unwrap(), x);
        let r = recognize_exercise(&bytes).unwrap();
        assert_eq!(r.fulfillment.body, fb);
        assert_eq!(r.precommit.body, p);
        assert_eq!(r.preimage, f.preimage);
        assert_eq!(r.external_commitment, *p.external_commitment());
        assert_eq!(r.witnesses.len(), 2);
    }

    /// P1: an exercise names exactly the keys its F and P name. The same
    /// bytes count at `(v_0, R_0, 0)` and `(v_1, R_1, 1)` and nowhere else —
    /// not at another attempt of the same vault, not at another parent, not
    /// at a vault the route does not touch.
    #[test]
    fn an_exercise_names_exactly_the_keys_its_fulfillment_and_precommit_name() {
        let f = swap_fixture_n(2);
        let built = exercise(&f, &[0, 1]);
        let bytes = built.exercise.encode();
        let legs = built.precommit.legs();
        assert!(exercise_names_key(&bytes, &legs[0].vault_id, &legs[0].parent_root, 0).is_some());
        assert!(exercise_names_key(&bytes, &legs[1].vault_id, &legs[1].parent_root, 1).is_some());
        assert!(exercise_names_key(&bytes, &legs[0].vault_id, &legs[0].parent_root, 1).is_none());
        assert!(exercise_names_key(&bytes, &legs[1].vault_id, &legs[1].parent_root, 0).is_none());
        assert!(exercise_names_key(&bytes, &legs[0].vault_id, &[0x99; 32], 0).is_none());
        assert!(exercise_names_key(&bytes, &[0x98; 32], &legs[0].parent_root, 0).is_none());
        assert!(exercise_names_key(
            b"not an exercise",
            &legs[0].vault_id,
            &legs[0].parent_root,
            0
        )
        .is_none());
    }

    /// The objects inside are bound to one another by hashed preimages: an
    /// F of another P, a preimage that is not P(E), a witness set that is not
    /// the one F commits — none of these is an exercise.
    #[test]
    fn an_exercise_whose_parts_are_not_one_operations_is_nothing() {
        let f = swap_fixture_n(2);
        let x = exercise(&f, &[0, 1]).exercise;
        let other = swap_fixture_n(1);
        let ox = exercise(&other, &[0]).exercise;
        // F of another P.
        let bent = SofiExercise::new(
            ox.fulfillment().to_vec(),
            x.precommit().to_vec(),
            x.preimage().to_vec(),
            x.witnesses().to_vec(),
            Vec::new(),
        )
        .unwrap();
        assert!(recognize_exercise(&bent.encode()).is_none());
        // A preimage that is not this P's.
        let bent = SofiExercise::new(
            x.fulfillment().to_vec(),
            x.precommit().to_vec(),
            other.preimage.encode().unwrap(),
            x.witnesses().to_vec(),
            Vec::new(),
        )
        .unwrap();
        assert!(recognize_exercise(&bent.encode()).is_none());
        // One witness swapped for another leg's: its leg binding is wrong.
        let mut ws = x.witnesses().to_vec();
        ws.swap(0, 1);
        let bent = SofiExercise::new(
            x.fulfillment().to_vec(),
            x.precommit().to_vec(),
            x.preimage().to_vec(),
            ws,
            Vec::new(),
        )
        .unwrap();
        assert!(recognize_exercise(&bent.encode()).is_none());
        // A witness bound to the right leg, P and E but claiming another
        // shadow: only the set F commits — the ids — catches it, because the
        // shadow is not in the leg binding. Mutation: drop the set check.
        let mut wrong_shadow = DlvPolicyFulfillmentBody::decode(&x.witnesses()[0]).unwrap();
        wrong_shadow.shadow_core = [0xEE; 32];
        let mut ws = x.witnesses().to_vec();
        ws[0] = wrong_shadow.encode();
        let bent = SofiExercise::new(
            x.fulfillment().to_vec(),
            x.precommit().to_vec(),
            x.preimage().to_vec(),
            ws,
            Vec::new(),
        )
        .unwrap();
        assert!(recognize_exercise(&bent.encode()).is_none());
    }

    /// An exercise final at its attempt cell has a completion proof built
    /// from the reads, and the proof checks against them.
    #[test]
    fn a_final_exercise_has_a_completion_proof_that_checks() {
        let f = swap_fixture_n(2);
        let built = exercise(&f, &[0, 1]);
        let bytes = built.exercise.encode();
        let leg = &built.precommit.legs()[0];
        let at = AttemptCell::new(
            &leg.vault_id,
            &leg.parent_root,
            0,
            &committed_set(),
            &committed_set_id(),
        )
        .expect("the committed set");
        let mut seats = Cell::at(at.routed());
        seats.write(&bytes, 1, &[]);
        assert!(matches!(
            attempt_completion(&at, &seats.evidence()),
            Ok(None)
        ));
        let mut seats = Cell::at(at.routed());
        seats.write(&bytes, ROUTE_LEN - 1, &[]);
        let Ok(Some((proven, proof))) = attempt_completion(&at, &seats.evidence()) else {
            panic!("a final exercise has a completion proof")
        };
        assert_eq!(
            proven.external_commitment,
            *built.precommit.external_commitment()
        );
        let checked = check_attempt_completion(&at, &seats.evidence(), &proof)
            .expect("the kept proof checks");
        assert_eq!(checked.fulfillment.body, built.fulfillment);
    }

    /// The ladder's read of a successor key: the exercise that holds it,
    /// identified by its E, final or leader-held; a cell whose leader holds
    /// no exercise naming the key is open; an unread leader decides nothing.
    #[test]
    fn a_successor_key_resolves_to_the_e_of_the_exercise_that_names_it_or_stays_open() {
        let f = swap_fixture_n(2);
        let built = exercise(&f, &[0, 1]);
        let bytes = built.exercise.encode();
        let leg = &built.precommit.legs()[0];
        let e = *built.precommit.external_commitment();
        let at = |attempt: u64| {
            AttemptCell::new(
                &leg.vault_id,
                &leg.parent_root,
                attempt,
                &committed_set(),
                &committed_set_id(),
            )
            .expect("the committed set")
        };
        let read = |seats: &Cell, attempt: u64| attempt_resolution(&at(attempt), &seats.evidence());
        let fact = |reading: &Result<CellReading<RecognizedExercise>, Missing>| match reading {
            Ok(held) => Ok(held.fact()),
            Err(missing) => Err(*missing),
        };
        for (last, state) in [
            (0, ChainState::LeaderHeld),
            (ROUTE_LEN - 1, ChainState::Final),
        ] {
            let mut cell = Cell::at(at(0).routed());
            cell.write(&bytes, last, &[]);
            let reading = read(&cell, 0);
            assert_eq!(fact(&reading), Ok(CellFact::Held { id: e, state }));
            let Ok(CellReading::Held { object, .. }) = reading else {
                panic!("the exercise holds the key")
            };
            assert_eq!(object.fulfillment.body, built.fulfillment);
        }
        let mut garbage = Cell::at(at(0).routed());
        garbage.write(b"garbage", ROUTE_LEN - 1, &[]);
        assert_eq!(fact(&read(&garbage, 0)), Ok(CellFact::Open));
        let mut other_attempt = Cell::at(at(7).routed());
        other_attempt.write(&bytes, ROUTE_LEN - 1, &[]);
        assert_eq!(
            fact(&read(&other_attempt, 7)),
            Ok(CellFact::Open),
            "the right bytes at another attempt's key name nothing there"
        );
        let mut written = Cell::at(at(0).routed());
        written.write(&bytes, ROUTE_LEN - 1, &[]);
        let mut unread = written.evidence();
        unread.seats[0].values = None;
        assert_eq!(
            fact(&attempt_resolution(&at(0), &unread)),
            Err(Missing::LeaderUnread)
        );
    }

    /// The leader of an attempt cell is the first member of the Fisher-Yates
    /// shuffle of the committed set under the vault's storage seed — nothing
    /// else enters (Part II §7.2).
    #[test]
    fn an_attempt_cells_leader_is_the_first_member_of_the_seeded_shuffle_over_s() {
        let (v, r) = ([0xA1; 32], [0xB2; 32]);
        let ids: Vec<Vec<u8>> = committed_set()
            .entries()
            .iter()
            .map(|e| e.member_id().to_vec())
            .collect();
        let expected = crate::sofi::fisher_yates::first_member(&derive::storage_seed(&v, &r), &ids)
            .expect("shuffle");
        for attempt in [0, 1, 7] {
            let cell = AttemptCell::new(&v, &r, attempt, &committed_set(), &committed_set_id())
                .expect("cell");
            assert_eq!(cell.routed().route().leader(), expected.as_slice());
        }
    }

    /// The seed consumes the vault and the parent root, so a writer cannot
    /// choose its leader: change either and the leader moves for some value.
    #[test]
    fn an_attempt_cells_leader_is_bound_to_the_vault_and_the_parent_root() {
        let leader = |v: [u8; 32], r: [u8; 32]| {
            AttemptCell::new(&v, &r, 0, &committed_set(), &committed_set_id())
                .expect("cell")
                .routed()
                .route()
                .leader()
                .to_vec()
        };
        let base = leader([0xA1; 32], [0xB2; 32]);
        assert!((0u8..32).any(|b| leader([0xA1; 32], [b; 32]) != base));
        assert!((0u8..32).any(|b| leader([b; 32], [0xB2; 32]) != base));
    }
}
