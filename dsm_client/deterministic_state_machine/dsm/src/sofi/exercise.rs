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

use super::arith::{CellResolution, ObjectResolution};
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
    let (_, fulfillment) = recognize_fulfillment(exercise.fulfillment())?;
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

/// `SuccessorResolution(K)` (Section 23.1) as the ladder reads it: the cell's
/// resolution over the recognized view, carrying the `E` of the exercise
/// that won — `Final(E)`, `LeaderHeld(E)`, or `Unresolved` — and the
/// exercise itself when there is one. A cell whose leader holds no exercise
/// naming the key is open; an unread leader establishes nothing; both are
/// `Unresolved`, and no key is ever dead.
pub fn attempt_resolution(
    objects: &ObjectResolution,
    vault_id: &D32,
    parent_root: &D32,
    attempt: u64,
) -> (CellResolution, Option<RecognizedExercise>) {
    let recognized = |bytes: &Vec<u8>| exercise_names_key(bytes, vault_id, parent_root, attempt);
    match objects {
        ObjectResolution::Final(bytes) => match recognized(bytes) {
            Some(x) => (CellResolution::Final(x.external_commitment), Some(x)),
            None => (CellResolution::Unresolved, None),
        },
        ObjectResolution::LeaderHeld(bytes) => match recognized(bytes) {
            Some(x) => (CellResolution::LeaderHeld(x.external_commitment), Some(x)),
            None => (CellResolution::Unresolved, None),
        },
        ObjectResolution::Open | ObjectResolution::Unavailable => {
            (CellResolution::Unresolved, None)
        }
    }
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
    use crate::sofi::wire::AttemptEntry;

    const KEY: [u8; 64] = [0x31; 64];
    const SIG: [u8; 8] = [0x77; 8];

    /// One two-leg operation as an exercise: F over attempts (0, 1), the
    /// canonical witnesses over the shadows P(E) commits, no closure.
    fn exercise(
        f: &Fixture,
        attempts: &[u64],
    ) -> (SofiExercise, TraderPrecommitBody, TraderFulfillmentBody) {
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
        (x, p.clone(), fb)
    }

    #[test]
    fn an_exercise_round_trips_and_rebuilds_into_bound_objects() {
        let f = swap_fixture_n(2);
        let (x, p, fb) = exercise(&f, &[0, 1]);
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
        let (x, p, _) = exercise(&f, &[0, 1]);
        let bytes = x.encode();
        let legs = p.legs();
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
        let (x, p, fb) = exercise(&f, &[0, 1]);
        let other = swap_fixture_n(1);
        let (ox, _, _) = exercise(&other, &[0]);
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
        let _ = (p, fb);
    }

    /// The ladder's read of a successor key: the E of the exercise that won,
    /// final or leader-held; anything that names no exercise for the key —
    /// an open cell, an unread leader, bytes the recognizer refuses — is
    /// unresolved, and no key is dead.
    #[test]
    fn a_successor_key_resolves_to_the_e_of_the_exercise_that_names_it_or_stays_open() {
        let f = swap_fixture_n(2);
        let (x, p, _) = exercise(&f, &[0, 1]);
        let bytes = x.encode();
        let leg = &p.legs()[0];
        let e = *p.external_commitment();
        let (res, got) = attempt_resolution(
            &ObjectResolution::Final(bytes.clone()),
            &leg.vault_id,
            &leg.parent_root,
            0,
        );
        assert_eq!(res, CellResolution::Final(e));
        assert!(got.is_some());
        let (res, _) = attempt_resolution(
            &ObjectResolution::LeaderHeld(bytes.clone()),
            &leg.vault_id,
            &leg.parent_root,
            0,
        );
        assert_eq!(res, CellResolution::LeaderHeld(e));
        for objects in [
            ObjectResolution::Final(b"garbage".to_vec()),
            ObjectResolution::Final(bytes.clone()),
            ObjectResolution::Open,
            ObjectResolution::Unavailable,
        ] {
            // the second one: right bytes, wrong attempt
            let (res, got) = attempt_resolution(&objects, &leg.vault_id, &leg.parent_root, 7);
            assert_eq!(res, CellResolution::Unresolved);
            assert!(got.is_none());
        }
    }
}
