// SPDX-License-Identifier: Apache-2.0

//! Section 17.5 and stage 8 of §31, rebuild step R11: the exercise, written
//! to every successor key of a route and read back as the ladder reads it.
//!
//! After `F` registers, any party MAY write the exercise (P2): the object
//! carries `F`, which only the trader could sign, and everything else in it
//! is bound to `F` by hashed preimages, so a relayer adds nothing and can
//! forge nothing. Each leg's cell is `K^(a_j)` of vault `v_j` at parent
//! `R_j`, written leader-first under the vault's storage seed (Part II §8);
//! the member stores bytes and decides nothing. What counts at a key is
//! Core's (`sofi::exercise::exercise_names_key`): the first exercise at the
//! leader whose `F` names `(v, a)` and whose `P` names `(v, R_n)`.

use dsm::common::domain_tags::TAG_DSM_SOFI_SUCC_CELL_V2;
use dsm::sofi::arith::{resolve_objects, CellResolution};
use dsm::sofi::conformance::{derive_policy_fulfillments, ConformanceEvidence};
use dsm::sofi::derive;
use dsm::sofi::exercise::{attempt_resolution, exercise_names_key, RecognizedExercise};
use dsm::sofi::publication::Publication;
use dsm::sofi::wire::{DlvPolicyFulfillmentBody, SofiExercise};
use dsm::types::error::DsmError;

use crate::sdk::sofi_register::InstallRequest;
use crate::sdk::storage_io::{read_cell_raw, successor_cell_leader_index, write_cell_leader_first};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

fn err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::verification(format!("{what}: {e}"))
}

/// The exercise of a request, over the evidence its conformance was decided
/// on: `F` and `P` in their envelopes, `P(E)`, the canonical witnesses
/// derived from `P` and the shadows `P(E)` commits, and every closure object
/// in reference order. A closure object the evidence does not hold is an
/// error here — the exercise carries the closure, so it cannot be built
/// without it.
pub fn build_exercise(
    request: &InstallRequest<'_>,
    evidence: &ConformanceEvidence,
) -> Result<SofiExercise, DsmError> {
    let canonical =
        derive::canonical_legs(request.preimage).map_err(|e| err("canonical legs", e))?;
    let shadows: Vec<D32> = request
        .precommit
        .legs()
        .iter()
        .map(|leg| {
            canonical
                .iter()
                .find(|l| l.vault_id == leg.vault_id)
                .map(|l| l.shadow_core)
                .ok_or_else(|| err("witnesses", "a leg P(E) does not derive"))
        })
        .collect::<Result<_, _>>()?;
    let witnesses: Vec<Vec<u8>> = derive_policy_fulfillments(request.precommit, &shadows)
        .map_err(|e| err("witnesses", format!("{e:?}")))?
        .iter()
        .map(DlvPolicyFulfillmentBody::encode)
        .collect();
    let mut closure = Vec::new();
    for reference in request.preimage.settlement().closure().refs() {
        let bytes = evidence
            .closure
            .get(reference)
            .ok_or_else(|| err("closure", format!("object not acquired for {reference:?}")))?;
        closure.push(bytes.clone());
    }
    SofiExercise::new(
        Publication::Fulfillment {
            body: request.fulfillment,
            signature: request.fulfillment_signature,
        }
        .object_bytes()
        .map_err(|e| err("fulfillment envelope", e))?,
        Publication::Precommit {
            body: request.precommit,
            signature: request.precommit_signature,
        }
        .object_bytes()
        .map_err(|e| err("precommit envelope", e))?,
        request.preimage.encode().map_err(|e| err("preimage", e))?,
        witnesses,
        closure,
    )
    .map_err(|e| err("exercise", e))
}

/// One leg's cell write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegWrite {
    pub vault_id: D32,
    pub parent_root: D32,
    pub attempt: u64,
    pub key: D32,
    pub leader_reached: bool,
    pub copies: u32,
}

/// Write `exercise` to every successor key its `F` names — `K^(a_j)` of
/// `v_j` at the parent `R_j` its `P` names — the leader of each vault's
/// storage seed first, the other members after. Nothing is checked at the
/// member; the bytes are the same everywhere.
pub async fn write_exercise(
    set: &StorageSet,
    exercise: &SofiExercise,
    recognized: &RecognizedExercise,
) -> Result<Vec<LegWrite>, DsmError> {
    let bytes = exercise.encode();
    let mut writes = Vec::new();
    for attempt in recognized.fulfillment.body.attempts() {
        let leg = recognized
            .precommit
            .body
            .legs()
            .iter()
            .find(|l| l.vault_id == attempt.vault_id)
            .ok_or_else(|| err("exercise", "an attempt names a vault P has no leg for"))?;
        let key = derive::successor_attempt_key(&leg.vault_id, &leg.parent_root, attempt.attempt);
        let seed = derive::storage_seed(&leg.vault_id, &leg.parent_root);
        let write = write_cell_leader_first(
            set,
            TAG_DSM_SOFI_SUCC_CELL_V2.source_bytes(),
            &key,
            &seed,
            &bytes,
        )
        .await?;
        writes.push(LegWrite {
            vault_id: leg.vault_id,
            parent_root: leg.parent_root,
            attempt: attempt.attempt,
            key,
            leader_reached: write.leader_reached,
            copies: write.copies,
        });
    }
    Ok(writes)
}

/// `SuccessorResolution(K^(attempt))` of `vault_id` at `parent_root`, as the
/// ladder reads it (Section 23.1): raw reads of the cell, the leader from the
/// vault's storage seed over the committed set, the recognized view
/// (`exercise_names_key`), then the `E` of the exercise that won, final or
/// leader-held, with the exercise itself. `Unresolved` for an open cell or an
/// unread leader; no key is ever dead.
pub async fn read_attempt_cell(
    set: &StorageSet,
    vault_id: &D32,
    parent_root: &D32,
    attempt: u64,
) -> Result<(CellResolution, Option<RecognizedExercise>), DsmError> {
    let key = derive::successor_attempt_key(vault_id, parent_root, attempt);
    let leader = successor_cell_leader_index(set, vault_id, parent_root)?;
    let reads = read_cell_raw(set, TAG_DSM_SOFI_SUCC_CELL_V2.source_bytes(), &key).await?;
    let objects = resolve_objects(&reads, leader, |bytes| {
        exercise_names_key(bytes, vault_id, parent_root, attempt).is_some()
    })
    .map_err(|e| err("cell read", e))?;
    Ok(attempt_resolution(&objects, vault_id, parent_root, attempt))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use dsm::sofi::exercise::recognize_exercise;
    use serial_test::serial;

    use super::*;
    use crate::sdk::sofi_register::{acquire_conformance_evidence, install_fulfillment};
    use crate::sdk::sofi_test_fixtures::{block_on, install_request, signed_route, SignedRoute};
    use crate::sdk::storage_io::fake_registers;

    fn succ_ns() -> &'static [u8] {
        TAG_DSM_SOFI_SUCC_CELL_V2.source_bytes()
    }

    /// The installed route's exercise, built over the evidence its
    /// conformance was decided on.
    fn exercise_of(r: &SignedRoute) -> (SofiExercise, RecognizedExercise) {
        let req = install_request(r);
        let ev = block_on(acquire_conformance_evidence(&r.set, &req)).unwrap();
        let x = build_exercise(&req, &ev).unwrap();
        let recognized = recognize_exercise(&x.encode()).unwrap();
        (x, recognized)
    }

    fn members(set: &StorageSet) -> Vec<String> {
        set.members().iter().map(|m| m.member_id.clone()).collect()
    }

    /// Stage 8 of §31: after registration, the exercise lands at every leg's
    /// successor key, the leader of that vault's storage seed first and every
    /// other member after, and each cell reads back final on the route's
    /// one `E` with the exercise inside.
    #[test]
    #[serial]
    fn an_exercise_is_written_to_every_successor_key_at_its_leader() {
        let r = signed_route(true);
        block_on(install_fulfillment(&r.set, &install_request(&r))).unwrap();
        let (x, recognized) = exercise_of(&r);
        let writes = block_on(write_exercise(&r.set, &x, &recognized)).unwrap();
        assert_eq!(writes.len(), 2, "one cell per leg");
        let bytes = x.encode();
        for w in &writes {
            assert!(w.leader_reached);
            assert_eq!(w.copies, 4);
            assert_eq!(
                w.key,
                derive::successor_attempt_key(&w.vault_id, &w.parent_root, w.attempt)
            );
            assert_eq!(
                fake_registers::holders(&r.set, succ_ns(), &w.key, &bytes),
                members(&r.set)
            );
            let (res, got) = block_on(read_attempt_cell(
                &r.set,
                &w.vault_id,
                &w.parent_root,
                w.attempt,
            ))
            .unwrap();
            assert_eq!(
                res,
                CellResolution::Final(*r.precommit.external_commitment())
            );
            assert_eq!(
                got.as_ref().map(|g| &g.fulfillment.body),
                Some(&r.fulfillment)
            );
        }
    }

    /// P1, OnlyExercisesCount: bytes that are not an exercise naming the key
    /// — garbage, and an exercise whose F names another attempt of this
    /// vault — count as nothing, however early they reached the leader. The
    /// route's own exercise is the first RECOGNIZED object and is final.
    #[test]
    #[serial]
    fn only_an_exercise_naming_the_key_counts() {
        let r = signed_route(true);
        block_on(install_fulfillment(&r.set, &install_request(&r))).unwrap();
        let (x, recognized) = exercise_of(&r);
        let leg = &recognized.precommit.body.legs()[0];
        let key = derive::successor_attempt_key(&leg.vault_id, &leg.parent_root, 0);
        let leader = successor_cell_leader_index(&r.set, &leg.vault_id, &leg.parent_root).unwrap();
        fake_registers::put_cell(&r.set, leader, succ_ns(), &key, b"not an exercise");
        // An exercise of the same route whose F names attempt 1 of this vault:
        // it is an exercise, and it names another key.
        let other = other_attempt(&r, 1);
        fake_registers::put_cell(&r.set, leader, succ_ns(), &key, &other.encode());
        let (res, _) = block_on(read_attempt_cell(
            &r.set,
            &leg.vault_id,
            &leg.parent_root,
            0,
        ))
        .unwrap();
        assert_eq!(
            res,
            CellResolution::Unresolved,
            "nothing naming the key has arrived"
        );
        block_on(write_exercise(&r.set, &x, &recognized)).unwrap();
        let (res, got) = block_on(read_attempt_cell(
            &r.set,
            &leg.vault_id,
            &leg.parent_root,
            0,
        ))
        .unwrap();
        assert_eq!(
            res,
            CellResolution::Final(*r.precommit.external_commitment())
        );
        assert_eq!(got.map(|g| g.fulfillment.body), Some(r.fulfillment.clone()));
    }

    /// An exercise cannot count at a key it does not name: written at
    /// `K^(1)` of a leg whose attempt it names as 0, it is nothing there.
    #[test]
    #[serial]
    fn an_exercise_cannot_count_at_another_key() {
        let r = signed_route(true);
        block_on(install_fulfillment(&r.set, &install_request(&r))).unwrap();
        let (x, recognized) = exercise_of(&r);
        let leg = &recognized.precommit.body.legs()[0];
        let elsewhere = derive::successor_attempt_key(&leg.vault_id, &leg.parent_root, 1);
        let leader = successor_cell_leader_index(&r.set, &leg.vault_id, &leg.parent_root).unwrap();
        fake_registers::put_cell(&r.set, leader, succ_ns(), &elsewhere, &x.encode());
        assert_eq!(
            fake_registers::holders(&r.set, succ_ns(), &elsewhere, &x.encode()).len(),
            5,
            "the member keeps what it is given"
        );
        let (res, got) = block_on(read_attempt_cell(
            &r.set,
            &leg.vault_id,
            &leg.parent_root,
            1,
        ))
        .unwrap();
        assert_eq!(res, CellResolution::Unresolved);
        assert!(got.is_none());
    }

    /// The same route, exercised with every leg at `attempt`: another
    /// fulfillment of the same P, signed by the trader.
    fn other_attempt(r: &SignedRoute, attempt: u64) -> SofiExercise {
        use crate::sdk::sofi_test_fixtures::trader_sign;
        use dsm::sofi::wire::{AttemptEntry, TraderFulfillmentBody};
        let f = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment
                .attempts()
                .iter()
                .map(|a| AttemptEntry {
                    vault_id: a.vault_id,
                    attempt,
                })
                .collect(),
            r.fulfillment.position(),
            r.fulfillment.signature_alg(),
            r.fulfillment.claimant_public_key(),
        )
        .unwrap();
        let sig = trader_sign(&derive::fulfillment_signing_digest(&f));
        let req = InstallRequest {
            precommit: &r.precommit,
            precommit_signature: &r.p_sig,
            preimage: &r.preimage,
            fulfillment: &f,
            fulfillment_signature: &sig,
            own_objects: &r.own,
        };
        let ev = block_on(acquire_conformance_evidence(&r.set, &req)).unwrap();
        build_exercise(&req, &ev).unwrap()
    }
}
