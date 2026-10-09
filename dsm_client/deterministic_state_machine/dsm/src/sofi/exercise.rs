// SPDX-License-Identifier: Apache-2.0

//! Section 17.5, rebuild step R11: the exercise, and what counts at a
//! successor key.
//!
//! The value written to each successor key of a route is one canonical
//! object, [`SofiExercise`], carrying the signed envelope of `F`, the
//! trader's signed `C_q`, the signed envelope of `P`, `P(E)`, every `G_j` and
//! every closure object. At the key
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

use crate::economic::claim_envelope::RegisteredEconomicClaim;
use crate::economic::register::{economic_root_register_key, root_claim_naming};
use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellFact,
    CellReading, CompletionProof, Missing, ProofRefusal, RoutedCell,
};
use super::conformance::closure_object_verifies;
use super::derive;
use super::publication::{
    recognize_fulfillment, recognize_policy_fulfillment, recognize_precommit, Publication, Signed,
};
use super::registration::fulfillment_proves_the_device;
use super::wire::{
    DlvPolicyFulfillmentBody, SettlementPreimage, SofiExercise, TraderFulfillmentBody,
    TraderPrecommitBody, ValidationRef,
};

type D32 = [u8; 32];

/// An exercise whose bytes rebuilt into the objects it carries, bound to one
/// another: `F` is `P`'s and proves `P`'s device, the signed `C_q` is the
/// claim of this `P` and `F` and proves its own authority, `P(E)` recomputes
/// `P`'s `E`, the witnesses are the set `F` commits, and the closure carries
/// one object per reference in `𝒞_E^pre`. [`recognize_exercise`] is its only
/// constructor and the fields are read-only, so every one of these bindings
/// holds for every value of the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecognizedExercise {
    fulfillment: Signed<TraderFulfillmentBody>,
    resolution_claim: Vec<u8>,
    precommit: Signed<TraderPrecommitBody>,
    preimage: SettlementPreimage,
    witnesses: Vec<DlvPolicyFulfillmentBody>,
    closure: Vec<Vec<u8>>,
    external_commitment: D32,
}

impl RecognizedExercise {
    /// `F`, signed.
    pub fn fulfillment(&self) -> &Signed<TraderFulfillmentBody> {
        &self.fulfillment
    }

    /// The trader's signed `C_q`, exactly as the trader signed it: what a
    /// relayer writes at `K_root(q)`, since only the trader can sign it (SoFi
    /// Amendment S20). Its body is `derive::resolution_claim(P, F)`.
    pub fn resolution_claim(&self) -> &[u8] {
        &self.resolution_claim
    }

    /// `P`, signed.
    pub fn precommit(&self) -> &Signed<TraderPrecommitBody> {
        &self.precommit
    }

    /// `P(E)`.
    pub fn preimage(&self) -> &SettlementPreimage {
        &self.preimage
    }

    /// The policy-fulfillment witnesses `F` commits.
    pub fn witnesses(&self) -> &[DlvPolicyFulfillmentBody] {
        &self.witnesses
    }

    /// The closure objects as carried, in reference order.
    pub fn closure(&self) -> &[Vec<u8>] {
        &self.closure
    }

    /// `E`, as `P` commits it and `P(E)` recomputes it.
    pub fn external_commitment(&self) -> &D32 {
        &self.external_commitment
    }

    /// The closure objects this exercise carries, each under the reference
    /// in `𝒞_E^pre` it answers: the exercise carries them in reference order
    /// (Section 17.5), and recognition requires one per reference. Nothing is
    /// trusted because it is here: Core re-derives every reference from the
    /// bytes it is handed.
    pub fn closure_objects(&self) -> std::collections::BTreeMap<ValidationRef, Vec<u8>> {
        self.preimage
            .settlement()
            .closure()
            .refs()
            .iter()
            .copied()
            .zip(self.closure.iter().cloned())
            .collect()
    }
}

/// Why an exercise could not be built from its objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExerciseBuildError {
    /// A leg of `P` has no canonical leg in `P(E)`, so its witness does not
    /// derive.
    Witnesses(String),
    /// The evidence holds no bytes for a closure reference.
    Closure(ValidationRef),
    /// An object has no canonical encoding.
    Wire(String),
}

impl core::fmt::Display for ExerciseBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Witnesses(why) => write!(f, "witnesses: {why}"),
            Self::Closure(reference) => write!(f, "closure: no object for {reference:?}"),
            Self::Wire(why) => write!(f, "wire: {why}"),
        }
    }
}

impl std::error::Error for ExerciseBuildError {}

/// The exercise of a position, from its objects: `F` and `P` in their
/// envelopes, the trader's signed `C_q` exactly as it is final at
/// `K_root(q)`, `P(E)`, the canonical witnesses derived from `P` and the
/// shadows `P(E)` commits, and every closure object in reference order from
/// the evidence its conformance is decided on. A function of public objects
/// (SoFi Amendment S25): whoever builds it — the trader writing its legs, or
/// a verifier whose key another exercise holds — builds the same exercise.
pub fn exercise_from_objects(
    objects: &super::resolve::ExerciseObjects<'_>,
    resolution_claim: &[u8],
    evidence: &super::conformance::ConformanceEvidence,
) -> Result<SofiExercise, ExerciseBuildError> {
    let wire = |e: &dyn core::fmt::Display| ExerciseBuildError::Wire(e.to_string());
    let canonical = derive::canonical_legs(objects.preimage)
        .map_err(|e| ExerciseBuildError::Witnesses(e.to_string()))?;
    let shadows: Vec<[u8; 32]> = objects
        .precommit
        .legs()
        .iter()
        .map(|leg| {
            canonical
                .iter()
                .find(|l| l.vault_id == leg.vault_id)
                .map(|l| l.shadow_core)
                .ok_or_else(|| {
                    ExerciseBuildError::Witnesses("a leg P(E) does not derive".to_string())
                })
        })
        .collect::<Result<_, _>>()?;
    let witnesses: Vec<Vec<u8>> =
        super::conformance::derive_policy_fulfillments(objects.precommit, &shadows)
            .map_err(|e| ExerciseBuildError::Witnesses(format!("{e:?}")))?
            .iter()
            .map(DlvPolicyFulfillmentBody::encode)
            .collect();
    let mut closure = Vec::new();
    for reference in objects.preimage.settlement().closure().refs() {
        let bytes = evidence
            .closure
            .get(reference)
            .ok_or(ExerciseBuildError::Closure(*reference))?;
        closure.push(bytes.clone());
    }
    SofiExercise::new(
        Publication::Fulfillment {
            body: objects.fulfillment,
            signature: objects.fulfillment_signature,
        }
        .object_bytes()
        .map_err(|e| wire(&e))?,
        resolution_claim.to_vec(),
        Publication::Precommit {
            body: objects.precommit,
            signature: objects.precommit_signature,
        }
        .object_bytes()
        .map_err(|e| wire(&e))?,
        objects.preimage.encode().map_err(|e| wire(&e))?,
        witnesses,
        closure,
    )
    .map_err(|e| wire(&e))
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
    // F is signed under the key P commits (conformance item 2, decidable in
    // hand): each envelope verified under its own body's key, and the two
    // keys one.
    if fulfillment.body.signature_alg() != precommit.body.signature_alg()
        || fulfillment.body.claimant_public_key() != precommit.body.claimant_public_key()
    {
        return None;
    }
    // F proves P's device from its own bytes (SoFi Amendment S20): its key,
    // with the AttA it carries, derives the DevID P names. Any other F can
    // never hold the trader's K_ful(q), so its exercise holds no vault key.
    if !fulfillment_proves_the_device(&fulfillment.body, precommit.body.device_id()) {
        return None;
    }
    // The trader's signed C_q (S20), recognized exactly as K_root(q) would
    // recognize it: a claim that proves its own authority there, the
    // signature verifying under the key it carries and that key with its
    // AttA deriving the device it names, and whose body is the C_q of this P
    // and F. That device is P's, as F's key with F's AttA derives it, and one
    // DevID has one (key, AttA), so C_q is signed under the key F is.
    // Whatever holds a vault key therefore carries everything a relayer needs
    // to register its F, and a trader that withholds its pair cannot hold the
    // key forever.
    let own_claim = derive::resolution_claim(&precommit.body, &fulfillment.body);
    let k_root =
        economic_root_register_key(&own_claim.genesis, &own_claim.device_id, own_claim.position);
    if !matches!(
        root_claim_naming(exercise.resolution_claim(), &k_root),
        Some(RegisteredEconomicClaim::ConditionalSofi(held)) if held == own_claim
    ) {
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
    // The closure is bound to `F` through `E` too (§17.5): each object is the
    // one its reference in `𝒞_E^pre` names, by the rule conformance item 8
    // decides it by. Bytes carrying any other object are not this
    // exercise, so they hold no key and can never stand where it should.
    let refs = preimage.settlement().closure().refs();
    if exercise.closure().len() != refs.len() {
        return None;
    }
    for (reference, bytes) in refs.iter().zip(exercise.closure()) {
        if !closure_object_verifies(reference, bytes).is_some_and(|verifies| verifies) {
            return None;
        }
    }
    Some(RecognizedExercise {
        fulfillment,
        resolution_claim: exercise.resolution_claim().to_vec(),
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

/// What the ladder reads at one attempt key (Section 23.1), bound to the key
/// it was read at: the storage fact — open, or which exercise (by its `E`)
/// holds the cell and how far its chain has gone — and the exercise holding
/// it, with its exact bytes. Built by [`attempt_resolution`] over the seats'
/// reads and by nothing else, so a leg's cell fact is always one Core
/// evaluated at that very key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptCellRead {
    vault_id: D32,
    parent_root: D32,
    attempt: u64,
    fact: CellFact,
    held: Option<(RecognizedExercise, Vec<u8>)>,
}

impl AttemptCellRead {
    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }

    pub fn parent_root(&self) -> &D32 {
        &self.parent_root
    }

    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    /// The storage fact at the key.
    pub fn fact(&self) -> CellFact {
        self.fact
    }

    /// The exercise holding the key, if any.
    pub fn exercise(&self) -> Option<&RecognizedExercise> {
        self.held.as_ref().map(|(exercise, _)| exercise)
    }

    /// The exact bytes of the exercise holding the key, if any: what a relay
    /// carries. Never found again by `E`, which names the exercise and not
    /// its bytes.
    pub fn value(&self) -> Option<&[u8]> {
        self.held.as_ref().map(|(_, value)| value.as_slice())
    }

    pub fn into_exercise(self) -> Option<RecognizedExercise> {
        self.held.map(|(exercise, _)| exercise)
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
) -> Result<AttemptCellRead, Missing> {
    let reading = evaluate(&cell.cell, evidence, exercise_at(cell))?;
    let fact = reading.fact();
    let held = match reading {
        CellReading::Held { object, value, .. } => Some((object, value)),
        CellReading::Open => None,
    };
    Ok(AttemptCellRead {
        vault_id: cell.vault_id,
        parent_root: cell.parent_root,
        attempt: cell.attempt,
        fact,
        held,
    })
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

/// Test fixtures shared with the facts tests: one operation as an exercise,
/// signed by the fixture trader.
#[cfg(test)]
#[allow(clippy::disallowed_methods)] // fixtures unwrap; a failure here is the signal
pub(crate) mod fixtures {
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::sofi::conformance::derive_policy_fulfillments;
    use crate::sofi::derive::precommit_id;
    use crate::sofi::publication::Publication;
    use crate::sofi::validation::fixtures::{signed_c_q, trader_keys, Fixture};
    use crate::sofi::wire::AttemptEntry;

    /// The trader's key, as every fixture `P` commits it.
    pub(crate) fn key() -> &'static [u8] {
        &trader_keys().0
    }

    /// The trader's signature over `digest`.
    pub(crate) fn signed(digest: D32) -> Vec<u8> {
        crate::crypto::sphincs::sphincs_sign(&trader_keys().1, &digest).unwrap()
    }

    /// An exercise with the precommit and fulfillment body it carries.
    pub(crate) struct Built {
        pub(crate) exercise: SofiExercise,
        pub(crate) precommit: TraderPrecommitBody,
        pub(crate) fulfillment: TraderFulfillmentBody,
    }

    /// One operation as an exercise: F over `attempts`, the trader's signed
    /// `C_q` of `P` and `F`, the canonical witnesses over the shadows P(E)
    /// commits, and the parent claim its closure references.
    pub(crate) fn exercise(f: &Fixture, attempts: &[u64]) -> Built {
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
            key(),
            crate::sofi::validation::fixtures::TRADER_ATT_A,
        )
        .unwrap();
        let x = SofiExercise::new(
            Publication::Fulfillment {
                body: &fb,
                signature: &signed(derive::fulfillment_signing_digest(&fb)),
            }
            .object_bytes()
            .unwrap(),
            signed_c_q(derive::resolution_claim(p, &fb)),
            Publication::Precommit {
                body: p,
                signature: &signed(derive::precommit_signing_digest(p)),
            }
            .object_bytes()
            .unwrap(),
            f.preimage.encode().unwrap(),
            witnesses
                .iter()
                .map(DlvPolicyFulfillmentBody::encode)
                .collect(),
            // 𝒞_E^pre references the parent P names and the trader's
            // balances before the trade; the exercise carries them.
            f.closure_in_order(),
        )
        .unwrap();
        Built {
            exercise: x,
            precommit: p.clone(),
            fulfillment: fb,
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::sofi::publication::Publication;
    use crate::sofi::registration::fulfillment_proves_the_device;
    use crate::sofi::validation::fixtures::{signed_c_q, swap_fixture_n, TRADER_ATT_A};
    use crate::sofi::wire::SignedSofiResolutionClaim;
    use crate::route_chain::fixtures::{committed_set, committed_set_id, Cell};
    use crate::route_chain::{CellFact, ChainState, ROUTE_LEN};

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
            ox.resolution_claim().to_vec(),
            x.precommit().to_vec(),
            x.preimage().to_vec(),
            x.witnesses().to_vec(),
            x.closure().to_vec(),
        )
        .unwrap();
        assert!(recognize_exercise(&bent.encode()).is_none());
        // A preimage that is not this P's.
        let bent = SofiExercise::new(
            x.fulfillment().to_vec(),
            x.resolution_claim().to_vec(),
            x.precommit().to_vec(),
            other.preimage.encode().unwrap(),
            x.witnesses().to_vec(),
            x.closure().to_vec(),
        )
        .unwrap();
        assert!(recognize_exercise(&bent.encode()).is_none());
        // One witness swapped for another leg's: its leg binding is wrong.
        let mut ws = x.witnesses().to_vec();
        ws.swap(0, 1);
        let bent = SofiExercise::new(
            x.fulfillment().to_vec(),
            x.resolution_claim().to_vec(),
            x.precommit().to_vec(),
            x.preimage().to_vec(),
            ws,
            x.closure().to_vec(),
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
            x.resolution_claim().to_vec(),
            x.precommit().to_vec(),
            x.preimage().to_vec(),
            ws,
            x.closure().to_vec(),
        )
        .unwrap();
        assert!(recognize_exercise(&bent.encode()).is_none());
    }

    /// SoFi §17.5 and §9: an exercise counts only when `F` and `P` are signed
    /// — each envelope's signature verifies over its body under the key the
    /// body commits, and `F`'s key is the one `P` commits. Bytes shaped like
    /// an exercise whose signatures do not verify are nothing, so written
    /// first at the leader they block nothing (storage spec §9 rule 3): the
    /// signed exercise that arrives after them holds the key.
    #[test]
    fn an_exercise_counts_only_when_f_and_p_are_signed_under_the_key_p_commits() {
        let f = swap_fixture_n(2);
        let honest = exercise(&f, &[0, 1]);
        let (p, fb) = (&honest.precommit, &honest.fulfillment);
        let with = |f_body: &TraderFulfillmentBody, f_sig: &[u8], p_sig: &[u8]| {
            SofiExercise::new(
                Publication::Fulfillment {
                    body: f_body,
                    signature: f_sig,
                }
                .object_bytes()
                .unwrap(),
                honest.exercise.resolution_claim().to_vec(),
                Publication::Precommit {
                    body: p,
                    signature: p_sig,
                }
                .object_bytes()
                .unwrap(),
                honest.exercise.preimage().to_vec(),
                honest.exercise.witnesses().to_vec(),
                honest.exercise.closure().to_vec(),
            )
            .unwrap()
            .encode()
        };
        let f_sig = signed(derive::fulfillment_signing_digest(fb));
        let p_sig = signed(derive::precommit_signing_digest(p));
        assert!(recognize_exercise(&with(fb, &f_sig, &p_sig)).is_some());

        // A signature that does not verify, in place of either.
        let junk = [0x77u8; 8];
        assert!(recognize_exercise(&with(fb, &junk, &p_sig)).is_none());
        assert!(recognize_exercise(&with(fb, &f_sig, &junk)).is_none());
        // P's signature where F's belongs: a real signature over another digest.
        assert!(recognize_exercise(&with(fb, &p_sig, &p_sig)).is_none());

        // F signed under a key other than the one P commits: it verifies
        // under its own key and is still not this P's exercise.
        let (other_pk, other_sk) = crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let foreign = TraderFulfillmentBody::new(
            *fb.precommit_id(),
            fb.policy_fulfillment_set().to_vec(),
            fb.attempts().to_vec(),
            fb.position(),
            ALG,
            &other_pk,
            crate::sofi::validation::fixtures::TRADER_ATT_A,
        )
        .unwrap();
        let foreign_sig = crate::crypto::sphincs::sphincs_sign(
            &other_sk,
            &derive::fulfillment_signing_digest(&foreign),
        )
        .unwrap();
        assert!(recognize_exercise(&with(&foreign, &foreign_sig, &p_sig)).is_none());

        // At the cell: the unsigned exercise first at the leader, the signed
        // one after it along the whole route — the signed one holds the key.
        let leg = &p.legs()[0];
        let at = AttemptCell::new(
            &leg.vault_id,
            &leg.parent_root,
            0,
            &committed_set(),
            &committed_set_id(),
        )
        .expect("the committed set");
        let mut cell = Cell::at(at.routed());
        cell.write(&with(fb, &junk, &junk), ROUTE_LEN - 1, &[]);
        cell.write(&with(fb, &f_sig, &p_sig), ROUTE_LEN - 1, &[]);
        assert_eq!(
            attempt_resolution(&at, &cell.evidence()).map(|r| r.fact()),
            Ok(CellFact::Held {
                id: *p.external_commitment(),
                state: ChainState::Final,
            })
        );
        let mut only_junk = Cell::at(at.routed());
        only_junk.write(&with(fb, &junk, &junk), ROUTE_LEN - 1, &[]);
        assert_eq!(
            attempt_resolution(&at, &only_junk.evidence()).map(|r| r.fact()),
            Ok(CellFact::Open)
        );
    }

    /// SoFi Amendment S20: the exercise carries the trader's signed `C_q` of
    /// its own `P` and `F`, so a relayer can register `F` from the exercise's
    /// bytes alone. An exercise counts only when that claim is there, is the
    /// claim `P` and `F` derive, and proves its own authority. Each bent
    /// alone is nothing.
    #[test]
    fn an_exercise_carries_the_traders_signed_claim_of_its_own_p_and_f() {
        let f = swap_fixture_n(2);
        let honest = exercise(&f, &[0, 1]);
        let (p, fb) = (&honest.precommit, &honest.fulfillment);
        let x = &honest.exercise;
        let with = |claim: Vec<u8>| {
            SofiExercise::new(
                x.fulfillment().to_vec(),
                claim,
                x.precommit().to_vec(),
                x.preimage().to_vec(),
                x.witnesses().to_vec(),
                x.closure().to_vec(),
            )
            .unwrap()
            .encode()
        };
        let own = derive::resolution_claim(p, fb);
        let recognized = recognize_exercise(&x.encode()).unwrap();
        assert_eq!(
            recognized.resolution_claim(),
            x.resolution_claim(),
            "the claim a relayer carries is the trader's bytes exactly"
        );
        assert_eq!(
            *SignedSofiResolutionClaim::decode(recognized.resolution_claim())
                .unwrap()
                .claim(),
            own
        );

        // No signed claim: bytes that are none, and the bare C_q.
        assert!(recognize_exercise(&with(b"not a claim".to_vec())).is_none());
        assert!(recognize_exercise(&with(own.encode())).is_none());

        // The trader's signed claim of another fulfillment of this P: it
        // proves its own authority, and it is not this F's claim. Mutation:
        // drop the body comparison.
        let other_f = exercise(&f, &[1, 0]).fulfillment;
        let other = derive::resolution_claim(p, &other_f);
        assert_ne!(other, own);
        assert!(recognize_exercise(&with(signed_c_q(other))).is_none());

        // This F's claim under the trader's signature of another claim: the
        // signature does not verify over this one. Mutation: drop the
        // verification.
        let misplaced = SignedSofiResolutionClaim::new(
            own,
            ALG,
            key(),
            TRADER_ATT_A,
            &signed(derive::resolution_claim_signing_digest(
                &other,
                ALG,
                key(),
                &TRADER_ATT_A,
            )),
        )
        .unwrap();
        assert!(recognize_exercise(&with(misplaced.encode())).is_none());

        // This F's claim signed by another device: the signature verifies
        // under the key it carries, and that key does not derive the device
        // the claim names.
        let (other_pk, other_sk) = generate_sphincs_keypair().unwrap();
        let foreign = SignedSofiResolutionClaim::new(
            own,
            ALG,
            &other_pk,
            TRADER_ATT_A,
            &sphincs_sign(
                &other_sk,
                &derive::resolution_claim_signing_digest(&own, ALG, &other_pk, &TRADER_ATT_A),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(recognize_exercise(&with(foreign.encode())).is_none());
    }

    /// SoFi Amendment S20: `F` proves `P`'s device from its own bytes, its key
    /// with the `AttA` it carries deriving the DevID `P` names. An `F` under
    /// the trader's key with another `AttA` verifies, and so does the claim
    /// the trader signs for it under its own `AttA`; but that `F` can never
    /// hold the trader's `K_ful(q)`, so an exercise carrying it must hold no
    /// vault key. Mutation: drop the device check.
    #[test]
    fn an_exercise_whose_fulfillment_does_not_prove_the_traders_device_is_nothing() {
        let f = swap_fixture_n(2);
        let honest = exercise(&f, &[0, 1]);
        let (p, fb) = (&honest.precommit, &honest.fulfillment);
        let x = &honest.exercise;
        let stray = TraderFulfillmentBody::new(
            *fb.precommit_id(),
            fb.policy_fulfillment_set().to_vec(),
            fb.attempts().to_vec(),
            fb.position(),
            ALG,
            key(),
            [0x5A; 32],
        )
        .unwrap();
        assert!(!fulfillment_proves_the_device(&stray, p.device_id()));
        let bent = SofiExercise::new(
            Publication::Fulfillment {
                body: &stray,
                signature: &signed(derive::fulfillment_signing_digest(&stray)),
            }
            .object_bytes()
            .unwrap(),
            signed_c_q(derive::resolution_claim(p, &stray)),
            x.precommit().to_vec(),
            x.preimage().to_vec(),
            x.witnesses().to_vec(),
            x.closure().to_vec(),
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

    /// An attempt cell names what holds it by `E`, which is no digest of any
    /// bytes. The read carries the exact bytes of the exercise holding the
    /// key — not the bytes the leader took first, the same `F` and `P` under
    /// signatures that do not verify — so a relay carries them and never
    /// looks them up again by `E`.
    #[test]
    fn a_held_attempt_cell_carries_the_exact_bytes_that_hold_it() {
        let f = swap_fixture_n(2);
        let built = exercise(&f, &[0, 1]);
        let bytes = built.exercise.encode();
        let leg = &built.precommit.legs()[0];
        let e = *built.precommit.external_commitment();
        let at = AttemptCell::new(
            &leg.vault_id,
            &leg.parent_root,
            0,
            &committed_set(),
            &committed_set_id(),
        )
        .expect("the committed set");
        let junk = [0x77u8; 8];
        let unsigned = SofiExercise::new(
            Publication::Fulfillment {
                body: &built.fulfillment,
                signature: &junk,
            }
            .object_bytes()
            .unwrap(),
            built.exercise.resolution_claim().to_vec(),
            Publication::Precommit {
                body: &built.precommit,
                signature: &junk,
            }
            .object_bytes()
            .unwrap(),
            built.exercise.preimage().to_vec(),
            built.exercise.witnesses().to_vec(),
            built.exercise.closure().to_vec(),
        )
        .unwrap()
        .encode();
        let mut seats = Cell::at(at.routed());
        seats.write(&unsigned, ROUTE_LEN - 1, &[]);
        seats.write(&bytes, ROUTE_LEN - 1, &[]);
        let read = attempt_resolution(&at, &seats.evidence()).expect("the leader is read");
        assert_eq!(
            read.fact(),
            CellFact::Held {
                id: e,
                state: ChainState::Final,
            }
        );
        assert_eq!(read.value(), Some(bytes.as_slice()));
        assert_ne!(
            e,
            crate::storage_cell::entry_digest(&bytes),
            "E names the exercise, not its bytes"
        );
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
        let fact = |reading: &Result<AttemptCellRead, Missing>| match reading {
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
            let Ok(held) = reading else {
                panic!("the exercise holds the key")
            };
            // The read is bound to the key it was evaluated at.
            assert_eq!(
                (held.vault_id(), held.parent_root(), held.attempt()),
                (&leg.vault_id, &leg.parent_root, 0)
            );
            let object = held.exercise().expect("the exercise holds the key");
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
