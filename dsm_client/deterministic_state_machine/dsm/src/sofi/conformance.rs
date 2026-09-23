// SPDX-License-Identifier: Apache-2.0

//! Binary validation composition and `FulfillmentConformance(F)`, the
//! predicate of Part IV §20.2, over evidence in hand.
//!
//! Nothing here evaluates DLV policy, balances, canonicality, attempt liveness
//! or storage finality of the route: that is `RouteValidation`. Conformance is
//! the other predicate — whether `F` is the exercise of exactly its `P`, with
//! the objects and storage facts the exercise depends on in hand — and it is
//! `Valid` or `Invalid` with a reason.
//!
//! Amendment S3: every Core predicate is binary and is evaluated only over
//! evidence in hand. "Unavailable" is not a predicate value. It is the
//! acquisition layer's report that a fetch has not completed, and its answer
//! is a bounded retry there; Core is not called until the evidence it needs
//! is complete. A read that established nothing — an object not fetched, or
//! fetched bytes that are not the object named — is therefore never evidence:
//! the acquisition layer discards it and fetches again, and a hostile relayer
//! serving garbage cannot end a lineage with it. A fact about bytes in hand
//! (a signature that does not verify, a set that is not the canonical one, an
//! attempt vector with a hole) is `Invalid`, permanently. Registration
//! supplies no truth value.

use std::collections::BTreeMap;

use crate::route_chain::{CellFact, ChainState};
use super::derive::{self, policy_fulfillment_id, precommit_id};
use super::publication::{recognize_setup, Signed};
use super::signature::{verify_fulfillment, verify_precommit, SignatureError};
use super::wire::{
    next_position, DlvPolicyFulfillmentBody, SettlementPreimage, SofiResolutionClaim,
    SofiWireError, TraderFulfillmentBody, TraderPrecommitBody, ValidationRef,
};
use crate::ccb::decode::policy_object_address;

type D32 = [u8; 32];

/// Static semantic validity over evidence in hand. Binary (Amendment S3):
/// `Invalid` is permanent, and there is no third value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    Valid,
    Invalid,
}

impl Validation {
    /// The conjunction: any Invalid is Invalid; otherwise Valid.
    pub fn and(self, other: Validation) -> Validation {
        match (self, other) {
            (Validation::Invalid, _) | (_, Validation::Invalid) => Validation::Invalid,
            _ => Validation::Valid,
        }
    }

    /// The conjunction over every per-leg and route-wide result.
    pub fn all(results: impl IntoIterator<Item = Validation>) -> Validation {
        results.into_iter().fold(Validation::Valid, Validation::and)
    }
}

/// Why a fulfillment is not a fulfillment of its pre-commit: a fact about the
/// bytes in hand, and so permanent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfillmentConformanceError {
    /// `F.precommit_id` does not name this P. (The producer's pre-sign check
    /// only: a verifier that fetched a P the fulfillment does not name has
    /// fetched nothing, see [`ConformanceMissing::Precommit`].)
    PrecommitMismatch,
    /// `F.position` is not `P.position + 1`. Item 1.
    PositionNotSuccessor { expected: u64, got: u64 },
    /// F is signed under a different algorithm or key than P commits. Item 2.
    KeyMismatch,
    /// The envelope of F carries no signature. Item 2.
    FulfillmentUnsigned,
    /// The signature F carries does not verify under the key F commits. Item 2.
    FulfillmentDoesNotVerify,
    /// The caller supplied a shadow digest count that is not one per P leg.
    ShadowCountMismatch { legs: usize, shadows: usize },
    /// The policy-fulfillment set is not exactly the canonical derived set.
    /// Item 3.
    PolicyFulfillmentSetNotCanonical,
    /// The attempt vector does not cover exactly P's legs. Item 4.
    AttemptsDoNotCoverLegs,
    /// P's legs are not the `(v, R, ρ)` triples its own `P(E)` derives. Item 7.
    LegsDoNotMatchPreimage,
    /// The setup body at `ρ` names another trader or another vault than the
    /// leg it is the setup of. Item 7.
    SetupNamesAnotherTraderOrVault { setup_ref: D32 },
    /// The setup body at `ρ` sits at or after `P.position`: a setup precedes
    /// the operation it enables. Item 7.
    SetupNotBeforeTheOperation { setup_ref: D32 },
    /// A closure reference names a content class that has no addressing rule,
    /// so no bytes can ever satisfy it. Item 8.
    ClosureReferenceHasNoAddressingRule { object_class: u16 },
    /// The successor position does not exist.
    Wire(SofiWireError),
    /// A referenced object's canonical bytes exceed `MAX_CLOSURE_OBJECT_BYTES`
    /// (SoFi §18.4).
    ClosureObjectTooLarge { bytes: usize },
    /// P, F and the parent envelopes together exceed `MAX_AUTH_ENVELOPES`.
    TooManyAuthEnvelopes { envelopes: usize },
    /// The unique objects the validation uses exceed
    /// `MAX_VALIDATION_FETCH_BYTES` in aggregate.
    ValidationFetchTooLarge { bytes: usize },
}

/// The bounds of SoFi §18.4 that conformance evidence can exceed. A known
/// bound violation is Invalid, never Unavailable. Every object here verified
/// against the reference it was fetched for — the acquisition layer admits
/// nothing else — so non-verifying candidates never count (§17.2, rule 5).
///
/// - each referenced object: at most `MAX_CLOSURE_OBJECT_BYTES`;
/// - signed envelopes, P and F plus one per parent claim reference: at most
///   `MAX_AUTH_ENVELOPES`;
/// - the unique objects, deduplicated by `ValidationRef`: at most
///   `MAX_VALIDATION_FETCH_BYTES` in aggregate.
pub fn conformance_bounds(
    evidence: &ConformanceEvidence,
) -> Result<(), FulfillmentConformanceError> {
    use super::wire::{MAX_AUTH_ENVELOPES, MAX_CLOSURE_OBJECT_BYTES, MAX_VALIDATION_FETCH_BYTES};

    let setups_outside_closure = evidence.setups.iter().filter(|(setup_ref, _)| {
        !evidence.closure.contains_key(&ValidationRef::Setup {
            setup_ref: **setup_ref,
        })
    });
    let mut total: usize = 0;
    for bytes in evidence
        .closure
        .values()
        .chain(setups_outside_closure.map(|(_, b)| b))
    {
        if bytes.len() > MAX_CLOSURE_OBJECT_BYTES {
            return Err(FulfillmentConformanceError::ClosureObjectTooLarge { bytes: bytes.len() });
        }
        total = total.saturating_add(bytes.len());
    }
    if total > MAX_VALIDATION_FETCH_BYTES {
        return Err(FulfillmentConformanceError::ValidationFetchTooLarge { bytes: total });
    }

    let parent_envelopes = evidence
        .closure
        .keys()
        .filter(|r| {
            matches!(
                r,
                ValidationRef::SingleRootClaim { .. } | ValidationRef::ConditionalClaim { .. }
            )
        })
        .count();
    let envelopes = 2 + parent_envelopes;
    if envelopes > MAX_AUTH_ENVELOPES {
        return Err(FulfillmentConformanceError::TooManyAuthEnvelopes { envelopes });
    }
    Ok(())
}

/// What the acquisition layer has not yet got for `FulfillmentConformance(F)`,
/// named so it can fetch it. None of these is a fact about F, and none is a
/// predicate value: the predicate is not evaluated until nothing is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceMissing {
    /// The referenced P was not fetched, or the fetched object is not the P
    /// that `F.precommit_id` names.
    Precommit,
    /// The fetched copy of P carries a signature that does not verify. Another
    /// envelope over the same body may exist: equality of precommits is
    /// equality of `PrecommitId`, which ignores the signature.
    PrecommitSignature,
    /// `P(E)` was not fetched, or the fetched preimage does not recompute the
    /// `E` that P commits.
    Preimage,
    /// A reference of `𝒞_E^pre` whose object was not fetched, or whose
    /// fetched bytes do not re-derive the reference.
    ClosureObject(ValidationRef),
    /// `SetupRegistered(ρ)` is not established: the setup object was not
    /// fetched as `Stored`, or the bytes at `ρ` do not re-derive `ρ`.
    Setup { setup_ref: D32 },
    /// The earlier attempt key `K^(attempt)` of this vault, which `F` skips
    /// past, has no permanent storage resolution in hand.
    PriorAttempt { vault_id: D32, attempt: u64 },
}

/// `FulfillmentConformance(F)`, over complete evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfillmentConformance {
    Valid,
    Invalid(FulfillmentConformanceError),
}

impl FulfillmentConformance {
    /// The verdict without its reason, for the resolution ladder.
    pub fn verdict(&self) -> Validation {
        match self {
            Self::Valid => Validation::Valid,
            Self::Invalid(_) => Validation::Invalid,
        }
    }
}

/// The exact `P` a fulfillment names, in the envelope a verifier fetched.
pub type PrecommitEnvelope = Signed<TraderPrecommitBody>;

/// Everything `FulfillmentConformance(F)` consumes, complete: objects that
/// were `Stored` and cells as Core resolved them, nothing defaulted (G2). The
/// acquisition layer builds this only once every item is in hand and every
/// fetched object re-derives the reference it was fetched for; until then it
/// reports what is missing ([`ConformanceMissing`]) and retries, and the
/// predicate is not evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceEvidence {
    /// Item 1: the P that `F.precommit_id` names, in a fetched envelope.
    pub precommit: PrecommitEnvelope,
    /// Items 3, 7 and 8: `P(E)`, fetched under `L(E)`.
    pub preimage: SettlementPreimage,
    /// Item 8: the bytes fetched for each reference of `𝒞_E^pre` — `Stored`
    /// bytes for a content, claim or setup reference; the final bytes at
    /// `K_root(p)` for a conditional-claim reference.
    pub closure: BTreeMap<ValidationRef, Vec<u8>>,
    /// Items 6 and 7: `Stored` setup objects (the signed envelope, Part II
    /// §10) by the `ρ` they were fetched for.
    pub setups: BTreeMap<D32, Vec<u8>>,
    /// Item 5: the storage fact at `K^(a)` of a vault, by `(v, a)`, for the
    /// attempts `F` skips past, as Core evaluated its route chains.
    pub prior_attempts: BTreeMap<(D32, u64), CellFact>,
}

/// The canonical `G_j` identity for every DLV leg of `P`, in P's leg order.
///
/// `shadow_cores[j]` is `c°_{V,j}`, the shadow digest E commits for leg `j`.
/// Because each `G_j` is a function of P's leg and E alone, a fulfillment has
/// exactly one admissible policy-fulfillment set.
pub fn derive_policy_fulfillments(
    precommit: &TraderPrecommitBody,
    shadow_cores: &[D32],
) -> Result<Vec<DlvPolicyFulfillmentBody>, FulfillmentConformanceError> {
    if shadow_cores.len() != precommit.legs().len() {
        return Err(FulfillmentConformanceError::ShadowCountMismatch {
            legs: precommit.legs().len(),
            shadows: shadow_cores.len(),
        });
    }
    let pid = precommit_id(precommit);
    Ok(precommit
        .legs()
        .iter()
        .zip(shadow_cores)
        .map(|(leg, shadow)| DlvPolicyFulfillmentBody {
            precommit_id: pid,
            external_commitment: *precommit.external_commitment(),
            vault_id: leg.vault_id,
            parent_root: leg.parent_root,
            shadow_core: *shadow,
        })
        .collect())
}

// ── The structural items, shared by the producer's pre-sign check and the
//    predicate so the two cannot drift ─────────────────────────────────────

/// Item 1, the arithmetic half: `q = P.p + 1`, checked.
fn successor_position(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
) -> Result<(), FulfillmentConformanceError> {
    let expected =
        next_position(precommit.position()).map_err(FulfillmentConformanceError::Wire)?;
    if fulfillment.position() != expected {
        return Err(FulfillmentConformanceError::PositionNotSuccessor {
            expected,
            got: fulfillment.position(),
        });
    }
    Ok(())
}

/// Item 2, the binding half: F's key is the key P committed.
fn key_is_the_precommitted_one(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
) -> Result<(), FulfillmentConformanceError> {
    if fulfillment.signature_alg() != precommit.signature_alg()
        || fulfillment.claimant_public_key() != precommit.claimant_public_key()
    {
        return Err(FulfillmentConformanceError::KeyMismatch);
    }
    Ok(())
}

/// Item 3: the policy-fulfillment set is exactly `Canon[PolicyFulfillmentId_j]`
/// over every leg of P. A subset, an extra identity, or a non-derived
/// identity is refused — there is no half-fulfillment.
fn policy_set_is_canonical(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
    shadow_cores: &[D32],
) -> Result<(), FulfillmentConformanceError> {
    let mut derived: Vec<D32> = derive_policy_fulfillments(precommit, shadow_cores)?
        .iter()
        .map(policy_fulfillment_id)
        .collect();
    derived.sort();
    if fulfillment.policy_fulfillment_set() != derived.as_slice() {
        return Err(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical);
    }
    Ok(())
}

/// Item 4: the attempts cover exactly the legs of P, one entry per leg in
/// leg order, none missing and none repeated.
fn attempts_cover_legs(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
) -> Result<(), FulfillmentConformanceError> {
    let leg_vaults: Vec<D32> = precommit.legs().iter().map(|l| l.vault_id).collect();
    let attempt_vaults: Vec<D32> = fulfillment.attempts().iter().map(|a| a.vault_id).collect();
    if leg_vaults != attempt_vaults {
        return Err(FulfillmentConformanceError::AttemptsDoNotCoverLegs);
    }
    Ok(())
}

/// The producer's pre-sign half of the predicate: identity, successor
/// position, signing key, the complete canonical policy-fulfillment set, and
/// an attempt vector over exactly P's legs — everything decidable from P, F
/// and the shadows E commits, before F is signed and before anything is
/// stored.
///
/// This does NOT require any referenced parent to be unconsumed: a
/// fulfillment may register after a parent is lost and then resolves Void.
pub fn check_fulfillment_against_precommit(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
    shadow_cores: &[D32],
) -> Result<(), FulfillmentConformanceError> {
    if fulfillment.precommit_id() != &precommit_id(precommit) {
        return Err(FulfillmentConformanceError::PrecommitMismatch);
    }
    successor_position(precommit, fulfillment)?;
    key_is_the_precommitted_one(precommit, fulfillment)?;
    policy_set_is_canonical(precommit, fulfillment, shadow_cores)?;
    attempts_cover_legs(precommit, fulfillment)
}

// ── The predicate ──────────────────────────────────────────────────────────

/// One item's outcome: a value over the bytes in hand, or the object the
/// item still needs.
enum Item {
    Valid,
    Invalid(FulfillmentConformanceError),
    Missing(ConformanceMissing),
}

/// The per-item outcomes, folded in ITEM order: the first Invalid item names
/// the reason, else the first missing object is what the acquisition layer
/// fetches next, else Valid. Invalid dominates whatever is missing, so a
/// withheld object can never hide a refusal, and nothing missing is ever read
/// as one.
#[derive(Default)]
struct Items(Vec<(u8, Item)>);

impl Items {
    fn valid(&mut self, item: u8) {
        self.0.push((item, Item::Valid));
    }
    fn invalid(&mut self, item: u8, why: FulfillmentConformanceError) {
        self.0.push((item, Item::Invalid(why)));
    }
    fn missing(&mut self, item: u8, what: ConformanceMissing) {
        self.0.push((item, Item::Missing(what)));
    }
    fn note(&mut self, item: u8, r: Result<(), FulfillmentConformanceError>) {
        match r {
            Ok(()) => self.valid(item),
            Err(why) => self.invalid(item, why),
        }
    }
    fn fold(self) -> Result<FulfillmentConformance, ConformanceMissing> {
        let mut invalid: Option<(u8, FulfillmentConformanceError)> = None;
        let mut missing: Option<(u8, ConformanceMissing)> = None;
        for (item, outcome) in self.0 {
            match outcome {
                Item::Valid => {}
                Item::Invalid(why) => {
                    if invalid.as_ref().is_none_or(|(first, _)| item < *first) {
                        invalid = Some((item, why));
                    }
                }
                Item::Missing(what) => {
                    if missing.as_ref().is_none_or(|(first, _)| item < *first) {
                        missing = Some((item, what));
                    }
                }
            }
        }
        match (invalid, missing) {
            (Some((_, why)), _) => Ok(FulfillmentConformance::Invalid(why)),
            (None, Some((_, what))) => Err(what),
            (None, None) => Ok(FulfillmentConformance::Valid),
        }
    }
}

/// Whether `bytes` are the object a closure reference names, under that
/// variant's own rule. `None` when no bytes could ever satisfy the reference.
fn closure_object_verifies(reference: &ValidationRef, bytes: &[u8]) -> Option<bool> {
    Some(match reference {
        ValidationRef::ContentAddr { object_class, addr } => {
            policy_object_address(*object_class, bytes)? == *addr
        }
        ValidationRef::SingleRootClaim { claim_ref } => derive::claim_ref(bytes) == *claim_ref,
        ValidationRef::ConditionalClaim {
            genesis,
            device_id,
            position,
            fulfillment_id,
        } => SofiResolutionClaim::decode(bytes).is_ok_and(|c| {
            c.genesis == *genesis
                && c.device_id == *device_id
                && c.position == *position
                && c.fulfillment_id == *fulfillment_id
        }),
        ValidationRef::Setup { setup_ref } => {
            recognize_setup(bytes).is_some_and(|(rho, _)| rho == *setup_ref)
        }
    })
}

/// `FulfillmentConformance(F)`, Part IV §20.2, over `F`, the signature its
/// envelope carries, and what the verifier fetched.
///
/// The eight items, in the order the reason reports them:
///
/// 1. the exact referenced `P` is available and verifies, and `q = P.p + 1`;
/// 2. `F` is signed, and its key equals the key `P` committed;
/// 3. the policy-fulfillment set is complete and canonical;
/// 4. the attempts cover exactly the legs of `P`, with no holes;
/// 5. for every `a_j > 0`, `K^(a_j − 1)` has a permanent storage resolution;
/// 6. `SetupRegistered` holds for every leg;
/// 7. identities and bounds hold;
/// 8. the exact `P(E)` and `𝒞_E^pre` are available and verify.
///
/// A producer MUST obtain `Valid` before it publishes `F`; a verifier draws
/// the same answer from the same bytes. Registration supplies no truth value.
///
/// `Err` names an object the evidence does not hold, or holds as bytes that
/// are not the object named: the predicate is not evaluated yet, and the
/// acquisition layer fetches what is named (Amendment S3). It is never a
/// value and is never recorded as one.
pub fn fulfillment_conformance(
    fulfillment: &TraderFulfillmentBody,
    fulfillment_signature: &[u8],
    evidence: &ConformanceEvidence,
) -> Result<FulfillmentConformance, ConformanceMissing> {
    // SoFi §18.4: a known bound violation is Invalid, and it is known from
    // the evidence alone.
    if let Err(bound) = conformance_bounds(evidence) {
        return Ok(FulfillmentConformance::Invalid(bound));
    }
    let mut items = Items::default();

    // Item 2, the half decidable from F alone: the envelope verifies under
    // the key F itself commits. Whether that key is P's is decided once P is
    // in hand; that F is signed at all is a fact about these bytes.
    items.note(
        2,
        verify_fulfillment(
            fulfillment,
            fulfillment_signature,
            fulfillment.claimant_public_key(),
        )
        .map_err(|e| match e {
            SignatureError::Missing { .. } => FulfillmentConformanceError::FulfillmentUnsigned,
            _ => FulfillmentConformanceError::FulfillmentDoesNotVerify,
        }),
    );

    // Item 1: the exact referenced P, available and verifying. A fetched
    // object that is not the P F names, or a copy whose envelope does not
    // verify, establishes nothing about P.
    let fetched = &evidence.precommit;
    if precommit_id(&fetched.body) != *fulfillment.precommit_id() {
        items.missing(1, ConformanceMissing::Precommit);
        return items.fold();
    }
    if verify_precommit(&fetched.body, &fetched.signature).is_err() {
        items.missing(1, ConformanceMissing::PrecommitSignature);
        return items.fold();
    }
    let precommit = &fetched.body;

    items.note(1, successor_position(precommit, fulfillment));
    items.note(2, key_is_the_precommitted_one(precommit, fulfillment));
    items.note(4, attempts_cover_legs(precommit, fulfillment));

    // Item 5: an attempt above zero skips past the key before it, which must
    // have resolved permanently — final on anything. A chain short of final
    // is not a resolution; a key never dies, so this waits and never refuses.
    for attempt in fulfillment.attempts() {
        let Some(earlier) = attempt.attempt.checked_sub(1) else {
            continue;
        };
        match evidence.prior_attempts.get(&(attempt.vault_id, earlier)) {
            Some(CellFact::Held {
                state: ChainState::Final,
                ..
            }) => items.valid(5),
            _ => items.missing(
                5,
                ConformanceMissing::PriorAttempt {
                    vault_id: attempt.vault_id,
                    attempt: earlier,
                },
            ),
        }
    }

    // Items 6 and 7: every leg's setup is Stored under its ρ, recomputed from
    // the bytes of its envelope; and once in hand, it is the setup of THIS
    // trader for THIS vault, made before the operation.
    for leg in precommit.legs() {
        let body = evidence
            .setups
            .get(&leg.setup_ref)
            .and_then(|bytes| recognize_setup(bytes))
            .filter(|(rho, _)| *rho == leg.setup_ref)
            .map(|(_, signed)| signed.body);
        let Some(body) = body else {
            items.missing(
                6,
                ConformanceMissing::Setup {
                    setup_ref: leg.setup_ref,
                },
            );
            continue;
        };
        items.valid(6);
        if body.genesis() != precommit.genesis()
            || body.device_id() != precommit.device_id()
            || body.vault_id() != &leg.vault_id
        {
            items.invalid(
                7,
                FulfillmentConformanceError::SetupNamesAnotherTraderOrVault {
                    setup_ref: leg.setup_ref,
                },
            );
        } else if body.position() >= precommit.position() {
            items.invalid(
                7,
                FulfillmentConformanceError::SetupNotBeforeTheOperation {
                    setup_ref: leg.setup_ref,
                },
            );
        } else {
            items.valid(7);
        }
    }

    // Item 8: the exact P(E) — the preimage that recomputes the E P commits —
    // and every object 𝒞_E^pre references. Items 3 and 7 read P(E) too: the
    // shadows E commits, and the legs it derives.
    let preimage = &evidence.preimage;
    if !derive::recompute_e(preimage).is_ok_and(|e| e == *precommit.external_commitment()) {
        items.missing(8, ConformanceMissing::Preimage);
        return items.fold();
    }
    items.valid(8);
    for reference in preimage.settlement().closure().refs() {
        match evidence
            .closure
            .get(reference)
            .map(|bytes| closure_object_verifies(reference, bytes))
        {
            Some(Some(true)) => items.valid(8),
            Some(None) => {
                let ValidationRef::ContentAddr { object_class, .. } = reference else {
                    // Only a content reference can lack an addressing rule.
                    continue;
                };
                items.invalid(
                    8,
                    FulfillmentConformanceError::ClosureReferenceHasNoAddressingRule {
                        object_class: *object_class,
                    },
                );
            }
            _ => items.missing(8, ConformanceMissing::ClosureObject(*reference)),
        }
    }

    // Item 7, the leg identities: P's legs are the (v, R, ρ) triples P(E)
    // derives. E binds the preimage, so a disagreement is P's own.
    let Ok(canonical) = derive::canonical_legs(preimage) else {
        // A preimage whose legs do not derive cannot exist: both constructors
        // refuse it. The fetched bytes are then not P(E).
        items.missing(8, ConformanceMissing::Preimage);
        return items.fold();
    };
    let mut derived: Vec<(D32, D32, D32)> = canonical
        .iter()
        .map(|l| (l.vault_id, l.parent_root, l.setup_ref))
        .collect();
    derived.sort();
    let named: Vec<(D32, D32, D32)> = precommit
        .legs()
        .iter()
        .map(|l| (l.vault_id, l.parent_root, l.setup_ref))
        .collect();
    if named != derived {
        items.invalid(7, FulfillmentConformanceError::LegsDoNotMatchPreimage);
        return items.fold();
    }
    items.valid(7);

    // Item 3: the canonical set, over the shadows E commits, in P's leg order.
    let shadows: Vec<D32> = precommit
        .legs()
        .iter()
        .filter_map(|leg| {
            canonical
                .iter()
                .find(|l| l.vault_id == leg.vault_id)
                .map(|l| l.shadow_core)
        })
        .collect();
    items.note(3, policy_set_is_canonical(precommit, fulfillment, &shadows));

    items.fold()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use std::sync::OnceLock;

    use super::Validation::{Invalid, Unavailable, Valid};
    use super::*;
    use crate::ccb::class;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::sofi::publication::Publication;
    use crate::sofi::validation::fixtures::{
        policies, policy_addr, swap_fixture_with, vault_id_of, DEV, G, P_POS, SIG_ALG,
    };
    use crate::sofi::wire::{AttemptEntry, PreEClosureIndex, PrecommitLeg, SofiSetupBody};

    #[test]
    fn invalid_dominates_and_unavailable_never_becomes_invalid() {
        assert_eq!(Valid.and(Valid), Valid);
        assert_eq!(Valid.and(Unavailable), Unavailable);
        assert_eq!(Unavailable.and(Invalid), Invalid);
        assert_eq!(Invalid.and(Unavailable), Invalid);
        assert_eq!(Validation::all([Valid, Unavailable, Valid]), Unavailable);
        assert_eq!(Validation::all([]), Valid);
    }

    fn token(byte: u8) -> D32 {
        [byte; 32]
    }

    const SETUP_POS: u64 = P_POS - 1;
    const CLAIM_BYTES: &[u8] = b"the exact registered claim envelope at p";

    /// The whole operation, signed once: two legs, real setup bodies whose ρ
    /// the legs carry, a closure naming one object of every reference kind,
    /// P and F signed under one SPHINCS+ key.
    struct Rig {
        sk: Vec<u8>,
        pk: Vec<u8>,
        precommit: TraderPrecommitBody,
        precommit_sig: Vec<u8>,
        preimage: SettlementPreimage,
        e: D32,
        fulfillment: TraderFulfillmentBody,
        fulfillment_sig: Vec<u8>,
        /// `(ρ_j, bytes)` in hop order.
        setups: Vec<(D32, Vec<u8>)>,
        closure: BTreeMap<ValidationRef, Vec<u8>>,
    }

    fn setup_body(pk: &[u8], j: usize, genesis: D32, device: D32, position: u64) -> SofiSetupBody {
        SofiSetupBody::new(
            genesis,
            device,
            position,
            vault_id_of(j),
            token(0xA0 + j as u8),
            token(0xB0 + j as u8),
            SIG_ALG,
            pk,
        )
        .unwrap()
    }

    /// `base` with `legs`, under `pk`: the fixture's P carries a placeholder
    /// key, and the tests need one that can sign.
    /// The published form of a setup: its envelope. The signature is not
    /// what conformance checks (SetupValid is RouteValidation's), so any
    /// non-empty one carries.
    fn setup_object(body: &SofiSetupBody) -> Vec<u8> {
        Publication::Setup {
            body,
            signature: &[0x5E; 8],
        }
        .object_bytes()
        .unwrap()
    }

    fn rebuild(
        base: &TraderPrecommitBody,
        pk: &[u8],
        legs: Vec<PrecommitLeg>,
    ) -> TraderPrecommitBody {
        TraderPrecommitBody::new(
            *base.genesis(),
            *base.device_id(),
            base.position(),
            *base.parent_claim_ref(),
            *base.external_commitment(),
            legs,
            *base.realize_root(),
            *base.void_root(),
            *base.storage_set_id(),
            SIG_ALG,
            pk,
        )
        .unwrap()
    }

    fn sign_p(sk: &[u8], p: &TraderPrecommitBody) -> Vec<u8> {
        sphincs_sign(sk, &derive::precommit_signing_digest(p)).unwrap()
    }

    /// The canonical F of `precommit` over `preimage`, with `attempts`.
    fn fulfillment_of(
        precommit: &TraderPrecommitBody,
        preimage: &SettlementPreimage,
        attempts: Vec<AttemptEntry>,
    ) -> TraderFulfillmentBody {
        let canonical = derive::canonical_legs(preimage).unwrap();
        let shadows: Vec<D32> = precommit
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
        let mut set: Vec<D32> = derive_policy_fulfillments(precommit, &shadows)
            .unwrap()
            .iter()
            .map(policy_fulfillment_id)
            .collect();
        set.sort();
        TraderFulfillmentBody::new(
            precommit_id(precommit),
            set,
            attempts,
            precommit.position() + 1,
            precommit.signature_alg(),
            precommit.claimant_public_key(),
        )
        .unwrap()
    }

    fn sign_f(sk: &[u8], f: &TraderFulfillmentBody) -> Vec<u8> {
        sphincs_sign(sk, &derive::fulfillment_signing_digest(f)).unwrap()
    }

    fn build_rig() -> Rig {
        let (pk, sk) = generate_sphincs_keypair().unwrap();
        let setups: Vec<(D32, Vec<u8>)> = (0..2)
            .map(|j| {
                let body = setup_body(&pk, j, G, DEV, SETUP_POS);
                (derive::setup_ref(&body), setup_object(&body))
            })
            .collect();
        let (market, _, _) = policies(0);
        let market_bytes = market.encode();
        let claim = SofiResolutionClaim {
            genesis: G,
            device_id: DEV,
            position: 3,
            fulfillment_id: token(0x42),
            realize_root: token(0x43),
            void_root: token(0x44),
        };
        let closure: BTreeMap<ValidationRef, Vec<u8>> = BTreeMap::from([
            (
                ValidationRef::ContentAddr {
                    object_class: class::MARKET_POLICY,
                    addr: policy_addr(class::MARKET_POLICY, &market_bytes),
                },
                market_bytes,
            ),
            (
                ValidationRef::SingleRootClaim {
                    claim_ref: derive::claim_ref(CLAIM_BYTES),
                },
                CLAIM_BYTES.to_vec(),
            ),
            (
                ValidationRef::ConditionalClaim {
                    genesis: G,
                    device_id: DEV,
                    position: 3,
                    fulfillment_id: token(0x42),
                },
                claim.encode(),
            ),
            (
                ValidationRef::Setup {
                    setup_ref: setups[0].0,
                },
                setups[0].1.clone(),
            ),
        ]);
        let mut refs: Vec<ValidationRef> = closure.keys().copied().collect();
        refs.sort_by_key(ValidationRef::encode);
        let f = swap_fixture_with(2, &|j| setups[j].0, PreEClosureIndex::new(refs).unwrap());
        let precommit = rebuild(&f.precommit, &pk, f.precommit.legs().to_vec());
        let precommit_sig = sign_p(&sk, &precommit);
        let e = derive::recompute_e(&f.preimage).unwrap();
        // Leg order is vault order; the second leg exercises attempt 1.
        let attempts: Vec<AttemptEntry> = precommit
            .legs()
            .iter()
            .enumerate()
            .map(|(i, leg)| AttemptEntry {
                vault_id: leg.vault_id,
                attempt: i as u64,
            })
            .collect();
        let fulfillment = fulfillment_of(&precommit, &f.preimage, attempts);
        let fulfillment_sig = sign_f(&sk, &fulfillment);
        Rig {
            sk,
            pk,
            precommit,
            precommit_sig,
            preimage: f.preimage,
            e,
            fulfillment,
            fulfillment_sig,
            setups,
            closure,
        }
    }

    fn rig() -> &'static Rig {
        static RIG: OnceLock<Rig> = OnceLock::new();
        RIG.get_or_init(build_rig)
    }

    /// Everything fetched: P, P(E), every closure object, both setups, and
    /// the prior attempt key of the leg that exercises attempt 1, final.
    fn everything(r: &Rig) -> ConformanceEvidence {
        let second = r.precommit.legs()[1].vault_id;
        ConformanceEvidence {
            precommit: Some(PrecommitEnvelope {
                body: r.precommit.clone(),
                signature: r.precommit_sig.clone(),
            }),
            preimage: Some(r.preimage.clone()),
            closure: r.closure.clone(),
            setups: r.setups.iter().cloned().collect(),
            prior_attempts: BTreeMap::from([((second, 0), CellResolution::Final(r.e))]),
        }
    }

    fn conformance(r: &Rig, ev: &ConformanceEvidence) -> FulfillmentConformance {
        fulfillment_conformance(&r.fulfillment, &r.fulfillment_sig, ev)
    }

    #[test]
    fn a_fulfillment_with_everything_in_hand_is_valid() {
        let r = rig();
        assert_eq!(
            conformance(r, &everything(r)),
            FulfillmentConformance::Valid
        );
        assert_eq!(conformance(r, &everything(r)).verdict(), Valid);
    }

    #[test]
    fn item_1_the_referenced_p_is_available_verifies_and_q_is_its_successor() {
        let r = rig();
        // Not fetched.
        let mut ev = everything(r);
        ev.precommit = None;
        assert_eq!(
            conformance(r, &ev),
            FulfillmentConformance::Unavailable(ConformanceMissing::Precommit)
        );
        // Fetched, but not the P F names: a different leg set gives a
        // different PrecommitId. That is nothing about P, not a refusal.
        let mut ev = everything(r);
        let mut legs = r.precommit.legs().to_vec();
        legs[0].parent_root = token(0x99);
        ev.precommit = Some(PrecommitEnvelope {
            body: rebuild(&r.precommit, &r.pk, legs),
            signature: r.precommit_sig.clone(),
        });
        assert_eq!(
            conformance(r, &ev),
            FulfillmentConformance::Unavailable(ConformanceMissing::Precommit)
        );
        // The right P in a copy whose envelope does not verify: another
        // envelope may, so this is missing, not invalid.
        let mut ev = everything(r);
        ev.precommit.as_mut().unwrap().signature = r.fulfillment_sig.clone();
        assert_eq!(
            conformance(r, &ev),
            FulfillmentConformance::Unavailable(ConformanceMissing::PrecommitSignature)
        );
        let mut ev = everything(r);
        ev.precommit.as_mut().unwrap().signature.clear();
        assert_eq!(
            conformance(r, &ev),
            FulfillmentConformance::Unavailable(ConformanceMissing::PrecommitSignature)
        );
        // q ≠ p + 1 is a fact about F.
        let f = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment.attempts().to_vec(),
            r.precommit.position() + 2,
            SIG_ALG,
            &r.pk,
        )
        .unwrap();
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &everything(r)),
            FulfillmentConformance::Invalid(FulfillmentConformanceError::PositionNotSuccessor {
                expected: r.precommit.position() + 1,
                got: r.precommit.position() + 2,
            })
        );
    }

    #[test]
    fn item_2_f_is_signed_under_the_key_p_committed() {
        let r = rig();
        let ev = everything(r);
        assert_eq!(
            fulfillment_conformance(&r.fulfillment, &[], &ev),
            FulfillmentConformance::Invalid(FulfillmentConformanceError::FulfillmentUnsigned)
        );
        assert_eq!(
            fulfillment_conformance(&r.fulfillment, &r.precommit_sig, &ev),
            FulfillmentConformance::Invalid(FulfillmentConformanceError::FulfillmentDoesNotVerify)
        );
        // Signed, and verifying, under a key that is not the one P committed.
        let (other_pk, other_sk) = generate_sphincs_keypair().unwrap();
        let f = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment.attempts().to_vec(),
            r.fulfillment.position(),
            SIG_ALG,
            &other_pk,
        )
        .unwrap();
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&other_sk, &f), &ev),
            FulfillmentConformance::Invalid(FulfillmentConformanceError::KeyMismatch)
        );
    }

    #[test]
    fn item_3_the_policy_fulfillment_set_is_the_canonical_set_of_p() {
        let r = rig();
        let ev = everything(r);
        let ids = r.fulfillment.policy_fulfillment_set().to_vec();
        let with_set = |set: Vec<D32>| {
            let f = TraderFulfillmentBody::new(
                *r.fulfillment.precommit_id(),
                set,
                r.fulfillment.attempts().to_vec(),
                r.fulfillment.position(),
                SIG_ALG,
                &r.pk,
            )
            .unwrap();
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &ev)
        };
        let refused = FulfillmentConformance::Invalid(
            FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical,
        );
        // A subset, an extra entry, and an id not derived from P.
        assert_eq!(with_set(vec![ids[0]]), refused);
        let mut extra = ids.clone();
        extra.push(token(0xFF));
        extra.sort();
        assert_eq!(with_set(extra), refused);
        assert_eq!(with_set(vec![token(0x01), token(0x02)]), refused);
        // Without P(E) the shadows E commits are not in hand, so the canonical
        // set cannot be derived: that waits.
        let mut without = everything(r);
        without.preimage = None;
        assert_eq!(
            conformance(r, &without),
            FulfillmentConformance::Unavailable(ConformanceMissing::Preimage)
        );
    }

    #[test]
    fn item_4_the_attempts_cover_exactly_the_legs_of_p_with_no_holes() {
        let r = rig();
        let ev = everything(r);
        let with_attempts = |attempts: Vec<AttemptEntry>| {
            let f = TraderFulfillmentBody::new(
                *r.fulfillment.precommit_id(),
                r.fulfillment.policy_fulfillment_set().to_vec(),
                attempts,
                r.fulfillment.position(),
                SIG_ALG,
                &r.pk,
            )
            .unwrap();
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &ev)
        };
        let refused =
            FulfillmentConformance::Invalid(FulfillmentConformanceError::AttemptsDoNotCoverLegs);
        let legs = r.precommit.legs();
        // A hole: one leg without an attempt.
        assert_eq!(
            with_attempts(vec![AttemptEntry {
                vault_id: legs[0].vault_id,
                attempt: 0,
            }]),
            refused
        );
        // A vault P does not name, in place of a leg.
        let mut foreign = r.fulfillment.attempts().to_vec();
        foreign[1].vault_id = token(0xFE);
        assert_eq!(with_attempts(foreign), refused);
    }

    #[test]
    fn item_5_an_earlier_attempt_must_have_a_permanent_storage_resolution() {
        let r = rig();
        let second = r.precommit.legs()[1].vault_id;
        let waits = FulfillmentConformance::Unavailable(ConformanceMissing::PriorAttempt {
            vault_id: second,
            attempt: 0,
        });
        // Not read.
        let mut ev = everything(r);
        ev.prior_attempts.clear();
        assert_eq!(conformance(r, &ev), waits);
        // Read, and open: no key ever dies, so this waits.
        ev.prior_attempts
            .insert((second, 0), CellResolution::Unresolved);
        assert_eq!(conformance(r, &ev), waits);
        // Held at the leader but not final: not yet permanent.
        ev.prior_attempts
            .insert((second, 0), CellResolution::LeaderHeld(token(0x77)));
        assert_eq!(conformance(r, &ev), waits);
        // Final on ANOTHER operation's E is a permanent resolution too: the
        // earlier key was lost, which is exactly why F skipped past it.
        ev.prior_attempts
            .insert((second, 0), CellResolution::Final(token(0x77)));
        assert_eq!(conformance(r, &ev), FulfillmentConformance::Valid);
        // Attempt 0 has no earlier key and reads nothing.
        let mut ev = everything(r);
        ev.prior_attempts.clear();
        let attempts: Vec<AttemptEntry> = r
            .precommit
            .legs()
            .iter()
            .map(|l| AttemptEntry {
                vault_id: l.vault_id,
                attempt: 0,
            })
            .collect();
        let f = fulfillment_of(&r.precommit, &r.preimage, attempts);
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &ev),
            FulfillmentConformance::Valid
        );
    }

    #[test]
    fn item_6_setup_registered_holds_for_every_leg() {
        let r = rig();
        let (rho_1, _) = r.setups[1].clone();
        let leg_1 = r
            .precommit
            .legs()
            .iter()
            .find(|l| l.setup_ref == rho_1)
            .unwrap();
        let missing = FulfillmentConformance::Unavailable(ConformanceMissing::Setup {
            setup_ref: leg_1.setup_ref,
        });
        // Not fetched as Stored.
        let mut ev = everything(r);
        ev.setups.remove(&rho_1);
        assert_eq!(conformance(r, &ev), missing);
        // Bytes at ρ_1 that are not the body ρ_1 is the reference of: the
        // other leg's setup, and garbage. Neither is the setup, neither is a
        // refusal.
        let mut ev = everything(r);
        ev.setups.insert(rho_1, r.setups[0].1.clone());
        assert_eq!(conformance(r, &ev), missing);
        let mut ev = everything(r);
        ev.setups.insert(rho_1, b"not a setup body".to_vec());
        assert_eq!(conformance(r, &ev), missing);
    }

    #[test]
    fn item_7_identities_and_bounds_hold() {
        let r = rig();
        // An operation whose hop 0 is set up by `body`: P(E) and P carry its
        // ρ, and the body is Stored under it, so the only question left is
        // whether it is the setup of this trader for this vault, made before
        // the operation.
        let with_hop_0_setup = |body: &SofiSetupBody| {
            let rho = derive::setup_ref(body);
            let bent = swap_fixture_with(
                2,
                &|j| if j == 0 { rho } else { r.setups[j].0 },
                r.preimage.settlement().closure().clone(),
            );
            let p = rebuild(&bent.precommit, &r.pk, bent.precommit.legs().to_vec());
            let f = fulfillment_of(&p, &bent.preimage, r.fulfillment.attempts().to_vec());
            let mut ev = everything(r);
            ev.precommit = Some(PrecommitEnvelope {
                signature: sign_p(&r.sk, &p),
                body: p,
            });
            ev.preimage = Some(bent.preimage);
            ev.setups.insert(rho, setup_object(body));
            (rho, fulfillment_conformance(&f, &sign_f(&r.sk, &f), &ev))
        };
        // Another trader's setup of this vault.
        let (rho, verdict) = with_hop_0_setup(&setup_body(&r.pk, 0, token(0x33), DEV, SETUP_POS));
        assert_eq!(
            verdict,
            FulfillmentConformance::Invalid(
                FulfillmentConformanceError::SetupNamesAnotherTraderOrVault { setup_ref: rho }
            )
        );
        // This trader's setup of another vault.
        let (rho, verdict) = with_hop_0_setup(&setup_body(&r.pk, 1, G, DEV, SETUP_POS));
        assert_eq!(
            verdict,
            FulfillmentConformance::Invalid(
                FulfillmentConformanceError::SetupNamesAnotherTraderOrVault { setup_ref: rho }
            )
        );
        // The right setup, at the operation's own position: not before it.
        let (rho, verdict) = with_hop_0_setup(&setup_body(&r.pk, 0, G, DEV, P_POS));
        assert_eq!(
            verdict,
            FulfillmentConformance::Invalid(
                FulfillmentConformanceError::SetupNotBeforeTheOperation { setup_ref: rho }
            )
        );
        // And the bound is strict on the right side: one position before is
        // fine, which the rig itself shows.
        assert_eq!(SETUP_POS + 1, P_POS);
        assert_eq!(
            conformance(r, &everything(r)),
            FulfillmentConformance::Valid
        );
        // P's legs are not what P(E) derives: same E, another parent root.
        let mut legs = r.precommit.legs().to_vec();
        legs[1].parent_root = token(0x5A);
        let p = rebuild(&r.precommit, &r.pk, legs);
        let f = fulfillment_of(&p, &r.preimage, r.fulfillment.attempts().to_vec());
        let mut ev = everything(r);
        ev.precommit = Some(PrecommitEnvelope {
            signature: sign_p(&r.sk, &p),
            body: p,
        });
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &ev),
            FulfillmentConformance::Invalid(FulfillmentConformanceError::LegsDoNotMatchPreimage)
        );
    }

    #[test]
    fn item_8_the_preimage_and_closure_are_available_and_verify() {
        let r = rig();
        // P(E) not fetched.
        let mut ev = everything(r);
        ev.preimage = None;
        assert_eq!(
            conformance(r, &ev),
            FulfillmentConformance::Unavailable(ConformanceMissing::Preimage)
        );
        // A preimage of another E: not P(E), nothing about P.
        let other = swap_fixture_with(
            2,
            &|j| r.setups[j].0,
            PreEClosureIndex::new(Vec::new()).unwrap(),
        );
        assert_ne!(derive::recompute_e(&other.preimage).unwrap(), r.e);
        let mut ev = everything(r);
        ev.preimage = Some(other.preimage);
        assert_eq!(
            conformance(r, &ev),
            FulfillmentConformance::Unavailable(ConformanceMissing::Preimage)
        );
        // Every kind of closure reference: withheld, then wrong bytes.
        for reference in r.preimage.settlement().closure().refs() {
            let missing =
                FulfillmentConformance::Unavailable(ConformanceMissing::ClosureObject(*reference));
            let mut ev = everything(r);
            ev.closure.remove(reference);
            assert_eq!(conformance(r, &ev), missing, "{reference:?} withheld");
            let mut ev = everything(r);
            ev.closure.insert(*reference, b"not that object".to_vec());
            assert_eq!(conformance(r, &ev), missing, "{reference:?} wrong bytes");
        }
        // A content reference to a class with no addressing rule can never
        // be satisfied: that is P(E)'s own defect, and E binds P to it.
        let mut refs: Vec<ValidationRef> = r.closure.keys().copied().collect();
        refs.push(ValidationRef::ContentAddr {
            object_class: 0x7777,
            addr: token(0x01),
        });
        refs.sort_by_key(ValidationRef::encode);
        let bent = swap_fixture_with(2, &|j| r.setups[j].0, PreEClosureIndex::new(refs).unwrap());
        let p = rebuild(&bent.precommit, &r.pk, bent.precommit.legs().to_vec());
        let f = fulfillment_of(&p, &bent.preimage, r.fulfillment.attempts().to_vec());
        let mut ev = everything(r);
        ev.precommit = Some(PrecommitEnvelope {
            signature: sign_p(&r.sk, &p),
            body: p,
        });
        ev.preimage = Some(bent.preimage);
        ev.closure.insert(
            ValidationRef::ContentAddr {
                object_class: 0x7777,
                addr: token(0x01),
            },
            b"anything".to_vec(),
        );
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &ev),
            FulfillmentConformance::Invalid(
                FulfillmentConformanceError::ClosureReferenceHasNoAddressingRule {
                    object_class: 0x7777
                }
            )
        );
    }

    /// The composition rule of the predicate: a refusal is reported over
    /// anything missing, in item order, and nothing missing is ever reported
    /// as a refusal.
    #[test]
    fn invalid_dominates_unavailable_in_item_order() {
        let r = rig();
        // Unsigned F with nothing else fetched: item 2 refuses.
        assert_eq!(
            fulfillment_conformance(&r.fulfillment, &[], &ConformanceEvidence::default()),
            FulfillmentConformance::Invalid(FulfillmentConformanceError::FulfillmentUnsigned)
        );
        // A signed F with nothing fetched: everything waits on P.
        assert_eq!(
            conformance(r, &ConformanceEvidence::default()),
            FulfillmentConformance::Unavailable(ConformanceMissing::Precommit)
        );
        // P in hand, a hole in the attempts, and P(E) withheld: item 4 refuses
        // over item 8's absence.
        let mut ev = everything(r);
        ev.preimage = None;
        let f = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            vec![AttemptEntry {
                vault_id: r.precommit.legs()[0].vault_id,
                attempt: 0,
            }],
            r.fulfillment.position(),
            SIG_ALG,
            &r.pk,
        )
        .unwrap();
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &ev),
            FulfillmentConformance::Invalid(FulfillmentConformanceError::AttemptsDoNotCoverLegs)
        );
        // Two refusals: the earlier item's reason is the one reported.
        let f = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            vec![token(0x01)],
            vec![AttemptEntry {
                vault_id: r.precommit.legs()[0].vault_id,
                attempt: 0,
            }],
            r.fulfillment.position(),
            SIG_ALG,
            &r.pk,
        )
        .unwrap();
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&r.sk, &f), &everything(r)),
            FulfillmentConformance::Invalid(
                FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical
            )
        );
    }

    /// The producer's pre-sign check is the structural half of the predicate:
    /// it accepts exactly what the predicate does not refuse on items 1 to 4,
    /// with the same reason.
    #[test]
    fn the_producers_pre_sign_check_is_the_structural_half_of_the_predicate() {
        let r = rig();
        let canonical = derive::canonical_legs(&r.preimage).unwrap();
        let shadows: Vec<D32> = r
            .precommit
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
        assert_eq!(
            check_fulfillment_against_precommit(&r.precommit, &r.fulfillment, &shadows),
            Ok(())
        );
        let mut extra = r.fulfillment.policy_fulfillment_set().to_vec();
        extra.push(token(0xFF));
        extra.sort();
        let f = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            extra,
            r.fulfillment.attempts().to_vec(),
            r.fulfillment.position(),
            SIG_ALG,
            &r.pk,
        )
        .unwrap();
        let structural = check_fulfillment_against_precommit(&r.precommit, &f, &shadows);
        let full = fulfillment_conformance(&f, &sign_f(&r.sk, &f), &everything(r));
        assert_eq!(
            structural,
            Err(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical)
        );
        assert_eq!(
            full,
            FulfillmentConformance::Invalid(structural.unwrap_err())
        );
    }
}
