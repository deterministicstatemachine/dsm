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
    ParentClaimRef, next_position, DlvPolicyFulfillmentBody, SettlementPreimage,
    SofiResolutionClaim, SofiWireError, TraderFulfillmentBody, TraderPrecommitBody, ValidationRef,
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
    /// `𝒞_E^pre` does not carry the typed reference of the parent P names
    /// (P conformance rule 2). Item 1.
    ParentReferenceNotInClosure,
    /// The bytes at the `claim_ref` P names are not a verifying root claim:
    /// P names a parent that is not a claim. Item 1.
    ParentClaimDoesNotVerify,
    /// The parent claim is not the position P extends: it names another
    /// trader or position, or a root other than `P.void_root = T°.pre_root`
    /// (P conformance rules 2 and 3). Item 1.
    ParentClaimIsAnotherPosition,
    /// P is signed under an algorithm or key other than its parent's: the
    /// single-root claim's, or the key of the parent `F` a conditional parent
    /// was installed by (P conformance rule 8, "the key binds to the parent
    /// claim"). Item 1.
    KeyIsNotTheParentClaimants,
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
    /// P's parent is conditional, and the `F` whose `FulfillmentId` it names
    /// was not fetched: the key P must bind to is that F's.
    ParentFulfillment { fulfillment_id: D32 },
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
    /// Item 1, for a conditional parent: the body of the `F` whose
    /// `FulfillmentId` P names. Its identity is the hash of its body, key
    /// included, so bytes that do not re-derive the id are not that `F`.
    pub parent_fulfillment: Option<TraderFulfillmentBody>,
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

/// Item 1, P conformance rules 3 and 8: P's key binds to the parent claim.
///
/// A single-root parent is the claim envelope at the `claim_ref` P names,
/// in hand as the closure object `𝒞_E^pre` references (rule 2): it must
/// verify, name P's trader and position, commit the root P voids to, and be
/// signed under P's key. A conditional parent's claim `C_p` carries no key:
/// it names the `F` that installed it, and P's key is that `F`'s. `Err`
/// carries the item's outcome: Invalid, or the object still missing.
fn parent_binds_the_key(
    precommit: &TraderPrecommitBody,
    evidence: &ConformanceEvidence,
) -> Result<(), Item> {
    let key_is_ps = |alg: u16, key: &[u8]| {
        alg == precommit.signature_alg() && key == precommit.claimant_public_key()
    };
    match precommit.parent_claim_ref() {
        ParentClaimRef::SingleRoot { claim_ref } => {
            let reference = precommit.parent_reference();
            let bytes = evidence
                .closure
                .get(&reference)
                .filter(|bytes| derive::claim_ref(bytes) == *claim_ref)
                .ok_or(Item::Missing(ConformanceMissing::ClosureObject(reference)))?;
            let claim =
                crate::economic::claim_envelope::decode_and_verify_economic_root_claim(bytes)
                    .map_err(|_| {
                        Item::Invalid(FulfillmentConformanceError::ParentClaimDoesNotVerify)
                    })?;
            let parent = claim.body();
            if parent.trader_genesis != *precommit.genesis()
                || parent.trader_devid != *precommit.device_id()
                || parent.economic_position != precommit.position()
                || parent.post_economic_root != *precommit.void_root()
            {
                return Err(Item::Invalid(
                    FulfillmentConformanceError::ParentClaimIsAnotherPosition,
                ));
            }
            if !key_is_ps(parent.signature_alg, &parent.claimant_public_key) {
                return Err(Item::Invalid(
                    FulfillmentConformanceError::KeyIsNotTheParentClaimants,
                ));
            }
            Ok(())
        }
        ParentClaimRef::Conditional { fulfillment_id } => {
            let parent = evidence
                .parent_fulfillment
                .as_ref()
                .filter(|f| derive::fulfillment_id(f) == *fulfillment_id)
                .ok_or(Item::Missing(ConformanceMissing::ParentFulfillment {
                    fulfillment_id: *fulfillment_id,
                }))?;
            if parent.position() != precommit.position() {
                return Err(Item::Invalid(
                    FulfillmentConformanceError::ParentClaimIsAnotherPosition,
                ));
            }
            if !key_is_ps(parent.signature_alg(), parent.claimant_public_key()) {
                return Err(Item::Invalid(
                    FulfillmentConformanceError::KeyIsNotTheParentClaimants,
                ));
            }
            Ok(())
        }
    }
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
    fn outcome(&mut self, item: u8, r: Result<(), Item>) {
        self.0.push((item, r.err().unwrap_or(Item::Valid)));
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
    items.outcome(1, parent_binds_the_key(precommit, evidence));
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
    // Item 1, P conformance rule 2: `𝒞_E^pre` carries the typed reference of
    // the parent P names, so E commits to it.
    if !preimage
        .settlement()
        .closure()
        .refs()
        .contains(&precommit.parent_reference())
    {
        items.invalid(1, FulfillmentConformanceError::ParentReferenceNotInClosure);
    }
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

/// The conformance items an exercise decides from its own bytes, before any
/// read (MR-DSM-0041, MR-DSM-0042): `P` and `F` and their signatures,
/// `P(E)`, the policy-fulfillment set, the attempts, and the closure objects
/// the exercise carries, in the preimage's reference order. `Some(reason)`
/// when one of them is Invalid: `F` does not conform whatever storage holds,
/// and nothing is fetched to know it. `None` when nothing in hand refutes
/// it; conformance is then decided over fetched evidence.
///
/// It is [`fulfillment_conformance`] over this evidence alone. Invalid
/// dominates whatever is missing, so an item that needs a fetch — a setup,
/// an earlier attempt key — never hides a refusal and never makes one.
pub fn conformance_invalid_in_hand(
    precommit: &PrecommitEnvelope,
    fulfillment: &TraderFulfillmentBody,
    fulfillment_signature: &[u8],
    preimage: &SettlementPreimage,
    carried_closure: &[Vec<u8>],
) -> Option<FulfillmentConformanceError> {
    let closure = preimage
        .settlement()
        .closure()
        .refs()
        .iter()
        .copied()
        .zip(carried_closure.iter().cloned())
        .collect();
    let in_hand = ConformanceEvidence {
        precommit: precommit.clone(),
        preimage: preimage.clone(),
        closure,
        setups: BTreeMap::new(),
        prior_attempts: BTreeMap::new(),
        parent_fulfillment: None,
    };
    match fulfillment_conformance(fulfillment, fulfillment_signature, &in_hand) {
        Ok(FulfillmentConformance::Invalid(why)) => Some(why),
        Ok(FulfillmentConformance::Valid) | Err(..) => None,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use std::sync::OnceLock;

    use super::Validation::{Invalid, Valid};
    use super::*;
    use crate::ccb::class;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::sofi::validation::fixtures::{
        policies, policy_addr, setup_body_for, setup_envelope_for, setup_ref_for,
        swap_fixture_with, swap_fixture_with_setups, trader_keys, vault_id_of, DEV, G, P_POS,
        SETUP_POS, SIG_ALG,
    };
    use crate::sofi::wire::{
        AttemptEntry, PreEClosureIndex, PrecommitLeg, SofiSetupBody, MAX_AUTH_ENVELOPES,
        MAX_CLOSURE_OBJECT_BYTES, MAX_VALIDATION_FETCH_BYTES,
    };

    #[test]
    fn invalid_dominates_the_conjunction() {
        assert_eq!(Valid.and(Valid), Valid);
        assert_eq!(Valid.and(Invalid), Invalid);
        assert_eq!(Invalid.and(Valid), Invalid);
        assert_eq!(Validation::all([Valid, Invalid, Valid]), Invalid);
        assert_eq!(Validation::all([]), Valid);
    }

    fn token(byte: u8) -> D32 {
        [byte; 32]
    }

    fn pk() -> &'static [u8] {
        &trader_keys().0
    }

    fn sk() -> &'static [u8] {
        &trader_keys().1
    }

    /// The whole operation, signed once: two legs, the trader's setups whose
    /// ρ the legs carry, a closure naming one object of every reference kind,
    /// P and F signed under the trader's key.
    struct Rig {
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

    /// A setup of vault `j` by `(genesis, device)` at `position`, under the
    /// trader's key.
    fn setup_at(j: usize, genesis: D32, device: D32, position: u64) -> SofiSetupBody {
        SofiSetupBody::new(
            genesis,
            device,
            position,
            vault_id_of(j),
            token(0xA0),
            token(0xB0),
            SIG_ALG,
            pk(),
        )
        .unwrap()
    }

    /// `base` with `legs`, under the trader's key.
    fn rebuild(base: &TraderPrecommitBody, legs: Vec<PrecommitLeg>) -> TraderPrecommitBody {
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
            pk(),
        )
        .unwrap()
    }

    fn sign_p(p: &TraderPrecommitBody) -> Vec<u8> {
        sphincs_sign(sk(), &derive::precommit_signing_digest(p)).unwrap()
    }

    fn sign_f(f: &TraderFulfillmentBody) -> Vec<u8> {
        sphincs_sign(sk(), &derive::fulfillment_signing_digest(f)).unwrap()
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

    /// `F` with every field of the rig's except `set`, `attempts`, `position`
    /// and the key, which the caller names.
    fn fulfillment_with(
        r: &Rig,
        set: Vec<D32>,
        attempts: Vec<AttemptEntry>,
        position: u64,
        key: &[u8],
    ) -> TraderFulfillmentBody {
        TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            set,
            attempts,
            position,
            SIG_ALG,
            key,
        )
        .unwrap()
    }

    fn build_rig() -> Rig {
        let setups: Vec<(D32, Vec<u8>)> = (0..2)
            .map(|j| {
                let vault = vault_id_of(j);
                (setup_ref_for(vault), setup_envelope_for(vault))
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
        let f = swap_fixture_with(2, PreEClosureIndex::new(refs).unwrap());
        // The fixture adds the single-root parent P names; the closure holds
        // its exact envelope under that reference.
        let mut closure = closure;
        closure.insert(f.precommit.parent_reference(), f.parent_claim.clone());
        let precommit = f.precommit;
        let precommit_sig = sign_p(&precommit);
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
        let fulfillment_sig = sign_f(&fulfillment);
        Rig {
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

    /// Everything in hand: P, P(E), every closure object, both setups, and
    /// the prior attempt key of the leg that exercises attempt 1, final.
    fn everything(r: &Rig) -> ConformanceEvidence {
        let second = r.precommit.legs()[1].vault_id;
        ConformanceEvidence {
            precommit: PrecommitEnvelope {
                body: r.precommit.clone(),
                signature: r.precommit_sig.clone(),
            },
            preimage: r.preimage.clone(),
            closure: r.closure.clone(),
            setups: r.setups.iter().cloned().collect(),
            prior_attempts: BTreeMap::from([(
                (second, 0),
                CellFact::Held {
                    id: r.e,
                    state: ChainState::Final,
                },
            )]),
            parent_fulfillment: None,
        }
    }

    fn conformance(
        r: &Rig,
        ev: &ConformanceEvidence,
    ) -> Result<FulfillmentConformance, ConformanceMissing> {
        fulfillment_conformance(&r.fulfillment, &r.fulfillment_sig, ev)
    }

    fn invalid(
        why: FulfillmentConformanceError,
    ) -> Result<FulfillmentConformance, ConformanceMissing> {
        Ok(FulfillmentConformance::Invalid(why))
    }

    // ── SoFi §18.4: a known bound violation is Invalid, from the evidence alone ──

    /// One closure object over `MAX_CLOSURE_OBJECT_BYTES` is Invalid by that
    /// bound, before any item is evaluated.
    #[test]
    fn a_closure_object_over_the_bound_is_invalid() {
        let r = rig();
        let mut ev = everything(r);
        let (reference, _) = ev
            .closure
            .iter()
            .next()
            .map(|(k, v)| (*k, v.clone()))
            .unwrap();
        let bytes = MAX_CLOSURE_OBJECT_BYTES + 1;
        ev.closure.insert(reference, vec![0u8; bytes]);
        assert_eq!(
            conformance(r, &ev),
            invalid(FulfillmentConformanceError::ClosureObjectTooLarge { bytes })
        );
        // Exactly at the bound, the object itself is not what refuses.
        let mut at = everything(r);
        at.closure
            .insert(reference, vec![0u8; MAX_CLOSURE_OBJECT_BYTES]);
        assert_ne!(
            conformance(r, &at),
            invalid(FulfillmentConformanceError::ClosureObjectTooLarge {
                bytes: MAX_CLOSURE_OBJECT_BYTES
            })
        );
    }

    /// Objects each within the per-object bound whose total exceeds
    /// `MAX_VALIDATION_FETCH_BYTES` are Invalid by the fetch bound. Setups
    /// outside the closure count toward it.
    #[test]
    fn a_validation_fetch_over_the_bound_is_invalid() {
        let r = rig();
        let mut ev = everything(r);
        // What the bound sums: every closure object, and every setup not
        // already among them.
        fn fetched(ev: &ConformanceEvidence) -> usize {
            ev.closure.values().map(Vec::len).sum::<usize>()
                + ev.setups
                    .iter()
                    .filter(|(r, _)| {
                        !ev.closure
                            .contains_key(&ValidationRef::Setup { setup_ref: **r })
                    })
                    .map(|(_, b)| b.len())
                    .sum::<usize>()
        }
        let each = MAX_CLOSURE_OBJECT_BYTES;
        let mut n = 0u8;
        while fetched(&ev) <= MAX_VALIDATION_FETCH_BYTES {
            n += 1;
            ev.setups.insert([n; 32], vec![0u8; each]);
        }
        let total = fetched(&ev);
        assert!(total > MAX_VALIDATION_FETCH_BYTES);
        assert_eq!(
            conformance(r, &ev),
            invalid(FulfillmentConformanceError::ValidationFetchTooLarge { bytes: total })
        );
    }

    /// The fulfillment, the precommit and one envelope per parent claim in
    /// the closure are the authenticated envelopes; more than
    /// `MAX_AUTH_ENVELOPES` of them is Invalid by that bound.
    #[test]
    fn too_many_auth_envelopes_is_invalid() {
        let r = rig();
        let mut ev = everything(r);
        let parents = ev
            .closure
            .keys()
            .filter(|k| {
                matches!(
                    k,
                    ValidationRef::SingleRootClaim { .. } | ValidationRef::ConditionalClaim { .. }
                )
            })
            .count();
        let mut added = 0usize;
        while 2 + parents + added <= MAX_AUTH_ENVELOPES {
            added += 1;
            ev.closure.insert(
                ValidationRef::SingleRootClaim {
                    claim_ref: [added as u8; 32],
                },
                vec![0u8; 8],
            );
        }
        let envelopes = 2 + parents + added;
        assert_eq!(
            conformance(r, &ev),
            invalid(FulfillmentConformanceError::TooManyAuthEnvelopes { envelopes })
        );
    }

    #[test]
    fn a_fulfillment_with_everything_in_hand_is_valid() {
        let r = rig();
        assert_eq!(
            conformance(r, &everything(r)),
            Ok(FulfillmentConformance::Valid)
        );
        assert_eq!(
            conformance(r, &everything(r)).map(|c| c.verdict()),
            Ok(Valid)
        );
    }

    #[test]
    fn item_1_the_referenced_p_verifies_and_q_is_its_successor() {
        let r = rig();
        // Not the P F names: a different leg set gives a different
        // PrecommitId. That is nothing about P, not a refusal.
        let mut ev = everything(r);
        let mut legs = r.precommit.legs().to_vec();
        legs[0].parent_root = token(0x99);
        ev.precommit = PrecommitEnvelope {
            body: rebuild(&r.precommit, legs),
            signature: r.precommit_sig.clone(),
        };
        assert_eq!(conformance(r, &ev), Err(ConformanceMissing::Precommit));
        // The right P in a copy whose envelope does not verify: another
        // envelope may, so this is missing, not invalid.
        let mut ev = everything(r);
        ev.precommit.signature = r.fulfillment_sig.clone();
        assert_eq!(
            conformance(r, &ev),
            Err(ConformanceMissing::PrecommitSignature)
        );
        let mut ev = everything(r);
        ev.precommit.signature.clear();
        assert_eq!(
            conformance(r, &ev),
            Err(ConformanceMissing::PrecommitSignature)
        );
        // q ≠ p + 1 is a fact about F.
        let f = fulfillment_with(
            r,
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment.attempts().to_vec(),
            r.precommit.position() + 2,
            pk(),
        );
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&f), &everything(r)),
            invalid(FulfillmentConformanceError::PositionNotSuccessor {
                expected: r.precommit.position() + 1,
                got: r.precommit.position() + 2,
            })
        );
    }

    // ── Item 1: P's key binds to the parent claim (P conformance 2, 3, 8) ──

    /// A root claim of the fixture trader at `position` over `root`, naming
    /// the manifest `manifest`, signed under `(pk, sk)`.
    fn root_claim(position: u64, root: D32, manifest: D32, pk: &[u8], sk: &[u8]) -> Vec<u8> {
        root_claim_of(G, DEV, position, root, manifest, pk, sk)
    }

    /// The same claim, naming the trader `(genesis, device)`.
    fn root_claim_of(
        genesis: D32,
        device: D32,
        position: u64,
        root: D32,
        manifest: D32,
        pk: &[u8],
        sk: &[u8],
    ) -> Vec<u8> {
        let body = crate::economic::claim::EconomicRootClaimBody::new(
            genesis,
            device,
            position,
            root,
            manifest,
            token(0x77),
            SIG_ALG,
            pk,
        )
        .unwrap();
        crate::economic::claim_envelope::sign_economic_root_claim(&body, sk).unwrap()
    }

    /// The root every one-hop fixture's P voids to: its trader tree's.
    fn one_hop_root() -> D32 {
        *crate::sofi::validation::fixtures::swap_fixture_n(1)
            .precommit
            .void_root()
    }

    /// A one-hop operation whose `𝒞_E^pre` also references `extra`, and the
    /// closure objects in hand: `extra` and the fixture's own parent claim.
    fn one_hop_with(
        extra: BTreeMap<ValidationRef, Vec<u8>>,
    ) -> (
        crate::sofi::validation::fixtures::Fixture,
        BTreeMap<ValidationRef, Vec<u8>>,
    ) {
        let mut refs: Vec<ValidationRef> = extra.keys().copied().collect();
        refs.sort_by_key(ValidationRef::encode);
        let f = swap_fixture_with(1, PreEClosureIndex::new(refs).unwrap());
        let mut closure = extra;
        closure.insert(f.precommit.parent_reference(), f.parent_claim.clone());
        (f, closure)
    }

    /// `f`'s P naming `parent` under `(pk, sk)`, its canonical F at attempt 0
    /// signed under the same key, and everything in hand.
    fn exercised(
        f: &crate::sofi::validation::fixtures::Fixture,
        closure: BTreeMap<ValidationRef, Vec<u8>>,
        parent: ParentClaimRef,
        pk: &[u8],
        sk: &[u8],
    ) -> (TraderFulfillmentBody, Vec<u8>, ConformanceEvidence) {
        let base = &f.precommit;
        let precommit = TraderPrecommitBody::new(
            *base.genesis(),
            *base.device_id(),
            base.position(),
            parent,
            *base.external_commitment(),
            base.legs().to_vec(),
            *base.realize_root(),
            *base.void_root(),
            *base.storage_set_id(),
            SIG_ALG,
            pk,
        )
        .unwrap();
        let p_sig = sphincs_sign(sk, &derive::precommit_signing_digest(&precommit)).unwrap();
        let attempts: Vec<AttemptEntry> = precommit
            .legs()
            .iter()
            .map(|leg| AttemptEntry {
                vault_id: leg.vault_id,
                attempt: 0,
            })
            .collect();
        let fulfillment = fulfillment_of(&precommit, &f.preimage, attempts);
        let f_sig = sphincs_sign(sk, &derive::fulfillment_signing_digest(&fulfillment)).unwrap();
        let vault = vault_id_of(0);
        let evidence = ConformanceEvidence {
            precommit: PrecommitEnvelope {
                body: precommit,
                signature: p_sig,
            },
            preimage: f.preimage.clone(),
            closure,
            setups: BTreeMap::from([(setup_ref_for(vault), setup_envelope_for(vault))]),
            prior_attempts: BTreeMap::new(),
            parent_fulfillment: None,
        };
        (fulfillment, f_sig, evidence)
    }

    fn own_parent(f: &crate::sofi::validation::fixtures::Fixture) -> ParentClaimRef {
        *f.precommit.parent_claim_ref()
    }

    /// MR-SOFI-0151, P conformance rule 8: a P that names the trader's
    /// registered claim but is signed under any other key does not conform,
    /// though P, F and every setup verify under the key P commits. Under the
    /// claim's own key the same operation conforms.
    #[test]
    fn a_precommit_under_a_key_its_parent_claim_does_not_carry_does_not_conform() {
        let (f, closure) = one_hop_with(BTreeMap::new());
        let (other_pk, other_sk) = generate_sphincs_keypair().unwrap();
        let (fb, f_sig, ev) = exercised(&f, closure.clone(), own_parent(&f), &other_pk, &other_sk);
        assert_eq!(
            fulfillment_conformance(&fb, &f_sig, &ev),
            invalid(FulfillmentConformanceError::KeyIsNotTheParentClaimants)
        );
        let (fb, f_sig, ev) = exercised(&f, closure, own_parent(&f), pk(), sk());
        assert_eq!(
            fulfillment_conformance(&fb, &f_sig, &ev),
            Ok(FulfillmentConformance::Valid)
        );
    }

    /// P conformance rules 2 and 3: a claim under the trader's key that names
    /// another genesis, device, position or root is not the parent P extends.
    #[test]
    fn a_parent_claim_of_another_position_or_root_does_not_conform() {
        let root = one_hop_root();
        for claim in [
            root_claim_of(token(0x12), DEV, P_POS, root, token(0x78), pk(), sk()),
            root_claim_of(G, token(0x23), P_POS, root, token(0x78), pk(), sk()),
            root_claim(P_POS + 1, root, token(0x78), pk(), sk()),
            root_claim(P_POS, token(0x5A), token(0x78), pk(), sk()),
        ] {
            let reference = ValidationRef::SingleRootClaim {
                claim_ref: derive::claim_ref(&claim),
            };
            let (f, closure) = one_hop_with(BTreeMap::from([(reference, claim.clone())]));
            let parent = ParentClaimRef::SingleRoot {
                claim_ref: derive::claim_ref(&claim),
            };
            let (fb, f_sig, ev) = exercised(&f, closure, parent, pk(), sk());
            assert_eq!(
                fulfillment_conformance(&fb, &f_sig, &ev),
                invalid(FulfillmentConformanceError::ParentClaimIsAnotherPosition)
            );
        }
    }

    /// Bytes at the `claim_ref` P names that are not a claim, or a claim
    /// whose signature does not verify, bind P to nothing.
    #[test]
    fn a_parent_that_is_not_a_verifying_claim_does_not_conform() {
        let mut tampered = root_claim(P_POS, one_hop_root(), token(0x78), pk(), sk());
        // The signature is the envelope's last field: its last byte flipped
        // leaves a claim that decodes and does not verify.
        *tampered.last_mut().unwrap() ^= 0x01;
        for bytes in [b"not a claim".to_vec(), tampered] {
            let reference = ValidationRef::SingleRootClaim {
                claim_ref: derive::claim_ref(&bytes),
            };
            let (f, closure) = one_hop_with(BTreeMap::from([(reference, bytes.clone())]));
            let parent = ParentClaimRef::SingleRoot {
                claim_ref: derive::claim_ref(&bytes),
            };
            let (fb, f_sig, ev) = exercised(&f, closure, parent, pk(), sk());
            assert_eq!(
                fulfillment_conformance(&fb, &f_sig, &ev),
                invalid(FulfillmentConformanceError::ParentClaimDoesNotVerify)
            );
        }
    }

    /// P conformance rule 2: a parent `𝒞_E^pre` does not reference is not the
    /// parent E commits to, even when its claim is in hand and binds. A parent
    /// the closure references but whose bytes are not in hand is missing.
    #[test]
    fn a_parent_the_closure_does_not_reference_does_not_conform() {
        let (f, closure) = one_hop_with(BTreeMap::new());
        let elsewhere = root_claim(P_POS, one_hop_root(), token(0x79), pk(), sk());
        let reference = ValidationRef::SingleRootClaim {
            claim_ref: derive::claim_ref(&elsewhere),
        };
        let parent = ParentClaimRef::SingleRoot {
            claim_ref: derive::claim_ref(&elsewhere),
        };
        let (fb, f_sig, mut ev) = exercised(&f, closure.clone(), parent, pk(), sk());
        ev.closure.insert(reference, elsewhere);
        assert_eq!(
            fulfillment_conformance(&fb, &f_sig, &ev),
            invalid(FulfillmentConformanceError::ParentReferenceNotInClosure)
        );

        let (fb, f_sig, mut ev) = exercised(&f, closure, own_parent(&f), pk(), sk());
        let own = f.precommit.parent_reference();
        ev.closure.remove(&own);
        assert_eq!(
            fulfillment_conformance(&fb, &f_sig, &ev),
            Err(ConformanceMissing::ClosureObject(own))
        );
    }

    /// The parent `F` at `P_POS` under `pk`, and the conditional claim `C_p`
    /// its position installed.
    fn conditional_parent(
        position: u64,
        pk: &[u8],
    ) -> (TraderFulfillmentBody, ValidationRef, Vec<u8>) {
        let parent = TraderFulfillmentBody::new(
            token(0x31),
            vec![token(0x32)],
            vec![AttemptEntry {
                vault_id: token(0x33),
                attempt: 0,
            }],
            position,
            SIG_ALG,
            pk,
        )
        .unwrap();
        let fulfillment_id = derive::fulfillment_id(&parent);
        let claim = SofiResolutionClaim {
            genesis: G,
            device_id: DEV,
            position: P_POS,
            fulfillment_id,
            realize_root: token(0x34),
            void_root: token(0x35),
        };
        let reference = ValidationRef::ConditionalClaim {
            genesis: G,
            device_id: DEV,
            position: P_POS,
            fulfillment_id,
        };
        (parent, reference, claim.encode())
    }

    /// P conformance rule 8 for a conditional parent: `C_p` carries no key,
    /// so P's key is the key of the `F` whose id P names — in hand, or the
    /// item is missing; another key, or an `F` at another position, does not
    /// conform. An `F` that is not the one P names binds nothing, whatever
    /// key it carries.
    #[test]
    fn a_conditional_parent_binds_p_to_the_key_of_the_f_that_installed_it() {
        let (other_pk, _) = generate_sphincs_keypair().unwrap();
        let case = |named: &TraderFulfillmentBody,
                    in_hand: Option<&TraderFulfillmentBody>,
                    reference,
                    claim: Vec<u8>| {
            let (f, closure) = one_hop_with(BTreeMap::from([(reference, claim)]));
            let parent = ParentClaimRef::Conditional {
                fulfillment_id: derive::fulfillment_id(named),
            };
            let (fb, f_sig, mut ev) = exercised(&f, closure, parent, pk(), sk());
            ev.parent_fulfillment = in_hand.cloned();
            fulfillment_conformance(&fb, &f_sig, &ev)
        };

        let (ours, reference, claim) = conditional_parent(P_POS, pk());
        assert_eq!(
            case(&ours, Some(&ours), reference, claim.clone()),
            Ok(FulfillmentConformance::Valid)
        );
        assert_eq!(
            case(&ours, None, reference, claim),
            Err(ConformanceMissing::ParentFulfillment {
                fulfillment_id: derive::fulfillment_id(&ours)
            })
        );
        let (theirs, reference, claim) = conditional_parent(P_POS, &other_pk);
        assert_eq!(
            case(&theirs, Some(&theirs), reference, claim.clone()),
            invalid(FulfillmentConformanceError::KeyIsNotTheParentClaimants)
        );
        // P names their F; an F of ours at the same position is not it.
        let substitute = TraderFulfillmentBody::new(
            token(0x3F),
            ours.policy_fulfillment_set().to_vec(),
            ours.attempts().to_vec(),
            P_POS,
            SIG_ALG,
            pk(),
        )
        .unwrap();
        assert_eq!(
            case(&theirs, Some(&substitute), reference, claim),
            Err(ConformanceMissing::ParentFulfillment {
                fulfillment_id: derive::fulfillment_id(&theirs)
            })
        );
        let (elsewhere, reference, claim) = conditional_parent(P_POS + 1, pk());
        assert_eq!(
            case(&elsewhere, Some(&elsewhere), reference, claim),
            invalid(FulfillmentConformanceError::ParentClaimIsAnotherPosition)
        );
    }

    /// The exercise's own bytes, with nothing fetched: the closure objects in
    /// the preimage's reference order.
    fn carried(r: &Rig) -> Vec<Vec<u8>> {
        r.preimage
            .settlement()
            .closure()
            .refs()
            .iter()
            .map(|reference| r.closure[reference].clone())
            .collect()
    }

    /// MR-DSM-0041: an item decidable from the exercise refuses it with
    /// nothing fetched; a conforming exercise has nothing refuted in hand,
    /// though its setups and earlier keys are not.
    #[test]
    fn what_the_exercise_decides_alone_is_decided_before_any_read() {
        let r = rig();
        let envelope = PrecommitEnvelope {
            body: r.precommit.clone(),
            signature: r.precommit_sig.clone(),
        };
        assert_eq!(
            conformance_invalid_in_hand(
                &envelope,
                &r.fulfillment,
                &r.fulfillment_sig,
                &r.preimage,
                &carried(r)
            ),
            None
        );
        let f = fulfillment_with(
            r,
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment.attempts().to_vec(),
            r.precommit.position() + 2,
            pk(),
        );
        assert_eq!(
            conformance_invalid_in_hand(&envelope, &f, &sign_f(&f), &r.preimage, &carried(r)),
            Some(FulfillmentConformanceError::PositionNotSuccessor {
                expected: r.precommit.position() + 1,
                got: r.precommit.position() + 2,
            })
        );
        assert_eq!(
            conformance_invalid_in_hand(&envelope, &r.fulfillment, &[], &r.preimage, &carried(r)),
            Some(FulfillmentConformanceError::FulfillmentUnsigned)
        );
    }

    #[test]
    fn item_2_f_is_signed_under_the_key_p_committed() {
        let r = rig();
        let ev = everything(r);
        assert_eq!(
            fulfillment_conformance(&r.fulfillment, &[], &ev),
            invalid(FulfillmentConformanceError::FulfillmentUnsigned)
        );
        assert_eq!(
            fulfillment_conformance(&r.fulfillment, &r.precommit_sig, &ev),
            invalid(FulfillmentConformanceError::FulfillmentDoesNotVerify)
        );
        // Signed, and verifying, under a key that is not the one P committed.
        let (other_pk, other_sk) = generate_sphincs_keypair().unwrap();
        let f = fulfillment_with(
            r,
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment.attempts().to_vec(),
            r.fulfillment.position(),
            &other_pk,
        );
        let other_sig = sphincs_sign(&other_sk, &derive::fulfillment_signing_digest(&f)).unwrap();
        assert_eq!(
            fulfillment_conformance(&f, &other_sig, &ev),
            invalid(FulfillmentConformanceError::KeyMismatch)
        );
    }

    #[test]
    fn item_3_the_policy_fulfillment_set_is_the_canonical_set_of_p() {
        let r = rig();
        let ev = everything(r);
        let ids = r.fulfillment.policy_fulfillment_set().to_vec();
        let with_set = |set: Vec<D32>| {
            let f = fulfillment_with(
                r,
                set,
                r.fulfillment.attempts().to_vec(),
                r.fulfillment.position(),
                pk(),
            );
            fulfillment_conformance(&f, &sign_f(&f), &ev)
        };
        let refused = invalid(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical);
        // A subset, an extra entry, and an id not derived from P.
        assert_eq!(with_set(vec![ids[0]]), refused);
        let mut extra = ids.clone();
        extra.push(token(0xFF));
        extra.sort();
        assert_eq!(with_set(extra), refused);
        assert_eq!(with_set(vec![token(0x01), token(0x02)]), refused);
    }

    #[test]
    fn item_4_the_attempts_cover_exactly_the_legs_of_p_with_no_holes() {
        let r = rig();
        let ev = everything(r);
        let with_attempts = |attempts: Vec<AttemptEntry>| {
            let f = fulfillment_with(
                r,
                r.fulfillment.policy_fulfillment_set().to_vec(),
                attempts,
                r.fulfillment.position(),
                pk(),
            );
            fulfillment_conformance(&f, &sign_f(&f), &ev)
        };
        let refused = invalid(FulfillmentConformanceError::AttemptsDoNotCoverLegs);
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
    fn item_5_an_earlier_attempt_must_be_final() {
        let r = rig();
        let second = r.precommit.legs()[1].vault_id;
        let waits = Err(ConformanceMissing::PriorAttempt {
            vault_id: second,
            attempt: 0,
        });
        // Not read.
        let mut ev = everything(r);
        ev.prior_attempts.clear();
        assert_eq!(conformance(r, &ev), waits);
        // Read, and open: no key ever dies, so this waits.
        ev.prior_attempts.insert((second, 0), CellFact::Open);
        assert_eq!(conformance(r, &ev), waits);
        // Held but not final: not yet permanent.
        for state in [ChainState::LeaderHeld, ChainState::Preserved] {
            ev.prior_attempts.insert(
                (second, 0),
                CellFact::Held {
                    id: token(0x77),
                    state,
                },
            );
            assert_eq!(conformance(r, &ev), waits, "{state:?}");
        }
        // Final on ANOTHER operation's E is a permanent resolution too: the
        // earlier key was lost, which is exactly why F skipped past it.
        ev.prior_attempts.insert(
            (second, 0),
            CellFact::Held {
                id: token(0x77),
                state: ChainState::Final,
            },
        );
        assert_eq!(conformance(r, &ev), Ok(FulfillmentConformance::Valid));
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
            fulfillment_conformance(&f, &sign_f(&f), &ev),
            Ok(FulfillmentConformance::Valid)
        );
    }

    #[test]
    fn item_6_setup_registered_holds_for_every_leg() {
        let r = rig();
        let rho_1 = r.setups[1].0;
        let missing = Err(ConformanceMissing::Setup { setup_ref: rho_1 });
        // Not held.
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
        // ρ, and the body is held under it, so the only question left is
        // whether it is the setup of this trader for this vault, made before
        // the operation.
        let with_hop_0_setup = |body: SofiSetupBody| {
            let rho = derive::setup_ref(&body);
            let bent = swap_fixture_with_setups(
                2,
                &|j| {
                    if j == 0 {
                        body.clone()
                    } else {
                        setup_body_for(vault_id_of(j))
                    }
                },
                r.preimage.settlement().closure().clone(),
            );
            let p = bent.precommit;
            let f = fulfillment_of(&p, &bent.preimage, r.fulfillment.attempts().to_vec());
            let mut ev = everything(r);
            ev.precommit = PrecommitEnvelope {
                signature: sign_p(&p),
                body: p,
            };
            ev.preimage = bent.preimage;
            ev.setups = bent.evidence.setups;
            (rho, fulfillment_conformance(&f, &sign_f(&f), &ev))
        };
        // Another trader's setup of this vault.
        let (rho, verdict) = with_hop_0_setup(setup_at(0, token(0x33), DEV, SETUP_POS));
        assert_eq!(
            verdict,
            invalid(FulfillmentConformanceError::SetupNamesAnotherTraderOrVault { setup_ref: rho })
        );
        // This trader's setup of another vault.
        let (rho, verdict) = with_hop_0_setup(setup_at(1, G, DEV, SETUP_POS));
        assert_eq!(
            verdict,
            invalid(FulfillmentConformanceError::SetupNamesAnotherTraderOrVault { setup_ref: rho })
        );
        // The right setup, at the operation's own position: not before it.
        let (rho, verdict) = with_hop_0_setup(setup_at(0, G, DEV, P_POS));
        assert_eq!(
            verdict,
            invalid(FulfillmentConformanceError::SetupNotBeforeTheOperation { setup_ref: rho })
        );
        // And the bound is strict on the right side: one position before is
        // fine, which the rig itself shows.
        assert_eq!(SETUP_POS + 1, P_POS);
        assert_eq!(
            conformance(r, &everything(r)),
            Ok(FulfillmentConformance::Valid)
        );
        // P's legs are not what P(E) derives: same E, another parent root.
        let mut legs = r.precommit.legs().to_vec();
        legs[1].parent_root = token(0x5A);
        let p = rebuild(&r.precommit, legs);
        let f = fulfillment_of(&p, &r.preimage, r.fulfillment.attempts().to_vec());
        let mut ev = everything(r);
        ev.precommit = PrecommitEnvelope {
            signature: sign_p(&p),
            body: p,
        };
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&f), &ev),
            invalid(FulfillmentConformanceError::LegsDoNotMatchPreimage)
        );
    }

    #[test]
    fn item_8_the_preimage_and_closure_verify() {
        let r = rig();
        // A preimage of another E: not P(E), nothing about P.
        let other = swap_fixture_with(2, PreEClosureIndex::new(Vec::new()).unwrap());
        assert_ne!(derive::recompute_e(&other.preimage).unwrap(), r.e);
        let mut ev = everything(r);
        ev.preimage = other.preimage;
        assert_eq!(conformance(r, &ev), Err(ConformanceMissing::Preimage));
        // Every kind of closure reference: withheld, then wrong bytes.
        for reference in r.preimage.settlement().closure().refs() {
            let missing = Err(ConformanceMissing::ClosureObject(*reference));
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
        let bent = swap_fixture_with(2, PreEClosureIndex::new(refs).unwrap());
        let p = bent.precommit;
        let f = fulfillment_of(&p, &bent.preimage, r.fulfillment.attempts().to_vec());
        let mut ev = everything(r);
        ev.precommit = PrecommitEnvelope {
            signature: sign_p(&p),
            body: p,
        };
        ev.preimage = bent.preimage;
        ev.closure.insert(
            ValidationRef::ContentAddr {
                object_class: 0x7777,
                addr: token(0x01),
            },
            b"anything".to_vec(),
        );
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&f), &ev),
            invalid(
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
    fn invalid_dominates_missing_in_item_order() {
        let r = rig();
        let mut legs = r.precommit.legs().to_vec();
        legs[0].parent_root = token(0x99);
        let mut another_p = everything(r);
        another_p.precommit = PrecommitEnvelope {
            body: rebuild(&r.precommit, legs),
            signature: r.precommit_sig.clone(),
        };
        // Unsigned F and not its P in hand: item 2 refuses over item 1.
        assert_eq!(
            fulfillment_conformance(&r.fulfillment, &[], &another_p),
            invalid(FulfillmentConformanceError::FulfillmentUnsigned)
        );
        // A signed F without its P in hand: everything waits on P.
        assert_eq!(
            conformance(r, &another_p),
            Err(ConformanceMissing::Precommit)
        );
        // P in hand, a hole in the attempts, and P(E) not the one E names:
        // item 4 refuses over item 8's missing object.
        let mut ev = everything(r);
        ev.preimage = swap_fixture_with(2, PreEClosureIndex::new(Vec::new()).unwrap()).preimage;
        let hole = vec![AttemptEntry {
            vault_id: r.precommit.legs()[0].vault_id,
            attempt: 0,
        }];
        let f = fulfillment_with(
            r,
            r.fulfillment.policy_fulfillment_set().to_vec(),
            hole.clone(),
            r.fulfillment.position(),
            pk(),
        );
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&f), &ev),
            invalid(FulfillmentConformanceError::AttemptsDoNotCoverLegs)
        );
        // Two refusals: the earlier item's reason is the one reported.
        let f = fulfillment_with(r, vec![token(0x01)], hole, r.fulfillment.position(), pk());
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&f), &everything(r)),
            invalid(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical)
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
        let f = fulfillment_with(
            r,
            extra,
            r.fulfillment.attempts().to_vec(),
            r.fulfillment.position(),
            pk(),
        );
        let structural = check_fulfillment_against_precommit(&r.precommit, &f, &shadows);
        assert_eq!(
            structural,
            Err(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical)
        );
        assert_eq!(
            fulfillment_conformance(&f, &sign_f(&f), &everything(r)),
            invalid(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical)
        );
    }
}
