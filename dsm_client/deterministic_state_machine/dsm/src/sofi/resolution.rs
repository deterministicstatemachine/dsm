// SPDX-License-Identifier: Apache-2.0

//! The verifier-local resolution core: facts in, one permanent answer out.
//!
//! Every function here is pure and total over the facts it is handed. It
//! fetches nothing, trusts no caller's opinion, and evaluates no policy: a
//! fact is either an objective storage observation ([`CellFact`]), a
//! static validity verdict ([`Validation`]), or a monotone register fact
//! (registration, canonicality, orphaning). Where those facts come
//! from is E2's and E3's business.
//!
//! ## What it decides
//!
//! - one trader position's result — [`resolve_position`], the F2 ladder;
//! - whether the route was actually consumed — [`consumed_route`];
//! - whether it can never be — [`fulfillment_impossible`]: conformance, then
//!   [`route_impossible`], the four arms;
//! - which DLV successor keys may be skipped — [`classify_attempt`] and
//!   [`walk`].
//!
//! ## Two things that are not the same
//!
//! `Invalid` means the operation never satisfied the DLV or protocol rules.
//! `Void` means a valid operation that could not execute — it lost contention
//! or became impossible. So validity is established BEFORE Void is declared,
//! and a position never moves `Void → Invalid` (R14-1). Core resolves only
//! over complete facts (Amendment S7); until they are complete the position
//! is not resolved at all.
//!
//! One `FinalE(E)` cell is not one executed swap. A route realizes only when
//! every required leg consumes its exact parent under one registered
//! fulfillment, which is why [`consumed_route`] quantifies over all legs.
//!
//! Registration supplies no truth value: `FulfillmentConformance(F)` is a
//! conjunct of [`consumed_route`] and rung 2 of the ladder (rebuild step
//! R12), so a registered `F` that never conformed is Invalid — never Void,
//! never Realized.

use crate::route_chain::{CellFact, ChainState};
use super::conformance::Validation;
use super::wire::next_attempt;

/// What a verifier has established about the predecessor position `p` that `P`
/// names as its trader parent `T0`.
///
/// A trader may build `P` on a conditional parent before that parent resolves,
/// because the storage fence only requires `p` to be storage-resolved; the
/// branch it guessed is decided here, not at ingress. Resolving `q` needs `p`
/// resolved: the SDK resolves the parent first as part of acquiring `q`'s
/// facts, and when its retries are exhausted the attempt fails on the network
/// (Amendment S7). An unresolved parent is never a fact Core is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentPosition {
    /// `T0` is an ordinary single-root claim. P conformance already bound
    /// `T°.pre_root` to that exact registered root at ingress.
    SingleRoot,
    /// `C_p` resolved and selected this root: `R_realize` when `p` realized,
    /// `R_void` when it voided.
    ConditionalSelected { selected_root: [u8; 32] },
    /// `C_p` resolved Invalid, so no root was ever selected. Terminal.
    ConditionalNoRoot,
}

/// A trader-position result. Every one is permanent (Amendment S7). Core
/// resolves only over complete storage facts: until they are complete the
/// SDK keeps reading and relaying, and when its retries are exhausted the
/// attempt fails on the network. That is never a resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The route consumed every required parent under this fulfillment.
    Realized,
    /// A valid operation that could not execute. Terminal.
    Void,
    /// The operation never satisfied the rules. Terminal.
    Invalid,
}

/// What the position does to the trader's economic lineage once it resolves.
/// `Void` installs the previous validated root and mutates nothing of its own
/// — that is all "SofiVoid has zero mutations" means. `advance_resolved`
/// (E1b-5) is the only constructor that acts on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionEffect {
    /// Install `P.realize_root`.
    InstallRealizeRoot,
    /// Install the previous validated root: no mutation of its own.
    InstallPreviousRoot,
    /// Nothing is installed, now or ever.
    None,
}

/// The effect of a resolved position. Invalid never has one, because the
/// lineage is terminal there.
pub fn effect_of(resolution: Resolution) -> PositionEffect {
    match resolution {
        Resolution::Realized => PositionEffect::InstallRealizeRoot,
        Resolution::Void => PositionEffect::InstallPreviousRoot,
        Resolution::Invalid => PositionEffect::None,
    }
}

/// What a verifier has established about the parent `(v, g, R)` a leg names,
/// against `R*_g` — the validated canonical root of that vault at that
/// generation (owner ruling, Section 44.4).
///
/// Three valued, and "not established" is not `false`: a parent the verifier
/// has not walked to leaves the position unresolved, and a parent it has
/// walked past defeats it. No value is both canonical and orphaned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentStatus {
    /// `R = R*_g`. The leg names the root that vault's lineage took.
    Canonical,
    /// `R ≠ R*_g`. That generation went to another root, so this parent is
    /// permanently refuted and no later evidence restores it.
    Orphaned,
    /// `R*_g` has not been established. A parent the verifier has not reached
    /// is not thereby refuted, and nothing here is a reason to decide.
    Unavailable,
}

/// The status of the parent `(v, g, R)` a leg names, decided against the one
/// fact that can decide it: `R*_g`, the canonical root this verifier itself
/// established for that vault at that generation.
///
/// `established` is `Some(R*_g)` when the verifier's chain for `v` reaches
/// generation `g`, and `None` when it does not. Nothing else is consulted,
/// because nothing else can settle it.
///
/// **ABSENCE NEVER REFUTES.** The tempting rule — a root the chain does not
/// name is orphaned — is wrong, and wrong in the direction that costs the
/// most. A vault's head is open precisely so that the NEXT root can still
/// arrive, so a root missing from a chain may be one an in-flight operation
/// is about to realize. Refuting it answers `Orphaned`, which is a
/// `RouteImpossible` arm and therefore a permanent `Void`, against a route
/// whose only defect is that this verifier looked early. That is the
/// unknown-as-verdict failure `ParentStatus` exists to remove, one layer up.
///
/// Only a DIFFERENT root at the SAME generation refutes, and that refutation
/// is permanent: `R*_g` is unique and never changes once established, because
/// a successor cell admits at most one realized consumption per attempt key
/// (`OneConsumerPerParent`, model-checked across crash and recover in
/// `tla/DSM_SofiSuccessorCells.tla`). So this decision inherits its
/// uniqueness from the storage layer and needs no argument of its own.
pub fn parent_status(established: Option<[u8; 32]>, claimed: &[u8; 32]) -> ParentStatus {
    match established {
        Some(root) if root == *claimed => ParentStatus::Canonical,
        Some(..) => ParentStatus::Orphaned,
        None => ParentStatus::Unavailable,
    }
}

/// The canonical roots a verifier established for one vault, in generation
/// order: `roots[g]` is `R*_g`.
///
/// Contiguous from generation zero, because the generation of a root is its
/// POSITION here. A gap would shift every generation after it and turn a
/// correct parent into a refuted one, so the builder stops at the first gap
/// rather than recording past it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultChain {
    pub roots: Vec<[u8; 32]>,
}

impl VaultChain {
    /// The status of a parent asked about at `generation` — [`parent_status`]
    /// over what this chain established there.
    pub fn status_of(&self, generation: u64, claimed: &[u8; 32]) -> ParentStatus {
        let established = usize::try_from(generation)
            .ok()
            .and_then(|g| self.roots.get(g))
            .copied();
        parent_status(established, claimed)
    }

    /// Whether this chain names `root` at any generation.
    ///
    /// POSITIVE EVIDENCE ONLY. Naming it establishes `Canonical`; not naming
    /// it establishes NOTHING, because the chain may simply be short. Callers
    /// use this where a root has to be established before something else can
    /// proceed, never to refute one.
    pub fn names(&self, root: &[u8; 32]) -> bool {
        self.roots.contains(root)
    }

    /// The generation `root` sits at, when this chain names it.
    pub fn generation_of(&self, root: &[u8; 32]) -> Option<u64> {
        self.roots.iter().position(|r| r == root).map(|g| g as u64)
    }

    /// The highest generation this chain established.
    pub fn head(&self) -> Option<(u64, [u8; 32])> {
        self.roots
            .last()
            .map(|r| ((self.roots.len() - 1) as u64, *r))
    }
}

/// The facts about one DLV leg of a registered fulfillment, at the attempt key
/// that fulfillment fixed for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegFacts {
    /// The storage resolution of `K^(a_j)`.
    pub cell: CellFact,
    /// The named parent `R_j` against this vault's validated canonical root
    /// at that generation.
    pub parent: ParentStatus,
    /// `∀ b < a_j. Skipped(K^(b))`.
    pub attempt_live: bool,
    /// The named parent was consumed by some `X ≠ E`. A parent that really
    /// was canonical and was then taken is THIS, never orphaning.
    pub parent_consumed_elsewhere: bool,
}

impl LegFacts {
    /// The leg's cell holds exactly `e`, finally.
    ///
    /// The commitment is the ROUTE's, never the leg's: one operation is bound
    /// to one `E`, and every required leg must be final on that same one. A
    /// per-leg commitment would let a "route" be assembled out of legs that
    /// each finalized a different operation.
    pub fn final_on(&self, e: &[u8; 32]) -> bool {
        self.cell
            == CellFact::Held {
                id: *e,
                state: ChainState::Final,
            }
    }

    /// Some OTHER operation's commitment holds this key's leader link, final or
    /// not. Either way this operation can never be final at the key: at most
    /// one value has a valid leader link at a cell (storage spec §9).
    pub fn final_on_other(&self, e: &[u8; 32]) -> bool {
        matches!(self.cell, CellFact::Held { id, .. } if id != *e)
    }
}

/// Everything a verifier needs about one trader position `q` and the
/// fulfillment `F` that claims it.
///
/// `parent_pre_root` is `P.void_root`, which P15-2 pins to `T°.pre_root`: the
/// root this operation was built on, and the root the parent must have
/// selected for the guessed branch to be the taken one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteFacts<'legs> {
    /// `E` — the ONE external commitment this operation is bound to. Every
    /// required leg must be final on exactly this value.
    pub external_commitment: [u8; 32],
    /// `FulfillmentRegistered(q, F)` — the exercise boundary.
    pub registered: bool,
    /// `FulfillmentConformance(F)` (Section 20.2), as the ladder reads it.
    /// Registration supplies no truth value for it: a registered `F` may be
    /// `Invalid`, and a producer's pre-sign check is not this verifier's.
    pub conformance: Validation,
    /// Arm (v) of `RouteImpossible` (Section 23.5): position `q` already
    /// holds a different claim — an ordinary transition, or another
    /// fulfillment of the same trader naming other attempt keys — so this
    /// `F` can never register (Section 21.1). Read from the position pair
    /// (R10); never true together with `registered`.
    pub position_lost: bool,
    /// What is known about the claim at `p`.
    pub parent: ParentPosition,
    /// `P.void_root == T°.pre_root`.
    pub parent_pre_root: [u8; 32],
    /// `RouteValidation(P, G, E)`, static.
    pub validation: Validation,
    /// `StorageResolved(q)`: registration and every successor key.
    pub storage_resolved: bool,
    /// One entry per leg of `P`, in P's leg order. A single-vault trade is the
    /// one-leg case.
    pub legs: &'legs [LegFacts],
}

impl RouteFacts<'_> {
    fn multi_leg(&self) -> bool {
        self.legs.len() > 1
    }

    /// A reserved key of this fulfillment was reached first, or is final, on another
    /// commitment.
    fn a_reserved_key_is_lost(&self) -> bool {
        self.legs
            .iter()
            .any(|l| l.final_on_other(&self.external_commitment))
    }

    fn a_parent_is_lost(&self) -> bool {
        self.legs
            .iter()
            .any(|l| l.parent == ParentStatus::Orphaned || l.parent_consumed_elsewhere)
    }
}

/// `TraderParentCompatible(P)`: the parent either is an ordinary claim, or is
/// a conditional claim that selected exactly the root this operation was built
/// on. The parent is always resolved here: Core resolves only over complete
/// facts, the predecessor's resolution among them (Amendment S7).
pub fn trader_parent_compatible(parent: &ParentPosition, parent_pre_root: &[u8; 32]) -> bool {
    match parent {
        ParentPosition::SingleRoot => true,
        ParentPosition::ConditionalSelected { selected_root } => selected_root == parent_pre_root,
        ParentPosition::ConditionalNoRoot => false,
    }
}

/// `TraderParentImpossible(P)`: the parent is terminal and did not select the
/// root this operation was built on — either it selected nothing (Invalid), or
/// it selected the other branch.
///
/// Objective and monotone.
pub fn trader_parent_impossible(parent: &ParentPosition, parent_pre_root: &[u8; 32]) -> bool {
    match parent {
        ParentPosition::ConditionalNoRoot => true,
        ParentPosition::ConditionalSelected { selected_root } => selected_root != parent_pre_root,
        ParentPosition::SingleRoot => false,
    }
}

/// `ConsumedRoute(F, E)` (Section 23.2): registered, conforming, statically
/// valid, built on the branch the parent actually took, and every required
/// leg finally consumed its exact canonical parent on this `E` at a live
/// attempt. A single-vault trade is the one-leg case.
///
/// This is where parent canonicality lives. `RouteValidation` never looks at
/// it, so a static verdict cannot depend on who won a race. And
/// `FulfillmentConformance` is a conjunct of its own: registration is a race
/// at a leader, not a verdict on the bytes that won it.
pub fn consumed_route(facts: &RouteFacts<'_>) -> bool {
    facts.registered
        && facts.conformance == Validation::Valid
        && facts.validation == Validation::Valid
        && trader_parent_compatible(&facts.parent, &facts.parent_pre_root)
        && !facts.legs.is_empty()
        && facts.legs.iter().all(|l| {
            l.parent == ParentStatus::Canonical
                && l.attempt_live
                && l.final_on(&facts.external_commitment)
        })
}

/// Which arm of `RouteImpossible(P, E)` holds, if any. The arms are stated
/// separately because a DLV key skip must be attributable to one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpossibleArm {
    /// (i) `RouteValidation = Invalid`. Static and monotone, and a function of
    /// P alone: the canonical `G` set is derived from P, so no search over
    /// candidate fulfillments is needed.
    ValidationInvalid,
    /// (ii) a named parent is permanently orphaned.
    ParentOrphaned,
    /// (iii′) a named parent was consumed by some `X ≠ E`, and the walk
    /// consumes a parent once.
    ParentConsumedElsewhere,
    /// (iv) `TraderParentImpossible(P)`: the trader parent is terminal on the
    /// other branch, or on none.
    TraderParentImpossible,
    /// (v) the fulfillment the exercise at `K` carries can never register:
    /// position `q` already holds a different claim (Section 21.1). Without
    /// this arm a trader whose exercise for attempt 0 won `K^(0)` while its
    /// fulfillment for attempt 1 registered strands the parent's attempt
    /// chain (`DSM_SofiFulfillment.tla`, `LostPosition`).
    PositionLost,
}

/// The arm of `RouteImpossible(P, E)` that holds, in arm order.
///
/// Arms (ii) to (v) hold whatever `RouteValidation` says. Arms (iv) and (v)
/// create no `Void`: under (iv) the trader position is Invalid through the
/// ladder, under (v) the position went to another claim and this `F` never
/// resolves through it; both arms exist only to stop an impossible operation
/// stranding a DLV successor key.
pub fn route_impossible(facts: &RouteFacts<'_>) -> Option<ImpossibleArm> {
    if facts.validation == Validation::Invalid {
        return Some(ImpossibleArm::ValidationInvalid);
    }
    if facts
        .legs
        .iter()
        .any(|l| l.parent == ParentStatus::Orphaned)
    {
        return Some(ImpossibleArm::ParentOrphaned);
    }
    if facts.legs.iter().any(|l| l.parent_consumed_elsewhere) {
        return Some(ImpossibleArm::ParentConsumedElsewhere);
    }
    if trader_parent_impossible(&facts.parent, &facts.parent_pre_root) {
        return Some(ImpossibleArm::TraderParentImpossible);
    }
    if facts.position_lost {
        return Some(ImpossibleArm::PositionLost);
    }
    None
}

/// Why Core does not resolve a position yet: its facts are not complete
/// (Amendment S7). Never a result and never recorded: the SDK keeps reading,
/// relaying and retrying within its budget, and when the retries are
/// exhausted the attempt fails on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incomplete {
    /// F is not registered at q.
    NotRegistered,
    /// Some required storage fact is not final, and nothing is lost yet.
    StorageNotFinal,
}

/// The resolution ladder (Section 24; Amendment S7). Verifier-local,
/// deterministic, permanent, and only over complete facts. The first matching
/// rung decides.
///
/// | Rung | Result | Condition |
/// |---|---|---|
/// | 0 | not yet (`Incomplete`) | F is not registered |
/// | 1 | Invalid | the parent resolved and did not select this operation's root |
/// | 2 | Invalid | `FulfillmentConformance(F) = Invalid` |
/// | 3 | Realized | `ConsumedRoute(F, E)` |
/// | 4 | Invalid | `RouteValidation = Invalid` |
/// | 5 | Void | storage-resolved, and a reserved key or a parent is lost |
/// | 6 | not yet (`Incomplete`) | otherwise: a required storage fact is not final |
///
/// The predecessor's resolution is part of the complete facts: the caller
/// resolves it first. Rung 1 comes before any route result: a position built
/// on a branch the parent never took is Invalid whatever its own legs did.
/// Both predicates are binary, so Void never waits on a third value: rung 4
/// has already turned an invalid route Invalid before rung 5 can Void it.
pub fn resolve_position(facts: &RouteFacts<'_>) -> Result<Resolution, Incomplete> {
    // 0 — nothing is exercised before registration.
    if !facts.registered {
        return Err(Incomplete::NotRegistered);
    }
    // 1 — the parent took another branch, or none.
    if trader_parent_impossible(&facts.parent, &facts.parent_pre_root) {
        return Ok(Resolution::Invalid);
    }
    // 2 — the fulfillment never satisfied its own rules. Terminal, whatever
    // the cells say: registration supplied no truth value.
    if facts.conformance == Validation::Invalid {
        return Ok(Resolution::Invalid);
    }
    // 3 — the route consumed every required parent.
    if consumed_route(facts) {
        return Ok(Resolution::Realized);
    }
    // 4 — statically invalid, permanently.
    if facts.validation == Validation::Invalid {
        return Ok(Resolution::Invalid);
    }
    // 5 — valid, storage-resolved, and lost.
    if facts.storage_resolved && (facts.a_reserved_key_is_lost() || facts.a_parent_is_lost()) {
        return Ok(Resolution::Void);
    }
    // 6 — the facts are not complete yet.
    Err(Incomplete::StorageNotFinal)
}

/// How one attempt key of one DLV leg classifies during the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptClass {
    /// The parent was consumed at this key by this operation. The walk stops.
    Consumed,
    /// This key can never consume the parent, so the walk moves on.
    Skipped,
    /// Neither is established. The walk stops without an answer.
    Unresolved,
}

/// Why a key is skippable, kept separate so a skip is always attributable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// A final cell of a single-leg operation whose validation is Invalid.
    RejectedFinalSingleLeg,
    /// A final cell of an operation that can never realize.
    RejectedFinalRoute(ImpossibleArm),
    /// A final cell of a fulfillment that is not the exercise of its P:
    /// `FulfillmentConformance(F) = Invalid` (SoFi §23.5, MR-SOFI-0238).
    RejectedFinalConformance,
}

/// Why a fulfillment can never realize (SoFi §23.5):
///
/// ```text
/// FulfillmentImpossible(F, E) ⇔ FulfillmentConformance(F) = Invalid ∨ RouteImpossible(P(F), E)
/// ```
///
/// `RouteImpossible` stays scoped to P and E and takes no F, because several
/// candidate fulfillments can reference one P; conformance is the F-level arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FulfillmentImpossibility {
    ConformanceInvalid,
    Route(ImpossibleArm),
}

/// `FulfillmentImpossible(F, E)`: the conformance arm first, then the route
/// arms. Both inputs are binary and in hand (Amendment S3).
pub fn fulfillment_impossible(facts: &RouteFacts<'_>) -> Option<FulfillmentImpossibility> {
    if facts.conformance == Validation::Invalid {
        return Some(FulfillmentImpossibility::ConformanceInvalid);
    }
    route_impossible(facts).map(FulfillmentImpossibility::Route)
}

/// Classify the attempt key of `leg` under the facts of the registered
/// fulfillment that reserved it.
///
/// A key is skippable only on a final cell of an operation that can never
/// realize. No key is ever taken: a key is open until an exercise naming it
/// reaches its leader, and nothing else can close it.
pub fn classify_attempt(
    facts: &RouteFacts<'_>,
    leg: &LegFacts,
) -> (AttemptClass, Option<SkipReason>) {
    if leg.final_on(&facts.external_commitment) {
        // A final cell of an operation that cannot realize is stranded, never
        // a partial execution: nothing rolls back, because the cell was never
        // consumed as an economic execution on its own.
        if let Some(why) = fulfillment_impossible(facts) {
            let reason = match why {
                FulfillmentImpossibility::ConformanceInvalid => {
                    SkipReason::RejectedFinalConformance
                }
                FulfillmentImpossibility::Route(ImpossibleArm::ValidationInvalid)
                    if !facts.multi_leg() =>
                {
                    SkipReason::RejectedFinalSingleLeg
                }
                FulfillmentImpossibility::Route(arm) => SkipReason::RejectedFinalRoute(arm),
            };
            return (AttemptClass::Skipped, Some(reason));
        }
        // A final cell is a consumption only when the whole operation
        // consumed: the same E across every required leg, validation Valid,
        // the trader parent compatible. One final cell is not one executed
        // swap (F4), so a leg's own facts are not enough.
        if consumed_route(facts) {
            return (AttemptClass::Consumed, None);
        }
    }
    // Neither skipped nor consumed on these facts: the cell is open or not
    // final, or another operation's commitment holds it, which is that
    // operation's question and not this one's.
    (AttemptClass::Unresolved, None)
}

/// Where the walk over one DLV parent's attempt keys ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkOutcome {
    /// The attempt counter has no successor. Refused, never wrapped and never
    /// saturated onto a key that is already decided.
    CounterExhausted { attempt: u64 },
    /// The parent was consumed at this attempt index.
    Consumed { attempt: u64 },
    /// Every key up to `attempt` was skipped, and that one is not resolved.
    Unresolved { attempt: u64 },
    /// The budget ran out. Resume at `cursor`; the answer is unchanged by
    /// where the chunking fell.
    Continue { cursor: u64 },
}

/// What an exercise's own bytes refute, before anything is read about it
/// (MR-DSM-0041, MR-DSM-0042).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefutedInHand {
    /// `FulfillmentConformance(F) = Invalid` from the exercise alone.
    Conformance,
    /// `RouteValidation(P, G, E) = Invalid` from `P` and `P(E)` alone, over
    /// a route of `legs` legs.
    Route { legs: usize },
}

/// How an attempt key classifies when the exercise holding it is refuted in
/// hand: the answer [`classify_attempt`] gives whatever the other facts are.
/// `FulfillmentImpossible` decides by its conformance arm, then by
/// `RouteImpossible`'s first arm, before any other fact is read, and nothing
/// consumes without both predicates Valid. So a cell final on `E` skips for
/// that reason, and any other cell is unresolved.
pub fn skip_in_hand(
    refuted: RefutedInHand,
    cell: &CellFact,
    external_commitment: &[u8; 32],
) -> (AttemptClass, Option<SkipReason>) {
    let final_on_e = *cell
        == CellFact::Held {
            id: *external_commitment,
            state: ChainState::Final,
        };
    if !final_on_e {
        return (AttemptClass::Unresolved, None);
    }
    let reason = match refuted {
        RefutedInHand::Conformance => SkipReason::RejectedFinalConformance,
        RefutedInHand::Route { legs } if legs > 1 => {
            SkipReason::RejectedFinalRoute(ImpossibleArm::ValidationInvalid)
        }
        RefutedInHand::Route { .. } => SkipReason::RejectedFinalSingleLeg,
    };
    (AttemptClass::Skipped, Some(reason))
}

/// The ladder over a position whose exercise is refuted in hand: registration
/// is the one fact it reads. Unregistered, rung 0 holds. Registered, the
/// position is Invalid whatever the other facts are — rung 1 when the parent
/// took another branch, else rung 2 for a non-conforming `F`, else rung 4
/// for an invalid route, which nothing before it can consume.
pub fn resolve_refuted_in_hand(registered: bool) -> Result<Resolution, Incomplete> {
    if registered {
        Ok(Resolution::Invalid)
    } else {
        Err(Incomplete::NotRegistered)
    }
}

/// What the walk has for one attempt key.
#[derive(Debug, Clone, Copy)]
pub enum KeyFacts<'f> {
    /// The complete facts of the exercise holding the key, and of the leg
    /// being walked.
    Complete(RouteFacts<'f>, LegFacts),
    /// The exercise holding the key is refuted by its own bytes; `cell` is
    /// the key's storage fact, read to find it.
    RefutedInHand {
        refuted: RefutedInHand,
        cell: CellFact,
        external_commitment: [u8; 32],
    },
}

/// Walk one DLV parent's attempt keys in ascending order: a skipped key moves
/// to the next, a consumed key stops, anything else stops as unresolved.
///
/// `keys` supplies what is known about attempt `a`, or `None` past what the
/// caller has established — which is `Unresolved`, never a skip. `budget`
/// bounds the examined keys only; it never changes the verdict, it only
/// defers it.
pub fn walk<'f, F>(base_attempt: u64, budget: usize, mut keys: F) -> WalkOutcome
where
    F: FnMut(u64) -> Option<KeyFacts<'f>>,
{
    let mut attempt = base_attempt;
    let mut examined = 0;
    while examined < budget {
        examined += 1;
        let class = match keys(attempt) {
            None => return WalkOutcome::Unresolved { attempt },
            Some(KeyFacts::Complete(facts, leg)) => classify_attempt(&facts, &leg).0,
            Some(KeyFacts::RefutedInHand {
                refuted,
                cell,
                external_commitment,
            }) => skip_in_hand(refuted, &cell, &external_commitment).0,
        };
        match class {
            AttemptClass::Consumed => return WalkOutcome::Consumed { attempt },
            AttemptClass::Unresolved => return WalkOutcome::Unresolved { attempt },
            AttemptClass::Skipped => match next_attempt(attempt) {
                Ok(next) => attempt = next,
                Err(..) => return WalkOutcome::CounterExhausted { attempt },
            },
        }
    }
    WalkOutcome::Continue { cursor: attempt }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sofi::conformance::Validation::{Invalid, Valid};

    const E: [u8; 32] = [0xE5; 32];
    const OTHER_E: [u8; 32] = [0x11; 32];
    const PRE: [u8; 32] = [0x99; 32];
    const OTHER_ROOT: [u8; 32] = [0x77; 32];

    #[test]
    fn the_established_root_of_that_generation_is_canonical() {
        assert_eq!(parent_status(Some(PRE), &PRE), ParentStatus::Canonical);
    }

    #[test]
    fn a_different_root_at_the_same_generation_orphans_permanently() {
        // R*_g is established and it is not what the leg names. Nothing later
        // restores this parent: a generation has one realized consumer.
        assert_eq!(
            parent_status(Some(OTHER_ROOT), &PRE),
            ParentStatus::Orphaned
        );
    }

    #[test]
    fn a_generation_the_chain_has_not_reached_waits_and_is_never_orphaned() {
        // THE CASE THAT MUST NOT BECOME A VERDICT. A head is open so that the
        // next root can still arrive, so a root this verifier cannot place is
        // not thereby refuted -- it may be the one an in-flight operation is
        // about to realize. Answering Orphaned here would Void it permanently.
        assert_eq!(parent_status(None, &PRE), ParentStatus::Unavailable);
        assert_ne!(parent_status(None, &PRE), ParentStatus::Orphaned);
    }

    #[test]
    fn an_unreached_generation_neither_consumes_nor_defeats_a_route() {
        // The status is not read in isolation: an unestablished parent leaves
        // the position unresolved, where an Orphaned one would Void it.
        let waiting = [LegFacts {
            parent: parent_status(None, &PRE),
            ..good_leg()
        }];
        assert_eq!(
            resolve_position(&realized(&waiting)),
            Err(Incomplete::StorageNotFinal)
        );
        let refuted = [LegFacts {
            parent: parent_status(Some(OTHER_ROOT), &PRE),
            ..good_leg()
        }];
        assert_eq!(resolve_position(&realized(&refuted)), Ok(Resolution::Void));
    }

    /// A leg that consumed its canonical parent on this operation's E.
    fn good_leg() -> LegFacts {
        LegFacts {
            cell: CellFact::Held {
                id: E,
                state: ChainState::Final,
            },
            parent: ParentStatus::Canonical,
            attempt_live: true,
            parent_consumed_elsewhere: false,
        }
    }

    fn open_leg() -> LegFacts {
        LegFacts {
            cell: CellFact::Open,
            ..good_leg()
        }
    }

    /// A registered, valid, single-leg operation on an ordinary parent whose
    /// leg has consumed: the Realized baseline every case below perturbs.
    fn realized<'l>(legs: &'l [LegFacts]) -> RouteFacts<'l> {
        RouteFacts {
            external_commitment: E,
            registered: true,
            conformance: Valid,
            position_lost: false,
            parent: ParentPosition::SingleRoot,
            parent_pre_root: PRE,
            validation: Valid,
            storage_resolved: true,
            legs,
        }
    }

    // ── step 0: registration is the exercise boundary ──────────────────────

    /// Lean `fulfillment_registration_is_exercise_boundary`, TLA
    /// `CellsOnlyAfterFulfillmentRegistered`: before registration nothing is
    /// exercised, whatever the cells say.
    #[test]
    fn an_unregistered_fulfillment_is_not_resolved_even_with_every_leg_final() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            registered: false,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Err(Incomplete::NotRegistered));
        assert!(!consumed_route(&facts));
    }

    // ── steps 1–2: the trader parent (P15-3, R17-3) ────────────────────────

    /// A lost leg under a conditional parent resolves by the branch the parent
    /// took: Void on the root this operation was built on, Invalid on the
    /// other. The parent is resolved before Core is called (Amendment S7), so
    /// a terminal Void is never retracted by a later parent answer.
    #[test]
    fn a_lost_leg_under_a_conditional_parent_resolves_by_the_branch_it_took() {
        let legs = [LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::LeaderHeld,
            },
            ..good_leg()
        }];
        let lost = realized(&legs);
        assert_eq!(lost.validation, Valid);
        assert!(lost.storage_resolved);
        assert_eq!(
            resolve_position(&RouteFacts {
                parent: ParentPosition::ConditionalSelected {
                    selected_root: OTHER_ROOT,
                },
                ..lost
            }),
            Ok(Resolution::Invalid)
        );
        assert_eq!(
            resolve_position(&RouteFacts {
                parent: ParentPosition::ConditionalSelected { selected_root: PRE },
                ..lost
            }),
            Ok(Resolution::Void)
        );
    }

    /// Lean `conditional_parent_on_the_taken_branch_processes_normally`.
    #[test]
    fn a_conditional_parent_that_selected_this_root_processes_normally() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            parent: ParentPosition::ConditionalSelected { selected_root: PRE },
            ..realized(&legs)
        };
        assert!(trader_parent_compatible(&facts.parent, &PRE));
        assert_eq!(resolve_position(&facts), Ok(Resolution::Realized));
    }

    /// Lean `conditional_parent_on_another_branch_is_invalid`: the trader
    /// guessed the branch and lost. Not Void — the operation was never the one
    /// the lineage took.
    #[test]
    fn a_conditional_parent_that_selected_another_root_is_invalid() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            parent: ParentPosition::ConditionalSelected {
                selected_root: OTHER_ROOT,
            },
            ..realized(&legs)
        };
        assert!(trader_parent_impossible(&facts.parent, &PRE));
        assert_eq!(resolve_position(&facts), Ok(Resolution::Invalid));
        assert!(!consumed_route(&facts));
        assert_eq!(
            route_impossible(&facts),
            Some(ImpossibleArm::TraderParentImpossible)
        );
    }

    /// Lean `terminal_parent_with_no_root_is_invalid_without_evidence`: a
    /// parent that selected no root makes the position Invalid, and its DLV
    /// key skips on arm (iv) over a statically valid route.
    #[test]
    fn a_terminal_parent_that_selected_no_root_is_invalid_and_its_key_skips() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            parent: ParentPosition::ConditionalNoRoot,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Ok(Resolution::Invalid));
        assert_eq!(
            route_impossible(&facts),
            Some(ImpossibleArm::TraderParentImpossible)
        );
        let (class, reason) = classify_attempt(&facts, &legs[0]);
        assert_eq!(class, AttemptClass::Skipped);
        assert_eq!(
            reason,
            Some(SkipReason::RejectedFinalRoute(
                ImpossibleArm::TraderParentImpossible
            ))
        );
    }

    /// SoFi §23.5, MR-SOFI-0238: a final cell of a conformance-Invalid
    /// fulfillment is skipped, so the walk moves past it instead of stalling
    /// on it forever. `RouteImpossible` stays silent: it takes no F.
    #[test]
    fn a_final_cell_of_a_conformance_invalid_fulfillment_is_skipped() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            conformance: Validation::Invalid,
            ..realized(&legs)
        };
        assert_eq!(route_impossible(&facts), None, "RouteImpossible takes no F");
        assert_eq!(
            fulfillment_impossible(&facts),
            Some(FulfillmentImpossibility::ConformanceInvalid)
        );
        let (class, reason) = classify_attempt(&facts, &legs[0]);
        assert_eq!(class, AttemptClass::Skipped);
        assert_eq!(reason, Some(SkipReason::RejectedFinalConformance));
    }

    /// Lean `trader_parent_arm_is_monotone`: a resolved parent fixes exactly
    /// one of compatible and impossible, for every root, so the arm never
    /// retracts and a compatible parent never becomes impossible.
    #[test]
    fn the_trader_parent_arm_is_monotone() {
        for root in [PRE, OTHER_ROOT] {
            for parent in [
                ParentPosition::SingleRoot,
                ParentPosition::ConditionalNoRoot,
                ParentPosition::ConditionalSelected { selected_root: PRE },
                ParentPosition::ConditionalSelected {
                    selected_root: OTHER_ROOT,
                },
            ] {
                let compatible = trader_parent_compatible(&parent, &root);
                let impossible = trader_parent_impossible(&parent, &root);
                assert!(
                    compatible != impossible,
                    "a resolved parent is exactly one of the two: {parent:?} against {root:?}"
                );
            }
        }
    }

    // ── step 3: consumption ────────────────────────────────────────────────

    /// Lean `fulfillment_atomic_all_or_none`, TLA `NoPartialRealization`: one
    /// final leg is not one executed swap.
    #[test]
    fn a_route_with_one_leg_still_open_is_not_consumed() {
        let legs = [good_leg(), open_leg()];
        let facts = RouteFacts { ..realized(&legs) };
        assert!(!consumed_route(&facts));
        assert_eq!(resolve_position(&facts), Err(Incomplete::StorageNotFinal));
    }

    /// Lean `route_validation_excludes_parent_canonicality`: canonicality is a
    /// consumption question, so a non-canonical parent cannot realize even
    /// though validation says Valid.
    #[test]
    fn a_parent_the_verifier_has_not_established_never_consumes() {
        let legs = [LegFacts {
            parent: ParentStatus::Unavailable,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert!(!consumed_route(&facts));
        assert_eq!(resolve_position(&facts), Err(Incomplete::StorageNotFinal));
    }

    /// An earlier attempt key another operation reached first means the fulfillment's own key was
    /// never live, so nothing it holds is a consumption.
    #[test]
    fn an_earlier_attempt_another_operation_reached_first_makes_this_key_not_live() {
        let legs = [LegFacts {
            attempt_live: false,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert!(!consumed_route(&facts));
    }

    /// An unestablished parent is not a refuted one. A parent the verifier
    /// has not established leaves the position unresolved; one it has
    /// established as another root defeats it. Under the pair of booleans
    /// `ParentStatus` replaced, both were `false` on both fields and the
    /// ladder could not tell them apart.
    #[test]
    fn an_unestablished_parent_waits_and_an_orphaned_one_defeats() {
        for (status, expected, arm) in [
            (
                ParentStatus::Unavailable,
                Err(Incomplete::StorageNotFinal),
                None,
            ),
            (
                ParentStatus::Orphaned,
                Ok(Resolution::Void),
                Some(ImpossibleArm::ParentOrphaned),
            ),
            (ParentStatus::Canonical, Ok(Resolution::Realized), None),
        ] {
            let legs = [LegFacts {
                parent: status,
                ..good_leg()
            }];
            let facts = realized(&legs);
            assert_eq!(facts.validation, Valid, "the route itself is sound");
            assert_eq!(
                resolve_position(&facts),
                expected,
                "{status:?} must resolve {expected:?}"
            );
            assert_eq!(route_impossible(&facts), arm, "{status:?}");
        }
    }

    /// Orphaning is a `RouteImpossible` condition, so a valid and conforming
    /// route that it defeats goes to Void — never Invalid, which would say
    /// the operation never satisfied the rules (owner ruling §44.4).
    #[test]
    fn an_orphaned_parent_voids_a_valid_route_and_never_invalidates_it() {
        let legs = [LegFacts {
            parent: ParentStatus::Orphaned,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert_eq!(resolve_position(&facts), Ok(Resolution::Void));
        assert_eq!(
            effect_of(Resolution::Void),
            PositionEffect::InstallPreviousRoot,
            "a Void moves nothing; the lineage continues where it was"
        );
        // Only a static refusal makes it Invalid, and that is a different fact.
        assert_eq!(
            resolve_position(&RouteFacts {
                validation: Invalid,
                ..facts
            }),
            Ok(Resolution::Invalid)
        );
    }

    /// A parent that really was canonical and was then taken by another
    /// route is `parent_consumed_elsewhere`, not orphaned. The two are
    /// different facts with the same terminal answer, and keeping them apart
    /// is what lets a skip be attributed (owner ruling §44.4).
    ///
    /// The leg's own key is open: a cell final on THIS operation's `E` would
    /// say we consumed the parent ourselves, which is not a route another
    /// operation took.
    #[test]
    fn a_canonical_parent_taken_by_another_route_is_consumed_not_orphaned() {
        let legs = [LegFacts {
            cell: CellFact::Open,
            parent: ParentStatus::Canonical,
            parent_consumed_elsewhere: true,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert_eq!(resolve_position(&facts), Ok(Resolution::Void));
        assert_eq!(
            route_impossible(&facts),
            Some(ImpossibleArm::ParentConsumedElsewhere),
            "the arm names which fact defeated it"
        );
    }

    // ── step 4: static invalidity ──────────────────────────────────────────

    /// TLA `ResolutionPermanent`, arm (i): Invalid is terminal and needs no
    /// storage resolution.
    #[test]
    fn a_statically_invalid_route_is_invalid_before_storage_resolves() {
        let legs = [open_leg()];
        let facts = RouteFacts {
            validation: Invalid,
            storage_resolved: false,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Ok(Resolution::Invalid));
        assert_eq!(
            route_impossible(&facts),
            Some(ImpossibleArm::ValidationInvalid)
        );
    }

    // ── step 5: Void, and only after Valid (R14-1) ─────────────────────────

    /// Lean `fulfillment_registrable_after_parent_loss_resolves_void`: a
    /// registered fulfillment whose parent a rival consumed is valid but
    /// defeated.
    #[test]
    fn a_valid_route_whose_parent_was_consumed_elsewhere_voids() {
        let legs = [LegFacts {
            cell: CellFact::Open,
            parent_consumed_elsewhere: true,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert_eq!(resolve_position(&facts), Ok(Resolution::Void));
        assert_eq!(
            effect_of(Resolution::Void),
            PositionEffect::InstallPreviousRoot
        );
    }

    /// A reserved key that died, and an objective abort, are both Void.
    #[test]
    fn a_reserved_key_another_operation_reached_first_voids() {
        let taken = [LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::LeaderHeld,
            },
            ..good_leg()
        }];
        assert_eq!(resolve_position(&realized(&taken)), Ok(Resolution::Void));
    }

    /// Lean `resolution_is_permanent` and its counterexample
    /// `literal_ladder_is_not_permanent`, TLA falsification
    /// `VoidBeforeValidation`: a lost route is Void only when it was valid,
    /// and Invalid when it never was. Rung 4 precedes rung 5, so a lost route
    /// is never voided ahead of its validation.
    #[test]
    fn a_lost_route_is_void_when_valid_and_invalid_when_not() {
        let legs = [LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::LeaderHeld,
            },
            ..good_leg()
        }];
        let lost = realized(&legs);
        assert_eq!(
            resolve_position(&RouteFacts {
                validation: Valid,
                ..lost
            }),
            Ok(Resolution::Void)
        );
        assert_eq!(
            resolve_position(&RouteFacts {
                validation: Invalid,
                ..lost
            }),
            Ok(Resolution::Invalid)
        );
    }

    /// Void needs storage resolution: a route that merely looks lost while its
    /// keys are open is not resolved.
    #[test]
    fn void_requires_storage_resolution() {
        let legs = [LegFacts {
            parent: ParentStatus::Orphaned,
            cell: CellFact::Open,
            ..good_leg()
        }];
        let facts = RouteFacts {
            storage_resolved: false,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Err(Incomplete::StorageNotFinal));
    }

    // ── rungs 3–4: FulfillmentConformance (R12) ───────────────────────────

    /// Lean `realized_requires_conformance`, TLA `RealizedRequiresConformance`
    /// (fault `_ConformanceDropped`): FulfillmentConformance is a conjunct of
    /// ConsumedRoute. A registered, statically valid route with every leg
    /// final on its E never realizes once its conformance is Invalid.
    #[test]
    fn realized_requires_conformance() {
        let legs = [good_leg(), good_leg()];
        let never = RouteFacts {
            conformance: Invalid,
            ..realized(&legs)
        };
        assert!(!consumed_route(&never));
        assert_eq!(resolve_position(&never), Ok(Resolution::Invalid));
        assert_eq!(
            resolve_position(&never).map(effect_of),
            Ok(PositionEffect::None)
        );
        // Only Valid realizes, and the effect is the realize root.
        assert!(consumed_route(&realized(&legs)));
        assert_eq!(resolve_position(&realized(&legs)), Ok(Resolution::Realized));
        assert_eq!(
            resolve_position(&realized(&legs)).map(effect_of),
            Ok(PositionEffect::InstallRealizeRoot)
        );
    }

    /// Lean `registration_is_not_conformance`, TLA `RegistrationIsNotConformance`:
    /// registration supplies no truth value. The same registered facts with
    /// conformance Invalid never realize.
    #[test]
    fn registration_is_not_conformance() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            conformance: Invalid,
            ..realized(&legs)
        };
        assert!(facts.registered);
        assert_ne!(resolve_position(&facts), Ok(Resolution::Realized));
    }

    /// Section 21.1: a registered, valid route already lost at a reserved key
    /// is Void only if it conformed, and Invalid if it never did. Rung 2
    /// precedes rung 5, so no route is voided ahead of its conformance.
    #[test]
    fn a_lost_route_is_void_only_if_it_conformed() {
        let legs = [LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::LeaderHeld,
            },
            ..good_leg()
        }];
        let lost = realized(&legs);
        assert!(lost.storage_resolved && lost.validation == Valid);
        assert_eq!(
            resolve_position(&RouteFacts {
                conformance: Valid,
                ..lost
            }),
            Ok(Resolution::Void)
        );
        assert_eq!(
            resolve_position(&RouteFacts {
                conformance: Invalid,
                ..lost
            }),
            Ok(Resolution::Invalid)
        );
    }

    // ── arm (v): the position went to another claim (R12) ────────────────

    /// TLA `LostPosition` (fault `_LostPositionDropped` →
    /// `ObjectiveRejectionImpliesSkipped`), Lean
    /// `a_lost_position_makes_a_final_route_skippable`: an exercise final at a
    /// key whose F can never register — the position holds another claim —
    /// is skipped, so the parent's attempt chain is not stranded. It is no
    /// Void: the position resolves through the claim that took it, never
    /// through this F.
    #[test]
    fn a_final_cell_whose_fulfillment_lost_its_position_is_skipped() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            registered: false,
            position_lost: true,
            ..realized(&legs)
        };
        assert_eq!(route_impossible(&facts), Some(ImpossibleArm::PositionLost));
        assert_eq!(
            classify_attempt(&facts, &legs[0]),
            (
                AttemptClass::Skipped,
                Some(SkipReason::RejectedFinalRoute(ImpossibleArm::PositionLost))
            )
        );
        assert_eq!(resolve_position(&facts), Err(Incomplete::NotRegistered));
        assert!(!consumed_route(&facts));
        // Without the arm the same cell is that F's open question forever.
        let held = RouteFacts {
            position_lost: false,
            ..facts
        };
        assert_eq!(route_impossible(&held), None);
        assert_eq!(
            classify_attempt(&held, &legs[0]).0,
            AttemptClass::Unresolved
        );
    }

    // ── rung 8, and the ladder as a whole ──────────────────────────────────

    /// Lean `resolution_is_permanent`: no terminal answer is reachable from
    /// another terminal answer as facts accumulate monotonically — storage
    /// resolving, or a cell's chain growing. Checked by enumeration over every
    /// fact combination the ladder reads.
    #[test]
    fn a_terminal_resolution_is_never_reached_from_another_terminal_one() {
        let held = |id: [u8; 32], state: ChainState| CellFact::Held { id, state };
        let cells = [
            held(E, ChainState::Final),
            held(E, ChainState::LeaderHeld),
            held(OTHER_E, ChainState::Final),
            held(OTHER_E, ChainState::LeaderHeld),
            CellFact::Open,
        ];
        let parents = [
            ParentPosition::SingleRoot,
            ParentPosition::ConditionalSelected { selected_root: PRE },
            ParentPosition::ConditionalSelected {
                selected_root: OTHER_ROOT,
            },
            ParentPosition::ConditionalNoRoot,
        ];
        for cell in cells {
            for parent in parents {
                for validation in [Valid, Invalid] {
                    for conformance in [Valid, Invalid] {
                        for storage_resolved in [false, true] {
                            let legs = [LegFacts { cell, ..good_leg() }];
                            let facts = RouteFacts {
                                external_commitment: E,
                                registered: true,
                                conformance,
                                position_lost: false,
                                parent,
                                parent_pre_root: PRE,
                                validation,
                                storage_resolved,
                                legs: &legs,
                            };
                            let before = resolve_position(&facts);
                            if !storage_resolved {
                                let after = resolve_position(&RouteFacts {
                                    storage_resolved: true,
                                    ..facts
                                });
                                assert!(
                                    before.is_err() || before == after,
                                    "{before:?} changed to {after:?} on storage resolution"
                                );
                            }
                            if let CellFact::Held {
                                id,
                                state: ChainState::LeaderHeld,
                            } = cell
                            {
                                let grown = [LegFacts {
                                    cell: held(id, ChainState::Final),
                                    ..good_leg()
                                }];
                                let after = resolve_position(&RouteFacts {
                                    legs: &grown,
                                    ..facts
                                });
                                assert!(
                                    before.is_err() || before == after,
                                    "{before:?} changed to {after:?} as the chain grew"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Realized and Void are the only results that continue the lineage, and
    /// Void contributes no mutation of its own.
    #[test]
    fn only_realized_installs_the_realize_root_and_void_installs_the_previous_one() {
        assert_eq!(
            effect_of(Resolution::Realized),
            PositionEffect::InstallRealizeRoot
        );
        assert_eq!(
            effect_of(Resolution::Void),
            PositionEffect::InstallPreviousRoot
        );
        assert_eq!(effect_of(Resolution::Invalid), PositionEffect::None);
    }

    // ── impossibility arms and the walk ────────────────────────────────────

    /// Lean `route_impossible_orphan_and_consumed_elsewhere_arms`: arms (ii)
    /// and (iii′) hold on a statically valid route.
    #[test]
    fn the_orphan_and_consumed_elsewhere_arms_hold_on_a_valid_route() {
        let orphaned = [LegFacts {
            parent: ParentStatus::Orphaned,
            ..good_leg()
        }];
        assert_eq!(
            route_impossible(&realized(&orphaned)),
            Some(ImpossibleArm::ParentOrphaned)
        );
        let taken = [LegFacts {
            parent_consumed_elsewhere: true,
            ..good_leg()
        }];
        assert_eq!(
            route_impossible(&realized(&taken)),
            Some(ImpossibleArm::ParentConsumedElsewhere)
        );
    }

    /// Lean `stranded_e_cell_is_not_partial_execution`: a final cell of an
    /// impossible route is skipped, and skipping it is not a rollback.
    #[test]
    fn a_stranded_final_cell_of_an_impossible_route_is_skipped() {
        let lost = [
            LegFacts {
                parent: ParentStatus::Orphaned,
                ..open_leg()
            },
            good_leg(),
        ];
        let facts = realized(&lost);
        let (class, reason) = classify_attempt(&facts, &lost[1]);
        assert_eq!(class, AttemptClass::Skipped);
        assert_eq!(
            reason,
            Some(SkipReason::RejectedFinalRoute(
                ImpossibleArm::ParentOrphaned
            ))
        );
    }

    /// A single-leg operation whose validation is Invalid gives the
    /// single-leg rejection, which is the arm the cell ingress path reports.
    #[test]
    fn a_single_leg_invalid_route_reports_the_single_leg_rejection() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            validation: Invalid,
            ..realized(&legs)
        };
        let (class, reason) = classify_attempt(&facts, &legs[0]);
        assert_eq!(class, AttemptClass::Skipped);
        assert_eq!(reason, Some(SkipReason::RejectedFinalSingleLeg));
    }

    /// A cell another operation reached first is that operation's question, not
    /// this one's: it is never skipped or consumed from these facts alone.
    #[test]
    fn a_cell_another_operation_reached_first_is_that_operations_question() {
        let legs = [LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::LeaderHeld,
            },
            ..good_leg()
        }];
        assert_eq!(
            classify_attempt(&realized(&legs), &legs[0]),
            (AttemptClass::Unresolved, None)
        );
    }

    /// The walk passes skipped keys, stops on a consumption, and the answer is
    /// the same however the budget chunks it.
    #[test]
    fn the_walk_is_chunking_equivalent() {
        // Attempts 0..3 were exercised by another operation whose route is
        // impossible: final on its E, rejected, so each is skipped. The facts
        // describe the ROUTE the key belongs to, because a key is consumed
        // only when its whole operation is.
        let rejected = LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::Final,
            },
            ..good_leg()
        };
        let rejected_legs = [rejected];
        let live_legs = [good_leg()];
        let facts_for = |attempt: u64| {
            let (legs, leg, e, validation) = if attempt < 3 {
                (&rejected_legs, rejected, OTHER_E, Invalid)
            } else {
                (&live_legs, good_leg(), E, Valid)
            };
            Some(KeyFacts::Complete(
                RouteFacts {
                    external_commitment: e,
                    registered: true,
                    conformance: Valid,
                    position_lost: false,
                    parent: ParentPosition::SingleRoot,
                    parent_pre_root: PRE,
                    validation,
                    storage_resolved: true,
                    legs,
                },
                leg,
            ))
        };
        assert_eq!(walk(0, 16, facts_for), WalkOutcome::Consumed { attempt: 3 });
        // A budget of two defers without deciding, and resuming lands the same.
        let WalkOutcome::Continue { cursor } = walk(0, 2, facts_for) else {
            panic!("a two-key budget cannot reach attempt 3")
        };
        assert_eq!(cursor, 2);
        assert_eq!(
            walk(cursor, 16, facts_for),
            WalkOutcome::Consumed { attempt: 3 }
        );
    }

    /// Every combination of the facts an in-hand refutation does not read,
    /// over one and two legs, with the walked leg's cell as given.
    fn around<'l>(
        legs: &'l [LegFacts],
        conformance: Validation,
        validation: Validation,
    ) -> Vec<RouteFacts<'l>> {
        let mut out = Vec::new();
        for registered in [true, false] {
            for position_lost in [true, false] {
                for storage_resolved in [true, false] {
                    for parent in [
                        ParentPosition::SingleRoot,
                        ParentPosition::ConditionalSelected { selected_root: PRE },
                        ParentPosition::ConditionalSelected {
                            selected_root: OTHER_ROOT,
                        },
                        ParentPosition::ConditionalNoRoot,
                    ] {
                        out.push(RouteFacts {
                            external_commitment: E,
                            registered,
                            conformance,
                            position_lost: position_lost && !registered,
                            parent,
                            parent_pre_root: PRE,
                            validation,
                            storage_resolved,
                            legs,
                        });
                    }
                }
            }
        }
        out
    }

    /// `skip_in_hand` and `resolve_refuted_in_hand` are the ladder's own
    /// answers: for every value of the facts they do not read, a key and a
    /// position whose exercise is refuted in hand classify and resolve exactly
    /// as `classify_attempt` and `resolve_position` do over the complete facts.
    #[test]
    fn an_in_hand_refutation_answers_as_the_complete_facts_do() {
        let other = LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::Final,
            },
            ..good_leg()
        };
        let held = LegFacts {
            cell: CellFact::Held {
                id: E,
                state: ChainState::LeaderHeld,
            },
            ..good_leg()
        };
        let orphaned = LegFacts {
            parent: ParentStatus::Orphaned,
            ..good_leg()
        };
        for walked in [good_leg(), open_leg(), other, held, orphaned] {
            for legs in [
                vec![walked],
                vec![walked, good_leg()],
                vec![walked, open_leg()],
            ] {
                let n = legs.len();
                for (refuted, conformance, validation) in [
                    (RefutedInHand::Conformance, Invalid, Valid),
                    (RefutedInHand::Conformance, Invalid, Invalid),
                    (RefutedInHand::Route { legs: n }, Valid, Invalid),
                ] {
                    for facts in around(&legs, conformance, validation) {
                        assert_eq!(
                            classify_attempt(&facts, &walked),
                            skip_in_hand(refuted, &walked.cell, &E),
                            "{refuted:?} over {facts:?}"
                        );
                        assert_eq!(
                            resolve_position(&facts),
                            resolve_refuted_in_hand(facts.registered),
                            "{refuted:?} over {facts:?}"
                        );
                    }
                }
            }
        }
    }

    /// A key whose exercise is refuted in hand skips in the walk with nothing
    /// else supplied about it.
    #[test]
    fn the_walk_skips_a_key_refuted_in_hand() {
        let final_e = CellFact::Held {
            id: E,
            state: ChainState::Final,
        };
        let live_legs = [good_leg()];
        let facts_for = |attempt: u64| match attempt {
            0 => Some(KeyFacts::RefutedInHand {
                refuted: RefutedInHand::Conformance,
                cell: final_e,
                external_commitment: E,
            }),
            1 => Some(KeyFacts::Complete(realized(&live_legs), good_leg())),
            _ => None,
        };
        assert_eq!(walk(0, 16, facts_for), WalkOutcome::Consumed { attempt: 1 });
        // Refuted, but not final on its E: nothing skips.
        let open_for = |attempt: u64| {
            (attempt == 0).then_some(KeyFacts::RefutedInHand {
                refuted: RefutedInHand::Route { legs: 1 },
                cell: CellFact::Open,
                external_commitment: E,
            })
        };
        assert_eq!(
            walk(0, 16, open_for),
            WalkOutcome::Unresolved { attempt: 0 }
        );
    }

    /// A key the caller has not fetched is unresolved, never a skip: the walk
    /// may not invent a skip from absence.
    #[test]
    fn an_unfetched_key_is_unresolved_not_skipped() {
        assert_eq!(
            walk(5, 16, |_| None),
            WalkOutcome::Unresolved { attempt: 5 }
        );
    }

    /// A final cell of a MULTI-LEG route is not a consumption on its own: the
    /// route consumes only when every required leg did. One FinalE(E) cell is
    /// not one executed swap.
    #[test]
    fn a_final_leg_of_an_incomplete_route_is_not_consumed() {
        let legs = [good_leg(), open_leg()];
        let facts = RouteFacts { ..realized(&legs) };
        assert_eq!(
            classify_attempt(&facts, &legs[0]),
            (AttemptClass::Unresolved, None)
        );
        // With every leg final, it consumes.
        let done = [good_leg(), good_leg()];
        let complete = RouteFacts { ..realized(&done) };
        assert_eq!(
            classify_attempt(&complete, &done[0]),
            (AttemptClass::Consumed, None)
        );
    }

    /// A final cell whose route is statically Invalid is not a consumption
    /// either: consumption carries the validation premise (F4).
    #[test]
    fn a_final_leg_of_an_invalid_route_is_not_consumed() {
        let legs = [good_leg()];
        let invalid = RouteFacts {
            validation: Invalid,
            ..realized(&legs)
        };
        assert!(!consumed_route(&invalid));
        assert_eq!(
            classify_attempt(&invalid, &legs[0]).0,
            AttemptClass::Skipped
        );
    }

    /// The attempt counter is checked, never saturated: a walk that reaches
    /// `u64::MAX` refuses rather than re-examining a key it already decided.
    #[test]
    fn the_attempt_counter_is_checked_not_saturated() {
        // Every key is skipped (final on a rejected exercise), so the walk
        // would advance forever; at `u64::MAX` it refuses instead.
        let rejected = LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::Final,
            },
            ..good_leg()
        };
        let legs = [rejected];
        // Facts for the top of the counter only: a walk that went anywhere else
        // would find none and stop Unresolved.
        let facts_for = |attempt: u64| {
            (attempt == u64::MAX).then_some(KeyFacts::Complete(
                RouteFacts {
                    external_commitment: OTHER_E,
                    registered: true,
                    conformance: Valid,
                    position_lost: false,
                    parent: ParentPosition::SingleRoot,
                    parent_pre_root: PRE,
                    validation: Invalid,
                    storage_resolved: true,
                    legs: &legs,
                },
                rejected,
            ))
        };
        assert_eq!(
            walk(u64::MAX, 4, facts_for),
            WalkOutcome::CounterExhausted { attempt: u64::MAX }
        );
    }

    /// ONE route, ONE E. Two legs that each finalized a DIFFERENT operation do
    /// not add up to a consumed route, however registered, valid and Complete
    /// the fulfillment is. With a per-leg commitment this was representable —
    /// and it would have let a "route" be assembled out of other operations'
    /// cells.
    #[test]
    fn legs_final_on_different_commitments_are_not_one_route() {
        let legs = [
            good_leg(),
            LegFacts {
                cell: CellFact::Held {
                    id: OTHER_E,
                    state: ChainState::Final,
                },
                ..good_leg()
            },
        ];
        let facts = RouteFacts { ..realized(&legs) };
        assert_eq!(facts.external_commitment, E);
        assert!(
            !consumed_route(&facts),
            "a leg final on another operation's E is not this route's consumption"
        );
        assert_ne!(resolve_position(&facts), Ok(Resolution::Realized));
        // It is the loss of the route, not a consumption: the second leg's key
        // is final on someone else's commitment.
        assert_eq!(resolve_position(&facts), Ok(Resolution::Void));
        // And the stray leg is never classified as consuming this route.
        assert_eq!(
            classify_attempt(&facts, &legs[1]).0,
            AttemptClass::Unresolved
        );
    }
}
