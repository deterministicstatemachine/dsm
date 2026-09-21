// SPDX-License-Identifier: Apache-2.0

//! The verifier-local resolution core: facts in, one permanent answer out.
//!
//! Every function here is pure and total over the facts it is handed. It
//! fetches nothing, trusts no caller's opinion, and evaluates no policy: a
//! fact is either an objective storage observation ([`CellResolution`]), a
//! static validity verdict ([`Validation`]), or a monotone register fact
//! (registration, canonicality, orphaning). Where those facts come
//! from is E2's and E3's business.
//!
//! ## What it decides
//!
//! - one trader position's result — [`resolve_position`], the F2 ladder;
//! - whether the route was actually consumed — [`consumed_route`];
//! - whether it can never be — [`route_impossible`], the four arms;
//! - which DLV successor keys may be skipped — [`classify_attempt`] and
//!   [`walk`].
//!
//! ## Two things that are not the same
//!
//! `Invalid` means the operation never satisfied the DLV or protocol rules.
//! `Void` means a valid operation that could not execute — it lost contention
//! or became impossible. So validity is established BEFORE Void is declared,
//! and a position never moves `Void → Invalid` (R14-1). Missing evidence keeps
//! a lost route Pending rather than voiding it.
//!
//! One `FinalE(E)` cell is not one executed swap. A route realizes only when
//! every required leg consumes its exact parent under one registered
//! fulfillment, which is why [`consumed_route`] quantifies over all legs.
//!
//! Registration supplies no truth value: `FulfillmentConformance(F)` is a
//! conjunct of [`consumed_route`] and rungs 3 and 4 of the ladder (rebuild
//! step R12), so a registered `F` that never conformed is Invalid and one
//! whose conformance is undecided is Pending — never Void, never Realized.

use super::arith::CellResolution;
use super::conformance::Validation;
use super::wire::next_attempt;

/// What a verifier has established about the predecessor position `p` that `P`
/// names as its trader parent `T0`.
///
/// A trader may build `P` on a conditional parent before that parent resolves,
/// because the storage fence only requires `p` to be storage-resolved. The
/// branch it guessed is decided here, not at ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentPosition {
    /// `T0` is an ordinary single-root claim. P conformance already bound
    /// `T°.pre_root` to that exact registered root at ingress.
    SingleRoot,
    /// `T0` is a conditional SoFi claim `C_p` that has not resolved.
    ConditionalPending,
    /// `C_p` resolved and selected this root: `R_realize` when `p` realized,
    /// `R_void` when it voided.
    ConditionalSelected { selected_root: [u8; 32] },
    /// `C_p` resolved Invalid, so no root was ever selected. Terminal.
    ConditionalNoRoot,
}

/// A trader-position result. Permanent once it is not `Pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The route consumed every required parent under this fulfillment.
    Realized,
    /// A valid operation that could not execute. Terminal.
    Void,
    /// The operation never satisfied the rules. Terminal.
    Invalid,
    /// Not yet decided, including while evidence is unavailable.
    Pending,
}

impl Resolution {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Resolution::Pending)
    }
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

/// The effect of a resolved position. Pending has no effect yet; Invalid never
/// has one, because the lineage is terminal there.
pub fn effect_of(resolution: Resolution) -> PositionEffect {
    match resolution {
        Resolution::Realized => PositionEffect::InstallRealizeRoot,
        Resolution::Void => PositionEffect::InstallPreviousRoot,
        Resolution::Invalid | Resolution::Pending => PositionEffect::None,
    }
}

/// What a verifier has established about the parent `(v, g, R)` a leg names,
/// against `R*_g` — the validated canonical root of that vault at that
/// generation (owner ruling, Section 44.4).
///
/// THREE VALUED, AND "UNKNOWN" IS NOT `false`. This replaced a pair of
/// booleans, `canonical_parent` and `parent_orphaned`, whose false-false
/// corner said two different things at once: a parent the verifier has not
/// walked to, and a parent it has walked past. The first must keep the
/// position Pending and the second must defeat it, so a verifier with no
/// producer for the second wrote `false` and silently meant the first.
///
/// The exclusion the ladder needs is now the type. `Coherent`'s assumption
/// that an orphaned parent is never canonical is not an assumption any more:
/// there is no value that is both.
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

/// The facts about one DLV leg of a registered fulfillment, at the attempt key
/// that fulfillment fixed for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegFacts {
    /// The storage resolution of `K^(a_j)`.
    pub cell: CellResolution,
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
        self.cell == CellResolution::Final(*e)
    }

    /// Some OTHER operation's commitment got to this key's leader first, or is
    /// already final there. Either way this operation can never be final at
    /// the key: `LeaderHeld` settles the race before the copies arrive.
    pub fn final_on_other(&self, e: &[u8; 32]) -> bool {
        matches!(
            self.cell,
            CellResolution::Final(v) | CellResolution::LeaderHeld(v) if v != *e
        )
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
/// on.
///
/// False while the parent is Pending: an undecided parent neither consumes nor
/// skips anything on its own.
pub fn trader_parent_compatible(parent: &ParentPosition, parent_pre_root: &[u8; 32]) -> bool {
    match parent {
        ParentPosition::SingleRoot => true,
        ParentPosition::ConditionalSelected { selected_root } => selected_root == parent_pre_root,
        ParentPosition::ConditionalPending | ParentPosition::ConditionalNoRoot => false,
    }
}

/// `TraderParentImpossible(P)`: the parent is terminal and did not select the
/// root this operation was built on — either it selected nothing (Invalid), or
/// it selected the other branch.
///
/// Objective and monotone, and false while the parent is Pending.
pub fn trader_parent_impossible(parent: &ParentPosition, parent_pre_root: &[u8; 32]) -> bool {
    match parent {
        ParentPosition::ConditionalNoRoot => true,
        ParentPosition::ConditionalSelected { selected_root } => selected_root != parent_pre_root,
        ParentPosition::SingleRoot | ParentPosition::ConditionalPending => false,
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
/// Arms (ii) to (v) need no validation evidence, so a stranded cell of an
/// impossible operation is skippable even while `RouteValidation` is
/// `Unavailable`. Arms (iv) and (v) create no `Void`: under (iv) the trader
/// position is Invalid through the ladder, under (v) the position went to
/// another claim and this `F` never resolves through it; both arms exist
/// only to stop an impossible operation stranding a DLV successor key.
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

/// The resolution ladder (Section 24). Verifier-local, deterministic, and
/// permanent once it is not `Pending`. The first matching rung decides.
///
/// | Rung | Result | Condition |
/// |---|---|---|
/// | 0 | Pending | F is not registered |
/// | 1 | Pending | the parent is a conditional claim that has not resolved |
/// | 2 | Invalid | the parent resolved and did not select this operation's root |
/// | 3 | Invalid | `FulfillmentConformance(F) = Invalid` |
/// | 4 | Pending | `FulfillmentConformance(F) = Unavailable` |
/// | 5 | Realized | `ConsumedRoute(F, E)` |
/// | 6 | Invalid | `RouteValidation = Invalid` |
/// | 7 | Void | both predicates Valid, storage-resolved, and the route is lost |
/// | 8 | Pending | otherwise, including `RouteValidation = Unavailable` |
///
/// Rungs 1 and 2 come before any route result: a position built on a branch
/// the parent never took is Invalid whatever its own legs did. Rungs 5 and 6
/// are Section 24's rows 5 to 7 in the order the Lean twin (`resolve`) states
/// them; the answers agree because `ConsumedRoute` carries `Valid`.
pub fn resolve_position(facts: &RouteFacts<'_>) -> Resolution {
    // 0 — nothing is exercised before registration.
    if !facts.registered {
        return Resolution::Pending;
    }
    // 1 — an undecided conditional parent decides nothing here yet.
    if facts.parent == ParentPosition::ConditionalPending {
        return Resolution::Pending;
    }
    // 2 — the parent took another branch, or none.
    if trader_parent_impossible(&facts.parent, &facts.parent_pre_root) {
        return Resolution::Invalid;
    }
    // 3 — the fulfillment never satisfied its own rules. Terminal, whatever
    // the cells say: registration supplied no truth value.
    if facts.conformance == Validation::Invalid {
        return Resolution::Invalid;
    }
    // 4 — conformance undecided. No route becomes Void while its conformance
    // is unknown (Section 21.1): a Void here could turn Invalid on evidence.
    if facts.conformance == Validation::Unavailable {
        return Resolution::Pending;
    }
    // 5 — the route consumed every required parent.
    if consumed_route(facts) {
        return Resolution::Realized;
    }
    // 6 — statically invalid, permanently.
    if facts.validation == Validation::Invalid {
        return Resolution::Invalid;
    }
    // 7 — both predicates Valid, storage-resolved, and lost. Validity first:
    // without it a route lost while evidence is Unavailable would Void and
    // then turn Invalid when the evidence arrived (R14-1).
    if facts.validation == Validation::Valid
        && facts.storage_resolved
        && (facts.a_reserved_key_is_lost() || facts.a_parent_is_lost())
    {
        return Resolution::Void;
    }
    // 8 — not decided. Evidence may still arrive.
    Resolution::Pending
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
        if let Some(arm) = route_impossible(facts) {
            let reason = if !facts.multi_leg() && arm == ImpossibleArm::ValidationInvalid {
                SkipReason::RejectedFinalSingleLeg
            } else {
                SkipReason::RejectedFinalRoute(arm)
            };
            return (AttemptClass::Skipped, Some(reason));
        }
        // A final cell is a CONSUMPTION only when the whole operation consumed
        // — the same E across every required leg, validation Valid, the trader
        // parent compatible. A leg's
        // own facts are not enough: one FinalE(E) cell is not one executed
        // swap (F4), and treating it as one is what would let a multi-leg
        // route consume a parent it never realized on.
        if consumed_route(facts) && leg.final_on(&facts.external_commitment) {
            return (AttemptClass::Consumed, None);
        }
    }
    // The leader holds another exercise first, or another exercise is final:
    // that key is the other operation's question, and this walker sees it as
    // unresolved until that operation's own facts settle it.
    if leg.final_on_other(&facts.external_commitment) {
        // Another operation's commitment sits here. Whether that consumed the
        // parent is that operation's question, not this one's.
        return (AttemptClass::Unresolved, None);
    }
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

/// Walk one DLV parent's attempt keys in ascending order: a skipped key moves
/// to the next, a consumed key stops, anything else stops as unresolved.
///
/// `keys` supplies the facts for attempt `a`, or `None` past what the caller
/// has fetched — which is `Unresolved`, never a skip. `budget` bounds the
/// examined keys only; it never changes the verdict, it only defers it.
pub fn walk<'f, F>(base_attempt: u64, budget: usize, mut keys: F) -> WalkOutcome
where
    F: FnMut(u64) -> Option<(RouteFacts<'f>, LegFacts)>,
{
    let mut attempt = base_attempt;
    for _ in 0..budget {
        match keys(attempt) {
            None => return WalkOutcome::Unresolved { attempt },
            Some((facts, leg)) => match classify_attempt(&facts, &leg).0 {
                AttemptClass::Consumed => return WalkOutcome::Consumed { attempt },
                AttemptClass::Unresolved => return WalkOutcome::Unresolved { attempt },
                AttemptClass::Skipped => match next_attempt(attempt) {
                    Ok(next) => attempt = next,
                    Err(_) => return WalkOutcome::CounterExhausted { attempt },
                },
            },
        }
    }
    WalkOutcome::Continue { cursor: attempt }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sofi::conformance::Validation::{Invalid, Unavailable, Valid};

    const E: [u8; 32] = [0xE5; 32];
    const OTHER_E: [u8; 32] = [0x11; 32];
    const PRE: [u8; 32] = [0x99; 32];
    const OTHER_ROOT: [u8; 32] = [0x77; 32];

    /// A leg that consumed its canonical parent on this operation's E.
    fn good_leg() -> LegFacts {
        LegFacts {
            cell: CellResolution::Final(E),
            parent: ParentStatus::Canonical,
            attempt_live: true,
            parent_consumed_elsewhere: false,
        }
    }

    fn pending_leg() -> LegFacts {
        LegFacts {
            cell: CellResolution::Unresolved,
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
    fn an_unregistered_fulfillment_is_pending_even_with_every_leg_final() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            registered: false,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Resolution::Pending);
        assert!(!consumed_route(&facts));
    }

    // ── steps 1–2: the trader parent (P15-3, R17-3) ────────────────────────

    /// Lean `conditional_parent_pending_keeps_the_position_pending`: q waits
    /// for p, and the wait is not a route verdict.
    #[test]
    fn a_conditional_parent_that_has_not_resolved_keeps_the_position_pending() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            parent: ParentPosition::ConditionalPending,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Resolution::Pending);
        // The parent alone neither consumes nor makes the route impossible.
        assert!(!trader_parent_compatible(&facts.parent, &PRE));
        assert!(!trader_parent_impossible(&facts.parent, &PRE));
        assert!(!consumed_route(&facts));
        assert_eq!(route_impossible(&facts), None);
    }

    /// Lean `conditional_parent_pending_keeps_the_position_pending`, TLA
    /// `PendingParentDecidesNothing`: an undecided parent OUTRANKS a lost leg.
    /// Voiding here would be the R14-1 break again in another guise — the
    /// parent could still select the other branch, whose answer is Invalid, so
    /// a terminal Void would have to be retracted.
    #[test]
    fn a_pending_parent_outranks_a_lost_leg_instead_of_voiding() {
        let legs = [LegFacts {
            cell: CellResolution::LeaderHeld(OTHER_E),
            ..good_leg()
        }];
        let waiting = RouteFacts {
            parent: ParentPosition::ConditionalPending,
            ..realized(&legs)
        };
        // Valid, storage-resolved and objectively lost — and still Pending.
        assert_eq!(waiting.validation, Valid);
        assert!(waiting.storage_resolved);
        assert_eq!(resolve_position(&waiting), Resolution::Pending);

        // The two ways the parent can settle, from those same facts.
        assert_eq!(
            resolve_position(&RouteFacts {
                parent: ParentPosition::ConditionalSelected {
                    selected_root: OTHER_ROOT,
                },
                ..waiting
            }),
            Resolution::Invalid
        );
        assert_eq!(
            resolve_position(&RouteFacts {
                parent: ParentPosition::ConditionalSelected { selected_root: PRE },
                ..waiting
            }),
            Resolution::Void
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
        assert_eq!(resolve_position(&facts), Resolution::Realized);
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
        assert_eq!(resolve_position(&facts), Resolution::Invalid);
        assert!(!consumed_route(&facts));
        assert_eq!(
            route_impossible(&facts),
            Some(ImpossibleArm::TraderParentImpossible)
        );
    }

    /// Lean `terminal_parent_with_no_root_is_invalid_without_evidence`: arm
    /// (iv) needs no validation evidence, so the DLV key still skips while
    /// `RouteValidation` is Unavailable.
    #[test]
    fn a_terminal_parent_that_selected_no_root_is_invalid_even_while_evidence_is_unavailable() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            parent: ParentPosition::ConditionalNoRoot,
            validation: Unavailable,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Resolution::Invalid);
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

    /// Lean `trader_parent_arm_is_monotone`: once the parent is terminal the
    /// arm never retracts, and a compatible parent never becomes impossible.
    #[test]
    fn the_trader_parent_arm_is_monotone() {
        // Pending is the only state where both are false; every terminal
        // state fixes exactly one of them, for every root.
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
                    "a terminal parent is exactly one of the two: {parent:?} against {root:?}"
                );
            }
        }
        let pending = ParentPosition::ConditionalPending;
        assert!(!trader_parent_compatible(&pending, &PRE));
        assert!(!trader_parent_impossible(&pending, &PRE));
    }

    // ── step 3: consumption ────────────────────────────────────────────────

    /// Lean `fulfillment_atomic_all_or_none`, TLA `NoPartialRealization`: one
    /// final leg is not one executed swap.
    #[test]
    fn a_route_with_one_leg_still_open_is_not_consumed() {
        let legs = [good_leg(), pending_leg()];
        let facts = RouteFacts { ..realized(&legs) };
        assert!(!consumed_route(&facts));
        assert_eq!(resolve_position(&facts), Resolution::Pending);
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
        assert_eq!(resolve_position(&facts), Resolution::Pending);
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

    /// THE THIRD VALUE IS NOT THE SECOND. A parent the verifier has not
    /// established keeps the position Pending; one it has established as
    /// another root defeats it. Under the pair of booleans this change
    /// replaced, both were `false` on both fields and the ladder could not
    /// tell them apart — so the verifier that had no producer for orphaning
    /// wrote the value that silently meant "not refuted" and hoped.
    #[test]
    fn an_unestablished_parent_waits_and_an_orphaned_one_defeats() {
        for (status, expected, arm) in [
            (ParentStatus::Unavailable, Resolution::Pending, None),
            (
                ParentStatus::Orphaned,
                Resolution::Void,
                Some(ImpossibleArm::ParentOrphaned),
            ),
            (ParentStatus::Canonical, Resolution::Realized, None),
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
        assert_eq!(resolve_position(&facts), Resolution::Void);
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
            Resolution::Invalid
        );
    }

    /// A parent that really was canonical and was then taken by another
    /// route is `parent_consumed_elsewhere`, not orphaned. The two are
    /// different facts with the same terminal answer, and keeping them apart
    /// is what lets a skip be attributed (owner ruling §44.4).
    ///
    /// The leg's own key is open: a cell final on THIS operation's `E` would
    /// say we consumed the parent ourselves, which is not a route another
    /// operation took. The first draft of this test asserted both at once and
    /// the ladder answered `Realized`, which was the test's error and not the
    /// ladder's.
    #[test]
    fn a_canonical_parent_taken_by_another_route_is_consumed_not_orphaned() {
        let legs = [LegFacts {
            cell: CellResolution::Unresolved,
            parent: ParentStatus::Canonical,
            parent_consumed_elsewhere: true,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert_eq!(resolve_position(&facts), Resolution::Void);
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
        let legs = [pending_leg()];
        let facts = RouteFacts {
            validation: Invalid,
            storage_resolved: false,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Resolution::Invalid);
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
            cell: CellResolution::Unresolved,
            parent_consumed_elsewhere: true,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert_eq!(resolve_position(&facts), Resolution::Void);
        assert_eq!(
            effect_of(Resolution::Void),
            PositionEffect::InstallPreviousRoot
        );
    }

    /// A reserved key that died, and an objective abort, are both Void.
    #[test]
    fn a_reserved_key_another_operation_reached_first_voids() {
        let taken = [LegFacts {
            cell: CellResolution::LeaderHeld(OTHER_E),
            ..good_leg()
        }];
        assert_eq!(resolve_position(&realized(&taken)), Resolution::Void);
    }

    /// Lean `resolution_is_permanent` and its counterexample
    /// `literal_ladder_is_not_permanent`, TLA falsification
    /// `VoidBeforeValidation`: a route already lost stays Pending while
    /// evidence is Unavailable, then resolves once — Void if it was valid,
    /// Invalid if it never was. Voiding first would flip a terminal answer.
    #[test]
    fn a_lost_route_waits_for_evidence_instead_of_voiding() {
        let legs = [LegFacts {
            cell: CellResolution::LeaderHeld(OTHER_E),
            ..good_leg()
        }];
        let unavailable = RouteFacts {
            validation: Unavailable,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&unavailable), Resolution::Pending);

        // The same facts once the evidence lands, both ways.
        assert_eq!(
            resolve_position(&RouteFacts {
                validation: Valid,
                ..unavailable
            }),
            Resolution::Void
        );
        assert_eq!(
            resolve_position(&RouteFacts {
                validation: Invalid,
                ..unavailable
            }),
            Resolution::Invalid
        );
    }

    /// Void needs storage resolution: a route that merely looks lost while its
    /// keys are open is still Pending.
    #[test]
    fn void_requires_storage_resolution() {
        let legs = [LegFacts {
            parent: ParentStatus::Orphaned,
            cell: CellResolution::Unresolved,
            ..good_leg()
        }];
        let facts = RouteFacts {
            storage_resolved: false,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Resolution::Pending);
    }

    // ── rungs 3–4: FulfillmentConformance (R12) ───────────────────────────

    /// Lean `realized_requires_conformance`, TLA `RealizedRequiresConformance`
    /// (fault `_ConformanceDropped`): FulfillmentConformance is a conjunct of
    /// ConsumedRoute. A registered, statically valid route with every leg
    /// final on its E does not realize until its conformance is Valid — and
    /// never does once it is Invalid.
    #[test]
    fn realized_requires_conformance() {
        let legs = [good_leg(), good_leg()];
        let undecided = RouteFacts {
            conformance: Unavailable,
            ..realized(&legs)
        };
        assert!(!consumed_route(&undecided));
        assert_eq!(resolve_position(&undecided), Resolution::Pending);
        let never = RouteFacts {
            conformance: Invalid,
            ..realized(&legs)
        };
        assert!(!consumed_route(&never));
        assert_eq!(resolve_position(&never), Resolution::Invalid);
        assert_eq!(effect_of(resolve_position(&never)), PositionEffect::None);
        // Only Valid realizes, and the effect is the realize root.
        assert!(consumed_route(&realized(&legs)));
        assert_eq!(resolve_position(&realized(&legs)), Resolution::Realized);
        assert_eq!(
            effect_of(resolve_position(&realized(&legs))),
            PositionEffect::InstallRealizeRoot
        );
    }

    /// Lean `registration_is_not_conformance`, TLA `RegistrationIsNotConformance`:
    /// registration supplies no truth value. The same registered facts with
    /// conformance anything but Valid never realize.
    #[test]
    fn registration_is_not_conformance() {
        let legs = [good_leg()];
        for conformance in [Invalid, Unavailable] {
            let facts = RouteFacts {
                conformance,
                ..realized(&legs)
            };
            assert!(facts.registered);
            assert_ne!(resolve_position(&facts), Resolution::Realized);
        }
    }

    /// Section 21.1: no route becomes Void while its conformance is unknown.
    /// A registered, valid route already lost at a reserved key stays Pending
    /// until conformance decides, then resolves once — Void if it conformed,
    /// Invalid if it never did.
    #[test]
    fn no_route_becomes_void_while_its_conformance_is_unknown() {
        let legs = [LegFacts {
            cell: CellResolution::LeaderHeld(OTHER_E),
            ..good_leg()
        }];
        let unknown = RouteFacts {
            conformance: Unavailable,
            ..realized(&legs)
        };
        assert!(unknown.storage_resolved && unknown.validation == Valid);
        assert_eq!(resolve_position(&unknown), Resolution::Pending);
        assert_eq!(
            resolve_position(&RouteFacts {
                conformance: Valid,
                ..unknown
            }),
            Resolution::Void
        );
        assert_eq!(
            resolve_position(&RouteFacts {
                conformance: Invalid,
                ..unknown
            }),
            Resolution::Invalid
        );
    }

    // ── arm (v): the position went to another claim (R12) ────────────────

    /// TLA `LostPosition` (fault `_LostPositionDropped` →
    /// `ObjectiveRejectionImpliesSkipped`), Lean
    /// `a_lost_position_makes_a_final_route_skippable`: an exercise final at a
    /// key whose F can never register — the position holds another claim —
    /// is skipped, with no validation evidence, so the parent's attempt chain
    /// is not stranded. It is no Void: the position resolves through the claim
    /// that took it, never through this F.
    #[test]
    fn a_final_cell_whose_fulfillment_lost_its_position_is_skipped() {
        let legs = [good_leg()];
        let facts = RouteFacts {
            registered: false,
            position_lost: true,
            conformance: Unavailable,
            validation: Unavailable,
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
        assert_eq!(resolve_position(&facts), Resolution::Pending);
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
    /// another terminal answer as facts accumulate monotonically. Checked by
    /// enumeration over every fact combination the ladder reads.
    #[test]
    fn a_terminal_resolution_is_never_reached_from_another_terminal_one() {
        let cells = [
            CellResolution::Final(E),
            CellResolution::Final(OTHER_E),
            CellResolution::LeaderHeld(OTHER_E),
            CellResolution::Unresolved,
        ];
        let parents = [
            ParentPosition::SingleRoot,
            ParentPosition::ConditionalPending,
            ParentPosition::ConditionalSelected { selected_root: PRE },
            ParentPosition::ConditionalSelected {
                selected_root: OTHER_ROOT,
            },
            ParentPosition::ConditionalNoRoot,
        ];
        for cell in cells {
            for parent in parents {
                for validation in [Valid, Invalid, Unavailable] {
                    for conformance in [Valid, Invalid, Unavailable] {
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
                            // Evidence arriving is the only monotone step that
                            // can change an Unavailable verdict — for either
                            // predicate.
                            if validation == Unavailable {
                                for settled in [Valid, Invalid] {
                                    let after = resolve_position(&RouteFacts {
                                        validation: settled,
                                        ..facts
                                    });
                                    assert!(
                                        before == Resolution::Pending || before == after,
                                        "{before:?} changed to {after:?} on evidence"
                                    );
                                }
                            }
                            if conformance == Unavailable {
                                for settled in [Valid, Invalid] {
                                    let after = resolve_position(&RouteFacts {
                                        conformance: settled,
                                        ..facts
                                    });
                                    assert!(
                                        before == Resolution::Pending || before == after,
                                        "{before:?} changed to {after:?} on conformance evidence"
                                    );
                                }
                            }
                            // Storage resolving cannot flip a terminal answer.
                            if !storage_resolved {
                                let after = resolve_position(&RouteFacts {
                                    storage_resolved: true,
                                    ..facts
                                });
                                assert!(
                                    before == Resolution::Pending || before == after,
                                    "{before:?} changed to {after:?} on storage resolution"
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
        assert_eq!(effect_of(Resolution::Pending), PositionEffect::None);
    }

    // ── impossibility arms and the walk ────────────────────────────────────

    /// Lean `route_impossible_orphan_and_consumed_elsewhere_arms`: arms (ii)
    /// and (iii′) hold without any validation evidence.
    #[test]
    fn the_orphan_and_consumed_elsewhere_arms_need_no_evidence() {
        let orphaned = [LegFacts {
            parent: ParentStatus::Orphaned,
            ..good_leg()
        }];
        let facts = RouteFacts {
            validation: Unavailable,
            ..realized(&orphaned)
        };
        assert_eq!(
            route_impossible(&facts),
            Some(ImpossibleArm::ParentOrphaned)
        );

        let taken = [LegFacts {
            parent_consumed_elsewhere: true,
            ..good_leg()
        }];
        let facts = RouteFacts {
            validation: Unavailable,
            ..realized(&taken)
        };
        assert_eq!(
            route_impossible(&facts),
            Some(ImpossibleArm::ParentConsumedElsewhere)
        );
    }

    /// Lean `stranded_e_cell_is_not_partial_execution`: a final cell of an
    /// impossible route is skipped, and skipping it is not a rollback.
    #[test]
    fn a_stranded_final_cell_of_an_impossible_route_is_skipped() {
        let legs = [good_leg(), pending_leg()];
        let facts = RouteFacts {
            legs: &legs,
            ..RouteFacts {
                validation: Unavailable,
                ..realized(&legs)
            }
        };
        let lost = [
            LegFacts {
                parent: ParentStatus::Orphaned,
                ..pending_leg()
            },
            good_leg(),
        ];
        let facts = RouteFacts {
            legs: &lost,
            ..facts
        };
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
            cell: CellResolution::LeaderHeld(OTHER_E),
            ..good_leg()
        }];
        let facts = RouteFacts {
            validation: Unavailable,
            ..realized(&legs)
        };
        assert_eq!(
            classify_attempt(&facts, &legs[0]),
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
            cell: CellResolution::Final(OTHER_E),
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
            Some((
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
        let legs = [good_leg(), pending_leg()];
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

    /// A final cell whose route is not statically Valid is not a consumption
    /// either — consumption carries the validation premise (F4).
    #[test]
    fn a_final_leg_of_an_unvalidated_route_is_not_consumed() {
        let legs = [good_leg()];
        let unavailable = RouteFacts {
            validation: Unavailable,
            ..realized(&legs)
        };
        assert_eq!(
            classify_attempt(&unavailable, &legs[0]).0,
            AttemptClass::Unresolved
        );
    }

    /// The attempt counter is checked, never saturated: a walk that reaches
    /// `u64::MAX` refuses rather than re-examining a key it already decided.
    #[test]
    fn the_attempt_counter_is_checked_not_saturated() {
        // Every key is skipped (final on a rejected exercise), so the walk
        // would advance forever; at `u64::MAX` it refuses instead.
        let rejected = LegFacts {
            cell: CellResolution::Final(OTHER_E),
            ..good_leg()
        };
        let legs = [rejected];
        let facts_for = |_attempt: u64| {
            Some((
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
                cell: CellResolution::Final(OTHER_E),
                ..good_leg()
            },
        ];
        let facts = RouteFacts { ..realized(&legs) };
        assert_eq!(facts.external_commitment, E);
        assert!(
            !consumed_route(&facts),
            "a leg final on another operation's E is not this route's consumption"
        );
        assert_ne!(resolve_position(&facts), Resolution::Realized);
        // It is the loss of the route, not a consumption: the second leg's key
        // is final on someone else's commitment.
        assert_eq!(resolve_position(&facts), Resolution::Void);
        // And the stray leg is never classified as consuming this route.
        assert_eq!(
            classify_attempt(&facts, &legs[1]).0,
            AttemptClass::Unresolved
        );
    }
}
