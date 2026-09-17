// SPDX-License-Identifier: Apache-2.0

//! The verifier-local resolution core: facts in, one permanent answer out.
//!
//! Every function here is pure and total over the facts it is handed. It
//! fetches nothing, trusts no caller's opinion, and evaluates no policy: a
//! fact is either an objective storage observation ([`CellResolution`]), a
//! static validity verdict ([`Validation`]), or a monotone register fact
//! (registration, canonicality, orphaning, an outcome). Where those facts come
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
//! fulfillment, which is why [`consumed_route`] quantifies over all legs and
//! takes the multi-leg outcome into account.

use super::arith::CellResolution;
use super::conformance::Validation;
use super::wire::OutcomeCell;

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

/// The facts about one DLV leg of a registered fulfillment, at the attempt key
/// that fulfillment fixed for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegFacts {
    /// The storage resolution of `K^(a_j)`.
    pub cell: CellResolution,
    /// The named parent `R_j` is this vault's canonical ancestry.
    pub canonical_parent: bool,
    /// `∀ b < a_j. Skipped(K^(b))`.
    pub attempt_live: bool,
    /// The named parent is permanently orphaned.
    pub parent_orphaned: bool,
    /// The named parent was consumed by some `X ≠ E`.
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

    /// The leg's cell is final on some OTHER operation's commitment.
    pub fn final_on_other(&self, e: &[u8; 32]) -> bool {
        matches!(self.cell, CellResolution::Final(v) if v != *e)
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
    /// What is known about the claim at `p`.
    pub parent: ParentPosition,
    /// `P.void_root == T°.pre_root`.
    pub parent_pre_root: [u8; 32],
    /// `RouteValidation(P, G, E)`, static.
    pub validation: Validation,
    /// `StorageResolved(q)`: registration, every successor key, and the
    /// outcome for a multi-leg F.
    pub storage_resolved: bool,
    /// One entry per leg of `P`, in P's leg order. A single-vault trade is the
    /// one-leg case.
    pub legs: &'legs [LegFacts],
    /// The route outcome at `K_out(F)`, where one is required.
    pub outcome: Option<OutcomeCell>,
}

impl RouteFacts<'_> {
    fn multi_leg(&self) -> bool {
        self.legs.len() > 1
    }

    /// A reserved key of this fulfillment is Dead, or final on another
    /// commitment.
    fn a_reserved_key_is_lost(&self) -> bool {
        self.legs
            .iter()
            .any(|l| l.cell == CellResolution::Dead || l.final_on_other(&self.external_commitment))
    }

    fn a_parent_is_lost(&self) -> bool {
        self.legs
            .iter()
            .any(|l| l.parent_orphaned || l.parent_consumed_elsewhere)
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

/// `ConsumedRoute(F, E)`: registered, statically valid, built on the branch the
/// parent actually took, and every required leg finally consumed its exact
/// canonical parent on this `E` at a live attempt — plus, for a multi-leg
/// route, an objective `CompleteFinal(F)`.
///
/// This is where parent canonicality lives. `RouteValidation` never looks at
/// it, so a static verdict cannot depend on who won a race.
pub fn consumed_route(facts: &RouteFacts<'_>) -> bool {
    facts.registered
        && facts.validation == Validation::Valid
        && trader_parent_compatible(&facts.parent, &facts.parent_pre_root)
        && !facts.legs.is_empty()
        && facts
            .legs
            .iter()
            .all(|l| l.canonical_parent && l.attempt_live && l.final_on(&facts.external_commitment))
        && (!facts.multi_leg() || facts.outcome == Some(OutcomeCell::Complete))
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
}

/// The arm of `RouteImpossible(P, E)` that holds, in arm order.
///
/// Arms (ii), (iii′) and (iv) need no validation evidence, so a stranded cell
/// of an impossible operation is skippable even while `RouteValidation` is
/// `Unavailable`. Arm (iv) creates no `Void`: the trader position is Invalid
/// through the ladder, and the arm exists only to stop an impossible operation
/// stranding a DLV successor key.
pub fn route_impossible(facts: &RouteFacts<'_>) -> Option<ImpossibleArm> {
    if facts.validation == Validation::Invalid {
        return Some(ImpossibleArm::ValidationInvalid);
    }
    if facts.legs.iter().any(|l| l.parent_orphaned) {
        return Some(ImpossibleArm::ParentOrphaned);
    }
    if facts.legs.iter().any(|l| l.parent_consumed_elsewhere) {
        return Some(ImpossibleArm::ParentConsumedElsewhere);
    }
    if trader_parent_impossible(&facts.parent, &facts.parent_pre_root) {
        return Some(ImpossibleArm::TraderParentImpossible);
    }
    None
}

/// The F2 resolution ladder, steps 0 through 6. Verifier-local, deterministic,
/// and permanent once it is not `Pending`.
///
/// | Step | Result | Condition |
/// |---|---|---|
/// | 0 | Pending | F is not registered |
/// | 1 | Pending | the parent is a conditional claim that has not resolved |
/// | 2 | Invalid | the parent resolved and did not select this operation's root |
/// | 3 | Realized | `ConsumedRoute(F, E)` |
/// | 4 | Invalid | `RouteValidation = Invalid` |
/// | 5 | Void | Valid, storage-resolved, and the route is lost |
/// | 6 | Pending | otherwise, including `Unavailable` |
///
/// Steps 1 and 2 come before any route result: a position built on a branch
/// the parent never took is Invalid whatever its own legs did.
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
    // 3 — the route consumed every required parent.
    if consumed_route(facts) {
        return Resolution::Realized;
    }
    // 4 — statically invalid, permanently.
    if facts.validation == Validation::Invalid {
        return Resolution::Invalid;
    }
    // 5 — valid, storage-resolved, and lost. Validity first: without it a
    // route lost while evidence is Unavailable would Void and then turn
    // Invalid when the evidence arrived (R14-1).
    if facts.validation == Validation::Valid
        && facts.storage_resolved
        && (facts.a_reserved_key_is_lost()
            || facts.a_parent_is_lost()
            || facts.outcome == Some(OutcomeCell::Abort))
    {
        return Resolution::Void;
    }
    // 6 — not decided. Evidence may still arrive.
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
    /// The cell can never reach finality under any completion.
    Dead,
    /// A final cell of a single-leg operation whose validation is Invalid.
    RejectedFinalSingleLeg,
    /// A final cell of an operation that can never realize.
    RejectedFinalRoute(ImpossibleArm),
    /// A registered fulfillment whose route objectively aborted.
    AbortFinalRoute,
}

/// Classify the attempt key of `leg` under the facts of the registered
/// fulfillment that reserved it.
///
/// A key is skippable on `Dead`, on a final cell of an operation that can
/// never realize, or on an objective abort. `AbortFinal` is safe because
/// `K_ful` exclusivity means the aborted fulfillment is the only one that
/// could have realized on this key.
pub fn classify_attempt(
    facts: &RouteFacts<'_>,
    leg: &LegFacts,
) -> (AttemptClass, Option<SkipReason>) {
    if leg.cell == CellResolution::Dead {
        return (AttemptClass::Skipped, Some(SkipReason::Dead));
    }
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
        if facts.registered && facts.outcome == Some(OutcomeCell::Abort) {
            return (AttemptClass::Skipped, Some(SkipReason::AbortFinalRoute));
        }
        // A final cell is a CONSUMPTION only when the whole operation consumed
        // — the same E across every required leg, validation Valid, the trader
        // parent compatible, and, for a route, an objective Complete. A leg's
        // own facts are not enough: one FinalE(E) cell is not one executed
        // swap (F4), and treating it as one is what would let a multi-leg
        // route consume a parent it never realized on.
        if consumed_route(facts) && leg.final_on(&facts.external_commitment) {
            return (AttemptClass::Consumed, None);
        }
    }
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
                AttemptClass::Skipped => match attempt.checked_add(1) {
                    Some(next) => attempt = next,
                    None => return WalkOutcome::CounterExhausted { attempt },
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
            canonical_parent: true,
            attempt_live: true,
            parent_orphaned: false,
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
            parent: ParentPosition::SingleRoot,
            parent_pre_root: PRE,
            validation: Valid,
            storage_resolved: true,
            legs,
            outcome: None,
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
            cell: CellResolution::Dead,
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
        let facts = RouteFacts {
            outcome: None,
            ..realized(&legs)
        };
        assert!(!consumed_route(&facts));
        assert_eq!(resolve_position(&facts), Resolution::Pending);
    }

    /// A multi-leg route needs the objective outcome, not just its cells.
    #[test]
    fn a_multi_leg_route_needs_complete_final() {
        let legs = [good_leg(), good_leg()];
        let without = RouteFacts {
            outcome: None,
            ..realized(&legs)
        };
        assert!(!consumed_route(&without));
        assert_eq!(resolve_position(&without), Resolution::Pending);
        let with = RouteFacts {
            outcome: Some(OutcomeCell::Complete),
            ..realized(&legs)
        };
        assert!(consumed_route(&with));
        assert_eq!(resolve_position(&with), Resolution::Realized);
    }

    /// Lean `route_validation_excludes_parent_canonicality`: canonicality is a
    /// consumption question, so a non-canonical parent cannot realize even
    /// though validation says Valid.
    #[test]
    fn a_non_canonical_parent_never_consumes() {
        let legs = [LegFacts {
            canonical_parent: false,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert!(!consumed_route(&facts));
        assert_eq!(resolve_position(&facts), Resolution::Pending);
    }

    /// A dead attempt index below this one means the fulfillment's own key was
    /// never live, so nothing it holds is a consumption.
    #[test]
    fn a_dead_earlier_attempt_makes_this_key_not_live_and_not_consumed() {
        let legs = [LegFacts {
            attempt_live: false,
            ..good_leg()
        }];
        let facts = realized(&legs);
        assert!(!consumed_route(&facts));
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
    fn a_dead_reserved_key_or_an_abort_voids() {
        let dead = [LegFacts {
            cell: CellResolution::Dead,
            ..good_leg()
        }];
        assert_eq!(resolve_position(&realized(&dead)), Resolution::Void);

        let legs = [good_leg(), pending_leg()];
        let aborted = RouteFacts {
            outcome: Some(OutcomeCell::Abort),
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&aborted), Resolution::Void);
    }

    /// Lean `resolution_is_permanent` and its counterexample
    /// `literal_ladder_is_not_permanent`, TLA falsification
    /// `VoidBeforeValidation`: a route already lost stays Pending while
    /// evidence is Unavailable, then resolves once — Void if it was valid,
    /// Invalid if it never was. Voiding first would flip a terminal answer.
    #[test]
    fn a_lost_route_waits_for_evidence_instead_of_voiding() {
        let legs = [LegFacts {
            cell: CellResolution::Dead,
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
            parent_orphaned: true,
            cell: CellResolution::Unresolved,
            ..good_leg()
        }];
        let facts = RouteFacts {
            storage_resolved: false,
            ..realized(&legs)
        };
        assert_eq!(resolve_position(&facts), Resolution::Pending);
    }

    // ── step 6, and the ladder as a whole ──────────────────────────────────

    /// Lean `resolution_is_permanent`: no terminal answer is reachable from
    /// another terminal answer as facts accumulate monotonically. Checked by
    /// enumeration over every fact combination the ladder reads.
    #[test]
    fn a_terminal_resolution_is_never_reached_from_another_terminal_one() {
        let cells = [
            CellResolution::Final(E),
            CellResolution::Final(OTHER_E),
            CellResolution::Dead,
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
                    for storage_resolved in [false, true] {
                        for outcome in [None, Some(OutcomeCell::Complete), Some(OutcomeCell::Abort)]
                        {
                            let legs = [LegFacts { cell, ..good_leg() }];
                            let facts = RouteFacts {
                                external_commitment: E,
                                registered: true,
                                parent,
                                parent_pre_root: PRE,
                                validation,
                                storage_resolved,
                                legs: &legs,
                                outcome,
                            };
                            let before = resolve_position(&facts);
                            // Evidence arriving is the only monotone step that
                            // can change an Unavailable verdict.
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
            parent_orphaned: true,
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
                parent_orphaned: true,
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

    /// A dead cell is skippable with no reference to the operation at all.
    #[test]
    fn a_dead_cell_is_skipped_on_the_storage_fact_alone() {
        let legs = [LegFacts {
            cell: CellResolution::Dead,
            ..good_leg()
        }];
        let facts = RouteFacts {
            validation: Unavailable,
            ..realized(&legs)
        };
        assert_eq!(
            classify_attempt(&facts, &legs[0]),
            (AttemptClass::Skipped, Some(SkipReason::Dead))
        );
    }

    /// An abort makes the key skippable; `K_ful` exclusivity is what makes
    /// that safe.
    #[test]
    fn an_aborted_route_makes_its_final_key_skippable() {
        let legs = [good_leg(), good_leg()];
        let facts = RouteFacts {
            outcome: Some(OutcomeCell::Abort),
            ..realized(&legs)
        };
        assert_eq!(
            classify_attempt(&facts, &legs[0]),
            (AttemptClass::Skipped, Some(SkipReason::AbortFinalRoute))
        );
    }

    /// The walk passes skipped keys, stops on a consumption, and the answer is
    /// the same however the budget chunks it.
    #[test]
    fn the_walk_is_chunking_equivalent() {
        let dead = LegFacts {
            cell: CellResolution::Dead,
            ..good_leg()
        };
        // The facts describe the ROUTE the key belongs to, because a key is
        // consumed only when its whole operation is.
        let dead_legs = [dead];
        let live_legs = [good_leg()];
        let facts_for = |attempt: u64| {
            let (legs, leg): (&[LegFacts], LegFacts) = if attempt < 3 {
                (&dead_legs, dead)
            } else {
                (&live_legs, good_leg())
            };
            Some((
                RouteFacts {
                    external_commitment: E,
                    registered: true,
                    parent: ParentPosition::SingleRoot,
                    parent_pre_root: PRE,
                    validation: Valid,
                    storage_resolved: true,
                    legs,
                    outcome: None,
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
    /// route consumes only when every required leg did and the outcome says
    /// Complete. One FinalE(E) cell is not one executed swap.
    #[test]
    fn a_final_leg_of_an_incomplete_route_is_not_consumed() {
        let legs = [good_leg(), pending_leg()];
        let facts = RouteFacts {
            outcome: None,
            ..realized(&legs)
        };
        assert_eq!(
            classify_attempt(&facts, &legs[0]),
            (AttemptClass::Unresolved, None)
        );
        // With every leg final AND the objective Complete, it consumes.
        let done = [good_leg(), good_leg()];
        let complete = RouteFacts {
            outcome: Some(OutcomeCell::Complete),
            ..realized(&done)
        };
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
        let dead = LegFacts {
            cell: CellResolution::Dead,
            ..good_leg()
        };
        let legs = [dead];
        let facts_for = |_attempt: u64| {
            Some((
                RouteFacts {
                    external_commitment: E,
                    registered: true,
                    parent: ParentPosition::SingleRoot,
                    parent_pre_root: PRE,
                    validation: Valid,
                    storage_resolved: true,
                    legs: &legs,
                    outcome: None,
                },
                dead,
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
        let facts = RouteFacts {
            outcome: Some(OutcomeCell::Complete),
            ..realized(&legs)
        };
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
