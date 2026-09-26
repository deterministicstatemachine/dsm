// SPDX-License-Identifier: Apache-2.0

//! What a verifier established about one exercise, from what it read: the
//! facts the resolution ladder reads, built here and nowhere else.
//!
//! Stage 9 of §31 and rebuild step R12 split the work in two. The SDK
//! fetches: the position pair, the attempt cells, the objects conformance
//! and validation consume, a vault's genesis. Core establishes: every read is
//! evaluated by Core into a fact bound to what it was read at
//! ([`RegistrationRead`], [`AttemptCellRead`], [`AttemptWalk`],
//! [`VaultChain`]), and [`establish`] turns those facts, over the evidence,
//! into the [`RouteFacts`] the ladder reads. The predicates are recomputed
//! here — `FulfillmentConformance` and `RouteValidation` over the evidence
//! in hand — so no value the ladder reads was ever stated by a caller.
//!
//! An exercise refuted by its own bytes reads nothing more
//! ([`refuted_in_hand`], MR-DSM-0041, MR-DSM-0042): for the trader's own
//! position, its registration is the one fact the ladder asks of it (§24
//! step 0); at a walked key, the cell it was found at.
//!
//! A fact this verifier has not established is never handed to the ladder in
//! another fact's place: it is [`NotEstablished`], named, and the caller
//! reads and relays again (Amendment S7). The one three-valued fact is a
//! leg's parent status, whose `Unavailable` is the ladder's own value for a
//! parent the verifier's chain has not reached.

use std::collections::BTreeMap;

use crate::economic::lineage::AdmittedEconomicPosition;
use crate::route_chain::{CellFact, ChainState, Missing as CellMissing};

use super::conformance::{
    conformance_invalid_in_hand, fulfillment_conformance, ConformanceEvidence, ConformanceMissing,
    Validation,
};
use super::derive;
use super::exercise::{AttemptCellRead, RecognizedExercise};
use super::registration::{Registration, RegistrationRead};
use super::resolution::{
    AttemptWalk, LegFacts, ParentPosition, ParentStatus, RefutedInHand, RouteFacts, VaultChain,
};
use super::validation::{route_invalid_in_hand, route_validation, vault_post_states, Evidence, Missing};
use super::wire::{ParentClaimRef, SettlementPreimage};

type D32 = [u8; 32];

/// An exercise refuted by its own bytes, bound to the exercise it refutes:
/// `FulfillmentConformance(F) = Invalid` from the exercise alone, or
/// `RouteValidation(P, G, E) = Invalid` from `P` and `P(E)` alone. Built by
/// [`refuted_in_hand`] over those bytes and by nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InHandRefutation {
    external_commitment: D32,
    fulfillment_id: D32,
    refuted: RefutedInHand,
}

impl InHandRefutation {
    pub fn external_commitment(&self) -> &D32 {
        &self.external_commitment
    }

    pub fn fulfillment_id(&self) -> &D32 {
        &self.fulfillment_id
    }

    pub fn refuted(&self) -> RefutedInHand {
        self.refuted
    }
}

/// What the exercise's own bytes refute, before any read (MR-DSM-0041).
pub fn refuted_in_hand(exercise: &RecognizedExercise) -> Option<InHandRefutation> {
    let bind = |refuted| InHandRefutation {
        external_commitment: exercise.external_commitment,
        fulfillment_id: derive::fulfillment_id(&exercise.fulfillment.body),
        refuted,
    };
    if conformance_invalid_in_hand(
        &exercise.precommit,
        &exercise.fulfillment.body,
        &exercise.fulfillment.signature,
        &exercise.preimage,
        &exercise.closure,
    )
    .is_some()
    {
        return Some(bind(RefutedInHand::Conformance));
    }
    route_invalid_in_hand(&exercise.precommit.body, &exercise.preimage)?;
    Some(bind(RefutedInHand::Route {
        legs: exercise.precommit.body.legs().len(),
    }))
}

/// A fact the ladder reads that this verifier has not established. Never a
/// result and never recorded: the caller reads, relays and retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotEstablished {
    /// The reads of the position pair do not decide registration yet.
    Registration(CellMissing),
    /// Conformance evidence not in hand after the retry budget.
    ConformanceEvidence(Vec<ConformanceMissing>),
    /// Route evidence not in hand after the retry budget.
    RouteEvidence(Vec<Missing>),
    /// Route evidence with no source this verifier can acquire it from: the
    /// leaf pre values of another trader's route.
    RouteEvidenceHasNoSource(Vec<Missing>),
    /// `P` names a conditional parent this verifier has not resolved.
    ParentUnresolved { fulfillment_id: D32 },
    /// A leg's attempt cell is not decided by its reads yet.
    AttemptCell {
        vault_id: D32,
        attempt: u64,
        missing: CellMissing,
    },
    /// A leg's earlier keys were not all classified: past the walk budget or
    /// the chain depth, or a key among them is not resolved.
    AttemptLiveness { vault_id: D32, attempt: u64 },
    /// The reads handed over are not about this exercise: a registration of
    /// another position, a cell of another key, evidence of another
    /// operation. Not a network status — the caller mis-assembled them —
    /// and never a verdict.
    NotThisExercise(&'static str),
}

/// What was read about one leg of `P`: its attempt cell, the vault's chain
/// as this verifier established it, and the walk over the earlier keys of
/// that leg's chain when its attempt is above zero.
#[derive(Debug, Clone, Copy)]
pub struct LegReads<'a> {
    pub cell: &'a AttemptCellRead,
    /// The canonical chain of the leg's vault, when this verifier has one.
    /// A vault with no chain is `Unavailable` for the leg naming it.
    pub chain: Option<&'a VaultChain>,
    /// The walk from the first key of the leg's parent, for
    /// `AttemptLive(K^(a))`. Not needed at attempt zero.
    pub walk: Option<&'a AttemptWalk>,
}

/// Everything that was read about one exercise, each item as Core evaluated
/// it.
#[derive(Debug, Clone, Copy)]
pub struct ExerciseReads<'a> {
    pub exercise: &'a RecognizedExercise,
    /// The position pair of `F.q`, routed by the root `P` was built on.
    pub registration: &'a RegistrationRead,
    /// What `FulfillmentConformance(F)` reads.
    pub conformance: &'a ConformanceEvidence,
    /// What `RouteValidation(P, G, E)` reads.
    pub evidence: &'a Evidence,
    /// This verifier's own admitted position at `P.p`, when `P` names a
    /// conditional parent: what that position selected is what this
    /// verifier itself resolved. Nothing else resolves a parent.
    pub parent: Option<&'a AdmittedEconomicPosition>,
    /// One entry per leg of `P`, in P's leg order.
    pub legs: &'a [LegReads<'a>],
}

/// The complete facts of one exercise, as this verifier established them:
/// what the ladder reads, and the evidence it was read over. Built by
/// [`establish`] and by nothing else; `pub(crate)` fields so that the
/// ladder's own tests can state facts, and nothing outside this crate can.
#[derive(Debug, Clone)]
pub struct EstablishedFacts {
    pub(crate) fulfillment_id: D32,
    pub(crate) external_commitment: D32,
    pub(crate) registered: bool,
    pub(crate) conformance: Validation,
    pub(crate) position_lost: bool,
    pub(crate) parent: ParentPosition,
    pub(crate) parent_pre_root: D32,
    pub(crate) validation: Validation,
    pub(crate) storage_resolved: bool,
    /// One per leg of `P`, in P's leg order.
    pub(crate) legs: Vec<LegFacts>,
    /// The key each leg's facts are about: `(vault, parent root, attempt)`.
    pub(crate) keys: Vec<(D32, D32, u64)>,
    /// `P(E)`, as the exercise carries it.
    pub(crate) preimage: SettlementPreimage,
    /// The evidence `RouteValidation` was decided over — the same bytes a
    /// realized advance derives its credits and balances from.
    pub(crate) evidence: Evidence,
}

impl EstablishedFacts {
    pub fn fulfillment_id(&self) -> &D32 {
        &self.fulfillment_id
    }

    pub fn external_commitment(&self) -> &D32 {
        &self.external_commitment
    }

    pub fn preimage(&self) -> &SettlementPreimage {
        &self.preimage
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub(crate) fn route_facts(&self) -> RouteFacts<'_> {
        RouteFacts {
            external_commitment: self.external_commitment,
            registered: self.registered,
            conformance: self.conformance,
            position_lost: self.position_lost,
            parent: self.parent,
            parent_pre_root: self.parent_pre_root,
            validation: self.validation,
            storage_resolved: self.storage_resolved,
            legs: &self.legs,
        }
    }

    /// The facts of the leg at `K^(attempt)` of `vault_id` at `parent_root`,
    /// when `P` has one there.
    pub(crate) fn leg_at(
        &self,
        vault_id: &D32,
        parent_root: &D32,
        attempt: u64,
    ) -> Option<LegFacts> {
        self.keys
            .iter()
            .position(|k| *k == (*vault_id, *parent_root, attempt))
            .and_then(|i| self.legs.get(i).copied())
    }
}

/// What this verifier established about the trader's own exercise: its
/// complete facts, or that its own bytes refute it. The one input a resolved
/// advance takes.
#[derive(Debug, Clone)]
pub enum Established {
    Facts(Box<EstablishedFacts>),
    RefutedInHand(RefutedPosition),
}

/// A position whose exercise is refuted in hand, with the one fact the
/// ladder asks of it: whether that exercise registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefutedPosition {
    pub(crate) fulfillment_id: D32,
    pub(crate) external_commitment: D32,
    pub(crate) refuted: RefutedInHand,
    pub(crate) registered: bool,
}

impl Established {
    /// The trader's own position over an exercise its bytes refute: nothing
    /// is read beyond the registration the caller read to find it.
    pub fn refuted(
        exercise: &RecognizedExercise,
        refutation: &InHandRefutation,
        registration: &RegistrationRead,
    ) -> Result<Self, NotEstablished> {
        if refutation.external_commitment != exercise.external_commitment {
            return Err(NotEstablished::NotThisExercise(
                "the refutation is of another exercise",
            ));
        }
        if !registration.is_of(&exercise.precommit.body, &exercise.fulfillment.body) {
            return Err(NotEstablished::NotThisExercise(
                "the registration read is of another position",
            ));
        }
        Ok(Self::RefutedInHand(RefutedPosition {
            fulfillment_id: refutation.fulfillment_id,
            external_commitment: refutation.external_commitment,
            refuted: refutation.refuted,
            registered: registration.is_registered_as(&exercise.fulfillment.body),
        }))
    }

    pub fn fulfillment_id(&self) -> &D32 {
        match self {
            Self::Facts(facts) => &facts.fulfillment_id,
            Self::RefutedInHand(refuted) => &refuted.fulfillment_id,
        }
    }

    pub fn external_commitment(&self) -> &D32 {
        match self {
            Self::Facts(facts) => &facts.external_commitment,
            Self::RefutedInHand(refuted) => &refuted.external_commitment,
        }
    }
}

/// A reserved key permanently resolved for the route bound to `e`: final on
/// anything, or its leader link held by another commitment, which no later
/// value can take from it. A key held on `e` itself and not final is not
/// resolved yet.
fn permanently_resolved(cell: &CellFact, e: &D32) -> bool {
    match cell {
        CellFact::Held {
            state: ChainState::Final,
            ..
        } => true,
        CellFact::Held { id, .. } => id != e,
        CellFact::Open => false,
    }
}

/// The complete facts of one exercise over what was read about it.
///
/// Registration from the position pair (R10): the pair decides for every `F`
/// at `q` at once, and a position held by another claim is this `F`'s
/// position lost (Section 21.1, arm (v)). `FulfillmentConformance` and
/// `RouteValidation` recomputed over the evidence (R5, R7). The trader
/// parent from the position this verifier resolved itself. Each leg's cell
/// at its successor key (R11), its parent against the vault's established
/// chain at the generation the evidence places it, and its liveness from the
/// walk over the earlier keys of that leg's chain.
pub fn establish(reads: &ExerciseReads<'_>) -> Result<EstablishedFacts, NotEstablished> {
    let exercise = reads.exercise;
    let precommit = &exercise.precommit.body;
    let fulfillment = &exercise.fulfillment.body;
    let e = exercise.external_commitment;

    if !reads.registration.is_of(precommit, fulfillment) {
        return Err(NotEstablished::NotThisExercise(
            "the registration read is of another position",
        ));
    }
    let (registered, position_lost) = match reads.registration.registration() {
        Registration::Registered(signed) => {
            let ours = signed.body == *fulfillment;
            (ours, !ours)
        }
        Registration::NeverRegistered { .. } => (false, true),
        Registration::Unresolved => (false, false),
    };

    // The trader parent: P names it; what it selected is this verifier's
    // own resolution of p, and nothing else resolves it.
    let parent = match precommit.parent_claim_ref() {
        ParentClaimRef::SingleRoot { .. } => ParentPosition::SingleRoot,
        ParentClaimRef::Conditional { fulfillment_id } => match reads.parent {
            Some(AdmittedEconomicPosition::ResolvedSofi {
                economic_position,
                selected_root,
                fulfillment_id: resolved,
                ..
            }) if *resolved == *fulfillment_id && *economic_position == precommit.position() => {
                ParentPosition::ConditionalSelected {
                    selected_root: *selected_root,
                }
            }
            Some(..) | None => {
                return Err(NotEstablished::ParentUnresolved {
                    fulfillment_id: *fulfillment_id,
                })
            }
        },
    };

    // FulfillmentConformance over the evidence, recomputed here (R7).
    if reads.conformance.precommit.body != *precommit
        || reads.conformance.preimage != exercise.preimage
    {
        return Err(NotEstablished::NotThisExercise(
            "the conformance evidence is of another operation",
        ));
    }
    let conformance = match fulfillment_conformance(
        fulfillment,
        &exercise.fulfillment.signature,
        reads.conformance,
    ) {
        Ok(verdict) => verdict.verdict(),
        Err(missing) => return Err(NotEstablished::ConformanceEvidence(vec![missing])),
    };

    // RouteValidation over the evidence, recomputed here (R5).
    let validation = match route_validation(precommit, &exercise.preimage, reads.evidence) {
        Ok(validation) => validation,
        Err(missing) => return Err(NotEstablished::RouteEvidence(vec![missing])),
    };

    // The GENERATION each leg's parent sits at, recomputed from the pre
    // states the evidence holds rather than asserted by the operation that
    // names the parent. Without it a parent cannot be refuted, only placed
    // positively, so a vault missing here is `Unavailable` and never
    // `Orphaned`.
    let generations: BTreeMap<D32, u64> =
        match vault_post_states(precommit, &exercise.preimage, reads.evidence) {
            Ok(posts) => posts
                .iter()
                .map(|post| (*post.vault_id(), post.pre_generation()))
                .collect(),
            Err(..) => BTreeMap::new(),
        };

    // Every leg of P at the attempt F fixed for it. The attempts cover the
    // legs exactly: that is conformance item 4, decided in hand.
    if reads.legs.len() != precommit.legs().len() {
        return Err(NotEstablished::NotThisExercise(
            "one cell read per leg of P, in P's leg order",
        ));
    }
    let mut legs = Vec::with_capacity(precommit.legs().len());
    let mut keys = Vec::with_capacity(precommit.legs().len());
    for (leg, read) in precommit.legs().iter().zip(reads.legs) {
        let attempt = fulfillment
            .attempts()
            .iter()
            .find(|a| a.vault_id == leg.vault_id)
            .map(|a| a.attempt)
            .ok_or(NotEstablished::NotThisExercise(
                "F names no attempt for a leg of P",
            ))?;
        if *read.cell.vault_id() != leg.vault_id
            || *read.cell.parent_root() != leg.parent_root
            || read.cell.attempt() != attempt
        {
            return Err(NotEstablished::NotThisExercise(
                "a cell read is of another key than the leg's",
            ));
        }
        let cell = read.cell.fact();
        // The chain decides, three-valued, at the generation the evidence
        // places the parent; without a generation it can still establish
        // the root positively, but it cannot refute one it has not placed.
        let parent = match (read.chain, generations.get(&leg.vault_id)) {
            (Some(chain), Some(generation)) => chain.status_of(*generation, &leg.parent_root),
            (Some(chain), None) if chain.names(&leg.parent_root) => ParentStatus::Canonical,
            (Some(..), None) | (None, _) => ParentStatus::Unavailable,
        };
        // `AttemptLive`: every earlier key of this leg's chain is skipped,
        // established by a walk from the first key.
        let (attempt_live, parent_consumed_elsewhere) = if attempt == 0 {
            (true, false)
        } else {
            let not_live = NotEstablished::AttemptLiveness {
                vault_id: leg.vault_id,
                attempt,
            };
            match read.walk {
                Some(walk)
                    if *walk.vault_id() == leg.vault_id
                        && *walk.parent_root() == leg.parent_root =>
                {
                    walk.liveness_of(attempt, &e).ok_or(not_live)?
                }
                Some(..) | None => return Err(not_live),
            }
        };
        legs.push(LegFacts {
            cell,
            parent,
            attempt_live,
            parent_consumed_elsewhere,
        });
        keys.push((leg.vault_id, leg.parent_root, attempt));
    }
    let storage_resolved = registered && legs.iter().all(|l| permanently_resolved(&l.cell, &e));
    Ok(EstablishedFacts {
        fulfillment_id: derive::fulfillment_id(fulfillment),
        external_commitment: e,
        registered,
        conformance,
        position_lost,
        parent,
        parent_pre_root: *precommit.void_root(),
        validation,
        storage_resolved,
        legs,
        keys,
        preimage: exercise.preimage.clone(),
        evidence: reads.evidence.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::economic::lineage::ValidatedEconomicRoot;
    use crate::route_chain::fixtures::{committed_set, committed_set_id, Cell};
    use crate::route_chain::ROUTE_LEN;
    use crate::sofi::exercise::fixtures::exercise as build_exercise;
    use crate::sofi::exercise::{attempt_resolution, recognize_exercise, AttemptCell};
    use crate::sofi::lineage::advance_resolved;
    use crate::sofi::publication::Publication;
    use crate::sofi::registration::{fulfillment_registered, PositionCells};
    use crate::sofi::resolution::{resolve_position, walk, Incomplete, KeyFacts, Resolution};
    use crate::sofi::validation::fixtures::{swap_fixture_n, Fixture};
    use crate::sofi::validation::trader_credits;
    use crate::sofi::wire::{TraderFulfillmentBody, TraderPrecommitBody};
    use crate::types::device_state::DeviceState;

    const OTHER_ROOT: D32 = [0x77; 32];
    const OTHER_E: D32 = [0x11; 32];

    /// One operation's reads, as the SDK fetches them: the position pair
    /// with `F` and `C_q` final, every leg's cell holding the exercise
    /// final, the conformance and route evidence the fixture supplies, and
    /// a chain per vault naming the leg's parent at generation zero.
    struct Reads {
        exercise: RecognizedExercise,
        registration: RegistrationRead,
        conformance: ConformanceEvidence,
        evidence: Evidence,
        cells: Vec<AttemptCellRead>,
        chains: BTreeMap<D32, VaultChain>,
    }

    impl Reads {
        fn legs(&self) -> Vec<LegReads<'_>> {
            self.cells
                .iter()
                .zip(self.exercise.precommit.body.legs())
                .map(|(cell, leg)| LegReads {
                    cell,
                    chain: self.chains.get(&leg.vault_id),
                    walk: None,
                })
                .collect()
        }

        fn establish(&self, legs: &[LegReads<'_>]) -> Result<EstablishedFacts, NotEstablished> {
            establish(&ExerciseReads {
                exercise: &self.exercise,
                registration: &self.registration,
                conformance: &self.conformance,
                evidence: &self.evidence,
                parent: None,
                legs,
            })
        }
    }

    /// The pair of `f`'s position, routed by `parent_root`, with the envelope
    /// final at `K_ful(q)` and, when `with_claim`, `C_q` final at `K_root(q)`.
    fn registration_read(
        p: &TraderPrecommitBody,
        f: &TraderFulfillmentBody,
        signature: &[u8],
        parent_root: &D32,
        with_claim: bool,
    ) -> RegistrationRead {
        let cells = PositionCells::new(
            p.genesis(),
            p.device_id(),
            f.position(),
            parent_root,
            &committed_set(),
            &committed_set_id(),
        )
        .unwrap();
        let envelope = Publication::Fulfillment { body: f, signature }
            .object_bytes()
            .unwrap();
        let mut ful = Cell::at(cells.fulfillment());
        ful.write(&envelope, ROUTE_LEN - 1, &[]);
        let mut root = Cell::at(cells.root().routed());
        if with_claim {
            root.write(&derive::resolution_claim(p, f).encode(), ROUTE_LEN - 1, &[]);
        }
        let lookup = BTreeMap::from([(derive::precommit_id(p), p.clone())]);
        fulfillment_registered(&cells, &ful.evidence(), &root.evidence(), &lookup).unwrap()
    }

    /// `K^(attempt)` of `vault_id` at `parent_root`, holding `bytes` final
    /// when given, open otherwise.
    fn cell_read(
        vault_id: &D32,
        parent_root: &D32,
        attempt: u64,
        bytes: Option<&[u8]>,
    ) -> AttemptCellRead {
        let at = AttemptCell::new(
            vault_id,
            parent_root,
            attempt,
            &committed_set(),
            &committed_set_id(),
        )
        .unwrap();
        let mut cell = Cell::at(at.routed());
        if let Some(bytes) = bytes {
            cell.write(bytes, ROUTE_LEN - 1, &[]);
        }
        attempt_resolution(&at, &cell.evidence()).unwrap()
    }

    /// What `FulfillmentConformance(F)` reads for the fixture's exercise.
    fn conformance_evidence(
        fx: &Fixture,
        exercise: &RecognizedExercise,
        prior_attempts: BTreeMap<(D32, u64), CellFact>,
    ) -> ConformanceEvidence {
        ConformanceEvidence {
            precommit: exercise.precommit.clone(),
            preimage: fx.preimage.clone(),
            closure: fx
                .preimage
                .settlement()
                .closure()
                .refs()
                .iter()
                .copied()
                .zip(exercise.closure.iter().cloned())
                .collect(),
            setups: fx.evidence.setups.clone(),
            prior_attempts,
            parent_fulfillment: None,
        }
    }

    /// The reads of a route of `legs` legs exercised at `attempts`, every
    /// cell holding the exercise final.
    fn reads(legs: usize, attempts: &[u64]) -> (Fixture, Reads) {
        let fx = swap_fixture_n(legs);
        let built = build_exercise(&fx, attempts);
        let bytes = built.exercise.encode();
        let exercise = recognize_exercise(&bytes).expect("the fixture's exercise recognizes");
        let registration = registration_read(
            &built.precommit,
            &built.fulfillment,
            &exercise.fulfillment.signature,
            built.precommit.void_root(),
            true,
        );
        let cells = built
            .precommit
            .legs()
            .iter()
            .zip(attempts)
            .map(|(leg, attempt)| {
                cell_read(&leg.vault_id, &leg.parent_root, *attempt, Some(&bytes))
            })
            .collect();
        let chains = built
            .precommit
            .legs()
            .iter()
            .map(|leg| {
                (
                    leg.vault_id,
                    chain_naming(&fx, &leg.vault_id, leg.parent_root),
                )
            })
            .collect();
        let conformance = conformance_evidence(&fx, &exercise, BTreeMap::new());
        let evidence = fx.evidence.clone();
        (
            fx,
            Reads {
                exercise,
                registration,
                conformance,
                evidence,
                cells,
                chains,
            },
        )
    }

    /// The chain of `vault_id` as this verifier would have established it
    /// for the fixture: `root` at the generation the fixture's vault state
    /// sits at, and a distinct filler root at each generation before it (a
    /// chain is read positionally, from generation zero).
    fn chain_naming(fx: &Fixture, vault_id: &D32, root: D32) -> VaultChain {
        let state_key = derive::vault_state_key(vault_id);
        let generation = match fx.evidence.vault_leaves.get(&(*vault_id, state_key)) {
            Some(crate::sofi::validation::VaultLeafPre::State(state)) => state.generation,
            _ => panic!("the fixture's evidence holds the vault's state"),
        };
        let mut roots: Vec<D32> = (0..generation).map(|g| [0xF0 ^ (g as u8); 32]).collect();
        roots.push(root);
        VaultChain::of_roots_for_test(roots)
    }

    /// The validated predecessor the fixture's `P` was built on.
    fn previous(p: &TraderPrecommitBody) -> ValidatedEconomicRoot {
        let ParentClaimRef::SingleRoot { claim_ref } = *p.parent_claim_ref() else {
            panic!("the fixture's P has an ordinary parent")
        };
        ValidatedEconomicRoot::rehydrate_from_admitted_store(AdmittedEconomicPosition::SingleRoot {
            economic_position: p.position(),
            economic_root: *p.void_root(),
            claim_ref,
        })
        .unwrap()
    }

    /// FROM READS TO ROOT, with nothing stated in between: the pair final,
    /// every leg's cell final on the exercise, the chain naming each parent,
    /// the predicates recomputed over the evidence. The facts say what the
    /// reads say, the ladder answers Realized, and the advance installs the
    /// realize root on that answer.
    #[test]
    fn a_consumed_route_is_established_from_its_reads_and_installs_the_realize_root() {
        let (fx, r) = reads(1, &[0]);
        let facts = r.establish(&r.legs()).expect("every read decides");
        let p = &r.exercise.precommit.body;
        let f = &r.exercise.fulfillment.body;
        assert_eq!(facts.fulfillment_id(), &derive::fulfillment_id(f));
        assert_eq!(facts.external_commitment(), p.external_commitment());
        assert!(facts.registered);
        assert!(!facts.position_lost);
        assert_eq!(
            facts.conformance,
            Validation::Valid,
            "conformance recomputed over the evidence"
        );
        assert_eq!(
            facts.validation,
            Validation::Valid,
            "validation recomputed over the evidence"
        );
        assert_eq!(facts.parent, ParentPosition::SingleRoot);
        assert_eq!(facts.parent_pre_root, *p.void_root());
        assert!(facts.storage_resolved);
        assert_eq!(facts.legs.len(), 1);
        assert_eq!(
            facts.legs[0],
            LegFacts {
                cell: CellFact::Held {
                    id: *p.external_commitment(),
                    state: ChainState::Final
                },
                parent: ParentStatus::Canonical,
                attempt_live: true,
                parent_consumed_elsewhere: false,
            }
        );
        assert_eq!(
            facts.keys[0],
            (p.legs()[0].vault_id, p.legs()[0].parent_root, 0)
        );
        assert_eq!(
            resolve_position(&facts.route_facts()),
            Ok(Resolution::Realized)
        );

        let mut receiver = DeviceState::new(*p.genesis(), *p.device_id(), vec![0x01; 32]);
        for credit in trader_credits(&fx.preimage, &fx.evidence).unwrap() {
            receiver = receiver.adopt_token(credit).unwrap();
        }
        let advanced = advance_resolved(
            &previous(p),
            p,
            f,
            p.parent_claim_ref(),
            &Established::Facts(Box::new(facts)),
            &receiver,
        )
        .expect("the route realized");
        assert_eq!(advanced.resolution, Resolution::Realized);
        assert_eq!(advanced.root.economic_root(), *p.realize_root());
    }

    /// The reads are bound: a registration read of another pair, a cell read
    /// of another key, or one read too few is not a fact about this
    /// exercise, and nothing is established from it.
    #[test]
    fn reads_of_another_position_or_key_establish_nothing() {
        let (_, r) = reads(1, &[0]);
        let p = &r.exercise.precommit.body;
        let f = &r.exercise.fulfillment.body;
        let legs = r.legs();

        // The pair routed by another root is another position's pair.
        let elsewhere = Reads {
            registration: registration_read(
                p,
                f,
                &r.exercise.fulfillment.signature,
                &OTHER_ROOT,
                true,
            ),
            ..reads_like(&r)
        };
        assert!(matches!(
            elsewhere.establish(&legs),
            Err(NotEstablished::NotThisExercise(..))
        ));

        // A cell read at another attempt of the leg's vault.
        let leg = &p.legs()[0];
        let other_key = cell_read(&leg.vault_id, &leg.parent_root, 3, None);
        let at_other_key = [LegReads {
            cell: &other_key,
            chain: r.chains.get(&leg.vault_id),
            walk: None,
        }];
        assert!(matches!(
            r.establish(&at_other_key),
            Err(NotEstablished::NotThisExercise(..))
        ));

        // One read per leg, in P's leg order.
        assert!(matches!(
            r.establish(&[]),
            Err(NotEstablished::NotThisExercise(..))
        ));
    }

    fn reads_like(r: &Reads) -> Reads {
        Reads {
            exercise: r.exercise.clone(),
            registration: r.registration.clone(),
            conformance: r.conformance.clone(),
            evidence: r.evidence.clone(),
            cells: r.cells.clone(),
            chains: r.chains.clone(),
        }
    }

    /// Registration is read from the pair, never assumed: with `C_q` not
    /// final at `K_root(q)` the position is unregistered, the ladder stops
    /// at rung 0, and nothing is lost either.
    #[test]
    fn an_unregistered_position_is_not_resolved() {
        let (_, mut r) = reads(1, &[0]);
        let p = &r.exercise.precommit.body;
        let f = &r.exercise.fulfillment.body;
        r.registration = registration_read(
            p,
            f,
            &r.exercise.fulfillment.signature,
            p.void_root(),
            false,
        );
        let facts = r.establish(&r.legs()).expect("every read decides");
        assert!(!facts.registered);
        assert!(!facts.position_lost);
        assert!(!facts.storage_resolved);
        assert_eq!(
            resolve_position(&facts.route_facts()),
            Err(Incomplete::NotRegistered)
        );
    }

    /// A leg's parent is decided against the chain this verifier
    /// established: a chain naming another root at the parent's generation
    /// refutes it — the route is Void — and no chain at all leaves the
    /// position waiting, never refuted.
    #[test]
    fn a_parent_the_chain_refutes_voids_and_one_it_has_not_placed_waits() {
        let (fx, mut r) = reads(1, &[0]);
        let vault_id = r.exercise.precommit.body.legs()[0].vault_id;
        r.chains
            .insert(vault_id, chain_naming(&fx, &vault_id, OTHER_ROOT));
        let refuted = r.establish(&r.legs()).expect("every read decides");
        assert_eq!(refuted.legs[0].parent, ParentStatus::Orphaned);
        assert_eq!(
            resolve_position(&refuted.route_facts()),
            Ok(Resolution::Void)
        );

        r.chains.clear();
        let waiting = r.establish(&r.legs()).expect("every read decides");
        assert_eq!(waiting.legs[0].parent, ParentStatus::Unavailable);
        assert_eq!(
            resolve_position(&waiting.route_facts()),
            Err(Incomplete::StorageNotFinal)
        );
    }

    /// A leg whose key is open is not resolved: the facts say so, and the
    /// ladder waits.
    #[test]
    fn an_open_leg_keeps_the_position_unresolved() {
        let (_, mut r) = reads(1, &[0]);
        let leg = r.exercise.precommit.body.legs()[0];
        r.cells = vec![cell_read(&leg.vault_id, &leg.parent_root, 0, None)];
        let facts = r.establish(&r.legs()).expect("every read decides");
        assert_eq!(facts.legs[0].cell, CellFact::Open);
        assert!(!facts.storage_resolved);
        assert_eq!(
            resolve_position(&facts.route_facts()),
            Err(Incomplete::StorageNotFinal)
        );
    }

    /// `AttemptLive` at an attempt above zero is a walk from the first key
    /// that reached it, and nothing less: no walk, or a walk that did not
    /// reach the attempt, establishes nothing; a walk over the earlier key
    /// skipped establishes it.
    #[test]
    fn liveness_above_attempt_zero_is_the_walk_that_reached_it() {
        let fx = swap_fixture_n(1);
        let built = build_exercise(&fx, &[1]);
        let bytes = built.exercise.encode();
        let exercise = recognize_exercise(&bytes).expect("the fixture's exercise recognizes");
        let leg = built.precommit.legs()[0];
        let (v, root) = (leg.vault_id, leg.parent_root);
        // Conformance item 5: the key this attempt skips past is final on
        // another operation.
        let prior = BTreeMap::from([(
            (v, 0),
            CellFact::Held {
                id: OTHER_E,
                state: ChainState::Final,
            },
        )]);
        let r = Reads {
            registration: registration_read(
                &built.precommit,
                &built.fulfillment,
                &exercise.fulfillment.signature,
                built.precommit.void_root(),
                true,
            ),
            conformance: conformance_evidence(&fx, &exercise, prior),
            evidence: fx.evidence.clone(),
            cells: vec![cell_read(&v, &root, 1, Some(&bytes))],
            chains: BTreeMap::from([(v, chain_naming(&fx, &v, root))]),
            exercise,
        };

        // No walk: not established.
        assert!(matches!(
            r.establish(&r.legs()),
            Err(NotEstablished::AttemptLiveness { vault_id, attempt: 1 }) if vault_id == v
        ));
        // A walk that did not reach the attempt: not established.
        let short = walk(&v, &root, 0, 16, |_| None);
        fn with<'a>(r: &'a Reads, v: &D32, w: &'a AttemptWalk) -> Vec<LegReads<'a>> {
            vec![LegReads {
                cell: &r.cells[0],
                chain: r.chains.get(v),
                walk: Some(w),
            }]
        }
        assert!(matches!(
            r.establish(&with(&r, &v, &short)),
            Err(NotEstablished::AttemptLiveness { vault_id, attempt: 1 }) if vault_id == v
        ));
        // A walk over key 0 skipped — held final by an operation whose
        // route is statically Invalid — reaches attempt 1: live.
        let rejected = LegFacts {
            cell: CellFact::Held {
                id: OTHER_E,
                state: ChainState::Final,
            },
            parent: ParentStatus::Canonical,
            attempt_live: true,
            parent_consumed_elsewhere: false,
        };
        let rejected_legs = [rejected];
        let reached = walk(&v, &root, 0, 1, |attempt| {
            (attempt == 0).then(|| {
                KeyFacts::complete_at(
                    v,
                    root,
                    0,
                    RouteFacts {
                        external_commitment: OTHER_E,
                        registered: true,
                        conformance: Validation::Valid,
                        position_lost: false,
                        parent: ParentPosition::SingleRoot,
                        parent_pre_root: root,
                        validation: Validation::Invalid,
                        storage_resolved: true,
                        legs: &rejected_legs,
                    },
                    rejected,
                )
            })
        });
        let facts = r
            .establish(&with(&r, &v, &reached))
            .expect("every read decides");
        assert!(facts.legs[0].attempt_live);
        assert!(!facts.legs[0].parent_consumed_elsewhere);
        assert_eq!(facts.keys[0], (v, root, 1));
        assert_eq!(
            resolve_position(&facts.route_facts()),
            Ok(Resolution::Realized)
        );
    }

    /// A refutation is bound to the exercise it refutes, and the position it
    /// is stated for is bound to its registration read; registration is the
    /// one fact read into it.
    #[test]
    fn a_refuted_position_is_bound_to_its_exercise_and_its_registration() {
        let (_, r) = reads(1, &[0]);
        let p = &r.exercise.precommit.body;
        let f = &r.exercise.fulfillment.body;
        let refutation = InHandRefutation {
            external_commitment: *p.external_commitment(),
            fulfillment_id: derive::fulfillment_id(f),
            refuted: RefutedInHand::Conformance,
        };
        let Established::RefutedInHand(position) =
            Established::refuted(&r.exercise, &refutation, &r.registration).unwrap()
        else {
            panic!("a refutation")
        };
        assert!(position.registered);
        assert_eq!(position.refuted, RefutedInHand::Conformance);

        let other = InHandRefutation {
            external_commitment: OTHER_E,
            ..refutation
        };
        assert!(matches!(
            Established::refuted(&r.exercise, &other, &r.registration),
            Err(NotEstablished::NotThisExercise(..))
        ));
        let elsewhere =
            registration_read(p, f, &r.exercise.fulfillment.signature, &OTHER_ROOT, true);
        assert!(matches!(
            Established::refuted(&r.exercise, &refutation, &elsewhere),
            Err(NotEstablished::NotThisExercise(..))
        ));
        let unregistered = registration_read(
            p,
            f,
            &r.exercise.fulfillment.signature,
            p.void_root(),
            false,
        );
        let Established::RefutedInHand(position) =
            Established::refuted(&r.exercise, &refutation, &unregistered).unwrap()
        else {
            panic!("a refutation")
        };
        assert!(!position.registered);
    }
}
