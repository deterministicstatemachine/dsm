// SPDX-License-Identifier: Apache-2.0
//! Stage 9 of §31 and the walk of §30, rebuild step R12: consumption and
//! resolution over the cells' route chains.
//!
//! Core decides; this module only fetches. For one exercise at one key it
//! first asks Core what the exercise's own bytes refute (MR-DSM-0041): a
//! refuted exercise is classified with nothing more read. Otherwise it builds
//! the facts the ladder reads (`RouteFacts`): registration from the position
//! pair (R10), `FulfillmentConformance` and `RouteValidation` over acquired
//! evidence (R5, R7), each leg's cell at its successor key (R11), attempt
//! liveness from the walk over the earlier keys of that leg's chain, and the
//! trader parent from the positions this verifier resolved itself. Then
//! Core's `walk` classifies the keys and `resolve_position` the position.
//!
//! Core resolves only over complete facts (Amendment S7). A fact this
//! verifier has not established is never handed to Core in another fact's
//! place: it is returned as [`NotEstablished`], named, and the caller reads
//! and relays again. The one three-valued fact is a leg's parent status,
//! whose `Unavailable` is Core's own value for a parent the verifier's chain
//! has not reached.
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use dsm::route_chain::{CellFact, ChainState, Missing as CellMissing};
use dsm::sofi::conformance::{
    conformance_invalid_in_hand, fulfillment_conformance, ConformanceMissing, Validation,
};
use dsm::sofi::exercise::{recognize_exercise, RecognizedExercise};
use dsm::sofi::registration::Registration;
use dsm::sofi::resolution::{
    effect_of, resolve_position, resolve_refuted_in_hand, walk, Incomplete, KeyFacts, LegFacts,
    ParentPosition, ParentStatus, PositionEffect, RefutedInHand, Resolution, RouteFacts,
    VaultChain, WalkOutcome,
};
use dsm::sofi::validation::{route_invalid_in_hand, route_validation, vault_post_states, Missing};
use dsm::sofi::wire::{ParentClaimRef, SofiExercise, ValidationRef};
use dsm::types::error::DsmError;

use crate::sdk::sofi_evidence::{acquire_evidence, Acquired, LocalLeaves};
use crate::sdk::sofi_exercise::read_attempt_cell;
use crate::sdk::sofi_register::{acquire_conformance_evidence, read_registration, InstallRequest};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

/// Keys one walk examines before it hands back a cursor (Section 23.6): a
/// budget only, never a verdict — resuming at the cursor lands the same
/// answer as one longer walk.
pub const WALK_BUDGET: usize = 16;

/// How far the facts of one exercise reach into the chains of its OTHER legs:
/// a two-leg route's liveness at leg 2 is a walk over leg 2's earlier keys,
/// whose exercises may themselves be routes. Past this depth a leg's
/// liveness is not established, and the facts of the exercise are not
/// complete.
pub const CHAIN_DEPTH: usize = 2;

/// What the verifier brings to a resolution: the committed set, its own
/// leaves, the trader positions it resolved itself and the vault ancestry it
/// walked. Every field is an established fact of THIS verifier; none is
/// trusted because somebody sent it.
pub struct Resolver<'a> {
    pub set: &'a StorageSet,
    /// This device's own `R_econ` leaves, for the trader-leaf pre values of
    /// its own routes.
    pub local: &'a LocalLeaves,
    /// The conditional positions this verifier resolved, by the fulfillment
    /// that installed them: what each selected, or that it selected none. A
    /// conditional parent absent here is not resolved by this verifier.
    pub parents: &'a BTreeMap<D32, ParentPosition>,
    /// The canonical chain this verifier established for each vault it needs
    /// one for (Section 30), built by `sofi_chain::ChainWalker`. A chain
    /// carries generations, which is what lets a parent be refuted
    /// ([`ParentStatus::Orphaned`]) rather than only waited on. A vault with
    /// no chain here is `Unavailable` for every leg naming it.
    pub chains: &'a BTreeMap<D32, VaultChain>,
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
    /// leaf pre values of another trader's route (`sofi_evidence`).
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
}

/// One trader position, as far as this verifier can take it (stage 9 of
/// §31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PositionOutcome {
    /// Core resolved the position over complete facts. Permanent.
    Resolved {
        resolution: Resolution,
        /// What `advance_resolved` (R13) does with it.
        effect: PositionEffect,
    },
    /// The facts are complete and the ladder does not resolve the position
    /// yet (Amendment S7).
    NotYet(Incomplete),
    /// A fact the ladder reads is not established.
    NotEstablished(NotEstablished),
}

impl PositionOutcome {
    fn of(ladder: Result<Resolution, Incomplete>) -> Self {
        match ladder {
            Ok(resolution) => Self::Resolved {
                resolution,
                effect: effect_of(resolution),
            },
            Err(incomplete) => Self::NotYet(incomplete),
        }
    }
}

/// Where a walk over one parent's attempt chain ended, with the exercise
/// that consumed the parent when one did — its consumed route's `V°` post
/// root is the next parent (Section 30, step 3) — and, when it stopped
/// unresolved at a key it could not classify, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walked {
    pub outcome: WalkOutcome,
    pub consumed: Option<RecognizedExercise>,
    pub not_established: Option<NotEstablished>,
}

/// The complete facts of one exercise; `RouteFacts` borrows them.
struct Fetched {
    external_commitment: D32,
    registered: bool,
    conformance: Validation,
    position_lost: bool,
    parent: ParentPosition,
    parent_pre_root: D32,
    validation: Validation,
    storage_resolved: bool,
    legs: Vec<LegFacts>,
    /// The index in `legs` of the leg whose key is being walked.
    walked_leg: usize,
}

impl Fetched {
    fn facts(&self) -> RouteFacts<'_> {
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
}

/// What this verifier knows about one exercise.
enum Known {
    /// Refuted by its own bytes: nothing else was read.
    RefutedInHand(RefutedInHand),
    /// The complete facts the ladder reads.
    Facts(Fetched),
}

/// One key the walk classified, with the exercise holding it.
struct KeyKnown {
    cell: CellFact,
    known: Known,
    exercise: RecognizedExercise,
}

impl KeyKnown {
    fn key_facts(&self) -> KeyFacts<'_> {
        match &self.known {
            Known::Facts(fetched) => {
                KeyFacts::Complete(fetched.facts(), fetched.legs[fetched.walked_leg])
            }
            Known::RefutedInHand(refuted) => KeyFacts::RefutedInHand {
                refuted: *refuted,
                cell: self.cell,
                external_commitment: self.exercise.external_commitment,
            },
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

/// What the exercise's own bytes refute, before any read (MR-DSM-0041).
fn refuted_in_hand(exercise: &RecognizedExercise) -> Option<RefutedInHand> {
    if let Some(why) = conformance_invalid_in_hand(
        &exercise.precommit,
        &exercise.fulfillment.body,
        &exercise.fulfillment.signature,
        &exercise.preimage,
        &exercise.closure,
    ) {
        log::info!("[sofi resolve] F is refuted in hand: {why:?}");
        return Some(RefutedInHand::Conformance);
    }
    let why = route_invalid_in_hand(&exercise.precommit.body, &exercise.preimage)?;
    log::info!("[sofi resolve] the route is refuted in hand: {why:?}");
    Some(RefutedInHand::Route {
        legs: exercise.precommit.body.legs().len(),
    })
}

/// The key of one leg being walked: vault, parent, attempt, and the cell as
/// it was just read.
#[derive(Clone, Copy)]
struct WalkedKey {
    vault_id: D32,
    parent_root: D32,
    attempt: u64,
    cell: CellFact,
}

type Fut<'s, T> = Pin<Box<dyn Future<Output = Result<T, DsmError>> + Send + 's>>;

impl Resolver<'_> {
    /// Section 30, step 2: walk the attempt keys of `vault_id` at
    /// `parent_root` from `cursor`, reading each cell, establishing what is
    /// known about the exercise it holds and letting Core classify it. A
    /// skipped key moves on, a consumed key stops with its exercise, anything
    /// else is unresolved; a spent budget hands back a cursor.
    pub async fn walk_parent(
        &self,
        vault_id: &D32,
        parent_root: &D32,
        cursor: u64,
        budget: usize,
    ) -> Result<Walked, DsmError> {
        self.walk_chain(*vault_id, *parent_root, cursor, budget, CHAIN_DEPTH)
            .await
    }

    /// Stage 9 of §31: the trader's own position, resolved over the exercise
    /// it built (R11).
    pub async fn resolve_trader_position(
        &self,
        exercise: &SofiExercise,
    ) -> Result<PositionOutcome, DsmError> {
        let recognized = recognize_exercise(&exercise.encode()).ok_or_else(|| {
            DsmError::verification("resolve: the bytes are not one operation's exercise")
        })?;
        self.resolve_recognized(recognized).await
    }

    /// The same, over an exercise already recognized — the one read back from
    /// a leg's cell (`read_attempt_cell`), which is how the device finds its
    /// own exercise again after a restart (R13). A refuted exercise reads
    /// only its registration, the one fact the ladder asks of it.
    pub async fn resolve_recognized(
        &self,
        recognized: RecognizedExercise,
    ) -> Result<PositionOutcome, DsmError> {
        let precommit = &recognized.precommit.body;
        let fulfillment = &recognized.fulfillment.body;
        let known = match self.facts_of(&recognized, None, CHAIN_DEPTH).await? {
            Ok(known) => known,
            Err(why) => return Ok(PositionOutcome::NotEstablished(why)),
        };
        Ok(match known {
            Known::Facts(fetched) => PositionOutcome::of(resolve_position(&fetched.facts())),
            Known::RefutedInHand(..) => {
                let registration = match read_registration(
                    self.set,
                    precommit.genesis(),
                    precommit.device_id(),
                    fulfillment.position(),
                    precommit.void_root(),
                )
                .await?
                {
                    Ok(registration) => registration,
                    Err(missing) => {
                        return Ok(PositionOutcome::NotEstablished(
                            NotEstablished::Registration(missing),
                        ))
                    }
                };
                let registered = matches!(
                    &registration,
                    Registration::Registered(signed) if signed.body == *fulfillment
                );
                PositionOutcome::of(resolve_refuted_in_hand(registered))
            }
        })
    }

    fn walk_chain(
        &self,
        vault_id: D32,
        parent_root: D32,
        cursor: u64,
        budget: usize,
        depth: usize,
    ) -> Fut<'_, Walked> {
        Box::pin(async move {
            // Core's walk asks for keys in order and stops on the first it
            // cannot classify; a key it asks for that is not read yet is read,
            // and the walk resumes. The chunking is invisible to the answer.
            let mut known: BTreeMap<u64, KeyKnown> = BTreeMap::new();
            loop {
                let outcome = walk(cursor, budget, |attempt| {
                    known.get(&attempt).map(KeyKnown::key_facts)
                });
                match outcome {
                    WalkOutcome::Unresolved { attempt } if !known.contains_key(&attempt) => {
                        let read =
                            match read_attempt_cell(self.set, &vault_id, &parent_root, attempt)
                                .await?
                            {
                                Ok(read) => read,
                                Err(missing) => {
                                    return Ok(Walked {
                                        outcome,
                                        consumed: None,
                                        not_established: Some(NotEstablished::AttemptCell {
                                            vault_id,
                                            attempt,
                                            missing,
                                        }),
                                    })
                                }
                            };
                        // An open key is unresolved, never a skip: no key is
                        // ever dead.
                        let Some(exercise) = read.exercise else {
                            return Ok(Walked {
                                outcome,
                                consumed: None,
                                not_established: None,
                            });
                        };
                        let key = WalkedKey {
                            vault_id,
                            parent_root,
                            attempt,
                            cell: read.fact,
                        };
                        match self.facts_of(&exercise, Some(key), depth).await? {
                            Ok(facts) => {
                                known.insert(
                                    attempt,
                                    KeyKnown {
                                        cell: read.fact,
                                        known: facts,
                                        exercise,
                                    },
                                );
                            }
                            Err(why) => {
                                return Ok(Walked {
                                    outcome,
                                    consumed: None,
                                    not_established: Some(why),
                                })
                            }
                        }
                    }
                    WalkOutcome::Consumed { attempt } => {
                        return Ok(Walked {
                            outcome,
                            consumed: known.remove(&attempt).map(|key| key.exercise),
                            not_established: None,
                        })
                    }
                    WalkOutcome::Unresolved { .. }
                    | WalkOutcome::CounterExhausted { .. }
                    | WalkOutcome::Continue { .. } => {
                        return Ok(Walked {
                            outcome,
                            consumed: None,
                            not_established: None,
                        })
                    }
                }
            }
        })
    }

    /// What is known about one exercise: refuted by its own bytes, or the
    /// complete facts the ladder reads. `walked` is the key the exercise was
    /// found at, whose cell is in hand and whose liveness the walk
    /// established by reaching it.
    fn facts_of<'s>(
        &'s self,
        exercise: &'s RecognizedExercise,
        walked: Option<WalkedKey>,
        depth: usize,
    ) -> Fut<'s, Result<Known, NotEstablished>> {
        Box::pin(async move {
            if let Some(refuted) = refuted_in_hand(exercise) {
                return Ok(Ok(Known::RefutedInHand(refuted)));
            }
            let precommit = &exercise.precommit.body;
            let fulfillment = &exercise.fulfillment.body;
            let e = exercise.external_commitment;

            // Registration from the position pair (R10). The pair decides
            // for every F at q at once: a position held by another claim is
            // this F's position lost (Section 21.1) — arm (v).
            let registration = match read_registration(
                self.set,
                precommit.genesis(),
                precommit.device_id(),
                fulfillment.position(),
                precommit.void_root(),
            )
            .await?
            {
                Ok(registration) => registration,
                Err(missing) => return Ok(Err(NotEstablished::Registration(missing))),
            };
            let (registered, position_lost) = match &registration {
                Registration::Registered(signed) => {
                    let ours = signed.body == *fulfillment;
                    (ours, !ours)
                }
                Registration::NeverRegistered { .. } => (false, true),
                Registration::Unresolved => (false, false),
            };

            // The trader parent: P names it; what it selected is this
            // verifier's own resolution of p.
            let parent = match precommit.parent_claim_ref() {
                ParentClaimRef::SingleRoot { .. } => ParentPosition::SingleRoot,
                ParentClaimRef::Conditional { fulfillment_id } => {
                    match self.parents.get(fulfillment_id) {
                        Some(parent) => *parent,
                        None => {
                            return Ok(Err(NotEstablished::ParentUnresolved {
                                fulfillment_id: *fulfillment_id,
                            }))
                        }
                    }
                }
            };

            // FulfillmentConformance over acquired evidence (R7), the
            // exercise supplying the objects only its trader held.
            let own: BTreeMap<ValidationRef, Vec<u8>> = exercise
                .preimage
                .settlement()
                .closure()
                .refs()
                .iter()
                .copied()
                .zip(exercise.closure.iter().cloned())
                .collect();
            let request = InstallRequest {
                precommit,
                precommit_signature: &exercise.precommit.signature,
                preimage: &exercise.preimage,
                fulfillment,
                fulfillment_signature: &exercise.fulfillment.signature,
                own_objects: &own,
            };
            let conformance = match acquire_conformance_evidence(self.set, &request).await? {
                Acquired::Complete(evidence) => {
                    match fulfillment_conformance(
                        fulfillment,
                        &exercise.fulfillment.signature,
                        &evidence,
                    ) {
                        Ok(verdict) => verdict.verdict(),
                        Err(missing) => {
                            return Ok(Err(NotEstablished::ConformanceEvidence(vec![missing])))
                        }
                    }
                }
                Acquired::Exhausted(missing) | Acquired::NoSource(missing) => {
                    return Ok(Err(NotEstablished::ConformanceEvidence(missing)))
                }
            };

            // RouteValidation over acquired evidence (R5).
            let evidence = match acquire_evidence(
                self.set,
                precommit,
                &exercise.preimage,
                self.local,
            )
            .await?
            {
                Acquired::Complete(evidence) => evidence,
                Acquired::Exhausted(missing) => {
                    return Ok(Err(NotEstablished::RouteEvidence(missing)))
                }
                Acquired::NoSource(missing) => {
                    return Ok(Err(NotEstablished::RouteEvidenceHasNoSource(missing)))
                }
            };
            let validation = match route_validation(precommit, &exercise.preimage, &evidence) {
                Ok(validation) => validation,
                Err(missing) => return Ok(Err(NotEstablished::RouteEvidence(vec![missing]))),
            };

            // The GENERATION each leg's parent sits at, recomputed from the
            // pre states the evidence holds rather than asserted by the
            // operation that names the parent. Without it a parent cannot be
            // refuted, only placed positively, so a vault missing here is
            // `Unavailable` and never `Orphaned`.
            let generations: BTreeMap<D32, u64> =
                match vault_post_states(precommit, &exercise.preimage, &evidence) {
                    Ok(posts) => posts
                        .into_iter()
                        .map(|post| (post.vault_id, post.pre_generation))
                        .collect(),
                    Err(refusal) => {
                        log::info!(
                            "[sofi resolve] the legs' generations are not recomputable: \
                             {refusal:?}"
                        );
                        BTreeMap::new()
                    }
                };

            // Every leg of P at the attempt F fixed for it. The attempts cover
            // the legs exactly: that is conformance item 4, decided in hand.
            let mut legs = Vec::with_capacity(precommit.legs().len());
            let mut walked_leg = 0;
            for (j, leg) in precommit.legs().iter().enumerate() {
                let here = walked
                    .filter(|k| k.vault_id == leg.vault_id && k.parent_root == leg.parent_root);
                if here.is_some() {
                    walked_leg = j;
                }
                let attempt = fulfillment
                    .attempts()
                    .iter()
                    .find(|a| a.vault_id == leg.vault_id)
                    .map(|a| a.attempt)
                    .ok_or_else(|| {
                        DsmError::verification(
                            "resolve: F names no attempt for a leg of P, past its in-hand check",
                        )
                    })?;
                let at_walked_key = here.filter(|k| k.attempt == attempt);
                let cell = match at_walked_key {
                    Some(key) => key.cell,
                    None => {
                        match read_attempt_cell(self.set, &leg.vault_id, &leg.parent_root, attempt)
                            .await?
                        {
                            Ok(read) => read.fact,
                            Err(missing) => {
                                return Ok(Err(NotEstablished::AttemptCell {
                                    vault_id: leg.vault_id,
                                    attempt,
                                    missing,
                                }))
                            }
                        }
                    }
                };
                // The walk is AT this leg, so the root it is standing on is
                // one it established: canonical by the same induction that
                // produced it. Otherwise the chain decides, three-valued, at
                // the generation the evidence places it.
                let parent = if here.is_some() {
                    ParentStatus::Canonical
                } else {
                    match (
                        self.chains.get(&leg.vault_id),
                        generations.get(&leg.vault_id),
                    ) {
                        (Some(chain), Some(generation)) => {
                            chain.status_of(*generation, &leg.parent_root)
                        }
                        // No generation for it: the chain can still establish
                        // the root positively, but it cannot refute one it has
                        // not placed.
                        (Some(chain), None) if chain.names(&leg.parent_root) => {
                            ParentStatus::Canonical
                        }
                        (Some(..), None) | (None, Some(..)) | (None, None) => {
                            ParentStatus::Unavailable
                        }
                    }
                };
                // `AttemptLive`: every earlier key of this leg's chain is
                // skipped. The walk established it for the key it reached;
                // any other leg's chain is walked over its earlier keys.
                let (attempt_live, parent_consumed_elsewhere) =
                    if at_walked_key.is_some() || attempt == 0 {
                        (true, false)
                    } else {
                        let not_live = NotEstablished::AttemptLiveness {
                            vault_id: leg.vault_id,
                            attempt,
                        };
                        let Some(below) = depth.checked_sub(1) else {
                            return Ok(Err(not_live));
                        };
                        let earlier =
                            usize::try_from(attempt).map_or(WALK_BUDGET, |a| a.min(WALK_BUDGET));
                        let chain = self
                            .walk_chain(leg.vault_id, leg.parent_root, 0, earlier, below)
                            .await?;
                        match chain.outcome {
                            WalkOutcome::Continue { cursor } if cursor == attempt => (true, false),
                            WalkOutcome::Consumed { .. } => (
                                false,
                                chain
                                    .consumed
                                    .is_some_and(|other| other.external_commitment != e),
                            ),
                            WalkOutcome::Continue { .. }
                            | WalkOutcome::Unresolved { .. }
                            | WalkOutcome::CounterExhausted { .. } => {
                                return Ok(Err(chain.not_established.unwrap_or(not_live)))
                            }
                        }
                    };
                legs.push(LegFacts {
                    cell,
                    parent,
                    attempt_live,
                    parent_consumed_elsewhere,
                });
            }
            let storage_resolved =
                registered && legs.iter().all(|l| permanently_resolved(&l.cell, &e));
            Ok(Ok(Known::Facts(Fetched {
                external_commitment: e,
                registered,
                conformance,
                position_lost,
                parent,
                parent_pre_root: *precommit.void_root(),
                validation,
                storage_resolved,
                legs,
                walked_leg,
            })))
        })
    }
}
