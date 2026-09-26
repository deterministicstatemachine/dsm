// SPDX-License-Identifier: Apache-2.0
//! Stage 9 of §31 and the walk of §30, rebuild step R12: the reads a
//! resolution stands on, fetched here; the facts, established by Core.
//!
//! Core decides; this module only fetches. For one exercise at one key it
//! first asks Core what the exercise's own bytes refute
//! (`facts::refuted_in_hand`, MR-DSM-0041, MR-DSM-0042): a refuted exercise
//! is classified with nothing read about it — at a walked key, nothing beyond
//! the cell it was found at; for the trader's own position, nothing beyond
//! the registration its caller read to find it. Otherwise it reads what the
//! ladder's facts are established from and hands the reads to
//! `facts::establish`: the position pair (R10), the objects
//! `FulfillmentConformance` and `RouteValidation` consume (R5, R7), each leg's
//! cell at its successor key (R11), and the walk over the earlier keys of that
//! leg's chain. Every read is a Core-evaluated witness bound to what it was
//! read at; every fact is Core's conclusion over them; the verdict is formed
//! nowhere here — `advance_resolved` runs the ladder over the established
//! facts, and `walk` classifies the keys of a chain.
//!
//! Core establishes only over complete reads (Amendment S7). A fact this
//! verifier has not established is never handed to Core in another fact's
//! place: it is [`NotEstablished`], named, and the caller reads and relays
//! again. The one three-valued fact is a leg's parent status, whose
//! `Unavailable` is Core's own value for a parent the verifier's chain has
//! not reached.
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use dsm::economic::lineage::AdmittedEconomicPosition;
use dsm::sofi::exercise::{AttemptCellRead, RecognizedExercise};
use dsm::sofi::facts::{
    establish, refuted_in_hand, Established, EstablishedFacts, ExerciseReads, InHandRefutation,
    LegReads, NotEstablished,
};
use dsm::sofi::registration::RegistrationRead;
use dsm::sofi::resolution::{walk, AttemptWalk, KeyFacts, VaultChain, WalkOutcome};
use dsm::sofi::wire::ValidationRef;
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
/// leaves, the position it resolved itself and the vault ancestry it walked.
/// Every field is an established fact of THIS verifier; none is trusted
/// because somebody sent it.
pub struct Resolver<'a> {
    pub set: &'a StorageSet,
    /// This device's own `R_econ` leaves, for the trader-leaf pre values of
    /// its own routes.
    pub local: &'a LocalLeaves,
    /// This verifier's own admitted position, when it resolved a conditional
    /// one: what a `P` naming that fulfillment as its parent was built on.
    /// Core reads what it selected; nothing else resolves a parent, and a
    /// conditional parent this verifier did not resolve is not established.
    pub parent: Option<&'a AdmittedEconomicPosition>,
    /// The canonical chain this verifier established for each vault it needs
    /// one for (Section 30), built by `sofi_chain::ChainWalker`. A chain
    /// carries generations, which is what lets a parent be refuted
    /// (`ParentStatus::Orphaned`) rather than only waited on. A vault with
    /// no chain here is `Unavailable` for every leg naming it.
    pub chains: &'a BTreeMap<D32, VaultChain>,
}

/// Where a walk over one parent's attempt chain ended, with the exercise
/// that consumed the parent when one did — its consumed route's `V°` post
/// root is the next parent (Section 30, step 3) — and, when it stopped
/// unresolved at a key it could not classify, why. Carries what it
/// classified, so that a walk resumed at its cursor ([`Resolver::continue_walk`])
/// still stands on every earlier key.
#[derive(Debug)]
pub struct Walked {
    pub outcome: WalkOutcome,
    /// The walk as Core made it: what a leg's liveness is read from.
    pub walk: AttemptWalk,
    pub consumed: Option<RecognizedExercise>,
    pub not_established: Option<NotEstablished>,
    known: BTreeMap<u64, KeyKnown>,
}

/// What this verifier knows about one exercise.
#[derive(Debug)]
enum Known {
    /// Refuted by its own bytes: nothing else was read.
    RefutedInHand(InHandRefutation),
    /// The complete facts Core established over the reads.
    Facts(Box<EstablishedFacts>),
}

/// One key the walk classified: the read that found the exercise holding
/// it, and what is known about that exercise.
#[derive(Debug)]
struct KeyKnown {
    read: AttemptCellRead,
    known: Known,
}

impl KeyKnown {
    /// The facts of this key as Core binds them to it: the exercise the read
    /// holds, and the facts established for that exercise.
    fn key_facts(&self) -> Option<KeyFacts<'_>> {
        match &self.known {
            Known::Facts(facts) => KeyFacts::of(&self.read, facts),
            Known::RefutedInHand(refutation) => KeyFacts::refuted(&self.read, refutation),
        }
    }
}

/// The key an exercise was found at while walking a chain: its read, and the
/// walk over the keys before it, which reached it by skipping every one.
#[derive(Clone, Copy)]
struct WalkedKey<'a> {
    read: &'a AttemptCellRead,
    reached: &'a AttemptWalk,
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
        self.walk_chain(
            *vault_id,
            *parent_root,
            cursor,
            budget,
            CHAIN_DEPTH,
            BTreeMap::new(),
        )
        .await
    }

    /// Resume a walk whose budget ran out (`WalkOutcome::Continue`) at its
    /// cursor, over everything it already classified: the answer is the same
    /// as one longer walk's, and a key reached this way still has every
    /// earlier key behind it for its liveness.
    pub async fn continue_walk(&self, previous: Walked, budget: usize) -> Result<Walked, DsmError> {
        let cursor = match previous.outcome {
            WalkOutcome::Continue { cursor } => cursor,
            WalkOutcome::Consumed { attempt }
            | WalkOutcome::Unresolved { attempt }
            | WalkOutcome::CounterExhausted { attempt } => attempt,
        };
        self.walk_chain(
            *previous.walk.vault_id(),
            *previous.walk.parent_root(),
            cursor,
            budget,
            CHAIN_DEPTH,
            previous.known,
        )
        .await
    }

    /// Stage 9 of §31: what this verifier establishes about the trader's own
    /// exercise, read back from a leg's cell (`read_attempt_cell`) — how the
    /// device finds its own exercise again after a restart (R13) — over the
    /// registration of its position, which the caller read to find that
    /// exercise. A refuted exercise reads nothing more: its registration is
    /// the one fact the ladder asks of it (§24 step 0), and it is in hand.
    /// The ladder runs inside `advance_resolved`, over what is returned here.
    pub async fn establish_own(
        &self,
        recognized: &RecognizedExercise,
        registration: &RegistrationRead,
    ) -> Result<Result<Established, NotEstablished>, DsmError> {
        Ok(
            match self
                .facts_of(recognized, None, CHAIN_DEPTH, Some(registration))
                .await?
            {
                Ok(Known::Facts(facts)) => Ok(Established::Facts(facts)),
                Ok(Known::RefutedInHand(refutation)) => {
                    Established::refuted(recognized, &refutation, registration)
                }
                Err(why) => Err(why),
            },
        )
    }

    fn walk_chain(
        &self,
        vault_id: D32,
        parent_root: D32,
        cursor: u64,
        budget: usize,
        depth: usize,
        mut known: BTreeMap<u64, KeyKnown>,
    ) -> Fut<'_, Walked> {
        Box::pin(async move {
            // Core's walk asks for keys in order and stops on the first it
            // cannot classify; a key it asks for that is not read yet is read,
            // and the walk resumes. The chunking is invisible to the answer.
            loop {
                let walked = walk(&vault_id, &parent_root, cursor, budget, |attempt| {
                    known.get(&attempt).and_then(KeyKnown::key_facts)
                });
                let outcome = walked.outcome();
                let done = |consumed, not_established, known| Walked {
                    outcome,
                    walk: walked,
                    consumed,
                    not_established,
                    known,
                };
                match outcome {
                    WalkOutcome::Unresolved { attempt } if !known.contains_key(&attempt) => {
                        let read =
                            match read_attempt_cell(self.set, &vault_id, &parent_root, attempt)
                                .await?
                            {
                                Ok(read) => read,
                                Err(missing) => {
                                    return Ok(done(
                                        None,
                                        Some(NotEstablished::AttemptCell {
                                            vault_id,
                                            attempt,
                                            missing,
                                        }),
                                        known,
                                    ))
                                }
                            };
                        // An open key is unresolved, never a skip: no key is
                        // ever dead.
                        let Some(exercise) = read.exercise().cloned() else {
                            return Ok(done(None, None, known));
                        };
                        // The walk reached this key by skipping every one
                        // before it. That liveness is stated as the walk
                        // over them, for Core to read, never as a flag.
                        let reached = walk(
                            &vault_id,
                            &parent_root,
                            0,
                            usize::try_from(attempt).unwrap_or(usize::MAX),
                            |a| known.get(&a).and_then(KeyKnown::key_facts),
                        );
                        let key = WalkedKey {
                            read: &read,
                            reached: &reached,
                        };
                        match self.facts_of(&exercise, Some(key), depth, None).await? {
                            Ok(facts) => {
                                known.insert(attempt, KeyKnown { read, known: facts });
                            }
                            Err(why) => return Ok(done(None, Some(why), known)),
                        }
                    }
                    WalkOutcome::Consumed { attempt } => {
                        let consumed = known
                            .get(&attempt)
                            .and_then(|key| key.read.exercise().cloned());
                        return Ok(done(consumed, None, known));
                    }
                    WalkOutcome::Unresolved { .. }
                    | WalkOutcome::CounterExhausted { .. }
                    | WalkOutcome::Continue { .. } => return Ok(done(None, None, known)),
                }
            }
        })
    }

    /// What is known about one exercise: refuted by its own bytes, or the
    /// complete facts Core established over the reads made here. `walked` is
    /// the key the exercise was found at, whose cell is in hand and whose
    /// liveness the walk established by reaching it. `registration` is the
    /// position's registration when the caller already read it; otherwise it
    /// is read here.
    fn facts_of<'s>(
        &'s self,
        exercise: &'s RecognizedExercise,
        walked: Option<WalkedKey<'s>>,
        depth: usize,
        registration: Option<&'s RegistrationRead>,
    ) -> Fut<'s, Result<Known, NotEstablished>> {
        Box::pin(async move {
            if let Some(refutation) = refuted_in_hand(exercise) {
                log::info!(
                    "[sofi resolve] the exercise is refuted in hand: {:?}",
                    refutation.refuted()
                );
                return Ok(Ok(Known::RefutedInHand(refutation)));
            }
            let precommit = &exercise.precommit.body;
            let fulfillment = &exercise.fulfillment.body;

            // Registration from the position pair (R10). The pair decides
            // for every F at q at once; Core reads it.
            let registration = match registration {
                Some(registration) => registration.clone(),
                None => match read_registration(
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
                },
            };

            // What FulfillmentConformance reads (R7), the exercise supplying
            // the objects only its trader held.
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
                Acquired::Complete(evidence) => evidence,
                Acquired::Exhausted(missing) | Acquired::NoSource(missing) => {
                    return Ok(Err(NotEstablished::ConformanceEvidence(missing)))
                }
            };

            // What RouteValidation reads (R5).
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

            // Every leg of P at the attempt F fixed for it: its cell, and the
            // walk over the earlier keys of its chain when its attempt is
            // above zero. The attempts cover the legs exactly: that is
            // conformance item 4, decided in hand.
            let mut cells = Vec::with_capacity(precommit.legs().len());
            let mut walks: Vec<Option<AttemptWalk>> = Vec::with_capacity(precommit.legs().len());
            for leg in precommit.legs() {
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
                let at_walked_key = walked.filter(|k| {
                    *k.read.vault_id() == leg.vault_id
                        && *k.read.parent_root() == leg.parent_root
                        && k.read.attempt() == attempt
                });
                let (cell, walk) = match at_walked_key {
                    Some(key) => (key.read.clone(), Some(*key.reached)),
                    None => {
                        let cell = match read_attempt_cell(
                            self.set,
                            &leg.vault_id,
                            &leg.parent_root,
                            attempt,
                        )
                        .await?
                        {
                            Ok(read) => read,
                            Err(missing) => {
                                return Ok(Err(NotEstablished::AttemptCell {
                                    vault_id: leg.vault_id,
                                    attempt,
                                    missing,
                                }))
                            }
                        };
                        // `AttemptLive`: every earlier key of this leg's
                        // chain is skipped, established by walking them.
                        let walk = if attempt == 0 {
                            None
                        } else {
                            let not_live = NotEstablished::AttemptLiveness {
                                vault_id: leg.vault_id,
                                attempt,
                            };
                            let Some(below) = depth.checked_sub(1) else {
                                return Ok(Err(not_live));
                            };
                            let earlier = usize::try_from(attempt)
                                .map_or(WALK_BUDGET, |a| a.min(WALK_BUDGET));
                            let chain = self
                                .walk_chain(
                                    leg.vault_id,
                                    leg.parent_root,
                                    0,
                                    earlier,
                                    below,
                                    BTreeMap::new(),
                                )
                                .await?;
                            if let Some(why) = chain.not_established {
                                return Ok(Err(why));
                            }
                            Some(chain.walk)
                        };
                        (cell, walk)
                    }
                };
                cells.push(cell);
                walks.push(walk);
            }
            let legs: Vec<LegReads<'_>> = precommit
                .legs()
                .iter()
                .zip(cells.iter().zip(walks.iter()))
                .map(|(leg, (cell, walk))| LegReads {
                    cell,
                    chain: self.chains.get(&leg.vault_id),
                    walk: walk.as_ref(),
                })
                .collect();
            let reads = ExerciseReads {
                exercise,
                registration: &registration,
                conformance: &conformance,
                evidence: &evidence,
                parent: self.parent,
                legs: &legs,
            };
            Ok(establish(&reads).map(|facts| Known::Facts(Box::new(facts))))
        })
    }
}
