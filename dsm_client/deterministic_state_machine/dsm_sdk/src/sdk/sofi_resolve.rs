// SPDX-License-Identifier: Apache-2.0
//! Stage 9 of §31 and the walk of §30, rebuild step R12: consumption and
//! resolution over raw reads.
//!
//! Core decides; this module only fetches. For one exercise at one key it
//! builds the facts the ladder reads (`RouteFacts`): registration from the
//! position pair (R10), `FulfillmentConformance` and `RouteValidation` from
//! acquired evidence (R5, R7), each leg's cell from its successor key (R11),
//! attempt liveness from the walk over the earlier keys of that leg's chain,
//! and the trader parent from the claims this verifier resolved itself. Then
//! Core's `walk` classifies the keys and `resolve_position` the position.
//!
//! Nothing here is defaulted. A fact the verifier has not established is
//! its unestablished value — an unread cell is `Unresolved`, an unwalked
//! parent is not canonical, an unresolved conditional parent is
//! `ConditionalPending` — and every such value keeps the walk unresolved and
//! the position Pending. One fact this step leaves unestablished for every
//! leg is orphaning: a parent is orphaned once its predecessor's canonical
//! successor resolved to something else, which the generation walk of
//! rebuild step R13 establishes; until then a defeated leg is seen through
//! the consumer the walk finds at its chain, or waits.
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

use dsm::sofi::arith::CellResolution;
use dsm::sofi::conformance::{fulfillment_conformance, Validation};
use dsm::sofi::exercise::{recognize_exercise, RecognizedExercise};
use dsm::sofi::registration::Registration;
use dsm::sofi::resolution::{
    effect_of, resolve_position, walk, LegFacts, ParentPosition, PositionEffect, Resolution,
    RouteFacts, WalkOutcome,
};
use dsm::sofi::validation::route_validation;
use dsm::sofi::wire::{ParentClaimRef, SofiExercise, ValidationRef};
use dsm::types::error::DsmError;

use crate::sdk::sofi_evidence::{acquire_evidence, LocalLeaves};
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
/// liveness is unestablished, which keeps its route unresolved — never a
/// skip, never a consumption.
pub const CHAIN_DEPTH: usize = 2;

/// What the verifier brings to a resolution: the committed set, its own
/// leaves, the trader positions it resolved itself and the vault ancestry it
/// walked. Every field is an established fact of THIS verifier; none is
/// trusted because somebody sent it.
pub struct Resolver<'a> {
    pub set: &'a StorageSet,
    /// The verifier's own `R_econ` leaves, for the trader-leaf pre values
    /// `RouteValidation` reads.
    pub local: &'a LocalLeaves,
    /// The conditional positions this verifier has resolved (stage 0 of §31),
    /// by the fulfillment that installed them: what each selected. A
    /// conditional parent absent here has not been resolved by this
    /// verifier, and the position built on it waits (`ConditionalPending`).
    pub parents: &'a BTreeMap<D32, ParentPosition>,
    /// The `(vault_id, root)` pairs this verifier walked to from a vault's
    /// genesis (Section 30): its established canonical ancestry. A leg whose
    /// parent is not here is not established canonical and never consumes.
    pub canonical: &'a BTreeSet<(D32, D32)>,
}

/// One trader position, resolved (stage 9 of §31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub resolution: Resolution,
    /// What `advance_resolved` (R13) does with it.
    pub effect: PositionEffect,
    pub registered: bool,
    pub conformance: Validation,
    pub validation: Validation,
}

/// Where a walk over one parent's attempt chain ended, with the exercise
/// that consumed the parent when one did: its consumed route's `V°` post
/// root is the next parent (Section 30, step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walked {
    pub outcome: WalkOutcome,
    pub consumed: Option<RecognizedExercise>,
}

/// The facts of one exercise, fetched; `RouteFacts` borrows them.
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
    exercise: RecognizedExercise,
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

/// A reserved key permanently resolved for the route bound to `e`: final on
/// anything, or lost at its leader to another commitment (`LeaderHeld`
/// settles the loss before the copies arrive). A key held on `e` itself is
/// not resolved yet.
fn permanently_resolved(cell: CellResolution, e: &D32) -> bool {
    match cell {
        CellResolution::Final(_) => true,
        CellResolution::LeaderHeld(x) => x != *e,
        CellResolution::Unresolved => false,
    }
}

/// The key of one leg being walked: vault, parent, attempt, and the cell as
/// it was just read.
#[derive(Clone, Copy)]
struct WalkedKey {
    vault_id: D32,
    parent_root: D32,
    attempt: u64,
    cell: CellResolution,
}

type Fut<'s, T> = Pin<Box<dyn Future<Output = Result<T, DsmError>> + 's>>;

impl Resolver<'_> {
    /// Section 30, step 2: walk the attempt keys of `vault_id` at
    /// `parent_root` from `cursor`, reading each cell raw, building the facts
    /// of the exercise it holds and letting Core classify it. A skipped key
    /// moves on, a consumed key stops with its exercise, anything else is
    /// unresolved; a spent budget hands back a cursor.
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

    /// Stage 9 of §31: the trader's own position, resolved from raw reads over
    /// the exercise it built (R11). The ladder's answer and its effect.
    pub async fn resolve_trader_position(
        &self,
        exercise: &SofiExercise,
    ) -> Result<Resolved, DsmError> {
        let recognized = recognize_exercise(&exercise.encode()).ok_or_else(|| {
            DsmError::verification("resolve: the bytes are not one operation's exercise")
        })?;
        self.resolve_recognized(recognized).await
    }

    /// The same, over an exercise already recognized — the one read back from
    /// a leg's cell (`read_attempt_cell`), which is how the device finds its
    /// own exercise again after a restart (R13).
    pub async fn resolve_recognized(
        &self,
        recognized: RecognizedExercise,
    ) -> Result<Resolved, DsmError> {
        let fetched = self.facts_of(recognized, None, CHAIN_DEPTH).await?;
        let resolution = resolve_position(&fetched.facts());
        Ok(Resolved {
            resolution,
            effect: effect_of(resolution),
            registered: fetched.registered,
            conformance: fetched.conformance,
            validation: fetched.validation,
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
            // cannot classify; a key it asks for that is not fetched yet is
            // fetched, and the walk resumes. The chunking is invisible to the
            // answer (`walk_chunking_preserves_result`).
            let mut fetched: BTreeMap<u64, Fetched> = BTreeMap::new();
            loop {
                let outcome = walk(cursor, budget, |attempt| {
                    fetched
                        .get(&attempt)
                        .map(|f| (f.facts(), f.legs[f.walked_leg]))
                });
                match outcome {
                    WalkOutcome::Unresolved { attempt } if !fetched.contains_key(&attempt) => {
                        let (cell, exercise) =
                            read_attempt_cell(self.set, &vault_id, &parent_root, attempt).await?;
                        let Some(exercise) = exercise else {
                            // Open, or the leader unread: unresolved, and
                            // never a skip (no key is ever dead).
                            return Ok(Walked {
                                outcome,
                                consumed: None,
                            });
                        };
                        let key = WalkedKey {
                            vault_id,
                            parent_root,
                            attempt,
                            cell,
                        };
                        let facts = self.facts_of(exercise, Some(key), depth).await?;
                        fetched.insert(attempt, facts);
                    }
                    WalkOutcome::Consumed { attempt } => {
                        return Ok(Walked {
                            outcome,
                            consumed: fetched.get(&attempt).map(|f| f.exercise.clone()),
                        })
                    }
                    other => {
                        return Ok(Walked {
                            outcome: other,
                            consumed: None,
                        })
                    }
                }
            }
        })
    }

    /// The facts of one exercise, as the ladder reads them, from raw reads.
    /// `walked` is the key the exercise was found at, whose cell is in hand
    /// and whose liveness the walk established by reaching it.
    fn facts_of(
        &self,
        exercise: RecognizedExercise,
        walked: Option<WalkedKey>,
        depth: usize,
    ) -> Fut<'_, Fetched> {
        Box::pin(async move {
            let precommit = &exercise.precommit.body;
            let fulfillment = &exercise.fulfillment.body;
            let e = exercise.external_commitment;

            // Registration from the position pair (R10). The pair decides
            // for every F at q at once: a root cell final on another claim,
            // or a fulfillment cell final on another F of this trader, is
            // this F's position lost (Section 21.1) — arm (v).
            let registration = read_registration(
                self.set,
                precommit.genesis(),
                precommit.device_id(),
                fulfillment.position(),
                precommit.void_root(),
            )
            .await?;
            let (registered, position_lost) = match &registration {
                Registration::Registered(signed) => {
                    let ours = signed.body == *fulfillment;
                    (ours, !ours)
                }
                Registration::NeverRegistered { .. } => (false, true),
                Registration::Unresolved => (false, false),
            };

            // FulfillmentConformance over acquired evidence (R7), the
            // exercise supplying the objects only its trader held, and the
            // earlier attempt keys F skips past resolved from their cells.
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
            // Item 5's cells come from the one shared acquisition (R9/R12,
            // owner ruling §44.4), so the producer and the verifier read the
            // same keys the same way and cannot disagree about what an
            // attempt skipped past.
            let evidence = acquire_conformance_evidence(self.set, &request).await?;
            let conformance =
                fulfillment_conformance(fulfillment, &exercise.fulfillment.signature, &evidence)
                    .verdict();

            // RouteValidation over acquired evidence (R5).
            let validation = route_validation(
                precommit,
                &exercise.preimage,
                &acquire_evidence(self.set, &exercise.preimage, self.local).await?,
            );

            // The trader parent: P names it; what it selected is this
            // verifier's own resolution of p, or nothing yet.
            let parent = match precommit.parent_claim_ref() {
                ParentClaimRef::SingleRoot { .. } => ParentPosition::SingleRoot,
                ParentClaimRef::Conditional { fulfillment_id } => self
                    .parents
                    .get(fulfillment_id)
                    .copied()
                    .unwrap_or(ParentPosition::ConditionalPending),
            };

            // Every leg of P at the attempt F fixed for it.
            let mut legs = Vec::with_capacity(precommit.legs().len());
            let mut walked_leg = 0;
            for (j, leg) in precommit.legs().iter().enumerate() {
                let here = walked
                    .filter(|k| k.vault_id == leg.vault_id && k.parent_root == leg.parent_root);
                if here.is_some() {
                    walked_leg = j;
                }
                let Some(attempt) = fulfillment
                    .attempts()
                    .iter()
                    .find(|a| a.vault_id == leg.vault_id)
                    .map(|a| a.attempt)
                else {
                    // F names no attempt for this leg: conformance item 4
                    // refuses it; the leg has no key to read.
                    legs.push(LegFacts {
                        cell: CellResolution::Unresolved,
                        canonical_parent: false,
                        attempt_live: false,
                        parent_orphaned: false,
                        parent_consumed_elsewhere: false,
                    });
                    continue;
                };
                let at_walked_key = here.is_some_and(|k| k.attempt == attempt);
                let cell = match here {
                    Some(k) if at_walked_key => k.cell,
                    _ => {
                        read_attempt_cell(self.set, &leg.vault_id, &leg.parent_root, attempt)
                            .await?
                            .0
                    }
                };
                let canonical_parent =
                    here.is_some() || self.canonical.contains(&(leg.vault_id, leg.parent_root));
                // `AttemptLive`: every earlier key of this leg's chain is
                // skipped. The walk established it for the key it reached;
                // any other leg's chain is walked over its earlier keys.
                let (attempt_live, parent_consumed_elsewhere) = if at_walked_key || attempt == 0 {
                    (true, false)
                } else if depth == 0 {
                    (false, false)
                } else {
                    let earlier = usize::try_from(attempt)
                        .unwrap_or(usize::MAX)
                        .min(WALK_BUDGET);
                    let chain = self
                        .walk_chain(leg.vault_id, leg.parent_root, 0, earlier, depth - 1)
                        .await?;
                    match chain.outcome {
                        WalkOutcome::Continue { cursor } => (cursor == attempt, false),
                        WalkOutcome::Consumed { .. } => (
                            false,
                            chain.consumed.is_some_and(|x| x.external_commitment != e),
                        ),
                        WalkOutcome::Unresolved { .. } | WalkOutcome::CounterExhausted { .. } => {
                            (false, false)
                        }
                    }
                };
                legs.push(LegFacts {
                    cell,
                    canonical_parent,
                    attempt_live,
                    parent_orphaned: false,
                    parent_consumed_elsewhere,
                });
            }
            let storage_resolved =
                registered && legs.iter().all(|l| permanently_resolved(l.cell, &e));
            Ok(Fetched {
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
                exercise,
            })
        })
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use dsm::common::domain_tags::TAG_DSM_SOFI_FULFILLMENT;
    use dsm::sofi::derive;
    use dsm::sofi::resolution::ImpossibleArm;
    use dsm::sofi::wire::{AttemptEntry, TraderFulfillmentBody};
    use serial_test::serial;

    use super::*;
    use crate::sdk::economic_registers::economic_root_namespace;
    use crate::sdk::sofi_exercise::{build_exercise, write_exercise};
    use crate::sdk::sofi_register::{install_fulfillment, position_of};
    use crate::sdk::sofi_test_fixtures::{
        block_on, install_request, pair_bytes, signed_route, trader_keys, SignedRoute, SIG_ALG,
    };
    use crate::sdk::storage_io::{fake_registers, leader_index, write_cells_leader_first};

    /// The route's exercise over the evidence its conformance was decided
    /// on, written to every leg's key.
    fn exercised(r: &SignedRoute) -> SofiExercise {
        let req = install_request(r);
        let ev = block_on(acquire_conformance_evidence(&r.set, &req)).unwrap();
        let x = build_exercise(&req, &ev).unwrap();
        let recognized = recognize_exercise(&x.encode()).unwrap();
        block_on(write_exercise(&r.set, &x, &recognized)).unwrap();
        x
    }

    /// The heads the trader walked to: the parents its legs name.
    fn walked_heads(r: &SignedRoute) -> BTreeSet<(D32, D32)> {
        r.precommit
            .legs()
            .iter()
            .map(|l| (l.vault_id, l.parent_root))
            .collect()
    }

    /// Stage 9: a registered, conforming, valid route whose exercise is
    /// final at every leg resolves Realized with the realize-root effect, and
    /// the walk over each parent finds the key consumed by that exercise.
    #[test]
    #[serial]
    fn a_registered_and_completed_route_is_realized_and_consumes_every_parent() {
        let r = signed_route(true);
        block_on(install_fulfillment(&r.set, &install_request(&r))).unwrap();
        let x = exercised(&r);
        let parents = BTreeMap::new();
        let canonical = walked_heads(&r);
        let resolver = Resolver {
            set: &r.set,
            local: &r.local,
            parents: &parents,
            canonical: &canonical,
        };
        assert_eq!(
            block_on(resolver.resolve_trader_position(&x)).unwrap(),
            Resolved {
                resolution: Resolution::Realized,
                effect: PositionEffect::InstallRealizeRoot,
                registered: true,
                conformance: Validation::Valid,
                validation: Validation::Valid,
            }
        );
        for leg in r.precommit.legs() {
            let walked =
                block_on(resolver.walk_parent(&leg.vault_id, &leg.parent_root, 0, WALK_BUDGET))
                    .unwrap();
            assert_eq!(walked.outcome, WalkOutcome::Consumed { attempt: 0 });
            assert_eq!(
                walked.consumed.map(|c| c.fulfillment.body),
                Some(r.fulfillment.clone())
            );
        }
    }

    /// Lean `realized_requires_conformance`, TLA `_ConformanceDropped`, at
    /// the resolver: a route whose pair is final at the position and whose
    /// exercise is final at every leg — registered, statically Valid — does
    /// not realize while its conformance is undecided. Here a leg's setup was
    /// never published, so item 6 is Unavailable: Pending, and the walk sees
    /// the key as open business, not consumed and not skipped.
    #[test]
    #[serial]
    fn a_registered_route_whose_setup_is_unpublished_is_pending_not_realized() {
        let r = signed_route(false);
        // The pair, written directly: the producer's gate (install) refuses
        // this route, and a verifier must not need the producer to have
        // behaved to read the position correctly.
        let at = position_of(&r.precommit, &r.fulfillment);
        let (f_bytes, claim) = pair_bytes(&r);
        block_on(write_cells_leader_first(
            &r.set,
            &at.seed,
            &[
                (
                    TAG_DSM_SOFI_FULFILLMENT.source_bytes().to_vec(),
                    at.k_ful,
                    f_bytes,
                ),
                (economic_root_namespace().to_vec(), at.k_root, claim),
            ],
        ))
        .unwrap();
        let x = exercised(&r);
        let parents = BTreeMap::new();
        let canonical = walked_heads(&r);
        let resolver = Resolver {
            set: &r.set,
            local: &r.local,
            parents: &parents,
            canonical: &canonical,
        };
        let resolved = block_on(resolver.resolve_trader_position(&x)).unwrap();
        assert!(resolved.registered, "the pair is final at the position");
        assert_eq!(resolved.validation, Validation::Valid);
        assert_eq!(resolved.conformance, Validation::Unavailable);
        assert_eq!(resolved.resolution, Resolution::Pending);
        assert_eq!(resolved.effect, PositionEffect::None);
        let leg = &r.precommit.legs()[0];
        let walked =
            block_on(resolver.walk_parent(&leg.vault_id, &leg.parent_root, 0, WALK_BUDGET))
                .unwrap();
        assert_eq!(walked.outcome, WalkOutcome::Unresolved { attempt: 0 });
        assert!(walked.consumed.is_none());
    }

    /// TLA `LostPosition` (`_LostPositionDropped`), Lean
    /// `a_lost_position_makes_a_final_route_skippable`, at the resolver: a
    /// claim first at the leader of `K_root(q)` settles that this F never
    /// registers. Its exercise, final at `K^(0)`, is then skipped — the walk
    /// moves to attempt 1 instead of stranding the parent — and the position
    /// stays Pending through this F: it resolves through the claim that took
    /// it.
    #[test]
    #[serial]
    fn an_exercise_whose_fulfillment_lost_its_position_is_skipped_not_stranded() {
        let r = signed_route(true);
        let at = position_of(&r.precommit, &r.fulfillment);
        let leader = leader_index(&r.set, &at.seed).unwrap();
        let rival = TraderFulfillmentBody::new(
            *r.fulfillment.precommit_id(),
            r.fulfillment.policy_fulfillment_set().to_vec(),
            r.fulfillment
                .attempts()
                .iter()
                .map(|a| AttemptEntry {
                    vault_id: a.vault_id,
                    attempt: a.attempt + 1,
                })
                .collect(),
            r.fulfillment.position(),
            SIG_ALG,
            &trader_keys().0,
        )
        .unwrap();
        let rival_claim = derive::resolution_claim(&r.precommit, &rival).encode();
        fake_registers::put_cell(
            &r.set,
            leader,
            economic_root_namespace(),
            &at.k_root,
            &rival_claim,
        );
        block_on(install_fulfillment(&r.set, &install_request(&r))).unwrap();
        let x = exercised(&r);
        let parents = BTreeMap::new();
        let canonical = walked_heads(&r);
        let resolver = Resolver {
            set: &r.set,
            local: &r.local,
            parents: &parents,
            canonical: &canonical,
        };
        let resolved = block_on(resolver.resolve_trader_position(&x)).unwrap();
        assert!(!resolved.registered);
        assert_eq!(resolved.resolution, Resolution::Pending);
        let leg = &r.precommit.legs()[0];
        let walked =
            block_on(resolver.walk_parent(&leg.vault_id, &leg.parent_root, 0, WALK_BUDGET))
                .unwrap();
        assert_eq!(
            walked.outcome,
            WalkOutcome::Unresolved { attempt: 1 },
            "attempt 0 is skipped as {:?}; attempt 1 is live and open",
            ImpossibleArm::PositionLost
        );
        assert!(walked.consumed.is_none());
    }
}
