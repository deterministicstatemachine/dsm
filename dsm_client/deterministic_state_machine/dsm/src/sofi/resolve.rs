// SPDX-License-Identifier: Apache-2.0

//! The SoFi verifier: what is read, in what order, and what it establishes —
//! stage 3 and stages 9–10 of §31, the walk of §30, rebuild steps R5, R7,
//! R10–R12 and R14 — over a [`SofiReads`] the SDK implements with bytes,
//! cells and its own local records, and nothing else.
//!
//! Core decides; the reads supply. Every cell is derived here from committed
//! state (`AttemptCell`, `PositionCells`) and evaluated here from every
//! seat's reads; every object is recognized here from its bytes; every
//! predicate is recomputed here over the evidence gathered; every fact the
//! ladder reads is established here ([`super::facts::establish`]) and the
//! ladder runs inside `advance_resolved`. Nothing an implementor of
//! [`SofiReads`] answers is a verdict: a member that did not answer is a
//! [`ReadFailure`], a network status; bytes are bytes until Core recognizes
//! them; a local record is this device's own earlier conclusion, checked
//! before it is stood on.
//!
//! The one thing this module does not do is I/O, and the one thing the SDK
//! does with a [`Verifier`] is answer its reads — the shape of the peer
//! lineage walker (`economic::peer_lineage::PeerEvidenceFetcher`), which
//! walks a foreign lineage the same way.

use std::collections::{BTreeMap, BTreeSet};

use crate::ccb::StorageSetMembers;
use crate::economic::lineage::{AcceptedClaim, ValidatedEconomicRoot};
use crate::economic::provenance::{PeerLineageFailure, ValidatedPeerTransition};
use crate::economic::register::root_completion;
use crate::economic::state::EconomicLeafState;
use crate::economic::tree::EconomicSmt;
use crate::route_chain::{
    CellEvidence, CellFact, ChainState, CompletionProof, Missing as CellMissing, RoutedCell,
};

use super::conformance::{
    fulfillment_conformance, ConformanceEvidence, ConformanceMissing, FulfillmentConformance,
    Validation,
};
use super::derive;
use super::exercise::{
    attempt_completion, attempt_resolution, AttemptCell, AttemptCellRead, RecognizedExercise,
};
use super::facts::{
    establish, establish_ground, refuted_in_hand, Established, EstablishedFacts, ExerciseReads,
    GroundFacts, GroundReads, InHandRefutation, LegReads, NotEstablished, ResolvedParent,
    TraderAtParent,
};
use super::lineage::{
    advance_peer_resolved, AdvanceError, PeerResolvedAdvance, genesis_accepted, genesis_root,
    vault_leaves_at_genesis, AcceptedVaultGenesis, GenesisInvalid, GenesisMissing, GenesisRefusal,
};
use super::publication::{recognize_setup, Signed};
use super::registration::{
    fulfillment_completion, fulfillment_registered, PositionCells, Registration, RegistrationRead,
};
use super::resolution::{
    skip_without_evidence, walk, AttemptClass, AttemptWalk, KeyFacts, RecordedGeneration,
    VaultChain, WalkOutcome,
};
use super::storage::{Discovered, Resolved};
use super::validation::{
    route_validation, setup_lineage, vault_post_states, Evidence, EvidenceNeeds, Missing,
    SetupLineage, VaultLeafPre, VaultPostState,
};
use super::wire::{
    CoreEntry, ParentClaimRef, SettlementPreimage, SofiResolutionClaim, TraderCore,
    TraderFulfillmentBody, TraderPreBalance, TraderPrecommitBody, ValidationRef,
    VaultGenesisPreimage, VaultStateLeaf,
};

type D32 = [u8; 32];

/// The pre values of one vault's leaves, by `(vault_id, key)`.
pub type VaultLeaves = BTreeMap<(D32, D32), VaultLeafPre>;

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

/// How many generations one call extends a vault's chain by. A budget only,
/// never a verdict: a chain that stops here is short, not complete, and a
/// generation it did not reach is `Unavailable`.
pub const GENERATION_BUDGET: usize = 16;

/// How far the chain walk recurses into OTHER vaults' chains. A multi-leg
/// route can only have consumed this vault's root if every leg's parent was
/// canonical, so establishing this chain can require establishing a
/// sibling's. Beta routes are two hops, so two levels cover them; past this
/// depth a sibling is unestablished, which stops this chain rather than
/// guessing at it.
pub const SIBLING_DEPTH: usize = 2;

/// Acquisition rounds before the evidence is `Exhausted`.
pub const ACQUIRE_ROUNDS: usize = 3;

/// A read that could not be made: a member did not answer, a local store
/// failed. A network status, never a verdict, and never a fact about the
/// operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFailure(pub String);

impl core::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why the verifier could not proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierFailure {
    /// A read could not be made.
    Read(String),
    /// What was read refutes the premise the verifier was working from: a
    /// vault's genesis is refused, this device's own record of a chain
    /// contradicts itself.
    Refused(String),
}

impl core::fmt::Display for VerifierFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read(why) => write!(f, "read: {why}"),
            Self::Refused(why) => write!(f, "refused: {why}"),
        }
    }
}

impl From<ReadFailure> for VerifierFailure {
    fn from(failure: ReadFailure) -> Self {
        Self::Read(failure.0)
    }
}

/// One generation this device recorded for a vault, as its store holds it:
/// the root at that generation, and — past genesis — the root it was built
/// on and the operation that consumed it. Rows are handed contiguously from
/// generation zero; what they link to is checked by
/// [`VaultChain::from_recorded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedGenerationRow {
    pub generation: u64,
    pub root: D32,
    pub pre_root: Option<D32>,
    pub consumed_by: Option<D32>,
}

/// What the verifier reads. Every answer is bytes, cells or this device's
/// own records; the verifier recognizes, evaluates and checks all of it.
pub trait SofiReads {
    /// Every seat's reads of `cell` (storage spec §9): what each seat holds,
    /// its committed state from a mirror, and each later seat's own mirror
    /// of the leader. The verifier evaluates the route chains.
    fn cell(&self, cell: &RoutedCell) -> Result<CellEvidence, ReadFailure>;
    /// `P` by `PrecommitId`: the one stored envelope under the id whose body
    /// re-derives it (R8).
    fn precommit(&self, id: &D32) -> Result<Resolved<Signed<TraderPrecommitBody>>, ReadFailure>;
    /// `F` by `FulfillmentId`.
    fn fulfillment(&self, id: &D32)
        -> Result<Resolved<Signed<TraderFulfillmentBody>>, ReadFailure>;
    /// The exact stored envelope bytes of the setup at `ρ`.
    fn setup_bytes(&self, setup_ref: &D32) -> Result<Resolved<Vec<u8>>, ReadFailure>;
    /// The exact bytes at a content address once `Stored` holds for them;
    /// `None` when they are not established.
    fn stored_bytes(&self, addr: &D32) -> Result<Option<Vec<u8>>, ReadFailure>;
    /// `TokenPolicyV3` bytes for `policy_commit`, rooted on the creator's
    /// chain. The verifier re-hashes them; `Err` when they are not in hand.
    fn token_policy_bytes(&self, policy_commit: &D32) -> Result<Vec<u8>, ReadFailure>;
    /// Every preimage published under vault `vault_id`'s genesis locator that
    /// recognizes to it, with its exact bytes, in append order.
    fn vault_genesis_candidates(
        &self,
        vault_id: &D32,
    ) -> Result<Discovered<(VaultGenesisPreimage, Vec<u8>)>, ReadFailure>;
    /// The vault named by every preimage published under token `t`'s vault
    /// token locator that decodes as a vault genesis preimage, in append
    /// order (Amendment S16). Candidates only: [`Verifier::vaults_of_token`]
    /// accepts each genesis and checks its market before it is a vault of
    /// `t`.
    fn vault_token_candidates(&self, token: &D32) -> Result<Discovered<D32>, ReadFailure>;
    /// The owner's transition at its creation position, validated by the
    /// peer lineage walk.
    fn vault_owner(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure>;
    /// This device's own record of vault `vault_id`'s leaves at the
    /// generation it established `root` at, for `keys` — a record that
    /// reproduces `root`, or `None`.
    fn vault_leaves_at(
        &self,
        vault_id: &D32,
        root: &D32,
        keys: &BTreeSet<D32>,
    ) -> Result<Option<VaultLeaves>, ReadFailure>;
    /// The root trader `(genesis, device_id)`'s lineage selected AT
    /// `position`, and the reference a later `P` names it by, by
    /// frontier-relative verification of that lineage (DSM Amendment A8;
    /// SoFi Amendment S15): a conditional position resolved from SoFi's
    /// public objects. What a walk resolves another trader's conditional
    /// parent with.
    fn trader_root_at(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<(ValidatedEconomicRoot, ParentClaimRef), PeerLineageFailure>;
    /// The claim lineage validation accepted at `position` of trader
    /// `(genesis, device_id)`: from this device's own admitted store when the
    /// trader is this device, and from the peer lineage walk otherwise —
    /// never this device's claim under another trader's name. A failure
    /// keeps the class lineage validation gave it; Core reads which classes
    /// are verdicts (`validation::setup_lineage`, SoFi Amendment S13).
    fn accepted_claim_at(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<AcceptedClaim, PeerLineageFailure>;
    /// The generations this device recorded for `vault_id`, contiguous from
    /// zero, in generation order.
    fn recorded_generations(
        &self,
        vault_id: &D32,
    ) -> Result<Vec<RecordedGenerationRow>, ReadFailure>;
    /// Record a generation the walk established.
    fn record_generation(&self, post: &VaultPostState) -> Result<(), ReadFailure>;
    /// Keep the completion proof of the value final at `cell` (storage spec
    /// §9 rule 11), with the reads `evidence` that showed it final. A final
    /// value holds the cell for good, so those reads answer for the cell
    /// again for as long as the reads are kept; nothing else read at a cell
    /// does.
    fn keep_completion(
        &self,
        cell: &RoutedCell,
        evidence: &CellEvidence,
        proof: &CompletionProof,
    ) -> Result<(), ReadFailure>;
}

/// This device's own `R_econ` leaves, checked against the root they claim to
/// form. Built from the device's leaf cache for its validated root, or by a
/// test from leaves it holds — never from a root somebody sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLeaves {
    genesis: D32,
    device_id: D32,
    root: D32,
    leaves: BTreeMap<D32, EconomicLeafState>,
}

impl LocalLeaves {
    /// Leaves of `(genesis, device_id)` that must recompute `root`; anything
    /// else is refused.
    pub fn checked(
        genesis: D32,
        device_id: D32,
        root: D32,
        leaves: impl IntoIterator<Item = (D32, EconomicLeafState)>,
    ) -> Result<Self, LeavesDoNotRecomputeTheRoot> {
        let mut tree = EconomicSmt::new();
        let mut map = BTreeMap::new();
        for (key, state) in leaves {
            let value = state
                .leaf_value()
                .map_err(|e| LeavesDoNotRecomputeTheRoot(format!("encode leaf state: {e}")))?;
            tree.insert(key, value);
            map.insert(key, state);
        }
        if tree.root() != root {
            return Err(LeavesDoNotRecomputeTheRoot(
                "local leaves do not recompute the validated root — discarded".to_string(),
            ));
        }
        Ok(Self {
            genesis,
            device_id,
            root,
            leaves: map,
        })
    }

    pub fn root(&self) -> D32 {
        self.root
    }

    /// The `TraderPreBalance` of every balance `core` states as present
    /// before the operation (SoFi Amendment S12): the values the exercise
    /// carries, so that a verifier that is not this device can judge it. A
    /// key the core writes as a balance that holds any other leaf is refused.
    pub fn pre_balances(
        &self,
        core: &TraderCore,
    ) -> Result<Vec<TraderPreBalance>, LeavesDoNotRecomputeTheRoot> {
        let mut out = Vec::new();
        for entry in core.entries() {
            match entry {
                CoreEntry::Relationship { .. } => {}
                CoreEntry::Mutation { .. } | CoreEntry::Read { .. } => {
                    match self.leaves.get(&entry.key()) {
                        None => {}
                        Some(EconomicLeafState::Balance(b)) => out.push(
                            TraderPreBalance::new(
                                self.genesis,
                                self.device_id,
                                b.policy_commit,
                                b.amount,
                            )
                            .map_err(|e| {
                                LeavesDoNotRecomputeTheRoot(format!(
                                    "a balance before the trade: {e}"
                                ))
                            })?,
                        ),
                        Some(
                            EconomicLeafState::Relationship(..)
                            | EconomicLeafState::ConsumedSource(..)
                            | EconomicLeafState::VaultCreation(..)
                            | EconomicLeafState::TokenCreation(..),
                        ) => {
                            return Err(LeavesDoNotRecomputeTheRoot(
                                "a trader core writes a balance at a key holding another leaf"
                                    .to_string(),
                            ))
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Every vault this device created: the creation record its validated
    /// root commits for each one (P15-12), in key order.
    pub fn vault_creations(&self) -> Vec<super::wire::VaultCreation> {
        let mut out = Vec::new();
        for state in self.leaves.values() {
            if let EconomicLeafState::VaultCreation(creation) = state {
                out.push(*creation);
            }
        }
        out
    }

    /// The relationship leaf this device holds with `vault_id`, if any.
    pub fn relationship(&self, vault_id: &D32) -> Option<super::wire::TraderRelationshipLeaf> {
        let key = derive::relationship_key(&self.genesis, &self.device_id, vault_id);
        match self.leaves.get(&key) {
            Some(EconomicLeafState::Relationship(leaf)) => Some(*leaf),
            Some(..) | None => None,
        }
    }
}

/// Leaves that do not form the root they were said to form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeavesDoNotRecomputeTheRoot(pub String);

impl core::fmt::Display for LeavesDoNotRecomputeTheRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a discovery examined every candidate and established each one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanExtent {
    Whole,
    Short,
}

/// What this verifier established about vault `v`'s genesis (SoFi §19.8;
/// §30 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultGenesis {
    /// The owner's validated creation carried this genesis, and it is
    /// accepted.
    Accepted(Box<AcceptedVaultGenesis>),
    /// No preimage the owner's creation carried is published under the
    /// vault's locator.
    NotPublished,
    /// The owner's lineage reaches `p_create` through a position whose route
    /// has not resolved: nothing a fetch can supply decides it yet.
    OwnerUnresolved(String),
    /// The genesis is refused: the owner's lineage is invalid or quarantined,
    /// or the genesis the owner created fails acceptance.
    Refused(String),
}

/// What an acquisition produced: the complete evidence a Core predicate
/// consumes, or what is still not in hand. Predicates are Valid or Invalid
/// only; these are the separate acquisition statuses (Amendment S3, owner
/// 2026-09-23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acquired<T, M> {
    /// Everything the predicate consumes is in hand and authenticates.
    Complete(T),
    /// The retry budget is spent and these items are still not in hand: the
    /// operation fails on the network. The caller evaluates nothing and
    /// records nothing.
    Exhausted(Vec<M>),
}

/// The objects one exercise's conformance is decided over: the trader's
/// signed `P` and `F`, `P(E)`, and the exact bytes the trader holds for the
/// closure references only it can supply — the registered claim envelope a
/// `SingleRootClaim` names, the final claim bytes at `K_root(p)` a
/// `ConditionalClaim` names. Core re-derives every reference from the
/// bytes; nothing here is trusted.
#[derive(Debug, Clone, Copy)]
pub struct ExerciseObjects<'a> {
    pub precommit: &'a TraderPrecommitBody,
    pub precommit_signature: &'a [u8],
    pub preimage: &'a SettlementPreimage,
    pub fulfillment: &'a TraderFulfillmentBody,
    pub fulfillment_signature: &'a [u8],
    pub own_objects: &'a BTreeMap<ValidationRef, Vec<u8>>,
}

/// What the verifier brings: its reads, the network's pinned set, the
/// network, and the position it resolved itself. Every
/// field is an established fact of THIS verifier; none is trusted because
/// somebody sent it.
pub struct Verifier<'a, R: SofiReads + ?Sized> {
    pub reads: &'a R,
    /// The network's pinned set, as the local catalog resolves it: cells
    /// are routed over it, and `RoutedCell::new` refuses members that do
    /// not re-derive `set_id`.
    pub members: &'a StorageSetMembers,
    pub set_id: D32,
    pub network_id: &'a [u8],
    /// What this verifier itself resolved at a conditional position: what a
    /// `P` naming that fulfillment as its parent was built on. Core reads
    /// what it selected. Another trader's conditional parent is resolved by
    /// frontier-relative verification of that trader's lineage
    /// ([`SofiReads::trader_root_at`]); one neither resolves is not
    /// established.
    pub parent: Option<ResolvedParent>,
    /// The vault geneses this request's verifiers accepted. Each is read
    /// from the network the first time one of them needs it and stood on
    /// after: a quote or a trade reads a vault's genesis once, not once for
    /// each token's discovery, each chain and each head. Only an acceptance
    /// is kept; anything not established is read again.
    accepted: AcceptedGeneses,
}

/// Vault geneses one operation accepted from the network, keyed by the vault
/// and the address of the exact genesis bytes the acceptance bound to the
/// owner's creation: what the verifiers of one operation share
/// ([`Verifier::new`]). A verdict is reused only for those bytes.
pub type AcceptedGeneses =
    std::sync::Arc<std::sync::Mutex<BTreeMap<(D32, D32), AcceptedVaultGenesis>>>;

/// The evidence a genesis verdict is bound to: the immutable address of the
/// exact preimage bytes, which acceptance requires to equal the bytes the
/// owner's creation carried.
fn genesis_evidence(bytes: &[u8]) -> D32 {
    crate::storage_object::immutable_addr(
        crate::common::domain_tags::TAG_DSM_SOFI_VAULT_GENESIS_OBJECT,
        bytes,
    )
}

/// What this operation already accepted for `vault_id`, among the bytes the
/// locator scan just read: a verdict keyed by those exact bytes, or nothing.
fn remembered<'m, 'c, T>(
    memo: &'m BTreeMap<(D32, D32), T>,
    vault_id: &D32,
    candidates: impl IntoIterator<Item = &'c [u8]>,
) -> Option<&'m T> {
    candidates
        .into_iter()
        .find_map(|bytes| memo.get(&(*vault_id, genesis_evidence(bytes))))
}

impl<'a, R: SofiReads + ?Sized> Verifier<'a, R> {
    /// A verifier over `reads` and the pinned set, standing on the geneses
    /// `accepted` holds: ones this request's verifiers accepted from the
    /// network, or none.
    pub fn new(
        reads: &'a R,
        members: &'a StorageSetMembers,
        set_id: D32,
        network_id: &'a [u8],
        parent: Option<ResolvedParent>,
        accepted: AcceptedGeneses,
    ) -> Self {
        Self {
            reads,
            members,
            set_id,
            network_id,
            parent,
            accepted,
        }
    }
}

/// Where a walk over one parent's attempt chain ended, with the exercise
/// that consumed the parent when one did — its consumed route's `V°` post
/// root is the next parent (Section 30, step 3) — and, when it stopped
/// unresolved at a key it could not classify, why. Carries what it
/// classified, so that a walk resumed at its cursor ([`Verifier::continue_walk`])
/// still stands on every earlier key.
#[derive(Debug)]
pub struct Walked {
    pub outcome: WalkOutcome,
    /// The walk as [`walk`] made it: what a leg's liveness is read from.
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
    /// Dead on the facts that need no validation evidence (MR-SOFI-0241):
    /// none of its validation evidence was acquired.
    Ground(Box<GroundFacts>),
    /// The complete facts established over the reads.
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
            Known::Ground(ground) => KeyFacts::ground(&self.read, ground),
            Known::RefutedInHand(refutation) => KeyFacts::refuted(&self.read, refutation),
        }
    }
}

/// What [`Verifier::read_legs`] read about one exercise before any of its
/// validation evidence: its position's registration, and one cell and one
/// walk per leg of `P`, in P's leg order.
struct LegsRead {
    registration: RegistrationRead,
    cells: Vec<AttemptCellRead>,
    walks: Vec<Option<AttemptWalk>>,
}

impl LegsRead {
    /// The reads of each leg of `precommit`, with its vault's chain.
    fn legs<'a>(
        &'a self,
        precommit: &TraderPrecommitBody,
        chains: &'a BTreeMap<D32, VaultChain>,
    ) -> Vec<LegReads<'a>> {
        precommit
            .legs()
            .iter()
            .zip(self.cells.iter().zip(self.walks.iter()))
            .map(|(leg, (cell, walk))| LegReads {
                cell,
                chain: chains.get(&leg.vault_id),
                walk: walk.as_ref(),
            })
            .collect()
    }
}

/// The key an exercise was found at while walking a chain: its read, and the
/// walk over the keys before it, which reached it by skipping every one.
#[derive(Clone, Copy)]
struct WalkedKey<'a> {
    read: &'a AttemptCellRead,
    reached: &'a AttemptWalk,
}

fn short_id(id: &D32) -> String {
    crate::utils::text_id::encode_base32_crockford(id)
}

impl<R: SofiReads + ?Sized> Verifier<'_, R> {
    // ── cells ───────────────────────────────────────────────────────────

    /// `K^(attempt)` of `vault_id` at `parent_root`, routed over the set.
    pub fn attempt_cell(
        &self,
        vault_id: &D32,
        parent_root: &D32,
        attempt: u64,
    ) -> Result<AttemptCell, VerifierFailure> {
        AttemptCell::new(vault_id, parent_root, attempt, self.members, &self.set_id)
            .map_err(|e| VerifierFailure::Refused(format!("attempt cell: {e:?}")))
    }

    /// The two cells of trader `(genesis, device_id)`'s position `position`,
    /// routed by `s(q)` from `parent_root` over the set.
    pub fn position_cells(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
        parent_root: &D32,
    ) -> Result<PositionCells, VerifierFailure> {
        PositionCells::new(
            genesis,
            device_id,
            position,
            parent_root,
            self.members,
            &self.set_id,
        )
        .map_err(|e| VerifierFailure::Refused(format!("position cells: {e:?}")))
    }

    // ── reads ───────────────────────────────────────────────────────────

    /// `SuccessorResolution(K^(attempt))` of `vault_id` at `parent_root`, as
    /// the ladder reads it (Section 23.1): the cell's route chains evaluated
    /// from every seat's reads into a read bound to the key. An exercise
    /// final at the cell has its completion proof kept (storage spec §9 rule
    /// 11). Reads that do not decide the cell yet — its leader unread, or its
    /// leader link not yet committed — are the inner `Err`: a network status
    /// for the caller to retry, never an open cell.
    pub fn read_attempt_cell(
        &self,
        vault_id: &D32,
        parent_root: &D32,
        attempt: u64,
    ) -> Result<Result<AttemptCellRead, CellMissing>, VerifierFailure> {
        let cell = self.attempt_cell(vault_id, parent_root, attempt)?;
        let evidence = self.reads.cell(cell.routed())?;
        let read = match attempt_resolution(&cell, &evidence) {
            Ok(read) => read,
            Err(missing) => return Ok(Err(missing)),
        };
        if let CellFact::Held {
            state: ChainState::Final,
            ..
        } = read.fact()
        {
            let (.., proof) = attempt_completion(&cell, &evidence)
                .map_err(|missing| {
                    VerifierFailure::Read(format!("attempt completion: {missing:?}"))
                })?
                .ok_or_else(|| {
                    VerifierFailure::Read(
                        "attempt completion: a final exercise has no completion proof".to_string(),
                    )
                })?;
            self.reads
                .keep_completion(cell.routed(), &evidence, &proof)?;
        }
        Ok(Ok(read))
    }

    /// `FulfillmentRegistered` at position `position` of trader `(genesis,
    /// device_id)`, derived from the route-chain reads of the two cells
    /// (Part II §13, rebuild step R10). `parent_root` is `R_p`, the root the
    /// verifier validated itself, from which `s(q)` and the route follow.
    /// Once registered, the completion proofs of both cells are kept (SoFi
    /// Amendment S10).
    ///
    /// Both cells are decided from their bytes alone (SoFi Amendment S20):
    /// no precommit is read, so nothing a fulfillment names can make this
    /// read wait, and the answer is the same at every time. The inner `Err` is
    /// what the reads do not yet show.
    pub fn read_registration(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
        parent_root: &D32,
    ) -> Result<Result<RegistrationRead, CellMissing>, VerifierFailure> {
        let cells = self.position_cells(genesis, device_id, position, parent_root)?;
        let ful_evidence = self.reads.cell(cells.fulfillment())?;
        let root_evidence = self.reads.cell(cells.root().routed())?;
        let registration = match fulfillment_registered(&cells, &ful_evidence, &root_evidence) {
            Ok(registration) => registration,
            Err(missing) => return Ok(Err(missing)),
        };
        if let Registration::Registered(..) = registration.registration() {
            let (.., ful_proof) = fulfillment_completion(&cells, &ful_evidence)
                .map_err(|missing| {
                    VerifierFailure::Read(format!("fulfillment completion: {missing:?}"))
                })?
                .ok_or_else(|| {
                    VerifierFailure::Read(
                        "fulfillment completion: a final value has no proof".to_string(),
                    )
                })?;
            self.reads
                .keep_completion(cells.fulfillment(), &ful_evidence, &ful_proof)?;
            let (.., root_proof) = root_completion(cells.root(), &root_evidence)
                .map_err(|missing| {
                    VerifierFailure::Read(format!("root claim completion: {missing:?}"))
                })?
                .ok_or_else(|| {
                    VerifierFailure::Read(
                        "root claim completion: a final value has no proof".to_string(),
                    )
                })?;
            self.reads
                .keep_completion(cells.root().routed(), &root_evidence, &root_proof)?;
        }
        Ok(Ok(registration))
    }

    /// The cell an attempt above zero skips past, read from the committed
    /// set: for every leg the fulfillment names at attempt `a > 0`, the
    /// storage fact at `K^(a-1)` of that leg's vault at its parent root.
    ///
    /// ONE PATH, SHARED (owner ruling, §44.4). The producer's install (R9)
    /// and the verifier's resolution (R12) read the same cell the same way,
    /// because they answer the same question: conformance item 5 requires
    /// the key before this one to have a permanent storage resolution
    /// (§20.2), and that key alone, however many keys come before it. A key
    /// whose reads do not decide it yet is absent from the map, and
    /// conformance names it missing. An attempt of zero has no earlier key
    /// and contributes no entry.
    pub fn acquire_prior_attempts(
        &self,
        precommit: &TraderPrecommitBody,
        fulfillment: &TraderFulfillmentBody,
    ) -> Result<BTreeMap<(D32, u64), CellFact>, VerifierFailure> {
        let mut cells = BTreeMap::new();
        for entry in fulfillment.attempts() {
            // F naming a leg P does not is conformance item 4's refusal;
            // there is no parent root to read a cell at.
            let Some(leg) = precommit
                .legs()
                .iter()
                .find(|l| l.vault_id == entry.vault_id)
            else {
                continue;
            };
            let Some(earlier) = entry.attempt.checked_sub(1) else {
                continue;
            };
            match self.read_attempt_cell(&leg.vault_id, &leg.parent_root, earlier)? {
                Ok(read) => {
                    cells.insert((entry.vault_id, earlier), read.fact());
                }
                Err(undecided) => {
                    log::info!("[sofi verifier] K^({earlier}) is not decided yet: {undecided:?}")
                }
            }
        }
        Ok(cells)
    }

    /// One round of reading what `FulfillmentConformance(F)` reads: `P` and
    /// `P(E)` from the objects, every leg's setup under its `ρ` (R8), the
    /// closure objects by the rule of each reference kind, and item 5's
    /// earlier attempt cells.
    fn gather_conformance(
        &self,
        objects: &ExerciseObjects<'_>,
    ) -> Result<ConformanceEvidence, VerifierFailure> {
        let mut setups = BTreeMap::new();
        for leg in objects.precommit.legs() {
            if let Resolved::Kept(bytes) = self.reads.setup_bytes(&leg.setup_ref)? {
                setups.insert(leg.setup_ref, bytes);
            }
        }
        let mut closure = BTreeMap::new();
        for reference in objects.preimage.settlement().closure().refs() {
            let bytes = match reference {
                ValidationRef::ContentAddr { addr, .. } => match objects.own_objects.get(reference)
                {
                    Some(bytes) => Some(bytes.clone()),
                    None => self.reads.stored_bytes(addr)?,
                },
                ValidationRef::Setup { setup_ref } => match self.reads.setup_bytes(setup_ref)? {
                    Resolved::Kept(bytes) => Some(bytes),
                    Resolved::None | Resolved::Unavailable => None,
                },
                ValidationRef::SingleRootClaim { .. } | ValidationRef::ConditionalClaim { .. } => {
                    objects.own_objects.get(reference).cloned()
                }
            };
            if let Some(bytes) = bytes {
                closure.insert(*reference, bytes);
            }
        }
        // Item 1 for a conditional parent: the F whose id P names, by that
        // id. Its id is the hash of its body, so the kept bytes are that F.
        let parent_fulfillment = match objects.precommit.parent_claim_ref() {
            ParentClaimRef::Conditional { fulfillment_id } => {
                match self.reads.fulfillment(fulfillment_id)? {
                    Resolved::Kept(signed) => Some(signed.body),
                    Resolved::None | Resolved::Unavailable => None,
                }
            }
            ParentClaimRef::SingleRoot { .. } => None,
        };
        Ok(ConformanceEvidence {
            precommit: Signed {
                body: objects.precommit.clone(),
                signature: objects.precommit_signature.to_vec(),
            },
            preimage: objects.preimage.clone(),
            closure,
            setups,
            prior_attempts: self.acquire_prior_attempts(objects.precommit, objects.fulfillment)?,
            parent_fulfillment,
        })
    }

    /// Acquire what `FulfillmentConformance(F)` reads, and ask the predicate
    /// whether it is complete: `Complete` once conformance reaches a verdict
    /// over it, `Exhausted` naming what is still missing after the retry
    /// budget (Amendment S3).
    pub fn acquire_conformance_evidence(
        &self,
        objects: &ExerciseObjects<'_>,
    ) -> Result<Acquired<ConformanceEvidence, ConformanceMissing>, VerifierFailure> {
        let mut missing = Vec::new();
        for round in 1..=ACQUIRE_ROUNDS {
            let evidence = self.gather_conformance(objects)?;
            match fulfillment_conformance(
                objects.fulfillment,
                objects.fulfillment_signature,
                &evidence,
            ) {
                Ok(FulfillmentConformance::Valid | FulfillmentConformance::Invalid(..)) => {
                    return Ok(Acquired::Complete(evidence))
                }
                Err(what) => {
                    log::info!(
                        "[sofi verifier] conformance round {round}/{ACQUIRE_ROUNDS}: not in hand: {what:?}"
                    );
                    missing = vec![what];
                }
            }
        }
        Ok(Acquired::Exhausted(missing))
    }

    /// Acquire everything `P` and `P(E)` need, from storage and the objects
    /// the operation carries, and ask the predicate whether it is complete.
    /// `Complete` once `route_validation` reaches a verdict over it;
    /// `Exhausted` naming what is still missing after [`ACQUIRE_ROUNDS`]
    /// rounds. Any verifier judges any trader's route the same way: the
    /// trader's balances before the trade come from the `TraderPreBalance`
    /// objects `𝒞_E^pre` names (SoFi Amendment S12), and `carried` are the
    /// closure objects the exercise, or the producer's own draft, holds.
    pub fn acquire_evidence(
        &self,
        precommit: &TraderPrecommitBody,
        preimage: &SettlementPreimage,
        carried: &BTreeMap<ValidationRef, Vec<u8>>,
    ) -> Result<Acquired<Evidence, Missing>, VerifierFailure> {
        let needs = EvidenceNeeds::of(precommit, preimage);
        let mut missing = Vec::new();
        for round in 1..=ACQUIRE_ROUNDS {
            let evidence = self.gather(precommit, preimage, &needs, carried)?;
            match route_validation(precommit, preimage, &evidence) {
                Ok(Validation::Valid | Validation::Invalid) => {
                    return Ok(Acquired::Complete(evidence))
                }
                Err(what) => {
                    log::info!(
                        "[sofi verifier] evidence round {round}/{ACQUIRE_ROUNDS}: not in hand: {what:?}"
                    );
                    missing = vec![what];
                }
            }
        }
        Ok(Acquired::Exhausted(missing))
    }

    /// One round of reading every item `needs` names: the trader's
    /// `TraderPreBalance` objects from what the operation carries or the
    /// immutable store, vault leaf pre values from the vault's accepted
    /// genesis at `R_0` or the generation this device established at the
    /// root the core names, policy objects from the immutable store under the
    /// addresses the vault state commits, token policies rooted by this
    /// device, setups at each `ρ`, and the claims the trader's lineage
    /// accepted at each setup's position.
    fn gather(
        &self,
        precommit: &TraderPrecommitBody,
        preimage: &SettlementPreimage,
        needs: &EvidenceNeeds,
        carried: &BTreeMap<ValidationRef, Vec<u8>>,
    ) -> Result<Evidence, VerifierFailure> {
        let mut objects: BTreeMap<D32, Vec<u8>> = BTreeMap::new();
        for addr in &needs.trader_pre_balances {
            let reference = ValidationRef::ContentAddr {
                object_class: crate::ccb::class::SOFI_TRADER_PRE_BALANCE,
                addr: *addr,
            };
            let bytes = match carried.get(&reference) {
                Some(bytes) => Some(bytes.clone()),
                None => self.reads.stored_bytes(addr)?,
            };
            if let Some(bytes) = bytes {
                objects.insert(*addr, bytes);
            }
        }

        let mut vault_leaves: VaultLeaves = BTreeMap::new();
        let mut token_policies: BTreeMap<D32, Vec<u8>> = BTreeMap::new();
        for (vault_id, keys) in &needs.vaults {
            let Some(state) = self.vault_pre(preimage, vault_id, keys, &mut vault_leaves)? else {
                continue;
            };
            for (class, addr) in EvidenceNeeds::policies_of(&state) {
                let Some(bytes) = self.reads.stored_bytes(&addr)? else {
                    continue;
                };
                // The tokens a market names are what the transferable check
                // reads. Bytes that are not a market name none, and the
                // predicate refuses them.
                if class == crate::ccb::class::MARKET_POLICY {
                    if let Ok(market) = crate::ccb::decode::decode_market_policy(&bytes) {
                        for commit in EvidenceNeeds::token_policies_of(&market) {
                            if crate::core::token::builtin_token_id_for_policy_commit(&commit)
                                .is_some()
                            {
                                continue;
                            }
                            match self.reads.token_policy_bytes(&commit) {
                                Ok(policy) => {
                                    token_policies.insert(commit, policy);
                                }
                                Err(failure) => {
                                    log::info!(
                                        "[sofi verifier] token policy not in hand: {failure}"
                                    )
                                }
                            }
                        }
                    }
                }
                objects.insert(addr, bytes);
            }
        }

        let mut setups: BTreeMap<D32, Vec<u8>> = BTreeMap::new();
        let mut setup_lineages: BTreeMap<u64, SetupLineage> = BTreeMap::new();
        for setup_ref in &needs.setups {
            let Resolved::Kept(bytes) = self.reads.setup_bytes(setup_ref)? else {
                continue;
            };
            if let Some((.., signed)) = recognize_setup(&bytes) {
                let position = signed.body.position();
                let validated = self.reads.accepted_claim_at(
                    precommit.genesis(),
                    precommit.device_id(),
                    position,
                );
                setup_lineages.insert(
                    position,
                    setup_lineage(
                        *precommit.genesis(),
                        *precommit.device_id(),
                        position,
                        validated,
                    ),
                );
            }
            setups.insert(*setup_ref, bytes);
        }

        Ok(Evidence::acquired(
            objects,
            vault_leaves,
            setups,
            token_policies,
            setup_lineages,
        ))
    }

    /// The pre values of vault `v`'s leaves at the root the operation's core
    /// names, into `vault_leaves`, and the vault state they hold. At `R_0`
    /// they are the accepted genesis; past it, the generation this device
    /// established at the root the core was built on, which must reproduce
    /// that root. `None` when they are not in hand.
    fn vault_pre(
        &self,
        preimage: &SettlementPreimage,
        vault_id: &D32,
        keys: &BTreeSet<D32>,
        vault_leaves: &mut VaultLeaves,
    ) -> Result<Option<VaultStateLeaf>, VerifierFailure> {
        let Some(pre_root) = preimage
            .dlv_cores()
            .iter()
            .find(|core| core.vault_id() == vault_id)
            .map(|core| *core.pre_root())
        else {
            return Ok(None);
        };
        let genesis = match self.vault_genesis(vault_id)? {
            VaultGenesis::Accepted(genesis) => genesis,
            VaultGenesis::NotPublished | VaultGenesis::OwnerUnresolved(..) => return Ok(None),
            VaultGenesis::Refused(why) => {
                return Err(VerifierFailure::Refused(format!(
                    "vault {} genesis refused: {why}",
                    short_id(vault_id)
                )))
            }
        };
        if genesis_root(vault_id, genesis.state()).ok() == Some(pre_root) {
            vault_leaves.extend(vault_leaves_at_genesis(vault_id, genesis.state(), keys));
            return Ok(Some(genesis.state().clone()));
        }
        let Some(leaves) = self.reads.vault_leaves_at(vault_id, &pre_root, keys)? else {
            return Ok(None);
        };
        let state_key = derive::vault_state_key(vault_id);
        let Some(VaultLeafPre::State(state)) = leaves.get(&(*vault_id, state_key)).cloned() else {
            return Ok(None);
        };
        vault_leaves.extend(leaves);
        Ok(Some(state))
    }

    /// Vault `v`'s genesis as this verifier accepts it: every preimage
    /// published under `vault_genesis_locator(v)` that recognizes to `v`,
    /// bound to the owner's creation as a walk of the owner's lineage
    /// validates it.
    ///
    /// Every candidate is tried, so a preimage appended first by anyone else
    /// cannot stand in front of the owner's: only the bytes the owner's
    /// creation carried are accepted. Every candidate names the same owner
    /// and `p_create`, because `v` derives from them.
    pub fn vault_genesis(&self, vault_id: &D32) -> Result<VaultGenesis, VerifierFailure> {
        let memo = || {
            self.accepted.lock().map_err(|e| {
                VerifierFailure::Read(format!("vault genesis: the accepted geneses: {e}"))
            })
        };
        // A candidate the scan could not establish may be the owner's
        // genesis, so only a complete scan says it is not published
        // (storage §4). The scan is read every time; what this operation
        // reuses is only the walk that bound those exact bytes to the
        // owner's creation.
        let (candidates, complete) = match self.reads.vault_genesis_candidates(vault_id)? {
            Discovered::Complete(candidates) => (candidates, true),
            Discovered::Partial(candidates) => (candidates, false),
        };
        let scanned = candidates.iter().map(|(.., bytes)| bytes.as_slice());
        if let Some(accepted) = remembered(&*memo()?, vault_id, scanned) {
            return Ok(VaultGenesis::Accepted(Box::new(accepted.clone())));
        }
        let not_published = || {
            if complete {
                Ok(VaultGenesis::NotPublished)
            } else {
                Err(VerifierFailure::Read(
                    "vault genesis: the locator scan did not establish every candidate".to_string(),
                ))
            }
        };
        let Some((first, ..)) = candidates.first() else {
            return not_published();
        };
        let owner = match self.reads.vault_owner(
            &first.owner_genesis,
            &first.owner_device_id,
            first.create_position,
        ) {
            Ok(owner) => owner,
            Err(PeerLineageFailure::Incomplete(why)) => {
                return Err(VerifierFailure::Read(format!("vault owner lineage: {why}")))
            }
            Err(PeerLineageFailure::Unresolved(why)) => {
                return Ok(VaultGenesis::OwnerUnresolved(why))
            }
            Err(PeerLineageFailure::Invalid(why) | PeerLineageFailure::Quarantined(why)) => {
                return Ok(VaultGenesis::Refused(format!("the owner's lineage: {why}")))
            }
        };
        let mut refused = None;
        for (.., bytes) in &candidates {
            match self.accept_with_policies(bytes, &owner)? {
                Ok(accepted) => {
                    memo()?.insert((*vault_id, genesis_evidence(bytes)), accepted.clone());
                    return Ok(VaultGenesis::Accepted(Box::new(accepted)));
                }
                Err(GenesisInvalid::NotTheCreationTheOwnerMade) => {}
                Err(why) => refused = Some(why),
            }
        }
        match refused {
            Some(why) => Ok(VaultGenesis::Refused(format!("{why:?}"))),
            None => not_published(),
        }
    }

    /// Amendment S16: the vaults whose market pairs `token`, found under its
    /// vault token locator, in the order the index names them.
    ///
    /// Discovery carries no authority. A candidate is kept only when its
    /// genesis is accepted — bound to the owner's validated creation by
    /// [`Self::vault_genesis`] — and the market that acceptance resolves
    /// pairs `token`; anything else appended under the locator is passed
    /// over. A candidate whose genesis or owner's lineage the reads do not
    /// establish yet, or a scan that stopped short, makes the discovery
    /// `Partial`: the vaults it kept are vaults of `token` all the same.
    pub fn vaults_of_token(
        &self,
        token: &D32,
    ) -> Result<Discovered<AcceptedVaultGenesis>, VerifierFailure> {
        let (candidates, mut scan) = match self.reads.vault_token_candidates(token) {
            Ok(Discovered::Complete(candidates)) => (candidates, ScanExtent::Whole),
            Ok(Discovered::Partial(candidates)) => (candidates, ScanExtent::Short),
            // The index read was not made: nothing established, and nothing
            // refuted (storage §4).
            Err(ReadFailure(..)) => (Vec::new(), ScanExtent::Short),
        };
        let mut examined = BTreeSet::new();
        let mut vaults = Vec::new();
        for vault_id in candidates {
            if !examined.insert(vault_id) {
                continue;
            }
            match self.vault_genesis(&vault_id) {
                Ok(VaultGenesis::Accepted(accepted)) => {
                    let market = accepted.market();
                    if market.token_a() == token || market.token_b() == token {
                        vaults.push(*accepted);
                    }
                }
                // Not a vault anyone created, or a genesis refused: not a
                // vault of `token`.
                Ok(VaultGenesis::NotPublished | VaultGenesis::Refused(_))
                | Err(VerifierFailure::Refused(_)) => {}
                // Not established yet: it may be a vault of `token`.
                Ok(VaultGenesis::OwnerUnresolved(_)) | Err(VerifierFailure::Read(_)) => {
                    scan = ScanExtent::Short
                }
            }
        }
        Ok(match scan {
            ScanExtent::Whole => Discovered::Complete(vaults),
            ScanExtent::Short => Discovered::Partial(vaults),
        })
    }

    /// `GenesisAccepted` over one candidate, reading the token policies the
    /// predicate names as missing. It consults at most the two tokens of the
    /// market, and a policy it names again after it was supplied is not the
    /// committed one.
    fn accept_with_policies(
        &self,
        bytes: &[u8],
        owner: &ValidatedPeerTransition,
    ) -> Result<Result<AcceptedVaultGenesis, GenesisInvalid>, VerifierFailure> {
        let mut policies = BTreeMap::new();
        loop {
            match genesis_accepted(self.network_id, bytes, owner, &policies) {
                Ok(accepted) => return Ok(Ok(accepted)),
                Err(GenesisRefusal::Invalid(why)) => return Ok(Err(why)),
                Err(GenesisRefusal::Missing(GenesisMissing::TokenPolicy { commit })) => {
                    if policies.contains_key(&commit) {
                        return Err(VerifierFailure::Refused(
                            "vault token policy: the rooted bytes are not the committed policy"
                                .to_string(),
                        ));
                    }
                    let policy = self.reads.token_policy_bytes(&commit).map_err(|failure| {
                        VerifierFailure::Read(format!("vault token policy: {failure}"))
                    })?;
                    policies.insert(commit, policy);
                }
            }
        }
    }

    // ── the chain (§30, R14) ─────────────────────────────────────────────

    /// The canonical chain of `vault_id`, extended as far as the committed
    /// set and the budget allow, recording each generation it establishes.
    ///
    /// The chain starts where every chain starts, at the accepted genesis
    /// (§30 step 1), read from the network by this verifier: the generations this
    /// device recorded before are its own memo, anchored at that genesis and
    /// linked one to the next ([`VaultChain::from_recorded`]) before they
    /// are stood on. Past the memo the chain grows by one consumption at a
    /// time — the exercise the walk classifies `Consumed` at the head, and
    /// the post state `vault_post_states` recomputes from it.
    pub fn chain(&self, vault_id: &D32) -> Result<VaultChain, VerifierFailure> {
        self.chain_to_depth(*vault_id, SIBLING_DEPTH, None)
    }

    /// `vault_id`'s canonical chain, extended only until it names `root`:
    /// what resolving a position whose leg was built on `root` needs, and no
    /// further. A position's facts never depend on the generations after the
    /// parent its leg names, and walking past them could meet an exercise
    /// whose own parent is the position being resolved.
    pub fn chain_until(&self, vault_id: &D32, root: &D32) -> Result<VaultChain, VerifierFailure> {
        self.chain_to_depth(*vault_id, SIBLING_DEPTH, Some(root))
    }

    fn chain_to_depth(
        &self,
        vault_id: D32,
        depth: usize,
        until: Option<&D32>,
    ) -> Result<VaultChain, VerifierFailure> {
        let genesis = match self.vault_genesis(&vault_id)? {
            VaultGenesis::Accepted(genesis) => *genesis,
            // Not established yet. The chain is empty, and an empty chain
            // refutes nothing.
            VaultGenesis::NotPublished | VaultGenesis::OwnerUnresolved(..) => {
                return Ok(VaultChain::default())
            }
            VaultGenesis::Refused(why) => {
                return Err(VerifierFailure::Refused(format!(
                    "chain: vault {} genesis refused: {why}",
                    short_id(&vault_id)
                )))
            }
        };
        let recorded: Vec<RecordedGeneration> = self
            .reads
            .recorded_generations(&vault_id)?
            .into_iter()
            .map(|row| RecordedGeneration {
                generation: row.generation,
                root: row.root,
                pre_root: row.pre_root,
                consumed_by: row.consumed_by,
            })
            .collect();
        let mut chain = VaultChain::from_recorded(&genesis, &recorded).map_err(|e| {
            VerifierFailure::Refused(format!(
                "chain: this device's record of vault {}: {e}",
                short_id(&vault_id)
            ))
        })?;
        // What the resolver is told while this chain is being extended:
        // this vault's chain SO FAR, plus any sibling chain a multi-leg
        // consumption forced us to establish. The chain so far is not an
        // assumption — it is the induction, from a genesis nobody
        // resolved through one realized consumption per step.
        let mut chains: BTreeMap<D32, VaultChain> = BTreeMap::new();
        chains.insert(vault_id, chain.clone());
        let mut extended = 0;
        while extended < GENERATION_BUDGET {
            if until.is_some_and(|root| chain.names(root)) {
                break;
            }
            extended += 1;
            // The chain is non-empty here, but say so in the type rather
            // than in a panic: an empty chain means nothing was
            // established, which is a stop, never a crash.
            let Some((.., current)) = chain.head() else {
                break;
            };
            let Some(post) = self.next_generation(&vault_id, &current, &mut chains, depth)? else {
                break;
            };
            self.reads.record_generation(&post)?;
            log::info!(
                "[sofi verifier] vault {}: generation {} established",
                short_id(&vault_id),
                post.generation()
            );
            chain.extend(&post).map_err(|e| {
                VerifierFailure::Refused(format!(
                    "chain: the consumption does not extend the chain: {e}"
                ))
            })?;
            chains.insert(vault_id, chain.clone());
        }
        Ok(chain)
    }

    /// The post state of the exercise that consumed `current`, or `None` when
    /// nothing has consumed it yet, nothing could be read, or the consumption
    /// cannot be recomputed. Every `None` stops the chain WITHOUT refuting
    /// anything.
    fn next_generation(
        &self,
        vault_id: &D32,
        current: &D32,
        chains: &mut BTreeMap<D32, VaultChain>,
        depth: usize,
    ) -> Result<Option<VaultPostState>, VerifierFailure> {
        // Two passes at most. The first can stall because a SIBLING leg's
        // parent is not established yet, which is not a fact about this
        // vault; the second runs once those chains have been walked.
        for pass in 0..2 {
            let mut walked = self.walk_chain(
                &*chains,
                *vault_id,
                *current,
                0,
                WALK_BUDGET,
                CHAIN_DEPTH,
                BTreeMap::new(),
            )?;
            // The budget chunks the walk and never ends it (§23.6): however
            // many keys junk holds, the walk resumes past them.
            while let WalkOutcome::Continue { .. } = walked.outcome {
                walked = self.continue_walk(&*chains, walked, WALK_BUDGET)?;
            }
            match walked.outcome {
                WalkOutcome::Consumed { .. } => {
                    let Some(exercise) = walked.consumed else {
                        return Ok(None);
                    };
                    return self.post_state_of(vault_id, current, &exercise);
                }
                WalkOutcome::Unresolved { attempt } if pass == 0 && depth > 0 => {
                    if !self.establish_siblings(vault_id, current, attempt, chains, depth)? {
                        return Ok(None);
                    }
                }
                WalkOutcome::Unresolved { .. }
                | WalkOutcome::CounterExhausted { .. }
                | WalkOutcome::Continue { .. } => {
                    if let Some(why) = walked.not_established {
                        log::info!("[sofi chain] the walk stopped short: {why:?}");
                    }
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    /// Recompute what `exercise` did to this vault. The post root is the
    /// fold's, over the pre state the evidence holds — never the value the
    /// producer wrote into `V°`, which is what `vault_post_states` checks.
    fn post_state_of(
        &self,
        vault_id: &D32,
        current: &D32,
        exercise: &RecognizedExercise,
    ) -> Result<Option<VaultPostState>, VerifierFailure> {
        let precommit = &exercise.precommit().body;
        let evidence = match self.acquire_evidence(
            precommit,
            exercise.preimage(),
            &exercise.closure_objects(),
        )? {
            Acquired::Complete(evidence) => evidence,
            Acquired::Exhausted(missing) => {
                log::info!("[sofi chain] a consumption's evidence is not in hand: {missing:?}");
                return Ok(None);
            }
        };
        // The evidence this verifier holds may not let it recompute the
        // consumption. The chain then stops; nothing is refuted.
        match vault_post_states(precommit, exercise.preimage(), &evidence) {
            Ok(posts) => Ok(posts
                .into_iter()
                .find(|p| p.vault_id() == vault_id && p.pre_root() == current)),
            Err(refusal) => {
                log::info!("[sofi chain] the consumption is not recomputable: {refusal:?}");
                Ok(None)
            }
        }
    }

    /// Establish the parents of the OTHER legs of whatever sits at this key,
    /// so a multi-leg consumption can be classified. Returns whether anything
    /// new was established — if nothing was, retrying the walk would read the
    /// same cells and reach the same answer.
    fn establish_siblings(
        &self,
        vault_id: &D32,
        current: &D32,
        attempt: u64,
        chains: &mut BTreeMap<D32, VaultChain>,
        depth: usize,
    ) -> Result<bool, VerifierFailure> {
        let exercise = match self.read_attempt_cell(vault_id, current, attempt)? {
            Ok(read) => read.into_exercise(),
            Err(missing) => {
                log::info!("[sofi chain] attempt {attempt} is not decided yet: {missing:?}");
                None
            }
        };
        let Some(exercise) = exercise else {
            return Ok(false);
        };
        let mut learned = false;
        for leg in exercise.precommit().body.legs() {
            if leg.vault_id == *vault_id || chains.contains_key(&leg.vault_id) {
                continue;
            }
            // POSITIVE evidence only for the RETRY decision: a sibling chain
            // that names the parent is new information and the walk is worth
            // repeating; one that does not name it changes no answer, so
            // repeating would read the same cells and stall the same way.
            // The chain is handed over either way — the resolver, not this
            // loop, decides what it means.
            let sibling = self.chain_to_depth(leg.vault_id, depth - 1, None)?;
            learned |= sibling.names(&leg.parent_root);
            chains.insert(leg.vault_id, sibling);
        }
        Ok(learned)
    }

    // ── resolution (§31 stage 9, R12) ────────────────────────────────────

    /// Section 30, step 2: walk the attempt keys of `vault_id` at
    /// `parent_root` from `cursor`, reading each cell, establishing what is
    /// known about the exercise it holds and classifying it. A skipped key
    /// moves on, a consumed key stops with its exercise, anything else is
    /// unresolved; a spent budget hands back a cursor. `chains` is what this
    /// verifier established for the vaults the walked exercises name.
    pub fn walk_parent(
        &self,
        chains: &BTreeMap<D32, VaultChain>,
        vault_id: &D32,
        parent_root: &D32,
        cursor: u64,
        budget: usize,
    ) -> Result<Walked, VerifierFailure> {
        self.walk_chain(
            chains,
            *vault_id,
            *parent_root,
            cursor,
            budget,
            CHAIN_DEPTH,
            BTreeMap::new(),
        )
    }

    /// Resume a walk whose budget ran out (`WalkOutcome::Continue`) at its
    /// cursor, over everything it already classified: the answer is the same
    /// as one longer walk's, and a key reached this way still has every
    /// earlier key behind it for its liveness.
    pub fn continue_walk(
        &self,
        chains: &BTreeMap<D32, VaultChain>,
        previous: Walked,
        budget: usize,
    ) -> Result<Walked, VerifierFailure> {
        let cursor = match previous.outcome {
            WalkOutcome::Continue { cursor } => cursor,
            WalkOutcome::Consumed { attempt }
            | WalkOutcome::Unresolved { attempt }
            | WalkOutcome::CounterExhausted { attempt } => attempt,
        };
        self.walk_chain(
            chains,
            *previous.walk.vault_id(),
            *previous.walk.parent_root(),
            cursor,
            budget,
            CHAIN_DEPTH,
            previous.known,
        )
    }

    /// Stage 9 of §31: what this verifier establishes about the trader's own
    /// exercise, read back from a leg's cell (`read_attempt_cell`) — how the
    /// device finds its own exercise again after a restart (R13) — over the
    /// registration of its position, which the caller read to find that
    /// exercise. A refuted exercise reads nothing more: its registration is
    /// the one fact the ladder asks of it (§24 step 0), and it is in hand.
    /// The ladder runs inside `advance_resolved`, over what is returned here.
    pub fn establish_own(
        &self,
        chains: &BTreeMap<D32, VaultChain>,
        recognized: &RecognizedExercise,
        registration: &RegistrationRead,
    ) -> Result<Result<Established, NotEstablished>, VerifierFailure> {
        if let Some(refutation) = refuted_in_hand(recognized) {
            log::info!(
                "[sofi verifier] the exercise is refuted in hand: {:?}",
                refutation.refuted()
            );
            return Ok(Established::refuted(recognized, &refutation, registration));
        }
        let read =
            match self.read_legs(chains, recognized, None, CHAIN_DEPTH, Some(registration))? {
                Ok(read) => read,
                Err(why) => return Ok(Err(why)),
            };
        let legs = read.legs(&recognized.precommit().body, chains);
        Ok(self
            .complete_facts(recognized, &read, &legs)?
            .map(|facts| Established::Facts(Box::new(facts))))
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_chain(
        &self,
        chains: &BTreeMap<D32, VaultChain>,
        vault_id: D32,
        parent_root: D32,
        cursor: u64,
        budget: usize,
        depth: usize,
        mut known: BTreeMap<u64, KeyKnown>,
    ) -> Result<Walked, VerifierFailure> {
        // The walk asks for keys in order and stops on the first it cannot
        // classify; a key it asks for that is not read yet is read, and the
        // walk resumes. The chunking is invisible to the answer.
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
                    let read = match self.read_attempt_cell(&vault_id, &parent_root, attempt)? {
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
                    // An open key is unresolved, never a skip: no key is ever
                    // dead.
                    let Some(exercise) = read.exercise().cloned() else {
                        return Ok(done(None, None, known));
                    };
                    // The walk reached this key by skipping every one before
                    // it. That liveness is stated as the walk over them, for
                    // the facts to read, never as a flag.
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
                    match self.facts_of(chains, &exercise, key, depth)? {
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
    }

    /// What is known about the exercise found at the walked `key`: refuted by
    /// its own bytes, dead on the facts that need no validation evidence
    /// (MR-SOFI-0241, Amendment S14), or the complete facts established over
    /// the reads made here. `key`'s cell is in hand, and the walk established
    /// its liveness by reaching it.
    fn facts_of(
        &self,
        chains: &BTreeMap<D32, VaultChain>,
        exercise: &RecognizedExercise,
        key: WalkedKey<'_>,
        depth: usize,
    ) -> Result<Result<Known, NotEstablished>, VerifierFailure> {
        if let Some(refutation) = refuted_in_hand(exercise) {
            log::info!(
                "[sofi verifier] the exercise is refuted in hand: {:?}",
                refutation.refuted()
            );
            return Ok(Ok(Known::RefutedInHand(refutation)));
        }
        let read = match self.read_legs(chains, exercise, Some(key), depth, None)? {
            Ok(read) => read,
            Err(why) => return Ok(Err(why)),
        };
        let legs = read.legs(&exercise.precommit().body, chains);

        // A cell that is dead on the facts needing no validation evidence is
        // skipped here, before any of that evidence is acquired, so evidence
        // that is not in hand never holds a dead cell live.
        let ground = match establish_ground(&GroundReads {
            exercise,
            registration: &read.registration,
            parent: self.parent_for(exercise),
            legs: &legs,
        }) {
            Ok(ground) => ground,
            Err(why) => return Ok(Err(why)),
        };
        let dead = ground
            .leg_at(
                key.read.vault_id(),
                key.read.parent_root(),
                key.read.attempt(),
            )
            .is_some_and(|leg| {
                skip_without_evidence(&ground.route_ground(), &leg).0 == AttemptClass::Skipped
            });
        if dead {
            return Ok(Ok(Known::Ground(Box::new(ground))));
        }
        Ok(self
            .complete_facts(exercise, &read, &legs)?
            .map(|facts| Known::Facts(Box::new(facts))))
    }

    /// What every classification of an exercise stands on, read before any of
    /// its validation evidence: the registration of its position, and each
    /// leg's cell and walk. `walked` is the key the exercise was found at,
    /// whose cell is in hand; `registration` is the position's registration
    /// when the caller already read it, and is read here otherwise.
    fn read_legs(
        &self,
        chains: &BTreeMap<D32, VaultChain>,
        exercise: &RecognizedExercise,
        walked: Option<WalkedKey<'_>>,
        depth: usize,
        registration: Option<&RegistrationRead>,
    ) -> Result<Result<LegsRead, NotEstablished>, VerifierFailure> {
        let precommit = &exercise.precommit().body;
        let fulfillment = &exercise.fulfillment().body;

        // Registration from the position pair (R10). The pair decides for
        // every F at q at once.
        let registration = match registration {
            Some(registration) => registration.clone(),
            None => match self.read_registration(
                precommit.genesis(),
                precommit.device_id(),
                fulfillment.position(),
                precommit.void_root(),
            )? {
                Ok(registration) => registration,
                Err(missing) => return Ok(Err(NotEstablished::Registration(missing))),
            },
        };

        // Every leg of P at the attempt F fixed for it: its cell, and the
        // walk over the earlier keys of its chain when its attempt is above
        // zero. The attempts cover the legs exactly: that is conformance
        // item 4, decided in hand.
        let mut cells = Vec::with_capacity(precommit.legs().len());
        let mut walks: Vec<Option<AttemptWalk>> = Vec::with_capacity(precommit.legs().len());
        for leg in precommit.legs() {
            let attempt = fulfillment
                .attempts()
                .iter()
                .find(|a| a.vault_id == leg.vault_id)
                .map(|a| a.attempt)
                .ok_or_else(|| {
                    VerifierFailure::Refused(
                        "resolve: F names no attempt for a leg of P, past its in-hand check"
                            .to_string(),
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
                    let cell =
                        match self.read_attempt_cell(&leg.vault_id, &leg.parent_root, attempt)? {
                            Ok(read) => read,
                            Err(missing) => {
                                return Ok(Err(NotEstablished::AttemptCell {
                                    vault_id: leg.vault_id,
                                    attempt,
                                    missing,
                                }))
                            }
                        };
                    // `AttemptLive`: every earlier key of this leg's chain is
                    // skipped, established by walking them. The keys are read
                    // in chunks of the walk's budget, which never ends the
                    // walk (§23.6), and then walked once from the first key
                    // over everything read.
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
                        let chunk_from = |cursor: u64| {
                            usize::try_from(attempt - cursor)
                                .map_or(WALK_BUDGET, |keys| keys.min(WALK_BUDGET))
                        };
                        let mut chunk = self.walk_chain(
                            chains,
                            leg.vault_id,
                            leg.parent_root,
                            0,
                            chunk_from(0),
                            below,
                            BTreeMap::new(),
                        )?;
                        loop {
                            if let Some(why) = chunk.not_established {
                                return Ok(Err(why));
                            }
                            match chunk.outcome {
                                WalkOutcome::Continue { cursor } if cursor < attempt => {
                                    chunk = self.walk_chain(
                                        chains,
                                        leg.vault_id,
                                        leg.parent_root,
                                        cursor,
                                        chunk_from(cursor),
                                        below,
                                        chunk.known,
                                    )?;
                                }
                                WalkOutcome::Continue { .. }
                                | WalkOutcome::Consumed { .. }
                                | WalkOutcome::Unresolved { .. }
                                | WalkOutcome::CounterExhausted { .. } => break,
                            }
                        }
                        let keys_below = usize::try_from(attempt).map_err(|e| {
                            VerifierFailure::Refused(format!("attempt {attempt}: {e}"))
                        })?;
                        Some(walk(&leg.vault_id, &leg.parent_root, 0, keys_below, |a| {
                            chunk.known.get(&a).and_then(KeyKnown::key_facts)
                        }))
                    };
                    (cell, walk)
                }
            };
            cells.push(cell);
            walks.push(walk);
        }
        Ok(Ok(LegsRead {
            registration,
            cells,
            walks,
        }))
    }

    /// The complete facts of the exercise over `read`: its validation
    /// evidence acquired, `FulfillmentConformance` and `RouteValidation`
    /// recomputed, and the facts established over all of it.
    fn complete_facts(
        &self,
        exercise: &RecognizedExercise,
        read: &LegsRead,
        legs: &[LegReads<'_>],
    ) -> Result<Result<EstablishedFacts, NotEstablished>, VerifierFailure> {
        let precommit = &exercise.precommit().body;
        let fulfillment = &exercise.fulfillment().body;

        // What FulfillmentConformance reads (R7), the exercise supplying the
        // objects only its trader held.
        let own = exercise.closure_objects();
        let objects = ExerciseObjects {
            precommit,
            precommit_signature: &exercise.precommit().signature,
            preimage: exercise.preimage(),
            fulfillment,
            fulfillment_signature: &exercise.fulfillment().signature,
            own_objects: &own,
        };
        let conformance = match self.acquire_conformance_evidence(&objects)? {
            Acquired::Complete(evidence) => evidence,
            Acquired::Exhausted(missing) => {
                return Ok(Err(NotEstablished::ConformanceEvidence(missing)))
            }
        };

        // What RouteValidation reads (R5).
        let evidence = match self.acquire_evidence(precommit, exercise.preimage(), &own)? {
            Acquired::Complete(evidence) => evidence,
            Acquired::Exhausted(missing) => return Ok(Err(NotEstablished::RouteEvidence(missing))),
        };

        let reads = ExerciseReads {
            exercise,
            registration: &read.registration,
            conformance: &conformance,
            evidence: &evidence,
            parent: self.parent_for(exercise),
            legs,
        };
        Ok(establish(&reads))
    }

    /// What the trader's lineage holds at the position `exercise`'s `P`
    /// names as its parent — the claim final at its `K_root(p)` and the root
    /// that claim installed — as this verifier establishes it: its own
    /// admitted position when that is the claim `P` names, and otherwise the
    /// frontier-relative walk of the trader's lineage (DSM Amendment A8; SoFi
    /// Amendment S15). Whether what is held is what `P` names is the facts'
    /// to decide (§6.62). A lineage the walk establishes Invalid at or before
    /// that position, or quarantines for a divergent write-once register
    /// cell, holds nothing there, ever: the verdict reaches the facts as such
    /// (SoFi Amendment S13, the same classes `validation::setup_lineage`
    /// reads). `None` while the reads do not establish the lineage at that
    /// position: the facts then report the parent unresolved, and nothing is
    /// refuted.
    fn parent_for(&self, exercise: &RecognizedExercise) -> Option<TraderAtParent> {
        let precommit = &exercise.precommit().body;
        let position = precommit.position();
        if let Some(own) = self.parent {
            if own.named == *precommit.parent_claim_ref() && own.economic_position == position {
                return Some(TraderAtParent::Held(own));
            }
        }
        trader_at_parent(
            position,
            self.reads
                .trader_root_at(precommit.genesis(), precommit.device_id(), position),
        )
    }
}

/// What the walk of a trader's lineage to `position` establishes there
/// (DSM Amendment A8; SoFi Amendment S15): the claim it holds and its root;
/// or, when the walk establishes the lineage Invalid at or before `position`
/// — an Invalid step, or a divergent write-once register cell it
/// quarantines — that it holds nothing there, ever (SoFi Amendment S13, the
/// classes `validation::setup_lineage` reads). Evidence not in hand and a
/// position the walk cannot pass yet establish nothing.
fn trader_at_parent(
    position: u64,
    walked: Result<(ValidatedEconomicRoot, ParentClaimRef), PeerLineageFailure>,
) -> Option<TraderAtParent> {
    match walked {
        Ok((root, named)) => held_at(
            position,
            root.economic_position(),
            root.economic_root(),
            named,
        )
        .map(TraderAtParent::Held),
        Err(PeerLineageFailure::Invalid(..) | PeerLineageFailure::Quarantined(..)) => {
            Some(TraderAtParent::LineageInvalid)
        }
        Err(PeerLineageFailure::Incomplete(..) | PeerLineageFailure::Unresolved(..)) => None,
    }
}

/// What a trader's lineage holds at `position`, from a walk that reached
/// `root_position`: the claim `named` final there and the `root` it
/// installed. A walk that reached another position holds nothing at this
/// one.
fn held_at(
    position: u64,
    root_position: u64,
    root: D32,
    named: ParentClaimRef,
) -> Option<ResolvedParent> {
    (root_position == position).then_some(ResolvedParent {
        economic_position: position,
        selected_root: root,
        named,
    })
}

/// Resolves another trader's conditional position for a frontier-relative
/// walk of that trader's lineage (DSM Amendment A8, SoFi Amendment S15):
/// Core's own verdict over SoFi's public objects for that position alone.
pub struct PeerPositionResolver<'a, R: SofiReads + ?Sized> {
    pub reads: &'a R,
    /// The network's pinned set, over which the position's cells are routed.
    pub members: &'a StorageSetMembers,
    pub set_id: D32,
    pub network_id: &'a [u8],
}

impl<R: SofiReads + ?Sized> crate::economic::peer_lineage::ConditionalPositionResolver
    for PeerPositionResolver<'_, R>
{
    fn resolve(
        &self,
        previous: &crate::economic::lineage::ValidatedEconomicRoot,
        parent: &ParentClaimRef,
        held: &SofiResolutionClaim,
    ) -> Result<
        (
            crate::economic::lineage::ValidatedEconomicRoot,
            AcceptedClaim,
        ),
        PeerLineageFailure,
    > {
        // The walk authenticated `q − 1` itself: `parent` is the claim it
        // accepted there and `previous` the root it holds — for a SoFi
        // position, the root that resolution selected. What a `P` at `q`
        // names as its parent is compared against exactly that (§6.62).
        let resolved = Some(ResolvedParent {
            economic_position: previous.economic_position(),
            selected_root: previous.economic_root(),
            named: *parent,
        });
        let verifier = Verifier::new(
            self.reads,
            self.members,
            self.set_id,
            self.network_id,
            resolved,
            AcceptedGeneses::default(),
        );
        let advanced = verifier.peer_position(previous, parent, held)?;
        Ok((advanced.root, advanced.claim))
    }
}

impl<R: SofiReads + ?Sized> Verifier<'_, R> {
    /// Advance ANOTHER trader's lineage through its SoFi position `q`, whose
    /// root cell holds the conditional claim `held` (SoFi Amendment S15; P15-9:
    /// a peer walk passes a resolved position).
    ///
    /// The same stages the trader's own device runs for its own position, over
    /// this verifier's reads: the registration from the position pair, `P` by
    /// its id, the exercise read back from the first leg's cell, each vault's
    /// canonical chain, and the facts Core establishes over them. The ladder
    /// then runs inside [`advance_peer_resolved`]. `held` counts only as the
    /// claim `(P, F)` derive: its two roots are the ones the resolution chooses
    /// between, or the position is Invalid.
    ///
    /// `previous` is the root the walk validated at `p`; `parent` is the claim
    /// the walk accepted there; `self.parent` is the walk's own resolution of
    /// `p` when `p` was itself a SoFi position. A read not in hand is
    /// `Incomplete`, facts that do not decide `q` yet are `Unresolved`, and
    /// only a verified contradiction is `Invalid`.
    pub fn peer_position(
        &self,
        previous: &crate::economic::lineage::ValidatedEconomicRoot,
        parent_claim: &ParentClaimRef,
        held: &SofiResolutionClaim,
    ) -> Result<PeerResolvedAdvance, PeerLineageFailure> {
        use PeerLineageFailure::{Incomplete, Invalid, Unresolved};
        let q = held.position;
        let read = |e: VerifierFailure| Incomplete(format!("position {q}: {e}"));

        // The registration, from the pair (R10). The claim final at the root
        // cell names one fulfillment; the pair must hold that one registered.
        let registration = self
            .read_registration(&held.genesis, &held.device_id, q, &previous.economic_root())
            .map_err(read)?
            .map_err(|missing| {
                Incomplete(format!("position {q}: the registration: {missing:?}"))
            })?;
        let fulfillment = match registration.registration() {
            Registration::Registered(signed)
                if derive::fulfillment_id(&signed.body) == held.fulfillment_id =>
            {
                signed.clone()
            }
            other => {
                return Err(Unresolved(format!(
                    "position {q}: the pair does not hold the registered fulfillment the root \
                     cell's claim names ({other:?})"
                )))
            }
        };
        let precommit = match self
            .reads
            .precommit(fulfillment.body.precommit_id())
            .map_err(|e| read(e.into()))?
        {
            Resolved::Kept(signed) => signed.body,
            Resolved::None | Resolved::Unavailable => {
                return Err(Incomplete(format!(
                    "position {q}: the precommit the fulfillment names is not in hand"
                )))
            }
        };
        // `held` counts only as the claim (P, F) derive (Amendment S15).
        // Registration pairs the cells by `FulfillmentId(F)` from their bytes
        // alone (Amendment S20), so the body is compared here, where `P` is in
        // hand: a claim naming F with another body is not F's `C_q`, and the
        // position is Invalid for the trader's lineage. A final value is the
        // cell's only one, so once they agree its two roots are the ones the
        // resolution chooses between.
        if derive::resolution_claim(&precommit, &fulfillment.body) != *held {
            return Err(Invalid(format!(
                "position {q}: the claim at K_root(q) names the fulfillment, but it is not the \
                 claim its P and F derive"
            )));
        }

        // The exercise, read back from the first leg's cell.
        let first = precommit
            .legs()
            .first()
            .ok_or_else(|| Invalid(format!("position {q}: P names no leg")))?;
        let attempt = fulfillment
            .body
            .attempts()
            .iter()
            .find(|a| a.vault_id == first.vault_id)
            .map(|a| a.attempt)
            .ok_or_else(|| {
                Invalid(format!(
                    "position {q}: F names no attempt for P's first leg"
                ))
            })?;
        let exercise = self
            .read_attempt_cell(&first.vault_id, &first.parent_root, attempt)
            .map_err(read)?
            .map_err(|missing| {
                Incomplete(format!("position {q}: the first leg's cell: {missing:?}"))
            })?
            .into_exercise()
            .ok_or_else(|| {
                Unresolved(format!(
                    "position {q}: no exercise holds the first leg's cell yet"
                ))
            })?;

        // Each vault's canonical chain as far as the parent the leg names,
        // and the facts over them.
        let mut chains: BTreeMap<D32, VaultChain> = BTreeMap::new();
        for leg in precommit.legs() {
            if let std::collections::btree_map::Entry::Vacant(slot) = chains.entry(leg.vault_id) {
                slot.insert(
                    self.chain_until(&leg.vault_id, &leg.parent_root)
                        .map_err(read)?,
                );
            }
        }
        let established = self
            .establish_own(&chains, &exercise, &registration)
            .map_err(read)?
            .map_err(|why| match why {
                NotEstablished::Registration(..)
                | NotEstablished::ConformanceEvidence(..)
                | NotEstablished::RouteEvidence(..)
                | NotEstablished::AttemptCell { .. } => {
                    Incomplete(format!("position {q}: the facts: {why:?}"))
                }
                NotEstablished::ParentUnresolved { .. }
                | NotEstablished::AttemptLiveness { .. }
                | NotEstablished::NotThisExercise(..) => {
                    Unresolved(format!("position {q}: the facts: {why:?}"))
                }
            })?;

        advance_peer_resolved(
            previous,
            &precommit,
            &fulfillment.body,
            parent_claim,
            &established,
        )
        .map_err(|e| match e {
            // Complete facts the ladder does not resolve yet, or facts read at
            // a cell some other exercise holds: nothing is known wrong.
            AdvanceError::FactsIncomplete(..) | AdvanceError::FactsAreNotThisOperation { .. } => {
                Unresolved(format!("position {q}: {e}"))
            }
            AdvanceError::LineageIsTerminal
            | AdvanceError::PositionIsNotSuccessor { .. }
            | AdvanceError::PreRootIsNotThePredecessor { .. }
            | AdvanceError::ParentClaimMismatch
            | AdvanceError::RefutedYetNotTerminal
            | AdvanceError::CreditsNotDerivable
            | AdvanceError::TokenNotAdopted { .. }
            | AdvanceError::BalancesNotDerivable(..)
            | AdvanceError::PreimageIsNotThisOperation { .. }
            | AdvanceError::Counter(..) => Invalid(format!("position {q}: {e}")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SoFi Amendment S16: another trader's conditional parent resolves only
    /// to the position `P` names, held by the fulfillment `P` names.
    /// A genesis verdict this operation reached is reused only for the
    /// exact bytes it bound to the owner's creation: the same bytes under the
    /// same vault find it; one changed byte, or the same bytes under another
    /// vault, find nothing, and are verified afresh.
    #[test]
    fn a_genesis_verdict_is_reused_only_for_the_bytes_it_bound() {
        let (vault, other) = ([0x5A; 32], [0x5B; 32]);
        let accepted = b"the exact genesis preimage bytes".to_vec();
        let mut changed = accepted.clone();
        changed[0] ^= 1;
        let mut memo = BTreeMap::new();
        memo.insert((vault, genesis_evidence(&accepted)), "verdict");
        assert_eq!(
            remembered(&memo, &vault, [accepted.as_slice()]),
            Some(&"verdict")
        );
        assert_eq!(
            remembered(&memo, &vault, [changed.as_slice(), accepted.as_slice()]),
            Some(&"verdict"),
            "found among other candidates"
        );
        assert_eq!(remembered(&memo, &vault, [changed.as_slice()]), None);
        assert_eq!(remembered(&memo, &other, [accepted.as_slice()]), None);
    }

    /// Pre-audit 12f, SoFi Amendment S13: the walk's verdict reaches the
    /// facts as what it is. A lineage the walk establishes Invalid at or
    /// before `p`, or quarantines for a divergent register cell, holds
    /// nothing at `p`, ever; evidence not in hand and a position the walk
    /// cannot pass yet establish nothing; a walk that holds a claim at `p`
    /// holds it there and nowhere else. On the old code every failure read as
    /// no parent, so a key held on an invalid lineage waited forever.
    #[test]
    fn the_walks_verdict_on_a_traders_lineage_reaches_the_facts() {
        use crate::economic::provenance::PeerLineageFailure as F;
        for verdict in [
            F::Invalid("a step's witness does not fold".to_string()),
            F::Quarantined("two claims hold the register cell".to_string()),
        ] {
            assert_eq!(
                trader_at_parent(7, Err(verdict)),
                Some(TraderAtParent::LineageInvalid)
            );
        }
        for pending in [
            F::Incomplete("the register cell is not decided yet".to_string()),
            F::Unresolved("a conditional position has not resolved".to_string()),
        ] {
            assert_eq!(trader_at_parent(7, Err(pending)), None);
        }
        let named = ParentClaimRef::SingleRoot {
            claim_ref: [0xC7; 32],
        };
        let at = |position| {
            ValidatedEconomicRoot::rehydrate_from_admitted_store(
                crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                    economic_position: position,
                    economic_root: [0x77; 32],
                    claim_ref: [0xC7; 32],
                },
            )
            .expect("an ordinary admitted position")
        };
        assert_eq!(
            trader_at_parent(7, Ok((at(7), named))),
            Some(TraderAtParent::Held(ResolvedParent {
                economic_position: 7,
                selected_root: [0x77; 32],
                named,
            }))
        );
        assert_eq!(trader_at_parent(7, Ok((at(6), named))), None);
    }

    /// What a walk holds counts only at the position it reached: there it is
    /// the claim final at `K_root(p)` and its root, whichever kind of claim
    /// that is, for the facts to compare with what `P` names (§6.62); a walk
    /// that reached another position holds nothing at `p`.
    #[test]
    fn what_a_walk_holds_counts_only_at_the_position_it_reached() {
        let (position, root) = (7, [0x77; 32]);
        for named in [
            ParentClaimRef::Conditional {
                fulfillment_id: [0xF7; 32],
            },
            ParentClaimRef::SingleRoot {
                claim_ref: [0xC7; 32],
            },
        ] {
            assert_eq!(
                held_at(position, position, root, named),
                Some(ResolvedParent {
                    economic_position: position,
                    selected_root: root,
                    named,
                })
            );
            assert_eq!(
                held_at(position, position + 1, root, named),
                None,
                "the root of another position"
            );
        }
    }
}
