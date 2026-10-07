// SPDX-License-Identifier: Apache-2.0

//! The foreign lineage verifier, frontier-relative (DSM Amendment A8).
//!
//! A receiver never replays a payer's history to genesis. It starts at its
//! own authenticated frontier for the payer — the last coordinate it
//! authenticated on the way to a step it accepted from the payer, or the
//! payer's activation root where it has none — and for each position from
//! there to the target it:
//!
//! 1. reads the claim final at the register cell derived from
//!    `(G, DevID, position)` and the root it authenticated at the position
//!    before;
//! 2. authenticates the claim: its manifest by content address, its key the
//!    AK the manifest's authority evidence proves (P0–P6), its register set
//!    the canonical set of the committed network;
//! 3. verifies the transition that produced the root against its
//!    authenticated parent, from that step's own evidence, with the SAME
//!    `advance_validated` any device runs.
//!
//! ## Sources
//!
//! A credit's source is held to account like a payer (DSM Amendment A8 as
//! corrected for sources, owner 2026-10-01): its own segment from this
//! verifier's frontier for it is validated step by step, its credits'
//! sources the same way, back to frontiers this verifier already validated.
//! A root the source only registered proves nothing about where its value
//! came from. The source step itself is a debit, so nothing further is asked
//! of it.
//!
//! ## Conditional positions
//!
//! A position whose claim is conditional (`C_q`) selects no root by its
//! bytes. Inside a chain, the [`ConditionalPositionResolver`] derives the root
//! it selected from SoFi's public objects for that position alone (SoFi
//! Amendment S15), and the chain continues from it.
//!
//! ## Budgeted and typed
//!
//! The peer is adversarial: a lineage can be arbitrarily long, so every
//! position spends from one step budget, and a budget that runs out is
//! `Incomplete`, never `Invalid`. `ValidatedEconomicRoot` stays
//! unconstructible from network data: the verifier holds one only because it
//! authenticated or validated it.

use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
    TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
};
use crate::crypto::domain::TaggedHashDomain;
use crate::economic::authority_evidence::{
    verify_authority_evidence, AuthorityEvidenceError, AuthorityFacts,
};
use crate::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
use crate::economic::claim_envelope::{RegisteredEconomicClaim, VerifiedEconomicRootClaim};
use crate::economic::decode::decode_admission_manifest;
use crate::economic::lineage::{
    activate, advance_validated, AcceptedClaim, AcceptedSubstrate, EconomicActivationSnapshot,
    EconomicValidationError, ValidatedEconomicRoot,
};
use crate::economic::provenance::{
    PeerLineageFailure, ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
};
use crate::economic::register::{
    read_root_cell, resolve_for_trader, resolve_root_register_profile, RegisteredEconomicRoot,
    RootCell, RootRegisterProfile,
};
use crate::economic::successor_evidence::verify_dsm_successor_evidence;
use crate::route_chain::{CellEvidence, CellReading, ChainState};
use crate::sofi::wire::{ParentClaimRef, SofiResolutionClaim};
use crate::utils::text_id::encode_base32_crockford;

/// Total step budget for one verification, across every identity it touches.
const WALK_STEP_BUDGET: usize = 512;

/// I/O the verifier needs: raw reads of the register cells it names, and
/// immutable objects by address. The fetcher supplies bytes, never a verdict:
/// the verifier evaluates every cell's route chains itself and re-checks every
/// address.
pub trait PeerEvidenceFetcher {
    /// Every seat's reads of `cell` (storage spec §9): the values each seat
    /// holds, its committed state from a mirror, and each later seat's own
    /// mirror of the leader. The verifier evaluates them.
    fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure>;
    /// The release that installed `generation` of the native reserve
    /// `reserve_id`, established final by a walk of the reserve lineage from
    /// its genesis state, with the state it succeeded. `Incomplete` while
    /// the lineage has not reached that generation.
    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure>;
    /// The network's root-register set as the local catalog resolves it —
    /// CANDIDATE entries the caller must re-derive and check, never authority.
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure>;
    /// Exact immutable bytes at `addr` under `namespace`.
    fn immutable(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
    /// The canonical `TokenPolicyV3` bytes rooted under `policy_commit` —
    /// the verifier's own anchoring (local store or the authoritative
    /// content-addressed path). The verifier re-hashes against the commit;
    /// unavailable is `Incomplete`, never `Invalid`.
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
}

/// A coordinate of a peer this verifier authenticated itself: its frontier
/// for that peer (DSM Amendment A8).
///
/// Either the peer's activation root, which every verifier derives without
/// being told it, or a coordinate a verification reached
/// ([`Self::reached_by`]) and the receiver recorded on the way to a step it
/// accepted. A root the peer merely claims is never a frontier: the fields
/// are private, and the only other constructor rehydrates what the receiver
/// recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFrontier {
    genesis: [u8; 32],
    device_id: [u8; 32],
    at: FrontierAt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FrontierAt {
    /// Position 0, the canonical empty root. No claim was accepted there.
    Activation,
    /// A position the receiver authenticated, the root it authenticated
    /// there, and the claim it accepted there.
    Recorded {
        economic_position: u64,
        economic_root: [u8; 32],
        accepted: ParentClaimRef,
    },
}

impl PeerFrontier {
    /// The peer's activation root: the frontier of a receiver that has
    /// authenticated nothing of this peer.
    pub fn activation(genesis: [u8; 32], device_id: [u8; 32]) -> Self {
        Self {
            genesis,
            device_id,
            at: FrontierAt::Activation,
        }
    }

    /// The coordinate `transition` reached: its position, the root it
    /// validated there and the claim it accepted there. `None` for a
    /// transition at a resolved SoFi position, whose facts do not carry the
    /// fulfillment that names its claim as a parent.
    pub fn reached_by(transition: &ValidatedPeerTransition) -> Option<Self> {
        match transition {
            ValidatedPeerTransition::SingleRoot(_) => Some(Self {
                genesis: *transition.peer_genesis(),
                device_id: *transition.peer_devid(),
                at: FrontierAt::Recorded {
                    economic_position: transition.validated_root().economic_position(),
                    economic_root: transition.validated_root().economic_root(),
                    accepted: ParentClaimRef::SingleRoot {
                        claim_ref: transition.accepted_claim().claim_ref(),
                    },
                },
            }),
            ValidatedPeerTransition::ResolvedSofi(_) => None,
        }
    }

    /// A frontier this device recorded, read back from its own store.
    ///
    /// **Only the receiver's frontier store may call this**, with exactly
    /// the fields of a frontier [`Self::reached_by`] produced and the
    /// receiver recorded. Anything read from a network or taken from a peer
    /// is not a frontier, and feeding it here is the fabrication the private
    /// fields exist to prevent.
    pub fn rehydrate_recorded(
        genesis: [u8; 32],
        device_id: [u8; 32],
        economic_position: u64,
        economic_root: [u8; 32],
        accepted: ParentClaimRef,
    ) -> Self {
        Self {
            genesis,
            device_id,
            at: FrontierAt::Recorded {
                economic_position,
                economic_root,
                accepted,
            },
        }
    }

    pub fn genesis(&self) -> &[u8; 32] {
        &self.genesis
    }

    pub fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }

    pub fn economic_position(&self) -> u64 {
        match &self.at {
            FrontierAt::Activation => 0,
            FrontierAt::Recorded {
                economic_position, ..
            } => *economic_position,
        }
    }

    /// The recorded coordinate: position, root and accepted claim. `None` at
    /// the activation root, which is never recorded.
    pub fn recorded(&self) -> Option<(u64, [u8; 32], &ParentClaimRef)> {
        match &self.at {
            FrontierAt::Activation => None,
            FrontierAt::Recorded {
                economic_position,
                economic_root,
                accepted,
            } => Some((*economic_position, *economic_root, accepted)),
        }
    }
}

/// The receiver's frontiers: the coordinates it recorded for each peer.
pub trait PeerFrontiers {
    /// This receiver's latest recorded frontier for `(genesis, device_id)`
    /// strictly below `position`, or `None` when it recorded none there.
    fn frontier_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Option<PeerFrontier>, PeerLineageFailure>;

    /// A coordinate a walk over these frontiers has just validated a step
    /// at: the whole segment to it, from a frontier this receiver held,
    /// passed (owner ruling 2026-10-01). Told as the walk validates it, not
    /// when the walk ends, so a walk that starts while this one is still
    /// running (a conditional position's resolution walks other traders,
    /// this peer among them) can start there. Never a recorded frontier:
    /// a receiver records one only with an acceptance.
    fn validated(&self, frontier: &PeerFrontier);
}

/// Derives the root a conditional SoFi position selected, from SoFi's public
/// objects for that position alone (SoFi Amendment S15).
pub trait ConditionalPositionResolver {
    /// `q = previous.economic_position() + 1`; `parent` is the claim accepted
    /// at `q − 1`, and `held` is the claim final at `K_root(q)`. Returns the
    /// root `q` selected and the claim accepted at `q`, or why it cannot:
    /// `Invalid` for a verified contradiction, `Incomplete` or `Unresolved`
    /// while the facts are not in hand or do not decide `q` yet.
    fn resolve(
        &self,
        previous: &ValidatedEconomicRoot,
        parent: &ParentClaimRef,
        held: &SofiResolutionClaim,
    ) -> Result<(ValidatedEconomicRoot, AcceptedClaim), PeerLineageFailure>;
}

/// A peer's lineage validated to its target step, with the frontier each
/// credit source's segment reached on the way.
///
/// Every source frontier here stands at a step whose whole segment, from a
/// frontier this receiver held, passed validation (DSM Amendment A8; owner
/// ruling 2026-10-01: "A frontier becomes trusted only after the complete
/// segment to it has passed validation"). The receiver records them in the
/// transaction that accepts the target, beside the target's own frontier, so
/// a later credit from the same source validates only the suffix.
#[derive(Debug)]
pub struct ValidatedPeerLineage {
    transition: ValidatedPeerTransition,
    source_frontiers: Vec<PeerFrontier>,
}

impl ValidatedPeerLineage {
    /// The target step's validated transition.
    pub fn transition(&self) -> &ValidatedPeerTransition {
        &self.transition
    }

    /// The frontier each credit source's segment reached, in the order the
    /// walk validated them.
    pub fn source_frontiers(&self) -> &[PeerFrontier] {
        &self.source_frontiers
    }

    /// The target step's transition and the sources' frontiers.
    pub fn into_parts(self) -> (ValidatedPeerTransition, Vec<PeerFrontier>) {
        (self.transition, self.source_frontiers)
    }
}

/// Verify a peer's lineage from this receiver's frontier to
/// `target_position`: the target step's validated transition, and the
/// frontiers its credits' sources reached.
///
/// Every step from the frontier to the target is validated from its own
/// evidence; a credit's source is validated through its own segment back
/// to a frontier this receiver holds, or one this walk already validated; a
/// conditional position before the target is resolved by `conditional`.
/// Nothing behind a frontier is read.
pub fn validate_peer_lineage(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<ValidatedPeerLineage, PeerLineageFailure> {
    if target_position == 0 {
        return Err(invalid(
            "position 0 is the activation root; it has no transition to validate",
        ));
    }
    let verifier = Verifier {
        fetcher,
        expected_network_id,
        register: Register::resolve(fetcher, expected_network_id)?,
        frontiers,
        conditional,
        steps_remaining: std::cell::Cell::new(WALK_STEP_BUDGET),
        sources_reached: std::cell::RefCell::new(Vec::new()),
        walked: std::cell::RefCell::new(Vec::new()),
        steps: std::cell::RefCell::new(std::collections::BTreeMap::new()),
    };
    let transition = verifier.segment(peer_genesis, peer_devid, target_position)?;
    Ok(ValidatedPeerLineage {
        transition,
        source_frontiers: verifier.sources_reached.into_inner(),
    })
}

/// The root a peer's lineage selected AT `position`, and the reference a later
/// `P` names that position by (DSM Amendment A8; SoFi Amendment S15): the
/// segment from this receiver's frontier, each step validated in full from its
/// own evidence, with `position` itself resolved through `conditional` when
/// its claim is conditional, exactly as an interior one. A walk resolves
/// another trader's conditional parent with it.
///
/// Not a debit source: it yields no [`ValidatedPeerTransition`]. Position 0
/// is the activation root, where no claim was accepted for a `P` to name, and
/// is `Invalid`. Nothing is recorded.
pub fn peer_root_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<(ValidatedEconomicRoot, ParentClaimRef), PeerLineageFailure> {
    peer_root_reached(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        position,
        frontiers,
        conditional,
    )
    .map(WalkedTo::into_answer)
}

/// What a complete walk to one position answered, with the coordinates it
/// validated on the way: the position itself when its claim is an ordinary
/// one (the rule of [`PeerFrontier::reached_by`]: a conditional position is
/// never a frontier), and every credit source's frontier. Each stands at the
/// end of a segment that passed validation from a frontier the receiver held
/// (owner ruling 2026-10-01: "A frontier becomes trusted only after the
/// complete segment to it has passed validation"), so a later walk of the
/// same peer, or of a source, can start there. None is recorded here.
#[derive(Debug)]
pub struct WalkedTo<T> {
    answer: T,
    reached: Vec<PeerFrontier>,
}

impl<T> WalkedTo<T> {
    /// What the walk answered at the position.
    pub fn answer(&self) -> &T {
        &self.answer
    }

    /// The coordinates the walk validated: the position's own, when it is an
    /// ordinary one, and the credit sources' frontiers.
    pub fn reached(&self) -> &[PeerFrontier] {
        &self.reached
    }

    /// The answer, without the coordinates.
    pub fn into_answer(self) -> T {
        self.answer
    }

    /// The answer and the coordinates.
    pub fn into_parts(self) -> (T, Vec<PeerFrontier>) {
        (self.answer, self.reached)
    }
}

/// [`peer_root_at`], with the coordinates the walk validated ([`WalkedTo`]).
pub fn peer_root_reached(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<WalkedTo<(ValidatedEconomicRoot, ParentClaimRef)>, PeerLineageFailure> {
    let verifier = Verifier {
        fetcher,
        expected_network_id,
        register: Register::resolve(fetcher, expected_network_id)?,
        frontiers,
        conditional,
        steps_remaining: std::cell::Cell::new(WALK_STEP_BUDGET),
        sources_reached: std::cell::RefCell::new(Vec::new()),
        walked: std::cell::RefCell::new(Vec::new()),
        steps: std::cell::RefCell::new(std::collections::BTreeMap::new()),
    };
    let below = position.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "position {position} has no successor to stand below"
        ))
    })?;
    let frontier = verifier.frontier_below(peer_genesis, peer_devid, below)?;
    let point = verifier.chain_through(peer_genesis, peer_devid, &frontier, position)?;
    let accepted = point.accepted.ok_or_else(|| {
        invalid(format!(
            "position {position} is the activation root: no claim was accepted there for a P \
             to name as its parent"
        ))
    })?;
    // The whole segment to `position` passed. An ordinary claim there is the
    // coordinate `reached_by` makes of a step: the position, the root the
    // walk validated there and the claim it accepted there.
    let own = match accepted {
        ParentClaimRef::SingleRoot { .. } => Some(PeerFrontier {
            genesis: *peer_genesis,
            device_id: *peer_devid,
            at: FrontierAt::Recorded {
                economic_position: point.root.economic_position(),
                economic_root: point.root.economic_root(),
                accepted,
            },
        }),
        ParentClaimRef::Conditional { .. } => None,
    };
    let mut reached = verifier.sources_reached.into_inner();
    reached.extend(own);
    Ok(WalkedTo {
        answer: (point.root, accepted),
        reached,
    })
}

/// The claim a peer's lineage accepted AT `position` (SoFi Amendment S15,
/// MR-SOFI-0347): what a setup naming that position is checked against. The
/// segment from this receiver's frontier is validated in full as a payer's
/// is, and `position` itself as its last step, or, when its claim is
/// conditional, resolved through `conditional` exactly as an interior
/// position is. A trader's setup made right after a SoFi position names the
/// claim that position's resolution accepted, so a conditional position is a
/// claim to resolve here, never a refusal. Nothing is recorded.
pub fn peer_claim_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<AcceptedClaim, PeerLineageFailure> {
    peer_claim_reached(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        position,
        frontiers,
        conditional,
    )
    .map(WalkedTo::into_answer)
}

/// [`peer_claim_at`], with the coordinates the walk validated ([`WalkedTo`]).
pub fn peer_claim_reached(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<WalkedTo<AcceptedClaim>, PeerLineageFailure> {
    if position == 0 {
        return Err(invalid(
            "position 0 is the activation root: no claim was accepted there",
        ));
    }
    let verifier = Verifier {
        fetcher,
        expected_network_id,
        register: Register::resolve(fetcher, expected_network_id)?,
        frontiers,
        conditional,
        steps_remaining: std::cell::Cell::new(WALK_STEP_BUDGET),
        sources_reached: std::cell::RefCell::new(Vec::new()),
        walked: std::cell::RefCell::new(Vec::new()),
        steps: std::cell::RefCell::new(std::collections::BTreeMap::new()),
    };
    let frontier = verifier.frontier_below(peer_genesis, peer_devid, position)?;
    let point = verifier.chain_through(peer_genesis, peer_devid, &frontier, position - 1)?;
    verifier.spend_step()?;
    let (answer, own) =
        match verifier.final_claim(peer_genesis, peer_devid, position, &point.root)? {
            RegisteredEconomicClaim::SingleRoot(claim) => {
                let step = verifier.full_step(
                    peer_genesis,
                    peer_devid,
                    position,
                    &point,
                    &claim,
                    StepRole::Segment,
                )?;
                (*step.accepted_claim(), PeerFrontier::reached_by(&step))
            }
            RegisteredEconomicClaim::ConditionalSofi(held) => {
                let (.., accepted) = verifier.resolve_conditional(
                    peer_genesis,
                    peer_devid,
                    position,
                    &point,
                    &held,
                )?;
                (accepted, None)
            }
        };
    let mut reached = verifier.sources_reached.into_inner();
    reached.extend(own);
    Ok(WalkedTo { answer, reached })
}

/// A failure met inside a step, kept in its own class and located at the
/// position where it was met.
fn at_position(position: u64, failure: PeerLineageFailure) -> PeerLineageFailure {
    match failure {
        PeerLineageFailure::Incomplete(m) => {
            PeerLineageFailure::Incomplete(format!("at position {position}: {m}"))
        }
        PeerLineageFailure::Invalid(m) => {
            PeerLineageFailure::Invalid(format!("at position {position}: {m}"))
        }
        PeerLineageFailure::Quarantined(m) => {
            PeerLineageFailure::Quarantined(format!("at position {position}: {m}"))
        }
        PeerLineageFailure::Unresolved(m) => {
            PeerLineageFailure::Unresolved(format!("at position {position}: {m}"))
        }
    }
}

/// The class of a step's validation failure. Evidence that verified as
/// wrong is `Invalid`; evidence that could not be established — a nested
/// peer's lineage, a reserve release, a token policy, acceptance evidence —
/// keeps the class it was established in, so an outage anywhere below a step
/// is retried and never read as a forgery (storage spec §4: a fact that is
/// not established is never read as its negation).
fn step_failure(position: u64, e: EconomicValidationError) -> PeerLineageFailure {
    use crate::economic::provenance::ProvenanceError as P;
    let invalid_at = |e: &dyn core::fmt::Display| invalid(format!("validation at {position}: {e}"));
    match e {
        EconomicValidationError::Provenance(p) => match p {
            P::GenesisReleasePolicy(failure)
            | P::PeerTransitionNotValidated { failure, .. }
            | P::AcceptanceEvidence(failure)
            | P::OwnerLineage(failure)
            | P::RegisterNotEstablished(failure)
            | P::ReleaseNotEstablished { failure, .. } => at_position(position, failure),
            P::GenesisReleaseInvalid(..)
            | P::MarketLegPolicy(..)
            | P::PeerDebitIsNotAnOnlineTransfer
            | P::PeerDebitNotAddressedToConsumer
            | P::PeerDebitIndexIsNotTheOperationDebit
            | P::PeerWitnessDoesNotMatchValidatedRoot
            | P::SofiLineageNotEligible
            | P::PeerMutationIsNotADebit { .. }
            | P::AssetMismatch { .. }
            | P::AmountMismatch { .. }
            | P::IndexOutOfRange { .. }
            | P::NotACredit { .. }
            | P::DuplicateSourceId
            | P::SourceNotRecordedAsConsumed { .. }
            | P::ConsumedByAnotherOperation
            | P::NotTheCanonicalReserve { .. }
            | P::GenerationIsGenesis
            | P::ReleaseInvalid(..)
            | P::ReleaseRecipientMismatch
            | P::ReleaseBindingMismatch
            | P::ReleaseForeignSet
            | P::ReleaseEvidenceAddrMismatch
            | P::RegisterNotResolvable(..) => invalid_at(&p),
        },
        EconomicValidationError::PreRootIsNotThePredecessor { .. }
        | EconomicValidationError::PositionIsNotSuccessor { .. }
        | EconomicValidationError::RegisteredClaimNamesAnotherTrader
        | EconomicValidationError::SetupPositionIsNotThePredecessor { .. }
        | EconomicValidationError::SetupRootIsNotTheDerivedRoot { .. }
        | EconomicValidationError::RegisteredRootDiffersFromWitness { .. }
        | EconomicValidationError::Transition(..)
        | EconomicValidationError::OperationDigestMismatch { .. }
        | EconomicValidationError::EconomicOperationIdMismatch { .. }
        | EconomicValidationError::SubstrateKindMismatch
        | EconomicValidationError::SubstrateEvidenceMismatch { .. }
        | EconomicValidationError::OfflineBoundaryWriteSetNotYetSpecified
        | EconomicValidationError::WriteSet(..)
        | EconomicValidationError::ManifestAddrMismatch { .. }
        | EconomicValidationError::Manifest(..) => invalid_at(&e),
    }
}

fn incomplete(m: impl Into<String>) -> PeerLineageFailure {
    PeerLineageFailure::Incomplete(m.into())
}

fn invalid(m: impl Into<String>) -> PeerLineageFailure {
    PeerLineageFailure::Invalid(m.into())
}

/// The network's root register, resolved once per verification: the pinned
/// profile, and the catalog's candidate set checked against it. Every root
/// cell of the verification is routed over this set. A catalog that offers
/// another set is this verifier's own fault, never the peer's, so it is not
/// `Invalid`.
struct Register {
    profile: RootRegisterProfile,
    set: crate::ccb::StorageSetMembers,
}

impl Register {
    fn resolve(
        fetcher: &dyn PeerEvidenceFetcher,
        expected_network_id: &[u8],
    ) -> Result<Self, PeerLineageFailure> {
        let profile = resolve_root_register_profile(expected_network_id)
            .map_err(|e| incomplete(format!("no root register for this network: {e}")))?;
        let set = fetcher.root_register_candidate_set(expected_network_id)?;
        profile.verify_candidate(&set).map_err(|e| {
            incomplete(format!(
                "the catalog's root register set is not the pinned one: {e}"
            ))
        })?;
        Ok(Self { profile, set })
    }
}

/// Where a chain stands: the root this verifier authenticated at a position,
/// and the claim it accepted there (`None` only at the activation root).
struct ChainPoint {
    root: ValidatedEconomicRoot,
    accepted: Option<ParentClaimRef>,
}

/// A single-root claim authenticated at its position.
struct Authenticated {
    manifest: EconomicAdmissionManifest,
    manifest_addr: [u8; 32],
    facts: AuthorityFacts,
}

/// Why a step is being validated, which decides where its own provenance
/// questions go.
#[derive(Clone, Copy)]
enum StepRole {
    /// A step of a segment from a frontier: its credits' sources are held
    /// to account through their own segments.
    Segment,
    /// A credit's source step: it must be an online transfer, a debit that
    /// names no source of its own.
    Source,
}

struct Verifier<'a> {
    fetcher: &'a dyn PeerEvidenceFetcher,
    expected_network_id: &'a [u8],
    register: Register,
    frontiers: &'a dyn PeerFrontiers,
    conditional: &'a dyn ConditionalPositionResolver,
    steps_remaining: std::cell::Cell<usize>,
    /// The frontier each credit source's segment reached in this walk, each
    /// standing at a step whose whole segment passed.
    sources_reached: std::cell::RefCell<Vec<PeerFrontier>>,
    /// Every coordinate this walk validated a step at, of any identity: the
    /// sources' steps and each step of a segment it chained through. Each
    /// stands at the end of a segment that passed whole from a frontier this
    /// verifier held, so a later walk of the same identity in this
    /// verification starts there (DSM Amendment A8; owner ruling
    /// 2026-10-01). Its evidence was asked of the same fetcher, so a
    /// recording fetcher holds it in the same closure.
    walked: std::cell::RefCell<Vec<PeerFrontier>>,
    /// The single-root steps this walk validated in full, by identity and
    /// position: a credit's source that is one of them is not validated a
    /// second time ([`Self::source_step`]).
    steps: std::cell::RefCell<std::collections::BTreeMap<StepAt, ValidatedPeerTransition>>,
}

/// A step of an identity: its genesis, device id and position.
type StepAt = ([u8; 32], [u8; 32], u64);

impl Verifier<'_> {
    fn spend_step(&self) -> Result<(), PeerLineageFailure> {
        let left = self.steps_remaining.get();
        if left == 0 {
            return Err(incomplete(
                "peer lineage verification budget exhausted — retry once the frontier has \
                 advanced",
            ));
        }
        self.steps_remaining.set(left - 1);
        Ok(())
    }

    /// This receiver's latest frontier for `(genesis, device_id)` below
    /// `position`: the one it recorded, or a coordinate this walk validated
    /// earlier ([`Self::walked`]), whichever is later; the activation root
    /// where it holds neither. A store that answers with another identity's
    /// coordinate, or one not below `position`, is this verifier's own fault
    /// and decides nothing about the peer.
    fn frontier_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<PeerFrontier, PeerLineageFailure> {
        let recorded = self.recorded_frontier_below(genesis, device_id, position)?;
        let reached = self
            .walked
            .borrow()
            .iter()
            .filter(|f| {
                f.genesis() == genesis
                    && f.device_id() == device_id
                    && f.economic_position() < position
            })
            .max_by_key(|f| f.economic_position())
            .cloned();
        Ok(match (recorded, reached) {
            (Some(recorded), Some(reached))
                if reached.economic_position() > recorded.economic_position() =>
            {
                reached
            }
            (Some(recorded), _) => recorded,
            (None, Some(reached)) => reached,
            (None, None) => PeerFrontier::activation(*genesis, *device_id),
        })
    }

    /// A single-root step this walk validated in full: kept for a credit
    /// that names it as its source, and its coordinate [`Self::reached`].
    fn validated_step(&self, step: &ValidatedPeerTransition) {
        if let Some(reached) = PeerFrontier::reached_by(step) {
            self.steps.borrow_mut().insert(
                (
                    *step.peer_genesis(),
                    *step.peer_devid(),
                    reached.economic_position(),
                ),
                step.clone(),
            );
            self.reached(reached);
        }
    }

    /// The step at `(genesis, device_id, position)` this walk already
    /// validated in full, when it answers a credit's source question as a
    /// source step's own validation would: an online transfer whose write
    /// set names no credit source. A source step is validated exactly as a
    /// segment step is, against the same parent and from the same evidence,
    /// and additionally refused unless its operation is an online transfer
    /// and refused at any credit source it names (`DebitHasNoSources`); a
    /// segment step meeting both is the transition that validation returns.
    /// Any other step is validated as a source, and refused there.
    fn validated_source(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Option<ValidatedPeerTransition> {
        let steps = self.steps.borrow();
        let step = steps.get(&(*genesis, *device_id, position))?;
        let online_transfer = matches!(
            step.verified_operation(),
            crate::types::operations::Operation::Transfer {
                authority_policy: None,
                ..
            }
        );
        (online_transfer && step.witness().credit_sources.is_empty()).then(|| step.clone())
    }

    /// A coordinate this walk validated a step at: a start for every later
    /// walk of the identity in this verification, and told to the frontiers
    /// for walks outside it.
    fn reached(&self, frontier: PeerFrontier) {
        self.frontiers.validated(&frontier);
        self.walked.borrow_mut().push(frontier);
    }

    /// The frontier this receiver recorded for `(genesis, device_id)` below
    /// `position`, checked to be the one asked for.
    fn recorded_frontier_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Option<PeerFrontier>, PeerLineageFailure> {
        let Some(frontier) = self
            .frontiers
            .frontier_below(genesis, device_id, position)?
        else {
            return Ok(None);
        };
        if frontier.genesis() != genesis
            || frontier.device_id() != device_id
            || frontier.economic_position() >= position
        {
            return Err(incomplete(format!(
                "the frontier store answered position {} of {}/{} for a frontier of {}/{} below \
                 {position}",
                frontier.economic_position(),
                encode_base32_crockford(frontier.genesis()),
                encode_base32_crockford(frontier.device_id()),
                encode_base32_crockford(genesis),
                encode_base32_crockford(device_id),
            )));
        }
        Ok(Some(frontier))
    }

    /// The chain point a frontier stands at.
    fn start(&self, frontier: &PeerFrontier) -> Result<ChainPoint, PeerLineageFailure> {
        match frontier.recorded() {
            None => Ok(ChainPoint {
                root: activate(EconomicActivationSnapshot::fresh())
                    .map_err(|e| invalid(format!("activation shape: {e}")))?,
                accepted: None,
            }),
            Some((position, root, accepted)) => Ok(ChainPoint {
                root: authenticated_root(position, root),
                accepted: Some(*accepted),
            }),
        }
    }

    /// The claim final at `position`'s root cell, routed from the root
    /// authenticated at the position before. Only a claim naming
    /// `K_root(position)` is recognized there, and the key is a hash of
    /// `(G, DevID, position)`, so the claim that holds the cell is this
    /// peer's at this position; any other bytes count as nothing, however
    /// early they arrived.
    fn final_claim(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        previous: &ValidatedEconomicRoot,
    ) -> Result<RegisteredEconomicClaim, PeerLineageFailure> {
        let cell = RootCell::new(
            genesis,
            device_id,
            position,
            &previous.economic_root(),
            &self.register.set,
            &self.register.profile.storage_set_id,
        )
        .map_err(|e| incomplete(format!("root cell at {position}: {e:?}")))?;
        let evidence = self.fetcher.register_cell(&cell)?;
        match read_root_cell(&cell, &evidence) {
            Ok(CellReading::Held {
                object,
                state: ChainState::Final,
                ..
            }) => Ok(object),
            Ok(CellReading::Held {
                state: ChainState::LeaderHeld | ChainState::Preserved,
                ..
            }) => Err(incomplete(format!(
                "position {position}: the claim holding the root cell is not final yet"
            ))),
            Ok(CellReading::Open) => Err(incomplete(format!(
                "position {position}: no claim holds the root cell"
            ))),
            Err(missing) => Err(incomplete(format!(
                "position {position}: the root cell is not decided yet: {missing:?}"
            ))),
        }
    }

    /// Authenticate a single-root claim: its manifest by content address,
    /// its key the AK the manifest's authority evidence proves (P0–P6), and
    /// its register set the canonical set of the peer's committed network,
    /// which must be the network being verified.
    fn authenticate(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        claim: &VerifiedEconomicRootClaim,
    ) -> Result<Authenticated, PeerLineageFailure> {
        let body = claim.body();
        let manifest_bytes = self.fetcher.immutable(
            TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
            &body.admission_manifest_addr,
        )?;
        let manifest = decode_admission_manifest(&manifest_bytes)
            .map_err(|e| invalid(format!("manifest at {position}: {e}")))?;
        let manifest_addr = manifest
            .addr()
            .map_err(|e| invalid(format!("manifest addr: {e}")))?;
        if manifest_addr != body.admission_manifest_addr {
            return Err(invalid("manifest bytes do not address-match the claim"));
        }
        let authority_bytes = self.fetcher.immutable(
            TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
            &manifest.authority_evidence_addr,
        )?;
        let facts = verify_authority_evidence(
            &authority_bytes,
            genesis,
            device_id,
            &manifest.authority_position,
        )
        .map_err(|e| match e {
            AuthorityEvidenceError::Incomplete(m) => incomplete(m),
            other => invalid(other.to_string()),
        })?;
        // The committed network must be the one being verified, and the
        // register set the claim binds must be that network's canonical set —
        // never sourced from transfer metadata or contacts. The pinned id
        // covers every `(member, incarnation)` pair, so a claim written under
        // a member's old incarnation does not name it.
        let trader_profile = resolve_for_trader(&facts.network_id, self.expected_network_id)
            .map_err(|e| invalid(format!("peer network refused: {e}")))?;
        if body.root_register_storage_set_id != trader_profile.storage_set_id {
            return Err(invalid(
                "claim binds a register set that is not the canonical set of the peer's \
                 committed network",
            ));
        }
        // The claim's key IS the proven AK — storage attribution is not the
        // cryptographic binding.
        if body.claimant_public_key != facts.proven_ak {
            return Err(invalid(
                "register claim is signed by a key that is not the P0–P6-proven AK",
            ));
        }
        Ok(Authenticated {
            manifest,
            manifest_addr,
            facts,
        })
    }

    /// A conditional position inside a chain: the resolver derives the root
    /// it selected, and the chain continues from it. At the activation root
    /// no claim was accepted, so no presentation can name a parent there and
    /// a conditional position there is `Invalid`.
    fn conditional_position(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        point: &ChainPoint,
        held: &SofiResolutionClaim,
    ) -> Result<ChainPoint, PeerLineageFailure> {
        let (root, _) = self.resolve_conditional(genesis, device_id, position, point, held)?;
        Ok(ChainPoint {
            root,
            accepted: Some(ParentClaimRef::Conditional {
                fulfillment_id: held.fulfillment_id,
            }),
        })
    }

    /// The root a conditional position selected and the claim accepted
    /// there, as the resolver derives them, held to this position of this
    /// peer.
    fn resolve_conditional(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        point: &ChainPoint,
        held: &SofiResolutionClaim,
    ) -> Result<(ValidatedEconomicRoot, AcceptedClaim), PeerLineageFailure> {
        let parent = point.accepted.as_ref().ok_or_else(|| {
            invalid(format!(
                "position {position}: a conditional position cannot follow the activation root, \
                 where no claim was accepted for it to name as its parent"
            ))
        })?;
        let (root, accepted) = self
            .conditional
            .resolve(&point.root, parent, held)
            .map_err(|failure| at_position(position, failure))?;
        if root.economic_position() != position
            || accepted.economic_position() != position
            || accepted.genesis() != *genesis
            || accepted.device_id() != *device_id
        {
            return Err(invalid(format!(
                "position {position}: the conditional resolution answered for another coordinate \
                 (root at {}, claim of {}/{} at {})",
                root.economic_position(),
                encode_base32_crockford(&accepted.genesis()),
                encode_base32_crockford(&accepted.device_id()),
                accepted.economic_position()
            )));
        }
        Ok((root, accepted))
    }

    /// One step validated in full from its own evidence: the transition that
    /// produced the registered root, against its authenticated parent, with
    /// the SAME conjuncts any device runs.
    fn full_step(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        point: &ChainPoint,
        claim: &VerifiedEconomicRootClaim,
        role: StepRole,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let Authenticated {
            manifest,
            manifest_addr,
            facts,
        } = self.authenticate(genesis, device_id, position, claim)?;
        let witness_bytes = self.fetcher.immutable(
            TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
            &manifest.transition_witness_addr,
        )?;
        let witness = crate::economic::decode::decode_transition_witness(&witness_bytes)
            .map_err(|e| invalid(format!("witness at {position}: {e}")))?;
        let successor_addr = match &manifest.substrate {
            AdmissionSubstrate::DsmSuccessor { evidence_addr } => *evidence_addr,
            AdmissionSubstrate::OfflineBoundary { .. } => {
                return Err(invalid(
                    "offline-boundary admissions have no specified write-set semantics yet",
                ))
            }
        };
        let successor_bytes = self
            .fetcher
            .immutable(TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, &successor_addr)?;
        let verified =
            verify_dsm_successor_evidence(&successor_bytes, genesis, device_id, &facts.proven_ak)
                .map_err(|e| invalid(format!("successor evidence at {position}: {e}")))?;
        if let StepRole::Source = role {
            // A credit's source is a peer's online transfer, and only its own
            // step is validated here. Its write set is a debit and names no
            // credit source, so nothing behind it is asked for.
            if !matches!(
                verified.operation,
                crate::types::operations::Operation::Transfer {
                    authority_policy: None,
                    ..
                }
            ) {
                return Err(invalid(format!(
                    "position {position}: the credit's source is not an online transfer"
                )));
            }
        }
        let accepted = AcceptedSubstrate::from_verified_dsm_successor(
            verified.operation.clone(),
            verified.c_dsm_plus,
            verified.embedded_parent,
            successor_addr,
        );
        let registered = RegisteredEconomicRoot::from_verified_single_root(claim);
        let ancestry = SourceAncestry { verifier: self };
        let no_sources = DebitHasNoSources { verifier: self };
        let provenance: &dyn ProvenanceResolver = match role {
            StepRole::Segment => &ancestry,
            StepRole::Source => &no_sources,
        };
        let advanced = advance_validated(
            &point.root,
            &registered,
            &manifest,
            &witness,
            &accepted,
            provenance,
            genesis,
            device_id,
            &facts.network_id,
            &facts.proven_ak,
        )
        .map_err(|e| step_failure(position, e))?;
        Ok(ValidatedPeerTransition::single_root_from_walk(
            *genesis,
            *device_id,
            advanced.root,
            witness,
            facts.proven_ak,
            verified.c_dsm_plus,
            verified.embedded_parent,
            verified.operation,
            manifest_addr,
            advanced.claim,
        ))
    }

    /// The payer's segment: every step from this receiver's frontier to
    /// `target`, each validated from its own evidence, and the target's
    /// validated transition.
    fn segment(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        target: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let frontier = self.frontier_below(genesis, device_id, target)?;
        let point = self.chain_through(genesis, device_id, &frontier, target - 1)?;
        self.spend_step()?;
        let claim = self.final_claim(genesis, device_id, target, &point.root)?;
        // The target is the step being presented, and a conditional position
        // selects no root by its bytes: the peer is mid-route, not forging.
        let claim = claim.single_root().map_err(|conditional| {
            PeerLineageFailure::Unresolved(format!(
                "peer {}/{} at position {target}: {conditional}",
                encode_base32_crockford(genesis),
                encode_base32_crockford(device_id)
            ))
        })?;
        self.full_step(genesis, device_id, target, &point, claim, StepRole::Segment)
    }

    /// The chain from `frontier` through `through`, inclusive: each position
    /// validated in full from its own evidence as a segment step, and a
    /// conditional one resolved by `conditional`. One budget step per
    /// position.
    fn chain_through(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        frontier: &PeerFrontier,
        through: u64,
    ) -> Result<ChainPoint, PeerLineageFailure> {
        let mut point = self.start(frontier)?;
        for position in frontier.economic_position() + 1..=through {
            self.spend_step()?;
            point = match self.final_claim(genesis, device_id, position, &point.root)? {
                RegisteredEconomicClaim::SingleRoot(claim) => {
                    let step = self.full_step(
                        genesis,
                        device_id,
                        position,
                        &point,
                        &claim,
                        StepRole::Segment,
                    )?;
                    // Every step from the frontier to here has passed: a
                    // later walk of this identity in this verification
                    // starts here, not behind it.
                    self.validated_step(&step);
                    ChainPoint {
                        root: *step.validated_root(),
                        accepted: Some(ParentClaimRef::SingleRoot {
                            claim_ref: step.accepted_claim().claim_ref(),
                        }),
                    }
                }
                RegisteredEconomicClaim::ConditionalSofi(held) => {
                    self.conditional_position(genesis, device_id, position, &point, &held)?
                }
            };
        }
        Ok(point)
    }

    /// A credit's source, held to account (DSM Amendment A8 as corrected for
    /// sources, owner 2026-10-01): the source's own segment from this
    /// receiver's frontier for it to the position before, every step
    /// validated in full from its own evidence exactly as a payer's segment
    /// is (`chain_through`, whose credits' sources are held to account the
    /// same way), then the source step itself.
    ///
    /// A root the source merely registered is not thereby valid: "admitted"
    /// means only that the source signed it, so a source walked by root
    /// claims alone could invent a root and pay out of it through a second
    /// wallet of its own. The walk stops at a frontier this receiver already
    /// validated, and when the ancestry exceeds the budget before reaching
    /// one it is `Incomplete`, never accepted on weaker evidence.
    fn source_step(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        if position == 0 {
            return Err(invalid(
                "position 0 is the activation root; it holds no debit to fund a credit",
            ));
        }
        if let Some(known) = self.validated_source(genesis, device_id, position) {
            if let Some(reached) = PeerFrontier::reached_by(&known) {
                self.sources_reached.borrow_mut().push(reached);
            }
            return Ok(known);
        }
        let frontier = self.frontier_below(genesis, device_id, position)?;
        let point = self.chain_through(genesis, device_id, &frontier, position - 1)?;
        self.spend_step()?;
        let source = match self.final_claim(genesis, device_id, position, &point.root)? {
            RegisteredEconomicClaim::SingleRoot(claim) => self.full_step(
                genesis,
                device_id,
                position,
                &point,
                &claim,
                StepRole::Source,
            )?,
            RegisteredEconomicClaim::ConditionalSofi(_) => {
                return Err(invalid(format!(
                    "position {position}: the credit's source is a conditional SoFi position, \
                     not an online transfer"
                )))
            }
        };
        // The whole segment to the source step has passed: its coordinate is
        // a frontier for the rest of this walk, and for the receiver once it
        // accepts the target.
        if let Some(reached) = PeerFrontier::reached_by(&source) {
            self.sources_reached.borrow_mut().push(reached);
        }
        self.validated_step(&source);
        Ok(source)
    }
}

/// A root this verifier authenticated at `position`: its recorded frontier,
/// whose whole segment it validated before recording it (DSM Amendment A8).
/// Never a root read from a network, and never a peer's word.
fn authenticated_root(position: u64, root: [u8; 32]) -> ValidatedEconomicRoot {
    ValidatedEconomicRoot::from_verifier_memo(position, root)
}

/// The provenance of a segment step's credits: each source validated
/// through its own segment, back to a frontier this verifier holds.
struct SourceAncestry<'v, 'a> {
    verifier: &'v Verifier<'a>,
}

/// The provenance of a credit's source step. That step is an online transfer,
/// whose write set is a debit: it names no credit source, so a question about
/// one means the step claims a credit an online transfer does not carry.
struct DebitHasNoSources<'v, 'a> {
    verifier: &'v Verifier<'a>,
}

impl ProvenanceResolver for SourceAncestry<'_, '_> {
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        self.verifier
            .source_step(peer_genesis, peer_devid, peer_economic_position)
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.verifier
            .fetcher
            .native_reserve_release(reserve_id, generation)
    }

    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
        self.verifier
            .fetcher
            .root_register_candidate_set(network_id)
    }

    fn immutable_evidence(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.immutable(namespace, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.anchored_policy_bytes(policy_commit)
    }
}

impl ProvenanceResolver for DebitHasNoSources<'_, '_> {
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        Err(invalid(format!(
            "an online transfer's step names a credit funded by {}/{} at position \
             {peer_economic_position}; its write set is a debit and carries no credit",
            encode_base32_crockford(peer_genesis),
            encode_base32_crockford(peer_devid),
        )))
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        Err(invalid(format!(
            "an online transfer's step names a credit from reserve {} at generation \
             {generation}; its write set is a debit and carries no credit",
            encode_base32_crockford(reserve_id),
        )))
    }

    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
        self.verifier
            .fetcher
            .root_register_candidate_set(network_id)
    }

    fn immutable_evidence(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.immutable(namespace, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.anchored_policy_bytes(policy_commit)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;

    use crate::economic::claim_envelope::device_fixture::{device, signed_conditional, Device};

    const PEER_G: [u8; 32] = [0x11; 32];

    /// The peer device: its id is derived from its key and AttA, so the
    /// claims it signs name its own cells (DSM Amendment A10).
    fn peer() -> &'static Device {
        static PEER: std::sync::OnceLock<Device> = std::sync::OnceLock::new();
        PEER.get_or_init(|| device([0xA7; 32]).expect("the peer device"))
    }

    fn peer_d() -> [u8; 32] {
        peer().devid
    }

    /// `claim` as the peer's root cell holds it: signed by the peer device
    /// (SoFi Amendment S20).
    fn peer_c_q(claim: SofiResolutionClaim) -> Vec<u8> {
        signed_conditional(claim, peer()).expect("the peer signs its own C_q")
    }
    const NETWORK: &[u8] = b"dsm-testnet";

    /// A fetcher over the network's pinned register set that serves one root
    /// cell, the one at `position`, holding `writes` written along the cell's
    /// route in order, each through route position `last`. The leader of every other
    /// root cell answers holding nothing. Every other capability refuses,
    /// because none of them should be reached: the walk has to stop at the
    /// claim.
    struct ConditionalCellFetcher {
        position: u64,
        writes: Vec<Vec<u8>>,
        last: usize,
    }

    impl PeerEvidenceFetcher for ConditionalCellFetcher {
        fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
            let mut seats = crate::route_chain::fixtures::Cell::at(cell.routed());
            if cell.economic_position() == self.position {
                for value in &self.writes {
                    seats.write(value, self.last, &[]);
                }
            }
            Ok(seats.evidence())
        }
        fn native_reserve_release(
            &self,
            reserve_id: &[u8; 32],
            generation: u64,
        ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(format!(
                "no reserve release in this test: {} at {generation}",
                encode_base32_crockford(reserve_id)
            )))
        }
        fn root_register_candidate_set(
            &self,
            network_id: &[u8],
        ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
            let pinned = crate::economic::register::pinned_root_register_members(network_id)
                .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))?;
            crate::ccb::StorageSetMembers::new(pinned)
                .map_err(|e| PeerLineageFailure::Incomplete(format!("{e:?}")))
        }
        fn immutable(
            &self,
            namespace: TaggedHashDomain<'static>,
            addr: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(format!(
                "no objects in this test: {} under {:?}",
                encode_base32_crockford(addr),
                namespace.source_bytes()
            )))
        }
        fn anchored_policy_bytes(
            &self,
            policy_commit: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(format!(
                "no policies in this test: {}",
                encode_base32_crockford(policy_commit)
            )))
        }
    }

    /// This test's frontier store: one recorded coordinate, the position
    /// before the cell under test.
    struct Recorded(PeerFrontier);

    impl Recorded {
        fn below(position: u64) -> Self {
            Self(PeerFrontier::rehydrate_recorded(
                PEER_G,
                peer_d(),
                position - 1,
                [0x77; 32],
                ParentClaimRef::SingleRoot {
                    claim_ref: [0x78; 32],
                },
            ))
        }
    }

    impl PeerFrontiers for Recorded {
        fn frontier_below(
            &self,
            _genesis: &[u8; 32],
            _device_id: &[u8; 32],
            _position: u64,
        ) -> Result<Option<PeerFrontier>, PeerLineageFailure> {
            Ok(Some(self.0.clone()))
        }

        /// These receivers keep nothing past a walk.
        fn validated(&self, _frontier: &PeerFrontier) {}
    }

    /// A receiver that has recorded nothing of this peer.
    struct NoneRecorded;

    impl PeerFrontiers for NoneRecorded {
        fn frontier_below(
            &self,
            _genesis: &[u8; 32],
            _device_id: &[u8; 32],
            _position: u64,
        ) -> Result<Option<PeerFrontier>, PeerLineageFailure> {
            Ok(None)
        }

        /// These receivers keep nothing past a walk.
        fn validated(&self, _frontier: &PeerFrontier) {}
    }

    /// No conditional position is resolved in these tests: every one of them
    /// stops before a resolver would be reached.
    struct NoResolution;

    impl ConditionalPositionResolver for NoResolution {
        fn resolve(
            &self,
            previous: &ValidatedEconomicRoot,
            _parent: &ParentClaimRef,
            held: &SofiResolutionClaim,
        ) -> Result<(ValidatedEconomicRoot, AcceptedClaim), PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(format!(
                "no conditional resolution in this test: position {} after {}",
                held.position,
                previous.economic_position()
            )))
        }
    }

    fn conditional_claim(position: u64) -> SofiResolutionClaim {
        SofiResolutionClaim {
            genesis: PEER_G,
            device_id: peer_d(),
            position,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        }
    }

    /// The fetcher a test hands the walk, counting every read of the peer it
    /// is asked for: root cells, objects, reserve releases and policies. The
    /// register's candidate set is the network's, not the peer's, and is not
    /// counted.
    struct CountingCells {
        inner: ConditionalCellFetcher,
        reads: std::cell::Cell<usize>,
    }

    impl CountingCells {
        fn read(&self) {
            self.reads.set(self.reads.get() + 1);
        }
    }

    impl PeerEvidenceFetcher for CountingCells {
        fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
            self.read();
            self.inner.register_cell(cell)
        }
        fn native_reserve_release(
            &self,
            reserve_id: &[u8; 32],
            generation: u64,
        ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
            self.read();
            self.inner.native_reserve_release(reserve_id, generation)
        }
        fn root_register_candidate_set(
            &self,
            network_id: &[u8],
        ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
            self.inner.root_register_candidate_set(network_id)
        }
        fn immutable(
            &self,
            namespace: TaggedHashDomain<'static>,
            addr: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            self.read();
            self.inner.immutable(namespace, addr)
        }
        fn anchored_policy_bytes(
            &self,
            policy_commit: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            self.read();
            self.inner.anchored_policy_bytes(policy_commit)
        }
    }

    /// Owner ruling 2026-10-01 (pre-audit item 3): a credit's source whose
    /// ancestry exceeds the walk budget before reaching a frontier this
    /// verifier holds is `Incomplete`, never accepted on weaker evidence, and
    /// nothing past the spent budget is read.
    #[test]
    fn a_source_walk_past_the_budget_is_incomplete_and_reads_nothing() {
        let fetcher = CountingCells {
            inner: ConditionalCellFetcher {
                position: 3,
                writes: Vec::new(),
                last: crate::route_chain::ROUTE_LEN - 1,
            },
            reads: std::cell::Cell::new(0),
        };
        let verifier = Verifier {
            fetcher: &fetcher,
            expected_network_id: NETWORK,
            register: Register::resolve(&fetcher, NETWORK).expect("the network's register"),
            frontiers: &NoneRecorded,
            conditional: &NoResolution,
            steps_remaining: std::cell::Cell::new(0),
            sources_reached: std::cell::RefCell::new(Vec::new()),
            walked: std::cell::RefCell::new(Vec::new()),
            steps: std::cell::RefCell::new(std::collections::BTreeMap::new()),
        };
        match verifier.source_step(&PEER_G, &peer_d(), 3) {
            Err(PeerLineageFailure::Incomplete(why)) => {
                assert!(why.contains("budget exhausted"), "{why}")
            }
            Err(other) => panic!("a spent budget is Incomplete, got {other:?}"),
            Ok(_) => panic!("a spent budget validated a source"),
        }
        assert_eq!(fetcher.reads.get(), 0, "nothing of the source was read");
    }

    /// DSM Amendment A8, `peer_root_at`: a frontier this receiver recorded AT
    /// the position is the answer, and nothing of the peer is read: the walk
    /// stands below `position + 1`, which the recorded frontier already is. A
    /// frontier is recorded only as `reached_by` records one, single-root.
    #[test]
    fn a_frontier_recorded_at_the_position_is_its_root_and_nothing_is_read() {
        let position = 6;
        let accepted = ParentClaimRef::SingleRoot {
            claim_ref: [0xF6; 32],
        };
        let recorded = Recorded(PeerFrontier::rehydrate_recorded(
            PEER_G,
            peer_d(),
            position,
            [0x66; 32],
            accepted,
        ));
        let fetcher = CountingCells {
            inner: ConditionalCellFetcher {
                position,
                writes: vec![peer_c_q(conditional_claim(position))],
                last: crate::route_chain::ROUTE_LEN - 1,
            },
            reads: std::cell::Cell::new(0),
        };
        let (root, named) = peer_root_at(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &recorded,
            &NoResolution,
        )
        .expect("the recorded point");
        assert_eq!(
            (root.economic_position(), root.economic_root(), named),
            (position, [0x66; 32], accepted)
        );
        assert_eq!(fetcher.reads.get(), 0, "nothing of the peer was read");
    }

    /// `peer_root_at` at position 0 is the activation root, where no claim was
    /// accepted: no `P` can name it as a parent, so it is `Invalid`, and no
    /// reference is made up for it.
    #[test]
    fn the_activation_root_names_no_parent() {
        let fetcher = ConditionalCellFetcher {
            position: 0,
            writes: Vec::new(),
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        match peer_root_at(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            0,
            &NoneRecorded,
            &NoResolution,
        ) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("activation root"), "{why}")
            }
            other => panic!("position 0 is Invalid, not {other:?}"),
        }
    }

    /// A CONDITIONAL PEER POSITION IS `Unresolved`, NOT `Invalid`.
    ///
    /// Before the union existed, the single-root decoder failed on these bytes
    /// and the walk mapped that failure to `Invalid` — i.e. to *authenticated
    /// forgery*, which is terminal and quarantining. Every honest counterparty
    /// that ever exercised a route would have been permanently refused by
    /// every peer, as a fraud, for being mid-route.
    #[test]
    fn a_conditional_peer_position_is_unresolved_and_never_invalid() {
        let position = 4;
        let fetcher = ConditionalCellFetcher {
            position,
            writes: vec![peer_c_q(conditional_claim(position))],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        let err = validate_peer_lineage(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &Recorded::below(position),
            &NoResolution,
        )
        .expect_err("a conditional position cannot produce a validated transition");

        match &err {
            PeerLineageFailure::Unresolved(m) => {
                assert!(
                    m.contains("commits two roots and has selected neither"),
                    "the refusal must say what it is waiting on, got: {m}"
                );
            }
            other => panic!("a conditional position must be Unresolved, got {other:?}"),
        }
        // The distinction is the whole point: not a forgery, not a quarantine,
        // and not a fetch that might succeed on retry.
        assert!(!matches!(err, PeerLineageFailure::Invalid(_)));
        assert!(!matches!(err, PeerLineageFailure::Quarantined(_)));
        assert!(!matches!(err, PeerLineageFailure::Incomplete(_)));
    }

    /// SoFi Amendment S15, MR-SOFI-0347: a setup made right after a SoFi
    /// position names the claim that position's resolution accepted, so the
    /// claim at a conditional position is asked of the resolver, never
    /// refused as a payer's conditional target is. With no resolution in
    /// hand the answer is the resolver's own, in its class.
    #[test]
    fn the_claim_at_a_conditional_position_is_asked_of_its_resolution() {
        let position = 4;
        let fetcher = ConditionalCellFetcher {
            position,
            writes: vec![peer_c_q(conditional_claim(position))],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        match peer_claim_at(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &Recorded::below(position),
            &NoResolution,
        ) {
            Err(PeerLineageFailure::Incomplete(why)) => {
                assert!(why.contains("no conditional resolution"), "{why}")
            }
            other => panic!("the resolver answers for a conditional position, not {other:?}"),
        }
    }

    /// A claim naming other coordinates never holds the root cell (storage
    /// spec §9 rule 3): only a claim whose own coordinates derive `K_root(q)`
    /// is recognized there, so a foreign claim written first blocks nothing,
    /// and a cell holding only foreign claims is open.
    #[test]
    fn a_claim_naming_other_coordinates_never_holds_the_root_cell() {
        let position = 3;
        let other = device([0x5A; 32]).expect("another device");
        let foreign = SofiResolutionClaim {
            genesis: [0x99; 32],
            device_id: other.devid,
            position,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        };
        let ours = SofiResolutionClaim {
            genesis: PEER_G,
            device_id: peer_d(),
            ..foreign
        };
        let walk = |writes: Vec<Vec<u8>>| {
            validate_peer_lineage(
                &ConditionalCellFetcher {
                    position,
                    writes,
                    last: crate::route_chain::ROUTE_LEN - 1,
                },
                NETWORK,
                &PEER_G,
                &peer_d(),
                position,
                &Recorded::below(position),
                &NoResolution,
            )
        };
        assert!(
            matches!(
                walk(vec![signed_conditional(foreign, &other).expect("its own C_q")]),
                Err(PeerLineageFailure::Incomplete(ref m)) if m.contains("no claim holds")
            ),
            "a cell holding only a foreign claim is open"
        );
        assert!(
            matches!(
                walk(vec![
                    signed_conditional(foreign, &other).expect("its own C_q"),
                    peer_c_q(ours),
                ]),
                Err(PeerLineageFailure::Unresolved(_))
            ),
            "the foreign claim first at the leader does not stop this trader's claim"
        );
    }

    /// Only a FINAL claim is read (storage spec §9 finality 3): a claim that
    /// holds the leader link, with fewer than two further links, decides
    /// nothing yet.
    #[test]
    fn a_claim_that_is_not_final_decides_nothing_yet() {
        let position = 2;
        for last in [0, 1] {
            let fetcher = ConditionalCellFetcher {
                position,
                writes: vec![peer_c_q(conditional_claim(position))],
                last,
            };
            let outcome = validate_peer_lineage(
                &fetcher,
                NETWORK,
                &PEER_G,
                &peer_d(),
                position,
                &Recorded::below(position),
                &NoResolution,
            );
            assert!(
                matches!(outcome, Err(PeerLineageFailure::Incomplete(ref m)) if m.contains("not final yet")),
                "written through position {last}: {outcome:?}"
            );
        }
    }

    /// A failure met below a step keeps its class: evidence that could not
    /// be established is retried, and only evidence that verified as wrong is
    /// `Invalid` (storage spec §4).
    #[test]
    fn a_step_failure_keeps_the_class_it_was_established_in() {
        use crate::economic::provenance::ProvenanceError as P;
        let unavailable = |m: &str| PeerLineageFailure::Incomplete(m.to_string());
        let provenance = |p: P| EconomicValidationError::Provenance(p);
        assert!(matches!(
            step_failure(
                3,
                provenance(P::ReleaseNotEstablished {
                    generation: 1,
                    failure: unavailable("the reserve lineage has not reached generation 1"),
                })
            ),
            PeerLineageFailure::Incomplete(_)
        ));
        assert!(matches!(
            step_failure(
                3,
                provenance(P::PeerTransitionNotValidated {
                    peer_economic_position: 2,
                    failure: PeerLineageFailure::Unresolved("mid-route".into()),
                })
            ),
            PeerLineageFailure::Unresolved(_)
        ));
        assert!(matches!(
            step_failure(
                3,
                provenance(P::OwnerLineage(unavailable("no member answered")))
            ),
            PeerLineageFailure::Incomplete(_)
        ));
        assert!(matches!(
            step_failure(
                3,
                provenance(P::RegisterNotEstablished(unavailable(
                    "the catalog could not be read"
                )))
            ),
            PeerLineageFailure::Incomplete(_)
        ));
        assert!(matches!(
            step_failure(
                3,
                provenance(P::AmountMismatch {
                    source: 1,
                    credit: 2
                })
            ),
            PeerLineageFailure::Invalid(_)
        ));
        assert!(matches!(
            step_failure(
                3,
                EconomicValidationError::RegisteredClaimNamesAnotherTrader
            ),
            PeerLineageFailure::Invalid(_)
        ));
    }

    /// NO PATH from a conditional cell to a validated root. The walk is the
    /// only way a foreign position becomes a `ValidatedEconomicRoot`, and it
    /// refuses — so neither branch of an unresolved `C_q` can be minted, and
    /// no `ValidatedPeerTransition` exists to carry one downstream.
    #[test]
    fn no_validated_root_is_minted_from_either_branch_of_an_unresolved_claim() {
        let position = 2;
        let claim = conditional_claim(position);
        let fetcher = ConditionalCellFetcher {
            position,
            writes: vec![peer_c_q(claim)],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        let outcome = validate_peer_lineage(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &Recorded::below(position),
            &NoResolution,
        );
        let err = outcome.expect_err("no validated transition");
        // Neither of the two committed roots appears in the refusal, because
        // nothing selected one. A message quoting `realize_root` would mean
        // some code path had already read it as "the" root.
        let rendered = err.to_string();
        for (name, root) in [
            ("realize_root", claim.realize_root),
            ("void_root", claim.void_root),
        ] {
            let b32 = crate::utils::text_id::encode_base32_crockford(&root);
            assert!(
                !rendered.contains(&b32),
                "{name} leaked into the refusal: {rendered}"
            );
        }
    }

    /// No claim is accepted at the activation root, so nothing can name it
    /// as a parent: a conditional position right after it is `Invalid`, and
    /// the resolver is never asked (DSM Amendment A8; SoFi S9, every leg
    /// follows a setup the trader registered).
    #[test]
    fn a_conditional_position_right_after_the_activation_root_is_invalid() {
        let fetcher = ConditionalCellFetcher {
            position: 1,
            writes: vec![peer_c_q(conditional_claim(1))],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        let outcome = validate_peer_lineage(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            2,
            &NoneRecorded,
            &NoResolution,
        );
        assert!(
            matches!(outcome, Err(PeerLineageFailure::Invalid(ref m)) if m.contains("cannot follow the activation root")),
            "{outcome:?}"
        );
    }

    /// A frontier store that answers at or past the target has decided
    /// nothing about the peer: the verification reads no cell and says the
    /// fault is its own.
    #[test]
    fn a_frontier_at_the_target_is_this_verifiers_fault_not_the_peers() {
        let position = 3;
        let fetcher = ConditionalCellFetcher {
            position,
            writes: vec![peer_c_q(conditional_claim(position))],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        let outcome = validate_peer_lineage(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position - 1,
            &Recorded::below(position),
            &NoResolution,
        );
        assert!(
            matches!(outcome, Err(PeerLineageFailure::Incomplete(ref m)) if m.contains("the frontier store answered")),
            "{outcome:?}"
        );
    }
}
