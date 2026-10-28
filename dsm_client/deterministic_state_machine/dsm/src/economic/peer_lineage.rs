// SPDX-License-Identifier: Apache-2.0

//! The foreign lineage verifier, frontier-relative (DSM Amendment A19,
//! restoring Amendment A8).
//!
//! A receiver accepts a peer's step only from a root it validated itself. It
//! starts at its own frontier for the peer: the last coordinate it validated,
//! or the peer's activation root where it holds none. For each position from
//! there to the target it:
//!
//! 1. reads the claim final at the register cell derived from
//!    `(G, DevID, position)` and the root it validated at the position
//!    before. The root a claim's own witness names is never the parent: it
//!    must equal the validated root, or `advance_validated` refuses the step;
//! 2. authenticates the claim: its manifest by content address, its key the
//!    AK the manifest's authority evidence proves (P0–P6), its register set
//!    the canonical set of the committed network;
//! 3. validates the transition that produced the root against that parent,
//!    with the SAME `advance_validated` any device runs.
//!
//! A payer's software can build a valid step on a root it invented and
//! register it, because a claim is self-signed and the register keeps what is
//! written first (audit finding SA-02). Read from the receiver's own
//! frontier, that step is not on the chain: the cell routed from the root the
//! receiver validated holds no claim, or a claim whose witness names another
//! root, and nothing is accepted.
//!
//! A receiver current with a peer walks one position per payment. Every
//! position spends from one budget for the whole verification, and a budget
//! that runs out is `Incomplete`, held and retried, never accepted.
//!
//! ## Sources
//!
//! A credit's source is held to account like a payer (Amendment A8 for
//! credit sources, owner 2026-10-01): its own segment from this verifier's
//! frontier for it is validated step by step, its credits' sources the same
//! way. The source step itself is an online transfer, a debit, so nothing
//! further is asked of it. Each source's coordinate reached is reported, for
//! the receiver to record with the acceptance.
//!
//! ## Conditional positions
//!
//! A position whose claim is conditional (`C_q`) selects no root by its
//! bytes. Inside a chain, the [`ConditionalPositionResolver`] derives the root
//! it selected from SoFi's public objects for that position alone (SoFi
//! Amendment S15), and the chain continues from it.

use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
    TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE, TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE,
    TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
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
    PeerLineageFailure, PeerSubstrate, ProvenanceResolver, ReserveReleaseWin,
    ValidatedPeerTransition,
};
use crate::economic::register::{
    read_root_cell, resolve_for_trader, resolve_root_register_profile, RegisteredEconomicRoot,
    RootCell, RootRegisterProfile,
};
use crate::economic::successor_evidence::verify_dsm_successor_evidence;
use crate::route_chain::{CellEvidence, CellReading, ChainState};
use crate::sofi::wire::{ParentClaimRef, SofiResolutionClaim};
use crate::utils::text_id::encode_base32_crockford;

/// The step budget for one verification, across every identity it touches:
/// the payer's segment and each credit source's.
pub const WALK_STEP_BUDGET: u32 = 512;

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
    /// The certified key of the EK step at `addr` in `signer`'s chain, when
    /// this verifier is a party to that relationship and holds the step.
    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure>;
    /// The canonical `TokenPolicyV3` bytes rooted under `policy_commit` —
    /// the verifier's own anchoring (local store or the authoritative
    /// content-addressed path). The verifier re-hashes against the commit;
    /// unavailable is `Incomplete`, never `Invalid`.
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
}

/// A coordinate of a peer this verifier validated itself: its frontier for
/// that peer (DSM Amendments A8, A19).
///
/// Either the peer's activation root, which every verifier derives without
/// being told it, or a coordinate a verification reached and the receiver
/// recorded. A root the peer merely claims is never a frontier: the fields
/// are private, and the only constructor from outside this module rehydrates
/// what the receiver recorded.
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
    /// A position the receiver validated, the root it validated there and
    /// the claim it accepted there.
    Recorded {
        economic_position: u64,
        economic_root: [u8; 32],
        accepted: Accepted,
    },
}

/// The claim a verifier accepted at a coordinate: the reference a later `P`
/// names it by as a parent, and `ClaimRef_p`, the digest of the claim Core
/// accepted there (SoFi §16), which a setup at that position is checked
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Accepted {
    parent: ParentClaimRef,
    claim_ref: [u8; 32],
}

impl PeerFrontier {
    /// The peer's activation root: the frontier of a receiver that has
    /// validated nothing of this peer.
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
                    accepted: Accepted {
                        parent: ParentClaimRef::SingleRoot {
                            claim_ref: transition.accepted_claim().claim_ref(),
                        },
                        claim_ref: transition.accepted_claim().claim_ref(),
                    },
                },
            }),
            ValidatedPeerTransition::ResolvedSofi(_) => None,
        }
    }

    /// The coordinate a chain this verifier walked stands at.
    fn at_point(genesis: [u8; 32], device_id: [u8; 32], point: &ChainPoint) -> Option<Self> {
        let accepted = point.accepted?;
        Some(Self {
            genesis,
            device_id,
            at: FrontierAt::Recorded {
                economic_position: point.root.economic_position(),
                economic_root: point.root.economic_root(),
                accepted,
            },
        })
    }

    /// A frontier this device recorded, read back from its own store.
    ///
    /// **Only the receiver's frontier store may call this**, with exactly
    /// the fields of a frontier this module produced and the receiver
    /// recorded. Anything read from a network or taken from a peer is not a
    /// frontier, and feeding it here is the fabrication the private fields
    /// exist to prevent.
    pub fn rehydrate_recorded(
        genesis: [u8; 32],
        device_id: [u8; 32],
        economic_position: u64,
        economic_root: [u8; 32],
        parent: ParentClaimRef,
        claim_ref: [u8; 32],
    ) -> Self {
        Self {
            genesis,
            device_id,
            at: FrontierAt::Recorded {
                economic_position,
                economic_root,
                accepted: Accepted { parent, claim_ref },
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

    /// The recorded coordinate: position, root, the reference a later `P`
    /// names its claim by, and that claim's digest. `None` at the activation
    /// root, which is never recorded.
    pub fn recorded(&self) -> Option<(u64, [u8; 32], &ParentClaimRef, [u8; 32])> {
        match &self.at {
            FrontierAt::Activation => None,
            FrontierAt::Recorded {
                economic_position,
                economic_root,
                accepted,
            } => Some((
                *economic_position,
                *economic_root,
                &accepted.parent,
                accepted.claim_ref,
            )),
        }
    }

    /// The claim this receiver accepted at `position`, when this coordinate
    /// is the one it validated there: answered from what it recorded, so
    /// nothing behind its frontier is read again (DSM Amendments A8, A19;
    /// SoFi Amendment S15).
    fn claim_accepted_at(&self, position: u64) -> Option<AcceptedClaim> {
        match &self.at {
            FrontierAt::Recorded {
                economic_position,
                accepted,
                ..
            } if *economic_position == position => Some(AcceptedClaim::from_validated_coordinate(
                self.genesis,
                self.device_id,
                position,
                accepted.claim_ref,
            )),
            FrontierAt::Activation | FrontierAt::Recorded { .. } => None,
        }
    }
}

/// What a receiver validated itself of a peer's offline account: the account
/// as one of the peer's offline boundaries (a load or an unload) left it, at
/// the economic position of the step that admitted the boundary (the owner's
/// receive rule, 2026-10-22: offline acceptance only trusts what the receiver
/// recorded from the peer's online history).
///
/// The account is named by its anchor bundle `B`, which commits the anchor's
/// identity and keys and the peer's online identity. The fields are private:
/// one is built only from a boundary this module's walk verified, in a step
/// that passed, and the only constructor from outside rehydrates what the
/// receiver recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerOfflineAccount {
    genesis: [u8; 32],
    device_id: [u8; 32],
    economic_position: u64,
    bundle: [u8; 32],
    account_root: [u8; 32],
    funding_chain: [u8; 32],
}

impl PeerOfflineAccount {
    /// The account `boundary` left, validated in the step at `position`.
    fn validated(
        genesis: [u8; 32],
        device_id: [u8; 32],
        position: u64,
        boundary: &crate::economic::offline_boundary::VerifiedOfflineBoundary,
    ) -> Self {
        Self {
            genesis,
            device_id,
            economic_position: position,
            bundle: boundary.bundle(),
            account_root: boundary.post_account_root(),
            funding_chain: boundary.operation_id(),
        }
    }

    /// An offline account this device recorded, read back from its own store.
    ///
    /// **Only the receiver's store may call this**, with exactly the fields of
    /// an account this module produced and the receiver recorded. Anything
    /// read from a network or taken from a peer is not a validated account,
    /// and feeding it here is the fabrication the private fields exist to
    /// prevent.
    pub fn rehydrate_recorded(
        genesis: [u8; 32],
        device_id: [u8; 32],
        economic_position: u64,
        bundle: [u8; 32],
        account_root: [u8; 32],
        funding_chain: [u8; 32],
    ) -> Self {
        Self {
            genesis,
            device_id,
            economic_position,
            bundle,
            account_root,
            funding_chain,
        }
    }

    pub fn genesis(&self) -> &[u8; 32] {
        &self.genesis
    }

    pub fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }

    /// The economic position of the step that admitted the boundary.
    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }

    /// The anchor bundle `B` that names the account.
    pub fn bundle(&self) -> &[u8; 32] {
        &self.bundle
    }

    /// The account's root after the boundary.
    pub fn account_root(&self) -> &[u8; 32] {
        &self.account_root
    }

    /// The account's funding chain after the boundary: the boundary's id.
    pub fn funding_chain(&self) -> &[u8; 32] {
        &self.funding_chain
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

/// What a verification cost: the positions it walked from the receiver's
/// frontiers, the payer's and each credit source's, and the root cells it
/// read. A receiver current with a peer walks one position for its payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepCost {
    /// Positions validated, across every identity the walk touched.
    pub steps_validated: u32,
    /// Routed reads of a root cell.
    pub routed_reads: u32,
    /// Credit sources walked to their source steps.
    pub source_steps: u32,
}

/// An answer about a peer, with what establishing it cost and every frontier
/// the walk established on the way.
///
/// Each frontier stands at the end of a segment that passed whole, from a
/// frontier this receiver held: the walked identity's own last coordinate and
/// each credit source's (owner ruling 2026-10-01: "A frontier becomes trusted
/// only after the complete segment to it has passed validation"). A walk that
/// fails returns none. The receiver records them whatever the walk was for
/// (owner ruling 2026-10-20, Amendment A19: "Record every successfully
/// validated economic frontier, including those reached through read-only
/// operations").
#[derive(Debug)]
pub struct Checked<T> {
    answer: T,
    cost: StepCost,
    reached: Vec<PeerFrontier>,
    offline_accounts: Vec<PeerOfflineAccount>,
}

impl<T> Checked<T> {
    pub fn answer(&self) -> &T {
        &self.answer
    }

    pub fn cost(&self) -> StepCost {
        self.cost
    }

    /// Every frontier this walk established, in the order it established
    /// them.
    pub fn reached(&self) -> &[PeerFrontier] {
        &self.reached
    }

    /// Every offline account this walk validated: what each offline boundary
    /// it passed left, in the order it passed them. Like the frontiers, they
    /// come only from a walk that passed, each from a step that passed whole.
    pub fn offline_accounts(&self) -> &[PeerOfflineAccount] {
        &self.offline_accounts
    }

    pub fn into_answer(self) -> T {
        self.answer
    }
}

/// How far a validation of a peer's lineage reached, walked toward its head
/// (DSM Amendment A19: on a contact add).
#[derive(Debug)]
pub struct ValidatedPrefix {
    reached: Option<PeerFrontier>,
    stop: PrefixStop,
}

/// Why a walk toward a peer's head stopped.
#[derive(Debug)]
pub enum PrefixStop {
    /// The next position's root cell holds no claim: the walk reached the
    /// head the register holds.
    Head,
    /// The walk stopped short, at its budget or on a read not decided yet;
    /// what it validated before stopping stands.
    Short(String),
}

impl ValidatedPrefix {
    /// The peer's coordinate the walk validated last, every position from
    /// the frontier it started at passed; `None` when it validated nothing
    /// past that frontier.
    pub fn reached(&self) -> Option<&PeerFrontier> {
        self.reached.as_ref()
    }

    /// Why the walk stopped.
    pub fn stop(&self) -> &PrefixStop {
        &self.stop
    }
}

/// Verify a peer's lineage from this receiver's frontier to
/// `target_position`: the target step's validated transition (DSM Amendment
/// A19).
///
/// Every step from the frontier to the target is validated from the root the
/// verifier validated before it; a credit's source is validated through its
/// own segment back to a frontier this receiver holds, or one this walk
/// already validated; a conditional position before the target is resolved
/// by `conditional`, and one at the target is `Unresolved`: the peer is
/// mid-route. Nothing behind a frontier is read.
pub fn validate_peer_lineage(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<ValidatedPeerTransition>, PeerLineageFailure> {
    if target_position == 0 {
        return Err(invalid(
            "position 0 is the activation root; it has no transition to validate",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, frontiers, conditional)?;
    let transition = verifier.segment(peer_genesis, peer_devid, target_position)?;
    let own = PeerFrontier::reached_by(&transition);
    Ok(verifier.checked(transition, own))
}

/// Validate a peer's lineage from this receiver's frontier toward its head,
/// as far as the register holds and the budget allows (DSM Amendment A19:
/// on a contact add, so the contact's first payment is one step). Every
/// position validated is validated as a segment step is, sources included.
/// A step that verifies as wrong is `Invalid`; stopping short is not a
/// failure, and what was validated before it stands.
pub fn validate_peer_prefix(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<ValidatedPrefix>, PeerLineageFailure> {
    let verifier = Verifier::new(fetcher, expected_network_id, frontiers, conditional)?;
    let (reached, stop) = verifier.toward_head(peer_genesis, peer_devid)?;
    let own = reached.clone();
    Ok(verifier.checked(ValidatedPrefix { reached, stop }, own))
}

/// The root a peer's lineage selected AT `position`, and the reference a
/// later `P` names that position by (DSM Amendment A19; SoFi Amendment S15):
/// the segment from this receiver's frontier, each step validated in full,
/// with `position` itself resolved through `conditional` when its claim is
/// conditional, exactly as an interior one.
///
/// Not a debit source: it yields no [`ValidatedPeerTransition`]. Position 0
/// is the activation root, where no claim was accepted for a `P` to name, and
/// is `Invalid`. The coordinate at `position` is a frontier like any other the
/// walk reached.
pub fn peer_root_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<(ValidatedEconomicRoot, ParentClaimRef)>, PeerLineageFailure> {
    if position == 0 {
        return Err(invalid(
            "position 0 is the activation root: no claim was accepted there for a P to name as \
             its parent",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, frontiers, conditional)?;
    let below = position.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "position {position} has no successor to stand below"
        ))
    })?;
    let frontier = verifier.frontier_below(peer_genesis, peer_devid, below)?;
    let point = verifier.chain_through(peer_genesis, peer_devid, &frontier, position)?;
    let accepted = point.accepted.map(|a| a.parent).ok_or_else(|| {
        invalid(format!(
            "position {position} is the activation root: no claim was accepted there for a P \
             to name as its parent"
        ))
    })?;
    let own = PeerFrontier::at_point(*peer_genesis, *peer_devid, &point);
    Ok(verifier.checked((point.root, accepted), own))
}

/// The claim a peer's lineage accepted AT `position` (SoFi Amendment S15,
/// MR-SOFI-0347): what a setup naming that position is checked against.
/// When this receiver validated `position` itself, the claim it recorded
/// there answers, and nothing behind its frontier is read again (DSM
/// Amendments A8, A19; MR-SOFI-0346). Otherwise the segment from its
/// frontier below `position` is validated in full as a payer's is, and
/// `position` itself as its last step, or, when its claim is conditional,
/// resolved through `conditional` exactly as an interior position is. The
/// coordinate at `position` is a frontier like any other the walk reached.
pub fn peer_claim_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    frontiers: &dyn PeerFrontiers,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<AcceptedClaim>, PeerLineageFailure> {
    if position == 0 {
        return Err(invalid(
            "position 0 is the activation root: no claim was accepted there",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, frontiers, conditional)?;
    let below = position.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "position {position} has no successor to stand below"
        ))
    })?;
    let frontier = verifier.frontier_below(peer_genesis, peer_devid, below)?;
    if let Some(accepted) = frontier.claim_accepted_at(position) {
        return Ok(verifier.checked(accepted, None));
    }
    let point = verifier.chain_through(peer_genesis, peer_devid, &frontier, position - 1)?;
    verifier.spend_step()?;
    let (accepted, own) =
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
                let (root, accepted) = verifier.resolve_conditional(
                    peer_genesis,
                    peer_devid,
                    position,
                    &point,
                    &held,
                )?;
                let at = ChainPoint {
                    root,
                    accepted: Some(Accepted {
                        parent: ParentClaimRef::Conditional {
                            fulfillment_id: held.fulfillment_id,
                        },
                        claim_ref: accepted.claim_ref(),
                    }),
                };
                (
                    accepted,
                    PeerFrontier::at_point(*peer_genesis, *peer_devid, &at),
                )
            }
        };
    Ok(verifier.checked(accepted, own))
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
            | P::PeerDebitIsNotAnOnlineTransfer
            | P::NotAnOfflineUnload
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
            | P::ReleaseParentNotOnTheReserve(..)
            | P::ReleaseNotTheSuccessor(..)
            | P::ReleaseIsNotTheEstablishedStep { .. }
            | P::ReleaseRecipientMismatch
            | P::ReleaseBindingMismatch
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
        | EconomicValidationError::OfflineBoundaryIdMismatch { .. }
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

/// Where a chain stands: the root this verifier validated at a position, and
/// the claim it accepted there (`None` only at the activation root).
struct ChainPoint {
    root: ValidatedEconomicRoot,
    accepted: Option<Accepted>,
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
    /// A step of a segment from a frontier: its credits' sources are held to
    /// account through their own segments.
    Segment,
    /// A credit's source step: it must be an online transfer, a debit that
    /// names no source of its own.
    Source,
}

/// What a root cell routed from one parent reads (storage spec §9).
enum AtRoute {
    /// This claim is final there, and no other ever will be.
    Final(Box<RegisteredEconomicClaim>),
    /// A claim holds the leader link, short of Final: any party may carry
    /// its chain on (§9 route chains, rule 8), so it can become final.
    Held,
    /// No claim holds the cell.
    Open,
    /// The reads in hand do not decide the cell.
    Undecided(String),
}

struct Verifier<'a> {
    fetcher: &'a dyn PeerEvidenceFetcher,
    expected_network_id: &'a [u8],
    register: Register,
    frontiers: &'a dyn PeerFrontiers,
    conditional: &'a dyn ConditionalPositionResolver,
    /// What this verification has cost so far, counted as it reads.
    cost: std::cell::Cell<StepCost>,
    /// Every frontier this walk established besides the walked identity's own
    /// last coordinate: each position a segment passed through, and each
    /// credit source's segment end, each standing at a step whose whole
    /// segment passed.
    established: std::cell::RefCell<Vec<PeerFrontier>>,
    /// Every offline account a step this walk validated left: each boundary
    /// in a step that passed.
    offline_accounts: std::cell::RefCell<Vec<PeerOfflineAccount>>,
}

impl<'a> Verifier<'a> {
    fn new(
        fetcher: &'a dyn PeerEvidenceFetcher,
        expected_network_id: &'a [u8],
        frontiers: &'a dyn PeerFrontiers,
        conditional: &'a dyn ConditionalPositionResolver,
    ) -> Result<Self, PeerLineageFailure> {
        Ok(Self {
            fetcher,
            expected_network_id,
            register: Register::resolve(fetcher, expected_network_id)?,
            frontiers,
            conditional,
            cost: std::cell::Cell::new(StepCost {
                steps_validated: 0,
                routed_reads: 0,
                source_steps: 0,
            }),
            established: std::cell::RefCell::new(Vec::new()),
            offline_accounts: std::cell::RefCell::new(Vec::new()),
        })
    }
}

impl Verifier<'_> {
    /// `answer`, with what this walk cost and every frontier it established:
    /// `own`, the walked identity's last coordinate, and each source's.
    fn checked<T>(self, answer: T, own: Option<PeerFrontier>) -> Checked<T> {
        let cost = self.cost.get();
        let reached = own
            .into_iter()
            .chain(self.established.into_inner())
            .collect();
        Checked {
            answer,
            cost,
            reached,
            offline_accounts: self.offline_accounts.into_inner(),
        }
    }

    fn count(&self, add: impl FnOnce(&mut StepCost)) {
        let mut cost = self.cost.get();
        add(&mut cost);
        self.cost.set(cost);
    }
    /// What the root cell at `position` routed from `previous` reads: the
    /// cell routed from the root authenticated at the position before. Only
    /// a claim naming `K_root(position)` is recognized there, and the key is
    /// a hash of `(G, DevID, position)`, so the claim that holds the cell is
    /// this peer's at this position; any other bytes count as nothing,
    /// however early they arrived.
    fn at_route(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        previous: &ValidatedEconomicRoot,
    ) -> Result<AtRoute, PeerLineageFailure> {
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
        Ok(match read_root_cell(&cell, &evidence) {
            Ok(CellReading::Held {
                object,
                state: ChainState::Final,
                ..
            }) => AtRoute::Final(Box::new(object)),
            Ok(CellReading::Held {
                state: ChainState::LeaderHeld | ChainState::Preserved,
                ..
            }) => AtRoute::Held,
            Ok(CellReading::Open) => AtRoute::Open,
            Err(missing) => AtRoute::Undecided(format!("{missing:?}")),
        })
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
        let parent = point.accepted.as_ref().map(|a| &a.parent).ok_or_else(|| {
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
        let (accepted, substrate) = match &manifest.substrate {
            AdmissionSubstrate::DsmSuccessor {
                evidence_addr: successor_addr,
            } => {
                let successor_bytes = self
                    .fetcher
                    .immutable(TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, successor_addr)?;
                let verified = verify_dsm_successor_evidence(
                    &successor_bytes,
                    genesis,
                    device_id,
                    &facts.proven_ak,
                )
                .map_err(|e| invalid(format!("successor evidence at {position}: {e}")))?;
                if let StepRole::Source = role {
                    // A credit's source is a peer's online transfer, and only
                    // its own step is validated here. Its write set is a
                    // debit and names no credit source, so nothing behind it
                    // is asked for.
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
                (
                    AcceptedSubstrate::from_verified_dsm_successor(
                        verified.operation.clone(),
                        verified.c_dsm_plus,
                        verified.embedded_parent,
                        *successor_addr,
                    ),
                    PeerSubstrate::Dsm {
                        c_dsm_plus: verified.c_dsm_plus,
                        embedded_parent: verified.embedded_parent,
                        verified_operation: verified.operation,
                    },
                )
            }
            AdmissionSubstrate::OfflineBoundary { evidence_addr } => {
                if let StepRole::Source = role {
                    return Err(invalid(format!(
                        "position {position}: the credit's source is an offline boundary, not an \
                         online transfer"
                    )));
                }
                let body_bytes = self
                    .fetcher
                    .immutable(TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE, evidence_addr)?;
                let verified = crate::economic::offline_boundary::OfflineBoundaryBody::verify(
                    &body_bytes,
                    genesis,
                    device_id,
                )
                .map_err(|e| invalid(format!("offline boundary at {position}: {e}")))?;
                (
                    AcceptedSubstrate::from_verified_offline_boundary(verified, *evidence_addr),
                    PeerSubstrate::OfflineBoundary(verified),
                )
            }
        };
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
        // The step passed whole: the offline account its boundary left is one
        // this receiver validated.
        if let PeerSubstrate::OfflineBoundary(boundary) = &substrate {
            self.offline_accounts
                .borrow_mut()
                .push(PeerOfflineAccount::validated(
                    *genesis, *device_id, position, boundary,
                ));
        }
        Ok(ValidatedPeerTransition::single_root_from_walk(
            *genesis,
            *device_id,
            advanced.root,
            witness,
            facts.proven_ak,
            substrate,
            manifest_addr,
            advanced.claim,
        ))
    }

    /// Spend one position of the walk's budget.
    fn spend_step(&self) -> Result<(), PeerLineageFailure> {
        if self.cost.get().steps_validated >= WALK_STEP_BUDGET {
            return Err(incomplete(format!(
                "the verification walked its budget of {WALK_STEP_BUDGET} positions before a \
                 frontier it holds; retry once the frontier has advanced"
            )));
        }
        self.count(|c| c.steps_validated += 1);
        Ok(())
    }

    /// This receiver's latest frontier for `(genesis, device_id)` below
    /// `position`: the one it recorded, or one a source's segment reached
    /// earlier in this walk, whichever is later; the activation root where
    /// it holds neither.
    fn frontier_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<PeerFrontier, PeerLineageFailure> {
        let recorded = self.recorded_frontier_below(genesis, device_id, position)?;
        let reached = self
            .established
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

    /// The frontier this receiver recorded for `(genesis, device_id)` below
    /// `position`, checked to be the one asked for. A store that answers with
    /// another identity's coordinate, or one not below `position`, is this
    /// verifier's own fault and decides nothing about the peer.
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
            Some((position, root, parent, claim_ref)) => Ok(ChainPoint {
                root: authenticated_root(position, root),
                accepted: Some(Accepted {
                    parent: *parent,
                    claim_ref,
                }),
            }),
        }
    }

    /// The claim final at `position`'s root cell, routed from the root
    /// validated at the position before. Anything short of a final claim
    /// there decides nothing yet: `Incomplete`.
    fn final_claim(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        previous: &ValidatedEconomicRoot,
    ) -> Result<RegisteredEconomicClaim, PeerLineageFailure> {
        self.count(|c| c.routed_reads += 1);
        match self.at_route(genesis, device_id, position, previous)? {
            AtRoute::Final(claim) => Ok(*claim),
            AtRoute::Held => Err(incomplete(format!(
                "position {position}: the claim holding the root cell is not final yet"
            ))),
            AtRoute::Open => Err(incomplete(format!(
                "position {position}: no claim holds the root cell routed from the root \
                 validated before it"
            ))),
            AtRoute::Undecided(why) => Err(incomplete(format!(
                "position {position}: the root cell is not decided yet: {why}"
            ))),
        }
    }

    /// The chain point `position` stands at, from the one before: its
    /// single-root step validated in full, or its conditional claim resolved
    /// from SoFi's public objects (SoFi Amendment S15).
    fn next_point(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        point: &ChainPoint,
        claim: RegisteredEconomicClaim,
    ) -> Result<ChainPoint, PeerLineageFailure> {
        match claim {
            RegisteredEconomicClaim::SingleRoot(claim) => {
                let step = self.full_step(
                    genesis,
                    device_id,
                    position,
                    point,
                    &claim,
                    StepRole::Segment,
                )?;
                Ok(ChainPoint {
                    root: *step.validated_root(),
                    accepted: Some(Accepted {
                        parent: ParentClaimRef::SingleRoot {
                            claim_ref: step.accepted_claim().claim_ref(),
                        },
                        claim_ref: step.accepted_claim().claim_ref(),
                    }),
                })
            }
            RegisteredEconomicClaim::ConditionalSofi(held) => {
                let (root, accepted) =
                    self.resolve_conditional(genesis, device_id, position, point, &held)?;
                Ok(ChainPoint {
                    root,
                    accepted: Some(Accepted {
                        parent: ParentClaimRef::Conditional {
                            fulfillment_id: held.fulfillment_id,
                        },
                        claim_ref: accepted.claim_ref(),
                    }),
                })
            }
        }
    }

    /// The chain from `frontier` through `through`, every position validated
    /// from the root validated before it.
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
            let claim = self.final_claim(genesis, device_id, position, &point.root)?;
            point = self.next_point(genesis, device_id, position, &point, claim)?;
            // The segment to `position` has passed whole: its coordinate is a
            // frontier, so a later read at or below it reads nothing behind it
            // (DSM Amendment A19: every validated frontier is recorded).
            self.keep_frontier(genesis, device_id, &point);
        }
        Ok(point)
    }

    /// The step at `target`, validated from the receiver's frontier: the
    /// chain to the position before, then the target's own single-root step.
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

    /// The chain from the receiver's frontier toward the head the register
    /// holds: the coordinate validated last, and why the walk stopped. A
    /// step that verifies as wrong is an error; stopping short is not.
    fn toward_head(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
    ) -> Result<(Option<PeerFrontier>, PrefixStop), PeerLineageFailure> {
        let frontier = self.frontier_below(genesis, device_id, u64::MAX)?;
        let mut point = self.start(&frontier)?;
        let mut reached = None;
        let mut position = frontier.economic_position();
        loop {
            position = match position.checked_add(1) {
                Some(next) => next,
                None => return Ok((reached, PrefixStop::Head)),
            };
            if let Err(spent) = self.spend_step() {
                return Ok((reached, PrefixStop::Short(spent.to_string())));
            }
            self.count(|c| c.routed_reads += 1);
            let claim = match self.at_route(genesis, device_id, position, &point.root)? {
                AtRoute::Final(claim) => *claim,
                AtRoute::Open => return Ok((reached, PrefixStop::Head)),
                AtRoute::Held => {
                    return Ok((
                        reached,
                        PrefixStop::Short(format!(
                            "position {position}: the claim holding the root cell is not final yet"
                        )),
                    ))
                }
                AtRoute::Undecided(why) => {
                    return Ok((
                        reached,
                        PrefixStop::Short(format!(
                            "position {position}: the root cell is not decided yet: {why}"
                        )),
                    ))
                }
            };
            point = match self.next_point(genesis, device_id, position, &point, claim) {
                Ok(next) => next,
                Err(PeerLineageFailure::Invalid(why)) => {
                    return Err(PeerLineageFailure::Invalid(why))
                }
                Err(PeerLineageFailure::Quarantined(why)) => {
                    return Err(PeerLineageFailure::Quarantined(why))
                }
                Err(PeerLineageFailure::Incomplete(why) | PeerLineageFailure::Unresolved(why)) => {
                    return Ok((reached, PrefixStop::Short(why)))
                }
            };
            self.keep_frontier(genesis, device_id, &point);
            reached = PeerFrontier::at_point(*genesis, *device_id, &point);
        }
    }

    /// Keep the coordinate `point` stands at as a frontier this walk
    /// established.
    fn keep_frontier(&self, genesis: &[u8; 32], device_id: &[u8; 32], point: &ChainPoint) {
        if let Some(reached) = PeerFrontier::at_point(*genesis, *device_id, point) {
            self.established.borrow_mut().push(reached);
        }
    }

    /// A credit's source: the source's own step at `position`, validated
    /// through its segment from this verifier's frontier for the source. It
    /// is an online transfer, a debit that names no source of its own.
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
        self.count(|c| c.source_steps += 1);
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
            self.established.borrow_mut().push(reached);
        }
        Ok(source)
    }
}

/// A root this verifier validated at `position`: a frontier the receiver
/// recorded, or the end of a step this walk validated (DSM Amendment A19).
/// Never a root a peer merely states.
fn authenticated_root(position: u64, root: [u8; 32]) -> ValidatedEconomicRoot {
    ValidatedEconomicRoot::from_verifier_memo(position, root)
}

/// The provenance of a segment step's credits: each source validated through
/// its own segment from this verifier's frontier for it (DSM Amendment A8, as
/// restored by A19).
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

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        self.verifier.fetcher.held_ek_step(signer, addr)
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

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        self.verifier.fetcher.held_ek_step(signer, addr)
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
        fn held_ek_step(
            &self,
            signer: &[u8; 32],
            addr: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(format!(
                "no relationship in this test: {} step {}",
                encode_base32_crockford(signer),
                encode_base32_crockford(addr)
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
                [0x78; 32],
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
        fn held_ek_step(
            &self,
            signer: &[u8; 32],
            addr: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
            self.read();
            self.inner.held_ek_step(signer, addr)
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
        let verifier = Verifier::new(&fetcher, NETWORK, &NoneRecorded, &NoResolution)
            .expect("the network's register");
        verifier.cost.set(StepCost {
            steps_validated: WALK_STEP_BUDGET,
            routed_reads: 0,
            source_steps: 0,
        });
        match verifier.source_step(&PEER_G, &peer_d(), 3) {
            Err(PeerLineageFailure::Incomplete(why)) => {
                assert!(why.contains("walked its budget"), "{why}")
            }
            Err(other) => panic!("a spent budget is Incomplete, got {other:?}"),
            Ok(_) => panic!("a spent budget validated a source"),
        }
        assert_eq!(fetcher.reads.get(), 0, "nothing of the source was read");
    }

    /// DSM Amendment A19, `peer_root_at`: a frontier this receiver recorded AT
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
            [0xF6; 32],
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
        .expect("the recorded point")
        .into_answer();
        assert_eq!(
            (root.economic_position(), root.economic_root(), named),
            (position, [0x66; 32], accepted)
        );
        assert_eq!(fetcher.reads.get(), 0, "nothing of the peer was read");
    }

    /// MR-SOFI-0346, MR-SOFI-0347 (DSM Amendment A19): `peer_claim_at` at a
    /// position this receiver validated and recorded answers with the claim
    /// it accepted there, and nothing of the peer is read: a setup's claim
    /// behind the receiver's frontier is never read again. The answer is the
    /// accepted claim's own digest, which for a conditional position is
    /// `C_q`'s and not the fulfillment that names it as a parent.
    /// MUTATION CONTROL: walking from the frontier below the position instead
    /// reads the peer's root cells and turns this red.
    #[test]
    fn a_claim_recorded_at_the_position_answers_and_nothing_is_read() {
        let position = 6;
        let recorded = Recorded(PeerFrontier::rehydrate_recorded(
            PEER_G,
            peer_d(),
            position,
            [0x66; 32],
            ParentClaimRef::Conditional {
                fulfillment_id: [0xF5; 32],
            },
            [0xF6; 32],
        ));
        let fetcher = CountingCells {
            inner: ConditionalCellFetcher {
                position,
                writes: vec![peer_c_q(conditional_claim(position))],
                last: crate::route_chain::ROUTE_LEN - 1,
            },
            reads: std::cell::Cell::new(0),
        };
        let claim = peer_claim_at(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &recorded,
            &NoResolution,
        )
        .expect("the recorded claim")
        .into_answer();
        assert_eq!(
            (
                claim.genesis(),
                claim.device_id(),
                claim.economic_position(),
                claim.claim_ref()
            ),
            (PEER_G, peer_d(), position, [0xF6; 32])
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

    /// A resolver whose answer names the coordinates it holds.
    #[derive(Clone, Copy)]
    struct AnswersFor {
        root_position: u64,
        claim_position: u64,
        genesis: [u8; 32],
        device_id: [u8; 32],
    }

    impl ConditionalPositionResolver for AnswersFor {
        fn resolve(
            &self,
            _previous: &ValidatedEconomicRoot,
            _parent: &ParentClaimRef,
            held: &SofiResolutionClaim,
        ) -> Result<(ValidatedEconomicRoot, AcceptedClaim), PeerLineageFailure> {
            Ok((
                authenticated_root(self.root_position, held.realize_root),
                AcceptedClaim::from_validated_coordinate(
                    self.genesis,
                    self.device_id,
                    self.claim_position,
                    [0xC1; 32],
                ),
            ))
        }
    }

    /// MR-DSM-0276: what a resolver answers for a conditional position is
    /// held to that position of that peer. The answer for the coordinate
    /// asked about is taken; one whose root stands at another position, or
    /// whose accepted claim is another position's, another genesis's or
    /// another device's, is `Invalid`, however it was derived.
    ///
    /// MUTATION CONTROL: dropping the coordinate comparison in
    /// `resolve_conditional` (`cond_coordinate`) turns this red.
    #[test]
    fn a_resolution_answered_for_another_coordinate_is_invalid() {
        let position = 4;
        let fetcher = ConditionalCellFetcher {
            position,
            writes: vec![peer_c_q(conditional_claim(position))],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        let ask = |resolver: &AnswersFor| {
            peer_claim_at(
                &fetcher,
                NETWORK,
                &PEER_G,
                &peer_d(),
                position,
                &Recorded::below(position),
                resolver,
            )
        };
        let honest = AnswersFor {
            root_position: position,
            claim_position: position,
            genesis: PEER_G,
            device_id: peer_d(),
        };
        if let Err(e) = ask(&honest) {
            panic!("the answer for the coordinate asked about is taken: {e:?}");
        }
        let elsewhere = [
            AnswersFor {
                root_position: position + 1,
                ..honest
            },
            AnswersFor {
                claim_position: position - 1,
                ..honest
            },
            AnswersFor {
                genesis: [0x99; 32],
                ..honest
            },
            AnswersFor {
                device_id: [0x98; 32],
                ..honest
            },
        ];
        for shifted in &elsewhere {
            match ask(shifted) {
                Err(PeerLineageFailure::Invalid(why)) => {
                    assert!(why.contains("answered for another coordinate"), "{why}")
                }
                other => panic!("an answer for another coordinate is Invalid, not {other:?}"),
            }
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

    /// Cells answered by the parent root they are routed from: `routed`
    /// holds each `(position, parent root, value)` written along the cell
    /// routed from that parent, final. Every routed read is recorded as the
    /// `(position, parent root)` of the cell asked for.
    struct ByParent {
        routed: Vec<(u64, [u8; 32], Vec<u8>)>,
        asked: std::cell::RefCell<Vec<(u64, [u8; 32])>>,
    }

    impl ByParent {
        fn routed_from(
            &self,
            cell: &RootCell,
            position: u64,
            parent: &[u8; 32],
        ) -> Result<bool, PeerLineageFailure> {
            let register = Register::resolve(self, NETWORK)?;
            RootCell::new(
                &PEER_G,
                &peer_d(),
                position,
                parent,
                &register.set,
                &register.profile.storage_set_id,
            )
            .map(|from| from.routed().seed() == cell.routed().seed())
            .map_err(|e| PeerLineageFailure::Incomplete(format!("{e:?}")))
        }
    }

    impl PeerEvidenceFetcher for ByParent {
        fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
            let mut seats = crate::route_chain::fixtures::Cell::at(cell.routed());
            for (position, parent, value) in &self.routed {
                if self.routed_from(cell, *position, parent)? {
                    seats.write(value, crate::route_chain::ROUTE_LEN - 1, &[]);
                }
            }
            for parent in [[0x41; 32], [0x99; 32]] {
                if self.routed_from(cell, cell.economic_position(), &parent)? {
                    self.asked
                        .borrow_mut()
                        .push((cell.economic_position(), parent));
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
        fn held_ek_step(
            &self,
            signer: &[u8; 32],
            addr: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(format!(
                "no relationship in this test: {} step {}",
                encode_base32_crockford(signer),
                encode_base32_crockford(addr)
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

    /// DSM Amendment A19 (audit finding SA-02): the claim at a position is
    /// read only at the cell routed from the root the receiver validated
    /// before it, never at the cell routed from a root the claim's own
    /// witness names. The receiver's frontier stands at position 4 with root
    /// `0x41…`; the peer's claim at 5 is final only along the cell routed from
    /// `0x99…`, a root the receiver never validated. The receiver asks for
    /// the cell routed from `0x41…` alone, finds no claim there, and accepts
    /// nothing.
    /// MUTATION CONTROL: routing the read from any root but the validated
    /// one turns this red.
    #[test]
    fn a_claim_on_a_root_the_receiver_never_validated_is_not_on_its_chain() {
        let position = 5;
        let claim = peer_c_q(conditional_claim(position));
        let fetcher = ByParent {
            routed: vec![(position, [0x99; 32], claim)],
            asked: std::cell::RefCell::new(Vec::new()),
        };
        let frontier = Recorded(PeerFrontier::rehydrate_recorded(
            PEER_G,
            peer_d(),
            position - 1,
            [0x41; 32],
            ParentClaimRef::SingleRoot {
                claim_ref: [0x78; 32],
            },
            [0x78; 32],
        ));
        let outcome = validate_peer_lineage(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &frontier,
            &NoResolution,
        );
        assert!(
            matches!(
                outcome,
                Err(PeerLineageFailure::Incomplete(ref m))
                    if m.contains("routed from the root validated before it")
            ),
            "{outcome:?}"
        );
        assert_eq!(
            *fetcher.asked.borrow(),
            vec![(position, [0x41; 32])],
            "only the cell routed from the validated root was read"
        );
    }

    /// DSM Amendment A19, contact add: a walk toward a peer's head stops at
    /// the first position whose root cell, routed from the root validated
    /// before it, holds no claim. With nothing validated past the frontier it
    /// started at, it reaches nothing new and reads one cell.
    #[test]
    fn a_walk_toward_the_head_stops_where_the_register_holds_nothing() {
        let fetcher = CountingCells {
            inner: ConditionalCellFetcher {
                position: 9,
                writes: Vec::new(),
                last: crate::route_chain::ROUTE_LEN - 1,
            },
            reads: std::cell::Cell::new(0),
        };
        let walked = validate_peer_prefix(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            &Recorded::below(4),
            &NoResolution,
        )
        .expect("an empty cell is the head, not a failure");
        assert!(matches!(walked.answer().stop(), PrefixStop::Head));
        assert!(walked.answer().reached().is_none());
        assert_eq!(walked.cost().routed_reads, 1);
        assert_eq!(fetcher.reads.get(), 1, "one root cell was read");
    }

    /// DSM Amendment A19, contact add: a walk that meets a position it
    /// cannot decide yet stops short and keeps what it validated, which is
    /// nothing here; it is not a failure of the contact.
    #[test]
    fn a_walk_toward_the_head_stops_short_on_a_cell_not_decided_yet() {
        let position = 4;
        let fetcher = ConditionalCellFetcher {
            position,
            writes: vec![peer_c_q(conditional_claim(position))],
            last: 0,
        };
        let walked = validate_peer_prefix(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            &Recorded::below(position),
            &NoResolution,
        )
        .expect("a cell not decided yet is no failure");
        match walked.answer().stop() {
            PrefixStop::Short(why) => assert!(why.contains("not final yet"), "{why}"),
            PrefixStop::Head => panic!("the cell holds a claim short of final"),
        }
        assert!(walked.answer().reached().is_none());
    }

    /// A walk toward the head spends from the same budget: with none left it
    /// stops short at once and reads nothing.
    #[test]
    fn a_walk_toward_the_head_past_its_budget_stops_short_and_reads_nothing() {
        let fetcher = CountingCells {
            inner: ConditionalCellFetcher {
                position: 1,
                writes: Vec::new(),
                last: crate::route_chain::ROUTE_LEN - 1,
            },
            reads: std::cell::Cell::new(0),
        };
        let verifier = Verifier::new(&fetcher, NETWORK, &NoneRecorded, &NoResolution)
            .expect("the network's register");
        verifier.cost.set(StepCost {
            steps_validated: WALK_STEP_BUDGET,
            routed_reads: 0,
            source_steps: 0,
        });
        let (reached, stop) = verifier
            .toward_head(&PEER_G, &peer_d())
            .expect("a spent budget is no failure");
        assert!(reached.is_none());
        assert!(matches!(stop, PrefixStop::Short(ref why) if why.contains("walked its budget")));
        assert_eq!(fetcher.reads.get(), 0, "nothing was read");
    }
}
