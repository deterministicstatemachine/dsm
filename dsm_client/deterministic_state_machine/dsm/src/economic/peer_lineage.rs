// SPDX-License-Identifier: Apache-2.0

//! The foreign step verifier, one hop (DSM Amendment A14).
//!
//! A receiver accepts a peer's step from the step's own parent, and reads
//! nothing behind that parent (owner paper, "Deterministic State Machines as
//! Guarded Linear Constraint Systems", Definition 57 and §29). For the step at
//! `position` it:
//!
//! 1. reads `K_root(position)`, a hash of `(G, DevID, position)`, at every
//!    member of the register. This is discovery: nothing found there is
//!    authority;
//! 2. takes each claim of the peer found there and the parent it names: for
//!    a single-root claim, the root its own witness was built on (the
//!    activation root at position 1);
//! 3. requires the claim to be the one final at the cell routed from that
//!    parent (Tripwire). Exactly one claim may survive: none is
//!    `Incomplete`, and two are a fork, `Invalid`, never one chosen;
//! 4. authenticates the claim (manifest by content address, the AK its
//!    authority evidence proves, the committed network's register set) and
//!    validates the transition from that parent with the SAME
//!    `advance_validated` any device runs, which refuses a witness built on
//!    any other root.
//!
//! The cost is a constant number of lookup stages, whatever the position.
//!
//! ## Sources
//!
//! A credit's source is the source's own step, validated the same way, one
//! hop. It is an online transfer, a debit that names no source of its own,
//! so nothing behind it is asked for.
//!
//! ## Conditional positions
//!
//! A conditional claim (`C_q`) selects no root by its bytes. Its parent is the
//! step one position back, validated one hop, and the
//! [`ConditionalPositionResolver`] derives the root it selected from SoFi's
//! public objects for that position alone (SoFi Amendment S15). A
//! conditional claim one position back is not resolved from its own parent:
//! nothing two positions back is read.

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
    economic_root_register_key, read_root_cell, resolve_for_trader, resolve_root_register_profile,
    root_claim_naming, RegisteredEconomicRoot, RootCell, RootRegisterProfile,
};
use crate::economic::successor_evidence::verify_dsm_successor_evidence;
use crate::route_chain::{CellEvidence, CellReading, ChainState};
use crate::sofi::wire::{ParentClaimRef, SofiResolutionClaim};
use crate::utils::text_id::encode_base32_crockford;

/// I/O the verifier needs: raw reads of the register cells it names, and
/// immutable objects by address. The fetcher supplies bytes, never a verdict:
/// the verifier evaluates every cell's route chains itself and re-checks every
/// address.
pub trait PeerEvidenceFetcher {
    /// Every value any member of the register holds under `K_root(position)`
    /// of `(genesis, device_id)`, as the member stores it (a route entry),
    /// read at every member without a route. It is
    /// where to look, never what is final: each claim found there is checked
    /// at the cell routed from the parent it names (DSM Amendment A14).
    /// `Incomplete` when no member answered.
    fn register_key_values(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Vec<Vec<u8>>, PeerLineageFailure>;
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

/// What checking one step of a peer cost, in lookup stages. Every count is
/// bounded by a constant whatever the peer's position (DSM Amendment A14):
/// one probe and one routed read for each claim found at a position, one
/// position back for a conditional claim's parent, and one step for each
/// credit's source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepCost {
    /// Unrouted reads of a register key at every member.
    pub register_probes: u32,
    /// Routed reads of a root cell.
    pub routed_reads: u32,
    /// Credit sources validated, one step each.
    pub source_steps: u32,
    /// Conditional claims whose parent was read one position back.
    pub conditional_hops: u32,
}

/// An answer about one step of a peer, with what checking it cost.
#[derive(Debug)]
pub struct Checked<T> {
    answer: T,
    cost: StepCost,
}

impl<T> Checked<T> {
    pub fn answer(&self) -> &T {
        &self.answer
    }

    pub fn cost(&self) -> StepCost {
        self.cost
    }

    pub fn into_answer(self) -> T {
        self.answer
    }
}

/// A peer's step at `target_position`, validated from its own parent (DSM
/// Amendment A14). The step's credits' sources are each validated the same
/// way, one hop. A conditional claim at the target is `Unresolved`: the peer
/// is mid-route, and no single transition can be validated there yet.
pub fn validate_peer_step(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<ValidatedPeerTransition>, PeerLineageFailure> {
    if target_position == 0 {
        return Err(invalid(
            "position 0 is the activation root; it has no transition to validate",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, conditional)?;
    let answer = verifier.step_at(peer_genesis, peer_devid, target_position, StepRole::Offered)?;
    Ok(Checked {
        answer,
        cost: verifier.cost.get(),
    })
}

/// The root a peer selected AT `position`, and the reference a later `P`
/// names that position by (SoFi Amendment S15): the step there validated
/// from its own parent, or, when its claim is conditional, resolved through
/// `conditional` from the step one position back.
///
/// Position 0 is the activation root, where no claim was accepted for a `P`
/// to name, and is `Invalid`.
pub fn peer_root_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<(ValidatedEconomicRoot, ParentClaimRef)>, PeerLineageFailure> {
    if position == 0 {
        return Err(invalid(
            "position 0 is the activation root: no claim was accepted there for a P to name as \
             its parent",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, conditional)?;
    let at = verifier.located(peer_genesis, peer_devid, position, ConditionalAt::Resolve)?;
    let answer = match &at.claim {
        RegisteredEconomicClaim::SingleRoot(claim) => {
            let step = verifier.full_step(
                peer_genesis,
                peer_devid,
                position,
                &at.parent,
                claim,
                StepRole::Offered,
            )?;
            (
                *step.validated_root(),
                ParentClaimRef::SingleRoot {
                    claim_ref: step.accepted_claim().claim_ref(),
                },
            )
        }
        RegisteredEconomicClaim::ConditionalSofi(held) => {
            let (root, _) = verifier.resolve_conditional(
                peer_genesis,
                peer_devid,
                position,
                &at.parent,
                held,
            )?;
            (
                root,
                ParentClaimRef::Conditional {
                    fulfillment_id: held.fulfillment_id,
                },
            )
        }
    };
    Ok(Checked {
        answer,
        cost: verifier.cost.get(),
    })
}

/// The claim a peer accepted AT `position` (SoFi Amendment S15,
/// MR-SOFI-0347): what a setup naming that position is checked against. The
/// step there is validated from its own parent, or, when its claim is
/// conditional, resolved from the step one position back, so a setup made
/// right after a SoFi position is checked against the claim that position's
/// resolution accepted.
pub fn peer_claim_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<AcceptedClaim>, PeerLineageFailure> {
    if position == 0 {
        return Err(invalid(
            "position 0 is the activation root: no claim was accepted there",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, conditional)?;
    let at = verifier.located(peer_genesis, peer_devid, position, ConditionalAt::Resolve)?;
    let answer = match &at.claim {
        RegisteredEconomicClaim::SingleRoot(claim) => *verifier
            .full_step(
                peer_genesis,
                peer_devid,
                position,
                &at.parent,
                claim,
                StepRole::Offered,
            )?
            .accepted_claim(),
        RegisteredEconomicClaim::ConditionalSofi(held) => {
            let (.., accepted) = verifier.resolve_conditional(
                peer_genesis,
                peer_devid,
                position,
                &at.parent,
                held,
            )?;
            accepted
        }
    };
    Ok(Checked {
        answer,
        cost: verifier.cost.get(),
    })
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

/// The parent a step is validated from: the root at the position before, and
/// the claim accepted there when it was read for a conditional claim to name
/// (`None` otherwise, and always at the activation root).
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
    /// The step asked about: each of its credits' sources is validated as a
    /// source, one hop.
    Offered,
    /// A credit's source step: it must be an online transfer, a debit that
    /// names no source of its own.
    Source,
}

/// What a conditional claim found at a position means to the question asked
/// there.
#[derive(Clone, Copy)]
enum ConditionalAt {
    /// Its root is wanted: it is resolved from the step one position back.
    Resolve,
    /// A transition is wanted: a conditional position has none yet, and the
    /// peer is mid-route.
    Unresolved,
    /// A credit's source is wanted: a conditional position is not an online
    /// transfer.
    Invalid,
}

/// A claim of a peer final at its position, and the parent it was found
/// final from.
struct Located {
    parent: ChainPoint,
    claim: RegisteredEconomicClaim,
}

struct Verifier<'a> {
    fetcher: &'a dyn PeerEvidenceFetcher,
    expected_network_id: &'a [u8],
    register: Register,
    conditional: &'a dyn ConditionalPositionResolver,
    /// What this check has cost so far, counted as it reads.
    cost: std::cell::Cell<StepCost>,
}

/// A claim's identity at its cell: the entry digest the register recognizes
/// it by (a single-root claim by its exact bytes, a conditional one by its
/// derived body `C_q`).
fn claim_identity(claim: &RegisteredEconomicClaim) -> [u8; 32] {
    match claim {
        RegisteredEconomicClaim::SingleRoot(c) => {
            crate::storage_cell::entry_digest(c.envelope_bytes())
        }
        RegisteredEconomicClaim::ConditionalSofi(c) => {
            crate::storage_cell::entry_digest(&c.encode())
        }
    }
}

impl<'a> Verifier<'a> {
    fn new(
        fetcher: &'a dyn PeerEvidenceFetcher,
        expected_network_id: &'a [u8],
        conditional: &'a dyn ConditionalPositionResolver,
    ) -> Result<Self, PeerLineageFailure> {
        Ok(Self {
            fetcher,
            expected_network_id,
            register: Register::resolve(fetcher, expected_network_id)?,
            conditional,
            cost: std::cell::Cell::new(StepCost {
                register_probes: 0,
                routed_reads: 0,
                source_steps: 0,
                conditional_hops: 0,
            }),
        })
    }
}

impl Verifier<'_> {
    fn count(&self, add: impl FnOnce(&mut StepCost)) {
        let mut cost = self.cost.get();
        add(&mut cost);
        self.cost.set(cost);
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
            StepRole::Offered => &ancestry,
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

    /// The claim of `(genesis, device_id)` final at `position`, and the parent
    /// it is final from (DSM Amendment A14).
    ///
    /// Every claim of the peer any member holds under `K_root(position)` is a
    /// candidate, and each is taken to the cell routed from the parent it
    /// names. Only a candidate final there survives. Exactly one may: none
    /// is `Incomplete`, and two are a fork, `Invalid`, with both named. The
    /// unrouted read only says where to look.
    fn located(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        conditional_at: ConditionalAt,
    ) -> Result<Located, PeerLineageFailure> {
        let key = economic_root_register_key(genesis, device_id, position);
        self.count(|c| c.register_probes += 1);
        let held = self
            .fetcher
            .register_key_values(genesis, device_id, position)?;
        // A member holds each value as a route entry, the copy written at one
        // position of some route: the value inside is the candidate, whatever
        // route it was written along.
        let namespace = crate::economic::register::economic_root_namespace();
        let mut seen = std::collections::BTreeSet::new();
        let candidates: Vec<RegisteredEconomicClaim> = held
            .iter()
            .filter_map(|bytes| crate::route_chain::RouteEntry::decode(bytes))
            .filter(|entry| entry.namespace == namespace && entry.key == key)
            .filter_map(|entry| root_claim_naming(&entry.value, &key))
            .filter(|claim| seen.insert(claim_identity(claim)))
            .collect();
        if candidates.is_empty() {
            return Err(incomplete(format!(
                "position {position}: no claim of this peer is held at its register key yet"
            )));
        }
        let mut survivors: Vec<Located> = Vec::new();
        let mut waiting: Vec<String> = Vec::new();
        let mut unresolved: Vec<String> = Vec::new();
        let mut conditional: Option<String> = None;
        for candidate in candidates {
            let parent = match &candidate {
                RegisteredEconomicClaim::SingleRoot(claim) => self.parent_named_by(position, claim),
                RegisteredEconomicClaim::ConditionalSofi(_) => match conditional_at {
                    ConditionalAt::Resolve => {
                        self.parent_of_conditional(genesis, device_id, position)
                    }
                    ConditionalAt::Unresolved | ConditionalAt::Invalid => {
                        if let Err(why) = candidate.single_root() {
                            conditional = Some(why.to_string());
                        }
                        continue;
                    }
                },
            };
            let parent = match parent {
                Ok(parent) => parent,
                Err(PeerLineageFailure::Incomplete(m)) => {
                    waiting.push(m);
                    continue;
                }
                Err(PeerLineageFailure::Unresolved(m)) => {
                    unresolved.push(m);
                    continue;
                }
                Err(other) => return Err(other),
            };
            self.count(|c| c.routed_reads += 1);
            match self.final_claim(genesis, device_id, position, &parent.root) {
                Ok(final_there) if claim_identity(&final_there) == claim_identity(&candidate) => {
                    survivors.push(Located {
                        parent,
                        claim: final_there,
                    })
                }
                // Another claim holds this candidate's route. If it is the
                // peer's at this key, it is a candidate here of its own.
                Ok(_) => waiting.push(format!(
                    "position {position}: a claim found at the register key is not the one final \
                     at the cell routed from its parent"
                )),
                Err(PeerLineageFailure::Incomplete(m)) => waiting.push(m),
                Err(other) => return Err(other),
            }
        }
        if survivors.len() > 1 {
            let named = survivors
                .iter()
                .map(|l| encode_base32_crockford(&claim_identity(&l.claim)))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(invalid(format!(
                "position {position}: {} claims of this peer are each final at the cell routed \
                 from their own parent ({named}); a fork is refused, never one chosen",
                survivors.len()
            )));
        }
        if let Some(found) = survivors.pop() {
            return Ok(found);
        }
        if !waiting.is_empty() {
            return Err(incomplete(waiting.join("; ")));
        }
        if !unresolved.is_empty() {
            return Err(PeerLineageFailure::Unresolved(unresolved.join("; ")));
        }
        match (conditional, conditional_at) {
            (Some(_), ConditionalAt::Invalid) => Err(invalid(format!(
                "position {position}: the credit's source is a conditional SoFi position, not an \
                 online transfer"
            ))),
            (Some(why), _) => Err(PeerLineageFailure::Unresolved(format!(
                "peer {}/{} at position {position}: {why}",
                encode_base32_crockford(genesis),
                encode_base32_crockford(device_id)
            ))),
            (None, _) => Err(incomplete(format!(
                "position {position}: no claim of this peer is final at the cell routed from its \
                 parent"
            ))),
        }
    }

    /// The parent a single-root claim at `position` names: the activation
    /// root at position 1, else the root its own witness was built on. It is
    /// only where to look: the claim must then be final at the cell routed
    /// from it, and its step valid from it, where `advance_validated`
    /// refuses a witness built on any other root.
    fn parent_named_by(
        &self,
        position: u64,
        claim: &VerifiedEconomicRootClaim,
    ) -> Result<ChainPoint, PeerLineageFailure> {
        if position == 1 {
            return Ok(ChainPoint {
                root: activate(EconomicActivationSnapshot::fresh())
                    .map_err(|e| invalid(format!("activation shape: {e}")))?,
                accepted: None,
            });
        }
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
        let witness_bytes = self.fetcher.immutable(
            TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
            &manifest.transition_witness_addr,
        )?;
        let witness = crate::economic::decode::decode_transition_witness(&witness_bytes)
            .map_err(|e| invalid(format!("witness at {position}: {e}")))?;
        Ok(ChainPoint {
            root: authenticated_root(position - 1, witness.pre_economic_root),
            accepted: None,
        })
    }

    /// The parent of a conditional claim at `position`: the step one position
    /// back, validated from its own parent, and the claim accepted there,
    /// which the resolution names as its parent (SoFi Amendment S15). One
    /// position back and no further: a conditional claim there is not
    /// resolved from its own parent here.
    fn parent_of_conditional(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<ChainPoint, PeerLineageFailure> {
        if position <= 1 {
            return Err(invalid(format!(
                "position {position}: a conditional position cannot follow the activation root, \
                 where no claim was accepted for it to name as its parent"
            )));
        }
        self.count(|c| c.conditional_hops += 1);
        let back = position - 1;
        let at = self
            .located(genesis, device_id, back, ConditionalAt::Unresolved)
            .map_err(|failure| match failure {
                PeerLineageFailure::Unresolved(m) => PeerLineageFailure::Unresolved(format!(
                    "the parent of conditional position {position} is itself conditional and is \
                     not resolved from its own parent here: {m}"
                )),
                other => other,
            })?;
        let claim = at.claim.single_root().map_err(|conditional| {
            PeerLineageFailure::Unresolved(format!("position {back}: {conditional}"))
        })?;
        let step = self.full_step(
            genesis,
            device_id,
            back,
            &at.parent,
            claim,
            StepRole::Offered,
        )?;
        Ok(ChainPoint {
            root: *step.validated_root(),
            accepted: Some(ParentClaimRef::SingleRoot {
                claim_ref: step.accepted_claim().claim_ref(),
            }),
        })
    }

    /// The single-root step at `position`, validated from its own parent in
    /// `role`.
    fn step_at(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        role: StepRole,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let conditional_at = match role {
            StepRole::Offered => ConditionalAt::Unresolved,
            StepRole::Source => ConditionalAt::Invalid,
        };
        let at = self.located(genesis, device_id, position, conditional_at)?;
        let claim = at.claim.single_root().map_err(|conditional| {
            PeerLineageFailure::Unresolved(format!(
                "peer {}/{} at position {position}: {conditional}",
                encode_base32_crockford(genesis),
                encode_base32_crockford(device_id)
            ))
        })?;
        self.full_step(genesis, device_id, position, &at.parent, claim, role)
    }

    /// A credit's source: the source's own step at `position`, validated one
    /// hop. It is an online transfer, a debit that names no source of its
    /// own, so nothing behind it is read.
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
        self.step_at(genesis, device_id, position, StepRole::Source)
    }
}

/// The root at `position` a step is validated from: the root a claim's own
/// witness at `position + 1` was built on, taken as the parent only because
/// that claim is final at the cell routed from it and its step is then
/// validated from it (DSM Amendment A14). Never a root a peer merely states.
fn authenticated_root(position: u64, root: [u8; 32]) -> ValidatedEconomicRoot {
    ValidatedEconomicRoot::from_verifier_memo(position, root)
}

/// The provenance of an offered step's credits: each source validated as
/// its own step, one hop (DSM Amendment A14).
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

    /// A fetcher over the network's pinned register set whose members hold
    /// `writes` under the register key of each listed position, written along
    /// each cell's route in order through route position `last`. Every probe
    /// is recorded by position. Every other capability refuses, because none
    /// of them should be reached.
    struct CellsAt {
        held: Vec<(u64, Vec<Vec<u8>>)>,
        last: usize,
        probed: std::cell::RefCell<Vec<u64>>,
    }

    impl CellsAt {
        fn new(held: Vec<(u64, Vec<Vec<u8>>)>) -> Self {
            Self {
                held,
                last: crate::route_chain::ROUTE_LEN - 1,
                probed: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn writes_at(&self, position: u64) -> Vec<Vec<u8>> {
            self.held
                .iter()
                .filter(|(at, _)| *at == position)
                .flat_map(|(_, writes)| writes.clone())
                .collect()
        }
    }

    impl PeerEvidenceFetcher for CellsAt {
        /// What members hold under the key: each value as its leader copy
        /// along a route of the cell, which route does not matter to a probe.
        fn register_key_values(
            &self,
            genesis: &[u8; 32],
            device_id: &[u8; 32],
            position: u64,
        ) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
            self.probed.borrow_mut().push(position);
            let register = Register::resolve(self, NETWORK)?;
            let cell = RootCell::new(
                genesis,
                device_id,
                position,
                &[0x5E; 32],
                &register.set,
                &register.profile.storage_set_id,
            )
            .map_err(|e| PeerLineageFailure::Incomplete(format!("{e:?}")))?;
            let routed = cell.routed();
            Ok(self
                .writes_at(position)
                .into_iter()
                .map(|value| {
                    crate::route_chain::RouteEntry::at_leader(
                        routed.namespace().to_vec(),
                        *routed.key(),
                        value,
                        routed.route(),
                    )
                    .encode()
                })
                .collect())
        }
        fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
            let mut seats = crate::route_chain::fixtures::Cell::at(cell.routed());
            for value in self.writes_at(cell.economic_position()) {
                seats.write(&value, self.last, &[]);
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

    /// `peer_root_at` at position 0 is the activation root, where no claim was
    /// accepted: no `P` can name it as a parent, so it is `Invalid`, and no
    /// reference is made up for it.
    #[test]
    fn the_activation_root_names_no_parent() {
        let fetcher = CellsAt::new(Vec::new());
        match peer_root_at(&fetcher, NETWORK, &PEER_G, &peer_d(), 0, &NoResolution) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("activation root"), "{why}")
            }
            other => panic!("position 0 is Invalid, not {other:?}"),
        }
        assert!(fetcher.probed.borrow().is_empty(), "nothing was read");
    }

    /// A CONDITIONAL PEER POSITION IS `Unresolved`, NOT `Invalid`: the peer is
    /// mid-route, not forging, and no single transition exists there yet.
    #[test]
    fn a_conditional_peer_position_is_unresolved_and_never_invalid() {
        let position = 4;
        let fetcher = CellsAt::new(vec![(
            position,
            vec![peer_c_q(conditional_claim(position))],
        )]);
        let err = validate_peer_step(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &NoResolution,
        )
        .expect_err("a conditional position cannot produce a validated transition");
        match &err {
            PeerLineageFailure::Unresolved(m) => assert!(
                m.contains("commits two roots and has selected neither"),
                "the refusal must say what it is waiting on, got: {m}"
            ),
            other => panic!("a conditional position must be Unresolved, got {other:?}"),
        }
    }

    /// DSM Amendment A14, the conditional bound: a conditional claim's parent
    /// is read one position back and no further. Two conditional positions
    /// back to back leave the later one `Unresolved`, and nothing two
    /// positions back is ever asked for.
    #[test]
    fn a_conditional_claims_parent_is_read_one_position_back_and_never_two() {
        let position = 40;
        let fetcher = CellsAt::new(vec![
            (position, vec![peer_c_q(conditional_claim(position))]),
            (
                position - 1,
                vec![peer_c_q(conditional_claim(position - 1))],
            ),
            (
                position - 2,
                vec![peer_c_q(conditional_claim(position - 2))],
            ),
        ]);
        let outcome = peer_claim_at(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &NoResolution,
        );
        assert!(
            matches!(outcome, Err(PeerLineageFailure::Unresolved(ref m)) if m.contains("itself conditional")),
            "{outcome:?}"
        );
        assert_eq!(
            *fetcher.probed.borrow(),
            vec![position, position - 1],
            "only the position and the one before it were read"
        );
    }

    /// A conditional claim whose one-back parent holds nothing yet waits for
    /// it; the resolver is not asked.
    #[test]
    fn a_conditional_claim_waits_for_its_parent_one_position_back() {
        let position = 4;
        let fetcher = CellsAt::new(vec![(
            position,
            vec![peer_c_q(conditional_claim(position))],
        )]);
        match peer_claim_at(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &NoResolution,
        ) {
            Err(PeerLineageFailure::Incomplete(why)) => {
                assert!(why.contains("position 3: no claim"), "{why}")
            }
            other => panic!("the parent is not there yet, not {other:?}"),
        }
    }

    /// A claim naming other coordinates is never a candidate at this peer's
    /// key: a key holding only foreign claims holds nothing of this peer.
    #[test]
    fn a_claim_naming_other_coordinates_is_never_a_candidate() {
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
        let check = |writes: Vec<Vec<u8>>| {
            validate_peer_step(
                &CellsAt::new(vec![(position, writes)]),
                NETWORK,
                &PEER_G,
                &peer_d(),
                position,
                &NoResolution,
            )
        };
        assert!(
            matches!(
                check(vec![signed_conditional(foreign, &other).expect("its own C_q")]),
                Err(PeerLineageFailure::Incomplete(ref m)) if m.contains("no claim of this peer")
            ),
            "a key holding only a foreign claim holds nothing of this peer"
        );
        assert!(
            matches!(
                check(vec![
                    signed_conditional(foreign, &other).expect("its own C_q"),
                    peer_c_q(ours),
                ]),
                Err(PeerLineageFailure::Unresolved(_))
            ),
            "the foreign claim does not hide this peer's own"
        );
    }

    /// A credit's source at a conditional position is not an online transfer:
    /// `Invalid`, and nothing behind it is read.
    #[test]
    fn a_source_at_a_conditional_position_is_invalid() {
        let position = 7;
        let fetcher = CellsAt::new(vec![(
            position,
            vec![peer_c_q(conditional_claim(position))],
        )]);
        let verifier =
            Verifier::new(&fetcher, NETWORK, &NoResolution).expect("the network's register");
        match verifier.source_step(&PEER_G, &peer_d(), position) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("not an online transfer"), "{why}")
            }
            other => panic!("a conditional source is Invalid, not {other:?}"),
        }
        assert_eq!(*fetcher.probed.borrow(), vec![position]);
        assert_eq!(verifier.cost.get().source_steps, 1);
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

    /// NO PATH from a conditional cell to a validated root: neither branch of
    /// an unresolved `C_q` is minted, and neither appears in the refusal.
    #[test]
    fn no_validated_root_is_minted_from_either_branch_of_an_unresolved_claim() {
        let position = 2;
        let claim = conditional_claim(position);
        let fetcher = CellsAt::new(vec![(position, vec![peer_c_q(claim)])]);
        let err = validate_peer_step(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            position,
            &NoResolution,
        )
        .expect_err("no validated transition");
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
    /// the resolver is never asked (SoFi S9, every leg follows a setup the
    /// trader registered).
    #[test]
    fn a_conditional_position_right_after_the_activation_root_is_invalid() {
        let fetcher = CellsAt::new(vec![(1, vec![peer_c_q(conditional_claim(1))])]);
        let outcome = peer_root_at(&fetcher, NETWORK, &PEER_G, &peer_d(), 1, &NoResolution);
        assert!(
            matches!(outcome, Err(PeerLineageFailure::Invalid(ref m)) if m.contains("cannot follow the activation root")),
            "{outcome:?}"
        );
    }

    /// Claims of the peer at one position, each written only along the cell
    /// routed from the parent its own witness names, with the manifests and
    /// witnesses they name; every member's probe of the key returns
    /// `probed`, in that order.
    struct RoutedClaims {
        position: u64,
        probed: Vec<Vec<u8>>,
        routed: Vec<([u8; 32], Vec<u8>)>,
        objects: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    }

    impl PeerEvidenceFetcher for RoutedClaims {
        fn register_key_values(
            &self,
            genesis: &[u8; 32],
            device_id: &[u8; 32],
            position: u64,
        ) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
            let register = Register::resolve(self, NETWORK)?;
            let cell = RootCell::new(
                genesis,
                device_id,
                position,
                &[0x5E; 32],
                &register.set,
                &register.profile.storage_set_id,
            )
            .map_err(|e| PeerLineageFailure::Incomplete(format!("{e:?}")))?;
            let routed = cell.routed();
            Ok(self
                .probed
                .iter()
                .map(|value| {
                    crate::route_chain::RouteEntry::at_leader(
                        routed.namespace().to_vec(),
                        *routed.key(),
                        value.clone(),
                        routed.route(),
                    )
                    .encode()
                })
                .collect())
        }
        fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
            let register = Register::resolve(self, NETWORK)?;
            let mut seats = crate::route_chain::fixtures::Cell::at(cell.routed());
            for (parent, value) in &self.routed {
                let from = RootCell::new(
                    &PEER_G,
                    &peer_d(),
                    self.position,
                    parent,
                    &register.set,
                    &register.profile.storage_set_id,
                )
                .map_err(|e| PeerLineageFailure::Incomplete(format!("{e:?}")))?;
                if from.routed().seed() == cell.routed().seed() {
                    seats.write(value, crate::route_chain::ROUTE_LEN - 1, &[]);
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
            _namespace: TaggedHashDomain<'static>,
            addr: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            self.objects.get(addr).cloned().ok_or_else(|| {
                PeerLineageFailure::Incomplete(format!(
                    "no object {} in this test",
                    encode_base32_crockford(addr)
                ))
            })
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

    /// The peer's claim at `position` whose witness was built on `parent`,
    /// signed by the peer, and the manifest and witness it names, by address.
    fn claim_built_on(
        position: u64,
        parent: [u8; 32],
        post: [u8; 32],
        objects: &mut std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Vec<u8> {
        use crate::economic::state::{EconomicBalanceState, EconomicLeafState};
        // A debit: it needs no credit source.
        let mutation = crate::economic::mutation::EconomicLeafMutation::new(
            Some(EconomicLeafState::Balance(
                EconomicBalanceState::new([0x3C; 32], 10).expect("a balance"),
            )),
            Some(EconomicLeafState::Balance(
                EconomicBalanceState::new([0x3C; 32], 3).expect("a balance"),
            )),
            vec![[0x5B; 32]; crate::economic::tree::ECONOMIC_SMT_HEIGHT],
        )
        .expect("a mutation");
        let witness = crate::economic::witness::EconomicTransitionWitness::new(
            parent,
            post,
            [0x31; 32],
            [0x32; 32],
            vec![mutation],
            Vec::new(),
        )
        .expect("a witness")
        .encode()
        .expect("witness bytes");
        let witness_addr = crate::crypto::blake3::domain_hash_bytes(
            TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
            &witness,
        );
        objects.insert(witness_addr, witness);
        let manifest = EconomicAdmissionManifest::new(
            [0x21; 32],
            witness_addr,
            [0x22; 32],
            AdmissionSubstrate::DsmSuccessor {
                evidence_addr: [0x23; 32],
            },
            Vec::new(),
        )
        .expect("a manifest");
        let manifest_addr = manifest.addr().expect("its address");
        objects.insert(manifest_addr, manifest.encode().expect("manifest bytes"));
        let profile = resolve_root_register_profile(NETWORK).expect("the register profile");
        let body = crate::economic::claim::EconomicRootClaimBody::new(
            PEER_G,
            peer_d(),
            position,
            post,
            manifest_addr,
            profile.storage_set_id,
            crate::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
            &peer().pk,
            peer().att_a,
        )
        .expect("a claim body");
        crate::economic::claim_envelope::sign_economic_root_claim(&body, &peer().sk)
            .expect("the peer signs its claim")
    }

    fn identity_of(bytes: &[u8]) -> [u8; 32] {
        claim_identity(
            &crate::economic::claim_envelope::decode_registered_economic_claim(bytes)
                .expect("a claim"),
        )
    }

    /// DSM Amendment A14: the unrouted probe is discovery only. Two claims of
    /// the peer sit under the key, and only the one listed second is final at
    /// the cell routed from the parent its own witness names; the first is
    /// final nowhere. The located claim is the final one, never the first
    /// the probe returned.
    #[test]
    fn only_the_claim_final_at_its_own_route_is_located() {
        let position = 5;
        let mut objects = std::collections::BTreeMap::new();
        let unfinal = claim_built_on(position, [0x42; 32], [0x62; 32], &mut objects);
        let finalized = claim_built_on(position, [0x41; 32], [0x61; 32], &mut objects);
        let fetcher = RoutedClaims {
            position,
            probed: vec![unfinal, finalized.clone()],
            routed: vec![([0x41; 32], finalized.clone())],
            objects,
        };
        let verifier =
            Verifier::new(&fetcher, NETWORK, &NoResolution).expect("the network's register");
        let at = verifier
            .located(&PEER_G, &peer_d(), position, ConditionalAt::Unresolved)
            .expect("one claim is final at its own route");
        assert_eq!(claim_identity(&at.claim), identity_of(&finalized));
        assert_eq!(at.parent.root.economic_root(), [0x41; 32]);
        assert_eq!(at.parent.root.economic_position(), position - 1);
    }

    /// DSM Amendment A14: two claims of the peer at one position, each final
    /// at the cell routed from its own witness's parent, are a fork, refused
    /// with both named, never one chosen.
    #[test]
    fn two_claims_final_at_their_own_routes_are_a_fork_and_refused() {
        let position = 5;
        let mut objects = std::collections::BTreeMap::new();
        let first = claim_built_on(position, [0x41; 32], [0x61; 32], &mut objects);
        let second = claim_built_on(position, [0x42; 32], [0x62; 32], &mut objects);
        let fetcher = RoutedClaims {
            position,
            probed: vec![first.clone(), second.clone()],
            routed: vec![([0x41; 32], first.clone()), ([0x42; 32], second.clone())],
            objects,
        };
        let verifier =
            Verifier::new(&fetcher, NETWORK, &NoResolution).expect("the network's register");
        match verifier.located(&PEER_G, &peer_d(), position, ConditionalAt::Unresolved) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("a fork is refused"), "{why}");
                for claim in [&first, &second] {
                    let named = encode_base32_crockford(&identity_of(claim));
                    assert!(why.contains(&named), "both claims are named: {why}");
                }
            }
            Err(other) => panic!("two final claims are a fork, Invalid, not {other:?}"),
            Ok(at) => panic!(
                "a fork located one claim: {}",
                encode_base32_crockford(&claim_identity(&at.claim))
            ),
        }
    }
}
