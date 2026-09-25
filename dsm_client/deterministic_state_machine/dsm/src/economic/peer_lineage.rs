// SPDX-License-Identifier: Apache-2.0

//! The foreign lineage walker — 5H made concrete.
//!
//! Given a peer's `(G, DevID)` and a target economic position, walk the
//! peer's registered lineage from a trusted start (the canonical empty root,
//! or a caller-supplied memo of THIS verifier's own earlier conclusion) and
//! validate every step with the SAME `advance_validated` any device runs.
//! `ValidatedEconomicRoot` stays unconstructible from network data — the
//! walker only ever holds one because the verifier returned it.
//!
//! ## Iterative, budgeted, typed
//!
//! The peer is adversarial: an acyclic lineage can still be arbitrarily
//! deep. Positions walk in a LOOP; cross-identity resolution (a peer's
//! witness funding from a third identity) re-enters through
//! [`WalkingResolver`] with a shared, depth-capped state — the explicit
//! `in_progress` set turns revisits into provenance-cycle refusals, and any
//! budget exhausting is `Incomplete`, never `Invalid`.
//!
//! ## Every fact is recomputed, nothing is taken from the claimant
//!
//! Per step: the register cell's winner decodes and self-verifies; the
//! manifest, authority evidence, witness and successor evidence are fetched
//! by content address; P0–P6 recovers the AK and the committed network;
//! `resolve_for_trader` requires the expected network; the claim's key must
//! BE the proven AK; the successor evidence's `sigma_dsm` must verify under
//! it. Only then does `advance_validated` run its conjuncts.

use std::collections::{HashMap, HashSet};

use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
    TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
};
use crate::crypto::domain::TaggedHashDomain;
use crate::economic::authority_evidence::{verify_authority_evidence, AuthorityEvidenceError};
use crate::economic::claim::AdmissionSubstrate;
use crate::economic::decode::decode_admission_manifest;
use crate::economic::lineage::{
    activate, advance_validated, AcceptedSubstrate, EconomicActivationSnapshot,
    EconomicValidationError, ValidatedEconomicRoot,
};
use crate::economic::provenance::{
    PeerLineageFailure, ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
};
use crate::economic::register::{
    read_root_cell, resolve_for_trader, resolve_root_register_profile, RegisteredEconomicRoot,
    RootCell,
};
use crate::route_chain::{CellEvidence, CellReading, ChainState};
use crate::economic::successor_evidence::verify_dsm_successor_evidence;
use crate::utils::text_id::encode_base32_crockford;
use crate::economic::witness::EconomicTransitionWitness;

/// Total step budget for one walk, across ALL identities it touches.
const WALK_STEP_BUDGET: usize = 512;
/// Cross-identity resolver re-entry depth cap — bounds the Rust stack, since
/// each re-entry is one frame; positions within one identity are a loop.
const CROSS_IDENTITY_DEPTH_CAP: usize = 32;

/// I/O the walker needs: raw reads of the register cells the walker names,
/// and immutable objects by address. The fetcher supplies bytes, never a
/// verdict: the walker evaluates every cell's route chains itself and
/// re-checks every address.
pub trait PeerEvidenceFetcher {
    /// Every seat's reads of `cell` (storage spec §9): the values each seat
    /// holds, its committed state from a mirror, and each later seat's own
    /// mirror of the leader. The walker evaluates them.
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
    /// the walker's own anchoring (local store or the authoritative
    /// content-addressed path). The verifier re-hashes against the commit;
    /// unavailable is `Incomplete`, never `Invalid`.
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
}

/// A trusted starting memo: a coordinate THIS verifier validated earlier
/// (device-local cache of its own conclusions — never authority over the
/// live register; a walk that fails `Invalid` from a memo start must be
/// retried from position 0 with the memo discarded).
#[derive(Debug, Clone, Copy)]
pub struct ValidatedStart {
    pub economic_position: u64,
    pub economic_root: [u8; 32],
}

/// One walk's shared state.
struct WalkState {
    steps_remaining: usize,
    depth: usize,
    in_progress: HashSet<([u8; 32], [u8; 32], u64)>,
    memo: HashMap<([u8; 32], [u8; 32], u64), ValidatedPeerTransition>,
}

/// The walker's re-entrant resolver: answers reserve-release questions from
/// the fetcher and peer-transition questions by walking THAT peer, sharing
/// the budget, memo, depth cap and cycle set.
struct WalkingResolver<'a> {
    fetcher: &'a dyn PeerEvidenceFetcher,
    expected_network_id: &'a [u8],
    state: std::cell::RefCell<&'a mut WalkState>,
}

impl ProvenanceResolver for WalkingResolver<'_> {
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let mut state = self.state.borrow_mut();
        walk_with_state(
            self.fetcher,
            self.expected_network_id,
            peer_genesis,
            peer_devid,
            peer_economic_position,
            None,
            &mut state,
        )
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.fetcher.native_reserve_release(reserve_id, generation)
    }

    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
        self.fetcher.root_register_candidate_set(network_id)
    }

    fn immutable_evidence(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.fetcher.immutable(namespace, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.fetcher.anchored_policy_bytes(policy_commit)
    }
}

/// Validate a peer's lineage up to `target_position` and return that step's
/// validated transition.
pub fn validate_peer_lineage(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
    start: Option<ValidatedStart>,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    let mut state = WalkState {
        steps_remaining: WALK_STEP_BUDGET,
        depth: 0,
        in_progress: HashSet::new(),
        memo: HashMap::new(),
    };
    walk_with_state(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        target_position,
        start,
        &mut state,
    )
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

fn walk_with_state(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
    start: Option<ValidatedStart>,
    state: &mut WalkState,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    if target_position == 0 {
        return Err(invalid(
            "position 0 is the activation root; it has no transition to validate",
        ));
    }
    let key = (*peer_genesis, *peer_devid, target_position);
    if let Some(hit) = state.memo.get(&key) {
        return Ok(hit.clone());
    }
    if state.in_progress.contains(&key) {
        return Err(invalid(
            "provenance cycle: this exact peer transition is already being validated on \
             this walk — validation edges must point strictly backward",
        ));
    }
    if state.depth >= CROSS_IDENTITY_DEPTH_CAP {
        return Err(incomplete(
            "cross-identity resolution depth cap reached — walk budget, not a forgery",
        ));
    }
    state.in_progress.insert(key);
    state.depth += 1;
    let result = walk_positions(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        target_position,
        start,
        state,
    );
    state.depth -= 1;
    state.in_progress.remove(&key);
    if let Ok(v) = &result {
        state.memo.insert(key, v.clone());
    }
    result
}

/// The per-identity position loop — iterative by construction.
#[allow(clippy::too_many_arguments)]
fn walk_positions(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
    start: Option<ValidatedStart>,
    state: &mut WalkState,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    // The register's committed set: this network's pinned set, which the
    // local catalog's candidate must re-derive. Every root cell of the walk
    // is routed over it. A catalog that offers another set is this
    // verifier's own fault, never the peer's, so it is not `Invalid`.
    let profile = resolve_root_register_profile(expected_network_id)
        .map_err(|e| incomplete(format!("no root register for this network: {e}")))?;
    let register_set = fetcher.root_register_candidate_set(expected_network_id)?;
    profile.verify_candidate(&register_set).map_err(|e| {
        incomplete(format!(
            "the catalog's root register set is not the pinned one: {e}"
        ))
    })?;

    // The trusted start: this verifier's own earlier conclusion, or the
    // canonical empty activation root — NEVER anything read from a network.
    // A memo at or past the target starts nothing.
    let memo = start.filter(|s| s.economic_position < target_position);
    let (mut validated, first_position) = match memo {
        // A memo is this verifier's own earlier conclusion about a peer, so it
        // is a settled single-root coordinate by construction: the walk can
        // only conclude at a position that produced a validated root, and it
        // refuses a conditional one (`Unresolved`) before ever getting there.
        Some(s) => (
            ValidatedEconomicRoot::from_verifier_memo(s.economic_position, s.economic_root),
            s.economic_position + 1,
        ),
        None => (
            activate(EconomicActivationSnapshot::fresh())
                .map_err(|e| invalid(format!("activation shape: {e}")))?,
            1,
        ),
    };

    #[allow(clippy::type_complexity)]
    let mut last: Option<(
        EconomicTransitionWitness,
        Vec<u8>,
        crate::types::operations::Operation,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    )> = None;
    for position in first_position..=target_position {
        if state.steps_remaining == 0 {
            return Err(incomplete(
                "peer lineage walk budget exhausted — retry with a cached start",
            ));
        }
        state.steps_remaining -= 1;

        // 1. The claim final at this position's root cell. The route is seeded
        // by the root THIS walk validated at the previous position, over the
        // pinned register set. Only a claim naming `K_root(q)` is recognized
        // there, and the key is a hash of `(G, DevID, q)`, so the claim that
        // holds the cell is this trader's at this position; any other bytes
        // at the cell count as nothing, however early they arrived.
        let cell = RootCell::new(
            peer_genesis,
            peer_devid,
            position,
            &validated.economic_root(),
            &register_set,
            &profile.storage_set_id,
        )
        .map_err(|e| incomplete(format!("root cell at {position}: {e:?}")))?;
        let evidence = fetcher.register_cell(&cell)?;
        let claim = match read_root_cell(&cell, &evidence) {
            Ok(CellReading::Held {
                object,
                state: ChainState::Final,
                ..
            }) => object,
            Ok(CellReading::Held {
                state: ChainState::LeaderHeld | ChainState::Preserved,
                ..
            }) => {
                return Err(incomplete(format!(
                    "position {position}: the claim holding the root cell is not final yet"
                )))
            }
            Ok(CellReading::Open) => {
                return Err(incomplete(format!(
                    "position {position}: no claim holds the root cell"
                )))
            }
            Err(missing) => {
                return Err(incomplete(format!(
                    "position {position}: the root cell is not decided yet: {missing:?}"
                )))
            }
        };

        // A conditional position is its own answer: the claim is authentic
        // and has selected no root, so the peer is mid-route, not forging.
        let claim = claim.single_root().map_err(|conditional| {
            PeerLineageFailure::Unresolved(format!(
                "peer {}/{} at position {position}: {conditional}",
                encode_base32_crockford(peer_genesis),
                encode_base32_crockford(peer_devid)
            ))
        })?;
        let body = claim.body().clone();

        // 2. The manifest, by content address.
        let manifest_bytes = fetcher.immutable(
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

        // 3. Authority: P0–P6 from portable evidence; recover AK + network.
        let authority_bytes = fetcher.immutable(
            TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
            &manifest.authority_evidence_addr,
        )?;
        let facts = verify_authority_evidence(
            &authority_bytes,
            peer_genesis,
            peer_devid,
            &manifest.authority_position,
        )
        .map_err(|e| match e {
            AuthorityEvidenceError::Incomplete(m) => incomplete(m),
            other => invalid(other.to_string()),
        })?;
        // The committed network must be the one we are validating against,
        // and the register set the claim binds must be that network's
        // canonical set — never sourced from transfer metadata or contacts.
        // The pinned id covers every `(member, incarnation)` pair, so a claim
        // written under a member's old incarnation does not name it.
        let trader_profile = resolve_for_trader(&facts.network_id, expected_network_id)
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

        // 4. The witness and the successor evidence, by content address.
        let witness_bytes = fetcher.immutable(
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
        let successor_bytes =
            fetcher.immutable(TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, &successor_addr)?;
        let verified = verify_dsm_successor_evidence(
            &successor_bytes,
            peer_genesis,
            peer_devid,
            &facts.proven_ak,
        )
        .map_err(|e| invalid(format!("successor evidence at {position}: {e}")))?;
        let accepted = AcceptedSubstrate::from_verified_dsm_successor(
            verified.operation.clone(),
            verified.c_dsm_plus,
            verified.embedded_parent,
            successor_addr,
        );

        // 5. The same conjuncts any device runs, over the verified claim.
        let registered = RegisteredEconomicRoot::from_verified_single_root(claim);
        let resolver = WalkingResolver {
            fetcher,
            expected_network_id,
            state: std::cell::RefCell::new(&mut *state),
        };
        let advanced = advance_validated(
            &validated,
            &registered,
            &manifest,
            &witness,
            &accepted,
            &resolver,
            peer_genesis,
            peer_devid,
            &facts.network_id,
            &facts.proven_ak,
        )
        .map_err(|e| step_failure(position, e))?;
        validated = advanced.root;
        last = Some((
            witness,
            facts.proven_ak.clone(),
            verified.operation,
            verified.c_dsm_plus,
            verified.embedded_parent,
            manifest_addr,
        ));
    }

    let (witness, proven_ak, verified_operation, c_dsm_plus, embedded_parent, manifest_addr) = last
        .ok_or_else(|| {
            incomplete("walk had no steps — the start memo already covers the target")
        })?;
    // SINGLE-ROOT BY CONSTRUCTION, not by label. Every position this walk
    // traversed decoded as a single-root claim: a conditional `C_q` is refused
    // above with `Unresolved`, resolved or not, because resolution is
    // verifier-local and never rewrites the register cell. So the one lineage
    // this function can honestly assert is the one it asserts here.
    Ok(ValidatedPeerTransition::single_root_from_walk(
        *peer_genesis,
        *peer_devid,
        validated,
        witness,
        proven_ak,
        c_dsm_plus,
        embedded_parent,
        verified_operation,
        manifest_addr,
    ))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sofi::wire::SofiResolutionClaim;

    const PEER_G: [u8; 32] = [0x11; 32];
    const PEER_D: [u8; 32] = [0x22; 32];
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

    fn conditional_claim(position: u64) -> SofiResolutionClaim {
        SofiResolutionClaim {
            genesis: PEER_G,
            device_id: PEER_D,
            position,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
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
            writes: vec![conditional_claim(position).encode()],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        let err = validate_peer_lineage(
            &fetcher,
            NETWORK,
            &PEER_G,
            &PEER_D,
            position,
            Some(ValidatedStart {
                economic_position: position - 1,
                economic_root: [0x77; 32],
            }),
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

    /// A claim naming other coordinates never holds the root cell (storage
    /// spec §9 rule 3): only a claim whose own coordinates derive `K_root(q)`
    /// is recognized there, so a foreign claim written first blocks nothing,
    /// and a cell holding only foreign claims is open.
    #[test]
    fn a_claim_naming_other_coordinates_never_holds_the_root_cell() {
        let position = 3;
        let foreign = SofiResolutionClaim {
            genesis: [0x99; 32],
            device_id: [0x88; 32],
            position,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        };
        let ours = SofiResolutionClaim {
            genesis: PEER_G,
            device_id: PEER_D,
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
                &PEER_D,
                position,
                Some(ValidatedStart {
                    economic_position: position - 1,
                    economic_root: [0x77; 32],
                }),
            )
        };
        assert!(
            matches!(
                walk(vec![foreign.encode()]),
                Err(PeerLineageFailure::Incomplete(ref m)) if m.contains("no claim holds")
            ),
            "a cell holding only a foreign claim is open"
        );
        assert!(
            matches!(
                walk(vec![foreign.encode(), ours.encode()]),
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
                writes: vec![conditional_claim(position).encode()],
                last,
            };
            let outcome = validate_peer_lineage(
                &fetcher,
                NETWORK,
                &PEER_G,
                &PEER_D,
                position,
                Some(ValidatedStart {
                    economic_position: position - 1,
                    economic_root: [0x77; 32],
                }),
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
            writes: vec![claim.encode()],
            last: crate::route_chain::ROUTE_LEN - 1,
        };
        let outcome = validate_peer_lineage(
            &fetcher,
            NETWORK,
            &PEER_G,
            &PEER_D,
            position,
            Some(ValidatedStart {
                economic_position: position - 1,
                economic_root: [0x77; 32],
            }),
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
}
