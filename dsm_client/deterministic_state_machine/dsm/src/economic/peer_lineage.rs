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
use crate::economic::claim_envelope::decode_and_verify_economic_root_claim;
use crate::economic::decode::decode_admission_manifest;
use crate::economic::lineage::{
    activate, advance_validated, AcceptedSubstrate, EconomicActivationSnapshot,
    ValidatedEconomicRoot,
};
use crate::economic::provenance::{
    FaucetTicketWin, PeerLineageFailure, ProvenanceResolver, ValidatedPeerTransition,
};
use crate::economic::register::{
    economic_root_register_key, resolve_for_trader, RegisteredEconomicRoot,
};
use crate::economic::successor_evidence::verify_dsm_successor_evidence;
use crate::economic::witness::EconomicTransitionWitness;

/// Total step budget for one walk, across ALL identities it touches.
const WALK_STEP_BUDGET: usize = 512;
/// Cross-identity resolver re-entry depth cap — bounds the Rust stack, since
/// each re-entry is one frame; positions within one identity are a loop.
const CROSS_IDENTITY_DEPTH_CAP: usize = 32;

/// I/O the walker needs, verified at the boundary: register winners at
/// quorum, and immutable objects whose bytes re-hash to their address. The
/// walker re-checks the address anyway — a fetcher cannot substitute bytes.
pub trait PeerEvidenceFetcher {
    /// The quorum-agreed winner bytes for one economic-root register cell,
    /// or `None` when no quorum winner exists (⇒ `Incomplete` upstream).
    /// Divergent non-identical values must surface as `Quarantined`.
    fn register_cell(&self, k_root: &[u8; 32]) -> Result<Option<Vec<u8>>, PeerLineageFailure>;
    /// The quorum-agreed winner bytes for one faucet-ticket cell.
    fn faucet_ticket_cell(
        &self,
        faucet_id: &[u8; 32],
        ticket_index: u64,
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure>;
    /// Exact immutable bytes at `addr` under `namespace`.
    fn immutable(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
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

/// The walker's re-entrant resolver: answers faucet-ticket questions from
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

    fn winning_faucet_ticket(
        &self,
        faucet_id: &[u8; 32],
        ticket_index: u64,
    ) -> Option<FaucetTicketWin> {
        self.fetcher
            .faucet_ticket_cell(faucet_id, ticket_index)
            .ok()
            .flatten()
            .map(|envelope_bytes| FaucetTicketWin { envelope_bytes })
    }

    fn immutable_evidence(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.fetcher.immutable(namespace, addr)
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
    // The trusted start: this verifier's own earlier conclusion, or the
    // canonical empty activation root — NEVER anything read from a network.
    let (mut validated, first_position) = match start {
        Some(s) if s.economic_position < target_position => (
            ValidatedEconomicRoot::rehydrate_from_admitted_store(
                s.economic_position,
                s.economic_root,
            ),
            s.economic_position + 1,
        ),
        _ => (
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
    )> = None;
    for position in first_position..=target_position {
        if state.steps_remaining == 0 {
            return Err(incomplete(
                "peer lineage walk budget exhausted — retry with a cached start",
            ));
        }
        state.steps_remaining -= 1;

        // 1. The register winner for this position.
        let k_root = economic_root_register_key(peer_genesis, peer_devid, position);
        let cell = fetcher
            .register_cell(&k_root)?
            .ok_or_else(|| incomplete(format!("position {position} has no quorum winner")))?;
        let claim = decode_and_verify_economic_root_claim(&cell)
            .map_err(|e| invalid(format!("register winner at {position}: {e}")))?;
        let body = claim.body;
        if body.trader_genesis != *peer_genesis
            || body.trader_devid != *peer_devid
            || body.economic_position != position
        {
            return Err(invalid(format!(
                "register winner at {position} names different coordinates"
            )));
        }

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
        let profile = resolve_for_trader(&facts.network_id, expected_network_id)
            .map_err(|e| invalid(format!("peer network refused: {e}")))?;
        if body.root_register_storage_set_id != profile.storage_set_id {
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

        // 5. The same conjuncts any device runs.
        let registered = RegisteredEconomicRoot {
            trader_genesis: *peer_genesis,
            trader_devid: *peer_devid,
            economic_position: position,
            post_economic_root: body.post_economic_root,
            admission_manifest_addr: body.admission_manifest_addr,
            storage_set_id: body.root_register_storage_set_id,
        };
        let resolver = WalkingResolver {
            fetcher,
            expected_network_id,
            state: std::cell::RefCell::new(&mut *state),
        };
        let (next, _funded) = advance_validated(
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
        .map_err(|e| invalid(format!("validation at {position}: {e}")))?;
        validated = next;
        last = Some((
            witness,
            facts.proven_ak.clone(),
            verified.operation,
            verified.c_dsm_plus,
        ));
    }

    let (witness, proven_ak, verified_operation, c_dsm_plus) = last.ok_or_else(|| {
        incomplete("walk had no steps — the start memo already covers the target")
    })?;
    Ok(ValidatedPeerTransition {
        peer_genesis: *peer_genesis,
        peer_devid: *peer_devid,
        validated_root: validated,
        witness,
        proven_ak,
        c_dsm_plus,
        verified_operation,
    })
}
