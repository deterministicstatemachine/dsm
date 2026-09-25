// SPDX-License-Identifier: Apache-2.0

//! The client side of the economic root register, and the live provenance
//! resolver.
//!
//! ## The root register is a cell (storage spec §9)
//!
//! `K_root(q)` is a keyed cell that keeps every value it is given. Core names
//! the cell and its route ([`RootCell`]); the writer writes the frozen claim
//! along that route, leader first, and Core evaluates the route chains from
//! the raw reads (`dsm::economic::register::read_root_cell`). Nothing is
//! counted and no node decides.
//!
//! ## Frozen envelopes
//!
//! Every envelope is signed ONCE, durably retained BEFORE the first member
//! write, and replayed byte-identically forever. SPHINCS+ signing here is
//! deterministic: a regenerated envelope is indistinguishable from a replayed
//! one downstream, so the safe design is for regeneration to be impossible.

use dsm::economic::claim_envelope::RegisteredEconomicClaim;
use dsm::economic::peer_lineage::ValidatedStart;
use dsm::economic::provenance::{
    PeerLineageFailure, ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
};
use dsm::economic::register::{read_root_cell, RootCell};
use dsm::route_chain::{CellEvidence, CellReading, ChainState, Missing};
use dsm::types::error::DsmError;

use crate::sdk::route_seats::{read_cell, write_recorded, NodeSeats, WriteReport};
use crate::sdk::storage_set::StorageSet;
use crate::util::text_id;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// `K_root(q)` of trader `(genesis, devid)` over the register set of
/// `network_id`: the members of `set`, which must re-derive the network's
/// pinned register id. `parent_root` is the root the caller validated at
/// `q - 1`.
pub(crate) fn root_cell(
    set: &StorageSet,
    network_id: &[u8],
    genesis: &[u8; 32],
    devid: &[u8; 32],
    economic_position: u64,
    parent_root: &[u8; 32],
) -> Result<RootCell, DsmError> {
    let profile = dsm::economic::register::resolve_root_register_profile(network_id)
        .map_err(|e| storage_err("root register profile", e))?;
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    RootCell::new(
        genesis,
        devid,
        economic_position,
        parent_root,
        &members,
        &profile.storage_set_id,
    )
    .map_err(|e| storage_err("root cell", format!("{e:?}")))
}

/// Write this device's frozen root claim at its root cell, along the cell's
/// route (storage spec §9), continuing an earlier write of the same claim.
/// Which claim holds the cell is read back ([`root_claim_settlement`]),
/// never inferred from the write.
pub async fn register_economic_root(
    set: &StorageSet,
    cell: &RootCell,
    frozen_envelope: &[u8],
) -> Result<WriteReport, DsmError> {
    write_recorded(set, cell.routed(), frozen_envelope).await
}

/// What the root cell settled for one claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootClaimSettlement {
    /// The claim is final at the cell: the register holds it.
    Final,
    /// Another claim holds the cell's leader link. No other value will ever
    /// be final there (storage spec §9 finality 2), so this claim never will.
    Lost { holder: RegisteredEconomicClaim },
    /// The cell is not decided for this claim yet: open, held by this claim
    /// but not final, or the evidence in hand does not decide it. A network
    /// status, retried with the same bytes.
    Pending(String),
}

/// Read the root cell and say what it settled for `envelope`.
pub async fn root_claim_settlement(
    set: &StorageSet,
    cell: &RootCell,
    envelope: &[u8],
) -> Result<RootClaimSettlement, DsmError> {
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cell.routed()).await;
    let ours = dsm::storage_cell::entry_digest(envelope);
    Ok(match read_root_cell(cell, &evidence) {
        Ok(CellReading::Held {
            id,
            state: ChainState::Final,
            ..
        }) if id == ours => RootClaimSettlement::Final,
        Ok(CellReading::Held { id, object, .. }) if id != ours => {
            RootClaimSettlement::Lost { holder: object }
        }
        Ok(CellReading::Held { state, .. }) => {
            RootClaimSettlement::Pending(format!("the claim holds the cell, {state:?}"))
        }
        Ok(CellReading::Open) => RootClaimSettlement::Pending("the cell is open".into()),
        Err(missing) => RootClaimSettlement::Pending(missing_text(missing)),
    })
}

/// The LIVE provenance resolver: raw reads of the register cells Core names,
/// the native reserve walked from its genesis state, immutable objects
/// re-hash-verified, peer lineages resolved through the Core walker with the
/// device-local validated-start memo (never authority: an `Invalid` from a
/// memo start discards the memo and re-walks from the activation root).
pub struct LiveRegisterResolver<'a> {
    pub set: &'a StorageSet,
    pub runtime: tokio::runtime::Handle,
    /// The network THIS verifier is validating against — the peer's
    /// committed network must match it (`resolve_for_trader`).
    pub expected_network_id: Vec<u8>,
}

fn incomplete(what: &str, e: impl core::fmt::Display) -> PeerLineageFailure {
    PeerLineageFailure::Incomplete(format!("{what}: {e}"))
}

impl LiveRegisterResolver<'_> {
    fn fetch_bytes(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        tokio::task::block_in_place(|| {
            self.runtime
                .block_on(crate::sdk::storage_io::fetch_immutable(
                    self.set, namespace, addr,
                ))
        })
        .map_err(|e| incomplete("immutable fetch", e))?
        .ok_or_else(|| {
            PeerLineageFailure::Incomplete(format!(
                "no member holds the immutable object {}::{}",
                String::from_utf8_lossy(namespace.source_bytes()),
                text_id::encode_base32_crockford(addr)
            ))
        })
    }

    /// The network's root-register set as THIS device's catalog resolves it.
    ///
    /// Candidates, not authority: the caller re-derives the id from these
    /// pairs and refuses a membership that is not the network's pinned one,
    /// so a misconfigured catalog is caught rather than believed.
    fn register_candidate(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        let set = crate::sdk::storage_set::canonical_set(network_id)
            .map_err(|e| incomplete("root register set", e))?;
        crate::sdk::storage_set::as_ccb_members(&set)
            .map_err(|e| incomplete("root register set", e))
    }

    fn reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        crate::sdk::native_reserve::release_at(
            self.set,
            &self.expected_network_id,
            &self.runtime,
            reserve_id,
            generation,
        )
        .map_err(|e| incomplete("native reserve walk", e))?
        .ok_or_else(|| {
            PeerLineageFailure::Incomplete(format!(
                "the reserve lineage has not reached a final release at generation {generation}"
            ))
        })
    }
}

impl dsm::economic::peer_lineage::PeerEvidenceFetcher for LiveRegisterResolver<'_> {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        self.register_candidate(network_id)
    }

    fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
        let seats = NodeSeats::new(self.set).map_err(|e| incomplete("register seats", e))?;
        Ok(tokio::task::block_in_place(|| {
            self.runtime.block_on(read_cell(&seats, cell.routed()))
        }))
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.reserve_release(reserve_id, generation)
    }

    fn immutable(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.fetch_bytes(namespace, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        anchored_policy_bytes(self.set, policy_commit, &self.runtime)
    }
}

/// Record a peer coordinate this verifier validated. The memo is a cache of
/// this verifier's own conclusions: a failed write loses a shortcut, never a
/// fact, so it is reported and the validated result still stands.
fn memoize(peer_genesis: &[u8; 32], peer_devid: &[u8; 32], result: &ValidatedPeerTransition) {
    let start = ValidatedStart {
        economic_position: result.validated_root().economic_position(),
        economic_root: result.validated_root().economic_root(),
    };
    if let Err(e) = crate::storage::client_db::economic_lineage::record_peer_validated(
        peer_genesis,
        peer_devid,
        &start,
    ) {
        log::warn!("peer lineage memo: not recorded: {e}");
    }
}

/// The memo-aware walk shared by every fetcher-shaped resolver: memo start,
/// Invalid-from-memo re-walk, and the memo write — over WHATEVER
/// `PeerEvidenceFetcher` the caller supplies, so a recording fetcher observes
/// exactly the closure the walk consumed.
pub(crate) fn resolve_peer_with_cache<F: dsm::economic::peer_lineage::PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    peer_economic_position: u64,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    use dsm::economic::peer_lineage::validate_peer_lineage;
    let memo = match crate::storage::client_db::economic_lineage::best_peer_start(
        peer_genesis,
        peer_devid,
        peer_economic_position,
    ) {
        Ok(memo) => memo,
        Err(e) => {
            log::warn!("peer lineage memo: unreadable, walking from the activation root: {e}");
            None
        }
    };
    let first = validate_peer_lineage(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        peer_economic_position,
        memo,
    );
    let result = match (first, memo) {
        // A memo start is never authority: an INVALID verdict from it
        // discards the memo and re-walks from the activation root.
        (Err(PeerLineageFailure::Invalid(reason)), Some(start)) => {
            log::warn!(
                "peer lineage: Invalid from the memo start at {}: {reason}; re-walking",
                start.economic_position
            );
            if let Err(e) = crate::storage::client_db::economic_lineage::clear_peer_lineage(
                peer_genesis,
                peer_devid,
            ) {
                log::warn!("peer lineage memo: not cleared: {e}");
            }
            validate_peer_lineage(
                fetcher,
                expected_network_id,
                peer_genesis,
                peer_devid,
                peer_economic_position,
                None,
            )
        }
        (Ok(validated), Some(start)) => {
            log::debug!(
                "peer lineage: validated from the memo start at {}",
                start.economic_position
            );
            Ok(validated)
        }
        (outcome, None) => outcome,
        (Err(failure), Some(start)) => {
            log::debug!(
                "peer lineage: not established from the memo start at {}: {failure}",
                start.economic_position
            );
            Err(failure)
        }
    }?;
    memoize(peer_genesis, peer_devid, &result);
    Ok(result)
}

/// The walk from the activation root, with no memo start: when the recorded
/// closure has not been proven Stored, a memo start would let the walk
/// skip fetches the durability push then never sees.
pub(crate) fn resolve_peer_with_cache_disabled<
    F: dsm::economic::peer_lineage::PeerEvidenceFetcher,
>(
    fetcher: &F,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    peer_economic_position: u64,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    let result = dsm::economic::peer_lineage::validate_peer_lineage(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        peer_economic_position,
        None,
    )?;
    memoize(peer_genesis, peer_devid, &result);
    Ok(result)
}

/// The RECORDING fetch boundary for recipient prevalidation. It IS the
/// `PeerEvidenceFetcher` the walker consumes, so every immutable object any
/// nested verification fetched lands in `recorded`, exact bytes by exact
/// address.
pub struct RecordingResolver<'a> {
    pub inner: &'a LiveRegisterResolver<'a>,
    /// `(namespace, inner addr, exact verified bytes)` for every immutable
    /// fetch the walk consumed. Register cells are read live along their
    /// routes and are not part of the recorded closure.
    pub recorded: std::cell::RefCell<
        Vec<(
            dsm::crypto::domain::TaggedHashDomain<'static>,
            [u8; 32],
            Vec<u8>,
        )>,
    >,
}

impl<'a> RecordingResolver<'a> {
    pub fn new(inner: &'a LiveRegisterResolver<'a>) -> Self {
        Self {
            inner,
            recorded: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// The memo-aware peer walk, recorded at the fetch boundary.
    pub fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        resolve_peer_with_cache(
            self,
            &self.inner.expected_network_id,
            peer_genesis,
            peer_devid,
            peer_economic_position,
        )
    }
}

impl dsm::economic::peer_lineage::PeerEvidenceFetcher for RecordingResolver<'_> {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        self.inner.register_candidate(network_id)
    }

    fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
        dsm::economic::peer_lineage::PeerEvidenceFetcher::register_cell(self.inner, cell)
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.inner.reserve_release(reserve_id, generation)
    }

    fn immutable(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        let bytes = self.inner.fetch_bytes(namespace, addr)?;
        self.recorded
            .borrow_mut()
            .push((namespace, *addr, bytes.clone()));
        Ok(bytes)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        // Not recorded: policy bytes are the VERIFIER'S OWN rooting in a
        // public object, re-fetchable by anyone holding the commit — not part
        // of the peer's evidence closure.
        anchored_policy_bytes(self.inner.set, policy_commit, &self.inner.runtime)
    }
}

impl ProvenanceResolver for LiveRegisterResolver<'_> {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        self.register_candidate(network_id)
    }

    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        resolve_peer_with_cache(
            self,
            &self.expected_network_id,
            peer_genesis,
            peer_devid,
            peer_economic_position,
        )
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.reserve_release(reserve_id, generation)
    }

    fn immutable_evidence(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.fetch_bytes(namespace, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        anchored_policy_bytes(self.set, policy_commit, &self.runtime)
    }
}

/// A token's policy bytes, rooted by the verifier itself: the local store
/// first, else the immutable object whose identity under `TAG_DSM_POLICY` is
/// the commit, fetched from `set` and re-hashed before anything trusts a
/// byte. Fetched bytes are kept, so the rooting is one-time per device.
/// Unavailable is `Incomplete`, never a permission.
pub(crate) fn anchored_policy_bytes(
    set: &StorageSet,
    policy_commit: &[u8; 32],
    runtime: &tokio::runtime::Handle,
) -> Result<Vec<u8>, PeerLineageFailure> {
    match crate::storage::client_db::token_registry::load_policy_verified(policy_commit) {
        Ok(Some(bytes)) => return Ok(bytes),
        Ok(None) => {}
        Err(e) => {
            return Err(PeerLineageFailure::Incomplete(format!(
                "the local token policy store is unreadable: {e}"
            )))
        }
    }
    let tag = dsm::common::domain_tags::TAG_DSM_POLICY;
    let bytes = tokio::task::block_in_place(|| {
        runtime.block_on(crate::sdk::storage_io::fetch_immutable(
            set,
            tag,
            policy_commit,
        ))
    })
    .map_err(|e| incomplete("token policy fetch", e))?
    .ok_or_else(|| {
        PeerLineageFailure::Incomplete(format!(
            "no member holds the policy {}",
            text_id::encode_base32_crockford(policy_commit)
        ))
    })?;
    if dsm::crypto::blake3::domain_hash_bytes(tag, &bytes) != *policy_commit {
        return Err(PeerLineageFailure::Incomplete(format!(
            "the bytes served for policy {} are not that policy",
            text_id::encode_base32_crockford(policy_commit)
        )));
    }
    if let Err(e) = crate::storage::client_db::token_registry::upsert_policy(policy_commit, &bytes)
    {
        log::warn!("token policy store: not kept: {e}");
    }
    Ok(bytes)
}

pub(crate) fn immutable_object_key(
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    payload: &[u8],
) -> String {
    immutable_object_key_for_inner(
        namespace,
        &dsm::storage_object::immutable_inner(namespace, payload),
    )
}

/// The same key from an already-known inner identity — how a holder of `ta_B`,
/// and not its bytes, names the frozen row that carries them.
pub(crate) fn immutable_object_key_for_inner(
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    inner: &[u8; 32],
) -> String {
    let addr = dsm::storage_object::immutable_addr_from_inner(namespace, inner);
    format!(
        "immutable::{}::{}",
        String::from_utf8_lossy(namespace.source_bytes()),
        text_id::encode_base32_crockford(&addr)
    )
}

/// The reads of a root cell do not decide it yet.
pub(crate) fn missing_text(missing: Missing) -> String {
    match missing {
        Missing::LeaderUnread => "the cell's leader has not been read".into(),
        Missing::LeaderLinkUncommitted => {
            "no ByteCommit of the leader covers the leader link yet".into()
        }
        Missing::SeatUnread { position } => format!("the seat at position {position} is unread"),
        Missing::LinkUncommitted { position } => {
            format!("no ByteCommit of the seat at position {position} covers its link yet")
        }
        Missing::LeaderLinkUnseen { position } => {
            format!("the seat at position {position} has not seen the leader link yet")
        }
    }
}
