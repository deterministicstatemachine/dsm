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
use dsm::economic::lineage::{AcceptedClaim, ValidatedEconomicRoot};
use dsm::economic::peer_lineage::{
    peer_claim_reached, peer_root_reached, validate_peer_lineage, ConditionalPositionResolver,
    PeerEvidenceFetcher, PeerFrontier, PeerFrontiers, ValidatedPeerLineage,
};
use dsm::sofi::wire::ParentClaimRef;
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

/// What the root cell after a validated position holds, read at its leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NextRootCell {
    /// The leader holds no claim for the next position: the identity has not
    /// moved past the validated one.
    Open,
    /// A claim holds the next position, in any chain state: the identity has
    /// moved on (or is moving), so the validated position is not its latest.
    Held,
    /// The evidence in hand does not decide the cell (an unread leader, an
    /// uncommitted link). Asked again, never read as either answer.
    Undecided(String),
}

/// Read `K_root(position + 1)` of `(genesis, devid)`, whose route is seeded
/// by `root`, the root validated at `position` (DSM §9: "what root does the
/// device hold at the next position?").
pub(crate) async fn next_root_cell(
    set: &StorageSet,
    network_id: &[u8],
    genesis: &[u8; 32],
    devid: &[u8; 32],
    position: u64,
    root: &[u8; 32],
) -> Result<NextRootCell, DsmError> {
    let next = position.checked_add(1).ok_or_else(|| {
        DsmError::invalid_operation(format!("position {position} has no successor"))
    })?;
    let cell = root_cell(set, network_id, genesis, devid, next, root)?;
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cell.routed()).await;
    Ok(match read_root_cell(&cell, &evidence) {
        Ok(CellReading::Open) => NextRootCell::Open,
        Ok(CellReading::Held { .. }) => NextRootCell::Held,
        Err(missing) => NextRootCell::Undecided(missing_text(missing)),
    })
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
    Lost {
        holder: Box<RegisteredEconomicClaim>,
    },
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
        Ok(CellReading::Held { id, object, .. }) if id != ours => RootClaimSettlement::Lost {
            holder: Box::new(object),
        },
        Ok(CellReading::Held { state, .. }) => {
            RootClaimSettlement::Pending(format!("the claim holds the cell, {state:?}"))
        }
        Ok(CellReading::Open) => RootClaimSettlement::Pending("the cell is open".into()),
        Err(missing) => RootClaimSettlement::Pending(missing_text(missing)),
    })
}

/// The LIVE provenance resolver: raw reads of the register cells Core names,
/// the native reserve walked from its genesis state, immutable objects
/// re-hash-verified, and peer lineages verified by Core from this device's
/// frontier for each peer (DSM Amendment A8).
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

    /// A step's manifest names the three objects a walk asks for next: the
    /// authority evidence, the transition witness and the successor evidence.
    /// They are fetched together into the kept objects, so the walk's three
    /// asks find them there instead of each waiting on a round trip of its
    /// own. A fetch that fails here changes nothing: the walk asks for that
    /// object itself and meets the failure there.
    fn prefetch_step_objects(&self, manifest_bytes: &[u8]) {
        use dsm::common::domain_tags::{
            TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE, TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE,
            TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
        };
        let manifest = match dsm::economic::decode::decode_admission_manifest(manifest_bytes) {
            Ok(manifest) => manifest,
            Err(e) => {
                // The walk decodes the same bytes and refuses them itself.
                log::debug!("step prefetch: not a manifest: {e}");
                return;
            }
        };
        let mut wanted = vec![
            (
                TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
                manifest.authority_evidence_addr,
            ),
            (
                TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
                manifest.transition_witness_addr,
            ),
        ];
        if let dsm::economic::claim::AdmissionSubstrate::DsmSuccessor { evidence_addr } =
            manifest.substrate
        {
            wanted.push((TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, evidence_addr));
        }
        let fetched = tokio::task::block_in_place(|| {
            self.runtime
                .block_on(futures::future::join_all(wanted.iter().map(
                    |(namespace, addr)| {
                        crate::sdk::storage_io::fetch_immutable(self.set, *namespace, addr)
                    },
                )))
        });
        for (fetch, (namespace, addr)) in fetched.into_iter().zip(&wanted) {
            if let Err(e) = fetch {
                log::debug!(
                    "step prefetch of {}::{}: {e}",
                    String::from_utf8_lossy(namespace.source_bytes()),
                    text_id::encode_base32_crockford(addr)
                );
            }
        }
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
        // A claim final at a root cell holds it for good (storage spec §9,
        // finality 2): reads Core evaluated as showing one are kept, and a
        // later walk through the same position evaluates them again instead
        // of reading the route.
        if let Some(kept) = crate::sdk::final_reads::final_cell(cell.routed()) {
            return Ok(kept);
        }
        let seats = NodeSeats::new(self.set).map_err(|e| incomplete("register seats", e))?;
        let evidence =
            tokio::task::block_in_place(|| self.runtime.block_on(read_cell(&seats, cell.routed())));
        if matches!(
            read_root_cell(cell, &evidence),
            Ok(CellReading::Held {
                state: ChainState::Final,
                ..
            })
        ) {
            crate::sdk::final_reads::keep_final_cell(cell.routed(), &evidence);
        }
        Ok(evidence)
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
        let bytes = self.fetch_bytes(namespace, addr)?;
        if namespace.source_bytes()
            == dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST.source_bytes()
        {
            self.prefetch_step_objects(&bytes);
        }
        Ok(bytes)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        anchored_policy_bytes(self.set, policy_commit, &self.runtime)
    }
}

/// This receiver's frontiers, as its store records them (DSM Amendment A8).
pub struct StoredFrontiers;

/// Whether `(genesis, device_id)` is this device's own identity.
fn is_this_device(genesis: &[u8; 32], device_id: &[u8; 32]) -> bool {
    let own_genesis = crate::sdk::app_state::AppState::get_genesis_hash();
    let own_device = crate::sdk::app_state::AppState::get_device_id();
    own_genesis.as_deref() == Some(genesis.as_slice())
        && own_device.as_deref() == Some(device_id.as_slice())
}

impl PeerFrontiers for StoredFrontiers {
    fn frontier_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Option<PeerFrontier>, PeerLineageFailure> {
        let unreadable = |e: anyhow::Error| {
            PeerLineageFailure::Incomplete(format!("the frontier store is unreadable: {e}"))
        };
        let recorded = crate::storage::client_db::economic_lineage::frontier_below(
            genesis, device_id, position,
        )
        .map_err(unreadable)?;
        // This device's own lineage is never walked: every credit a wallet
        // holds from this device names it as a source, and the walk went
        // back through this device's whole history, position by position.
        let own = if is_this_device(genesis, device_id) {
            crate::storage::client_db::economic_lineage::own_frontier_below(
                genesis, device_id, position,
            )
            .map_err(unreadable)?
        } else {
            None
        };
        let frontier = match (recorded, own) {
            (Some(r), Some(o)) if o.economic_position() > r.economic_position() => Some(o),
            (None, Some(o)) => Some(o),
            (r, _) => r,
        };
        log::info!(
            "[A8] peer {} below position {position}: walk starts at {}",
            text_id::encode_base32_crockford(device_id),
            match &frontier {
                Some(f) => format!("the frontier at {}", f.economic_position()),
                None => "the activation root".to_string(),
            }
        );
        Ok(frontier)
    }
}

/// A peer's lineage verified to `peer_economic_position` from this
/// receiver's frontier (DSM Amendment A8): the target step's validated
/// transition, for a caller that accepts nothing from the peer and so records
/// none of the frontiers the walk reached.
///
/// A position's lineage is fixed once it exists (each step commits to its
/// parent), so a walk that validated it once validates it every time. This
/// process keeps each one it validated, by network, peer and position, and
/// answers the same question from it: a vault's chain names the same traders
/// at the same positions generation after generation, and walking each from
/// its activation root again re-verified every signature on the way. Only a
/// validation is kept: a refusal or an incomplete walk is walked again. It is
/// memory, never a recorded frontier (A8 records one only on acceptance).
///
/// A walk for another position of the same peer starts from the highest
/// coordinate this process validated below it ([`RememberedFrontiers`]), when
/// that is above the receiver's recorded frontier: the coordinate a walk
/// reached ([`PeerFrontier::reached_by`]) and every credit source's frontier
/// it validated on the way stand at the end of a complete validated segment
/// (owner ruling 2026-10-01), so only the suffix past them is walked. A
/// vault's chain names its traders at a new position every generation, and
/// each was walked from the recorded frontier again.
pub(crate) fn resolve_peer<F: PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    peer_economic_position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    let key = (
        expected_network_id.to_vec(),
        *peer_genesis,
        *peer_devid,
        peer_economic_position,
    );
    if let Some(known) = validated_peers().get(&key) {
        return Ok(known);
    }
    validated_peers().walks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (validated, sources) = validate_peer_lineage(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        peer_economic_position,
        &RememberedFrontiers {
            network: expected_network_id,
        },
        conditional,
    )?
    .into_parts();
    log::info!(
        "[A8] peer {} validated at position {peer_economic_position}",
        text_id::encode_base32_crockford(peer_devid)
    );
    for reached in PeerFrontier::reached_by(&validated).into_iter().chain(sources) {
        validated_peers().reach(expected_network_id, reached);
    }
    validated_peers().keep(key, validated.clone());
    Ok(validated)
}

/// The frontiers a walk for [`resolve_peer`] starts from: the receiver's
/// recorded frontier below the position, or the highest coordinate this
/// process validated below it on `network`, whichever is higher.
pub(crate) struct RememberedFrontiers<'a> {
    pub(crate) network: &'a [u8],
}

impl PeerFrontiers for RememberedFrontiers<'_> {
    fn frontier_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Option<PeerFrontier>, PeerLineageFailure> {
        let recorded = StoredFrontiers.frontier_below(genesis, device_id, position)?;
        let floor = recorded.as_ref().map_or(0, PeerFrontier::economic_position);
        match validated_peers().reached_below(self.network, genesis, device_id, position) {
            Some(remembered) if remembered.economic_position() > floor => {
                log::info!(
                    "[A8] peer {} below position {position}: walk starts at {}, which this \
                     process validated",
                    text_id::encode_base32_crockford(device_id),
                    remembered.economic_position()
                );
                Ok(Some(remembered))
            }
            Some(_) | None => Ok(recorded),
        }
    }
}

/// The root a trader's lineage selected at a position and the reference a
/// later `P` names it by (`SofiReads::trader_root_at`): what the
/// frontier-relative walk of the lineage to that position establishes.
///
/// A position's lineage is fixed once it exists, so the walk that validated
/// it once validates it every time, and the root it reached is that root for
/// good. This process keeps each one by network, trader and position, as
/// [`resolve_peer`] keeps a validated transition: a holdings status asked
/// every few seconds walked the wallet's whole lineage on every poll, and a
/// vault walk asked the same trader's parent for every exercise naming it.
/// Only a complete walk is kept; a refusal, an incomplete or an unresolved
/// walk is walked again. The walk starts from [`RememberedFrontiers`], and
/// the coordinates it validated are kept for later walks of the same trader,
/// as `resolve_peer`'s are. Nothing is recorded as a frontier.
pub(crate) fn resolve_peer_root<F: PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<(ValidatedEconomicRoot, ParentClaimRef), PeerLineageFailure> {
    let key = (expected_network_id.to_vec(), *genesis, *device_id, position);
    if let Some(known) = validated_peers().roots.get(&key) {
        return Ok(known);
    }
    validated_peers()
        .root_walks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (known, reached) = peer_root_reached(
        fetcher,
        expected_network_id,
        genesis,
        device_id,
        position,
        &RememberedFrontiers {
            network: expected_network_id,
        },
        conditional,
    )?
    .into_parts();
    log::info!(
        "[A8] trader {} root validated at position {position}",
        text_id::encode_base32_crockford(device_id)
    );
    for frontier in reached {
        validated_peers().reach(expected_network_id, frontier);
    }
    validated_peers().roots.keep(key, known);
    Ok(known)
}

/// The claim a trader's lineage accepted at a position
/// (`SofiReads::accepted_claim_at` for another trader): what a setup naming
/// that position is checked against, by the frontier-relative walk of the
/// lineage to it (SoFi Amendment S15, MR-SOFI-0347).
///
/// Kept as [`resolve_peer_root`] keeps a root, and for the same reason: the
/// claim accepted at a position is fixed once the walk reached it. Route
/// evidence asked it once per setup in every acquisition round, and a vault
/// walk asked it again for every exercise of the same trader. Only a
/// complete walk is kept; the walk starts from [`RememberedFrontiers`] and
/// the coordinates it validated are kept. Nothing is recorded as a frontier.
pub(crate) fn resolve_peer_claim<F: PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<AcceptedClaim, PeerLineageFailure> {
    let key = (expected_network_id.to_vec(), *genesis, *device_id, position);
    if let Some(known) = validated_peers().claims.get(&key) {
        return Ok(known);
    }
    validated_peers()
        .claim_walks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (accepted, reached) = peer_claim_reached(
        fetcher,
        expected_network_id,
        genesis,
        device_id,
        position,
        &RememberedFrontiers {
            network: expected_network_id,
        },
        conditional,
    )?
    .into_parts();
    log::info!(
        "[A8] trader {} claim validated at position {position}",
        text_id::encode_base32_crockford(device_id)
    );
    for frontier in reached {
        validated_peers().reach(expected_network_id, frontier);
    }
    validated_peers().claims.keep(key, accepted);
    Ok(accepted)
}

/// The peer positions this process validated (see [`resolve_peer`]).
type PeerKey = (Vec<u8>, [u8; 32], [u8; 32], u64);
/// A peer on a network: whose validated coordinates [`ValidatedPeers`] keeps.
type PeerOn = (Vec<u8>, [u8; 32], [u8; 32]);

/// What complete walks established, by network, peer and position.
struct Kept<V> {
    entries: std::sync::Mutex<std::collections::HashMap<PeerKey, V>>,
}

impl<V: Clone> Kept<V> {
    fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
    /// The kept answers. A thread that panicked holding the lock left whole
    /// entries behind (each is inserted in one step), so the map is taken as
    /// it stands.
    fn entries(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<PeerKey, V>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
    fn get(&self, key: &PeerKey) -> Option<V> {
        self.entries().get(key).cloned()
    }
    fn keep(&self, key: PeerKey, value: V) {
        let mut entries = self.entries();
        if entries.len() >= VALIDATED_PEERS_MAX {
            entries.clear();
        }
        entries.insert(key, value);
    }
}

pub(crate) struct ValidatedPeers {
    kept: Kept<ValidatedPeerTransition>,
    /// The roots [`resolve_peer_root`] established.
    roots: Kept<(ValidatedEconomicRoot, ParentClaimRef)>,
    /// The claims [`resolve_peer_claim`] established.
    claims: Kept<AcceptedClaim>,
    /// The coordinates walks validated, by peer and position.
    reached: std::sync::Mutex<
        std::collections::HashMap<PeerOn, std::collections::BTreeMap<u64, PeerFrontier>>,
    >,
    /// The walks [`resolve_peer`] made: each question the memory did not answer.
    walks: std::sync::atomic::AtomicU64,
    /// The walks [`resolve_peer_root`] made.
    root_walks: std::sync::atomic::AtomicU64,
    /// The walks [`resolve_peer_claim`] made.
    claim_walks: std::sync::atomic::AtomicU64,
}

/// More than a phone's traders: past it the memory starts over, and the next
/// walk of each position is a full walk again.
const VALIDATED_PEERS_MAX: usize = 4096;

impl ValidatedPeers {
    fn get(&self, key: &PeerKey) -> Option<ValidatedPeerTransition> {
        self.kept.get(key)
    }
    /// The validated coordinates. As [`Kept::entries`]: each is inserted in one
    /// step, so a panic leaves whole entries.
    fn reached(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::HashMap<PeerOn, std::collections::BTreeMap<u64, PeerFrontier>>,
    > {
        match self.reached.lock() {
            Ok(reached) => reached,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
    /// Keep a coordinate a complete walk validated on `network`.
    fn reach(&self, network: &[u8], frontier: PeerFrontier) {
        let mut reached = self.reached();
        if reached.len() >= VALIDATED_PEERS_MAX {
            reached.clear();
        }
        let positions = reached
            .entry((network.to_vec(), *frontier.genesis(), *frontier.device_id()))
            .or_default();
        if positions.len() >= VALIDATED_PEERS_MAX {
            positions.clear();
        }
        positions.insert(frontier.economic_position(), frontier);
    }
    /// The highest coordinate validated for the peer on `network` strictly
    /// below `position`.
    fn reached_below(
        &self,
        network: &[u8],
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Option<PeerFrontier> {
        self.reached()
            .get(&(network.to_vec(), *genesis, *device_id))?
            .range(..position)
            .next_back()
            .map(|(_, frontier)| frontier.clone())
    }
    fn keep(&self, key: PeerKey, validated: ValidatedPeerTransition) {
        self.kept.keep(key, validated);
    }
    #[cfg(test)]
    pub(crate) fn walks(&self) -> u64 {
        self.walks.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn root_walks(&self) -> u64 {
        self.root_walks.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn claim_walks(&self) -> u64 {
        self.claim_walks.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn forget(&self) {
        self.kept.entries().clear();
        self.roots.entries().clear();
        self.claims.entries().clear();
        self.reached().clear();
    }
}

pub(crate) fn validated_peers() -> &'static ValidatedPeers {
    static PEERS: once_cell::sync::Lazy<ValidatedPeers> =
        once_cell::sync::Lazy::new(|| ValidatedPeers {
            kept: Kept::new(),
            roots: Kept::new(),
            claims: Kept::new(),
            reached: std::sync::Mutex::new(std::collections::HashMap::new()),
            walks: std::sync::atomic::AtomicU64::new(0),
            root_walks: std::sync::atomic::AtomicU64::new(0),
            claim_walks: std::sync::atomic::AtomicU64::new(0),
        });
    &PEERS
}

/// A peer's lineage verified to `peer_economic_position` from this
/// receiver's frontier (DSM Amendment A8), over WHATEVER fetcher the caller
/// supplies, so a recording fetcher observes exactly the closure the
/// verification consumed, with the frontiers its credits' sources reached.
/// Nothing is recorded here: a frontier, the peer's or a source's, is
/// recorded only in the transaction that accepts a step from the peer.
pub(crate) fn resolve_peer_lineage<F: PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    peer_economic_position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<ValidatedPeerLineage, PeerLineageFailure> {
    let validated = validate_peer_lineage(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        peer_economic_position,
        &StoredFrontiers,
        conditional,
    )?;
    log::info!(
        "[A8] peer {} validated at position {peer_economic_position}",
        text_id::encode_base32_crockford(peer_devid)
    );
    Ok(validated)
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

    /// The peer's lineage verified from this receiver's frontier, recorded at
    /// the fetch boundary, with the frontiers its credits' sources reached.
    pub fn validated_peer_lineage(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
        conditional: &dyn ConditionalPositionResolver,
    ) -> Result<ValidatedPeerLineage, PeerLineageFailure> {
        resolve_peer_lineage(
            self,
            &self.inner.expected_network_id,
            peer_genesis,
            peer_devid,
            peer_economic_position,
            conditional,
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
        // A conditional position in the peer's segment is resolved from
        // SoFi's public objects for that position (SoFi Amendment S15).
        let context =
            crate::sdk::sofi_reads::VerifierContext::new(self.set, None, None).map_err(|e| {
                PeerLineageFailure::Incomplete(format!("SoFi reads are unavailable: {e}"))
            })?;
        resolve_peer(
            self,
            &self.expected_network_id,
            peer_genesis,
            peer_devid,
            peer_economic_position,
            &context.peer_position_resolver(),
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
    // ERA's policy is Core's own (SoFi Amendment S11): answered from its
    // bytes, never fetched and never stored.
    if *policy_commit == dsm::core::token::token_state_manager::era_policy_commit() {
        return Ok(dsm::core::token::era_policy::era_policy_bytes().to_vec());
    }
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
