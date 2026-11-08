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
    peer_claim_at, peer_root_at, scan_offline_boundaries, validate_peer_step, Checked, OfflineScan,
    ConditionalPositionResolver, OfflineRecords, PeerEvidenceFetcher, StepCost,
    OFFLINE_SCAN_POSITIONS,
};
use dsm::sofi::wire::ParentClaimRef;
use dsm::economic::provenance::{
    PeerLineageFailure, ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
};
use dsm::economic::register::{read_root_cell, RootCell};
use dsm::route_chain::{CellEvidence, CellReading, ChainState, Missing};
use dsm::types::error::DsmError;

use crate::sdk::route_seats::{
    read_cell, read_cell_kept, root_claim_final, write_recorded, NodeSeats, WriteReport,
};
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
    // A claim final at the cell holds it for good: kept once read final.
    let evidence = read_cell_kept(&seats, cell.routed(), &cell.keeps(), |evidence| {
        root_claim_final(&cell, evidence)
    })
    .await;
    Ok(match read_root_cell(&cell, &evidence) {
        Ok(CellReading::Open) => NextRootCell::Open,
        Ok(CellReading::Held { .. }) => NextRootCell::Held,
        Err(missing) => NextRootCell::Undecided(missing_text(missing)),
    })
}

/// Write this device's frozen root claim at its root cell, along the cell's
/// route (storage spec §9), continuing an earlier write of the same claim.
/// At the leader the cell's own rule for what can count there decides
/// whether another claim is first, and the write is then taken. Which claim
/// holds the cell is read back ([`root_claim_settlement`]), never inferred
/// from the write.
pub async fn register_economic_root(
    set: &StorageSet,
    cell: &RootCell,
    frozen_envelope: &[u8],
) -> Result<WriteReport, DsmError> {
    write_recorded(set, cell.routed(), &cell.keeps(), frozen_envelope).await
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
    // A claim final at the cell holds it for good: kept once read final.
    let evidence = read_cell_kept(&seats, cell.routed(), &cell.keeps(), |evidence| {
        root_claim_final(cell, evidence)
    })
    .await;
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
/// re-hash-verified, and peers' steps validated by Core, each from its own
/// parent (DSM Amendment A14).
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

    /// A step's manifest names the three objects a check asks for next: the
    /// authority evidence, the transition witness and the successor evidence.
    /// They are fetched together into the kept objects, so the check's three
    /// asks find them there instead of each waiting on a round trip of its
    /// own. A fetch that fails here changes nothing: the check asks for that
    /// object itself and meets the failure there.
    fn prefetch_step_objects(&self, manifest_bytes: &[u8]) {
        use dsm::common::domain_tags::{
            TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE, TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE,
            TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
        };
        let manifest = match dsm::economic::decode::decode_admission_manifest(manifest_bytes) {
            Ok(manifest) => manifest,
            Err(e) => {
                // The check decodes the same bytes and refuses them itself.
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

    fn register_key_values(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
        tokio::task::block_in_place(|| {
            self.runtime
                .block_on(register_key_values(self.set, genesis, device_id, position))
        })
    }

    fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
        #[cfg(test)]
        asked_cells::note(cell.routed().key());
        // A claim final at a root cell holds it for good (storage spec §9,
        // finality 2): reads Core evaluated as showing one are kept, and a
        // later check of the same position evaluates them again instead of
        // reading the route.
        if let Some(kept) = crate::sdk::final_reads::final_cell(cell.routed()) {
            return Ok(kept);
        }
        let seats = NodeSeats::new(self.set).map_err(|e| incomplete("register seats", e))?;
        let evidence = tokio::task::block_in_place(|| {
            self.runtime
                .block_on(read_cell(&seats, cell.routed(), &cell.keeps()))
        });
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

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        held_ek_step(signer, addr)
    }
}

/// Every value any member of `set` holds under `K_root(position)` of
/// `(genesis, devid)` (DSM Amendment A14): the candidates Core checks, each at
/// the cell routed from the parent it names. Every member is asked at once.
/// Discovery, never authority, so nothing read here is kept. `Incomplete`
/// when no member answered.
pub(crate) async fn register_key_values(
    set: &StorageSet,
    genesis: &[u8; 32],
    devid: &[u8; 32],
    position: u64,
) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
    use crate::sdk::route_seats::RouteSeats;
    let seats = NodeSeats::new(set).map_err(|e| incomplete("register seats", e))?;
    let key = dsm::economic::register::economic_root_register_key(genesis, devid, position);
    #[cfg(test)]
    asked_cells::note(&key);
    let namespace = dsm::economic::register::economic_root_namespace();
    // Only a claim naming this key is kept: what anyone else wrote under it
    // costs the read and nothing it holds.
    let keep = |bytes: &[u8]| {
        dsm::route_chain::RouteEntry::decode(bytes).is_some_and(|entry| {
            entry.namespace == namespace
                && entry.key == key
                && dsm::economic::register::root_claim_naming(&entry.value, &key).is_some()
        })
    };
    let members = seats.members();
    let answers = futures::future::join_all(members.iter().map(|member| {
        crate::sdk::route_seats::kept_values(&seats, member, namespace, &key, &keep)
    }))
    .await;
    if answers.iter().all(Option::is_none) {
        return Err(PeerLineageFailure::Incomplete(format!(
            "no member answered for {}'s register key at position {position}",
            text_id::encode_base32_crockford(devid)
        )));
    }
    Ok(answers.into_iter().flatten().flatten().collect())
}

/// The offline accounts this receiver recorded of its peers, as its store
/// holds them (the owner's receive rule, 2026-10-22).
pub struct StoredOfflineRecords;

impl OfflineRecords for StoredOfflineRecords {
    fn offline_account_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        bundle: &[u8; 32],
        position: u64,
    ) -> Result<Option<dsm::economic::peer_lineage::PeerOfflineAccount>, PeerLineageFailure> {
        crate::storage::client_db::economic_lineage::offline_account_below(
            genesis, device_id, bundle, position,
        )
        .map_err(|e| {
            PeerLineageFailure::Incomplete(format!("the offline account store is unreadable: {e}"))
        })
    }
}

/// What one check of a peer's step cost, logged where it ran (DSM Amendment
/// A14): every count is bounded by a constant, whatever the position.
fn log_cost(what: &str, devid: &[u8; 32], position: u64, cost: &StepCost) {
    log::info!(
        "[A14] {what} of {} at position {position}: register_probes={} routed_reads={} \
         source_steps={} conditional_hops={}",
        text_id::encode_base32_crockford(devid),
        cost.register_probes,
        cost.routed_reads,
        cost.source_steps,
        cost.conditional_hops
    );
}

/// Record what a check validated, in one transaction, whatever the check was
/// for: the offline accounts the boundaries it passed left, the payments they
/// exposed, and the EK steps it verified. Core returns them only from steps
/// that passed whole, so nothing a peer sent, registered or signed is recorded
/// here. A store that cannot be written leaves the check's answer not
/// established, as a store that cannot be read does.
fn record_established<T>(
    what: &str,
    devid: &[u8; 32],
    position: u64,
    checked: Checked<T>,
) -> Result<T, PeerLineageFailure> {
    log_cost(what, devid, position, &checked.cost());
    crate::storage::client_db::economic_lineage::record_validated(
        checked.offline_accounts(),
        checked.offline_exposures(),
        checked.ek_steps(),
    )
    .map_err(|e| {
        PeerLineageFailure::Incomplete(format!("recording what this check validated: {e}"))
    })?;
    Ok(checked.into_answer())
}

/// A peer's step at `peer_economic_position`, validated from its own parent
/// (DSM Amendment A14), over WHATEVER fetcher the caller supplies.
///
/// Core answers every time it is asked here. What a validation read is kept
/// as evidence (`final_reads`: final cells and immutable objects), and the
/// process keeps no verdict (SA-92). One SoFi operation's contexts keep the
/// answers they were given for that operation alone (`sofi_reads`).
pub(crate) fn resolve_peer<F: PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    peer_economic_position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    let checked = validate_peer_step(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        peer_economic_position,
        &StoredOfflineRecords,
        conditional,
    )?;
    record_established("step", peer_devid, peer_economic_position, checked)
}

/// The root a trader selected at a position and the reference a later `P`
/// names it by (`SofiReads::trader_root_at`), validated one hop (DSM
/// Amendment A14).
pub(crate) fn resolve_peer_root<F: PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<(ValidatedEconomicRoot, ParentClaimRef), PeerLineageFailure> {
    let checked = peer_root_at(
        fetcher,
        expected_network_id,
        genesis,
        device_id,
        position,
        &StoredOfflineRecords,
        conditional,
    )?;
    record_established("root", device_id, position, checked)
}

/// The claim a trader accepted at a position (`SofiReads::accepted_claim_at`
/// for another trader): what a setup naming that position is checked against
/// (SoFi Amendment S15, MR-SOFI-0347), validated one hop (DSM Amendment A14).
pub(crate) fn resolve_peer_claim<F: PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    position: u64,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<AcceptedClaim, PeerLineageFailure> {
    let checked = peer_claim_at(
        fetcher,
        expected_network_id,
        genesis,
        device_id,
        position,
        &StoredOfflineRecords,
        conditional,
    )?;
    record_established("claim", device_id, position, checked)
}

/// Validate one hop the offline boundaries among `positions` of a payer,
/// recording the accounts they left and the payments they exposed. A read that
/// stops short records what it validated. One that meets a boundary that
/// verifies as wrong records nothing.
async fn read_payer_offline_boundaries(
    genesis: [u8; 32],
    device_id: [u8; 32],
    positions: std::ops::Range<u64>,
) -> Result<OfflineScan, PeerLineageFailure> {
    let network_id = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| PeerLineageFailure::Incomplete(format!("the committed network: {e}")))?;
    let set = crate::sdk::storage_set::canonical_set(&network_id)
        .map_err(|e| PeerLineageFailure::Incomplete(format!("the register set: {e}")))?;
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let live = LiveRegisterResolver {
            set: &set,
            runtime,
            expected_network_id: network_id.clone(),
        };
        let sofi = crate::sdk::sofi_reads::VerifierContext::new(&set, None, None)
            .map_err(|e| PeerLineageFailure::Incomplete(format!("SoFi reads: {e}")))?;
        let checked = scan_offline_boundaries(
            &live,
            &network_id,
            &genesis,
            &device_id,
            positions,
            &StoredOfflineRecords,
            &sofi.peer_position_resolver(),
        )?;
        let reached = checked.answer().reached();
        record_established("offline scan", &device_id, reached, checked)
    })
    .await
    .map_err(|e| PeerLineageFailure::Incomplete(format!("the payer's read did not finish: {e}")))?
}

/// Scan a payer's positions from `from` for the offline boundaries that expose
/// what it paid this device offline (SA-91), within
/// [`OFFLINE_SCAN_POSITIONS`].
pub(crate) async fn scan_payer_offline_boundaries(
    genesis: [u8; 32],
    device_id: [u8; 32],
    from: u64,
) -> Result<(), String> {
    let scan = read_payer_offline_boundaries(
        genesis,
        device_id,
        from..from.saturating_add(OFFLINE_SCAN_POSITIONS),
    )
    .await
    .map_err(|e| e.to_string())?;
    log::info!(
        "[A14] payer {} scanned from position {from} to {}: {:?}",
        text_id::encode_base32_crockford(&device_id),
        scan.reached(),
        scan.stop()
    );
    Ok(())
}

/// The one position a payer's notice names (DSM Amendment A30), validated one
/// hop when it is an offline boundary. A constant cost, whatever the position
/// and however long the payer's history. The notice is believed in nothing:
/// a step that is no boundary is read and records nothing. The scan has reached
/// `position` only when the position was read to its end.
pub(crate) async fn record_peer_offline_boundary(
    genesis: [u8; 32],
    device_id: [u8; 32],
    position: u64,
) -> Result<OfflineScan, PeerLineageFailure> {
    let next = position.checked_add(1).ok_or_else(|| {
        PeerLineageFailure::Invalid(format!("position {position} is past every position"))
    })?;
    read_payer_offline_boundaries(genesis, device_id, position..next).await
}

/// The RECORDING fetch boundary for recipient prevalidation. It IS the
/// `PeerEvidenceFetcher` the step check consumes, so every immutable object
/// any nested verification fetched lands in `recorded`, exact bytes by exact
/// address.
pub struct RecordingResolver<'a> {
    pub inner: &'a LiveRegisterResolver<'a>,
    /// `(namespace, inner addr, exact verified bytes)` for every immutable
    /// fetch the check consumed. Register cells are read live along their
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

    /// The peer's step validated from its own parent (DSM Amendment A14), its
    /// evidence recorded at the fetch boundary.
    pub fn validated_peer_step(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
        conditional: &dyn ConditionalPositionResolver,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        resolve_peer(
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

    fn register_key_values(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
        // Discovery, not part of the recorded closure.
        dsm::economic::peer_lineage::PeerEvidenceFetcher::register_key_values(
            self.inner, genesis, device_id, position,
        )
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

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        // Not recorded: a held step is the verifier's own relationship
        // record, not part of the peer's evidence closure.
        held_ek_step(signer, addr)
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
        // A conditional position is resolved from SoFi's public objects for
        // that position (SoFi Amendment S15).
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

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        held_ek_step(signer, addr)
    }
}

/// The key a held EK step certified: a step of one of this device's own
/// relationships, recorded as its bilateral step completed. An unreadable
/// store is `Incomplete`, never "not held".
pub(crate) fn held_ek_step(
    signer: &[u8; 32],
    addr: &[u8; 32],
) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
    crate::storage::client_db::economic_lineage::held_ek_step(signer, addr).map_err(|e| {
        PeerLineageFailure::Incomplete(format!("the relationship record is unreadable: {e}"))
    })
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
    match held_policy_bytes(policy_commit)? {
        Some(bytes) => Ok(bytes),
        None => tokio::task::block_in_place(|| {
            runtime.block_on(fetched_policy_bytes(set, policy_commit))
        }),
    }
}

/// [`anchored_policy_bytes`] for a caller already on the runtime.
pub(crate) async fn anchored_policy_bytes_async(
    set: &StorageSet,
    policy_commit: &[u8; 32],
) -> Result<Vec<u8>, PeerLineageFailure> {
    match held_policy_bytes(policy_commit)? {
        Some(bytes) => Ok(bytes),
        None => fetched_policy_bytes(set, policy_commit).await,
    }
}

/// The policy bytes a Transfer or Burn of `policy_commit` carries (owner
/// question 9, 2026-10-27): the token's committed policy as this device holds
/// it, ERA's being Core's own bytes. A device moves only a token it holds,
/// and it adopted that token's policy to hold it. Core re-hashes the bytes to
/// the commit in the write set; this is only where they come from.
pub(crate) fn carried_token_policy(policy_commit: &[u8; 32]) -> Result<Vec<u8>, DsmError> {
    match held_policy_bytes(policy_commit) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(DsmError::invalid_operation(
            "this device holds no committed policy for the token: it moves only tokens whose \
             policy it adopted",
        )),
        Err(failure) => Err(DsmError::invalid_operation(format!(
            "the token's committed policy: {failure}"
        ))),
    }
}

/// The policy this device already holds for `policy_commit`, or none.
fn held_policy_bytes(policy_commit: &[u8; 32]) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
    // ERA's policy is Core's own (SoFi Amendment S11): answered from its
    // bytes, never fetched and never stored.
    if *policy_commit == dsm::core::token::token_state_manager::era_policy_commit() {
        return Ok(Some(
            dsm::core::token::era_policy::era_policy_bytes().to_vec(),
        ));
    }
    crate::storage::client_db::token_registry::load_policy_verified(policy_commit).map_err(|e| {
        PeerLineageFailure::Incomplete(format!("the local token policy store is unreadable: {e}"))
    })
}

/// The policy object `policy_commit` names, fetched from `set`, re-hashed,
/// and kept.
async fn fetched_policy_bytes(
    set: &StorageSet,
    policy_commit: &[u8; 32],
) -> Result<Vec<u8>, PeerLineageFailure> {
    let tag = dsm::common::domain_tags::TAG_DSM_POLICY;
    let bytes = crate::sdk::storage_io::fetch_immutable(set, tag, policy_commit)
        .await
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
        Missing::CompletionRefuted => {
            "fresh reads refuted the completion proof kept for the value final here".into()
        }
    }
}

/// Every register key and routed root-cell key a check asked this process's
/// resolver for, kept reads included: a check asks the key and the cell of the
/// position it validates, so this counts the positions read where the members'
/// request logs cannot (a final cell is read from its seats once and kept).
/// Observation for tests.
#[cfg(test)]
pub(crate) mod asked_cells {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static ASKED: Mutex<Option<HashMap<[u8; 32], usize>>> = Mutex::new(None);

    fn asked() -> std::sync::MutexGuard<'static, Option<HashMap<[u8; 32], usize>>> {
        match ASKED.lock() {
            Ok(asked) => asked,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn note(key: &[u8; 32]) {
        *asked()
            .get_or_insert_with(HashMap::new)
            .entry(*key)
            .or_insert(0) += 1;
    }

    /// The asks since the last take, and forget them.
    pub(crate) fn take() -> HashMap<[u8; 32], usize> {
        asked().take().into_iter().flatten().collect()
    }
}
