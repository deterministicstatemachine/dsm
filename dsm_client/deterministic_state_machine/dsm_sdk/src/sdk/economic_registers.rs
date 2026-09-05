// SPDX-License-Identifier: Apache-2.0

//! Client-side quorum operations on the economic write-once registers, plus
//! ticket selection and the live provenance resolver.
//!
//! ## Counting (Req 15.8, with the owner's tightened write rule)
//!
//! A member's answer counts toward quorum ONLY when the echoed `x-dsm-node-id`
//! equals the member id queried. On writes: `accepted` and `held-identical`
//! count (attributed); a `refused` whose held digest equals OUR digest is an
//! acceptance in different words (attributed, and not taken on trust
//! otherwise); a generic `refused` NEVER counts. Unattributed refusals still
//! count toward "contested" — an unattributed refusal can only fail the claim
//! closed, never open.
//!
//! ## Frozen envelopes
//!
//! Every envelope is signed ONCE, durably retained BEFORE the first
//! register-member write, and replayed byte-identically forever. SPHINCS+
//! signing here is deterministic: a regenerated envelope is indistinguishable
//! from a replayed one downstream, so the safe design is for regeneration to
//! be impossible — the load-only discipline of `FrozenClaimEnvelope`, applied
//! to both new registers.
//!
//! ## Ticket selection is STRATEGY, not validity
//!
//! Any in-range ticket is valid. [`select_ticket`] only decides where this
//! client looks first, which is why it lives here (SDK) and not in protocol
//! core: changing the search strategy later must not masquerade as a protocol
//! change. The seed includes the TARGET ECONOMIC POSITION so each admitted
//! position gets its own deterministic sequence — without it, claim 10,001
//! would walk the identity's 10,000 already-consumed tickets first. Selection
//! is publicly predictable; V1 promises conservation, not anti-targeting.

use dsm::common::domain_tags::TAG_DSM_ERA_FAUCET_TICKET_SELECT;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::economic::faucet::{faucet_claim_evidence_addr, ERA_FAUCET_TICKET_COUNT};
use dsm::economic::provenance::{
    FaucetTicketWin, PeerLineageFailure, ProvenanceResolver, ValidatedPeerTransition,
};
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::{ClaimFanout, MemberClaimResult};
use crate::sdk::storage_set::StorageSet;
use crate::util::text_id;

/// Deterministically choose the ticket this claimant tries at `attempt` for
/// `target_economic_position`. Exact-uniform over the ticket space via the
/// DJTE rejection sampler.
pub fn select_ticket(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    target_economic_position: u64,
    attempt: u64,
) -> Result<u64, DsmError> {
    let mut h = dsm_domain_hasher(TAG_DSM_ERA_FAUCET_TICKET_SELECT);
    h.update(genesis);
    h.update(device_id);
    h.update(&target_economic_position.to_be_bytes());
    h.update(&attempt.to_be_bytes());
    let seed = *h.finalize().as_bytes();
    dsm::emissions::uniform_index(&seed, ERA_FAUCET_TICKET_COUNT)
}

/// Unforgeable evidence that THIS claim envelope won its cell at quorum.
/// Private fields; constructible only by the claim functions below.
#[derive(Debug, Clone)]
pub struct ClaimedCell {
    accepted: u32,
    total: u32,
}

impl ClaimedCell {
    pub fn accepted(&self) -> u32 {
        self.accepted
    }
    pub fn total(&self) -> u32 {
        self.total
    }
}

/// Why a register operation did not establish its cell.
#[derive(Debug)]
pub enum RegisterError {
    /// Not enough attributed members answered; retry later with the SAME bytes.
    StorageUnavailable { accepted: u32, total: u32 },
    /// Another value holds the cell. For a ticket: pick the next attempt's
    /// ticket. For a root cell: see `Conflict` — contested here means OUR
    /// bytes lost, which for a root written only by us is already abnormal.
    Contested { refused_by: u32 },
    /// CATASTROPHIC (root register only): members hold DIFFERENT values for
    /// one cell, or a cell this device owns holds bytes this device never
    /// signed. Quarantine — never hash-order, never overwrite, never retry.
    Conflict { detail: String },
}

impl core::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StorageUnavailable { accepted, total } => write!(
                f,
                "register unavailable: {accepted}/{total} attributed acceptances — retry with \
                 the SAME frozen bytes"
            ),
            Self::Contested { refused_by } => {
                write!(
                    f,
                    "register cell held by another value ({refused_by} refusals)"
                )
            }
            Self::Conflict { detail } => write!(
                f,
                "REGISTER CONFLICT — quarantine, do not retry, do not overwrite: {detail}"
            ),
        }
    }
}

/// Count a claim fan-out under Req 15.8 + the tightened write rule.
fn count_claim(
    fanout: &ClaimFanout,
    our_digest: &[u8; 32],
    quorum: u32,
) -> Result<ClaimedCell, RegisterError> {
    let mut accepted = 0u32;
    let mut refused_by = 0u32;
    for o in &fanout.outcomes {
        let attributed = o.echoed_node_id.as_deref() == Some(o.member_id.as_str());
        match &o.result {
            MemberClaimResult::Accepted | MemberClaimResult::HeldIdentical => {
                if attributed {
                    accepted += 1;
                }
            }
            MemberClaimResult::Refused { held_digest } => {
                // Refused-with-OUR-digest is an acceptance in different words
                // — and carries the same attribution requirement. A generic
                // refusal NEVER counts toward quorum.
                if held_digest.as_deref() == Some(our_digest.as_slice()) {
                    if attributed {
                        accepted += 1;
                    }
                } else {
                    refused_by += 1;
                }
            }
            MemberClaimResult::Unavailable(_) => {}
        }
    }
    if accepted >= quorum {
        Ok(ClaimedCell {
            accepted,
            total: fanout.total,
        })
    } else if refused_by > 0 {
        Err(RegisterError::Contested { refused_by })
    } else {
        Err(RegisterError::StorageUnavailable {
            accepted,
            total: fanout.total,
        })
    }
}

/// Claim one faucet ticket with the FROZEN envelope bytes, at the members of
/// `set` serving `network_id` — the network whose canonical faucet the ticket
/// belongs to.
pub async fn claim_faucet_ticket(
    set: &StorageSet,
    network_id: &[u8],
    frozen_envelope: &[u8],
) -> Result<ClaimedCell, RegisterError> {
    let digest = faucet_claim_evidence_addr(frozen_envelope);
    let fanout =
        crate::sdk::storage_io::submit_faucet_ticket_claim(set, network_id, frozen_envelope)
            .await
            .map_err(|e| RegisterError::StorageUnavailable {
                accepted: 0,
                total: {
                    let _ = e;
                    set.len() as u32
                },
            })?;
    count_claim(&fanout, &digest, set.quorum())
}

/// Register the economic root with the FROZEN claim envelope bytes.
pub async fn register_economic_root(
    set: &StorageSet,
    frozen_envelope: &[u8],
) -> Result<ClaimedCell, RegisterError> {
    let digest =
        dsm::economic::claim_envelope::economic_root_claim_envelope_digest(frozen_envelope);
    let fanout = crate::sdk::storage_io::submit_economic_root_claim(set, frozen_envelope)
        .await
        .map_err(|_| RegisterError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
        })?;
    match count_claim(&fanout, &digest, set.quorum()) {
        // A root cell is written ONLY by its owner with frozen bytes, so a
        // contest is not a race lost — it is a cell this device owns holding
        // bytes this device never sent from this store. Quarantine.
        Err(RegisterError::Contested { refused_by }) => Err(RegisterError::Conflict {
            detail: format!(
                "{refused_by} member(s) hold a DIFFERENT record for this device's own \
                 economic position"
            ),
        }),
        other => other,
    }
}

/// The quorum-agreed winner for one cell, or `None` when no winner is
/// established.
///
/// For the faucet-ticket and economic-root cells, whose callers act only on a
/// winner. Anything else — an explicit empty at quorum, contradictory claims,
/// or an unusable read — is `None` here, and a caller that must tell those
/// apart uses [`dsm::economic::cell_observation::observe_cell`] directly, as
/// the vault cells do.
async fn read_cell_quorum(
    set: &StorageSet,
    reads: Vec<dsm::economic::cell_observation::MemberCellRead>,
) -> Result<Option<Vec<u8>>, RegisterError> {
    use dsm::economic::cell_observation::{observe_cell, CellObservation};
    match observe_cell(&reads, set.quorum()) {
        CellObservation::Claimed(b) => Ok(Some(b)),
        CellObservation::Conflict { distinct } => Err(RegisterError::Conflict {
            detail: format!("{distinct} distinct values observed for one write-once cell"),
        }),
        CellObservation::EmptyAtQuorum | CellObservation::Unavailable { .. } => Ok(None),
    }
}

/// The quorum winner for one faucet ticket, if established.
pub async fn read_winning_faucet_ticket(
    set: &StorageSet,
    faucet_id: &[u8; 32],
    ticket_index: u64,
) -> Result<Option<Vec<u8>>, RegisterError> {
    let rows = crate::sdk::storage_io::read_faucet_ticket_cell(set, faucet_id, ticket_index)
        .await
        .map_err(|_| RegisterError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
        })?;
    read_cell_quorum(set, rows).await
}

/// Resolve the set a vault COMMITTED, fail-closed.
///
/// The id is re-derived from the committed member ids and the catalog entry
/// must reproduce it, so configuration only says WHERE to reach a member — it
/// can never substitute a different set. A verifier's own default fleet is its
/// opinion; the vault's signed state is the rule.
fn resolve_committed_set(
    storage_set: &dsm::ccb::StorageSetMembers,
) -> Result<crate::sdk::storage_set::StorageSet, RegisterError> {
    let unavailable = || RegisterError::StorageUnavailable {
        accepted: 0,
        total: storage_set.len() as u32,
    };
    let id = dsm::ccb::storage_set_id(storage_set).map_err(|_| unavailable())?;
    let catalog =
        crate::sdk::storage_set::StorageSetCatalog::from_env_config().map_err(|_| unavailable())?;
    catalog.resolve(&id).cloned().ok_or_else(unavailable)
}

/// OBSERVE one settlement-slot cell at the quorum the vault's owner committed.
///
/// This is the frontier walk's edge source. A write-once cell is the only
/// answer in this system whose omission is not expressible: a set listing can
/// silently omit a key and no signature repairs that, but a cell either holds
/// a value or does not, and q attributed members saying "nothing here" is a
/// fact rather than an absence of one.
pub async fn observe_settlement_slot_cell(
    set: &StorageSet,
    vault_id: &[u8; 32],
    parent_sequence: u64,
    quorum: u32,
) -> Result<dsm::economic::cell_observation::CellObservation, RegisterError> {
    let rows = crate::sdk::storage_io::read_settlement_slot_cell(set, vault_id, parent_sequence)
        .await
        .map_err(|_| RegisterError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
        })?;
    Ok(dsm::economic::cell_observation::observe_cell(&rows, quorum))
}

/// The quorum winner for one economic-root cell, if established. Used for
/// lost-response recovery: a crash after a register write is resolved by
/// READING the register, never by re-signing.
pub async fn read_economic_root_cell(
    set: &StorageSet,
    k_root: &[u8; 32],
) -> Result<Option<Vec<u8>>, RegisterError> {
    let rows = crate::sdk::storage_io::read_economic_root_cell_rows(set, k_root)
        .await
        .map_err(|_| RegisterError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
        })?;
    read_cell_quorum(set, rows).await
}

/// The LIVE provenance resolver: register cells at quorum, immutable objects
/// re-hash-verified, peer lineages resolved through the core walker with the
/// device-local validated-start cache (never authority — an `Invalid` from a
/// cached start discards the row and re-walks from position 0).
pub struct LiveRegisterResolver<'a> {
    pub set: &'a StorageSet,
    pub runtime: tokio::runtime::Handle,
    /// The network THIS verifier is validating against — the peer's
    /// committed network must match it (`resolve_for_trader`).
    pub expected_network_id: Vec<u8>,
}

impl LiveRegisterResolver<'_> {
    fn fetch_bytes(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        let a = *addr;
        let fetched = tokio::task::block_in_place(|| {
            self.runtime
                .block_on(crate::sdk::storage_io::fetch_immutable_payload(
                    namespace, &a,
                ))
        })
        .map_err(|e| PeerLineageFailure::Incomplete(format!("immutable fetch: {e}")))?;
        fetched.ok_or_else(|| {
            PeerLineageFailure::Incomplete(format!(
                "immutable object not found on any member: {}::{}",
                String::from_utf8_lossy(namespace.source_bytes()),
                crate::util::text_id::encode_base32_crockford(addr)
            ))
        })
    }
}

impl dsm::economic::peer_lineage::PeerEvidenceFetcher for LiveRegisterResolver<'_> {
    /// The network's root-register set as THIS device's catalog resolves it.
    ///
    /// Candidates, not authority: the caller re-derives the id from these
    /// pairs and refuses a membership that is not the network's canonical
    /// one, so a locally misconfigured or hostile catalog is caught rather
    /// than believed. A member that rebuilt its register appears here under a
    /// new incarnation and therefore changes the id it can serve.
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        let profile = dsm::economic::register::resolve_root_register_profile(network_id)
            .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))?;
        let catalog = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))?;
        // The catalog holds sets, not networks: find the one whose membership
        // IS this network's, and let `derive_set_id` be the thing that decides
        // whether it really is.
        let candidate = catalog
            .sets()
            .iter()
            .find_map(|s| {
                let members = crate::sdk::storage_set::as_ccb_members(s).ok()?;
                profile.derive_set_id(&members).ok().map(|_| members)
            })
            .ok_or_else(|| {
                PeerLineageFailure::Incomplete(
                    "no configured storage set has this network's canonical membership".into(),
                )
            })?;
        Ok(candidate)
    }

    fn register_cell(&self, k_root: &[u8; 32]) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        let k = *k_root;
        tokio::task::block_in_place(|| self.runtime.block_on(read_economic_root_cell(self.set, &k)))
            .map_err(|e| match e {
                RegisterError::Conflict { detail } => PeerLineageFailure::Quarantined(detail),
                other => PeerLineageFailure::Incomplete(other.to_string()),
            })
    }

    fn faucet_ticket_cell(
        &self,
        faucet_id: &[u8; 32],
        ticket_index: u64,
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        let fid = *faucet_id;
        tokio::task::block_in_place(|| {
            self.runtime
                .block_on(read_winning_faucet_ticket(self.set, &fid, ticket_index))
        })
        .map_err(|e| match e {
            RegisterError::Conflict { detail } => PeerLineageFailure::Quarantined(detail),
            other => PeerLineageFailure::Incomplete(other.to_string()),
        })
    }

    fn settlement_slot_observation(
        &self,
        vault_id: &[u8; 32],
        parent_sequence: u64,
        storage_set: &dsm::ccb::StorageSetMembers,
        quorum: u32,
    ) -> dsm::economic::cell_observation::CellObservation {
        use dsm::economic::cell_observation::CellObservation;
        let v = *vault_id;
        // A set this verifier cannot resolve is an inability to observe, not
        // an observation. Same for a transport failure below.
        let Ok(set) = resolve_committed_set(storage_set) else {
            return CellObservation::Unavailable {
                attributed: 0,
                required: quorum,
            };
        };
        tokio::task::block_in_place(|| {
            self.runtime.block_on(observe_settlement_slot_cell(
                &set,
                &v,
                parent_sequence,
                quorum,
            ))
        })
        .unwrap_or(CellObservation::Unavailable {
            attributed: 0,
            required: quorum,
        })
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
        anchored_policy_bytes_local_or_network(policy_commit, &self.runtime)
    }
}

/// The cache-aware walk shared by every fetcher-shaped resolver: cached
/// start, Invalid-from-cache re-walk, and the validated memo write — over
/// WHATEVER `PeerEvidenceFetcher` the caller supplies, so a recording
/// fetcher observes exactly the closure the walk consumed (correction 2:
/// the recorder must BE the fetch boundary, never an outer decorator).
pub(crate) fn resolve_peer_with_cache<F: dsm::economic::peer_lineage::PeerEvidenceFetcher>(
    fetcher: &F,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    peer_economic_position: u64,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    use dsm::economic::peer_lineage::{validate_peer_lineage, ValidatedStart};
    // The device-local memo of THIS verifier's own earlier conclusions.
    let cached = crate::storage::client_db::economic_lineage::best_peer_start(
        peer_genesis,
        peer_devid,
        peer_economic_position,
    )
    .ok()
    .flatten()
    .map(|(economic_position, economic_root)| ValidatedStart {
        economic_position,
        economic_root,
    });
    let first = validate_peer_lineage(
        fetcher,
        expected_network_id,
        peer_genesis,
        peer_devid,
        peer_economic_position,
        cached,
    );
    let result = match (first, cached) {
        // A cached start is never authority: an INVALID verdict from it
        // discards the memo and re-walks from the activation root.
        (Err(PeerLineageFailure::Invalid(_)), Some(_)) => {
            let _ = crate::storage::client_db::economic_lineage::clear_peer_lineage(
                peer_genesis,
                peer_devid,
            );
            validate_peer_lineage(
                fetcher,
                expected_network_id,
                peer_genesis,
                peer_devid,
                peer_economic_position,
                None,
            )
        }
        (other, _) => other,
    }?;
    let _ = crate::storage::client_db::economic_lineage::record_peer_validated(
        peer_genesis,
        peer_devid,
        result.validated_root.economic_position(),
        &result.validated_root.economic_root(),
    );
    Ok(result)
}

/// The walk with the cached fast path DISABLED: when the recorded closure
/// has not yet been proven q-durable, a cached start would let the walk skip
/// fetches the durability push then never sees (correction 4) — so walk from
/// the activation root and let the recorder observe the FULL closure.
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
    let _ = crate::storage::client_db::economic_lineage::record_peer_validated(
        peer_genesis,
        peer_devid,
        result.validated_root.economic_position(),
        &result.validated_root.economic_root(),
    );
    Ok(result)
}

/// The RECORDING fetch boundary for recipient prevalidation (3.5b PR4,
/// correction 2). It is not a decorator around `LiveRegisterResolver`'s
/// resolver face — it IS the `PeerEvidenceFetcher` the walker consumes, so
/// every immutable object any nested verification fetched (manifests,
/// witnesses, authority/successor evidence, acceptance bundles, EK steps)
/// lands in `recorded`, exact bytes by exact address. q-durable closure ==
/// this list, nothing less.
pub struct RecordingResolver<'a> {
    pub inner: &'a LiveRegisterResolver<'a>,
    /// `(namespace, inner addr, exact verified bytes)` for every immutable
    /// fetch the walk consumed. Register cells are quorum reads of
    /// write-once registers — q-held by definition — and are not recorded.
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

    /// The cache-aware peer walk, recorded at the fetch boundary.
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
        dsm::economic::peer_lineage::PeerEvidenceFetcher::root_register_candidate_set(
            self.inner, network_id,
        )
    }

    fn register_cell(&self, k_root: &[u8; 32]) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        dsm::economic::peer_lineage::PeerEvidenceFetcher::register_cell(self.inner, k_root)
    }

    fn faucet_ticket_cell(
        &self,
        faucet_id: &[u8; 32],
        ticket_index: u64,
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        dsm::economic::peer_lineage::PeerEvidenceFetcher::faucet_ticket_cell(
            self.inner,
            faucet_id,
            ticket_index,
        )
    }

    fn settlement_slot_observation(
        &self,
        vault_id: &[u8; 32],
        parent_sequence: u64,
        storage_set: &dsm::ccb::StorageSetMembers,
        quorum: u32,
    ) -> dsm::economic::cell_observation::CellObservation {
        // A register read, not an immutable object — nothing to record; the
        // q-durable closure covers content-addressed evidence only.
        dsm::economic::peer_lineage::PeerEvidenceFetcher::settlement_slot_observation(
            self.inner,
            vault_id,
            parent_sequence,
            storage_set,
            quorum,
        )
    }

    fn immutable(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        let bytes = dsm::economic::peer_lineage::PeerEvidenceFetcher::immutable(
            self.inner, namespace, addr,
        )?;
        self.recorded
            .borrow_mut()
            .push((namespace, *addr, bytes.clone()));
        Ok(bytes)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        // NOT recorded: policy bytes are the VERIFIER'S OWN rooting in a
        // public anchor, re-fetchable by anyone holding the commit — they are
        // not part of the peer's evidence closure and owe no q-durability.
        dsm::economic::peer_lineage::PeerEvidenceFetcher::anchored_policy_bytes(
            self.inner,
            policy_commit,
        )
    }
}

impl ProvenanceResolver for LiveRegisterResolver<'_> {
    /// The network's root-register set as THIS device's catalog resolves it.
    ///
    /// Candidates, not authority: the caller re-derives the id from these
    /// pairs and refuses a membership that is not the network's canonical
    /// one, so a locally misconfigured or hostile catalog is caught rather
    /// than believed. A member that rebuilt its register appears here under a
    /// new incarnation and therefore changes the id it can serve.
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        let profile = dsm::economic::register::resolve_root_register_profile(network_id)
            .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))?;
        let catalog = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))?;
        // The catalog holds sets, not networks: find the one whose membership
        // IS this network's, and let `derive_set_id` be the thing that decides
        // whether it really is.
        let candidate = catalog
            .sets()
            .iter()
            .find_map(|s| {
                let members = crate::sdk::storage_set::as_ccb_members(s).ok()?;
                profile.derive_set_id(&members).ok().map(|_| members)
            })
            .ok_or_else(|| {
                PeerLineageFailure::Incomplete(
                    "no configured storage set has this network's canonical membership".into(),
                )
            })?;
        Ok(candidate)
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

    fn winning_faucet_ticket(
        &self,
        faucet_id: &[u8; 32],
        ticket_index: u64,
    ) -> Option<FaucetTicketWin> {
        let set = self.set;
        let fid = *faucet_id;
        let bytes = tokio::task::block_in_place(|| {
            self.runtime
                .block_on(read_winning_faucet_ticket(set, &fid, ticket_index))
        })
        .ok()
        .flatten()?;
        Some(FaucetTicketWin {
            envelope_bytes: bytes,
        })
    }

    fn settlement_slot_observation(
        &self,
        vault_id: &[u8; 32],
        parent_sequence: u64,
        storage_set: &dsm::ccb::StorageSetMembers,
        quorum: u32,
    ) -> dsm::economic::cell_observation::CellObservation {
        dsm::economic::peer_lineage::PeerEvidenceFetcher::settlement_slot_observation(
            self,
            vault_id,
            parent_sequence,
            storage_set,
            quorum,
        )
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
        anchored_policy_bytes_local_or_network(policy_commit, &self.runtime)
    }
}

/// The verifier's OWN rooting in a token's public anchor: local anchored
/// bytes first, else a fetch from the authoritative content-addressed path,
/// re-hashed against the commit before anything trusts a byte (the network
/// is a locator, never authority). Successfully fetched bytes are persisted
/// — anchors are public, and anyone holding one may root to the token — so
/// the rooting is one-time per device. Unavailable is `Incomplete`: an
/// availability condition, never a permission.
pub(crate) fn anchored_policy_bytes_local_or_network(
    policy_commit: &[u8; 32],
    runtime: &tokio::runtime::Handle,
) -> Result<Vec<u8>, PeerLineageFailure> {
    if let Ok(Some(bytes)) =
        crate::storage::client_db::token_registry::load_policy_verified(policy_commit)
    {
        return Ok(bytes);
    }
    let pc = *policy_commit;
    let fetched = tokio::task::block_in_place(|| {
        runtime.block_on(crate::handlers::token_routes::try_fetch_policy_from_network(&pc))
    })
    .map_err(PeerLineageFailure::Incomplete)?;
    let Some(bytes) = fetched else {
        return Err(PeerLineageFailure::Incomplete(
            "anchored policy bytes unavailable — root this device to the token's public \
             anchor, then retry"
                .into(),
        ));
    };
    if dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &bytes)
        != pc
    {
        return Err(PeerLineageFailure::Incomplete(
            "fetched policy bytes do not hash to the anchor — treating as unavailable".into(),
        ));
    }
    // Root durably (best-effort): the bytes verified against the public
    // anchor this device already holds.
    let _ = crate::storage::client_db::token_registry::upsert_policy(&pc, &bytes);
    Ok(bytes)
}

/// Base32 path helpers shared by live and fake paths.
pub(crate) fn faucet_ticket_path(faucet_id: &[u8; 32], ticket_index: u64) -> String {
    format!(
        "/api/v2/faucet-ticket/{}/{}",
        text_id::encode_base32_crockford(faucet_id),
        ticket_index
    )
}

pub(crate) fn settlement_slot_path(vault_id: &[u8; 32], parent_sequence: u64) -> String {
    format!(
        "/api/v2/settlement-slot/{}/{}",
        text_id::encode_base32_crockford(vault_id),
        parent_sequence
    )
}

pub(crate) fn economic_root_path(k_root: &[u8; 32]) -> String {
    format!(
        "/api/v2/economic-root/{}",
        text_id::encode_base32_crockford(k_root)
    )
}

/// The republish-sweep object key for an immutable blob:
/// `immutable::{namespace}::{addr_b32}`. Same shape `dlv_routes` uses, so the
/// one generic sweep carries faucet evidence too.
/// THE TRADER'S READ of a vault owner's reserve proof, from an untrusted
/// locator to verified leaves.
///
/// The advertisement is unsigned and carries only `(addr, position)`. Neither
/// is believed. The position's root is resolved from the OWNER's own
/// write-once register cell by the same lineage walk a foreign verifier runs,
/// the artifact is fetched by content address and re-hashed to it, and every
/// leaf key, commitment and inclusion path is recomputed against that root. A
/// locator naming the wrong position or a different artifact therefore fails;
/// it can never yield leaves under a root the owner did not register.
///
/// Returns the vault-reserve leaves for `vault_id` only. A caller still has to
/// decide whether the amounts are the ones it expects — this answers "what did
/// the owner's registered root commit", never "is that the right state".
pub(crate) fn verified_owner_reserve_leaves(
    set: &StorageSet,
    expected_network_id: &[u8],
    owner_genesis: &[u8; 32],
    owner_devid: &[u8; 32],
    vault_id: &[u8; 32],
    proof_addr: &[u8; 32],
    economic_position: u64,
) -> Result<Vec<dsm::economic::state::EconomicVaultReserveState>, DsmError> {
    let resolver = LiveRegisterResolver {
        set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: expected_network_id.to_vec(),
    };
    let owner = resolver
        .validated_peer_transition(owner_genesis, owner_devid, economic_position)
        .map_err(|e| {
            DsmError::verification(format!(
                "owner reserve proof: the owner's economic lineage at position \
                 {economic_position} does not validate: {e:?}"
            ))
        })?;
    let root = owner.validated_root.economic_root();
    let artifact = tokio::task::block_in_place(|| {
        resolver.runtime.block_on(fetch_verified_economic_proof(
            proof_addr,
            owner_genesis,
            owner_devid,
            economic_position,
            &root,
        ))
    })?;
    Ok(artifact
        .states()
        .filter_map(|s| match s {
            dsm::economic::state::EconomicLeafState::VaultReserve(v) if v.vault_id == *vault_id => {
                Some(v.clone())
            }
            _ => None,
        })
        .collect())
}

/// Fetch an economic proof artifact by content address and verify it against
/// coordinates the caller established INDEPENDENTLY — the publisher's
/// write-once register cell at that position, read at quorum.
///
/// The address is a locator and nothing more. Wherever it came from (a
/// routing advertisement, an evidence descriptor, a peer message) has no
/// bearing on what the artifact proves: the bytes are re-hashed to the
/// requested identity by the fetch, and then every leaf key, leaf commitment
/// and inclusion path is recomputed against the root the CALLER named. An
/// artifact naming any other publisher, position or root is refused.
pub(crate) async fn fetch_verified_economic_proof(
    inner_addr: &[u8; 32],
    publisher_genesis: &[u8; 32],
    publisher_devid: &[u8; 32],
    position: u64,
    root: &[u8; 32],
) -> Result<dsm::economic::proof_artifact::EconomicProofArtifact, DsmError> {
    let payload = crate::sdk::storage_io::fetch_immutable_payload(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_PROOF_ARTIFACT,
        inner_addr,
    )
    .await?
    .ok_or_else(|| {
        DsmError::storage(
            "economic proof artifact is not published".to_string(),
            None::<std::io::Error>,
        )
    })?;
    let artifact = dsm::economic::proof_artifact::decode_economic_proof_artifact(&payload)
        .map_err(|e| DsmError::verification(format!("economic proof artifact: {e}")))?;
    artifact
        .verify_against(publisher_genesis, publisher_devid, position, root)
        .map_err(|e| DsmError::verification(format!("economic proof artifact: {e}")))?;
    Ok(artifact)
}

pub(crate) fn immutable_object_key(
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    payload: &[u8],
) -> String {
    let addr = dsm::storage_object::immutable_addr(namespace, payload);
    format!(
        "immutable::{}::{}",
        String::from_utf8_lossy(namespace.source_bytes()),
        text_id::encode_base32_crockford(&addr)
    )
}

#[cfg(test)]
mod tests {
    //! Direct controls on the Req 15.8 counting rules — the pure gates every
    //! register operation funnels through. Each test is the mutation control
    //! for one counting clause: weaken that clause and its test goes red.

    use super::*;
    use crate::sdk::storage_node_sdk::{ClaimFanout, MemberClaimOutcome, MemberClaimResult};
    use crate::sdk::storage_set::StorageMember;

    fn three_member_set() -> StorageSet {
        StorageSet::new(
            (1..=3)
                .map(|i| StorageMember {
                    register_incarnation_id: [0xC0 | i as u8; 32],
                    member_id: format!("dsm-node-{i}"),
                    endpoint: format!("http://127.0.0.1:808{i}"),
                })
                .collect(),
        )
        .expect("set")
    }

    fn outcome(member: &str, echo: Option<&str>, result: MemberClaimResult) -> MemberClaimOutcome {
        MemberClaimOutcome {
            member_id: member.to_string(),
            endpoint: String::new(),
            result,
            echoed_node_id: echo.map(str::to_string),
        }
    }

    fn fanout(outcomes: Vec<MemberClaimOutcome>) -> ClaimFanout {
        let total = outcomes.len() as u32;
        ClaimFanout { outcomes, total }
    }

    #[test]
    fn an_unattributed_acceptance_never_counts() {
        // Two members say "accepted" but one echoes a DIFFERENT node id —
        // a response that cannot be attributed to the member queried is
        // uncountable (Req 15.8), so quorum is NOT met.
        let f = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome(
                "dsm-node-2",
                Some("dsm-node-9"),
                MemberClaimResult::Accepted,
            ),
            outcome(
                "dsm-node-3",
                None,
                MemberClaimResult::Unavailable("down".into()),
            ),
        ]);
        match count_claim(&f, &[0u8; 32], 2) {
            Err(RegisterError::StorageUnavailable { accepted, .. }) => assert_eq!(accepted, 1),
            other => panic!("unattributed acceptance counted: {other:?}"),
        }
    }

    #[test]
    fn a_generic_refusal_never_counts_toward_quorum() {
        // One attributed acceptance + one generic refusal at q=2: the refusal
        // must fail the claim CLOSED (contested), never count toward it.
        let f = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome(
                "dsm-node-2",
                Some("dsm-node-2"),
                MemberClaimResult::Refused { held_digest: None },
            ),
            outcome(
                "dsm-node-3",
                None,
                MemberClaimResult::Unavailable("down".into()),
            ),
        ]);
        match count_claim(&f, &[0u8; 32], 2) {
            Err(RegisterError::Contested { refused_by }) => assert_eq!(refused_by, 1),
            other => panic!("generic refusal mis-counted: {other:?}"),
        }
    }

    #[test]
    fn refused_with_our_exact_digest_counts_only_when_attributed() {
        // held-identical reported as a refusal carrying OUR digest is an
        // acceptance in different words — with the same attribution bar.
        let ours = [7u8; 32];
        let held = MemberClaimResult::Refused {
            held_digest: Some(ours.to_vec()),
        };
        let attributed = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome("dsm-node-2", Some("dsm-node-2"), held.clone()),
        ]);
        let cell = count_claim(&attributed, &ours, 2).expect("attributed identical digest counts");
        assert_eq!(cell.accepted(), 2);

        let unattributed = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome("dsm-node-2", Some("dsm-node-9"), held),
        ]);
        assert!(
            count_claim(&unattributed, &ours, 2).is_err(),
            "identical digest without attribution must not count"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn divergent_values_in_one_write_once_cell_are_a_conflict() {
        // Two attributed members holding DIFFERENT bytes for one cell is the
        // catastrophic case: quarantine, never hash-order, never overwrite.
        use dsm::economic::cell_observation::MemberCellRead;
        let set = three_member_set();
        let reads = vec![
            MemberCellRead::Value(vec![1u8]),
            MemberCellRead::Value(vec![2u8]),
            MemberCellRead::Absent,
        ];
        match read_cell_quorum(&set, reads).await {
            Err(RegisterError::Conflict { .. }) => {}
            other => panic!("divergent cell not quarantined: {other:?}"),
        }
    }

    /// CONFIGURATION LOCATES A MEMBER; IT NEVER SUBSTITUTES A SET.
    ///
    /// The committed set is resolved by RE-DERIVING its id from the member ids
    /// a catalog entry lists and requiring that to reproduce the id the vault
    /// signed. A catalog holding some other fleet therefore cannot answer for
    /// this vault's register — it fails closed instead of quietly reading a
    /// different one.
    ///
    /// In beta the configured fleet and every vault's birth set are the same
    /// three members, so this is the property that is decidable today; the
    /// behavioural difference only appears once a second set exists.
    #[test]
    fn a_committed_set_resolves_only_from_members_that_re_derive_its_id() {
        let members = dsm::ccb::StorageSetMembers::new(&[
            (b"dsm-node-1".as_slice(), [0xC0; 32]),
            (b"dsm-node-2".as_slice(), [0xC1; 32]),
            (b"dsm-node-3".as_slice(), [0xC2; 32]),
        ])
        .expect("members");
        let committed_id = dsm::ccb::storage_set_id(&members).expect("id");

        let foreign = dsm::ccb::StorageSetMembers::new(&[
            (b"somebody-elses-node-1".as_slice(), [0xC0; 32]),
            (b"somebody-elses-node-2".as_slice(), [0xC1; 32]),
            (b"somebody-elses-node-3".as_slice(), [0xC2; 32]),
        ])
        .expect("members");
        assert_ne!(
            dsm::ccb::storage_set_id(&foreign).expect("id"),
            committed_id,
            "the two sets must differ for this to prove anything"
        );

        // A set whose members do not re-derive the committed id is refused,
        // whatever the local catalog happens to contain.
        assert!(
            resolve_committed_set(&foreign).is_err(),
            "a foreign set must not resolve"
        );
    }

    /// ATTRIBUTION IS FOLDED INTO THE READ, and it is load-bearing in the
    /// dangerous direction: an unattributed response must not be counted as an
    /// ABSENCE, because a quorum of absences is the one observation a forward
    /// lineage walk treats as terminal.
    ///
    /// The cell is empty here, so a correctly-echoing member says `Absent`. A
    /// member whose response carries another id or none, and a member that is
    /// down, each say nothing at all — and the observation is `Unavailable`
    /// rather than an emptiness a walker would act on.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mis_echoed_or_failing_member_is_never_counted_as_an_absence() {
        use dsm::economic::cell_observation::{observe_cell, CellObservation, MemberCellRead};
        let set = three_member_set();
        crate::sdk::storage_io::fake_registers::reset();
        crate::sdk::storage_io::fake_registers::set_echo(
            "dsm-node-2",
            Some("dsm-node-9".to_string()),
        );
        // And a member that is simply DOWN. An outage is the same kind of
        // non-answer as a mis-echo: it must never become the absence a
        // forward walk would read as a frontier.
        crate::sdk::storage_io::fake_registers::fail_member("dsm-node-3", true);
        let reads = crate::sdk::storage_io::fake_registers::read(
            &set,
            crate::sdk::storage_io::fake_registers::RegisterKind::EconomicRoot,
            b"cell-key",
        );
        assert_eq!(
            reads[0],
            MemberCellRead::Absent,
            "an attributed member with no row asserts absence"
        );
        assert_eq!(
            reads[1],
            MemberCellRead::Unavailable,
            "a mis-echoed response is not an answer"
        );
        assert_eq!(
            reads[2],
            MemberCellRead::Unavailable,
            "a member that is down is not an answer"
        );
        assert!(
            matches!(
                observe_cell(&reads, set.quorum()),
                CellObservation::Unavailable { attributed: 1, .. }
            ),
            "one absence is short of quorum and the other two answered nothing"
        );
        crate::sdk::storage_io::fake_registers::reset();
    }
}
