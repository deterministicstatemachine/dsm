// SPDX-License-Identifier: Apache-2.0

//! The client side of the economic root register, and the live provenance
//! resolver.
//!
//! ## The root register is a cell (Part II §8, §13)
//!
//! `K_root(q)` is a keyed cell that keeps every value it is given. The writer
//! computes the leader from `s(q)` over the committed set and writes there
//! first; Core derives `LeaderHeld` and `Final` from the raw reads
//! (`dsm::sofi::arith::resolve_objects`). Nothing is counted and no node
//! decides.
//!
//! ## Frozen envelopes
//!
//! Every envelope is signed ONCE, durably retained BEFORE the first member
//! write, and replayed byte-identically forever. SPHINCS+ signing here is
//! deterministic: a regenerated envelope is indistinguishable from a replayed
//! one downstream, so the safe design is for regeneration to be impossible.

use dsm::economic::provenance::{
    PeerLineageFailure, ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
};

use crate::sdk::storage_set::StorageSet;
use crate::util::text_id;

/// Evidence that THIS envelope reached its cell's leader. Private fields;
/// constructible only by the register functions below.
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
    /// The leader was not reached, or too few members answered; retry later
    /// with the SAME bytes.
    StorageUnavailable { accepted: u32, total: u32 },
}

impl core::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StorageUnavailable { accepted, total } => write!(
                f,
                "register unavailable: {accepted}/{total} members hold the bytes — retry with \
                 the SAME frozen bytes"
            ),
        }
    }
}

/// The namespace of the economic root cells: the key domain's own bytes.
fn economic_root_namespace() -> &'static [u8] {
    dsm::common::domain_tags::TAG_DSM_TRADER_ECONOMIC_ROOT_REGISTER_KEY.source_bytes()
}

/// An object naming `K_root(q)`: a registered economic claim whose own
/// coordinates derive that key. Bytes that are not one count as nothing
/// (Part II §8): they are neither a rival nor a winner.
fn names_root_key(value: &[u8], k_root: &[u8; 32]) -> bool {
    dsm::economic::claim_envelope::decode_registered_economic_claim(value)
        .map(|claim| {
            let (genesis, devid) = claim.trader();
            dsm::economic::register::economic_root_register_key(
                &genesis,
                &devid,
                claim.economic_position(),
            ) == *k_root
        })
        .unwrap_or(false)
}

/// Register this device's frozen root claim at `K_root(q)` (Part II §8): the
/// leader of `s(q)` gets the bytes first, the other members after. Succeeds
/// once the leader holds the write — the race at the key is then settled
/// for these bytes unless another object got there first, which Core reads
/// back as `LeaderHeld` of that object. Copies not reached now may be
/// carried by anyone later; finality is never decided here.
pub async fn register_economic_root(
    set: &StorageSet,
    genesis: &[u8; 32],
    devid: &[u8; 32],
    economic_position: u64,
    parent_root: &[u8; 32],
    frozen_envelope: &[u8],
) -> Result<ClaimedCell, RegisterError> {
    let k_root =
        dsm::economic::register::economic_root_register_key(genesis, devid, economic_position);
    let seed =
        dsm::economic::register::position_seed(genesis, devid, economic_position, parent_root);
    let total = set.len() as u32;
    let write = crate::sdk::storage_io::write_cell_leader_first(
        set,
        economic_root_namespace(),
        &k_root,
        &seed,
        frozen_envelope,
    )
    .await
    .map_err(|_| RegisterError::StorageUnavailable { accepted: 0, total })?;
    if !write.leader_reached {
        return Err(RegisterError::StorageUnavailable {
            accepted: write.copies,
            total,
        });
    }
    Ok(ClaimedCell {
        accepted: write.copies + 1,
        total,
    })
}

/// The FINAL value at `K_root(q)` (Part II §13), derived by Core from raw
/// member reads: the leader's first object naming the key, held by two other
/// members. `seed` is `s(q)` from a root the caller validated itself. `None`
/// while the cell is open, or held at the leader but not yet copied; no key
/// is ever dead, so there is no conflict to report.
pub async fn read_economic_root_cell(
    set: &StorageSet,
    k_root: &[u8; 32],
    seed: &[u8; 32],
) -> Result<Option<Vec<u8>>, RegisterError> {
    use dsm::sofi::arith::{resolve_objects, ObjectResolution};
    let total = set.len() as u32;
    let unavailable = || RegisterError::StorageUnavailable { accepted: 0, total };
    let leader = crate::sdk::storage_io::leader_index(set, seed).map_err(|_| unavailable())?;
    let reads = crate::sdk::storage_io::read_cell_raw(set, economic_root_namespace(), k_root)
        .await
        .map_err(|_| unavailable())?;
    // Only objects naming the key are observed; everything else is nothing.
    match resolve_objects(&reads, leader, |v| names_root_key(v, k_root))
        .map_err(|_| unavailable())?
    {
        ObjectResolution::Final(bytes) => Ok(Some(bytes)),
        ObjectResolution::LeaderHeld(_)
        | ObjectResolution::Open
        | ObjectResolution::Unavailable => Ok(None),
    }
}

/// The LIVE provenance resolver: register cells final at their leader, the
/// native reserve walked from its genesis state, immutable objects
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
        // IS this network's PINNED register, and let `verify_candidate` decide
        // whether it really is.
        let candidate = catalog
            .sets()
            .iter()
            .find_map(|s| {
                let members = crate::sdk::storage_set::as_ccb_members(s).ok()?;
                profile.verify_candidate(&members).ok().map(|()| members)
            })
            .ok_or_else(|| {
                PeerLineageFailure::Incomplete(
                    "no configured storage set has this network's canonical membership".into(),
                )
            })?;
        Ok(candidate)
    }

    fn register_cell(
        &self,
        k_root: &[u8; 32],
        seed: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        let (k, s) = (*k_root, *seed);
        tokio::task::block_in_place(|| {
            self.runtime
                .block_on(read_economic_root_cell(self.set, &k, &s))
        })
        .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<Option<ReserveReleaseWin>, PeerLineageFailure> {
        crate::sdk::native_reserve::release_at(
            self.set,
            &self.expected_network_id,
            &self.runtime,
            reserve_id,
            generation,
        )
        .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))
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
        result.validated_root().economic_position(),
        &result.validated_root().economic_root(),
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
        result.validated_root().economic_position(),
        &result.validated_root().economic_root(),
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

    fn register_cell(
        &self,
        k_root: &[u8; 32],
        seed: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        dsm::economic::peer_lineage::PeerEvidenceFetcher::register_cell(self.inner, k_root, seed)
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<Option<ReserveReleaseWin>, PeerLineageFailure> {
        dsm::economic::peer_lineage::PeerEvidenceFetcher::native_reserve_release(
            self.inner, reserve_id, generation,
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
        // IS this network's PINNED register, and let `verify_candidate` decide
        // whether it really is.
        let candidate = catalog
            .sets()
            .iter()
            .find_map(|s| {
                let members = crate::sdk::storage_set::as_ccb_members(s).ok()?;
                profile.verify_candidate(&members).ok().map(|()| members)
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

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Option<ReserveReleaseWin> {
        crate::sdk::native_reserve::release_at(
            self.set,
            &self.expected_network_id,
            &self.runtime,
            reserve_id,
            generation,
        )
        .ok()
        .flatten()
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
