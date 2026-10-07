// SPDX-License-Identifier: Apache-2.0
//! What the SoFi verifier reads, answered from the storage nodes and this
//! device's own records: the SDK's [`SofiReads`].
//!
//! Core decides what is read and what it means (`dsm::sofi::resolve`); this
//! module only answers — bytes, cells, this device's own rows — the way
//! `LiveRegisterResolver` answers the peer lineage walk. Every network read
//! runs on the SDK's multi-thread runtime from the verifier's synchronous
//! call (`block_in_place`), which is the shape the peer walk already has.

use std::collections::BTreeMap;
use std::future::Future;

use dsm::ccb::StorageSetMembers;
use dsm::common::domain_tags::{TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR, TAG_DSM_SOFI_VAULT_TOKEN_LOCATOR};
use dsm::economic::lineage::{AcceptedClaim, AdmittedEconomicPosition, ValidatedEconomicRoot};
use dsm::crypto::domain::TaggedHashDomain;
use dsm::economic::peer_lineage::PeerEvidenceFetcher;
use dsm::economic::provenance::{PeerLineageFailure, ReserveReleaseWin, ValidatedPeerTransition};
use dsm::economic::register::{read_root_cell, RootCell};
use dsm::route_chain::{CellEvidence, CellReading, ChainState, CompletionProof, RoutedCell};
use dsm::sofi::derive;
use dsm::sofi::facts::ResolvedParent;
use dsm::sofi::publication::Signed;
use dsm::sofi::resolve::{
    AcceptedGeneses, JudgedKey, KeptJudgement, LocalLeaves, PeerPositionResolver, ReadFailure,
    RecordedGenerationRow, SofiReads, Verifier, VerifierFailure,
};
use dsm::sofi::storage::{Discovered, Resolved};
use dsm::sofi::validation::VaultPostState;
use dsm::sofi::wire::{
    ParentClaimRef, TraderFulfillmentBody, TraderPrecommitBody, VaultGenesisPreimage,
};
use dsm::types::error::DsmError;

use crate::sdk::economic_admission_flow::committed_network_id;
use crate::sdk::economic_registers::{
    anchored_policy_bytes, resolve_peer, resolve_peer_claim, resolve_peer_root,
    LiveRegisterResolver,
};
use crate::sdk::route_seats::{keep_completion, read_cell, NodeSeats};
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit, fetch_setup_bytes, LOCATOR_BUDGET};
use crate::sdk::storage_io::{read_stored_bytes_kept, resolve_locator_all};
use crate::sdk::storage_set::{as_ccb_members, StorageSet};
use crate::storage::client_db::{economic_lineage, sofi_vault_head};

type D32 = [u8; 32];

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// A verifier failure as the SDK reports it: a read that could not be made
/// is a storage error; what the reads refuted is an invalid operation.
pub fn verifier_error(failure: VerifierFailure) -> DsmError {
    match failure {
        VerifierFailure::Read(why) => storage_err("sofi verifier", why),
        VerifierFailure::Refused(why) => {
            DsmError::invalid_operation(format!("sofi verifier: {why}"))
        }
    }
}

/// The leaves of this device's validated root, from the leaf cache; the
/// cache is a cache, so its root is recomputed and must equal the validated
/// one.
pub fn local_leaves_of_validated(
    genesis: &D32,
    device_id: &D32,
    validated: &ValidatedEconomicRoot,
) -> Result<LocalLeaves, DsmError> {
    let leaves = if validated.economic_position() == 0 {
        Vec::new()
    } else {
        economic_lineage::load_leaf_cache().map_err(|e| storage_err("load leaf cache", e))?
    };
    let decoded: Vec<(D32, dsm::economic::state::EconomicLeafState)> = leaves
        .iter()
        .map(|(key, .., ccb)| {
            dsm::economic::decode::decode_leaf_state(ccb)
                .map(|state| (*key, state))
                .map_err(|e| storage_err("decode cached leaf state", e))
        })
        .collect::<Result<_, _>>()?;
    LocalLeaves::checked(*genesis, *device_id, validated.economic_root(), decoded)
        .map_err(|e| storage_err("local leaves", e))
}

/// The verifier's reads over the storage nodes of the pinned set and this
/// device's own records.
pub struct LiveSofiReads<'a> {
    set: &'a StorageSet,
    runtime: tokio::runtime::Handle,
    network: Vec<u8>,
    /// This device's `(genesis, device_id)` when it verifies as a trader:
    /// the one identity its own admitted store answers for.
    own: Option<(D32, D32)>,
    /// What this context read and keeps for its life — one resolution, one
    /// quote, one walk — so the verifier's passes over the same cells and
    /// objects read each once ([`ReadOnce`]).
    once: std::sync::Arc<ReadOnce>,
}

/// What the contexts of one operation keep between them: the readings
/// [`ReadOnce`] keeps (the roots verified for other traders are kept by the
/// process). Each is final, and holds whatever position this device stands on, so a
/// context built after the device's own position moved (a setup admitted
/// mid-operation) stands on them too. One operation's contexts share one; a
/// new operation starts from none.
#[derive(Clone, Default)]
pub struct KeptReadings {
    once: std::sync::Arc<ReadOnce>,
}

/// The readings one context keeps: only those nothing later can change. A
/// cell's reads are kept once Core evaluated them as showing a final value
/// at the cell — a final value holds the cell for good; an object once Core
/// read it `Stored`, kept under its id, or re-hashed to its address; a
/// locator's candidates once every one was examined. An open or undecided
/// cell, and an unavailable or partial reading, is read again each time it
/// is asked for: it may have been written since.
#[derive(Default)]
struct ReadOnce {
    cells: std::sync::Mutex<BTreeMap<CellId, CellEvidence>>,
    objects: std::sync::Mutex<BTreeMap<D32, Option<Vec<u8>>>>,
    /// The peer walks' immutable objects, by namespace and identity: bytes a
    /// member served that re-hashed to their address.
    fetched: std::sync::Mutex<BTreeMap<(Vec<u8>, D32), Vec<u8>>>,
    precommits: std::sync::Mutex<BTreeMap<D32, Resolved<Signed<TraderPrecommitBody>>>>,
    fulfillments: std::sync::Mutex<BTreeMap<D32, Resolved<Signed<TraderFulfillmentBody>>>>,
    setups: std::sync::Mutex<BTreeMap<D32, Resolved<Vec<u8>>>>,
    geneses: std::sync::Mutex<BTreeMap<D32, Discovered<(VaultGenesisPreimage, Vec<u8>)>>>,
}

/// A cell as its reading depends on it: the namespace and key it is read
/// at, and the seed and committed set its route is derived from.
type CellId = (Vec<u8>, D32, D32, D32);

fn cell_id(cell: &RoutedCell) -> CellId {
    (
        cell.namespace().to_vec(),
        *cell.key(),
        *cell.seed(),
        *cell.committed_set_id(),
    )
}

/// The kept readings could not be consulted.
struct Unkept(String);

impl From<Unkept> for ReadFailure {
    fn from(unkept: Unkept) -> Self {
        ReadFailure(format!("the readings kept: {}", unkept.0))
    }
}

impl From<Unkept> for PeerLineageFailure {
    fn from(unkept: Unkept) -> Self {
        PeerLineageFailure::Incomplete(format!("the readings kept: {}", unkept.0))
    }
}

/// `memo`'s reading under `key`, or `read` it and keep it when `complete`.
fn read_once<K: Ord, V: Clone, E: From<Unkept>>(
    memo: &std::sync::Mutex<BTreeMap<K, V>>,
    key: K,
    read: impl FnOnce() -> Result<V, E>,
    complete: impl FnOnce(&V) -> bool,
) -> Result<V, E> {
    let lock = || memo.lock().map_err(|e| Unkept(e.to_string()));
    if let Some(kept) = lock()?.get(&key) {
        return Ok(kept.clone());
    }
    let reading = read()?;
    if complete(&reading) {
        lock()?.insert(key, reading.clone());
    }
    Ok(reading)
}

/// Every candidate under the locator was examined.
fn discovered_all<T>(discovered: &Discovered<T>) -> bool {
    matches!(discovered, Discovered::Complete(..))
}

/// The peer step checks' reads, through the context's: a resolution that
/// checks the same trader's step twice reads its register cell and objects
/// once.
struct OnceFetcher<'r, 'a> {
    live: LiveRegisterResolver<'a>,
    once: &'r ReadOnce,
}

impl PeerEvidenceFetcher for OnceFetcher<'_, '_> {
    /// Never kept: what members hold under a key is where to look, and a
    /// later look may find a claim that was not there yet.
    fn register_key_values(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
        self.live.register_key_values(genesis, device_id, position)
    }

    fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
        // Kept once Core reads a final claim at the cell from them.
        read_once(
            &self.once.cells,
            cell_id(cell.routed()),
            || self.live.register_cell(cell),
            |evidence| {
                matches!(
                    read_root_cell(cell, evidence),
                    Ok(CellReading::Held {
                        state: ChainState::Final,
                        ..
                    })
                )
            },
        )
    }

    fn native_reserve_release(
        &self,
        reserve_id: &D32,
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.live.native_reserve_release(reserve_id, generation)
    }

    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<StorageSetMembers, PeerLineageFailure> {
        self.live.root_register_candidate_set(network_id)
    }

    fn immutable(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &D32,
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        // Kept only as the object it is: bytes whose identity under
        // `namespace`, recomputed here, is `addr`.
        read_once(
            &self.once.fetched,
            (namespace.source_bytes().to_vec(), *addr),
            || self.live.immutable(namespace, addr),
            |bytes| dsm::storage_object::immutable_inner(namespace, bytes) == *addr,
        )
    }

    fn anchored_policy_bytes(&self, policy_commit: &D32) -> Result<Vec<u8>, PeerLineageFailure> {
        self.live.anchored_policy_bytes(policy_commit)
    }

    fn held_ek_step(
        &self,
        signer: &D32,
        addr: &D32,
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        self.live.held_ek_step(signer, addr)
    }
}

impl<'a> LiveSofiReads<'a> {
    /// This device's `(genesis, device_id)` when it verifies as a trader.
    pub(crate) fn own(&self) -> Option<(D32, D32)> {
        self.own
    }

    pub fn new(set: &'a StorageSet, own: Option<(D32, D32)>) -> Result<Self, DsmError> {
        Self::keeping(set, own, &KeptReadings::default())
    }

    /// [`Self::new`], keeping its readings in `kept`, which the other
    /// contexts of the same operation share.
    fn keeping(
        set: &'a StorageSet,
        own: Option<(D32, D32)>,
        kept: &KeptReadings,
    ) -> Result<Self, DsmError> {
        Ok(Self {
            set,
            runtime: tokio::runtime::Handle::current(),
            network: committed_network_id()?,
            own,
            once: kept.once.clone(),
        })
    }

    /// The peer walks' fetcher: the live one, through this context's
    /// readings.
    fn peer_resolver(&self) -> OnceFetcher<'_, '_> {
        OnceFetcher {
            live: LiveRegisterResolver {
                set: self.set,
                runtime: self.runtime.clone(),
                expected_network_id: self.network.clone(),
            },
            once: &self.once,
        }
    }

    /// Another trader's lineage to `position`, verified from this device's
    /// frontier for it (DSM Amendment A8); a conditional position on the way
    /// is resolved by Core over SoFi's public objects for that position alone
    /// (SoFi Amendment S15).
    fn peer_walk(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let members = as_ccb_members(self.set)
            .map_err(|e| PeerLineageFailure::Incomplete(format!("the storage set: {e}")))?;
        let conditional = PeerPositionResolver {
            reads: self,
            members: &members,
            set_id: self.set.id(),
            network_id: &self.network,
            programs: crate::sdk::outcome_programs::registry(),
        };
        resolve_peer(
            &self.peer_resolver(),
            &self.network,
            genesis,
            device_id,
            position,
            &conditional,
        )
    }

    fn block<T>(&self, fut: impl Future<Output = T>) -> T {
        tokio::task::block_in_place(|| self.runtime.block_on(fut))
    }

    fn read<T>(
        &self,
        what: &str,
        fut: impl Future<Output = Result<T, DsmError>>,
    ) -> Result<T, ReadFailure> {
        self.block(fut)
            .map_err(|e| ReadFailure(format!("{what}: {e}")))
    }
}

/// A vault genesis preimage recognized from its bytes, with those bytes:
/// bytes that do not decode as one are no candidate under either of the
/// indexes a genesis is published under.
fn recognize_genesis(bytes: &[u8]) -> Option<(VaultGenesisPreimage, Vec<u8>)> {
    let preimage = VaultGenesisPreimage::decode(bytes).ok()?;
    Some((preimage, bytes.to_vec()))
}

impl SofiReads for LiveSofiReads<'_> {
    fn cell(&self, cell: &RoutedCell) -> Result<CellEvidence, ReadFailure> {
        // The reads Core evaluated as final here are kept with the
        // completion proof ([`Self::keep_completion`]); anything else is
        // read again.
        let kept = self
            .once
            .cells
            .lock()
            .map_err(|e| ReadFailure::from(Unkept(e.to_string())))?
            .get(&cell_id(cell))
            .cloned();
        if let Some(kept) = kept {
            return Ok(kept);
        }
        // An earlier verification in this process may have read it final.
        if let Some(kept) = crate::sdk::final_reads::final_cell(cell) {
            return Ok(kept);
        }
        let seats = NodeSeats::new(self.set).map_err(|e| ReadFailure(format!("seats: {e}")))?;
        Ok(self.block(read_cell(&seats, cell)))
    }

    fn precommit(&self, id: &D32) -> Result<Resolved<Signed<TraderPrecommitBody>>, ReadFailure> {
        read_once(
            &self.once.precommits,
            *id,
            || self.read("precommit", fetch_precommit(self.set, id)),
            |read| matches!(read, Resolved::Kept(..)),
        )
    }

    fn fulfillment(
        &self,
        id: &D32,
    ) -> Result<Resolved<Signed<TraderFulfillmentBody>>, ReadFailure> {
        read_once(
            &self.once.fulfillments,
            *id,
            || self.read("fulfillment", fetch_fulfillment(self.set, id)),
            |read| matches!(read, Resolved::Kept(..)),
        )
    }

    fn setup_bytes(&self, setup_ref: &D32) -> Result<Resolved<Vec<u8>>, ReadFailure> {
        read_once(
            &self.once.setups,
            *setup_ref,
            || self.read("setup", fetch_setup_bytes(self.set, setup_ref)),
            |read| matches!(read, Resolved::Kept(..)),
        )
    }

    fn stored_bytes(&self, addr: &D32) -> Result<Option<Vec<u8>>, ReadFailure> {
        read_once(
            &self.once.objects,
            *addr,
            || self.read("stored bytes", read_stored_bytes_kept(self.set, addr)),
            Option::is_some,
        )
    }

    fn token_policy_bytes(&self, policy_commit: &D32) -> Result<Vec<u8>, ReadFailure> {
        anchored_policy_bytes(self.set, policy_commit, &self.runtime)
            .map_err(|failure| ReadFailure(format!("token policy: {failure}")))
    }

    fn vault_genesis_candidates(
        &self,
        vault_id: &D32,
    ) -> Result<Discovered<(VaultGenesisPreimage, Vec<u8>)>, ReadFailure> {
        let locator = derive::vault_genesis_locator(vault_id);
        read_once(
            &self.once.geneses,
            *vault_id,
            || {
                self.read(
                    "vault genesis candidates",
                    resolve_locator_all(
                        self.set,
                        TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
                        &locator,
                        LOCATOR_BUDGET,
                        |bytes| {
                            recognize_genesis(bytes).map(|(preimage, bytes)| {
                                (
                                    derive::vault_genesis_locator(&preimage.vault_id()),
                                    (preimage, bytes),
                                )
                            })
                        },
                    ),
                )
            },
            discovered_all,
        )
    }

    fn vault_token_candidates(&self, token: &D32) -> Result<Discovered<D32>, ReadFailure> {
        let locator = derive::vault_token_locator(token);
        self.read(
            "vault token candidates",
            resolve_locator_all(
                self.set,
                TAG_DSM_SOFI_VAULT_TOKEN_LOCATOR.source_bytes(),
                &locator,
                LOCATOR_BUDGET,
                // Every genesis preimage under the locator is a candidate;
                // Core accepts it and checks its market (Amendment S16).
                |bytes| {
                    recognize_genesis(bytes).map(|(preimage, ..)| (locator, preimage.vault_id()))
                },
            ),
        )
    }

    fn escrow_cell_candidates(&self, verdict_cell: &D32) -> Result<Discovered<D32>, ReadFailure> {
        let locator = dsm::sofi::escrow::cell_locator(verdict_cell);
        self.read(
            "escrow cell candidates",
            resolve_locator_all(
                self.set,
                dsm::common::domain_tags::TAG_DSM_ESCROW_CELL_LOCATOR.source_bytes(),
                &locator,
                LOCATOR_BUDGET,
                // Every genesis preimage under the locator is a candidate;
                // Core accepts it and checks its terms derive the cell (SoFi
                // Amendment S21).
                |bytes| {
                    recognize_genesis(bytes).map(|(preimage, ..)| (locator, preimage.vault_id()))
                },
            ),
        )
    }

    fn vault_owner(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        self.peer_walk(genesis, device_id, position)
    }

    fn vault_state_at(
        &self,
        vault_id: &D32,
        root: &D32,
    ) -> Result<Option<dsm::sofi::wire::VaultStateLeaf>, ReadFailure> {
        sofi_vault_head::state_at(vault_id, root)
            .map_err(|e| ReadFailure(format!("vault head: {e}")))
    }

    fn recorded_baseline(
        &self,
        genesis: &dsm::sofi::lineage::AcceptedVaultGenesis,
    ) -> Result<Option<dsm::sofi::frontier::VerifiedFrontier>, ReadFailure> {
        let Some((generation, bundle)) = sofi_vault_head::baseline(genesis.vault_id())
            .map_err(|e| ReadFailure(format!("vault baseline: {e}")))?
        else {
            return Ok(None);
        };
        // The record is this device's own; it stands only as Core
        // authenticates it again now.
        match crate::sdk::vault_baseline::authenticate(&bundle, genesis) {
            Ok(verified) if verified.frontier().generation == generation => Ok(Some(verified)),
            Ok(..) => Err(ReadFailure(
                "the recorded baseline is not at the generation it was recorded at".into(),
            )),
            Err(e) => Err(ReadFailure(format!("the recorded baseline: {e}"))),
        }
    }

    fn trader_root_at(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<(ValidatedEconomicRoot, ParentClaimRef), PeerLineageFailure> {
        // Verified roots are kept by the process, not by this context: a
        // holdings status builds a context for every poll.
        let members = as_ccb_members(self.set)
            .map_err(|e| PeerLineageFailure::Incomplete(format!("the storage set: {e}")))?;
        let conditional = PeerPositionResolver {
            reads: self,
            members: &members,
            set_id: self.set.id(),
            network_id: &self.network,
            programs: crate::sdk::outcome_programs::registry(),
        };
        resolve_peer_root(
            &self.peer_resolver(),
            &self.network,
            genesis,
            device_id,
            position,
            &conditional,
        )
    }

    fn accepted_claim_at(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<AcceptedClaim, PeerLineageFailure> {
        if self.own != Some((*genesis, *device_id)) {
            // Another trader's position: the claim frontier-relative
            // verification of its lineage accepted there (SoFi Amendment
            // S15, MR-SOFI-0347) — a SoFi position's by its resolution, since
            // a setup made right after one names that claim — or the walk's
            // failure in the class it gave it. The process keeps each claim a
            // complete walk established.
            let members = as_ccb_members(self.set)
                .map_err(|e| PeerLineageFailure::Incomplete(format!("the storage set: {e}")))?;
            let conditional = PeerPositionResolver {
                reads: self,
                members: &members,
                set_id: self.set.id(),
                network_id: &self.network,
                programs: crate::sdk::outcome_programs::registry(),
            };
            return resolve_peer_claim(
                &self.peer_resolver(),
                &self.network,
                genesis,
                device_id,
                position,
                &conditional,
            );
        }
        let admitted = economic_lineage::get_admitted_at(position)
            .map_err(|e| PeerLineageFailure::Incomplete(format!("admitted history: {e}")))?
            .ok_or_else(|| {
                PeerLineageFailure::Incomplete(format!("no admitted position at {position}"))
            })?;
        AcceptedClaim::rehydrate_from_admitted_store(*genesis, *device_id, admitted)
            .map_err(|unresolved| PeerLineageFailure::Unresolved(unresolved.to_string()))
    }

    fn recorded_generations(
        &self,
        vault_id: &D32,
    ) -> Result<Vec<RecordedGenerationRow>, ReadFailure> {
        sofi_vault_head::recorded_generations(vault_id)
            .map_err(|e| ReadFailure(format!("recorded generations: {e}")))
    }

    fn record_generation(&self, post: &VaultPostState) -> Result<(), ReadFailure> {
        sofi_vault_head::record_walked(post)
            .map_err(|e| ReadFailure(format!("record generation: {e}")))
    }

    fn keep_completion(
        &self,
        cell: &RoutedCell,
        evidence: &CellEvidence,
        proof: &CompletionProof,
    ) -> Result<(), ReadFailure> {
        keep_completion(cell, proof).map_err(|e| ReadFailure(format!("keep completion: {e}")))?;
        crate::sdk::final_reads::keep_final_cell(cell, evidence);
        self.once
            .cells
            .lock()
            .map_err(|e| ReadFailure::from(Unkept(e.to_string())))?
            .insert(cell_id(cell), evidence.clone());
        Ok(())
    }

    fn kept_judgement(&self, key: &JudgedKey) -> Result<Option<KeptJudgement>, ReadFailure> {
        Ok(judgements().get(key).cloned())
    }

    fn keep_judgement(&self, key: JudgedKey, judgement: KeptJudgement) -> Result<(), ReadFailure> {
        let mut kept = judgements();
        if kept.len() >= JUDGEMENTS_MAX {
            kept.clear();
        }
        kept.insert(key, judgement);
        Ok(())
    }
}

/// The skipped keys walks judged, kept for the life of the process (see
/// `SofiReads::keep_judgement`): a vault's head is walked by every quote,
/// every `sofi.vaults` and every escrow status, and each re-read and
/// re-judged the exercises its skipped keys hold, their validation evidence
/// and the traders' lineages included. Only the walk decides what is kept.
static JUDGEMENTS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<JudgedKey, KeptJudgement>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// More than the skipped keys a phone's vaults hold: past it the memory
/// starts over, and the next walk judges each key again.
const JUDGEMENTS_MAX: usize = 512;

/// The kept judgements. A thread that panicked holding the lock left whole
/// entries behind (each is inserted in one step), so the map is taken as it
/// stands.
fn judgements(
) -> std::sync::MutexGuard<'static, std::collections::HashMap<JudgedKey, KeptJudgement>> {
    match JUDGEMENTS.lock() {
        Ok(kept) => kept,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Forget every kept judgement, where a test stands in for a fresh start
/// (`final_reads::forget_everything`): tests reuse identities, and so
/// vaults and exercises, over fleets that start empty.
#[cfg(test)]
pub(crate) fn forget_judgements() {
    judgements().clear();
}

/// The judgements kept, for a test.
#[cfg(test)]
pub(crate) fn judgements_kept() -> usize {
    judgements().len()
}

/// Everything a [`Verifier`] borrows, held together: the reads over the
/// pinned set, the set's members and id, the committed network, and — when
/// the verifier is a trader — its identity and the position it resolved
/// itself.
pub struct VerifierContext<'a> {
    reads: LiveSofiReads<'a>,
    members: StorageSetMembers,
    set_id: D32,
    network: Vec<u8>,
    parent: Option<ResolvedParent>,
    /// The vault geneses this context's verifiers accepted from the network.
    accepted: AcceptedGeneses,
}

impl<'a> VerifierContext<'a> {
    /// A verifier over `set`. `own` and `parent` are this device's identity
    /// and resolved predecessor when it verifies as a trader; a relay or a
    /// reader of another trader's position brings neither.
    pub fn new(
        set: &'a StorageSet,
        own: Option<(D32, D32)>,
        parent: Option<&'a AdmittedEconomicPosition>,
    ) -> Result<Self, DsmError> {
        Self::sharing(set, own, parent, &AcceptedGeneses::default())
    }

    /// [`Self::new`], standing on the vault geneses `accepted` holds: the
    /// ones this request's other contexts accepted from the network. Every
    /// context one operation builds shares one memo, so the operation reads
    /// each vault's genesis — a locator scan and a walk of its owner's
    /// lineage — once.
    pub fn sharing(
        set: &'a StorageSet,
        own: Option<(D32, D32)>,
        parent: Option<&'a AdmittedEconomicPosition>,
        accepted: &AcceptedGeneses,
    ) -> Result<Self, DsmError> {
        Self::sharing_kept(set, own, parent, accepted, &KeptReadings::default())
    }

    /// [`Self::sharing`], keeping its readings in `kept`: every context one
    /// operation builds over the set reads a final cell, an object or another
    /// trader's verified root once between them, though the device's own
    /// position moved between the contexts.
    pub fn sharing_kept(
        set: &'a StorageSet,
        own: Option<(D32, D32)>,
        parent: Option<&'a AdmittedEconomicPosition>,
        accepted: &AcceptedGeneses,
        kept: &KeptReadings,
    ) -> Result<Self, DsmError> {
        Ok(Self {
            reads: LiveSofiReads::keeping(set, own, kept)?,
            members: as_ccb_members(set)?,
            set_id: set.id(),
            network: committed_network_id()?,
            parent: parent.and_then(ResolvedParent::of),
            accepted: accepted.clone(),
        })
    }

    /// Core's resolver of another trader's conditional position (SoFi
    /// Amendment S15), over this context's reads, for a frontier-relative walk
    /// of that trader's lineage (DSM Amendment A8).
    pub fn peer_position_resolver(&self) -> PeerPositionResolver<'_, LiveSofiReads<'a>> {
        PeerPositionResolver {
            reads: &self.reads,
            members: &self.members,
            set_id: self.set_id,
            network_id: &self.network,
            programs: crate::sdk::outcome_programs::registry(),
        }
    }

    pub fn verifier(&self) -> Verifier<'_, LiveSofiReads<'a>> {
        Verifier::new(
            &self.reads,
            &self.members,
            self.set_id,
            &self.network,
            self.parent,
            self.accepted.clone(),
        )
        .with_programs(crate::sdk::outcome_programs::registry().clone())
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::sdk::storage_node_sdk::SetClient;
    use dsm::crypto::domain::TaggedHashDomain;
    use dsm::sofi::resolve::VaultGenesis;

    /// MR-STOR-0021 (storage §4): a candidate under a vault's genesis locator
    /// whose bytes no member holds may be the genesis, so the scan is a
    /// network failure, never "not published"; a candidate whose bytes are
    /// held and are not a genesis is established, and nothing. On the storage
    /// node's own code, on Postgres, as a booted device: the verifier's reads
    /// are over the network this device's genesis committed, so the test
    /// establishes that device itself rather than standing on one an earlier
    /// test left behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn an_unestablished_genesis_candidate_is_not_read_as_unpublished() {
        let _device = crate::test_support::one_device::Device::start(0xE3).await;
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let client = SetClient::new(&set).expect("a client of the set");
        let index = TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes();
        let ctx = VerifierContext::new(&set, None, None).expect("a verifier over the set");

        // Held bytes that are not a genesis: every candidate established.
        let held_vault = [0x71; 32];
        let domain = TaggedHashDomain::try_new(b"DSM/test/not-a-vault-genesis").expect("domain");
        let garbage = b"these bytes decode as no vault genesis preimage";
        assert_eq!(client.put_immutable(domain, garbage).await, 5);
        let held = dsm::storage_object::immutable_addr(domain, garbage);
        let locator = derive::vault_genesis_locator(&held_vault);
        assert_eq!(client.append_index(index, &locator, &held).await, 5);
        assert!(matches!(
            ctx.verifier().vault_genesis(&held_vault),
            Ok(VaultGenesis::NotPublished)
        ));

        // An address whose bytes no member holds: not established.
        let unknown_vault = [0x72; 32];
        let locator = derive::vault_genesis_locator(&unknown_vault);
        assert_eq!(client.append_index(index, &locator, &[0x99; 32]).await, 5);
        assert!(
            matches!(
                ctx.verifier().vault_genesis(&unknown_vault),
                Err(VerifierFailure::Read(..))
            ),
            "a candidate nobody holds must not read as an unpublished genesis"
        );
    }
}
