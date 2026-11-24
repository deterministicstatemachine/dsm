//! A vault's per-trade proof records on the storage nodes (owner ruling,
//! 2026-11-22: "Okay, good, then do it." and "Do it. That's two.").
//!
//! A record is an immutable object (`DSM/sofi/vault-proof-record/v1`),
//! indexed under its vault and generation and under its vault and root.
//! Both indexes are discovery only: what a reader finds under them stands
//! only as Core verifies the record's proof
//! (`dsm::sofi::vault_proof::verify_record`) and the walk from the record's
//! parent finds the record's trade consumed that parent.
//!
//! The newest record is found from the generation this device established
//! last: forward by doubling steps while a record verifies, then by halves.
//! Each trade this device makes is proven and published once its walk
//! establishes the trade's generation, on top of the newest record, with any
//! generation between them that its traders left unproven proven first from
//! the generations this process's walks established.

use std::collections::BTreeMap;
use std::sync::Mutex;

use dsm::common::domain_tags::{
    TAG_DSM_SOFI_VAULT_PROOF_GENERATION_LOCATOR, TAG_DSM_SOFI_VAULT_PROOF_RECORD,
    TAG_DSM_SOFI_VAULT_PROOF_ROOT_LOCATOR,
};
use dsm::shared_lineage::BundleStep;
use dsm::sofi::lineage::AcceptedVaultGenesis;
use dsm::sofi::storage::Discovered;
use dsm::sofi::validation::VaultPostState;
use dsm::sofi::vault_proof::{self, generation_locator, record_names, root_locator, ProvenVaultHead};
use dsm::types::error::DsmError;

use crate::sdk::sofi_publish::LOCATOR_BUDGET;
use crate::sdk::storage_io::{append_to_index, put_immutable, resolve_locator_all};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::sofi_vault_head;

type D32 = [u8; 32];

/// The generations a process keeps of each vault, for proving what their
/// traders left unproven: one route's worth of trades past the newest record
/// and more.
const KEPT_GENERATIONS: usize = 64;

fn storage(what: &str, why: impl core::fmt::Display) -> DsmError {
    DsmError::storage(
        format!("vault proof: {what}: {why}"),
        None::<std::io::Error>,
    )
}

/// Put `bytes`, a record, and index it under its vault's generation and
/// root.
pub(crate) async fn publish(set: &StorageSet, bytes: &[u8]) -> Result<(), DsmError> {
    let (vault_id, generation, root) = record_names(bytes).map_err(|e| storage("the record", e))?;
    let (addr, took) = put_immutable(set, TAG_DSM_SOFI_VAULT_PROOF_RECORD, bytes).await?;
    if took == 0 {
        return Err(storage("publish", "no member took the record"));
    }
    append_to_index(
        set,
        TAG_DSM_SOFI_VAULT_PROOF_GENERATION_LOCATOR.source_bytes(),
        &generation_locator(&vault_id, generation),
        &addr,
    )
    .await?;
    append_to_index(
        set,
        TAG_DSM_SOFI_VAULT_PROOF_ROOT_LOCATOR.source_bytes(),
        &root_locator(&vault_id, &root),
        &addr,
    )
    .await?;
    log::info!(
        "[vault proof] published generation {generation} of vault {}",
        crate::util::text_id::encode_base32_crockford(&vault_id)
    );
    Ok(())
}

/// The records indexed under `locator` whose own bytes name it again
/// (`name` maps what a record names to the locator it belongs under).
async fn records_under(
    set: &StorageSet,
    namespace: &[u8],
    locator: &D32,
    name: impl Fn(&(D32, u64, D32)) -> D32,
) -> Result<Vec<Vec<u8>>, DsmError> {
    let found =
        resolve_locator_all(
            set,
            namespace,
            locator,
            LOCATOR_BUDGET,
            |bytes| match record_names(bytes) {
                Ok(names) => Some((name(&names), bytes.to_vec())),
                Err(..) => None,
            },
        )
        .await?;
    Ok(match found {
        Discovered::Complete(records) | Discovered::Partial(records) => records,
    })
}

/// `vault_id`'s records at `generation`, unverified.
pub(crate) async fn records_at(
    set: &StorageSet,
    vault_id: &D32,
    generation: u64,
) -> Result<Vec<Vec<u8>>, DsmError> {
    records_under(
        set,
        TAG_DSM_SOFI_VAULT_PROOF_GENERATION_LOCATOR.source_bytes(),
        &generation_locator(vault_id, generation),
        |(vault, generation, _)| generation_locator(vault, *generation),
    )
    .await
}

/// `vault_id`'s records whose root is `root`, unverified.
pub(crate) async fn records_at_root(
    set: &StorageSet,
    vault_id: &D32,
    root: &D32,
) -> Result<Vec<Vec<u8>>, DsmError> {
    records_under(
        set,
        TAG_DSM_SOFI_VAULT_PROOF_ROOT_LOCATOR.source_bytes(),
        &root_locator(vault_id, root),
        |(vault, _, root)| root_locator(vault, root),
    )
    .await
}

/// The first of `genesis`'s vault's records at `generation` whose proof Core
/// verifies, with its bytes.
async fn proven_at(
    set: &StorageSet,
    genesis: &AcceptedVaultGenesis,
    generation: u64,
) -> Result<Option<(ProvenVaultHead, Vec<u8>)>, DsmError> {
    let vault_id = genesis.vault_id();
    // A record whose proof does not verify is passed over (DSM Amendment
    // A15: discovery carries no authority).
    for bytes in records_at(set, vault_id, generation).await? {
        match vault_proof::verify_record(&bytes, vault_id, genesis.genesis_root()) {
            Ok(head) => return Ok(Some((head, bytes))),
            Err(why) => {
                log::info!("[vault proof] a record at generation {generation} passed over: {why}");
                continue;
            }
        }
    }
    Ok(None)
}

/// The generation of `genesis`'s vault's newest record whose proof
/// verifies, with that record, or `None` where none does: from the
/// generation this device established last, forward by doubling steps while
/// a record verifies, then by halves between the last that did and the
/// first that did not.
async fn newest(
    set: &StorageSet,
    genesis: &AcceptedVaultGenesis,
) -> Result<Option<(u64, Vec<u8>)>, DsmError> {
    let vault_id = genesis.vault_id();
    let hint = sofi_vault_head::head(vault_id)
        .map_err(|e| storage("the vault head", e))?
        .map_or(0, |head| head.generation);
    let mut found: Option<(u64, Vec<u8>)> = None;
    if hint > 0 {
        if let Some((_, bytes)) = proven_at(set, genesis, hint).await? {
            found = Some((hint, bytes));
        }
    }
    let mut low = found.as_ref().map_or(0, |(generation, _)| *generation);
    let mut step = 1;
    let high = loop {
        let at = low + step;
        match proven_at(set, genesis, at).await? {
            Some((_, bytes)) => {
                found = Some((at, bytes));
                low = at;
                step *= 2;
            }
            None => break at,
        }
    };
    let mut high = high;
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        match proven_at(set, genesis, mid).await? {
            Some((_, bytes)) => {
                found = Some((mid, bytes));
                low = mid;
            }
            None => high = mid,
        }
    }
    Ok(found)
}

/// What a walk of `genesis`'s vault starts from: with `root`, the records
/// whose root is `root`; otherwise every record at the newest generation a
/// record verifies at, the verified one first, then those one generation
/// below it. Core verifies each again and tries them in order.
pub(crate) async fn candidates(
    set: &StorageSet,
    genesis: &AcceptedVaultGenesis,
    root: Option<&D32>,
) -> Result<Vec<Vec<u8>>, DsmError> {
    let vault_id = genesis.vault_id();
    if let Some(root) = root {
        return records_at_root(set, vault_id, root).await;
    }
    let mut out = Vec::new();
    if let Some((generation, verified)) = newest(set, genesis).await? {
        out.push(verified.clone());
        out.extend(
            records_at(set, vault_id, generation)
                .await?
                .into_iter()
                .filter(|bytes| *bytes != verified),
        );
        if generation > 1 {
            out.extend(records_at(set, vault_id, generation - 1).await?);
        }
    }
    Ok(out)
}

/// The generations this process's walks established, by vault and
/// generation: what proves a generation its trader left unproven.
static ESTABLISHED: Mutex<BTreeMap<D32, BTreeMap<u64, VaultPostState>>> =
    Mutex::new(BTreeMap::new());

/// Keep `post`, a generation a walk established, and when its trade is
/// `own`'s, prove it and publish its record on a thread of its own: proving
/// takes seconds of every core, and no caller's runtime waits on it or
/// outlives it.
pub(crate) fn established(
    set: &StorageSet,
    genesis: &AcceptedVaultGenesis,
    post: &VaultPostState,
    own: Option<(D32, D32)>,
) -> Result<(), DsmError> {
    {
        let mut kept = ESTABLISHED
            .lock()
            .map_err(|e| storage("the established generations", e))?;
        let vault = kept.entry(*post.vault_id()).or_default();
        vault.insert(post.generation(), post.clone());
        while vault.len() > KEPT_GENERATIONS {
            vault.pop_first();
        }
    }
    let BundleStep::Vault {
        trader_genesis,
        trader_device_id,
        ..
    } = post.step()
    else {
        return Ok(());
    };
    if own != Some((*trader_genesis, *trader_device_id)) {
        return Ok(());
    }
    // A generation reaches here from its trader's walk and from the
    // position's commit: it is proven once.
    let key: ProofKey = (*post.vault_id(), post.generation(), *post.root());
    if !STARTED
        .lock()
        .map_err(|e| storage("the proofs started", e))?
        .insert(key)
    {
        return Ok(());
    }
    let (set, genesis, generation) = (set.clone(), genesis.clone(), post.generation());
    let spawned = std::thread::Builder::new()
        .name("vault-proof".into())
        .spawn(move || -> Result<(), DsmError> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| storage("the proving thread's runtime", e))?;
            runtime.block_on(prove_up_to(&set, &genesis, generation))
        });
    let proving = match spawned {
        Ok(proving) => proving,
        Err(e) => {
            // Not started: the next trade that reaches it starts it again.
            forget_started(&key)?;
            return Err(storage("the proving thread", e));
        }
    };
    PROVING
        .lock()
        .map_err(|e| storage("the proofs in progress", e))?
        .push((key, proving));
    Ok(())
}

/// A proof's vault, generation and root.
type ProofKey = (D32, u64, D32);

/// The proofs this process started and has not seen finish.
static PROVING: Mutex<Vec<(ProofKey, std::thread::JoinHandle<Result<(), DsmError>>)>> =
    Mutex::new(Vec::new());

/// The generations this process started proving, by vault, generation and
/// root: each is proven once, and one that failed is started again by the
/// next trade that reaches it.
static STARTED: Mutex<std::collections::BTreeSet<ProofKey>> =
    Mutex::new(std::collections::BTreeSet::new());

fn forget_started(key: &ProofKey) -> Result<(), DsmError> {
    STARTED
        .lock()
        .map_err(|e| storage("the proofs started", e))?
        .remove(key);
    Ok(())
}

/// Wait for every proof this process started to be published or refused:
/// what a device that is about to stop, or a reader that needs the records
/// its own trades leave, waits on.
///
/// A proof that failed is reported here and dropped: its generation is
/// proven again by the next trade of this device that reaches it.
pub(crate) async fn settled() -> Result<(), DsmError> {
    loop {
        let proving = std::mem::take(
            &mut *PROVING
                .lock()
                .map_err(|e| storage("the proofs in progress", e))?,
        );
        if proving.is_empty() {
            return Ok(());
        }
        for (key, handle) in proving {
            let generation = key.1;
            let joined = tokio::task::spawn_blocking(move || handle.join())
                .await
                .map_err(|e| storage("waiting for a proof", e))?;
            let finished = match joined {
                Ok(finished) => finished,
                Err(panic) => {
                    forget_started(&key)?;
                    let why = panic
                        .downcast_ref::<&str>()
                        .map(|why| why.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned());
                    return Err(storage(
                        "a proof",
                        format!("the thread proving generation {generation} panicked: {why:?}"),
                    ));
                }
            };
            if let Err(e) = finished {
                forget_started(&key)?;
                log::warn!("[vault proof] generation {generation} not proven: {e}");
            }
        }
    }
}

/// Prove and publish `genesis`'s vault up to `generation`: from the newest
/// record at or below it that verifies (or the genesis), each generation
/// after it this process established, in order.
async fn prove_up_to(
    set: &StorageSet,
    genesis: &AcceptedVaultGenesis,
    generation: u64,
) -> Result<(), DsmError> {
    let vault_id = *genesis.vault_id();
    let posts: Option<BTreeMap<u64, VaultPostState>> = ESTABLISHED
        .lock()
        .map_err(|e| storage("the established generations", e))?
        .get(&vault_id)
        .cloned();
    // Down from `generation` to the newest generation a record verifies at,
    // collecting what this process established above it.
    let mut pending: Vec<VaultPostState> = Vec::new();
    let mut at = generation;
    let mut base: Option<ProvenVaultHead> = None;
    while at > 0 {
        if let Some((head, _)) = proven_at(set, genesis, at).await? {
            base = Some(head);
            break;
        }
        let post = posts
            .as_ref()
            .and_then(|posts| posts.get(&at))
            .ok_or_else(|| {
                storage(
                    "prove",
                    format!("generation {at} is neither proven nor established here"),
                )
            })?;
        pending.push(post.clone());
        at -= 1;
    }
    let mut tree = match &base {
        Some(head) => head.tree().clone(),
        None => vault_proof::genesis_tree(genesis).map_err(|e| storage("the genesis tree", e))?,
    };
    let mut prev = base;
    for post in pending.into_iter().rev() {
        let (record, next) = tokio::task::spawn_blocking({
            let (prev, tree, post, genesis) =
                (prev.clone(), tree.clone(), post.clone(), genesis.clone());
            move || {
                let record = vault_proof::prove_step(prev.as_ref(), &tree, &post)
                    .map_err(|e| storage("prove", e))?;
                let bytes = record.encode();
                let head =
                    vault_proof::verify_record(&bytes, genesis.vault_id(), genesis.genesis_root())
                        .map_err(|e| storage("the record just proven", e))?;
                Ok::<_, DsmError>((bytes, head))
            }
        })
        .await
        .map_err(|e| storage("the proving thread", e))??;
        publish(set, &record).await?;
        tree = next.tree().clone();
        prev = Some(next);
    }
    Ok(())
}
