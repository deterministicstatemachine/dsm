// SPDX-License-Identifier: Apache-2.0

//! The owner baseline (SoFi Amendment S24), on both sides of a connection.
//!
//! **The owner.** A vault's owner signs a baseline at the generation it
//! established last — a `VaultFrontierV1`, the `OwnerBaselineAuthV1` binding
//! it to the owner's authority position, and an `AnchorPresentationV3` over
//! that — publishes it under `vault_baseline_locator(v, g)`, and hands a
//! trader its witness under the frontier's root: the vault's state leaf and
//! the trader's relationship proof, each with its path, from the owner's own
//! whole tree. The witness carries no authority.
//!
//! **The reader.** A wallet that holds nothing of a vault reads the
//! baselines published at the generation it was offered, and Core
//! authenticates each. One frontier: the wallet checks the witness against
//! its root and starts the vault's record there, and the chain walk goes on
//! from it. None: nothing is adopted, and the walk starts at the genesis.
//! Two: the owner signed two frontiers at one generation, and the vault is
//! quarantined (Req 6.3) — nothing is chosen, and nothing falls back.

use std::collections::BTreeMap;

use prost::Message;

use dsm::common::domain_tags::{
    TAG_DSM_SOFI_VAULT_BASELINE_LOCATOR, TAG_DSM_SOFI_VAULT_FRONTIER_OBJECT,
    TAG_DSM_SOFI_VAULT_HISTORY_HEAD, TAG_DSM_SOFI_VAULT_HISTORY_LEAF,
    TAG_DSM_SOFI_VAULT_HISTORY_LOCATOR, TAG_DSM_SOFI_VAULT_HISTORY_NODE,
    TAG_DSM_SOFI_VAULT_LEAF_STATE,
};
use dsm::crypto::domain::TaggedHashDomain;
use dsm::sofi::derive;
use dsm::shared_lineage::GenerationChain;
use dsm::sofi::history::{history_locator, HistoryBuilder};
use dsm::sofi::frontier::{
    authenticate_frontier_owner, baseline_commitment, frontier_commitment, vault_tree_at,
    witness_from_tree, VaultTree, VaultTreeError, VaultWitness, VerifiedFrontier,
};
use dsm::sofi::lineage::AcceptedVaultGenesis;
use dsm::sofi::resolve::{VaultGenesis, Verifier};
use dsm::sofi::storage::Discovered;
use dsm::sofi::wire::{OwnerBaselineAuthV1, VaultFrontierV1, VaultFrontierWitnessV1};
use dsm::types::error::DsmError;

use crate::generated;
use crate::sdk::identity_presentation::{
    build_own_anchor_presentation, derive_own_authority_context, OwnerIdentityInputs,
    ParsedPresentation,
};
use crate::sdk::sofi_reads::LiveSofiReads;
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::sofi_vault_head::{self, BaselineAdoption};

type D32 = [u8; 32];

/// Baselines read at one generation: one is the owner's, two are an
/// equivocation, and a flood is unavailable.
const BASELINES_PER_GENERATION: usize = 8;

fn failure(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(
        format!("vault baseline: {what}: {e}"),
        None::<std::io::Error>,
    )
}

/// A baseline's bytes, decoded: the parsed presentation and the exact
/// authentication and frontier bytes it carries.
struct Decoded {
    presentation: ParsedPresentation,
    auth: Vec<u8>,
    frontier: Vec<u8>,
}

fn decode(bundle: &[u8]) -> Result<Decoded, DsmError> {
    let baseline = generated::VaultBaselineV1::decode(bundle).map_err(|e| failure("decode", e))?;
    let presentation = baseline
        .presentation
        .as_ref()
        .ok_or_else(|| failure("decode", "no presentation"))?;
    Ok(Decoded {
        presentation: ParsedPresentation::parse(presentation)?,
        auth: baseline.auth_ccb,
        frontier: baseline.frontier_ccb,
    })
}

/// Core's authentication of a baseline's bytes for `genesis`'s vault.
pub(crate) fn authenticate(
    bundle: &[u8],
    genesis: &AcceptedVaultGenesis,
) -> Result<VerifiedFrontier, DsmError> {
    let decoded = decode(bundle)?;
    authenticate_frontier_owner(
        &decoded.presentation.anchor,
        &decoded.auth,
        &decoded.frontier,
        &decoded.presentation.presented(),
        genesis,
    )
    .map_err(|e| failure("authenticate", e))
}

/// The locator an owner baseline of `genesis`'s vault is published under,
/// recomputed from its authenticated frontier, with the frontier and the
/// bytes. Only a baseline Core authenticates as the owner's is recognized:
/// bytes that merely decode as a baseline are nothing under the locator, so
/// baseline-shaped junk ahead of the owner's never takes a place the owner's
/// needs (SA-132).
fn recognize_owners(
    bundle: &[u8],
    genesis: &AcceptedVaultGenesis,
) -> Option<(D32, (VerifiedFrontier, Vec<u8>))> {
    match authenticate(bundle, genesis) {
        Ok(verified) => {
            let frontier = verified.frontier();
            Some((
                derive::vault_baseline_locator(&frontier.vault_id, frontier.generation),
                (verified, bundle.to_vec()),
            ))
        }
        Err(why) => {
            log::debug!("[vault baseline] passed over a candidate: {why}");
            None
        }
    }
}

// ── The owner ──────────────────────────────────────────────────────────────

/// Sign this device's baseline of `frontier`, as the vault's owner `own_g`.
pub(crate) fn sign(
    network: &[u8],
    own_g: &D32,
    frontier: &VaultFrontierV1,
) -> Result<Vec<u8>, DsmError> {
    let seed = crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed()
        .ok_or_else(|| failure("sign", "no cached wallet seed"))?;
    let inputs = OwnerIdentityInputs::beta(network);
    let context = derive_own_authority_context(&seed, inputs)?;
    if context.g != *own_g {
        return Err(failure(
            "sign",
            "the re-derived identity is not this device's genesis",
        ));
    }
    let auth = OwnerBaselineAuthV1 {
        frontier_commitment: frontier_commitment(frontier),
        owner_authority_transition_digest: context.position,
    };
    let presentation =
        build_own_anchor_presentation(&seed, inputs, own_g, &baseline_commitment(&auth))?;
    Ok(generated::VaultBaselineV1 {
        presentation: Some(presentation),
        auth_ccb: auth.encode(),
        frontier_ccb: frontier.encode(),
    }
    .encode_to_vec())
}

/// The owner's whole tree of `vault_id` at `generation`, its state, and its
/// relationship leaves by key: this device's record, which Core binds leaf by
/// leaf and refuses unless it recomputes the root recorded there
/// (`sofi::frontier::vault_tree_at`). `None` when the record does not
/// recompute that root: this device did not see every leaf.
pub(crate) fn tree_at(
    vault_id: &D32,
    generation: u64,
    root: &D32,
) -> Result<Option<VaultTree>, DsmError> {
    let rows: Vec<(D32, D32, Vec<u8>)> = sofi_vault_head::leaf_rows(vault_id, generation)
        .map_err(|e| failure("leaves", e))?
        .into_iter()
        .map(|(key, value, _, preimage)| (key, value, preimage))
        .collect();
    match vault_tree_at(vault_id, root, &rows) {
        Ok(tree) => Ok(Some(tree)),
        Err(VaultTreeError::DoesNotRecomputeTheRoot { .. }) => Ok(None),
        Err(e) => Err(failure("tree", e)),
    }
}

/// What the owner hands a trader: each vault's witness, and why each vault
/// it owns that it did not witness was left out (the wallet then walks that
/// vault from its genesis).
pub(crate) struct Offered {
    pub(crate) witnesses: Vec<dsm::types::proto::ConnectVaultWitnessV1>,
    pub(crate) not_offered: Vec<String>,
}

/// What the owner hands `trader` for each vault it owns that trades either
/// of `tokens`: the generation of the baseline it published, signing and
/// publishing one at the generation it established last when it has not,
/// and `trader`'s witness under that baseline's root.
pub(crate) async fn offer(
    core: &crate::sdk::core_sdk::CoreSDK,
    set: &StorageSet,
    tokens: &[D32],
    trader: (D32, D32),
) -> Offered {
    let mut offered = Offered {
        witnesses: Vec::new(),
        not_offered: Vec::new(),
    };
    // Without its standing this device names none of its vaults: every one
    // is left to the wallet's walk.
    let (creations, own_g, own_d) =
        match (crate::sdk::sofi_flow::standing(core), core.device_head()) {
            (Ok(standing), Some(head)) => (
                standing.local.vault_creations(),
                head.genesis_digest(),
                head.devid(),
            ),
            (Err(why), _) => {
                offered
                    .not_offered
                    .push(format!("every vault: no standing: {why}"));
                return offered;
            }
            (.., None) => {
                offered
                    .not_offered
                    .push("every vault: no device head".into());
                return offered;
            }
        };
    let ctx = match crate::sdk::sofi_reads::VerifierContext::new(set, Some((own_g, own_d)), None) {
        Ok(ctx) => ctx,
        Err(why) => {
            offered
                .not_offered
                .push(format!("every vault: no verifier: {why}"));
            return offered;
        }
    };
    let verifier = ctx.verifier();
    for creation in creations {
        let vault = crate::util::text_id::encode_base32_crockford(&creation.vault_id[..5]);
        match offer_one(set, &verifier, &own_g, &creation.vault_id, tokens, trader).await {
            Ok(Some(witness)) => offered.witnesses.push(witness),
            Ok(None) => {}
            Err(why) => offered.not_offered.push(format!("{vault}: {why}")),
        }
    }
    offered
}

async fn offer_one(
    set: &StorageSet,
    verifier: &Verifier<'_, crate::sdk::sofi_reads::LiveSofiReads<'_>>,
    own_g: &D32,
    vault_id: &D32,
    tokens: &[D32],
    trader: (D32, D32),
) -> Result<Option<dsm::types::proto::ConnectVaultWitnessV1>, DsmError> {
    let Some(history) = owner_chain(verifier, vault_id)? else {
        return Ok(None);
    };
    let (generation, root) = (history.head().generation(), *history.head().state_root());
    // At the genesis a reader needs no baseline: the genesis is one read.
    if generation == 0 {
        return Ok(None);
    }
    let Some(whole) = tree_at(vault_id, generation, &root)? else {
        return Ok(None);
    };
    let market = crate::sdk::storage_io::read_stored_bytes_kept(set, &whole.state.market_policy)
        .await?
        .ok_or_else(|| failure("market", "the vault's market policy is not Stored"))?;
    let market =
        dsm::ccb::decode::decode_market_policy(&market).map_err(|e| failure("market", e))?;
    if !tokens
        .iter()
        .any(|t| t == market.token_a() || t == market.token_b())
    {
        return Ok(None);
    }
    ensure_baseline(set, own_g, vault_id, &history).await?;
    let rel_key = derive::relationship_key(&trader.0, &trader.1, vault_id);
    let witness = witness_from_tree(
        &whole.tree,
        vault_id,
        &whole.state,
        whole.relationships.get(&rel_key).copied(),
        &trader.0,
        &trader.1,
    );
    Ok(Some(dsm::types::proto::ConnectVaultWitnessV1 {
        vault_id: vault_id.to_vec(),
        generation,
        witness_ccb: witness.encode().map_err(|e| failure("witness", e))?,
    }))
}

/// Whether [`ensure_baseline`] published a baseline, or found one published.
pub(crate) enum BaselineAt {
    Published,
    AlreadyPublished,
}

/// `vault_id`'s generation chain as Core walks the vault now, from its
/// accepted genesis: what its owner signs a baseline over. `None` while the
/// genesis is not accepted, and for a chain from a baseline this device
/// adopted, which holds no history from the genesis to sign.
fn owner_chain(
    verifier: &Verifier<'_, crate::sdk::sofi_reads::LiveSofiReads<'_>>,
    vault_id: &D32,
) -> Result<Option<GenerationChain>, DsmError> {
    let VaultGenesis::Accepted(genesis) = verifier
        .vault_genesis(vault_id)
        .map_err(|e| failure("genesis", e))?
    else {
        return Ok(None);
    };
    let chain = verifier.chain(vault_id).map_err(|e| failure("chain", e))?;
    Ok(chain
        .generation_chain(vault_id, &genesis)
        .map_err(|e| failure("generation chain", format!("{e:?}")))?
        .map(|(history, _)| history))
}

/// Sign and publish the owner's baseline of `vault_id` at the head of
/// `history`, the vault's chain as Core walked it, unless one is published at
/// that generation already: its history first, which the baseline commits and
/// a reader proves a root below it from (SoFi Amendment S26), then the
/// frontier and the baseline.
async fn ensure_baseline(
    set: &StorageSet,
    own_g: &D32,
    vault_id: &D32,
    history: &GenerationChain,
) -> Result<BaselineAt, DsmError> {
    let (generation, root) = (history.head().generation(), *history.head().state_root());
    if sofi_vault_head::owner_baseline(vault_id, generation)
        .map_err(|e| failure("baseline", e))?
        .is_some()
    {
        return Ok(BaselineAt::AlreadyPublished);
    }
    let history_root = publish_history(set, vault_id, history).await?;
    let frontier = VaultFrontierV1 {
        vault_id: *vault_id,
        generation,
        root,
        history_root,
    };
    let network = crate::sdk::economic_admission_flow::committed_network_id()?;
    let bundle = sign(&network, own_g, &frontier)?;
    publish(set, &frontier, &bundle).await?;
    sofi_vault_head::put_owner_baseline(vault_id, generation, &bundle)
        .map_err(|e| failure("baseline", e))?;
    log::info!(
        "[vault baseline] {}: published the baseline at generation {generation}",
        crate::util::text_id::encode_base32_crockford(&vault_id[..5]),
    );
    Ok(BaselineAt::Published)
}

/// The owner's duty (SoFi Amendment S24): a continuously online owner
/// publishes a baseline after each realized generation. Each vault this
/// device created is walked by Core from its accepted genesis, and a
/// baseline is published at the head the walk established when none is
/// published at that generation yet. Never on an admission's path: a baseline not published
/// costs a fresh reader speed and nothing else. Returns how many baselines
/// were published, and why each vault that has none at its head was left.
pub(crate) async fn publish_owned_baselines(
    core: &crate::sdk::core_sdk::CoreSDK,
    set: &StorageSet,
) -> (u32, Vec<String>) {
    let mut left = Vec::new();
    // A device mid-admission publishes after it; one with no admitted
    // position has created no vault.
    let Some(head) = core
        .device_head()
        .filter(|head| head.pending_economic_admission().is_none())
    else {
        return (0, left);
    };
    let (genesis, device_id) = (head.genesis_digest(), head.devid());
    match crate::storage::client_db::economic_lineage::get_admitted() {
        Ok(Some(..)) => {}
        Ok(None) => return (0, left),
        Err(e) => return (0, vec![format!("every vault: the admitted position: {e}")]),
    }
    let creations = match crate::sdk::economic_admission_flow::validated_root_or_activate(core)
        .and_then(|validated| {
            crate::sdk::sofi_reads::local_leaves_of_validated(&genesis, &device_id, &validated)
        }) {
        Ok(local) => local.vault_creations(),
        Err(why) => return (0, vec![format!("every vault: this device's leaves: {why}")]),
    };
    if creations.is_empty() {
        return (0, left);
    }
    let ctx =
        match crate::sdk::sofi_reads::VerifierContext::new(set, Some((genesis, device_id)), None) {
            Ok(ctx) => ctx,
            Err(why) => return (0, vec![format!("every vault: no verifier: {why}")]),
        };
    let verifier = ctx.verifier();
    let mut published = 0u32;
    for creation in creations {
        let vault = crate::util::text_id::encode_base32_crockford(&creation.vault_id[..5]);
        let history = match owner_chain(&verifier, &creation.vault_id) {
            Ok(Some(history)) => history,
            Ok(None) => {
                left.push(format!("{vault}: no chain from its accepted genesis"));
                continue;
            }
            Err(why) => {
                left.push(format!("{vault}: its chain: {why}"));
                continue;
            }
        };
        let generation = history.head().generation();
        // At the genesis a reader needs no baseline: the genesis is one read.
        if generation == 0 {
            continue;
        }
        match ensure_baseline(set, &genesis, &creation.vault_id, &history).await {
            Ok(BaselineAt::Published) => published += 1,
            Ok(BaselineAt::AlreadyPublished) => {}
            Err(why) => left.push(format!("{vault}: generation {generation}: {why}")),
        }
    }
    (published, left)
}

/// How many objects of a history are put at once.
const HISTORY_PUTS_AT_ONCE: usize = 16;

/// Publish `vault_id`'s history up to the head of `history` (SoFi Amendment
/// S26), the vault's chain as Core walked it from its genesis: for every
/// generation not published yet, its leaf, indexed under its root, the
/// interior nodes it completed and the state leaf at its root; then the head.
/// Returns the history root a frontier at that generation commits. Every
/// object must reach a member, or nothing is recorded as published and no
/// baseline is signed.
pub(crate) async fn publish_history(
    set: &StorageSet,
    vault_id: &D32,
    history: &GenerationChain,
) -> Result<D32, DsmError> {
    let generation = history.head().generation();
    let roots: Vec<(u64, D32)> = (0..=generation)
        .map(|g| {
            history
                .at(g)
                .map(|(root, _)| (g, root))
                .ok_or_else(|| failure("history", format!("generation {g} is not walked")))
        })
        .collect::<Result<_, _>>()?;
    let published =
        sofi_vault_head::history_published(vault_id).map_err(|e| failure("history", e))?;
    let mut builder = HistoryBuilder::new(*vault_id);
    let mut objects: Vec<(TaggedHashDomain<'static>, Vec<u8>)> = Vec::new();
    let mut index: Vec<(D32, D32)> = Vec::new();
    for (row_generation, row_root) in &roots {
        let appended = builder.append(row_root);
        if published.is_some_and(|published| *row_generation <= published) {
            continue;
        }
        index.push((
            history_locator(vault_id, row_root),
            dsm::storage_object::immutable_addr(TAG_DSM_SOFI_VAULT_HISTORY_LEAF, &appended.leaf),
        ));
        objects.push((TAG_DSM_SOFI_VAULT_HISTORY_LEAF, appended.leaf));
        for (.., node) in appended.nodes {
            objects.push((TAG_DSM_SOFI_VAULT_HISTORY_NODE, node));
        }
        // The genesis state is the genesis preimage's own.
        if *row_generation > 0 {
            let state = sofi_vault_head::state_at(vault_id, row_root)
                .map_err(|e| failure("history", e))?
                .ok_or_else(|| {
                    failure(
                        "history",
                        format!("no state recorded at generation {row_generation}"),
                    )
                })?;
            objects.push((
                TAG_DSM_SOFI_VAULT_LEAF_STATE,
                state.encode().map_err(|e| failure("history", e))?,
            ));
        }
    }
    let head = builder
        .head()
        .filter(|head| head.generation == generation)
        .ok_or_else(|| {
            failure(
                "history",
                format!("this device's record does not reach generation {generation}"),
            )
        })?;
    objects.push((
        TAG_DSM_SOFI_VAULT_HISTORY_HEAD,
        head.encode().map_err(|e| failure("history", e))?,
    ));
    for some in objects.chunks(HISTORY_PUTS_AT_ONCE) {
        let puts = futures::future::join_all(some.iter().map(|(namespace, bytes)| {
            crate::sdk::storage_io::put_immutable(set, *namespace, bytes)
        }))
        .await;
        for put in puts {
            let (.., took) = put?;
            if took == 0 {
                return Err(failure("history", "no member took a history object"));
            }
        }
    }
    for some in index.chunks(HISTORY_PUTS_AT_ONCE) {
        let appends = futures::future::join_all(some.iter().map(|(locator, addr)| {
            crate::sdk::storage_io::append_to_index(
                set,
                TAG_DSM_SOFI_VAULT_HISTORY_LOCATOR.source_bytes(),
                locator,
                addr,
            )
        }))
        .await;
        for appended in appends {
            if appended? == 0 {
                return Err(failure(
                    "history",
                    "no member took a history locator append",
                ));
            }
        }
    }
    sofi_vault_head::put_history_published(vault_id, generation)
        .map_err(|e| failure("history", e))?;
    dsm::sofi::history::history_root(&head).map_err(|e| failure("history", e))
}

/// Store a baseline at every member and append it under its locator. Both
/// must reach a member, or the baseline is not offered.
pub(crate) async fn publish(
    set: &StorageSet,
    frontier: &VaultFrontierV1,
    bundle: &[u8],
) -> Result<(), DsmError> {
    let (addr, took) =
        crate::sdk::storage_io::put_immutable(set, TAG_DSM_SOFI_VAULT_FRONTIER_OBJECT, bundle)
            .await?;
    if took == 0 {
        return Err(failure("publish", "no member took the baseline"));
    }
    let appended = crate::sdk::storage_io::append_to_index(
        set,
        TAG_DSM_SOFI_VAULT_BASELINE_LOCATOR.source_bytes(),
        &derive::vault_baseline_locator(&frontier.vault_id, frontier.generation),
        &addr,
    )
    .await?;
    if appended == 0 {
        return Err(failure("publish", "no member took the locator append"));
    }
    Ok(())
}

// ── The reader ─────────────────────────────────────────────────────────────

/// An owner baseline Core authenticated whose root is not the one this
/// device's record holds at its generation: two authenticated roots at one
/// generation. Named, never decided: the record is kept as it is and the
/// baseline is not taken, and no verdict is recorded on the vault. A record
/// the next walk heals (MR-DSM-0331, the record follows Core) takes the
/// baseline after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContradictedBaseline {
    pub vault_id: D32,
    pub generation: u64,
    /// The root this device's record holds at `generation`.
    pub held_root: D32,
    /// The root the owner's authenticated baseline names there.
    pub baseline_root: D32,
}

impl core::fmt::Display for ContradictedBaseline {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let id = |d: &D32| crate::util::text_id::encode_base32_crockford(&d[..5]);
        write!(
            f,
            "vault {}: the record holds root {} at generation {}, and the owner's \
             authenticated baseline there names {}; the record is kept and the baseline is \
             not taken",
            id(&self.vault_id),
            id(&self.held_root),
            self.generation,
            id(&self.baseline_root)
        )
    }
}

/// What adopting one offered baseline came to.
enum Adoption {
    Adopted(u64),
    /// The baseline is not later than the one this device's record starts
    /// at, or nothing usable was offered or published: the walk goes on as
    /// it would have.
    NotAdopted(String),
    /// The record holds another root at the baseline's generation.
    Contradicted(ContradictedBaseline),
    /// The owner signed two frontiers at the generation (Req 6.3).
    Quarantined(String),
    /// The baseline authenticates and the witness contradicts its root.
    Refused(String),
}

/// Adopt each baseline `offered` that is later than the one this device's
/// record of its vault starts at, as `own` (MR-DSM-0331: the latest
/// authenticated owner baseline). A vault whose owner equivocated is
/// quarantined and a witness its authenticated baseline contradicts is
/// refused; either is an error, and neither falls back to a walk from the
/// genesis. A baseline the record contradicts at its generation is named in
/// what this returns. Every other outcome leaves the vault to its walk.
pub(crate) async fn adopt(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    offered: &[dsm::types::proto::ConnectVaultWitnessV1],
    own: (D32, D32),
) -> Result<Vec<ContradictedBaseline>, DsmError> {
    let adoptions =
        futures::future::join_all(offered.iter().map(|o| adopt_one(set, verifier, o, own))).await;
    let mut refused = Vec::new();
    let mut contradicted = Vec::new();
    for (offered, adoption) in offered.iter().zip(adoptions) {
        let vault = crate::util::text_id::encode_base32_crockford(
            &offered.vault_id[..offered.vault_id.len().min(5)],
        );
        match adoption {
            Adoption::Adopted(generation) => log::info!(
                "[vault baseline] {vault}: started at the owner's baseline, generation {generation}"
            ),
            Adoption::NotAdopted(why) => {
                log::info!(
                    "[vault baseline] {vault}: walked from its genesis or the baseline this \
                     device adopted before: {why}"
                )
            }
            Adoption::Contradicted(named) => {
                log::warn!("[vault baseline] {named}");
                contradicted.push(named);
            }
            Adoption::Quarantined(why) | Adoption::Refused(why) => {
                refused.push(format!("{vault}: {why}"))
            }
        }
    }
    if refused.is_empty() {
        Ok(contradicted)
    } else {
        Err(failure("adopt", refused.join("; ")))
    }
}

/// Unavailability, as an adoption outcome: the walk goes on as it would
/// have.
fn unavailable(what: &str, e: impl core::fmt::Display) -> Adoption {
    Adoption::NotAdopted(format!("{what}: {e}"))
}

async fn adopt_one(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    offered: &dsm::types::proto::ConnectVaultWitnessV1,
    own: (D32, D32),
) -> Adoption {
    let vault_id: D32 = match offered.vault_id.as_slice().try_into() {
        Ok(vault_id) => vault_id,
        Err(e) => return Adoption::Refused(format!("the offered vault id: {e}")),
    };
    match sofi_vault_head::quarantined(&vault_id) {
        Ok(Some(why)) => return Adoption::Quarantined(why),
        Ok(None) => {}
        Err(e) => return unavailable("quarantine", e),
    }
    // Only a later baseline is the latest; one at or below the baseline the
    // record starts at is not taken, and nothing is read for it.
    match sofi_vault_head::baseline(&vault_id) {
        Ok(Some((held, ..))) if held >= offered.generation => {
            return Adoption::NotAdopted(format!(
                "the baseline at generation {} is not later than the one this device's \
                 record starts at, {held}",
                offered.generation
            ))
        }
        Ok(..) => {}
        Err(e) => return unavailable("the held baseline", e),
    }
    let genesis = match tokio::task::block_in_place(|| verifier.vault_genesis(&vault_id)) {
        Ok(VaultGenesis::Accepted(genesis)) => *genesis,
        Ok(..) => return Adoption::NotAdopted("the genesis is not accepted".into()),
        Err(e) => return unavailable("genesis", e),
    };
    let locator = derive::vault_baseline_locator(&vault_id, offered.generation);
    let found = match crate::sdk::storage_io::resolve_locator_all(
        set,
        TAG_DSM_SOFI_VAULT_BASELINE_LOCATOR.source_bytes(),
        &locator,
        BASELINES_PER_GENERATION,
        |bundle| recognize_owners(bundle, &genesis),
    )
    .await
    {
        Ok(found) => found,
        Err(e) => return unavailable("the baseline locator", e),
    };
    // Only the owner's authenticated frontiers were recognized. Two are an
    // equivocation however much else is unread; one is the owner's only once
    // the read shows it is alone.
    let complete = matches!(found, Discovered::Complete(..));
    let authenticated = match found {
        Discovered::Complete(found) | Discovered::Partial(found) => found,
    };
    let mut frontiers: BTreeMap<D32, (VerifiedFrontier, Vec<u8>)> = BTreeMap::new();
    for (verified, bundle) in authenticated {
        frontiers
            .entry(*verified.commitment())
            .or_insert((verified, bundle));
    }
    if frontiers.len() > 1 {
        let why = format!(
            "STORAGE_SAFETY_VIOLATION: the owner signed {} frontiers at generation {}",
            frontiers.len(),
            offered.generation
        );
        return match sofi_vault_head::quarantine(&vault_id, &why) {
            Ok(()) => Adoption::Quarantined(why),
            Err(e) => Adoption::Quarantined(format!("{why} (not recorded: {e})")),
        };
    }
    if !complete {
        return Adoption::NotAdopted(format!(
            "the baselines at generation {} are not all read yet",
            offered.generation
        ));
    }
    let Some((verified, bundle)) = frontiers.into_values().next() else {
        return Adoption::NotAdopted(format!(
            "no baseline at generation {} authenticates",
            offered.generation
        ));
    };
    let wire = match VaultFrontierWitnessV1::decode(&offered.witness_ccb) {
        Ok(wire) => wire,
        Err(e) => return Adoption::Refused(format!("the witness does not decode: {e}")),
    };
    let witness = match VaultWitness::from_baseline(&verified, &wire, own.0, own.1) {
        Ok(witness) => witness,
        Err(e) => {
            return Adoption::Refused(format!(
                "the witness contradicts the authenticated baseline: {e}"
            ))
        }
    };
    match sofi_vault_head::adopt_baseline(&witness, &bundle) {
        Ok(BaselineAdoption::Adopted) => Adoption::Adopted(witness.generation()),
        Ok(BaselineAdoption::NotLater { held }) => Adoption::NotAdopted(format!(
            "the baseline at generation {} is not later than the one this device's record \
             starts at, {held}",
            witness.generation()
        )),
        Ok(BaselineAdoption::Contradicted { held_root }) => {
            Adoption::Contradicted(ContradictedBaseline {
                vault_id,
                generation: witness.generation(),
                held_root,
                baseline_root: *witness.root(),
            })
        }
        Err(e) => unavailable("recording the baseline", e),
    }
}
