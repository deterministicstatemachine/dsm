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
};
use dsm::sofi::derive;
use dsm::sofi::frontier::{
    authenticate_frontier_owner, baseline_commitment, frontier_commitment, witness_from_tree,
    VaultWitness, VerifiedFrontier,
};
use dsm::sofi::lineage::AcceptedVaultGenesis;
use dsm::sofi::resolve::{VaultGenesis, Verifier};
use dsm::sofi::storage::Discovered;
use dsm::sofi::wire::{
    OwnerBaselineAuthV1, VaultFrontierV1, VaultFrontierWitnessV1, VaultRelationshipLeaf,
    VaultStateLeaf,
};
use dsm::types::error::DsmError;

use crate::generated;
use crate::sdk::identity_presentation::{
    build_own_anchor_presentation, derive_own_authority_context, OwnerIdentityInputs,
    ParsedPresentation,
};
use crate::sdk::sofi_reads::LiveSofiReads;
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::sofi_vault_head;

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

/// The locator a baseline's bytes are published under, recomputed from its
/// frontier, and the bytes themselves.
fn recognize(bundle: &[u8]) -> Option<(D32, Vec<u8>)> {
    // Bytes that are no baseline are nothing under the locator.
    let frontier = match generated::VaultBaselineV1::decode(bundle) {
        Ok(baseline) => match VaultFrontierV1::decode(&baseline.frontier_ccb) {
            Ok(frontier) => frontier,
            Err(..) => return None,
        },
        Err(..) => return None,
    };
    Some((
        derive::vault_baseline_locator(&frontier.vault_id, frontier.generation),
        bundle.to_vec(),
    ))
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
/// relationship leaves by key — rebuilt from this device's record and
/// checked against the root it recorded there.
pub(crate) fn tree_at(
    vault_id: &D32,
    generation: u64,
    root: &D32,
) -> Result<
    Option<(
        dsm::economic::tree::EconomicSmt,
        VaultStateLeaf,
        BTreeMap<D32, VaultRelationshipLeaf>,
    )>,
    DsmError,
> {
    let rows =
        sofi_vault_head::leaf_rows(vault_id, generation).map_err(|e| failure("leaves", e))?;
    let mut tree = dsm::economic::tree::EconomicSmt::new();
    let mut state = None;
    let mut relationships = BTreeMap::new();
    let state_key = derive::vault_state_key(vault_id);
    for (key, value, _, preimage) in &rows {
        tree.insert(*key, *value);
        if *key == state_key {
            state = Some(VaultStateLeaf::decode(preimage).map_err(|e| failure("state", e))?);
        } else {
            relationships.insert(
                *key,
                VaultRelationshipLeaf::decode(preimage).map_err(|e| failure("relationship", e))?,
            );
        }
    }
    if tree.root() != *root {
        return Ok(None);
    }
    Ok(state.map(|state| (tree, state, relationships)))
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
    let (creations, own_g) = match (crate::sdk::sofi_flow::standing(core), core.device_head()) {
        (Ok(standing), Some(head)) => (standing.local.vault_creations(), head.genesis_digest()),
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
    for creation in creations {
        let vault = crate::util::text_id::encode_base32_crockford(&creation.vault_id[..5]);
        match offer_one(set, &own_g, &creation.vault_id, tokens, trader).await {
            Ok(Some(witness)) => offered.witnesses.push(witness),
            Ok(None) => {}
            Err(why) => offered.not_offered.push(format!("{vault}: {why}")),
        }
    }
    offered
}

async fn offer_one(
    set: &StorageSet,
    own_g: &D32,
    vault_id: &D32,
    tokens: &[D32],
    trader: (D32, D32),
) -> Result<Option<dsm::types::proto::ConnectVaultWitnessV1>, DsmError> {
    let Some(head) = sofi_vault_head::head(vault_id).map_err(|e| failure("head", e))? else {
        return Ok(None);
    };
    // At the genesis a reader needs no baseline: the genesis is one read.
    if head.generation == 0 {
        return Ok(None);
    }
    let Some((tree, state, relationships)) = tree_at(vault_id, head.generation, &head.root)? else {
        return Ok(None);
    };
    let market = crate::sdk::storage_io::read_stored_bytes_kept(set, &state.market_policy)
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
    if sofi_vault_head::owner_baseline(vault_id, head.generation)
        .map_err(|e| failure("baseline", e))?
        .is_none()
    {
        let frontier = VaultFrontierV1 {
            vault_id: *vault_id,
            generation: head.generation,
            root: head.root,
        };
        let network = crate::sdk::economic_admission_flow::committed_network_id()?;
        let bundle = sign(&network, own_g, &frontier)?;
        publish(set, &frontier, &bundle).await?;
        sofi_vault_head::put_owner_baseline(vault_id, head.generation, &bundle)
            .map_err(|e| failure("baseline", e))?;
        log::info!(
            "[vault baseline] {}: published the baseline at generation {}",
            crate::util::text_id::encode_base32_crockford(&vault_id[..5]),
            head.generation
        );
    }
    let rel_key = derive::relationship_key(&trader.0, &trader.1, vault_id);
    let witness = witness_from_tree(
        &tree,
        vault_id,
        &state,
        relationships.get(&rel_key).copied(),
        &trader.0,
        &trader.1,
    );
    Ok(Some(dsm::types::proto::ConnectVaultWitnessV1 {
        vault_id: vault_id.to_vec(),
        generation: head.generation,
        witness_ccb: witness.encode().map_err(|e| failure("witness", e))?,
    }))
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

/// What adopting one offered baseline came to.
enum Adoption {
    Adopted(u64),
    /// This device already holds a record of the vault, or nothing usable
    /// was offered or published: the walk goes on as it would have.
    NotAdopted(String),
    /// The owner signed two frontiers at the generation (Req 6.3).
    Quarantined(String),
    /// The baseline authenticates and the witness contradicts its root.
    Refused(String),
}

/// Adopt the baselines `offered` for the vaults this device holds nothing
/// of, as `own`. A vault whose owner equivocated is quarantined and a
/// witness its authenticated baseline contradicts is refused; either is an
/// error, and neither falls back to a walk from the genesis. Every other
/// outcome leaves the vault to its walk.
pub(crate) async fn adopt(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    offered: &[dsm::types::proto::ConnectVaultWitnessV1],
    own: (D32, D32),
) -> Result<(), DsmError> {
    let adoptions =
        futures::future::join_all(offered.iter().map(|o| adopt_one(set, verifier, o, own))).await;
    let mut refused = Vec::new();
    for (offered, adoption) in offered.iter().zip(adoptions) {
        let vault = crate::util::text_id::encode_base32_crockford(
            &offered.vault_id[..offered.vault_id.len().min(5)],
        );
        match adoption {
            Adoption::Adopted(generation) => log::info!(
                "[vault baseline] {vault}: started at the owner's baseline, generation {generation}"
            ),
            Adoption::NotAdopted(why) => {
                log::info!("[vault baseline] {vault}: walked from what this device holds: {why}")
            }
            Adoption::Quarantined(why) | Adoption::Refused(why) => {
                refused.push(format!("{vault}: {why}"))
            }
        }
    }
    if refused.is_empty() {
        Ok(())
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
    match sofi_vault_head::head(&vault_id) {
        Ok(Some(..)) => {
            return Adoption::NotAdopted("this device holds a record of the vault".into())
        }
        Ok(None) => {}
        Err(e) => return unavailable("head", e),
    }
    let genesis = match tokio::task::block_in_place(|| verifier.vault_genesis(&vault_id)) {
        Ok(VaultGenesis::Accepted(genesis)) => *genesis,
        Ok(..) => return Adoption::NotAdopted("the genesis is not accepted".into()),
        Err(e) => return unavailable("genesis", e),
    };
    let locator = derive::vault_baseline_locator(&vault_id, offered.generation);
    let bundles = match crate::sdk::storage_io::resolve_locator_all(
        set,
        TAG_DSM_SOFI_VAULT_BASELINE_LOCATOR.source_bytes(),
        &locator,
        BASELINES_PER_GENERATION,
        recognize,
    )
    .await
    {
        Ok(Discovered::Complete(bundles) | Discovered::Partial(bundles)) => bundles,
        Err(e) => return unavailable("the baseline locator", e),
    };
    // Every candidate is authenticated; one that does not is passed over,
    // and only an authenticated frontier counts.
    let mut frontiers: BTreeMap<D32, (VerifiedFrontier, Vec<u8>)> = BTreeMap::new();
    let mut passed_over = Vec::new();
    for bundle in bundles {
        match authenticate(&bundle, &genesis) {
            Ok(verified) => {
                frontiers
                    .entry(*verified.commitment())
                    .or_insert((verified, bundle));
            }
            Err(why) => passed_over.push(why.to_string()),
        }
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
    let Some((verified, bundle)) = frontiers.into_values().next() else {
        return Adoption::NotAdopted(format!(
            "no baseline at generation {} authenticates ({} passed over: {})",
            offered.generation,
            passed_over.len(),
            passed_over.join("; ")
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
        Ok(()) => Adoption::Adopted(witness.generation()),
        Err(e) => unavailable("recording the baseline", e),
    }
}
