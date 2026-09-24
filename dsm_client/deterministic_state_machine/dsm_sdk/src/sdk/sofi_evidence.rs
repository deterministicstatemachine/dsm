// SPDX-License-Identifier: Apache-2.0

//! Evidence acquisition (rebuild step R5): the only way production code
//! builds an [`Evidence`], from fetched bytes and the verifier's own validated
//! tree, never from a default.
//!
//! What a preimage needs is Core's question ([`EvidenceNeeds::of`]). What
//! each item is, once fetched, is Core's question again — `validate`
//! re-authenticates every object against its address and every leaf against
//! the core that names it. This module fetches:
//!
//! | item | from |
//! |---|---|
//! | trader leaf pre values | this device's own leaves, checked against its validated root — for its own routes only |
//! | vault leaf pre values | the vault's accepted genesis (SoFi §19.8) at `R_0`; past it, the vault head this device resolved |
//! | policy objects | the immutable store, under the address the vault state commits, `Stored` on three members |
//! | token policies | the policy each market token commits, rooted by this device |
//! | setups | the envelope `Stored` at each leg's `ρ` |
//! | accepted claims | the claims this device's lineage accepted, at each setup's position — for its own routes only |
//!
//! Amendment S3: Core's predicates are binary and see only complete evidence.
//! Whether the evidence is complete is Core's answer too: an acquisition
//! round ends by asking `route_validation`, and a `Missing` answer is
//! retried up to the budget, then reported as [`Acquired::Exhausted`] — a
//! network failure, never a predicate value.
//!
//! Another trader's route is a hole: SoFi §17.5 says an exercise proves
//! itself from its own bytes and state the reader already holds, but
//! `TraderSideValid` reads the trader's leaf pre values, the trader core
//! carries only their hashes, and no section names where a verifier that is
//! not the trader gets them. Acquisition answers [`Acquired::NoSource`] for
//! them rather than supplying anything in their place.

use std::collections::BTreeMap;

use dsm::common::domain_tags::TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR;
use dsm::economic::lineage::{AcceptedClaim, ValidatedEconomicRoot};
use dsm::economic::provenance::{PeerLineageFailure, ValidatedPeerTransition};
use dsm::economic::state::EconomicLeafState;
use dsm::economic::tree::EconomicSmt;
use dsm::sofi::derive;
use dsm::sofi::lineage::{
    genesis_accepted, genesis_root, vault_leaves_at_genesis, AcceptedVaultGenesis, GenesisInvalid,
    GenesisMissing, GenesisRefusal,
};
use dsm::sofi::publication::recognize_setup;
use dsm::sofi::storage::Resolved;
use dsm::sofi::conformance::Validation;
use dsm::sofi::validation::{
    route_validation, Evidence, EvidenceNeeds, Missing, TraderLeafPre, VaultLeafPre,
};
use dsm::sofi::wire::{SettlementPreimage, TraderCore, TraderPrecommitBody, VaultGenesisPreimage};
use dsm::types::error::DsmError;

use crate::sdk::economic_registers::{
    anchored_policy_bytes, resolve_peer_with_cache, LiveRegisterResolver,
};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::sofi_vault_head;

type D32 = [u8; 32];

/// Candidates one locator scan may examine before it is `Unavailable`.
pub const LOCATOR_BUDGET: usize = 64;

/// Acquisition rounds before the evidence is `Exhausted`.
pub const ACQUIRE_ROUNDS: usize = 3;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// This device's own `R_econ` leaves, checked against the root they claim to
/// form. Built from the leaf cache for the device's validated root, or by a
/// test from leaves it holds — never from a root somebody sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLeaves {
    genesis: D32,
    device_id: D32,
    root: D32,
    leaves: BTreeMap<D32, EconomicLeafState>,
}

impl LocalLeaves {
    /// The leaves of this device's validated root, from the leaf cache; the
    /// cache is a cache, so its root is recomputed and must equal the
    /// validated one.
    pub fn of_validated(
        genesis: &D32,
        device_id: &D32,
        validated: &ValidatedEconomicRoot,
    ) -> Result<Self, DsmError> {
        let leaves = if validated.economic_position() == 0 {
            Vec::new()
        } else {
            crate::storage::client_db::economic_lineage::load_leaf_cache()
                .map_err(|e| storage_err("load leaf cache", e))?
        };
        let decoded: Vec<(D32, EconomicLeafState)> = leaves
            .iter()
            .map(|(key, .., ccb)| {
                dsm::economic::decode::decode_leaf_state(ccb)
                    .map(|state| (*key, state))
                    .map_err(|e| storage_err("decode cached leaf state", e))
            })
            .collect::<Result<_, _>>()?;
        Self::checked(*genesis, *device_id, validated.economic_root(), decoded)
    }

    /// Leaves of `(genesis, device_id)` that must recompute `root`; anything
    /// else is refused.
    pub fn checked(
        genesis: D32,
        device_id: D32,
        root: D32,
        leaves: impl IntoIterator<Item = (D32, EconomicLeafState)>,
    ) -> Result<Self, DsmError> {
        let mut tree = EconomicSmt::new();
        let mut map = BTreeMap::new();
        for (key, state) in leaves {
            let value = state
                .leaf_value()
                .map_err(|e| storage_err("encode leaf state", e))?;
            tree.insert(key, value);
            map.insert(key, state);
        }
        if tree.root() != root {
            return Err(DsmError::storage(
                "local leaves do not recompute the validated root — discarded".to_string(),
                None::<std::io::Error>,
            ));
        }
        Ok(Self {
            genesis,
            device_id,
            root,
            leaves: map,
        })
    }

    pub fn root(&self) -> D32 {
        self.root
    }

    /// Evidence holding the pre value of every key `core` names, from these
    /// leaves alone: what `Fold(T°, E)` reads, before anything is published.
    /// A key holding a write-once record has no trader-leaf pre value and is
    /// refused.
    pub fn trader_evidence(&self, core: &TraderCore) -> Result<Evidence, DsmError> {
        let mut trader_leaves = BTreeMap::new();
        for entry in core.entries() {
            let key = entry.key();
            let pre = self.pre(&key).ok_or_else(|| {
                DsmError::invalid_operation("a trader core names a key holding a write-once record")
            })?;
            trader_leaves.insert(key, pre);
        }
        Ok(Evidence::acquired(
            BTreeMap::new(),
            trader_leaves,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        ))
    }

    /// Every relationship leaf this device holds: the vaults it is set up
    /// with.
    pub fn relationships(&self) -> Vec<dsm::sofi::wire::TraderRelationshipLeaf> {
        let mut out = Vec::new();
        for state in self.leaves.values() {
            if let EconomicLeafState::Relationship(leaf) = state {
                out.push(*leaf);
            }
        }
        out
    }

    /// The relationship leaf this device holds with `vault_id`, if any.
    pub fn relationship(&self, vault_id: &D32) -> Option<dsm::sofi::wire::TraderRelationshipLeaf> {
        let key = derive::relationship_key(&self.genesis, &self.device_id, vault_id);
        match self.leaves.get(&key) {
            Some(EconomicLeafState::Relationship(leaf)) => Some(*leaf),
            Some(..) | None => None,
        }
    }

    /// Whether `precommit` is this device's own: the only routes whose trader
    /// leaves and accepted claims this device holds.
    fn owns(&self, precommit: &TraderPrecommitBody) -> bool {
        *precommit.genesis() == self.genesis && *precommit.device_id() == self.device_id
    }

    /// The pre value at `key` as Core reads a trader leaf. The tree is whole,
    /// so a key it does not hold is absent. A key holding a write-once record
    /// has no trader-leaf pre value: Core reads trader leaves only at balance
    /// and relationship keys, which are domain-separated from every record
    /// key.
    pub fn pre(&self, key: &D32) -> Option<TraderLeafPre> {
        match self.leaves.get(key) {
            None => Some(TraderLeafPre::Absent),
            Some(EconomicLeafState::Balance(b)) => Some(TraderLeafPre::Balance(b.clone())),
            Some(EconomicLeafState::Relationship(r)) => Some(TraderLeafPre::Relationship(*r)),
            Some(
                EconomicLeafState::ConsumedSource(..)
                | EconomicLeafState::VaultCreation(..)
                | EconomicLeafState::TokenCreation(..),
            ) => None,
        }
    }
}

/// What this verifier established about vault `v`'s genesis (SoFi §19.8;
/// §30 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultGenesis {
    /// The owner's validated creation carried this genesis, and it is
    /// accepted.
    Accepted(Box<AcceptedVaultGenesis>),
    /// No preimage the owner's creation carried is published under the
    /// vault's locator.
    NotPublished,
    /// The owner's lineage reaches `p_create` through a position whose route
    /// has not resolved: nothing a fetch can supply decides it yet.
    OwnerUnresolved(String),
    /// The genesis is refused: the owner's lineage is invalid or quarantined,
    /// or the genesis the owner created fails acceptance.
    Refused(String),
}

/// Vault `v`'s genesis as this verifier accepts it: every preimage published
/// under `vault_genesis_locator(v)` that recognizes to `v`, bound to the
/// owner's creation as a walk of the owner's lineage validates it.
///
/// Every candidate is tried, so a preimage appended first by anyone else
/// cannot stand in front of the owner's: only the bytes the owner's creation
/// carried are accepted. Every candidate names the same owner and `p_create`,
/// because `v` derives from them.
pub async fn fetch_vault_genesis(
    set: &StorageSet,
    vault_id: &D32,
) -> Result<VaultGenesis, DsmError> {
    let locator = derive::vault_genesis_locator(vault_id);
    let resolved = crate::sdk::storage_io::resolve_locator_all(
        set,
        TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
        &locator,
        LOCATOR_BUDGET,
        |bytes| {
            let preimage = VaultGenesisPreimage::decode(bytes).ok()?;
            Some((
                derive::vault_genesis_locator(&preimage.vault_id()),
                (preimage, bytes.to_vec()),
            ))
        },
    )
    .await?;
    let candidates = match resolved {
        Resolved::Kept(candidates) => candidates,
        Resolved::None => return Ok(VaultGenesis::NotPublished),
        Resolved::Unavailable => {
            return Err(storage_err(
                "vault genesis",
                "the locator scan did not complete",
            ))
        }
    };
    let Some((first, ..)) = candidates.first() else {
        return Ok(VaultGenesis::NotPublished);
    };
    let network = crate::sdk::economic_admission_flow::committed_network_id()?;
    let resolver = LiveRegisterResolver {
        set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: network.clone(),
    };
    let owner = match resolve_peer_with_cache(
        &resolver,
        &network,
        &first.owner_genesis,
        &first.owner_device_id,
        first.create_position,
    ) {
        Ok(owner) => owner,
        Err(PeerLineageFailure::Incomplete(why)) => {
            return Err(storage_err("vault owner lineage", why))
        }
        Err(PeerLineageFailure::Unresolved(why)) => return Ok(VaultGenesis::OwnerUnresolved(why)),
        Err(PeerLineageFailure::Invalid(why) | PeerLineageFailure::Quarantined(why)) => {
            return Ok(VaultGenesis::Refused(format!("the owner's lineage: {why}")))
        }
    };
    let mut refused = None;
    for (.., bytes) in &candidates {
        match accept_with_policies(set, &resolver, &network, bytes, &owner)? {
            Ok(accepted) => return Ok(VaultGenesis::Accepted(Box::new(accepted))),
            Err(GenesisInvalid::NotTheCreationTheOwnerMade) => {}
            Err(why) => refused = Some(why),
        }
    }
    Ok(match refused {
        Some(why) => VaultGenesis::Refused(format!("{why:?}")),
        None => VaultGenesis::NotPublished,
    })
}

/// `GenesisAccepted` over one candidate, fetching the token policies Core
/// names as missing. Core consults at most the two tokens of the market, and
/// a policy it names again after it was supplied is not the committed one.
fn accept_with_policies(
    set: &StorageSet,
    resolver: &LiveRegisterResolver<'_>,
    network: &[u8],
    bytes: &[u8],
    owner: &ValidatedPeerTransition,
) -> Result<Result<AcceptedVaultGenesis, GenesisInvalid>, DsmError> {
    let mut policies = BTreeMap::new();
    loop {
        match genesis_accepted(network, bytes, owner, &policies) {
            Ok(accepted) => return Ok(Ok(accepted)),
            Err(GenesisRefusal::Invalid(why)) => return Ok(Err(why)),
            Err(GenesisRefusal::Missing(GenesisMissing::TokenPolicy { commit })) => {
                if policies.contains_key(&commit) {
                    return Err(storage_err(
                        "vault token policy",
                        "the rooted bytes are not the committed policy",
                    ));
                }
                let policy = anchored_policy_bytes(set, &commit, &resolver.runtime)
                    .map_err(|failure| storage_err("vault token policy", failure))?;
                policies.insert(commit, policy);
            }
        }
    }
}

/// What an acquisition produced: the complete evidence a Core predicate
/// consumes, or what is still not in hand. Predicates are Valid or Invalid
/// only; these are the separate acquisition statuses (Amendment S3, owner
/// 2026-09-23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acquired<T, M> {
    /// Everything the predicate consumes is in hand and authenticates.
    Complete(T),
    /// The retry budget is spent and these items are still not in hand: the
    /// operation fails on the network. The caller evaluates nothing and
    /// records nothing.
    Exhausted(Vec<M>),
    /// These items have no source this verifier can acquire them from, so no
    /// retry can supply them. The caller evaluates nothing and records
    /// nothing.
    NoSource(Vec<M>),
}

/// Acquire everything `P` and `P(E)` need, from storage and this device's
/// own state, and ask Core whether it is complete. `Complete` once
/// `route_validation` reaches a verdict over it; `Exhausted` naming what Core
/// still misses after [`ACQUIRE_ROUNDS`] rounds; `NoSource` for another
/// trader's route (module docs).
pub async fn acquire_evidence(
    set: &StorageSet,
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    local: &LocalLeaves,
) -> Result<Acquired<Evidence, Missing>, DsmError> {
    let needs = EvidenceNeeds::of(precommit, preimage);
    if !local.owns(precommit) {
        return Ok(Acquired::NoSource(
            needs
                .trader_keys
                .iter()
                .map(|key| Missing::TraderLeaf { key: *key })
                .collect(),
        ));
    }
    let mut missing = Vec::new();
    for round in 1..=ACQUIRE_ROUNDS {
        let evidence = gather(set, precommit, preimage, local, &needs).await?;
        match route_validation(precommit, preimage, &evidence) {
            Ok(Validation::Valid | Validation::Invalid) => return Ok(Acquired::Complete(evidence)),
            Err(what) => {
                log::info!("[sofi evidence] round {round}/{ACQUIRE_ROUNDS}: not in hand: {what:?}");
                missing = vec![what];
            }
        }
    }
    Ok(Acquired::Exhausted(missing))
}

/// One round of fetching every item `needs` names, for this device's own
/// route.
async fn gather(
    set: &StorageSet,
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    local: &LocalLeaves,
    needs: &EvidenceNeeds,
) -> Result<Evidence, DsmError> {
    let trader_leaves: BTreeMap<D32, TraderLeafPre> = needs
        .trader_keys
        .iter()
        .filter_map(|key| local.pre(key).map(|pre| (*key, pre)))
        .collect();

    let runtime = tokio::runtime::Handle::current();
    let mut vault_leaves: BTreeMap<(D32, D32), VaultLeafPre> = BTreeMap::new();
    let mut objects: BTreeMap<D32, Vec<u8>> = BTreeMap::new();
    let mut token_policies: BTreeMap<D32, Vec<u8>> = BTreeMap::new();
    for (vault_id, keys) in &needs.vaults {
        let Some(state) = vault_pre(set, preimage, vault_id, keys, &mut vault_leaves).await? else {
            continue;
        };
        for (class, addr) in EvidenceNeeds::policies_of(&state) {
            let Some(bytes) = crate::sdk::storage_io::read_stored_bytes(set, &addr).await? else {
                continue;
            };
            // The tokens a market names are what the transferable check reads.
            // Bytes that are not a market name none, and Core refuses them.
            if class == dsm::ccb::class::MARKET_POLICY {
                if let Ok(market) = dsm::ccb::decode::decode_market_policy(&bytes) {
                    for commit in EvidenceNeeds::token_policies_of(&market) {
                        if dsm::core::token::builtin_token_id_for_policy_commit(&commit).is_some() {
                            continue;
                        }
                        match anchored_policy_bytes(set, &commit, &runtime) {
                            Ok(policy) => {
                                token_policies.insert(commit, policy);
                            }
                            Err(failure) => {
                                log::info!("[sofi evidence] token policy not in hand: {failure}")
                            }
                        }
                    }
                }
            }
            objects.insert(addr, bytes);
        }
    }

    let mut setups: BTreeMap<D32, Vec<u8>> = BTreeMap::new();
    let mut accepted_claims: BTreeMap<u64, AcceptedClaim> = BTreeMap::new();
    for setup_ref in &needs.setups {
        let Resolved::Kept(bytes) =
            crate::sdk::sofi_publish::fetch_setup_bytes(set, setup_ref).await?
        else {
            continue;
        };
        if let Some((.., signed)) = recognize_setup(&bytes) {
            let position = signed.body.position();
            if let Some(claim) = accepted_claim_at(precommit, position)? {
                accepted_claims.insert(position, claim);
            }
        }
        setups.insert(*setup_ref, bytes);
    }

    Ok(Evidence::acquired(
        objects,
        trader_leaves,
        vault_leaves,
        setups,
        token_policies,
        accepted_claims,
    ))
}

/// The claim this device's lineage accepted at `position`, from its
/// admitted history. `None` when it admitted no position there, or the
/// position is conditional and unresolved — registered, never accepted.
fn accepted_claim_at(
    precommit: &TraderPrecommitBody,
    position: u64,
) -> Result<Option<AcceptedClaim>, DsmError> {
    let Some(admitted) = crate::storage::client_db::economic_lineage::get_admitted_at(position)
        .map_err(|e| storage_err("admitted history", e))?
    else {
        return Ok(None);
    };
    match AcceptedClaim::rehydrate_from_admitted_store(
        *precommit.genesis(),
        *precommit.device_id(),
        admitted,
    ) {
        Ok(claim) => Ok(Some(claim)),
        Err(unresolved) => {
            log::info!("[sofi evidence] no accepted claim at {position}: {unresolved:?}");
            Ok(None)
        }
    }
}

/// The pre values of vault `v`'s leaves at the root the operation's core
/// names, into `vault_leaves`, and the vault state they hold. At `R_0` they
/// are the accepted genesis; past it, the vault head this device resolved,
/// which must be the head the core was built on and reproduce its own root.
/// `None` when they are not in hand.
async fn vault_pre(
    set: &StorageSet,
    preimage: &SettlementPreimage,
    vault_id: &D32,
    keys: &std::collections::BTreeSet<D32>,
    vault_leaves: &mut BTreeMap<(D32, D32), VaultLeafPre>,
) -> Result<Option<dsm::sofi::wire::VaultStateLeaf>, DsmError> {
    let Some(pre_root) = preimage
        .dlv_cores()
        .iter()
        .find(|core| core.vault_id() == vault_id)
        .map(|core| *core.pre_root())
    else {
        return Ok(None);
    };
    let genesis = match fetch_vault_genesis(set, vault_id).await? {
        VaultGenesis::Accepted(genesis) => genesis,
        VaultGenesis::NotPublished | VaultGenesis::OwnerUnresolved(..) => return Ok(None),
        VaultGenesis::Refused(why) => {
            return Err(DsmError::invalid_operation(format!(
                "vault {} genesis refused: {why}",
                crate::util::text_id::encode_base32_crockford(vault_id)
            )))
        }
    };
    if genesis_root(vault_id, genesis.state()).ok() == Some(pre_root) {
        vault_leaves.extend(vault_leaves_at_genesis(vault_id, genesis.state(), keys));
        return Ok(Some(genesis.state().clone()));
    }
    let Some((.., leaves)) = sofi_vault_head::leaves_at_head(vault_id, keys)
        .map_err(|e| storage_err("vault head", e))?
        .filter(|(head, ..)| head.root == pre_root)
    else {
        return Ok(None);
    };
    let state_key = derive::vault_state_key(vault_id);
    let Some(VaultLeafPre::State(state)) = leaves.get(&(*vault_id, state_key)).cloned() else {
        return Ok(None);
    };
    vault_leaves.extend(leaves);
    Ok(Some(state))
}
