// SPDX-License-Identifier: Apache-2.0

//! Real evidence acquisition (rebuild step R5): the only way production code
//! builds a [`Evidence`], from fetched bytes and the verifier's own validated
//! tree, never from a default.
//!
//! What a preimage needs is Core's question ([`EvidenceNeeds::of`]). What
//! each item is, once fetched, is Core's question again — `validate`
//! re-authenticates every object against its address and every leaf against
//! the core that names it. This module only fetches:
//!
//! | item | from |
//! |---|---|
//! | trader leaf pre values | the verifier's own leaves, rebuilt and checked against the validated root |
//! | vault leaf pre values | the vault's genesis preimage, found by its locator and recognized by Core; at `R_0` the tree holds exactly the state leaf |
//! | policy objects | the immutable store, under the address the vault state commits, `Stored` on three members |
//!
//! Anything that is not fetched is simply absent from the evidence, and Core
//! answers `Unavailable` for it — never `Invalid`, never a filled-in value.
//! A vault past its genesis is such a case until the successor walk of rebuild
//! step R12 extends the fetch.

use std::collections::BTreeMap;

use dsm::common::domain_tags::{TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT};
use dsm::economic::lineage::ValidatedEconomicRoot;
use dsm::economic::state::EconomicLeafState;
use dsm::economic::tree::EconomicSmt;
use dsm::sofi::derive;
use dsm::sofi::lineage::{genesis_root, vault_leaves_at_genesis};
use dsm::sofi::storage::Resolved;
use dsm::sofi::validation::{Evidence, EvidenceNeeds, TraderLeafPre, VaultLeafPre};
use dsm::sofi::wire::{SettlementPreimage, VaultGenesisPreimage};
use dsm::types::error::DsmError;

use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

/// Candidates one locator scan may examine before it is `Unavailable`.
pub const LOCATOR_BUDGET: usize = 64;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// The verifier's own `R_econ` leaves, checked against the root they claim
/// to form. Built from the leaf cache for the device's validated root, or
/// by a test from leaves it holds — never from a root somebody sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLeaves {
    root: D32,
    leaves: BTreeMap<D32, EconomicLeafState>,
}

impl LocalLeaves {
    /// The leaves of THIS device's validated root, from the leaf cache; the
    /// cache is a cache, so its root is recomputed and must equal the
    /// validated one.
    pub fn of_validated(validated: &ValidatedEconomicRoot) -> Result<Self, DsmError> {
        let leaves = if validated.economic_position() == 0 {
            Vec::new()
        } else {
            crate::storage::client_db::economic_lineage::load_leaf_cache()
                .map_err(|e| storage_err("load leaf cache", e))?
        };
        let decoded: Vec<(D32, EconomicLeafState)> = leaves
            .iter()
            .map(|(key, _value, ccb)| {
                dsm::economic::decode::decode_leaf_state(ccb)
                    .map(|state| (*key, state))
                    .map_err(|e| storage_err("decode cached leaf state", e))
            })
            .collect::<Result<_, _>>()?;
        Self::checked(validated.economic_root(), decoded)
    }

    /// Leaves that must recompute `root`; anything else is refused.
    pub fn checked(
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
        Ok(Self { root, leaves: map })
    }

    pub fn root(&self) -> D32 {
        self.root
    }

    /// The pre value at `key`, as Core reads it.
    fn pre(&self, key: &D32) -> TraderLeafPre {
        match self.leaves.get(key) {
            Some(EconomicLeafState::Balance(b)) => TraderLeafPre::Balance(b.clone()),
            Some(EconomicLeafState::Relationship(r)) => TraderLeafPre::Relationship(*r),
            // A write-once record at a key a core touches: not a balance, not
            // a relationship — Core compares and refuses. Here it is simply
            // not one of the two pre values a core can start from.
            Some(_) | None => TraderLeafPre::Absent,
        }
    }
}

/// The vault genesis preimage, found under `vault_genesis_locator(v)` and
/// recognized by Core: strict decode, and `vault_id()` recomputed from the
/// bytes must be `v`. `None` when nothing verifying is indexed, or the scan
/// could not complete.
pub async fn fetch_vault_genesis(
    set: &StorageSet,
    vault_id: &D32,
) -> Result<Option<VaultGenesisPreimage>, DsmError> {
    let locator = derive::vault_genesis_locator(vault_id);
    let resolved = crate::sdk::storage_io::resolve_locator(
        set,
        TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
        TAG_DSM_SOFI_VAULT_GENESIS_OBJECT,
        &locator,
        LOCATOR_BUDGET,
        |bytes| {
            let preimage = VaultGenesisPreimage::decode(bytes).ok()?;
            Some((
                derive::vault_genesis_locator(&preimage.vault_id()),
                preimage,
            ))
        },
    )
    .await?;
    Ok(match resolved {
        Resolved::Kept(preimage) => Some(preimage),
        Resolved::None | Resolved::Unavailable => None,
    })
}

/// Acquire everything `preimage` needs, from storage and the local leaves.
/// What could not be fetched is left out, and Core answers `Unavailable`.
pub async fn acquire_evidence(
    set: &StorageSet,
    preimage: &SettlementPreimage,
    local: &LocalLeaves,
) -> Result<Evidence, DsmError> {
    let needs = EvidenceNeeds::of(preimage);

    let trader_leaves: BTreeMap<D32, TraderLeafPre> = needs
        .trader_keys
        .iter()
        .map(|key| (*key, local.pre(key)))
        .collect();

    let mut vault_leaves: BTreeMap<(D32, D32), VaultLeafPre> = BTreeMap::new();
    let mut objects: BTreeMap<D32, Vec<u8>> = BTreeMap::new();
    for (vault_id, keys) in &needs.vaults {
        let Some(genesis) = fetch_vault_genesis(set, vault_id).await? else {
            continue;
        };
        // The core names the parent root it was built against; the genesis
        // is that state only when the roots agree. A vault past R_0 needs the
        // successor walk, which is not this step: its leaves stay unfetched.
        let at_genesis = preimage
            .dlv_cores()
            .iter()
            .find(|core| core.vault_id() == vault_id)
            .map(|core| genesis_root(vault_id, &genesis.state).ok() == Some(*core.pre_root()))
            .unwrap_or(true);
        if !at_genesis {
            continue;
        }
        vault_leaves.extend(vault_leaves_at_genesis(vault_id, &genesis.state, keys));
        for (_class, addr) in EvidenceNeeds::policies_of(&genesis.state) {
            if let Some(bytes) = crate::sdk::storage_io::read_stored_bytes(set, &addr).await? {
                objects.insert(addr, bytes);
            }
        }
    }
    Ok(Evidence::acquired(objects, trader_leaves, vault_leaves))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    //! Gate G3 at the acquisition: over the fake fleet, evidence built only
    //! from fetched bytes validates a first trade at a vault's genesis; each
    //! item withheld is `Unavailable` with its own `Missing`; bytes that do
    //! not authenticate to their address are never an item; an authentic
    //! object that is wrong is refused by Core with its own `Invalid`.

    use super::*;
    use dsm::common::domain_tags::TAG_DSM_MARKET_POLICY_OBJECT;
    use dsm::economic::keys::balance_key;
    use dsm::economic::state::EconomicBalanceState;
    use dsm::sofi::validation::{validate, Invalid, Missing, Refusal};
    use serial_test::serial;

    use crate::sdk::sofi_test_fixtures::{
        all_policies, d, five, token, RouteFixture, VaultAtGenesis, DEV, G, OWNER_DEV, OWNER_G,
        P_CREATE,
    };
    use crate::sdk::storage_io::fake_fleet;

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        crate::runtime::get_runtime().block_on(fut)
    }

    /// Evidence acquired from fetched bytes and the trader's own leaves
    /// validates a first trade at the vault's genesis: nothing defaulted,
    /// nothing filled in, every item consumed.
    #[test]
    #[serial]
    fn acquired_evidence_validates_a_first_trade_at_vault_genesis() {
        fake_fleet::reset();
        let set = five();
        let f = RouteFixture::swap(1, set.id());
        f.publish(&set, &all_policies());
        let evidence = f.acquire(&set);
        assert_eq!(
            evidence.objects.len(),
            3,
            "the three policy objects, by address"
        );
        assert_eq!(
            evidence.trader_leaves.len(),
            3,
            "the in, out and relationship keys"
        );
        assert_eq!(
            evidence.vault_leaves.len(),
            2,
            "the state key and the relationship key"
        );
        assert_eq!(validate(&f.precommit, &f.preimage, &evidence), Ok(()));
    }

    /// `acquired_bytes_are_stored` (Lean): every object in the evidence is
    /// exactly the Stored bytes at the address the vault state commits, and
    /// the acquisition fetches exactly what the preimage needs.
    #[test]
    #[serial]
    fn acquired_bytes_are_stored() {
        fake_fleet::reset();
        let set = five();
        let f = RouteFixture::swap(1, set.id());
        f.publish(&set, &all_policies());
        let evidence = f.acquire(&set);
        let needs = EvidenceNeeds::of(&f.preimage);
        for class in all_policies() {
            let (addr, bytes) = f.vaults[0].policy(class);
            assert_eq!(evidence.objects.get(&addr).map(Vec::as_slice), Some(bytes));
            assert_eq!(
                block_on(crate::sdk::storage_io::read_stored_bytes(&set, &addr)).unwrap(),
                Some(bytes.to_vec())
            );
        }
        assert_eq!(
            evidence.trader_leaves.keys().copied().collect::<Vec<_>>(),
            needs.trader_keys.iter().copied().collect::<Vec<_>>()
        );
        assert_eq!(
            evidence
                .vault_leaves
                .keys()
                .map(|(_, k)| *k)
                .collect::<Vec<_>>(),
            needs.vaults[&f.vaults[0].vault_id]
                .iter()
                .copied()
                .collect::<Vec<_>>()
        );
    }

    /// `nothing_is_defaulted` (Lean): with nothing published, the evidence
    /// holds no object and no vault leaf, and Core answers Unavailable —
    /// never a filled-in state, never Invalid. The R5 mutation control:
    /// make the acquisition fill an unfetched vault with an empty state and
    /// this goes red.
    #[test]
    #[serial]
    fn nothing_is_defaulted() {
        fake_fleet::reset();
        let set = five();
        let f = RouteFixture::swap(1, set.id());
        let evidence = f.acquire(&set);
        assert!(evidence.objects.is_empty());
        assert!(evidence.vault_leaves.is_empty());
        assert!(matches!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Unavailable(
                Missing::VaultLeaf { .. } | Missing::VaultState { .. }
            ))
        ));
    }

    /// G3, withheld: each policy object missing from storage is its own
    /// `Missing::Policy`, never Invalid.
    #[test]
    #[serial]
    fn a_withheld_policy_object_is_unavailable_never_invalid() {
        for withheld in all_policies() {
            fake_fleet::reset();
            let set = five();
            let f = RouteFixture::swap(1, set.id());
            let published: Vec<u16> = all_policies()
                .into_iter()
                .filter(|c| *c != withheld)
                .collect();
            f.publish(&set, &published);
            let evidence = f.acquire(&set);
            let (addr, _) = f.vaults[0].policy(withheld);
            assert!(!evidence.objects.contains_key(&addr));
            assert_eq!(
                validate(&f.precommit, &f.preimage, &evidence),
                Err(Refusal::Unavailable(Missing::Policy { addr }))
            );
        }
    }

    /// G3, corrupted at storage: bytes at a policy's address that do not
    /// re-hash to it are held by every member and are still nothing — the
    /// object is not acquired and the verdict is Unavailable.
    #[test]
    #[serial]
    fn bytes_that_do_not_authenticate_to_their_address_are_never_acquired() {
        fake_fleet::reset();
        let set = five();
        let f = RouteFixture::swap(1, set.id());
        f.publish(
            &set,
            &[dsm::ccb::class::FEE_POLICY, dsm::ccb::class::RELEASE_POLICY],
        );
        let (addr, _) = f.vaults[0].policy(dsm::ccb::class::MARKET_POLICY);
        for m in set.members() {
            fake_fleet::hold_bytes(
                &m.member_id,
                addr,
                TAG_DSM_MARKET_POLICY_OBJECT.source_bytes(),
                b"not the market policy",
            );
        }
        let evidence = f.acquire(&set);
        assert!(!evidence.objects.contains_key(&addr));
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Unavailable(Missing::Policy { addr }))
        );
    }

    /// G3, an authentic object that is wrong: the vault's committed market
    /// trades another pair than the hop prices. The genesis and its policies
    /// are acquired exactly as published — three objects, authenticated —
    /// and Core refuses the hop with its own Invalid. Acquisition decides
    /// nothing; it fetches.
    #[test]
    #[serial]
    fn an_authentic_but_wrong_policy_is_acquired_and_refused_by_core() {
        fake_fleet::reset();
        let set = five();
        // The hop prices t0 -> t1 against a vault whose market is (t2, t3).
        let f = RouteFixture::swap_with(1, set.id(), |_| (token(2), token(3)));
        f.publish(&set, &all_policies());
        let evidence = f.acquire(&set);
        assert_eq!(evidence.objects.len(), 3, "acquired exactly as published");
        match validate(&f.precommit, &f.preimage, &evidence) {
            Err(Refusal::Invalid(reason)) => {
                assert!(
                    !matches!(reason, Invalid::LeafPreValueMismatch),
                    "the refusal is about the market, not the leaves: {reason:?}"
                );
            }
            other => panic!("Core must refuse the hop as Invalid, got {other:?}"),
        }
    }

    /// A vault past its genesis: the core names a parent root the genesis
    /// does not produce, so its leaves stay unfetched (the successor walk of
    /// rebuild step R12) and the verdict is Unavailable, not a state made up.
    #[test]
    #[serial]
    fn a_vault_past_genesis_is_unavailable_until_the_walk() {
        fake_fleet::reset();
        let set = five();
        let f = RouteFixture::swap(1, set.id());
        let mut advanced = f.vaults[0].genesis.clone();
        advanced.state.generation = 3;
        advanced.state.reserve_a += 1;
        let bytes = advanced.encode().unwrap();
        let addr = fake_fleet::put_object(&set, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT, &bytes);
        fake_fleet::append_index(
            &set,
            TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
            &derive::vault_genesis_locator(&f.vaults[0].vault_id),
            &addr,
        );
        let evidence = f.acquire(&set);
        assert!(evidence.vault_leaves.is_empty());
        assert!(matches!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Unavailable(_))
        ));
    }

    /// A genesis naming another vault under this vault's locator is garbage
    /// under the locator: Core recomputes `vault_id()` and keeps nothing.
    #[test]
    #[serial]
    fn a_genesis_of_another_vault_under_the_locator_is_never_kept() {
        fake_fleet::reset();
        let set = five();
        let f = RouteFixture::swap(1, set.id());
        let other = VaultAtGenesis::new(
            OWNER_G,
            OWNER_DEV,
            P_CREATE + 9,
            (token(0), token(1)),
            set.id(),
        );
        assert_ne!(other.vault_id, f.vaults[0].vault_id);
        let bytes = other.genesis.encode().unwrap();
        let addr = fake_fleet::put_object(&set, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT, &bytes);
        fake_fleet::append_index(
            &set,
            TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
            &derive::vault_genesis_locator(&f.vaults[0].vault_id),
            &addr,
        );
        assert!(block_on(fetch_vault_genesis(&set, &f.vaults[0].vault_id))
            .unwrap()
            .is_none());
        assert!(block_on(fetch_vault_genesis(&set, &other.vault_id))
            .unwrap()
            .is_none());
    }

    /// Local leaves are the verifier's own: a set of leaves that does not
    /// recompute the validated root is refused before it can be evidence.
    #[test]
    fn local_leaves_must_recompute_the_validated_root() {
        let key = balance_key(&G, &DEV, &d(0x40));
        let leaf = EconomicLeafState::Balance(EconomicBalanceState {
            policy_commit: d(0x40),
            amount: 1,
        });
        assert!(LocalLeaves::checked([0xEE; 32], vec![(key, leaf.clone())]).is_err());
        let mut tree = EconomicSmt::new();
        tree.insert(key, leaf.leaf_value().unwrap());
        assert!(LocalLeaves::checked(tree.root(), vec![(key, leaf)]).is_ok());
    }

    /// Withholding the trader's own leaf: the verifier's leaves are checked
    /// against its root, so a leaf cannot be dropped silently — a set without
    /// it is another root, and refused. The Core twin is
    /// `missing_evidence_is_unavailable_never_invalid`.
    #[test]
    fn a_trader_leaf_cannot_be_withheld_from_the_verifiers_own_root() {
        let f = RouteFixture::swap(1, [0x77; 32]);
        assert!(LocalLeaves::checked(f.local.root(), Vec::new()).is_err());
    }
}
