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
    use dsm::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
    use dsm::common::domain_tags::{
        TAG_DSM_FEE_POLICY_OBJECT, TAG_DSM_MARKET_POLICY_OBJECT, TAG_DSM_RELEASE_POLICY_OBJECT,
    };
    use dsm::dlv::route_commit::constant_product_output_classified;
    use dsm::economic::keys::balance_key;
    use dsm::economic::state::EconomicBalanceState;
    use dsm::economic::tree::{ABSENT_LEAF, ECONOMIC_SMT_HEIGHT};
    use dsm::sofi::smt::{batch_fold, FoldEntry};
    use dsm::sofi::validation::{validate, Invalid, Missing, Refusal};
    use dsm::sofi::wire::{
        CoreEntry, DlvCore, ParentClaimRef, PreEClosureIndex, PrecommitLeg, SettlementBody,
        SwapHop, TraderCore, TraderPrecommitBody, TraderRelationshipLeaf, VaultStateLeaf,
        VAULT_STATUS_ACTIVE,
    };
    use serial_test::serial;

    use crate::sdk::storage_io::fake_fleet;
    use crate::sdk::storage_set::{StorageMember, StorageSet};

    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];
    const OWNER_G: D32 = [0x91; 32];
    const OWNER_DEV: D32 = [0x92; 32];
    const P_POS: u64 = 5;
    const P_CREATE: u64 = 7;
    const FEE_BPS: u32 = 30;
    const RESERVE_A: u64 = 10_000;
    const RESERVE_B: u64 = 20_000;
    const AMOUNT_IN: u64 = 1_000;
    const SIG_ALG: u16 = 0x0001;

    fn d(byte: u8) -> D32 {
        [byte; 32]
    }

    fn five() -> StorageSet {
        StorageSet::new(
            (1..=5)
                .map(|i| StorageMember {
                    member_id: format!("m{i}"),
                    register_incarnation_id: [i as u8; 32],
                    endpoint: format!("http://m{i}.example"),
                })
                .collect(),
        )
        .expect("five members")
    }

    fn policy_addr(class: u16, bytes: &[u8]) -> D32 {
        dsm::ccb::decode::policy_object_address(class, bytes).expect("a policy class")
    }

    /// One vault at its genesis, trading `(a, b)`, and everything a trader
    /// needs to draft a first swap against it.
    struct Fixture {
        vault_id: D32,
        genesis: VaultGenesisPreimage,
        policies: [(u16, Vec<u8>); 3],
        precommit: TraderPrecommitBody,
        preimage: SettlementPreimage,
        local: LocalLeaves,
    }

    fn fixture(pair: (D32, D32)) -> Fixture {
        fixture_with(pair, P_CREATE)
    }

    /// The same, for a vault born at `create_position` — a different vault.
    fn fixture_with(pair: (D32, D32), create_position: u64) -> Fixture {
        let (a, b) = pair;
        let market = MarketPolicy::beta_constant_product(a, b).unwrap().encode();
        let fee = FeePolicy::new(FEE_BPS).unwrap().encode();
        let release = ReleasePolicy::beta_owner_local_full_close().encode();
        let set = five();
        let state = VaultStateLeaf {
            owner_genesis: OWNER_G,
            owner_device_id: OWNER_DEV,
            create_position,
            market_policy: policy_addr(dsm::ccb::class::MARKET_POLICY, &market),
            fee_policy: policy_addr(dsm::ccb::class::FEE_POLICY, &fee),
            release_policy: policy_addr(dsm::ccb::class::RELEASE_POLICY, &release),
            storage_set_id: set.id(),
            generation: 0,
            reserve_a: RESERVE_A,
            reserve_b: RESERVE_B,
            status: VAULT_STATUS_ACTIVE,
        };
        let genesis = VaultGenesisPreimage {
            owner_genesis: OWNER_G,
            owner_device_id: OWNER_DEV,
            create_position,
            state: state.clone(),
        };
        let vault_id = genesis.vault_id();

        // The vault's tree at R_0: its state leaf and nothing else.
        let state_key = derive::vault_state_key(&vault_id);
        let rel_key = derive::relationship_key(&G, &DEV, &vault_id);
        let mut vault_tree = EconomicSmt::new();
        vault_tree.insert(state_key, derive::vault_state_leaf_value(&state).unwrap());
        let parent_root = vault_tree.root();
        assert_eq!(parent_root, genesis_root(&vault_id, &state).unwrap());

        // The trade the hop prices against the genesis reserves.
        let (token_in, token_out) = (d(0x40), d(0x41));
        let amount_out =
            constant_product_output_classified(AMOUNT_IN, RESERVE_A, RESERVE_B, FEE_BPS).unwrap();
        let base = derive::relationship_leaf_genesis(&derive::setup_id(&G, &DEV, P_POS, &vault_id));
        let post_state = VaultStateLeaf {
            generation: 1,
            reserve_a: RESERVE_A + AMOUNT_IN,
            reserve_b: RESERVE_B - amount_out,
            ..state.clone()
        };
        let mut vault_entries = vec![
            CoreEntry::Mutation {
                key: state_key,
                pre: derive::vault_state_leaf_value(&state).unwrap(),
                post: derive::vault_state_leaf_value(&post_state).unwrap(),
                path: vault_tree.siblings(&state_key).to_vec(),
            },
            CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id,
                base,
                path: vault_tree.siblings(&rel_key).to_vec(),
            },
        ];
        vault_entries.sort_by_key(|e| e.key());
        let core = DlvCore::new(vault_id, parent_root, G, DEV, base, vault_entries).unwrap();

        // The trader's own tree: the token spent, and the relationship its
        // setup installed.
        let in_key = balance_key(&G, &DEV, &token_in);
        let out_key = balance_key(&G, &DEV, &token_out);
        let in_balance = EconomicBalanceState {
            policy_commit: token_in,
            amount: 50_000,
        };
        let rel_leaf = TraderRelationshipLeaf {
            vault_id,
            leaf: base,
        };
        let leaves = vec![
            (in_key, EconomicLeafState::Balance(in_balance.clone())),
            (rel_key, EconomicLeafState::Relationship(rel_leaf)),
        ];
        let mut trader_tree = EconomicSmt::new();
        for (key, state) in &leaves {
            trader_tree.insert(*key, state.leaf_value().unwrap());
        }
        let local = LocalLeaves::checked(trader_tree.root(), leaves).unwrap();
        let out_balance = EconomicBalanceState {
            policy_commit: token_out,
            amount: amount_out,
        };
        let in_after = EconomicBalanceState {
            policy_commit: token_in,
            amount: 50_000 - AMOUNT_IN,
        };
        let mut trader_entries = vec![
            CoreEntry::Mutation {
                key: in_key,
                pre: EconomicLeafState::Balance(in_balance).leaf_value().unwrap(),
                post: EconomicLeafState::Balance(in_after).leaf_value().unwrap(),
                path: trader_tree.siblings(&in_key).to_vec(),
            },
            CoreEntry::Mutation {
                key: out_key,
                pre: ABSENT_LEAF,
                post: EconomicLeafState::Balance(out_balance)
                    .leaf_value()
                    .unwrap(),
                path: trader_tree.siblings(&out_key).to_vec(),
            },
            CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id,
                base,
                path: trader_tree.siblings(&rel_key).to_vec(),
            },
        ];
        trader_entries.sort_by_key(|e| e.key());
        let trader_core =
            TraderCore::new(G, DEV, P_POS + 1, trader_tree.root(), trader_entries).unwrap();

        let hop = SwapHop {
            vault_id,
            parent_root,
            setup_ref: d(0x55),
            token_in,
            amount_in: AMOUNT_IN,
            token_out,
            amount_out,
        };
        let settlement = SettlementBody::Swap {
            token_in,
            amount_in: AMOUNT_IN,
            token_out,
            exact_out: amount_out,
            hops: vec![hop],
            trader_core: derive::trader_core_digest(&trader_core.encode().unwrap()),
            dlv_cores: vec![derive::dlv_core_digest(&core.encode().unwrap())],
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        };
        let preimage =
            SettlementPreimage::new(settlement, trader_core.clone(), vec![core]).unwrap();
        let e = derive::recompute_e(&preimage).unwrap();

        // The realize root is what T° folds to UNDER E.
        let fold_entries: Vec<FoldEntry> = trader_core
            .entries()
            .iter()
            .map(|entry| {
                let path: [D32; ECONOMIC_SMT_HEIGHT] = entry.path().try_into().unwrap();
                let (pre, post) = match entry {
                    CoreEntry::Mutation { pre, post, .. } => (
                        (*pre != ABSENT_LEAF).then_some(*pre),
                        (*post != ABSENT_LEAF).then_some(*post),
                    ),
                    CoreEntry::Relationship { base, vault_id, .. } => (
                        Some(derive::trader_relationship_leaf_value(&rel_leaf)),
                        Some(derive::trader_relationship_leaf_value(
                            &TraderRelationshipLeaf {
                                vault_id: *vault_id,
                                leaf: derive::relationship_leaf_next(base, &e),
                            },
                        )),
                    ),
                    CoreEntry::Read { .. } => unreachable!("no reads in this fixture"),
                };
                FoldEntry {
                    key: entry.key(),
                    pre,
                    post,
                    path: Box::new(path),
                }
            })
            .collect();
        let realize_root = batch_fold(&fold_entries).unwrap().post_root;

        let precommit = TraderPrecommitBody::new(
            G,
            DEV,
            P_POS,
            ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            e,
            vec![PrecommitLeg {
                vault_id,
                parent_root,
                setup_ref: d(0x55),
            }],
            realize_root,
            trader_tree.root(),
            set.id(),
            SIG_ALG,
            &[0x01; 64],
        )
        .unwrap();
        Fixture {
            vault_id,
            genesis,
            policies: [
                (dsm::ccb::class::MARKET_POLICY, market),
                (dsm::ccb::class::FEE_POLICY, fee),
                (dsm::ccb::class::RELEASE_POLICY, release),
            ],
            precommit,
            preimage,
            local,
        }
    }

    fn namespace_of(class: u16) -> dsm::crypto::domain::TaggedHashDomain<'static> {
        match class {
            dsm::ccb::class::MARKET_POLICY => TAG_DSM_MARKET_POLICY_OBJECT,
            dsm::ccb::class::FEE_POLICY => TAG_DSM_FEE_POLICY_OBJECT,
            _ => TAG_DSM_RELEASE_POLICY_OBJECT,
        }
    }

    /// Publish the genesis and the policies to every member and index the
    /// genesis under its locator — what rebuild step R8's producer will do.
    fn publish(set: &StorageSet, f: &Fixture, policies: &[u16]) {
        let bytes = f.genesis.encode().unwrap();
        let addr = fake_fleet::put_object(set, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT, &bytes);
        fake_fleet::append_index(
            set,
            TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
            &derive::vault_genesis_locator(&f.vault_id),
            &addr,
        );
        for (class, bytes) in &f.policies {
            if policies.contains(class) {
                fake_fleet::put_object(set, namespace_of(*class), bytes);
            }
        }
    }

    fn all_policies() -> [u16; 3] {
        [
            dsm::ccb::class::MARKET_POLICY,
            dsm::ccb::class::FEE_POLICY,
            dsm::ccb::class::RELEASE_POLICY,
        ]
    }

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
        let f = fixture((d(0x40), d(0x41)));
        publish(&set, &f, &all_policies());
        let evidence = block_on(acquire_evidence(&set, &f.preimage, &f.local)).unwrap();
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
        let f = fixture((d(0x40), d(0x41)));
        publish(&set, &f, &all_policies());
        let evidence = block_on(acquire_evidence(&set, &f.preimage, &f.local)).unwrap();
        let needs = EvidenceNeeds::of(&f.preimage);
        for (class, bytes) in &f.policies {
            let addr = policy_addr(*class, bytes);
            assert_eq!(evidence.objects.get(&addr), Some(bytes));
            assert_eq!(
                block_on(crate::sdk::storage_io::read_stored_bytes(&set, &addr)).unwrap(),
                Some(bytes.clone())
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
            needs.vaults[&f.vault_id]
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
        let f = fixture((d(0x40), d(0x41)));
        let evidence = block_on(acquire_evidence(&set, &f.preimage, &f.local)).unwrap();
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
            let f = fixture((d(0x40), d(0x41)));
            let published: Vec<u16> = all_policies()
                .into_iter()
                .filter(|c| *c != withheld)
                .collect();
            publish(&set, &f, &published);
            let evidence = block_on(acquire_evidence(&set, &f.preimage, &f.local)).unwrap();
            let (_, bytes) = f.policies.iter().find(|(c, _)| *c == withheld).unwrap();
            let addr = policy_addr(withheld, bytes);
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
        let f = fixture((d(0x40), d(0x41)));
        publish(
            &set,
            &f,
            &[dsm::ccb::class::FEE_POLICY, dsm::ccb::class::RELEASE_POLICY],
        );
        let (_, market) = &f.policies[0];
        let addr = policy_addr(dsm::ccb::class::MARKET_POLICY, market);
        for m in set.members() {
            fake_fleet::hold_bytes(
                &m.member_id,
                addr,
                TAG_DSM_MARKET_POLICY_OBJECT.source_bytes(),
                b"not the market policy",
            );
        }
        let evidence = block_on(acquire_evidence(&set, &f.preimage, &f.local)).unwrap();
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
        let f = fixture((d(0x42), d(0x43)));
        publish(&set, &f, &all_policies());
        let evidence = block_on(acquire_evidence(&set, &f.preimage, &f.local)).unwrap();
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
    /// does not produce, so its leaves stay unfetched (the successor walk is
    /// rebuild step R12) and the verdict is Unavailable, not a state made up.
    #[test]
    #[serial]
    fn a_vault_past_genesis_is_unavailable_until_the_walk() {
        fake_fleet::reset();
        let set = five();
        let f = fixture((d(0x40), d(0x41)));
        let mut advanced = f.genesis.clone();
        advanced.state.generation = 3;
        advanced.state.reserve_a += 1;
        let bytes = advanced.encode().unwrap();
        let addr = fake_fleet::put_object(&set, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT, &bytes);
        fake_fleet::append_index(
            &set,
            TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
            &derive::vault_genesis_locator(&f.vault_id),
            &addr,
        );
        let evidence = block_on(acquire_evidence(&set, &f.preimage, &f.local)).unwrap();
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
        let f = fixture((d(0x40), d(0x41)));
        let other = fixture_with((d(0x40), d(0x41)), P_CREATE + 1);
        assert_ne!(other.vault_id, f.vault_id);
        let bytes = other.genesis.encode().unwrap();
        let addr = fake_fleet::put_object(&set, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT, &bytes);
        fake_fleet::append_index(
            &set,
            TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
            &derive::vault_genesis_locator(&f.vault_id),
            &addr,
        );
        assert!(block_on(fetch_vault_genesis(&set, &f.vault_id))
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
    #[serial]
    fn a_trader_leaf_cannot_be_withheld_from_the_verifiers_own_root() {
        let f = fixture((d(0x40), d(0x41)));
        assert!(LocalLeaves::checked(f.local.root(), Vec::new()).is_err());
    }
}
