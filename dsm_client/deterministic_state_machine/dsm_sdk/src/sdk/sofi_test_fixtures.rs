// SPDX-License-Identifier: Apache-2.0

//! Test-only SoFi fixtures over the fake fleet: whole operations built the
//! way a trader builds them — the trees first, then the cores against them,
//! then `E`, then the roots `E` fixes — with the vaults at their genesis, the
//! genesis preimages and policies publishable to the fake members, and the
//! evidence acquired from there.
//!
//! Shared by the acquisition tests (`sofi_evidence`) and the producer tests
//! (`sofi_sdk`): a producer that fails closed can only be exercised with
//! evidence that was actually fetched.

#![allow(clippy::disallowed_methods)] // test fixtures; a failure here is the signal

use std::collections::BTreeSet;

use dsm::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
use dsm::common::domain_tags::{
    TAG_DSM_FEE_POLICY_OBJECT, TAG_DSM_MARKET_POLICY_OBJECT, TAG_DSM_RELEASE_POLICY_OBJECT,
    TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT,
};
use dsm::dlv::route_commit::constant_product_output_classified;
use dsm::economic::keys::balance_key;
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::{EconomicSmt, ABSENT_LEAF, ECONOMIC_SMT_HEIGHT};
use dsm::sofi::derive;
use dsm::sofi::lineage::genesis_root;
use dsm::sofi::smt::{batch_fold, FoldEntry};
use dsm::sofi::validation::Evidence;
use dsm::sofi::wire::{
    CoreEntry, DlvCore, ParentClaimRef, PreEClosureIndex, PrecommitLeg, SettlementBody,
    SettlementPreimage, SwapHop, TraderCore, TraderPrecommitBody, TraderRelationshipLeaf,
    VaultGenesisPreimage, VaultStateLeaf, VAULT_STATUS_ACTIVE, VAULT_STATUS_RETIRED,
};

use crate::sdk::sofi_evidence::{acquire_evidence, LocalLeaves};
use crate::sdk::sofi_sdk::TraderContext;
use crate::sdk::storage_io::fake_fleet;
use crate::sdk::storage_set::{StorageMember, StorageSet};

pub type D32 = [u8; 32];

pub const G: D32 = [0x11; 32];
pub const DEV: D32 = [0x22; 32];
pub const OWNER_G: D32 = [0x91; 32];
pub const OWNER_DEV: D32 = [0x92; 32];
pub const P_POS: u64 = 5;
pub const P_CREATE: u64 = 7;
pub const FEE_BPS: u32 = 30;
pub const RESERVE_A: u64 = 10_000;
pub const RESERVE_B: u64 = 20_000;
pub const AMOUNT_IN: u64 = 1_000;
pub const SIG_ALG: u16 = 0x0001;
pub const SET_ID_PLACEHOLDER: D32 = [0x77; 32];

pub fn d(byte: u8) -> D32 {
    [byte; 32]
}

/// Token `j` of the chain `t0 → t1 → …`, strictly ordered as the market
/// policy requires.
pub fn token(j: usize) -> D32 {
    d(0x40 + j as u8)
}

pub fn five() -> StorageSet {
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

pub fn policy_addr(class: u16, bytes: &[u8]) -> D32 {
    dsm::ccb::decode::policy_object_address(class, bytes).expect("a policy class")
}

pub fn all_policies() -> [u16; 3] {
    [
        dsm::ccb::class::MARKET_POLICY,
        dsm::ccb::class::FEE_POLICY,
        dsm::ccb::class::RELEASE_POLICY,
    ]
}

fn namespace_of(class: u16) -> dsm::crypto::domain::TaggedHashDomain<'static> {
    match class {
        dsm::ccb::class::MARKET_POLICY => TAG_DSM_MARKET_POLICY_OBJECT,
        dsm::ccb::class::FEE_POLICY => TAG_DSM_FEE_POLICY_OBJECT,
        _ => TAG_DSM_RELEASE_POLICY_OBJECT,
    }
}

/// One vault at its genesis: its state, its genesis preimage and the three
/// policy objects the state commits.
#[derive(Debug, Clone)]
pub struct VaultAtGenesis {
    pub vault_id: D32,
    pub genesis: VaultGenesisPreimage,
    pub policies: [(u16, Vec<u8>); 3],
    pub parent_root: D32,
}

impl VaultAtGenesis {
    /// A vault owned by `(owner_genesis, owner_device)`, born at
    /// `create_position`, trading `pair`, with the beta fee and release
    /// policies and the genesis reserves.
    pub fn new(
        owner_genesis: D32,
        owner_device: D32,
        create_position: u64,
        pair: (D32, D32),
        storage_set_id: D32,
    ) -> Self {
        let (a, b) = pair;
        let market = MarketPolicy::beta_constant_product(a, b).unwrap().encode();
        let fee = FeePolicy::new(FEE_BPS).unwrap().encode();
        let release = ReleasePolicy::beta_owner_local_full_close().encode();
        let state = VaultStateLeaf {
            owner_genesis,
            owner_device_id: owner_device,
            create_position,
            market_policy: policy_addr(dsm::ccb::class::MARKET_POLICY, &market),
            fee_policy: policy_addr(dsm::ccb::class::FEE_POLICY, &fee),
            release_policy: policy_addr(dsm::ccb::class::RELEASE_POLICY, &release),
            storage_set_id,
            generation: 0,
            reserve_a: RESERVE_A,
            reserve_b: RESERVE_B,
            status: VAULT_STATUS_ACTIVE,
        };
        let genesis = VaultGenesisPreimage {
            owner_genesis,
            owner_device_id: owner_device,
            create_position,
            state: state.clone(),
        };
        let vault_id = genesis.vault_id();
        let parent_root = genesis_root(&vault_id, &state).unwrap();
        Self {
            vault_id,
            genesis,
            policies: [
                (dsm::ccb::class::MARKET_POLICY, market),
                (dsm::ccb::class::FEE_POLICY, fee),
                (dsm::ccb::class::RELEASE_POLICY, release),
            ],
            parent_root,
        }
    }

    pub fn state(&self) -> &VaultStateLeaf {
        &self.genesis.state
    }

    /// The vault's tree at `R_0`: exactly its state leaf.
    pub fn tree(&self) -> EconomicSmt {
        let mut tree = EconomicSmt::new();
        tree.insert(
            derive::vault_state_key(&self.vault_id),
            derive::vault_state_leaf_value(self.state()).unwrap(),
        );
        tree
    }

    /// Publish the genesis and the named policies to every member of `set`,
    /// and index the genesis under its locator — what rebuild step R8's
    /// producer does.
    pub fn publish(&self, set: &StorageSet, policies: &[u16]) {
        let bytes = self.genesis.encode().unwrap();
        let addr = fake_fleet::put_object(set, TAG_DSM_SOFI_VAULT_GENESIS_OBJECT, &bytes);
        fake_fleet::append_index(
            set,
            TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
            &derive::vault_genesis_locator(&self.vault_id),
            &addr,
        );
        for (class, bytes) in &self.policies {
            if policies.contains(class) {
                fake_fleet::put_object(set, namespace_of(*class), bytes);
            }
        }
    }

    /// The bytes and address of one of its policies.
    pub fn policy(&self, class: u16) -> (D32, &[u8]) {
        let (_, bytes) = self.policies.iter().find(|(c, _)| *c == class).unwrap();
        (policy_addr(class, bytes), bytes)
    }
}

/// A whole operation, built the way a trader builds one, against vaults at
/// their genesis: the inputs every producer takes, and the evidence a
/// verifier acquires for it.
pub struct RouteFixture {
    pub vaults: Vec<VaultAtGenesis>,
    pub hops: Vec<SwapHop>,
    pub cores: Vec<DlvCore>,
    pub trader_core: TraderCore,
    pub settlement: SettlementBody,
    pub preimage: SettlementPreimage,
    pub precommit: TraderPrecommitBody,
    pub realize_root: D32,
    pub void_root: D32,
    pub local: LocalLeaves,
    pub storage_set_id: D32,
    /// The trader's identity for the context: the trader for a swap, the
    /// owner for a close.
    pub trader: (D32, D32),
}

impl RouteFixture {
    /// An `n`-hop swap `t0 → t1 → … → tn` through `n` vaults owned by
    /// `OWNER_*`, each at its genesis, by trader `(G, DEV)` at position
    /// `P_POS`. `market_of(j)` overrides vault `j`'s pair.
    pub fn swap(n: usize, storage_set_id: D32) -> Self {
        Self::swap_with(n, storage_set_id, |j| (token(j), token(j + 1)))
    }

    pub fn swap_with(
        n: usize,
        storage_set_id: D32,
        market_of: impl Fn(usize) -> (D32, D32),
    ) -> Self {
        let vaults: Vec<VaultAtGenesis> = (0..n)
            .map(|j| {
                VaultAtGenesis::new(
                    OWNER_G,
                    OWNER_DEV,
                    P_CREATE + j as u64,
                    market_of(j),
                    storage_set_id,
                )
            })
            .collect();

        // Hops chain: each gives out what the next takes in.
        let mut amount = AMOUNT_IN;
        let mut hops = Vec::new();
        let mut cores = Vec::new();
        let mut bases = Vec::new();
        for (j, vault) in vaults.iter().enumerate() {
            let (token_in, token_out) = (token(j), token(j + 1));
            let amount_out =
                constant_product_output_classified(amount, RESERVE_A, RESERVE_B, FEE_BPS).unwrap();
            let base = derive::relationship_leaf_genesis(&derive::setup_id(
                &G,
                &DEV,
                P_POS,
                &vault.vault_id,
            ));
            bases.push(base);
            let state = vault.state();
            let post_state = VaultStateLeaf {
                generation: 1,
                reserve_a: RESERVE_A + amount,
                reserve_b: RESERVE_B - amount_out,
                ..state.clone()
            };
            cores.push(vault_core(vault, &post_state, base));
            hops.push(SwapHop {
                vault_id: vault.vault_id,
                parent_root: vault.parent_root,
                setup_ref: d(0x55 + j as u8),
                token_in,
                amount_in: amount,
                token_out,
                amount_out,
            });
            amount = amount_out;
        }
        let intent_in = token(0);
        let intent_out = token(n);
        let exact_out = amount;

        // The trader's own tree: the token spent, and one relationship its
        // setup installed per vault.
        let in_key = balance_key(&G, &DEV, &intent_in);
        let out_key = balance_key(&G, &DEV, &intent_out);
        let in_balance = EconomicBalanceState {
            policy_commit: intent_in,
            amount: 50_000,
        };
        let mut leaves = vec![(in_key, EconomicLeafState::Balance(in_balance.clone()))];
        for (vault, base) in vaults.iter().zip(&bases) {
            leaves.push((
                derive::relationship_key(&G, &DEV, &vault.vault_id),
                EconomicLeafState::Relationship(TraderRelationshipLeaf {
                    vault_id: vault.vault_id,
                    leaf: *base,
                }),
            ));
        }
        let trader_tree = tree_of(&leaves);
        let local = LocalLeaves::checked(trader_tree.root(), leaves.clone()).unwrap();
        let mut trader_entries = vec![
            CoreEntry::Mutation {
                key: in_key,
                pre: EconomicLeafState::Balance(in_balance).leaf_value().unwrap(),
                post: EconomicLeafState::Balance(EconomicBalanceState {
                    policy_commit: intent_in,
                    amount: 50_000 - AMOUNT_IN,
                })
                .leaf_value()
                .unwrap(),
                path: trader_tree.siblings(&in_key).to_vec(),
            },
            CoreEntry::Mutation {
                key: out_key,
                pre: ABSENT_LEAF,
                post: EconomicLeafState::Balance(EconomicBalanceState {
                    policy_commit: intent_out,
                    amount: exact_out,
                })
                .leaf_value()
                .unwrap(),
                path: trader_tree.siblings(&out_key).to_vec(),
            },
        ];
        for (vault, base) in vaults.iter().zip(&bases) {
            let rel_key = derive::relationship_key(&G, &DEV, &vault.vault_id);
            trader_entries.push(CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id: vault.vault_id,
                base: *base,
                path: trader_tree.siblings(&rel_key).to_vec(),
            });
        }
        trader_entries.sort_by_key(|e| e.key());
        let trader_core =
            TraderCore::new(G, DEV, P_POS + 1, trader_tree.root(), trader_entries).unwrap();

        let mut sorted_cores = cores.clone();
        sorted_cores.sort_by_key(|c| *c.vault_id());
        let settlement = SettlementBody::Swap {
            token_in: intent_in,
            amount_in: AMOUNT_IN,
            token_out: intent_out,
            exact_out,
            hops: hops.clone(),
            trader_core: derive::trader_core_digest(&trader_core.encode().unwrap()),
            dlv_cores: sorted_cores
                .iter()
                .map(|c| derive::dlv_core_digest(&c.encode().unwrap()))
                .collect(),
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        };
        Self::finish(
            vaults,
            hops,
            cores,
            trader_core,
            settlement,
            &leaves,
            local,
            storage_set_id,
            (G, DEV),
        )
    }

    /// The trader `(G, DEV)` closing its OWN vault at genesis: both reserves
    /// come back, the vault retires.
    pub fn close(storage_set_id: D32) -> Self {
        let vault = VaultAtGenesis::new(G, DEV, P_CREATE, (token(0), token(1)), storage_set_id);
        let base =
            derive::relationship_leaf_genesis(&derive::setup_id(&G, &DEV, P_POS, &vault.vault_id));
        let state = vault.state();
        let retired = VaultStateLeaf {
            generation: 1,
            reserve_a: 0,
            reserve_b: 0,
            status: VAULT_STATUS_RETIRED,
            ..state.clone()
        };
        let core = vault_core(&vault, &retired, base);

        let rel_key = derive::relationship_key(&G, &DEV, &vault.vault_id);
        let leaves = vec![(
            rel_key,
            EconomicLeafState::Relationship(TraderRelationshipLeaf {
                vault_id: vault.vault_id,
                leaf: base,
            }),
        )];
        let trader_tree = tree_of(&leaves);
        let local = LocalLeaves::checked(trader_tree.root(), leaves.clone()).unwrap();
        let a_key = balance_key(&G, &DEV, &token(0));
        let b_key = balance_key(&G, &DEV, &token(1));
        let mut trader_entries = vec![
            CoreEntry::Mutation {
                key: a_key,
                pre: ABSENT_LEAF,
                post: EconomicLeafState::Balance(EconomicBalanceState {
                    policy_commit: token(0),
                    amount: RESERVE_A,
                })
                .leaf_value()
                .unwrap(),
                path: trader_tree.siblings(&a_key).to_vec(),
            },
            CoreEntry::Mutation {
                key: b_key,
                pre: ABSENT_LEAF,
                post: EconomicLeafState::Balance(EconomicBalanceState {
                    policy_commit: token(1),
                    amount: RESERVE_B,
                })
                .leaf_value()
                .unwrap(),
                path: trader_tree.siblings(&b_key).to_vec(),
            },
            CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id: vault.vault_id,
                base,
                path: trader_tree.siblings(&rel_key).to_vec(),
            },
        ];
        trader_entries.sort_by_key(|e| e.key());
        let trader_core =
            TraderCore::new(G, DEV, P_POS + 1, trader_tree.root(), trader_entries).unwrap();
        let settlement = SettlementBody::Close {
            vault_id: vault.vault_id,
            parent_root: vault.parent_root,
            setup_ref: d(0x55),
            owner_authority: dsm::sofi::wire::OwnerAuthority::Origin,
            reserve_a: RESERVE_A,
            reserve_b: RESERVE_B,
            trader_core: derive::trader_core_digest(&trader_core.encode().unwrap()),
            dlv_core: derive::dlv_core_digest(&core.encode().unwrap()),
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        };
        Self::finish(
            vec![vault],
            Vec::new(),
            vec![core],
            trader_core,
            settlement,
            &leaves,
            local,
            storage_set_id,
            (G, DEV),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        vaults: Vec<VaultAtGenesis>,
        hops: Vec<SwapHop>,
        cores: Vec<DlvCore>,
        trader_core: TraderCore,
        settlement: SettlementBody,
        leaves: &[(D32, EconomicLeafState)],
        local: LocalLeaves,
        storage_set_id: D32,
        trader: (D32, D32),
    ) -> Self {
        let preimage =
            SettlementPreimage::new(settlement.clone(), trader_core.clone(), cores.clone())
                .unwrap();
        let e = derive::recompute_e(&preimage).unwrap();
        let void_root = *trader_core.pre_root();
        let realize_root = fold_under(&trader_core, leaves, &e);
        let mut legs: Vec<PrecommitLeg> = vaults
            .iter()
            .enumerate()
            .map(|(j, v)| PrecommitLeg {
                vault_id: v.vault_id,
                parent_root: v.parent_root,
                setup_ref: d(0x55 + j as u8),
            })
            .collect();
        legs.sort_by_key(|l| l.vault_id);
        let precommit = TraderPrecommitBody::new(
            trader.0,
            trader.1,
            P_POS,
            ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            e,
            legs,
            realize_root,
            void_root,
            storage_set_id,
            SIG_ALG,
            &[0x01; 64],
        )
        .unwrap();
        Self {
            vaults,
            hops,
            cores,
            trader_core,
            settlement,
            preimage,
            precommit,
            realize_root,
            void_root,
            local,
            storage_set_id,
            trader,
        }
    }

    /// Publish every vault's genesis and the named policies.
    pub fn publish(&self, set: &StorageSet, policies: &[u16]) {
        for vault in &self.vaults {
            vault.publish(set, policies);
        }
    }

    /// Acquire the evidence this operation needs from `set` and the trader's
    /// own leaves.
    pub fn acquire(&self, set: &StorageSet) -> Evidence {
        crate::runtime::get_runtime()
            .block_on(acquire_evidence(set, &self.preimage, &self.local))
            .unwrap()
    }

    /// The context a producer takes, with `claimant_public_key` borrowed
    /// from the caller.
    pub fn ctx<'a>(&self, claimant_public_key: &'a [u8]) -> TraderContext<'a> {
        TraderContext {
            genesis: self.trader.0,
            device_id: self.trader.1,
            position: P_POS,
            parent_claim: ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            storage_set_id: self.storage_set_id,
            signature_alg: SIG_ALG,
            claimant_public_key,
            trader_core: self.trader_core.clone(),
        }
    }

    /// The set of vault ids the operation names.
    pub fn vault_ids(&self) -> BTreeSet<D32> {
        self.vaults.iter().map(|v| v.vault_id).collect()
    }
}

/// `V°`: the state mutation to `post_state` and the trader's relationship
/// advancement, against the vault's genesis tree.
fn vault_core(vault: &VaultAtGenesis, post_state: &VaultStateLeaf, base: D32) -> DlvCore {
    let tree = vault.tree();
    let state_key = derive::vault_state_key(&vault.vault_id);
    let rel_key = derive::relationship_key(&G, &DEV, &vault.vault_id);
    let mut entries = vec![
        CoreEntry::Mutation {
            key: state_key,
            pre: derive::vault_state_leaf_value(vault.state()).unwrap(),
            post: derive::vault_state_leaf_value(post_state).unwrap(),
            path: tree.siblings(&state_key).to_vec(),
        },
        CoreEntry::Relationship {
            genesis: G,
            device_id: DEV,
            vault_id: vault.vault_id,
            base,
            path: tree.siblings(&rel_key).to_vec(),
        },
    ];
    entries.sort_by_key(|e| e.key());
    DlvCore::new(vault.vault_id, vault.parent_root, G, DEV, base, entries).unwrap()
}

fn tree_of(leaves: &[(D32, EconomicLeafState)]) -> EconomicSmt {
    let mut tree = EconomicSmt::new();
    for (key, state) in leaves {
        tree.insert(*key, state.leaf_value().unwrap());
    }
    tree
}

/// `Fold(T°, E)`: what the trader core folds to under `E`, with each
/// relationship post from `relationship_leaf_next`.
fn fold_under(trader_core: &TraderCore, leaves: &[(D32, EconomicLeafState)], e: &D32) -> D32 {
    let entries: Vec<FoldEntry> = trader_core
        .entries()
        .iter()
        .map(|entry| {
            let path: [D32; ECONOMIC_SMT_HEIGHT] = entry.path().try_into().unwrap();
            let (pre, post) = match entry {
                CoreEntry::Mutation { pre, post, .. } => (
                    (*pre != ABSENT_LEAF).then_some(*pre),
                    (*post != ABSENT_LEAF).then_some(*post),
                ),
                CoreEntry::Relationship { base, vault_id, .. } => {
                    let held = leaves.iter().find_map(|(k, s)| match s {
                        EconomicLeafState::Relationship(r) if *k == entry.key() => Some(*r),
                        _ => None,
                    });
                    (
                        held.map(|r| derive::trader_relationship_leaf_value(&r)),
                        Some(derive::trader_relationship_leaf_value(
                            &TraderRelationshipLeaf {
                                vault_id: *vault_id,
                                leaf: derive::relationship_leaf_next(base, e),
                            },
                        )),
                    )
                }
                CoreEntry::Read { .. } => unreachable!("no reads in these fixtures"),
            };
            FoldEntry {
                key: entry.key(),
                pre,
                post,
                path: Box::new(path),
            }
        })
        .collect();
    batch_fold(&entries).unwrap().post_root
}
