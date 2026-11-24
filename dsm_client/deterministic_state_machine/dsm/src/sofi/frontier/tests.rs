// SPDX-License-Identifier: Apache-2.0

//! A witness is accepted only when both of its paths fold to the root a
//! reader established, and a witness advanced through each generation's
//! write set is, after every step, exactly the reference tree's.

use std::collections::BTreeMap;

use super::*;
use crate::merkle::batch_fold::FoldEntry;
use crate::sofi::wire::{VaultGenesisPreimage, VAULT_STATUS_ACTIVE};

fn d(byte: u8) -> D32 {
    [byte; 32]
}

/// A vault's owner: its genesis and origin device.
struct Identity {
    g: D32,
    devid: D32,
}

fn owner() -> &'static Identity {
    static OWNER: Identity = Identity {
        g: [0x31; 32],
        devid: [0x32; 32],
    };
    &OWNER
}

fn state_of(who: &Identity, generation: u64, reserve_a: u64) -> VaultStateLeaf {
    VaultStateLeaf {
        owner_genesis: who.g,
        owner_device_id: who.devid,
        create_position: 3,
        market_policy: d(0x40),
        fee_policy: d(0x41),
        release_policy: d(0x42),
        storage_set_id: d(0x43),
        generation,
        reserve_a,
        reserve_b: 20_000,
        status: VAULT_STATUS_ACTIVE,
    }
}

/// A genesis `who` owns, accepted as given.
fn genesis_of(who: &Identity) -> AcceptedVaultGenesis {
    let market =
        crate::ccb::state::MarketPolicy::beta_constant_product(d(0x60), d(0x61)).expect("market");
    AcceptedVaultGenesis::of_preimage_for_test(
        VaultGenesisPreimage {
            owner_genesis: who.g,
            owner_device_id: who.devid,
            create_position: 3,
            state: state_of(who, 0, 10_000),
        },
        market,
    )
}

/// A trader of the vault: `(genesis, device_id)`.
fn trader(i: u8) -> (D32, D32) {
    (d(0x80 | i), d(0x90 | i))
}

/// The reference: a vault's whole tree, its state and its relationship
/// leaves, moved one generation at a time by the write set a trade carries.
#[derive(Clone)]
struct Vault {
    id: D32,
    tree: EconomicSmt,
    state: VaultStateLeaf,
    relationships: BTreeMap<D32, VaultRelationshipLeaf>,
}

impl Vault {
    /// The vault at generation `generation`, with traders `0..traders`
    /// already holding relationship leaves.
    fn at(genesis: &AcceptedVaultGenesis, generation: u64, traders: u8) -> Self {
        let (tree, state, relationships) = Self::tree_at(genesis, generation, traders);
        Self {
            id: *genesis.vault_id(),
            tree,
            state,
            relationships,
        }
    }

    /// `wire` checked as `who`'s witness under this vault's root, the root a
    /// reader established.
    fn checked(
        &self,
        wire: &VaultFrontierWitnessV1,
        who: (D32, D32),
    ) -> Result<VaultWitness, WitnessRefused> {
        VaultWitness::checked(
            self.id,
            self.state.generation,
            self.tree.root(),
            wire,
            who.0,
            who.1,
        )
    }

    fn tree_at(
        genesis: &AcceptedVaultGenesis,
        generation: u64,
        traders: u8,
    ) -> (
        EconomicSmt,
        VaultStateLeaf,
        BTreeMap<D32, VaultRelationshipLeaf>,
    ) {
        let id = *genesis.vault_id();
        let state = state_of(owner(), generation, 10_000 + generation);
        let mut tree = EconomicSmt::new();
        tree.insert(
            derive::vault_state_key(&id),
            derive::vault_state_leaf_value(&state).expect("state"),
        );
        let mut relationships = BTreeMap::new();
        for i in 0..traders {
            let (g, dev) = trader(i);
            let leaf = VaultRelationshipLeaf {
                trader_genesis: g,
                trader_device_id: dev,
                leaf: d(0x20 | i),
            };
            let key = derive::relationship_key(&g, &dev, &id);
            tree.insert(key, derive::vault_relationship_leaf_value(&leaf));
            relationships.insert(key, leaf);
        }
        (tree, state, relationships)
    }

    fn witness_for(&self, who: (D32, D32)) -> VaultFrontierWitnessV1 {
        let key = derive::relationship_key(&who.0, &who.1, &self.id);
        witness_from_tree(
            &self.tree,
            &self.id,
            &self.state,
            self.relationships.get(&key).copied(),
            &who.0,
            &who.1,
        )
    }

    fn entry(&self, key: D32, post: Option<D32>) -> FoldEntry {
        FoldEntry {
            key,
            pre: self.tree.get(&key).copied(),
            post,
            path: Box::new(self.tree.siblings(&key)),
        }
    }

    /// One trade by `who`: the state's generation and reserves move, and
    /// `who`'s relationship leaf advances. Returns the post state Core
    /// would recompute, and moves the reference.
    fn trade(&mut self, who: (D32, D32), e: u8) -> VaultPostState {
        let state_key = derive::vault_state_key(&self.id);
        let rel_key = derive::relationship_key(&who.0, &who.1, &self.id);
        let mut post_state = self.state.clone();
        post_state.generation += 1;
        post_state.reserve_a += 7;
        let base = match self.relationships.get(&rel_key) {
            Some(leaf) => leaf.leaf,
            None => d(0x0F),
        };
        let leaf = VaultRelationshipLeaf {
            trader_genesis: who.0,
            trader_device_id: who.1,
            leaf: derive::relationship_leaf_next(&base, &d(e)),
        };
        let mut entries = vec![
            self.entry(
                state_key,
                Some(derive::vault_state_leaf_value(&post_state).expect("state")),
            ),
            self.entry(rel_key, Some(derive::vault_relationship_leaf_value(&leaf))),
        ];
        entries.sort_by_key(|e| e.key);
        let root = crate::sofi::smt::verify_batch(&self.tree.root(), &entries).expect("folds");
        let post = VaultPostState::of_write_set_for_test(
            self.id,
            self.tree.root(),
            root,
            post_state.clone(),
            Some((rel_key, leaf)),
            entries.clone(),
        );
        for entry in &entries {
            if let Some(value) = entry.post {
                self.tree.insert(entry.key, value);
            }
        }
        self.state = post_state;
        self.relationships.insert(rel_key, leaf);
        post
    }

    /// `witness` is exactly what this reference holds for its trader.
    fn agrees(&self, witness: &VaultWitness) {
        let (g, dev) = witness.trader();
        let rel_key = derive::relationship_key(g, dev, &self.id);
        assert_eq!(*witness.root(), self.tree.root());
        assert_eq!(witness.generation(), self.state.generation);
        assert_eq!(*witness.state(), self.state);
        assert_eq!(
            *witness.state_path(),
            self.tree.siblings(&derive::vault_state_key(&self.id))
        );
        assert_eq!(
            witness.relationship.as_ref(),
            self.relationships.get(&rel_key)
        );
        assert_eq!(*witness.relationship_path(), self.tree.siblings(&rel_key));
    }
}

/// A witness is accepted only when both of its paths fold to the root the
/// reader established. Each mutation is refused; the control is accepted.
#[test]
fn a_witness_is_accepted_only_under_the_established_root() {
    let genesis = genesis_of(owner());
    let vault = Vault::at(&genesis, 12, 5);
    let (present, absent) = (trader(2), trader(9));

    // Controls: a trader with a leaf, and one without.
    for who in [present, absent] {
        let witness = vault
            .checked(&vault.witness_for(who), who)
            .expect("the owner's witness");
        vault.agrees(&witness);
    }

    let from = |wire: &VaultFrontierWitnessV1, who: (D32, D32)| {
        vault.checked(wire, who).expect_err("refused")
    };

    let mut bent_state = vault.witness_for(present);
    bent_state.state_path[200][0] ^= 0x01;
    assert_eq!(
        from(&bent_state, present),
        WitnessRefused::StateNotUnderRoot
    );

    let mut old_state = vault.witness_for(present);
    old_state.state_leaf.generation = 11;
    assert!(matches!(
        from(&old_state, present),
        WitnessRefused::StateGeneration { .. }
    ));

    // Another trader's leaf, presented as this trader's.
    assert_eq!(
        from(&vault.witness_for(trader(3)), present),
        WitnessRefused::RelationshipTrader
    );

    // Absent, claimed for a trader whose leaf exists: the fold refuses it.
    let mut hidden = vault.witness_for(present);
    hidden.relationship = FrontierRelationship::Absent {
        path: hidden.relationship.path().to_vec(),
    };
    assert_eq!(
        from(&hidden, present),
        WitnessRefused::RelationshipNotUnderRoot
    );

    // Present, with a leaf value the tree does not hold.
    let mut forged = vault.witness_for(present);
    if let FrontierRelationship::Present { leaf, .. } = &mut forged.relationship {
        leaf.leaf = d(0x5E);
    }
    assert_eq!(
        from(&forged, present),
        WitnessRefused::RelationshipNotUnderRoot
    );

    // A short path.
    let mut short = vault.witness_for(absent);
    short.state_path.pop();
    assert!(matches!(
        from(&short, absent),
        WitnessRefused::PathDepth(..)
    ));
}

/// A witness at g-10, then ten trades by other traders: the reader's witness,
/// advanced through each write set, is the reference tree's after every one —
/// for a reader with a relationship leaf and for one without.
#[test]
fn a_witness_advances_through_ten_other_traders_trades() {
    let genesis = genesis_of(owner());
    for reader in [trader(1), trader(30)] {
        let mut vault = Vault::at(&genesis, 20, 6);
        let mut witness = vault
            .checked(&vault.witness_for(reader), reader)
            .expect("the owner's witness");
        for step in 0..10u8 {
            // Old traders and new ones, never the reader.
            let other = trader(if step % 2 == 0 { 3 } else { 10 + step });
            let post = vault.trade(other, step);
            witness = witness.advance(&post).expect("advances");
            vault.agrees(&witness);
        }
        assert_eq!(witness.generation(), 30);
    }
}

/// The reader trades in the middle: its own leaf becomes the one the write
/// set advanced, from absent on its first trade and from its leaf on its
/// second, and the witness stays the reference tree's throughout.
#[test]
fn the_readers_own_trades_become_its_relationship() {
    let genesis = genesis_of(owner());
    let reader = trader(40);
    let mut vault = Vault::at(&genesis, 0, 0);
    let mut witness =
        VaultWitness::at_genesis(&genesis, reader.0, reader.1).expect("the genesis witness");
    vault.agrees(&witness);
    for (step, who) in [trader(1), reader, trader(2), reader, trader(1)]
        .into_iter()
        .enumerate()
    {
        let post = vault.trade(who, step as u8);
        witness = witness.advance(&post).expect("advances");
        vault.agrees(&witness);
    }
}

/// A write set with one corrupted sibling, a post state built on another
/// root, and a post state naming a leaf its write set did not write are each
/// refused, never advanced past.
#[test]
fn an_advance_the_write_set_does_not_prove_is_refused() {
    let genesis = genesis_of(owner());
    let reader = trader(2);
    let mut vault = Vault::at(&genesis, 8, 4);
    let witness = vault
        .checked(&vault.witness_for(reader), reader)
        .expect("the owner's witness");
    let before = vault.clone();
    let post = vault.trade(trader(3), 1);

    // Control.
    witness
        .advance(&post)
        .expect("the honest write set advances");

    // One sibling bent, at the top, the middle and the bottom of a path.
    for at in [0usize, 128, 255] {
        let mut entries = post.entries().to_vec();
        entries[0].path[at][5] ^= 0x08;
        // The post state names the honest roots; only its write set is bent.
        let bent = VaultPostState::of_write_set_for_test(
            *post.vault_id(),
            *post.pre_root(),
            *post.root(),
            post.state().clone(),
            post.relationship().copied(),
            entries,
        );
        assert!(matches!(
            witness.advance(&bent).expect_err("refused"),
            WitnessRefused::Advance(..)
        ));
    }

    // Built on another generation's root.
    let mut ahead = vault.clone();
    let later = ahead.trade(trader(1), 2);
    assert_eq!(
        witness.advance(&later).expect_err("refused"),
        WitnessRefused::NotBuiltOnTheWitness
    );

    // A post state whose state is not the one its write set wrote.
    let mut priced = post.state().clone();
    priced.reserve_b += 1;
    let mispriced = VaultPostState::of_write_set_for_test(
        *post.vault_id(),
        *post.pre_root(),
        *post.root(),
        priced,
        post.relationship().copied(),
        post.entries().to_vec(),
    );
    assert_eq!(
        witness.advance(&mispriced).expect_err("refused"),
        WitnessRefused::AdvancedValue
    );

    // A post state that names, as the reader's, a leaf its write set did not
    // write there.
    let mut lying = before;
    let honest = lying.trade(reader, 3);
    let (key, mut leaf) = *honest.relationship().expect("the reader's leaf");
    leaf.leaf = d(0x6B);
    let named = VaultPostState::of_write_set_for_test(
        *honest.vault_id(),
        *honest.pre_root(),
        *honest.root(),
        honest.state().clone(),
        Some((key, leaf)),
        honest.entries().to_vec(),
    );
    assert_eq!(
        witness.advance(&named).expect_err("refused"),
        WitnessRefused::AdvancedValue
    );
}

/// What a fresh reader holds does not grow with the vault: the witness is
/// the same size at generation 4 and at generation 40, with 3 traders or 60.
#[test]
fn the_witness_is_constant_in_size() {
    let genesis = genesis_of(owner());
    let sizes: Vec<usize> = [(4u64, 3u8), (40, 60)]
        .into_iter()
        .map(|(generation, traders)| {
            let vault = Vault::at(&genesis, generation, traders);
            vault
                .witness_for(trader(1))
                .encode()
                .expect("encodes")
                .len()
        })
        .collect();
    assert_eq!(sizes[0], sizes[1]);
}

/// A vault record's rows: the state leaf at the vault's state key, and a
/// relationship leaf for each trader, as an owner's device stores them.
fn vault_rows(vault_id: &D32, traders: &[u8]) -> Vec<(D32, D32, Vec<u8>)> {
    let state = state_of(owner(), 4, 9_000);
    let mut rows = vec![(
        derive::vault_state_key(vault_id),
        derive::vault_state_leaf_value(&state).expect("a state value"),
        state.encode().expect("state bytes"),
    )];
    for i in traders {
        let (g, devid) = trader(*i);
        let leaf = VaultRelationshipLeaf {
            trader_genesis: g,
            trader_device_id: devid,
            leaf: d(0xB0 | i),
        };
        rows.push((
            derive::relationship_key(&g, &devid, vault_id),
            derive::vault_relationship_leaf_value(&leaf),
            leaf.encode(),
        ));
    }
    rows
}

/// The root `rows` recompute, computed apart from the function under test.
fn root_of_rows(rows: &[(D32, D32, Vec<u8>)]) -> D32 {
    let mut tree = EconomicSmt::new();
    for (key, value, ..) in rows {
        tree.insert(*key, *value);
    }
    tree.root()
}

/// THE OWNER'S WHOLE TREE IS CORE'S (SoFi §2.1). A record that recomputes
/// the root gives its tree, its state leaf and every relationship by key,
/// and the witness stated from it is accepted under that root.
#[test]
fn a_vault_record_that_recomputes_its_root_is_its_tree() {
    let vault_id = d(0x5A);
    let rows = vault_rows(&vault_id, &[1, 2]);
    let root = root_of_rows(&rows);
    let whole = vault_tree_at(&vault_id, &root, &rows).expect("the record is the tree");
    assert_eq!(whole.tree.root(), root);
    assert_eq!(whole.state, state_of(owner(), 4, 9_000));
    let (g, devid) = trader(1);
    let key = derive::relationship_key(&g, &devid, &vault_id);
    assert_eq!(whole.relationships.len(), 2);
    assert_eq!(
        whole.relationships.get(&key).map(|leaf| leaf.leaf),
        Some(d(0xB1))
    );
}

/// A RECORD THAT IS NOT THE VAULT'S TREE AT THE ROOT STATES NOTHING. A record
/// missing a leaf does not recompute the root; a row whose bytes are another
/// leaf than its value hashes is refused although the root recomputes; and a
/// record with no state leaf is refused.
/// MUTATION CONTROL: the root check removed, or the leaf binding removed,
/// turns this red.
#[test]
fn a_vault_record_that_is_not_its_tree_at_the_root_is_refused() {
    let vault_id = d(0x5A);
    let rows = vault_rows(&vault_id, &[1, 2]);
    let root = root_of_rows(&rows);

    assert!(matches!(
        vault_tree_at(&vault_id, &root, &rows[..2]),
        Err(VaultTreeError::DoesNotRecomputeTheRoot { root: named, .. }) if named == root
    ));

    let mut forged = rows.clone();
    let (g, devid) = trader(2);
    forged[2].2 = VaultRelationshipLeaf {
        trader_genesis: g,
        trader_device_id: devid,
        leaf: d(0xEE),
    }
    .encode();
    assert_eq!(root_of_rows(&forged), root, "the root still recomputes");
    assert_eq!(
        vault_tree_at(&vault_id, &root, &forged).map(|whole| whole.tree.root()),
        Err(VaultTreeError::RowIsNotItsLeaf { key: rows[2].0 })
    );

    let relationships_only = rows[1..].to_vec();
    assert_eq!(
        vault_tree_at(
            &vault_id,
            &root_of_rows(&relationships_only),
            &relationships_only
        )
        .map(|whole| whole.tree.root()),
        Err(VaultTreeError::NoStateLeaf)
    );
}
