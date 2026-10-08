// SPDX-License-Identifier: Apache-2.0

//! SoFi Amendment S24: an owner baseline authenticates only through the
//! owner's own P0–P6, in order; a witness is accepted only when both of its
//! paths fold to the authenticated root; and a witness advanced through each
//! generation's write set is, after every step, exactly the reference tree's.

use std::collections::BTreeMap;

use super::*;
use crate::ccb::{
    delegation_genesis_sentinel, genesis_v3_commitment, role, sigalg, transition_genesis_sentinel,
    DeviceTreeRootTransition, GenesisParamsV3, RootProgressionDelegation,
};
use crate::common::device_tree::{DevTreeProof, DeviceTree};
use crate::core::identity::authority_resolver::{SignedDelegation, SignedTransition};
use crate::core::identity::genesis_v2::derive_devid;
use crate::crypto::signatures::SignatureKeyPair;
use crate::crypto::sphincs::sphincs_sign;
use crate::dlv::vault_state_anchor_v3::sign_vault_state_anchor_v3;
use crate::merkle::batch_fold::FoldEntry;
use crate::sofi::history::{history_root, HistoryBuilder};
use crate::sofi::wire::{VaultGenesisPreimage, VAULT_STATUS_ACTIVE};

const NET: &[u8] = b"dsm-test";

fn d(byte: u8) -> D32 {
    [byte; 32]
}

/// A single-device identity, as the beta wallet derives one: `D_0` under the
/// GRK, `T_0` establishing the one-device tree under the device key.
struct Identity {
    g: D32,
    devid: D32,
    ak: SignatureKeyPair,
    params: GenesisParamsV3,
    delegations: Vec<SignedDelegation>,
    transitions: Vec<SignedTransition>,
    t0: D32,
    proof: DevTreeProof,
    atta: D32,
}

impl Identity {
    fn new(seed: u8) -> Self {
        let kp = |s: u8| SignatureKeyPair::generate_from_entropy(&[s; 32]).expect("keypair");
        let grk = kp(seed);
        let ak = kp(seed.wrapping_add(1));
        let atta = d(seed.wrapping_add(2));
        let devid = derive_devid(&ak.public_key, &atta);
        let params = GenesisParamsV3::new(
            d(seed.wrapping_add(3)),
            NET,
            3,
            sigalg::SPHINCS_PLUS_SPX256F,
            &grk.public_key,
        )
        .expect("params");
        let g = genesis_v3_commitment(&params).expect("G");
        let d0 = RootProgressionDelegation {
            genesis_id: g,
            role: role::DEVICE_TREE_ROOT_PROGRESSION,
            role_version: role::BETA_ROLE_VERSION,
            delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
            delegated_pk: ak.public_key.clone(),
            delegation_number: 0,
            parent_delegation_digest: delegation_genesis_sentinel(),
            activation_transition_digest: transition_genesis_sentinel(),
        };
        let tree = DeviceTree::single(devid);
        let t0 = DeviceTreeRootTransition {
            genesis_id: g,
            predecessor_transition_digest: transition_genesis_sentinel(),
            new_root: tree.root(),
            version_number: 0,
            delegation_digest: d0.digest().expect("D_0"),
        };
        let delegations = vec![SignedDelegation {
            grk_signature: sphincs_sign(&grk.secret_key, &d0.signing_digest().expect("D_0"))
                .expect("sign"),
            delegation: d0,
        }];
        let transitions = vec![SignedTransition {
            delegate_signature: sphincs_sign(&ak.secret_key, &t0.signing_digest()).expect("sign"),
            transition: t0.clone(),
        }];
        Self {
            g,
            devid,
            proof: tree.proof(&devid).expect("the device's own proof"),
            ak,
            params,
            delegations,
            transitions,
            t0: t0.digest(),
            atta,
        }
    }

    fn presented(&self) -> PresentedIdentity<'_> {
        PresentedIdentity {
            genesis_params: &self.params,
            delegations: &self.delegations,
            transitions: &self.transitions,
            inclusion: &self.proof,
            ak_pk: &self.ak.public_key,
            atta: &self.atta,
        }
    }

    /// The baseline this identity signs over `frontier`, at its own `T_0`:
    /// `(anchor, auth bytes, frontier bytes)`.
    fn baseline(&self, frontier: &VaultFrontierV1) -> (SignedVaultStateAnchorV3, Vec<u8>, Vec<u8>) {
        let auth = OwnerBaselineAuthV1 {
            frontier_commitment: frontier_commitment(frontier),
            owner_authority_transition_digest: self.t0,
        };
        let anchor = sign_vault_state_anchor_v3(
            &baseline_commitment(&auth),
            &self.ak.secret_key,
            &self.ak.public_key,
        )
        .expect("sign");
        (anchor, auth.encode(), frontier.encode())
    }
}

fn owner() -> &'static Identity {
    static OWNER: std::sync::OnceLock<Identity> = std::sync::OnceLock::new();
    OWNER.get_or_init(|| Identity::new(0x31))
}

fn stranger() -> &'static Identity {
    static STRANGER: std::sync::OnceLock<Identity> = std::sync::OnceLock::new();
    STRANGER.get_or_init(|| Identity::new(0x51))
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
    /// Every root the reference had, generation by generation (SoFi
    /// Amendment S26).
    history: HistoryBuilder,
}

impl Vault {
    /// The vault at generation `generation`, with traders `0..traders`
    /// already holding relationship leaves; its history is the root its
    /// tree had at each generation before.
    fn at(genesis: &AcceptedVaultGenesis, generation: u64, traders: u8) -> Self {
        let mut history = HistoryBuilder::new(*genesis.vault_id());
        for earlier in 0..generation {
            history.append(&Self::tree_at(genesis, earlier, traders).0.root());
        }
        let (tree, state, relationships) = Self::tree_at(genesis, generation, traders);
        history.append(&tree.root());
        Self {
            id: *genesis.vault_id(),
            tree,
            state,
            relationships,
            history,
        }
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

    fn frontier(&self) -> VaultFrontierV1 {
        let head = self.history.head().expect("a vault has a history");
        assert_eq!(head.generation, self.state.generation);
        VaultFrontierV1 {
            vault_id: self.id,
            generation: self.state.generation,
            root: self.tree.root(),
            history_root: history_root(&head).expect("the head encodes"),
        }
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
        self.history.append(&self.tree.root());
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
        assert_eq!(witness.relationship(), self.relationships.get(&rel_key));
        assert_eq!(*witness.relationship_path(), self.tree.siblings(&rel_key));
    }
}

fn authenticate(
    who: &Identity,
    signed: &(SignedVaultStateAnchorV3, Vec<u8>, Vec<u8>),
    genesis: &AcceptedVaultGenesis,
) -> Result<VerifiedFrontier, ResolveFailure> {
    authenticate_frontier_owner(&signed.0, &signed.1, &signed.2, &who.presented(), genesis)
}

/// The owner's baseline authenticates, and what it accepts is the frontier
/// the owner bound: its vault, generation and root.
#[test]
fn an_owner_baseline_authenticates_its_frontier() {
    let genesis = genesis_of(owner());
    let vault = Vault::at(&genesis, 12, 5);
    let frontier = vault.frontier();
    let verified = authenticate(owner(), &owner().baseline(&frontier), &genesis)
        .expect("the owner's baseline");
    assert_eq!(*verified.frontier(), frontier);
    assert_eq!(*verified.commitment(), frontier_commitment(&frontier));
    assert_eq!(verified.owner().device_id, owner().devid);
}

/// Every binding is load-bearing: each mutation below breaks one, and each
/// is refused. The control is the test above.
#[test]
fn a_baseline_is_refused_for_each_broken_binding() {
    let genesis = genesis_of(owner());
    let vault = Vault::at(&genesis, 12, 5);
    let frontier = vault.frontier();
    let honest = owner().baseline(&frontier);
    let refused = |signed: &(SignedVaultStateAnchorV3, Vec<u8>, Vec<u8>), who: &Identity| {
        authenticate(who, signed, &genesis).expect_err("refused")
    };

    // The signature does not verify.
    let mut bent = honest.clone();
    bent.0.signature[9] ^= 0x10;
    assert!(matches!(
        refused(&bent, owner()),
        ResolveFailure::Invalid(..)
    ));

    // The authentication bytes are not the ones signed.
    let mut other_auth = honest.clone();
    other_auth.1 = OwnerBaselineAuthV1 {
        frontier_commitment: frontier_commitment(&frontier),
        owner_authority_transition_digest: d(0x77),
    }
    .encode();
    assert!(matches!(
        refused(&other_auth, owner()),
        ResolveFailure::Invalid(..)
    ));

    // Signed, but at a position the owner's chain never reached.
    let unreached = {
        let auth = OwnerBaselineAuthV1 {
            frontier_commitment: frontier_commitment(&frontier),
            owner_authority_transition_digest: d(0x77),
        };
        let anchor = sign_vault_state_anchor_v3(
            &baseline_commitment(&auth),
            &owner().ak.secret_key,
            &owner().ak.public_key,
        )
        .expect("sign");
        (anchor, auth.encode(), frontier.encode())
    };
    assert!(matches!(
        refused(&unreached, owner()),
        ResolveFailure::Incomplete(..)
    ));

    // A stranger's own valid baseline of this vault: not the vault's owner.
    let by_stranger = stranger().baseline(&frontier);
    assert!(matches!(
        refused(&by_stranger, stranger()),
        ResolveFailure::Invalid(..)
    ));

    // The owner's identity presented beside a stranger's signature: the
    // position the stranger committed is not on the owner's chain.
    assert!(matches!(
        refused(&by_stranger, owner()),
        ResolveFailure::Incomplete(..)
    ));

    // The owner's baseline bytes and presentation, under a signature by
    // another key: both halves verify, and they are not one key.
    let mut other_signer = honest.clone();
    other_signer.0 = sign_vault_state_anchor_v3(
        &baseline_commitment(&OwnerBaselineAuthV1::decode(&honest.1).expect("auth")),
        &stranger().ak.secret_key,
        &stranger().ak.public_key,
    )
    .expect("sign");
    assert!(matches!(
        refused(&other_signer, owner()),
        ResolveFailure::Invalid(..)
    ));

    // The owner signed, but the frontier presented is another one.
    let mut swapped = honest.clone();
    swapped.2 = VaultFrontierV1 {
        root: d(0x99),
        ..frontier
    }
    .encode();
    assert!(matches!(
        refused(&swapped, owner()),
        ResolveFailure::Invalid(..)
    ));

    // The owner signed a frontier of another vault.
    let elsewhere = owner().baseline(&VaultFrontierV1 {
        vault_id: d(0x98),
        ..frontier
    });
    assert!(matches!(
        refused(&elsewhere, owner()),
        ResolveFailure::Invalid(..)
    ));

    // A stranger's vault: the owner's baseline proves the wrong owner.
    let theirs = genesis_of(stranger());
    let of_theirs = owner().baseline(&VaultFrontierV1 {
        vault_id: *theirs.vault_id(),
        ..frontier
    });
    assert!(matches!(
        authenticate(owner(), &of_theirs, &theirs).expect_err("refused"),
        ResolveFailure::Invalid(..)
    ));
}

/// A witness is accepted only when both of its paths fold to the root the
/// owner signed. Each mutation is refused; the control is accepted.
#[test]
fn a_witness_is_accepted_only_under_the_authenticated_root() {
    let genesis = genesis_of(owner());
    let vault = Vault::at(&genesis, 12, 5);
    let verified = authenticate(owner(), &owner().baseline(&vault.frontier()), &genesis)
        .expect("the owner's baseline");
    let (present, absent) = (trader(2), trader(9));

    // Controls: a trader with a leaf, and one without.
    for who in [present, absent] {
        let witness = VaultWitness::from_baseline(&verified, &vault.witness_for(who), who.0, who.1)
            .expect("the owner's witness");
        vault.agrees(&witness);
    }

    let from = |wire: &VaultFrontierWitnessV1, who: (D32, D32)| {
        VaultWitness::from_baseline(&verified, wire, who.0, who.1).expect_err("refused")
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

    let mut other_owner = vault.witness_for(present);
    other_owner.state_leaf.owner_genesis = stranger().g;
    assert_eq!(from(&other_owner, present), WitnessRefused::StateOwner);

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

/// Baseline at g-10, then ten trades by other traders: the reader's witness,
/// advanced through each write set, is the reference tree's after every one —
/// for a reader with a relationship leaf and for one without.
#[test]
fn a_witness_advances_through_ten_other_traders_trades() {
    let genesis = genesis_of(owner());
    for reader in [trader(1), trader(30)] {
        let mut vault = Vault::at(&genesis, 20, 6);
        let verified = authenticate(owner(), &owner().baseline(&vault.frontier()), &genesis)
            .expect("the owner's baseline");
        let mut witness =
            VaultWitness::from_baseline(&verified, &vault.witness_for(reader), reader.0, reader.1)
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
    let verified = authenticate(owner(), &owner().baseline(&vault.frontier()), &genesis)
        .expect("the owner's baseline");
    let witness =
        VaultWitness::from_baseline(&verified, &vault.witness_for(reader), reader.0, reader.1)
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

/// The three objects round-trip through their CCB bytes, and a trailing byte
/// or another class's envelope is refused.
#[test]
fn the_baseline_objects_decode_strictly() {
    let genesis = genesis_of(owner());
    let vault = Vault::at(&genesis, 6, 3);
    let frontier = vault.frontier();
    let auth = OwnerBaselineAuthV1 {
        frontier_commitment: frontier_commitment(&frontier),
        owner_authority_transition_digest: owner().t0,
    };
    let witness = vault.witness_for(trader(1));
    let absent = vault.witness_for(trader(50));
    assert_eq!(
        VaultFrontierV1::decode(&frontier.encode()).expect("frontier"),
        frontier
    );
    assert_eq!(
        OwnerBaselineAuthV1::decode(&auth.encode()).expect("auth"),
        auth
    );
    for w in [&witness, &absent] {
        let bytes = w.encode().expect("encodes");
        assert_eq!(&VaultFrontierWitnessV1::decode(&bytes).expect("witness"), w);
        let mut trailing = bytes.clone();
        trailing.push(0x01);
        VaultFrontierWitnessV1::decode(&trailing).expect_err("a trailing byte is refused");
    }
    let mut trailing = frontier.encode();
    trailing.push(0x01);
    VaultFrontierV1::decode(&trailing).expect_err("a trailing byte is refused");
    VaultFrontierV1::decode(&auth.encode()).expect_err("another class is refused");
    OwnerBaselineAuthV1::decode(&frontier.encode()).expect_err("another class is refused");
}
