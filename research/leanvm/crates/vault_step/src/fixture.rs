//! Random valid vault steps, for tests and benches: a vault, its policies, a tree holding its state leaf and other
//! traders' relationship leaves, and one trade.

use crate::reference::*;
use rand::{Rng, SeedableRng, rngs::StdRng};

pub struct Fixture {
    pub witness: StepWitness,
    pub r_prev: D32,
    pub public: StepPublic,
}

/// A valid step from `seed`: the trader's relationship leaf already in the tree when `present`, `others` other
/// traders' leaves beside it, and `attempt` the successor attempt.
pub fn fixture(seed: u64, present: bool, others: usize, attempt: u64) -> Fixture {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut d32 = || -> D32 { rng.random() };
    let vault_id = d32();
    let (mut token_a, mut token_b) = (d32(), d32());
    if token_a > token_b {
        std::mem::swap(&mut token_a, &mut token_b);
    }
    let (owner_genesis, owner_device_id, _, storage_set_id) = (d32(), d32(), d32(), d32());
    let (trader_genesis, trader_device_id, relationship_base, external_commitment) = (d32(), d32(), d32(), d32());
    let fee_bps = 30;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5eed);
    let state = VaultStateLeaf {
        owner_genesis,
        owner_device_id,
        create_position: rng.random_range(1..1 << 40),
        market_policy: market_policy_addr(&token_a, &token_b),
        fee_policy: fee_policy_addr(fee_bps),
        release_policy: release_policy_addr(),
        storage_set_id,
        generation: rng.random_range(0..1 << 20),
        reserve_a: rng.random_range(1 << 40..1 << 60),
        reserve_b: rng.random_range(1 << 40..1 << 60),
        status: VAULT_STATUS_ACTIVE,
    };
    let in_is_a = rng.random();
    let amount_in = rng.random_range(1 << 20..1 << 36);
    let (reserve_in, reserve_out) = if in_is_a {
        (state.reserve_a, state.reserve_b)
    } else {
        (state.reserve_b, state.reserve_a)
    };
    let amount_out = constant_product_output(amount_in, reserve_in, reserve_out, fee_bps).expect("a priced hop");
    let hop = Hop {
        in_is_a,
        amount_in,
        amount_out,
    };

    let mut tree = Tree::new();
    let state_key = vault_state_key(&vault_id);
    tree.insert(state_key, vault_state_leaf_value(&state));
    let rel_key = relationship_key(&trader_genesis, &trader_device_id, &vault_id);
    if present {
        tree.insert(
            rel_key,
            vault_relationship_leaf_value(&trader_genesis, &trader_device_id, &relationship_base),
        );
    }
    for _ in 0..others {
        let (g, d, base) = (rng.random(), rng.random(), rng.random());
        tree.insert(
            relationship_key(&g, &d, &vault_id),
            vault_relationship_leaf_value(&g, &d, &base),
        );
    }
    let r_prev = tree.root();
    let witness = StepWitness {
        vault_id,
        state,
        token_a,
        token_b,
        fee_bps,
        hop,
        kind: Kind::Swap,
        trader_genesis,
        trader_device_id,
        relationship_base,
        relationship_present: present,
        external_commitment,
        attempt,
        state_path: tree.path(&state_key),
        relationship_path: tree.path(&rel_key),
    };
    let public = step(&witness, &r_prev).expect("a valid step");
    Fixture {
        witness,
        r_prev,
        public,
    }
}

/// `steps` consecutive valid steps of one vault from `seed`: each step's `R_prev` the one before's `R_next`, each a
/// trade by a new trader (its leaf absent) or, every third step, by the first trader again (its leaf present).
pub fn chain(seed: u64, steps: usize) -> Vec<Fixture> {
    let mut rng = StdRng::seed_from_u64(seed);
    let d32 = |rng: &mut StdRng| -> D32 { rng.random() };
    let vault_id = d32(&mut rng);
    let (mut token_a, mut token_b) = (d32(&mut rng), d32(&mut rng));
    if token_a > token_b {
        std::mem::swap(&mut token_a, &mut token_b);
    }
    let fee_bps = 30;
    let mut state = VaultStateLeaf {
        owner_genesis: d32(&mut rng),
        owner_device_id: d32(&mut rng),
        create_position: rng.random_range(1..1 << 40),
        market_policy: market_policy_addr(&token_a, &token_b),
        fee_policy: fee_policy_addr(fee_bps),
        release_policy: release_policy_addr(),
        storage_set_id: d32(&mut rng),
        generation: rng.random_range(0..1 << 20),
        reserve_a: rng.random_range(1 << 50..1 << 60),
        reserve_b: rng.random_range(1 << 50..1 << 60),
        status: VAULT_STATUS_ACTIVE,
    };
    let state_key = vault_state_key(&vault_id);
    let mut tree = Tree::new();
    tree.insert(state_key, vault_state_leaf_value(&state));
    for _ in 0..4 {
        let (g, d, base) = (d32(&mut rng), d32(&mut rng), d32(&mut rng));
        tree.insert(relationship_key(&g, &d, &vault_id), vault_relationship_leaf_value(&g, &d, &base));
    }
    // The first trader, and its leaf once it has one.
    let (first_g, first_d) = (d32(&mut rng), d32(&mut rng));
    let mut first_leaf: Option<D32> = None;
    let mut out = Vec::new();
    for i in 0..steps {
        let returning = i % 3 == 2 && first_leaf.is_some();
        let (trader_genesis, trader_device_id) = if i == 0 || returning {
            (first_g, first_d)
        } else {
            (d32(&mut rng), d32(&mut rng))
        };
        let (present, relationship_base) = match (returning, first_leaf) {
            (true, Some(leaf)) => (true, leaf),
            _ => (false, d32(&mut rng)),
        };
        let in_is_a = rng.random();
        let amount_in = rng.random_range(1 << 20..1 << 36);
        let (r_in, r_out) = if in_is_a {
            (state.reserve_a, state.reserve_b)
        } else {
            (state.reserve_b, state.reserve_a)
        };
        let amount_out = constant_product_output(amount_in, r_in, r_out, fee_bps).expect("a priced hop");
        let rel_key = relationship_key(&trader_genesis, &trader_device_id, &vault_id);
        let r_prev = tree.root();
        let witness = StepWitness {
            vault_id,
            state: state.clone(),
            token_a,
            token_b,
            fee_bps,
            hop: Hop {
                in_is_a,
                amount_in,
                amount_out,
            },
            kind: Kind::Swap,
            trader_genesis,
            trader_device_id,
            relationship_base,
            relationship_present: present,
            external_commitment: d32(&mut rng),
            attempt: 0,
            state_path: tree.path(&state_key),
            relationship_path: tree.path(&rel_key),
        };
        let public = step(&witness, &r_prev).expect("a valid step");
        // The step's two writes.
        let post = swap_vault_post(&state, fee_bps, &witness.hop).unwrap();
        tree.insert(state_key, vault_state_leaf_value(&post));
        let next = relationship_leaf_next(&relationship_base, &witness.external_commitment);
        tree.insert(rel_key, vault_relationship_leaf_value(&trader_genesis, &trader_device_id, &next));
        assert_eq!(tree.root(), public.r_next, "the step's R_next is the tree's after its writes");
        if (trader_genesis, trader_device_id) == (first_g, first_d) {
            first_leaf = Some(next);
        }
        state = post;
        out.push(Fixture {
            witness,
            r_prev,
            public,
        });
    }
    out
}

/// Signed escrow terms' bytes (`EscrowTerms::encode`): each branch a label, its signers' keys (strictly ascending)
/// and its recipient.
pub fn signed_terms(token: &D32, y: &D32, branches: &[(Vec<u8>, Vec<[u8; SPX256F_KEY]>, D32, D32)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(CLASS_ESCROW_TERMS.to_be_bytes());
    out.extend(SCHEMA_V1.to_be_bytes());
    out.extend(token);
    out.extend(y);
    out.extend((branches.len() as u32).to_be_bytes());
    for (label, keys, g, d) in branches {
        out.extend((label.len() as u32).to_be_bytes());
        out.extend(label);
        out.extend((keys.len() as u32).to_be_bytes());
        for key in keys {
            out.extend(SPX256F.to_be_bytes());
            out.extend((SPX256F_KEY as u32).to_be_bytes());
            out.extend(key);
        }
        out.extend(g);
        out.extend(d);
    }
    out
}

/// Computed escrow terms' bytes (`ComputedEscrowTerms::encode`): the table's program, setup digest, two session
/// keys and two start commitments, then the three branches' recipients.
pub fn computed_terms(token: &D32, y: &D32, table: [&D32; 2], keys: [[u8; SPX256F_KEY]; 2], starts: [&D32; 2], recipients: [(D32, D32); 3]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(CLASS_ESCROW_COMPUTED_TERMS.to_be_bytes());
    out.extend(SCHEMA_V2.to_be_bytes());
    out.extend(token);
    out.extend(y);
    out.extend(table[0]);
    out.extend(table[1]);
    for key in keys {
        out.extend(SPX256F.to_be_bytes());
        out.extend((SPX256F_KEY as u32).to_be_bytes());
        out.extend(key);
    }
    out.extend(starts[0]);
    out.extend(starts[1]);
    out.extend(3u32.to_be_bytes());
    for (label, (g, d)) in COMPUTED_LABELS.iter().zip(recipients) {
        out.extend((label.len() as u32).to_be_bytes());
        out.extend(*label);
        out.extend(g);
        out.extend(d);
    }
    out
}

/// Which terms a release fixture's vault holds.
#[derive(Clone, Copy, Debug)]
pub enum Terms {
    /// Signed terms with this many branches, each with up to four signers and labels of up to 64 bytes.
    Signed { branches: usize },
    Computed,
}

/// A valid close (`Kind::Close`, the owner closing) or release (`Kind::Release`, the trader one branch pays) from
/// `seed`: the vault's own id, its state leaf and the trader's relationship leaf in a tree with `others` other
/// traders' leaves.
pub fn terminal(seed: u64, release: Option<Terms>, present: bool, others: usize) -> Fixture {
    let mut rng = StdRng::seed_from_u64(seed);
    let d32 = |rng: &mut StdRng| -> D32 { rng.random() };
    let (owner_genesis, owner_device_id) = (d32(&mut rng), d32(&mut rng));
    let create_position = rng.random_range(1..1 << 40);
    let vault_id = vault_id(&owner_genesis, &owner_device_id, create_position);
    let (mut token_a, mut token_b) = (d32(&mut rng), d32(&mut rng));
    if token_a > token_b {
        std::mem::swap(&mut token_a, &mut token_b);
    }
    let fee_bps = 30;
    let mut state = VaultStateLeaf {
        owner_genesis,
        owner_device_id,
        create_position,
        market_policy: market_policy_addr(&token_a, &token_b),
        fee_policy: fee_policy_addr(fee_bps),
        release_policy: release_policy_addr(),
        storage_set_id: d32(&mut rng),
        generation: rng.random_range(0..1 << 20),
        reserve_a: rng.random_range(1 << 40..1 << 60),
        reserve_b: rng.random_range(1 << 40..1 << 60),
        status: VAULT_STATUS_ACTIVE,
    };
    let (mut trader_genesis, mut trader_device_id) = (owner_genesis, owner_device_id);
    let kind = match release {
        None => Kind::Close,
        Some(terms) => {
            let (token, y) = (d32(&mut rng), d32(&mut rng));
            let mut recipients: Vec<(D32, D32)> = Vec::new();
            let bytes = match terms {
                Terms::Signed { branches } => {
                    let mut labels: Vec<Vec<u8>> = (0..branches)
                        .map(|i| {
                            let len = rng.random_range(1..=ESCROW_MAX_OUTCOME_BYTES);
                            let mut l: Vec<u8> = (0..len).map(|_| rng.random()).collect();
                            l[0] = i as u8; // distinct, so strictly ascending once sorted
                            l
                        })
                        .collect();
                    labels.sort();
                    let rows: Vec<_> = labels
                        .into_iter()
                        .map(|label| {
                            let mut keys: Vec<[u8; SPX256F_KEY]> = (0..rng.random_range(1..=ESCROW_MAX_SIGNERS))
                                .map(|_| std::array::from_fn(|_| rng.random()))
                                .collect();
                            keys.sort();
                            keys.dedup();
                            let r = (d32(&mut rng), d32(&mut rng));
                            recipients.push(r);
                            (label, keys, r.0, r.1)
                        })
                        .collect();
                    signed_terms(&token, &y, &rows)
                }
                Terms::Computed => {
                    let r: [(D32, D32); 3] = std::array::from_fn(|_| (d32(&mut rng), d32(&mut rng)));
                    recipients = r.to_vec();
                    let keys: [[u8; SPX256F_KEY]; 2] = std::array::from_fn(|_| std::array::from_fn(|_| rng.random()));
                    computed_terms(&token, &y, [&d32(&mut rng), &d32(&mut rng)], keys, [&d32(&mut rng), &d32(&mut rng)], r)
                }
            };
            let view = decode_escrow(&bytes).expect("fixture terms decode");
            let pick = rng.random_range(0..view.branches.len());
            (trader_genesis, trader_device_id) = recipients[pick];
            let addr = terms_address_of(&bytes);
            (state.market_policy, state.fee_policy, state.release_policy) = (addr, addr, addr);
            state.reserve_b = 0;
            Kind::Release(Release {
                verdict_cell: view.cell,
                outcome: view.branches[pick].0.clone(),
                terms: bytes,
            })
        }
    };
    let relationship_base = d32(&mut rng);
    let mut tree = Tree::new();
    let state_key = vault_state_key(&vault_id);
    tree.insert(state_key, vault_state_leaf_value(&state));
    let rel_key = relationship_key(&trader_genesis, &trader_device_id, &vault_id);
    if present {
        tree.insert(rel_key, vault_relationship_leaf_value(&trader_genesis, &trader_device_id, &relationship_base));
    }
    for _ in 0..others {
        let (g, d, base) = (d32(&mut rng), d32(&mut rng), d32(&mut rng));
        tree.insert(relationship_key(&g, &d, &vault_id), vault_relationship_leaf_value(&g, &d, &base));
    }
    let r_prev = tree.root();
    let witness = StepWitness {
        vault_id,
        state,
        token_a,
        token_b,
        fee_bps,
        hop: Hop {
            in_is_a: false,
            amount_in: 0,
            amount_out: 0,
        },
        kind,
        trader_genesis,
        trader_device_id,
        relationship_base,
        relationship_present: present,
        external_commitment: d32(&mut rng),
        attempt: rng.random_range(0..3),
        state_path: tree.path(&state_key),
        relationship_path: tree.path(&rel_key),
    };
    let public = step(&witness, &r_prev).expect("a valid terminal step");
    Fixture {
        witness,
        r_prev,
        public,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_chain_links() {
        let c = super::chain(7, 6);
        for w in c.windows(2) {
            assert_eq!(w[1].r_prev, w[0].public.r_next);
            assert_eq!(w[1].public.generation, w[0].public.generation + 1);
        }
        assert!(c.iter().any(|f| f.witness.relationship_present));
    }

    use super::*;

    /// Closes and releases of every kind are valid steps, retire the vault and only a release has an op digest; the
    /// largest signed terms take several BLAKE3 chunks.
    #[test]
    fn terminal_steps_are_valid() {
        let mut biggest = 0;
        for (seed, release) in [
            (1, None),
            (2, Some(Terms::Computed)),
            (3, Some(Terms::Signed { branches: 1 })),
            (4, Some(Terms::Signed { branches: 3 })),
            (5, Some(Terms::Signed { branches: ESCROW_MAX_BRANCHES })),
        ] {
            let f = terminal(seed, release, seed % 2 == 0, 2);
            assert_eq!(f.public.generation, f.witness.state.generation + 1);
            assert_eq!(f.public.op_digest == [0; 32], release.is_none());
            if let Kind::Release(r) = &f.witness.kind {
                biggest = biggest.max(r.terms.len());
                // Another outcome, another cell, or a trader no branch pays: refused.
                let mut bad = f.witness.clone();
                if let Kind::Release(r) = &mut bad.kind {
                    r.verdict_cell[0] ^= 1;
                }
                assert_eq!(step(&bad, &f.r_prev), Err("VerdictCellIsNotTheTerms"));
                let mut bad = f.witness.clone();
                bad.trader_genesis[0] ^= 1;
                assert!(step(&bad, &f.r_prev).is_err());
            } else {
                let mut bad = f.witness.clone();
                bad.trader_device_id[3] ^= 1;
                assert_eq!(step(&bad, &f.r_prev), Err("NotTheVaultOwner"));
            }
        }
        assert!(biggest > 1024, "the largest terms span several chunks: {biggest}");
    }

    /// The reference accepts a valid step, its post-root is the tree's after the two writes, and each kind of bad
    /// step is refused.
    #[test]
    fn reference_step_agrees_with_the_tree() {
        for (seed, present, others, attempt) in [(1, true, 3, 0), (2, false, 0, 5), (3, false, 6, 1)] {
            let f = fixture(seed, present, others, attempt);
            let w = &f.witness;
            // Rebuild the tree after the step and compare roots.
            let mut tree = Tree::new();
            let post = swap_vault_post(&w.state, w.fee_bps, &w.hop).unwrap();
            tree.insert(vault_state_key(&w.vault_id), vault_state_leaf_value(&post));
            let next = relationship_leaf_next(&w.relationship_base, &w.external_commitment);
            let rel_key = relationship_key(&w.trader_genesis, &w.trader_device_id, &w.vault_id);
            tree.insert(rel_key, vault_relationship_leaf_value(&w.trader_genesis, &w.trader_device_id, &next));
            let mut rng = StdRng::seed_from_u64(seed ^ 0x5eed);
            // Re-draw the other traders exactly as the fixture did.
            let _: (u64, u64, u64, bool, u64) = (
                rng.random_range(1..1 << 40),
                rng.random_range(0..1 << 20),
                rng.random_range(1 << 40..1 << 60),
                rng.random(),
                rng.random_range(1 << 40..1 << 60),
            );
            let _ = &mut rng;
            assert_eq!(f.public.generation, w.state.generation + 1);
            assert_eq!(f.public.r_prev, f.r_prev);
            assert_ne!(f.public.r_next, f.r_prev);
            if others == 0 {
                assert_eq!(f.public.r_next, tree.root(), "seed {seed}");
            }
            // Refusals.
            let mut bad = w.clone();
            bad.hop.amount_out += 1;
            assert!(step(&bad, &f.r_prev).is_err());
            let mut bad = w.clone();
            bad.fee_bps += 1;
            assert!(step(&bad, &f.r_prev).is_err());
            let mut bad = w.clone();
            bad.state_path[7][0] ^= 1;
            assert!(step(&bad, &f.r_prev).is_err());
            let mut bad = w.clone();
            bad.relationship_present = !present;
            assert!(step(&bad, &f.r_prev).is_err());
        }
    }
}
