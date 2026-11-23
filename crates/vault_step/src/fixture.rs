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
    let (owner_genesis, owner_device_id, release_policy, storage_set_id) = (d32(), d32(), d32(), d32());
    let (trader_genesis, trader_device_id, relationship_base, external_commitment) = (d32(), d32(), d32(), d32());
    let fee_bps = 30;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5eed);
    let state = VaultStateLeaf {
        owner_genesis,
        owner_device_id,
        create_position: rng.random_range(1..1 << 40),
        market_policy: market_policy_addr(&token_a, &token_b),
        fee_policy: fee_policy_addr(fee_bps),
        release_policy,
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
        release_policy: d32(&mut rng),
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
