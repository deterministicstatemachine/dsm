//! DSM Core's vault-step checks, ported line for line from `dsm_client/deterministic_state_machine/dsm/src` at
//! `origin/main` cc9e44b36 (2026-11-20), hashing with the `blake3` crate. This is the specification the leanVM program
//! (`guests/vault_step.py`) must agree with, and the source of its test inputs. Every function names its Core original.

pub type D32 = [u8; 32];

// ── crypto/blake3.rs, storage_object.rs ────────────────────────────────────

/// `dsm_domain_hasher`: `BLAKE3(tag ‖ 0x00 ‖ parts…)`.
pub fn h(tag: &[u8], parts: &[&[u8]]) -> D32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(&[0]);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

pub const TAG_VAULT_STATE_KEY: &[u8] = b"DSM/sofi/vault-state-key/v1";
pub const TAG_VAULT_LEAF_STATE: &[u8] = b"DSM/sofi/vault-leaf-state/v1";
pub const TAG_REL_KEY: &[u8] = b"DSM/sofi/rel-key/v1";
pub const TAG_REL_LEAF: &[u8] = b"DSM/sofi/rel-leaf/v1";
pub const TAG_SUCC_CELL_V2: &[u8] = b"DSM/sofi/succ-cell/v2";
pub const TAG_SUCC_ATTEMPT: &[u8] = b"DSM/sofi/succ-attempt/v1";
pub const TAG_MARKET_POLICY_OBJECT: &[u8] = b"DSM/market-policy-object/v1";
pub const TAG_FEE_POLICY_OBJECT: &[u8] = b"DSM/fee-policy-object/v1";
pub const TAG_STORAGE_OBJECT: &[u8] = b"DSM/storage-object";
pub const TAG_SMT_LEAF: &[u8] = b"DSM/economic-smt-leaf/v1";
pub const TAG_SMT_NODE: &[u8] = b"DSM/economic-smt-node/v1";
/// Not Core's: this research build's statement digest. 31 bytes, so with its NUL every field is limb-aligned.
pub const TAG_STATEMENT: &[u8] = b"DSM/research/vault-step-stmt/v1";

/// `storage_object::immutable_addr`: `H(storage-object ‖ N ‖ H(N ‖ payload))`.
pub fn immutable_addr(namespace: &[u8], payload: &[u8]) -> D32 {
    let inner = h(namespace, &[payload]);
    h(TAG_STORAGE_OBJECT, &[namespace, &inner])
}

// ── ccb ─────────────────────────────────────────────────────────────────────

pub const CLASS_MARKET_POLICY: u16 = 0x0007;
pub const CLASS_FEE_POLICY: u16 = 0x000A;
pub const CLASS_VAULT_STATE_LEAF: u16 = 0x004B;
pub const CLASS_VAULT_RELATIONSHIP_LEAF: u16 = 0x004C;
pub const SCHEMA_V1: u16 = 1;
pub const FAMILY_CONSTANT_PRODUCT_EXACT_INPUT: u16 = 0x0001;
pub const BETA_VERSION: u16 = 1;
pub const VAULT_STATUS_ACTIVE: u16 = 0x0001;
pub const BPS_DENOMINATOR: u32 = 10_000;

fn env(out: &mut Vec<u8>, class: u16) {
    out.extend(class.to_be_bytes());
    out.extend(SCHEMA_V1.to_be_bytes());
}

/// `ccb::state::MarketPolicy::encode` (the beta constant-product family).
pub fn market_policy_bytes(token_a: &D32, token_b: &D32) -> Vec<u8> {
    let mut out = Vec::new();
    env(&mut out, CLASS_MARKET_POLICY);
    out.extend(FAMILY_CONSTANT_PRODUCT_EXACT_INPUT.to_be_bytes());
    out.extend(BETA_VERSION.to_be_bytes());
    out.extend(token_a);
    out.extend(token_b);
    out
}

/// `ccb::state::FeePolicy::encode`.
pub fn fee_policy_bytes(fee_bps: u32) -> Vec<u8> {
    let mut out = Vec::new();
    env(&mut out, CLASS_FEE_POLICY);
    out.extend(fee_bps.to_be_bytes());
    out
}

/// `ccb::decode::policy_object_address` for the two classes a swap reads.
pub fn market_policy_addr(token_a: &D32, token_b: &D32) -> D32 {
    immutable_addr(TAG_MARKET_POLICY_OBJECT, &market_policy_bytes(token_a, token_b))
}
pub fn fee_policy_addr(fee_bps: u32) -> D32 {
    immutable_addr(TAG_FEE_POLICY_OBJECT, &fee_policy_bytes(fee_bps))
}

/// `sofi::wire::objects::VaultStateLeaf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStateLeaf {
    pub owner_genesis: D32,
    pub owner_device_id: D32,
    pub create_position: u64,
    pub market_policy: D32,
    pub fee_policy: D32,
    pub release_policy: D32,
    pub storage_set_id: D32,
    pub generation: u64,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub status: u16,
}

impl VaultStateLeaf {
    /// `VaultStateLeaf::encode`: 230 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        env(&mut out, CLASS_VAULT_STATE_LEAF);
        out.extend(self.owner_genesis);
        out.extend(self.owner_device_id);
        out.extend(self.create_position.to_be_bytes());
        out.extend(self.market_policy);
        out.extend(self.fee_policy);
        out.extend(self.release_policy);
        out.extend(self.storage_set_id);
        out.extend(self.generation.to_be_bytes());
        out.extend(self.reserve_a.to_be_bytes());
        out.extend(self.reserve_b.to_be_bytes());
        out.extend(self.status.to_be_bytes());
        out
    }
}

/// `VaultRelationshipLeaf::encode`: 100 bytes.
pub fn vault_relationship_leaf_bytes(genesis: &D32, device_id: &D32, leaf: &D32) -> Vec<u8> {
    let mut out = Vec::new();
    env(&mut out, CLASS_VAULT_RELATIONSHIP_LEAF);
    out.extend(genesis);
    out.extend(device_id);
    out.extend(leaf);
    out
}

// ── sofi/derive.rs ──────────────────────────────────────────────────────────

pub fn vault_state_key(vault_id: &D32) -> D32 {
    h(TAG_VAULT_STATE_KEY, &[vault_id])
}
pub fn vault_state_leaf_value(leaf: &VaultStateLeaf) -> D32 {
    h(TAG_VAULT_LEAF_STATE, &[&leaf.encode()])
}
pub fn vault_relationship_leaf_value(genesis: &D32, device_id: &D32, leaf: &D32) -> D32 {
    h(TAG_VAULT_LEAF_STATE, &[&vault_relationship_leaf_bytes(genesis, device_id, leaf)])
}
pub fn relationship_key(genesis: &D32, device_id: &D32, vault_id: &D32) -> D32 {
    h(TAG_REL_KEY, &[genesis, device_id, vault_id])
}
pub fn relationship_leaf_next(current_leaf: &D32, external_commitment: &D32) -> D32 {
    h(TAG_REL_LEAF, &[current_leaf, external_commitment])
}
pub fn successor_base_key(vault_id: &D32, parent_root: &D32) -> D32 {
    h(TAG_SUCC_CELL_V2, &[vault_id, parent_root])
}
pub fn successor_attempt_key(vault_id: &D32, parent_root: &D32, attempt: u64) -> D32 {
    let base = successor_base_key(vault_id, parent_root);
    if attempt == 0 {
        return base;
    }
    h(TAG_SUCC_ATTEMPT, &[&base, &attempt.to_be_bytes()])
}

// ── economic/tree.rs, merkle/batch_fold.rs ────────────────────────────────

pub const HEIGHT: usize = 256;
pub const ABSENT_LEAF: D32 = [0; 32];

pub fn econ_leaf(key: &D32, value: &D32) -> D32 {
    h(TAG_SMT_LEAF, &[key, value])
}
pub fn econ_node(left: &D32, right: &D32) -> D32 {
    h(TAG_SMT_NODE, &[left, right])
}
pub fn leaf_node(key: &D32, value: Option<&D32>) -> D32 {
    value.map_or(ABSENT_LEAF, |v| econ_leaf(key, v))
}
/// `merkle::sparse_merkle_tree::get_bit`: MSB-first within each byte.
pub fn get_bit(key: &D32, bit_index: usize) -> u8 {
    (key[bit_index / 8] >> (7 - bit_index % 8)) & 1
}
pub fn default_node(height: usize) -> D32 {
    static TABLE: std::sync::OnceLock<Vec<D32>> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = vec![ABSENT_LEAF];
        for _ in 0..HEIGHT {
            let child = t[t.len() - 1];
            t.push(econ_node(&child, &child));
        }
        t
    });
    table[height.min(HEIGHT)]
}

/// One fold entry: `batch_fold::FoldEntry`, its path leaf-to-root (`path[0]` the deepest sibling).
#[derive(Clone, Debug)]
pub struct FoldEntry {
    pub key: D32,
    pub pre: Option<D32>,
    pub post: Option<D32>,
    pub path: Vec<D32>,
}

fn sibling_at(entry: &FoldEntry, depth: usize) -> D32 {
    entry.path[HEIGHT - 1 - depth]
}

fn fold_single(entry: &FoldEntry, depth: usize) -> (D32, D32) {
    let mut pre = leaf_node(&entry.key, entry.pre.as_ref());
    let mut post = leaf_node(&entry.key, entry.post.as_ref());
    for level in (depth..HEIGHT).rev() {
        let sibling = sibling_at(entry, level);
        let (l_pre, r_pre, l_post, r_post) = if get_bit(&entry.key, level) == 0 {
            (pre, sibling, post, sibling)
        } else {
            (sibling, pre, sibling, post)
        };
        pre = econ_node(&l_pre, &r_pre);
        post = econ_node(&l_post, &r_post);
    }
    (pre, post)
}

fn subtree(depth: usize, entries: &[&FoldEntry]) -> Result<(D32, D32), &'static str> {
    if entries.len() == 1 {
        return Ok(fold_single(entries[0], depth));
    }
    let split = entries.partition_point(|e| get_bit(&e.key, depth) == 0);
    let (low, high) = entries.split_at(split);
    if low.is_empty() || high.is_empty() {
        let sibling = sibling_at(entries[0], depth);
        if entries.iter().any(|e| sibling_at(e, depth) != sibling) {
            return Err("InconsistentPath");
        }
        let (pre, post) = subtree(depth + 1, entries)?;
        return Ok(if low.is_empty() {
            (econ_node(&sibling, &pre), econ_node(&sibling, &post))
        } else {
            (econ_node(&pre, &sibling), econ_node(&post, &sibling))
        });
    }
    let (low_pre, low_post) = subtree(depth + 1, low)?;
    let (high_pre, high_post) = subtree(depth + 1, high)?;
    if low.iter().any(|e| sibling_at(e, depth) != high_pre) || high.iter().any(|e| sibling_at(e, depth) != low_pre)
    {
        return Err("InconsistentPath");
    }
    Ok((econ_node(&low_pre, &high_pre), econ_node(&low_post, &high_post)))
}

/// `batch_fold::batch_fold`: the pre- and post-roots of a write set.
pub fn batch_fold(entries: &[FoldEntry]) -> Result<(D32, D32), &'static str> {
    if entries.is_empty() {
        return Err("NoEntries");
    }
    if entries.windows(2).any(|w| w[0].key >= w[1].key) {
        return Err("KeysNotAscending");
    }
    let refs: Vec<&FoldEntry> = entries.iter().collect();
    subtree(0, &refs)
}

// ── dlv/route_commit.rs, sofi/validation.rs ────────────────────────────────

/// `constant_product_output_classified`, its refusals collapsed.
pub fn constant_product_output(input: u64, reserve_in: u64, reserve_out: u64, fee_bps: u32) -> Option<u64> {
    if input == 0 || reserve_in == 0 || reserve_out == 0 || fee_bps >= BPS_DENOMINATOR {
        return None;
    }
    let after_fee = u128::from(input).checked_mul(u128::from(BPS_DENOMINATOR - fee_bps))?;
    let denom = u128::from(reserve_in).checked_mul(u128::from(BPS_DENOMINATOR))?.checked_add(after_fee)?;
    let num = u128::from(reserve_out).checked_mul(after_fee)?;
    let out = num / denom;
    if out == 0 {
        return None;
    }
    u64::try_from(out).ok()
}

/// A swap hop as the step sees it: which side comes in, and the two amounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hop {
    pub in_is_a: bool,
    pub amount_in: u64,
    pub amount_out: u64,
}

/// `swap_vault_post`: the state after the hop, or why not.
pub fn swap_vault_post(state: &VaultStateLeaf, fee_bps: u32, hop: &Hop) -> Result<VaultStateLeaf, &'static str> {
    if state.status != VAULT_STATUS_ACTIVE {
        return Err("VaultIsNotActive");
    }
    let (reserve_in, reserve_out) = if hop.in_is_a {
        (state.reserve_a, state.reserve_b)
    } else {
        (state.reserve_b, state.reserve_a)
    };
    let priced = constant_product_output(hop.amount_in, reserve_in, reserve_out, fee_bps)
        .ok_or("PriceIsNotTheConstantProduct")?;
    if priced != hop.amount_out {
        return Err("PriceIsNotTheConstantProduct");
    }
    let new_in = reserve_in.checked_add(hop.amount_in).ok_or("reserve in")?;
    let new_out = reserve_out.checked_sub(hop.amount_out).ok_or("reserve out")?;
    if new_out == 0 {
        return Err("reserve out");
    }
    let generation = state.generation.checked_add(1).ok_or("vault generation")?;
    let (reserve_a, reserve_b) = if hop.in_is_a { (new_in, new_out) } else { (new_out, new_in) };
    Ok(VaultStateLeaf {
        generation,
        reserve_a,
        reserve_b,
        ..state.clone()
    })
}

// ── one step ────────────────────────────────────────────────────────────────

/// What the prover holds for one step (the statement's private inputs).
#[derive(Clone, Debug)]
pub struct StepWitness {
    pub vault_id: D32,
    pub state: VaultStateLeaf,
    pub token_a: D32,
    pub token_b: D32,
    pub fee_bps: u32,
    pub hop: Hop,
    pub trader_genesis: D32,
    pub trader_device_id: D32,
    /// The relationship base `h_j`; whether the vault's tree held it before (else the leaf was absent).
    pub relationship_base: D32,
    pub relationship_present: bool,
    pub external_commitment: D32,
    pub attempt: u64,
    /// Leaf-to-root paths against `R_prev`: the state leaf's and the relationship leaf's.
    pub state_path: Vec<D32>,
    pub relationship_path: Vec<D32>,
}

/// What a reader sees (the statement's public values).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepPublic {
    pub vault_id: D32,
    pub r_prev: D32,
    pub r_next: D32,
    pub generation: u64,
    pub external_commitment: D32,
    pub attempt_key: D32,
}

impl StepPublic {
    /// This research build's statement digest, the leanVM program's public input.
    pub fn digest(&self) -> D32 {
        h(
            TAG_STATEMENT,
            &[
                &self.vault_id,
                &self.r_prev,
                &self.r_next,
                &self.generation.to_be_bytes(),
                &self.external_commitment,
                &self.attempt_key,
            ],
        )
    }
}

/// Every check of `docs/plans/2026-11-22-vault-step-proof-statement.md` 1..9, as Core makes them, from the witness;
/// the public values if they all pass. `r_prev` is the claimed pre-root.
pub fn step(w: &StepWitness, r_prev: &D32) -> Result<StepPublic, &'static str> {
    // 2, and the policies the state commits: the market policy decodes only with a strictly ordered pair.
    if w.token_a >= w.token_b {
        return Err("TokenPairNotStrictlyOrdered");
    }
    if w.state.market_policy != market_policy_addr(&w.token_a, &w.token_b) {
        return Err("market policy does not address");
    }
    if w.fee_bps >= BPS_DENOMINATOR || w.state.fee_policy != fee_policy_addr(w.fee_bps) {
        return Err("fee policy does not address");
    }
    // 1, 3, 4, 5.
    let post = swap_vault_post(&w.state, w.fee_bps, &w.hop)?;
    // 6, 7, 8.
    let state_key = vault_state_key(&w.vault_id);
    let rel_key = relationship_key(&w.trader_genesis, &w.trader_device_id, &w.vault_id);
    let rel_pre = w
        .relationship_present
        .then(|| vault_relationship_leaf_value(&w.trader_genesis, &w.trader_device_id, &w.relationship_base));
    let next = relationship_leaf_next(&w.relationship_base, &w.external_commitment);
    let rel_post = vault_relationship_leaf_value(&w.trader_genesis, &w.trader_device_id, &next);
    let mut entries = vec![
        FoldEntry {
            key: state_key,
            pre: Some(vault_state_leaf_value(&w.state)),
            post: Some(vault_state_leaf_value(&post)),
            path: w.state_path.clone(),
        },
        FoldEntry {
            key: rel_key,
            pre: rel_pre,
            post: Some(rel_post),
            path: w.relationship_path.clone(),
        },
    ];
    entries.sort_by_key(|e| e.key);
    let (pre_root, post_root) = batch_fold(&entries)?;
    if pre_root != *r_prev {
        return Err("PreRootMismatch");
    }
    // 9.
    Ok(StepPublic {
        vault_id: w.vault_id,
        r_prev: *r_prev,
        r_next: post_root,
        generation: post.generation,
        external_commitment: w.external_commitment,
        attempt_key: successor_attempt_key(&w.vault_id, r_prev, w.attempt),
    })
}

// ── a sparse tree for fixtures ──────────────────────────────────────────────

/// A sparse 256-level tree of the economic hashes, for building fixtures: its root and any key's path.
pub struct Tree {
    leaves: std::collections::BTreeMap<D32, D32>,
}

impl Tree {
    pub fn new() -> Self {
        Self {
            leaves: Default::default(),
        }
    }

    pub fn insert(&mut self, key: D32, value: D32) {
        self.leaves.insert(key, value);
    }

    /// The node at `depth` over the keys agreeing with `prefix` on its first `depth` bits.
    fn node(&self, depth: usize, keys: &[(&D32, &D32)]) -> D32 {
        if keys.is_empty() {
            return default_node(HEIGHT - depth);
        }
        if depth == HEIGHT {
            return econ_leaf(keys[0].0, keys[0].1);
        }
        let split = keys.partition_point(|(k, _)| get_bit(k, depth) == 0);
        let (low, high) = keys.split_at(split);
        econ_node(&self.node(depth + 1, low), &self.node(depth + 1, high))
    }

    fn keys(&self) -> Vec<(&D32, &D32)> {
        self.leaves.iter().collect()
    }

    pub fn root(&self) -> D32 {
        self.node(0, &self.keys())
    }

    /// The leaf-to-root path at `key`, present or not.
    pub fn path(&self, key: &D32) -> Vec<D32> {
        let all = self.keys();
        let mut out = vec![[0; 32]; HEIGHT];
        for depth in 0..HEIGHT {
            let prefix = |k: &D32| (0..depth).all(|b| get_bit(k, b) == get_bit(key, b));
            let theirs: Vec<(&D32, &D32)> = all
                .iter()
                .copied()
                .filter(|(k, _)| prefix(k) && get_bit(k, depth) != get_bit(key, depth))
                .collect();
            out[HEIGHT - 1 - depth] = self.node(depth + 1, &theirs);
        }
        out
    }
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}
