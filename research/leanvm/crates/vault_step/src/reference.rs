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
pub const TAG_VAULT_ID: &[u8] = b"DSM/sofi/vault-id/v1";
pub const TAG_RELEASE_POLICY_OBJECT: &[u8] = b"DSM/release-policy-object/v1";
pub const TAG_ESCROW_TERMS_OBJECT: &[u8] = b"DSM/escrow/terms-object/v1";
pub const TAG_ESCROW_OUTCOME_TABLE: &[u8] = b"DSM/escrow/outcome-table/v1";
pub const TAG_ESCROW_VERDICT_CELL: &[u8] = b"DSM/escrow/verdict-cell/v1";
pub const TAG_ESCROW_COMPUTED_TABLE: &[u8] = b"DSM/escrow/computed-table/v1";
pub const TAG_ESCROW_COMPUTED_MATCH: &[u8] = b"DSM/escrow/computed-match/v1";
/// Not Core's: this research build's digest of what a release names, its verdict cell and outcome (`op_digest`).
pub const TAG_RELEASE_OP: &[u8] = b"DSM/research/vault-release-op/v1";
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
pub const VAULT_STATUS_RETIRED: u16 = 0x0002;
pub const CLASS_RELEASE_POLICY: u16 = 0x0009;
pub const CLASS_ESCROW_TERMS: u16 = 0x0063;
pub const CLASS_ESCROW_COMPUTED_TERMS: u16 = 0x0067;
pub const SCHEMA_V2: u16 = 2;
pub const FAMILY_OWNER_LOCAL_FULL_CLOSE: u16 = 0x0001;
/// `sigalg::SPHINCS_PLUS_SPX256F`, the one signature algorithm, and its key width.
pub const SPX256F: u16 = 0x0002;
pub const SPX256F_KEY: usize = 64;
pub const ESCROW_MAX_OUTCOME_BYTES: usize = 64;
pub const ESCROW_MAX_BRANCHES: usize = 16;
pub const ESCROW_MAX_SIGNERS: usize = 4;
pub const COMPUTED_LABELS: [&[u8]; 3] = [b"a-wins", b"b-wins", b"void"];
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

/// `ccb::ReleasePolicy::beta_owner_local_full_close().encode()`: the one release policy a market vault names.
pub fn release_policy_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    env(&mut out, CLASS_RELEASE_POLICY);
    out.extend(FAMILY_OWNER_LOCAL_FULL_CLOSE.to_be_bytes());
    out.extend(BETA_VERSION.to_be_bytes());
    out
}
pub fn release_policy_addr() -> D32 {
    immutable_addr(TAG_RELEASE_POLICY_OBJECT, &release_policy_bytes())
}

/// `sofi::escrow::terms_address_of`.
pub fn terms_address_of(bytes: &[u8]) -> D32 {
    immutable_addr(TAG_ESCROW_TERMS_OBJECT, bytes)
}

/// `derive::vault_id`: `H(vault-id/v1 ‖ G_o ‖ DevID_o ‖ u64be(p_create))`.
pub fn vault_id(owner_genesis: &D32, owner_device_id: &D32, create_position: u64) -> D32 {
    h(TAG_VAULT_ID, &[owner_genesis, owner_device_id, &create_position.to_be_bytes()])
}

/// Escrow terms as a release reads them (`EscrowKind::decode`, `verdict_cell_of` / `match_cell_of`, `recipient`):
/// the cell the terms bind the vault to, and each branch's label and recipient. Signed terms (`0x0063`) or computed
/// terms (`0x0067`); anything else, or any byte left over, does not decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowView {
    pub cell: D32,
    pub branches: Vec<(Vec<u8>, D32, D32)>,
    /// Signed terms' outcome table as `τ` hashes it (`OutcomeTable::digest_preimage`); empty for computed terms.
    pub table: Vec<u8>,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let out = self.b.get(self.i..self.i + n).ok_or("short")?;
        self.i += n;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<usize, &'static str> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn d32(&mut self) -> Result<D32, &'static str> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn count(&mut self, min: usize, max: usize) -> Result<usize, &'static str> {
        let n = self.u32()?;
        if n < min || n > max { Err("count") } else { Ok(n) }
    }
    /// `read_var_bytes`.
    fn var(&mut self, max: usize) -> Result<&'a [u8], &'static str> {
        let n = self.count(1, max)?;
        self.take(n)
    }
    /// `read_key`: the algorithm and a key of its width; its canonical bytes.
    fn key(&mut self) -> Result<&'a [u8], &'static str> {
        let start = self.i;
        if self.u16()? != SPX256F || self.u32()? != SPX256F_KEY {
            return Err("key");
        }
        self.take(SPX256F_KEY)?;
        Ok(&self.b[start..self.i])
    }
}

pub fn decode_escrow(bytes: &[u8]) -> Result<EscrowView, &'static str> {
    let mut c = Cursor { b: bytes, i: 0 };
    let class = c.u16()?;
    let schema = c.u16()?;
    let _token = c.d32()?;
    let y = c.d32()?;
    let view = match (class, schema) {
        (CLASS_ESCROW_TERMS, SCHEMA_V1) => {
            let n = c.count(1, ESCROW_MAX_BRANCHES)?;
            // τ's preimage (`OutcomeTable::digest_preimage`): u8 counts where the terms have u32s, no recipients.
            let mut table = vec![n as u8];
            let mut branches = Vec::new();
            let mut last: Option<&[u8]> = None;
            for _ in 0..n {
                let label = c.var(ESCROW_MAX_OUTCOME_BYTES)?;
                if last.is_some_and(|l| l >= label) {
                    return Err("branches not strictly ascending");
                }
                last = Some(label);
                table.extend((label.len() as u32).to_be_bytes());
                table.extend(label);
                let ns = c.count(1, ESCROW_MAX_SIGNERS)?;
                table.push(ns as u8);
                let mut last_key: Option<&[u8]> = None;
                for _ in 0..ns {
                    let key = c.key()?;
                    if last_key.is_some_and(|k| k >= key) {
                        return Err("signers not strictly ascending");
                    }
                    last_key = Some(key);
                    table.extend(key);
                }
                branches.push((label.to_vec(), c.d32()?, c.d32()?));
            }
            let tau = h(TAG_ESCROW_OUTCOME_TABLE, &[&table]);
            EscrowView {
                cell: h(TAG_ESCROW_VERDICT_CELL, &[&y, &tau]),
                branches,
                table,
            }
        }
        (CLASS_ESCROW_COMPUTED_TERMS, SCHEMA_V2) => {
            // The computed table's canonical bytes, `τ_c`'s preimage: program, setup digest, two keys, two commitments.
            let start = c.i;
            c.take(64)?;
            let a = c.key()?;
            let b = c.key()?;
            if a == b {
                return Err("session keys not distinct");
            }
            c.take(64)?;
            let tau_c = h(TAG_ESCROW_COMPUTED_TABLE, &[&bytes[start..c.i]]);
            if c.count(3, 3)? != 3 {
                return Err("count");
            }
            let mut branches = Vec::new();
            for want in COMPUTED_LABELS {
                let label = c.var(ESCROW_MAX_OUTCOME_BYTES)?;
                if label != want {
                    return Err("computed labels");
                }
                branches.push((label.to_vec(), c.d32()?, c.d32()?));
            }
            EscrowView {
                cell: h(TAG_ESCROW_COMPUTED_MATCH, &[&y, &tau_c]),
                branches,
                table: Vec::new(),
            }
        }
        _ => return Err("not escrow terms"),
    };
    if c.i != bytes.len() {
        return Err("trailing bytes");
    }
    Ok(view)
}

/// `validation::retire_vault_post`: the next generation, every reserve released, retired.
pub fn retire_vault_post(state: &VaultStateLeaf) -> Result<VaultStateLeaf, &'static str> {
    Ok(VaultStateLeaf {
        generation: state.generation.checked_add(1).ok_or("vault generation")?,
        reserve_a: 0,
        reserve_b: 0,
        status: VAULT_STATUS_RETIRED,
        ..state.clone()
    })
}

/// What a release names (`SettlementBody::Release`): the verdict cell and the outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub terms: Vec<u8>,
    pub verdict_cell: D32,
    pub outcome: Vec<u8>,
}

/// This research build's digest of what a release names: `H(vault-release-op ‖ K_verdict ‖ u32be(|o|) ‖ o)`.
pub fn release_op_digest(verdict_cell: &D32, outcome: &[u8]) -> D32 {
    h(TAG_RELEASE_OP, &[verdict_cell, &(outcome.len() as u32).to_be_bytes(), outcome])
}

/// The operation a step is (`SettlementBody`'s three branches): a swap hop, the owner's full close, or an escrow
/// vault's release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Swap,
    Close,
    Release(Release),
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
    // Core's paths are `[D32; FOLD_HEIGHT]`: a path of any other length is no path.
    if entries.iter().any(|e| e.path.len() != HEIGHT) {
        return Err("PathLength");
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepWitness {
    pub vault_id: D32,
    pub state: VaultStateLeaf,
    pub token_a: D32,
    pub token_b: D32,
    pub fee_bps: u32,
    /// The hop, for a swap; zero otherwise.
    pub hop: Hop,
    /// Which operation the step is.
    pub kind: Kind,
    pub trader_genesis: D32,
    pub trader_device_id: D32,
    /// The relationship base `h_j`; whether the vault's tree held it before (else the leaf was absent).
    ///
    /// When the leaf is absent, nothing in the vault's step pins the base: Core pins it by agreement with the trader's
    /// own core (`T°`, `validation.rs` `relationship_bases`), the trader's side of the trade, which the statement puts
    /// outside the step (its row 12). The vault-step proof alone leaves it free there.
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
    /// A release's `release_op_digest`; zeros for a swap or a close.
    pub op_digest: D32,
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
                &self.op_digest,
            ],
        )
    }
}

/// Every check of `docs/plans/2026-11-22-vault-step-proof-statement.md` 1..9, as Core makes them, from the witness;
/// the public values if they all pass. `r_prev` is the claimed pre-root.
pub fn step(w: &StepWitness, r_prev: &D32) -> Result<StepPublic, &'static str> {
    if w.state.status != VAULT_STATUS_ACTIVE {
        return Err("VaultIsNotActive");
    }
    let s = &w.state;
    let post = match &w.kind {
        Kind::Swap | Kind::Close => {
            // A market's three policies (`Policies::resolve`): the market policy decodes only with a strictly ordered
            // pair, the fee policy with a fee below the denominator, the release policy is the one beta profile.
            if w.token_a >= w.token_b {
                return Err("TokenPairNotStrictlyOrdered");
            }
            if s.market_policy != market_policy_addr(&w.token_a, &w.token_b) {
                return Err("market policy does not address");
            }
            if w.fee_bps >= BPS_DENOMINATOR || s.fee_policy != fee_policy_addr(w.fee_bps) {
                return Err("fee policy does not address");
            }
            if s.release_policy != release_policy_addr() {
                return Err("release policy does not address");
            }
            if w.kind == Kind::Swap {
                swap_vault_post(s, w.fee_bps, &w.hop)?
            } else {
                // `validate_close`: the origin owner, the owner's own vault id, everything out.
                if (w.trader_genesis, w.trader_device_id) != (s.owner_genesis, s.owner_device_id) {
                    return Err("NotTheVaultOwner");
                }
                if vault_id(&s.owner_genesis, &s.owner_device_id, s.create_position) != w.vault_id {
                    return Err("VaultIdIsNotTheOwnersDerivation");
                }
                retire_vault_post(s)?
            }
        }
        Kind::Release(r) => {
            // `validate_release`: the owner's own vault id, the whole held amount, escrow terms all three slots name,
            // the cell they bind, and the named outcome's branch paying this trader.
            if vault_id(&s.owner_genesis, &s.owner_device_id, s.create_position) != w.vault_id {
                return Err("VaultIdIsNotTheOwnersDerivation");
            }
            if s.reserve_a == 0 || s.reserve_b != 0 {
                return Err("ReleaseIsNotTheWholeAmount");
            }
            let addr = terms_address_of(&r.terms);
            if s.market_policy != addr || s.fee_policy != addr || s.release_policy != addr {
                return Err("TermsAreNotEscrow");
            }
            let view = decode_escrow(&r.terms)?;
            if view.cell != r.verdict_cell {
                return Err("VerdictCellIsNotTheTerms");
            }
            match view.branches.iter().find(|(label, _, _)| *label == r.outcome) {
                None => return Err("OutcomeHasNoBranch"),
                Some((_, g, d)) if (*g, *d) != (w.trader_genesis, w.trader_device_id) => {
                    return Err("NotTheBranchRecipient");
                }
                Some(_) => {}
            }
            retire_vault_post(s)?
        }
    };
    let (pre_root, public) = statement_for(w, r_prev, &post)?;
    if pre_root != *r_prev {
        return Err("PreRootMismatch");
    }
    Ok(public)
}

/// The statement a step with post-state `post` would publish, and the pre-root its paths fold to, with none of
/// `step`'s checks: what a prover who skips them would claim. Tests use it to forge consistent statements.
pub fn statement_for(w: &StepWitness, r_prev: &D32, post: &VaultStateLeaf) -> Result<(D32, StepPublic), &'static str> {
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
            post: Some(vault_state_leaf_value(post)),
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
    // 9.
    Ok((
        pre_root,
        StepPublic {
            vault_id: w.vault_id,
            r_prev: *r_prev,
            r_next: post_root,
            generation: post.generation,
            external_commitment: w.external_commitment,
            attempt_key: successor_attempt_key(&w.vault_id, r_prev, w.attempt),
            op_digest: match &w.kind {
                Kind::Release(r) => release_op_digest(&r.verdict_cell, &r.outcome),
                _ => [0; 32],
            },
        },
    ))
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
