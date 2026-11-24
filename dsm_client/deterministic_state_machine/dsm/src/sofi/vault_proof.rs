// SPDX-License-Identifier: Apache-2.0

//! Per-trade vault proofs (owner ruling, 2026-11-22: "Okay, good, then do
//! it." and "Do it. That's two.").
//!
//! Each trade leaves the vault's new state in one record: the vault's whole
//! tree at the new root (its state leaf and every relationship leaf), and a
//! leanVM proof that folds the previous record's proof with this step's
//! checks (`research/leanvm`, the vault step: Core's swap, close and release
//! arithmetic, both leaves' writes against `R_prev`, the attempt key). A
//! reader checks the newest record's one proof, back to the vault's accepted
//! genesis, and the one consumption it names, never the vault's history.
//!
//! What a record establishes, [`verify_record`] checks: the claims name this
//! vault, its accepted genesis root as the chain's first root, and the
//! record's root as its last; the attempt key is the one the record's parent
//! root and attempt derive; the leaves rebuild the record's root; the proof
//! verifies against the claims. That the record's trade consumed its parent
//! is checked by the chain walk from the parent (`resolve`): the one step a
//! reader judges.

use std::sync::Once;

use aggregation::{AggregateClaims, AggregateProof, OutputClaims, VaultStep};
use leanvm_isa::Prover as _;
use leanvm_prover::StableProver;

use crate::common::domain_tags::{
    TAG_DSM_SOFI_VAULT_PROOF_GENERATION_LOCATOR, TAG_DSM_SOFI_VAULT_PROOF_ROOT_LOCATOR,
};
use crate::crypto::blake3::dsm_domain_hasher;

use super::derive;
use super::frontier::{vault_tree_at, VaultTree, VaultTreeError};
use super::validation::VaultPostState;
use super::wire::{VaultRelationshipLeaf, VaultStateLeaf};

type D32 = [u8; 32];

/// The record's encoding version.
pub const RECORD_VERSION: u16 = 1;

/// The proof's code rate, as its log: rate 1/2, what the phone measurements
/// were taken at (2.3 to 3 s to prove, about 95 ms to verify, on an A16).
pub const LOG_INV_RATE: usize = 1;

/// The largest record a reader decodes: an immutable object's payload.
pub const MAX_RECORD_BYTES: usize = crate::storage_object::MAX_IMMUTABLE_PAYLOAD_BYTES;

/// One trade's record of a vault: its tree after the trade and the proof of
/// every step from the genesis to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRecord {
    pub vault_id: D32,
    /// The generation after the step.
    pub generation: u64,
    /// The root the step was built on, which the step's attempt key derives
    /// from.
    pub r_prev: D32,
    /// The attempt the step's trade was written at.
    pub attempt: u64,
    /// The root after the step.
    pub root: D32,
    /// The canonical bytes of every leaf of the vault's tree at `root`: the
    /// state leaf first, then each relationship leaf, keys ascending.
    pub leaves: Vec<Vec<u8>>,
    /// The proof's claims (`AggregateClaims::to_bytes`).
    pub claims: Vec<u8>,
    /// The proof (`AggregateProof::to_bytes`).
    pub proof: Vec<u8>,
}

/// Why a record establishes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofRefused {
    /// The bytes are not one canonical record.
    Encoding(&'static str),
    /// The record is another vault's.
    OtherVault,
    /// The claims do not decode, or carry more than the vault's chain.
    Claims(&'static str),
    /// The claims do not state what the record says.
    ClaimsDisagree(&'static str),
    /// The leaves do not rebuild the record's root.
    Tree(VaultTreeError),
    /// A relationship leaf's bytes are not one.
    RelationshipLeaf(crate::ccb::decode::DecodeError),
    /// The leaves are not in their canonical order.
    LeafOrder,
    /// The proof does not decode.
    ProofEncoding,
    /// The proof does not verify against the claims.
    ProofInvalid,
}

impl core::fmt::Display for ProofRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(why) => write!(f, "the vault proof record does not decode: {why}"),
            Self::OtherVault => write!(f, "the vault proof record is another vault's"),
            Self::Claims(why) => write!(f, "the vault proof's claims {why}"),
            Self::ClaimsDisagree(why) => {
                write!(
                    f,
                    "the vault proof's claims disagree with the record: {why}"
                )
            }
            Self::Tree(why) => write!(f, "the vault proof record's leaves: {why}"),
            Self::RelationshipLeaf(why) => {
                write!(f, "a relationship leaf of the vault proof record: {why:?}")
            }
            Self::LeafOrder => write!(f, "the vault proof record's leaves are not in order"),
            Self::ProofEncoding => write!(f, "the vault proof does not decode"),
            Self::ProofInvalid => write!(f, "the vault proof does not verify"),
        }
    }
}

impl std::error::Error for ProofRefused {}

/// Why a step was not proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveRefused {
    /// The generation is not one the vault step proves (its vault core
    /// writes more than the state leaf and the trader's relationship leaf).
    NotAProvableStep,
    /// The previous record is not this step's parent.
    NotTheParent,
    /// The tree the step is built on is not at the step's parent.
    TreeNotAtTheParent,
    /// The prover refused (`aggregation::AggregateError`).
    Prover(String),
    /// The leaves after the step have no canonical bytes.
    Leaf(String),
}

impl core::fmt::Display for ProveRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAProvableStep => {
                write!(f, "this generation is not a step the vault proof proves")
            }
            Self::NotTheParent => write!(f, "the previous vault proof is not this step's parent"),
            Self::TreeNotAtTheParent => write!(f, "the vault's tree is not at this step's parent"),
            Self::Prover(why) => write!(f, "proving the vault step: {why}"),
            Self::Leaf(why) => write!(f, "the vault's leaves: {why}"),
        }
    }
}

impl std::error::Error for ProveRefused {}

/// A record Core verified: the vault at `generation`, its whole tree, and
/// what the next step's proof folds.
#[derive(Debug, Clone)]
pub struct ProvenVaultHead {
    vault_id: D32,
    generation: u64,
    root: D32,
    r_prev: D32,
    external_commitment: D32,
    tree: VaultTree,
    claims: Vec<u8>,
    proof: Vec<u8>,
}

impl ProvenVaultHead {
    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn root(&self) -> &D32 {
        &self.root
    }
    /// The root the proven step was built on.
    pub fn r_prev(&self) -> &D32 {
        &self.r_prev
    }
    /// `E` of the proven step's trade.
    pub fn external_commitment(&self) -> &D32 {
        &self.external_commitment
    }
    /// The vault's whole tree at `root`.
    pub fn tree(&self) -> &VaultTree {
        &self.tree
    }
}

// ── where records are found ─────────────────────────────────────────────────

/// `H(vault-proof-generation-locator ‖ v ‖ u64be(g))`: where `vault_id`'s
/// records at `generation` are indexed.
pub fn generation_locator(vault_id: &D32, generation: u64) -> D32 {
    let mut hasher = dsm_domain_hasher(TAG_DSM_SOFI_VAULT_PROOF_GENERATION_LOCATOR);
    hasher.update(vault_id);
    hasher.update(&generation.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// `H(vault-proof-root-locator ‖ v ‖ R)`: where `vault_id`'s records whose
/// root is `root` are indexed.
pub fn root_locator(vault_id: &D32, root: &D32) -> D32 {
    let mut hasher = dsm_domain_hasher(TAG_DSM_SOFI_VAULT_PROOF_ROOT_LOCATOR);
    hasher.update(vault_id);
    hasher.update(root);
    *hasher.finalize().as_bytes()
}

/// The vault, generation and root a record's bytes name, decoded and nothing
/// else: what recognizes a record under its locators. Discovery only.
pub fn record_names(bytes: &[u8]) -> Result<(D32, u64, D32), ProofRefused> {
    ProofRecord::decode(bytes).map(|record| (record.vault_id, record.generation, record.root))
}

/// The vault's tree at its accepted genesis: the state leaf alone (SoFi
/// §19.8), what the first step is proven from.
pub fn genesis_tree(
    genesis: &super::lineage::AcceptedVaultGenesis,
) -> Result<VaultTree, ProveRefused> {
    let state = genesis.state().clone();
    let bytes = state
        .encode()
        .map_err(|e| ProveRefused::Leaf(e.to_string()))?;
    let value =
        derive::vault_state_leaf_value(&state).map_err(|e| ProveRefused::Leaf(e.to_string()))?;
    let rows = [(derive::vault_state_key(genesis.vault_id()), value, bytes)];
    vault_tree_at(genesis.vault_id(), genesis.genesis_root(), &rows)
        .map_err(|e| ProveRefused::Leaf(e.to_string()))
}

// ── the record's bytes ──────────────────────────────────────────────────────

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProofRefused> {
        if n > self.0.len() {
            return Err(ProofRefused::Encoding("short"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProofRefused> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32, ProofRefused> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, ProofRefused> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn bytes(&mut self) -> Result<&'a [u8], ProofRefused> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

impl ProofRecord {
    /// The record's canonical bytes: the version, the five fixed fields, the
    /// leaves, the claims and the proof, each variable part length-prefixed
    /// (u32, big-endian).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.proof.len() + self.claims.len() + 1024);
        out.extend(RECORD_VERSION.to_be_bytes());
        out.extend(self.vault_id);
        out.extend(self.generation.to_be_bytes());
        out.extend(self.r_prev);
        out.extend(self.attempt.to_be_bytes());
        out.extend(self.root);
        out.extend((self.leaves.len() as u32).to_be_bytes());
        for leaf in &self.leaves {
            push_bytes(&mut out, leaf);
        }
        push_bytes(&mut out, &self.claims);
        push_bytes(&mut out, &self.proof);
        out
    }

    /// A record from its canonical bytes; nothing is verified.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofRefused> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ProofRefused::Encoding("too large"));
        }
        let mut r = Reader(bytes);
        if u16::from_be_bytes(r.array()?) != RECORD_VERSION {
            return Err(ProofRefused::Encoding("version"));
        }
        let vault_id = r.array()?;
        let generation = r.u64()?;
        let r_prev = r.array()?;
        let attempt = r.u64()?;
        let root = r.array()?;
        let count = r.u32()? as usize;
        // Each leaf takes at least its length prefix: a forged count
        // allocates nothing the bytes cannot fill.
        if count > r.0.len() / 4 {
            return Err(ProofRefused::Encoding("leaf count"));
        }
        let mut leaves = Vec::with_capacity(count);
        for _ in 0..count {
            leaves.push(r.bytes()?.to_vec());
        }
        let claims = r.bytes()?.to_vec();
        let proof = r.bytes()?.to_vec();
        if !r.0.is_empty() {
            return Err(ProofRefused::Encoding("trailing bytes"));
        }
        Ok(Self {
            vault_id,
            generation,
            r_prev,
            attempt,
            root,
            leaves,
            claims,
            proof,
        })
    }
}

/// The canonical leaves of `tree`: the state leaf, then each relationship
/// leaf by key.
fn leaves_of(tree: &VaultTree) -> Result<Vec<Vec<u8>>, ProveRefused> {
    let mut leaves = vec![tree
        .state
        .encode()
        .map_err(|e| ProveRefused::Leaf(e.to_string()))?];
    leaves.extend(
        tree.relationships
            .values()
            .map(VaultRelationshipLeaf::encode),
    );
    Ok(leaves)
}

/// The rows `vault_tree_at` rebuilds a tree from, each leaf's key and value
/// derived from its own bytes, in the record's canonical order.
fn rows_of(vault_id: &D32, leaves: &[Vec<u8>]) -> Result<Vec<(D32, D32, Vec<u8>)>, ProofRefused> {
    let (state, relationships) = leaves
        .split_first()
        .ok_or(ProofRefused::Tree(VaultTreeError::NoStateLeaf))?;
    let state_leaf = VaultStateLeaf::decode(state)
        .map_err(|e| ProofRefused::Tree(VaultTreeError::StateDoesNotDecode(e)))?;
    let state_value = derive::vault_state_leaf_value(&state_leaf)
        .map_err(|e| ProofRefused::Tree(VaultTreeError::StateHasNoBytes(e)))?;
    let mut rows = vec![(
        derive::vault_state_key(vault_id),
        state_value,
        state.clone(),
    )];
    let mut last: Option<D32> = None;
    for bytes in relationships {
        let leaf = VaultRelationshipLeaf::decode(bytes).map_err(ProofRefused::RelationshipLeaf)?;
        let key = derive::relationship_key(&leaf.trader_genesis, &leaf.trader_device_id, vault_id);
        if last.is_some_and(|last| last >= key) {
            return Err(ProofRefused::LeafOrder);
        }
        last = Some(key);
        rows.push((
            key,
            derive::vault_relationship_leaf_value(&leaf),
            bytes.clone(),
        ));
    }
    Ok(rows)
}

/// Check `bytes` as `vault_id`'s record, its chain starting at
/// `genesis_root`, the root of the genesis this verifier accepted.
pub fn verify_record(
    bytes: &[u8],
    vault_id: &D32,
    genesis_root: &D32,
) -> Result<ProvenVaultHead, ProofRefused> {
    let record = ProofRecord::decode(bytes)?;
    if record.vault_id != *vault_id {
        return Err(ProofRefused::OtherVault);
    }
    let claims =
        AggregateClaims::from_bytes(&record.claims).ok_or(ProofRefused::Claims("do not decode"))?;
    if !claims.lean_xmss.is_empty()
        || !claims.lean_sphincs.is_empty()
        || claims.da_commitment.is_some()
    {
        return Err(ProofRefused::Claims("carry more than the vault's chain"));
    }
    let chain = claims
        .vault
        .ok_or(ProofRefused::Claims("carry no vault chain"))?;
    let agree = |ok: bool, what: &'static str| {
        if ok {
            Ok(())
        } else {
            Err(ProofRefused::ClaimsDisagree(what))
        }
    };
    agree(chain.vault_id == *vault_id, "vault")?;
    agree(
        chain.r_first == *genesis_root,
        "the chain does not start at the accepted genesis",
    )?;
    agree(chain.r_last == record.root, "root")?;
    agree(chain.generation == record.generation, "generation")?;
    agree(
        chain.attempt_key
            == derive::successor_attempt_key(vault_id, &record.r_prev, record.attempt),
        "attempt key",
    )?;
    let rows = rows_of(vault_id, &record.leaves)?;
    let tree = vault_tree_at(vault_id, &record.root, &rows).map_err(ProofRefused::Tree)?;
    agree(
        tree.state.generation == record.generation,
        "the state leaf's generation",
    )?;
    // The costly check last.
    let proof = AggregateProof::from_bytes(&record.proof).ok_or(ProofRefused::ProofEncoding)?;
    if !proof.verify(&claims) {
        return Err(ProofRefused::ProofInvalid);
    }
    Ok(ProvenVaultHead {
        vault_id: *vault_id,
        generation: record.generation,
        root: record.root,
        r_prev: record.r_prev,
        external_commitment: chain.external_commitment,
        tree,
        claims: record.claims,
        proof: record.proof,
    })
}

/// Prove the generation `post` and return its record: the step's checks,
/// folded onto `prev`'s proof when the step is past the genesis. `tree` is
/// the vault's whole tree at `post`'s parent root. Takes a few seconds on a
/// phone, one proof at a time.
pub fn prove_step(
    prev: Option<&ProvenVaultHead>,
    tree: &VaultTree,
    post: &VaultPostState,
) -> Result<ProofRecord, ProveRefused> {
    let witness = post.proof_witness().ok_or(ProveRefused::NotAProvableStep)?;
    let attempt = match post.step() {
        crate::shared_lineage::BundleStep::Vault { attempt, .. } => *attempt,
        crate::shared_lineage::BundleStep::Reserve { .. } => {
            return Err(ProveRefused::NotAProvableStep)
        }
    };
    if tree.tree.root() != *post.pre_root() || tree.state.generation != post.pre_generation() {
        return Err(ProveRefused::TreeNotAtTheParent);
    }
    let children = match prev {
        Some(prev) => {
            if prev.vault_id != *post.vault_id()
                || prev.generation != post.pre_generation()
                || prev.root != *post.pre_root()
            {
                return Err(ProveRefused::NotTheParent);
            }
            let claims = AggregateClaims::from_bytes(&prev.claims)
                .ok_or_else(|| ProveRefused::Prover("the previous claims do not decode".into()))?;
            let proof = AggregateProof::from_bytes(&prev.proof)
                .ok_or_else(|| ProveRefused::Prover("the previous proof does not decode".into()))?;
            vec![(claims, proof)]
        }
        // The first step's chain starts at its own parent: the genesis.
        None if post.pre_generation() == 0 => Vec::new(),
        None => return Err(ProveRefused::NotTheParent),
    };
    static INIT: Once = Once::new();
    INIT.call_once(StableProver::init);
    let step = VaultStep {
        witness: witness.clone(),
        r_prev: *post.pre_root(),
    };
    let (claims, proof, _) = aggregation::aggregate_with_vault::<StableProver>(
        &children,
        Vec::new(),
        Vec::new(),
        None,
        OutputClaims::All,
        LOG_INV_RATE,
        Some(&step),
    )
    .map_err(|e| ProveRefused::Prover(format!("{e:?}")))?;
    let mut after = tree.clone();
    after.state = post.state().clone();
    if let Some((key, leaf)) = post.relationship() {
        after.relationships.insert(*key, *leaf);
    }
    Ok(ProofRecord {
        vault_id: *post.vault_id(),
        generation: post.generation(),
        r_prev: *post.pre_root(),
        attempt,
        root: *post.root(),
        leaves: leaves_of(&after)?,
        claims: claims.to_bytes(),
        proof: proof.to_bytes(),
    })
}

#[cfg(test)]
mod tests {
    //! A record of one proven step, from the vault step's own fixture: the
    //! honest record verifies, and every field a reader relies on, changed,
    //! is refused.

    use super::*;
    use vault_step::reference as vs;

    /// One proven swap of a vault whose tree holds its state leaf alone, the
    /// trader's leaf absent: the record, and the root its chain starts at.
    fn proven() -> (ProofRecord, D32) {
        let f = vault_step::fixture::first_trade(7);
        let w = &f.witness;
        static INIT: Once = Once::new();
        INIT.call_once(StableProver::init);
        let (claims, proof, _) = aggregation::aggregate_with_vault::<StableProver>(
            &[],
            Vec::new(),
            Vec::new(),
            None,
            OutputClaims::All,
            LOG_INV_RATE,
            Some(&VaultStep {
                witness: w.clone(),
                r_prev: f.r_prev,
            }),
        )
        .expect("the fixture's step proves");
        let post = vs::swap_vault_post(&w.state, w.fee_bps, &w.hop).expect("the fixture's swap");
        let state = VaultStateLeaf {
            owner_genesis: post.owner_genesis,
            owner_device_id: post.owner_device_id,
            create_position: post.create_position,
            market_policy: post.market_policy,
            fee_policy: post.fee_policy,
            release_policy: post.release_policy,
            storage_set_id: post.storage_set_id,
            generation: post.generation,
            reserve_a: post.reserve_a,
            reserve_b: post.reserve_b,
            status: post.status,
        };
        let relationship = VaultRelationshipLeaf {
            trader_genesis: w.trader_genesis,
            trader_device_id: w.trader_device_id,
            leaf: derive::relationship_leaf_next(&w.relationship_base, &w.external_commitment),
        };
        let record = ProofRecord {
            vault_id: w.vault_id,
            generation: f.public.generation,
            r_prev: f.r_prev,
            attempt: w.attempt,
            root: f.public.r_next,
            leaves: vec![
                state.encode().expect("the post state encodes"),
                relationship.encode(),
            ],
            claims: claims.to_bytes(),
            proof: proof.to_bytes(),
        };
        (record, f.r_prev)
    }

    /// The honest record verifies, and Core's own leaf hashes rebuild the
    /// root the leanVM step reached: the step and Core agree. Each field a
    /// reader relies on, changed, is refused.
    #[test]
    fn a_proven_step_verifies_and_each_relied_on_field_changed_is_refused() {
        let (record, start) = proven();
        let vault_id = record.vault_id;
        let head = verify_record(&record.encode(), &vault_id, &start).expect("the honest record");
        assert_eq!(
            (head.generation(), *head.root(), *head.r_prev()),
            (record.generation, record.root, record.r_prev)
        );
        assert_eq!(head.tree().tree.root(), record.root);

        let refused = |changed: &ProofRecord, start: &D32| {
            verify_record(&changed.encode(), &vault_id, start).expect_err("refused")
        };
        // Another genesis.
        let mut other_start = start;
        other_start[0] ^= 1;
        assert!(matches!(
            refused(&record, &other_start),
            ProofRefused::ClaimsDisagree(..)
        ));
        // Another root, generation or attempt than the proof's.
        let mut changed = record.clone();
        changed.root[3] ^= 1;
        assert!(matches!(
            refused(&changed, &start),
            ProofRefused::ClaimsDisagree(..)
        ));
        let mut changed = record.clone();
        changed.generation += 1;
        assert!(matches!(
            refused(&changed, &start),
            ProofRefused::ClaimsDisagree(..)
        ));
        let mut changed = record.clone();
        changed.attempt += 1;
        assert!(matches!(
            refused(&changed, &start),
            ProofRefused::ClaimsDisagree(..)
        ));
        // Leaves that are not the tree at the root.
        let mut changed = record.clone();
        changed.leaves.pop();
        assert!(matches!(refused(&changed, &start), ProofRefused::Tree(..)));
        let mut changed = record.clone();
        changed.leaves.reverse();
        assert!(matches!(refused(&changed, &start), ProofRefused::Tree(..)));
        // Another vault's record.
        assert_eq!(
            verify_record(&record.encode(), &[0xAB; 32], &start).expect_err("refused"),
            ProofRefused::OtherVault
        );
        // A trailing byte, and a proof with one byte changed.
        let mut bytes = record.encode();
        bytes.push(0);
        assert!(matches!(
            verify_record(&bytes, &vault_id, &start).expect_err("refused"),
            ProofRefused::Encoding(..)
        ));
        let mut changed = record.clone();
        let at = changed.proof.len() / 2;
        changed.proof[at] ^= 0x10;
        assert!(matches!(
            refused(&changed, &start),
            ProofRefused::ProofInvalid | ProofRefused::ProofEncoding
        ));
    }

    /// A record's bytes decode to the record they encode, and a forged leaf
    /// count allocates nothing.
    #[test]
    fn a_record_round_trips_and_a_forged_count_is_refused() {
        let record = ProofRecord {
            vault_id: [1; 32],
            generation: 3,
            r_prev: [2; 32],
            attempt: 1,
            root: [3; 32],
            leaves: vec![vec![4; 10], vec![5; 20]],
            claims: vec![6; 7],
            proof: vec![7; 9],
        };
        assert_eq!(ProofRecord::decode(&record.encode()), Ok(record.clone()));
        let mut bytes = record.encode();
        // The leaf count sits after the version and the five fixed fields.
        let count_at = 2 + 32 + 8 + 32 + 8 + 32;
        bytes[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            ProofRecord::decode(&bytes),
            Err(ProofRefused::Encoding("leaf count"))
        );
    }
}
