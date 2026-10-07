// SPDX-License-Identifier: Apache-2.0

//! The owner baseline and the reader's witness (SoFi Amendment S24).
//!
//! A party that holds nothing of a vault starts from the latest baseline its
//! owner signed, not from the genesis. The baseline is three objects, and
//! each says one thing:
//!
//! - [`VaultFrontierV1`] — the vault's root at one generation. Economic state
//!   only: `c_f = H(vault-frontier/v1; CCB)`.
//! - [`OwnerBaselineAuthV1`] — `c_f`, and the owner-authority position the
//!   signer is proven at. `c_n = H(vault-baseline/v1; CCB)`.
//! - An `AnchorPresentationV3` over `c_n`, by the owner.
//!
//! [`authenticate_frontier_owner`] checks them in that order and is the only
//! way to a [`VerifiedFrontier`]. Authority and economic state meet only at
//! `frontier_commitment`, so a change in the owner's authority lineage
//! changes no root and no parent identity.
//!
//! What a reader then holds is a [`VaultWitness`]: the vault's state leaf
//! with its path, and the reader's own relationship leaf (or its absence)
//! with its path, under one authenticated root. Constant in size, whatever
//! the vault's age or the number of its traders. It is advanced through each
//! generation's write set ([`VaultWitness::advance`]): a path is specific to
//! its root, and the receipt's own paths recompute every sibling it wrote.

use crate::common::domain_tags::{
    TAG_DSM_SOFI_VAULT_BASELINE, TAG_DSM_SOFI_VAULT_FRONTIER, TAG_DSM_SOFI_VAULT_FRONTIER_OBJECT,
};
use crate::core::identity::authority_resolver::{
    resolve_owner_authority_at_position, OwnerAuthorityAtPosition, PresentedIdentity,
    ResolveFailure,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::dlv::vault_state_anchor_v3::{verify_anchor_v3_candidate, SignedVaultStateAnchorV3};
use crate::economic::tree::{leaf_node, root_from_path, EconomicSmt, ECONOMIC_SMT_HEIGHT};

use super::derive;
use super::lineage::AcceptedVaultGenesis;
use super::smt::fold::{advance_path, AdvanceError};
use super::validation::VaultPostState;
use super::wire::{
    FrontierRelationship, OwnerBaselineAuthV1, SofiWireError, VaultFrontierV1,
    VaultFrontierWitnessV1, VaultRelationshipLeaf, VaultStateLeaf,
};

type D32 = [u8; 32];
type Path = [D32; ECONOMIC_SMT_HEIGHT];

fn tagged(tag: crate::crypto::domain::TaggedHashDomain<'static>, bytes: &[u8]) -> D32 {
    let mut h = dsm_domain_hasher(tag);
    h.update(bytes);
    *h.finalize().as_bytes()
}

/// `c_f = H(vault-frontier/v1; CCB(VaultFrontierV1))`.
pub fn frontier_commitment(frontier: &VaultFrontierV1) -> D32 {
    tagged(TAG_DSM_SOFI_VAULT_FRONTIER, &frontier.encode())
}

/// `c_n = H(vault-baseline/v1; CCB(OwnerBaselineAuthV1))` — what the owner's
/// anchor signs.
pub fn baseline_commitment(auth: &OwnerBaselineAuthV1) -> D32 {
    tagged(TAG_DSM_SOFI_VAULT_BASELINE, &auth.encode())
}

/// The immutable-store address of a frontier, a baseline's authentication
/// object, a frontier witness or a baseline's presentation.
pub fn frontier_object_addr(bytes: &[u8]) -> D32 {
    crate::storage_object::immutable_addr(TAG_DSM_SOFI_VAULT_FRONTIER_OBJECT, bytes)
}

/// A frontier whose root the vault's owner signed, as Core authenticated it.
/// Private fields and one constructor, [`authenticate_frontier_owner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFrontier {
    frontier: VaultFrontierV1,
    commitment: D32,
    owner_genesis: D32,
    owner: OwnerAuthorityAtPosition,
}

impl VerifiedFrontier {
    pub fn frontier(&self) -> &VaultFrontierV1 {
        &self.frontier
    }

    /// `c_f`: two baselines of one vault at one generation are one frontier
    /// exactly when this agrees.
    pub fn commitment(&self) -> &D32 {
        &self.commitment
    }

    /// The owner authority the baseline's signer was proven to hold.
    pub fn owner(&self) -> &OwnerAuthorityAtPosition {
        &self.owner
    }
}

fn invalid(msg: impl Into<String>) -> ResolveFailure {
    ResolveFailure::Invalid(msg.into())
}

/// Authenticate an owner baseline of `genesis`'s vault, in the order SoFi
/// Amendment S24 fixes:
///
/// 1. the anchor's candidate key signed `c_n`, and `auth_bytes` re-hash to it;
/// 2. P0–P6 at the position `auth_bytes` commits prove the accepted genesis's
///    owner, and the proven key is the candidate, byte for byte;
/// 3. `frontier_bytes` re-hash to the `frontier_commitment` `auth_bytes`
///    binds, and the frontier names this vault.
///
/// Only then is the frontier's root accepted. Every failure is the
/// resolver's class: material missing is `Absent` or `Incomplete`, anything
/// that does not verify is `Invalid`.
pub fn authenticate_frontier_owner(
    anchor: &SignedVaultStateAnchorV3,
    auth_bytes: &[u8],
    frontier_bytes: &[u8],
    presented: &PresentedIdentity<'_>,
    genesis: &AcceptedVaultGenesis,
) -> Result<VerifiedFrontier, ResolveFailure> {
    // 1 — the signature, and the bytes it signed.
    verify_anchor_v3_candidate(anchor).map_err(|e| invalid(format!("baseline: {e}")))?;
    if tagged(TAG_DSM_SOFI_VAULT_BASELINE, auth_bytes) != anchor.state_commitment {
        return Err(invalid(
            "baseline: the authentication bytes do not hash to the anchor's commitment",
        ));
    }
    let auth = OwnerBaselineAuthV1::decode(auth_bytes)
        .map_err(|e| invalid(format!("baseline: authentication object: {e}")))?;

    // 2 — the owner, at the position the signer committed.
    let owner_genesis = genesis.preimage().owner_genesis;
    let proven = resolve_owner_authority_at_position(
        &owner_genesis,
        &auth.owner_authority_transition_digest,
        presented,
    )?;
    if proven.device_id != genesis.preimage().owner_device_id {
        return Err(invalid(
            "baseline: the proven device is not the vault's owner device",
        ));
    }
    if anchor.candidate_public_key != proven.ak_pk {
        return Err(invalid(
            "baseline: the anchor's candidate key is not the proven owner key",
        ));
    }

    // 3 — the frontier the owner bound, and only that one.
    let commitment = tagged(TAG_DSM_SOFI_VAULT_FRONTIER, frontier_bytes);
    if commitment != auth.frontier_commitment {
        return Err(invalid(
            "baseline: the frontier bytes are not the frontier the owner bound",
        ));
    }
    let frontier = VaultFrontierV1::decode(frontier_bytes)
        .map_err(|e| invalid(format!("baseline: frontier: {e}")))?;
    if frontier.vault_id != *genesis.vault_id() {
        return Err(invalid("baseline: the frontier names another vault"));
    }
    Ok(VerifiedFrontier {
        frontier,
        commitment,
        owner_genesis,
        owner: proven,
    })
}

/// Why a witness is not one of the vault at a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRefused {
    /// A path is not one sibling per level.
    PathDepth(String),
    /// The state leaf does not encode.
    StateLeaf(SofiWireError),
    /// The state leaf and its path do not fold to the root.
    StateNotUnderRoot,
    /// The state leaf is not at the witness's generation.
    StateGeneration { expected: u64, got: u64 },
    /// The state leaf names another owner than the baseline's.
    StateOwner,
    /// The relationship, present or absent, does not fold to the root.
    RelationshipNotUnderRoot,
    /// The relationship leaf names another trader.
    RelationshipTrader,
    /// The write set was not built on the witness's root and generation.
    NotBuiltOnTheWitness,
    /// The write set does not advance the held paths.
    Advance(AdvanceError),
    /// The advanced value is not the one the post state names.
    AdvancedValue,
}

impl core::fmt::Display for WitnessRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PathDepth(why) => write!(f, "a path is not one sibling per level: {why}"),
            Self::StateLeaf(e) => write!(f, "the state leaf: {e}"),
            Self::StateNotUnderRoot => write!(f, "the state leaf is not under the root"),
            Self::StateGeneration { expected, got } => write!(
                f,
                "the state leaf is at generation {got}, the witness at {expected}"
            ),
            Self::StateOwner => write!(f, "the state leaf names another owner"),
            Self::RelationshipNotUnderRoot => {
                write!(f, "the relationship proof is not under the root")
            }
            Self::RelationshipTrader => write!(f, "the relationship leaf names another trader"),
            Self::NotBuiltOnTheWitness => {
                write!(f, "the generation was not built on the witness's root")
            }
            Self::Advance(e) => write!(f, "{e}"),
            Self::AdvancedValue => {
                write!(f, "the advanced leaf is not the one the post state names")
            }
        }
    }
}

impl std::error::Error for WitnessRefused {}

fn path_of(path: &[D32]) -> Result<Box<Path>, WitnessRefused> {
    let fixed: &Path = path
        .try_into()
        .map_err(|e: core::array::TryFromSliceError| WitnessRefused::PathDepth(e.to_string()))?;
    Ok(Box::new(*fixed))
}

fn state_value(state: &VaultStateLeaf) -> Result<D32, WitnessRefused> {
    derive::vault_state_leaf_value(state).map_err(WitnessRefused::StateLeaf)
}

/// One reader's witness of a vault at one authenticated root: the vault's
/// state leaf with its path, and this reader's relationship leaf — or its
/// absence — with its path (SoFi Amendment S24).
///
/// Every constructor checks both paths against a root that is already
/// authenticated: the accepted genesis's, a [`VerifiedFrontier`]'s, the head
/// of a chain this verifier established, or the post root of a generation
/// [`Self::advance`] recomputed. Nothing else makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultWitness {
    vault_id: D32,
    generation: u64,
    root: D32,
    state: VaultStateLeaf,
    state_path: Box<Path>,
    trader_genesis: D32,
    trader_device_id: D32,
    relationship: Option<VaultRelationshipLeaf>,
    relationship_path: Box<Path>,
}

impl VaultWitness {
    /// `wire` checked against `(vault_id, generation, root)` for the trader
    /// `(trader_genesis, trader_device_id)`.
    fn checked(
        vault_id: D32,
        generation: u64,
        root: D32,
        wire: &VaultFrontierWitnessV1,
        trader_genesis: D32,
        trader_device_id: D32,
    ) -> Result<Self, WitnessRefused> {
        let state = wire.state_leaf.clone();
        if state.generation != generation {
            return Err(WitnessRefused::StateGeneration {
                expected: generation,
                got: state.generation,
            });
        }
        let state_key = derive::vault_state_key(&vault_id);
        let state_path = path_of(&wire.state_path)?;
        let state_leaf = leaf_node(&state_key, Some(&state_value(&state)?));
        if root_from_path(&state_key, &state_leaf, &state_path) != root {
            return Err(WitnessRefused::StateNotUnderRoot);
        }
        let rel_key = derive::relationship_key(&trader_genesis, &trader_device_id, &vault_id);
        let (relationship, relationship_path) = match &wire.relationship {
            FrontierRelationship::Absent { path } => (None, path_of(path)?),
            FrontierRelationship::Present { leaf, path } => {
                if leaf.trader_genesis != trader_genesis
                    || leaf.trader_device_id != trader_device_id
                {
                    return Err(WitnessRefused::RelationshipTrader);
                }
                (Some(*leaf), path_of(path)?)
            }
        };
        let value = relationship
            .as_ref()
            .map(derive::vault_relationship_leaf_value);
        if root_from_path(
            &rel_key,
            &leaf_node(&rel_key, value.as_ref()),
            &relationship_path,
        ) != root
        {
            return Err(WitnessRefused::RelationshipNotUnderRoot);
        }
        Ok(Self {
            vault_id,
            generation,
            root,
            state,
            state_path,
            trader_genesis,
            trader_device_id,
            relationship,
            relationship_path,
        })
    }

    /// The witness at the vault's genesis, where the tree holds its state
    /// leaf alone and no trader has a relationship yet.
    pub fn at_genesis(
        genesis: &AcceptedVaultGenesis,
        trader_genesis: D32,
        trader_device_id: D32,
    ) -> Result<Self, WitnessRefused> {
        let vault_id = *genesis.vault_id();
        let state = genesis.state().clone();
        let mut tree = EconomicSmt::new();
        tree.insert(derive::vault_state_key(&vault_id), state_value(&state)?);
        let wire = witness_from_tree(
            &tree,
            &vault_id,
            &state,
            None,
            &trader_genesis,
            &trader_device_id,
        );
        Self::checked(
            vault_id,
            state.generation,
            *genesis.genesis_root(),
            &wire,
            trader_genesis,
            trader_device_id,
        )
    }

    /// The witness at an owner baseline: `wire` checked against the root
    /// the owner signed, its state leaf naming that owner.
    pub fn from_baseline(
        baseline: &VerifiedFrontier,
        wire: &VaultFrontierWitnessV1,
        trader_genesis: D32,
        trader_device_id: D32,
    ) -> Result<Self, WitnessRefused> {
        if wire.state_leaf.owner_genesis != baseline.owner_genesis
            || wire.state_leaf.owner_device_id != baseline.owner.device_id
        {
            return Err(WitnessRefused::StateOwner);
        }
        let frontier = baseline.frontier();
        Self::checked(
            frontier.vault_id,
            frontier.generation,
            frontier.root,
            wire,
            trader_genesis,
            trader_device_id,
        )
    }

    /// This device's own record of its witness, checked against the head of
    /// a chain it established: the memo, read back, proves nothing until
    /// both of its paths fold to that head. The CI gate pins this
    /// constructor to its callers.
    pub fn recorded(
        chain: &super::resolution::VaultChain,
        vault_id: &D32,
        wire: &VaultFrontierWitnessV1,
        trader_genesis: D32,
        trader_device_id: D32,
    ) -> Result<Self, WitnessRefused> {
        let (generation, root) = chain.head().ok_or(WitnessRefused::NotBuiltOnTheWitness)?;
        Self::checked(
            *vault_id,
            generation,
            root,
            wire,
            trader_genesis,
            trader_device_id,
        )
    }

    /// This device's own record of its witness, advanced through `post`:
    /// the record proves nothing until both of its paths fold to the root
    /// `post` was built on, which Core recomputed, and the advance checks
    /// everything after that. What the store calls as it records each
    /// generation.
    pub fn advance_recorded(
        wire: &VaultFrontierWitnessV1,
        trader_genesis: D32,
        trader_device_id: D32,
        post: &VaultPostState,
    ) -> Result<Self, WitnessRefused> {
        Self::checked(
            *post.vault_id(),
            post.pre_generation(),
            *post.pre_root(),
            wire,
            trader_genesis,
            trader_device_id,
        )?
        .advance(post)
    }

    /// The witness one generation on: both paths advanced from this root to
    /// `post`'s through `post`'s own write set. The state becomes the post
    /// state; the relationship becomes the leaf `post` advanced when it was
    /// this trader's, and stays as it was otherwise. Each advanced leaf must
    /// fold to the post root.
    pub fn advance(&self, post: &VaultPostState) -> Result<Self, WitnessRefused> {
        if *post.vault_id() != self.vault_id
            || *post.pre_root() != self.root
            || post.pre_generation() != self.generation
        {
            return Err(WitnessRefused::NotBuiltOnTheWitness);
        }
        let (pre_root, post_root) = (self.root, *post.root());
        let state_key = derive::vault_state_key(&self.vault_id);
        let state = advance_path(
            &pre_root,
            &post_root,
            post.entries(),
            &state_key,
            Some(&state_value(&self.state)?),
            &self.state_path,
        )
        .map_err(WitnessRefused::Advance)?;
        if state.value != Some(state_value(post.state())?) {
            return Err(WitnessRefused::AdvancedValue);
        }
        let rel_key =
            derive::relationship_key(&self.trader_genesis, &self.trader_device_id, &self.vault_id);
        let held = self
            .relationship
            .as_ref()
            .map(derive::vault_relationship_leaf_value);
        let advanced = advance_path(
            &pre_root,
            &post_root,
            post.entries(),
            &rel_key,
            held.as_ref(),
            &self.relationship_path,
        )
        .map_err(WitnessRefused::Advance)?;
        let relationship = match post.relationship() {
            Some((key, leaf)) if *key == rel_key => Some(*leaf),
            _ => self.relationship,
        };
        if advanced.value
            != relationship
                .as_ref()
                .map(derive::vault_relationship_leaf_value)
        {
            return Err(WitnessRefused::AdvancedValue);
        }
        Ok(Self {
            vault_id: self.vault_id,
            generation: post.generation(),
            root: post_root,
            state: post.state().clone(),
            state_path: state.path,
            trader_genesis: self.trader_genesis,
            trader_device_id: self.trader_device_id,
            relationship,
            relationship_path: advanced.path,
        })
    }

    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn root(&self) -> &D32 {
        &self.root
    }
    pub fn state(&self) -> &VaultStateLeaf {
        &self.state
    }
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }
    /// The trader whose relationship this witness proves.
    pub fn trader(&self) -> (&D32, &D32) {
        (&self.trader_genesis, &self.trader_device_id)
    }
    pub fn relationship(&self) -> Option<&VaultRelationshipLeaf> {
        self.relationship.as_ref()
    }
    pub fn relationship_path(&self) -> &Path {
        &self.relationship_path
    }

    /// The witness as its wire object, for this device's own record.
    pub fn to_wire(&self) -> VaultFrontierWitnessV1 {
        witness_wire(
            &self.state,
            self.state_path.to_vec(),
            self.relationship,
            self.relationship_path.to_vec(),
        )
    }
}

fn witness_wire(
    state: &VaultStateLeaf,
    state_path: Vec<D32>,
    relationship: Option<VaultRelationshipLeaf>,
    relationship_path: Vec<D32>,
) -> VaultFrontierWitnessV1 {
    VaultFrontierWitnessV1 {
        state_leaf: state.clone(),
        state_path,
        relationship: match relationship {
            Some(leaf) => FrontierRelationship::Present {
                leaf,
                path: relationship_path,
            },
            None => FrontierRelationship::Absent {
                path: relationship_path,
            },
        },
    }
}

/// The witness a holder of the whole tree states for one trader: what a
/// vault's owner hands a reader. It carries no authority — the reader checks
/// it against a root it authenticated — and `relationship` is the leaf the
/// holder's record has at the trader's key.
pub fn witness_from_tree(
    tree: &EconomicSmt,
    vault_id: &D32,
    state: &VaultStateLeaf,
    relationship: Option<VaultRelationshipLeaf>,
    trader_genesis: &D32,
    trader_device_id: &D32,
) -> VaultFrontierWitnessV1 {
    let rel_key = derive::relationship_key(trader_genesis, trader_device_id, vault_id);
    witness_wire(
        state,
        tree.siblings(&derive::vault_state_key(vault_id)).to_vec(),
        relationship,
        tree.siblings(&rel_key).to_vec(),
    )
}

#[cfg(test)]
mod tests;
