// SPDX-License-Identifier: Apache-2.0

//! SoFi v8 derivations — every key and identity, each `BLAKE3(tag ‖ 0x00 ‖
//! data)` under its own `DSM/sofi/*` domain.
//!
//! Identities are over canonical BODY bytes, never over signature envelopes,
//! so a second valid signature over the same body is the same object. The one
//! exception is deliberate and pre-existing: an ordinary economic root claim
//! is identified by its exact envelope digest ([`claim_ref`]), because the
//! root register stores exact envelope bytes and that identity is not
//! redefined here.

use crate::common::domain_tags::{
    TAG_DSM_SOFI_ATOMIC_EXT_MULTIVAULT_V5, TAG_DSM_SOFI_ATOMIC_EXT_V4, TAG_DSM_SOFI_DLV_CORE_V3,
    TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT, TAG_DSM_SOFI_FULFILLMENT, TAG_DSM_SOFI_FULFILLMENT_ID,
    TAG_DSM_SOFI_FULFILLMENT_SIGN, TAG_DSM_SOFI_PREIMAGE_LOCATOR, TAG_DSM_SOFI_REL_GENESIS,
    TAG_DSM_SOFI_REL_INDEX, TAG_DSM_SOFI_REL_KEY, TAG_DSM_SOFI_REL_LEAF,
    TAG_DSM_SOFI_ROUTE_LEG_SET, TAG_DSM_SOFI_ROUTE_OUTCOME_V2, TAG_DSM_SOFI_SETTLEMENT_CORE_V3,
    TAG_DSM_SOFI_SETUP_ID, TAG_DSM_SOFI_SETUP_REF, TAG_DSM_SOFI_SETUP_SIGN,
    TAG_DSM_SOFI_VAULT_CREATION_KEY, TAG_DSM_SOFI_STORAGE_SEED_V4, TAG_DSM_SOFI_SUCC_ATTEMPT,
    TAG_DSM_SOFI_SUCC_CELL_V2, TAG_DSM_SOFI_TRADER_CORE_V3, TAG_DSM_SOFI_TRADER_PRECOMMIT_ID,
    TAG_DSM_SOFI_ROUTE_DIGEST, TAG_DSM_SOFI_TRADER_PRECOMMIT_SIGN,
    TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR, TAG_DSM_SOFI_VAULT_ID, TAG_DSM_SOFI_VAULT_LEAF_STATE,
    TAG_DSM_SOFI_VAULT_STATE_KEY,
};
use crate::common::domain_tags::TAG_DSM_ECONOMIC_LEAF_STATE;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;

use super::wire::{
    DlvPolicyFulfillmentBody, RouteDigestPreimage, RouteLegSet, SettlementBody, SettlementPreimage,
    RouteLegEntry, SofiResolutionClaim, SofiSetupBody, SofiWireError, TraderFulfillmentBody,
    TraderPrecommitBody, TraderRelationshipLeaf, VaultRelationshipLeaf, VaultStateLeaf,
    CANONICAL_MAX_LEGS, ROUTE_MIN_LEGS,
};

type D32 = [u8; 32];

fn h(tag: TaggedHashDomain<'static>, parts: &[&[u8]]) -> D32 {
    let mut hasher = dsm_domain_hasher(tag);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

// ── identity, relationship, setup ──────────────────────────────────────────

/// `v = H(vault-id/v1 ‖ G_o ‖ DevID_o ‖ u64be(p_create))`.
pub fn vault_id(owner_genesis: &D32, owner_device_id: &D32, create_position: u64) -> D32 {
    h(
        TAG_DSM_SOFI_VAULT_ID,
        &[
            owner_genesis,
            owner_device_id,
            &create_position.to_be_bytes(),
        ],
    )
}

/// `H(vault-state-key/v1 ‖ v)` — where a vault's own state leaf sits in its
/// DLV tree. One key per vault, so the state cannot be split across leaves.
pub fn vault_state_key(vault_id: &D32) -> D32 {
    h(TAG_DSM_SOFI_VAULT_STATE_KEY, &[vault_id])
}

/// The value of a vault's own state leaf: `H(vault-leaf-state/v1 ‖ CCB)`.
pub fn vault_state_leaf_value(leaf: &VaultStateLeaf) -> Result<D32, SofiWireError> {
    Ok(h(TAG_DSM_SOFI_VAULT_LEAF_STATE, &[&leaf.encode()?]))
}

/// The value of a trader's relationship leaf in a vault's tree. Same tag as
/// the state leaf, which is safe because the leaf's own envelope is inside the
/// preimage: the two classes can never collide.
pub fn vault_relationship_leaf_value(leaf: &VaultRelationshipLeaf) -> D32 {
    h(TAG_DSM_SOFI_VAULT_LEAF_STATE, &[&leaf.encode()])
}

/// The value of the trader's own relationship leaf in `R_econ`. It follows the
/// ECONOMIC leaf-state rule, not the vault one, because that is the tree it
/// lives in — the two rules are deliberately distinct tags.
pub fn trader_relationship_leaf_value(leaf: &TraderRelationshipLeaf) -> D32 {
    let mut hasher = dsm_domain_hasher(TAG_DSM_ECONOMIC_LEAF_STATE);
    hasher.update(&leaf.encode());
    *hasher.finalize().as_bytes()
}

/// `X_route = H(route-digest/v1 ‖ CCB(RouteDigestPreimage))`.
pub fn route_digest(preimage: &RouteDigestPreimage) -> Result<D32, SofiWireError> {
    Ok(h(TAG_DSM_SOFI_ROUTE_DIGEST, &[&preimage.encode()?]))
}

/// `H(vault-genesis-locator/v1 ‖ v)`.
pub fn vault_genesis_locator(vault_id: &D32) -> D32 {
    h(TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR, &[vault_id])
}

/// `H(vault-creation-key/v1 ‖ G_o ‖ DevID_o ‖ v)` — where the owner's
/// creation record lives in `R_econ` (P15-12).
///
/// Scoped to the owner's identity like every other economic key, even though
/// `vault_id` already derives from it: the key names a leaf in ONE device's
/// tree, and the convention is what keeps that legible.
pub fn vault_creation_key(owner_genesis: &D32, owner_device_id: &D32, vault_id: &D32) -> D32 {
    h(
        TAG_DSM_SOFI_VAULT_CREATION_KEY,
        &[owner_genesis, owner_device_id, vault_id],
    )
}

/// `k_{T,v} = H(rel-key/v1 ‖ G ‖ DevID ‖ v)`.
pub fn relationship_key(genesis: &D32, device_id: &D32, vault_id: &D32) -> D32 {
    h(TAG_DSM_SOFI_REL_KEY, &[genesis, device_id, vault_id])
}

/// `σ = H(setup-id/v1 ‖ G ‖ DevID ‖ u64be(p) ‖ v)`. Independent of the
/// post-root, so the leaf genesis built from it has no cycle.
pub fn setup_id(genesis: &D32, device_id: &D32, position: u64, vault_id: &D32) -> D32 {
    h(
        TAG_DSM_SOFI_SETUP_ID,
        &[genesis, device_id, &position.to_be_bytes(), vault_id],
    )
}

/// `h⁰ = H(rel-genesis/v1 ‖ σ)`.
pub fn relationship_leaf_genesis(setup_id: &D32) -> D32 {
    h(TAG_DSM_SOFI_REL_GENESIS, &[setup_id])
}

/// `hʲ⁺¹ = H(rel-leaf/v1 ‖ hʲ ‖ E)` — inserted by BindExt, never present in a core.
pub fn relationship_leaf_next(current_leaf: &D32, external_commitment: &D32) -> D32 {
    h(TAG_DSM_SOFI_REL_LEAF, &[current_leaf, external_commitment])
}

/// `H(rel-index/v1 ‖ G ‖ DevID ‖ v)` — one relationship per identity and vault.
pub fn relationship_index_key(genesis: &D32, device_id: &D32, vault_id: &D32) -> D32 {
    h(TAG_DSM_SOFI_REL_INDEX, &[genesis, device_id, vault_id])
}

/// `ρ = H(setup-ref/v1 ‖ CCB(SofiSetupBody))`.
pub fn setup_ref(body: &SofiSetupBody) -> D32 {
    h(TAG_DSM_SOFI_SETUP_REF, &[&body.encode()])
}

/// `m_setup = H(setup-sign/v1 ‖ CCB(SofiSetupBody))`.
pub fn setup_signing_digest(body: &SofiSetupBody) -> D32 {
    h(TAG_DSM_SOFI_SETUP_SIGN, &[&body.encode()])
}

/// The exact registered-claim reference for an ordinary economic root claim:
/// the existing exact-envelope digest, unchanged.
pub fn claim_ref(exact_envelope_bytes: &[u8]) -> D32 {
    crate::economic::claim_envelope::economic_root_claim_envelope_digest(exact_envelope_bytes)
}

// ── P, G, F, C_q ───────────────────────────────────────────────────────────

/// `PrecommitId = H(trader-precommit-id/v1 ‖ CCB(P))`.
pub fn precommit_id(body: &TraderPrecommitBody) -> D32 {
    h(TAG_DSM_SOFI_TRADER_PRECOMMIT_ID, &[&body.encode()])
}

/// `m_P = H(trader-precommit-sign/v1 ‖ CCB(P))`.
pub fn precommit_signing_digest(body: &TraderPrecommitBody) -> D32 {
    h(TAG_DSM_SOFI_TRADER_PRECOMMIT_SIGN, &[&body.encode()])
}

/// `PolicyFulfillmentId_j = H(dlv-policy-fulfillment/v1 ‖ CCB(G_j))`.
pub fn policy_fulfillment_id(body: &DlvPolicyFulfillmentBody) -> D32 {
    h(TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT, &[&body.encode()])
}

/// `FulfillmentId = H(fulfillment-id/v1 ‖ CCB(F))`.
pub fn fulfillment_id(body: &TraderFulfillmentBody) -> D32 {
    h(TAG_DSM_SOFI_FULFILLMENT_ID, &[&body.encode()])
}

/// `m_F = H(fulfillment-sign/v1 ‖ CCB(F))`.
pub fn fulfillment_signing_digest(body: &TraderFulfillmentBody) -> D32 {
    h(TAG_DSM_SOFI_FULFILLMENT_SIGN, &[&body.encode()])
}

/// `K_ful = H(fulfillment/v1 ‖ G ‖ DevID ‖ u64be(q))`.
pub fn fulfillment_register_key(genesis: &D32, device_id: &D32, position: u64) -> D32 {
    h(
        TAG_DSM_SOFI_FULFILLMENT,
        &[genesis, device_id, &position.to_be_bytes()],
    )
}

/// The conditional position a member derives when it accepts F. Never
/// caller-supplied: every field comes from the verified P and F.
pub fn resolution_claim(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
) -> SofiResolutionClaim {
    SofiResolutionClaim {
        genesis: *precommit.genesis(),
        device_id: *precommit.device_id(),
        position: fulfillment.position(),
        fulfillment_id: fulfillment_id(fulfillment),
        realize_root: *precommit.realize_root(),
        void_root: *precommit.void_root(),
    }
}

/// `K_out(F) = H(route-outcome/v2 ‖ FulfillmentId)`.
pub fn route_outcome_key(fulfillment_id: &D32) -> D32 {
    h(TAG_DSM_SOFI_ROUTE_OUTCOME_V2, &[fulfillment_id])
}

// ── successor attempts and routing seed ────────────────────────────────────

/// `K^(0) = H(succ-cell/v2 ‖ v ‖ R_n)`.
pub fn successor_base_key(vault_id: &D32, parent_root: &D32) -> D32 {
    h(TAG_DSM_SOFI_SUCC_CELL_V2, &[vault_id, parent_root])
}

/// `K^(a)`: `K^(0)` at `a = 0`, else `H(succ-attempt/v1 ‖ K^(0) ‖ u64be(a))`.
/// O(1) in `a`, so an attacker-supplied index costs one hash.
pub fn successor_attempt_key(vault_id: &D32, parent_root: &D32, attempt: u64) -> D32 {
    let base = successor_base_key(vault_id, parent_root);
    if attempt == 0 {
        return base;
    }
    h(TAG_DSM_SOFI_SUCC_ATTEMPT, &[&base, &attempt.to_be_bytes()])
}

/// `s_{v,n} = H(storage-seed/v4 ‖ v ‖ R_n)`.
pub fn storage_seed(vault_id: &D32, parent_root: &D32) -> D32 {
    h(TAG_DSM_SOFI_STORAGE_SEED_V4, &[vault_id, parent_root])
}

// ── cores and the external commitment ──────────────────────────────────────

/// `c_T° = H(trader-core/v3 ‖ CCB(T°))` over the exact canonical core bytes.
pub fn trader_core_digest(canonical_core: &[u8]) -> D32 {
    h(TAG_DSM_SOFI_TRADER_CORE_V3, &[canonical_core])
}

/// `c_V° = H(dlv-core/v3 ‖ CCB(V°))`.
pub fn dlv_core_digest(canonical_core: &[u8]) -> D32 {
    h(TAG_DSM_SOFI_DLV_CORE_V3, &[canonical_core])
}

/// `b° = H(settlement-core/v3 ‖ CCB(B°))`.
pub fn settlement_core_digest(canonical_core: &[u8]) -> D32 {
    h(TAG_DSM_SOFI_SETTLEMENT_CORE_V3, &[canonical_core])
}

/// Single-vault `E = H(atomic-ext/v4 ‖ v ‖ R_n ‖ ρ ‖ c_T° ‖ c_V° ‖ b° ‖ X_route)`.
///
/// No attempt index, availability view, routing order, first member or witness
/// enters E.
#[allow(clippy::too_many_arguments)]
pub fn external_commitment_single(
    vault_id: &D32,
    parent_root: &D32,
    setup_ref: &D32,
    trader_core: &D32,
    dlv_core: &D32,
    settlement_core: &D32,
    route: &D32,
) -> D32 {
    h(
        TAG_DSM_SOFI_ATOMIC_EXT_V4,
        &[
            vault_id,
            parent_root,
            setup_ref,
            trader_core,
            dlv_core,
            settlement_core,
            route,
        ],
    )
}

/// `H(Γ) = H(route-leg-set/v1 ‖ CCB(Γ))`.
pub fn route_leg_set_digest(legs: &RouteLegSet) -> D32 {
    h(TAG_DSM_SOFI_ROUTE_LEG_SET, &[&legs.encode()])
}

/// Route `E = H(atomic-ext/multivault/v5 ‖ c_T° ‖ b° ‖ X_route ‖ H(Γ))`.
pub fn external_commitment_route(
    trader_core: &D32,
    settlement_core: &D32,
    route: &D32,
    legs: &RouteLegSet,
) -> D32 {
    h(
        TAG_DSM_SOFI_ATOMIC_EXT_MULTIVAULT_V5,
        &[
            trader_core,
            settlement_core,
            route,
            &route_leg_set_digest(legs),
        ],
    )
}

/// `RecomputeE`: the one derivation from a settlement preimage to `E`.
///
/// The FORM is a function of the preimage alone — the branch of `B°` and its
/// leg count — so a caller cannot choose a reading. A one-leg operation, swap
/// or close, is the single-vault form; two or more legs is the multivault
/// form. `X_route`'s variant comes from the same branch, so a close digest can
/// never be folded as a swap one [R17-4].
/// The canonical leg set `P(E)` implies: for every DLV parent the settlement
/// references, the `(vault_id, parent_root, setup_ref, shadow_core)` that
/// exactly one valid preimage can produce.
///
/// **This is the authority for `c°_{V,j}`.** A shadow is not something a
/// witness asserts and a reader accepts — it is `dlv_core_digest` over the
/// `V°_j` the preimage carries, so for a given `E` there is exactly one
/// admissible shadow per leg. A member holding `P(E)` can therefore decide
/// whether a policy-fulfillment witness carries the right one, which is what
/// §2 asks of G ingress: `(v_j, R_j, c°_{V,j})` must match a stored P leg
/// AND `P(E)`.
///
/// [`recompute_e`] is built on this, so the value a member checks against and
/// the value that goes into `E` are the same derivation and cannot drift.
/// Both E forms are covered: a one-leg settlement yields one entry, and a
/// route yields `ROUTE_MIN_LEGS..=CANONICAL_MAX_LEGS`.
pub fn canonical_legs(preimage: &SettlementPreimage) -> Result<Vec<RouteLegEntry>, SofiWireError> {
    let settlement = preimage.settlement();
    if settlement.leg_count() < ROUTE_MIN_LEGS {
        let core = preimage
            .dlv_cores()
            .first()
            .ok_or(SofiWireError::Cardinality {
                field: "dlv cores",
                min: 1,
                max: 1,
                got: 0,
            })?;
        let (vault_id, parent_root, setup_ref) = match settlement {
            SettlementBody::Swap { hops, .. } => {
                let hop = &hops[0];
                (hop.vault_id, hop.parent_root, hop.setup_ref)
            }
            SettlementBody::Close {
                vault_id,
                parent_root,
                setup_ref,
                ..
            } => (*vault_id, *parent_root, *setup_ref),
        };
        return Ok(vec![RouteLegEntry {
            vault_id,
            parent_root,
            setup_ref,
            shadow_core: dlv_core_digest(&core.encode()?),
        }]);
    }
    preimage
        .dlv_cores()
        .iter()
        .map(|core| {
            let hop = match settlement {
                SettlementBody::Swap { hops, .. } => hops
                    .iter()
                    .find(|h| h.vault_id == *core.vault_id())
                    .ok_or(SofiWireError::Cardinality {
                        field: "dlv cores",
                        min: 1,
                        max: CANONICAL_MAX_LEGS,
                        got: 0,
                    })?,
                SettlementBody::Close { .. } => {
                    return Err(SofiWireError::Cardinality {
                        field: "close legs",
                        min: 1,
                        max: 1,
                        got: preimage.dlv_cores().len(),
                    })
                }
            };
            Ok(RouteLegEntry {
                vault_id: hop.vault_id,
                parent_root: hop.parent_root,
                setup_ref: hop.setup_ref,
                shadow_core: dlv_core_digest(&core.encode()?),
            })
        })
        .collect()
}

pub fn recompute_e(preimage: &SettlementPreimage) -> Result<D32, SofiWireError> {
    // No bound check here, and none is missing: an oversized `P(E)` cannot
    // reach this function because it cannot exist. `SettlementPreimage` has
    // private fields and exactly two entry points — `new` and `decode` — and
    // both refuse anything over `MAX_SETTLEMENT_PREIMAGE_BYTES`. Re-checking
    // it here would be a branch no test could reach, which is the kind of
    // decoration a mutation gate rightly finds hollow.
    let settlement = preimage.settlement();
    let b_core = settlement_core_digest(&settlement.encode()?);
    let trader_core = trader_core_digest(&preimage.trader_core().encode()?);
    let route = route_digest(&settlement.route_digest_preimage())?;
    // ONE derivation of the leg set, shared with every reader that needs to
    // know which shadow `E` commits.
    let legs = canonical_legs(preimage)?;
    if settlement.leg_count() < ROUTE_MIN_LEGS {
        let leg = &legs[0];
        return Ok(external_commitment_single(
            &leg.vault_id,
            &leg.parent_root,
            &leg.setup_ref,
            &trader_core,
            &leg.shadow_core,
            &b_core,
            &route,
        ));
    }
    Ok(external_commitment_route(
        &trader_core,
        &b_core,
        &route,
        &RouteLegSet::new(legs)?,
    ))
}

/// `L(E) = H(preimage-locator/v1 ‖ E)`.
pub fn preimage_locator(external_commitment: &D32) -> D32 {
    h(TAG_DSM_SOFI_PREIMAGE_LOCATOR, &[external_commitment])
}
