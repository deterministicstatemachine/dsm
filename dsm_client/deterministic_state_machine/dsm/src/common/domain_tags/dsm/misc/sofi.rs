// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: SoFi v8 — the unilateral trader operation
//! `TraderPrecommit P → DLVPolicyFulfillment G_1 … G_n → TraderFulfillment F`.
//!
//! Every derivation under these tags is `BLAKE3(tag ‖ 0x00 ‖ data)` via
//! `dsm_domain_hasher`. The derivations themselves live in `crate::sofi::derive`
//! beside the field tables in `crate::sofi::wire`; this file only allocates
//! the domains.

use crate::crypto::domain::TaggedHashDomain;

// ── Relationship setup (F1) ────────────────────────────────────────────────

/// `k_{T,v} = H(tag ‖ G ‖ DevID ‖ v)` — the relationship leaf key.
pub const TAG_DSM_SOFI_REL_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/rel-key/v1");
/// `H(tag ‖ G_o ‖ DevID_o ‖ v)` — the owner's vault-CREATION record key in
/// `R_econ` (P15-12).
///
/// Shaped like [`TAG_DSM_SOFI_REL_KEY`] because it is the same kind of thing:
/// a SoFi leaf in the owner's own economic tree, scoped to the identity whose
/// tree it is. Deliberately NOT the vault-genesis locator, which addresses a
/// vault's genesis at the storage layer (F10) — one derivation serving two
/// namespaces is how a storage coordinate and an economic key end up
/// colliding.
pub const TAG_DSM_SOFI_VAULT_CREATION_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/vault-creation-key/v1");
/// `σ = H(tag ‖ G ‖ DevID ‖ u64be(p) ‖ v)` — the pre-state-independent setup id.
pub const TAG_DSM_SOFI_SETUP_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/setup-id/v1");
/// `h⁰ = H(tag ‖ σ)` — relationship-leaf genesis.
pub const TAG_DSM_SOFI_REL_GENESIS: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/rel-genesis/v1");
/// `hʲ⁺¹ = H(tag ‖ hʲ ‖ E)` — relationship-leaf advance.
pub const TAG_DSM_SOFI_REL_LEAF: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/rel-leaf/v1");
/// `H(tag ‖ G ‖ DevID ‖ v)` — the one-relationship-per-identity-and-vault index key.
pub const TAG_DSM_SOFI_REL_INDEX: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/rel-index/v1");
/// `ρ = H(tag ‖ CCB(SofiSetupBody))` — the setup reference. Body identity only.
pub const TAG_DSM_SOFI_SETUP_REF: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/setup-ref/v1");
/// `m_setup = H(tag ‖ CCB(SofiSetupBody))` — what the claimant signs.
pub const TAG_DSM_SOFI_SETUP_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/setup-sign/v1");

// ── P → G → F (F2) ─────────────────────────────────────────────────────────

/// `PrecommitId = H(tag ‖ CCB(TraderPrecommitBody))`.
pub const TAG_DSM_SOFI_TRADER_PRECOMMIT_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/trader-precommit-id/v1");
/// `m_P = H(tag ‖ CCB(TraderPrecommitBody))`.
pub const TAG_DSM_SOFI_TRADER_PRECOMMIT_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/trader-precommit-sign/v1");
/// `PolicyFulfillmentId_j = H(tag ‖ CCB(DlvPolicyFulfillmentBody_j))`. A
/// deterministic witness identity, never an issuer signature domain.
pub const TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/dlv-policy-fulfillment/v1");
/// `K_ful = H(tag ‖ G ‖ DevID ‖ u64be(q))` — the fulfillment register key.
pub const TAG_DSM_SOFI_FULFILLMENT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/fulfillment/v1");
/// `FulfillmentId = H(tag ‖ CCB(TraderFulfillmentBody))`.
pub const TAG_DSM_SOFI_FULFILLMENT_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/fulfillment-id/v1");
/// `m_F = H(tag ‖ CCB(TraderFulfillmentBody))`.
pub const TAG_DSM_SOFI_FULFILLMENT_SIGN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/fulfillment-sign/v1");

// ── Successor attempts and route outcome (F6, F7) ──────────────────────────

/// `K^(0) = H(tag ‖ v ‖ R_n)`.
pub const TAG_DSM_SOFI_SUCC_CELL_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/succ-cell/v2");
/// `K^(a) = H(tag ‖ K^(0) ‖ u64be(a))` for `a ≥ 1`. O(1), not a chain.
pub const TAG_DSM_SOFI_SUCC_ATTEMPT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/succ-attempt/v1");
/// `s_{v,n} = H(tag ‖ v ‖ R_n)` — the Fisher-Yates seed.
pub const TAG_DSM_SOFI_STORAGE_SEED_V4: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/storage-seed/v4");
/// `H(tag ‖ s ‖ u32be(i) ‖ u32be(ctr))` — Fisher-Yates PRF words; the shuffle
/// of the committed set that names a cell's leader (Part II §7).
pub const TAG_DSM_SOFI_FY_PRF: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/fy-prf/v1");

// ── Cores and the external commitment (F3) ─────────────────────────────────

/// `c_T° = H(tag ‖ CCB(T°))`.
pub const TAG_DSM_SOFI_TRADER_CORE_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/trader-core/v3");
/// `c_V° = H(tag ‖ CCB(V°))`.
pub const TAG_DSM_SOFI_DLV_CORE_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/dlv-core/v3");
/// `b° = H(tag ‖ CCB(B°))`.
pub const TAG_DSM_SOFI_SETTLEMENT_CORE_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/settlement-core/v3");
/// Single-vault `E = H(tag ‖ v ‖ R_n ‖ ρ ‖ c_T° ‖ c_V° ‖ b° ‖ X_route)`.
pub const TAG_DSM_SOFI_ATOMIC_EXT_V4: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/atomic-ext/v4");
/// Route `E = H(tag ‖ c_T° ‖ b° ‖ X_route ‖ H(Γ))`.
pub const TAG_DSM_SOFI_ATOMIC_EXT_MULTIVAULT_V5: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/atomic-ext/multivault/v5");
/// `H(Γ) = H(tag ‖ CCB(RouteLegSet))` — the route-leg set digest folded into a
/// route E.
pub const TAG_DSM_SOFI_ROUTE_LEG_SET: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/route-leg-set/v1");
/// `L(E) = H(tag ‖ E)` — where the settlement preimage is stored.
pub const TAG_DSM_SOFI_PREIMAGE_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/preimage-locator/v1");

// ── Vault identity and genesis (F10) ───────────────────────────────────────

/// `v = H(tag ‖ G_o ‖ DevID_o ‖ u64be(p_create))`.
pub const TAG_DSM_SOFI_VAULT_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/vault-id/v1");
/// `H(tag ‖ v)` — the locator under which a vault's genesis preimage is
/// indexed (Part II §11).
pub const TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/vault-genesis-locator/v1");
/// Immutable-store namespace of the EXACT `VaultGenesisPreimage` bytes
/// (Part II §10): `addr = immutable_addr(tag, bytes)`; the reader recomputes
/// it and `vault_id()` from the bytes.
pub const TAG_DSM_SOFI_VAULT_GENESIS_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/vault-genesis-object/v1");

// ── Immutable-store namespaces of the published protocol objects (Part II
//    §10, rebuild step R8). One per kind: the namespace is part of the
//    address, so bytes of one kind can never be fetched as another. ────────

/// The signed setup envelope (`SignedSofiObject` over `SofiSetupBody`),
/// indexed under `ρ` and under the relationship index key.
pub const TAG_DSM_SOFI_SETUP_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/setup-object/v1");
/// The signed precommit envelope, indexed under `PrecommitId`.
pub const TAG_DSM_SOFI_PRECOMMIT_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/precommit-object/v1");
/// The exact `P(E)` bytes, indexed under `L(E)`.
pub const TAG_DSM_SOFI_PREIMAGE_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/preimage-object/v1");
/// A policy-fulfillment witness `G_j` (no signature), indexed under
/// `PolicyFulfillmentId_j`.
pub const TAG_DSM_SOFI_POLICY_FULFILLMENT_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/policy-fulfillment-object/v1");
/// The signed fulfillment envelope, indexed under `FulfillmentId`.
pub const TAG_DSM_SOFI_FULFILLMENT_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/fulfillment-object/v1");

// ── The DLV tree's leaves, and the route digest (P15-4, P15-8) ─────────────

/// `H(tag ‖ v)` — where a vault's own state leaf sits in its DLV tree.
pub const TAG_DSM_SOFI_VAULT_STATE_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/vault-state-key/v1");
/// `H(tag ‖ CCB(leaf))` — the value of EITHER DLV leaf class. The leaf's own
/// envelope is the discriminant, so one tag cannot conflate the two.
pub const TAG_DSM_SOFI_VAULT_LEAF_STATE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/vault-leaf-state/v1");
/// `X_route = H(tag ‖ CCB(RouteDigestPreimage))` — over the variant-
/// discriminated union, so a Swap digest can never be read as a Close one.
pub const TAG_DSM_SOFI_ROUTE_DIGEST: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/route-digest/v1");

// ── Reserved: allocated so the names cannot be reused; no derivation exists ─

/// Reserved for a future storage-membership handover transition. Not ruled.
pub const TAG_DSM_SOFI_MEMBERSHIP_HANDOVER: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/membership-handover/v1");
/// Reserved for v8 §31 trade digests. Out of scope.
pub const TAG_DSM_SOFI_TRADE_DIGEST: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/trade-digest/v1");
/// Reserved for v8 §31 reference windows. Out of scope.
pub const TAG_DSM_SOFI_REF_WINDOW: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sofi/ref-window/v1");

#[cfg(test)]
pub(crate) const SOFI_TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_SOFI_REL_KEY,
    TAG_DSM_SOFI_SETUP_ID,
    TAG_DSM_SOFI_REL_GENESIS,
    TAG_DSM_SOFI_REL_LEAF,
    TAG_DSM_SOFI_REL_INDEX,
    TAG_DSM_SOFI_SETUP_REF,
    TAG_DSM_SOFI_SETUP_SIGN,
    TAG_DSM_SOFI_TRADER_PRECOMMIT_ID,
    TAG_DSM_SOFI_TRADER_PRECOMMIT_SIGN,
    TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT,
    TAG_DSM_SOFI_FULFILLMENT,
    TAG_DSM_SOFI_FULFILLMENT_ID,
    TAG_DSM_SOFI_FULFILLMENT_SIGN,
    TAG_DSM_SOFI_SUCC_CELL_V2,
    TAG_DSM_SOFI_SUCC_ATTEMPT,
    TAG_DSM_SOFI_STORAGE_SEED_V4,
    TAG_DSM_SOFI_FY_PRF,
    TAG_DSM_SOFI_TRADER_CORE_V3,
    TAG_DSM_SOFI_DLV_CORE_V3,
    TAG_DSM_SOFI_SETTLEMENT_CORE_V3,
    TAG_DSM_SOFI_ATOMIC_EXT_V4,
    TAG_DSM_SOFI_ATOMIC_EXT_MULTIVAULT_V5,
    TAG_DSM_SOFI_ROUTE_LEG_SET,
    TAG_DSM_SOFI_PREIMAGE_LOCATOR,
    TAG_DSM_SOFI_VAULT_ID,
    TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR,
    TAG_DSM_SOFI_VAULT_GENESIS_OBJECT,
    TAG_DSM_SOFI_SETUP_OBJECT,
    TAG_DSM_SOFI_PRECOMMIT_OBJECT,
    TAG_DSM_SOFI_PREIMAGE_OBJECT,
    TAG_DSM_SOFI_POLICY_FULFILLMENT_OBJECT,
    TAG_DSM_SOFI_FULFILLMENT_OBJECT,
    TAG_DSM_SOFI_VAULT_CREATION_KEY,
    TAG_DSM_SOFI_VAULT_STATE_KEY,
    TAG_DSM_SOFI_VAULT_LEAF_STATE,
    TAG_DSM_SOFI_ROUTE_DIGEST,
    TAG_DSM_SOFI_MEMBERSHIP_HANDOVER,
    TAG_DSM_SOFI_TRADE_DIGEST,
    TAG_DSM_SOFI_REF_WINDOW,
];
