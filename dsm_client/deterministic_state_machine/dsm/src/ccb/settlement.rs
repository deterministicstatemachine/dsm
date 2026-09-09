// SPDX-License-Identifier: Apache-2.0

//! THE CANONICAL SETTLEMENT BUNDLE AND EVERYTHING IT NESTS — amendments 2c-A,
//! 2c-B, 2c-A.1.
//!
//! First-ship encoders, schema 1 unless the registry says otherwise:
//!
//! | Class    | Object                  | §     |
//! |----------|-------------------------|-------|
//! | `0x000E` | `SettlementBundle`      | §5.19 |
//! | `0x000F` | `ConsumedDlvTransition` | §5.21 |
//! | `0x0010` | `DlvProofMaterial`      | §5.22 — zero fields, never emitted in beta |
//! | `0x0033` | `MarketTerms`           | §5.20 |
//! | `0x0031` | `DsmSuccessorEvidence`  | §5.23 — substrate, frozen by 2c-B |
//! | `0x000B` | `TradeIntent`           | §5.5  |
//! | `0x000D` | `Route` schema 2        | §5.13 |
//! | `0x0015` | `Allocation` schema 2   | §5.10 |
//! | `0x0016` | `AllocationBundle` s2   | §5.11 |
//!
//! `b = H_dom(DSM/settlement-bundle, CCB(SettlementBundle))`, computed by
//! [`crate::dlv::settlement_bundle`] over the bytes this module emits — never
//! over protobuf, which §2.10 says is never a CCB blob.
//!
//! **Constructors validate; encoders never repair.** The shape rule (§5.19),
//! beta's `|{T_v}| == 1`, the in-bundle structural checks 2c-A owns
//! (`V_{n+1}.parent_state_commitment == T_v.parent_binding`; a close's
//! successor is retired), the fixed lengths 2c-B pins (`entropy` 32,
//! `sigma_dsm` 49,856) and 2c-A.1's rulings (field 4 exactly 49,856 when
//! present; `proof_material` never present; an `AllocationBundle` and a
//! `Route` never empty) are refused at construction, so an object that
//! encodes is one a verifier accepts structurally. What needs `V_n` — the
//! generation, the storage set, the quorum, every field disposition — is
//! 2c-C3's and is derived from `VDS.COMMON.10.a`, not re-checked here.
//!
//! **The successor is carried complete, once.** `0x000F` field 2 is the whole
//! nested `0x0001` schema 4 state; `c_{n+1}` is derived from those bytes and
//! never carried beside them (§5.21), which is what gives `VDS.COMMON.10.a`
//! its second operand.

use super::state::{FeePolicy, VaultStateV2};
use super::{
    class, push_absent, push_bytes, push_digest32, push_envelope, push_present, push_u32, push_u64,
    CcbError, CcbObject,
};

/// The one signature length schema 1 accepts wherever a `SPHINCS_PLUS_SPX256F`
/// signature is carried (`0x000F` field 4, `0x0031` field 7).
pub const SPX256F_SIGNATURE_LEN: usize = 49_856;

/// `0x0031` field 5 — a BLAKE3 output, exactly this long.
pub const ENTROPY_LEN: usize = 32;

/// The beta transition cardinality of a bundle (2c-A ruling 3).
pub const BETA_TRANSITIONS: usize = 1;

fn require_len(field: &'static str, v: &[u8], expected: usize) -> Result<(), CcbError> {
    if v.len() == expected {
        Ok(())
    } else {
        Err(CcbError::FixedLength {
            field,
            expected,
            got: v.len(),
        })
    }
}

// ── 0x000B TradeIntent ──────────────────────────────────────────────────────

/// §5.5 — the nine members of `TradeIntent`, in order. No expiry, no
/// timestamp, no duration: §9.1 excludes them and §2.8 forbids adding one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeIntent {
    pub token_in: [u8; 32],
    pub amount_in: u64,
    pub token_out: [u8; 32],
    pub min_out: u64,
    pub max_fee: u64,
    pub max_hops: u32,
    pub max_fanout: u32,
    pub k: u32,
    pub nonce: [u8; 32],
}

impl CcbObject for TradeIntent {
    const CLASS: u16 = class::TRADE_INTENT;
    const SCHEMA: u16 = 1;
}

impl TradeIntent {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.token_in); // 1
        push_u64(&mut out, self.amount_in); // 2
        push_digest32(&mut out, &self.token_out); // 3
        push_u64(&mut out, self.min_out); // 4
        push_u64(&mut out, self.max_fee); // 5
        push_u32(&mut out, self.max_hops); // 6
        push_u32(&mut out, self.max_fanout); // 7
        push_u32(&mut out, self.k); // 8
        push_digest32(&mut out, &self.nonce); // 9
        out
    }
}

// ── 0x0015 Allocation (schema 2) ────────────────────────────────────────────

/// §5.10 — `a = (parent_binding, Δ_in, Δ_out, e, Φ)`. No `vault_id`: `c_n`
/// commits it, and a carried copy could disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub parent_binding: [u8; 32],
    pub delta_in: u64,
    pub delta_out: u64,
    pub encumbrance_claim: [u8; 32],
    pub fee_policy: FeePolicy,
}

impl CcbObject for Allocation {
    /// Schema 2: `p_v` became `c_n`; schema 1 is burned.
    const CLASS: u16 = class::ALLOCATION;
    const SCHEMA: u16 = 2;
}

impl Allocation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.parent_binding); // 1
        push_u64(&mut out, self.delta_in); // 2
        push_u64(&mut out, self.delta_out); // 3
        push_digest32(&mut out, &self.encumbrance_claim); // 4
        out.extend_from_slice(&self.fee_policy.encode()); // 5
        out
    }
}

// ── 0x0016 AllocationBundle (schema 2) ──────────────────────────────────────

/// §5.11 — a same-pair fan-out, `1 ≤ f ≤ max_fanout`, ordered by complete
/// element CCB (§2.4). `max_fanout` is `TradeIntent` field 7 and is checked
/// against the count there, not carried here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationBundle {
    allocations: Vec<Allocation>,
}

impl CcbObject for AllocationBundle {
    const CLASS: u16 = class::ALLOCATION_BUNDLE;
    const SCHEMA: u16 = 2;
}

impl AllocationBundle {
    /// Sorts by element encoding; refuses an empty bundle and a duplicate.
    pub fn new(allocations: Vec<Allocation>) -> Result<Self, CcbError> {
        if allocations.is_empty() {
            return Err(CcbError::EmptySequence {
                class: class::ALLOCATION_BUNDLE,
            });
        }
        let mut encoded: Vec<Vec<u8>> = allocations.iter().map(Allocation::encode).collect();
        encoded.sort_unstable();
        if encoded.windows(2).any(|w| w[0] == w[1]) {
            return Err(CcbError::DuplicateSetElement {
                class: class::ALLOCATION_BUNDLE,
            });
        }
        let mut allocations = allocations;
        allocations.sort_by_cached_key(Allocation::encode);
        Ok(Self { allocations })
    }

    pub fn allocations(&self) -> &[Allocation] {
        &self.allocations
    }

    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        let count = u32::try_from(self.allocations.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, count);
        for a in &self.allocations {
            out.extend_from_slice(&a.encode());
        }
        Ok(out)
    }
}

// ── 0x000D Route (schema 2) ─────────────────────────────────────────────────

/// One hop: a single allocation or a same-pair bundle. The envelope of the
/// nested object is the discriminant; there is no tag beside it (§5.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteLeg {
    Single(Allocation),
    Bundle(AllocationBundle),
}

impl RouteLeg {
    fn encode(&self) -> Result<Vec<u8>, CcbError> {
        match self {
            RouteLeg::Single(a) => Ok(a.encode()),
            RouteLeg::Bundle(b) => b.encode(),
        }
    }
}

/// §5.13 — a SEQUENCE of legs in execution order, never sorted: reordering
/// hops is a different route. A route with no legs executes nothing and is
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    legs: Vec<RouteLeg>,
}

impl CcbObject for Route {
    const CLASS: u16 = class::ROUTE;
    const SCHEMA: u16 = 2;
}

impl Route {
    pub fn new(legs: Vec<RouteLeg>) -> Result<Self, CcbError> {
        if legs.is_empty() {
            return Err(CcbError::EmptySequence {
                class: class::ROUTE,
            });
        }
        Ok(Self { legs })
    }

    pub fn legs(&self) -> &[RouteLeg] {
        &self.legs
    }

    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        let count = u32::try_from(self.legs.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, count);
        for leg in &self.legs {
            out.extend_from_slice(&leg.encode()?);
        }
        Ok(out)
    }
}

// ── 0x0031 DsmSuccessorEvidence (substrate, 2c-B) ───────────────────────────

/// §5.23 — the trader's ordinary-DSM successor evidence, carried inside
/// `MarketTerms` so a crashed or foreign verifier can reconstruct exactly
/// `trader_parent → trader_successor`. `c_dsm_plus` is NOT a field (2c-B
/// ruling 1: recompute, never restate); field 6 `encapsulated_entropy` is
/// always absent in this profile and has no member here — the encoder emits
/// its absence marker, and the decoder refuses presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsmSuccessorEvidence {
    pub rel_key: [u8; 32],
    /// Must equal `MarketTerms.trader_parent`; carried so the equality is
    /// checked, not assumed.
    pub embedded_parent: [u8; 32],
    pub counterparty_devid: [u8; 32],
    /// A `DlvSettleOperationPreimageV1` — a foreign, little-endian grammar
    /// frozen by 2c-B and carried opaquely here (§2.10 permits it).
    pub operation_bytes: Vec<u8>,
    pub entropy: [u8; 32],
    /// Exactly [`SPX256F_SIGNATURE_LEN`] bytes.
    sigma_dsm: Vec<u8>,
}

impl CcbObject for DsmSuccessorEvidence {
    const CLASS: u16 = class::DSM_SUCCESSOR_EVIDENCE;
    const SCHEMA: u16 = 1;
}

impl DsmSuccessorEvidence {
    /// Refuses empty operation bytes and any signature length but 49,856.
    pub fn new(
        rel_key: [u8; 32],
        embedded_parent: [u8; 32],
        counterparty_devid: [u8; 32],
        operation_bytes: Vec<u8>,
        entropy: [u8; 32],
        sigma_dsm: Vec<u8>,
    ) -> Result<Self, CcbError> {
        if operation_bytes.is_empty() {
            return Err(CcbError::EmptyBytes {
                field: "operation_bytes",
            });
        }
        require_len("sigma_dsm", &sigma_dsm, SPX256F_SIGNATURE_LEN)?;
        Ok(Self {
            rel_key,
            embedded_parent,
            counterparty_devid,
            operation_bytes,
            entropy,
            sigma_dsm,
        })
    }

    pub fn sigma_dsm(&self) -> &[u8] {
        &self.sigma_dsm
    }

    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.rel_key); // 1
        push_digest32(&mut out, &self.embedded_parent); // 2
        push_digest32(&mut out, &self.counterparty_devid); // 3
        push_bytes(&mut out, &self.operation_bytes)?; // 4
        push_bytes(&mut out, &self.entropy)?; // 5 — `bytes`, exactly 32
        push_absent(&mut out); // 6 encapsulated_entropy — always absent
        push_bytes(&mut out, &self.sigma_dsm)?; // 7
        Ok(out)
    }
}

// ── 0x0033 MarketTerms ──────────────────────────────────────────────────────

/// §5.20 — everything a market settlement has and an owner close does not.
/// Nested by value in `0x000E` field 1; never separately content-addressed.
/// `I = H_dom(DSM/intent, CCB(intent))` is derived, never carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketTerms {
    pub intent: TradeIntent,
    /// `X = H_dom(DSM/route-set, CCB(Q))`; `Q` itself lives in the receipt
    /// publication set (2c-A ruling 2).
    pub route_set_commitment: [u8; 32],
    pub selected_route: Route,
    /// The exact ordinary-DSM bilateral parent-state commitment of the TRADER
    /// — never the vault's `c_n` (5c-2 amendment A: two coordinate systems).
    pub trader_parent: [u8; 32],
    /// The exact prepared `C_dsm+`.
    pub trader_successor: [u8; 32],
    /// Mandatory: a market bundle without it is unencodable, not invalid.
    pub recovery_material: DsmSuccessorEvidence,
}

impl CcbObject for MarketTerms {
    const CLASS: u16 = class::MARKET_TERMS;
    const SCHEMA: u16 = 1;
}

impl MarketTerms {
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        out.extend_from_slice(&self.intent.encode()); // 1
        push_digest32(&mut out, &self.route_set_commitment); // 2
        out.extend_from_slice(&self.selected_route.encode()?); // 3
        push_digest32(&mut out, &self.trader_parent); // 4
        push_digest32(&mut out, &self.trader_successor); // 5
        out.extend_from_slice(&self.recovery_material.encode()?); // 6
        Ok(out)
    }
}

// ── 0x0010 DlvProofMaterial ─────────────────────────────────────────────────

/// §5.22 — zero fields; the bare envelope is defined and never emitted, because
/// beta encodes `0x000F` field 3 absent and schema 1 refuses it present. The
/// type exists so the class constant has an owner and the propagation rule has
/// something to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlvProofMaterial;

impl CcbObject for DlvProofMaterial {
    const CLASS: u16 = class::DLV_PROOF_MATERIAL;
    const SCHEMA: u16 = 1;
}

impl DlvProofMaterial {
    /// The 4-byte envelope, for the vector that pins it. Nothing in
    /// production calls this.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        out
    }
}

// ── 0x000F ConsumedDlvTransition ────────────────────────────────────────────

/// §5.21 — the exact consumed parent by commitment, the complete proposed
/// successor by value, and the per-transition owner-authorization marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedDlvTransition {
    pub parent_binding: [u8; 32],
    pub successor: VaultStateV2,
    /// Present iff owner close: one `SPHINCS_PLUS_SPX256F` signature over the
    /// `CloseAuthorizationPreimageV1` bytes 2c-B freezes.
    close_authorization: Option<Vec<u8>>,
}

impl CcbObject for ConsumedDlvTransition {
    const CLASS: u16 = class::CONSUMED_DLV_TRANSITION;
    const SCHEMA: u16 = 1;
}

impl ConsumedDlvTransition {
    /// A market transition: no authorization marker. Refuses a successor whose
    /// field 12 is not this parent (the in-bundle linkage check, §5.21).
    pub fn market(parent_binding: [u8; 32], successor: VaultStateV2) -> Result<Self, CcbError> {
        Self::linked(parent_binding, &successor)?;
        Ok(Self {
            parent_binding,
            successor,
            close_authorization: None,
        })
    }

    /// An owner-close transition. Refuses a signature of any length but
    /// 49,856 (2c-A.1 ruling 5), a successor not linked to this parent, and a
    /// successor that is not retired — both legs zero (2c-A structural
    /// checks; 2c-C3 erratum D2).
    pub fn owner_close(
        parent_binding: [u8; 32],
        successor: VaultStateV2,
        close_authorization: Vec<u8>,
    ) -> Result<Self, CcbError> {
        Self::linked(parent_binding, &successor)?;
        require_len(
            "close_authorization",
            &close_authorization,
            SPX256F_SIGNATURE_LEN,
        )?;
        if successor.reserve_a != 0 || successor.reserve_b != 0 {
            return Err(CcbError::CloseSuccessorNotRetired {
                reserve_a: successor.reserve_a,
                reserve_b: successor.reserve_b,
            });
        }
        Ok(Self {
            parent_binding,
            successor,
            close_authorization: Some(close_authorization),
        })
    }

    fn linked(parent_binding: [u8; 32], successor: &VaultStateV2) -> Result<(), CcbError> {
        if successor.parent_state_commitment != parent_binding {
            return Err(CcbError::ParentLinkage);
        }
        Ok(())
    }

    pub fn close_authorization(&self) -> Option<&[u8]> {
        self.close_authorization.as_deref()
    }

    pub fn is_owner_close(&self) -> bool {
        self.close_authorization.is_some()
    }

    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.parent_binding); // 1
        out.extend_from_slice(&self.successor.encode()?); // 2 — complete 0x0001 s4
        push_absent(&mut out); // 3 proof_material — beta always absent
        match &self.close_authorization {
            // 4
            None => push_absent(&mut out),
            Some(sig) => {
                push_present(&mut out);
                push_bytes(&mut out, sig)?;
            }
        }
        Ok(out)
    }
}

// ── 0x000E SettlementBundle ─────────────────────────────────────────────────

/// The two shapes a bundle may take, decided by field 1 alone (§5.19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleShape {
    Market,
    OwnerClose,
}

/// §5.19 — `B`. Constructed only through [`SettlementBundle::market`] and
/// [`SettlementBundle::owner_close`], so an object that exists satisfies the
/// shape rule and the beta cardinality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementBundle {
    market_terms: Option<MarketTerms>,
    transitions: Vec<ConsumedDlvTransition>,
}

impl CcbObject for SettlementBundle {
    const CLASS: u16 = class::SETTLEMENT_BUNDLE;
    const SCHEMA: u16 = 1;
}

impl SettlementBundle {
    /// A market bundle: terms present, exactly one transition (beta), and that
    /// transition carries no close authorization.
    pub fn market(
        terms: MarketTerms,
        transitions: Vec<ConsumedDlvTransition>,
    ) -> Result<Self, CcbError> {
        Self::beta_cardinality(&transitions)?;
        if transitions
            .iter()
            .any(ConsumedDlvTransition::is_owner_close)
        {
            return Err(CcbError::BundleShape(
                "a market bundle carries a close authorization",
            ));
        }
        Ok(Self {
            market_terms: Some(terms),
            transitions,
        })
    }

    /// An owner close: no terms, exactly one transition, and it is authorized.
    pub fn owner_close(transition: ConsumedDlvTransition) -> Result<Self, CcbError> {
        if !transition.is_owner_close() {
            return Err(CcbError::BundleShape(
                "an owner close carries no close authorization",
            ));
        }
        Ok(Self {
            market_terms: None,
            transitions: vec![transition],
        })
    }

    fn beta_cardinality(transitions: &[ConsumedDlvTransition]) -> Result<(), CcbError> {
        if transitions.len() != BETA_TRANSITIONS {
            return Err(CcbError::TransitionCount {
                got: transitions.len(),
            });
        }
        Ok(())
    }

    pub fn shape(&self) -> BundleShape {
        if self.market_terms.is_some() {
            BundleShape::Market
        } else {
            BundleShape::OwnerClose
        }
    }

    pub fn market_terms(&self) -> Option<&MarketTerms> {
        self.market_terms.as_ref()
    }

    /// The transitions in canonical (§2.4) order. With beta's cardinality of
    /// one, ordering is trivial; it is still the set's order.
    pub fn transitions(&self) -> &[ConsumedDlvTransition] {
        &self.transitions
    }

    /// The transition whose parent is `c_n`, if any (2c-A.1 ruling 7).
    pub fn transition_for_parent(&self, c_n: &[u8; 32]) -> Option<&ConsumedDlvTransition> {
        self.transitions.iter().find(|t| t.parent_binding == *c_n)
    }

    /// `CCB(SettlementBundle)`: field 1 with its marker always emitted, then
    /// the transition set ordered by complete element encoding.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        match &self.market_terms {
            // 1
            None => push_absent(&mut out),
            Some(t) => {
                push_present(&mut out);
                out.extend_from_slice(&t.encode()?);
            }
        }
        let mut encoded: Vec<Vec<u8>> = self
            .transitions
            .iter()
            .map(ConsumedDlvTransition::encode)
            .collect::<Result<_, _>>()?;
        encoded.sort_unstable();
        if encoded.windows(2).any(|w| w[0] == w[1]) {
            return Err(CcbError::DuplicateSetElement {
                class: class::SETTLEMENT_BUNDLE,
            });
        }
        let count = u32::try_from(encoded.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, count); // 2
        for t in encoded {
            out.extend_from_slice(&t);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::ccb::state::{EncumbranceSet, MarketPolicy, ReleasePolicy, StorageSetMembers};

    fn members() -> StorageSetMembers {
        StorageSetMembers::new(&[
            (b"node-1".as_slice(), [0x11; 32]),
            (b"node-2".as_slice(), [0x22; 32]),
            (b"node-3".as_slice(), [0x33; 32]),
        ])
        .unwrap()
    }

    /// The 2c-A worked fixture: zero claims, three 6-byte members, budget
    /// absent — a 423-byte `V_{n+1}`.
    fn successor(parent: [u8; 32], reserve_a: u64, reserve_b: u64) -> VaultStateV2 {
        VaultStateV2 {
            owner_genesis_id: [0x01; 32],
            owner_device_id: [0x02; 32],
            vault_id: [0x03; 32],
            generation: 8,
            reserve_a,
            reserve_b,
            market_policy: MarketPolicy::beta_constant_product([0x10; 32], [0x20; 32]).unwrap(),
            release_policy: ReleasePolicy::beta_owner_local_full_close(),
            fee_policy: FeePolicy::new(30).unwrap(),
            encumbrances: EncumbranceSet::empty(),
            iteration_budget: None,
            parent_state_commitment: parent,
            owner_authority_transition_digest: [0x0D; 32],
            storage_set: members(),
            quorum: 2,
        }
    }

    fn sig() -> Vec<u8> {
        vec![0xA5; SPX256F_SIGNATURE_LEN]
    }

    fn evidence() -> DsmSuccessorEvidence {
        DsmSuccessorEvidence::new(
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            vec![0x1A; 300],
            [0x55; 32],
            vec![0x57; SPX256F_SIGNATURE_LEN],
        )
        .unwrap()
    }

    fn intent() -> TradeIntent {
        TradeIntent {
            token_in: [0x10; 32],
            amount_in: 10_000,
            token_out: [0x20; 32],
            min_out: 4_900,
            max_fee: 100,
            max_hops: 1,
            max_fanout: 1,
            k: 1,
            nonce: [0x5E; 32],
        }
    }

    fn allocation(parent: [u8; 32]) -> Allocation {
        Allocation {
            parent_binding: parent,
            delta_in: 10_000,
            delta_out: 4_935,
            encumbrance_claim: [0x00; 32],
            fee_policy: FeePolicy::new(30).unwrap(),
        }
    }

    fn terms(parent: [u8; 32]) -> MarketTerms {
        MarketTerms {
            intent: intent(),
            route_set_commitment: [0x58; 32],
            selected_route: Route::new(vec![RouteLeg::Single(allocation(parent))]).unwrap(),
            trader_parent: [0x52; 32],
            trader_successor: [0x59; 32],
            recovery_material: evidence(),
        }
    }

    // ── the worked owner-close layout, byte for byte where 2c-A pins it ──

    #[test]
    fn the_owner_close_fixture_is_exactly_the_worked_size() {
        let parent = [0xC0; 32];
        let v = successor(parent, 0, 0);
        assert_eq!(v.encode().unwrap().len(), 423, "0x0001 schema 4 fixture");
        let t = ConsumedDlvTransition::owner_close(parent, v, sig()).unwrap();
        assert_eq!(t.encode().unwrap().len(), 50_321, "0x000F");
        let b = SettlementBundle::owner_close(t).unwrap();
        let bytes = b.encode().unwrap();
        assert_eq!(bytes.len(), 50_330, "0x000E owner close");
        // 2c-A's layout: envelope, field 1 ABSENT, count = 1, then 0x000F.
        assert_eq!(
            &bytes[..9],
            &[0x00, 0x0E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(&bytes[9..13], &[0x00, 0x0F, 0x00, 0x01]);
        assert_eq!(&bytes[13..45], &parent, "parent_binding is a bare digest32");
        assert_eq!(
            &bytes[45..49],
            &[0x00, 0x01, 0x00, 0x04],
            "successor is 0x0001 schema 4"
        );
        assert_eq!(b.shape(), BundleShape::OwnerClose);
    }

    #[test]
    fn a_market_bundle_encodes_with_field_one_present_and_no_authorization() {
        let parent = [0xC1; 32];
        let t =
            ConsumedDlvTransition::market(parent, successor(parent, 1_010_000, 495_065)).unwrap();
        let b = SettlementBundle::market(terms(parent), vec![t]).unwrap();
        let bytes = b.encode().unwrap();
        assert_eq!(&bytes[..5], &[0x00, 0x0E, 0x00, 0x01, 0x01]);
        assert_eq!(
            &bytes[5..9],
            &[0x00, 0x33, 0x00, 0x01],
            "MarketTerms follows the marker"
        );
        assert_eq!(b.shape(), BundleShape::Market);
        // The transition's last two bytes: proof_material absent, field 4 absent.
        assert_eq!(&bytes[bytes.len() - 2..], &[0x00, 0x00]);
    }

    // ── the shape rule and the structural checks refuse at construction ──

    #[test]
    fn the_shape_rule_is_enforced_by_the_constructors() {
        let parent = [0xC2; 32];
        let close =
            ConsumedDlvTransition::owner_close(parent, successor(parent, 0, 0), sig()).unwrap();
        assert_eq!(
            SettlementBundle::market(terms(parent), vec![close.clone()]),
            Err(CcbError::BundleShape(
                "a market bundle carries a close authorization"
            ))
        );
        let market = ConsumedDlvTransition::market(parent, successor(parent, 1, 1)).unwrap();
        assert_eq!(
            SettlementBundle::owner_close(market.clone()),
            Err(CcbError::BundleShape(
                "an owner close carries no close authorization"
            ))
        );
        assert_eq!(
            SettlementBundle::market(terms(parent), vec![market.clone(), market]),
            Err(CcbError::TransitionCount { got: 2 })
        );
        assert_eq!(
            SettlementBundle::market(terms(parent), vec![]),
            Err(CcbError::TransitionCount { got: 0 })
        );
    }

    #[test]
    fn a_successor_not_linked_to_its_parent_is_refused() {
        let parent = [0xC3; 32];
        let wrong = successor([0xC4; 32], 0, 0);
        assert_eq!(
            ConsumedDlvTransition::market(parent, wrong.clone()),
            Err(CcbError::ParentLinkage)
        );
        assert_eq!(
            ConsumedDlvTransition::owner_close(parent, wrong, sig()),
            Err(CcbError::ParentLinkage)
        );
    }

    #[test]
    fn a_close_whose_successor_is_not_retired_is_refused() {
        let parent = [0xC5; 32];
        assert_eq!(
            ConsumedDlvTransition::owner_close(parent, successor(parent, 1, 0), sig()),
            Err(CcbError::CloseSuccessorNotRetired {
                reserve_a: 1,
                reserve_b: 0
            })
        );
    }

    #[test]
    fn a_close_authorization_of_any_other_length_is_refused() {
        let parent = [0xC6; 32];
        for len in [
            0usize,
            1,
            SPX256F_SIGNATURE_LEN - 1,
            SPX256F_SIGNATURE_LEN + 1,
        ] {
            assert_eq!(
                ConsumedDlvTransition::owner_close(parent, successor(parent, 0, 0), vec![0; len]),
                Err(CcbError::FixedLength {
                    field: "close_authorization",
                    expected: SPX256F_SIGNATURE_LEN,
                    got: len
                }),
                "{len}"
            );
        }
    }

    #[test]
    fn evidence_lengths_are_fixed_by_schema_one() {
        assert_eq!(
            DsmSuccessorEvidence::new([0; 32], [0; 32], [0; 32], vec![1], [0; 32], vec![0; 10]),
            Err(CcbError::FixedLength {
                field: "sigma_dsm",
                expected: SPX256F_SIGNATURE_LEN,
                got: 10
            })
        );
        assert_eq!(
            DsmSuccessorEvidence::new(
                [0; 32],
                [0; 32],
                [0; 32],
                vec![],
                [0; 32],
                vec![0; SPX256F_SIGNATURE_LEN]
            ),
            Err(CcbError::EmptyBytes {
                field: "operation_bytes"
            })
        );
        // Field 6 is emitted absent, field 5 as length-prefixed bytes of 32.
        let e = evidence().encode().unwrap();
        let off = 4 + 32 * 3 + 4 + 300;
        assert_eq!(
            &e[off..off + 4],
            &[0, 0, 0, 32],
            "entropy is `bytes`, length 32"
        );
        assert_eq!(e[off + 4 + 32], 0x00, "encapsulated_entropy absent");
    }

    #[test]
    fn a_route_is_a_sequence_and_a_bundle_is_a_set() {
        let a = allocation([0x01; 32]);
        let b = allocation([0x02; 32]);
        let forward = Route::new(vec![
            RouteLeg::Single(a.clone()),
            RouteLeg::Single(b.clone()),
        ])
        .unwrap();
        let backward = Route::new(vec![
            RouteLeg::Single(b.clone()),
            RouteLeg::Single(a.clone()),
        ])
        .unwrap();
        assert_ne!(
            forward.encode().unwrap(),
            backward.encode().unwrap(),
            "hop order is part of the route"
        );
        let set_ab = AllocationBundle::new(vec![a.clone(), b.clone()]).unwrap();
        let set_ba = AllocationBundle::new(vec![b.clone(), a.clone()]).unwrap();
        assert_eq!(
            set_ab.encode().unwrap(),
            set_ba.encode().unwrap(),
            "§2.4 ordering"
        );
        assert_eq!(
            AllocationBundle::new(vec![a.clone(), a.clone()]),
            Err(CcbError::DuplicateSetElement {
                class: class::ALLOCATION_BUNDLE
            })
        );
        assert_eq!(
            AllocationBundle::new(vec![]),
            Err(CcbError::EmptySequence {
                class: class::ALLOCATION_BUNDLE
            })
        );
        assert_eq!(
            Route::new(vec![]),
            Err(CcbError::EmptySequence {
                class: class::ROUTE
            })
        );
    }

    // ── the decoders: strict, and the successor span is the supplied operand ──

    use crate::ccb::decode::{
        decode_settlement_bundle, decode_settlement_bundle_canonical, DecodeError,
    };

    #[test]
    fn both_shapes_round_trip_and_the_successor_span_is_the_exact_nested_bytes() {
        let parent = [0xD0; 32];
        let v = successor(parent, 0, 0);
        let close = SettlementBundle::owner_close(
            ConsumedDlvTransition::owner_close(parent, v.clone(), sig()).unwrap(),
        )
        .unwrap();
        let bytes = close.encode().unwrap();
        let d = decode_settlement_bundle_canonical(&bytes).unwrap();
        assert_eq!(d.bundle, close);
        assert_eq!(d.successor_spans.len(), 1);
        assert_eq!(
            &bytes[d.successor_spans[0].clone()],
            v.encode().unwrap().as_slice()
        );

        let mv = successor(parent, 1_010_000, 495_065);
        let market = SettlementBundle::market(
            terms(parent),
            vec![ConsumedDlvTransition::market(parent, mv.clone()).unwrap()],
        )
        .unwrap();
        let bytes = market.encode().unwrap();
        let d = decode_settlement_bundle_canonical(&bytes).unwrap();
        assert_eq!(d.bundle, market);
        assert_eq!(
            &bytes[d.successor_spans[0].clone()],
            mv.encode().unwrap().as_slice()
        );
        assert_eq!(
            d.bundle
                .transition_for_parent(&parent)
                .map(|t| t.parent_binding),
            Some(parent)
        );
    }

    #[test]
    fn the_decoder_refuses_trailing_bytes_a_present_proof_material_and_a_wrong_field_four() {
        let parent = [0xD1; 32];
        let close = SettlementBundle::owner_close(
            ConsumedDlvTransition::owner_close(parent, successor(parent, 0, 0), sig()).unwrap(),
        )
        .unwrap();
        let mut bytes = close.encode().unwrap();
        bytes.push(0);
        assert_eq!(
            decode_settlement_bundle(&bytes),
            Err(DecodeError::TrailingBytes { extra: 1 })
        );
        bytes.pop();
        // field 3 sits right after the 423-byte successor: bytes[13 + 32 + 423].
        let f3 = 13 + 32 + 423;
        assert_eq!(bytes[f3], 0x00);
        let mut present = bytes.clone();
        present[f3] = 0x01;
        assert!(matches!(
            decode_settlement_bundle(&present),
            Err(DecodeError::Invalid(m)) if m.contains("proof_material")
        ));
        // field 4 length prefix follows the field-4 marker: shorten it by one.
        let f4_len = f3 + 2;
        let mut short = bytes.clone();
        short[f4_len..f4_len + 4]
            .copy_from_slice(&((SPX256F_SIGNATURE_LEN - 1) as u32).to_be_bytes());
        short.pop();
        assert!(matches!(
            decode_settlement_bundle(&short),
            Err(DecodeError::Invalid(m)) if m.contains("close_authorization")
        ));
    }

    #[test]
    fn a_non_canonical_nested_successor_is_refused_by_the_round_trip() {
        // Two claims emitted in the wrong order inside the nested successor:
        // the constructor cannot represent that, so the decoder rebuilds a
        // sorted set and the re-encoding differs from the input.
        use crate::ccb::state::EncumbranceClaim;
        let parent = [0xD2; 32];
        let claim = |seq: u64| EncumbranceClaim {
            parent_binding: parent,
            claim_seq: seq,
            amount: 5,
            token: [0x10; 32],
            purpose: 1,
        };
        let mut v = successor(parent, 7, 7);
        v.encumbrances = EncumbranceSet::new(vec![claim(1), claim(2)]).unwrap();
        let canonical_v = v.encode().unwrap();
        let t = ConsumedDlvTransition::market(parent, v).unwrap();
        let b = SettlementBundle::market(terms(parent), vec![t]).unwrap();
        let bytes = b.encode().unwrap();
        // Locate the two claims inside the successor and swap them.
        let c1 = claim(1).encode();
        let c2 = claim(2).encode();
        let pos = bytes
            .windows(c1.len() + c2.len())
            .position(|w| w == [c1.clone(), c2.clone()].concat())
            .expect("the claims are adjacent and canonical in the input");
        let mut swapped = bytes.clone();
        swapped[pos..pos + c1.len() + c2.len()].copy_from_slice(&[c2.clone(), c1.clone()].concat());
        assert_ne!(swapped, bytes);
        assert!(
            decode_settlement_bundle(&swapped).is_ok(),
            "the plain decoder normalizes"
        );
        assert!(matches!(
            decode_settlement_bundle_canonical(&swapped),
            Err(DecodeError::Invalid(m)) if m.contains("re-encode")
        ));
        let _ = canonical_v;
    }

    #[test]
    fn a_misordered_allocation_bundle_and_a_present_encapsulated_entropy_are_refused() {
        let a = allocation([0x01; 32]);
        let b = allocation([0x02; 32]);
        let bundle = AllocationBundle::new(vec![a.clone(), b.clone()]).unwrap();
        let canonical = bundle.encode().unwrap();
        let mut swapped = [canonical[..8].to_vec(), b.encode(), a.encode()].concat();
        assert_eq!(swapped.len(), canonical.len());
        let mut c = crate::ccb::decode::Cursor { b: &swapped, i: 0 };
        assert!(matches!(
            crate::ccb::decode::allocation_bundle_at(&mut c),
            Err(DecodeError::Invalid(m)) if m.contains("canonical order")
        ));
        swapped.clear();

        let e = evidence().encode().unwrap();
        let off = 4 + 32 * 3 + 4 + 300 + 4 + 32;
        let mut present = e.clone();
        present[off] = 0x01;
        let mut c = crate::ccb::decode::Cursor { b: &present, i: 0 };
        assert!(matches!(
            crate::ccb::decode::dsm_successor_evidence_at(&mut c),
            Err(DecodeError::Invalid(m)) if m.contains("encapsulated_entropy")
        ));
    }

    #[test]
    fn the_proof_material_envelope_is_four_bytes_and_never_emitted() {
        assert_eq!(DlvProofMaterial.encode(), vec![0x00, 0x10, 0x00, 0x01]);
        let parent = [0xC7; 32];
        let t = ConsumedDlvTransition::market(parent, successor(parent, 1, 1)).unwrap();
        let bytes = t.encode().unwrap();
        // field 3 is the byte after the 423-byte successor.
        assert_eq!(bytes[4 + 32 + 423], 0x00);
    }
}
