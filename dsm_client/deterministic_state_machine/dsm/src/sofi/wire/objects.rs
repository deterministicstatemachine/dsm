// SPDX-License-Identifier: Apache-2.0

//! SoFi v8 wire objects: validating constructors, canonical encoders and
//! strict decoders for the field tables in [`super`].

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::{class, push_bytes, push_digest32, push_u16, push_u32, push_u64, sigalg};

use super::{SofiWireError, MAX_CLOSURE_REFS, ROUTE_MAX_LEGS, ROUTE_MIN_LEGS};

/// Every v8 object ships at schema 1.
pub const SCHEMA_V1: u16 = 1;

type D32 = [u8; 32];

// ── shared validation and primitive helpers ────────────────────────────────

fn push_env(out: &mut Vec<u8>, object_class: u16) {
    push_u16(out, object_class);
    push_u16(out, SCHEMA_V1);
}

fn wire_invalid(e: SofiWireError) -> DecodeError {
    DecodeError::Invalid(e.to_string())
}

fn check_key(alg: u16, key: &[u8]) -> Result<(), SofiWireError> {
    let expected = sigalg::public_key_len(alg).ok_or(SofiWireError::UnknownSignatureAlg { alg })?;
    if key.len() != expected {
        return Err(SofiWireError::KeyLengthMismatch {
            expected,
            got: key.len(),
        });
    }
    Ok(())
}

fn check_count(
    field: &'static str,
    min: usize,
    max: usize,
    got: usize,
) -> Result<(), SofiWireError> {
    if got < min || got > max {
        return Err(SofiWireError::Cardinality {
            field,
            min,
            max,
            got,
        });
    }
    Ok(())
}

fn check_strictly_ascending<K: Ord>(field: &'static str, keys: &[K]) -> Result<(), SofiWireError> {
    for (i, w) in keys.windows(2).enumerate() {
        if w[0] >= w[1] {
            return Err(SofiWireError::NotStrictlyAscending {
                field,
                index: i + 1,
            });
        }
    }
    Ok(())
}

/// Read a sequence count and refuse it BEFORE allocating, so a hostile count
/// cannot become an allocation.
fn read_count(
    c: &mut Cursor<'_>,
    field: &'static str,
    min: usize,
    max: usize,
) -> Result<usize, DecodeError> {
    let n = c.u32()? as usize;
    check_count(field, min, max, n).map_err(wire_invalid)?;
    Ok(n)
}

fn read_key(c: &mut Cursor<'_>) -> Result<(u16, Vec<u8>), DecodeError> {
    let alg = c.u16()?;
    let len = c.u32()? as usize;
    // Bound the take by the declared width before touching the bytes.
    let expected = sigalg::public_key_len(alg)
        .ok_or(SofiWireError::UnknownSignatureAlg { alg })
        .map_err(wire_invalid)?;
    if len != expected {
        return Err(wire_invalid(SofiWireError::KeyLengthMismatch {
            expected,
            got: len,
        }));
    }
    Ok((alg, c.take(len)?.to_vec()))
}

fn finish<T>(c: &Cursor<'_>, value: T) -> Result<T, DecodeError> {
    if c.i != c.b.len() {
        return Err(DecodeError::TrailingBytes {
            extra: c.b.len() - c.i,
        });
    }
    Ok(value)
}

fn push_key(out: &mut Vec<u8>, alg: u16, key: &[u8]) {
    push_u16(out, alg);
    // Width is fixed by the validated algorithm, so this cannot overflow.
    let _ = push_bytes(out, key);
}

// ── 0x0036 SofiSetupBody ───────────────────────────────────────────────────

/// The relationship setup claim (F1). Identity is `ρ` over these bytes; the
/// signature envelope is authorization, never identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SofiSetupBody {
    genesis: D32,
    device_id: D32,
    position: u64,
    vault_id: D32,
    claim_ref: D32,
    setup_root: D32,
    signature_alg: u16,
    claimant_public_key: Vec<u8>,
}

impl SofiSetupBody {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis: D32,
        device_id: D32,
        position: u64,
        vault_id: D32,
        claim_ref: D32,
        setup_root: D32,
        signature_alg: u16,
        claimant_public_key: &[u8],
    ) -> Result<Self, SofiWireError> {
        check_key(signature_alg, claimant_public_key)?;
        Ok(Self {
            genesis,
            device_id,
            position,
            vault_id,
            claim_ref,
            setup_root,
            signature_alg,
            claimant_public_key: claimant_public_key.to_vec(),
        })
    }

    pub fn genesis(&self) -> &D32 {
        &self.genesis
    }
    pub fn device_id(&self) -> &D32 {
        &self.device_id
    }
    pub fn position(&self) -> u64 {
        self.position
    }
    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }
    pub fn claim_ref(&self) -> &D32 {
        &self.claim_ref
    }
    pub fn setup_root(&self) -> &D32 {
        &self.setup_root
    }
    pub fn signature_alg(&self) -> u16 {
        self.signature_alg
    }
    pub fn claimant_public_key(&self) -> &[u8] {
        &self.claimant_public_key
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_SETUP_BODY);
        push_digest32(&mut out, &self.genesis);
        push_digest32(&mut out, &self.device_id);
        push_u64(&mut out, self.position);
        push_digest32(&mut out, &self.vault_id);
        push_digest32(&mut out, &self.claim_ref);
        push_digest32(&mut out, &self.setup_root);
        push_key(&mut out, self.signature_alg, &self.claimant_public_key);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_SETUP_BODY, SCHEMA_V1)?;
        let genesis = c.digest32()?;
        let device_id = c.digest32()?;
        let position = c.u64()?;
        let vault_id = c.digest32()?;
        let claim_ref = c.digest32()?;
        let setup_root = c.digest32()?;
        let (alg, key) = read_key(&mut c)?;
        let v = Self::new(
            genesis, device_id, position, vault_id, claim_ref, setup_root, alg, &key,
        )
        .map_err(wire_invalid)?;
        finish(&c, v)
    }
}

// ── ParentClaimRef: 0x003B | 0x003C ────────────────────────────────────────

/// The exact trader parent `T0`. The nested envelope is the discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentClaimRef {
    /// An exact single-root economic claim, by its exact envelope digest.
    SingleRoot { claim_ref: D32 },
    /// A conditional SoFi position, by the fulfillment that installed it.
    Conditional { fulfillment_id: D32 },
}

impl ParentClaimRef {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::SingleRoot { claim_ref } => {
                push_env(&mut out, class::SOFI_PARENT_SINGLE_ROOT_CLAIM);
                push_digest32(&mut out, claim_ref);
            }
            Self::Conditional { fulfillment_id } => {
                push_env(&mut out, class::SOFI_PARENT_CONDITIONAL_CLAIM);
                push_digest32(&mut out, fulfillment_id);
            }
        }
        out
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        match c.peek_class()? {
            class::SOFI_PARENT_SINGLE_ROOT_CLAIM => {
                c.envelope(class::SOFI_PARENT_SINGLE_ROOT_CLAIM, SCHEMA_V1)?;
                Ok(Self::SingleRoot {
                    claim_ref: c.digest32()?,
                })
            }
            class::SOFI_PARENT_CONDITIONAL_CLAIM => {
                c.envelope(class::SOFI_PARENT_CONDITIONAL_CLAIM, SCHEMA_V1)?;
                Ok(Self::Conditional {
                    fulfillment_id: c.digest32()?,
                })
            }
            got => Err(DecodeError::WrongClass { got }),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
        finish(&c, v)
    }
}

// ── 0x0037 TraderPrecommitBody ─────────────────────────────────────────────

/// One DLV leg of `P`: the exact parent state named, and the relationship
/// reference the trader uses for that vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecommitLeg {
    pub vault_id: D32,
    pub parent_root: D32,
    pub setup_ref: D32,
}

/// `P` — the trader's unilateral, non-economic pre-commit (F2 stage 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraderPrecommitBody {
    genesis: D32,
    device_id: D32,
    position: u64,
    parent_claim_ref: ParentClaimRef,
    external_commitment: D32,
    legs: Vec<PrecommitLeg>,
    realize_root: D32,
    void_root: D32,
    storage_set_id: D32,
    signature_alg: u16,
    claimant_public_key: Vec<u8>,
}

impl TraderPrecommitBody {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis: D32,
        device_id: D32,
        position: u64,
        parent_claim_ref: ParentClaimRef,
        external_commitment: D32,
        legs: Vec<PrecommitLeg>,
        realize_root: D32,
        void_root: D32,
        storage_set_id: D32,
        signature_alg: u16,
        claimant_public_key: &[u8],
    ) -> Result<Self, SofiWireError> {
        // A pre-commit at the last position names a successor that cannot exist.
        super::next_position(position)?;
        check_count("precommit legs", 1, ROUTE_MAX_LEGS, legs.len())?;
        let keys: Vec<D32> = legs.iter().map(|l| l.vault_id).collect();
        check_strictly_ascending("precommit legs", &keys)?;
        check_key(signature_alg, claimant_public_key)?;
        Ok(Self {
            genesis,
            device_id,
            position,
            parent_claim_ref,
            external_commitment,
            legs,
            realize_root,
            void_root,
            storage_set_id,
            signature_alg,
            claimant_public_key: claimant_public_key.to_vec(),
        })
    }

    pub fn genesis(&self) -> &D32 {
        &self.genesis
    }
    pub fn device_id(&self) -> &D32 {
        &self.device_id
    }
    pub fn position(&self) -> u64 {
        self.position
    }
    pub fn parent_claim_ref(&self) -> &ParentClaimRef {
        &self.parent_claim_ref
    }
    pub fn external_commitment(&self) -> &D32 {
        &self.external_commitment
    }
    pub fn legs(&self) -> &[PrecommitLeg] {
        &self.legs
    }
    pub fn realize_root(&self) -> &D32 {
        &self.realize_root
    }
    pub fn void_root(&self) -> &D32 {
        &self.void_root
    }
    pub fn storage_set_id(&self) -> &D32 {
        &self.storage_set_id
    }
    pub fn signature_alg(&self) -> u16 {
        self.signature_alg
    }
    pub fn claimant_public_key(&self) -> &[u8] {
        &self.claimant_public_key
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_TRADER_PRECOMMIT_BODY);
        push_digest32(&mut out, &self.genesis);
        push_digest32(&mut out, &self.device_id);
        push_u64(&mut out, self.position);
        out.extend_from_slice(&self.parent_claim_ref.encode());
        push_digest32(&mut out, &self.external_commitment);
        push_u32(&mut out, self.legs.len() as u32);
        for l in &self.legs {
            push_digest32(&mut out, &l.vault_id);
            push_digest32(&mut out, &l.parent_root);
            push_digest32(&mut out, &l.setup_ref);
        }
        push_digest32(&mut out, &self.realize_root);
        push_digest32(&mut out, &self.void_root);
        push_digest32(&mut out, &self.storage_set_id);
        push_key(&mut out, self.signature_alg, &self.claimant_public_key);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_TRADER_PRECOMMIT_BODY, SCHEMA_V1)?;
        let genesis = c.digest32()?;
        let device_id = c.digest32()?;
        let position = c.u64()?;
        let parent_claim_ref = ParentClaimRef::at(&mut c)?;
        let external_commitment = c.digest32()?;
        let n = read_count(&mut c, "precommit legs", 1, ROUTE_MAX_LEGS)?;
        let mut legs = Vec::with_capacity(n);
        for _ in 0..n {
            legs.push(PrecommitLeg {
                vault_id: c.digest32()?,
                parent_root: c.digest32()?,
                setup_ref: c.digest32()?,
            });
        }
        let realize_root = c.digest32()?;
        let void_root = c.digest32()?;
        let storage_set_id = c.digest32()?;
        let (alg, key) = read_key(&mut c)?;
        let v = Self::new(
            genesis,
            device_id,
            position,
            parent_claim_ref,
            external_commitment,
            legs,
            realize_root,
            void_root,
            storage_set_id,
            alg,
            &key,
        )
        .map_err(wire_invalid)?;
        finish(&c, v)
    }
}

// ── 0x0038 DlvPolicyFulfillmentBody ────────────────────────────────────────

/// `G_j` — the canonical identity of the deterministic policy-fulfillment
/// witness for one DLV leg of `P`. No issuer, no signature, no evidence
/// encoding: exactly one identity per `(P, E, vault, parent state, shadow)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlvPolicyFulfillmentBody {
    pub precommit_id: D32,
    pub external_commitment: D32,
    pub vault_id: D32,
    pub parent_root: D32,
    pub shadow_core: D32,
}

impl DlvPolicyFulfillmentBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_DLV_POLICY_FULFILLMENT_BODY);
        push_digest32(&mut out, &self.precommit_id);
        push_digest32(&mut out, &self.external_commitment);
        push_digest32(&mut out, &self.vault_id);
        push_digest32(&mut out, &self.parent_root);
        push_digest32(&mut out, &self.shadow_core);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_DLV_POLICY_FULFILLMENT_BODY, SCHEMA_V1)?;
        let v = Self {
            precommit_id: c.digest32()?,
            external_commitment: c.digest32()?,
            vault_id: c.digest32()?,
            parent_root: c.digest32()?,
            shadow_core: c.digest32()?,
        };
        finish(&c, v)
    }
}

// ── 0x0039 TraderFulfillmentBody ───────────────────────────────────────────

/// The successor-attempt index chosen for one DLV leg at exercise time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptEntry {
    pub vault_id: D32,
    pub attempt: u64,
}

/// `F` — the trader's exercise. Never restates a field of `P`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraderFulfillmentBody {
    precommit_id: D32,
    policy_fulfillment_set: Vec<D32>,
    attempts: Vec<AttemptEntry>,
    position: u64,
    signature_alg: u16,
    claimant_public_key: Vec<u8>,
}

impl TraderFulfillmentBody {
    pub fn new(
        precommit_id: D32,
        policy_fulfillment_set: Vec<D32>,
        attempts: Vec<AttemptEntry>,
        position: u64,
        signature_alg: u16,
        claimant_public_key: &[u8],
    ) -> Result<Self, SofiWireError> {
        check_count(
            "policy fulfillment set",
            1,
            ROUTE_MAX_LEGS,
            policy_fulfillment_set.len(),
        )?;
        check_strictly_ascending("policy fulfillment set", &policy_fulfillment_set)?;
        check_count("attempts", 1, ROUTE_MAX_LEGS, attempts.len())?;
        let keys: Vec<D32> = attempts.iter().map(|a| a.vault_id).collect();
        check_strictly_ascending("attempts", &keys)?;
        check_key(signature_alg, claimant_public_key)?;
        Ok(Self {
            precommit_id,
            policy_fulfillment_set,
            attempts,
            position,
            signature_alg,
            claimant_public_key: claimant_public_key.to_vec(),
        })
    }

    pub fn precommit_id(&self) -> &D32 {
        &self.precommit_id
    }
    pub fn policy_fulfillment_set(&self) -> &[D32] {
        &self.policy_fulfillment_set
    }
    pub fn attempts(&self) -> &[AttemptEntry] {
        &self.attempts
    }
    pub fn position(&self) -> u64 {
        self.position
    }
    pub fn signature_alg(&self) -> u16 {
        self.signature_alg
    }
    pub fn claimant_public_key(&self) -> &[u8] {
        &self.claimant_public_key
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_TRADER_FULFILLMENT_BODY);
        push_digest32(&mut out, &self.precommit_id);
        push_u32(&mut out, self.policy_fulfillment_set.len() as u32);
        for id in &self.policy_fulfillment_set {
            push_digest32(&mut out, id);
        }
        push_u32(&mut out, self.attempts.len() as u32);
        for a in &self.attempts {
            push_digest32(&mut out, &a.vault_id);
            push_u64(&mut out, a.attempt);
        }
        push_u64(&mut out, self.position);
        push_key(&mut out, self.signature_alg, &self.claimant_public_key);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_TRADER_FULFILLMENT_BODY, SCHEMA_V1)?;
        let precommit_id = c.digest32()?;
        let n = read_count(&mut c, "policy fulfillment set", 1, ROUTE_MAX_LEGS)?;
        let mut set = Vec::with_capacity(n);
        for _ in 0..n {
            set.push(c.digest32()?);
        }
        let m = read_count(&mut c, "attempts", 1, ROUTE_MAX_LEGS)?;
        let mut attempts = Vec::with_capacity(m);
        for _ in 0..m {
            attempts.push(AttemptEntry {
                vault_id: c.digest32()?,
                attempt: c.u64()?,
            });
        }
        let position = c.u64()?;
        let (alg, key) = read_key(&mut c)?;
        let v =
            Self::new(precommit_id, set, attempts, position, alg, &key).map_err(wire_invalid)?;
        finish(&c, v)
    }
}

// ── 0x003A SofiResolutionClaim ─────────────────────────────────────────────

/// `C_q` — one outcome-independent conditional economic position, installed
/// in the same local transaction that accepts `F`. The member derives it; a
/// caller never supplies these bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SofiResolutionClaim {
    pub genesis: D32,
    pub device_id: D32,
    pub position: u64,
    pub fulfillment_id: D32,
    pub realize_root: D32,
    pub void_root: D32,
}

impl SofiResolutionClaim {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_RESOLUTION_CLAIM);
        push_digest32(&mut out, &self.genesis);
        push_digest32(&mut out, &self.device_id);
        push_u64(&mut out, self.position);
        push_digest32(&mut out, &self.fulfillment_id);
        push_digest32(&mut out, &self.realize_root);
        push_digest32(&mut out, &self.void_root);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_RESOLUTION_CLAIM, SCHEMA_V1)?;
        let v = Self {
            genesis: c.digest32()?,
            device_id: c.digest32()?,
            position: c.u64()?,
            fulfillment_id: c.digest32()?,
            realize_root: c.digest32()?,
            void_root: c.digest32()?,
        };
        finish(&c, v)
    }
}

// ── ValidationRef: 0x003D..=0x0040 ─────────────────────────────────────────

/// One typed validation reference. Each variant has exactly one fetch and
/// verification rule, and randomized signature envelopes are never
/// content-bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationRef {
    /// Immutable bytes re-hashed under the class's own addressing rule.
    ContentAddr { object_class: u16, addr: D32 },
    /// An exact single-root economic claim by exact envelope digest.
    SingleRootClaim { claim_ref: D32 },
    /// A conditional position at `(G, DevID, p)`, installed by `fulfillment_id`.
    ConditionalClaim {
        genesis: D32,
        device_id: D32,
        position: u64,
        fulfillment_id: D32,
    },
    /// A relationship setup by body identity `ρ`.
    Setup { setup_ref: D32 },
}

impl ValidationRef {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::ContentAddr { object_class, addr } => {
                push_env(&mut out, class::SOFI_REF_CONTENT_ADDR);
                push_u16(&mut out, *object_class);
                push_digest32(&mut out, addr);
            }
            Self::SingleRootClaim { claim_ref } => {
                push_env(&mut out, class::SOFI_REF_SINGLE_ROOT_CLAIM);
                push_digest32(&mut out, claim_ref);
            }
            Self::ConditionalClaim {
                genesis,
                device_id,
                position,
                fulfillment_id,
            } => {
                push_env(&mut out, class::SOFI_REF_CONDITIONAL_CLAIM);
                push_digest32(&mut out, genesis);
                push_digest32(&mut out, device_id);
                push_u64(&mut out, *position);
                push_digest32(&mut out, fulfillment_id);
            }
            Self::Setup { setup_ref } => {
                push_env(&mut out, class::SOFI_REF_SETUP);
                push_digest32(&mut out, setup_ref);
            }
        }
        out
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        match c.peek_class()? {
            class::SOFI_REF_CONTENT_ADDR => {
                c.envelope(class::SOFI_REF_CONTENT_ADDR, SCHEMA_V1)?;
                Ok(Self::ContentAddr {
                    object_class: c.u16()?,
                    addr: c.digest32()?,
                })
            }
            class::SOFI_REF_SINGLE_ROOT_CLAIM => {
                c.envelope(class::SOFI_REF_SINGLE_ROOT_CLAIM, SCHEMA_V1)?;
                Ok(Self::SingleRootClaim {
                    claim_ref: c.digest32()?,
                })
            }
            class::SOFI_REF_CONDITIONAL_CLAIM => {
                c.envelope(class::SOFI_REF_CONDITIONAL_CLAIM, SCHEMA_V1)?;
                Ok(Self::ConditionalClaim {
                    genesis: c.digest32()?,
                    device_id: c.digest32()?,
                    position: c.u64()?,
                    fulfillment_id: c.digest32()?,
                })
            }
            class::SOFI_REF_SETUP => {
                c.envelope(class::SOFI_REF_SETUP, SCHEMA_V1)?;
                Ok(Self::Setup {
                    setup_ref: c.digest32()?,
                })
            }
            got => Err(DecodeError::WrongClass { got }),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
        finish(&c, v)
    }
}

// ── 0x0041 PreEClosureIndex ────────────────────────────────────────────────

/// Classes a `ContentAddr` may never name inside `𝒞_E^pre`.
///
/// Two reasons, and every entry has one of them. Either the object contains
/// or depends on the CURRENT E (P, G, F, `C_q`, auxiliary evidence, records,
/// outcome cells, the closure index itself), or the object has its own typed
/// reference whose identity rule a content hash would bypass (setup bodies go
/// through `ρ`; economic root claims go through the exact envelope digest).
pub const CLOSURE_FORBIDDEN_CONTENT_CLASSES: &[u16] = &[
    class::ECONOMIC_ROOT_CLAIM_BODY,
    class::SOFI_SETUP_BODY,
    class::SOFI_TRADER_PRECOMMIT_BODY,
    class::SOFI_DLV_POLICY_FULFILLMENT_BODY,
    class::SOFI_TRADER_FULFILLMENT_BODY,
    class::SOFI_RESOLUTION_CLAIM,
    class::SOFI_PRE_E_CLOSURE_INDEX,
    class::SOFI_POLICY_FULFILLMENT_AUX_REF,
    class::SOFI_RECORD_FULFILLMENT_REGISTERED,
    class::SOFI_RECORD_SUCCESSOR_DEAD,
    class::SOFI_RECORD_SUCCESSOR_FINAL,
    class::SOFI_RECORD_OUTCOME_COMPLETE,
    class::SOFI_RECORD_OUTCOME_ABORT,
    class::SOFI_OUTCOME_CELL_COMPLETE,
    class::SOFI_OUTCOME_CELL_ABORT,
];

/// `𝒞_E^pre` — the exact finite set of E-independent validation references,
/// encoded once inside `B°`. Its digest is derived when needed and is never a
/// second normative field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreEClosureIndex {
    refs: Vec<ValidationRef>,
}

impl PreEClosureIndex {
    pub fn new(refs: Vec<ValidationRef>) -> Result<Self, SofiWireError> {
        check_count("closure refs", 0, MAX_CLOSURE_REFS, refs.len())?;
        for r in &refs {
            if let ValidationRef::ContentAddr { object_class, .. } = r {
                if CLOSURE_FORBIDDEN_CONTENT_CLASSES.contains(object_class) {
                    return Err(SofiWireError::ForbiddenClosureClass {
                        object_class: *object_class,
                    });
                }
            }
        }
        let encoded: Vec<Vec<u8>> = refs.iter().map(ValidationRef::encode).collect();
        check_strictly_ascending("closure refs", &encoded)?;
        Ok(Self { refs })
    }

    pub fn refs(&self) -> &[ValidationRef] {
        &self.refs
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_PRE_E_CLOSURE_INDEX);
        push_u32(&mut out, self.refs.len() as u32);
        for r in &self.refs {
            out.extend_from_slice(&r.encode());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_PRE_E_CLOSURE_INDEX, SCHEMA_V1)?;
        let n = read_count(&mut c, "closure refs", 0, MAX_CLOSURE_REFS)?;
        let mut refs = Vec::with_capacity(n);
        for _ in 0..n {
            refs.push(ValidationRef::at(&mut c)?);
        }
        let v = Self::new(refs).map_err(wire_invalid)?;
        finish(&c, v)
    }
}

// ── 0x0042 PolicyFulfillmentAuxRef ─────────────────────────────────────────

/// One content-addressed auxiliary evidence candidate for a policy-fulfillment
/// witness. Many may exist per `(policy_fulfillment_id, evidence_class)`; there
/// is no singleton slot, and a candidate can only ever establish validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyFulfillmentAuxRef {
    pub policy_fulfillment_id: D32,
    pub evidence_class: u16,
    pub addr: D32,
}

impl PolicyFulfillmentAuxRef {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_POLICY_FULFILLMENT_AUX_REF);
        push_digest32(&mut out, &self.policy_fulfillment_id);
        push_u16(&mut out, self.evidence_class);
        push_digest32(&mut out, &self.addr);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_POLICY_FULFILLMENT_AUX_REF, SCHEMA_V1)?;
        let v = Self {
            policy_fulfillment_id: c.digest32()?,
            evidence_class: c.u16()?,
            addr: c.digest32()?,
        };
        finish(&c, v)
    }
}

// ── ResolutionRecord: 0x0043..=0x0047 ──────────────────────────────────────

/// A typed, write-once resolution record. The variant's class is its kind, so
/// a value of one kind can never decode as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionRecord {
    FulfillmentRegistered {
        fulfillment_key: D32,
        fulfillment_id: D32,
    },
    SuccessorDead {
        successor_key: D32,
    },
    SuccessorFinal {
        successor_key: D32,
        external_commitment: D32,
    },
    OutcomeComplete {
        outcome_key: D32,
    },
    OutcomeAbort {
        outcome_key: D32,
    },
}

impl ResolutionRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::FulfillmentRegistered {
                fulfillment_key,
                fulfillment_id,
            } => {
                push_env(&mut out, class::SOFI_RECORD_FULFILLMENT_REGISTERED);
                push_digest32(&mut out, fulfillment_key);
                push_digest32(&mut out, fulfillment_id);
            }
            Self::SuccessorDead { successor_key } => {
                push_env(&mut out, class::SOFI_RECORD_SUCCESSOR_DEAD);
                push_digest32(&mut out, successor_key);
            }
            Self::SuccessorFinal {
                successor_key,
                external_commitment,
            } => {
                push_env(&mut out, class::SOFI_RECORD_SUCCESSOR_FINAL);
                push_digest32(&mut out, successor_key);
                push_digest32(&mut out, external_commitment);
            }
            Self::OutcomeComplete { outcome_key } => {
                push_env(&mut out, class::SOFI_RECORD_OUTCOME_COMPLETE);
                push_digest32(&mut out, outcome_key);
            }
            Self::OutcomeAbort { outcome_key } => {
                push_env(&mut out, class::SOFI_RECORD_OUTCOME_ABORT);
                push_digest32(&mut out, outcome_key);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = match c.peek_class()? {
            class::SOFI_RECORD_FULFILLMENT_REGISTERED => {
                c.envelope(class::SOFI_RECORD_FULFILLMENT_REGISTERED, SCHEMA_V1)?;
                Self::FulfillmentRegistered {
                    fulfillment_key: c.digest32()?,
                    fulfillment_id: c.digest32()?,
                }
            }
            class::SOFI_RECORD_SUCCESSOR_DEAD => {
                c.envelope(class::SOFI_RECORD_SUCCESSOR_DEAD, SCHEMA_V1)?;
                Self::SuccessorDead {
                    successor_key: c.digest32()?,
                }
            }
            class::SOFI_RECORD_SUCCESSOR_FINAL => {
                c.envelope(class::SOFI_RECORD_SUCCESSOR_FINAL, SCHEMA_V1)?;
                Self::SuccessorFinal {
                    successor_key: c.digest32()?,
                    external_commitment: c.digest32()?,
                }
            }
            class::SOFI_RECORD_OUTCOME_COMPLETE => {
                c.envelope(class::SOFI_RECORD_OUTCOME_COMPLETE, SCHEMA_V1)?;
                Self::OutcomeComplete {
                    outcome_key: c.digest32()?,
                }
            }
            class::SOFI_RECORD_OUTCOME_ABORT => {
                c.envelope(class::SOFI_RECORD_OUTCOME_ABORT, SCHEMA_V1)?;
                Self::OutcomeAbort {
                    outcome_key: c.digest32()?,
                }
            }
            got => return Err(DecodeError::WrongClass { got }),
        };
        finish(&c, v)
    }
}

// ── OutcomeCell: 0x0048 | 0x0049 ───────────────────────────────────────────

/// The value a member holds at `K_out(F)`. Storage-level only: `Complete`
/// means every reserved leg key of F reached `FinalE(E)`, never acceptance.
/// There is no Dead state for this resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeCell {
    Complete,
    Abort,
}

impl OutcomeCell {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Complete => push_env(&mut out, class::SOFI_OUTCOME_CELL_COMPLETE),
            Self::Abort => push_env(&mut out, class::SOFI_OUTCOME_CELL_ABORT),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = match c.peek_class()? {
            class::SOFI_OUTCOME_CELL_COMPLETE => {
                c.envelope(class::SOFI_OUTCOME_CELL_COMPLETE, SCHEMA_V1)?;
                Self::Complete
            }
            class::SOFI_OUTCOME_CELL_ABORT => {
                c.envelope(class::SOFI_OUTCOME_CELL_ABORT, SCHEMA_V1)?;
                Self::Abort
            }
            got => return Err(DecodeError::WrongClass { got }),
        };
        finish(&c, v)
    }
}

// ── 0x004A RouteLegSet ─────────────────────────────────────────────────────

/// One entry of `Γ`: each setup reference is paired with its own vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteLegEntry {
    pub vault_id: D32,
    pub parent_root: D32,
    pub setup_ref: D32,
    pub shadow_core: D32,
}

/// `Γ` — the canonical route-leg set of a multi-vault E.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteLegSet {
    legs: Vec<RouteLegEntry>,
}

impl RouteLegSet {
    pub fn new(legs: Vec<RouteLegEntry>) -> Result<Self, SofiWireError> {
        check_count("route legs", ROUTE_MIN_LEGS, ROUTE_MAX_LEGS, legs.len())?;
        let keys: Vec<D32> = legs.iter().map(|l| l.vault_id).collect();
        check_strictly_ascending("route legs", &keys)?;
        Ok(Self { legs })
    }

    pub fn legs(&self) -> &[RouteLegEntry] {
        &self.legs
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_ROUTE_LEG_SET);
        push_u32(&mut out, self.legs.len() as u32);
        for l in &self.legs {
            push_digest32(&mut out, &l.vault_id);
            push_digest32(&mut out, &l.parent_root);
            push_digest32(&mut out, &l.setup_ref);
            push_digest32(&mut out, &l.shadow_core);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_ROUTE_LEG_SET, SCHEMA_V1)?;
        let n = read_count(&mut c, "route legs", ROUTE_MIN_LEGS, ROUTE_MAX_LEGS)?;
        let mut legs = Vec::with_capacity(n);
        for _ in 0..n {
            legs.push(RouteLegEntry {
                vault_id: c.digest32()?,
                parent_root: c.digest32()?,
                setup_ref: c.digest32()?,
                shadow_core: c.digest32()?,
            });
        }
        let v = Self::new(legs).map_err(wire_invalid)?;
        finish(&c, v)
    }
}
