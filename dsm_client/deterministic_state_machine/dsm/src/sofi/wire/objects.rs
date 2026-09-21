// SPDX-License-Identifier: Apache-2.0

//! SoFi v8 wire objects: validating constructors, canonical encoders and
//! strict decoders for the field tables in [`super`].

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::{class, push_bytes, push_digest32, push_u16, push_u32, push_u64, sigalg};

use crate::economic::tree::ECONOMIC_SMT_HEIGHT;

use super::{
    SofiWireError, CANONICAL_MAX_LEGS, MAX_CLOSURE_REFS, MAX_CORE_ENTRIES, MAX_EXERCISE_BYTES,
    MAX_SETTLEMENT_PREIMAGE_BYTES, ROUTE_MIN_LEGS, VAULT_STATUS_ACTIVE, VAULT_STATUS_RETIRED,
};

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
        check_count("precommit legs", 1, CANONICAL_MAX_LEGS, legs.len())?;
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
        let n = read_count(&mut c, "precommit legs", 1, CANONICAL_MAX_LEGS)?;
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
            CANONICAL_MAX_LEGS,
            policy_fulfillment_set.len(),
        )?;
        check_strictly_ascending("policy fulfillment set", &policy_fulfillment_set)?;
        check_count("attempts", 1, CANONICAL_MAX_LEGS, attempts.len())?;
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
        let n = read_count(&mut c, "policy fulfillment set", 1, CANONICAL_MAX_LEGS)?;
        let mut set = Vec::with_capacity(n);
        for _ in 0..n {
            set.push(c.digest32()?);
        }
        let m = read_count(&mut c, "attempts", 1, CANONICAL_MAX_LEGS)?;
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

// ── 0x005C SignedSofiObject ────────────────────────────────────────────────

/// The largest signature any supported algorithm produces, with headroom.
/// SPX256f is 49,856 bytes and dominates anything carrying one.
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;

/// The transport envelope for a canonical SoFi body plus the trader's
/// signature over it.
///
/// **It authenticates a body; it never redefines one.** `P` is `P` because of
/// its canonical `TraderPrecommitBody`, and `PrecommitId` is derived from that
/// body — not from these bytes. Two valid signature encodings over one body
/// are the same protocol object at the same identity, which is what lets an
/// honest relayer republish without racing the trader into a conflict.
///
/// **`body_class` is not a dispatch hint.** It is checked against the class
/// the inner canonical bytes actually carry, and the signing preimage is
/// rederived from the DECODED object — see `signature::verify_signed_object`,
/// which is where the class-specific rules live. The envelope is generic; the
/// verification deliberately is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSofiObject {
    body_class: u16,
    body_ccb: Vec<u8>,
    signature_alg: u16,
    signature: Vec<u8>,
}

impl SignedSofiObject {
    /// The only constructor. It refuses a body class this envelope does not
    /// carry, so no producer in this codebase can emit one — the matching
    /// refusal on the consumer side is in `verify_signed_object`, and both
    /// exist because a producer check and a verifier check answer different
    /// questions.
    pub fn new(
        body_class: u16,
        body_ccb: &[u8],
        signature_alg: u16,
        signature: &[u8],
    ) -> Result<Self, SofiWireError> {
        if !matches!(
            body_class,
            class::SOFI_SETUP_BODY
                | class::SOFI_TRADER_PRECOMMIT_BODY
                | class::SOFI_TRADER_FULFILLMENT_BODY
        ) {
            return Err(SofiWireError::UnsupportedSignedBodyClass { body_class });
        }
        if body_ccb.is_empty() || body_ccb.len() > MAX_SETTLEMENT_PREIMAGE_BYTES {
            return Err(SofiWireError::ObjectTooLarge {
                field: "body_ccb",
                bytes: body_ccb.len(),
                max: MAX_SETTLEMENT_PREIMAGE_BYTES,
            });
        }
        if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
            return Err(SofiWireError::ObjectTooLarge {
                field: "signature",
                bytes: signature.len(),
                max: MAX_SIGNATURE_BYTES,
            });
        }
        // The algorithm must be one the registry declares. It is checked
        // again against the BODY's own `signature_alg` at verification: the
        // body is signed and this envelope is not, so a disagreement between
        // them is resolved in favour of the body rather than left as a fork.
        sigalg::public_key_len(signature_alg)
            .ok_or(SofiWireError::UnknownSignatureAlg { alg: signature_alg })?;
        Ok(Self {
            body_class,
            body_ccb: body_ccb.to_vec(),
            signature_alg,
            signature: signature.to_vec(),
        })
    }

    pub fn body_class(&self) -> u16 {
        self.body_class
    }

    pub fn body_ccb(&self) -> &[u8] {
        &self.body_ccb
    }

    pub fn signature_alg(&self) -> u16 {
        self.signature_alg
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_SIGNED_OBJECT);
        push_u16(&mut out, self.body_class);
        // Lengths are validated by `new` and by `decode`, so neither can
        // overflow the u32 prefix here.
        let _ = push_bytes(&mut out, &self.body_ccb);
        push_u16(&mut out, self.signature_alg);
        let _ = push_bytes(&mut out, &self.signature);
        out
    }

    /// Decode WITHOUT restricting the body class.
    ///
    /// A hostile envelope naming an unsupported class must decode so that it
    /// can be refused by name at verification, rather than failing here as an
    /// indistinguishable parse error. The producer-side restriction lives in
    /// [`Self::new`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_SIGNED_OBJECT, SCHEMA_V1)?;
        let body_class = c.u16()?;
        let body_ccb = read_var_bytes(&mut c, MAX_SETTLEMENT_PREIMAGE_BYTES)?;
        let signature_alg = c.u16()?;
        let signature = read_var_bytes(&mut c, MAX_SIGNATURE_BYTES)?;
        let v = Self {
            body_class,
            body_ccb,
            signature_alg,
            signature,
        };
        finish(&c, v)
    }
}

/// A length-prefixed byte string, bounded before it is taken.
fn read_var_bytes(c: &mut Cursor<'_>, max: usize) -> Result<Vec<u8>, DecodeError> {
    let n = c.u32()? as usize;
    if n == 0 || n > max {
        return Err(DecodeError::Invalid(format!(
            "length {n} is outside 1..={max}"
        )));
    }
    Ok(c.take(n)?.to_vec())
}

// ── ValidationRef: 0x003D..=0x0040 ─────────────────────────────────────────

// ── 0x005E SofiExercise ─────────────────────────────────────────────────────

/// The exercise: the value written to every successor key of a route
/// (Section 17.5). Everything a reader needs to classify it is inside — `F`
/// and `P` in the envelopes their signatures travel in, `P(E)`, the witnesses
/// and the closure objects — and everything is bound to `F` by hashed
/// preimages. It names its own attempt through `F` and its own parents
/// through `P`, so it cannot count at another key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SofiExercise {
    fulfillment: Vec<u8>,
    precommit: Vec<u8>,
    preimage: Vec<u8>,
    witnesses: Vec<Vec<u8>>,
    closure: Vec<Vec<u8>>,
}

const MAX_EXERCISE_PART_BYTES: usize = MAX_SETTLEMENT_PREIMAGE_BYTES + MAX_SIGNATURE_BYTES;

impl SofiExercise {
    /// The only constructor. Each part is the canonical bytes of the object
    /// it carries; the codec bounds the parts and the whole. What the parts
    /// MEAN — that the envelopes decode, that `F` is `P`'s, that the
    /// witnesses are the canonical set — is recognition (`sofi::exercise`),
    /// not construction.
    pub fn new(
        fulfillment: Vec<u8>,
        precommit: Vec<u8>,
        preimage: Vec<u8>,
        witnesses: Vec<Vec<u8>>,
        closure: Vec<Vec<u8>>,
    ) -> Result<Self, SofiWireError> {
        for (field, bytes) in [
            ("fulfillment", &fulfillment),
            ("precommit", &precommit),
            ("preimage", &preimage),
        ] {
            if bytes.is_empty() || bytes.len() > MAX_EXERCISE_PART_BYTES {
                return Err(SofiWireError::ObjectTooLarge {
                    field,
                    bytes: bytes.len(),
                    max: MAX_EXERCISE_PART_BYTES,
                });
            }
        }
        check_count("witnesses", 1, CANONICAL_MAX_LEGS, witnesses.len())?;
        check_count("closure objects", 0, MAX_CLOSURE_REFS, closure.len())?;
        for (field, list) in [("witness", &witnesses), ("closure object", &closure)] {
            for bytes in list {
                if bytes.is_empty() || bytes.len() > MAX_EXERCISE_PART_BYTES {
                    return Err(SofiWireError::ObjectTooLarge {
                        field,
                        bytes: bytes.len(),
                        max: MAX_EXERCISE_PART_BYTES,
                    });
                }
            }
        }
        let v = Self {
            fulfillment,
            precommit,
            preimage,
            witnesses,
            closure,
        };
        let total = v.encode().len();
        if total > MAX_EXERCISE_BYTES {
            return Err(SofiWireError::ObjectTooLarge {
                field: "exercise",
                bytes: total,
                max: MAX_EXERCISE_BYTES,
            });
        }
        Ok(v)
    }

    pub fn fulfillment(&self) -> &[u8] {
        &self.fulfillment
    }

    pub fn precommit(&self) -> &[u8] {
        &self.precommit
    }

    pub fn preimage(&self) -> &[u8] {
        &self.preimage
    }

    pub fn witnesses(&self) -> &[Vec<u8>] {
        &self.witnesses
    }

    pub fn closure(&self) -> &[Vec<u8>] {
        &self.closure
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_EXERCISE);
        let _ = push_bytes(&mut out, &self.fulfillment);
        let _ = push_bytes(&mut out, &self.precommit);
        let _ = push_bytes(&mut out, &self.preimage);
        push_u32(&mut out, self.witnesses.len() as u32);
        for w in &self.witnesses {
            let _ = push_bytes(&mut out, w);
        }
        push_u32(&mut out, self.closure.len() as u32);
        for o in &self.closure {
            let _ = push_bytes(&mut out, o);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_EXERCISE_BYTES {
            return Err(DecodeError::Invalid(format!(
                "exercise of {} bytes exceeds {MAX_EXERCISE_BYTES}",
                bytes.len()
            )));
        }
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_EXERCISE, SCHEMA_V1)?;
        let fulfillment = read_var_bytes(&mut c, MAX_EXERCISE_PART_BYTES)?;
        let precommit = read_var_bytes(&mut c, MAX_EXERCISE_PART_BYTES)?;
        let preimage = read_var_bytes(&mut c, MAX_EXERCISE_PART_BYTES)?;
        let n = read_count(&mut c, "witnesses", 1, CANONICAL_MAX_LEGS)?;
        let mut witnesses = Vec::with_capacity(n);
        for _ in 0..n {
            witnesses.push(read_var_bytes(&mut c, MAX_EXERCISE_PART_BYTES)?);
        }
        let m = read_count(&mut c, "closure objects", 0, MAX_CLOSURE_REFS)?;
        let mut closure = Vec::with_capacity(m);
        for _ in 0..m {
            closure.push(read_var_bytes(&mut c, MAX_EXERCISE_PART_BYTES)?);
        }
        let v = Self {
            fulfillment,
            precommit,
            preimage,
            witnesses,
            closure,
        };
        finish(&c, v)
    }
}

/// One typed validation reference. Each variant has exactly one fetch and
/// verification rule, and randomized signature envelopes are never
/// content-bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    // The signed envelope wraps P and F, both of which commit E. Without this
    // entry the wrapper would be a back door into `𝒞_E^pre` for the two
    // objects the acyclicity argument most depends on keeping out — the list
    // is keyed by CLASS, so a new wrapper class is not covered by the entries
    // for the bodies it carries.
    class::SOFI_SIGNED_OBJECT,
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

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        c.envelope(class::SOFI_PRE_E_CLOSURE_INDEX, SCHEMA_V1)?;
        let n = read_count(c, "closure refs", 0, MAX_CLOSURE_REFS)?;
        let mut refs = Vec::with_capacity(n);
        for _ in 0..n {
            refs.push(ValidationRef::at(c)?);
        }
        Self::new(refs).map_err(wire_invalid)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
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
        check_count("route legs", ROUTE_MIN_LEGS, CANONICAL_MAX_LEGS, legs.len())?;
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
        let n = read_count(&mut c, "route legs", ROUTE_MIN_LEGS, CANONICAL_MAX_LEGS)?;
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

// ═══════════════════════════════════════════════════════════════════════════
// The DLV tree, the cores, B° and vault genesis (P15-4, 6, 7, 8, 11, 12)
// ═══════════════════════════════════════════════════════════════════════════

/// `P(E)` has a frozen byte bound (R8-12). An object over it has no canonical
/// representation at all, so the codec refuses it on both sides rather than
/// leaving the rule to a later layer.
fn check_preimage_bytes(bytes: &[u8]) -> Result<(), SofiWireError> {
    if bytes.len() > MAX_SETTLEMENT_PREIMAGE_BYTES {
        return Err(SofiWireError::ObjectTooLarge {
            field: "settlement preimage",
            bytes: bytes.len(),
            max: MAX_SETTLEMENT_PREIMAGE_BYTES,
        });
    }
    Ok(())
}

fn check_status(status: u16) -> Result<(), SofiWireError> {
    if status != VAULT_STATUS_ACTIVE && status != VAULT_STATUS_RETIRED {
        return Err(SofiWireError::UnknownVaultStatus { status });
    }
    Ok(())
}

fn check_path(path: &[D32]) -> Result<(), SofiWireError> {
    if path.len() != ECONOMIC_SMT_HEIGHT {
        return Err(SofiWireError::PathDepth {
            expected: ECONOMIC_SMT_HEIGHT,
            got: path.len(),
        });
    }
    Ok(())
}

fn push_path(out: &mut Vec<u8>, path: &[D32]) {
    push_u32(out, path.len() as u32);
    for sib in path {
        push_digest32(out, sib);
    }
}

fn read_path(c: &mut Cursor<'_>) -> Result<Vec<D32>, DecodeError> {
    let n = read_count(c, "path", ECONOMIC_SMT_HEIGHT, ECONOMIC_SMT_HEIGHT)?;
    (0..n).map(|_| c.digest32()).collect()
}

// ── 0x004B VaultStateLeaf ──────────────────────────────────────────────────

/// The vault's own state leaf. `owner_device_id` is the ORIGIN device: it fixes
/// `vault_id` forever and is not a claim about who controls the vault now.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        check_status(self.status)?;
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_VAULT_STATE_LEAF);
        push_digest32(&mut out, &self.owner_genesis);
        push_digest32(&mut out, &self.owner_device_id);
        push_u64(&mut out, self.create_position);
        push_digest32(&mut out, &self.market_policy);
        push_digest32(&mut out, &self.fee_policy);
        push_digest32(&mut out, &self.release_policy);
        push_digest32(&mut out, &self.storage_set_id);
        push_u64(&mut out, self.generation);
        push_u64(&mut out, self.reserve_a);
        push_u64(&mut out, self.reserve_b);
        push_u16(&mut out, self.status);
        Ok(out)
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        c.envelope(class::SOFI_VAULT_STATE_LEAF, SCHEMA_V1)?;
        let leaf = Self {
            owner_genesis: c.digest32()?,
            owner_device_id: c.digest32()?,
            create_position: c.u64()?,
            market_policy: c.digest32()?,
            fee_policy: c.digest32()?,
            release_policy: c.digest32()?,
            storage_set_id: c.digest32()?,
            generation: c.u64()?,
            reserve_a: c.u64()?,
            reserve_b: c.u64()?,
            status: c.u16()?,
        };
        check_status(leaf.status).map_err(wire_invalid)?;
        Ok(leaf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
        finish(&c, v)
    }
}

// ── 0x004C VaultRelationshipLeaf ───────────────────────────────────────────

/// A trader's relationship leaf inside a vault's DLV tree. The key material is
/// explicit so the tree can be rebuilt by replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultRelationshipLeaf {
    pub trader_genesis: D32,
    pub trader_device_id: D32,
    pub leaf: D32,
}

impl VaultRelationshipLeaf {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_VAULT_RELATIONSHIP_LEAF);
        push_digest32(&mut out, &self.trader_genesis);
        push_digest32(&mut out, &self.trader_device_id);
        push_digest32(&mut out, &self.leaf);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_VAULT_RELATIONSHIP_LEAF, SCHEMA_V1)?;
        let v = Self {
            trader_genesis: c.digest32()?,
            trader_device_id: c.digest32()?,
            leaf: c.digest32()?,
        };
        finish(&c, v)
    }
}

// ── 0x004D TraderRelationshipLeaf ──────────────────────────────────────────

/// The trader's own `R_econ` leaf for one vault relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraderRelationshipLeaf {
    pub vault_id: D32,
    pub leaf: D32,
}

impl TraderRelationshipLeaf {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_TRADER_RELATIONSHIP_LEAF);
        push_digest32(&mut out, &self.vault_id);
        push_digest32(&mut out, &self.leaf);
        out
    }

    /// Nested decode, for `R_econ`'s class-keyed leaf reader. It shares the
    /// field order with [`Self::decode`] rather than restating it, so the two
    /// cannot drift.
    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        c.envelope(class::SOFI_TRADER_RELATIONSHIP_LEAF, SCHEMA_V1)?;
        Ok(Self {
            vault_id: c.digest32()?,
            leaf: c.digest32()?,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
        finish(&c, v)
    }
}

// ── 0x004E | 0x004F | 0x0050 CoreEntry ─────────────────────────────────────

/// One per-key entry of a core, with its full authentication path against the
/// core's `pre_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreEntry {
    /// A leaf written from `pre` to `post`.
    Mutation {
        key: D32,
        pre: D32,
        post: D32,
        path: Vec<D32>,
    },
    /// A leaf read and not written. It still binds, because the fold covers it.
    Read {
        key: D32,
        value: D32,
        path: Vec<D32>,
    },
    /// A relationship leaf. Its post is `H(rel-leaf ‖ base ‖ E)` and cannot be
    /// carried here: E is not known until the whole preimage is folded.
    Relationship {
        genesis: D32,
        device_id: D32,
        vault_id: D32,
        base: D32,
        path: Vec<D32>,
    },
}

impl CoreEntry {
    /// The `R_econ` key this entry is about. A relationship entry derives it
    /// from its key material rather than restating it.
    pub fn key(&self) -> D32 {
        match self {
            Self::Mutation { key, .. } | Self::Read { key, .. } => *key,
            Self::Relationship {
                genesis,
                device_id,
                vault_id,
                ..
            } => super::super::derive::relationship_key(genesis, device_id, vault_id),
        }
    }

    pub fn path(&self) -> &[D32] {
        match self {
            Self::Mutation { path, .. } | Self::Read { path, .. } => path,
            Self::Relationship { path, .. } => path,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        check_path(self.path())?;
        let mut out = Vec::new();
        match self {
            Self::Mutation {
                key,
                pre,
                post,
                path,
            } => {
                push_env(&mut out, class::SOFI_CORE_ENTRY_MUTATION);
                push_digest32(&mut out, key);
                push_digest32(&mut out, pre);
                push_digest32(&mut out, post);
                push_path(&mut out, path);
            }
            Self::Read { key, value, path } => {
                push_env(&mut out, class::SOFI_CORE_ENTRY_READ);
                push_digest32(&mut out, key);
                push_digest32(&mut out, value);
                push_path(&mut out, path);
            }
            Self::Relationship {
                genesis,
                device_id,
                vault_id,
                base,
                path,
            } => {
                push_env(&mut out, class::SOFI_CORE_ENTRY_RELATIONSHIP);
                push_digest32(&mut out, genesis);
                push_digest32(&mut out, device_id);
                push_digest32(&mut out, vault_id);
                push_digest32(&mut out, base);
                push_path(&mut out, path);
            }
        }
        Ok(out)
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        match c.peek_class()? {
            class::SOFI_CORE_ENTRY_MUTATION => {
                c.envelope(class::SOFI_CORE_ENTRY_MUTATION, SCHEMA_V1)?;
                Ok(Self::Mutation {
                    key: c.digest32()?,
                    pre: c.digest32()?,
                    post: c.digest32()?,
                    path: read_path(c)?,
                })
            }
            class::SOFI_CORE_ENTRY_READ => {
                c.envelope(class::SOFI_CORE_ENTRY_READ, SCHEMA_V1)?;
                Ok(Self::Read {
                    key: c.digest32()?,
                    value: c.digest32()?,
                    path: read_path(c)?,
                })
            }
            class::SOFI_CORE_ENTRY_RELATIONSHIP => {
                c.envelope(class::SOFI_CORE_ENTRY_RELATIONSHIP, SCHEMA_V1)?;
                Ok(Self::Relationship {
                    genesis: c.digest32()?,
                    device_id: c.digest32()?,
                    vault_id: c.digest32()?,
                    base: c.digest32()?,
                    path: read_path(c)?,
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

fn check_entries(entries: &[CoreEntry]) -> Result<(), SofiWireError> {
    check_count("core entries", 1, MAX_CORE_ENTRIES, entries.len())?;
    for e in entries {
        check_path(e.path())?;
    }
    let keys: Vec<D32> = entries.iter().map(CoreEntry::key).collect();
    check_strictly_ascending("core entries", &keys)
}

fn push_entries(out: &mut Vec<u8>, entries: &[CoreEntry]) -> Result<(), SofiWireError> {
    push_u32(out, entries.len() as u32);
    for e in entries {
        out.extend_from_slice(&e.encode()?);
    }
    Ok(())
}

fn read_entries(c: &mut Cursor<'_>) -> Result<Vec<CoreEntry>, DecodeError> {
    let n = read_count(c, "core entries", 1, MAX_CORE_ENTRIES)?;
    (0..n).map(|_| CoreEntry::at(c)).collect()
}

// ── 0x0051 TraderCore ──────────────────────────────────────────────────────

/// `T°`, scoped to `(G, DevID, q)`: E cannot be rebuilt at a later position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraderCore {
    genesis: D32,
    device_id: D32,
    position: u64,
    pre_root: D32,
    entries: Vec<CoreEntry>,
}

impl TraderCore {
    pub fn new(
        genesis: D32,
        device_id: D32,
        position: u64,
        pre_root: D32,
        entries: Vec<CoreEntry>,
    ) -> Result<Self, SofiWireError> {
        check_entries(&entries)?;
        Ok(Self {
            genesis,
            device_id,
            position,
            pre_root,
            entries,
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
    pub fn pre_root(&self) -> &D32 {
        &self.pre_root
    }
    pub fn entries(&self) -> &[CoreEntry] {
        &self.entries
    }

    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_TRADER_CORE);
        push_digest32(&mut out, &self.genesis);
        push_digest32(&mut out, &self.device_id);
        push_u64(&mut out, self.position);
        push_digest32(&mut out, &self.pre_root);
        push_entries(&mut out, &self.entries)?;
        Ok(out)
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        c.envelope(class::SOFI_TRADER_CORE, SCHEMA_V1)?;
        let genesis = c.digest32()?;
        let device_id = c.digest32()?;
        let position = c.u64()?;
        let pre_root = c.digest32()?;
        let entries = read_entries(c)?;
        Self::new(genesis, device_id, position, pre_root, entries).map_err(wire_invalid)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
        finish(&c, v)
    }
}

// ── 0x0052 DlvCore ─────────────────────────────────────────────────────────

/// `V°_j`. Its marker carries the trader's identity and the relationship base
/// `T°` proved, so the two cores cannot be paired with a different trader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlvCore {
    vault_id: D32,
    pre_root: D32,
    trader_genesis: D32,
    trader_device_id: D32,
    relationship_base: D32,
    entries: Vec<CoreEntry>,
}

impl DlvCore {
    pub fn new(
        vault_id: D32,
        pre_root: D32,
        trader_genesis: D32,
        trader_device_id: D32,
        relationship_base: D32,
        entries: Vec<CoreEntry>,
    ) -> Result<Self, SofiWireError> {
        check_entries(&entries)?;
        Ok(Self {
            vault_id,
            pre_root,
            trader_genesis,
            trader_device_id,
            relationship_base,
            entries,
        })
    }

    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }
    pub fn pre_root(&self) -> &D32 {
        &self.pre_root
    }
    pub fn trader_genesis(&self) -> &D32 {
        &self.trader_genesis
    }
    pub fn trader_device_id(&self) -> &D32 {
        &self.trader_device_id
    }
    pub fn relationship_base(&self) -> &D32 {
        &self.relationship_base
    }
    pub fn entries(&self) -> &[CoreEntry] {
        &self.entries
    }

    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_DLV_CORE);
        push_digest32(&mut out, &self.vault_id);
        push_digest32(&mut out, &self.pre_root);
        push_digest32(&mut out, &self.trader_genesis);
        push_digest32(&mut out, &self.trader_device_id);
        push_digest32(&mut out, &self.relationship_base);
        push_entries(&mut out, &self.entries)?;
        Ok(out)
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        c.envelope(class::SOFI_DLV_CORE, SCHEMA_V1)?;
        let vault_id = c.digest32()?;
        let pre_root = c.digest32()?;
        let trader_genesis = c.digest32()?;
        let trader_device_id = c.digest32()?;
        let relationship_base = c.digest32()?;
        let entries = read_entries(c)?;
        Self::new(
            vault_id,
            pre_root,
            trader_genesis,
            trader_device_id,
            relationship_base,
            entries,
        )
        .map_err(wire_invalid)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
        finish(&c, v)
    }
}

// ── 0x0055 | 0x0056 OwnerAuthority ─────────────────────────────────────────

/// Who may close a vault. Frozen as a union now so activating DSM succession
/// later needs no byte change [R18-1].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAuthority {
    /// The vault's origin device — the only branch semantic validation accepts.
    /// Today's mnemonic recovery re-derives the same `(G, DevID)` and key, so
    /// a recovered owner closes through this branch.
    Origin,
    /// A DSM succession successor, named opaquely. Encodable and decodable;
    /// ALWAYS Invalid (never Unavailable) in this protocol, because a verifier
    /// KNOWS the branch is not activated. No production builder emits it.
    DsmSuccessor {
        authority_class: u16,
        authority_addr: D32,
    },
}

impl OwnerAuthority {
    /// Whether this protocol version can act on the branch at all. Semantic
    /// validation turns `false` into Invalid, never Unavailable.
    pub fn is_activated(&self) -> bool {
        matches!(self, Self::Origin)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Origin => push_env(&mut out, class::SOFI_OWNER_AUTHORITY_ORIGIN),
            Self::DsmSuccessor {
                authority_class,
                authority_addr,
            } => {
                push_env(&mut out, class::SOFI_OWNER_AUTHORITY_DSM_SUCCESSOR);
                push_u16(&mut out, *authority_class);
                push_digest32(&mut out, authority_addr);
            }
        }
        out
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        match c.peek_class()? {
            class::SOFI_OWNER_AUTHORITY_ORIGIN => {
                c.envelope(class::SOFI_OWNER_AUTHORITY_ORIGIN, SCHEMA_V1)?;
                Ok(Self::Origin)
            }
            class::SOFI_OWNER_AUTHORITY_DSM_SUCCESSOR => {
                c.envelope(class::SOFI_OWNER_AUTHORITY_DSM_SUCCESSOR, SCHEMA_V1)?;
                Ok(Self::DsmSuccessor {
                    authority_class: c.u16()?,
                    authority_addr: c.digest32()?,
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

// ── hop entries, shared by the Swap branch and its route digest ────────────

/// One hop of a swap, in hop order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapHop {
    pub vault_id: D32,
    pub parent_root: D32,
    pub setup_ref: D32,
    pub token_in: D32,
    pub amount_in: u64,
    pub token_out: D32,
    pub amount_out: u64,
}

impl SwapHop {
    fn push(&self, out: &mut Vec<u8>) {
        push_digest32(out, &self.vault_id);
        push_digest32(out, &self.parent_root);
        push_digest32(out, &self.setup_ref);
        push_digest32(out, &self.token_in);
        push_u64(out, self.amount_in);
        push_digest32(out, &self.token_out);
        push_u64(out, self.amount_out);
    }

    fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            vault_id: c.digest32()?,
            parent_root: c.digest32()?,
            setup_ref: c.digest32()?,
            token_in: c.digest32()?,
            amount_in: c.u64()?,
            token_out: c.digest32()?,
            amount_out: c.u64()?,
        })
    }
}

/// Hops are in HOP order, not sorted — the route's shape is the order. So
/// distinctness is checked as a set, and a repeated vault is refused [R15-4]:
/// every DLV parent is referenced at most once per route.
fn check_hops(hops: &[SwapHop]) -> Result<(), SofiWireError> {
    check_count("swap hops", 1, CANONICAL_MAX_LEGS, hops.len())?;
    let mut sorted: Vec<D32> = hops.iter().map(|h| h.vault_id).collect();
    sorted.sort_unstable();
    check_strictly_ascending("swap hop vault ids", &sorted)
}

fn push_hops(out: &mut Vec<u8>, hops: &[SwapHop]) {
    push_u32(out, hops.len() as u32);
    for h in hops {
        h.push(out);
    }
}

fn read_hops(c: &mut Cursor<'_>) -> Result<Vec<SwapHop>, DecodeError> {
    let n = read_count(c, "swap hops", 1, CANONICAL_MAX_LEGS)?;
    let hops: Vec<SwapHop> = (0..n).map(|_| SwapHop::at(c)).collect::<Result<_, _>>()?;
    check_hops(&hops).map_err(wire_invalid)?;
    Ok(hops)
}

// ── 0x0057 | 0x0058 RouteDigestPreimage ────────────────────────────────────

/// What `X_route` commits. The variant is discriminated, so `RecomputeE`
/// derives it from `B°`'s own branch and cannot reinterpret one as the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDigestPreimage {
    Swap {
        hops: Vec<SwapHop>,
    },
    Close {
        vault_id: D32,
        parent_root: D32,
        setup_ref: D32,
        reserve_a: u64,
        reserve_b: u64,
    },
}

impl RouteDigestPreimage {
    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        let mut out = Vec::new();
        match self {
            Self::Swap { hops } => {
                check_hops(hops)?;
                push_env(&mut out, class::SOFI_ROUTE_DIGEST_SWAP);
                push_hops(&mut out, hops);
            }
            Self::Close {
                vault_id,
                parent_root,
                setup_ref,
                reserve_a,
                reserve_b,
            } => {
                push_env(&mut out, class::SOFI_ROUTE_DIGEST_CLOSE);
                push_digest32(&mut out, vault_id);
                push_digest32(&mut out, parent_root);
                push_digest32(&mut out, setup_ref);
                push_u64(&mut out, *reserve_a);
                push_u64(&mut out, *reserve_b);
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = match c.peek_class()? {
            class::SOFI_ROUTE_DIGEST_SWAP => {
                c.envelope(class::SOFI_ROUTE_DIGEST_SWAP, SCHEMA_V1)?;
                Self::Swap {
                    hops: read_hops(&mut c)?,
                }
            }
            class::SOFI_ROUTE_DIGEST_CLOSE => {
                c.envelope(class::SOFI_ROUTE_DIGEST_CLOSE, SCHEMA_V1)?;
                Self::Close {
                    vault_id: c.digest32()?,
                    parent_root: c.digest32()?,
                    setup_ref: c.digest32()?,
                    reserve_a: c.u64()?,
                    reserve_b: c.u64()?,
                }
            }
            got => return Err(DecodeError::WrongClass { got }),
        };
        finish(&c, v)
    }
}

// ── 0x0053 | 0x0054 SettlementBody (B°) ────────────────────────────────────

/// `B°` — the settlement body, one branch per operation kind. The branch fixes
/// the write sets, the static checks and the route digest's variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementBody {
    Swap {
        token_in: D32,
        amount_in: u64,
        token_out: D32,
        exact_out: u64,
        hops: Vec<SwapHop>,
        trader_core: D32,
        dlv_cores: Vec<D32>,
        closure: PreEClosureIndex,
    },
    Close {
        vault_id: D32,
        parent_root: D32,
        setup_ref: D32,
        owner_authority: OwnerAuthority,
        reserve_a: u64,
        reserve_b: u64,
        trader_core: D32,
        dlv_core: D32,
        closure: PreEClosureIndex,
    },
}

impl SettlementBody {
    /// How many DLV parents the operation references: hop count for a swap,
    /// one for a close. It selects the form of E, never the beta cap.
    pub fn leg_count(&self) -> usize {
        match self {
            Self::Swap { hops, .. } => hops.len(),
            Self::Close { .. } => 1,
        }
    }

    /// `𝒞_E^pre` — the E-independent validation references this branch
    /// commits, whatever the branch.
    pub fn closure(&self) -> &PreEClosureIndex {
        match self {
            Self::Swap { closure, .. } | Self::Close { closure, .. } => closure,
        }
    }

    /// The route-digest preimage this branch commits. Derived from the branch,
    /// so no caller chooses the reading.
    pub fn route_digest_preimage(&self) -> RouteDigestPreimage {
        match self {
            Self::Swap { hops, .. } => RouteDigestPreimage::Swap { hops: hops.clone() },
            Self::Close {
                vault_id,
                parent_root,
                setup_ref,
                reserve_a,
                reserve_b,
                ..
            } => RouteDigestPreimage::Close {
                vault_id: *vault_id,
                parent_root: *parent_root,
                setup_ref: *setup_ref,
                reserve_a: *reserve_a,
                reserve_b: *reserve_b,
            },
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        let mut out = Vec::new();
        match self {
            Self::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core,
                dlv_cores,
                closure,
            } => {
                check_hops(hops)?;
                // One core reference per carried core, in P(E)'s own order
                // (which is sorted by vault id). The references are DIGESTS,
                // so they carry no order of their own and nothing here can
                // bind them to the cores — `sofi::validation` does that, and
                // must, because the cores are not in scope at this layer.
                check_count("dlv cores", 1, CANONICAL_MAX_LEGS, dlv_cores.len())?;
                push_env(&mut out, class::SOFI_SETTLEMENT_SWAP);
                push_digest32(&mut out, token_in);
                push_u64(&mut out, *amount_in);
                push_digest32(&mut out, token_out);
                push_u64(&mut out, *exact_out);
                push_hops(&mut out, hops);
                push_digest32(&mut out, trader_core);
                push_u32(&mut out, dlv_cores.len() as u32);
                for core in dlv_cores {
                    push_digest32(&mut out, core);
                }
                out.extend_from_slice(&closure.encode());
            }
            Self::Close {
                vault_id,
                parent_root,
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                trader_core,
                dlv_core,
                closure,
            } => {
                push_env(&mut out, class::SOFI_SETTLEMENT_CLOSE);
                push_digest32(&mut out, vault_id);
                push_digest32(&mut out, parent_root);
                push_digest32(&mut out, setup_ref);
                out.extend_from_slice(&owner_authority.encode());
                push_u64(&mut out, *reserve_a);
                push_u64(&mut out, *reserve_b);
                push_digest32(&mut out, trader_core);
                push_digest32(&mut out, dlv_core);
                out.extend_from_slice(&closure.encode());
            }
        }
        Ok(out)
    }

    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        match c.peek_class()? {
            class::SOFI_SETTLEMENT_SWAP => {
                c.envelope(class::SOFI_SETTLEMENT_SWAP, SCHEMA_V1)?;
                let token_in = c.digest32()?;
                let amount_in = c.u64()?;
                let token_out = c.digest32()?;
                let exact_out = c.u64()?;
                let hops = read_hops(c)?;
                let trader_core = c.digest32()?;
                let n = read_count(c, "dlv cores", 1, CANONICAL_MAX_LEGS)?;
                let dlv_cores: Vec<D32> = (0..n).map(|_| c.digest32()).collect::<Result<_, _>>()?;
                let closure = PreEClosureIndex::at(c)?;
                Ok(Self::Swap {
                    token_in,
                    amount_in,
                    token_out,
                    exact_out,
                    hops,
                    trader_core,
                    dlv_cores,
                    closure,
                })
            }
            class::SOFI_SETTLEMENT_CLOSE => {
                c.envelope(class::SOFI_SETTLEMENT_CLOSE, SCHEMA_V1)?;
                Ok(Self::Close {
                    vault_id: c.digest32()?,
                    parent_root: c.digest32()?,
                    setup_ref: c.digest32()?,
                    owner_authority: OwnerAuthority::at(c)?,
                    reserve_a: c.u64()?,
                    reserve_b: c.u64()?,
                    trader_core: c.digest32()?,
                    dlv_core: c.digest32()?,
                    closure: PreEClosureIndex::at(c)?,
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

// ── 0x0059 SettlementPreimage (P(E)) ───────────────────────────────────────

/// `P(E) = {B°, T°, V° sorted by vault_id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPreimage {
    settlement: SettlementBody,
    trader_core: TraderCore,
    dlv_cores: Vec<DlvCore>,
}

impl SettlementPreimage {
    pub fn new(
        settlement: SettlementBody,
        trader_core: TraderCore,
        dlv_cores: Vec<DlvCore>,
    ) -> Result<Self, SofiWireError> {
        // EXACTLY one core per DLV parent the settlement references. Without
        // this, two different canonical `P(E)` byte strings — one carrying a
        // spare core — recompute to the same single-vault E, because the
        // derivation reads only the first. That is a second preimage for one
        // commitment, with no hash collision anywhere in it.
        let expected = settlement.leg_count();
        check_count("dlv cores", expected, expected, dlv_cores.len())?;
        let keys: Vec<D32> = dlv_cores.iter().map(|c| *c.vault_id()).collect();
        check_strictly_ascending("dlv cores", &keys)?;
        let preimage = Self {
            settlement,
            trader_core,
            dlv_cores,
        };
        // An oversized P(E) has NO admissible canonical representation, so the
        // object refuses to exist rather than existing unencodable.
        check_preimage_bytes(&preimage.encode_unchecked()?)?;
        Ok(preimage)
    }

    pub fn settlement(&self) -> &SettlementBody {
        &self.settlement
    }
    pub fn trader_core(&self) -> &TraderCore {
        &self.trader_core
    }
    pub fn dlv_cores(&self) -> &[DlvCore] {
        &self.dlv_cores
    }

    fn encode_unchecked(&self) -> Result<Vec<u8>, SofiWireError> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_SETTLEMENT_PREIMAGE);
        out.extend_from_slice(&self.settlement.encode()?);
        out.extend_from_slice(&self.trader_core.encode()?);
        push_u32(&mut out, self.dlv_cores.len() as u32);
        for core in &self.dlv_cores {
            out.extend_from_slice(&core.encode()?);
        }
        Ok(out)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        let out = self.encode_unchecked()?;
        check_preimage_bytes(&out)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Refused BEFORE parsing: an oversized preimage is not a thing to be
        // examined and then rejected, it is bytes that name no object.
        check_preimage_bytes(bytes).map_err(wire_invalid)?;
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_SETTLEMENT_PREIMAGE, SCHEMA_V1)?;
        let settlement = SettlementBody::at(&mut c)?;
        let trader_core = TraderCore::at(&mut c)?;
        let n = read_count(&mut c, "dlv cores", 1, CANONICAL_MAX_LEGS)?;
        let dlv_cores: Vec<DlvCore> = (0..n)
            .map(|_| DlvCore::at(&mut c))
            .collect::<Result<_, _>>()?;
        let v = Self::new(settlement, trader_core, dlv_cores).map_err(wire_invalid)?;
        finish(&c, v)
    }
}

// ── 0x005A VaultGenesisPreimage · 0x005B VaultCreation ─────────────────────

/// What `GenesisAccepted` validates against: the identity that fixes
/// `vault_id`, and the exact state `V_0` must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultGenesisPreimage {
    pub owner_genesis: D32,
    pub owner_device_id: D32,
    pub create_position: u64,
    pub state: VaultStateLeaf,
}

impl VaultGenesisPreimage {
    /// `v = H(vault-id/v1 ‖ G_o ‖ DevID_o ‖ u64be(p_create))`, recomputed from
    /// these bytes rather than carried, so a genesis cannot name another vault.
    pub fn vault_id(&self) -> D32 {
        super::super::derive::vault_id(
            &self.owner_genesis,
            &self.owner_device_id,
            self.create_position,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, SofiWireError> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_VAULT_GENESIS_PREIMAGE);
        push_digest32(&mut out, &self.owner_genesis);
        push_digest32(&mut out, &self.owner_device_id);
        push_u64(&mut out, self.create_position);
        out.extend_from_slice(&self.state.encode()?);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SOFI_VAULT_GENESIS_PREIMAGE, SCHEMA_V1)?;
        let v = Self {
            owner_genesis: c.digest32()?,
            owner_device_id: c.digest32()?,
            create_position: c.u64()?,
            state: VaultStateLeaf::at(&mut c)?,
        };
        finish(&c, v)
    }
}

/// The owner's insert-only creation record at `p_create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultCreation {
    pub vault_id: D32,
    pub genesis_root: D32,
    pub amount_a: u64,
    pub amount_b: u64,
}

impl VaultCreation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SOFI_VAULT_CREATION);
        push_digest32(&mut out, &self.vault_id);
        push_digest32(&mut out, &self.genesis_root);
        push_u64(&mut out, self.amount_a);
        push_u64(&mut out, self.amount_b);
        out
    }

    /// Decode at a cursor, for a nested reader. The economic leaf decoder
    /// needs this: a creation record is also an `R_econ` leaf (P15-12), and
    /// the leaf carries these exact bytes rather than a second encoding.
    pub(crate) fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        c.envelope(class::SOFI_VAULT_CREATION, SCHEMA_V1)?;
        Ok(Self {
            vault_id: c.digest32()?,
            genesis_root: c.digest32()?,
            amount_a: c.u64()?,
            amount_b: c.u64()?,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        let v = Self::at(&mut c)?;
        finish(&c, v)
    }
}
