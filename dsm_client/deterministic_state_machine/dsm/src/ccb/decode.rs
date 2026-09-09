// SPDX-License-Identifier: Apache-2.0

//! The production CCB decoders — strict, one live schema per class.
//!
//! CCB is not self-describing: structure comes from `(class, schema)` plus
//! the registry. Each decoder accepts exactly its class's live schema and
//! rebuilds the object through the same validating constructors the encoder
//! uses, so a decoded object cannot represent anything an encoder would
//! refuse. `VaultStateV2` decodes at schema 4; the settlement bundle and what
//! it nests (amendment 2c-A.1) decode at the schemas the registry names, and
//! the bundle decoder records the exact byte span of every nested successor —
//! the second operand of `VDS.COMMON.10.a` — and offers a whole-bundle round
//! trip under the frozen encoder (2c-A.1 ruling 8).
//!
//! **Burned schemas are refused, not upgraded.** A schema-1 or schema-2 blob
//! gets a distinct error naming the burn — there is no fallback, no
//! dual-read, and no migration, because a clean reprovision means no
//! old-format state is valid.
//!
//! **Trailing bytes are refused.** A payload that decodes and then continues
//! is not a `V_n` with a suffix; it is not a `V_n`.
//!
//! The conformance test's parser remains fully independent of this module —
//! that independence is the uniqueness proof, and this decoder existing does
//! not weaken it: this is a consumer, not a check.

use super::settlement::{
    Allocation, AllocationBundle, ConsumedDlvTransition, DsmSuccessorEvidence, MarketTerms, Route,
    RouteLeg, SettlementBundle, TradeIntent, ENTROPY_LEN,
};
use super::state::{
    EncumbranceClaim, EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy, StorageSetMembers,
    VaultStateV2,
};
use super::{class, family, schema, CcbError, CcbObject};

/// Why a byte string is not a decodable `V_n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Wrong object class in the envelope.
    WrongClass { got: u16 },
    /// A burned schema version — refused, never upgraded.
    BurnedSchema { got: u16 },
    /// An unknown (never-assigned) schema version.
    UnknownSchema { got: u16 },
    /// The bytes ended before the layout did.
    Truncated,
    /// The layout ended before the bytes did.
    TrailingBytes { extra: usize },
    /// A field decoded to a value the validating constructors refuse.
    Invalid(String),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::WrongClass { got } => {
                write!(f, "unexpected object class {got:#06x}")
            }
            DecodeError::BurnedSchema { got } => write!(
                f,
                "VaultStateV2 schema {got} is burned; there is no upgrade path — reprovision"
            ),
            DecodeError::UnknownSchema { got } => write!(f, "unknown schema {got}"),
            DecodeError::Truncated => write!(f, "payload ends before the layout does"),
            DecodeError::TrailingBytes { extra } => {
                write!(f, "{extra} trailing bytes after a complete V_n")
            }
            DecodeError::Invalid(e) => write!(f, "invalid field: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Shared by the economic decoders so there is ONE set of truncation and
/// envelope semantics in the crate, not two that can drift apart.
pub(crate) struct Cursor<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) i: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.i.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.b.len() {
            return Err(DecodeError::Truncated);
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    pub(crate) fn digest32(&mut self) -> Result<[u8; 32], DecodeError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    /// The class of the object at the cursor, without consuming it. Needed
    /// for a heterogeneous inline sequence, where the envelope IS the
    /// discriminant.
    pub(crate) fn peek_class(&self) -> Result<u16, DecodeError> {
        if self.i + 2 > self.b.len() {
            return Err(DecodeError::Truncated);
        }
        Ok(u16::from_be_bytes([self.b[self.i], self.b[self.i + 1]]))
    }
    pub(crate) fn envelope(
        &mut self,
        want_class: u16,
        want_schema: u16,
    ) -> Result<(), DecodeError> {
        let c = self.u16()?;
        let s = self.u16()?;
        if c != want_class {
            return Err(DecodeError::WrongClass { got: c });
        }
        if s != want_schema {
            if schema::is_burned(c, s) {
                return Err(DecodeError::BurnedSchema { got: s });
            }
            return Err(DecodeError::UnknownSchema { got: s });
        }
        Ok(())
    }
}

pub(crate) fn invalid(e: CcbError) -> DecodeError {
    DecodeError::Invalid(e.to_string())
}

/// Decode a `GenesisParamsV3` — class `0x0018`, schema 1, strict.
pub fn decode_genesis_params(bytes: &[u8]) -> Result<super::genesis::GenesisParamsV3, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(class::GENESIS_PARAMS_V3, 1)?;
    let genesis_nonce = c.digest32()?;
    let nid_len = c.u32()? as usize;
    let network_id = c.take(nid_len)?.to_vec();
    let genesis_version = c.u32()?;
    let grk_alg_id = c.u16()?;
    let pk_len = c.u32()? as usize;
    let grk_pk = c.take(pk_len)?.to_vec();
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    super::genesis::GenesisParamsV3::new(
        genesis_nonce,
        &network_id,
        genesis_version,
        grk_alg_id,
        &grk_pk,
    )
    .map_err(invalid)
}

/// Decode a `RootProgressionDelegation` — class `0x0019`, schema 1, strict.
pub fn decode_delegation(
    bytes: &[u8],
) -> Result<super::devtree::RootProgressionDelegation, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(class::ROOT_PROGRESSION_DELEGATION, 1)?;
    let d = super::devtree::RootProgressionDelegation {
        genesis_id: c.digest32()?,
        role: c.u16()?,
        role_version: c.u16()?,
        delegated_alg_id: c.u16()?,
        delegated_pk: {
            let len = c.u32()? as usize;
            c.take(len)?.to_vec()
        },
        delegation_number: c.u64()?,
        parent_delegation_digest: c.digest32()?,
        activation_transition_digest: c.digest32()?,
    };
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    // Round-trip through the validating encoder so a decoded delegation
    // cannot carry a key its declared algorithm refuses.
    d.encode().map_err(invalid)?;
    Ok(d)
}

/// Decode a `DeviceTreeRootTransition` — class `0x001A`, schema 1, strict.
pub fn decode_transition(
    bytes: &[u8],
) -> Result<super::devtree::DeviceTreeRootTransition, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(class::DEVICE_TREE_ROOT_TRANSITION, 1)?;
    let t = super::devtree::DeviceTreeRootTransition {
        genesis_id: c.digest32()?,
        predecessor_transition_digest: c.digest32()?,
        new_root: c.digest32()?,
        version_number: c.u64()?,
        delegation_digest: c.digest32()?,
    };
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    Ok(t)
}

/// Decode `CCB(V_n)` — class `0x0001`, schema 4, strict, no trailing bytes.
pub fn decode_vault_state(bytes: &[u8]) -> Result<VaultStateV2, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    let v = vault_state_at(&mut c)?;
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    Ok(v)
}

/// A `VaultStateV2` at the cursor — the nested form `0x000F` field 2 uses.
pub(crate) fn vault_state_at(c: &mut Cursor<'_>) -> Result<VaultStateV2, DecodeError> {
    // Envelope. Burned schemas get their own refusal so the error names the
    // reprovision rather than reading as a parse bug.
    let cls = c.u16()?;
    let sch = c.u16()?;
    if cls != class::VAULT_STATE_V2 {
        return Err(DecodeError::WrongClass { got: cls });
    }
    if sch != VaultStateV2::SCHEMA {
        if schema::is_burned(cls, sch) {
            return Err(DecodeError::BurnedSchema { got: sch });
        }
        return Err(DecodeError::UnknownSchema { got: sch });
    }

    let owner_genesis_id = c.digest32()?; // 1
    let owner_device_id = c.digest32()?; // 2
    let vault_id = c.digest32()?; // 3
    let generation = c.u64()?; // 4
    let reserve_a = c.u64()?; // 5
    let reserve_b = c.u64()?; // 6

    // 7 MarketPolicy — rebuilt through the validating constructor, so a
    // decoded policy cannot carry a family the beta profile refuses.
    c.envelope(class::MARKET_POLICY, MarketPolicy::SCHEMA)?;
    let fam = c.u16()?;
    let ver = c.u16()?;
    if fam != family::CONSTANT_PRODUCT_EXACT_INPUT || ver != family::BETA_VERSION {
        return Err(DecodeError::Invalid(format!(
            "market family {fam:#06x} v{ver} is not the beta profile"
        )));
    }
    let token_a = c.digest32()?;
    let token_b = c.digest32()?;
    let market_policy = MarketPolicy::beta_constant_product(token_a, token_b).map_err(invalid)?;

    // 8 ReleasePolicy.
    c.envelope(class::RELEASE_POLICY, ReleasePolicy::SCHEMA)?;
    let fam = c.u16()?;
    let ver = c.u16()?;
    if fam != family::OWNER_LOCAL_FULL_CLOSE || ver != family::BETA_VERSION {
        return Err(DecodeError::Invalid(format!(
            "release family {fam:#06x} v{ver} is not the beta profile"
        )));
    }
    let release_policy = ReleasePolicy::beta_owner_local_full_close();

    // 9 FeePolicy.
    c.envelope(class::FEE_POLICY, FeePolicy::SCHEMA)?;
    let fee_policy = FeePolicy::new(c.u32()?).map_err(invalid)?;

    // 10 EncumbranceSet — elements rebuilt and re-validated; duplicate or
    // misordered input is refused by the constructor, not repaired.
    c.envelope(class::ENCUMBRANCE_SET, EncumbranceSet::SCHEMA)?;
    let claim_count = c.u32()?;
    let mut claims = Vec::new();
    for _ in 0..claim_count {
        c.envelope(class::ENCUMBRANCE_CLAIM, EncumbranceClaim::SCHEMA)?;
        claims.push(EncumbranceClaim {
            parent_binding: c.digest32()?,
            claim_seq: c.u64()?,
            amount: c.u64()?,
            token: c.digest32()?,
            purpose: c.u16()?,
        });
    }
    let encumbrances = EncumbranceSet::new(claims).map_err(invalid)?;

    // 11 optional iteration budget — the marker is always present.
    let iteration_budget = match c.u8()? {
        0x00 => None,
        0x01 => Some(c.u64()?),
        other => {
            return Err(DecodeError::Invalid(format!(
                "presence marker must be 0x00 or 0x01, got {other:#04x}"
            )))
        }
    };

    let parent_state_commitment = c.digest32()?; // 12
    let owner_authority_transition_digest = c.digest32()?; // 13

    // 14 StorageSet.
    c.envelope(class::STORAGE_SET, StorageSetMembers::SCHEMA)?;
    let member_count = c.u32()?;
    let mut entries: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
    for _ in 0..member_count {
        let len = c.u32()? as usize;
        let member_id = c.take(len)?.to_vec();
        // The incarnation is part of the entry, not a trailing array: a
        // truncated stream fails here rather than producing a set whose
        // members have lost their incarnations.
        entries.push((member_id, c.digest32()?));
    }
    let entry_refs: Vec<(&[u8], [u8; 32])> = entries
        .iter()
        .map(|(id, inc)| (id.as_slice(), *inc))
        .collect();
    let storage_set = StorageSetMembers::new(&entry_refs).map_err(invalid)?;

    let quorum = c.u32()?; // 15

    Ok(VaultStateV2 {
        owner_genesis_id,
        owner_device_id,
        vault_id,
        generation,
        reserve_a,
        reserve_b,
        market_policy,
        release_policy,
        fee_policy,
        encumbrances,
        iteration_budget,
        parent_state_commitment,
        owner_authority_transition_digest,
        storage_set,
        quorum,
    })
}

// ── The settlement bundle and what it nests (amendment 2c-A.1) ──────────────

fn presence(c: &mut Cursor<'_>) -> Result<bool, DecodeError> {
    match c.u8()? {
        0x00 => Ok(false),
        0x01 => Ok(true),
        other => Err(DecodeError::Invalid(format!(
            "presence marker must be 0x00 or 0x01, got {other:#04x}"
        ))),
    }
}

fn bytes_field<'a>(c: &mut Cursor<'a>) -> Result<&'a [u8], DecodeError> {
    let len = c.u32()? as usize;
    c.take(len)
}

fn fee_policy_at(c: &mut Cursor<'_>) -> Result<FeePolicy, DecodeError> {
    c.envelope(class::FEE_POLICY, FeePolicy::SCHEMA)?;
    FeePolicy::new(c.u32()?).map_err(invalid)
}

/// `0x000B` schema 1.
pub(crate) fn trade_intent_at(c: &mut Cursor<'_>) -> Result<TradeIntent, DecodeError> {
    c.envelope(class::TRADE_INTENT, TradeIntent::SCHEMA)?;
    Ok(TradeIntent {
        token_in: c.digest32()?,
        amount_in: c.u64()?,
        token_out: c.digest32()?,
        min_out: c.u64()?,
        max_fee: c.u64()?,
        max_hops: c.u32()?,
        max_fanout: c.u32()?,
        k: c.u32()?,
        nonce: c.digest32()?,
    })
}

/// `0x0015` schema 2.
pub(crate) fn allocation_at(c: &mut Cursor<'_>) -> Result<Allocation, DecodeError> {
    c.envelope(class::ALLOCATION, Allocation::SCHEMA)?;
    Ok(Allocation {
        parent_binding: c.digest32()?,
        delta_in: c.u64()?,
        delta_out: c.u64()?,
        encumbrance_claim: c.digest32()?,
        fee_policy: fee_policy_at(c)?,
    })
}

/// `0x0016` schema 2. Members must arrive in canonical (§2.4) order; a
/// misordered set is refused, never sorted (2c-A.1 ruling 8).
pub(crate) fn allocation_bundle_at(c: &mut Cursor<'_>) -> Result<AllocationBundle, DecodeError> {
    c.envelope(class::ALLOCATION_BUNDLE, AllocationBundle::SCHEMA)?;
    let count = c.u32()? as usize;
    let mut members = Vec::with_capacity(count);
    let mut previous: Option<Vec<u8>> = None;
    for _ in 0..count {
        let a = allocation_at(c)?;
        let enc = a.encode();
        if let Some(prev) = &previous {
            if *prev >= enc {
                return Err(DecodeError::Invalid(
                    "allocation bundle members are not in canonical order".into(),
                ));
            }
        }
        previous = Some(enc);
        members.push(a);
    }
    AllocationBundle::new(members).map_err(invalid)
}

/// `0x000D` schema 2 — a sequence in wire order; the nested envelope is the
/// leg discriminant.
pub(crate) fn route_at(c: &mut Cursor<'_>) -> Result<Route, DecodeError> {
    c.envelope(class::ROUTE, Route::SCHEMA)?;
    let count = c.u32()? as usize;
    let mut legs = Vec::with_capacity(count);
    for _ in 0..count {
        legs.push(match c.peek_class()? {
            class::ALLOCATION => RouteLeg::Single(allocation_at(c)?),
            class::ALLOCATION_BUNDLE => RouteLeg::Bundle(allocation_bundle_at(c)?),
            got => return Err(DecodeError::WrongClass { got }),
        });
    }
    Route::new(legs).map_err(invalid)
}

/// `0x0031` schema 1. `entropy` is exactly 32 bytes; `encapsulated_entropy`
/// present is refused; `sigma_dsm` is exactly 49,856 (2c-B).
pub(crate) fn dsm_successor_evidence_at(
    c: &mut Cursor<'_>,
) -> Result<DsmSuccessorEvidence, DecodeError> {
    c.envelope(class::DSM_SUCCESSOR_EVIDENCE, DsmSuccessorEvidence::SCHEMA)?;
    let rel_key = c.digest32()?;
    let embedded_parent = c.digest32()?;
    let counterparty_devid = c.digest32()?;
    let operation_bytes = bytes_field(c)?.to_vec();
    let entropy_bytes = bytes_field(c)?;
    let entropy: [u8; ENTROPY_LEN] = entropy_bytes.try_into().map_err(|_| {
        DecodeError::Invalid(format!(
            "entropy is {} bytes; schema 1 fixes it at exactly {ENTROPY_LEN}",
            entropy_bytes.len()
        ))
    })?;
    if presence(c)? {
        return Err(DecodeError::Invalid(
            "encapsulated_entropy is present; schema 1 refuses it".into(),
        ));
    }
    let sigma_dsm = bytes_field(c)?.to_vec();
    DsmSuccessorEvidence::new(
        rel_key,
        embedded_parent,
        counterparty_devid,
        operation_bytes,
        entropy,
        sigma_dsm,
    )
    .map_err(invalid)
}

/// `0x0033` schema 1.
pub(crate) fn market_terms_at(c: &mut Cursor<'_>) -> Result<MarketTerms, DecodeError> {
    c.envelope(class::MARKET_TERMS, MarketTerms::SCHEMA)?;
    let terms = MarketTerms {
        intent: trade_intent_at(c)?,
        route_set_commitment: c.digest32()?,
        selected_route: route_at(c)?,
        trader_parent: c.digest32()?,
        trader_successor: c.digest32()?,
        recovery_material: dsm_successor_evidence_at(c)?,
    };
    // 2c-B's in-bundle half, enforced where a foreign bundle actually arrives.
    terms.check_evidence_linkage().map_err(invalid)?;
    Ok(terms)
}

/// A decoded `0x000F` with the exact byte span its field 2 occupied in the
/// input — `VDS.COMMON.10.a`'s supplied operand, never re-encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTransition {
    pub transition: ConsumedDlvTransition,
    pub successor_span: core::ops::Range<usize>,
}

/// `0x000F` schema 1. `proof_material` present is refused (2c-A.1 ruling 6);
/// the constructors refuse a wrong-length authorization, an unlinked
/// successor and an unretired close (rulings 5, 9).
pub(crate) fn consumed_dlv_transition_at(
    c: &mut Cursor<'_>,
) -> Result<DecodedTransition, DecodeError> {
    c.envelope(
        class::CONSUMED_DLV_TRANSITION,
        ConsumedDlvTransition::SCHEMA,
    )?;
    let parent_binding = c.digest32()?; // 1
    let start = c.i;
    let successor = vault_state_at(c)?; // 2
    let successor_span = start..c.i;
    if presence(c)? {
        // 3
        return Err(DecodeError::Invalid(
            "proof_material is present; beta encodes it absent and schema 1 refuses it".into(),
        ));
    }
    let transition = if presence(c)? {
        // 4
        let sig = bytes_field(c)?.to_vec();
        ConsumedDlvTransition::owner_close(parent_binding, successor, sig).map_err(invalid)?
    } else {
        ConsumedDlvTransition::market(parent_binding, successor).map_err(invalid)?
    };
    Ok(DecodedTransition {
        transition,
        successor_span,
    })
}

/// A decoded bundle and, aligned with `bundle.transitions()`, the byte span
/// of each transition's nested successor in the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSettlementBundle {
    pub bundle: SettlementBundle,
    pub successor_spans: Vec<core::ops::Range<usize>>,
}

/// Decode `CCB(B)` — class `0x000E`, schema 1, strict, no trailing bytes. The
/// shape rule and beta cardinality are enforced by the constructors.
pub fn decode_settlement_bundle(bytes: &[u8]) -> Result<DecodedSettlementBundle, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(class::SETTLEMENT_BUNDLE, SettlementBundle::SCHEMA)?;
    let market_terms = if presence(&mut c)? {
        // 1
        Some(market_terms_at(&mut c)?)
    } else {
        None
    };
    let count = c.u32()? as usize; // 2
    let mut decoded = Vec::with_capacity(count);
    let mut previous: Option<Vec<u8>> = None;
    for _ in 0..count {
        let d = consumed_dlv_transition_at(&mut c)?;
        let enc = d.transition.encode().map_err(invalid)?;
        if let Some(prev) = &previous {
            if *prev >= enc {
                return Err(DecodeError::Invalid(
                    "transitions are not in canonical order".into(),
                ));
            }
        }
        previous = Some(enc);
        decoded.push(d);
    }
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    let successor_spans: Vec<_> = decoded.iter().map(|d| d.successor_span.clone()).collect();
    let transitions: Vec<_> = decoded.into_iter().map(|d| d.transition).collect();
    let bundle = match market_terms {
        Some(terms) => SettlementBundle::market(terms, transitions).map_err(invalid)?,
        None => {
            let mut transitions = transitions;
            let Some(only) = (transitions.len() == 1).then(|| transitions.remove(0)) else {
                return Err(invalid(CcbError::TransitionCount {
                    got: transitions.len(),
                }));
            };
            SettlementBundle::owner_close(only).map_err(invalid)?
        }
    };
    Ok(DecodedSettlementBundle {
        bundle,
        successor_spans,
    })
}

/// [`decode_settlement_bundle`], and then the whole-bundle round trip under
/// the frozen encoder: `encode(decode(B)) == B`, nested successor included, so
/// a non-canonical `V_{n+1}` inside a bundle makes the bundle non-canonical
/// before `VDS.COMMON.10.a` is reached (2c-A.1 ruling 8).
pub fn decode_settlement_bundle_canonical(
    bytes: &[u8],
) -> Result<DecodedSettlementBundle, DecodeError> {
    let d = decode_settlement_bundle(bytes)?;
    let re = d.bundle.encode().map_err(invalid)?;
    if re != bytes {
        return Err(DecodeError::Invalid(
            "the bundle does not re-encode to itself under the frozen encoder".into(),
        ));
    }
    Ok(d)
}
