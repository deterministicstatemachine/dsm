// SPDX-License-Identifier: Apache-2.0

//! The production `VaultStateV2` decoder — strict, schema-3-only.
//!
//! CCB is not self-describing: structure comes from `(class, schema)` plus
//! the registry. This decoder accepts exactly `0x0001` schema 3 and rebuilds
//! the state through the same validating constructors the encoder uses, so a
//! decoded object cannot represent anything an encoder would refuse.
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
                write!(f, "expected class 0x0001, got {got:#06x}")
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

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.i.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.b.len() {
            return Err(DecodeError::Truncated);
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn digest32(&mut self) -> Result<[u8; 32], DecodeError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn envelope(&mut self, want_class: u16, want_schema: u16) -> Result<(), DecodeError> {
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

fn invalid(e: CcbError) -> DecodeError {
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

/// Decode `CCB(V_n)` — class `0x0001`, schema 3, strict, no trailing bytes.
pub fn decode_vault_state(bytes: &[u8]) -> Result<VaultStateV2, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };

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
    let mut members: Vec<Vec<u8>> = Vec::new();
    for _ in 0..member_count {
        let len = c.u32()? as usize;
        members.push(c.take(len)?.to_vec());
    }
    let member_refs: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    let storage_set = StorageSetMembers::new(&member_refs).map_err(invalid)?;

    let quorum = c.u32()?; // 15

    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }

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
