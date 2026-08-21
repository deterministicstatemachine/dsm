// SPDX-License-Identifier: Apache-2.0

//! The `VaultStateV2` encoding closure — registry §5.1–§5.4, §5.7, §5.9.

use super::{
    class, family, push_absent, push_bytes, push_digest32, push_envelope, push_present, push_u16,
    push_u32, push_u64, CcbError, FEE_DENOMINATOR,
};

/// `0x0002` — the committed storage set.
///
/// **This class does not carry the §2.1 envelope.** Its encoding is the frozen
/// shipping layout: a count, then each member id as bare length-prefixed bytes.
/// Every deployed vault's signed anchor already commits a `storage_set_id`
/// under this construction, so wrapping it now would invalidate all of them.
/// A generic "nested object gets an envelope" helper must never be applied
/// here — the result would be perfectly deterministic and not normative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSetMembers {
    members: Vec<Vec<u8>>,
}

impl StorageSetMembers {
    /// Sorts the ids and refuses an empty set, an empty id, or a duplicate.
    ///
    /// Sorting is canonicalization the format calls for; refusing duplicates
    /// is not. A duplicate is a producer bug, and collapsing it would map two
    /// logical inputs onto one encoding.
    pub fn new(member_ids: &[&[u8]]) -> Result<Self, CcbError> {
        if member_ids.is_empty() || member_ids.iter().any(|id| id.is_empty()) {
            return Err(CcbError::EmptyStorageSetOrMember);
        }
        let mut members: Vec<Vec<u8>> = member_ids.iter().map(|id| id.to_vec()).collect();
        members.sort_unstable();
        if members.windows(2).any(|w| w[0] == w[1]) {
            return Err(CcbError::DuplicateSetElement {
                class: class::STORAGE_SET,
            });
        }
        Ok(Self { members })
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// `u32_be(count) ‖ for each id in ascending byte order: u32_be(len) ‖ id`.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        let count = u32::try_from(self.members.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, count);
        for id in &self.members {
            push_bytes(&mut out, id)?;
        }
        Ok(out)
    }
}

/// `0x0004` — one encumbrance claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncumbranceClaim {
    pub vault_id: [u8; 32],
    pub parent_state_commitment: [u8; 32],
    pub claim_seq: u64,
    pub amount: u64,
    pub token: [u8; 32],
    pub purpose: u16,
}

impl EncumbranceClaim {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope(&mut out, class::ENCUMBRANCE_CLAIM, 1);
        push_digest32(&mut out, &self.vault_id);
        push_digest32(&mut out, &self.parent_state_commitment);
        push_u64(&mut out, self.claim_seq);
        push_u64(&mut out, self.amount);
        push_digest32(&mut out, &self.token);
        push_u16(&mut out, self.purpose);
        out
    }
}

/// `0x0005` — the encumbrance set, ordered by element encoding per §2.4.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncumbranceSet {
    claims: Vec<EncumbranceClaim>,
}

impl EncumbranceSet {
    pub fn new(claims: Vec<EncumbranceClaim>) -> Result<Self, CcbError> {
        let mut encoded: Vec<Vec<u8>> = claims.iter().map(EncumbranceClaim::encode).collect();
        encoded.sort_unstable();
        if encoded.windows(2).any(|w| w[0] == w[1]) {
            return Err(CcbError::DuplicateSetElement {
                class: class::ENCUMBRANCE_SET,
            });
        }
        let mut claims = claims;
        claims.sort_by_cached_key(EncumbranceClaim::encode);
        Ok(Self { claims })
    }

    pub fn empty() -> Self {
        Self { claims: Vec::new() }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope(&mut out, class::ENCUMBRANCE_SET, 1);
        let count = u32::try_from(self.claims.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, count);
        for claim in &self.claims {
            out.extend_from_slice(&claim.encode());
        }
        Ok(out)
    }
}

/// `0x0007` — the market predicate family committed at vault birth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketPolicy {
    family_id: u16,
    family_version: u16,
    token_a_policy_commit: [u8; 32],
    token_b_policy_commit: [u8; 32],
}

impl MarketPolicy {
    /// The beta family. Refuses an unordered or equal token pair rather than
    /// swapping it: the order is a validity condition, and swapping would map
    /// two distinct logical inputs onto one encoding.
    pub fn beta_constant_product(
        token_a_policy_commit: [u8; 32],
        token_b_policy_commit: [u8; 32],
    ) -> Result<Self, CcbError> {
        if token_a_policy_commit >= token_b_policy_commit {
            return Err(CcbError::TokenPairNotStrictlyOrdered);
        }
        Ok(Self {
            family_id: family::CONSTANT_PRODUCT_EXACT_INPUT,
            family_version: family::BETA_VERSION,
            token_a_policy_commit,
            token_b_policy_commit,
        })
    }

    pub fn token_a(&self) -> &[u8; 32] {
        &self.token_a_policy_commit
    }

    pub fn token_b(&self) -> &[u8; 32] {
        &self.token_b_policy_commit
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope(&mut out, class::MARKET_POLICY, 1);
        push_u16(&mut out, self.family_id);
        push_u16(&mut out, self.family_version);
        push_digest32(&mut out, &self.token_a_policy_commit);
        push_digest32(&mut out, &self.token_b_policy_commit);
        out
    }
}

/// `0x0009` — the release family. Two fields and no parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePolicy {
    family_id: u16,
    family_version: u16,
}

impl ReleasePolicy {
    /// Both legs to zero in one transition, vault retired. There is nothing to
    /// parameterise: the amounts are the parent's reserves, the destination is
    /// ordinary owner balance, the authority is the owner signature over the
    /// exact successor, and the timing is Req 6.30's.
    pub fn beta_owner_local_full_close() -> Self {
        Self {
            family_id: family::OWNER_LOCAL_FULL_CLOSE,
            family_version: family::BETA_VERSION,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope(&mut out, class::RELEASE_POLICY, 1);
        push_u16(&mut out, self.family_id);
        push_u16(&mut out, self.family_version);
        out
    }
}

/// `0x000A` — the fee policy, an exact rational over `FEE_DENOMINATOR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicy {
    fee_bps: u32,
}

impl FeePolicy {
    pub fn new(fee_bps: u32) -> Result<Self, CcbError> {
        if fee_bps >= FEE_DENOMINATOR {
            return Err(CcbError::FeeAtOrAboveDenominator { fee_bps });
        }
        Ok(Self { fee_bps })
    }

    pub fn fee_bps(&self) -> u32 {
        self.fee_bps
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope(&mut out, class::FEE_POLICY, 1);
        push_u32(&mut out, self.fee_bps);
        out
    }
}

/// `0x0001` — the DLV state, the fifteen members of Def 4.1 in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStateV2 {
    pub owner_genesis_id: [u8; 32],
    pub owner_device_id: [u8; 32],
    pub vault_id: [u8; 32],
    pub generation: u64,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub market_policy: MarketPolicy,
    pub release_policy: ReleasePolicy,
    pub fee_policy: FeePolicy,
    pub encumbrances: EncumbranceSet,
    pub iteration_budget: Option<u64>,
    pub parent_state_commitment: [u8; 32],
    pub owner_root: [u8; 32],
    pub storage_set: StorageSetMembers,
    pub quorum: u32,
}

impl VaultStateV2 {
    /// Fields 1..15 in Def 4.1 order.
    ///
    /// Field 14 nests the storage set by its **frozen layout**, with no
    /// envelope. That is the one place this encoder deviates from §2.6, and it
    /// is deliberate. The result stays uniquely parseable because the set
    /// begins with its own count and every member is length-prefixed, so a
    /// reader knows exactly where field 14 ends and the `u32` of field 15
    /// begins.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope(&mut out, class::VAULT_STATE_V2, 1);
        push_digest32(&mut out, &self.owner_genesis_id); // 1
        push_digest32(&mut out, &self.owner_device_id); // 2
        push_digest32(&mut out, &self.vault_id); // 3
        push_u64(&mut out, self.generation); // 4
        push_u64(&mut out, self.reserve_a); // 5
        push_u64(&mut out, self.reserve_b); // 6
        out.extend_from_slice(&self.market_policy.encode()); // 7
        out.extend_from_slice(&self.release_policy.encode()); // 8
        out.extend_from_slice(&self.fee_policy.encode()); // 9
        out.extend_from_slice(&self.encumbrances.encode()?); // 10
        match self.iteration_budget {
            // 11
            None => push_absent(&mut out),
            Some(budget) => {
                push_present(&mut out);
                push_u64(&mut out, budget);
            }
        }
        push_digest32(&mut out, &self.parent_state_commitment); // 12
        push_digest32(&mut out, &self.owner_root); // 13
        out.extend_from_slice(&self.storage_set.encode()?); // 14 — no envelope
        push_u32(&mut out, self.quorum); // 15
        Ok(out)
    }
}
