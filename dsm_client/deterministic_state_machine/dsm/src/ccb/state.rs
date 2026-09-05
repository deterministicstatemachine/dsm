// SPDX-License-Identifier: Apache-2.0

//! The `VaultStateV2` encoding closure — registry §5.1–§5.4, §5.7, §5.9.

use super::{
    class, family, push_absent, push_bytes, push_digest32, push_envelope, push_present, push_u16,
    push_u32, push_u64, CcbError, CcbObject, FEE_DENOMINATOR,
};

/// One committed set entry: a member, and the register incarnation that
/// member was serving when the vault committed this set.
///
/// The pair is ONE authority fact — "this member, in this register
/// incarnation" — so it is one object rather than two index-aligned arrays.
/// `member_id` stays independently readable, because a resolver still needs
/// it to find the member's endpoint; `register_incarnation_id` stays
/// independently verifiable, because every read requires the responding
/// member to echo the exact value committed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSetEntry {
    member_id: Vec<u8>,
    register_incarnation_id: [u8; 32],
}

impl StorageSetEntry {
    pub fn member_id(&self) -> &[u8] {
        &self.member_id
    }

    pub fn register_incarnation_id(&self) -> [u8; 32] {
        self.register_incarnation_id
    }
}

/// `0x0002` schema 3 — the committed storage set, an ordinary CCB object.
///
/// Schema 1 froze an envelope-less layout because deployed anchors committed
/// set ids under it. The state-identity cut deleted those anchors, so schema 2
/// carried the §2.1 envelope like every other class.
///
/// Schema 3 changes WHAT is committed, not just how. A set of bare node ids
/// says only *which nodes*; a member that lost and rebuilt its register still
/// satisfies it, and can then assert emptiness for a cell the real incarnation
/// once held — an undetectable substitution, because owning the node identity
/// was the whole test. An entry is now the pair, so the set id commits to
/// *which durable register histories on those nodes*, and a rebuilt member
/// cannot impersonate continuity merely by still holding its identity key.
///
/// Set ids therefore differ from schema-2 ones. That is the reprovision, and
/// it is the point: an ambiguous authority encoding is not worth preserving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSetMembers {
    entries: Vec<StorageSetEntry>,
}

impl CcbObject for StorageSetMembers {
    const CLASS: u16 = class::STORAGE_SET;
    const SCHEMA: u16 = 3;
}

impl StorageSetMembers {
    /// Sorts by MEMBER ID and refuses an empty set, an empty member id, a
    /// duplicate member id, or a zero incarnation.
    ///
    /// Sorting is by `member_id` alone, never by the pair: sorting on the
    /// whole entry would let one member appear twice under two incarnations
    /// and still produce a strictly ascending list, which is exactly the
    /// ambiguity this schema exists to remove. A duplicate member id is
    /// therefore refused REGARDLESS of incarnation.
    ///
    /// An all-zero incarnation is refused because that is the value a member
    /// has before it has ever established one; committing it would bind a
    /// vault to "whatever this node had not yet decided".
    pub fn new(entries: &[(&[u8], [u8; 32])]) -> Result<Self, CcbError> {
        if entries.is_empty() || entries.iter().any(|(id, _)| id.is_empty()) {
            return Err(CcbError::EmptyStorageSetOrMember);
        }
        if entries.iter().any(|(_, inc)| inc == &[0u8; 32]) {
            return Err(CcbError::ZeroRegisterIncarnation);
        }
        let mut entries: Vec<StorageSetEntry> = entries
            .iter()
            .map(|(id, inc)| StorageSetEntry {
                member_id: id.to_vec(),
                register_incarnation_id: *inc,
            })
            .collect();
        entries.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        if entries.windows(2).any(|w| w[0].member_id == w[1].member_id) {
            return Err(CcbError::DuplicateSetElement {
                class: class::STORAGE_SET,
            });
        }
        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The committed entries, ascending by member id.
    pub fn entries(&self) -> &[StorageSetEntry] {
        &self.entries
    }

    /// The incarnation this set commits for `member_id`, if it is a member.
    ///
    /// A reader resolves an endpoint by member id and then requires THIS
    /// value back from whatever answers there.
    pub fn register_incarnation_of(&self, member_id: &[u8]) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|e| e.member_id == member_id)
            .map(|e| e.register_incarnation_id)
    }

    /// `envelope ‖ u32_be(count) ‖ for each entry in ascending member-id
    /// order: u32_be(len) ‖ member_id ‖ register_incarnation_id`.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        let count = u32::try_from(self.entries.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, count);
        for e in &self.entries {
            push_bytes(&mut out, &e.member_id)?;
            push_digest32(&mut out, &e.register_incarnation_id);
        }
        Ok(out)
    }
}

/// `0x0004` schema 2 — one encumbrance claim.
///
/// `parent_binding` is the **creation parent**: the `c_n` of the state the
/// transition that created this claim consumed. It is never the containing
/// state's own `c_k`. `E` is a member of `V_n`, so reading it that way would
/// give `c_n → CCB(V_n) → E_n → e_j → c_n` — a hash fixed point no encoder can
/// compute. A claim surviving into a later successor is carried **byte for
/// byte**; refreshing its parent to the current state is how an implementation
/// reaches the cycle while believing it is tidying up.
///
/// `vault_id` is not a field: `parent_binding` commits it, and carrying both
/// would admit an encodable pair that disagrees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncumbranceClaim {
    pub parent_binding: [u8; 32],
    pub claim_seq: u64,
    pub amount: u64,
    pub token: [u8; 32],
    pub purpose: u16,
}

impl CcbObject for EncumbranceClaim {
    const CLASS: u16 = class::ENCUMBRANCE_CLAIM;
    const SCHEMA: u16 = 2;
}

impl EncumbranceClaim {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.parent_binding);
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

impl CcbObject for EncumbranceSet {
    const CLASS: u16 = class::ENCUMBRANCE_SET;
    const SCHEMA: u16 = 2;
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
        push_envelope::<Self>(&mut out);
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

impl CcbObject for MarketPolicy {
    const CLASS: u16 = class::MARKET_POLICY;
    const SCHEMA: u16 = 1;
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
        push_envelope::<Self>(&mut out);
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

impl CcbObject for ReleasePolicy {
    const CLASS: u16 = class::RELEASE_POLICY;
    const SCHEMA: u16 = 1;
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
        push_envelope::<Self>(&mut out);
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

impl CcbObject for FeePolicy {
    const CLASS: u16 = class::FEE_POLICY;
    const SCHEMA: u16 = 1;
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
        push_envelope::<Self>(&mut out);
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
    /// Field 13 — the committed device-authority position: `t_j` of the
    /// `DeviceTreeRootTransition` under which the owner asserts the device
    /// authority signing for this vault. **Invariant across market
    /// successors** — copied byte for byte, never advanced, because a market
    /// successor executes while the owner is absent and must not move the
    /// owner-authority reference.
    pub owner_authority_transition_digest: [u8; 32],
    pub storage_set: StorageSetMembers,
    pub quorum: u32,
}

impl CcbObject for VaultStateV2 {
    const CLASS: u16 = class::VAULT_STATE_V2;
    /// Schema 4. The field list is unchanged from schema 3; field 14 now
    /// nests `0x0002` at schema 3 (the storage set carries each member's
    /// register incarnation), and §2.7 nests by complete CCB including the
    /// nested schema version — so a nested bump propagates upward whether or
    /// not this object's own fields moved. Schemas 1 and 2 are burned for the
    /// same reason.
    const SCHEMA: u16 = 4;
}

impl VaultStateV2 {
    /// Fields 1..15 in Def 4.1 order, every nested member by complete CCB.
    ///
    /// There is no longer a deviation to explain: field 14 nests `0x0002`
    /// schema 2 with its envelope, exactly like fields 7–10.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
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
        push_digest32(&mut out, &self.owner_authority_transition_digest); // 13
        out.extend_from_slice(&self.storage_set.encode()?); // 14
        push_u32(&mut out, self.quorum); // 15
        Ok(out)
    }
}
