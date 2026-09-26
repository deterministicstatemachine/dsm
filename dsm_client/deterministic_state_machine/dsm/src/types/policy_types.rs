// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token Policy Types (Protobuf-only transport; binary-only digests).
//!
//! The enforcer's view of a committed token policy ([`PolicyFile`]) and the
//! 32-byte commitment it is keyed by ([`PolicyAnchor`]). A policy's identity
//! is the commitment of its `TokenPolicyV3` bytes (SoFi §47), computed where
//! the bytes are registered (`crate::core::token::policy`); nothing here
//! hashes.
//! - No time of any kind in a policy.
//! - Absolutely no hex/json/base64/serde in any Rust path.

use std::collections::HashMap;

use crate::types::error::DsmError;
use prost::Message;

/// Fixed-length digest type for anchors and policy-bound hashes.
pub type Digest32 = [u8; 32];

/// The 32-byte commitment a token policy is keyed by: its `policy_commit`,
/// the hash of its committed `TokenPolicyV3` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyAnchor(pub Digest32);

impl PolicyAnchor {
    /// Borrow the raw 32-byte anchor.
    #[inline]
    pub fn as_bytes(&self) -> &Digest32 {
        &self.0
    }

    /// Construct directly from a 32-byte array.
    #[inline]
    pub fn from_bytes(bytes: Digest32) -> Self {
        PolicyAnchor(bytes)
    }

    /// Encode the anchor to Base32 Crockford for human-readable representation
    pub fn to_base32(&self) -> String {
        // Use base32 crate which supports Crockford encoding
        base32::encode(base32::Alphabet::Crockford, &self.0)
    }

    /// Decode a Base32 Crockford string to a PolicyAnchor
    pub fn from_base32(s: &str) -> Result<Self, DsmError> {
        let bytes = base32::decode(base32::Alphabet::Crockford, s)
            .ok_or_else(|| DsmError::invalid_parameter("Invalid base32 Crockford string"))?;
        if bytes.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "Base32 string must decode to exactly 32 bytes",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PolicyAnchor(arr))
    }

    /// Encode the anchor to a filename-safe byte vector without using hex/base64.
    /// This uses an escape scheme to avoid the two forbidden POSIX filename bytes:
    ///  - 0x00 (NUL)
    ///  - 0x2F ('/')
    ///    It also escapes 0xFF as a sentinel. Encoding is reversible and injective.
    pub fn to_path_component_bytes(&self) -> Vec<u8> {
        const ESC: u8 = 0xFF;
        const FORBIDDEN_A: u8 = 0x00; // NUL
        const FORBIDDEN_B: u8 = 0x2F; // '/'
        let mut out = Vec::with_capacity(self.0.len());
        for &b in self.0.iter() {
            match b {
                FORBIDDEN_A | FORBIDDEN_B | ESC => {
                    // Escape: ESC then masked value (xor for bijection)
                    out.push(ESC);
                    out.push(b ^ 0xA5);
                }
                _ => out.push(b),
            }
        }
        out
    }

    /// Decode a filename-safe byte slice created by `to_path_component_bytes` back to a PolicyAnchor.
    /// Returns None if the input is malformed.
    pub fn from_path_component_bytes(b: &[u8]) -> Option<Self> {
        const ESC: u8 = 0xFF;
        let mut raw = Vec::with_capacity(32);
        let mut i = 0;
        while i < b.len() {
            let x = b[i];
            if x == ESC {
                // Must have a following byte
                if i + 1 >= b.len() {
                    return None;
                }
                let y = b[i + 1] ^ 0xA5;
                raw.push(y);
                i += 2;
            } else {
                raw.push(x);
                i += 1;
            }
            if raw.len() > 32 {
                return None;
            }
        }
        if raw.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Some(Self(arr))
    }
}

/// What a committed policy constrains, as the enforcer evaluates it: the
/// operations its flags permit and the supply it was created with (SoFi
/// §47–§54), derived from the parsed blob by
/// `crate::core::token::policy::enforced_policy` and stated by nothing else.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyCondition {
    /// Restrict allowed operation types (interpreted as a set).
    OperationRestriction { allowed_operations: Vec<String> },

    /// Bitcoin tap safety constraints (dBTC §12).
    /// Protocol law — frozen into policy_commit via canonical bytes.
    /// Any modification produces a distinct GT (different token).
    BitcoinTapConstraint {
        /// Maximum successor vault generations (§12.1.1).
        max_successor_depth: u32,
        /// Minimum vault balance after fractional exit, in sats (§12.1.2).
        min_vault_balance_sats: u64,
        /// Bitcoin dust floor in sats — hard floor for any UTXO output.
        dust_floor_sats: u64,
        /// Required Bitcoin block depth for entry/exit anchors (§12.1.3).
        min_confirmations: u64,
    },

    /// The whole supply the token is created with: nothing is minted after
    /// genesis (SoFi §48), and no supply is unlimited (§54).
    SupplyCap { max_supply: u128 },
}

/// The enforcer's view of one committed policy.
#[derive(Debug, Clone)]
pub struct PolicyFile {
    /// Human-friendly name (UI/ops only; not on wire hashing).
    pub name: String,
    /// Human-friendly version label (UI/ops only).
    pub version: String,
    /// Author identity (semantic).
    pub author: String,
    /// Optional description (UI/ops only).
    pub description: Option<String>,
    /// Constraining conditions.
    pub conditions: Vec<PolicyCondition>,
    /// Extra key/value metadata (UI/ops only).
    pub metadata: HashMap<String, String>,
}

impl PolicyFile {
    /// Construct a new policy file.
    pub fn new(name: &str, version: &str, author: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            author: author.to_string(),
            description: None,
            conditions: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn add_condition(&mut self, condition: PolicyCondition) -> &mut Self {
        self.conditions.push(condition);
        self
    }

    pub fn add_metadata(&mut self, key: &str, value: &str) -> &mut Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_description(&mut self, description: &str) -> &mut Self {
        self.description = Some(description.to_string());
        self
    }

    /// Canonical deterministic serialization (binary): the `CanonicalPolicy`
    /// proto, the shape [`Self::from_canonical_bytes`] reads.
    ///
    /// Design:
    /// - **Excluded**: `metadata`, `description`, `name`, `version`
    ///   (UI/ops only; avoid non-semantic drift).
    /// - **Included**: `author`, `conditions` (semantic).
    /// - Set-like fields are **sorted** (operations).
    /// - Output is a compact binary layout (no text encodings).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DsmError> {
        let proto: crate::types::proto::CanonicalPolicy = self.into();
        let mut buf = Vec::new();
        proto
            .encode(&mut buf)
            .map_err(|e| DsmError::SerializationError(format!("Protobuf encode failed: {}", e)))?;
        Ok(buf)
    }

    /// Deserialize from canonical binary format (CanonicalPolicy proto).
    ///
    /// The canonical encoding contains only the semantic fields: `author`
    /// and `conditions`. Non-semantic fields (`name`, `version`,
    /// `description`, `metadata`) are empty.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let proto = crate::types::proto::CanonicalPolicy::decode(bytes).map_err(|e| {
            DsmError::SerializationError(format!("CanonicalPolicy decode failed: {}", e))
        })?;

        let conditions = proto
            .conditions
            .iter()
            .map(|c| c.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name: String::new(),
            version: String::new(),
            author: proto.author,
            description: None,
            conditions,
            metadata: std::collections::HashMap::new(),
        })
    }
}

impl From<&PolicyFile> for crate::types::proto::CanonicalPolicy {
    fn from(file: &PolicyFile) -> Self {
        Self {
            author: file.author.clone(),
            conditions: file.conditions.iter().map(|c| c.into()).collect(),
        }
    }
}

impl From<&PolicyCondition> for crate::types::proto::PolicyConditionProto {
    fn from(cond: &PolicyCondition) -> Self {
        use crate::types::proto::policy_condition_proto::Kind;
        use crate::types::proto::*;

        let kind = match cond {
            PolicyCondition::OperationRestriction { allowed_operations } => {
                let mut sorted = allowed_operations.clone();
                sorted.sort();
                Kind::OperationRestriction(OperationRestrictionProto {
                    allowed_operations: sorted,
                })
            }
            PolicyCondition::BitcoinTapConstraint {
                max_successor_depth,
                min_vault_balance_sats,
                dust_floor_sats,
                min_confirmations,
            } => Kind::BitcoinTapConstraint(BitcoinTapConstraintProto {
                max_successor_depth: *max_successor_depth,
                min_vault_balance_sats: *min_vault_balance_sats,
                dust_floor_sats: *dust_floor_sats,
                min_confirmations: *min_confirmations,
            }),
            PolicyCondition::SupplyCap { max_supply } => Kind::SupplyCap(SupplyCapProto {
                max_supply_u128: max_supply.to_be_bytes().to_vec(),
            }),
        };

        Self { kind: Some(kind) }
    }
}

impl TryFrom<&crate::types::proto::PolicyConditionProto> for PolicyCondition {
    type Error = DsmError;
    fn try_from(proto: &crate::types::proto::PolicyConditionProto) -> Result<Self, Self::Error> {
        use crate::types::proto::policy_condition_proto::Kind;
        use crate::types::proto::*;

        match &proto.kind {
            Some(Kind::OperationRestriction(p)) => Ok(PolicyCondition::OperationRestriction {
                allowed_operations: p.allowed_operations.clone(),
            }),
            Some(Kind::BitcoinTapConstraint(p)) => Ok(PolicyCondition::BitcoinTapConstraint {
                max_successor_depth: p.max_successor_depth,
                min_vault_balance_sats: p.min_vault_balance_sats,
                dust_floor_sats: p.dust_floor_sats,
                min_confirmations: p.min_confirmations,
            }),
            Some(Kind::SupplyCap(p)) => {
                if p.max_supply_u128.len() != 16 {
                    return Err(DsmError::SerializationError(
                        "SupplyCap max_supply must be 16 bytes".into(),
                    ));
                }
                let mut max_supply = 0u128;
                for b in &p.max_supply_u128 {
                    max_supply = (max_supply << 8) | (*b as u128);
                }
                Ok(PolicyCondition::SupplyCap { max_supply })
            }
            None => Err(DsmError::SerializationError(
                "Missing policy condition kind".into(),
            )),
        }
    }
}

/// A policy as the enforcer holds it: its view and the commitment it is
/// keyed by.
#[derive(Debug, Clone)]
pub struct TokenPolicy {
    pub file: PolicyFile,
    pub anchor: PolicyAnchor,
}

impl TokenPolicy {
    /// The enforcer's view `file` of the policy committed at `anchor`. The
    /// commitment is computed where the bytes are registered
    /// (`crate::core::token::policy::TokenPolicySystem::register_policy`)
    /// and never from `file`.
    pub fn new_with_anchor(file: PolicyFile, anchor: PolicyAnchor) -> Self {
        Self { file, anchor }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_are_sorted_in_canonical_bytes() {
        let mut p1 = PolicyFile::new("n", "v", "a");
        p1.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into(), "lock".into(), "burn".into()],
        });
        let b1 = p1.canonical_bytes().unwrap();

        let mut p2 = PolicyFile::new("n", "v", "a");
        p2.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["burn".into(), "transfer".into(), "lock".into()],
        });
        let b2 = p2.canonical_bytes().unwrap();

        assert_eq!(b1, b2);
    }

    #[test]
    fn anchor_from_bytes_as_bytes_roundtrip() {
        let raw = [0xABu8; 32];
        let anchor = PolicyAnchor::from_bytes(raw);
        assert_eq!(*anchor.as_bytes(), raw);
    }

    #[test]
    fn anchor_base32_roundtrip() {
        let raw = [0x42u8; 32];
        let anchor = PolicyAnchor::from_bytes(raw);
        let encoded = anchor.to_base32();
        let decoded = PolicyAnchor::from_base32(&encoded).unwrap();
        assert_eq!(anchor.0, decoded.0);
    }

    #[test]
    fn anchor_from_base32_invalid_string() {
        let result = PolicyAnchor::from_base32("!!invalid!!");
        assert!(result.is_err());
    }

    #[test]
    fn anchor_from_base32_wrong_length() {
        let short = base32::encode(base32::Alphabet::Crockford, &[1, 2, 3]);
        let result = PolicyAnchor::from_base32(&short);
        assert!(result.is_err());
    }

    #[test]
    fn anchor_path_component_roundtrip_no_special_bytes() {
        let raw = [0x42u8; 32];
        let anchor = PolicyAnchor::from_bytes(raw);
        let encoded = anchor.to_path_component_bytes();
        let decoded = PolicyAnchor::from_path_component_bytes(&encoded).unwrap();
        assert_eq!(anchor.0, decoded.0);
        assert_eq!(encoded.len(), 32, "No escaping needed for 0x42");
    }

    #[test]
    fn anchor_path_component_roundtrip_with_special_bytes() {
        let mut raw = [0u8; 32];
        raw[0] = 0x00; // NUL — forbidden
        raw[1] = 0x2F; // '/' — forbidden
        raw[2] = 0xFF; // ESC sentinel
        let anchor = PolicyAnchor::from_bytes(raw);
        let encoded = anchor.to_path_component_bytes();
        assert!(encoded.len() > 32, "Special bytes should be escaped");
        let decoded = PolicyAnchor::from_path_component_bytes(&encoded).unwrap();
        assert_eq!(anchor.0, decoded.0);
    }

    #[test]
    fn from_path_component_bytes_truncated_escape() {
        let bad = vec![0xFF]; // ESC with no following byte
        assert!(PolicyAnchor::from_path_component_bytes(&bad).is_none());
    }

    #[test]
    fn from_path_component_bytes_too_long() {
        let too_long = vec![0x42u8; 33];
        assert!(PolicyAnchor::from_path_component_bytes(&too_long).is_none());
    }

    #[test]
    fn policy_file_builder_methods() {
        let mut pf = PolicyFile::new("test", "v1", "alice");
        pf.with_description("A test policy");
        pf.add_metadata("key1", "val1");
        pf.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into()],
        });

        assert_eq!(pf.description.as_deref(), Some("A test policy"));
        assert_eq!(pf.metadata.get("key1").unwrap(), "val1");
        assert_eq!(pf.conditions.len(), 1);
    }

    #[test]
    fn policy_file_canonical_bytes_from_canonical_bytes_roundtrip() {
        let mut pf = PolicyFile::new("name", "v1", "carol");
        pf.add_condition(PolicyCondition::SupplyCap {
            max_supply: 1_000_000,
        });
        pf.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into()],
        });
        let canonical = pf.canonical_bytes().unwrap();
        let restored = PolicyFile::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(restored.author, "carol");
        assert_eq!(restored.conditions, pf.conditions);
        assert!(restored.name.is_empty(), "name excluded from canonical");
    }

    /// A committed policy carrying a vault condition (the reserved
    /// `vault_enforcement`, field 2) names a fact no verifier derives: it does
    /// not decode, so no token under it can be adopted or evaluated. The same
    /// for the condition kinds the policy grammar (SoFi §47–§54) does not
    /// name — an identity allowlist over caller-stated strings (field 1), an
    /// emission schedule (5), a credit bundle (6), a custom constraint (7) —
    /// which are reserved. A policy of evaluable conditions still decodes.
    #[test]
    fn a_policy_carrying_a_condition_the_grammar_does_not_name_does_not_decode() {
        // CanonicalPolicy { author: "a", conditions: [ { <field>: { 1: 100 } } ] }
        for field in [1u8, 2, 5, 6, 7] {
            let condition = [(field << 3) | 2, 0x02, 0x08, 0x64];
            let mut bytes = vec![0x0A, 0x01, b'a', 0x12, condition.len() as u8];
            bytes.extend_from_slice(&condition);
            assert!(
                PolicyFile::from_canonical_bytes(&bytes).is_err(),
                "condition kind {field} decoded"
            );
        }

        let mut evaluable = PolicyFile::new("n", "v", "a");
        evaluable.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into()],
        });
        let canonical = evaluable.canonical_bytes().expect("canonical");
        assert!(PolicyFile::from_canonical_bytes(&canonical).is_ok());
    }
}
