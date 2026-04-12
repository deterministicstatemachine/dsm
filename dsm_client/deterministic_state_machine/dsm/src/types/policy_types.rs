//! Token Policy Types (Protobuf-only transport; binary-only digests).
//!
//! Content-Addressed Token Policy Anchors (CTPA).
//! - Canonical hashing: BLAKE3 over a deterministic byte layout (binary).
//! - No wall-clock influence on canonical bytes (created_tick is metadata only).
//! - Absolutely no hex/json/base64/serde in any Rust path.

use std::collections::HashMap;

use crate::utils::deterministic_time as dt;
use crate::{
    crypto::blake3,
    types::{error::DsmError, operations::VerificationType},
};
use prost::Message;

/// Fixed-length digest type for anchors and policy-bound hashes.
pub type Digest32 = [u8; 32];

/// PolicyAnchor is the 32-byte identifier (BLAKE3) of a canonical policy file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyAnchor(pub Digest32);

impl PolicyAnchor {
    /// Create a new policy anchor from a policy file (content-addressed).
    ///
    /// NOTE: `PolicyFile::canonical_bytes()` is stable across platforms/runs.
    pub fn from_policy(policy: &PolicyFile) -> Result<Self, DsmError> {
        let bytes = policy.canonical_bytes()?;
        let h = blake3::domain_hash("DSM/cpta", &bytes);
        Ok(PolicyAnchor(*h.as_bytes()))
    }

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

    /// Encode the anchor to a display/URI-safe Base32 Crockford string.
    ///
    /// This helper is for UI, filenames, and URI presentation only. It is not
    /// part of any canonical commit or acceptance path.
    pub fn to_display_base32(&self) -> String {
        base32::encode(base32::Alphabet::Crockford, &self.0)
    }

    /// Build the canonical display URI form for this anchor.
    pub fn to_policy_uri(&self) -> String {
        format!("dsm:policy:{}", self.to_display_base32())
    }

    /// Decode a display/URI Base32 Crockford string into a `PolicyAnchor`.
    ///
    /// This accepts either the raw Crockford text or the prefixed
    /// `dsm:policy:<base32>` presentation form.
    pub fn from_policy_uri(value: &str) -> Result<Self, DsmError> {
        let base32_value = value.strip_prefix("dsm:policy:").unwrap_or(value);
        let bytes = base32::decode(base32::Alphabet::Crockford, base32_value)
            .ok_or_else(|| DsmError::invalid_parameter("Invalid policy anchor display string"))?;
        if bytes.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "Policy anchor display string must decode to exactly 32 bytes",
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

/// Possible vault-level conditions referenced by policies.
#[derive(Debug, Clone, PartialEq)]
pub enum VaultCondition {
    /// Unlock with matching hash challenge (domain-separated upstream).
    Hash(Vec<u8>),
    /// Minimum balance required.
    MinimumBalance(u64),
    /// Required vault type label.
    VaultType(String),
    /// Smart policy (canonical protobuf bytes).
    SmartPolicy(Vec<u8>),
}

/// Policy-level conditions that constrain token behavior.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyCondition {
    /// Only allow listed identities (optionally including their derivatives).
    IdentityConstraint {
        allowed_identities: Vec<String>,
        allow_derived: bool,
    },

    /// Delegate enforcement to a vault-level condition.
    VaultEnforcement { condition: VaultCondition },

    /// Restrict allowed operation types (interpreted as a set).
    OperationRestriction { allowed_operations: Vec<String> },

    /// Constrain operation to a specific logical time range (tick numbers).
    /// Replaces wall-clock time constraints with deterministic tick ranges.
    LogicalTimeConstraint { min_tick: u64, max_tick: u64 },

    /// Emissions schedule parameters (DJTE).
    EmissionsSchedule {
        total_supply: u64,
        shard_depth: u8,
        schedule_steps: u8,
        initial_step_emissions: u64,
        initial_step_amount: u64,
    },

    /// Credit bundle policy (sender-pays economic rate limiting).
    CreditBundlePolicy {
        bundle_size: u64,
        debit_rule: String,
        refill_rule: String,
    },

    /// Custom constraints with string parameters.
    Custom {
        constraint_type: String,
        parameters: HashMap<String, String>,
    },

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
}

/// Role-based access control for token policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRole {
    pub id: String,
    pub name: String,
    /// Interpreted as a set; canonicalized by sorted textual form.
    pub permissions: Vec<String>,
}

/// Immutable policy file content. Its canonical bytes are content-addressed.
#[derive(Debug, Clone)]
pub struct PolicyFile {
    /// Human-friendly name (UI/ops only; not on wire hashing).
    pub name: String,
    /// Human-friendly version label (UI/ops only).
    pub version: String,
    /// Deterministic tick for creation (UI/ops only; EXCLUDED from canonical bytes).
    pub created_tick: u64,
    /// Author identity (semantic).
    pub author: String,
    /// Optional description (UI/ops only).
    pub description: Option<String>,
    /// Constraining conditions.
    pub conditions: Vec<PolicyCondition>,
    /// Roles and permissions.
    pub roles: Vec<PolicyRole>,
    /// Extra key/value metadata (UI/ops only).
    pub metadata: HashMap<String, String>,
}

impl PolicyFile {
    /// Construct a new policy file with deterministic tick for UI/ops.
    pub fn new(name: &str, version: &str, author: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            created_tick: dt::tick().1, // UI/ops metadata only
            author: author.to_string(),
            description: None,
            conditions: Vec::new(),
            roles: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn add_condition(&mut self, condition: PolicyCondition) -> &mut Self {
        self.conditions.push(condition);
        self
    }

    pub fn add_role(&mut self, role: PolicyRole) -> &mut Self {
        self.roles.push(role);
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

    /// Derive the CTPA anchor for this file.
    pub fn generate_anchor(&self) -> Result<PolicyAnchor, DsmError> {
        PolicyAnchor::from_policy(self)
    }

    /// Canonical deterministic serialization for hashing (binary).
    ///
    /// Design:
    /// - **Excluded**: `created_tick`, `metadata`, `description`, `name`, `version`
    ///   (UI/ops only; avoid non-semantic drift).
    /// - **Included**: `author`, `conditions`, `roles` (semantic).
    /// - Set-like fields are **sorted** (regions, identities, operations, role perms).
    /// - Output is a compact binary layout (no text encodings).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DsmError> {
        let proto: crate::types::proto::CanonicalPolicy = self.into();
        let mut buf = Vec::new();
        proto
            .encode(&mut buf)
            .map_err(|e| DsmError::SerializationError(format!("Protobuf encode failed: {}", e)))?;
        Ok(buf)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DsmError> {
        let proto: crate::types::proto::StoredPolicy = self.into();
        let mut buf = Vec::new();
        proto
            .encode(&mut buf)
            .map_err(|e| DsmError::SerializationError(format!("Protobuf encode failed: {}", e)))?;
        Ok(buf)
    }

    /// Deserialize from canonical binary format (CanonicalPolicy proto).
    ///
    /// The canonical encoding contains only the semantic fields: `author`,
    /// `conditions`, and `roles`. Non-semantic fields (`name`, `version`,
    /// `created_tick`, `description`, `metadata`) are set to defaults.
    /// This is used when fetching policies from storage nodes, which store
    /// canonical bytes for content-addressed integrity.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let proto = crate::types::proto::CanonicalPolicy::decode(bytes).map_err(|e| {
            DsmError::SerializationError(format!("CanonicalPolicy decode failed: {}", e))
        })?;

        let conditions = proto
            .conditions
            .iter()
            .map(|c| c.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let roles = proto.roles.iter().map(|r| r.into()).collect();

        Ok(Self {
            name: String::new(),
            version: String::new(),
            created_tick: 0,
            author: proto.author,
            description: None,
            conditions,
            roles,
            metadata: std::collections::HashMap::new(),
        })
    }

    /// Deserialize from full StoredPolicy binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let proto = crate::types::proto::StoredPolicy::decode(bytes)
            .map_err(|e| DsmError::SerializationError(format!("Protobuf decode failed: {}", e)))?;

        let conditions = proto
            .conditions
            .iter()
            .map(|c| c.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let roles = proto.roles.iter().map(|r| r.into()).collect();

        Ok(Self {
            name: proto.name,
            version: proto.revision,
            created_tick: proto.created_tick,
            author: proto.author,
            description: if proto.description.is_empty() {
                None
            } else {
                Some(proto.description)
            },
            conditions,
            roles,
            metadata: proto.metadata,
        })
    }
}

impl From<&PolicyFile> for crate::types::proto::StoredPolicy {
    fn from(file: &PolicyFile) -> Self {
        Self {
            name: file.name.clone(),
            revision: file.version.clone(),
            created_tick: file.created_tick,
            author: file.author.clone(),
            description: file.description.clone().unwrap_or_default(),
            conditions: file.conditions.iter().map(|c| c.into()).collect(),
            roles: file.roles.iter().map(|r| r.into()).collect(),
            metadata: file.metadata.clone(),
        }
    }
}

impl From<&PolicyFile> for crate::types::proto::CanonicalPolicy {
    fn from(file: &PolicyFile) -> Self {
        Self {
            author: file.author.clone(),
            conditions: file.conditions.iter().map(|c| c.into()).collect(),
            roles: file.roles.iter().map(|r| r.into()).collect(),
        }
    }
}

impl From<&PolicyCondition> for crate::types::proto::PolicyConditionProto {
    fn from(cond: &PolicyCondition) -> Self {
        use crate::types::proto::policy_condition_proto::Kind;
        use crate::types::proto::*;

        let kind = match cond {
            PolicyCondition::IdentityConstraint {
                allowed_identities,
                allow_derived,
            } => {
                let mut sorted = allowed_identities.clone();
                sorted.sort();
                Kind::IdentityConstraint(IdentityConstraintProto {
                    allowed_identities: sorted,
                    allow_derived: *allow_derived,
                })
            }
            PolicyCondition::VaultEnforcement { condition } => {
                Kind::VaultEnforcement(VaultEnforcementProto {
                    condition: Some(condition.into()),
                })
            }
            PolicyCondition::OperationRestriction { allowed_operations } => {
                let mut sorted = allowed_operations.clone();
                sorted.sort();
                Kind::OperationRestriction(OperationRestrictionProto {
                    allowed_operations: sorted,
                })
            }
            PolicyCondition::LogicalTimeConstraint { min_tick, max_tick } => {
                Kind::LogicalTimeConstraint(LogicalTimeConstraintProto {
                    min_tick: *min_tick,
                    max_tick: *max_tick,
                })
            }
            PolicyCondition::EmissionsSchedule {
                total_supply,
                shard_depth,
                schedule_steps,
                initial_step_emissions,
                initial_step_amount,
            } => Kind::EmissionsSchedule(EmissionsScheduleProto {
                total_supply: *total_supply,
                shard_depth: *shard_depth as u32,
                schedule_steps: *schedule_steps as u32,
                initial_step_emissions: *initial_step_emissions,
                initial_step_amount: *initial_step_amount,
            }),
            PolicyCondition::CreditBundlePolicy {
                bundle_size,
                debit_rule,
                refill_rule,
            } => Kind::CreditBundlePolicy(CreditBundlePolicyProto {
                bundle_size: *bundle_size,
                debit_rule: debit_rule.clone(),
                refill_rule: refill_rule.clone(),
            }),
            PolicyCondition::Custom {
                constraint_type,
                parameters,
            } => {
                let mut kv: Vec<ParamKv> = parameters
                    .iter()
                    .map(|(k, v)| ParamKv {
                        key: k.clone(),
                        value: v.clone(),
                    })
                    .collect();
                kv.sort_by(|a, b| a.key.cmp(&b.key));
                Kind::Custom(CustomConstraintProto {
                    constraint_type: constraint_type.clone(),
                    parameters: parameters.clone(),
                    parameters_kv: kv,
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
            Some(Kind::IdentityConstraint(p)) => Ok(PolicyCondition::IdentityConstraint {
                allowed_identities: p.allowed_identities.clone(),
                allow_derived: p.allow_derived,
            }),
            Some(Kind::VaultEnforcement(p)) => Ok(PolicyCondition::VaultEnforcement {
                condition: p
                    .condition
                    .as_ref()
                    .ok_or(DsmError::SerializationError(
                        "Missing vault condition".into(),
                    ))?
                    .try_into()?,
            }),
            Some(Kind::OperationRestriction(p)) => Ok(PolicyCondition::OperationRestriction {
                allowed_operations: p.allowed_operations.clone(),
            }),
            Some(Kind::LogicalTimeConstraint(p)) => Ok(PolicyCondition::LogicalTimeConstraint {
                min_tick: p.min_tick,
                max_tick: p.max_tick,
            }),
            Some(Kind::EmissionsSchedule(p)) => Ok(PolicyCondition::EmissionsSchedule {
                total_supply: p.total_supply,
                shard_depth: p.shard_depth as u8,
                schedule_steps: p.schedule_steps as u8,
                initial_step_emissions: p.initial_step_emissions,
                initial_step_amount: p.initial_step_amount,
            }),
            Some(Kind::CreditBundlePolicy(p)) => Ok(PolicyCondition::CreditBundlePolicy {
                bundle_size: p.bundle_size,
                debit_rule: p.debit_rule.clone(),
                refill_rule: p.refill_rule.clone(),
            }),
            Some(Kind::Custom(p)) => Ok(PolicyCondition::Custom {
                constraint_type: p.constraint_type.clone(),
                parameters: if !p.parameters_kv.is_empty() {
                    p.parameters_kv
                        .iter()
                        .map(|kv| (kv.key.clone(), kv.value.clone()))
                        .collect()
                } else {
                    p.parameters.clone()
                },
            }),
            Some(Kind::BitcoinTapConstraint(p)) => Ok(PolicyCondition::BitcoinTapConstraint {
                max_successor_depth: p.max_successor_depth,
                min_vault_balance_sats: p.min_vault_balance_sats,
                dust_floor_sats: p.dust_floor_sats,
                min_confirmations: p.min_confirmations,
            }),
            None => Err(DsmError::SerializationError(
                "Missing policy condition kind".into(),
            )),
        }
    }
}

impl From<&VaultCondition> for crate::types::proto::VaultConditionProto {
    fn from(cond: &VaultCondition) -> Self {
        use crate::types::proto::vault_condition_proto::Kind;
        let kind = match cond {
            VaultCondition::Hash(h) => Kind::Hash(h.clone()),
            VaultCondition::MinimumBalance(b) => Kind::MinimumBalance(*b),
            VaultCondition::VaultType(t) => Kind::VaultType(t.clone()),
            VaultCondition::SmartPolicy(p) => Kind::SmartPolicy(p.clone()),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<&crate::types::proto::VaultConditionProto> for VaultCondition {
    type Error = DsmError;
    fn try_from(proto: &crate::types::proto::VaultConditionProto) -> Result<Self, Self::Error> {
        use crate::types::proto::vault_condition_proto::Kind;
        match &proto.kind {
            Some(Kind::Hash(h)) => Ok(VaultCondition::Hash(h.clone())),
            Some(Kind::MinimumBalance(b)) => Ok(VaultCondition::MinimumBalance(*b)),
            Some(Kind::VaultType(t)) => Ok(VaultCondition::VaultType(t.clone())),
            Some(Kind::SmartPolicy(p)) => Ok(VaultCondition::SmartPolicy(p.clone())),
            None => Err(DsmError::SerializationError(
                "Missing vault condition kind".into(),
            )),
        }
    }
}

impl From<&PolicyRole> for crate::types::proto::PolicyRoleProto {
    fn from(role: &PolicyRole) -> Self {
        let mut sorted_permissions = role.permissions.clone();
        sorted_permissions.sort();
        Self {
            id: role.id.clone(),
            name: role.name.clone(),
            permissions: sorted_permissions,
        }
    }
}

impl From<&crate::types::proto::PolicyRoleProto> for PolicyRole {
    fn from(proto: &crate::types::proto::PolicyRoleProto) -> Self {
        Self {
            id: proto.id.clone(),
            name: proto.name.clone(),
            permissions: proto.permissions.clone(),
        }
    }
}

/// In-memory, runtime policy bundle + verification state.
#[derive(Debug, Clone)]
pub struct TokenPolicy {
    pub file: PolicyFile,
    pub anchor: PolicyAnchor,
    pub verified: bool,
    pub last_verified: u64, // deterministic tick, UI/ops only
}

impl TokenPolicy {
    pub fn new(file: PolicyFile) -> Result<Self, DsmError> {
        let anchor = file.generate_anchor()?;
        let now = dt::tick().1;
        Ok(Self {
            file,
            anchor,
            verified: false,
            last_verified: now,
        })
    }

    pub fn mark_verified(&mut self) {
        self.verified = true;
        self.last_verified = dt::tick().1;
    }

    /// No time-based conditions are supported.
    pub fn is_condition_satisfied(&self, _condition: &PolicyCondition) -> bool {
        true
    }

    pub fn are_time_conditions_satisfied(&self) -> bool {
        true
    }
}

/// Audit record for policy verification operations.
#[derive(Debug, Clone)]
pub struct PolicyVerification {
    pub verification_type: VerificationType,
    pub parameters: HashMap<String, Vec<u8>>,
    pub tick: u64, // deterministic tick (UI/ops only)
    pub result: bool,
    pub message: Option<String>,
    pub proof: Option<Vec<u8>>,
}

impl PolicyVerification {
    pub fn new(verification_type: VerificationType) -> Self {
        Self {
            verification_type,
            parameters: HashMap::new(),
            tick: dt::tick().1,
            result: false,
            message: None,
            proof: None,
        }
    }

    pub fn success(mut self, message: Option<String>, proof: Option<Vec<u8>>) -> Self {
        self.result = true;
        self.message = message;
        self.proof = proof;
        self
    }

    pub fn failure(mut self, message: String) -> Self {
        self.result = false;
        self.message = Some(message);
        self
    }

    pub fn with_parameter(mut self, key: &str, value: Vec<u8>) -> Self {
        self.parameters.insert(key.to_string(), value);
        self
    }
}

/// Lightweight policy handle used by some SDK surfaces.
pub struct Policy {
    pub name: String,
    pub conditions: Vec<PolicyCondition>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_is_stable_and_ignores_created_tick() {
        let mut p1 = PolicyFile::new("Name", "v2", "authorX");
        p1.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into(), "mint".into()],
        });
        p1.roles.push(PolicyRole {
            id: "admin".into(),
            name: "Admin".into(),
            permissions: vec![],
        });

        // Clone and perturb UI/ops fields that must not affect canonical hash
        let mut p2 = p1.clone();
        p2.created_tick = p1.created_tick + 1_000_000;
        p2.metadata.insert("note".into(), "hello".into());
        p2.description = Some("desc".into());
        p2.name = "Other".into();
        p2.version = "v2".into();

        let a1 = p1.generate_anchor().unwrap();
        let a2 = p2.generate_anchor().unwrap();
        assert_eq!(a1.0, a2.0, "UI/ops fields must not affect anchor");
    }

    #[test]
    fn sets_are_sorted_in_canonical_bytes() {
        let mut p1 = PolicyFile::new("n", "v", "a");
        p1.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into(), "mint".into(), "burn".into()],
        });
        let b1 = p1.canonical_bytes().unwrap();

        let mut p2 = PolicyFile::new("n", "v", "a");
        p2.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["burn".into(), "transfer".into(), "mint".into()],
        });
        let b2 = p2.canonical_bytes().unwrap();

        assert_eq!(blake3::hash(&b1).as_bytes(), blake3::hash(&b2).as_bytes());
    }

    #[test]
    fn anchor_from_bytes_as_bytes_roundtrip() {
        let raw = [0xABu8; 32];
        let anchor = PolicyAnchor::from_bytes(raw);
        assert_eq!(*anchor.as_bytes(), raw);
    }

    #[test]
    fn anchor_display_base32_roundtrip() {
        let raw = [0x42u8; 32];
        let anchor = PolicyAnchor::from_bytes(raw);
        let encoded = anchor.to_display_base32();
        let decoded = PolicyAnchor::from_policy_uri(&encoded).unwrap();
        assert_eq!(anchor.0, decoded.0);
    }

    #[test]
    fn anchor_from_policy_uri_invalid_string() {
        let result = PolicyAnchor::from_policy_uri("!!invalid!!");
        assert!(result.is_err());
    }

    #[test]
    fn anchor_from_policy_uri_wrong_length() {
        let short = base32::encode(base32::Alphabet::Crockford, &[1, 2, 3]);
        let result = PolicyAnchor::from_policy_uri(&short);
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
        pf.add_condition(PolicyCondition::LogicalTimeConstraint {
            min_tick: 0,
            max_tick: 100,
        });
        pf.add_role(PolicyRole {
            id: "r1".into(),
            name: "Role1".into(),
            permissions: vec!["read".into()],
        });

        assert_eq!(pf.description.as_deref(), Some("A test policy"));
        assert_eq!(pf.metadata.get("key1").unwrap(), "val1");
        assert_eq!(pf.conditions.len(), 1);
        assert_eq!(pf.roles.len(), 1);
    }

    #[test]
    fn policy_file_to_bytes_from_bytes_roundtrip() {
        let mut pf = PolicyFile::new("roundtrip", "v2", "bob");
        pf.with_description("desc");
        pf.add_metadata("k", "v");
        pf.add_condition(PolicyCondition::IdentityConstraint {
            allowed_identities: vec!["id1".into()],
            allow_derived: true,
        });
        pf.add_role(PolicyRole {
            id: "admin".into(),
            name: "Admin".into(),
            permissions: vec!["write".into(), "read".into()],
        });

        let bytes = pf.to_bytes().unwrap();
        let restored = PolicyFile::from_bytes(&bytes).unwrap();
        assert_eq!(restored.name, "roundtrip");
        assert_eq!(restored.version, "v2");
        assert_eq!(restored.author, "bob");
        assert_eq!(restored.description.as_deref(), Some("desc"));
        assert_eq!(restored.conditions.len(), 1);
        assert_eq!(restored.roles.len(), 1);
        assert_eq!(restored.roles[0].id, "admin");
    }

    #[test]
    fn policy_file_canonical_bytes_from_canonical_bytes_roundtrip() {
        let mut pf = PolicyFile::new("name", "v1", "carol");
        pf.add_condition(PolicyCondition::EmissionsSchedule {
            total_supply: 1_000_000,
            shard_depth: 4,
            schedule_steps: 10,
            initial_step_emissions: 500,
            initial_step_amount: 100,
        });
        let canonical = pf.canonical_bytes().unwrap();
        let restored = PolicyFile::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(restored.author, "carol");
        assert_eq!(restored.conditions.len(), 1);
        assert!(restored.name.is_empty(), "name excluded from canonical");
    }

    #[test]
    fn token_policy_new_and_mark_verified() {
        let pf = PolicyFile::new("tp", "v1", "auth");
        let mut tp = TokenPolicy::new(pf).unwrap();
        assert!(!tp.verified);
        tp.mark_verified();
        assert!(tp.verified);
    }

    #[test]
    fn token_policy_conditions_always_satisfied() {
        let pf = PolicyFile::new("tp", "v1", "auth");
        let tp = TokenPolicy::new(pf).unwrap();
        let cond = PolicyCondition::LogicalTimeConstraint {
            min_tick: 0,
            max_tick: 100,
        };
        assert!(tp.is_condition_satisfied(&cond));
        assert!(tp.are_time_conditions_satisfied());
    }

    #[test]
    fn policy_verification_success_and_failure() {
        let pv = PolicyVerification::new(VerificationType::Standard);
        assert!(!pv.result);
        assert!(pv.message.is_none());

        let success = PolicyVerification::new(VerificationType::Standard)
            .with_parameter("pk", vec![1, 2, 3])
            .success(Some("ok".into()), Some(vec![9]));
        assert!(success.result);
        assert_eq!(success.message.as_deref(), Some("ok"));
        assert_eq!(success.proof, Some(vec![9]));
        assert_eq!(success.parameters.get("pk").unwrap(), &vec![1, 2, 3]);

        let fail = PolicyVerification::new(VerificationType::Standard).failure("bad".into());
        assert!(!fail.result);
        assert_eq!(fail.message.as_deref(), Some("bad"));
    }

    #[test]
    fn vault_condition_proto_roundtrip() {
        let conditions = vec![
            VaultCondition::Hash(vec![1, 2, 3]),
            VaultCondition::MinimumBalance(1000),
            VaultCondition::VaultType("standard".into()),
            VaultCondition::SmartPolicy(vec![0xDE, 0xAD]),
        ];
        for cond in &conditions {
            let proto: crate::types::proto::VaultConditionProto = cond.into();
            let restored = VaultCondition::try_from(&proto).unwrap();
            assert_eq!(&restored, cond);
        }
    }

    #[test]
    fn different_authors_produce_different_anchors() {
        let p1 = PolicyFile::new("n", "v", "alice");
        let p2 = PolicyFile::new("n", "v", "bob");
        let a1 = p1.generate_anchor().unwrap();
        let a2 = p2.generate_anchor().unwrap();
        assert_ne!(a1.0, a2.0);
    }
}
