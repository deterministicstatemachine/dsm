// SPDX-License-Identifier: MIT OR Apache-2.0

//! src/core/token/policy/policy_enforcement.rs
//! Policy Enforcement Engine (protobuf-only; binary comparisons; no hex/base64/JSON).
//!
//! Enforces token policy constraints (CTPA).
//! Determinism rules:
//! - No time of any kind.
//! - No alternate paths.

use std::collections::HashMap;

use crate::types::{
    error::DsmError,
    policy_types::{PolicyCondition, PolicyRole, TokenPolicy},
};

/// Minimal error type for policy enforcement failures that are not simply allow/deny decisions
#[derive(Debug)]
pub struct EnforcementError {
    pub message: String,
}

impl core::fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EnforcementError {}

/// Result of policy enforcement
#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub allowed: bool,
    pub reason: String,
    pub conditions: Vec<String>,
    pub context: HashMap<String, String>,
}

impl EnforcementResult {
    #[inline]
    pub fn allowed(reason: &str) -> Self {
        Self {
            allowed: true,
            reason: reason.to_string(),
            conditions: Vec::new(),
            context: HashMap::new(),
        }
    }

    #[inline]
    pub fn denied(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
            conditions: Vec::new(),
            context: HashMap::new(),
        }
    }

    #[inline]
    pub fn with_context(mut self, k: &str, v: &str) -> Self {
        self.context.insert(k.to_string(), v.to_string());
        self
    }

    #[inline]
    pub fn is_success(&self) -> bool {
        self.allowed
    }
}

/// Identity context (local-only; deterministic)
#[derive(Debug, Clone)]
pub struct IdentityContext {
    pub id: String,
    pub assigned_roles: Option<Vec<String>>,
    pub derivation_path: Option<Vec<String>>,
}

/// Policy enforcement context (constructed from operation + caller-provided binary data)
#[derive(Debug, Clone)]
pub struct EnforcementContext {
    pub operation_type: String,
    pub identity: Option<IdentityContext>,
    pub region: Option<String>,
    pub data: HashMap<String, Vec<u8>>,
}

impl EnforcementContext {
    pub fn new(operation_type: &str) -> Self {
        Self {
            operation_type: operation_type.to_string(),
            identity: None,
            region: None,
            data: HashMap::new(),
        }
    }

    pub fn with_identity(mut self, identity: &str) -> Self {
        self.identity = Some(IdentityContext {
            id: identity.to_string(),
            assigned_roles: None,
            derivation_path: None,
        });
        self
    }

    pub fn with_region(mut self, region: &str) -> Self {
        self.region = Some(region.to_string());
        self
    }

    pub fn with_data(mut self, key: &str, value: Vec<u8>) -> Self {
        self.data.insert(key.to_string(), value);
        self
    }

    /// The operation's amount, derived by the SDK from the operation itself:
    /// `amount_u64`, exactly 8 bytes little-endian.
    pub fn amount_witness(&self) -> Option<u64> {
        let bytes = self.data.get("amount_u64")?;
        <[u8; 8]>::try_from(bytes.as_slice())
            .ok()
            .map(u64::from_le_bytes)
    }
}

/// Policy enforcement engine
#[derive(Debug, Default)]
pub struct PolicyEnforcer;

/// Canonical preimage a burn or creation authorisation signs.
///
/// SINGLE definition, used by both the signer and the verifier. If each built
/// its own, a drift between them would either reject honest operations or —
/// far worse — accept a signature over a different message than the one being
/// executed.
///
/// Binds the asset, the operation, the amount and the authorising identity, so
/// a signature cannot be replayed onto a different asset, a different amount,
/// or the opposite operation.
pub fn token_authorization_preimage(
    policy_commit: &[u8; 32],
    op: &str,
    token_id: &[u8],
    amount: u64,
    authorized_by: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"dsm/token-auth/v1\0");
    msg.extend_from_slice(op.as_bytes());
    msg.push(0);
    msg.extend_from_slice(policy_commit);
    msg.extend_from_slice(&(token_id.len() as u32).to_le_bytes());
    msg.extend_from_slice(token_id);
    msg.extend_from_slice(&amount.to_le_bytes());
    msg.extend_from_slice(&(authorized_by.len() as u32).to_le_bytes());
    msg.extend_from_slice(authorized_by);
    crate::crypto::blake3::token_domain_hash(policy_commit, op, &msg)
        .as_bytes()
        .to_vec()
}

/// Context keys carrying the burn or creation authorisation witness.
pub mod witness_keys {
    /// Concatenated `(u32 pk_len, pk, u32 sig_len, sig)` records.
    pub const AUTHORIZATIONS: &str = "token_authorizations";
    pub const POLICY_COMMIT: &str = "policy_commit";
    pub const TOKEN_ID: &str = "token_id";
    pub const AMOUNT: &str = "amount_le";
    pub const AUTHORIZED_BY: &str = "authorized_by";
    /// Circulating supply DERIVED from canonical state (never a cached count).
    pub const CIRCULATING: &str = "circulating_le";
}

/// Split the concatenated witness into `(pk, sig)` pairs.
fn parse_authorizations(blob: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= blob.len() {
        let pk_len =
            u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
        off += 4;
        if off + pk_len + 4 > blob.len() {
            return out;
        }
        let pk = blob[off..off + pk_len].to_vec();
        off += pk_len;
        let sig_len =
            u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
        off += 4;
        if off + sig_len > blob.len() {
            return out;
        }
        let sig = blob[off..off + sig_len].to_vec();
        off += sig_len;
        out.push((pk, sig));
    }
    out
}

impl PolicyEnforcer {
    pub fn new() -> Self {
        Self
    }

    pub async fn enforce_policy(
        &self,
        policy: &TokenPolicy,
        operation_type: &str,
        context_data: &HashMap<String, Vec<u8>>,
    ) -> Result<EnforcementResult, DsmError> {
        let mut ctx = EnforcementContext::new(operation_type);

        for (k, v) in context_data {
            ctx = ctx.with_data(k, v.clone());
        }

        if let Some(id_bytes) = context_data.get("identity") {
            if let Ok(id) = String::from_utf8(id_bytes.clone()) {
                ctx = ctx.with_identity(&id);
            }
        }
        if let Some(region_bytes) = context_data.get("region") {
            if let Ok(region) = String::from_utf8(region_bytes.clone()) {
                ctx = ctx.with_region(&region);
            }
        }

        for condition in &policy.file.conditions {
            let res = self.check_condition(condition, &ctx).await?;
            if !res.allowed {
                return Ok(res);
            }
        }

        if !policy.file.roles.is_empty() {
            let ok = self
                .check_role_permissions(&policy.file.roles, &ctx)
                .await?;
            if !ok {
                return Ok(EnforcementResult::denied(
                    "Operation not permitted by role-based access control",
                ));
            }
        }

        Ok(EnforcementResult::allowed(
            "All policy conditions satisfied",
        ))
    }

    /// Evaluate one condition. Exposed so the authority/supply guarantees can
    /// be asserted directly rather than only through a full policy round trip
    /// — these are security properties and deserve pointed tests.
    pub async fn check_condition(
        &self,
        condition: &PolicyCondition,
        ctx: &EnforcementContext,
    ) -> Result<EnforcementResult, DsmError> {
        match condition {
            PolicyCondition::IdentityConstraint {
                allowed_identities,
                allow_derived,
            } => {
                if let Some(ref id) = ctx.identity {
                    if allowed_identities.iter().any(|s| s == &id.id) {
                        return Ok(EnforcementResult::allowed("Identity authorized"));
                    }
                    if *allow_derived && self.is_derived_identity(id, allowed_identities).await {
                        return Ok(EnforcementResult::allowed("Derived identity authorized"));
                    }
                    Ok(EnforcementResult::denied("Identity not authorized"))
                } else {
                    Ok(EnforcementResult::denied("No identity provided"))
                }
            }

            PolicyCondition::OperationRestriction { allowed_operations } => {
                // Issue #183 Finding 3 fix: match the case-sensitive canonical
                // encoding. `CanonicalPolicy` sorts `allowed_operations` with
                // a case-sensitive `Vec::sort()`, so `["transfer"]` and
                // `["Transfer"]` are distinct policy_commits. Enforcement
                // previously used `eq_ignore_ascii_case`, which let
                // `"Transfer"` (uppercase) pass under a policy committed to
                // `"transfer"` only — semantic gap. Match exactly.
                let allowed = allowed_operations
                    .iter()
                    .any(|op| op == &ctx.operation_type);
                if allowed {
                    Ok(EnforcementResult::allowed("Operation permitted"))
                } else {
                    Ok(EnforcementResult::denied("Operation not permitted"))
                }
            }

            PolicyCondition::TokenAuthority { signers, threshold } => {
                // Gates burn and create_token, which authorize through the
                // embedded `token_authorization_preimage` witness. There is
                // no minting after genesis (SoFi §48). Other operations are
                // governed by their own conditions.
                if !matches!(ctx.operation_type.as_str(), "burn" | "create_token") {
                    return Ok(EnforcementResult::allowed(
                        "TokenAuthority does not gate this operation",
                    ));
                }

                let Some(blob) = ctx.data.get(witness_keys::AUTHORIZATIONS) else {
                    return Ok(EnforcementResult::denied(
                        "No burn or creation authorization presented",
                    ));
                };
                let (Some(pc), Some(token_id), Some(amount_le), Some(authorized_by)) = (
                    ctx.data.get(witness_keys::POLICY_COMMIT),
                    ctx.data.get(witness_keys::TOKEN_ID),
                    ctx.data.get(witness_keys::AMOUNT),
                    ctx.data.get(witness_keys::AUTHORIZED_BY),
                ) else {
                    return Ok(EnforcementResult::denied(
                        "Authorization context incomplete",
                    ));
                };
                let Ok(policy_commit) = <[u8; 32]>::try_from(pc.as_slice()) else {
                    return Ok(EnforcementResult::denied(
                        "Authorization policy_commit malformed",
                    ));
                };
                let Ok(amount_bytes) = <[u8; 8]>::try_from(amount_le.as_slice()) else {
                    return Ok(EnforcementResult::denied("Authorization amount malformed"));
                };
                let amount = u64::from_le_bytes(amount_bytes);

                // The verifier builds the message ITSELF from the operation
                // being executed. Accepting a caller-supplied preimage would
                // let an attacker sign one message and execute another.
                let expected = token_authorization_preimage(
                    &policy_commit,
                    &ctx.operation_type,
                    token_id,
                    amount,
                    authorized_by,
                );

                // Count DISTINCT policy signers, so one key cannot satisfy a
                // k>1 threshold by signing repeatedly.
                let mut satisfied: Vec<usize> = Vec::new();
                for (pk, sig) in parse_authorizations(blob) {
                    // Key comes from the POLICY, never from the proof: match
                    // first, verify second.
                    let Some(idx) = signers.iter().position(|s| *s == pk) else {
                        continue;
                    };
                    if satisfied.contains(&idx) {
                        continue;
                    }
                    if matches!(
                        crate::crypto::sphincs::sphincs_verify(&pk, &expected, &sig),
                        Ok(true)
                    ) {
                        satisfied.push(idx);
                    }
                }

                if satisfied.len() as u32 >= *threshold {
                    Ok(EnforcementResult::allowed(
                        "Burn or creation authority threshold satisfied",
                    ))
                } else {
                    Ok(EnforcementResult::denied(
                        "Burn or creation authority threshold not satisfied",
                    ))
                }
            }

            PolicyCondition::SupplyCap { max_supply } => {
                // Only creation brings supply into being: nothing is minted
                // after genesis (SoFi §48).
                if ctx.operation_type != "create_token" {
                    return Ok(EnforcementResult::allowed(
                        "SupplyCap does not gate this operation",
                    ));
                }
                let (Some(amount_le), Some(circ_le)) = (
                    ctx.data.get(witness_keys::AMOUNT),
                    ctx.data.get(witness_keys::CIRCULATING),
                ) else {
                    // Fail closed: without the derived circulating supply the
                    // cap cannot be evaluated, and guessing would enforce it
                    // against the wrong number.
                    return Ok(EnforcementResult::denied(
                        "Supply cap cannot be evaluated without circulating supply",
                    ));
                };
                let (Ok(a), Ok(c)) = (
                    <[u8; 8]>::try_from(amount_le.as_slice()),
                    <[u8; 8]>::try_from(circ_le.as_slice()),
                ) else {
                    return Ok(EnforcementResult::denied("Supply context malformed"));
                };
                let amount = u64::from_le_bytes(a) as u128;
                let circulating = u64::from_le_bytes(c) as u128;
                if circulating.saturating_add(amount) <= *max_supply {
                    Ok(EnforcementResult::allowed("Within supply cap"))
                } else {
                    Ok(EnforcementResult::denied(
                        "Creation would exceed the token's maximum supply",
                    ))
                }
            }

            PolicyCondition::Custom {
                constraint_type,
                parameters,
            } => {
                self.check_custom_constraint(constraint_type, parameters, ctx)
                    .await
            }

            PolicyCondition::EmissionsSchedule { .. } => {
                // Configuration-only; does not deny operations directly.
                Ok(EnforcementResult::allowed("Emissions schedule parameter"))
            }

            PolicyCondition::CreditBundlePolicy { .. } => {
                // Configuration-only; does not deny operations directly.
                Ok(EnforcementResult::allowed("Credit bundle policy parameter"))
            }

            PolicyCondition::BitcoinTapConstraint { .. } => {
                // Configuration-only; tap safety is enforced at vault creation
                // and fractional exit time, not during generic policy enforcement.
                Ok(EnforcementResult::allowed(
                    "Bitcoin tap constraint parameter",
                ))
            }
        }
    }

    async fn check_custom_constraint(
        &self,
        constraint_type: &str,
        parameters: &HashMap<String, String>,
        ctx: &EnforcementContext,
    ) -> Result<EnforcementResult, DsmError> {
        match constraint_type {
            "amount_limit" => {
                let max_amount = parameters
                    .get("max_amount")
                    .and_then(|s| s.parse::<u64>().ok());

                let Some(max_amount) = max_amount else {
                    return Ok(EnforcementResult::denied("Missing/invalid max_amount"));
                };

                match ctx.amount_witness() {
                    Some(v) if v <= max_amount => {
                        Ok(EnforcementResult::allowed("Amount limit satisfied"))
                    }
                    Some(_) => Ok(EnforcementResult::denied("Amount exceeds limit")),
                    None => Ok(EnforcementResult::denied("No amount witness provided")),
                }
            }

            _ => {
                // Production-safe default: unknown custom constraint DENIES unless explicitly waived.
                Ok(EnforcementResult::denied("Unknown custom constraint"))
            }
        }
    }

    async fn check_role_permissions(
        &self,
        roles: &[PolicyRole],
        ctx: &EnforcementContext,
    ) -> Result<bool, DsmError> {
        let Some(identity) = ctx.identity.as_ref() else {
            return Ok(false);
        };

        for role in roles {
            if self.user_has_role(identity, &role.id).await {
                // Issue #183 Finding 3 fix: role-permission match must use
                // case-sensitive comparison to align with the case-sensitive
                // canonical sort of role permissions in `CanonicalPolicy`.
                let permitted = role.permissions.iter().any(|op| op == &ctx.operation_type);
                if permitted {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    async fn user_has_role(&self, id: &IdentityContext, role_id: &str) -> bool {
        id.assigned_roles
            .as_ref()
            .map(|rs| rs.iter().any(|r| r == role_id))
            .unwrap_or(false)
    }

    async fn is_derived_identity(&self, id: &IdentityContext, allowed: &[String]) -> bool {
        if allowed.is_empty() {
            return false;
        }
        match &id.derivation_path {
            Some(path) if !path.is_empty() => {
                if let Some(tail) = path.last() {
                    allowed.iter().any(|a| a == tail)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::policy_types::{PolicyCondition, PolicyFile, TokenPolicy};

    #[tokio::test]
    async fn identity_constraint_denies() -> Result<(), Box<dyn std::error::Error>> {
        let enforcer = PolicyEnforcer::new();

        let mut pf = PolicyFile::new("ID", "1.0.0", "a");
        pf.add_condition(PolicyCondition::IdentityConstraint {
            allowed_identities: vec!["allowed_user".into()],
            allow_derived: false,
        });
        let pol = TokenPolicy::new(pf)?;

        let mut ctx = HashMap::new();
        ctx.insert("identity".into(), b"unauthorized_user".to_vec());

        let res = enforcer.enforce_policy(&pol, "transfer", &ctx).await?;
        assert!(!res.allowed);
        Ok(())
    }

    // ────────────────────────────────────────────────────────────────────────
    // Issue #183 Finding 3 regression — OperationRestriction must be
    // case-sensitive so enforcement aligns with the case-sensitive canonical
    // sort that goes into the policy_commit anchor.
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn operation_restriction_is_case_sensitive() -> Result<(), Box<dyn std::error::Error>> {
        let enforcer = PolicyEnforcer::new();

        let mut pf = PolicyFile::new("OP", "1.0.0", "a");
        pf.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["transfer".into()],
        });
        let pol = TokenPolicy::new(pf)?;

        let ctx = HashMap::new();

        // Exact-case match — must allow.
        let res = enforcer.enforce_policy(&pol, "transfer", &ctx).await?;
        assert!(res.allowed, "exact-case operation must be allowed");

        // Uppercase variant — must reject (canonical anchor sees only
        // "transfer"; allowing "Transfer" would diverge enforcement from
        // the anchored permission set).
        let res = enforcer.enforce_policy(&pol, "Transfer", &ctx).await?;
        assert!(
            !res.allowed,
            "uppercase \"Transfer\" must NOT match a policy committed to \"transfer\""
        );

        // Mixed case — must reject.
        let res = enforcer.enforce_policy(&pol, "TraNsFeR", &ctx).await?;
        assert!(
            !res.allowed,
            "mixed-case \"TraNsFeR\" must NOT match a policy committed to \"transfer\""
        );

        Ok(())
    }
}
