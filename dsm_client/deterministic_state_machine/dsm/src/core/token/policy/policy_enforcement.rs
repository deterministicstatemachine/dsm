//! src/core/token/policy/policy_enforcement.rs
//! Policy Enforcement Engine (protobuf-only; binary comparisons; no hex/base64/JSON).
//!
//! Enforces token policy constraints (CTPA).
//! Determinism rules:
//! - No wall-clock.
//! - Require an explicit tick witness from context_data under key "tick" (u64 LE).
//! - No alternate paths.

use std::collections::HashMap;
use std::sync::Arc;

use prost::Message;

use crate::types::{
    error::DsmError,
    policy_types::{PolicyCondition, PolicyRole, TokenPolicy, VaultCondition},
};
use crate::verification::proof_primitives::{
    amount_witness_u64, rate_limit_witness_u64, smart_policy_witness_present,
    tick_from_context_data, vault_balance_witness_u64,
};

use super::policy_cache::PolicyCache;

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
    pub tick: u64,
    pub context: HashMap<String, String>,
}

impl EnforcementResult {
    #[inline]
    pub fn allowed(reason: &str, tick: u64) -> Self {
        Self {
            allowed: true,
            reason: reason.to_string(),
            conditions: Vec::new(),
            tick,
            context: HashMap::new(),
        }
    }

    #[inline]
    pub fn denied(reason: &str, tick: u64) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
            conditions: Vec::new(),
            tick,
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

/// Vault enforcement context (optional structured fields)
#[derive(Debug, Clone)]
pub struct VaultEnforcementContext {
    pub vault_state: String,
    pub min_balance: Option<u64>,
    pub vault_type: Option<String>,
    pub custom_data: HashMap<String, String>,
}

/// Policy enforcement context (constructed from operation + caller-provided binary data)
#[derive(Debug, Clone)]
pub struct EnforcementContext {
    pub operation_type: String,
    pub tick: u64,
    pub identity: Option<IdentityContext>,
    pub region: Option<String>,
    pub data: HashMap<String, Vec<u8>>,
    pub vault_context: Option<VaultEnforcementContext>,
}

impl EnforcementContext {
    pub fn new(operation_type: &str, tick: u64) -> Self {
        Self {
            operation_type: operation_type.to_string(),
            tick,
            identity: None,
            region: None,
            data: HashMap::new(),
            vault_context: None,
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

    pub fn with_vault_context(mut self, v: VaultEnforcementContext) -> Self {
        self.vault_context = Some(v);
        self
    }

    /// Rate-limit witness lookup:
    /// key format: "rate_limit::`<op>`.last_k::`<N>`" -> u64 LE count
    pub fn rate_limit_witness(&self, op: &str, last_k: u64) -> Option<u64> {
        rate_limit_witness_u64(&self.data, op, last_k)
    }

    /// Amount witness:
    /// Require "amount_u64" -> u64 LE.
    pub fn amount_witness(&self) -> Option<u64> {
        amount_witness_u64(&self.data)
    }
}

/// Policy enforcement engine
#[derive(Debug)]
pub struct PolicyEnforcer {
    policy_cache: Arc<PolicyCache>,
}

impl PolicyEnforcer {
    pub fn new(policy_cache: Arc<PolicyCache>) -> Self {
        Self { policy_cache }
    }

    pub async fn enforce_policy(
        &self,
        policy: &TokenPolicy,
        operation_type: &str,
        context_data: &HashMap<String, Vec<u8>>,
    ) -> Result<EnforcementResult, DsmError> {
        // Advisory: check cache coherence by anchor; does not affect allow/deny.
        let _ = self.policy_cache.get_policy(&policy.anchor).await?;

        // Require explicit tick witness: key "tick" -> u64 LE.
        let tick = tick_from_context_data(context_data).ok_or_else(|| {
            DsmError::InvalidOperation("policy enforcement requires tick witness".to_string())
        })?;

        let mut ctx = EnforcementContext::new(operation_type, tick);

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
                    tick,
                ));
            }
        }

        Ok(EnforcementResult::allowed(
            "All policy conditions satisfied",
            tick,
        ))
    }

    async fn check_condition(
        &self,
        condition: &PolicyCondition,
        ctx: &EnforcementContext,
    ) -> Result<EnforcementResult, DsmError> {
        let tick = ctx.tick;

        match condition {
            PolicyCondition::IdentityConstraint {
                allowed_identities,
                allow_derived,
            } => {
                if let Some(ref id) = ctx.identity {
                    if allowed_identities.iter().any(|s| s == &id.id) {
                        return Ok(EnforcementResult::allowed("Identity authorized", tick));
                    }
                    if *allow_derived && self.is_derived_identity(id, allowed_identities).await {
                        return Ok(EnforcementResult::allowed(
                            "Derived identity authorized",
                            tick,
                        ));
                    }
                    Ok(EnforcementResult::denied("Identity not authorized", tick))
                } else {
                    Ok(EnforcementResult::denied("No identity provided", tick))
                }
            }

            PolicyCondition::VaultEnforcement { condition } => {
                self.check_vault_condition(condition, ctx).await
            }

            PolicyCondition::OperationRestriction { allowed_operations } => {
                let allowed = allowed_operations
                    .iter()
                    .any(|op| op.eq_ignore_ascii_case(&ctx.operation_type));
                if allowed {
                    Ok(EnforcementResult::allowed("Operation permitted", tick))
                } else {
                    Ok(EnforcementResult::denied("Operation not permitted", tick))
                }
            }

            PolicyCondition::LogicalTimeConstraint { min_tick, max_tick } => {
                if ctx.tick >= *min_tick && ctx.tick <= *max_tick {
                    Ok(EnforcementResult::allowed(
                        "Within allowed tick range",
                        tick,
                    ))
                } else {
                    Ok(EnforcementResult::denied(
                        "Outside allowed tick range",
                        tick,
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
                Ok(EnforcementResult::allowed(
                    "Emissions schedule parameter",
                    tick,
                ))
            }

            PolicyCondition::CreditBundlePolicy { .. } => {
                // Configuration-only; does not deny operations directly.
                Ok(EnforcementResult::allowed(
                    "Credit bundle policy parameter",
                    tick,
                ))
            }

            PolicyCondition::BitcoinTapConstraint { .. } => {
                // Configuration-only; tap safety is enforced at vault creation
                // and fractional exit time, not during generic policy enforcement.
                Ok(EnforcementResult::allowed(
                    "Bitcoin tap constraint parameter",
                    tick,
                ))
            }
        }
    }

    #[allow(clippy::unused_async)]
    async fn check_vault_condition(
        &self,
        cond: &VaultCondition,
        ctx: &EnforcementContext,
    ) -> Result<EnforcementResult, DsmError> {
        let tick = ctx.tick;

        match cond {
            VaultCondition::Hash(expected) => {
                if let Some(actual) = ctx.data.get("vault.hash") {
                    if actual.as_slice() == expected.as_slice() {
                        Ok(EnforcementResult::allowed("Vault hash satisfied", tick))
                    } else {
                        Ok(EnforcementResult::denied("Vault hash mismatch", tick))
                    }
                } else {
                    Ok(EnforcementResult::denied("Vault hash not provided", tick))
                }
            }

            VaultCondition::MinimumBalance(min_balance) => {
                // Prefer deterministic witness in ctx.data: "vault.balance_u64" -> u64 LE.
                let current = vault_balance_witness_u64(&ctx.data)
                    .or_else(|| ctx.vault_context.as_ref().and_then(|v| v.min_balance));

                match current {
                    Some(v) if v >= *min_balance => Ok(EnforcementResult::allowed(
                        "Minimum balance satisfied",
                        tick,
                    )),
                    Some(_) => Ok(EnforcementResult::denied(
                        "Insufficient vault balance",
                        tick,
                    )),
                    None => Ok(EnforcementResult::denied("No vault balance provided", tick)),
                }
            }

            VaultCondition::VaultType(required) => {
                let vt = ctx
                    .data
                    .get("vault.type")
                    .and_then(|b| String::from_utf8(b.clone()).ok())
                    .or_else(|| {
                        ctx.vault_context
                            .as_ref()
                            .and_then(|v| v.vault_type.clone())
                    });

                match vt {
                    Some(v) if v == *required => {
                        Ok(EnforcementResult::allowed("Vault type verified", tick))
                    }
                    Some(_) => Ok(EnforcementResult::denied("Vault type mismatch", tick)),
                    None => Ok(EnforcementResult::denied("No vault type provided", tick)),
                }
            }

            VaultCondition::SmartPolicy(bytes) => {
                // Deterministic rule:
                // - Policy must parse as SmartPolicy protobuf.
                // - Caller must provide a non-empty witness under "smart_policy_witness".
                // This prevents “parse-only allow” and keeps enforcement deterministic.
                let parse_ok = crate::types::proto::SmartPolicy::decode(bytes.as_slice()).is_ok();
                if !parse_ok {
                    return Ok(EnforcementResult::denied(
                        "Invalid SmartPolicy protobuf",
                        tick,
                    ));
                }

                let witness_ok = smart_policy_witness_present(&ctx.data);

                if witness_ok {
                    Ok(EnforcementResult::allowed(
                        "SmartPolicy witness satisfied",
                        tick,
                    ))
                } else {
                    Ok(EnforcementResult::denied(
                        "SmartPolicy witness missing",
                        tick,
                    ))
                }
            }
        }
    }

    async fn check_custom_constraint(
        &self,
        constraint_type: &str,
        parameters: &HashMap<String, String>,
        ctx: &EnforcementContext,
    ) -> Result<EnforcementResult, DsmError> {
        let tick = ctx.tick;

        match constraint_type {
            "rate_limit" => {
                let max_n = parameters
                    .get("max_n")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let last_k = parameters
                    .get("last_k")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                if max_n == 0 || last_k == 0 {
                    return Ok(EnforcementResult::denied(
                        "rate_limit not configured (max_n/last_k missing)",
                        tick,
                    ));
                }

                match ctx.rate_limit_witness(&ctx.operation_type, last_k) {
                    Some(count) if count >= max_n => {
                        Ok(EnforcementResult::denied("rate_limit exceeded", tick))
                    }
                    Some(_) => Ok(EnforcementResult::allowed("rate_limit satisfied", tick)),
                    None => Ok(EnforcementResult::denied(
                        "rate_limit witness missing",
                        tick,
                    )),
                }
            }

            "amount_limit" => {
                let max_amount = parameters
                    .get("max_amount")
                    .and_then(|s| s.parse::<u64>().ok());

                let Some(max_amount) = max_amount else {
                    return Ok(EnforcementResult::denied(
                        "Missing/invalid max_amount",
                        tick,
                    ));
                };

                match ctx.amount_witness() {
                    Some(v) if v <= max_amount => {
                        Ok(EnforcementResult::allowed("Amount limit satisfied", tick))
                    }
                    Some(_) => Ok(EnforcementResult::denied("Amount exceeds limit", tick)),
                    None => Ok(EnforcementResult::denied(
                        "No amount witness provided",
                        tick,
                    )),
                }
            }

            _ => {
                // Production-safe default: unknown custom constraint DENIES unless explicitly waived.
                Ok(EnforcementResult::denied("Unknown custom constraint", tick))
            }
        }
    }

    async fn check_role_permissions(
        &self,
        roles: &[PolicyRole],
        ctx: &EnforcementContext,
    ) -> Result<bool, DsmError> {
        let Some(identity) = ctx.identity.as_ref() else {
            return Ok(true);
        };

        for role in roles {
            if self.user_has_role(identity, &role.id).await {
                let permitted = role
                    .permissions
                    .iter()
                    .any(|op| op.eq_ignore_ascii_case(&ctx.operation_type));
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
    use crate::types::policy_types::{PolicyCondition, PolicyFile, TokenPolicy, VaultCondition};
    use crate::core::token::policy::policy_cache::{PolicyCache, PolicyCacheConfig};

    #[tokio::test]
    async fn identity_constraint_denies() -> Result<(), Box<dyn std::error::Error>> {
        let cache = Arc::new(PolicyCache::new(PolicyCacheConfig::default()));
        let enforcer = PolicyEnforcer::new(cache);

        let mut pf = PolicyFile::new("ID", "1.0.0", "a");
        pf.add_condition(PolicyCondition::IdentityConstraint {
            allowed_identities: vec!["allowed_user".into()],
            allow_derived: false,
        });
        let pol = TokenPolicy::new(pf)?;

        let mut ctx = HashMap::new();
        ctx.insert("identity".into(), b"unauthorized_user".to_vec());
        ctx.insert("tick".into(), 2_u64.to_le_bytes().to_vec());

        let res = enforcer.enforce_policy(&pol, "transfer", &ctx).await?;
        assert!(!res.allowed);
        Ok(())
    }

    #[tokio::test]
    async fn vault_min_balance_needs_witness() -> Result<(), Box<dyn std::error::Error>> {
        let cache = Arc::new(PolicyCache::new(PolicyCacheConfig::default()));
        let enforcer = PolicyEnforcer::new(cache);

        let mut pf = PolicyFile::new("VB", "1.0.0", "a");
        pf.add_condition(PolicyCondition::VaultEnforcement {
            condition: VaultCondition::MinimumBalance(100),
        });
        let pol = TokenPolicy::new(pf)?;

        let mut ctx = HashMap::new();
        ctx.insert("tick".into(), 3_u64.to_le_bytes().to_vec());

        let res = enforcer.enforce_policy(&pol, "transfer", &ctx).await?;
        assert!(!res.allowed);

        ctx.insert("vault.balance_u64".into(), 150_u64.to_le_bytes().to_vec());
        let res = enforcer.enforce_policy(&pol, "transfer", &ctx).await?;
        assert!(res.allowed);

        Ok(())
    }
}
