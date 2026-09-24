// SPDX-License-Identifier: MIT OR Apache-2.0

//! src/core/token/policy/mod.rs
//! Token Policy Module
//!
//! Implements the Content-Addressed Token Policy Anchor (CTPA) system for DSM tokens.
//! - Caching
//! - Validation
//! - Enforcement
//! - Governance
//!
//! Determinism rules:
//! - No wall-clock.
//! - Enforcement prefers explicit tick witness in context_data ("tick" -> u64 LE).

pub mod policy_cache;
pub mod policy_enforcement;
pub mod policy_validation;

pub use policy_cache::{PolicyCache, PolicyCacheEntry, PolicyCacheConfig};
pub use policy_enforcement::{EnforcementError, EnforcementResult, PolicyEnforcer};
pub use policy_validation::{PolicyValidator, ValidationContext, ValidationMode, ValidationResult};

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::types::{
    error::DsmError,
    policy_types::{PolicyAnchor, PolicyFile, TokenPolicy},
};

/// Loads a token's committed policy from durable storage on a cache miss.
///
/// Installed by the SDK, which owns both the durable `token_policies` store and
/// the single policy parser. Core keeps enforcement; it does not learn to read
/// the client database or to parse policy bytes a second way.
///
/// The implementation is required to re-derive the CPTA anchor from the loaded
/// bytes and reject anything that does not match, so a miss can never be
/// satisfied by bytes the storage layer merely *claims* belong to this token.
pub type PolicyResolver =
    Arc<dyn Fn(&str) -> Option<(PolicyFile, PolicyAnchor)> + Send + Sync + 'static>;

/// Central token policy system for DSM
#[derive(Clone)]
pub struct TokenPolicySystem {
    policy_cache: Arc<PolicyCache>,
    enforcer: Arc<PolicyEnforcer>,
    validator: Arc<PolicyValidator>,
    /// In-memory index ONLY. Authority for persisted policy bytes is the
    /// durable store behind `resolver`; this is a cache in front of it.
    token_policies: Arc<RwLock<HashMap<String, PolicyAnchor>>>,
    resolver: Arc<RwLock<Option<PolicyResolver>>>,
}

impl std::fmt::Debug for TokenPolicySystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPolicySystem")
            .field("indexed_tokens", &self.token_policies.read().len())
            .finish_non_exhaustive()
    }
}

impl Default for TokenPolicySystem {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenPolicySystem {
    pub fn new() -> Self {
        let cache = Arc::new(PolicyCache::new(PolicyCacheConfig::default()));
        let enforcer = Arc::new(PolicyEnforcer::new());
        let validator = Arc::new(PolicyValidator::new());

        Self {
            policy_cache: cache,
            enforcer,
            validator,
            token_policies: Arc::new(RwLock::new(HashMap::new())),
            resolver: Arc::new(RwLock::new(None)),
        }
    }

    /// Install the durable-storage resolver used on a cache miss.
    pub fn set_policy_resolver(&self, resolver: PolicyResolver) {
        *self.resolver.write() = Some(resolver);
    }

    pub async fn register_token_policy(
        &self,
        token_id: &str,
        policy_file: PolicyFile,
    ) -> Result<PolicyAnchor, DsmError> {
        let anchor = PolicyAnchor::from_policy(&policy_file)?;
        self.register_token_policy_with_anchor(token_id, policy_file, anchor.clone())
            .await?;
        Ok(anchor)
    }

    /// Register a token policy while preserving an already-authoritative
    /// policy anchor.
    ///
    /// Use this when the policy bytes are committed externally (for example,
    /// via storage-layer `DSM/policy` anchoring) and token operations must
    /// bind to that exact 32-byte commitment.
    pub async fn register_token_policy_with_anchor(
        &self,
        token_id: &str,
        policy_file: PolicyFile,
        anchor: PolicyAnchor,
    ) -> Result<(), DsmError> {
        // Validate policy deterministically
        let validation_context = ValidationContext::new(token_id, &policy_file);
        let validation_result = self.validator.validate_policy(&validation_context).await?;

        if !validation_result.is_valid {
            return Err(DsmError::policy_violation(
                "policy_validation",
                format!(
                    "Policy validation failed: {} (errors: {:?})",
                    validation_result.message, validation_result.errors
                ),
                None::<std::convert::Infallible>,
            ));
        }

        let token_policy = TokenPolicy::new_with_anchor(policy_file, anchor.clone());
        self.policy_cache.store_policy(anchor.clone(), token_policy);

        // Register mappings
        self.policy_cache
            .index_token_policy(token_id.to_string(), anchor.clone());
        self.token_policies
            .write()
            .insert(token_id.to_string(), anchor.clone());

        log::info!("Registered policy for token {}", token_id);
        Ok(())
    }

    pub async fn get_token_policy(&self, token_id: &str) -> Result<Option<TokenPolicy>, DsmError> {
        let anchor = { self.token_policies.read().get(token_id).cloned() };
        if let Some(anchor) = anchor {
            if let Some(policy) = self.policy_cache.get_policy(&anchor).await? {
                return Ok(Some(policy));
            }
        }

        // Cache miss (never indexed, or evicted) is NOT absence. This map lives only as long as the
        // process, so after a restart every created and adopted token looked
        // policy-less and enforcement denied them — on device that surfaced as
        // "Token policy violation for RIGB: No policy registered for token"
        // while the committed policy sat in durable storage the whole time.
        //
        // So a miss consults the durable store rather than concluding. The
        // resolver re-derives the CPTA anchor from the loaded bytes and returns
        // None unless it matches exactly, so this can only ever install the
        // policy the token actually committed to. Genuinely absent, malformed,
        // or mismatched bytes still yield None and the caller still denies.
        let resolver = { self.resolver.read().clone() };
        if let Some(resolver) = resolver {
            if let Some((policy_file, anchor)) = resolver(token_id) {
                let policy = TokenPolicy::new_with_anchor(policy_file, anchor.clone());
                self.policy_cache.store_policy(anchor.clone(), policy);
                self.policy_cache
                    .index_token_policy(token_id.to_string(), anchor.clone());
                self.token_policies
                    .write()
                    .insert(token_id.to_string(), anchor.clone());
                log::info!("[policy] rehydrated {token_id} from durable storage on cache miss");
                return self.policy_cache.get_policy(&anchor).await;
            }
        }
        Ok(None)
    }

    pub async fn enforce_policy(
        &self,
        token_id: &str,
        operation_type: &str,
        context: &HashMap<String, Vec<u8>>,
    ) -> Result<EnforcementResult, DsmError> {
        if let Some(policy) = self.get_token_policy(token_id).await? {
            self.enforcer
                .enforce_policy(&policy, operation_type, context)
                .await
        } else {
            Ok(EnforcementResult::denied("No policy registered for token"))
        }
    }

    pub fn has_policy_restrictions(&self, token_id: &str) -> bool {
        self.token_policies.read().contains_key(token_id)
    }

    pub fn get_policy_anchor(&self, token_id: &str) -> Option<PolicyAnchor> {
        self.token_policies.read().get(token_id).cloned()
    }

    pub async fn preload_standard_policies(&self) -> Result<(), DsmError> {
        let root_policy = self.create_root_token_policy();
        self.register_token_policy("ERA", root_policy).await?;
        Ok(())
    }

    pub fn preload_standard_policies_blocking(&self) -> Result<(), DsmError> {
        // Avoid nested runtime panics: if inside a runtime, do the work on a dedicated thread.
        if tokio::runtime::Handle::try_current().is_ok() {
            let sys = self.clone();
            let join_res = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        DsmError::internal(
                            format!("Failed to build runtime for policy preload: {e}"),
                            None::<std::convert::Infallible>,
                        )
                    })?;
                rt.block_on(sys.preload_standard_policies())
            })
            .join();

            return match join_res {
                Ok(res) => res,
                Err(_) => Err(DsmError::internal(
                    "Failed to join policy preload thread",
                    None::<std::convert::Infallible>,
                )),
            };
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                DsmError::internal(
                    format!("Failed to build runtime for policy preload: {e}"),
                    None::<std::convert::Infallible>,
                )
            })?;
        rt.block_on(self.preload_standard_policies())
    }

    fn create_root_token_policy(&self) -> PolicyFile {
        let mut policy = PolicyFile::new("ERA Token Policy", "1.0.0", "system");
        policy.with_description("Default policy for the ERA token in DSM ecosystem");
        policy.add_metadata("token_type", "native");
        policy.add_metadata("governance", "meritocratic");
        policy.add_metadata("supply_model", "fixed");
        policy
    }
}

impl crate::core::token::token_state_manager::PolicyCommitResolver for TokenPolicySystem {
    /// Resolve a token_id to its 32-byte CPTA policy_commit.
    ///
    /// Returns the registered `PolicyAnchor` bytes if the token has a policy.
    /// Missing policy anchors fail closed.
    fn resolve(&self, token_id: &str) -> Result<[u8; 32], DsmError> {
        self.get_policy_anchor(token_id)
            .map(|a| a.0)
            .ok_or_else(|| {
                DsmError::invalid_operation(format!("Missing policy anchor for token {token_id}"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_system_creation() {
        let system = TokenPolicySystem::new();
        assert!(!system.has_policy_restrictions("test_token"));
    }

    #[tokio::test]
    async fn test_register_token_policy() {
        let system = TokenPolicySystem::new();

        let mut policy = PolicyFile::new("Test Policy", "1.0.0", "test_creator");
        policy.add_metadata("test_key", "test_value");
        let anchor = system
            .register_token_policy("test_token", policy)
            .await
            .unwrap();

        assert!(system.has_policy_restrictions("test_token"));
        assert_eq!(system.get_policy_anchor("test_token"), Some(anchor));
    }

    #[tokio::test]
    async fn test_resolve_missing_policy_fails_closed() {
        let system = TokenPolicySystem::new();
        let resolved = crate::core::token::token_state_manager::PolicyCommitResolver::resolve(
            &system,
            "missing_token",
        );
        assert!(resolved.is_err());
    }
}
