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
pub mod policy_manager;
pub mod policy_validation;

pub use policy_cache::{PolicyCache, PolicyCacheEntry, PolicyCacheConfig};
pub use policy_enforcement::{EnforcementError, EnforcementResult, PolicyEnforcer};
pub use policy_manager::{
    PolicyBuilder, PolicyManager, PolicyManagerConfig, PolicySignature, PolicyTemplate,
    PolicyUpdateRequest, PolicyUpdateHistory, PolicyVote, Vote, VoteDecision, VoteStatus,
};
pub use policy_validation::{PolicyValidator, ValidationContext, ValidationMode, ValidationResult};

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::types::{
    error::DsmError,
    policy_types::{PolicyAnchor, PolicyFile, TokenPolicy},
    token_types::TokenMetadata,
};

/// Central token policy system for DSM
#[derive(Debug, Clone)]
pub struct TokenPolicySystem {
    policy_cache: Arc<PolicyCache>,
    enforcer: Arc<PolicyEnforcer>,
    manager: Arc<PolicyManager>,
    validator: Arc<PolicyValidator>,
    token_policies: Arc<RwLock<HashMap<String, PolicyAnchor>>>,
}

impl TokenPolicySystem {
    pub fn policy_manager(&self) -> Arc<PolicyManager> {
        self.manager.clone()
    }

    pub fn new() -> Result<Self, DsmError> {
        let cache = Arc::new(PolicyCache::new(PolicyCacheConfig::default()));
        let enforcer = Arc::new(PolicyEnforcer::new(cache.clone()));
        let manager = Arc::new(PolicyManager::new(PolicyManagerConfig::default()));
        let validator = Arc::new(PolicyValidator::new());

        Ok(Self {
            policy_cache: cache,
            enforcer,
            manager,
            validator,
            token_policies: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn register_token_policy(
        &self,
        token_id: &str,
        policy_file: PolicyFile,
    ) -> Result<PolicyAnchor, DsmError> {
        let anchor = PolicyAnchor::from_policy(&policy_file)?;

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

        let token_policy = TokenPolicy::new(policy_file)?;
        self.policy_cache.store_policy(anchor.clone(), token_policy);

        // Register mappings
        self.policy_cache
            .index_token_policy(token_id.to_string(), anchor.clone());
        self.token_policies
            .write()
            .insert(token_id.to_string(), anchor.clone());

        log::info!("Registered policy for token {}", token_id);
        Ok(anchor)
    }

    pub async fn get_token_policy(&self, token_id: &str) -> Result<Option<TokenPolicy>, DsmError> {
        let anchor = { self.token_policies.read().get(token_id).cloned() };
        if let Some(anchor) = anchor {
            self.policy_cache.get_policy(&anchor).await
        } else {
            Ok(None)
        }
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
            // No policy registered -> allow by default.
            // tick is best-effort; use peek (non-advancing) via enforcer default patterns elsewhere.
            Ok(EnforcementResult::allowed("No policy restrictions", 0))
        }
    }

    pub async fn validate_token_metadata(
        &self,
        metadata: &TokenMetadata,
    ) -> Result<ValidationResult, DsmError> {
        let anchor = self.get_policy_anchor(&metadata.token_id).ok_or_else(|| {
            DsmError::not_found(
                "Token policy",
                Some(format!(
                    "No policy registered for token {}",
                    metadata.token_id
                )),
            )
        })?;

        let declared_anchor = metadata.policy_anchor.as_deref().ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "Token {} metadata is missing a policy anchor",
                metadata.token_id
            ))
        })?;
        let declared_anchor = PolicyAnchor::from_policy_uri(declared_anchor)?;
        if declared_anchor != anchor {
            return Err(DsmError::invalid_operation(format!(
                "Token {} metadata policy anchor does not match registered policy",
                metadata.token_id
            )));
        }

        if let Some(policy) = self.policy_cache.get_policy(&anchor).await? {
            let context = ValidationContext::new(&metadata.token_id, &policy.file);
            self.validator
                .validate_token_metadata(&context, metadata)
                .await
        } else {
            Err(DsmError::not_found(
                "Token policy",
                Some("Policy not found for registered anchor".to_string()),
            ))
        }
    }

    pub async fn update_token_policy(
        &self,
        token_id: &str,
        new_policy: PolicyFile,
        authorization: &[u8],
    ) -> Result<PolicyAnchor, DsmError> {
        self.manager
            .verify_policy_update_authorization(token_id, authorization)
            .await?;
        self.register_token_policy(token_id, new_policy).await
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

impl Default for TokenPolicySystem {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            log::error!("TokenPolicySystem default init failed: {e}");
            let cache = Arc::new(PolicyCache::new(PolicyCacheConfig::default()));
            Self {
                policy_cache: cache.clone(),
                enforcer: Arc::new(PolicyEnforcer::new(cache)),
                manager: Arc::new(PolicyManager::new(PolicyManagerConfig::default())),
                validator: Arc::new(PolicyValidator::new()),
                token_policies: Arc::new(RwLock::new(HashMap::new())),
            }
        })
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
    use crate::types::token_types::{TokenMetadata, TokenType};

    #[tokio::test]
    async fn test_policy_system_creation() {
        let system = TokenPolicySystem::new().unwrap();
        assert!(!system.has_policy_restrictions("test_token"));
    }

    #[tokio::test]
    async fn test_register_token_policy() {
        let system = TokenPolicySystem::new().unwrap();

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
        let system = TokenPolicySystem::new().unwrap();
        let resolved = crate::core::token::token_state_manager::PolicyCommitResolver::resolve(
            &system,
            "missing_token",
        );
        assert!(resolved.is_err());
    }

    #[tokio::test]
    async fn test_token_metadata_validation_requires_policy_anchor() {
        let system = TokenPolicySystem::new().unwrap();

        let owner_id = blake3::hash(b"test_owner").into();
        let metadata = TokenMetadata::new(
            "test_token",
            "Test Token",
            "TEST",
            18,
            TokenType::Created,
            owner_id,
            0,
            None,
        );

        let result = system.validate_token_metadata(&metadata).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_token_metadata_validation_accepts_equivalent_lowercase_policy_anchor_uri() {
        let system = TokenPolicySystem::new().unwrap();

        let policy = PolicyFile::new("Test Policy", "1.0.0", "test_creator");
        let anchor = system
            .register_token_policy("test_token", policy)
            .await
            .unwrap();

        let owner_id = blake3::hash(b"test_owner").into();
        let metadata = TokenMetadata::new(
            "test_token",
            "Test Token",
            "TEST",
            18,
            TokenType::Created,
            owner_id,
            0,
            Some(anchor.to_policy_uri().to_lowercase()),
        );

        let result = system.validate_token_metadata(&metadata).await;
        assert!(
            result.is_ok(),
            "lowercase policy URI should validate by bytes"
        );
    }
}
