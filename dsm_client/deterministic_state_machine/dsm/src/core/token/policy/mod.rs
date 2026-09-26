// SPDX-License-Identifier: MIT OR Apache-2.0

//! src/core/token/policy/mod.rs
//! Token policies as the enforcer sees them.
//!
//! A token's policy is the `TokenPolicyV3` bytes committed at its
//! `policy_commit = BLAKE3(TAG_DSM_POLICY, bytes)` (SoFi §47), read by Core's
//! one parser (`crate::economic::token_policy`). Nothing here takes a policy
//! any other way: registration takes the bytes, recomputes the commitment
//! from them and derives the enforcer's view from what the blob says
//! (`policy_enforcement::enforced_policy`), and enforcement is keyed by the
//! commitment an operation names. A token with no committed policy — ERA,
//! whose `policy_commit` constant has no preimage yet — has no policy here,
//! and an operation naming it is refused for that reason.
//!
//! Determinism rules: no wall-clock; enforcement reads only what the
//! operation carries and what Core derived from canonical state.

pub mod policy_cache;
pub mod policy_enforcement;

pub use policy_cache::{PolicyCache, PolicyCacheConfig, PolicyCacheEntry};
pub use policy_enforcement::{
    enforced_policy, permitted_operations, EnforcementError, EnforcementResult, PolicyEnforcer,
};

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::types::{
    error::DsmError,
    policy_types::{PolicyAnchor, TokenPolicy},
};

/// Answers the durable `TokenPolicyV3` bytes recorded at a policy commitment,
/// on a cache miss. Installed by the SDK, which owns the durable
/// `token_policies` store; Core does not learn to read the client database.
///
/// The bytes are trusted for nothing: [`TokenPolicySystem::policy_at`]
/// recomputes the commitment from them and takes them only when it is the
/// one asked for, so a miss can never be satisfied by bytes the storage
/// layer merely *claims* belong to this commitment.
pub type PolicyResolver = Arc<dyn Fn(&[u8; 32]) -> Option<Vec<u8>> + Send + Sync + 'static>;

/// The token policies this process has read, keyed by commitment.
#[derive(Clone)]
pub struct TokenPolicySystem {
    /// In-memory ONLY. Authority for a policy is its committed bytes, behind
    /// `resolver`; this is a cache in front of them.
    policy_cache: Arc<PolicyCache>,
    enforcer: Arc<PolicyEnforcer>,
    resolver: Arc<RwLock<Option<PolicyResolver>>>,
}

impl std::fmt::Debug for TokenPolicySystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPolicySystem")
            .field("cached_policies", &self.policy_cache.len())
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
        Self {
            policy_cache: Arc::new(PolicyCache::new(PolicyCacheConfig::default())),
            enforcer: Arc::new(PolicyEnforcer::new()),
            resolver: Arc::new(RwLock::new(None)),
        }
    }

    /// Install the durable-storage resolver consulted on a cache miss.
    pub fn set_policy_resolver(&self, resolver: PolicyResolver) {
        *self.resolver.write() = Some(resolver);
    }

    /// The commitment of `bytes`: `BLAKE3(TAG_DSM_POLICY, bytes)` (SoFi §47).
    pub fn commitment_of(bytes: &[u8]) -> [u8; 32] {
        crate::crypto::blake3::domain_hash_bytes(crate::common::domain_tags::TAG_DSM_POLICY, bytes)
    }

    /// Register the policy these exact `TokenPolicyV3` bytes are, and answer
    /// its commitment. The commitment is recomputed from the bytes, the blob
    /// is read by Core's one parser, and the enforcer's view is derived from
    /// what it says: nothing about the policy is taken from the caller.
    pub fn register_policy(&self, bytes: &[u8]) -> Result<[u8; 32], DsmError> {
        let commit = Self::commitment_of(bytes);
        let parsed = crate::economic::token_policy::parse_token_policy(bytes).map_err(|e| {
            DsmError::invalid_operation(format!(
                "token policy: the committed bytes do not parse: {e}"
            ))
        })?;
        let anchor = PolicyAnchor::from_bytes(commit);
        self.policy_cache.store_policy(
            anchor.clone(),
            TokenPolicy::new_with_anchor(enforced_policy(&parsed), anchor),
        );
        Ok(commit)
    }

    /// The policy committed at `commit`: from the cache, else from the
    /// durable bytes the resolver answers, taken only when they are the
    /// policy at exactly this commitment. `None` when no committed policy is
    /// in hand — a miss is not absence, and neither is bytes at another
    /// commitment, but there is nothing to evaluate against either way.
    pub async fn policy_at(&self, commit: &[u8; 32]) -> Result<Option<TokenPolicy>, DsmError> {
        let anchor = PolicyAnchor::from_bytes(*commit);
        if let Some(policy) = self.policy_cache.get_policy(&anchor).await? {
            return Ok(Some(policy));
        }
        let resolver = { self.resolver.read().clone() };
        let Some(resolver) = resolver else {
            return Ok(None);
        };
        let Some(bytes) = resolver(commit) else {
            return Ok(None);
        };
        if Self::commitment_of(&bytes) != *commit {
            log::warn!(
                "[policy] the durable store answered bytes at another commitment for {}; not a policy",
                crate::utils::text_id::encode_base32_crockford(commit)
            );
            return Ok(None);
        }
        self.register_policy(&bytes)?;
        log::info!(
            "[policy] rehydrated {} from durable storage on cache miss",
            crate::utils::text_id::encode_base32_crockford(commit)
        );
        self.policy_cache.get_policy(&anchor).await
    }

    /// Whether the policy committed at `commit` permits `operation_type` in
    /// `context`. Denied when no policy is committed there.
    pub async fn enforce_policy(
        &self,
        commit: &[u8; 32],
        operation_type: &str,
        context: &HashMap<String, Vec<u8>>,
    ) -> Result<EnforcementResult, DsmError> {
        match self.policy_at(commit).await? {
            Some(policy) => {
                self.enforcer
                    .enforce_policy(&policy, operation_type, context)
                    .await
            }
            None => Ok(EnforcementResult::denied(
                "no policy is committed at the commitment the operation names",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic::token_policy::{POLICY_FLAG_BURN, POLICY_FLAG_TRANSFERABLE};
    use crate::sofi::validation::fixtures::token_policy_bytes_with;
    use crate::types::policy_types::PolicyCondition;

    fn context(amount: u64) -> HashMap<String, Vec<u8>> {
        let mut context = HashMap::new();
        context.insert("amount_u64".to_string(), amount.to_le_bytes().to_vec());
        context
    }

    /// SoFi §47: a policy is registered from its committed bytes alone — the
    /// commitment recomputed from them, the enforcer's view derived from what
    /// the blob says (its genesis supply, its flags) and nothing else.
    #[tokio::test]
    async fn a_policy_is_registered_from_its_committed_bytes_alone() {
        let system = TokenPolicySystem::new();
        let bytes = token_policy_bytes_with(1, POLICY_FLAG_TRANSFERABLE | POLICY_FLAG_BURN);
        let commit = system
            .register_policy(&bytes)
            .expect("the fixture blob parses");
        assert_eq!(commit, TokenPolicySystem::commitment_of(&bytes));

        let policy = system
            .policy_at(&commit)
            .await
            .expect("cache read")
            .expect("registered");
        assert_eq!(*policy.anchor.as_bytes(), commit);
        assert!(policy
            .file
            .conditions
            .contains(&PolicyCondition::SupplyCap {
                max_supply: 1_000_000_000
            }));
        assert!(policy
            .file
            .conditions
            .contains(&PolicyCondition::OperationRestriction {
                allowed_operations: permitted_operations(true, true),
            }));
        assert_eq!(policy.file.conditions.len(), 2);
        assert!(
            system
                .enforce_policy(&commit, "transfer", &context(5))
                .await
                .expect("enforced")
                .allowed
        );
    }

    /// Storage §4: bytes the durable store answers for a commitment are the
    /// policy there only if they re-hash to it. Bytes at another commitment
    /// establish no policy, and an operation naming the commitment is denied.
    #[tokio::test]
    async fn bytes_at_another_commitment_are_not_the_policy_asked_for() {
        let system = TokenPolicySystem::new();
        let other = token_policy_bytes_with(2, POLICY_FLAG_TRANSFERABLE);
        let other_again = other.clone();
        let asked =
            TokenPolicySystem::commitment_of(&token_policy_bytes_with(3, POLICY_FLAG_TRANSFERABLE));
        system.set_policy_resolver(Arc::new(move |_commit: &[u8; 32]| Some(other.clone())));

        assert!(system.policy_at(&asked).await.expect("read").is_none());
        let result = system
            .enforce_policy(&asked, "transfer", &context(1))
            .await
            .expect("enforced");
        assert!(!result.allowed, "{}", result.reason);
        assert!(
            system
                .policy_cache
                .get_policy(&PolicyAnchor::from_bytes(TokenPolicySystem::commitment_of(
                    &other_again
                )))
                .await
                .expect("cache read")
                .is_none(),
            "a refused answer registers nothing, under any commitment"
        );
    }

    /// A commitment no committed policy is in hand for — ERA's today, whose
    /// constant has no preimage — permits nothing: the operation is denied
    /// for the absence, never allowed by a default.
    #[tokio::test]
    async fn an_operation_naming_a_commitment_without_a_policy_is_denied() {
        let system = TokenPolicySystem::new();
        let era = crate::core::token::token_state_manager::era_policy_commit();
        let result = system
            .enforce_policy(&era, "transfer", &context(1))
            .await
            .expect("enforced");
        assert!(!result.allowed);
        assert_eq!(
            result.reason,
            "no policy is committed at the commitment the operation names"
        );
    }

    /// The durable bytes at a commitment are taken on a cache miss when they
    /// re-hash to it; the policy is then the one those bytes commit.
    #[tokio::test]
    async fn a_cache_miss_takes_the_durable_bytes_that_re_hash_to_the_commitment() {
        let system = TokenPolicySystem::new();
        let bytes = token_policy_bytes_with(4, 0);
        let commit = TokenPolicySystem::commitment_of(&bytes);
        let stored = bytes.clone();
        system.set_policy_resolver(Arc::new(move |asked: &[u8; 32]| {
            (*asked == TokenPolicySystem::commitment_of(&stored)).then(|| stored.clone())
        }));
        let policy = system
            .policy_at(&commit)
            .await
            .expect("read")
            .expect("rehydrated from the durable bytes");
        assert_eq!(*policy.anchor.as_bytes(), commit);
        let result = system
            .enforce_policy(&commit, "transfer", &context(1))
            .await
            .expect("enforced");
        assert!(
            !result.allowed,
            "the fixture with no flags is not transferable"
        );
    }
}
