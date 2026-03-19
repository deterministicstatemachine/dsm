//! src/core/token/policy/policy_manager.rs
//! Policy Manager Module
//!
//! Manages policy governance, updates, and authorization for token policies
//! in the DSM Content-Addressed Token Policy Anchor (CTPA) system.
//!
//! Determinism rules:
//! - No wall-clock.
//! - “Time” fields are deterministic ticks only.
//! - Update frequency limits are expressed in ticks windows.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::types::{
    error::DsmError,
    policy_types::{PolicyAnchor, PolicyCondition, PolicyFile, PolicyRole, VaultCondition},
};
use crate::util::deterministic_time as dt;

#[inline]
fn now_tick() -> u64 {
    dt::tick().1
}

/// Policy manager configuration
#[derive(Debug, Clone)]
pub struct PolicyManagerConfig {
    pub require_authorization: bool,
    pub min_signatures: usize,

    /// Maximum updates allowed inside a sliding window of ticks.
    pub max_updates_per_window: u32,
    /// Sliding window size in ticks.
    pub update_window_ticks: u64,

    /// How long cached authorization is accepted (ticks).
    pub authorization_grace_ticks: u64,

    pub enable_versioning: bool,
    pub max_versions: usize,
}

impl Default for PolicyManagerConfig {
    fn default() -> Self {
        Self {
            require_authorization: true,
            min_signatures: 1,
            max_updates_per_window: 10,
            update_window_ticks: 3600,
            authorization_grace_ticks: 3600,
            enable_versioning: true,
            max_versions: 10,
        }
    }
}

/// Policy template for easy policy creation
#[derive(Debug, Clone)]
pub struct PolicyTemplate {
    pub name: String,
    pub description: String,
    pub conditions: Vec<PolicyCondition>,
    pub roles: Vec<PolicyRole>,
    pub metadata: HashMap<String, String>,
}

impl PolicyTemplate {
    pub fn basic_token() -> Self {
        Self {
            name: "Basic Token Policy".to_string(),
            description: "Standard token policy with basic operation restrictions".to_string(),
            conditions: vec![PolicyCondition::OperationRestriction {
                allowed_operations: vec![
                    "transfer".to_string(),
                    "lock".to_string(),
                    "unlock".to_string(),
                ],
            }],
            roles: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn restricted_token() -> Self {
        let mut t = Self::basic_token();
        t.name = "Restricted Token Policy".to_string();
        t.description = "Restricted token policy with identity constraints".to_string();
        t.conditions.push(PolicyCondition::IdentityConstraint {
            allowed_identities: Vec::new(),
            allow_derived: false,
        });
        t
    }

    pub fn to_policy_file(self, author: &str) -> PolicyFile {
        let mut policy = PolicyFile::new(&self.name, "1.0.0", author);

        if !self.description.is_empty() {
            policy.with_description(&self.description);
        }

        for condition in self.conditions {
            policy.add_condition(condition);
        }
        for role in self.roles {
            policy.add_role(role);
        }
        for (k, v) in self.metadata {
            policy.add_metadata(&k, &v);
        }

        // Optional: stamp created_tick with a deterministic tick if it’s not set internally.
        if policy.created_tick == 0 {
            policy.created_tick = now_tick();
        }

        policy
    }
}

/// Policy builder for fluent policy creation
#[derive(Debug, Clone)]
pub struct PolicyBuilder {
    name: String,
    version: String,
    author: String,
    description: Option<String>,
    conditions: Vec<PolicyCondition>,
    roles: Vec<PolicyRole>,
    metadata: HashMap<String, String>,
}

impl PolicyBuilder {
    pub fn new(name: &str, author: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            author: author.to_string(),
            description: None,
            conditions: Vec::new(),
            roles: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    pub fn with_identity_constraint(
        mut self,
        allowed_identities: Vec<String>,
        allow_derived: bool,
    ) -> Self {
        self.conditions.push(PolicyCondition::IdentityConstraint {
            allowed_identities,
            allow_derived,
        });
        self
    }

    pub fn with_operation_restriction(mut self, allowed_operations: Vec<String>) -> Self {
        self.conditions
            .push(PolicyCondition::OperationRestriction { allowed_operations });
        self
    }

    pub fn with_vault_enforcement(mut self, condition: VaultCondition) -> Self {
        self.conditions
            .push(PolicyCondition::VaultEnforcement { condition });
        self
    }

    pub fn with_custom_condition(
        mut self,
        constraint_type: &str,
        parameters: HashMap<String, String>,
    ) -> Self {
        self.conditions.push(PolicyCondition::Custom {
            constraint_type: constraint_type.to_string(),
            parameters,
        });
        self
    }

    pub fn with_role(mut self, role: PolicyRole) -> Self {
        self.roles.push(role);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> PolicyFile {
        let mut policy = PolicyFile::new(&self.name, &self.version, &self.author);

        if let Some(desc) = self.description {
            policy.with_description(&desc);
        }

        for condition in self.conditions {
            policy.add_condition(condition);
        }
        for role in self.roles {
            policy.add_role(role);
        }
        for (k, v) in self.metadata {
            policy.add_metadata(&k, &v);
        }

        if policy.created_tick == 0 {
            policy.created_tick = now_tick();
        }

        policy
    }
}

/// Policy update request
#[derive(Debug, Clone)]
pub struct PolicyUpdateRequest {
    pub token_id: String,
    pub new_policy: PolicyFile,
    pub signatures: Vec<PolicySignature>,
    pub reason: String,
    pub tick: u64,
    pub metadata: HashMap<String, String>,
}

/// Policy signature for authorization
#[derive(Debug, Clone)]
pub struct PolicySignature {
    pub signer: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub tick: u64,
}

/// Policy update history entry
#[derive(Debug, Clone)]
pub struct PolicyUpdateHistory {
    pub update_id: String,
    pub token_id: String,
    pub previous_anchor: Option<PolicyAnchor>,
    pub new_anchor: PolicyAnchor,
    pub tick: u64,
    pub updated_by: String,
    pub reason: String,
    pub signatures: Vec<PolicySignature>,
}

/// Policy governance voting
#[derive(Debug, Clone)]
pub struct PolicyVote {
    pub vote_id: String,
    pub token_id: String,
    pub proposed_policy: PolicyFile,
    pub votes: Vec<Vote>,
    pub start_tick: u64,
    pub end_tick: u64,
    pub status: VoteStatus,
    pub approval_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct Vote {
    pub voter: String,
    pub decision: VoteDecision,
    pub weight: f64,
    pub tick: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VoteDecision {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VoteStatus {
    Active,
    Approved,
    Rejected,
    Expired,
}

/// Policy manager for governance operations
#[derive(Debug)]
pub struct PolicyManager {
    config: PolicyManagerConfig,
    update_history: Arc<RwLock<Vec<PolicyUpdateHistory>>>,
    active_votes: Arc<RwLock<HashMap<String, PolicyVote>>>,
    auth_cache: Arc<RwLock<HashMap<String, AuthorizationEntry>>>,
    update_frequency: Arc<RwLock<HashMap<String, Vec<u64>>>>,
}

#[derive(Debug, Clone)]
struct AuthorizationEntry {
    authorization: Vec<u8>,
    cached_at: u64,
    expires_at: u64,
}

impl PolicyManager {
    pub fn new(config: PolicyManagerConfig) -> Self {
        Self {
            config,
            update_history: Arc::new(RwLock::new(Vec::new())),
            active_votes: Arc::new(RwLock::new(HashMap::new())),
            auth_cache: Arc::new(RwLock::new(HashMap::new())),
            update_frequency: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[allow(clippy::unused_async)]
    pub async fn create_policy_from_template(
        &self,
        template: PolicyTemplate,
        author: &str,
    ) -> Result<PolicyFile, DsmError> {
        Ok(template.to_policy_file(author))
    }

    pub fn get_policy_templates() -> Vec<PolicyTemplate> {
        vec![
            PolicyTemplate::basic_token(),
            PolicyTemplate::restricted_token(),
        ]
    }

    pub fn policy_builder(name: &str, author: &str) -> PolicyBuilder {
        PolicyBuilder::new(name, author)
    }

    #[allow(clippy::unused_async)]
    pub async fn create_basic_token_policy(
        &self,
        token_name: &str,
        author: &str,
    ) -> Result<PolicyFile, DsmError> {
        let template = PolicyTemplate::basic_token();
        let mut policy = template.to_policy_file(author);
        policy.name = format!("{token_name} Token Policy");
        policy.add_metadata("token_name", token_name);
        policy.add_metadata("policy_type", "basic");
        Ok(policy)
    }

    #[allow(clippy::unused_async)]
    pub async fn create_restricted_token_policy(
        &self,
        token_name: &str,
        author: &str,
        allowed_identities: Vec<String>,
    ) -> Result<PolicyFile, DsmError> {
        Ok(
            PolicyBuilder::new(&format!("{token_name} Restricted Policy"), author)
                .description(&format!("Restricted access policy for {token_name} token"))
                .with_identity_constraint(allowed_identities, false)
                .with_metadata("token_name", token_name)
                .with_metadata("policy_type", "restricted")
                .build(),
        )
    }

    /// Deterministic “time lock” using logical ticks.
    #[allow(clippy::unused_async)]
    pub async fn create_time_locked_token_policy(
        &self,
        token_name: &str,
        author: &str,
        lock_duration_ticks: u64,
    ) -> Result<PolicyFile, DsmError> {
        let current = now_tick();
        let unlock_tick = current
            .checked_add(lock_duration_ticks)
            .ok_or_else(|| DsmError::invalid_parameter("Lock duration too large"))?;

        let mut policy = PolicyBuilder::new(&format!("{token_name} Tick-Locked Policy"), author)
            .description(&format!("Tick-locked policy for {token_name} token"))
            .with_metadata("token_name", token_name)
            .with_metadata("policy_type", "tick_locked")
            .with_metadata("unlock_tick", &unlock_tick.to_string())
            .build();

        policy.add_condition(PolicyCondition::LogicalTimeConstraint {
            min_tick: unlock_tick,
            max_tick: u64::MAX,
        });

        Ok(policy)
    }

    #[allow(clippy::unused_async)]
    pub async fn submit_policy_update(
        &self,
        request: PolicyUpdateRequest,
    ) -> Result<PolicyAnchor, DsmError> {
        self.validate_update_request(&request).await?;

        if self.config.require_authorization {
            self.verify_authorization(&request).await?;
        }

        self.check_update_frequency(&request.token_id).await?;

        let new_anchor = PolicyAnchor::from_policy(&request.new_policy)?;
        let history_entry = PolicyUpdateHistory {
            update_id: self.generate_update_id(),
            token_id: request.token_id.clone(),
            previous_anchor: None,
            new_anchor: new_anchor.clone(),
            tick: now_tick(),
            updated_by: self.extract_primary_signer(&request.signatures),
            reason: request.reason,
            signatures: request.signatures,
        };

        {
            let mut history = self.update_history.write();
            history.push(history_entry);
            if self.config.enable_versioning && history.len() > self.config.max_versions {
                history.remove(0);
            }
        }

        self.record_update_frequency(&request.token_id).await;

        log::info!("Policy update applied for token {}", request.token_id);
        Ok(new_anchor)
    }

    #[allow(clippy::unused_async)]
    pub async fn verify_policy_update_authorization(
        &self,
        token_id: &str,
        authorization: &[u8],
    ) -> Result<(), DsmError> {
        {
            let auth_cache = self.auth_cache.read();
            if let Some(entry) = auth_cache.get(token_id) {
                let t = now_tick();
                if t < entry.expires_at && entry.authorization == authorization {
                    return Ok(());
                }
            }
        }

        if authorization.is_empty() {
            return Err(DsmError::invalid_parameter("Authorization cannot be empty"));
        }

        let t = now_tick();
        let auth_entry = AuthorizationEntry {
            authorization: authorization.to_vec(),
            cached_at: t,
            expires_at: t.saturating_add(self.config.authorization_grace_ticks),
        };

        {
            let mut auth_cache = self.auth_cache.write();
            auth_cache.insert(token_id.to_string(), auth_entry);
        }

        Ok(())
    }

    pub fn is_authorization_valid(&self, token_id: &str) -> bool {
        let auth_cache = self.auth_cache.read();
        if let Some(entry) = auth_cache.get(token_id) {
            let t = now_tick();
            let age = t.saturating_sub(entry.cached_at);
            let fresh = age < self.config.authorization_grace_ticks;
            let not_expired = t < entry.expires_at;
            fresh && not_expired
        } else {
            false
        }
    }

    pub fn get_cached_authorization(&self, token_id: &str) -> Option<Vec<u8>> {
        if self.is_authorization_valid(token_id) {
            self.auth_cache
                .read()
                .get(token_id)
                .map(|e| e.authorization.clone())
        } else {
            None
        }
    }

    #[allow(clippy::unused_async)]
    pub async fn start_governance_vote(
        &self,
        token_id: &str,
        proposed_policy: PolicyFile,
        duration_ticks: u64,
        approval_threshold: f64,
    ) -> Result<String, DsmError> {
        let vote_id = self.generate_vote_id();
        let t = now_tick();

        let vote = PolicyVote {
            vote_id: vote_id.clone(),
            token_id: token_id.to_string(),
            proposed_policy,
            votes: Vec::new(),
            start_tick: t,
            end_tick: t.saturating_add(duration_ticks),
            status: VoteStatus::Active,
            approval_threshold,
        };

        self.active_votes.write().insert(vote_id.clone(), vote);
        log::info!("Started governance vote {} for token {}", vote_id, token_id);
        Ok(vote_id)
    }

    #[allow(clippy::unused_async)]
    pub async fn cast_vote(
        &self,
        vote_id: &str,
        voter: &str,
        decision: VoteDecision,
        weight: f64,
        signature: Vec<u8>,
    ) -> Result<(), DsmError> {
        let mut active_votes = self.active_votes.write();
        let Some(vote) = active_votes.get_mut(vote_id) else {
            return Err(DsmError::not_found(
                "Vote",
                Some(format!("Vote not found: {vote_id}")),
            ));
        };

        let t = now_tick();
        if t > vote.end_tick {
            vote.status = VoteStatus::Expired;
            return Err(DsmError::invalid_parameter("Vote has expired"));
        }
        if vote.status != VoteStatus::Active {
            return Err(DsmError::invalid_parameter("Vote is no longer active"));
        }
        if vote.votes.iter().any(|v| v.voter == voter) {
            return Err(DsmError::invalid_parameter("Voter already cast a vote"));
        }

        vote.votes.push(Vote {
            voter: voter.to_string(),
            decision,
            weight,
            tick: t,
            signature,
        });

        self.check_vote_completion(vote);
        Ok(())
    }

    #[allow(clippy::unused_async)]
    pub async fn get_update_history(&self, token_id: &str) -> Vec<PolicyUpdateHistory> {
        self.update_history
            .read()
            .iter()
            .filter(|h| h.token_id == token_id)
            .cloned()
            .collect()
    }

    #[allow(clippy::unused_async)]
    pub async fn get_active_votes(&self) -> Vec<PolicyVote> {
        self.active_votes
            .read()
            .values()
            .filter(|v| v.status == VoteStatus::Active)
            .cloned()
            .collect()
    }

    #[allow(clippy::unused_async)]
    pub async fn cleanup(&self) -> Result<(), DsmError> {
        let t = now_tick();

        {
            let mut active_votes = self.active_votes.write();
            active_votes.retain(|_, v| t <= v.end_tick && v.status == VoteStatus::Active);
        }

        {
            let mut auth_cache = self.auth_cache.write();
            auth_cache.retain(|_, e| t < e.expires_at);
        }

        {
            let mut freq = self.update_frequency.write();
            let window = self.config.update_window_ticks;
            freq.retain(|_, ticks| {
                ticks.retain(|&x| t.saturating_sub(x) < window);
                !ticks.is_empty()
            });
        }

        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn validate_update_request(&self, request: &PolicyUpdateRequest) -> Result<(), DsmError> {
        if request.token_id.is_empty() {
            return Err(DsmError::invalid_parameter("Token ID is required"));
        }
        if request.new_policy.name.is_empty() {
            return Err(DsmError::invalid_parameter("Policy name is required"));
        }

        if self.config.require_authorization {
            if request.signatures.is_empty() {
                return Err(DsmError::invalid_parameter("Signatures are required"));
            }
            if request.signatures.len() < self.config.min_signatures {
                return Err(DsmError::invalid_parameter(format!(
                    "Insufficient signatures: {} < {}",
                    request.signatures.len(),
                    self.config.min_signatures
                )));
            }
        }

        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn verify_authorization(&self, request: &PolicyUpdateRequest) -> Result<(), DsmError> {
        for (i, s) in request.signatures.iter().enumerate() {
            if s.signature.is_empty() {
                return Err(DsmError::invalid_parameter(format!(
                    "Signature {i} is empty"
                )));
            }
            if s.public_key.is_empty() {
                return Err(DsmError::invalid_parameter(format!(
                    "Public key {i} is empty"
                )));
            }
        }
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn check_update_frequency(&self, token_id: &str) -> Result<(), DsmError> {
        let t = now_tick();
        let window = self.config.update_window_ticks;
        let limit = self.config.max_updates_per_window as usize;

        let freq = self.update_frequency.read();
        if let Some(ts) = freq.get(token_id) {
            let recent = ts.iter().filter(|&&x| t.saturating_sub(x) < window).count();
            if recent >= limit {
                return Err(DsmError::invalid_parameter(format!(
                    "Update frequency limit exceeded: {} >= {}",
                    recent, limit
                )));
            }
        }
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn record_update_frequency(&self, token_id: &str) {
        let t = now_tick();
        self.update_frequency
            .write()
            .entry(token_id.to_string())
            .or_default()
            .push(t);
    }

    fn extract_primary_signer(&self, signatures: &[PolicySignature]) -> String {
        signatures
            .first()
            .map(|s| s.signer.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn generate_update_id(&self) -> String {
        format!("update_{}", now_tick())
    }

    fn generate_vote_id(&self) -> String {
        format!("vote_{}", now_tick())
    }

    fn check_vote_completion(&self, vote: &mut PolicyVote) {
        let total: f64 = vote.votes.iter().map(|v| v.weight).sum();
        if total <= 0.0 {
            return;
        }

        let approve: f64 = vote
            .votes
            .iter()
            .filter(|v| v.decision == VoteDecision::Approve)
            .map(|v| v.weight)
            .sum();

        let ratio = approve / total;
        if ratio >= vote.approval_threshold {
            vote.status = VoteStatus::Approved;
            return;
        }

        // Conservative reject check: if even treating all Abstain as Approve can’t reach threshold.
        let abstain: f64 = vote
            .votes
            .iter()
            .filter(|v| v.decision == VoteDecision::Abstain)
            .map(|v| v.weight)
            .sum();

        let max_possible = (approve + abstain) / total;
        if max_possible < vote.approval_threshold {
            vote.status = VoteStatus::Rejected;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::policy_types::PolicyFile;

    #[tokio::test]
    async fn test_policy_manager_creation() {
        let manager = PolicyManager::new(PolicyManagerConfig::default());
        let history = manager.get_update_history("test_token").await;
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_policy_update_request_no_auth() {
        let config = PolicyManagerConfig {
            require_authorization: false,
            min_signatures: 0,
            ..Default::default()
        };
        let manager = PolicyManager::new(config);

        let policy_file = PolicyFile::new("Test Policy", "1.0.0", "test_author");
        let request = PolicyUpdateRequest {
            token_id: "test_token".to_string(),
            new_policy: policy_file,
            signatures: Vec::new(),
            reason: "Test update".to_string(),
            tick: now_tick(),
            metadata: HashMap::new(),
        };

        let result = manager.submit_policy_update(request).await;
        assert!(result.is_ok());
    }
}
