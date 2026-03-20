//! src/core/token/policy/policy_validation.rs
//! Policy Validation Module
//!
//! Validates token policies and their application to token metadata
//! according to DSM Content-Addressed Token Policy Anchor (CTPA) standards.
//!
//! Determinism rules:
//! - No wall-clock.
//! - “Time” means deterministic ticks only.
//! - No string encodings for binary anchors/hashes in logs or comparisons.

use std::collections::{HashMap, HashSet};

use crate::types::{
    error::DsmError,
    policy_types::{PolicyCondition, PolicyFile, PolicyRole, VaultCondition},
    token_types::TokenMetadata,
};
use crate::utils::deterministic_time as dt;
use prost::Message;
use base32; // Add base32 import

/// Validation result for policy checks
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the validation passed
    pub is_valid: bool,
    /// Validation message
    pub message: String,
    /// List of validation errors
    pub errors: Vec<ValidationError>,
    /// List of validation warnings
    pub warnings: Vec<ValidationWarning>,
    /// Deterministic tick at which validation was produced (for logging/audit only)
    pub tick: u64,
    /// Additional validation context
    pub context: HashMap<String, String>,
}

impl ValidationResult {
    pub fn valid(message: &str, tick: u64) -> Self {
        Self {
            is_valid: true,
            message: message.to_string(),
            errors: Vec::new(),
            warnings: Vec::new(),
            tick,
            context: HashMap::new(),
        }
    }

    pub fn invalid(message: &str, errors: Vec<ValidationError>, tick: u64) -> Self {
        Self {
            is_valid: false,
            message: message.to_string(),
            errors,
            warnings: Vec::new(),
            tick,
            context: HashMap::new(),
        }
    }

    pub fn with_warning(mut self, warning: ValidationWarning) -> Self {
        self.warnings.push(warning);
        self
    }

    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// Validation error types
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidStructure(String),
    MissingField(String),
    InvalidValue(String, String),
    ConflictingConditions(String),
    InvalidTimeConstraint(String),
    InvalidIdentityConstraint(String),
    InvalidVaultCondition(String),
    InvalidOperationRestriction(String),
    InvalidCustomConstraint(String),
    PolicyTooComplex(String),
    UnsupportedFeature(String),
}

impl ValidationError {
    pub fn message(&self) -> &str {
        match self {
            ValidationError::InvalidStructure(msg) => msg,
            ValidationError::MissingField(msg) => msg,
            ValidationError::InvalidValue(_, msg) => msg,
            ValidationError::ConflictingConditions(msg) => msg,
            ValidationError::InvalidTimeConstraint(msg) => msg,
            ValidationError::InvalidIdentityConstraint(msg) => msg,
            ValidationError::InvalidVaultCondition(msg) => msg,
            ValidationError::InvalidOperationRestriction(msg) => msg,
            ValidationError::InvalidCustomConstraint(msg) => msg,
            ValidationError::PolicyTooComplex(msg) => msg,
            ValidationError::UnsupportedFeature(msg) => msg,
        }
    }
}

/// Validation warning types
#[derive(Debug, Clone)]
pub enum ValidationWarning {
    PerformanceConcern(String),
    SecurityRecommendation(String),
    BestPractice(String),
    CompatibilityWarning(String),
}

impl ValidationWarning {
    pub fn message(&self) -> &str {
        match self {
            ValidationWarning::PerformanceConcern(msg) => msg,
            ValidationWarning::SecurityRecommendation(msg) => msg,
            ValidationWarning::BestPractice(msg) => msg,
            ValidationWarning::CompatibilityWarning(msg) => msg,
        }
    }
}

/// Validation context for policy checking
#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub token_id: String,
    pub policy_file: PolicyFile,
    /// Deterministic tick the caller wants this validation bound to
    pub current_tick: u64,
    pub parameters: HashMap<String, Vec<u8>>,
    pub validation_mode: ValidationMode,
}

/// Validation mode enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationMode {
    Strict,
    Permissive,
    Development,
    Production,
}

impl ValidationContext {
    pub fn new(token_id: &str, policy_file: &PolicyFile) -> Self {
        let (_, t) = dt::peek();
        Self {
            token_id: token_id.to_string(),
            policy_file: policy_file.clone(),
            current_tick: t,
            parameters: HashMap::new(),
            validation_mode: ValidationMode::Strict,
        }
    }

    pub fn with_mode(mut self, mode: ValidationMode) -> Self {
        self.validation_mode = mode;
        self
    }

    pub fn with_parameter(mut self, key: &str, value: Vec<u8>) -> Self {
        self.parameters.insert(key.to_string(), value);
        self
    }

    pub fn with_tick(mut self, tick: u64) -> Self {
        self.current_tick = tick;
        self
    }
}

/// Policy validator implementation
#[derive(Debug)]
pub struct PolicyValidator {
    max_complexity: u32,
    max_conditions: usize,
    max_roles: usize,
}

impl PolicyValidator {
    pub fn new() -> Self {
        Self {
            max_complexity: 1000,
            max_conditions: 50,
            max_roles: 20,
        }
    }

    pub fn with_limits(max_complexity: u32, max_conditions: usize, max_roles: usize) -> Self {
        Self {
            max_complexity,
            max_conditions,
            max_roles,
        }
    }

    #[allow(clippy::unused_async)]
    pub async fn validate_policy(
        &self,
        context: &ValidationContext,
    ) -> Result<ValidationResult, DsmError> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        self.validate_basic_structure(&context.policy_file, &mut errors, &mut warnings);
        self.validate_conditions(&context.policy_file.conditions, &mut errors, &mut warnings);
        self.validate_roles(&context.policy_file.roles, &mut errors, &mut warnings);
        self.validate_complexity(&context.policy_file, &mut errors, &mut warnings);
        self.validate_mode_specific(context, &mut errors, &mut warnings);

        let is_valid = errors.is_empty();
        let message = if is_valid {
            "Policy validation successful".to_string()
        } else {
            format!("Policy validation failed with {} errors", errors.len())
        };

        let mut result = if is_valid {
            ValidationResult::valid(&message, context.current_tick)
        } else {
            ValidationResult::invalid(&message, errors, context.current_tick)
        };

        for warning in warnings {
            result = result.with_warning(warning);
        }

        result = result
            .with_context("token_id", &context.token_id)
            .with_context("policy_name", &context.policy_file.name)
            .with_context("policy_version", &context.policy_file.version);

        Ok(result)
    }

    #[allow(clippy::unused_async)]
    pub async fn validate_token_metadata(
        &self,
        context: &ValidationContext,
        metadata: &TokenMetadata,
    ) -> Result<ValidationResult, DsmError> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Policy anchor in TokenMetadata must be a Base32-encoded 32-byte hash.
        if let Some(ref policy_anchor_str) = metadata.policy_anchor {
            // Remove "dsm:policy:" prefix if present
            let clean_policy_anchor_str = policy_anchor_str
                .strip_prefix("dsm:policy:")
                .unwrap_or(policy_anchor_str);

            match base32::decode(base32::Alphabet::Crockford, clean_policy_anchor_str) {
                Some(bytes) => {
                    if bytes.len() != 32 {
                        errors.push(ValidationError::InvalidValue(
                            "policy_anchor".to_string(),
                            format!("Policy anchor must decode to 32 bytes, got {}", bytes.len()),
                        ));
                    }
                }
                None => {
                    errors.push(ValidationError::InvalidValue(
                        "policy_anchor".to_string(),
                        "Policy anchor is not valid Base32".to_string(),
                    ));
                }
            }
        }

        self.validate_token_type_compatibility(&context.policy_file, metadata, &mut errors);
        self.validate_metadata_fields(&context.policy_file, metadata, &mut errors, &mut warnings);
        self.validate_owner_constraints(&context.policy_file, metadata, &mut errors);

        let is_valid = errors.is_empty();
        let message = if is_valid {
            "Token metadata validation successful".to_string()
        } else {
            format!(
                "Token metadata validation failed with {} errors",
                errors.len()
            )
        };

        let mut result = if is_valid {
            ValidationResult::valid(&message, context.current_tick)
        } else {
            ValidationResult::invalid(&message, errors, context.current_tick)
        };

        for warning in warnings {
            result = result.with_warning(warning);
        }

        Ok(result)
    }

    fn validate_basic_structure(
        &self,
        policy: &PolicyFile,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) {
        if policy.name.is_empty() {
            errors.push(ValidationError::MissingField(
                "Policy name is required".to_string(),
            ));
        }
        if policy.version.is_empty() {
            errors.push(ValidationError::MissingField(
                "Policy version is required".to_string(),
            ));
        }
        if policy.author.is_empty() {
            errors.push(ValidationError::MissingField(
                "Policy author is required".to_string(),
            ));
        }

        if !policy.version.is_empty() && !self.is_valid_version(&policy.version) {
            errors.push(ValidationError::InvalidValue(
                "version".to_string(),
                "Version must follow semantic versioning (e.g., 1.0.0)".to_string(),
            ));
        }

        // created_tick is optional in a deterministic/clockless system; warn if missing.
        if policy.created_tick == 0 {
            warnings.push(ValidationWarning::BestPractice(
                "Policy created_tick is unset (0). Consider setting a deterministic tick at creation."
                    .to_string(),
            ));
        }
    }

    fn validate_conditions(
        &self,
        conditions: &[PolicyCondition],
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) {
        if conditions.len() > self.max_conditions {
            errors.push(ValidationError::PolicyTooComplex(format!(
                "Too many conditions: {} > {}",
                conditions.len(),
                self.max_conditions
            )));
        }

        for (index, condition) in conditions.iter().enumerate() {
            match condition {
                PolicyCondition::IdentityConstraint {
                    allowed_identities,
                    allow_derived: _,
                } => {
                    if allowed_identities.is_empty() {
                        errors.push(ValidationError::InvalidIdentityConstraint(format!(
                            "Condition {index}: No allowed identities specified"
                        )));
                    }

                    let mut uniq = HashSet::new();
                    for identity in allowed_identities {
                        if !uniq.insert(identity) {
                            warnings.push(ValidationWarning::BestPractice(format!(
                                "Condition {index}: Duplicate identity: {identity}"
                            )));
                        }
                        if identity.is_empty() {
                            errors.push(ValidationError::InvalidIdentityConstraint(format!(
                                "Condition {index}: Empty identity string"
                            )));
                        }
                    }
                }

                PolicyCondition::VaultEnforcement { condition } => {
                    self.validate_vault_condition(condition, index, errors, warnings);
                }

                PolicyCondition::OperationRestriction { allowed_operations } => {
                    if allowed_operations.is_empty() {
                        errors.push(ValidationError::InvalidOperationRestriction(format!(
                            "Condition {index}: allowed_operations is empty"
                        )));
                    } else {
                        let mut uniq = HashSet::new();
                        for op in allowed_operations {
                            if op.is_empty() {
                                errors.push(ValidationError::InvalidOperationRestriction(format!(
                                    "Condition {index}: operation name cannot be empty"
                                )));
                            }
                            if !uniq.insert(op) {
                                warnings.push(ValidationWarning::BestPractice(format!(
                                    "Condition {index}: Duplicate operation: {op}"
                                )));
                            }
                        }
                    }
                }

                PolicyCondition::LogicalTimeConstraint { min_tick, max_tick } => {
                    if min_tick > max_tick {
                        errors.push(ValidationError::InvalidTimeConstraint(format!(
                            "Condition {index}: min_tick {min_tick} > max_tick {max_tick}"
                        )));
                    }
                }

                PolicyCondition::Custom {
                    constraint_type,
                    parameters,
                } => {
                    if constraint_type.is_empty() {
                        errors.push(ValidationError::InvalidCustomConstraint(format!(
                            "Condition {index}: Custom constraint type cannot be empty"
                        )));
                    }
                    if parameters.is_empty() {
                        warnings.push(ValidationWarning::BestPractice(format!(
                            "Condition {index}: Custom constraint has no parameters"
                        )));
                    }
                }

                PolicyCondition::EmissionsSchedule {
                    total_supply,
                    shard_depth,
                    schedule_steps,
                    initial_step_emissions: _,
                    initial_step_amount: _,
                } => {
                    if *total_supply == 0 {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "Total supply must be positive".to_string(),
                        ));
                    }
                    if *shard_depth == 0 || *shard_depth > 32 {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "Shard depth must be between 1 and 32".to_string(),
                        ));
                    }
                    if *schedule_steps == 0 {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "Schedule steps must be positive".to_string(),
                        ));
                    }
                }

                PolicyCondition::CreditBundlePolicy {
                    bundle_size,
                    debit_rule,
                    refill_rule,
                } => {
                    if *bundle_size == 0 {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "Bundle size must be positive".to_string(),
                        ));
                    }
                    if debit_rule.is_empty() {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "Debit rule cannot be empty".to_string(),
                        ));
                    }
                    if refill_rule.is_empty() {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "Refill rule cannot be empty".to_string(),
                        ));
                    }
                }

                PolicyCondition::BitcoinTapConstraint {
                    max_successor_depth,
                    min_vault_balance_sats,
                    dust_floor_sats,
                    min_confirmations,
                } => {
                    if *max_successor_depth == 0 {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "max_successor_depth must be positive".to_string(),
                        ));
                    }
                    if *dust_floor_sats == 0 {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "dust_floor_sats must be positive (Bitcoin consensus minimum)"
                                .to_string(),
                        ));
                    }
                    if *min_vault_balance_sats < *dust_floor_sats {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            format!(
                                "min_vault_balance_sats ({}) must be >= dust_floor_sats ({})",
                                min_vault_balance_sats, dust_floor_sats
                            ),
                        ));
                    }
                    if *min_confirmations == 0 {
                        errors.push(ValidationError::InvalidValue(
                            format!("Condition {index}"),
                            "min_confirmations must be positive".to_string(),
                        ));
                    }
                }
            }
        }

        self.check_condition_conflicts(conditions, errors);
    }

    fn validate_vault_condition(
        &self,
        vault_condition: &VaultCondition,
        condition_index: usize,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) {
        match vault_condition {
            VaultCondition::Hash(hash) => {
                if hash.is_empty() {
                    errors.push(ValidationError::InvalidVaultCondition(format!(
                        "Condition {condition_index}: Vault hash cannot be empty"
                    )));
                } else if hash.len() != 32 {
                    errors.push(ValidationError::InvalidVaultCondition(format!(
                        "Condition {condition_index}: Vault hash must be 32 bytes"
                    )));
                }
            }

            VaultCondition::MinimumBalance(balance) => {
                if *balance == 0 {
                    warnings.push(ValidationWarning::BestPractice(format!(
                        "Condition {condition_index}: Zero minimum balance is effectively no restriction"
                    )));
                }
            }

            VaultCondition::VaultType(vault_type) => {
                if vault_type.is_empty() {
                    errors.push(ValidationError::InvalidVaultCondition(format!(
                        "Condition {condition_index}: Vault type cannot be empty"
                    )));
                }
            }

            VaultCondition::SmartPolicy(policy_bytes) => {
                match crate::types::proto::SmartPolicy::decode(&policy_bytes[..]) {
                    Ok(policy) => {
                        if policy.clauses.is_empty() {
                            errors.push(ValidationError::InvalidVaultCondition(format!(
                            "Condition {condition_index}: SmartPolicy must have at least one clause"
                        )));
                        }
                        if policy.version == 0 {
                            warnings.push(ValidationWarning::BestPractice(format!(
                                "Condition {condition_index}: SmartPolicy version should be > 0"
                            )));
                        }
                    }
                    Err(e) => {
                        errors.push(ValidationError::InvalidVaultCondition(format!(
                            "Condition {condition_index}: Invalid SmartPolicy protobuf: {e}"
                        )));
                    }
                }
            }
        }
    }

    fn validate_roles(
        &self,
        roles: &[PolicyRole],
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) {
        if roles.len() > self.max_roles {
            errors.push(ValidationError::PolicyTooComplex(format!(
                "Too many roles: {} > {}",
                roles.len(),
                self.max_roles
            )));
        }

        let mut role_ids = HashSet::new();
        for (index, role) in roles.iter().enumerate() {
            if role.id.is_empty() {
                errors.push(ValidationError::MissingField(format!(
                    "Role {index}: Role ID is required"
                )));
            }
            if role.name.is_empty() {
                errors.push(ValidationError::MissingField(format!(
                    "Role {index}: Role name is required"
                )));
            }
            if !role.id.is_empty() && !role_ids.insert(&role.id) {
                errors.push(ValidationError::InvalidValue(
                    "role_id".to_string(),
                    format!("Role {index}: Duplicate role ID: {}", role.id),
                ));
            }
            if role.permissions.is_empty() {
                warnings.push(ValidationWarning::SecurityRecommendation(format!(
                    "Role {index}: Role has no permissions"
                )));
            }
        }
    }

    fn validate_complexity(
        &self,
        policy: &PolicyFile,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) {
        let score = self.calculate_complexity_score(policy);

        if score > self.max_complexity {
            errors.push(ValidationError::PolicyTooComplex(format!(
                "Policy complexity {} exceeds maximum {}",
                score, self.max_complexity
            )));
        } else if u64::from(score) * 5 > u64::from(self.max_complexity) * 4 {
            warnings.push(ValidationWarning::PerformanceConcern(format!(
                "High policy complexity: {score} (over 80% of limit)"
            )));
        } else if score > self.max_complexity / 2 {
            warnings.push(ValidationWarning::PerformanceConcern(format!(
                "Moderate policy complexity: {score}"
            )));
        }
    }

    fn calculate_complexity_score(&self, policy: &PolicyFile) -> u32 {
        let mut score = 10;
        score += policy.conditions.len() as u32 * 5;
        score += policy.roles.len() as u32 * 3;
        score += policy.metadata.len() as u32;

        for c in &policy.conditions {
            match c {
                PolicyCondition::Custom { .. } => score += 10,
                PolicyCondition::VaultEnforcement { .. } => score += 8,
                PolicyCondition::OperationRestriction { allowed_operations } => {
                    score += allowed_operations.len() as u32 * 2;
                }
                PolicyCondition::IdentityConstraint {
                    allowed_identities, ..
                } => {
                    score += allowed_identities.len() as u32;
                }
                _ => score += 2,
            }
        }

        score
    }

    fn validate_mode_specific(
        &self,
        context: &ValidationContext,
        _errors: &mut [ValidationError],
        warnings: &mut Vec<ValidationWarning>,
    ) {
        match context.validation_mode {
            ValidationMode::Production => {
                if context.policy_file.description.is_none() {
                    warnings.push(ValidationWarning::BestPractice(
                        "Policy description recommended in production".to_string(),
                    ));
                }
                if context.policy_file.conditions.is_empty() {
                    warnings.push(ValidationWarning::SecurityRecommendation(
                        "No policy conditions in production mode".to_string(),
                    ));
                }
            }
            ValidationMode::Development => {
                if context.policy_file.conditions.len() > 20 {
                    warnings.push(ValidationWarning::PerformanceConcern(
                        "Many conditions may impact development performance".to_string(),
                    ));
                }
            }
            ValidationMode::Strict => {
                // Strict mode: ensure policy is not “empty allow-all” unless explicitly intended.
                if context.policy_file.conditions.is_empty() && context.policy_file.roles.is_empty()
                {
                    warnings.push(ValidationWarning::SecurityRecommendation(
                        "Strict mode with no conditions/roles results in allow-all".to_string(),
                    ));
                }
            }
            ValidationMode::Permissive => {}
        }

        // If there are errors already, no extra action needed.
        if !_errors.is_empty() {
            // return;
        }
    }

    fn validate_token_type_compatibility(
        &self,
        _policy: &PolicyFile,
        _metadata: &TokenMetadata,
        _errors: &mut [ValidationError],
    ) {
        // Hook point for future hard restrictions. Kept permissive for now.
    }

    fn validate_metadata_fields(
        &self,
        _policy: &PolicyFile,
        _metadata: &TokenMetadata,
        _errors: &mut [ValidationError],
        _warnings: &mut [ValidationWarning],
    ) {
        // Hook point for required/typed metadata fields.
    }

    fn validate_owner_constraints(
        &self,
        _policy: &PolicyFile,
        _metadata: &TokenMetadata,
        _errors: &mut [ValidationError],
    ) {
        // Hook point for owner / issuer constraints.
    }

    fn check_condition_conflicts(
        &self,
        conditions: &[PolicyCondition],
        errors: &mut Vec<ValidationError>,
    ) {
        // Minimal, deterministic conflict detection:
        // - Multiple OperationRestriction conditions must have a non-empty intersection.
        let mut op_sets: Vec<HashSet<String>> = Vec::new();
        for c in conditions {
            if let PolicyCondition::OperationRestriction { allowed_operations } = c {
                let set: HashSet<String> = allowed_operations
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
                op_sets.push(set);
            }
        }
        if op_sets.len() >= 2 {
            let mut it = op_sets.into_iter();
            let mut inter = it.next().unwrap_or_default();
            for s in it {
                inter = inter.intersection(&s).cloned().collect();
            }
            if inter.is_empty() {
                errors.push(ValidationError::ConflictingConditions(
                    "OperationRestriction conditions have empty intersection (token becomes unusable)"
                        .to_string(),
                ));
            }
        }
    }

    fn is_valid_version(&self, version: &str) -> bool {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        parts.iter().all(|p| p.parse::<u32>().is_ok())
    }
}

impl Default for PolicyValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::policy_types::PolicyFile;

    #[tokio::test]
    async fn test_policy_validation_success() {
        let validator = PolicyValidator::new();
        let policy_file = PolicyFile::new("Test Policy", "1.0.0", "test_author");
        let context = ValidationContext::new("test_token", &policy_file)
            .with_mode(ValidationMode::Permissive);

        let result = validator.validate_policy(&context).await.unwrap();
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_policy_validation_missing_fields() {
        let validator = PolicyValidator::new();
        let policy_file = PolicyFile::new("", "", "");
        let context = ValidationContext::new("test_token", &policy_file);

        let result = validator.validate_policy(&context).await.unwrap();
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, ValidationError::MissingField(_))));
    }

    #[tokio::test]
    async fn test_policy_validation_invalid_version() {
        let validator = PolicyValidator::new();
        let policy_file = PolicyFile::new("Test Policy", "invalid_version", "test_author");
        let context = ValidationContext::new("test_token", &policy_file);

        let result = validator.validate_policy(&context).await.unwrap();
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, ValidationError::InvalidValue(_, _))));
    }
}
