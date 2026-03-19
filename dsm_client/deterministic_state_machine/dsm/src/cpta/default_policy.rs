//! Default Token Policy Generator
//!
//! Provides a standardized default policy for tokens when no custom policy
//! is specified at creation time. Every token in the DSM system requires a
//! Content-Addressed Token Policy Anchor (CTPA).
//!
//! NOTE: Clockless protocol: no time-based conditions are generated or enforced.

use std::collections::HashMap;

use crate::types::{
    error::DsmError,
    operations::{TransactionMode, VerificationType},
    policy_types::{PolicyCondition, PolicyFile, PolicyRole},
};
// No time utilities required

pub struct PolicyParameters {
    pub mode: TransactionMode,
    pub verification: VerificationType,
    pub name: String,
    pub version: String,
    pub author: String,
}

/// Represents the default policy configuration
#[derive(Default)]
pub struct DefaultPolicy {}

// No time parsing required

pub fn generate_default_policy(
    token_id: &str,
    token_name: &str,
    creator_id: &str,
) -> Result<PolicyFile, DsmError> {
    // Create basic policy file
    let mut policy = PolicyFile::new(
        &format!("Default Policy for {token_name}"),
        "1.0",
        creator_id,
    );

    // Add description
    policy.description = Some(format!(
        "Default policy for token {token_id} ({token_name}). Created automatically at token genesis."
    ));

    // Allow creator to control the token
    policy.add_condition(PolicyCondition::IdentityConstraint {
        allowed_identities: vec![creator_id.to_string()],
        allow_derived: true,
    });

    // Basic operation restrictions (allow transfer by default)
    policy.add_condition(PolicyCondition::OperationRestriction {
        allowed_operations: vec!["Transfer".to_string()],
    });

    // Minimal metadata (no wall-clock fields)
    policy
        .add_metadata("token_id", token_id)
        .add_metadata("is_default_policy", "true");

    // Roles
    policy.add_role(PolicyRole {
        id: "owner".to_string(),
        name: "Token Owner".to_string(),
        permissions: vec!["Transfer".to_string()],
    });

    policy.add_role(PolicyRole {
        id: "user".to_string(),
        name: "Token User".to_string(),
        permissions: vec![
            "Transfer".to_string(),
            "LockToken".to_string(),
            "UnlockToken".to_string(),
        ],
    });

    Ok(policy)
}

/// Generate a specialized token policy file
///
/// No time-based specialized policies supported.
pub fn generate_specialized_policy(
    token_id: &str,
    token_name: &str,
    creator_id: &str,
    policy_type: &str,
    params: &HashMap<String, String>,
) -> Result<PolicyFile, DsmError> {
    // Start with default policy
    let mut policy = generate_default_policy(token_id, token_name, creator_id)?;

    // Override policy name and description
    policy.name = format!("{policy_type} Policy for {token_name}");
    policy.description = Some(format!(
        "Specialized {policy_type} policy for token {token_id} ({token_name}). Created with custom parameters."
    ));

    match policy_type {
        "TimeLocked" => {
            return Err(DsmError::invalid_operation(
                "Time-based policies are not supported",
            ));
        }

        "IdentityBound" => {
            // Allowed identities (comma-separated)
            let allowed_identities = if let Some(ids) = params.get("allowed_identities") {
                ids.split(',').map(|s| s.trim().to_string()).collect()
            } else {
                vec![creator_id.to_string()]
            };

            // Allow derived identities?
            let allow_derived = params
                .get("allow_derived")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            // Replace default identity constraint
            policy
                .conditions
                .retain(|c| !matches!(c, PolicyCondition::IdentityConstraint { .. }));
            policy.add_condition(PolicyCondition::IdentityConstraint {
                allowed_identities,
                allow_derived,
            });

            policy
                .add_metadata("policy_type", "identity_bound")
                .add_metadata("allow_derived", &allow_derived.to_string());
        }

        "RestrictedOperations" => {
            // Allowed operations (comma-separated)
            let allowed_ops: Vec<String> = if let Some(ops) = params.get("allowed_operations") {
                ops.split(',').map(|s| s.trim().to_string()).collect()
            } else {
                // Default to transfer-only if not specified
                vec!["Transfer".to_string()]
            };

            // Replace default operation restrictions
            policy
                .conditions
                .retain(|c| !matches!(c, PolicyCondition::OperationRestriction { .. }));
            policy.add_condition(PolicyCondition::OperationRestriction {
                allowed_operations: allowed_ops,
            });

            policy.add_metadata("policy_type", "restricted_operations");
        }

        _ => {
            return Err(DsmError::invalid_operation(format!(
                "Unknown policy type: {policy_type}"
            )));
        }
    }

    Ok(policy)
}

pub fn create_policy(params: PolicyParameters) -> Result<PolicyFile, DsmError> {
    // Create basic policy file
    let mut policy = PolicyFile::new(&params.name, &params.version, &params.author);

    // Add verification/operation condition driven by parameters
    policy.add_condition(PolicyCondition::OperationRestriction {
        allowed_operations: vec!["Transfer".to_string()],
    });

    Ok(policy)
}
