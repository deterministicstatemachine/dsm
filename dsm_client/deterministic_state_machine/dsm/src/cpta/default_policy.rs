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
        allowed_operations: vec!["transfer".to_string()],
    });

    // Minimal metadata (no wall-clock fields)
    policy
        .add_metadata("token_id", token_id)
        .add_metadata("is_default_policy", "true");

    // Roles
    policy.add_role(PolicyRole {
        id: "owner".to_string(),
        name: "Token Owner".to_string(),
        permissions: vec!["transfer".to_string()],
    });

    policy.add_role(PolicyRole {
        id: "user".to_string(),
        name: "Token User".to_string(),
        permissions: vec![
            "transfer".to_string(),
            "lock_token".to_string(),
            "unlock_token".to_string(),
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
                vec!["transfer".to_string()]
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
        allowed_operations: vec!["transfer".to_string()],
    });

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_default_policy_basic_fields() {
        let policy = generate_default_policy("tok-1", "MyToken", "creator-abc").unwrap();

        assert_eq!(policy.name, "Default Policy for MyToken");
        assert_eq!(policy.author, "creator-abc");
        assert!(policy.description.as_ref().unwrap().contains("tok-1"));
    }

    #[test]
    fn test_generate_default_policy_conditions() {
        let policy = generate_default_policy("tok-1", "MyToken", "creator-abc").unwrap();

        let has_identity = policy.conditions.iter().any(|c| {
            matches!(
                c,
                PolicyCondition::IdentityConstraint {
                    allowed_identities,
                    allow_derived: true,
                } if allowed_identities == &["creator-abc".to_string()]
            )
        });
        assert!(
            has_identity,
            "default policy must include identity constraint for creator"
        );

        let has_ops = policy.conditions.iter().any(|c| {
            matches!(
                c,
                PolicyCondition::OperationRestriction { allowed_operations }
                if allowed_operations == &["transfer".to_string()]
            )
        });
        assert!(
            has_ops,
            "default policy must restrict operations to transfer"
        );
    }

    #[test]
    fn test_generate_default_policy_roles() {
        let policy = generate_default_policy("tok-1", "MyToken", "creator-abc").unwrap();

        assert_eq!(policy.roles.len(), 2);
        assert_eq!(policy.roles[0].id, "owner");
        assert_eq!(policy.roles[1].id, "user");
        assert!(policy.roles[1]
            .permissions
            .contains(&"lock_token".to_string()));
        assert!(policy.roles[1]
            .permissions
            .contains(&"unlock_token".to_string()));
    }

    #[test]
    fn test_generate_default_policy_metadata() {
        let policy = generate_default_policy("tok-42", "TestToken", "alice").unwrap();

        assert_eq!(policy.metadata.get("token_id").unwrap(), "tok-42");
        assert_eq!(policy.metadata.get("is_default_policy").unwrap(), "true");
    }

    #[test]
    fn test_specialized_policy_time_locked_rejected() {
        let params = HashMap::new();
        let result = generate_specialized_policy("t1", "T", "c", "TimeLocked", &params);

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Time-based policies are not supported"));
    }

    #[test]
    fn test_specialized_policy_unknown_type_rejected() {
        let params = HashMap::new();
        let result = generate_specialized_policy("t1", "T", "c", "Bogus", &params);

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Unknown policy type"));
    }

    #[test]
    fn test_specialized_policy_identity_bound_custom_ids() {
        let mut params = HashMap::new();
        params.insert("allowed_identities".to_string(), "alice, bob".to_string());
        params.insert("allow_derived".to_string(), "true".to_string());

        let policy =
            generate_specialized_policy("t1", "TestToken", "creator", "IdentityBound", &params)
                .unwrap();

        assert!(policy.name.contains("IdentityBound"));

        let id_constraint = policy
            .conditions
            .iter()
            .find(|c| matches!(c, PolicyCondition::IdentityConstraint { .. }));
        match id_constraint {
            Some(PolicyCondition::IdentityConstraint {
                allowed_identities,
                allow_derived,
            }) => {
                assert_eq!(
                    allowed_identities,
                    &["alice".to_string(), "bob".to_string()]
                );
                assert!(*allow_derived);
            }
            _ => panic!("expected IdentityConstraint"),
        }
    }

    #[test]
    fn test_specialized_policy_identity_bound_defaults() {
        let params = HashMap::new();
        let policy =
            generate_specialized_policy("t1", "T", "creator", "IdentityBound", &params).unwrap();

        let id_constraint = policy
            .conditions
            .iter()
            .find(|c| matches!(c, PolicyCondition::IdentityConstraint { .. }));
        match id_constraint {
            Some(PolicyCondition::IdentityConstraint {
                allowed_identities,
                allow_derived,
            }) => {
                assert_eq!(allowed_identities, &["creator".to_string()]);
                assert!(!*allow_derived);
            }
            _ => panic!("expected IdentityConstraint"),
        }
    }

    #[test]
    fn test_specialized_policy_restricted_operations() {
        let mut params = HashMap::new();
        params.insert(
            "allowed_operations".to_string(),
            "Transfer, Burn".to_string(),
        );

        let policy =
            generate_specialized_policy("t1", "T", "c", "RestrictedOperations", &params).unwrap();

        let ops_condition = policy
            .conditions
            .iter()
            .find(|c| matches!(c, PolicyCondition::OperationRestriction { .. }));
        match ops_condition {
            Some(PolicyCondition::OperationRestriction { allowed_operations }) => {
                assert_eq!(
                    allowed_operations,
                    &["burn".to_string(), "transfer".to_string()]
                );
            }
            _ => panic!("expected OperationRestriction"),
        }
    }

    #[test]
    fn test_specialized_policy_restricted_operations_defaults_to_transfer() {
        let params = HashMap::new();
        let policy =
            generate_specialized_policy("t1", "T", "c", "RestrictedOperations", &params).unwrap();

        let ops_condition = policy
            .conditions
            .iter()
            .find(|c| matches!(c, PolicyCondition::OperationRestriction { .. }));
        match ops_condition {
            Some(PolicyCondition::OperationRestriction { allowed_operations }) => {
                assert_eq!(allowed_operations, &["transfer".to_string()]);
            }
            _ => panic!("expected OperationRestriction"),
        }
    }

    #[test]
    fn test_create_policy_basic() {
        let params = PolicyParameters {
            mode: TransactionMode::Bilateral,
            verification: VerificationType::Standard,
            name: "Custom".to_string(),
            version: "2.0".to_string(),
            author: "bob".to_string(),
        };
        let policy = create_policy(params).unwrap();

        assert_eq!(policy.name, "Custom");
        assert_eq!(policy.version, "2.0");
        assert_eq!(policy.author, "bob");
        assert!(!policy.conditions.is_empty());
    }
}
