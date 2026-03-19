#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use crate::cpta::default_policy::{
        generate_default_policy, generate_specialized_policy,
    };
    use crate::cpta::policy_store::PolicyStore;
    use crate::types::policy_types::{PolicyAnchor, PolicyCondition, PolicyFile, PolicyRole};
    use crate::core::token::policy::{PolicyEnforcer, PolicyCache};
    use crate::types::error::DsmError;
    use crate::types::operations::{Operation, TransactionMode, VerificationType};
    use crate::types::token_types::Balance;

    #[derive(Debug, Default)]
    struct MockPolicyPersistence {
        storage: Mutex<HashMap<PolicyAnchor, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl crate::cpta::policy_store::PolicyPersistence for MockPolicyPersistence {
        async fn read(&self, anchor: &PolicyAnchor) -> Result<Vec<u8>, DsmError> {
            let storage = self.storage.lock().unwrap();
            storage.get(anchor).cloned().ok_or_else(|| DsmError::not_found("Policy", None))
        }
        async fn write(&self, anchor: &PolicyAnchor, data: &[u8]) -> Result<(), DsmError> {
            let mut storage = self.storage.lock().unwrap();
            storage.insert(anchor.clone(), data.to_vec());
            Ok(())
        }
        async fn delete(&self, anchor: &PolicyAnchor) -> Result<(), DsmError> {
            let mut storage = self.storage.lock().unwrap();
            storage.remove(anchor);
            Ok(())
        }
        async fn list_anchors(&self) -> Result<Vec<PolicyAnchor>, DsmError> {
            let storage = self.storage.lock().unwrap();
            Ok(storage.keys().cloned().collect())
        }
    }

    // No time-based semantics in a clockless system

    #[tokio::test]
    async fn test_policy_anchor_creation_and_verification() {
        // Create a policy file
        let mut policy = PolicyFile::new("Test Policy", "1.0", "test_creator");
        // Add a non-time condition for anchor testing
        policy.add_condition(PolicyCondition::OperationRestriction { allowed_operations: vec!["transfer".into(), "mint".into()] });

        // Generate anchor
        let anchor = policy.generate_anchor().expect("Failed to generate anchor");

        // Verify the anchor's properties
        assert_eq!(anchor.0.len(), 32, "CTPA anchor should be exactly 32 bytes");

        // Verify canonical bytes are non-empty and stable for identical content
        let canonical = policy.canonical_bytes();
        assert!(!canonical.is_empty(), "Canonical bytes must not be empty");

        // Cloning preserves content deterministically; anchors should match
        let cloned = policy.clone();
        let cloned_anchor = cloned
            .generate_anchor()
            .expect("Failed to generate anchor from cloned policy");
        assert_eq!(
            anchor, cloned_anchor,
            "Anchors should be identical for cloned policy (deterministic encoding)"
        );

        // Verify that anchor Base32 Crockford representation roundtrips
        let base32_str = anchor.to_base32();
        let from_base32 = PolicyAnchor::from_base32(&base32_str).expect("Failed to parse base32");
        assert_eq!(anchor, from_base32, "Anchor should match after base32 roundtrip");
    }

    #[tokio::test]
    async fn test_policy_store_operations() {
        // Create a policy store
        let store = PolicyStore::new(Arc::new(MockPolicyPersistence::default()));

        // Create a policy
        let policy = generate_default_policy("TEST_TOKEN", "Test Token", "test_creator")
            .expect("Failed to generate default policy");

        // Store the policy
        let anchor = store
            .store_policy(&policy)
            .await
            .expect("Failed to store policy");

        // Retrieve the policy
        let retrieved = store
            .get_policy(&anchor)
            .await
            .expect("Failed to retrieve policy");

        // Verify retrieved policy matches original
        assert_eq!(
            retrieved.file.name, policy.name,
            "Retrieved policy name should match original"
        );
        assert_eq!(
            retrieved.file.conditions.len(),
            policy.conditions.len(),
            "Retrieved policy should have same number of conditions"
        );

        // Test policy caching
        let cached = store.get_from_cache(&anchor);
        assert!(cached.is_some(), "Policy should be cached after retrieval");

        // Test clearing cache
        store.clear_cache();
        let cached_after_clear = store.get_from_cache(&anchor);
        assert!(cached_after_clear.is_none(), "Cache should be empty after clear");

        // Verify the policy can still be retrieved from storage
        let retrieved_again = store
            .get_policy(&anchor)
            .await
            .expect("Failed to retrieve policy after cache clear");
        assert_eq!(
            retrieved_again.file.name, policy.name,
            "Policy should still be retrievable after cache clear"
        );
    }

    #[tokio::test]
    async fn test_policy_enforcement_denies_when_operation_not_allowed() {
        let cache = std::sync::Arc::new(PolicyCache::new());
        let enforcer = PolicyEnforcer::new(cache);

        let mut policy = PolicyFile::new("Restricted Ops Policy", "1.0", "test_creator");
        policy.add_condition(PolicyCondition::OperationRestriction { allowed_operations: vec![] });

        let anchor = policy
            .generate_anchor()
            .expect("Failed to generate anchor");
        let token_policy = crate::types::policy_types::TokenPolicy {
            file: policy,
            anchor,
            verified: true,
            last_verified: 1,
        };

        let ctx = std::collections::HashMap::new();
        let res = enforcer.enforce_policy(&token_policy, "transfer", &ctx).await.expect("enforcement");
        assert!(!res.allowed, "Operation should be denied by restriction");
    }

    #[tokio::test]
    async fn test_default_policy_generation() {
        // Generate a default policy
        let policy = generate_default_policy("TEST_TOKEN", "Test Token", "test_creator")
            .expect("Failed to generate default policy");

        // Verify default policy properties (no time-based conditions)
        assert!(
            policy
                .conditions
                .iter()
                .any(|c| matches!(c, PolicyCondition::IdentityConstraint { .. })),
            "Default policy should include an identity constraint"
        );

        assert!(
            policy.conditions.iter().any(|c| matches!(
                c,
                PolicyCondition::IdentityConstraint { allowed_identities, .. }
                if allowed_identities.contains(&"test_creator".to_string())
            )),
            "Default policy should include creator in allowed identities"
        );

        assert!(
            policy.conditions.iter().any(|c| matches!(
                c,
                PolicyCondition::OperationRestriction { allowed_operations }
                if allowed_operations.iter().any(|op| matches!(op, Operation::Transfer { .. }))
            )),
            "Default policy should allow transfers"
        );
    }

    #[tokio::test]
    async fn test_specialized_policy_generation() {
        // Time-locked specialized policy is unsupported
        let mut params = HashMap::new();
        params.insert("unlock_time".to_string(), "9999999999".to_string());
        let result = generate_specialized_policy(
            "TIME_LOCKED",
            "Time Locked Token",
            "test_creator",
            "TimeLocked",
            &params,
        );
        assert!(result.is_err(), "TimeLocked policy should be rejected");

        // Test invalid policy type still yields a validation error
        let result = generate_specialized_policy(
            "INVALID",
            "Invalid Policy",
            "test_creator",
            "NonexistentType",
            &params,
        );

        assert!(result.is_err(), "Should fail with non-existent policy type");
        assert!(
            matches!(result, Err(DsmError::Validation { .. })),
            "Should return validation error for invalid policy type"
        );
    }

    #[tokio::test]
    async fn test_policy_idempotency() {
        // In a deterministic, clockless system: identical inputs => identical anchors.
        let policy1 = generate_default_policy("IDEMPOTENCY_TEST", "Idempotency Test", "test_creator")
            .expect("Failed to generate first policy");

        let policy2 = generate_default_policy("IDEMPOTENCY_TEST", "Idempotency Test", "test_creator")
            .expect("Failed to generate second policy");

        let anchor1 = policy1
            .generate_anchor()
            .expect("Failed to generate first anchor");
        let anchor2 = policy2
            .generate_anchor()
            .expect("Failed to generate second anchor");

        // Expect equality (no hidden wall-clock salt)
        assert_eq!(
            anchor1, anchor2,
            "Identical policy instances should produce identical anchors in a clockless system"
        );

        // Cloning preserves identical encoding
        let policy3 = policy1.clone();
        let anchor3 = policy3
            .generate_anchor()
            .expect("Failed to generate third anchor");

        assert_eq!(anchor1, anchor3, "Cloned policy should have identical anchor");
    }

    #[tokio::test]
    async fn test_policy_role_permissions() {
        let mut policy = PolicyFile::new("Role Test Policy", "1.0", "test_creator");

        // Add roles with different permissions
        policy.add_role(PolicyRole {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            permissions: vec![Operation::Transfer {
                to_device_id: Vec::new(),
                amount: Balance::zero(),
                token_id: String::new(),
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: Vec::new(),
                to: String::new(),
                message: String::new(),
            }],
        });

        policy.add_role(PolicyRole {
            id: "user".to_string(),
            name: "User".to_string(),
            permissions: vec![Operation::Transfer {
                to_device_id: Vec::new(),
                amount: Balance::zero(),
                token_id: String::new(),
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: Vec::new(),
                to: String::new(),
                message: String::new(),
            }],
        });

        // Verify roles were added correctly
        assert_eq!(policy.roles.len(), 2, "Policy should have 2 roles");

        let admin_role = policy
            .roles
            .iter()
            .find(|r| r.id == "admin")
            .expect("Admin role not found");
        let user_role = policy
            .roles
            .iter()
            .find(|r| r.id == "user")
            .expect("User role not found");

        assert!(
            admin_role
                .permissions
                .iter()
                .any(|op| matches!(op, Operation::Transfer { .. })),
            "Admin should have Transfer permission"
        );
        assert!(
            user_role
                .permissions
                .iter()
                .any(|op| matches!(op, Operation::Transfer { .. })),
            "User should have Transfer permission"
        );
        assert!(
            !user_role
                .permissions
                .iter()
                .any(|op| matches!(op, Operation::Mint { .. })),
            "User should not have Mint permission"
        );
    }

    #[test]
    fn test_transfer_policy() {
        let mut policy = PolicyFile::new("Test Policy", "1.0", "test_creator");
        policy.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec![Operation::Transfer {
                to_device_id: b"any".to_vec(),
                amount: Balance::zero(),
                token_id: String::new(),
                mode: TransactionMode::Bilateral,
                nonce: vec![],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: Vec::new(),
                to: String::new(),
                message: String::new(),
            }],
        });

        // Assert operations are allowed correctly
        assert!(policy.conditions.iter().any(|c| match c {
            PolicyCondition::OperationRestriction { allowed_operations } => {
                allowed_operations.iter().any(|op| matches!(op, Operation::Transfer { .. }))
            }
            _ => false,
        }), "Transfer must be allowed by OperationRestriction");
    }
}