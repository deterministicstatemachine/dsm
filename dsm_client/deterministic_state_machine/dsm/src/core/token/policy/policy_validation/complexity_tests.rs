#[cfg(test)]
mod tests {
    use crate::core::token::policy::policy_validation::{PolicyValidator, ValidationWarning};
    use crate::types::policy_types::PolicyFile;

    // Helper to create a dummy policy with a specific complexity score.
    // Base score is 10.
    // Each metadata entry adds 1.
    fn create_policy_with_score(target_score: u32) -> PolicyFile {
        let mut policy = PolicyFile::new("Test Policy", "1.0.0", "tester");

        let mut current_score = 10; // Base score

        // Add metadata to reach target score (1 point each)
        while current_score < target_score {
            policy
                .metadata
                .insert(format!("key_{}", current_score), "value".to_string());
            current_score += 1;
        }

        policy
    }

    #[tokio::test]
    async fn test_complexity_warning_threshold_exact_80_percent() {
        // Max complexity 20. 80% is 16.
        // Threshold check is: score * 5 > max * 4
        // 16 * 5 = 80. 20 * 4 = 80. 80 > 80 is FALSE.
        // So 16 should NOT trigger warning.

        let validator = PolicyValidator::with_limits(20, 100, 100);
        let policy = create_policy_with_score(16);
        let context =
            crate::core::token::policy::policy_validation::ValidationContext::new("token", &policy);

        let result = validator
            .validate_policy(&context)
            .await
            .expect("Validation failed");

        // Check that we do NOT have the high complexity warning
        let has_warning = result.warnings.iter().any(|w|
            matches!(w, ValidationWarning::PerformanceConcern(msg) if msg.contains("exceeds 80%"))
        );

        assert!(!has_warning, "Should not warn at exactly 80% (16/20)");
    }

    #[tokio::test]
    async fn test_complexity_warning_threshold_above_80_percent() {
        // Max complexity 20. 80% is 16.
        // 17 * 5 = 85. 20 * 4 = 80. 85 > 80 is TRUE.
        // So 17 SHOULD trigger warning.

        let validator = PolicyValidator::with_limits(20, 100, 100);
        let policy = create_policy_with_score(17);
        let context =
            crate::core::token::policy::policy_validation::ValidationContext::new("token", &policy);

        let result = validator
            .validate_policy(&context)
            .await
            .expect("Validation failed");

        let has_warning = result.warnings.iter().any(|w|
            matches!(w, ValidationWarning::PerformanceConcern(msg) if msg.contains("exceeds 80%"))
        );

        assert!(has_warning, "Should warn above 80% (17/20)");
    }

    #[tokio::test]
    async fn test_complexity_integer_math_precision() {
        // Test a case where float math might have been ambiguous or different.
        // Max 100. 80% is 80.
        // 80 should not warn. 81 should warn.

        let validator = PolicyValidator::with_limits(100, 100, 100);

        // 80
        let policy_80 = create_policy_with_score(80);
        let context_80 = crate::core::token::policy::policy_validation::ValidationContext::new(
            "token", &policy_80,
        );
        let result_80 = validator
            .validate_policy(&context_80)
            .await
            .expect("Validation failed");
        assert!(!result_80.warnings.iter().any(|w| matches!(w, ValidationWarning::PerformanceConcern(msg) if msg.contains("exceeds 80%"))));

        // 81
        let policy_81 = create_policy_with_score(81);
        let context_81 = crate::core::token::policy::policy_validation::ValidationContext::new(
            "token", &policy_81,
        );
        let result_81 = validator
            .validate_policy(&context_81)
            .await
            .expect("Validation failed");
        assert!(result_81.warnings.iter().any(|w| matches!(w, ValidationWarning::PerformanceConcern(msg) if msg.contains("exceeds 80%"))));
    }

    #[tokio::test]
    async fn test_policy_complexity_exceeds_limit() {
        // Test that exceeding the absolute limit returns an error (not just a warning).
        // Max 50.
        let validator = PolicyValidator::with_limits(50, 100, 100);

        // Create policy with score 51
        let policy = create_policy_with_score(51);
        let context =
            crate::core::token::policy::policy_validation::ValidationContext::new("token", &policy);

        let result = validator
            .validate_policy(&context)
            .await
            .expect("Validation should complete");

        assert!(
            !result.is_valid,
            "Should be invalid when complexity exceeds limit"
        );
        // Check that we have a PolicyTooComplex error
        // We can't easily check the variant because it's wrapped, but we know it's invalid.
    }

    #[tokio::test]
    async fn test_policy_complexity_within_limit_high() {
        // Test a policy that is high complexity (warns) but valid (no error).
        // Max 100. Score 90.
        let validator = PolicyValidator::with_limits(100, 100, 100);
        let policy = create_policy_with_score(90);
        let context =
            crate::core::token::policy::policy_validation::ValidationContext::new("token", &policy);

        let result = validator.validate_policy(&context).await;

        assert!(
            result.is_ok(),
            "Should be valid even if high complexity (as long as < max)"
        );
        let result = result.unwrap();
        assert!(result.is_valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::PerformanceConcern(_))));
    }
}
