//! Integration tests for DeTFi example specifications.
//!
//! Validates that every YAML spec in `examples/detfi/` parses correctly
//! through the dsm-gen schema and generates valid code in all 4 languages.

use dsm_gen::generators::kotlin::KotlinGenerator;
use dsm_gen::generators::rust_gen::RustGenerator;
use dsm_gen::generators::swift::SwiftGenerator;
use dsm_gen::generators::typescript::TypeScriptGenerator;
use dsm_gen::generators::CodeGenerator;
use dsm_gen::schema::{DsmSpecification, FulfillmentConditionSpec};
use std::path::PathBuf;

// ------------------------------------------------------------------
// Path helpers
// ------------------------------------------------------------------

fn detfi_vault_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/detfi/vaults")
        .join(name)
}

fn detfi_policy_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/detfi/policies")
        .join(name)
}

fn load_spec(path: &PathBuf) -> DsmSpecification {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    serde_yaml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()))
}

// ------------------------------------------------------------------
// Vault parse tests
// ------------------------------------------------------------------

#[test]
fn test_simple_escrow_parses() {
    let spec = load_spec(&detfi_vault_path("01-simple-escrow.yaml"));
    match spec {
        DsmSpecification::Vault(v) => {
            assert_eq!(v.name, "SimpleEscrow");
            assert_eq!(v.version, "1.0.0");

            // Fulfillment must be Payment
            match &v.fulfillment_condition {
                FulfillmentConditionSpec::Payment(p) => {
                    assert_eq!(p.amount, 500);
                    assert_eq!(p.token_id, "DSM");
                    assert!(!p.recipient.is_empty());
                    assert!(!p.verification_state.is_empty());
                }
                other => panic!("Expected Payment, got {other:?}"),
            }

            // Assets
            assert_eq!(v.assets.len(), 1);
            assert_eq!(v.assets[0].asset_id, "DSM");
            assert_eq!(v.assets[0].amount, 500);

            // Tick lock (clockless)
            let Some(tl) = v.tick_lock.as_ref() else { panic!("tick_lock required") };
            assert_eq!(tl.duration_iterations, 14400);

            // Recovery
            let Some(rec) = v.recovery.as_ref() else { panic!("recovery required") };
            match &rec.mechanism {
                dsm_gen::schema::RecoveryMechanism::SocialRecovery {
                    trustees,
                    threshold,
                } => {
                    assert_eq!(trustees.len(), 3);
                    assert_eq!(*threshold, 2);
                }
                other => panic!("Expected SocialRecovery, got {other:?}"),
            }
        }
        _ => panic!("Expected Vault spec"),
    }
}

#[test]
fn test_bitcoin_backed_vault_parses() {
    let spec = load_spec(&detfi_vault_path("02-bitcoin-backed-vault.yaml"));
    match spec {
        DsmSpecification::Vault(v) => {
            assert_eq!(v.name, "BitcoinBackedVault");

            match &v.fulfillment_condition {
                FulfillmentConditionSpec::BitcoinHtlc(h) => {
                    assert!(!h.hash_lock.is_empty());
                    assert!(!h.refund_hash_lock.is_empty());
                    assert_eq!(h.refund_iterations, 1000);
                    assert!(!h.bitcoin_pubkey.is_empty());
                    assert_eq!(h.expected_btc_amount_sats, 100_000);
                    assert!(matches!(h.network, dsm_gen::schema::BitcoinNetwork::Testnet));
                    assert_eq!(h.min_confirmations, 100);
                }
                other => panic!("Expected BitcoinHtlc, got {other:?}"),
            }

            // No recovery — HTLC has its own refund path
            assert!(v.recovery.is_none());
        }
        _ => panic!("Expected Vault spec"),
    }
}

#[test]
fn test_conditional_multisig_parses() {
    let spec = load_spec(&detfi_vault_path("03-conditional-multisig.yaml"));
    match spec {
        DsmSpecification::Vault(v) => {
            assert_eq!(v.name, "ConditionalMultiSigVault");

            // Must be And with exactly 2 conditions
            match &v.fulfillment_condition {
                FulfillmentConditionSpec::And(and) => {
                    assert_eq!(and.conditions.len(), 2);

                    // First: MultiSignature
                    match &and.conditions[0] {
                        FulfillmentConditionSpec::MultiSignature(ms) => {
                            assert_eq!(ms.public_keys.len(), 3);
                            assert_eq!(ms.threshold, 2);
                        }
                        other => panic!("Expected MultiSignature as first And condition, got {other:?}"),
                    }

                    // Second: CryptoCondition
                    match &and.conditions[1] {
                        FulfillmentConditionSpec::CryptoCondition(cc) => {
                            assert!(!cc.condition_hash.is_empty());
                            assert!(!cc.public_params.is_empty());
                        }
                        other => panic!("Expected CryptoCondition as second And condition, got {other:?}"),
                    }
                }
                other => panic!("Expected And, got {other:?}"),
            }

            // Two assets
            assert_eq!(v.assets.len(), 2);

            // Tick lock with release_to_recipient
            let Some(tl) = v.tick_lock.as_ref() else { panic!("tick_lock required") };
            assert_eq!(tl.duration_iterations, 100_000);

            // Recovery present
            assert!(v.recovery.is_some());
        }
        _ => panic!("Expected Vault spec"),
    }
}

#[test]
fn test_oracle_attested_release_parses() {
    let spec = load_spec(&detfi_vault_path("04-oracle-attested-release.yaml"));
    match spec {
        DsmSpecification::Vault(v) => {
            assert_eq!(v.name, "OracleAttestedRelease");

            // Must be Or with CryptoCondition + StateReference
            match &v.fulfillment_condition {
                FulfillmentConditionSpec::Or(or) => {
                    assert_eq!(or.conditions.len(), 2);

                    match &or.conditions[0] {
                        FulfillmentConditionSpec::CryptoCondition(_) => {}
                        other => panic!("Expected CryptoCondition, got {other:?}"),
                    }

                    match &or.conditions[1] {
                        FulfillmentConditionSpec::StateReference(sr) => {
                            assert_eq!(sr.reference_states.len(), 2);
                            assert!(!sr.parameters.is_empty());
                        }
                        other => panic!("Expected StateReference, got {other:?}"),
                    }
                }
                other => panic!("Expected Or, got {other:?}"),
            }

            // Tick lock with burn action
            let Some(tl) = v.tick_lock.as_ref() else { panic!("tick_lock required") };
            assert_eq!(tl.duration_iterations, 200_000);
        }
        _ => panic!("Expected Vault spec"),
    }
}

// ------------------------------------------------------------------
// Policy parse tests
// ------------------------------------------------------------------

#[test]
fn test_stablecoin_policy_parses() {
    let spec = load_spec(&detfi_policy_path("01-stablecoin-transfer.yaml"));
    match spec {
        DsmSpecification::Policy(p) => {
            assert_eq!(p.name, "StablecoinTransferPolicy");
            assert_eq!(p.rules.len(), 4);

            // Verify rule names are unique
            let names: Vec<&str> = p.rules.iter().map(|r| r.name.as_str()).collect();
            assert_eq!(names.len(), 4);
            assert!(names.contains(&"jurisdiction_block"));
            assert!(names.contains(&"high_value_review"));
            assert!(names.contains(&"standard_transfer_limit"));
            assert!(names.contains(&"off_hours_delay"));

            // Highest priority rule is the deny
            let Some(highest) = p.rules.iter().max_by_key(|r| r.priority) else { panic!("rules must not be empty") };
            assert_eq!(highest.name, "jurisdiction_block");
        }
        _ => panic!("Expected Policy spec"),
    }
}

#[test]
fn test_tiered_approval_policy_parses() {
    let spec = load_spec(&detfi_policy_path("02-tiered-approval.yaml"));
    match spec {
        DsmSpecification::Policy(p) => {
            assert_eq!(p.name, "TieredApprovalPolicy");
            assert_eq!(p.rules.len(), 4);

            // Verify all condition types are distinct
            let types: Vec<&str> = p
                .rules
                .iter()
                .map(|r| match &r.condition.condition_type {
                    dsm_gen::schema::ConditionType::Custom => "custom",
                    dsm_gen::schema::ConditionType::Whitelist => "whitelist",
                    dsm_gen::schema::ConditionType::SignatureRequired => "signature_required",
                    dsm_gen::schema::ConditionType::AmountLimit => "amount_limit",
                    dsm_gen::schema::ConditionType::Blacklist => "blacklist",
                    dsm_gen::schema::ConditionType::IterationWindow => "iteration_window",
                })
                .collect();
            assert!(types.contains(&"custom"));
            assert!(types.contains(&"whitelist"));
            assert!(types.contains(&"signature_required"));
            assert!(types.contains(&"amount_limit"));
        }
        _ => panic!("Expected Policy spec"),
    }
}

// ------------------------------------------------------------------
// Code generation tests — all vaults × all languages
// ------------------------------------------------------------------

/// Returns (filename, expected_base_name) — the base name is what dsm-gen
/// produces after stripping a trailing "Vault" suffix (see `base_vault_name`).
/// The generated class will be `{base_name}VaultClient`.
fn all_vault_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("01-simple-escrow.yaml", "SimpleEscrow"),
        // "BitcoinBackedVault" → strips "Vault" → base = "BitcoinBacked"
        ("02-bitcoin-backed-vault.yaml", "BitcoinBacked"),
        // "ConditionalMultiSigVault" → strips "Vault" → base = "ConditionalMultiSig"
        ("03-conditional-multisig.yaml", "ConditionalMultiSig"),
        ("04-oracle-attested-release.yaml", "OracleAttestedRelease"),
    ]
}

fn all_policy_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("01-stablecoin-transfer.yaml", "StablecoinTransferPolicy"),
        ("02-tiered-approval.yaml", "TieredApprovalPolicy"),
    ]
}

#[test]
fn test_all_detfi_vaults_generate_rust() -> Result<(), Box<dyn std::error::Error>> {
    let generator = RustGenerator::new(true, true);
    for (file, name) in all_vault_files() {
        let spec = load_spec(&detfi_vault_path(file));
        let code = generator
            .generate(&spec)
            .unwrap_or_else(|e| panic!("Rust generation failed for {file}: {e}"));

        assert!(
            code.contains(&format!("{name}VaultClient")),
            "{file}: missing {name}VaultClient"
        );
        assert!(
            code.contains("VaultLifecycle"),
            "{file}: missing VaultLifecycle"
        );
        assert!(
            code.contains("FulfillmentCondition"),
            "{file}: missing FulfillmentCondition"
        );

        // Invariant checks
        assert!(
            !code.contains("duration_seconds"),
            "{file}: Invariant #4 violated — wall-clock time"
        );
        assert!(
            !code.contains("serde_json"),
            "{file}: Invariant #2 violated — serde_json"
        );
        assert!(
            !code.contains("TimeLock"),
            "{file}: Invariant #4 violated — TimeLock"
        );
    }
    Ok(())
}

#[test]
fn test_all_detfi_vaults_generate_typescript() -> Result<(), Box<dyn std::error::Error>> {
    let generator = TypeScriptGenerator::new(true, true);
    for (file, name) in all_vault_files() {
        let spec = load_spec(&detfi_vault_path(file));
        let code = generator
            .generate(&spec)
            .unwrap_or_else(|e| panic!("TS generation failed for {file}: {e}"));

        assert!(
            code.contains(&format!("{name}VaultClient")),
            "{file}: missing {name}VaultClient"
        );
        assert!(
            code.contains("VaultLifecycle"),
            "{file}: missing VaultLifecycle"
        );

        // Invariant checks
        assert!(
            !code.contains("duration_seconds"),
            "{file}: Invariant #4 violated"
        );
        assert!(
            !code.contains("JSON.parse"),
            "{file}: Invariant #2 violated — JSON.parse"
        );
        assert!(
            !code.contains("JSON.stringify"),
            "{file}: Invariant #2 violated — JSON.stringify"
        );
    }
    Ok(())
}

#[test]
fn test_all_detfi_vaults_generate_kotlin() -> Result<(), Box<dyn std::error::Error>> {
    let generator = KotlinGenerator::new(true, true);
    for (file, name) in all_vault_files() {
        let spec = load_spec(&detfi_vault_path(file));
        let code = generator
            .generate(&spec)
            .unwrap_or_else(|e| panic!("Kotlin generation failed for {file}: {e}"));

        assert!(
            code.contains(&format!("{name}VaultClient")),
            "{file}: missing {name}VaultClient"
        );
        assert!(
            code.contains("sealed class FulfillmentCondition"),
            "{file}: missing sealed class"
        );

        // Invariant checks
        assert!(
            !code.contains("duration_seconds"),
            "{file}: Invariant #4 violated"
        );
        assert!(
            !code.contains("Gson"),
            "{file}: Invariant #2 violated — Gson"
        );
    }
    Ok(())
}

#[test]
fn test_all_detfi_vaults_generate_swift() -> Result<(), Box<dyn std::error::Error>> {
    let generator = SwiftGenerator::new(true, true);
    for (file, name) in all_vault_files() {
        let spec = load_spec(&detfi_vault_path(file));
        let code = generator
            .generate(&spec)
            .unwrap_or_else(|e| panic!("Swift generation failed for {file}: {e}"));

        assert!(
            code.contains(&format!("{name}VaultClient")),
            "{file}: missing {name}VaultClient"
        );
        assert!(
            code.contains("indirect enum FulfillmentCondition"),
            "{file}: missing indirect enum"
        );

        // Invariant checks
        assert!(
            !code.contains("duration_seconds"),
            "{file}: Invariant #4 violated"
        );
    }
    Ok(())
}

#[test]
fn test_all_detfi_policies_generate_all_languages() -> Result<(), Box<dyn std::error::Error>> {
    let generators: Vec<(&str, Box<dyn CodeGenerator>)> = vec![
        ("Rust", Box::new(RustGenerator::new(false, false))),
        ("TS", Box::new(TypeScriptGenerator::new(false, false))),
        ("Kotlin", Box::new(KotlinGenerator::new(false, false))),
        ("Swift", Box::new(SwiftGenerator::new(false, false))),
    ];

    for (file, _name) in all_policy_files() {
        let spec = load_spec(&detfi_policy_path(file));
        for (lang, gen) in &generators {
            let code = gen
                .generate(&spec)
                .unwrap_or_else(|e| panic!("{lang} generation failed for {file}: {e}"));

            assert!(
                code.contains("PolicyClient"),
                "{lang}/{file}: missing PolicyClient"
            );
            assert!(
                !code.contains("duration_seconds"),
                "{lang}/{file}: Invariant #4 violated"
            );
        }
    }
    Ok(())
}
