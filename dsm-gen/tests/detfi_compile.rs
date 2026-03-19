//! Integration tests for DeTFi blob compilation.
//!
//! Validates that YAML specs compile to valid Base32 blobs that
//! round-trip correctly through encode/decode.

use dsm_gen::base32;
use dsm_gen::compiler::{self, CompiledBlob};
use dsm_gen::schema::{DsmSpecification, DeploymentMode};
use std::path::PathBuf;

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

fn load_and_compile(path: &PathBuf, mode: Option<DeploymentMode>) -> CompiledBlob {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    let spec: DsmSpecification = serde_yaml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()));
    compiler::compile(&spec, mode)
        .unwrap_or_else(|e| panic!("Failed to compile {}: {e}", path.display()))
}

// ---- Header format tests ----

#[test]
fn test_vault_blob_header_posted() {
    let blob = load_and_compile(
        &detfi_vault_path("01-simple-escrow.yaml"),
        Some(DeploymentMode::Posted),
    );
    assert!(blob.bytes.len() >= 3, "Blob too short");
    assert_eq!(blob.bytes[0], 1, "Version should be 1");
    assert_eq!(blob.bytes[1], 1, "Mode should be 1 (posted)");
    assert_eq!(blob.bytes[2], 0, "Type should be 0 (vault)");
}

#[test]
fn test_vault_blob_header_local() {
    let blob = load_and_compile(
        &detfi_vault_path("01-simple-escrow.yaml"),
        Some(DeploymentMode::Local),
    );
    assert_eq!(blob.bytes[1], 0, "Mode should be 0 (local)");
}

#[test]
fn test_policy_blob_header() {
    let blob = load_and_compile(
        &detfi_policy_path("01-stablecoin-transfer.yaml"),
        None,
    );
    assert_eq!(blob.bytes[0], 1, "Version should be 1");
    assert_eq!(blob.bytes[1], 1, "Mode should be 1 (posted) for policies");
    assert_eq!(blob.bytes[2], 1, "Type should be 1 (policy)");
}

// ---- Base32 round-trip tests ----

#[test]
fn test_vault_blob_base32_roundtrip() {
    let blob = load_and_compile(
        &detfi_vault_path("01-simple-escrow.yaml"),
        Some(DeploymentMode::Posted),
    );
    let decoded = base32::decode(&blob.base32).expect("Base32 decode failed");
    assert_eq!(decoded, blob.bytes, "Base32 round-trip mismatch");
}

#[test]
fn test_policy_blob_base32_roundtrip() {
    let blob = load_and_compile(
        &detfi_policy_path("01-stablecoin-transfer.yaml"),
        None,
    );
    let decoded = base32::decode(&blob.base32).expect("Base32 decode failed");
    assert_eq!(decoded, blob.bytes, "Base32 round-trip mismatch");
}

// ---- Determinism tests ----

#[test]
fn test_vault_compilation_is_deterministic() {
    let blob1 = load_and_compile(
        &detfi_vault_path("02-bitcoin-backed-vault.yaml"),
        Some(DeploymentMode::Posted),
    );
    let blob2 = load_and_compile(
        &detfi_vault_path("02-bitcoin-backed-vault.yaml"),
        Some(DeploymentMode::Posted),
    );
    assert_eq!(blob1.hash, blob2.hash, "Same input must produce same hash");
    assert_eq!(blob1.base32, blob2.base32, "Same input must produce same blob");
}

#[test]
fn test_different_modes_produce_different_blobs() {
    let posted = load_and_compile(
        &detfi_vault_path("01-simple-escrow.yaml"),
        Some(DeploymentMode::Posted),
    );
    let local = load_and_compile(
        &detfi_vault_path("01-simple-escrow.yaml"),
        Some(DeploymentMode::Local),
    );
    assert_ne!(posted.hash, local.hash, "Different modes must produce different hashes");
}

// ---- Vault template tests ----

#[test]
fn test_vault_blob_has_zero_device_id() {
    let blob = load_and_compile(
        &detfi_vault_path("01-simple-escrow.yaml"),
        Some(DeploymentMode::Posted),
    );
    // Header is 3 bytes. Proto field 1 (device_id): tag(1) + len(1) + data(32) starts at byte 3.
    assert_eq!(blob.bytes[3], 0x0A, "Field 1 tag");
    assert_eq!(blob.bytes[4], 32, "Field 1 length");
    let device_id = &blob.bytes[5..37];
    assert_eq!(device_id, &[0u8; 32], "device_id must be zeros (template)");
}

#[test]
fn test_vault_blob_has_nonzero_precommit() {
    let blob = load_and_compile(
        &detfi_vault_path("01-simple-escrow.yaml"),
        Some(DeploymentMode::Posted),
    );
    // Field 3 (precommit): starts at byte 3 + 34 + 34 = 71
    // tag(1) + len(1) + data(32) = 34 per field
    let precommit = &blob.bytes[73..105]; // 71+2 to 71+2+32
    assert_ne!(precommit, &[0u8; 32], "precommit must be nonzero (derived from spec hash)");
}

// ---- All examples compile ----

#[test]
fn test_all_vault_examples_compile() {
    let vaults = vec![
        "01-simple-escrow.yaml",
        "02-bitcoin-backed-vault.yaml",
        "03-conditional-multisig.yaml",
        "04-oracle-attested-release.yaml",
    ];
    for name in vaults {
        let blob = load_and_compile(&detfi_vault_path(name), None);
        assert!(!blob.base32.is_empty(), "{name}: empty blob");
        assert_eq!(blob.bytes[2], 0, "{name}: should be vault type");
        let (ver, _mode, typ) = compiler::parse_header(&blob.bytes)
            .unwrap_or_else(|e| panic!("{name}: header parse failed: {e}"));
        assert_eq!(ver, 1);
        assert_eq!(typ, 0);
    }
}

#[test]
fn test_all_policy_examples_compile() {
    let policies = vec![
        "01-stablecoin-transfer.yaml",
        "02-tiered-approval.yaml",
    ];
    for name in policies {
        let blob = load_and_compile(&detfi_policy_path(name), None);
        assert!(!blob.base32.is_empty(), "{name}: empty blob");
        assert_eq!(blob.bytes[2], 1, "{name}: should be policy type");
        let (ver, _mode, typ) = compiler::parse_header(&blob.bytes)
            .unwrap_or_else(|e| panic!("{name}: header parse failed: {e}"));
        assert_eq!(ver, 1);
        assert_eq!(typ, 1);
    }
}
