//! DeTFi compiler: YAML spec → Base32 protobuf blob.
//!
//! Produces content-addressed deterministic objects (Level 0).
//! Vault blobs are templates with device_id = zeros — the phone
//! fills in identity at instantiation time.

use crate::base32;
use crate::schema::{DsmSpecification, DeploymentMode, VaultSpecification, PolicySpecification};
use anyhow::{Context, Result};

/// Blob header bytes prepended to every compiled artifact.
/// Byte 0: format version (currently 1)
/// Byte 1: deployment mode (0 = local, 1 = posted)
/// Byte 2: artifact type (0 = vault, 1 = policy)
const BLOB_VERSION: u8 = 1;
const MODE_LOCAL: u8 = 0;
const MODE_POSTED: u8 = 1;
const TYPE_VAULT: u8 = 0;
const TYPE_POLICY: u8 = 1;

/// Compiled blob result
#[derive(Debug, Clone)]
pub struct CompiledBlob {
    /// Raw bytes (header + proto payload)
    pub bytes: Vec<u8>,
    /// Base32 Crockford encoded string
    pub base32: String,
    /// BLAKE3 hash of the raw bytes
    pub hash: [u8; 32],
    /// Artifact type description
    pub artifact_type: &'static str,
}

/// Compile a DsmSpecification into a Base32 blob.
pub fn compile(spec: &DsmSpecification, mode_override: Option<DeploymentMode>) -> Result<CompiledBlob> {
    match spec {
        DsmSpecification::Vault(vault) => compile_vault(vault, mode_override),
        DsmSpecification::Policy(policy) => compile_policy(policy),
    }
}

/// Compile a vault spec into a DlvCreateV3 template blob.
///
/// Template fields:
/// - device_id: [0u8; 32] (phone fills at instantiation)
/// - policy_digest: from --policy-anchor or [0u8; 32]
/// - precommit: BLAKE3("DSM/dlv/precommit\0" || spec_hash)
/// - vault_id: BLAKE3("DSM/dlv\0" || device_id || policy_digest || precommit)
fn compile_vault(vault: &VaultSpecification, mode_override: Option<DeploymentMode>) -> Result<CompiledBlob> {
    let mode = mode_override
        .or_else(|| vault.deployment_mode.clone())
        .unwrap_or(DeploymentMode::Posted);
    let mode_byte = match mode {
        DeploymentMode::Posted => MODE_POSTED,
        DeploymentMode::Local => MODE_LOCAL,
    };

    // Compute a deterministic spec hash for precommit derivation
    let spec_yaml = serde_yaml::to_string(vault)
        .context("Failed to re-serialize vault spec for hashing")?;
    let spec_hash = blake3::hash(spec_yaml.as_bytes());

    // Derive precommit: BLAKE3("DSM/dlv/precommit\0" || spec_hash)
    let mut precommit_hasher = blake3::Hasher::new();
    precommit_hasher.update(b"DSM/dlv/precommit\0");
    precommit_hasher.update(spec_hash.as_bytes());
    let precommit: [u8; 32] = *precommit_hasher.finalize().as_bytes();

    // Template device_id and policy_digest are zeros
    let device_id = [0u8; 32];
    let policy_digest = [0u8; 32];

    // Derive vault_id: BLAKE3("DSM/dlv\0" || device_id || policy_digest || precommit)
    let mut vault_id_hasher = blake3::Hasher::new();
    vault_id_hasher.update(b"DSM/dlv\0");
    vault_id_hasher.update(&device_id);
    vault_id_hasher.update(&policy_digest);
    vault_id_hasher.update(&precommit);
    let vault_id: [u8; 32] = *vault_id_hasher.finalize().as_bytes();

    // Build DlvCreateV3 proto bytes manually (5 x 32-byte fields)
    // Proto wire format: field 1-5 are all `bytes` type (wire type 2 = LEN)
    // Each field: tag(1 byte) + length(1 byte) + data(32 bytes) = 34 bytes per field
    let mut proto_bytes = Vec::with_capacity(5 * 34);
    // Field 1: device_id (tag = 0x0A = field 1, wire type 2)
    proto_bytes.push(0x0A);
    proto_bytes.push(32);
    proto_bytes.extend_from_slice(&device_id);
    // Field 2: policy_digest (tag = 0x12 = field 2, wire type 2)
    proto_bytes.push(0x12);
    proto_bytes.push(32);
    proto_bytes.extend_from_slice(&policy_digest);
    // Field 3: precommit (tag = 0x1A = field 3, wire type 2)
    proto_bytes.push(0x1A);
    proto_bytes.push(32);
    proto_bytes.extend_from_slice(&precommit);
    // Field 4: vault_id (tag = 0x22 = field 4, wire type 2)
    proto_bytes.push(0x22);
    proto_bytes.push(32);
    proto_bytes.extend_from_slice(&vault_id);
    // Field 5: parent_digest (tag = 0x2A = field 5, wire type 2) — empty for genesis
    // Omit empty field per proto3 convention

    // Assemble blob: header + proto
    let mut blob = Vec::with_capacity(3 + proto_bytes.len());
    blob.push(BLOB_VERSION);
    blob.push(mode_byte);
    blob.push(TYPE_VAULT);
    blob.extend_from_slice(&proto_bytes);

    let hash = *blake3::hash(&blob).as_bytes();
    let b32 = base32::encode(&blob);

    Ok(CompiledBlob {
        bytes: blob,
        base32: b32,
        hash,
        artifact_type: "vault",
    })
}

/// Compile a policy spec into a TokenPolicyV3 blob.
fn compile_policy(policy: &PolicySpecification) -> Result<CompiledBlob> {
    // Serialize the policy spec as canonical YAML (deterministic)
    let policy_yaml = serde_yaml::to_string(policy)
        .context("Failed to serialize policy spec")?;
    let policy_bytes = policy_yaml.as_bytes();

    // Build TokenPolicyV3 proto: field 1 = bytes policy_bytes
    // Tag 0x0A (field 1, wire type 2) + varint length + data
    let mut proto_bytes = Vec::with_capacity(5 + policy_bytes.len());
    proto_bytes.push(0x0A); // field 1, wire type 2
    // Varint encode the length
    encode_varint(&mut proto_bytes, policy_bytes.len() as u64);
    proto_bytes.extend_from_slice(policy_bytes);

    // Assemble blob: header + proto
    let mut blob = Vec::with_capacity(3 + proto_bytes.len());
    blob.push(BLOB_VERSION);
    blob.push(MODE_POSTED); // policies are always posted
    blob.push(TYPE_POLICY);
    blob.extend_from_slice(&proto_bytes);

    let hash = *blake3::hash(&blob).as_bytes();
    let b32 = base32::encode(&blob);

    Ok(CompiledBlob {
        bytes: blob,
        base32: b32,
        hash,
        artifact_type: "policy",
    })
}

/// Parse a compiled blob's header.
pub fn parse_header(blob: &[u8]) -> Result<(u8, DeploymentMode, u8)> {
    if blob.len() < 3 {
        anyhow::bail!("Blob too short: need at least 3 bytes, got {}", blob.len());
    }
    let version = blob[0];
    if version != BLOB_VERSION {
        anyhow::bail!("Unsupported blob version: {version} (expected {BLOB_VERSION})");
    }
    let mode = match blob[1] {
        MODE_LOCAL => DeploymentMode::Local,
        MODE_POSTED => DeploymentMode::Posted,
        other => anyhow::bail!("Invalid mode byte: {other}"),
    };
    let artifact_type = blob[2];
    if artifact_type > 1 {
        anyhow::bail!("Invalid artifact type: {artifact_type}");
    }
    Ok((version, mode, artifact_type))
}

/// Protobuf varint encoding (unsigned).
fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}
