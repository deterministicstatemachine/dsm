# DeTFi Phase 1: Compile & Launch Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `dsm-gen compile` subcommand that produces Base32 protobuf blobs from YAML vault/policy specs, and a `detfi.launch` bridge route that instantiates them on the phone.

**Architecture:** dsm-gen gets a new `compiler.rs` module that converts parsed YAML specs into proto bytes (DlvCreateV3 for vaults, TokenPolicyV3 for policies), prepends a 3-byte header (version, mode, type), and Base32 Crockford encodes the result. The phone gets a new `detfi.launch` bridge route that decodes these blobs, fills in device-specific fields, and creates live vaults/policies.

**Tech Stack:** Rust (dsm-gen crate), prost for proto encoding, blake3 for hashing, TypeScript (frontend), protobuf (bridge)

---

### Task 1: Add Base32 Crockford to dsm-gen

**Files:**
- Create: `dsm-gen/src/base32.rs`
- Modify: `dsm-gen/src/lib.rs`

**Step 1: Create `dsm-gen/src/base32.rs`**

Port the encode/decode functions from `dsm_sdk/src/util/text_id.rs` into dsm-gen.
This avoids adding a dependency on the full SDK crate.

```rust
//! Base32 Crockford encoding/decoding for compiled blob output.
//! Ported from dsm_sdk::util::text_id — canonical DSM encoding.

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | b as u16;
        bits_left += 8;
        while bits_left >= 5 {
            let idx = ((buffer >> (bits_left - 5)) & 0b1_1111) as usize;
            out.push(ALPHABET[idx] as char);
            bits_left -= 5;
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0b1_1111) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'H' => Some(c - b'A' + 10),
            b'J'..=b'K' => Some(c - b'J' + 18),
            b'M'..=b'N' => Some(c - b'M' + 20),
            b'P'..=b'T' => Some(c - b'P' + 22),
            b'V'..=b'Z' => Some(c - b'V' + 27),
            b'O' | b'o' => Some(0),
            b'I' | b'i' | b'L' | b'l' => Some(1),
            b'a'..=b'z' => val(c - 32),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;
    for &c in s.as_bytes() {
        let v = val(c)?;
        buffer = (buffer << 5) | v as u16;
        bits_left += 5;
        if bits_left >= 8 {
            out.push((buffer >> (bits_left - 8)) as u8);
            bits_left -= 8;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let data = vec![0u8; 32];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
    #[test]
    fn roundtrip_nonzero() {
        let data: Vec<u8> = (0..160).map(|i| i as u8).collect();
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
```

**Step 2: Register module in `dsm-gen/src/lib.rs`**

Add `pub mod base32;` after `pub mod schema;`.

**Step 3: Run tests**

Run: `cargo test -p dsm-gen base32`
Expected: 2 tests pass

**Step 4: Commit**

```bash
git add dsm-gen/src/base32.rs dsm-gen/src/lib.rs
git commit -m "feat(dsm-gen): add Base32 Crockford encode/decode module"
```

---

### Task 2: Extend VaultSpecification with deployment_mode

**Files:**
- Modify: `dsm-gen/src/schema.rs`

**Step 1: Add DeploymentMode enum and fields to VaultSpecification**

Add after the `BitcoinNetwork` enum (around line 199):

```rust
/// Deployment mode for compiled vault blobs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Published to storage nodes. Creator can go offline.
    Posted,
    /// Local only. Bilateral fulfillment (BLE/QR/NFC).
    Local,
}
```

Add three new optional fields to `VaultSpecification` (after `metadata`):

```rust
    /// Deployment mode: posted (storage nodes) or local (bilateral).
    /// Default: posted. Only used by `dsm-gen compile`.
    pub deployment_mode: Option<DeploymentMode>,

    /// External commitment context strings for atomic grouping (Level 1).
    /// Reserved for Phase 2 program compilation.
    pub external_commits: Option<Vec<String>>,

    /// Pre-commitment fork group name (Level 1).
    /// Reserved for Phase 2 program compilation.
    pub fork_group: Option<String>,
```

**Step 2: Run all existing tests to verify backwards compatibility**

Run: `cargo test -p dsm-gen`
Expected: All 17 tests pass (existing YAML specs don't have these fields, serde skips them as `Option`)

**Step 3: Commit**

```bash
git add dsm-gen/src/schema.rs
git commit -m "feat(dsm-gen): add deployment_mode, external_commits, fork_group to VaultSpecification"
```

---

### Task 3: Create the compiler module

**Files:**
- Create: `dsm-gen/src/compiler.rs`
- Modify: `dsm-gen/src/lib.rs`

**Step 1: Create `dsm-gen/src/compiler.rs`**

```rust
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
```

**Step 2: Register module in `dsm-gen/src/lib.rs`**

Add `pub mod compiler;` after `pub mod base32;`.

**Step 3: Verify it compiles**

Run: `cargo check -p dsm-gen`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add dsm-gen/src/compiler.rs dsm-gen/src/lib.rs
git commit -m "feat(dsm-gen): add compiler module for YAML-to-blob compilation"
```

---

### Task 4: Add Compile CLI subcommand

**Files:**
- Modify: `dsm-gen/src/main.rs`

**Step 1: Add Compile variant to Commands enum**

Add after the `Validate` variant (around line 89):

```rust
    /// Compile specification to Base32 protobuf blob
    Compile {
        /// Path to vault.yaml or policy.yaml specification
        spec_file: PathBuf,

        /// Deployment mode (posted = storage nodes, local = bilateral)
        #[arg(long, value_enum, default_value = "posted")]
        mode: CompileMode,

        /// Policy anchor (Base32 Crockford, 32 bytes) to bind vault to
        #[arg(long)]
        policy_anchor: Option<String>,

        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
```

Add the CompileMode enum:

```rust
#[derive(Debug, Clone, ValueEnum)]
enum CompileMode {
    Posted,
    Local,
}
```

**Step 2: Add handler in main() match**

Add after the Validate branch:

```rust
        Commands::Compile {
            spec_file,
            mode,
            policy_anchor: _policy_anchor,
            output,
        } => {
            compile_specification(spec_file, mode, output, cli.output_dir)?;
        }
```

**Step 3: Implement compile_specification function**

```rust
fn compile_specification(
    spec_file: PathBuf,
    mode: CompileMode,
    output: Option<PathBuf>,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    let content = fs::read_to_string(&spec_file)
        .with_context(|| format!("Failed to read specification file: {spec_file:?}"))?;

    let spec: DsmSpecification = if spec_file.extension().and_then(|s| s.to_str()) == Some("json") {
        serde_json::from_str(&content).with_context(|| "Failed to parse JSON specification")?
    } else {
        serde_yaml::from_str(&content).with_context(|| "Failed to parse YAML specification")?
    };

    let mode_override = Some(match mode {
        CompileMode::Posted => dsm_gen::schema::DeploymentMode::Posted,
        CompileMode::Local => dsm_gen::schema::DeploymentMode::Local,
    });

    let blob = dsm_gen::compiler::compile(&spec, mode_override)
        .with_context(|| "Compilation failed")?;

    // Output
    if let Some(out_path) = output.or_else(|| output_dir.map(|d| {
        let stem = spec_file.file_stem().unwrap_or_default().to_string_lossy();
        d.join(format!("{stem}.b32"))
    })) {
        ensure_parent_dir(&out_path)?;
        fs::write(&out_path, &blob.base32)
            .with_context(|| format!("Failed to write blob to {out_path:?}"))?;
        eprintln!("Compiled {} blob: {out_path:?}", blob.artifact_type);
    } else {
        // stdout
        println!("{}", blob.base32);
    }

    let hash_hex = blake3::Hash::from(blob.hash).to_hex();
    eprintln!("Blob hash (BLAKE3): {hash_hex}");
    eprintln!("Blob size: {} bytes ({} Base32 chars)", blob.bytes.len(), blob.base32.len());

    Ok(())
}
```

**Step 4: Verify CLI works**

Run: `cargo run -p dsm-gen -- compile examples/detfi/vaults/01-simple-escrow.yaml`
Expected: Base32 blob output to stdout, hash and size to stderr

Run: `cargo run -p dsm-gen -- compile examples/detfi/vaults/01-simple-escrow.yaml --mode local`
Expected: Different blob (mode byte = 0 instead of 1)

**Step 5: Commit**

```bash
git add dsm-gen/src/main.rs
git commit -m "feat(dsm-gen): add compile subcommand for YAML-to-blob compilation"
```

---

### Task 5: Write compile integration tests

**Files:**
- Create: `dsm-gen/tests/detfi_compile.rs`

**Step 1: Write tests**

```rust
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
    // Tag = 0x0A, Len = 0x20 (32)
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
        // Verify header parses
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
```

**Step 2: Run tests**

Run: `cargo test -p dsm-gen --test detfi_compile`
Expected: All tests pass

**Step 3: Run full test suite for regressions**

Run: `cargo test -p dsm-gen`
Expected: All tests pass (detfi_examples + enhanced_policy_test + detfi_compile)

**Step 4: Commit**

```bash
git add dsm-gen/tests/detfi_compile.rs
git commit -m "test(dsm-gen): add compile integration tests for all DeTFi examples"
```

---

### Task 6: Update examples README with compile walkthrough

**Files:**
- Modify: `examples/detfi/README.md`

**Step 1: Add "Compile and Launch" section**

Add a new section after the "Walkthrough: Transfer Policies" section:

```markdown
## Walkthrough: Compile to Base32 Blob

The `dsm-gen compile` command converts a YAML spec into a Base32 protobuf blob
that can be pasted directly into the DSM phone app.

### Step 1: Compile a Vault

\`\`\`bash
# Compile to Base32 (output to stdout)
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml

# Compile with explicit mode
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml --mode posted
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml --mode local

# Compile to file
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml --output escrow.b32
\`\`\`

### Step 2: Understand the Blob

The blob is a 3-byte header + protobuf payload, Base32 Crockford encoded:

| Byte | Field | Values |
|------|-------|--------|
| 0 | Version | `1` (current) |
| 1 | Mode | `0` = local, `1` = posted |
| 2 | Type | `0` = vault, `1` = policy |
| 3+ | Proto | `DlvCreateV3` or `TokenPolicyV3` bytes |

### Step 3: Paste into the Phone

1. Copy the Base32 string from stdout or the `.b32` file
2. Open the DSM app → Settings → Developer Options → DeTFi Launch
3. Paste the blob
4. The app auto-detects the type (vault/policy) and mode (posted/local)
5. Tap "Launch" — the app fills in your device identity and creates the vault

### Step 4: Compile a Policy

\`\`\`bash
dsm-gen compile examples/detfi/policies/01-stablecoin-transfer.yaml
\`\`\`

Policies are always posted (they're content-addressed and immutable).
The blob contains the full policy definition. Paste it into the app
to publish the policy and get its anchor hash.
```

**Step 2: Commit**

```bash
git add examples/detfi/README.md
git commit -m "docs: add compile walkthrough to DeTFi cookbook"
```

---

### Task 7: Pre-compile example blobs

**Files:**
- Create: `examples/detfi/compiled/` directory
- Create: one `.b32` file per example

**Step 1: Create compiled directory and generate blobs**

```bash
mkdir -p examples/detfi/compiled
cargo run -p dsm-gen -- compile examples/detfi/vaults/01-simple-escrow.yaml --output examples/detfi/compiled/01-simple-escrow-posted.b32
cargo run -p dsm-gen -- compile examples/detfi/vaults/01-simple-escrow.yaml --mode local --output examples/detfi/compiled/01-simple-escrow-local.b32
cargo run -p dsm-gen -- compile examples/detfi/vaults/02-bitcoin-backed-vault.yaml --output examples/detfi/compiled/02-bitcoin-backed-vault.b32
cargo run -p dsm-gen -- compile examples/detfi/vaults/03-conditional-multisig.yaml --output examples/detfi/compiled/03-conditional-multisig.b32
cargo run -p dsm-gen -- compile examples/detfi/vaults/04-oracle-attested-release.yaml --output examples/detfi/compiled/04-oracle-attested-release.b32
cargo run -p dsm-gen -- compile examples/detfi/policies/01-stablecoin-transfer.yaml --output examples/detfi/compiled/01-stablecoin-transfer.b32
cargo run -p dsm-gen -- compile examples/detfi/policies/02-tiered-approval.yaml --output examples/detfi/compiled/02-tiered-approval.b32
```

**Step 2: Commit**

```bash
git add examples/detfi/compiled/
git commit -m "feat: pre-compile DeTFi example blobs for one-paste launch"
```

---

## Summary

After all 7 tasks, the dsm-gen compile pipeline is complete:

- `dsm-gen compile <spec.yaml>` → Base32 blob to stdout
- `dsm-gen compile <spec.yaml> --mode local` → local-mode blob
- `dsm-gen compile <spec.yaml> --output file.b32` → blob to file
- All 6 DeTFi examples have pre-compiled `.b32` files
- Full test coverage: header format, Base32 roundtrip, determinism, template fields
- README updated with compile walkthrough

The `detfi.launch` bridge route (phone-side) is deferred to a follow-up plan
since it touches the SDK, Android JNI, and frontend layers — a separate
cross-layer task.
