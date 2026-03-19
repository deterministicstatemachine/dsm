// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic, software-only secure key storage ("SoftVault").
//! - No TEEs / platform keystores.
//! - Deterministic envelope format; no wall clocks, no RNG.
//! - KEK = BLAKE3(binding_key || device_id || alias || purpose || key_type || pass_tag?).
//! - Nonce = BLAKE3("DSM/Vault/Nonce/v2\0" || device_id || alias || purpose || key_type || write_seqno_le)[0..24].
//! - Per-entry write_seqno increments deterministically on each store() overwrite.
//! - Binary-only I/O; no JSON/hex/base64.
//!
//! File layout (little-endian):
//!   u32 header_len
//!   `[header_bytes]`  // VaultHeader v3 (fixed + variable tail)
//!   [24-byte nonce] // redundant; must equal the derived nonce, checked on read
//!   u32 ciphertext_len
//!   `[ciphertext]`    // XChaCha20-Poly1305 with AAD = header_bytes

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use blake3;
use dsm::crypto::blake3::dsm_domain_hasher;
use zeroize::Zeroize;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

use dsm::types::error::DsmError;

/// Supported key kinds for storage. Extend as needed, keeping tag strings stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyType {
    DeviceSphincsSk,
    DeviceKyberSk,
    PeerKey,
    TokenKey,
    Other(String),
}

impl KeyType {
    fn as_tag(&self) -> &'static str {
        match self {
            KeyType::DeviceSphincsSk => "dev_sphincs_sk",
            KeyType::DeviceKyberSk => "dev_kyber_sk",
            KeyType::PeerKey => "peer_key",
            KeyType::TokenKey => "token_key",
            KeyType::Other(_) => "other",
        }
    }
}

/// Software-only key storage trait.
pub trait KeyStorage: Send + Sync {
    /// Store private key bytes; returns a 32-byte binary address (blake3 of header||ciphertext).
    fn store_key(
        &self,
        alias: &str,
        key_type: KeyType,
        key_bytes: &[u8],
    ) -> Result<[u8; 32], DsmError>;
    /// Retrieve private key bytes.
    fn retrieve_key(&self, alias: &str, key_type: KeyType) -> Result<Vec<u8>, DsmError>;
    /// Delete a stored key if present.
    fn delete_key(&self, alias: &str, key_type: KeyType) -> Result<(), DsmError>;
}

/// Source for a 32-byte device binding key (DBRW-derived). Plug in your real implementation.
pub trait BindingKeyProvider: Send + Sync {
    fn device_binding_key(&self) -> Result<[u8; 32], DsmError>;
}

/// Test-only binder deriving a deterministic key from `device_id`.
#[cfg(test)]
pub struct TestBindingKeyProvider {
    device_id: String,
}

#[cfg(test)]
impl TestBindingKeyProvider {
    pub fn new(device_id: String) -> Self {
        Self { device_id }
    }
}

#[cfg(test)]
impl BindingKeyProvider for TestBindingKeyProvider {
    fn device_binding_key(&self) -> Result<[u8; 32], DsmError> {
        let mut out = [0u8; 32];
        let d = blake3::hash(self.device_id.as_bytes());
        out.copy_from_slice(d.as_bytes());
        Ok(out)
    }
}

/// DBRW-backed binder intended to be deterministic across processes/devices of the same identity.
/// This default implementation is **stable**: it derives the binding key from a domain-separated
/// hash of the provided device_id_hint. Replace with a platform DBRW that returns the same 32B
/// across runs on the same device (no clocks, no randomness).
#[derive(Clone)]
pub struct DbrwBindingKeyProvider {
    device_id_hint: String,
}

impl DbrwBindingKeyProvider {
    pub fn new(device_id_hint: String) -> Self {
        Self { device_id_hint }
    }
}

impl BindingKeyProvider for DbrwBindingKeyProvider {
    fn device_binding_key(&self) -> Result<[u8; 32], DsmError> {
        let mut hasher = dsm_domain_hasher("DSM/DBRW/BINDING/v2");
        hasher.update(self.device_id_hint.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        Ok(out)
    }
}

/// File-backed vault implementing `KeyStorage` with deterministic envelopes.
pub struct SoftVaultKeyStorage<B: BindingKeyProvider> {
    base_dir: PathBuf,
    device_id: String,
    binder: B,
    passphrase_tag: Option<[u8; 32]>,
}

impl<B: BindingKeyProvider> SoftVaultKeyStorage<B> {
    /// Create a new vault under `base_dir`.
    pub fn new<P: AsRef<Path>>(
        base_dir: P,
        device_id: String,
        binder: B,
        passphrase: Option<&str>,
    ) -> Result<Self, DsmError> {
        let base = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base).map_err(|e| {
            DsmError::storage(format!("create vault dir: {e}"), None::<std::io::Error>)
        })?;
        // Derive a deterministic 32-byte tag from passphrase using BLAKE3 derive_key (two-arg API).
        let passphrase_tag =
            passphrase.map(|p| blake3::derive_key("DSM/softvault/passphrase\0", p.as_bytes()));
        Ok(Self {
            base_dir: base,
            device_id,
            binder,
            passphrase_tag,
        })
    }

    #[inline]
    fn derive_pass_tag(&self) -> Option<[u8; 32]> {
        self.passphrase_tag
    }

    fn derive_kek(
        &self,
        alias: &str,
        purpose: &str,
        key_type: &KeyType,
    ) -> Result<[u8; 32], DsmError> {
        let binding = self.binder.device_binding_key()?;
        let mut h = dsm_domain_hasher("DSM/Vault/KEK/v2");
        h.update(&binding);
        h.update(self.device_id.as_bytes());
        h.update(alias.as_bytes());
        h.update(purpose.as_bytes());
        h.update(key_type.as_tag().as_bytes());
        if let Some(tag) = self.derive_pass_tag() {
            h.update(&tag);
        }
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        Ok(out)
    }

    fn derive_nonce(
        &self,
        alias: &str,
        purpose: &str,
        key_type: &KeyType,
        write_seqno: u64,
    ) -> [u8; 24] {
        let mut h = dsm_domain_hasher("DSM/Vault/Nonce/v2");
        h.update(self.device_id.as_bytes());
        h.update(alias.as_bytes());
        h.update(purpose.as_bytes());
        h.update(key_type.as_tag().as_bytes());
        h.update(&write_seqno.to_le_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 24];
        out.copy_from_slice(&digest.as_bytes()[..24]);
        out
    }

    fn key_path(&self, alias: &str, purpose: &str, key_type: &KeyType) -> PathBuf {
        let fname = format!("{}__{}__{}.vault", alias, purpose, key_type.as_tag());
        self.base_dir.join(fname)
    }

    fn try_read_existing_seqno(path: &Path) -> Result<Option<u64>, DsmError> {
        if !path.exists() {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        {
            let mut f = fs::File::open(path).map_err(|e| {
                DsmError::storage(format!("open for seqno: {e}"), None::<std::io::Error>)
            })?;
            f.read_to_end(&mut bytes).map_err(|e| {
                DsmError::storage(format!("read for seqno: {e}"), None::<std::io::Error>)
            })?;
        }
        // framing: u32 header_len | header_bytes | ...
        if bytes.len() < 4 {
            return Ok(None);
        }
        let mut off = 0usize;
        let mut u32b = [0u8; 4];
        u32b.copy_from_slice(&bytes[off..off + 4]);
        off += 4;
        let hlen = u32::from_le_bytes(u32b) as usize;
        if bytes.len() < off + hlen {
            return Ok(None);
        }
        let header_bytes = &bytes[off..off + hlen];
        let (hdr, _) = VaultHeader::decode_fixed(header_bytes)?;
        Ok(Some(hdr.write_seqno))
    }
}

#[derive(Clone)]
struct VaultHeader {
    version: u8,            // format version (3)
    algo_id: u8,            // 1 = XChaCha20-Poly1305
    nonce_len: u8,          // 24
    key_len: u8,            // 32
    key_type_tag: [u8; 16], // hashed tag of logical key type
    write_seqno: u64,       // deterministic counter, not time
    alias_len: u16,
    purpose_len: u16,
    commit_id_len: u16,
    policy_len: u16,
}

impl VaultHeader {
    fn from_fields(
        key_type: &KeyType,
        alias: &str,
        purpose: &str,
        commit_id: &[u8],
        policy_anchor: Option<&str>,
        write_seqno: u64,
    ) -> Self {
        let mut kt = [0u8; 16];
        let t =
            dsm::crypto::blake3::domain_hash("DSM/vault-key-type", key_type.as_tag().as_bytes());
        kt.copy_from_slice(&t.as_bytes()[..16]);
        Self {
            version: 3,
            algo_id: 1, // XChaCha20-Poly1305
            nonce_len: 24,
            key_len: 32,
            key_type_tag: kt,
            write_seqno,
            alias_len: alias.len() as u16,
            purpose_len: purpose.len() as u16,
            commit_id_len: commit_id.len() as u16,
            policy_len: policy_anchor.map(|s| s.len() as u16).unwrap_or(0),
        }
    }

    fn encode(
        &self,
        buf: &mut Vec<u8>,
        alias: &str,
        purpose: &str,
        commit_id: &[u8],
        policy_anchor: Option<&str>,
    ) {
        buf.push(self.version);
        buf.push(self.algo_id);
        buf.push(self.nonce_len);
        buf.push(self.key_len);
        buf.extend_from_slice(&self.key_type_tag);
        buf.extend_from_slice(&self.write_seqno.to_le_bytes());
        buf.extend_from_slice(&self.alias_len.to_le_bytes());
        buf.extend_from_slice(&self.purpose_len.to_le_bytes());
        buf.extend_from_slice(&self.commit_id_len.to_le_bytes());
        buf.extend_from_slice(&self.policy_len.to_le_bytes());
        buf.extend_from_slice(alias.as_bytes());
        buf.extend_from_slice(purpose.as_bytes());
        buf.extend_from_slice(commit_id);
        if let Some(p) = policy_anchor {
            buf.extend_from_slice(p.as_bytes());
        }
    }

    fn decode_fixed(bytes: &[u8]) -> Result<(Self, usize), DsmError> {
        // min fixed = 1+1+1+1 + 16 + 8 + 2+2+2+2 = 36
        if bytes.len() < 36 {
            return Err(DsmError::serialization_error(
                "vault header too short",
                "VaultHeader",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let version = bytes[0];
        let algo_id = bytes[1];
        let nonce_len = bytes[2];
        let key_len = bytes[3];
        let mut key_type_tag = [0u8; 16];
        key_type_tag.copy_from_slice(&bytes[4..20]);
        let mut off = 20;

        let mut u64b = [0u8; 8];
        u64b.copy_from_slice(&bytes[off..off + 8]);
        off += 8;
        let write_seqno = u64::from_le_bytes(u64b);

        let get_u16 = |o: &mut usize| -> u16 {
            let mut u = [0u8; 2];
            u.copy_from_slice(&bytes[*o..*o + 2]);
            *o += 2;
            u16::from_le_bytes(u)
        };
        let alias_len = get_u16(&mut off);
        let purpose_len = get_u16(&mut off);
        let commit_id_len = get_u16(&mut off);
        let policy_len = get_u16(&mut off);

        Ok((
            Self {
                version,
                algo_id,
                nonce_len,
                key_len,
                key_type_tag,
                write_seqno,
                alias_len,
                purpose_len,
                commit_id_len,
                policy_len,
            },
            off,
        ))
    }
}

struct Envelope {
    header_bytes: Vec<u8>,
    nonce: [u8; 24], // XChaCha fixed
    ciphertext: Vec<u8>,
}

impl Envelope {
    fn address(&self) -> [u8; 32] {
        *dsm::crypto::blake3::domain_hash(
            "DSM/vault-envelope-v2",
            &[&self.header_bytes[..], &self.ciphertext].concat(),
        )
        .as_bytes()
    }
}

impl<B: BindingKeyProvider> KeyStorage for SoftVaultKeyStorage<B> {
    fn store_key(
        &self,
        alias: &str,
        key_type: KeyType,
        key_bytes: &[u8],
    ) -> Result<[u8; 32], DsmError> {
        let purpose = "private_key";
        let mut kek = self.derive_kek(alias, purpose, &key_type)?;
        let commit_id = {
            let mut h = dsm_domain_hasher("DSM/vault-commitment-v2");
            h.update(self.device_id.as_bytes());
            h.update(alias.as_bytes());
            h.update(purpose.as_bytes());
            h.update(key_type.as_tag().as_bytes());
            *h.finalize().as_bytes()
        };
        let policy_anchor: Option<&str> = None;

        // Determine deterministic write_seqno (read existing, else start at 1).
        let path = self.key_path(alias, purpose, &key_type);
        let write_seqno = match Self::try_read_existing_seqno(&path)? {
            Some(prev) => prev
                .checked_add(1)
                .ok_or_else(|| DsmError::storage("write_seqno overflow", None::<std::io::Error>))?,
            None => 1u64,
        };

        // Header
        let header = VaultHeader::from_fields(
            &key_type,
            alias,
            purpose,
            &commit_id,
            policy_anchor,
            write_seqno,
        );
        let mut header_bytes = Vec::with_capacity(
            1 + 1 + 1 + 1 + 16 + 8 + 2 + 2 + 2 + 2 + alias.len() + purpose.len() + commit_id.len(),
        );
        header.encode(&mut header_bytes, alias, purpose, &commit_id, policy_anchor);

        // Deterministic Nonce (24 bytes)
        let nonce_arr = self.derive_nonce(alias, purpose, &key_type, write_seqno);
        let nonce = XNonce::from(nonce_arr);

        // AEAD (XChaCha20-Poly1305) with AAD = header_bytes
        let aead = XChaCha20Poly1305::new_from_slice(&kek)
            .map_err(|_| DsmError::crypto("invalid AEAD key length", None::<std::io::Error>))?;
        let ciphertext = aead
            .encrypt(
                &nonce,
                Payload {
                    msg: key_bytes,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| DsmError::crypto("AEAD encrypt failed", None::<std::io::Error>))?;

        let env = Envelope {
            header_bytes,
            nonce: nonce_arr,
            ciphertext,
        };
        let addr = env.address();

        // Atomic write with a deterministic lock attempt (no sleeps, no clocks).
        let lock_path = path.with_extension("vault.lock");
        let mut have_lock = false;
        for _ in 0..1024 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut lockf) => {
                    let _ = lockf.write_all(b"1");
                    have_lock = true;
                    break;
                }
                Err(_) => { /* deterministic retry, no delay */ }
            }
        }
        if !have_lock {
            return Err(DsmError::storage(
                "lock acquisition failed (deterministic retries exhausted)",
                None::<std::io::Error>,
            ));
        }

        let tmp_path = path.with_extension("vault.tmp");
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                DsmError::storage(
                    format!("create tmp vault file: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        let header_len = (env.header_bytes.len() as u32).to_le_bytes();
        let cipher_len = (env.ciphertext.len() as u32).to_le_bytes();
        f.write_all(&header_len)?;
        f.write_all(&env.header_bytes)?;
        f.write_all(&env.nonce)?;
        f.write_all(&cipher_len)?;
        f.write_all(&env.ciphertext)?;
        f.flush()?;
        // Restrict file permissions to owner-only (private key material)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        // No fsync-based timing; rely on rename atomicity at the OS level deterministically.
        fs::rename(&tmp_path, &path).map_err(|e| {
            DsmError::storage(format!("atomic rename: {e}"), None::<std::io::Error>)
        })?;
        let _ = fs::remove_file(&lock_path);

        // Zeroize kek material
        kek.zeroize();

        Ok(addr)
    }

    fn retrieve_key(&self, alias: &str, key_type: KeyType) -> Result<Vec<u8>, DsmError> {
        let purpose = "private_key";
        let mut kek = self.derive_kek(alias, purpose, &key_type)?;
        let path = self.key_path(alias, purpose, &key_type);

        let mut bytes = Vec::new();
        {
            let mut f = fs::File::open(&path).map_err(|_e| {
                DsmError::not_found("vault_key", Some(format!("{alias}:{:?}", key_type)))
            })?;
            f.read_to_end(&mut bytes)?;
        }

        // Parse envelope framing
        let mut off = 0usize;
        let rd_u32 = |b: &[u8], o: &mut usize| -> Result<u32, DsmError> {
            if b.len() < *o + 4 {
                return Err(DsmError::serialization_error(
                    "envelope",
                    "truncated u32",
                    None::<String>,
                    None::<std::io::Error>,
                ));
            }
            let mut t = [0u8; 4];
            t.copy_from_slice(&b[*o..*o + 4]);
            *o += 4;
            Ok(u32::from_le_bytes(t))
        };
        if bytes.len() < 4 {
            return Err(DsmError::serialization_error(
                "envelope",
                "truncated",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let hlen = rd_u32(&bytes, &mut off)? as usize;
        if bytes.len() < off + hlen + 24 + 4 {
            return Err(DsmError::serialization_error(
                "envelope",
                "truncated body",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let header_bytes = bytes[off..off + hlen].to_vec();
        off += hlen;

        // Decode header (sanity) + obtain write_seqno for nonce re-derivation check
        let (hdr, _) = VaultHeader::decode_fixed(&header_bytes)?;
        if hdr.algo_id != 1 || hdr.nonce_len != 24 {
            return Err(DsmError::serialization_error(
                "envelope",
                "unsupported algo/nonce",
                None::<String>,
                None::<std::io::Error>,
            ));
        }

        let mut nonce_arr = [0u8; 24];
        nonce_arr.copy_from_slice(&bytes[off..off + 24]);
        off += 24;
        let clen = rd_u32(&bytes, &mut off)? as usize;
        if bytes.len() < off + clen {
            return Err(DsmError::serialization_error(
                "envelope",
                "truncated ciphertext",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let ciphertext = bytes[off..off + clen].to_vec();

        // Defensive: ensure stored nonce equals the deterministic one for this header (drift guard).
        // Reconstruct alias/purpose slices from header tail lengths.
        let mut tail_off = 36usize; // fixed portion parsed by decode_fixed
        let alias_len = hdr.alias_len as usize;
        let purpose_len = hdr.purpose_len as usize;
        let commit_len = hdr.commit_id_len as usize;
        if header_bytes.len()
            < tail_off + alias_len + purpose_len + commit_len + (hdr.policy_len as usize)
        {
            return Err(DsmError::serialization_error(
                "header",
                "tail truncated",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let alias_b = &header_bytes[tail_off..tail_off + alias_len];
        tail_off += alias_len;
        let purpose_b = &header_bytes[tail_off..tail_off + purpose_len];
        tail_off += purpose_len;
        let _commit_b = &header_bytes[tail_off..tail_off + commit_len];
        tail_off += commit_len;
        let _policy_b = if hdr.policy_len > 0 {
            &header_bytes[tail_off..tail_off + (hdr.policy_len as usize)]
        } else {
            &[][..]
        };

        let alias_s = std::str::from_utf8(alias_b).map_err(|_| {
            DsmError::serialization_error(
                "header",
                "alias utf8",
                None::<String>,
                None::<std::io::Error>,
            )
        })?;
        let purpose_s = std::str::from_utf8(purpose_b).map_err(|_| {
            DsmError::serialization_error(
                "header",
                "purpose utf8",
                None::<String>,
                None::<std::io::Error>,
            )
        })?;

        let expected_nonce = self.derive_nonce(alias_s, purpose_s, &key_type, hdr.write_seqno);
        if expected_nonce != nonce_arr {
            return Err(DsmError::crypto(
                "nonce/header mismatch",
                None::<std::io::Error>,
            ));
        }

        // Decrypt (XChaCha20-Poly1305)
        let aead = XChaCha20Poly1305::new_from_slice(&kek)
            .map_err(|_| DsmError::crypto("invalid AEAD key length", None::<std::io::Error>))?;
        let nonce = XNonce::from(nonce_arr);
        let plain = aead
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| DsmError::crypto("AEAD decrypt failed", None::<std::io::Error>))?;

        // Zeroize sensitive material
        kek.zeroize();

        Ok(plain)
    }

    fn delete_key(&self, alias: &str, key_type: KeyType) -> Result<(), DsmError> {
        let purpose = "private_key";
        let path = self.key_path(alias, purpose, &key_type);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                DsmError::storage(format!("delete key: {e}"), None::<std::io::Error>)
            })?;
        }
        Ok(())
    }
}

impl<B: BindingKeyProvider> SoftVaultKeyStorage<B> {
    /// Export an opaque envelope (header||nonce||ciphertext) for mirroring. Binary-only.
    pub fn export_envelope(&self, alias: &str, key_type: KeyType) -> Result<Vec<u8>, DsmError> {
        let purpose = "private_key";
        let path = self.key_path(alias, purpose, &key_type);
        let mut bytes = Vec::new();
        let mut f = fs::File::open(&path).map_err(|_e| {
            DsmError::not_found("vault_key", Some(format!("{alias}:{:?}", key_type)))
        })?;
        f.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// Import a previously exported envelope into the vault atomically (overwrites existing).
    pub fn import_envelope(
        &self,
        alias: &str,
        key_type: KeyType,
        envelope_bytes: &[u8],
    ) -> Result<[u8; 32], DsmError> {
        let purpose = "private_key";

        // Compute address to return
        let mut off = 0usize;
        let rd_u32 = |b: &[u8], o: &mut usize| -> Result<u32, DsmError> {
            if b.len() < *o + 4 {
                return Err(DsmError::serialization_error(
                    "envelope",
                    "truncated u32",
                    None::<String>,
                    None::<std::io::Error>,
                ));
            }
            let mut t = [0u8; 4];
            t.copy_from_slice(&b[*o..*o + 4]);
            *o += 4;
            Ok(u32::from_le_bytes(t))
        };
        if envelope_bytes.len() < 4 {
            return Err(DsmError::serialization_error(
                "envelope",
                "truncated",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let hlen = rd_u32(envelope_bytes, &mut off)? as usize;
        if envelope_bytes.len() < off + hlen + 24 + 4 {
            return Err(DsmError::serialization_error(
                "envelope",
                "truncated body",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let header_bytes = &envelope_bytes[off..off + hlen];
        off += hlen;

        // Sanity: ensure header declares XChaCha-only and version >= 3
        let (hdr, _) = VaultHeader::decode_fixed(header_bytes)?;
        if hdr.algo_id != 1 || hdr.nonce_len != 24 {
            return Err(DsmError::serialization_error(
                "envelope",
                "unsupported algo/nonce in import",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        if hdr.version < 3 {
            return Err(DsmError::serialization_error(
                "envelope",
                "older header version not supported",
                None::<String>,
                None::<std::io::Error>,
            ));
        }

        // Skip nonce + cipher_len to reach ciphertext slice for address computation
        let _nonce = &envelope_bytes[off..off + 24];
        off += 24;
        let clen = rd_u32(envelope_bytes, &mut off)? as usize;
        if envelope_bytes.len() < off + clen {
            return Err(DsmError::serialization_error(
                "envelope",
                "truncated ciphertext",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let ciphertext = &envelope_bytes[off..off + clen];

        let addr: [u8; 32] = {
            let mut h = dsm_domain_hasher("DSM/vault-envelope-v2");
            h.update(header_bytes);
            h.update(ciphertext);
            *h.finalize().as_bytes()
        };

        // Atomic write with deterministic retries
        let path = self.key_path(alias, purpose, &key_type);
        let lock_path = path.with_extension("vault.lock");
        let mut have_lock = false;
        for _ in 0..1024 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut lockf) => {
                    let _ = lockf.write_all(b"1");
                    have_lock = true;
                    break;
                }
                Err(_) => { /* retry deterministically */ }
            }
        }
        if !have_lock {
            return Err(DsmError::storage(
                "lock acquisition failed (deterministic retries exhausted)",
                None::<std::io::Error>,
            ));
        }

        let tmp_path = path.with_extension("vault.tmp");
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                DsmError::storage(
                    format!("create tmp vault file: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        f.write_all(envelope_bytes)?;
        f.flush()?;
        // Restrict file permissions to owner-only (private key material)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        fs::rename(&tmp_path, &path).map_err(|e| {
            DsmError::storage(format!("atomic rename: {e}"), None::<std::io::Error>)
        })?;
        let _ = fs::remove_file(&lock_path);
        Ok(addr)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_store_retrieve_delete() {
        let dir = tempfile::tempdir().unwrap();
        let device_id = "dev-123".to_string();
        let binder = TestBindingKeyProvider::new(device_id.clone());
        let vault = SoftVaultKeyStorage::new(dir.path(), device_id.clone(), binder, None).unwrap();

        let key = b"super_secret_key_material_here";
        let addr = vault
            .store_key("device_signing", KeyType::DeviceSphincsSk, key)
            .unwrap();
        assert_ne!(addr, [0u8; 32]);

        let loaded = vault
            .retrieve_key("device_signing", KeyType::DeviceSphincsSk)
            .unwrap();
        assert_eq!(loaded, key);

        vault
            .delete_key("device_signing", KeyType::DeviceSphincsSk)
            .unwrap();
        let _err = vault
            .retrieve_key("device_signing", KeyType::DeviceSphincsSk)
            .unwrap_err();
    }

    #[test]
    fn wrong_passphrase_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let device_id = "dev-xyz".to_string();
        let binder = TestBindingKeyProvider::new(device_id.clone());
        let vault_ok = SoftVaultKeyStorage::new(
            dir.path(),
            device_id.clone(),
            binder,
            Some("correct horse battery staple"),
        )
        .unwrap();
        let key = b"material";
        vault_ok
            .store_key("k", KeyType::DeviceKyberSk, key)
            .unwrap();

        // New instance with wrong passphrase
        let binder2 = TestBindingKeyProvider::new(device_id.clone());
        let vault_bad = SoftVaultKeyStorage::new(
            dir.path(),
            device_id.clone(),
            binder2,
            Some("incorrect passphrase"),
        )
        .unwrap();
        let _err = vault_bad
            .retrieve_key("k", KeyType::DeviceKyberSk)
            .unwrap_err();
    }

    #[test]
    fn tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let device_id = "dev-tamper".to_string();
        let binder = TestBindingKeyProvider::new(device_id.clone());
        let vault = SoftVaultKeyStorage::new(dir.path(), device_id.clone(), binder, None).unwrap();
        let key = b"K";
        vault.store_key("t", KeyType::TokenKey, key).unwrap();
        // Flip a byte in file
        let path = vault.key_path("t", "private_key", &KeyType::TokenKey);
        let mut bytes = std::fs::read(&path).unwrap();
        let blen = bytes.len();
        if blen > 12 {
            bytes[blen - 12] ^= 0xFF;
        }
        std::fs::write(&path, &bytes).unwrap();
        let _err = vault.retrieve_key("t", KeyType::TokenKey).unwrap_err();
    }

    #[test]
    fn export_import_roundtrip_dbrw() {
        // Validate that DbrwBindingKeyProvider is deterministic and importable.
        let dir = tempfile::tempdir().unwrap();
        let device_id = "dev-dbrw-1".to_string();
        let binder = DbrwBindingKeyProvider::new(device_id.clone());
        let vault =
            SoftVaultKeyStorage::new(dir.path(), device_id.clone(), binder, Some("pw")).unwrap();

        let key = b"db_key";
        vault.store_key("alias", KeyType::PeerKey, key).unwrap();
        let env = vault.export_envelope("alias", KeyType::PeerKey).unwrap();

        // Recreate with a fresh instance and same binder hint/passphrase
        let binder2 = DbrwBindingKeyProvider::new(device_id.clone());
        let vault2 =
            SoftVaultKeyStorage::new(dir.path(), device_id.clone(), binder2, Some("pw")).unwrap();
        let _addr = vault2
            .import_envelope("alias", KeyType::PeerKey, &env)
            .unwrap();
        let loaded = vault2.retrieve_key("alias", KeyType::PeerKey).unwrap();
        assert_eq!(loaded, key);
    }
}
