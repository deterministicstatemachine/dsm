//! Persistent SPHINCS+ keypair used by this storage node for genesis-MPC
//! commit/reveal signatures (spec §5 / plan Task A.2).
//!
//! # Lifecycle
//!
//! - **First startup:** generate a fresh SPHINCS+ keypair (SPX256f),
//!   generate a random 32-byte AEAD salt, AEAD-encrypt the secret key
//!   with a salt-derived key, persist three files in `state_dir`
//!   (all created with mode 0600):
//!     - `mpc_key.bin`        — encrypted SK (XChaCha20-Poly1305)
//!     - `mpc_key.pub`        — public key (plain)
//!     - `mpc_aead_salt.bin`  — 32-byte salt
//! - **Subsequent startup:** read the three files, decrypt the SK,
//!   return the key in memory wrapped in a zero-on-drop guard.
//!
//! # Threat model
//!
//! The AEAD-at-rest layer prevents accidental SK exfiltration via:
//! - plain `cp -r state_dir/` snapshots / backups
//! - hosting-provider disk snapshots where the salt file isn't co-located
//! - shipping a SQLite dump that happens to live next to `mpc_key.bin`
//!
//! It does NOT prevent root-on-host compromise — at that point the SK
//! is also in process memory and the salt is on the same disk. For
//! mainnet, operator-passphrase-derived encryption (with prompt at
//! every restart) would close that gap at the cost of blocking
//! unattended restarts. The chosen posture is consistent with
//! `dsm_sdk::storage::client_db::cert_chain`, which uses the same
//! XChaCha20-Poly1305 + BLAKE3-domain-tagged-key envelope (cert-chain
//! sources its binding from `K_DBRW`; storage nodes source theirs from
//! a local random salt since they don't have silicon binding).
//!
//! # File format
//!
//! `mpc_key.bin`:
//! - Bytes 0..24: random nonce
//! - Bytes 24..:  ciphertext + 16-byte AEAD tag
//!
//! `mpc_aead_salt.bin`:
//! - 32 bytes of OS RNG output.
//!
//! `mpc_key.pub`:
//! - Raw SPHINCS+ public key bytes (length determined by SPX256f).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dsm::crypto::sphincs::{generate_sphincs_keypair, SphincsVariant};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain tag for deriving the AEAD key from the persisted salt.
/// Distinct from `dsm_sdk`'s cert-chain tag so an accidental salt
/// reuse across components doesn't produce the same AEAD key.
const STORAGE_NODE_MPC_AEAD_DOMAIN: &str = "DSM/storage-node-mpc-aead";

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// SPHINCS+ AEAD tag length (poly1305).
const AEAD_TAG_LEN: usize = 16;

/// AAD pinned to the file format so a swap between MPC-key ciphertext
/// and any other future encrypted blob fails decryption rather than
/// silently producing wrong plaintext.
const STORAGE_NODE_MPC_AAD: &[u8] = b"DSM/storage-node-mpc-key-v1\0";

/// Per-node SPHINCS+ keypair used for genesis-MPC participation
/// signatures. The secret key is wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StorageNodeMpcKey {
    #[zeroize(skip)]
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl StorageNodeMpcKey {
    /// Returns a borrowed view of the secret key bytes. Callers MUST
    /// NOT clone these bytes into long-lived buffers; the zeroize
    /// drop only protects the bytes stored in this struct.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

impl std::fmt::Debug for StorageNodeMpcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageNodeMpcKey")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key_len", &self.secret_key.len())
            .finish_non_exhaustive()
    }
}

/// Errors surfaced while loading or generating the MPC key. All
/// variants are terminal — the node MUST refuse to start if any
/// MpcKeyError surfaces during `load_or_generate_mpc_key`.
#[derive(Debug, Error)]
pub enum MpcKeyError {
    #[error("MPC state directory I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("SPHINCS+ keypair generation failed: {0}")]
    Keygen(String),
    #[error("AEAD encrypt failed (unable to seal MPC secret key)")]
    AeadEncrypt,
    #[error(
        "AEAD decrypt failed (tampered ciphertext, wrong salt, or partial file write); \
         refusing to start"
    )]
    AeadDecrypt,
    #[error("on-disk MPC files are inconsistent: {0}")]
    Inconsistent(&'static str),
}

/// Load the storage node's MPC keypair from `state_dir`, or generate
/// + persist a new one if any of the three files are missing.
///
/// Caller invariant: `state_dir` already exists and is writable.
/// This function creates it if missing (with 0700 on Unix) to make
/// first-startup simpler, but a misconfigured deployment that points
/// `state_dir` at a non-creatable path will surface `Io`.
///
/// On success, the three files in `state_dir` are guaranteed:
/// - `mpc_aead_salt.bin` (32 bytes, mode 0600)
/// - `mpc_key.bin`       (≥ 40 bytes — nonce + ciphertext + tag — mode 0600)
/// - `mpc_key.pub`       (SPHINCS+ public key, mode 0600)
pub fn load_or_generate_mpc_key(state_dir: &Path) -> Result<StorageNodeMpcKey, MpcKeyError> {
    if !state_dir.exists() {
        fs::create_dir_all(state_dir)?;
        set_permissions_strict(state_dir, 0o700)?;
    }

    let salt_path = state_dir.join("mpc_aead_salt.bin");
    let sk_path = state_dir.join("mpc_key.bin");
    let pk_path = state_dir.join("mpc_key.pub");

    let all_present = salt_path.exists() && sk_path.exists() && pk_path.exists();
    let any_present = salt_path.exists() || sk_path.exists() || pk_path.exists();

    if any_present && !all_present {
        return Err(MpcKeyError::Inconsistent(
            "partial MPC key state on disk; refuse to overwrite (delete state_dir/mpc_*\
             manually after taking a backup to force regeneration)",
        ));
    }

    if !all_present {
        return generate_and_persist(&salt_path, &sk_path, &pk_path);
    }

    load_existing(&salt_path, &sk_path, &pk_path)
}

fn generate_and_persist(
    salt_path: &Path,
    sk_path: &Path,
    pk_path: &Path,
) -> Result<StorageNodeMpcKey, MpcKeyError> {
    // 1. SPHINCS+ keygen.
    let (public_key, mut secret_key) =
        generate_sphincs_keypair().map_err(|e| MpcKeyError::Keygen(format!("{e:?}")))?;

    // 2. Random salt.
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // 3. Derive AEAD key + seal SK.
    let aead_key = derive_aead_key(&salt);
    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|_| MpcKeyError::AeadEncrypt)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &secret_key,
                aad: STORAGE_NODE_MPC_AAD,
            },
        )
        .map_err(|_| MpcKeyError::AeadEncrypt)?;

    // 4. Atomic-ish write: write each file, then chmod.
    write_strict(salt_path, &salt)?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&ciphertext);
    write_strict(sk_path, &sealed)?;
    write_strict(pk_path, &public_key)?;

    // 5. Wipe local copies of bytes we just wrote; struct holds the
    //    plaintext SK going forward, zeroized on drop.
    salt.zeroize();
    nonce_bytes.zeroize();
    let sk_for_struct = std::mem::take(&mut secret_key);
    Ok(StorageNodeMpcKey {
        public_key,
        secret_key: sk_for_struct,
    })
}

fn load_existing(
    salt_path: &Path,
    sk_path: &Path,
    pk_path: &Path,
) -> Result<StorageNodeMpcKey, MpcKeyError> {
    let salt = read_exact_len(salt_path, SALT_LEN)?;
    let sealed = read_to_vec(sk_path)?;
    let public_key = read_to_vec(pk_path)?;

    if sealed.len() < NONCE_LEN + AEAD_TAG_LEN {
        return Err(MpcKeyError::Inconsistent(
            "mpc_key.bin too short to contain nonce + ciphertext + AEAD tag",
        ));
    }

    let aead_key = derive_aead_key(&salt);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&aead_key).map_err(|_| MpcKeyError::AeadDecrypt)?;
    let (nonce_bytes, ct_with_tag) = sealed.split_at(NONCE_LEN);
    let secret_key = cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ct_with_tag,
                aad: STORAGE_NODE_MPC_AAD,
            },
        )
        .map_err(|_| MpcKeyError::AeadDecrypt)?;

    // SK length sanity check matches the variant we encode with.
    let expected_sk_len = dsm::crypto::sphincs::secret_key_bytes(SphincsVariant::SPX256f);
    if secret_key.len() != expected_sk_len {
        return Err(MpcKeyError::Inconsistent(
            "decrypted SPHINCS+ secret key has unexpected length for SPX256f variant",
        ));
    }
    let expected_pk_len = dsm::crypto::sphincs::public_key_bytes(SphincsVariant::SPX256f);
    if public_key.len() != expected_pk_len {
        return Err(MpcKeyError::Inconsistent(
            "stored SPHINCS+ public key has unexpected length for SPX256f variant",
        ));
    }

    Ok(StorageNodeMpcKey {
        public_key,
        secret_key,
    })
}

fn derive_aead_key(salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher(STORAGE_NODE_MPC_AEAD_DOMAIN);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

fn read_exact_len(path: &Path, expected_len: usize) -> Result<[u8; SALT_LEN], MpcKeyError> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; SALT_LEN];
    file.read_exact(&mut buf)?;
    let mut trailing = [0u8; 1];
    if let Ok(extra) = file.read(&mut trailing) {
        if extra != 0 {
            return Err(MpcKeyError::Inconsistent(
                "mpc_aead_salt.bin is longer than 32 bytes",
            ));
        }
    }
    let _ = expected_len; // pinned by the [u8; SALT_LEN] type.
    Ok(buf)
}

fn read_to_vec(path: &Path) -> Result<Vec<u8>, MpcKeyError> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_strict(path: &Path, bytes: &[u8]) -> Result<(), MpcKeyError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_permissions_strict(path, 0o600)?;
    Ok(())
}

#[cfg(unix)]
fn set_permissions_strict(path: &Path, mode: u32) -> Result<(), MpcKeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_permissions_strict(_path: &Path, _mode: u32) -> Result<(), MpcKeyError> {
    // On non-Unix the mode bits don't map; defer to platform ACLs.
    Ok(())
}

/// Convenience for tests / config helpers: default state-directory
/// path under `${HOME}/.dsm/storage-node` (or `./dsm-state` if HOME
/// is unset). Production deployments override this via the
/// `storage.state_dir` config key.
pub fn default_state_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".dsm/storage-node")
    } else {
        PathBuf::from("./dsm-state")
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn assert_sphincs_lengths(key: &StorageNodeMpcKey) {
        assert_eq!(
            key.public_key.len(),
            dsm::crypto::sphincs::public_key_bytes(SphincsVariant::SPX256f),
            "public key length mismatch for SPX256f"
        );
        assert_eq!(
            key.secret_key_bytes().len(),
            dsm::crypto::sphincs::secret_key_bytes(SphincsVariant::SPX256f),
            "secret key length mismatch for SPX256f"
        );
    }

    #[test]
    fn first_run_generates_and_persists_all_three_files() {
        let dir = tempdir().expect("tempdir");
        let key = load_or_generate_mpc_key(dir.path()).expect("first-run keygen");
        assert_sphincs_lengths(&key);
        assert!(dir.path().join("mpc_aead_salt.bin").exists());
        assert!(dir.path().join("mpc_key.bin").exists());
        assert!(dir.path().join("mpc_key.pub").exists());
    }

    #[test]
    fn second_run_reloads_same_keypair() {
        let dir = tempdir().expect("tempdir");
        let first = load_or_generate_mpc_key(dir.path()).expect("first-run keygen");
        let second = load_or_generate_mpc_key(dir.path()).expect("second-run load");
        assert_eq!(
            first.public_key, second.public_key,
            "public key must be stable across restart"
        );
        assert_eq!(
            first.secret_key_bytes(),
            second.secret_key_bytes(),
            "secret key must be stable across restart"
        );
    }

    #[test]
    fn missing_salt_with_present_sk_is_inconsistent() {
        let dir = tempdir().expect("tempdir");
        // Force partial state: pre-populate only mpc_key.bin
        std::fs::write(dir.path().join("mpc_key.bin"), b"unused").expect("write stub");
        match load_or_generate_mpc_key(dir.path()) {
            Err(MpcKeyError::Inconsistent(_)) => {}
            other => panic!("expected Inconsistent error, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_salt_yields_aead_decrypt_error() {
        let dir = tempdir().expect("tempdir");
        load_or_generate_mpc_key(dir.path()).expect("first-run keygen");
        // Flip a byte in the salt to simulate disk corruption / wrong salt.
        let salt_path = dir.path().join("mpc_aead_salt.bin");
        let mut salt = std::fs::read(&salt_path).expect("read salt");
        salt[0] ^= 0xFF;
        std::fs::write(&salt_path, salt).expect("write tampered salt");
        match load_or_generate_mpc_key(dir.path()) {
            Err(MpcKeyError::AeadDecrypt) => {}
            other => panic!("expected AeadDecrypt error, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_ciphertext_yields_aead_decrypt_error() {
        let dir = tempdir().expect("tempdir");
        load_or_generate_mpc_key(dir.path()).expect("first-run keygen");
        // Flip a byte in the ciphertext region (past the 24-byte nonce).
        let sk_path = dir.path().join("mpc_key.bin");
        let mut sealed = std::fs::read(&sk_path).expect("read sk");
        sealed[NONCE_LEN + 5] ^= 0xFF;
        std::fs::write(&sk_path, sealed).expect("write tampered sk");
        match load_or_generate_mpc_key(dir.path()) {
            Err(MpcKeyError::AeadDecrypt) => {}
            other => panic!("expected AeadDecrypt error, got {other:?}"),
        }
    }

    #[test]
    fn aead_key_derivation_is_deterministic() {
        let salt = [0xAB; SALT_LEN];
        let k1 = derive_aead_key(&salt);
        let k2 = derive_aead_key(&salt);
        assert_eq!(k1, k2);
        // Different salt → different key.
        let salt2 = [0xCD; SALT_LEN];
        let k3 = derive_aead_key(&salt2);
        assert_ne!(k1, k3);
    }
}
