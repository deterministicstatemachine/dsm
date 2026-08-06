// SPDX-License-Identifier: MIT OR Apache-2.0

// File: dsm/src/core/identity/genesis.rs
//! DSM Genesis (STRICT, bytes-first)
//!
//! - n-of-n commit-then-reveal entropy aggregation (participants ≥3); NOT
//!   threshold cryptography — every participant's contribution is required.
//! - GenesisV2 is mnemonic-rooted; no DBRW/anti-cloning signal is required for
//!   genesis / identity creation and is not part of genesis binding.
//! - No system wall-clock dependence.
//! - Bytes-only at logical boundaries; strings are local to display/IDs only.
//! - Hashing: BLAKE3 everywhere (32-byte outputs).

use crate::core::identity::Identity;
use crate::crypto::kyber;
use crate::crypto::sphincs;
use crate::types::error::DsmError;
use crate::types::identifiers::NodeId;

use rand::RngCore;
use std::collections::HashSet;
use crate::crypto::blake3::dsm_domain_hasher;

// -------------------- Helpers --------------------

#[inline]
#[allow(dead_code)]
fn generate_secure_random(rng: &mut impl RngCore, len: usize) -> Result<Vec<u8>, DsmError> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    Ok(bytes)
}

#[inline]
fn blake3_hash(data: &[u8]) -> Result<[u8; 32], DsmError> {
    Ok(*crate::crypto::blake3::domain_hash(
        crate::crypto::domain::TaggedHashDomain::from_static(b"DSM/genesis-hash"),
        data,
    )
    .as_bytes())
}

#[allow(dead_code)]
fn select_random_subset<T: Clone>(
    items: &[T],
    count: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<T>, DsmError> {
    if count > items.len() {
        return Err(DsmError::invalid_parameter(
            "Subset count larger than input size",
        ));
    }
    let mut indices: Vec<usize> = (0..items.len()).collect();
    for i in 0..count {
        let j = (rng.next_u32() as usize % (items.len() - i)) + i;
        indices.swap(i, j);
    }
    Ok(indices[..count].iter().map(|&i| items[i].clone()).collect())
}

// -------------------- Types --------------------

#[derive(Debug, Clone)]
pub struct StateUpdate {
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SigningKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct KyberKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Contribution {
    pub data: Vec<u8>,
    pub verified: bool,
}

/// Production Genesis state (bytes-first).
///
/// Per whitepaper §2.5 there is no threshold cryptography — `b_1, ..., b_n`
/// is index notation for "all n contributions" from `participants` (n ≥ 3).
/// The session is n-of-n commit-then-reveal, not t-of-n.
#[derive(Debug, Clone)]
pub struct GenesisState {
    pub hash: [u8; 32],            // 32 bytes
    pub initial_entropy: [u8; 32], // 32 bytes
    pub participants: HashSet<String>,
    pub merkle_root: Option<[u8; 32]>,
    pub device_id: Option<[u8; 32]>,
    pub signing_key: SigningKey,
    pub kyber_keypair: KyberKey,
    pub contributions: Vec<Contribution>,
}

impl zeroize::ZeroizeOnDrop for GenesisState {}
impl zeroize::Zeroize for GenesisState {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        self.kyber_keypair.zeroize();
        for c in &mut self.contributions {
            c.data.zeroize();
        }
        if let Some(mr) = &mut self.merkle_root {
            mr.zeroize();
        }
        self.hash.zeroize();
        self.initial_entropy.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct GenesisParameters {
    pub node_id: String,
    pub version: String,
    pub metadata: String,
}

#[derive(Debug, Clone)]
pub struct GenesisDeviceKey {
    pub public_key: [u8; 32],
    pub device_binding: [u8; 32],
}
impl GenesisDeviceKey {
    pub fn new() -> Result<Self, DsmError> {
        Ok(Self {
            public_key: [0u8; 32],
            device_binding: [0u8; 32],
        })
    }
}

// -------------------- PQ Key Impl --------------------

impl SigningKey {
    pub fn new() -> Result<Self, DsmError> {
        let (pk, sk) = sphincs::generate_sphincs_keypair()?;
        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    #[allow(dead_code)]
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DsmError> {
        sphincs::sphincs_sign(&self.secret_key, message)
    }

    #[allow(dead_code)]
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, DsmError> {
        sphincs::sphincs_verify(&self.public_key, message, signature)
    }
}

impl KyberKey {
    pub fn new() -> Result<Self, DsmError> {
        let keypair = kyber::generate_kyber_keypair()?;
        Ok(Self {
            public_key: keypair.public_key.clone(),
            secret_key: keypair.secret_key.clone(),
        })
    }

    #[allow(dead_code)]
    fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        let (ss, ct) = kyber::kyber_encapsulate(recipient_public_key)?;
        Ok((ss, ct))
    }

    #[allow(dead_code)]
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DsmError> {
        kyber::kyber_decapsulate(&self.secret_key, ciphertext)
    }
}

// -------------------- Core hashing --------------------

/// Per-genesis initial entropy seed (distinct sub-domain so the value
/// is independent of the genesis hash even when inputs partially overlap).
fn calculate_initial_entropy(
    genesis_hash: &[u8],
    contributions: &[Vec<u8>],
) -> Result<[u8; 32], DsmError> {
    let mut hasher = dsm_domain_hasher(crate::crypto::domain::TaggedHashDomain::from_static(
        b"DSM/genesis-initial-entropy",
    ));
    hasher.update(genesis_hash);
    for contrib in contributions {
        hasher.update(contrib);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Sub-genesis entropy derivation for a device under a master genesis.
/// Uses its own sub-domain so collisions with the genesis-hash and
/// initial-entropy derivations are structurally impossible.
fn calculate_device_entropy(
    sub_genesis_hash: &[u8],
    master_entropy: &[u8],
    device_id: &str,
    device_specific_entropy: &[u8],
) -> Result<[u8; 32], DsmError> {
    let mut hasher = dsm_domain_hasher(crate::crypto::domain::TaggedHashDomain::from_static(
        b"DSM/sub-genesis-device-entropy",
    ));
    hasher.update(sub_genesis_hash);
    hasher.update(master_entropy);
    hasher.update(device_id.as_bytes());
    hasher.update(device_specific_entropy);
    Ok(*hasher.finalize().as_bytes())
}

// -------------------- Genesis construction (STRICT) --------------------

pub fn derive_device_sub_genesis(
    master_genesis: &GenesisState,
    device_id: &str,
    device_specific_entropy: &[u8],
) -> Result<GenesisState, DsmError> {
    let mut combined = Vec::with_capacity(
        master_genesis.hash.len() + device_id.len() + device_specific_entropy.len(),
    );
    combined.extend_from_slice(&master_genesis.hash);
    combined.extend_from_slice(device_id.as_bytes());
    combined.extend_from_slice(device_specific_entropy);

    let sub_genesis_hash = blake3_hash(&combined)?;

    let signing_key = SigningKey::new()?;
    let kyber_keypair = KyberKey::new()?;

    Ok(GenesisState {
        hash: sub_genesis_hash,
        initial_entropy: calculate_device_entropy(
            &sub_genesis_hash,
            &master_genesis.initial_entropy,
            device_id,
            device_specific_entropy,
        )?,
        participants: HashSet::from([device_id.to_string()]),
        merkle_root: Some(master_genesis.hash),
        device_id: Some(
            *crate::crypto::blake3::domain_hash(
                crate::crypto::domain::TaggedHashDomain::from_static(b"DSM/device-id"),
                device_id.as_bytes(),
            )
            .as_bytes(),
        ),
        signing_key,
        kyber_keypair,
        contributions: vec![Contribution {
            data: device_specific_entropy.to_vec(),
            verified: true,
        }],
    })
}

// -------------------- Invalidation --------------------

const INVALIDATION_REQUEST_DOMAIN: &[u8] = b"DSM/identity/invalidate\0";

pub fn create_invalidation_request(identity: &Identity, reason: &str) -> Result<Vec<u8>, DsmError> {
    let reason_bytes = reason.as_bytes();
    let reason_len = u32::try_from(reason_bytes.len())
        .map_err(|_| DsmError::invalid_operation("Invalidation reason exceeds u32 length"))?;

    let mut out = Vec::with_capacity(
        INVALIDATION_REQUEST_DOMAIN.len()
            + identity.master_genesis.hash.len()
            + 4
            + reason_bytes.len(),
    );
    out.extend_from_slice(INVALIDATION_REQUEST_DOMAIN);
    out.extend_from_slice(&identity.master_genesis.hash);
    out.extend_from_slice(&reason_len.to_be_bytes());
    out.extend_from_slice(reason_bytes);
    Ok(out)
}

pub fn process_invalidation(identity: &Identity, request: &[u8]) -> Result<bool, DsmError> {
    let expected_prefix_len =
        INVALIDATION_REQUEST_DOMAIN.len() + identity.master_genesis.hash.len() + 4;
    if request.len() < expected_prefix_len {
        return Ok(false);
    }

    let domain_end = INVALIDATION_REQUEST_DOMAIN.len();
    if &request[..domain_end] != INVALIDATION_REQUEST_DOMAIN {
        return Ok(false);
    }

    let genesis_end = domain_end + identity.master_genesis.hash.len();
    if request[domain_end..genesis_end] != identity.master_genesis.hash {
        return Ok(false);
    }

    let reason_len_end = genesis_end + 4;
    let reason_len = u32::from_be_bytes(
        request[genesis_end..reason_len_end]
            .try_into()
            .map_err(|_| DsmError::invalid_operation("Invalid invalidation length header"))?,
    ) as usize;

    if request.len() != reason_len_end + reason_len {
        return Ok(false);
    }

    std::str::from_utf8(&request[reason_len_end..])
        .map_err(|_| DsmError::invalid_operation("Invalid UTF-8 in invalidation request reason"))?;

    Ok(true)
}

// -------------------- Verification --------------------

/// Strict §2.5 verification of a `GenesisState`.
///
/// Because the canonical genesis hash `G` is acyclic and publicly
/// recomputable (it folds only `device_id` and `H(contribution_i)`), the
/// post-conversion `GenesisState` carries everything needed to recompute it.
/// This check therefore strict-fails unless:
///   - there are ≥3 contributions (whitepaper §2.5 floor; n-of-n),
///   - `hash`, `initial_entropy`, and `device_id` are present/non-zero,
///   - the canonical `G` recomputed from `(device_id, contributions)` equals
///     the stored `hash` (the substantive §2.5 check), and
///   - the initial-entropy seed re-derives from `(hash, contributions)` under
///     the `"DSM/genesis-initial-entropy"` sub-domain (defense in depth).
pub fn verify_genesis_state(genesis: &GenesisState) -> Result<bool, DsmError> {
    use crate::types::genesis_types::{compute_genesis_hash, hash_contribution, MPCContribution};

    if genesis.contributions.len() < 3 {
        return Ok(false);
    }
    if genesis.hash == [0u8; 32] || genesis.initial_entropy == [0u8; 32] {
        return Ok(false);
    }
    let device_id = match genesis.device_id {
        Some(d) => d,
        None => return Ok(false),
    };

    // Substantive §2.5 check: recompute the canonical genesis hash `G` from the
    // public inputs and strict-fail on mismatch. `contributor_id` is irrelevant
    // to `G` (sort tie-breaker only), so the empty id used here reproduces the
    // session's hash exactly.
    let contributions: Vec<MPCContribution> = genesis
        .contributions
        .iter()
        .map(|c| MPCContribution::new(String::new(), hash_contribution(&c.data), Vec::new(), 0))
        .collect();
    if compute_genesis_hash(&device_id, &contributions) != genesis.hash {
        return Ok(false);
    }

    // Defense in depth: the initial-entropy seed must re-derive from the same
    // `(hash, contributions)` tuple.
    let contribs: Vec<Vec<u8>> = genesis
        .contributions
        .iter()
        .map(|c| c.data.clone())
        .collect();
    if calculate_initial_entropy(&genesis.hash, &contribs)? != genesis.initial_entropy {
        return Ok(false);
    }

    Ok(true)
}

// -------------------- MPC-only entrypoint --------------------

pub async fn create_genesis_via_blind_mpc(
    device_id: [u8; 32],
    storage_nodes: Vec<NodeId>,
    metadata: Option<Vec<u8>>,
) -> Result<GenesisState, DsmError> {
    let session =
        crate::core::identity::genesis_session::create_genesis(device_id, storage_nodes, metadata)
            .await?;

    let gs = convert_session_to_genesis_state_compat(&session)?;
    if !verify_genesis_state(&gs)? {
        return Err(DsmError::invalid_operation(
            "MPC genesis verification failed",
        ));
    }
    Ok(gs)
}

pub fn create_genesis_via_blind_mpc_with_contributors(
    device_id: [u8; 32],
    storage_nodes: Vec<NodeId>,
    device_entropy: [u8; 32],
    mpc_entropies: Vec<[u8; 32]>,
    metadata: Option<Vec<u8>>,
) -> Result<GenesisState, DsmError> {
    let metadata = metadata.unwrap_or_else(|| b"DSMv2|bytes|no-wallclock".to_vec());

    let mut session = crate::core::identity::genesis_session::GenesisSession::new(metadata)?;
    session.initialize_mpc(device_id, storage_nodes)?;
    session.set_entropies(device_entropy, mpc_entropies)?;
    session.compute_commitments();
    session.compute_genesis_id();
    session.validate_session()?;

    let gs = convert_session_to_genesis_state_compat(&session)?;
    if !verify_genesis_state(&gs)? {
        return Err(DsmError::invalid_operation(
            "MPC genesis verification failed",
        ));
    }
    Ok(gs)
}

// -------------------- Device entropy --------------------

pub fn get_device_entropy(
    device_id: &str,
) -> Result<Vec<u8>, crate::core::identity::IdentityError> {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher(
        crate::crypto::domain::TaggedHashDomain::from_static(b"DSM/DEV_ENT/v2"),
    );
    hasher.update(device_id.as_bytes());
    Ok(hasher.finalize().as_bytes().to_vec())
}

// -------------------- GenesisState impl --------------------

impl GenesisState {
    pub fn new() -> Result<Self, DsmError> {
        let signing_key = SigningKey::new()?;
        let kyber_keypair = KyberKey::new()?;
        Ok(Self {
            hash: [0u8; 32],
            initial_entropy: [0u8; 32],
            signing_key,
            kyber_keypair,
            participants: HashSet::new(),
            merkle_root: Some([0u8; 32]),
            device_id: None,
            contributions: Vec::new(),
        })
    }

    pub fn get_signing_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.signing_key.secret_key.clone())
    }

    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.signing_key.public_key.clone())
    }
}

impl std::fmt::Display for GenesisState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GenesisState(hash={:?})", self.hash)
    }
}

// -------------------- Session compatibility --------------------

/// Result of canonical Genesis v2 creation: the in-memory [`GenesisState`] plus the PUBLIC
/// `genesis_nonce` and the [`crate::core::identity::genesis_v2::GenesisEntropyProfile`] the
/// caller persists into the GenesisRecord (so `G` is recoverable from the mnemonic).
pub struct GenesisV2Outcome {
    pub state: GenesisState,
    pub genesis_nonce: [u8; 32],
    pub profile: crate::core::identity::genesis_v2::GenesisEntropyProfile,
}

/// Canonical mnemonic-rooted genesis (whitepaper §2.5 v2; NO storage nodes / NO MPC).
///
/// Deterministically derives the full key tree from the BIP39 `wallet_seed` via
/// [`crate::core::identity::genesis_v2::derive_genesis_v2`] and packages it as a
/// [`GenesisState`]. The signing key is the AK keypair (rooted in `device_seed`, so it does
/// not depend on `DevID`); the ML-KEM keypair is derived from `Smaster` under `"DSM/kyber\0"`,
/// matching the master-keypair derivation. `Smaster`/`s0` are NOT persisted — they are
/// re-derived from the wallet seed on demand. Anti-clone is NOT established here.
#[allow(clippy::too_many_arguments)]
pub fn create_genesis_v2(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    device_slot: u32,
    genesis_version: u32,
    authority_policy_hash: &[u8; 32],
    atta: &[u8; 32],
) -> Result<GenesisV2Outcome, DsmError> {
    let v2 = crate::core::identity::genesis_v2::derive_genesis_v2(
        wallet_seed,
        network_id,
        wallet_index,
        device_slot,
        genesis_version,
        authority_policy_hash,
        atta,
    )?;

    // ML-KEM (Kyber) keypair from Smaster — the same context the master-keypair derivation uses.
    let (kyber_public, kyber_secret) =
        crate::crypto::kyber::generate_kyber_keypair_from_entropy(&v2.smaster, "DSM/kyber\0")?;

    let state = GenesisState {
        hash: v2.g,
        initial_entropy: v2.genesis_nonce, // public, deterministic; no MPC entropy in v2
        participants: HashSet::new(),      // no storage nodes for MnemonicV2
        merkle_root: None,
        device_id: Some(v2.devid),
        signing_key: SigningKey {
            public_key: v2.ak_public.clone(),
            secret_key: v2.ak_secret.clone(),
        },
        kyber_keypair: KyberKey {
            public_key: kyber_public,
            secret_key: kyber_secret,
        },
        contributions: Vec::new(),
    };

    Ok(GenesisV2Outcome {
        state,
        genesis_nonce: v2.genesis_nonce,
        profile: crate::core::identity::genesis_v2::GenesisEntropyProfile::MnemonicV2,
    })
}

/// Canonical mnemonic-rooted genesis with a self-derived (recoverable) device-birth `AttA`.
///
/// Computes the public genesis digest `G` first, derives `AttA = derive_atta(wallet_seed, G,
/// device_slot)` (deterministic, recoverable, no silicon / no random root), then runs
/// [`create_genesis_v2`]. This is the SDK/Android wallet-creation entry point: the only secret
/// input is the BIP39 `wallet_seed`. Returns the same [`GenesisV2Outcome`].
pub fn create_genesis_v2_self_attested(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    device_slot: u32,
    genesis_version: u32,
    authority_policy_hash: &[u8; 32],
) -> Result<GenesisV2Outcome, DsmError> {
    use crate::core::identity::genesis_v2::{derive_atta, derive_genesis_g, derive_genesis_nonce};
    let genesis_nonce = derive_genesis_nonce(wallet_seed, network_id, wallet_index);
    let g = derive_genesis_g(&genesis_nonce, network_id, genesis_version);
    let atta = derive_atta(wallet_seed, &g, device_slot);
    create_genesis_v2(
        wallet_seed,
        network_id,
        wallet_index,
        device_slot,
        genesis_version,
        authority_policy_hash,
        &atta,
    )
}

pub fn convert_session_to_genesis_state_compat(
    session: &crate::core::identity::genesis_session::GenesisSession,
) -> Result<GenesisState, DsmError> {
    // Canonical contribution materials `[device_id ∥ device_entropy, b_1, …, b_n]`
    // — exactly the bytes the session hashed into `G`. Metadata is
    // NOT contributions and are excluded (they don't bind `G`).
    let contribs: Vec<Vec<u8>> = session.canonical_contribution_materials();

    // Use the session's genesis_id directly (computed per whitepaper §2.5 in
    // genesis_session::compute_genesis_id) so the value the caller sees matches
    // the value the session validated.  This closes Issue #252's sub-bug 3
    // (caller-returned hash differing from session-level hash) and is exactly
    // what `verify_genesis_state` recomputes from these stored contributions.
    let hash = session.genesis_id;
    let initial_entropy = calculate_initial_entropy(&hash, &contribs)?;

    // Master keypair per whitepaper §12 eq.13.  The CSPRNG secret root s0 is
    // folded into Smaster; both keypairs are deterministic given (s0, device_id,
    // authority_policy_hash).  The genesis_session derivation zeroises its
    // IKM/seed buffers internally.
    let mk = session.derive_master_keypair()?;
    let signing_key = SigningKey {
        public_key: mk.sphincs_public.clone(),
        secret_key: mk.sphincs_secret.clone(),
    };
    let kyber_keypair = KyberKey {
        public_key: mk.kyber_public.clone(),
        secret_key: mk.kyber_secret.clone(),
    };

    let participants: HashSet<String> = session
        .storage_nodes
        .iter()
        .map(|n| String::from_utf8_lossy(n.as_bytes()).into_owned())
        .collect();

    let contributions: Vec<Contribution> = contribs
        .iter()
        .map(|c| Contribution {
            data: c.clone(),
            verified: true,
        })
        .collect();

    let gs = GenesisState {
        hash,
        initial_entropy,
        participants,
        merkle_root: None,
        device_id: Some(session.device_id),
        signing_key,
        kyber_keypair,
        contributions,
    };

    if session.storage_nodes.len() < 3 {
        return Err(DsmError::invalid_parameter(
            "GenesisSession must have ≥3 storage_nodes (whitepaper §2.5)",
        ));
    }
    Ok(gs)
}

// -------------------- Tests --------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(name: &str, hash_byte: u8) -> Identity {
        Identity::with_genesis(
            name.to_string(),
            GenesisState {
                hash: [hash_byte; 32],
                initial_entropy: [hash_byte.wrapping_add(1); 32],
                participants: ["p1".to_string(), "p2".to_string(), "p3".to_string()]
                    .into_iter()
                    .collect(),
                merkle_root: None,
                device_id: None,
                signing_key: SigningKey::new().expect("signing key"),
                kyber_keypair: KyberKey::new().expect("kyber key"),
                contributions: vec![],
            },
        )
    }

    #[tokio::test]
    async fn test_genesis_state_creation_mpc_only() {
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let device_id = [0xAB; 32];
        let res = create_genesis_via_blind_mpc(device_id, nodes, Some(b"test".to_vec())).await;

        let genesis = match res {
            Ok(g) => g,
            Err(e) => panic!("create_genesis_via_blind_mpc should succeed: {e:?}"),
        };

        assert_eq!(genesis.participants.len(), 3);
        assert_eq!(genesis.hash.len(), 32);
        assert_eq!(genesis.initial_entropy.len(), 32);
    }

    #[test]
    fn test_device_genesis_derivation() {
        let participants = vec!["p1".to_string(), "p2".to_string(), "p3".to_string()];
        let master = GenesisState {
            hash: [1u8; 32],
            initial_entropy: [2u8; 32],
            participants: participants.into_iter().collect(),
            merkle_root: None,
            device_id: None,
            signing_key: SigningKey::new().unwrap(),
            kyber_keypair: KyberKey::new().unwrap(),
            contributions: vec![],
        };

        let device_id = "device1";
        let device_entropy = b"device-specific-entropy";

        let device = match derive_device_sub_genesis(&master, device_id, device_entropy) {
            Ok(d) => d,
            Err(e) => panic!("derive_device_sub_genesis should succeed: {e:?}"),
        };

        assert_eq!(device.participants.len(), 1);
        assert!(device.merkle_root.is_some());
        assert_eq!(device.merkle_root.unwrap(), master.hash);
        assert_eq!(
            device.device_id.unwrap(),
            *crate::crypto::blake3::domain_hash(
                crate::crypto::domain::TaggedHashDomain::from_static(b"DSM/device-id"),
                device_id.as_bytes()
            )
            .as_bytes()
        );
        assert_eq!(device.hash.len(), 32);
        assert_eq!(device.initial_entropy.len(), 32);
    }

    #[tokio::test]
    async fn test_verification_mpc() {
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let device_id = [7u8; 32];
        let genesis = match create_genesis_via_blind_mpc(device_id, nodes, None).await {
            Ok(g) => g,
            Err(e) => panic!("create_genesis_via_blind_mpc should succeed: {e:?}"),
        };

        let ok = match verify_genesis_state(&genesis) {
            Ok(v) => v,
            Err(e) => panic!("verify_genesis_state should be callable: {e:?}"),
        };
        assert!(ok);
    }

    #[test]
    fn test_mpc_genesis_with_provided_contributors_preserves_entropy_bytes() {
        let device_id = [0x41; 32];
        let device_entropy = [0x52; 32];
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let node_entropies = vec![[0x61; 32], [0x62; 32], [0x63; 32]];
        let metadata = b"meta".to_vec();
        let genesis = create_genesis_via_blind_mpc_with_contributors(
            device_id,
            nodes,
            device_entropy,
            node_entropies.clone(),
            Some(metadata.clone()),
        )
        .expect("provided contributors should build a valid genesis state");

        // Canonical materials: device contribution + one per node. Metadata is
        // NOT a contribution and is excluded from `G`.
        assert_eq!(genesis.contributions.len(), 1 + node_entropies.len());

        let mut expected_device_contribution = Vec::with_capacity(64);
        expected_device_contribution.extend_from_slice(&device_id);
        expected_device_contribution.extend_from_slice(&device_entropy);
        assert_eq!(genesis.contributions[0].data, expected_device_contribution);
        assert_eq!(genesis.contributions[1].data, node_entropies[0].to_vec());
        assert_eq!(genesis.contributions[2].data, node_entropies[1].to_vec());
        assert_eq!(genesis.contributions[3].data, node_entropies[2].to_vec());

        // The produced hash must strictly re-verify (canonical §2.5 recompute).
        assert!(verify_genesis_state(&genesis).expect("verify is callable"));
    }

    #[tokio::test]
    async fn test_quantum_resistant_keys() {
        use crate::crypto::sphincs::SphincsVariant;

        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let device_id = [0x11; 32];
        let g = match create_genesis_via_blind_mpc(device_id, nodes, None).await {
            Ok(x) => x,
            Err(_) => return,
        };

        assert!(!g.signing_key.public_key.is_empty());
        assert!(!g.signing_key.secret_key.is_empty());
        assert!(!g.kyber_keypair.public_key.is_empty());
        assert!(!g.kyber_keypair.secret_key.is_empty());

        assert_eq!(
            g.signing_key.public_key.len(),
            sphincs::public_key_bytes(SphincsVariant::SPX256f)
        );
        assert_eq!(
            g.signing_key.secret_key.len(),
            sphincs::secret_key_bytes(SphincsVariant::SPX256f)
        );
        assert_eq!(g.kyber_keypair.public_key.len(), kyber::public_key_bytes());
        assert_eq!(g.kyber_keypair.secret_key.len(), kyber::secret_key_bytes());
    }

    #[test]
    fn test_invalidation_request_is_bound_to_exact_master_genesis_hash() {
        let identity_a = test_identity("alice", 0x11);
        let identity_b = test_identity("alice-clone", 0x22);

        let request = create_invalidation_request(&identity_a, "device compromise")
            .expect("binary invalidation request should be created");

        assert!(
            request.starts_with(INVALIDATION_REQUEST_DOMAIN),
            "request must use the canonical binary invalidation domain"
        );
        assert!(process_invalidation(&identity_a, &request)
            .expect("owner identity must accept its own request"));
        assert!(!process_invalidation(&identity_b, &request)
            .expect("different identities must not accept replayed requests"));
    }

    #[test]
    fn create_genesis_v2_is_deterministic_and_mnemonic_rooted() {
        use crate::core::identity::genesis_v2::{derive_genesis_v2, GenesisEntropyProfile};
        let seed = b"bip39-wallet-seed-deterministic-test-............................";
        let net = b"dsm-test";
        let aph = [0x11u8; 32];
        let atta = [0x22u8; 32];

        let a = create_genesis_v2(seed, net, 0, 0, 2, &aph, &atta).expect("v2 genesis");
        let b = create_genesis_v2(seed, net, 0, 0, 2, &aph, &atta).expect("v2 genesis");

        // Canonical profile + no storage nodes / no MPC contributions.
        assert_eq!(a.profile, GenesisEntropyProfile::MnemonicV2);
        assert!(a.state.participants.is_empty());
        assert!(a.state.contributions.is_empty());

        // Fully deterministic from the wallet seed (recovery re-derives identically).
        assert_eq!(a.genesis_nonce, b.genesis_nonce);
        assert_eq!(a.state.hash, b.state.hash);
        assert_eq!(a.state.device_id, b.state.device_id);
        assert_eq!(
            a.state.signing_key.public_key,
            b.state.signing_key.public_key
        );
        assert_eq!(
            a.state.kyber_keypair.public_key,
            b.state.kyber_keypair.public_key
        );

        // GenesisState matches the underlying chain (G, DevID, AK pk).
        let v2 = derive_genesis_v2(seed, net, 0, 0, 2, &aph, &atta).expect("chain");
        assert_eq!(a.state.hash, v2.g);
        assert_eq!(a.state.device_id, Some(v2.devid));
        assert_eq!(a.state.signing_key.public_key, v2.ak_public);
        assert_eq!(a.genesis_nonce, v2.genesis_nonce);

        // A different wallet seed yields a different genesis + identity.
        let c = create_genesis_v2(
            b"a-different-wallet-seed-of-some-length-........",
            net,
            0,
            0,
            2,
            &aph,
            &atta,
        )
        .expect("v2 genesis");
        assert_ne!(a.state.hash, c.state.hash);
        assert_ne!(a.state.device_id, c.state.device_id);
        assert_ne!(
            a.state.signing_key.public_key,
            c.state.signing_key.public_key
        );
    }

    #[test]
    fn create_genesis_v2_self_attested_is_deterministic_and_recoverable() {
        use crate::core::identity::genesis_v2::{
            derive_atta, derive_genesis_g, derive_genesis_nonce, GenesisEntropyProfile,
        };
        let seed = b"bip39-wallet-seed-self-attested-test-............................";
        let net = b"dsm-test";
        let aph = [0x33u8; 32];

        // The canonical Android/SDK wallet-creation entry: only the wallet seed is secret.
        let a =
            create_genesis_v2_self_attested(seed, net, 0, 0, 2, &aph).expect("self-attested v2");
        let b =
            create_genesis_v2_self_attested(seed, net, 0, 0, 2, &aph).expect("self-attested v2");
        assert_eq!(a.profile, GenesisEntropyProfile::MnemonicV2);
        assert_eq!(a.state.hash, b.state.hash);
        assert_eq!(a.state.device_id, b.state.device_id);
        assert_eq!(a.genesis_nonce, b.genesis_nonce);

        // The self-derived AttA reproduces DevID from the mnemonic alone (recovery): the
        // self-attested DevID equals create_genesis_v2 with the explicitly-derived AttA.
        let nonce = derive_genesis_nonce(seed, net, 0);
        let g = derive_genesis_g(&nonce, net, 2);
        let atta = derive_atta(seed, &g, 0);
        let explicit = create_genesis_v2(seed, net, 0, 0, 2, &aph, &atta).expect("explicit v2");
        assert_eq!(a.state.device_id, explicit.state.device_id);
        assert_eq!(a.state.hash, explicit.state.hash);
        assert_eq!(a.genesis_nonce, explicit.genesis_nonce);

        // A different wallet seed yields a different self-attested identity.
        let c = create_genesis_v2_self_attested(
            b"another-self-attested-seed-of-length-....",
            net,
            0,
            0,
            2,
            &aph,
        )
        .expect("self-attested v2");
        assert_ne!(a.state.device_id, c.state.device_id);
    }
}
