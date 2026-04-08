// File: dsm/src/core/identity/genesis.rs
//! DSM Genesis (STRICT, bytes-first)
//!
//! - Enforces MPC security invariants in-core (threshold ≥3; participants ≥3).
//! - DBRW is a local, optional anti-cloning signal; it must not be required for
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
    Ok(*crate::crypto::blake3::domain_hash("DSM/genesis-hash", data).as_bytes())
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

/// Production Genesis state (bytes-first)
#[derive(Debug, Clone)]
pub struct GenesisState {
    pub hash: [u8; 32],            // 32 bytes
    pub initial_entropy: [u8; 32], // 32 bytes
    pub threshold: usize,
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

fn calculate_genesis_hash(contributions: &[Vec<u8>], anchor: &[u8]) -> Result<[u8; 32], DsmError> {
    let mut hasher = dsm_domain_hasher("DSM/genesis");
    hasher.update(anchor);
    for contrib in contributions {
        hasher.update(contrib);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn calculate_initial_entropy(
    genesis_hash: &[u8],
    contributions: &[Vec<u8>],
) -> Result<[u8; 32], DsmError> {
    let mut hasher = dsm_domain_hasher("DSM/genesis");
    hasher.update(genesis_hash);
    for contrib in contributions {
        hasher.update(contrib);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn calculate_device_entropy(
    sub_genesis_hash: &[u8],
    master_entropy: &[u8],
    device_id: &str,
    device_specific_entropy: &[u8],
) -> Result<[u8; 32], DsmError> {
    let mut hasher = dsm_domain_hasher("DSM/genesis");
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
            *crate::crypto::blake3::domain_hash("DSM/device-id", device_id.as_bytes()).as_bytes(),
        ),
        signing_key,
        kyber_keypair,
        contributions: vec![Contribution {
            data: device_specific_entropy.to_vec(),
            verified: true,
        }],
        threshold: 3,
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

pub fn verify_genesis_state(genesis: &GenesisState) -> Result<bool, DsmError> {
    if genesis.threshold < 3 {
        return Ok(false);
    }
    if genesis.contributions.len() < genesis.threshold {
        return Ok(false);
    }

    let anchor = b"genesis";
    let contribs: Vec<Vec<u8>> = genesis
        .contributions
        .iter()
        .map(|c| c.data.clone())
        .collect();
    let calc_hash = calculate_genesis_hash(&contribs, anchor)?;
    if calc_hash != genesis.hash {
        return Ok(false);
    }

    let calc_entropy = calculate_initial_entropy(&genesis.hash, &contribs)?;
    if calc_entropy != genesis.initial_entropy {
        return Ok(false);
    }

    Ok(true)
}

// -------------------- MPC-only entrypoint --------------------

pub async fn create_genesis_via_blind_mpc(
    device_id: [u8; 32],
    storage_nodes: Vec<NodeId>,
    threshold: usize,
    metadata: Option<Vec<u8>>,
) -> Result<GenesisState, DsmError> {
    let session = crate::core::identity::genesis_mpc::create_mpc_genesis(
        device_id,
        storage_nodes,
        threshold,
        metadata,
    )
    .await?;

    let gs = convert_session_to_genesis_state_compat(&session)?;
    if !verify_genesis_state(&gs)? {
        return Err(DsmError::invalid_operation(
            "MPC genesis verification failed",
        ));
    }
    Ok(gs)
}

// -------------------- Device entropy (no DBRW) --------------------

pub fn get_device_entropy(
    device_id: &str,
) -> Result<Vec<u8>, crate::core::identity::IdentityError> {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/DEV_ENT/v2");
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
            threshold: 3,
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

pub fn convert_session_to_genesis_state_compat(
    session: &crate::core::identity::genesis_mpc::GenesisSession,
) -> Result<GenesisState, DsmError> {
    // Build deterministic contribution set from the session (bytes-only)
    let mut contribs: Vec<Vec<u8>> = Vec::new();

    // Device contribution = device_id || device_entropy
    let mut dev = Vec::with_capacity(64);
    dev.extend_from_slice(&session.device_id);
    dev.extend_from_slice(&session.device_entropy);
    contribs.push(dev);

    // NOTE: DBRW is record-only; do not bind genesis to it.

    // MPC entropies
    for m in &session.mpc_entropies {
        contribs.push(m.to_vec());
    }

    // Include metadata to stabilize derivation
    contribs.push(session.metadata.clone());

    let hash = calculate_genesis_hash(&contribs, b"genesis")?;
    let initial_entropy = calculate_initial_entropy(&hash, &contribs)?;

    let signing_key = SigningKey::new()?;
    let kyber_keypair = KyberKey::new()?;

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
        threshold: session.threshold,
        participants,
        merkle_root: None,
        device_id: Some(session.device_id),
        signing_key,
        kyber_keypair,
        contributions,
    };

    if gs.threshold < 3 {
        return Err(DsmError::invalid_parameter(
            "GenesisSession threshold < 3 is not permitted",
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
                threshold: 3,
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
        let threshold = 3;

        let res =
            create_genesis_via_blind_mpc(device_id, nodes, threshold, Some(b"test".to_vec())).await;

        let genesis = match res {
            Ok(g) => g,
            Err(e) => panic!("create_genesis_via_blind_mpc should succeed: {e:?}"),
        };

        assert_eq!(genesis.threshold, threshold);
        assert_eq!(genesis.hash.len(), 32);
        assert_eq!(genesis.initial_entropy.len(), 32);
    }

    #[test]
    fn test_device_genesis_derivation() {
        let participants = vec!["p1".to_string(), "p2".to_string(), "p3".to_string()];
        let master = GenesisState {
            hash: [1u8; 32],
            initial_entropy: [2u8; 32],
            threshold: 3,
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

        assert_eq!(device.threshold, 3);
        assert_eq!(device.participants.len(), 1);
        assert!(device.merkle_root.is_some());
        assert_eq!(device.merkle_root.unwrap(), master.hash);
        assert_eq!(
            device.device_id.unwrap(),
            *crate::crypto::blake3::domain_hash("DSM/device-id", device_id.as_bytes()).as_bytes()
        );
        assert_eq!(device.hash.len(), 32);
        assert_eq!(device.initial_entropy.len(), 32);
    }

    #[tokio::test]
    async fn test_verification_mpc() {
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let device_id = [7u8; 32];

        let genesis = match create_genesis_via_blind_mpc(device_id, nodes, 3, None).await {
            Ok(g) => g,
            Err(e) => panic!("create_genesis_via_blind_mpc should succeed: {e:?}"),
        };

        let ok = match verify_genesis_state(&genesis) {
            Ok(v) => v,
            Err(e) => panic!("verify_genesis_state should be callable: {e:?}"),
        };
        assert!(ok);
    }

    #[tokio::test]
    async fn test_quantum_resistant_keys() {
        use crate::crypto::sphincs::SphincsVariant;

        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let device_id = [0x11; 32];

        let g = match create_genesis_via_blind_mpc(device_id, nodes, 3, None).await {
            Ok(x) => x,
            Err(_) => return,
        };

        assert!(!g.signing_key.public_key.is_empty());
        assert!(!g.signing_key.secret_key.is_empty());
        assert!(!g.kyber_keypair.public_key.is_empty());
        assert!(!g.kyber_keypair.secret_key.is_empty());

        assert_eq!(
            g.signing_key.public_key.len(),
            sphincs::public_key_bytes(SphincsVariant::SPX256s)
        );
        assert_eq!(
            g.signing_key.secret_key.len(),
            sphincs::secret_key_bytes(SphincsVariant::SPX256s)
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
}
