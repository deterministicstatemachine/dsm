// File: dsm/src/core/identity/genesis_mpc.rs
//! DSM Genesis MPC Protocol Implementation (STRICT, bytes-only)
//!
//! Invariants:
//! - No wall-clock APIs. Use deterministic ticks (u64) from util::deterministic_time.
//! - No hex/base64 in data structures; bytes-only at boundaries.
//! - ≥3 storage nodes and threshold ≥3 (no 2-of-N), no alternate-path entropy.
//! - Storage/publishing is trait-only (SDK implements I/O).
//!
//! This module implements the MPC genesis creation protocol with commitment–reveal,
//! optional DBRW binding (record-only; not part of genesis binding), SPHINCS+ signing
//! keygen and Kyber KEM keygen hooks.

use crate::crypto::blake3::dsm_domain_hasher;

use async_trait::async_trait;
use std::io::Read;

use crate::crypto::kyber;
use crate::crypto::sphincs;
use crate::types::error::DsmError;
use crate::types::identifiers::NodeId;
use crate::util::deterministic_time;

// -------------------- Deterministic ticks --------------------

#[inline]
fn now_tick() -> u64 {
    deterministic_time::tick_index()
}

// -------------------- Traits (SDK implements real I/O) --------------------

/// Payload safe for external publication (bytes-only)
#[derive(Debug, Clone)]
pub struct SanitizedGenesisPayload {
    pub genesis_hash: [u8; 32],
    pub device_id: [u8; 32],
    pub public_key: Vec<u8>, // SPHINCS+ public key
    pub threshold: usize,
    pub participants: Vec<NodeId>,
    pub created_at_ticks: u64,
}

#[async_trait]
pub trait GenesisPublisher {
    async fn publish(&self, payload: &SanitizedGenesisPayload) -> Result<(), DsmError>;
    async fn retrieve(&self, genesis_hash: &[u8; 32]) -> Result<SanitizedGenesisPayload, DsmError>;
}

#[async_trait]
pub trait GenesisStorage {
    async fn put(&self, genesis_hash: &[u8; 32], payload: &[u8]) -> Result<(), DsmError>;
    async fn get(&self, genesis_hash: &[u8; 32]) -> Result<Vec<u8>, DsmError>;
}

/// Optional network transport for real MPC collection.
///
/// This is NOT required by the core convenience entrypoint (`create_mpc_genesis`),
/// but is provided for SDK integration.
#[async_trait]
pub trait GenesisMpcTransport {
    async fn collect_node_entropy(
        &self,
        node: &NodeId,
        session_id: &[u8; 32],
        device_commitment: &[u8; 32],
    ) -> Result<[u8; 32], DsmError>;
}

// -------------------- Keys (PQ primitives) --------------------

#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SigningKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}
impl SigningKey {
    pub fn new() -> Result<Self, DsmError> {
        let (pk, sk) = sphincs::generate_sphincs_keypair()?;
        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    #[allow(dead_code)]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DsmError> {
        sphincs::sphincs_sign(&self.secret_key, message)
    }

    #[allow(dead_code)]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, DsmError> {
        sphincs::sphincs_verify(&self.public_key, message, signature)
    }
}

#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct KyberKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}
impl KyberKey {
    pub fn new() -> Result<Self, DsmError> {
        let kp = kyber::generate_kyber_keypair()?;
        Ok(Self {
            public_key: kp.public_key.clone(),
            secret_key: kp.secret_key.clone(),
        })
    }
}

// -------------------- Genesis MPC session --------------------

#[derive(Debug, Clone)]
pub struct GenesisSession {
    /// Unique 256-bit session id
    pub session_id: [u8; 32],
    /// Device-specific entropy (32B)
    pub device_entropy: [u8; 32],
    /// DBRW binding (32B) when available (record-only, not part of genesis binding)
    pub dbrw_binding: Option<[u8; 32]>,
    /// Entropies from storage nodes (32B each)
    pub mpc_entropies: Vec<[u8; 32]>,
    /// Session metadata (opaque bytes)
    pub metadata: Vec<u8>,
    /// Commitments C_i = H(session_id || contribution_i_material)
    pub commitments: Vec<[u8; 32]>,
    /// Reveals: exact contribution materials used for each commitment
    pub reveals: Vec<Vec<u8>>,
    /// Final genesis id: H(session_id || device_entropy || mpc_i... || metadata)
    pub genesis_id: [u8; 32],
    /// Participants
    pub storage_nodes: Vec<NodeId>,
    pub threshold: usize,
    /// Device id (32B)
    pub device_id: [u8; 32],
    /// Deterministic ticks
    pub created_at_ticks: u64,
}

impl GenesisSession {
    /// Create a new session with random session_id; other fields zero/empty.
    pub fn new(metadata: Vec<u8>) -> Result<Self, DsmError> {
        let mut sid = [0u8; 32];
        crate::crypto::rng::random_bytes(32)
            .as_slice()
            .read_exact(&mut sid)
            .map_err(|e| DsmError::crypto("Failed to generate session ID".to_string(), Some(e)))?;

        Ok(Self {
            session_id: sid,
            device_entropy: [0u8; 32],
            dbrw_binding: None,
            mpc_entropies: Vec::new(),
            metadata,
            commitments: Vec::new(),
            reveals: Vec::new(),
            genesis_id: [0u8; 32],
            storage_nodes: Vec::new(),
            threshold: 0,
            device_id: [0u8; 32],
            created_at_ticks: now_tick(),
        })
    }

    /// Initialize MPC with participants and threshold (≥3 and ≤ nodes)
    pub fn initialize_mpc(
        &mut self,
        device_id: [u8; 32],
        storage_nodes: Vec<NodeId>,
        threshold: usize,
    ) -> Result<(), DsmError> {
        if storage_nodes.len() < 3 {
            return Err(DsmError::invalid_parameter("MPC requires ≥3 storage nodes"));
        }
        if threshold < 3 || threshold > storage_nodes.len() {
            return Err(DsmError::invalid_parameter(
                "Threshold must be ≥3 and ≤ participants",
            ));
        }
        self.device_id = device_id;
        self.storage_nodes = storage_nodes;
        self.threshold = threshold;
        Ok(())
    }

    /// Set device + MPC entropies (bytes-only). DBRW binding is set separately.
    pub fn set_entropies(
        &mut self,
        device_entropy: [u8; 32],
        mpc_entropies: Vec<[u8; 32]>,
    ) -> Result<(), DsmError> {
        self.device_entropy = device_entropy;
        self.mpc_entropies = mpc_entropies;
        Ok(())
    }

    /// Compute commitments: C_i = H(session_id || contribution)
    /// contributions = [device_entropy, mpc_i...]
    pub fn compute_commitments(&mut self) {
        let mut contributions: Vec<Vec<u8>> = Vec::new();

        // Device contribution (DBRW is not part of genesis binding)
        contributions.push(self.device_entropy.to_vec());

        // MPC contributions
        for m in &self.mpc_entropies {
            contributions.push(m.to_vec());
        }

        self.commitments = contributions
            .iter()
            .map(|c| {
                let mut h = dsm_domain_hasher("DSM/genesis-mpc");
                h.update(&self.session_id);
                h.update(c);
                let mut out = [0u8; 32];
                out.copy_from_slice(h.finalize().as_bytes());
                out
            })
            .collect();

        self.reveals = contributions;
    }

    /// Verify commitments against reveals
    pub fn verify_commitments(&self) -> bool {
        if self.commitments.len() != self.reveals.len() {
            return false;
        }
        for (rev, com) in self.reveals.iter().zip(self.commitments.iter()) {
            let mut h = dsm_domain_hasher("DSM/genesis-mpc");
            h.update(&self.session_id);
            h.update(rev);
            let mut out = [0u8; 32];
            out.copy_from_slice(h.finalize().as_bytes());
            if &out != com {
                return false;
            }
        }
        true
    }

    /// Compute genesis id: H(session_id || device_entropy || mpc_i... || metadata)
    ///
    /// DBRW is intentionally NOT part of the genesis binding.
    pub fn compute_genesis_id(&mut self) {
        let mut h = dsm_domain_hasher("DSM/genesis-mpc");
        h.update(&self.session_id);
        h.update(&self.device_entropy);
        for m in &self.mpc_entropies {
            h.update(m);
        }
        h.update(&self.metadata);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        self.genesis_id = out;
    }

    /// Validate full session
    pub fn validate_session(&self) -> Result<(), DsmError> {
        if self.storage_nodes.len() < 3 {
            return Err(DsmError::invalid_operation("MPC requires ≥3 storage nodes"));
        }
        if self.threshold < 3 || self.threshold > self.storage_nodes.len() {
            return Err(DsmError::invalid_operation("Invalid MPC threshold"));
        }
        if self.mpc_entropies.len() != self.storage_nodes.len() {
            return Err(DsmError::invalid_operation(
                "MPC entropy count must equal node count",
            ));
        }
        if !self.verify_commitments() {
            return Err(DsmError::invalid_operation(
                "Commitment verification failed",
            ));
        }
        if self.genesis_id == [0u8; 32] {
            return Err(DsmError::invalid_operation("Genesis ID not computed"));
        }
        Ok(())
    }
}

// -------------------- Helpers --------------------

#[inline]
#[allow(dead_code)]
fn to_arr32(v: &[u8]) -> Result<[u8; 32], DsmError> {
    if v.len() != 32 {
        return Err(DsmError::invalid_parameter("expected 32 bytes"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    Ok(a)
}

/// Deterministic device entropy (bytes-only), derived from 32-byte device_id
pub fn generate_device_entropy(device_id: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/genesis-device-entropy");
    h.update(device_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

// -------------------- High-level MPC creation (no I/O) --------------------

/// Production DSM MPC Creation (bytes-only).
///
/// This entrypoint is the core, no-I/O version: it models the MPC entropies
/// without performing network collection. SDK integrations should use
/// `create_mpc_genesis_with_transport`.
pub async fn create_mpc_genesis(
    device_id: [u8; 32],
    storage_nodes: Vec<NodeId>,
    threshold: usize,
    metadata: Option<Vec<u8>>,
) -> Result<GenesisSession, DsmError> {
    if storage_nodes.len() < 3 {
        return Err(DsmError::InvalidParameter(format!(
            "MPC requires ≥3 nodes, got {}",
            storage_nodes.len()
        )));
    }
    if threshold < 3 || threshold > storage_nodes.len() {
        return Err(DsmError::InvalidParameter(format!(
            "threshold must be ≥3 and ≤ nodes ({}), got {}",
            storage_nodes.len(),
            threshold
        )));
    }

    let meta = metadata.unwrap_or_else(|| b"DSMv2|bytes|no-wallclock".to_vec());

    // Device entropy (32B)
    let device_entropy = {
        let mut e = [0u8; 32];
        crate::crypto::rng::random_bytes(32)
            .as_slice()
            .read_exact(&mut e)
            .map_err(|e| {
                DsmError::crypto("Failed to generate device entropy".to_string(), Some(e))
            })?;
        e
    };

    // MPC entropies (modeled; SDK provides real collection in integration)
    let mut mpc_entropies: Vec<[u8; 32]> = Vec::with_capacity(storage_nodes.len());
    for _ in 0..storage_nodes.len() {
        let mut e = [0u8; 32];
        crate::crypto::rng::random_bytes(32)
            .as_slice()
            .read_exact(&mut e)
            .map_err(|e| DsmError::crypto("Failed to generate MPC entropy".to_string(), Some(e)))?;
        mpc_entropies.push(e);
    }

    let mut session = GenesisSession::new(meta)?;
    session.initialize_mpc(device_id, storage_nodes, threshold)?;
    session.set_entropies(device_entropy, mpc_entropies)?;

    session.compute_commitments();
    session.compute_genesis_id();
    session.validate_session()?;

    Ok(session)
}

/// SDK-integrated MPC Creation using a transport for node entropy collection.
/// DBRW is optional and stored in the session for later gating/attestation; it is not
/// part of genesis binding.
pub async fn create_mpc_genesis_with_transport<T: GenesisMpcTransport + Sync>(
    device_id: [u8; 32],
    storage_nodes: Vec<NodeId>,
    threshold: usize,
    metadata: Option<Vec<u8>>,
    transport: &T,
    dbrw_binding: Option<[u8; 32]>,
) -> Result<GenesisSession, DsmError> {
    if storage_nodes.len() < 3 {
        return Err(DsmError::InvalidParameter(format!(
            "MPC requires ≥3 nodes, got {}",
            storage_nodes.len()
        )));
    }
    if threshold < 3 || threshold > storage_nodes.len() {
        return Err(DsmError::InvalidParameter(format!(
            "threshold must be ≥3 and ≤ nodes ({}), got {}",
            storage_nodes.len(),
            threshold
        )));
    }

    let meta = metadata.unwrap_or_else(|| b"DSMv2|bytes|no-wallclock".to_vec());

    // Device entropy (32B)
    let device_entropy = {
        let mut e = [0u8; 32];
        crate::crypto::rng::random_bytes(32)
            .as_slice()
            .read_exact(&mut e)
            .map_err(|e| {
                DsmError::crypto("Failed to generate device entropy".to_string(), Some(e))
            })?;
        e
    };

    let mut session = GenesisSession::new(meta)?;
    session.initialize_mpc(device_id, storage_nodes.clone(), threshold)?;
    session.device_entropy = device_entropy;
    session.dbrw_binding = dbrw_binding;

    // Device commitment material for transport calls: H(session_id || device_entropy)
    let device_commitment = {
        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/genesis-device-commit");
        h.update(&session.session_id);
        h.update(&session.device_entropy);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // Collect node entropies from SDK transport
    let mut mpc_entropies: Vec<[u8; 32]> = Vec::with_capacity(storage_nodes.len());
    for n in &storage_nodes {
        let e = transport
            .collect_node_entropy(n, &session.session_id, &device_commitment)
            .await?;
        mpc_entropies.push(e);
    }
    session.mpc_entropies = mpc_entropies;

    session.compute_commitments();
    session.compute_genesis_id();
    session.validate_session()?;

    Ok(session)
}

// -------------------- JNI/result bridge (bytes-only) --------------------

#[derive(Debug, Clone)]
pub struct GenesisCreationResult {
    pub success: bool,
    pub genesis_device_id: Option<[u8; 32]>,
    pub genesis_hash: Option<[u8; 32]>,
    pub device_entropy: Option<[u8; 32]>,
    pub blind_key: Option<Vec<u8>>,
    pub storage_nodes: Option<Vec<NodeId>>,
    pub error: Option<String>,
}
impl GenesisCreationResult {
    pub fn success(session: &GenesisSession, blind_key: Option<Vec<u8>>) -> Self {
        Self {
            success: true,
            genesis_device_id: Some(session.device_id),
            genesis_hash: Some(session.genesis_id),
            device_entropy: Some(session.device_entropy),
            blind_key,
            storage_nodes: Some(session.storage_nodes.clone()),
            error: None,
        }
    }
    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            genesis_device_id: None,
            genesis_hash: None,
            device_entropy: None,
            blind_key: None,
            storage_nodes: None,
            error: Some(message.to_string()),
        }
    }
}

// -------------------- Tests --------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn id32(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    #[test]
    fn test_session_new() {
        let meta = b"DSMv2|meta".to_vec();
        let s = GenesisSession::new(meta.clone()).unwrap();
        assert_eq!(s.metadata, meta);
        assert_ne!(s.session_id, [0u8; 32]);
        assert_eq!(s.genesis_id, [0u8; 32]);
        assert!(s.storage_nodes.is_empty());
        assert!(s.created_at_ticks > 0);
    }

    #[test]
    fn test_init_validate_thresholds() {
        let mut s = GenesisSession::new(b"m".to_vec()).unwrap();
        let device = id32(7);
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        assert!(s.initialize_mpc(device, nodes.clone(), 3).is_ok());

        let mut bad = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(bad
            .initialize_mpc(device, vec![NodeId::new("n1")], 3)
            .is_err());

        let mut bad2 = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(bad2.initialize_mpc(device, nodes.clone(), 2).is_err());

        let mut bad3 = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(bad3.initialize_mpc(device, nodes.clone(), 4).is_err());
    }

    #[test]
    fn test_device_entropy_derivation() {
        let id = id32(1);
        let e1 = generate_device_entropy(&id);
        let e2 = generate_device_entropy(&id);
        assert_eq!(e1, e2);
        assert_ne!(e1, [0u8; 32]);
    }

    #[test]
    fn test_commit_reveal_and_genesis() {
        let mut s = GenesisSession::new(b"meta".to_vec()).unwrap();
        s.initialize_mpc(
            id32(9),
            vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")],
            3,
        )
        .unwrap();
        s.device_entropy = id32(11);
        s.mpc_entropies = vec![id32(21), id32(22), id32(23)];

        // DBRW may exist, but doesn't affect genesis binding
        s.dbrw_binding = Some(id32(0xDB));

        s.compute_commitments();
        assert_eq!(s.commitments.len(), 1 + s.mpc_entropies.len());
        assert!(s.verify_commitments());

        s.compute_genesis_id();
        assert_ne!(s.genesis_id, [0u8; 32]);
        s.validate_session().unwrap();
    }

    #[tokio::test]
    async fn test_create_mpc_genesis_path() {
        let dev = id32(0xAA);
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let s = create_mpc_genesis(dev, nodes, 3, Some(b"DSMv2|test".to_vec())).await;

        let sess = match s {
            Ok(sess) => sess,
            Err(e) => panic!("create_mpc_genesis should succeed: {e:?}"),
        };
        assert_ne!(sess.genesis_id, [0u8; 32]);
        assert!(sess.verify_commitments());
        assert_eq!(sess.mpc_entropies.len(), sess.storage_nodes.len());
    }
}
