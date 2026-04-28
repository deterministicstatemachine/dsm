// File: dsm/src/core/identity/genesis_mpc.rs
//! DSM Genesis MPC Protocol Implementation (STRICT, bytes-only)
//!
//! Invariants:
//! - No wall-clock APIs. Use deterministic ticks (u64) from utils::deterministic_time.
//! - No hex/base64 in data structures; bytes-only at boundaries.
//! - ≥3 storage nodes; every reveal is bound (n-of-n by construction —
//!   `mpc_entropies.len() == storage_nodes.len()` is the operative invariant,
//!   so no decorative threshold is recorded or signed).
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
use crate::utils::deterministic_time;

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

/// Two-phase MPC transport: collect commits from every participant BEFORE
/// any reveal is requested (bias-resistance gate, see WP §11.1).
///
/// SDK implementations perform real I/O against storage nodes. The core
/// orchestrator [`run_two_phase_mpc`] enforces the phase ordering — every
/// commit MUST be gathered before any reveal is solicited.
#[async_trait]
pub trait GenesisMpcTransport {
    /// Collect a participant's commitment.
    /// Returns the 32-byte commit `BLAKE3("DSM/genesis-mpc\0" || session_id || node_reveal)`.
    async fn collect_commit(
        &self,
        node: &NodeId,
        session_id: &[u8; 32],
        device_commitment: &[u8; 32],
    ) -> Result<[u8; 32], DsmError>;

    /// Collect a participant's reveal. Implementations MUST refuse to release
    /// the reveal until the participant observes that every other peer has
    /// already published its commit; the core enforces this ordering on the
    /// caller side via [`run_two_phase_mpc`].
    async fn collect_reveal(
        &self,
        node: &NodeId,
        session_id: &[u8; 32],
    ) -> Result<[u8; 32], DsmError>;
}

/// Recompute the canonical commit for a given reveal.
#[inline]
pub fn commit_for_reveal(session_id: &[u8; 32], reveal: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/genesis-mpc");
    h.update(session_id);
    h.update(reveal);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
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
    /// Final genesis id: H(session_id || device_entropy || mpc_i... || metadata)
    pub genesis_id: [u8; 32],
    /// Participants
    pub storage_nodes: Vec<NodeId>,
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
            genesis_id: [0u8; 32],
            storage_nodes: Vec::new(),
            device_id: [0u8; 32],
            created_at_ticks: now_tick(),
        })
    }

    /// Initialize MPC with participants (≥3). Genesis MPC is n-of-n by
    /// construction: every participant must reveal, and every reveal is
    /// bound into the canonical [`GenesisA0`] anchor. There is no separate
    /// threshold parameter — the operative invariant is
    /// `mpc_entropies.len() == storage_nodes.len()`.
    pub fn initialize_mpc(
        &mut self,
        device_id: [u8; 32],
        storage_nodes: Vec<NodeId>,
    ) -> Result<(), DsmError> {
        if storage_nodes.len() < 3 {
            return Err(DsmError::invalid_parameter("MPC requires ≥3 storage nodes"));
        }
        self.device_id = device_id;
        self.storage_nodes = storage_nodes;
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

    /// Compute genesis id via the canonical [`GenesisA0`] anchor (WP §2.5).
    /// This binds session_id, device_id, sorted participants, device_entropy,
    /// every MPC reveal, and metadata into
    /// `G = BLAKE3("DSM/genesis\0" || canonical_bytes(A_0))`.
    ///
    /// Participant ordering is part of the binding so that an adversary
    /// cannot quietly shuffle participants to land on a different genesis.
    ///
    /// DBRW is intentionally NOT part of the genesis binding.
    pub fn compute_genesis_id(&mut self) -> Result<(), DsmError> {
        let a0 = self.build_a0()?;
        self.genesis_id = a0.genesis_id()?;
        Ok(())
    }

    /// Build the canonical [`GenesisA0`] anchor for this session. The reveal
    /// list comes from `mpc_entropies` paired with the sorted node list.
    pub fn build_a0(&self) -> Result<crate::core::identity::genesis_a0::GenesisA0, DsmError> {
        if self.mpc_entropies.len() != self.storage_nodes.len() {
            return Err(DsmError::invalid_operation(
                "MPC entropy count must equal node count",
            ));
        }
        let pairs: Vec<(NodeId, [u8; 32])> = self
            .storage_nodes
            .iter()
            .cloned()
            .zip(self.mpc_entropies.iter().copied())
            .collect();
        crate::core::identity::genesis_a0::GenesisA0::build(
            self.session_id,
            self.device_id,
            self.storage_nodes.clone(),
            self.device_entropy,
            pairs,
            self.metadata.clone(),
        )
    }

    /// Validate full session end-to-end. Re-derives `genesis_id` from the
    /// canonical [`GenesisA0`] anchor and rejects any drift between stored
    /// fields and derived values.
    pub fn validate_session(&self) -> Result<(), DsmError> {
        if self.storage_nodes.len() < 3 {
            return Err(DsmError::invalid_operation("MPC requires ≥3 storage nodes"));
        }
        if self.mpc_entropies.len() != self.storage_nodes.len() {
            return Err(DsmError::invalid_operation(
                "MPC entropy count must equal node count",
            ));
        }
        let a0 = self.build_a0()?;
        if a0.genesis_id()? != self.genesis_id {
            return Err(DsmError::invalid_operation(
                "genesis_id does not match canonical A_0 derivation",
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

// -------------------- High-level MPC creation (transport-driven only) --------------------

/// SDK-integrated two-phase MPC genesis creation. Collects every commit
/// from the sorted participant set BEFORE any reveal is solicited
/// (bias-resistance, WP §11.1), then verifies each reveal against its
/// recorded commit. The session's `genesis_id` is bound to the canonical
/// [`GenesisA0`] anchor (sorted participants, device_id, device_entropy,
/// all reveals, metadata).
///
/// `dbrw_binding` is recorded on the session for downstream attestation but
/// is intentionally NOT part of the genesis binding — the genesis must remain
/// derivable from public inputs alone (WP §12).
pub async fn create_mpc_genesis_with_transport<T: GenesisMpcTransport + Sync>(
    device_id: [u8; 32],
    storage_nodes: Vec<NodeId>,
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

    let meta = metadata.unwrap_or_else(|| b"DSMv2|bytes|no-wallclock".to_vec());

    let mut session = GenesisSession::new(meta)?;
    // Sort participants bytewise to match the canonical A_0 ordering before
    // we publish session_id-bound commits.
    let mut sorted = storage_nodes;
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    session.initialize_mpc(device_id, sorted.clone())?;
    session.device_entropy = generate_device_entropy(&device_id);
    session.dbrw_binding = dbrw_binding;

    // Device commitment material for transport calls: H(session_id || device_entropy).
    let device_commitment = {
        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/genesis-device-commit");
        h.update(&session.session_id);
        h.update(&session.device_entropy);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    run_two_phase_mpc(&mut session, transport, &device_commitment).await?;
    Ok(session)
}

/// Drive the two-phase MPC: gather every commit, then every reveal, then
/// verify each reveal against its recorded commit. Any mismatch aborts the
/// session with a bias-resistance error.
pub async fn run_two_phase_mpc<T: GenesisMpcTransport + Sync>(
    session: &mut GenesisSession,
    transport: &T,
    device_commitment: &[u8; 32],
) -> Result<(), DsmError> {
    // Phase 1 — collect all commits before any reveals.
    let mut commits: Vec<[u8; 32]> = Vec::with_capacity(session.storage_nodes.len());
    for node in &session.storage_nodes {
        let c = transport
            .collect_commit(node, &session.session_id, device_commitment)
            .await?;
        commits.push(c);
    }

    // Phase 2 — collect reveals; each must match its prior commit.
    let mut reveals: Vec<[u8; 32]> = Vec::with_capacity(session.storage_nodes.len());
    for (i, node) in session.storage_nodes.iter().enumerate() {
        let r = transport.collect_reveal(node, &session.session_id).await?;
        if commit_for_reveal(&session.session_id, &r) != commits[i] {
            return Err(DsmError::invalid_operation(
                "MPC reveal does not match prior commit (bias-resistance violated)",
            ));
        }
        reveals.push(r);
    }

    session.mpc_entropies = reveals;
    session.compute_genesis_id()?;
    session.validate_session()?;
    Ok(())
}

// -------------------- Deterministic test transport --------------------

/// Deterministic in-process MPC transport for tests. Each node's reveal is
/// derived from `BLAKE3("DSM/test-mpc-reveal\0" || seed || node_id ||
/// session_id)` and the matching commit is computed honestly. This mimics
/// N independent storage nodes without any network or shared state.
#[cfg(any(test, feature = "test-transport"))]
#[derive(Debug, Clone)]
pub struct DeterministicTestTransport {
    pub seed: [u8; 32],
}

#[cfg(any(test, feature = "test-transport"))]
impl DeterministicTestTransport {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    fn reveal_for(&self, node: &NodeId, session_id: &[u8; 32]) -> [u8; 32] {
        let mut h = dsm_domain_hasher("DSM/test-mpc-reveal");
        h.update(&self.seed);
        h.update(node.as_bytes());
        h.update(session_id);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

#[cfg(any(test, feature = "test-transport"))]
#[async_trait]
impl GenesisMpcTransport for DeterministicTestTransport {
    async fn collect_commit(
        &self,
        node: &NodeId,
        session_id: &[u8; 32],
        _device_commitment: &[u8; 32],
    ) -> Result<[u8; 32], DsmError> {
        let r = self.reveal_for(node, session_id);
        Ok(commit_for_reveal(session_id, &r))
    }

    async fn collect_reveal(
        &self,
        node: &NodeId,
        session_id: &[u8; 32],
    ) -> Result<[u8; 32], DsmError> {
        Ok(self.reveal_for(node, session_id))
    }
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
        assert!(s.initialize_mpc(device, nodes.clone()).is_ok());

        let mut bad = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(bad.initialize_mpc(device, vec![NodeId::new("n1")]).is_err());

        let mut bad2 = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(bad2
            .initialize_mpc(device, vec![NodeId::new("n1"), NodeId::new("n2")])
            .is_err());
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
        )
        .unwrap();
        s.device_entropy = id32(11);
        s.mpc_entropies = vec![id32(21), id32(22), id32(23)];

        // DBRW may exist, but doesn't affect genesis binding
        s.dbrw_binding = Some(id32(0xDB));

        s.compute_genesis_id().unwrap();
        assert_ne!(s.genesis_id, [0u8; 32]);
        s.validate_session().unwrap();
    }

    #[test]
    fn genesis_id_binds_participant_change_rejects() {
        // Same inputs except participant set differs → genesis_id must differ.
        let nodes = vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")];
        let mut s1 = GenesisSession::new(b"m".to_vec()).unwrap();
        s1.initialize_mpc(id32(1), nodes.clone()).unwrap();
        s1.device_entropy = id32(2);
        s1.mpc_entropies = vec![id32(10), id32(11), id32(12)];
        s1.compute_genesis_id().unwrap();

        let mut s2 = GenesisSession::new(b"m".to_vec()).unwrap();
        s2.session_id = s1.session_id;
        // Use a 4-node set to compare against the 3-node anchor.
        let nodes4 = vec![
            NodeId::new("a"),
            NodeId::new("b"),
            NodeId::new("c"),
            NodeId::new("d"),
        ];
        s2.initialize_mpc(id32(1), nodes4).unwrap();
        s2.device_entropy = id32(2);
        s2.mpc_entropies = vec![id32(10), id32(11), id32(12), id32(13)];
        s2.compute_genesis_id().unwrap();

        assert_ne!(s1.genesis_id, s2.genesis_id);
    }

    #[test]
    fn validate_session_rejects_genesis_id_drift() {
        let mut s = GenesisSession::new(b"meta".to_vec()).unwrap();
        s.initialize_mpc(
            id32(7),
            vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")],
        )
        .unwrap();
        s.device_entropy = id32(11);
        s.mpc_entropies = vec![id32(21), id32(22), id32(23)];
        s.compute_genesis_id().unwrap();
        s.genesis_id[0] ^= 0xFF;
        assert!(s.validate_session().is_err());
    }

    #[tokio::test]
    async fn create_mpc_genesis_with_transport_two_phase() {
        let dev = id32(0xAA);
        let nodes = vec![NodeId::new("n3"), NodeId::new("n1"), NodeId::new("n2")];
        let t = DeterministicTestTransport::new([0x42; 32]);
        let s =
            create_mpc_genesis_with_transport(dev, nodes, Some(b"DSMv2|test".to_vec()), &t, None)
                .await
                .expect("two-phase MPC should succeed");
        assert_ne!(s.genesis_id, [0u8; 32]);
        // Participants must come back sorted bytewise.
        let names: Vec<&[u8]> = s.storage_nodes.iter().map(|n| n.as_bytes()).collect();
        let expected: Vec<&[u8]> = vec![b"n1", b"n2", b"n3"];
        assert_eq!(names, expected);
    }

    #[tokio::test]
    async fn create_mpc_genesis_with_transport_is_replay_safe() {
        let dev = id32(0xAA);
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let t = DeterministicTestTransport::new([0x42; 32]);
        let a =
            create_mpc_genesis_with_transport(dev, nodes.clone(), Some(b"meta".to_vec()), &t, None)
                .await
                .unwrap();
        let b = create_mpc_genesis_with_transport(dev, nodes, Some(b"meta".to_vec()), &t, None)
            .await
            .unwrap();
        // session_id is randomly generated per session, so genesis differs;
        // but per-session canonical re-derivation must succeed both times.
        a.validate_session().unwrap();
        b.validate_session().unwrap();
    }

    /// Bias-resistance: a transport that lies about a reveal (different from
    /// what it committed to) MUST be rejected.
    #[tokio::test]
    async fn create_mpc_genesis_with_transport_rejects_bias_attack() {
        struct LyingTransport {
            honest: DeterministicTestTransport,
        }
        #[async_trait::async_trait]
        impl GenesisMpcTransport for LyingTransport {
            async fn collect_commit(
                &self,
                node: &NodeId,
                session_id: &[u8; 32],
                d: &[u8; 32],
            ) -> Result<[u8; 32], DsmError> {
                self.honest.collect_commit(node, session_id, d).await
            }
            async fn collect_reveal(
                &self,
                node: &NodeId,
                session_id: &[u8; 32],
            ) -> Result<[u8; 32], DsmError> {
                let mut r = self.honest.collect_reveal(node, session_id).await?;
                r[0] ^= 0xFF; // diverge from the prior commit
                Ok(r)
            }
        }

        let dev = id32(0xAA);
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let t = LyingTransport {
            honest: DeterministicTestTransport::new([0x42; 32]),
        };
        let r =
            create_mpc_genesis_with_transport(dev, nodes, Some(b"meta".to_vec()), &t, None).await;
        assert!(
            r.is_err(),
            "bias attack must be rejected by the two-phase verifier"
        );
    }
}
