// File: dsm/src/core/identity/genesis_mpc.rs
//! DSM Genesis MPC Protocol Implementation (STRICT, bytes-only)
//!
//! Invariants:
//! - No wall-clock APIs. Use deterministic ticks (u64) from utils::deterministic_time.
//! - No hex/base64 in data structures; bytes-only at boundaries.
//! - ≥3 storage nodes contribute entropy (n-of-n commit-then-reveal).  This is
//!   not threshold cryptography — `b_1, ..., b_n` in whitepaper §2.5 is index
//!   notation for "all n contributions"; there is no t-of-n DKG or Shamir.
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
    /// DBRW binding K_DBRW (32B) per whitepaper §12 def.3.
    ///
    /// Mixed into `S_master` IKM (whitepaper §11.1 eq.13) at keypair
    /// derivation time — NEVER serialised, logged, or included in any
    /// commitment.  Zeroised when the session is dropped.  Not part of
    /// the genesis hash `G` (which §2.5 keeps publicly recomputable).
    pub dbrw_binding: [u8; 32],
    /// Entropies from storage nodes (32B each)
    pub mpc_entropies: Vec<[u8; 32]>,
    /// Session metadata (opaque bytes)
    pub metadata: Vec<u8>,
    /// Commitments C_i = H("DSM/genesis-commit\0" || session_id || contribution_i)
    pub commitments: Vec<[u8; 32]>,
    /// Reveals: exact contribution materials used for each commitment
    pub reveals: Vec<Vec<u8>>,
    /// Genesis hash per whitepaper §2.5:
    /// G = BLAKE3("DSM/genesis\0" || device_entropy || mpc_i... || A)
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
    /// `dbrw_binding` MUST be set via `set_dbrw_binding` before
    /// `compute_genesis_id` finalises (or, for end-to-end production,
    /// is supplied to `create_mpc_genesis*` and routed through here).
    pub fn new(metadata: Vec<u8>) -> Result<Self, DsmError> {
        let mut sid = [0u8; 32];
        crate::crypto::rng::random_bytes(32)
            .as_slice()
            .read_exact(&mut sid)
            .map_err(|e| DsmError::crypto("Failed to generate session ID".to_string(), Some(e)))?;

        Ok(Self {
            session_id: sid,
            device_entropy: [0u8; 32],
            dbrw_binding: [0u8; 32],
            mpc_entropies: Vec::new(),
            metadata,
            commitments: Vec::new(),
            reveals: Vec::new(),
            genesis_id: [0u8; 32],
            storage_nodes: Vec::new(),
            device_id: [0u8; 32],
            created_at_ticks: now_tick(),
        })
    }

    /// Set the DBRW binding K_DBRW for this session.  Required before
    /// `validate_session()` (and Step-5 keypair derivation).
    pub fn set_dbrw_binding(&mut self, k_dbrw: [u8; 32]) {
        self.dbrw_binding = k_dbrw;
    }

    /// Initialize MPC with participants (≥3 storage nodes; whitepaper §2.5
    /// requires `b_1, ..., b_n` from all n participants — no threshold).
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

    /// Compute participant commitments: C_i = H("DSM/genesis-commit\0" ‖
    /// session_id ‖ contribution_i).  The commitment domain is distinct
    /// from the genesis-hash domain so the two derivations cannot
    /// collide; per the BLAKE3 domain-separation rule, every BLAKE3 use
    /// gets its own tag.
    ///
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
                let mut h = dsm_domain_hasher("DSM/genesis-commit");
                h.update(&self.session_id);
                h.update(c);
                let mut out = [0u8; 32];
                out.copy_from_slice(h.finalize().as_bytes());
                out
            })
            .collect();

        self.reveals = contributions;
    }

    /// Verify commitments against reveals using the commit-domain.
    pub fn verify_commitments(&self) -> bool {
        if self.commitments.len() != self.reveals.len() {
            return false;
        }
        for (rev, com) in self.reveals.iter().zip(self.commitments.iter()) {
            let mut h = dsm_domain_hasher("DSM/genesis-commit");
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

    /// Compute genesis id per whitepaper §2.5:
    ///
    /// ```text
    /// G = BLAKE3("DSM/genesis\0" ‖ b_1 ‖ ... ‖ b_n ‖ A)
    /// ```
    ///
    /// where `b_1 = device_entropy`, `b_2..b_n = mpc_entropies` (n-of-n),
    /// and `A` is the contextual binding parameters: device_id ‖ sorted
    /// participants ‖ metadata.  The participant ordering is the
    /// canonical lex-sort of NodeId bytes so the hash is independent of
    /// transport-time order.
    ///
    /// `K_DBRW` is intentionally NOT part of `A` — silicon binding
    /// happens one layer down at master-seed derivation (whitepaper
    /// §11.1 eq.13), not at the genesis hash.
    pub fn compute_genesis_id(&mut self) {
        let mut h = dsm_domain_hasher("DSM/genesis");
        // b_1 = device_entropy
        h.update(&self.device_entropy);
        // b_2..b_n = mpc_entropies (n-of-n contributions)
        for m in &self.mpc_entropies {
            h.update(m);
        }
        // A = contextual binding parameters
        h.update(&canonical_a(&self.device_id, &self.storage_nodes, &self.metadata));
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        self.genesis_id = out;
    }

    /// Validate full session.  Requires DBRW binding (K_DBRW) to be set
    /// per whitepaper §11.1 eq.13 prerequisite for master-seed derivation.
    pub fn validate_session(&self) -> Result<(), DsmError> {
        if self.storage_nodes.len() < 3 {
            return Err(DsmError::invalid_operation("MPC requires ≥3 storage nodes"));
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
        if self.dbrw_binding == [0u8; 32] {
            return Err(DsmError::invalid_operation(
                "DBRW binding (K_DBRW) not set; required by whitepaper §11.1 eq.13",
            ));
        }
        Ok(())
    }

    /// Derive the silicon-bound SPHINCS+ and Kyber keypairs from this
    /// session's `S_master` per whitepaper §11.1 eq.13:
    ///
    /// ```text
    /// s_0           = BLAKE3("DSM/step-salt\0" ‖ G)
    /// S_master      = HKDF-Extract(salt = "DSM/dev\0",
    ///                              IKM  = G ‖ DevID ‖ K_DBRW ‖ s_0)
    /// sphincs_seed  = HKDF-Expand(S_master, "DSM/sphincs-plus-seed\0", 32)
    /// (AK_sk, AK_pk)= SPHINCS+.KeyGen(sphincs_seed)
    /// (KEM_sk, KEM_pk)= ML-KEM.KeyGen(BLAKE3-derive(S_master, "DSM/kyber\0"))
    /// ```
    ///
    /// Both keypairs are silicon-bound: differing `K_DBRW` produces
    /// different keys even with identical public inputs (`device_id`,
    /// `participants`, `metadata`, contributions).  `K_DBRW` flows only
    /// through the local IKM buffer in `derive_master_seed`, which is
    /// zeroised before this function returns; it is never serialised,
    /// logged, or committed.
    ///
    /// Preconditions:
    /// - `compute_genesis_id` has been called (`genesis_id != [0u8; 32]`)
    /// - `dbrw_binding` is a non-zero `K_DBRW`
    pub fn derive_silicon_bound_keypair(&self) -> Result<GenesisMasterKeypair, DsmError> {
        use zeroize::Zeroize;

        if self.genesis_id == [0u8; 32] {
            return Err(DsmError::invalid_operation(
                "compute_genesis_id must be called before derive_silicon_bound_keypair",
            ));
        }
        if self.dbrw_binding == [0u8; 32] {
            return Err(DsmError::invalid_operation(
                "K_DBRW must be set before derive_silicon_bound_keypair",
            ));
        }

        // S_master = HKDF-Extract(salt = "DSM/dev\0", IKM).  The free
        // function zeroises its IKM internally.
        let mut s_master =
            derive_master_seed(&self.genesis_id, &self.device_id, &self.dbrw_binding);

        // SPHINCS+ keypair from a 32-byte seed expanded out of S_master.
        let mut sphincs_seed_vec =
            crate::crypto::hkdf::expand(&s_master, b"DSM/sphincs-plus-seed\0", 32);
        let mut sphincs_seed: [u8; 32] =
            sphincs_seed_vec.as_slice().try_into().map_err(|_| {
                DsmError::crypto(
                    "SPHINCS+ seed length mismatch",
                    None::<std::io::Error>,
                )
            })?;
        sphincs_seed_vec.zeroize();

        let sphincs_kp =
            sphincs::generate_keypair_from_seed(sphincs::SphincsVariant::SPX256f, &sphincs_seed)?;
        sphincs_seed.zeroize();

        // ML-KEM (Kyber) keypair, domain-separated under "DSM/kyber\0".
        let (kyber_pk, kyber_sk) =
            kyber::generate_kyber_keypair_from_entropy(&s_master, "DSM/kyber\0")?;

        // S_master has now produced both keypairs; clear it.
        s_master.zeroize();

        Ok(GenesisMasterKeypair {
            sphincs_public: sphincs_kp.public_key.clone(),
            sphincs_secret: sphincs_kp.secret_key.clone(),
            kyber_public: kyber_pk,
            kyber_secret: kyber_sk,
        })
    }
}

impl zeroize::Zeroize for GenesisSession {
    /// Zeroize sensitive material on drop.  K_DBRW MUST NEVER outlive
    /// the session in serialised or in-memory form (whitepaper §11.1
    /// + §12 normative rule).
    fn zeroize(&mut self) {
        self.dbrw_binding.zeroize();
        self.device_entropy.zeroize();
        for e in &mut self.mpc_entropies {
            e.zeroize();
        }
    }
}

impl Drop for GenesisSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
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

/// Canonical encoding of the contextual binding parameters `A` from
/// whitepaper §2.5.  Bytes-only, length-prefixed, deterministic given
/// the same inputs regardless of transport-time NodeId ordering.
///
/// Layout:
/// ```text
/// device_id           : 32 bytes
/// participant_count   : u32 little-endian
/// for each participant (lex-sorted by raw NodeId bytes):
///   length            : u32 little-endian
///   bytes
/// metadata_length     : u32 little-endian
/// metadata            : bytes
/// ```
fn canonical_a(device_id: &[u8; 32], storage_nodes: &[NodeId], metadata: &[u8]) -> Vec<u8> {
    let mut sorted: Vec<&[u8]> = storage_nodes.iter().map(|n| n.as_bytes()).collect();
    sorted.sort();

    let participant_bytes_total: usize = sorted.iter().map(|p| p.len() + 4).sum();
    let mut a = Vec::with_capacity(32 + 4 + participant_bytes_total + 4 + metadata.len());

    // device_id
    a.extend_from_slice(device_id);

    // sorted participants (canonical lex order on raw bytes)
    a.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for p in &sorted {
        a.extend_from_slice(&(p.len() as u32).to_le_bytes());
        a.extend_from_slice(p);
    }

    // metadata
    a.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    a.extend_from_slice(metadata);

    a
}

/// Per-genesis step-salt: `s_0 = BLAKE3("DSM/step-salt\0" || G)` per
/// storage-nodes spec §5.  Mixed into the master-seed IKM (whitepaper
/// §11.1 eq.13) at keypair derivation time.
pub fn compute_step_salt(g: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/step-salt");
    h.update(g);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Derive the master seed `S_master` per whitepaper §11.1 eq.13:
///
/// ```text
/// s_0      = BLAKE3("DSM/step-salt\0" ‖ G)
/// S_master = HKDF-Extract(salt = "DSM/dev\0",
///                         IKM  = G ‖ DevID ‖ K_DBRW ‖ s_0)
/// ```
///
/// `K_DBRW` enters the master seed only through the local `ikm` buffer,
/// which is zeroised before this function returns.  The output
/// `S_master` is the only place the binding survives — and it must be
/// expanded into per-purpose seeds (SPHINCS+, Kyber, etc.) and then
/// itself zeroised by callers.
///
/// Pulled out as a free function so external verifiers (and the
/// determinism property tests) can recompute it byte-for-byte from the
/// public inputs (`g`, `device_id`) plus the held-on-device `K_DBRW`.
pub fn derive_master_seed(
    g: &[u8; 32],
    device_id: &[u8; 32],
    k_dbrw: &[u8; 32],
) -> [u8; 32] {
    use zeroize::Zeroize;

    let s_0 = compute_step_salt(g);
    let mut ikm: Vec<u8> = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(g);
    ikm.extend_from_slice(device_id);
    ikm.extend_from_slice(k_dbrw);
    ikm.extend_from_slice(&s_0);

    let s_master = crate::crypto::hkdf::extract(b"DSM/dev\0", &ikm);

    // K_DBRW is now folded into S_master — clear the staging buffer.
    ikm.zeroize();

    s_master
}

/// Outputs of the silicon-bound master-keypair derivation
/// (whitepaper §11.1).  Both keypairs are `ZeroizeOnDrop` because they
/// embody long-lived device secrets.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct GenesisMasterKeypair {
    pub sphincs_public: Vec<u8>,
    pub sphincs_secret: Vec<u8>,
    pub kyber_public: Vec<u8>,
    pub kyber_secret: Vec<u8>,
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
    k_dbrw: [u8; 32],
    metadata: Option<Vec<u8>>,
) -> Result<GenesisSession, DsmError> {
    if storage_nodes.len() < 3 {
        return Err(DsmError::InvalidParameter(format!(
            "MPC requires ≥3 nodes, got {}",
            storage_nodes.len()
        )));
    }
    if k_dbrw == [0u8; 32] {
        return Err(DsmError::InvalidParameter(
            "K_DBRW must be a non-zero binding (whitepaper §12)".into(),
        ));
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
    session.initialize_mpc(device_id, storage_nodes)?;
    session.set_entropies(device_entropy, mpc_entropies)?;
    session.set_dbrw_binding(k_dbrw);

    session.compute_commitments();
    session.compute_genesis_id();
    session.validate_session()?;

    Ok(session)
}

/// SDK-integrated MPC Creation using a transport for node entropy collection.
///
/// `K_DBRW` is mandatory (whitepaper §11.1 eq.13: required IKM for the
/// master-seed derivation that produces the SPHINCS+/Kyber keypair).
/// Callers obtain it from `crate::crypto::cdbrw_binding::derive_cdbrw_binding_key`
/// against real hardware/environment fingerprints.
pub async fn create_mpc_genesis_with_transport<T: GenesisMpcTransport + Sync>(
    device_id: [u8; 32],
    storage_nodes: Vec<NodeId>,
    k_dbrw: [u8; 32],
    metadata: Option<Vec<u8>>,
    transport: &T,
) -> Result<GenesisSession, DsmError> {
    if storage_nodes.len() < 3 {
        return Err(DsmError::InvalidParameter(format!(
            "MPC requires ≥3 nodes, got {}",
            storage_nodes.len()
        )));
    }
    if k_dbrw == [0u8; 32] {
        return Err(DsmError::InvalidParameter(
            "K_DBRW must be a non-zero binding (whitepaper §12)".into(),
        ));
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
    session.initialize_mpc(device_id, storage_nodes.clone())?;
    session.device_entropy = device_entropy;
    session.set_dbrw_binding(k_dbrw);

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
    fn test_init_validate_participant_count() {
        let mut s = GenesisSession::new(b"m".to_vec()).unwrap();
        let device = id32(7);
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        assert!(s.initialize_mpc(device, nodes.clone()).is_ok());

        // <3 storage nodes rejected.
        let mut bad = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(bad
            .initialize_mpc(device, vec![NodeId::new("n1")])
            .is_err());

        let mut bad2 = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(bad2
            .initialize_mpc(device, vec![NodeId::new("n1"), NodeId::new("n2")])
            .is_err());

        // ≥3 always accepted; n-of-n contribution per whitepaper §2.5.
        let mut ok4 = GenesisSession::new(b"x".to_vec()).unwrap();
        assert!(ok4
            .initialize_mpc(
                device,
                vec![
                    NodeId::new("n1"),
                    NodeId::new("n2"),
                    NodeId::new("n3"),
                    NodeId::new("n4"),
                ]
            )
            .is_ok());
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

        // K_DBRW is mandatory for validate_session; not part of genesis hash.
        s.set_dbrw_binding(id32(0xDB));

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
        let k_dbrw = id32(0xDB);
        let s = create_mpc_genesis(dev, nodes, k_dbrw, Some(b"DSMv2|test".to_vec())).await;

        let sess = match s {
            Ok(sess) => sess,
            Err(e) => panic!("create_mpc_genesis should succeed: {e:?}"),
        };
        assert_ne!(sess.genesis_id, [0u8; 32]);
        assert!(sess.verify_commitments());
        assert_eq!(sess.mpc_entropies.len(), sess.storage_nodes.len());
    }

    /// Whitepaper §2.5 conformance: an external verifier with the same
    /// public inputs (device_id, participants, metadata, contributions)
    /// must independently recompute the genesis hash byte-for-byte.
    #[test]
    fn genesis_id_is_recomputable_from_public_inputs() {
        let mut s = GenesisSession::new(b"meta".to_vec()).unwrap();
        // Deliberately scramble the participant order on input — the
        // canonical_a() helper sorts internally, so order at call time
        // must not change the hash.
        let nodes = vec![
            NodeId::new("zeta"),
            NodeId::new("alpha"),
            NodeId::new("middle"),
        ];
        s.initialize_mpc(id32(0x42), nodes.clone()).unwrap();
        s.device_entropy = id32(0xD0);
        s.mpc_entropies = vec![id32(0xE1), id32(0xE2), id32(0xE3)];
        s.compute_commitments();
        s.compute_genesis_id();

        // Independent recomputation following whitepaper §2.5 exactly.
        let expected = {
            let mut h = dsm_domain_hasher("DSM/genesis");
            h.update(&s.device_entropy);
            for m in &s.mpc_entropies {
                h.update(m);
            }
            h.update(&canonical_a(&s.device_id, &s.storage_nodes, &s.metadata));
            let mut out = [0u8; 32];
            out.copy_from_slice(h.finalize().as_bytes());
            out
        };
        assert_eq!(s.genesis_id, expected);

        // Permuting the participant order at the call site must NOT
        // change the hash (canonical_a sorts).
        let mut s2 = GenesisSession::new(b"meta".to_vec()).unwrap();
        let permuted = vec![
            NodeId::new("middle"),
            NodeId::new("zeta"),
            NodeId::new("alpha"),
        ];
        // Same session_id needs the same metadata + device_id, but
        // session_id is random so we copy from s.
        s2.session_id = s.session_id;
        s2.initialize_mpc(id32(0x42), permuted).unwrap();
        s2.device_entropy = id32(0xD0);
        s2.mpc_entropies = vec![id32(0xE1), id32(0xE2), id32(0xE3)];
        s2.compute_genesis_id();
        assert_eq!(s.genesis_id, s2.genesis_id);
    }

    /// Issue #252 sub-bug 3: session.genesis_id MUST match the value the
    /// caller-facing converter publishes.  No second recomputation under
    /// a different formula.
    #[tokio::test]
    async fn session_genesis_id_matches_caller_facing_state_hash() {
        use crate::core::identity::genesis::convert_session_to_genesis_state_compat;
        let dev = id32(0x77);
        let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];
        let k_dbrw = id32(0xDB);
        let session = create_mpc_genesis(dev, nodes, k_dbrw, Some(b"meta".to_vec()))
            .await
            .expect("create_mpc_genesis succeeds");

        let gs = convert_session_to_genesis_state_compat(&session)
            .expect("convert succeeds");

        assert_eq!(
            session.genesis_id, gs.hash,
            "Issue #252 sub-bug 3: session-level genesis_id must match \
             the GenesisState.hash returned to callers"
        );
    }

    /// Domain separation: the participant commitment domain
    /// (`DSM/genesis-commit`) must NOT collide with the genesis hash
    /// domain (`DSM/genesis`) under the same input bytes.
    #[test]
    fn commit_domain_is_distinct_from_genesis_domain() {
        let input = id32(0xAB).to_vec();
        let mut h_g = dsm_domain_hasher("DSM/genesis");
        h_g.update(&input);
        let g_hash = h_g.finalize();
        let mut h_c = dsm_domain_hasher("DSM/genesis-commit");
        h_c.update(&input);
        let c_hash = h_c.finalize();
        assert_ne!(g_hash.as_bytes(), c_hash.as_bytes());
    }

    /// Helper: build a session with deterministic, fixed inputs so the
    /// silicon-bound keypair derivation is reproducible across runs.
    fn deterministic_session(
        device_id: [u8; 32],
        nodes: Vec<NodeId>,
        device_entropy: [u8; 32],
        mpc_entropies: Vec<[u8; 32]>,
        metadata: Vec<u8>,
        k_dbrw: [u8; 32],
    ) -> GenesisSession {
        let mut s = GenesisSession::new(metadata).unwrap();
        s.initialize_mpc(device_id, nodes).unwrap();
        s.device_entropy = device_entropy;
        s.mpc_entropies = mpc_entropies;
        s.set_dbrw_binding(k_dbrw);
        s.compute_commitments();
        s.compute_genesis_id();
        s
    }

    /// Whitepaper §11.1 conformance: same `(device_id, K_DBRW,
    /// participants, metadata, contributions)` ⇒ same SPHINCS+ + Kyber
    /// keypair.  This is the core silicon-binding determinism property.
    #[test]
    fn silicon_bound_keypair_is_deterministic_under_same_inputs() {
        let device_id = id32(0x42);
        let nodes = vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")];
        let dev_e = id32(0xD0);
        let mpc_e = vec![id32(0xE1), id32(0xE2), id32(0xE3)];
        let meta = b"DSMv2|determinism".to_vec();
        let k_dbrw = id32(0xDB);

        let s1 = deterministic_session(
            device_id,
            nodes.clone(),
            dev_e,
            mpc_e.clone(),
            meta.clone(),
            k_dbrw,
        );
        let s2 = deterministic_session(device_id, nodes, dev_e, mpc_e, meta, k_dbrw);

        // Sanity: the two sessions agree on the public-recomputable G.
        assert_eq!(s1.genesis_id, s2.genesis_id);

        let kp1 = s1.derive_silicon_bound_keypair().unwrap();
        let kp2 = s2.derive_silicon_bound_keypair().unwrap();

        assert_eq!(kp1.sphincs_public, kp2.sphincs_public);
        assert_eq!(kp1.sphincs_secret, kp2.sphincs_secret);
        assert_eq!(kp1.kyber_public, kp2.kyber_public);
        assert_eq!(kp1.kyber_secret, kp2.kyber_secret);

        // And neither is degenerate.
        assert!(!kp1.sphincs_public.is_empty());
        assert!(!kp1.kyber_public.is_empty());
    }

    /// Whitepaper §12 silicon-binding: differing `K_DBRW` MUST produce
    /// different keypairs even when every public input is identical.
    /// Without this, `K_DBRW` is merely decorative.
    #[test]
    fn silicon_bound_keypair_changes_with_k_dbrw() {
        let device_id = id32(0x42);
        let nodes = vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")];
        let dev_e = id32(0xD0);
        let mpc_e = vec![id32(0xE1), id32(0xE2), id32(0xE3)];
        let meta = b"DSMv2|silicon".to_vec();

        let s_dev_a = deterministic_session(
            device_id,
            nodes.clone(),
            dev_e,
            mpc_e.clone(),
            meta.clone(),
            id32(0xA0),
        );
        let s_dev_b = deterministic_session(
            device_id,
            nodes.clone(),
            dev_e,
            mpc_e.clone(),
            meta.clone(),
            id32(0xB0),
        );

        // Public-inputs ⇒ G is identical (the spec keeps G publicly
        // recomputable; K_DBRW is not part of A).
        assert_eq!(s_dev_a.genesis_id, s_dev_b.genesis_id);

        // But the keypairs must diverge — silicon is bound one layer
        // down, in the master-seed IKM.
        let kp_a = s_dev_a.derive_silicon_bound_keypair().unwrap();
        let kp_b = s_dev_b.derive_silicon_bound_keypair().unwrap();

        assert_ne!(kp_a.sphincs_public, kp_b.sphincs_public);
        assert_ne!(kp_a.sphincs_secret, kp_b.sphincs_secret);
        assert_ne!(kp_a.kyber_public, kp_b.kyber_public);
        assert_ne!(kp_a.kyber_secret, kp_b.kyber_secret);
    }

    /// Whitepaper §11.1 + §12 normative rule: `K_DBRW` MUST NEVER
    /// appear in any externally-publishable bytes.  Concretely, no
    /// 32-byte window of the SanitizedGenesisPayload encoding may
    /// equal the `K_DBRW` value.
    #[test]
    fn k_dbrw_never_appears_in_sanitized_payload_bytes() {
        let device_id = id32(0x42);
        let nodes = vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")];
        let dev_e = id32(0xD0);
        let mpc_e = vec![id32(0xE1), id32(0xE2), id32(0xE3)];
        let meta = b"DSMv2|nonleak".to_vec();
        // Use a high-entropy K_DBRW so accidental match probability is
        // negligible.  (id32(b) only varies by tag byte; we want full
        // byte-pattern uniqueness.)
        let k_dbrw: [u8; 32] = [
            0x9a, 0x73, 0x21, 0xf0, 0x4c, 0x88, 0xb1, 0x5d,
            0xee, 0x06, 0x97, 0x42, 0xa8, 0x33, 0xcf, 0x10,
            0x5b, 0xc4, 0x29, 0x77, 0x84, 0x1e, 0xd3, 0x6a,
            0x2f, 0x90, 0xab, 0x71, 0x05, 0xfd, 0x68, 0x4e,
        ];

        let s = deterministic_session(device_id, nodes, dev_e, mpc_e, meta, k_dbrw);
        let mk = s.derive_silicon_bound_keypair().unwrap();

        // Construct the externally-publishable payload (the only thing
        // that is allowed to leave the device).
        let payload = SanitizedGenesisPayload {
            genesis_hash: s.genesis_id,
            device_id: s.device_id,
            public_key: mk.sphincs_public.clone(),
            participants: s.storage_nodes.clone(),
            created_at_ticks: s.created_at_ticks,
        };

        // Flatten the payload into a single byte stream (every field
        // that could possibly be transmitted).
        let mut flat: Vec<u8> = Vec::new();
        flat.extend_from_slice(&payload.genesis_hash);
        flat.extend_from_slice(&payload.device_id);
        flat.extend_from_slice(&payload.public_key);
        for n in &payload.participants {
            flat.extend_from_slice(n.as_bytes());
        }
        flat.extend_from_slice(&payload.created_at_ticks.to_le_bytes());
        // And include the public Kyber key, which would also ship.
        flat.extend_from_slice(&mk.kyber_public);

        // Sanity: there's enough material to hold a 32-byte pattern.
        assert!(flat.len() >= k_dbrw.len());

        // No 32-byte window may equal K_DBRW.
        let mut leaked = false;
        for w in flat.windows(k_dbrw.len()) {
            if w == k_dbrw {
                leaked = true;
                break;
            }
        }
        assert!(
            !leaked,
            "K_DBRW byte-pattern leaked into externally-publishable payload"
        );
    }

    /// Independent recomputation of S_master from public inputs +
    /// K_DBRW must match the value the session derives, end-to-end.
    /// This pins the §11.1 IKM ordering.
    #[test]
    fn master_seed_matches_independent_recomputation() {
        let device_id = id32(0x42);
        let nodes = vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")];
        let dev_e = id32(0xD0);
        let mpc_e = vec![id32(0xE1), id32(0xE2), id32(0xE3)];
        let meta = b"DSMv2|recompute".to_vec();
        let k_dbrw = id32(0x55);

        let s = deterministic_session(device_id, nodes, dev_e, mpc_e, meta, k_dbrw);

        // Spec-side recomputation: G already lives in s.genesis_id.
        let s_master_session = derive_master_seed(&s.genesis_id, &s.device_id, &s.dbrw_binding);

        // Independent path: rebuild IKM from the spec layout directly.
        let s_0 = compute_step_salt(&s.genesis_id);
        let mut ikm: Vec<u8> = Vec::new();
        ikm.extend_from_slice(&s.genesis_id);
        ikm.extend_from_slice(&s.device_id);
        ikm.extend_from_slice(&k_dbrw);
        ikm.extend_from_slice(&s_0);
        let s_master_independent = crate::crypto::hkdf::extract(b"DSM/dev\0", &ikm);

        assert_eq!(s_master_session, s_master_independent);
    }
}
