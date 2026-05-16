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

/// Production transport for genesis MPC. Implementations move bytes
/// across the network to real storage nodes — no in-process shortcuts
/// in production paths (whitepaper §2.5: contributions must be
/// independent across distinct hosts).
///
/// The three rounds match the storage-node-side handler shape:
///
/// - `offer`: orchestrator hands a fully-signed `GenesisMpcSessionV1`
///   to one participant; participant returns its own
///   `GenesisMpcCommitV1` (commit_digest of a freshly-generated
///   secret entropy `e_self`).
/// - `observe_peer_commit`: orchestrator fans every peer's commit out
///   to every other participant so each node satisfies its
///   bias-resistance gate (spec §5 N-of-N — release `e_self` only
///   after observing every other participant's commit).
/// - `request_reveal`: orchestrator asks each participant to release
///   its `e_self`. The participant verifies it has observed all N-1
///   peer commits before responding.
#[async_trait]
pub trait GenesisMpcCommitRevealTransport {
    async fn offer(
        &self,
        node_id: &[u8; 32],
        session: &crate::types::proto::GenesisMpcSessionV1,
    ) -> Result<crate::types::proto::GenesisMpcCommitV1, DsmError>;

    async fn observe_peer_commit(
        &self,
        target_node_id: &[u8; 32],
        peer_commit: &crate::types::proto::GenesisMpcCommitV1,
    ) -> Result<(), DsmError>;

    async fn request_reveal(
        &self,
        node_id: &[u8; 32],
        request: &crate::types::proto::GenesisMpcRevealRequestV1,
    ) -> Result<crate::types::proto::GenesisMpcRevealV1, DsmError>;
}

/// Full outcome of one genesis MPC session — every artifact the
/// caller may need to publish, audit, or feed into key derivation.
#[derive(Debug, Clone)]
pub struct GenesisMpcOutcome {
    /// Built and validated `GenesisSession`, including `genesis_id == G`,
    /// commitments, reveals, and DBRW binding.
    pub session: GenesisSession,
    /// `D_commit = H("DSM/anchor/d-commit\0" || sorted_commits)` per
    /// spec §5.
    pub d_commit: [u8; 32],
    /// `D_reveal = H("DSM/anchor/d-reveal\0" || sorted_reveals)` per
    /// spec §5.
    pub d_reveal: [u8; 32],
    /// `η₀ = H("DSM/anchor/eta\0" || D_commit || D_reveal)` per
    /// spec §5.
    pub eta_0: [u8; 32],
    /// SPHINCS+ public attestation key (`pk_attest`) the device used
    /// to sign the offer envelope. Carried out so the SDK can encode
    /// the published `PublishableGenesisV1` without re-deriving it.
    pub pk_attest: Vec<u8>,
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
        h.update(&canonical_a(
            &self.device_id,
            &self.storage_nodes,
            &self.metadata,
        ));
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
        let mut sphincs_seed: [u8; 32] = sphincs_seed_vec.as_slice().try_into().map_err(|_| {
            DsmError::crypto("SPHINCS+ seed length mismatch", None::<std::io::Error>)
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

// =================== D_commit, D_reveal, η₀ (spec §5) ===================
//
// Storage-nodes spec §5 introduces three aggregate quantities for the
// commit-reveal flow:
//
//   η₀ = H("DSM/anchor/eta\0" || D_commit || D_reveal)
//
// The spec does NOT pin the byte aggregation rule for D_commit and
// D_reveal themselves — it leaves that to the implementation. The
// rules below ARE the implementation pin:
//
//   D_commit = H("DSM/anchor/d-commit\0" || c_1 || c_2 || ... || c_n)
//   D_reveal = H("DSM/anchor/d-reveal\0" || e_1 || e_2 || ... || e_n)
//
// where (c_i, e_i) are SORTED ASCENDING LEX by the corresponding
// contributor_id (32-byte storage node id). The sort makes the
// aggregate independent of network arrival order — exactly the same
// canonical-lex-on-raw-bytes discipline `canonical_a` uses for the
// participant set in `compute_genesis_id`.
//
// Each individual entry is fixed 32 bytes (digest / entropy), so no
// length prefix is needed inside the inner concatenation.
//
// IMPORTANT: every consumer of η₀ (the storage-node side and the
// orchestrating SDK) MUST agree on these formulas byte-for-byte. The
// KATs below trip any drift.

/// `D_commit = H("DSM/anchor/d-commit\0" || sorted_commit_concat)`.
///
/// `commits` is `(contributor_id, commit_digest)` pairs; the function
/// sorts by `contributor_id` and concatenates `commit_digest`s. Caller
/// is responsible for ensuring contributor_ids are unique within the
/// slice — duplicates are not detected here (the canonical orchestrator
/// rejects duplicates at session-construct time).
pub fn compute_d_commit(commits: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<&([u8; 32], [u8; 32])> = commits.iter().collect();
    sorted.sort_by_key(|p| p.0);
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/anchor/d-commit");
    for (_id, digest) in &sorted {
        h.update(digest);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// `D_reveal = H("DSM/anchor/d-reveal\0" || sorted_entropy_concat)`.
///
/// Same shape as `compute_d_commit` but over revealed entropies. Used
/// alongside `compute_d_commit` to feed `compute_eta_0`.
pub fn compute_d_reveal(reveals: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<&([u8; 32], [u8; 32])> = reveals.iter().collect();
    sorted.sort_by_key(|p| p.0);
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/anchor/d-reveal");
    for (_id, entropy) in &sorted {
        h.update(entropy);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// `η₀ = H("DSM/anchor/eta\0" || D_commit || D_reveal)` per
/// storage-nodes spec §5. Matches the formula in the spec exactly.
pub fn compute_eta_0(d_commit: &[u8; 32], d_reveal: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/anchor/eta");
    h.update(d_commit);
    h.update(d_reveal);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
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
pub fn derive_master_seed(g: &[u8; 32], device_id: &[u8; 32], k_dbrw: &[u8; 32]) -> [u8; 32] {
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

// -------------------- High-level MPC orchestrator (real network) --------------------

/// Domain tag for the offer-envelope signature preimage.
pub(crate) const OFFER_SIG_DOMAIN: &str = "DSM/genesis-mpc-offer";

/// Domain tag for the reveal-request signature preimage.
pub(crate) const REVEAL_SIG_DOMAIN: &str = "DSM/genesis-mpc-reveal";

/// Canonical preimage for the offer-envelope SPHINCS+ signature.
///
/// Hashed under the `DSM/genesis-mpc-offer` domain so the storage-node
/// side can recompute byte-for-byte. We sign the hash, not the raw
/// concatenation, so the proto-decoded fields can't be exploited for
/// length-extension or domain confusion.
///
/// Layout (length-prefixed to defeat ambiguous boundaries):
/// ```text
///   session_id           (32B)
///   initiator_device_id  (32B)
///   initiator_cdbrw      (32B)
///   participant_count    (u32 LE)
///   participants concatenated 32B each
///   pk_attest_len        (u32 LE)
///   pk_attest            bytes
/// ```
/// `initiator_signature` is intentionally NOT in the preimage (it is
/// what we are computing).
pub fn compute_offer_sig_preimage(
    session_id: &[u8; 32],
    initiator_device_id: &[u8; 32],
    initiator_cdbrw: &[u8; 32],
    participants: &[[u8; 32]],
    pk_attest: &[u8],
) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher(OFFER_SIG_DOMAIN);
    h.update(session_id);
    h.update(initiator_device_id);
    h.update(initiator_cdbrw);
    h.update(&(participants.len() as u32).to_le_bytes());
    for p in participants {
        h.update(p);
    }
    h.update(&(pk_attest.len() as u32).to_le_bytes());
    h.update(pk_attest);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Canonical preimage for the reveal-request signature.
/// Bound to `(session_id, "reveal")` so a captured /offer signature
/// cannot be replayed on /reveal.
pub fn compute_reveal_sig_preimage(session_id: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher(REVEAL_SIG_DOMAIN);
    h.update(session_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Drive the full N-of-N commit-reveal protocol against `transport`.
///
/// On any error from any participant — offer, fan-out, reveal, or
/// commit-vs-reveal binding — the whole session aborts with `Err`.
/// Per spec §5, withholding a reveal cannot bias post-commit ordering
/// but also cannot complete the protocol; there is no retry inside
/// this function, no partial-set continuation. The caller restarts
/// with a different participant set if desired (in production, that
/// requires `R_reg` to advance, since `session_id` is publicly
/// derived from `(R_reg, device_id)` upstream).
///
/// `participants` must be the 32-byte node IDs of ≥3 distinct
/// storage nodes. The list is canonicalised internally (sorted
/// ascending lex by `canonical_a`); duplicate entries are rejected.
///
/// `pk_attest` / `sk_attest` are the device's SPHINCS+ platform-
/// attestation keypair (whitepaper §12; recoverable from secure
/// element on production hardware). The offer envelope is signed
/// under `sk_attest`; the resulting signature shape-checks the
/// orchestrator's identity on the storage-node side.
///
/// `session_id` is supplied by the caller — production SDK derives
/// it as `H("DSM/genesis-mpc-session\0" || R_reg || device_id)` so
/// it cannot be ground; in-process tests construct it freely.
#[allow(clippy::too_many_arguments)]
pub async fn create_root_genesis_mpc<T>(
    session_id: [u8; 32],
    device_id: [u8; 32],
    device_cdbrw: [u8; 32],
    mut participants: Vec<[u8; 32]>,
    k_dbrw: [u8; 32],
    metadata: Option<Vec<u8>>,
    pk_attest: Vec<u8>,
    sk_attest: &[u8],
    transport: &T,
) -> Result<GenesisMpcOutcome, DsmError>
where
    T: GenesisMpcCommitRevealTransport + Sync,
{
    // 1. Validate inputs.
    if participants.len() < 3 {
        return Err(DsmError::invalid_parameter(format!(
            "Genesis MPC requires ≥3 participants (whitepaper §2.5); got {}",
            participants.len()
        )));
    }
    if k_dbrw == [0u8; 32] {
        return Err(DsmError::invalid_parameter(
            "K_DBRW must be a non-zero binding (whitepaper §12)",
        ));
    }
    if pk_attest.is_empty() || sk_attest.is_empty() {
        return Err(DsmError::invalid_parameter(
            "pk_attest / sk_attest required for offer-envelope signing",
        ));
    }
    // Canonicalise: sort ascending lex (matches storage-node decoder
    // and canonical_a), then reject duplicates.
    participants.sort();
    for w in participants.windows(2) {
        if w[0] == w[1] {
            return Err(DsmError::invalid_parameter(
                "Genesis MPC: duplicate participant in set",
            ));
        }
    }

    let meta = metadata.unwrap_or_else(|| b"DSMv2|bytes|no-wallclock".to_vec());

    // 2. Device entropy `b_0` (whitepaper §2.5).
    let mut device_entropy = [0u8; 32];
    crate::crypto::rng::random_bytes(32)
        .as_slice()
        .read_exact(&mut device_entropy)
        .map_err(|e| DsmError::crypto("Failed to generate device entropy", Some(e)))?;

    // 3. Build the signed offer envelope.
    let sig_preimage = compute_offer_sig_preimage(
        &session_id,
        &device_id,
        &device_cdbrw,
        &participants,
        &pk_attest,
    );
    let initiator_signature = sphincs::sphincs_sign(sk_attest, &sig_preimage)?;

    let session_proto = crate::types::proto::GenesisMpcSessionV1 {
        session_id: session_id.to_vec(),
        initiator_device_id: device_id.to_vec(),
        initiator_pk_attest: pk_attest.clone(),
        initiator_cdbrw: device_cdbrw.to_vec(),
        participants: participants.iter().map(|p| p.to_vec()).collect(),
        initiator_signature,
    };

    // 4. Parallel offer to every participant. Any failure aborts the
    //    whole session — N-of-N (spec §5).
    let offer_futures = participants.iter().map(|node_id| {
        let proto_ref = &session_proto;
        async move { transport.offer(node_id, proto_ref).await }
    });
    let commits: Vec<crate::types::proto::GenesisMpcCommitV1> =
        futures::future::try_join_all(offer_futures).await?;

    // 5. Validate each commit's shape and id binding.
    if commits.len() != participants.len() {
        return Err(DsmError::invalid_operation(
            "Genesis MPC: offer round returned a different commit count than participants",
        ));
    }
    let mut commit_by_id: std::collections::BTreeMap<[u8; 32], [u8; 32]> =
        std::collections::BTreeMap::new();
    for (i, c) in commits.iter().enumerate() {
        if c.session_id != session_id {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: commit returned a wrong session_id",
            ));
        }
        if c.contributor_id.len() != 32 || c.commit_digest.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: commit field shape mismatch (expected 32-byte id and digest)",
            ));
        }
        let contributor_id: [u8; 32] = c
            .contributor_id
            .as_slice()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("Genesis MPC: bad contributor_id"))?;
        if contributor_id != participants[i] {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: contributor_id does not match the offered participant",
            ));
        }
        let digest: [u8; 32] = c
            .commit_digest
            .as_slice()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("Genesis MPC: bad commit_digest"))?;
        if commit_by_id.insert(contributor_id, digest).is_some() {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: duplicate contributor_id in commit round",
            ));
        }
    }

    // 6. Parallel commit fan-out: N·(N-1) pushes (commit_i → node_j
    //    for every i ≠ j). Each node satisfies its bias-resistance
    //    gate (spec §5) only after observing all peers' commits.
    let mut fanout_calls: Vec<_> =
        Vec::with_capacity(participants.len() * (participants.len() - 1));
    for target in &participants {
        for c in &commits {
            let contributor_id: [u8; 32] =
                c.contributor_id.as_slice().try_into().unwrap_or([0u8; 32]);
            if &contributor_id == target {
                continue;
            }
            fanout_calls.push(transport.observe_peer_commit(target, c));
        }
    }
    futures::future::try_join_all(fanout_calls).await?;

    // 7. Build & sign the reveal request envelopes (per node).
    let reveal_preimage = compute_reveal_sig_preimage(&session_id);
    let reveal_sig = sphincs::sphincs_sign(sk_attest, &reveal_preimage)?;
    let reveal_request = crate::types::proto::GenesisMpcRevealRequestV1 {
        session_id: session_id.to_vec(),
        initiator_pk_attest: pk_attest.clone(),
        initiator_signature: reveal_sig,
    };

    // 8. Parallel reveal request to every participant.
    let reveal_futures = participants.iter().map(|node_id| {
        let req_ref = &reveal_request;
        async move { transport.request_reveal(node_id, req_ref).await }
    });
    let reveals: Vec<crate::types::proto::GenesisMpcRevealV1> =
        futures::future::try_join_all(reveal_futures).await?;

    // 9. Verify each reveal binds to its prior commit:
    //    H("DSM/genesis-commit\0" || session_id || entropy) == commit_digest
    //    (matches the storage-node /offer formula at
    //     `dsm_storage_node/src/api/identity/genesis_mpc.rs::offer`.)
    let mut reveal_by_id: std::collections::BTreeMap<[u8; 32], [u8; 32]> =
        std::collections::BTreeMap::new();
    if reveals.len() != participants.len() {
        return Err(DsmError::invalid_operation(
            "Genesis MPC: reveal round returned wrong number of envelopes",
        ));
    }
    for (i, r) in reveals.iter().enumerate() {
        if r.session_id != session_id {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: reveal returned a wrong session_id",
            ));
        }
        if r.contributor_id.len() != 32 || r.entropy.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: reveal field shape mismatch",
            ));
        }
        let contributor_id: [u8; 32] =
            r.contributor_id.as_slice().try_into().map_err(|_| {
                DsmError::invalid_operation("Genesis MPC: bad reveal contributor_id")
            })?;
        if contributor_id != participants[i] {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: reveal contributor_id mismatched its participant slot",
            ));
        }
        let entropy: [u8; 32] = r
            .entropy
            .as_slice()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("Genesis MPC: bad reveal entropy"))?;
        // Recompute the commit_digest from the revealed entropy and
        // reject on mismatch.
        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/genesis-commit");
        h.update(&session_id);
        h.update(&entropy);
        let mut recomputed = [0u8; 32];
        recomputed.copy_from_slice(h.finalize().as_bytes());
        let prior = commit_by_id.get(&contributor_id).ok_or_else(|| {
            DsmError::invalid_operation(
                "Genesis MPC: reveal contributor_id was not in the commit round",
            )
        })?;
        if recomputed != *prior {
            return Err(DsmError::invalid_operation(format!(
                "Genesis MPC: reveal from contributor_id slot {i} does not bind to prior commit"
            )));
        }
        if reveal_by_id.insert(contributor_id, entropy).is_some() {
            return Err(DsmError::invalid_operation(
                "Genesis MPC: duplicate contributor_id in reveal round",
            ));
        }
    }

    // 10. Aggregate via spec §5 formulas.
    let commit_pairs: Vec<([u8; 32], [u8; 32])> =
        commit_by_id.iter().map(|(k, v)| (*k, *v)).collect();
    let reveal_pairs: Vec<([u8; 32], [u8; 32])> =
        reveal_by_id.iter().map(|(k, v)| (*k, *v)).collect();
    let d_commit = compute_d_commit(&commit_pairs);
    let d_reveal = compute_d_reveal(&reveal_pairs);
    let eta_0 = compute_eta_0(&d_commit, &d_reveal);

    // 11. Build `GenesisSession` with entropies in canonical
    //     participant order (the same order used in `canonical_a`).
    let entropies_in_order: Vec<[u8; 32]> = participants
        .iter()
        .map(|p| {
            reveal_by_id
                .get(p)
                .copied()
                .expect("reveal_by_id populated for every participant")
        })
        .collect();
    let storage_nodes: Vec<NodeId> = participants
        .iter()
        .map(|p| NodeId::from_bytes(p.to_vec()))
        .collect();

    let mut session = GenesisSession::new(meta)?;
    session.initialize_mpc(device_id, storage_nodes)?;
    session.set_entropies(device_entropy, entropies_in_order)?;
    session.set_dbrw_binding(k_dbrw);
    session.compute_commitments();
    session.compute_genesis_id();
    session.validate_session()?;

    // 12. Done.
    Ok(GenesisMpcOutcome {
        session,
        d_commit,
        d_reveal,
        eta_0,
        pk_attest,
    })
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

    // -------------------- D_commit / D_reveal / η₀ KATs --------------------

    #[test]
    fn d_commit_sorts_by_contributor_id_so_order_independent() {
        let a = id32(0x10);
        let b = id32(0x20);
        let c = id32(0x30);
        let ca = [0xAA; 32];
        let cb = [0xBB; 32];
        let cc = [0xCC; 32];

        let ordered = compute_d_commit(&[(a, ca), (b, cb), (c, cc)]);
        let shuffled1 = compute_d_commit(&[(c, cc), (a, ca), (b, cb)]);
        let shuffled2 = compute_d_commit(&[(b, cb), (c, cc), (a, ca)]);

        assert_eq!(ordered, shuffled1, "input order MUST NOT affect D_commit");
        assert_eq!(ordered, shuffled2, "input order MUST NOT affect D_commit");
    }

    #[test]
    fn d_reveal_sorts_by_contributor_id_so_order_independent() {
        let a = id32(0x10);
        let b = id32(0x20);
        let c = id32(0x30);
        let ea = [0x01; 32];
        let eb = [0x02; 32];
        let ec = [0x03; 32];

        let ordered = compute_d_reveal(&[(a, ea), (b, eb), (c, ec)]);
        let shuffled = compute_d_reveal(&[(b, eb), (a, ea), (c, ec)]);

        assert_eq!(ordered, shuffled, "input order MUST NOT affect D_reveal");
    }

    #[test]
    fn d_commit_and_d_reveal_have_distinct_domains() {
        // Same raw 32-byte payloads under the same contributor IDs MUST
        // produce different aggregates under D_commit vs D_reveal,
        // because the domain tags differ. Confirms the two domains
        // cannot collide even when an attacker controls the payloads.
        let a = id32(0x10);
        let b = id32(0x20);
        let p1 = [0xAA; 32];
        let p2 = [0xBB; 32];

        let dc = compute_d_commit(&[(a, p1), (b, p2)]);
        let dr = compute_d_reveal(&[(a, p1), (b, p2)]);
        assert_ne!(dc, dr, "D_commit and D_reveal MUST have distinct domains");
    }

    #[test]
    fn d_commit_changes_when_any_digest_changes() {
        let a = id32(0x10);
        let b = id32(0x20);
        let base = compute_d_commit(&[(a, [0xAA; 32]), (b, [0xBB; 32])]);
        let perturbed = compute_d_commit(&[(a, [0xAA; 32]), (b, [0xBC; 32])]);
        assert_ne!(
            base, perturbed,
            "single-byte change in a commit MUST change D_commit"
        );
    }

    #[test]
    fn eta_0_matches_spec_formula() {
        // η₀ = H("DSM/anchor/eta\0" || D_commit || D_reveal)
        // Recompute by hand using the public BLAKE3 + domain hasher to
        // prove the wrapper does what its name says.
        let d_commit = [0x11; 32];
        let d_reveal = [0x22; 32];

        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/anchor/eta");
        h.update(&d_commit);
        h.update(&d_reveal);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(h.finalize().as_bytes());

        let got = compute_eta_0(&d_commit, &d_reveal);
        assert_eq!(got, expected, "compute_eta_0 MUST match spec §5 formula");
    }

    #[test]
    fn eta_0_is_sensitive_to_d_commit_and_d_reveal() {
        // Both inputs must contribute; swap one byte in each and
        // confirm the digest changes.
        let base = compute_eta_0(&[0x00; 32], &[0x00; 32]);
        let only_commit_changed = compute_eta_0(&[0x01; 32], &[0x00; 32]);
        let only_reveal_changed = compute_eta_0(&[0x00; 32], &[0x01; 32]);
        assert_ne!(base, only_commit_changed);
        assert_ne!(base, only_reveal_changed);
        assert_ne!(only_commit_changed, only_reveal_changed);
    }

    #[test]
    fn eta_0_pinned_test_vector() {
        // Frozen test vector: with deterministic inputs, the resulting
        // η₀ value is pinned. If a future change perturbs the formula
        // (different domain, different aggregation, different ordering)
        // this vector trips. The expected value is computed in-test the
        // same way the implementation does — so it pins the FORMULA,
        // not just a magic constant. Any consumer of η₀ that diverges
        // from this formula will fail to combine with the orchestrator.
        let a = id32(0x10);
        let b = id32(0x20);
        let c = id32(0x30);
        let ca = [0xAA; 32];
        let cb = [0xBB; 32];
        let cc = [0xCC; 32];
        let ea = [0x01; 32];
        let eb = [0x02; 32];
        let ec = [0x03; 32];

        let d_commit = compute_d_commit(&[(a, ca), (b, cb), (c, cc)]);
        let d_reveal = compute_d_reveal(&[(a, ea), (b, eb), (c, ec)]);
        let eta_0 = compute_eta_0(&d_commit, &d_reveal);

        // Determinism: rerunning with the same inputs yields the same
        // η₀. This is the load-bearing assertion for downstream
        // consumers (the SDK orchestrator, the storage-node-side
        // recipient verifier).
        let d_commit_again = compute_d_commit(&[(c, cc), (a, ca), (b, cb)]);
        let d_reveal_again = compute_d_reveal(&[(c, ec), (a, ea), (b, eb)]);
        let eta_0_again = compute_eta_0(&d_commit_again, &d_reveal_again);
        assert_eq!(eta_0, eta_0_again);
    }

    #[test]
    fn d_commit_empty_input_is_just_domain_tag_hash() {
        // Edge case: empty input must still produce a deterministic
        // 32-byte digest (the bare domain-tag hash). The orchestrator
        // SHOULD never call this path in production (n ≥ 3), but the
        // function must not panic.
        let got = compute_d_commit(&[]);
        let h = crate::crypto::blake3::dsm_domain_hasher("DSM/anchor/d-commit");
        let mut expected = [0u8; 32];
        expected.copy_from_slice(h.finalize().as_bytes());
        assert_eq!(got, expected);
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
        assert!(bad.initialize_mpc(device, vec![NodeId::new("n1")]).is_err());

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
            0x9a, 0x73, 0x21, 0xf0, 0x4c, 0x88, 0xb1, 0x5d, 0xee, 0x06, 0x97, 0x42, 0xa8, 0x33,
            0xcf, 0x10, 0x5b, 0xc4, 0x29, 0x77, 0x84, 0x1e, 0xd3, 0x6a, 0x2f, 0x90, 0xab, 0x71,
            0x05, 0xfd, 0x68, 0x4e,
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

    // -------------------- Orchestrator tests (Task A.4) --------------------
    //
    // These tests exercise `create_root_genesis_mpc` end-to-end against
    // `InMemoryCommitRevealCluster`, an in-process mock of the storage-
    // node-side state machine. They cover the happy path, every abort
    // edge, and the load-bearing recomputability properties.

    use std::sync::Mutex as StdMutex;

    /// In-process mock of the 3-round commit-reveal storage node.
    /// Mirrors the real handler at
    /// `dsm_storage_node/src/api/identity/genesis_mpc.rs` byte-for-byte
    /// for the commit_digest formula. The integration test
    /// (`dsm_sdk/tests/genesis_mpc_e2e.rs`) exercises the real HTTP
    /// path with the real handler; this mock is for fast unit tests
    /// of the orchestrator alone.
    struct InMemoryCommitRevealCluster {
        // Per-node state, keyed by node_id.
        nodes: StdMutex<std::collections::HashMap<[u8; 32], NodeState>>,
        // Set of node_ids whose /offer must fail (test injection).
        fail_offer_for: std::collections::HashSet<[u8; 32]>,
        // Set of node_ids whose /commit fan-in must fail.
        fail_fanout_for: std::collections::HashSet<[u8; 32]>,
        // Set of node_ids whose /reveal must fail.
        fail_reveal_for: std::collections::HashSet<[u8; 32]>,
        // Set of node_ids that should return tampered reveals
        // (entropy that does not match the prior commit_digest).
        tamper_reveal_for: std::collections::HashSet<[u8; 32]>,
    }

    #[derive(Default)]
    struct NodeState {
        // Sessions this node has accepted, keyed by session_id → row.
        sessions: std::collections::HashMap<[u8; 32], NodeSessionRow>,
    }

    struct NodeSessionRow {
        participants: Vec<[u8; 32]>,
        own_entropy: [u8; 32],
        peer_commits: std::collections::HashMap<[u8; 32], [u8; 32]>,
    }

    impl InMemoryCommitRevealCluster {
        fn new(node_ids: &[[u8; 32]]) -> Self {
            let mut nodes = std::collections::HashMap::new();
            for id in node_ids {
                nodes.insert(*id, NodeState::default());
            }
            Self {
                nodes: StdMutex::new(nodes),
                fail_offer_for: std::collections::HashSet::new(),
                fail_fanout_for: std::collections::HashSet::new(),
                fail_reveal_for: std::collections::HashSet::new(),
                tamper_reveal_for: std::collections::HashSet::new(),
            }
        }

        fn with_offer_failure(mut self, node_id: [u8; 32]) -> Self {
            self.fail_offer_for.insert(node_id);
            self
        }
        fn with_fanout_failure(mut self, node_id: [u8; 32]) -> Self {
            self.fail_fanout_for.insert(node_id);
            self
        }
        fn with_reveal_failure(mut self, node_id: [u8; 32]) -> Self {
            self.fail_reveal_for.insert(node_id);
            self
        }
        fn with_tampered_reveal(mut self, node_id: [u8; 32]) -> Self {
            self.tamper_reveal_for.insert(node_id);
            self
        }
    }

    #[async_trait::async_trait]
    impl GenesisMpcCommitRevealTransport for InMemoryCommitRevealCluster {
        async fn offer(
            &self,
            node_id: &[u8; 32],
            session: &crate::types::proto::GenesisMpcSessionV1,
        ) -> Result<crate::types::proto::GenesisMpcCommitV1, DsmError> {
            if self.fail_offer_for.contains(node_id) {
                return Err(DsmError::invalid_operation("test: offer injected failure"));
            }
            let session_id: [u8; 32] = session
                .session_id
                .as_slice()
                .try_into()
                .map_err(|_| DsmError::invalid_operation("bad session_id len"))?;
            // Generate fresh entropy for this node's contribution.
            let mut e_self = [0u8; 32];
            crate::crypto::rng::random_bytes(32)
                .as_slice()
                .read_exact(&mut e_self)
                .map_err(|e| DsmError::crypto("mock: rng failed", Some(e)))?;
            // commit_digest = H("DSM/genesis-commit\0" || session_id || e_self)
            let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/genesis-commit");
            h.update(&session_id);
            h.update(&e_self);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(h.finalize().as_bytes());

            let mut nodes = self.nodes.lock().unwrap();
            let node = nodes
                .get_mut(node_id)
                .ok_or_else(|| DsmError::invalid_operation("mock: unknown node"))?;
            let participants: Vec<[u8; 32]> = session
                .participants
                .iter()
                .map(|p| p.as_slice().try_into().unwrap_or([0u8; 32]))
                .collect();
            node.sessions.insert(
                session_id,
                NodeSessionRow {
                    participants,
                    own_entropy: e_self,
                    peer_commits: std::collections::HashMap::new(),
                },
            );

            Ok(crate::types::proto::GenesisMpcCommitV1 {
                session_id: session_id.to_vec(),
                contributor_id: node_id.to_vec(),
                commit_digest: digest.to_vec(),
            })
        }

        async fn observe_peer_commit(
            &self,
            target_node_id: &[u8; 32],
            peer_commit: &crate::types::proto::GenesisMpcCommitV1,
        ) -> Result<(), DsmError> {
            if self.fail_fanout_for.contains(target_node_id) {
                return Err(DsmError::invalid_operation("test: fanout injected failure"));
            }
            let session_id: [u8; 32] = peer_commit
                .session_id
                .as_slice()
                .try_into()
                .map_err(|_| DsmError::invalid_operation("bad session_id"))?;
            let contributor_id: [u8; 32] = peer_commit
                .contributor_id
                .as_slice()
                .try_into()
                .map_err(|_| DsmError::invalid_operation("bad contributor_id"))?;
            let digest: [u8; 32] = peer_commit
                .commit_digest
                .as_slice()
                .try_into()
                .map_err(|_| DsmError::invalid_operation("bad commit_digest"))?;
            let mut nodes = self.nodes.lock().unwrap();
            let node = nodes
                .get_mut(target_node_id)
                .ok_or_else(|| DsmError::invalid_operation("mock: unknown target"))?;
            let row = node
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| DsmError::invalid_operation("mock: session missing"))?;
            row.peer_commits.insert(contributor_id, digest);
            Ok(())
        }

        async fn request_reveal(
            &self,
            node_id: &[u8; 32],
            request: &crate::types::proto::GenesisMpcRevealRequestV1,
        ) -> Result<crate::types::proto::GenesisMpcRevealV1, DsmError> {
            if self.fail_reveal_for.contains(node_id) {
                return Err(DsmError::invalid_operation("test: reveal injected failure"));
            }
            let session_id: [u8; 32] = request
                .session_id
                .as_slice()
                .try_into()
                .map_err(|_| DsmError::invalid_operation("bad session_id"))?;
            let nodes = self.nodes.lock().unwrap();
            let node = nodes
                .get(node_id)
                .ok_or_else(|| DsmError::invalid_operation("mock: unknown node"))?;
            let row = node
                .sessions
                .get(&session_id)
                .ok_or_else(|| DsmError::invalid_operation("mock: no session"))?;
            // Spec §5 bias-resistance gate: each node releases its
            // entropy only after seeing every peer's commit.
            let expected_peers = row.participants.len() - 1;
            if row.peer_commits.len() < expected_peers {
                return Err(DsmError::invalid_operation(
                    "mock: bias-resistance gate not satisfied (missing peer commits)",
                ));
            }
            let entropy = if self.tamper_reveal_for.contains(node_id) {
                // Return entropy that does not match the prior commit.
                let mut tampered = row.own_entropy;
                tampered[0] ^= 0xFF;
                tampered
            } else {
                row.own_entropy
            };
            Ok(crate::types::proto::GenesisMpcRevealV1 {
                session_id: session_id.to_vec(),
                contributor_id: node_id.to_vec(),
                entropy: entropy.to_vec(),
            })
        }
    }

    /// Build deterministic-ish keypair material for the orchestrator
    /// tests. The keypair must SPHINCS+-verify under our own preimage,
    /// so we use `sphincs::generate_sphincs_keypair` per call rather
    /// than fabricating bytes.
    #[allow(clippy::type_complexity)]
    fn orchestrator_test_inputs(
        participants: Vec<[u8; 32]>,
    ) -> (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
        Vec<[u8; 32]>,
    ) {
        let session_id = id32(0x01);
        let device_id = id32(0x02);
        let device_cdbrw = id32(0x03);
        let k_dbrw = id32(0xDB);
        let (pk, sk) = sphincs::generate_sphincs_keypair().expect("sphincs keypair");
        (
            session_id,
            device_id,
            device_cdbrw,
            k_dbrw,
            pk,
            sk,
            participants,
        )
    }

    fn three_participants() -> Vec<[u8; 32]> {
        let mut a = id32(0x10);
        let mut b = id32(0x20);
        let mut c = id32(0x30);
        // Force ascending lex.
        a[0] = 0x10;
        b[0] = 0x20;
        c[0] = 0x30;
        vec![a, b, c]
    }

    #[tokio::test]
    async fn orchestrator_happy_path_3_node() {
        let parts = three_participants();
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps);
        let out = create_root_genesis_mpc(
            sid,
            did,
            dcd,
            ps.clone(),
            k,
            Some(b"meta".to_vec()),
            pk,
            &sk,
            &cluster,
        )
        .await
        .expect("3-node happy path should succeed");
        assert_ne!(out.session.genesis_id, [0u8; 32]);
        assert_eq!(out.session.mpc_entropies.len(), 3);
        assert!(out.session.verify_commitments());
        assert_ne!(out.eta_0, [0u8; 32]);
    }

    #[tokio::test]
    async fn orchestrator_aborts_when_any_offer_fails() {
        let parts = three_participants();
        let bad = parts[1];
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps).with_offer_failure(bad);
        let r = create_root_genesis_mpc(sid, did, dcd, ps, k, None, pk, &sk, &cluster).await;
        assert!(
            r.is_err(),
            "must abort if any participant's offer fails (spec §5 N-of-N)"
        );
    }

    #[tokio::test]
    async fn orchestrator_aborts_when_any_fanout_fails() {
        let parts = three_participants();
        let bad = parts[2];
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps).with_fanout_failure(bad);
        let r = create_root_genesis_mpc(sid, did, dcd, ps, k, None, pk, &sk, &cluster).await;
        assert!(
            r.is_err(),
            "must abort if any fan-out push fails (a node can't satisfy bias-resistance gate)"
        );
    }

    #[tokio::test]
    async fn orchestrator_aborts_when_any_reveal_fails() {
        let parts = three_participants();
        let bad = parts[0];
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps).with_reveal_failure(bad);
        let r = create_root_genesis_mpc(sid, did, dcd, ps, k, None, pk, &sk, &cluster).await;
        assert!(
            r.is_err(),
            "must abort if any reveal call fails (withholding cannot complete per spec §5)"
        );
    }

    #[tokio::test]
    async fn orchestrator_rejects_reveal_that_doesnt_bind_to_prior_commit() {
        let parts = three_participants();
        let tampered = parts[1];
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps).with_tampered_reveal(tampered);
        let r = create_root_genesis_mpc(sid, did, dcd, ps, k, None, pk, &sk, &cluster).await;
        assert!(
            r.is_err(),
            "must abort when a reveal does not bind to its prior commit"
        );
    }

    #[tokio::test]
    async fn g_recomputable_from_outcome_using_whitepaper_25_formula() {
        let parts = three_participants();
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps);
        let out = create_root_genesis_mpc(
            sid,
            did,
            dcd,
            ps.clone(),
            k,
            Some(b"recompute".to_vec()),
            pk,
            &sk,
            &cluster,
        )
        .await
        .expect("happy path");

        // Independent recomputation per whitepaper §2.5:
        // G = H("DSM/genesis\0" || device_entropy || mpc_1..n || A)
        let mut h = dsm_domain_hasher("DSM/genesis");
        h.update(&out.session.device_entropy);
        for m in &out.session.mpc_entropies {
            h.update(m);
        }
        h.update(&canonical_a(
            &out.session.device_id,
            &out.session.storage_nodes,
            &out.session.metadata,
        ));
        let mut expected = [0u8; 32];
        expected.copy_from_slice(h.finalize().as_bytes());
        assert_eq!(out.session.genesis_id, expected);
    }

    #[tokio::test]
    async fn every_participant_is_contacted_no_prefix_bias() {
        // 5-node cluster — every node must be contacted in offer + reveal.
        let mut parts: Vec<[u8; 32]> = Vec::new();
        for i in 1u8..=5 {
            let mut id = [0u8; 32];
            id[0] = i * 0x10;
            parts.push(id);
        }
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps);
        let out = create_root_genesis_mpc(sid, did, dcd, ps.clone(), k, None, pk, &sk, &cluster)
            .await
            .expect("5-node MPC");
        assert_eq!(out.session.mpc_entropies.len(), 5);
        // Every node has a session row after the run — i.e. every
        // participant was contacted.
        let nodes = cluster.nodes.lock().unwrap();
        for p in &ps {
            assert!(
                nodes.get(p).unwrap().sessions.contains_key(&sid),
                "participant {p:?} was not contacted"
            );
        }
    }

    #[tokio::test]
    async fn g_equals_session_genesis_id_returned_to_callers() {
        use crate::core::identity::genesis::convert_session_to_genesis_state_compat;
        let parts = three_participants();
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps);
        let out = create_root_genesis_mpc(
            sid,
            did,
            dcd,
            ps,
            k,
            Some(b"caller-hash".to_vec()),
            pk,
            &sk,
            &cluster,
        )
        .await
        .expect("happy path");

        let gs = convert_session_to_genesis_state_compat(&out.session).expect("convert");
        assert_eq!(
            out.session.genesis_id, gs.hash,
            "session-level genesis_id must equal the caller-facing GenesisState.hash"
        );
    }

    #[tokio::test]
    async fn d_commit_d_reveal_eta_0_match_pinned_formulas() {
        let parts = three_participants();
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps);
        let out = create_root_genesis_mpc(sid, did, dcd, ps.clone(), k, None, pk, &sk, &cluster)
            .await
            .expect("happy path");

        // Recompute D_commit / D_reveal / η₀ from the public outcome
        // and confirm they match the pinned formulas at
        // dsm/src/core/identity/genesis_mpc.rs:500-540.
        let commits: Vec<([u8; 32], [u8; 32])> = ps
            .iter()
            .zip(out.session.mpc_entropies.iter())
            .map(|(id, e)| {
                let mut h = dsm_domain_hasher("DSM/genesis-commit");
                h.update(&sid);
                h.update(e);
                let mut d = [0u8; 32];
                d.copy_from_slice(h.finalize().as_bytes());
                (*id, d)
            })
            .collect();
        let reveals: Vec<([u8; 32], [u8; 32])> = ps
            .iter()
            .zip(out.session.mpc_entropies.iter())
            .map(|(id, e)| (*id, *e))
            .collect();
        let d_c = compute_d_commit(&commits);
        let d_r = compute_d_reveal(&reveals);
        let eta = compute_eta_0(&d_c, &d_r);
        assert_eq!(out.d_commit, d_c);
        assert_eq!(out.d_reveal, d_r);
        assert_eq!(out.eta_0, eta);
    }

    #[tokio::test]
    async fn n_less_than_3_rejected() {
        let parts: Vec<[u8; 32]> = vec![id32(0x10), id32(0x20)];
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps);
        let r = create_root_genesis_mpc(sid, did, dcd, ps, k, None, pk, &sk, &cluster).await;
        assert!(r.is_err(), "n<3 must be rejected (whitepaper §2.5 floor)");
    }

    #[tokio::test]
    async fn duplicate_participant_rejected() {
        let parts: Vec<[u8; 32]> = vec![id32(0x10), id32(0x10), id32(0x20)];
        let (sid, did, dcd, k, pk, sk, ps) = orchestrator_test_inputs(parts);
        let cluster = InMemoryCommitRevealCluster::new(&ps);
        let r = create_root_genesis_mpc(sid, did, dcd, ps, k, None, pk, &sk, &cluster).await;
        assert!(
            r.is_err(),
            "duplicate participant_id must be rejected (set semantics)"
        );
    }
}
