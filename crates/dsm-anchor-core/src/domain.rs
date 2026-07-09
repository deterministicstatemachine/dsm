//! Canonical domain tags for the **Software Authority, Hardware Identity** anchor (v2).
//! These strings are normative: the producer and every verifier recompute each value with
//! the exact same tag, so they must match across the appliance and all verifiers. Only the
//! tags the v2 design calls for are here — the boot-fence / MACANDD-witness / fused-anchor-
//! head / WOTS tags are deleted (no legacy).

// --- Enrollment / one-way birth fuse (§7) ---
/// Birth fuse preimage `s_birth`; destroyed after deriving the birth commitment.
pub const BIRTH_SECRET_V1: &str = "DSM/anchor/birth-secret/v1";
/// Public birth commitment `S_birth = H(tag ‖ s_birth)`, bound into `B`.
pub const BIRTH_COMMITMENT_V1: &str = "DSM/anchor/birth-commitment/v1";
/// Partition signing-key seed derivation (from partition entropy, pre-bundle).
pub const PARTITION_KEY_SEED_V1: &str = "DSM/partition-key-seed/v1";
/// Fixed-width public commitment `commit(x) = H(tag ‖ x)` to a variable-length public value
/// (an online / chip / host public key), so `B`'s preimage stays canonical and unambiguous.
pub const ANCHOR_COMMIT_V2: &str = "DSM/anchor/commit/v2";
/// Online-identity commitment `H(tag ‖ pk_on)` bound into `B` — the dual-identity join point.
pub const ONLINE_ID_COMMIT_V2: &str = "DSM/identity/online-commit/v2";
/// Immutable anchor bundle `B` (§7): binds `H(pk_on)`, `stpub`, `commit(pk_chip)`,
/// `commit(pk_host)`, `H0`, `device_id`, `policy_hash`, `S_birth`.
pub const ANCHOR_BUNDLE_V2: &str = "DSM/anchor-bundle/v2";
/// Genesis offline frontier `h_0 = H(tag ‖ B ‖ genesis_root)`; seeds the forward-only chain.
pub const ANCHOR_FRONTIER_GENESIS_V2: &str = "DSM/anchor-frontier-genesis/v2";

// --- Software-Authority / Hardware-Identity root advance (v2) ---
// Uniqueness is a DSM device-SMT property; the release binds ONE root-advance message
// `M_{i+1}` under three independent signatures (σ^DSM seed, σ^chip resident TROPIC01
// Ed25519, σ^host RP2350 partition). No hardware counter read is on the acceptance path.
/// Transition core digest `D_{i+1} = H(tag ‖ enc(Δ°))`; Δ° excludes the successor root.
pub const TRANSITION_DIGEST_V2: &str = "DSM/transition-digest/v2";
/// Forward-only offline frontier advance `h_{i+1} = H(tag ‖ h_i ‖ D_{i+1})`.
pub const ANCHOR_ROOT_ADVANCE_V2: &str = "DSM/anchor-root-advance/v2";
/// Anchor-state leaf `L_i = H(tag ‖ B ‖ h_i ‖ le64(u_i))`, committed inside device SMT root `R_i`.
pub const ANCHOR_STATE_V2: &str = "DSM/anchor-state/v2";
/// Root-advance message `M_{i+1}` — the single message all three signatures cover.
pub const ROOT_ADVANCE_MESSAGE_V2: &str = "DSM/root-advance/v2";
