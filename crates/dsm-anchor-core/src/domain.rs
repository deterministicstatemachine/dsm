//! Canonical domain tags for the Boot Fenced Fused Anchor construction.
//! These strings are normative: the producer and every verifier recompute each
//! value with the exact same tag, so they must match across the appliance and
//! all verifiers.

// --- Enrollment / one-way birth fuse (§7–§9) ---
/// Birth fuse preimage `s_birth` (Def. 12); destroyed after deriving `p₀`.
pub const BIRTH_SECRET_V1: &str = "DSM/anchor/birth-secret/v1";
/// Public birth commitment `S_birth = H(tag ‖ s_birth)`.
pub const BIRTH_COMMITMENT_V1: &str = "DSM/anchor/birth-commitment/v1";
/// Immutable anchor bundle `B` (Def. 14).
pub const ANCHOR_BUNDLE_V1: &str = "DSM/anchor-bundle/v1";
/// Initial fused anchor head `A₀`.
pub const FUSED_ANCHOR_HEAD_INIT_V1: &str = "DSM/fused-anchor-head/init/v1";
/// Initial boot fence head `J₀`.
pub const FUSED_BOOT_HEAD_INIT_V1: &str = "DSM/fused-boot-head/init/v1";
/// Initial partition ratchet seed `p₀ = HKDF(s_birth, tag ‖ B ‖ A₀ ‖ J₀)`.
pub const PARTITION_RATCHET_SEED_V1: &str = "DSM/partition-ratchet-seed/v1";
/// Partition signing-key seed derivation (from partition entropy, pre-bundle).
pub const PARTITION_KEY_SEED_V1: &str = "DSM/partition-key-seed/v1";

// --- Boot fence (§11) ---
/// Boot fuse input `X^boot` consumed by the boot MACANDD slot.
pub const BOOT_FUSE_INPUT_V1: &str = "DSM/boot-fuse-input/v1";
/// Partition boot ratchet advance `p_{b+1}`.
pub const PARTITION_BOOT_RATCHET_V1: &str = "DSM/partition-boot-ratchet/v1";
/// Boot fence head advance `J_{b+1}`.
pub const FUSED_BOOT_HEAD_V1: &str = "DSM/fused-boot-head/v1";
/// Partition boot certificate message (signed by PartSign).
pub const PARTITION_BOOT_CERT_V1: &str = "DSM/partition-boot-cert/v1";
/// Public commitment to a private value: `commit(x) = H(tag ‖ x)`.
pub const ANCHOR_COMMIT_V1: &str = "DSM/anchor/commit/v1";

// --- Root advance (§15–§18) ---
/// Transition digest `D = H(tag ‖ enc(Δ))` (Def. 14 of §15).
pub const TRANSITION_DIGEST_V1: &str = "DSM/root-advance/transition-digest/v1";
/// Boot bound root advance message `M` (§16) — bound by both certs and the witness.
pub const FUSED_ROOT_ADVANCE_MESSAGE_V1: &str = "DSM/fused-root-advance-message/v1";
/// Partition commitment `C^P` (§17).
pub const PARTITION_COMMIT_V1: &str = "DSM/partition-commit/v1";
/// TROPIC01 transfer witness input `X^T` (§17), binds the partition commitment.
pub const TROPIC_FUSED_TRANSFER_INPUT_V1: &str = "DSM/tropic-fused-transfer-input/v1";
/// TROPIC01 transfer witness signing seed `K^T` (§17), keyed by `W^T`.
pub const TROPIC_FUSED_TRANSFER_WITNESS_KEY_V1: &str = "DSM/tropic/fused-transfer-witness-key/v1";
/// TROPIC01 transfer witness message `M^T` (§17) — the digest StepSign covers.
pub const TROPIC_FUSED_TRANSFER_WITNESS_MESSAGE_V1: &str =
    "DSM/tropic/fused-transfer-witness-message/v1";
/// Partition final certificate message `M^P` (§17) — binds the TROPIC witness back.
pub const PARTITION_FINAL_CERT_V1: &str = "DSM/partition-final-cert/v1";
/// Next fused anchor head `A_{i+1}` (§18).
pub const FUSED_ANCHOR_HEAD_V1: &str = "DSM/fused-anchor-head/v1";
/// Committed public-witness-key handle `P_hw = H(tag ‖ pk_hw)`.
pub const PK_HASH_V1: &str = "DSM/tropic/pk-hash/v1";

// --- WOTS-over-BLAKE3 witness signature (§19) ---
/// WOTS chain step function F.
pub const WOTS_CHAIN_V1: &str = "DSM/anchor/wots-chain/v1";
/// WOTS per-chain secret derivation from the seed.
pub const WOTS_SK_V1: &str = "DSM/anchor/wots-sk/v1";
/// WOTS public-key compression of the chain tops.
pub const WOTS_PK_V1: &str = "DSM/anchor/wots-pk/v1";
