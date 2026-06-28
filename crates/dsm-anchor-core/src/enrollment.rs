//! Enrollment: the one-way birth fuse (§7), the immutable anchor bundle `B`
//! (§8), and the initial fused heads `A₀` / `J₀` / partition ratchet `p₀` (§9).
//!
//! The birth fuse preimage `s_birth` is destroyed immediately after deriving
//! `p₀`; only `S_birth = H(s_birth)` survives (committed inside `B`). Public
//! enrollment data is therefore insufficient to recreate the initial fused
//! lineage on new hardware (Thm 27).

extern crate alloc;
use alloc::vec::Vec;

use crate::domain;
use crate::hash::{h, kdf};
use crate::tropic::PartitionSig;
use crate::util::{u16_le, u32_le, u64_le, zeroize};

/// Public commitment `commit(x) = H("DSM/anchor/commit/v1" ‖ x)` to a private
/// value (the partition pubkey, the ratchet, a boot witness).
pub fn commit(x: &[u8]) -> [u8; 32] {
    h(domain::ANCHOR_COMMIT_V1, &[x])
}

/// Inputs to the birth ceremony. The 32-byte entropy fields come from the RP2350
/// TRNG, the TROPIC01 birth witness, and the host; the rest are the enrolled
/// identity and policy.
pub struct BirthInputs<'a> {
    pub partition_trng: &'a [u8; 32],
    pub tropic_birth_witness: &'a [u8; 32],
    pub host_nonce: &'a [u8; 32],
    pub device_id: &'a [u8; 32],
    pub policy_hash: &'a [u8; 32],
    pub partition_device_id: &'a [u8; 32],
    /// TROPIC01 anchor identifier (the pinned chip identity).
    pub tropic_anchor_id: &'a [u8; 32],
    /// Partition-key birth entropy (seeds `PartitionSig::part_keygen`).
    pub partition_key_seed: &'a [u8; 32],
    /// Enrolled TROPIC01 counter value `H₀`.
    pub enrolled_counter: u32,
    /// MACANDD slots: boot fence `q_boot`, transfer witness `q_tx`.
    pub q_boot: u16,
    pub q_tx: u16,
    /// Genesis DSM SMT root `h₀` (the active root at anchor counter 0).
    pub genesis_root: &'a [u8; 32],
}

/// Result of birth. Public fields go into DSM state / are pinned by receivers;
/// the `partition_*` private fields are non-exportable appliance state.
pub struct Birth {
    /// Anchor bundle `B` (immutable, committed by every root).
    pub bundle: [u8; 32],
    /// Initial fused anchor head `A₀`.
    pub anchor_head: [u8; 32],
    /// Initial boot fence head `J₀`.
    pub boot_head: [u8; 32],
    /// Public birth commitment `S_birth` (committed inside `B`).
    pub birth_commitment: [u8; 32],
    /// Partition public key (committed inside `B` as `commit(pk)`; pinned by receivers).
    pub partition_pk: Vec<u8>,
    /// SECRET partition signing key (non-exportable on device).
    pub partition_sk: Vec<u8>,
    /// SECRET initial partition ratchet `p₀` (non-exportable on device).
    pub partition_ratchet: [u8; 32],
}

/// `B = H(tag ‖ commit(partition_pk) ‖ partition_device_id ‖ tropic_anchor_id ‖
/// H₀ ‖ q_boot ‖ q_tx ‖ device_id ‖ policy_hash ‖ S_birth)` (§8, Def. 14). The
/// partition pubkey is bound via its `commit` so the bundle preimage is fixed-width.
#[allow(clippy::too_many_arguments)]
pub fn anchor_bundle(
    partition_pk: &[u8],
    partition_device_id: &[u8; 32],
    tropic_anchor_id: &[u8; 32],
    enrolled_counter: u32,
    q_boot: u16,
    q_tx: u16,
    device_id: &[u8; 32],
    policy_hash: &[u8; 32],
    birth_commitment: &[u8; 32],
) -> [u8; 32] {
    let pk_commit = commit(partition_pk);
    h(
        domain::ANCHOR_BUNDLE_V1,
        &[
            &pk_commit,
            partition_device_id,
            tropic_anchor_id,
            &u32_le(enrolled_counter),
            &u16_le(q_boot),
            &u16_le(q_tx),
            device_id,
            policy_hash,
            birth_commitment,
        ],
    )
}

/// Run the birth ceremony (§7–§9). Generates the partition keypair, forms the
/// bundle and initial heads, derives the partition ratchet seed, and **destroys
/// the birth fuse preimage**.
pub fn birth<P: PartitionSig>(inp: &BirthInputs) -> Birth {
    // Partition keypair (pre-bundle, so its pubkey can be bound into B).
    let part_seed = h(
        domain::PARTITION_KEY_SEED_V1,
        &[inp.partition_key_seed, inp.partition_device_id],
    );
    let (partition_sk, partition_pk) = P::part_keygen(&part_seed);

    // One-way birth fuse and its public commitment.
    let mut s_birth = h(
        domain::BIRTH_SECRET_V1,
        &[
            inp.partition_trng,
            inp.tropic_birth_witness,
            inp.host_nonce,
            inp.device_id,
            inp.policy_hash,
        ],
    );
    let birth_commitment = h(domain::BIRTH_COMMITMENT_V1, &[&s_birth]);

    let bundle = anchor_bundle(
        &partition_pk,
        inp.partition_device_id,
        inp.tropic_anchor_id,
        inp.enrolled_counter,
        inp.q_boot,
        inp.q_tx,
        inp.device_id,
        inp.policy_hash,
        &birth_commitment,
    );

    let anchor_head = h(
        domain::FUSED_ANCHOR_HEAD_INIT_V1,
        &[&bundle, inp.genesis_root, &u64_le(0), &birth_commitment],
    );
    let boot_head = h(
        domain::FUSED_BOOT_HEAD_INIT_V1,
        &[&bundle, &anchor_head, &u64_le(0), &birth_commitment],
    );

    // Initial partition ratchet, then destroy the birth fuse preimage.
    let partition_ratchet = kdf(
        &s_birth,
        domain::PARTITION_RATCHET_SEED_V1,
        &[&bundle, &anchor_head, &boot_head],
    );
    zeroize(&mut s_birth);

    Birth {
        bundle,
        anchor_head,
        boot_head,
        birth_commitment,
        partition_pk,
        partition_sk,
        partition_ratchet,
    }
}
