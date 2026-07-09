//! Enrollment (§7): the one-way birth fuse, the immutable anchor bundle `B`, and the
//! genesis offline frontier `h_0`.
//!
//! `B` fuses the three identity factors — the online identity commitment `H(pk_on)`, the
//! chip static identity `stpub`, the resident chip key `pk_chip` (`σ^chip`), and the
//! partition key `pk_host` (`σ^host`) — with the enrolled counter `H0`, the device id, the
//! policy hash, and a public birth commitment `S_birth`. The birth fuse preimage `s_birth`
//! is destroyed immediately after `S_birth` is committed, so public enrollment data cannot
//! recreate `B` on new hardware. There is no partition ratchet and no boot head — the v2
//! anchor advances only the forward-only frontier `h_i`.

extern crate alloc;
use alloc::vec::Vec;

use crate::domain;
use crate::hash::h;
use crate::tropic::PartitionSig;
use crate::util::{u32_le, zeroize};

/// Fixed-width public commitment `commit(x) = H("DSM/anchor/commit/v2" ‖ x)` to a
/// variable-length public value (chip / host key), so `B`'s preimage stays canonical.
pub fn commit(x: &[u8]) -> [u8; 32] {
    h(domain::ANCHOR_COMMIT_V2, &[x])
}

/// Inputs to the birth ceremony. The 32-byte entropy fields come from the RP2350 TRNG, the
/// TROPIC01 birth witness, and the host; the rest are the enrolled identity and policy.
pub struct BirthInputs<'a> {
    pub partition_trng: &'a [u8; 32],
    pub chip_birth_witness: &'a [u8; 32],
    pub host_nonce: &'a [u8; 32],
    pub device_id: &'a [u8; 32],
    pub policy_hash: &'a [u8; 32],
    pub partition_device_id: &'a [u8; 32],
    /// TROPIC01 stable chip identity `stpub` (the pinned anchor id).
    pub anchor_id: &'a [u8; 32],
    /// Resident non-exportable Ed25519 chip public key `pk_chip` (the `σ^chip` key).
    pub chip_pk: &'a [u8],
    /// Online DSM identity public key `pk_on` (bound as `H(pk_on)`; the dual-identity join).
    pub online_id_pk: &'a [u8],
    /// Partition-key birth entropy (seeds `PartitionSig::part_keygen`).
    pub partition_key_seed: &'a [u8; 32],
    /// Enrolled TROPIC01 counter value `H₀`.
    pub enrolled_counter: u32,
    /// DSM genesis state root that seeds the offline frontier `h_0`.
    pub genesis_root: &'a [u8; 32],
}

/// Result of birth. Public fields go into DSM state / are pinned by receivers; the
/// `partition_sk` is non-exportable appliance state.
pub struct Birth {
    /// Anchor bundle `B` (immutable, committed by every root).
    pub bundle: [u8; 32],
    /// Genesis offline frontier `h_0` (seeds the forward-only frontier chain).
    pub genesis_frontier: [u8; 32],
    /// Public birth commitment `S_birth` (committed inside `B`).
    pub birth_commitment: [u8; 32],
    /// Partition public key `pk_host` (`σ^host`; pinned by receivers, bound into `B`).
    pub partition_pk: Vec<u8>,
    /// SECRET partition signing key (non-exportable on device).
    pub partition_sk: Vec<u8>,
    /// Resident chip public key `pk_chip` (`σ^chip`; echoed for pinning, bound into `B`).
    pub chip_pk: Vec<u8>,
}

/// `B = H("DSM/anchor-bundle/v2" ‖ H(pk_on) ‖ stpub ‖ commit(pk_chip) ‖ commit(pk_host) ‖
/// le32(H0) ‖ device_id ‖ policy_hash ‖ S_birth)` (§7). Variable-length keys are bound via
/// fixed-width commitments so the preimage is unambiguous.
#[allow(clippy::too_many_arguments)]
pub fn anchor_bundle(
    online_id_pk: &[u8],
    anchor_id: &[u8; 32],
    chip_pk: &[u8],
    partition_pk: &[u8],
    enrolled_counter: u32,
    device_id: &[u8; 32],
    policy_hash: &[u8; 32],
    birth_commitment: &[u8; 32],
) -> [u8; 32] {
    let pk_on_commit = h(domain::ONLINE_ID_COMMIT_V2, &[online_id_pk]);
    let pk_chip_commit = commit(chip_pk);
    let pk_host_commit = commit(partition_pk);
    h(
        domain::ANCHOR_BUNDLE_V2,
        &[
            &pk_on_commit,
            anchor_id,
            &pk_chip_commit,
            &pk_host_commit,
            &u32_le(enrolled_counter),
            device_id,
            policy_hash,
            birth_commitment,
        ],
    )
}

/// Run the birth ceremony (§7). Generates the partition keypair, forms the bundle and the
/// genesis frontier, and **destroys the birth fuse preimage**.
pub fn birth<P: PartitionSig>(inp: &BirthInputs) -> Birth {
    // Partition keypair (pre-bundle, so its pubkey can be bound into B).
    let part_seed = h(
        domain::PARTITION_KEY_SEED_V1,
        &[inp.partition_key_seed, inp.partition_device_id],
    );
    let (partition_sk, partition_pk) = P::part_keygen(&part_seed);

    // One-way birth fuse and its public commitment (binds fresh device entropy into B).
    let mut s_birth = h(
        domain::BIRTH_SECRET_V1,
        &[
            inp.partition_trng,
            inp.chip_birth_witness,
            inp.host_nonce,
            inp.device_id,
            inp.policy_hash,
        ],
    );
    let birth_commitment = h(domain::BIRTH_COMMITMENT_V1, &[&s_birth]);
    zeroize(&mut s_birth);

    let bundle = anchor_bundle(
        inp.online_id_pk,
        inp.anchor_id,
        inp.chip_pk,
        &partition_pk,
        inp.enrolled_counter,
        inp.device_id,
        inp.policy_hash,
        &birth_commitment,
    );
    let genesis_frontier = h(
        domain::ANCHOR_FRONTIER_GENESIS_V2,
        &[&bundle, inp.genesis_root],
    );

    Birth {
        bundle,
        genesis_frontier,
        birth_commitment,
        partition_pk,
        partition_sk,
        chip_pk: inp.chip_pk.to_vec(),
    }
}
