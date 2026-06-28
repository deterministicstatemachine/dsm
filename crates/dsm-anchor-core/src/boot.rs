//! Boot fence (§11): the boot ticket and boot chain that gate offline mode.
//!
//! Offline transfer is disabled until a boot ticket (or chain) proves the boot
//! head advanced `J_b → J_{b'}` from the DSM-committed boot head, jointly via the
//! RP2350 partition boot ratchet and the TROPIC01 boot MACANDD slot `q_boot`. A
//! copied state image on new hardware cannot advance the committed boot head
//! (Thm 28), so it cannot resume offline mode.

extern crate alloc;
use alloc::vec::Vec;

use crate::domain;
use crate::enrollment::commit;
use crate::hash::h;
use crate::util::u64_le;

/// `X^boot = H(tag ‖ B ‖ Aᵢ ‖ J_b ‖ boot_seq ‖ firmware_measurement ‖ partition_device_id)`.
pub fn boot_fuse_input(
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    prev_boot_head: &[u8; 32],
    boot_seq: u64,
    firmware_measurement: &[u8; 32],
    partition_device_id: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::BOOT_FUSE_INPUT_V1,
        &[
            bundle,
            anchor_head,
            prev_boot_head,
            &u64_le(boot_seq),
            firmware_measurement,
            partition_device_id,
        ],
    )
}

/// `p_{b+1} = H(tag ‖ p_b ‖ W^boot ‖ B ‖ Aᵢ ‖ J_b ‖ boot_seq ‖ firmware_measurement)`.
pub fn advance_ratchet(
    prev_ratchet: &[u8; 32],
    boot_witness: &[u8; 32],
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    prev_boot_head: &[u8; 32],
    boot_seq: u64,
    firmware_measurement: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::PARTITION_BOOT_RATCHET_V1,
        &[
            prev_ratchet,
            boot_witness,
            bundle,
            anchor_head,
            prev_boot_head,
            &u64_le(boot_seq),
            firmware_measurement,
        ],
    )
}

/// `J_{b+1} = H(tag ‖ B ‖ Aᵢ ‖ J_b ‖ boot_seq ‖ commit(p_{b+1}) ‖ commit(W^boot) ‖ firmware_measurement)`.
pub fn next_boot_head(
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    prev_boot_head: &[u8; 32],
    boot_seq: u64,
    next_ratchet: &[u8; 32],
    boot_witness: &[u8; 32],
    firmware_measurement: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::FUSED_BOOT_HEAD_V1,
        &[
            bundle,
            anchor_head,
            prev_boot_head,
            &u64_le(boot_seq),
            &commit(next_ratchet),
            &commit(boot_witness),
            firmware_measurement,
        ],
    )
}

/// `M^P_boot = H(tag ‖ B ‖ Aᵢ ‖ J_b ‖ J_{b+1} ‖ boot_seq ‖ firmware_measurement)` —
/// the digest the partition signs to certify the boot-head advance.
pub fn boot_cert_message(
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    prev_boot_head: &[u8; 32],
    next_boot_head: &[u8; 32],
    boot_seq: u64,
    firmware_measurement: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::PARTITION_BOOT_CERT_V1,
        &[
            bundle,
            anchor_head,
            prev_boot_head,
            next_boot_head,
            &u64_le(boot_seq),
            firmware_measurement,
        ],
    )
}

/// One boot ticket (§11 / wire `BootTicket`). `partition_boot_signature` is
/// `PartSign(M^P_boot)`; `tropic_boot_witness` is `commit(W^boot)`.
#[derive(Clone)]
pub struct BootTicket {
    pub anchor_bundle: [u8; 32],
    pub anchor_head: [u8; 32],
    pub prev_boot_head: [u8; 32],
    pub next_boot_head: [u8; 32],
    pub boot_seq: u64,
    pub firmware_measurement: [u8; 32],
    pub partition_boot_signature: Vec<u8>,
    pub tropic_boot_input: [u8; 32],
    pub tropic_boot_witness: [u8; 32],
}

impl BootTicket {
    /// Recompute the partition boot-cert message this ticket's signature covers.
    pub fn cert_message(&self) -> [u8; 32] {
        boot_cert_message(
            &self.anchor_bundle,
            &self.anchor_head,
            &self.prev_boot_head,
            &self.next_boot_head,
            self.boot_seq,
            &self.firmware_measurement,
        )
    }
}
