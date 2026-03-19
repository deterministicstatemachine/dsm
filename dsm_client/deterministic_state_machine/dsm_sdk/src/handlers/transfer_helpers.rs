// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared transfer and receipt helper free functions for AppRouterImpl.
//!
//! These are extracted verbatim from the original `app_router_impl.rs` top-level
//! free functions (backup lines 48–171).

/// Build a stitched receipt from an applied state transition.
/// Delegates to the shared `build_bilateral_receipt()` in `sdk::receipts`
/// which computes real genesis, SMT roots, relation proofs, and device proofs.
///
/// `device_tree_root`: explicit R_G for the sender device. `None` is rejected.
pub(crate) fn build_online_receipt(
    applied_state: &dsm::types::state_types::State,
    from_device: &[u8],
    to_device: &[u8],
    device_tree_root: Option<[u8; 32]>,
) -> Option<Vec<u8>> {
    let mut dev_a = [0u8; 32];
    if from_device.len() >= 32 {
        dev_a.copy_from_slice(&from_device[..32]);
    }
    let mut dev_b = [0u8; 32];
    if to_device.len() >= 32 {
        dev_b.copy_from_slice(&to_device[..32]);
    }
    crate::sdk::receipts::build_bilateral_receipt(
        dev_a,
        dev_b,
        applied_state.prev_state_hash,
        applied_state.hash,
        device_tree_root,
    )
}

/// Build canonical stitched receipt bytes + commitment sigma for unlock proofs.
///
/// Delegates to the single authoritative `build_receipt_struct()` in `sdk::receipts`
/// for all cryptographic material, then derives sigma from the receipt commitment.
///
/// `device_tree_root`: explicit R_G for the sender device. `None` is rejected.
pub(crate) fn build_online_receipt_and_sigma(
    applied_state: &dsm::types::state_types::State,
    from_device: &[u8],
    to_device: &[u8],
    device_tree_root: Option<[u8; 32]>,
) -> Option<(Vec<u8>, [u8; 32])> {
    let mut dev_a = [0u8; 32];
    if from_device.len() >= 32 {
        dev_a.copy_from_slice(&from_device[..32]);
    }
    let mut dev_b = [0u8; 32];
    if to_device.len() >= 32 {
        dev_b.copy_from_slice(&to_device[..32]);
    }

    let receipt = crate::sdk::receipts::build_receipt_struct(
        dev_a,
        dev_b,
        applied_state.prev_state_hash,
        applied_state.hash,
        device_tree_root,
    )?;
    let bytes = receipt.to_canonical_protobuf().ok()?;
    let sigma = receipt.compute_commitment().ok()?;
    Some((bytes, sigma))
}

/// Build receipt with real SMT roots and inclusion proofs (§4.2 compliant).
///
/// Use this variant when the caller has access to the `BoundedSmt` and has
/// already performed the SMT-Replace, collecting pre/post roots and proofs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_online_receipt_with_smt(
    from_device: &[u8],
    to_device: &[u8],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    parent_root: [u8; 32],
    child_root: [u8; 32],
    rel_proof_parent: Vec<u8>,
    rel_proof_child: Vec<u8>,
    device_tree_root: Option<[u8; 32]>,
) -> Option<Vec<u8>> {
    let mut dev_a = [0u8; 32];
    if from_device.len() >= 32 {
        dev_a.copy_from_slice(&from_device[..32]);
    }
    let mut dev_b = [0u8; 32];
    if to_device.len() >= 32 {
        dev_b.copy_from_slice(&to_device[..32]);
    }
    crate::sdk::receipts::build_bilateral_receipt_with_smt(
        dev_a,
        dev_b,
        parent_tip,
        child_tip,
        parent_root,
        child_root,
        rel_proof_parent,
        rel_proof_child,
        device_tree_root,
    )
}
