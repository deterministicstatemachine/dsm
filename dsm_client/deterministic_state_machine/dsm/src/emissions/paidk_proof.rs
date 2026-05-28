// SPDX-License-Identifier: MIT OR Apache-2.0

//! PaidK spend-gate proof verification for DJTE emissions (issue #186 Finding 2).
//!
//! `JoinActivationProof.gate_proof` is the opaque byte field that demonstrates
//! the device cleared the PaidK spend-gate before its activation event is
//! eligible for emissions. Previously the field was never validated — any
//! arbitrary bytes were accepted by `verify_emission`. This module decodes
//! a `PaidKGateProofV1` protobuf and enforces the structural predicate from
//! whitepaper §16:
//!
//! ```text
//! PaidK(G, DevID, R) := |{r in R | VerifyPayment(r) AND amt(r) >= FLAT_RATE}| >= K
//! ```
//!
//! Structural checks:
//!   * `>= K` receipts present (K = 3, matches `dsm_storage_node/src/api/vault/paidk.rs`)
//!   * every receipt's `device_id` matches the activating device (`jap.id`)
//!   * `>= K` distinct `operator_node_id` values across the bundle
//!   * `amount >= FLAT_RATE` per receipt (FLAT_RATE = 1000)
//!
//! NOT enforced here (tracked as follow-on work — see issue #186 closing note):
//!   * per-receipt operator signatures (`VerifyPayment(r)` proper). The
//!     `StoragePaymentReceiptV3` schema doesn't carry operator signatures yet.
//!     Once it does, plumb that verification through here.
//!
//! Constants are kept locally and assertion-checked against any future shared
//! config to prevent silent drift from the storage-node side.

use std::collections::HashSet;

use prost::Message;

use crate::types::error::DsmError;
use crate::types::proto::{PaidKGateProofV1, StoragePaymentReceiptV3};

/// PaidK threshold — distinct operators required. Must match
/// `DEFAULT_K` in `dsm_storage_node/src/api/vault/paidk.rs`.
pub const PAIDK_K: usize = 3;

/// Minimum payment per receipt. Must match `DEFAULT_FLAT_RATE` in
/// `dsm_storage_node/src/api/vault/paidk.rs`.
pub const PAIDK_FLAT_RATE: u64 = 1000;

/// Verify a PaidK gate-proof bound to a specific activating device.
///
/// `gate_proof_bytes` is the raw `JoinActivationProof.gate_proof` field;
/// `device_id` is the 32-byte device identifier the gate-proof must attest to
/// (in the current schema, this is `jap.id`).
pub fn verify_paidk_gate_proof(
    gate_proof_bytes: &[u8],
    device_id: &[u8; 32],
) -> Result<(), DsmError> {
    if gate_proof_bytes.is_empty() {
        return Err(DsmError::Verification(
            "PaidK gate_proof missing (empty bytes)".into(),
        ));
    }

    let proof = PaidKGateProofV1::decode(gate_proof_bytes).map_err(|e| {
        DsmError::Verification(format!("PaidK gate_proof decode failed: {e}"))
    })?;

    if proof.receipts.len() < PAIDK_K {
        return Err(DsmError::Verification(format!(
            "PaidK gate_proof has {} receipts, requires >= {PAIDK_K}",
            proof.receipts.len()
        )));
    }

    let mut distinct_operators: HashSet<[u8; 32]> = HashSet::new();
    for (i, r) in proof.receipts.iter().enumerate() {
        validate_receipt_shape(r, i)?;

        if r.device_id.as_slice() != device_id.as_slice() {
            return Err(DsmError::Verification(format!(
                "PaidK receipt #{i} device_id mismatch: receipt does not bind to activating device"
            )));
        }

        if r.amount < PAIDK_FLAT_RATE {
            return Err(DsmError::Verification(format!(
                "PaidK receipt #{i} amount {} below FLAT_RATE {PAIDK_FLAT_RATE}",
                r.amount
            )));
        }

        let mut op = [0u8; 32];
        op.copy_from_slice(&r.operator_node_id);
        if !distinct_operators.insert(op) {
            // Duplicate operator entries don't count separately, but we keep
            // walking — final count check below catches the shortfall.
        }
    }

    if distinct_operators.len() < PAIDK_K {
        return Err(DsmError::Verification(format!(
            "PaidK gate_proof has {} distinct operators, requires >= {PAIDK_K}",
            distinct_operators.len()
        )));
    }

    Ok(())
}

fn validate_receipt_shape(r: &StoragePaymentReceiptV3, index: usize) -> Result<(), DsmError> {
    if r.device_id.len() != 32 {
        return Err(DsmError::Verification(format!(
            "PaidK receipt #{index} device_id must be 32 bytes, got {}",
            r.device_id.len()
        )));
    }
    if r.operator_node_id.len() != 32 {
        return Err(DsmError::Verification(format!(
            "PaidK receipt #{index} operator_node_id must be 32 bytes, got {}",
            r.operator_node_id.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_receipt(device_id: [u8; 32], operator_id: u8, amount: u64) -> StoragePaymentReceiptV3 {
        StoragePaymentReceiptV3 {
            device_id: device_id.to_vec(),
            operator_node_id: vec![operator_id; 32],
            amount,
            receipt_digest: vec![0u8; 32],
        }
    }

    fn encode(proof: &PaidKGateProofV1) -> Vec<u8> {
        let mut buf = Vec::new();
        proof.encode(&mut buf).expect("encode PaidKGateProofV1");
        buf
    }

    #[test]
    fn accepts_k_distinct_operators_at_flat_rate() {
        let device = [0xABu8; 32];
        let proof = PaidKGateProofV1 {
            receipts: vec![
                mk_receipt(device, 1, PAIDK_FLAT_RATE),
                mk_receipt(device, 2, PAIDK_FLAT_RATE),
                mk_receipt(device, 3, PAIDK_FLAT_RATE + 50),
            ],
        };
        verify_paidk_gate_proof(&encode(&proof), &device).expect("valid proof must accept");
    }

    #[test]
    fn rejects_empty_bytes() {
        let device = [0xABu8; 32];
        let err = verify_paidk_gate_proof(&[], &device).expect_err("empty must reject");
        assert!(format!("{err}").contains("empty bytes"), "got: {err}");
    }

    #[test]
    fn rejects_fewer_than_k_receipts() {
        let device = [0xABu8; 32];
        let proof = PaidKGateProofV1 {
            receipts: vec![
                mk_receipt(device, 1, PAIDK_FLAT_RATE),
                mk_receipt(device, 2, PAIDK_FLAT_RATE),
            ],
        };
        let err = verify_paidk_gate_proof(&encode(&proof), &device)
            .expect_err("k-1 must reject");
        assert!(format!("{err}").contains("requires >="));
    }

    #[test]
    fn rejects_duplicate_operator() {
        let device = [0xABu8; 32];
        let proof = PaidKGateProofV1 {
            receipts: vec![
                mk_receipt(device, 1, PAIDK_FLAT_RATE),
                mk_receipt(device, 1, PAIDK_FLAT_RATE), // duplicate operator
                mk_receipt(device, 2, PAIDK_FLAT_RATE),
            ],
        };
        let err = verify_paidk_gate_proof(&encode(&proof), &device)
            .expect_err("duplicate operator must reject");
        assert!(format!("{err}").contains("distinct operators"));
    }

    #[test]
    fn rejects_below_flat_rate() {
        let device = [0xABu8; 32];
        let proof = PaidKGateProofV1 {
            receipts: vec![
                mk_receipt(device, 1, PAIDK_FLAT_RATE),
                mk_receipt(device, 2, PAIDK_FLAT_RATE - 1), // under flat rate
                mk_receipt(device, 3, PAIDK_FLAT_RATE),
            ],
        };
        let err = verify_paidk_gate_proof(&encode(&proof), &device)
            .expect_err("under flat-rate must reject");
        assert!(format!("{err}").contains("below FLAT_RATE"));
    }

    #[test]
    fn rejects_device_id_mismatch() {
        let device = [0xABu8; 32];
        let other = [0xCDu8; 32];
        let proof = PaidKGateProofV1 {
            receipts: vec![
                mk_receipt(other, 1, PAIDK_FLAT_RATE), // wrong device
                mk_receipt(device, 2, PAIDK_FLAT_RATE),
                mk_receipt(device, 3, PAIDK_FLAT_RATE),
            ],
        };
        let err = verify_paidk_gate_proof(&encode(&proof), &device)
            .expect_err("device_id mismatch must reject");
        assert!(format!("{err}").contains("device_id mismatch"));
    }

    #[test]
    fn rejects_malformed_proto_bytes() {
        let device = [0xABu8; 32];
        let err = verify_paidk_gate_proof(&[0xFF, 0xFF, 0xFF], &device)
            .expect_err("garbage bytes must reject");
        assert!(format!("{err}").contains("decode failed"));
    }
}
