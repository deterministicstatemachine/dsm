//! Deterministic commitment generation for state transitions.
//!
//! Produces canonical, domain-separated BLAKE3 commitments over operations
//! and state transition parameters. All commitments are deterministic: the
//! same inputs always produce the same 32-byte digest.

use crate::types::operations::Operation;

const OUT_LEN: usize = 32;

// Domain separation tags (versioned, null-terminated style)
const DOM_BASE: &[u8] = b"DSM/commit/base/v2\0";
const DOM_TIMELOCK: &[u8] = b"DSM/commit/timelock/v2\0";
const DOM_CONDITIONAL: &[u8] = b"DSM/commit/conditional/v2\0";
const DOM_RECURRING: &[u8] = b"DSM/commit/recurring/v2\0";

// Canonicalization bounds (defensive, deterministic)
const MAX_OP_BYTES_LEN: usize = 256 * 1024; // hard cap to avoid pathological allocations
const MAX_RECIPIENT_INFO_LEN: usize = 8 * 1024;
const MAX_TEXT_LEN: usize = 256;

/// Create a deterministic commitment for a token operation.
///
/// Deterministic encoding rules:
/// - Domain separation tag included
/// - Each field is length-prefixed to remove concatenation ambiguity
/// - `conditions` string is canonicalized (ASCII, trimmed, lowercase)
pub fn create_deterministic_commitment(
    current_state_hash: &[u8; 32],
    operation: &Operation,
    recipient_info: &[u8],
    conditions: Option<&str>,
) -> Vec<u8> {
    let op_bytes = operation.to_bytes();
    if !inputs_ok(current_state_hash, &op_bytes, recipient_info) {
        return Vec::new();
    }

    let cond = match conditions {
        Some(s) => match canonical_text(s) {
            Ok(v) => Some(v),
            Err(_) => return Vec::new(),
        },
        None => None,
    };

    hash_fields(
        DOM_BASE,
        current_state_hash,
        &op_bytes,
        recipient_info,
        cond.as_deref(),
        None,
    )
}

/// Create a deterministic commitment that unlocks at a deterministic *slot*.
///
/// NOTE: `unlock_time` is treated as a deterministic counter/slot, NOT wall time.
pub fn create_time_locked_commitment(
    current_state_hash: &[u8; 32],
    operation: &Operation,
    recipient_info: &[u8],
    unlock_time: u64,
) -> Vec<u8> {
    let op_bytes = operation.to_bytes();
    if !inputs_ok(current_state_hash, &op_bytes, recipient_info) {
        return Vec::new();
    }

    let mut extra = [0u8; 8];
    extra.copy_from_slice(&unlock_time.to_le_bytes());

    hash_fields(
        DOM_TIMELOCK,
        current_state_hash,
        &op_bytes,
        recipient_info,
        None,
        Some(&extra),
    )
}

/// Create a conditional deterministic commitment.
///
/// `condition` and `oracle_id` are canonicalized (ASCII, trimmed, lowercase).
pub fn create_conditional_commitment(
    current_state_hash: &[u8; 32],
    operation: &Operation,
    recipient_info: &[u8],
    condition: &str,
    oracle_id: &str,
) -> Vec<u8> {
    let op_bytes = operation.to_bytes();
    if !inputs_ok(current_state_hash, &op_bytes, recipient_info) {
        return Vec::new();
    }

    let cond = match canonical_text(condition) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let oracle = match canonical_text(oracle_id) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    // Encode condition + oracle as a single canonical text payload with explicit separators.
    // This is deterministic and avoids ambiguity.
    let combined = format!("cond={};oracle={}", cond, oracle);

    hash_fields(
        DOM_CONDITIONAL,
        current_state_hash,
        &op_bytes,
        recipient_info,
        Some(&combined),
        None,
    )
}

/// Create a recurring payment deterministic commitment.
///
/// NOTE:
/// - `period_seconds` is treated as a deterministic period *slot size*, NOT seconds.
/// - `end_date` is treated as a deterministic end *slot*, NOT a date.
pub fn create_recurring_commitment(
    current_state_hash: &[u8; 32],
    operation: &Operation,
    recipient_info: &[u8],
    period_seconds: u64,
    end_date: u64,
) -> Vec<u8> {
    let op_bytes = operation.to_bytes();
    if !inputs_ok(current_state_hash, &op_bytes, recipient_info) {
        return Vec::new();
    }

    let mut extra = [0u8; 16];
    extra[0..8].copy_from_slice(&period_seconds.to_le_bytes());
    extra[8..16].copy_from_slice(&end_date.to_le_bytes());

    hash_fields(
        DOM_RECURRING,
        current_state_hash,
        &op_bytes,
        recipient_info,
        None,
        Some(&extra),
    )
}

/// Verify a deterministic commitment (base variant).
pub fn verify_deterministic_commitment(
    commitment: &[u8],
    current_state_hash: &[u8; 32],
    operation: &Operation,
    recipient_info: &[u8],
    conditions: Option<&str>,
) -> bool {
    if commitment.len() != OUT_LEN {
        return false;
    }
    let calculated =
        create_deterministic_commitment(current_state_hash, operation, recipient_info, conditions);
    calculated.as_slice() == commitment
}

// ---------- Internal helpers (deterministic, canonical) ----------

fn inputs_ok(_current_state_hash: &[u8; 32], op_bytes: &[u8], recipient_info: &[u8]) -> bool {
    // current_state_hash is fixed size [u8; 32], so no length check needed.
    // We could check for zero hash if that's invalid, but for now we just check other inputs.
    if op_bytes.is_empty() || op_bytes.len() > MAX_OP_BYTES_LEN {
        return false;
    }
    if recipient_info.is_empty() || recipient_info.len() > MAX_RECIPIENT_INFO_LEN {
        return false;
    }
    true
}

/// Canonical text:
/// - trim
/// - ASCII only
/// - lowercase
/// - bounded length
fn canonical_text(s: &str) -> Result<String, ()> {
    let t = s.trim();
    if t.is_empty() || t.len() > MAX_TEXT_LEN {
        return Err(());
    }
    if !t.is_ascii() {
        return Err(());
    }
    Ok(t.to_ascii_lowercase())
}

fn hash_fields(
    domain: &[u8],
    current_state_hash: &[u8],
    op_bytes: &[u8],
    recipient_info: &[u8],
    opt_text: Option<&str>,
    opt_extra: Option<&[u8]>,
) -> Vec<u8> {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/commitment-fields");
    hasher.update(domain);

    // field 1: state hash (length-prefixed)
    crate::crypto::canonical_lp::write_lp(&mut hasher, current_state_hash);

    // field 2: operation bytes (length-prefixed)
    crate::crypto::canonical_lp::write_lp(&mut hasher, op_bytes);

    // field 3: recipient info (length-prefixed)
    crate::crypto::canonical_lp::write_lp(&mut hasher, recipient_info);

    // field 4: optional text (length-prefixed; empty if absent)
    if let Some(s) = opt_text {
        let bytes = s.as_bytes();
        crate::crypto::canonical_lp::write_lp(&mut hasher, bytes);
    } else {
        crate::crypto::canonical_lp::write_lp(&mut hasher, &[]);
    }

    // field 5: optional extra bytes (length-prefixed; empty if absent)
    if let Some(e) = opt_extra {
        crate::crypto::canonical_lp::write_lp(&mut hasher, e);
    } else {
        crate::crypto::canonical_lp::write_lp(&mut hasher, &[]);
    }

    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::types::{operations::PreCommitmentOp, token_types::Balance};

    #[derive(Default, Clone)]
    struct TestPreCommitment {}

    impl From<TestPreCommitment> for PreCommitmentOp {
        fn from(_: TestPreCommitment) -> Self {
            PreCommitmentOp::default()
        }
    }

    fn mk_transfer(amount: u64) -> Operation {
        use crate::types::operations::TransactionMode;
        let mut balance = Balance::zero();
        balance.update_add(amount);

        let (_pk, sk) = generate_sphincs_keypair().expect("keypair");

        let mut op = Operation::Transfer {
            to_device_id: b"recipient123".to_vec(),
            verification: crate::types::operations::VerificationType::Standard,
            token_id: b"token123".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: Some(PreCommitmentOp::from(TestPreCommitment::default())),
            recipient: b"recipient123".to_vec(),
            to: b"recipient123".to_vec(),
            message: String::from("Test message"),
            amount: balance,
            signature: Vec::new(),
        };

        let sig = sphincs_sign(&sk, &op.to_bytes()).expect("sign transfer");
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig;
        }

        op
    }

    #[test]
    fn test_create_deterministic_commitment() {
        let current_state_hash = [1u8; 32];
        let recipient_info = b"recipient_public_key";
        let conditions = Some("Payment For Services"); // will be canonicalized

        let operation = mk_transfer(100);

        let commitment = create_deterministic_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        );

        assert_eq!(commitment.len(), 32);

        let commitment2 = create_deterministic_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        );
        assert_eq!(commitment, commitment2);

        let different_operation = mk_transfer(200);

        let different_commitment = create_deterministic_commitment(
            &current_state_hash,
            &different_operation,
            recipient_info,
            conditions,
        );

        assert_ne!(commitment, different_commitment);
    }

    #[test]
    fn test_verify_deterministic_commitment() {
        let current_state_hash = [1u8; 32];
        let recipient_info = b"recipient_public_key";
        let operation = mk_transfer(100);
        let conditions = Some("payment for services");

        let commitment = create_deterministic_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        );

        assert!(verify_deterministic_commitment(
            &commitment,
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        ));

        let different_operation = mk_transfer(200);

        assert!(!verify_deterministic_commitment(
            &commitment,
            &current_state_hash,
            &different_operation,
            recipient_info,
            conditions,
        ));
    }

    #[test]
    fn test_time_locked_commitment_is_slot_based() {
        let current_state_hash = [1u8; 32];
        let recipient_info = b"recipient_public_key";
        let unlock_slot = 42u64; // deterministic counter/slot

        let operation = mk_transfer(100);

        let commitment = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_slot,
        );

        let commitment2 = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_slot,
        );
        assert_eq!(commitment, commitment2);

        let different_commitment = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_slot + 1,
        );
        assert_ne!(commitment, different_commitment);
    }

    #[test]
    fn test_conditional_commitment() {
        let current_state_hash = [1u8; 32];
        let recipient_info = b"recipient_public_key";
        let condition = "btc_price_gt_50000";
        let oracle_id = "crypto_price_oracle";

        let operation = mk_transfer(100);

        let commitment = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            condition,
            oracle_id,
        );

        let commitment2 = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            condition,
            oracle_id,
        );
        assert_eq!(commitment, commitment2);

        let different_commitment = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            "btc_price_gt_60000",
            oracle_id,
        );
        assert_ne!(commitment, different_commitment);
    }

    #[test]
    fn test_recurring_commitment_is_slot_based() {
        let current_state_hash = [1u8; 32];
        let recipient_info = b"recipient_public_key";
        let period_slot = 7u64; // deterministic period size in slots
        let end_slot = 100u64; // deterministic end slot

        let operation = mk_transfer(100);

        let commitment = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            period_slot,
            end_slot,
        );

        let commitment2 = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            period_slot,
            end_slot,
        );
        assert_eq!(commitment, commitment2);

        let different_commitment = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            period_slot + 1,
            end_slot,
        );
        assert_ne!(commitment, different_commitment);
    }
}
