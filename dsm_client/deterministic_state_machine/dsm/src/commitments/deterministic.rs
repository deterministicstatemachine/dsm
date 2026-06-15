// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic commitment generation for state transitions.
//!
//! Produces canonical, domain-separated BLAKE3 commitments over operations
//! and state transition parameters. All commitments are deterministic: the
//! same inputs always produce the same 32-byte digest.
//!
//! Issue #180.D fix: all `create_*_commitment` constructors now return
//! `Result<Vec<u8>, DsmError>` instead of silently emitting `Vec::new()` on
//! invalid input. Empty-vector fail-silent behavior hid input-validation
//! errors and let callers downstream treat a sentinel as a real digest.

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::common::domain_tags::TAG_COMMITMENT_FIELDS;

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
) -> Result<Vec<u8>, DsmError> {
    let op_bytes = operation.to_bytes();
    validate_inputs(&op_bytes, recipient_info)?;

    let cond = match conditions {
        Some(s) => Some(canonical_text(s)?),
        None => None,
    };

    Ok(hash_fields(
        DOM_BASE,
        current_state_hash,
        &op_bytes,
        recipient_info,
        cond.as_deref(),
        None,
    ))
}

/// Create a deterministic commitment that unlocks at a deterministic *slot*.
///
/// NOTE: `unlock_time` is treated as a deterministic counter/slot, NOT wall time.
pub fn create_time_locked_commitment(
    current_state_hash: &[u8; 32],
    operation: &Operation,
    recipient_info: &[u8],
    unlock_time: u64,
) -> Result<Vec<u8>, DsmError> {
    let op_bytes = operation.to_bytes();
    validate_inputs(&op_bytes, recipient_info)?;

    let mut extra = [0u8; 8];
    extra.copy_from_slice(&unlock_time.to_le_bytes());

    Ok(hash_fields(
        DOM_TIMELOCK,
        current_state_hash,
        &op_bytes,
        recipient_info,
        None,
        Some(&extra),
    ))
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
) -> Result<Vec<u8>, DsmError> {
    let op_bytes = operation.to_bytes();
    validate_inputs(&op_bytes, recipient_info)?;

    let cond = canonical_text(condition)?;
    let oracle = canonical_text(oracle_id)?;

    // Encode condition + oracle as a single canonical text payload with explicit separators.
    // This is deterministic and avoids ambiguity.
    let combined = format!("cond={};oracle={}", cond, oracle);

    Ok(hash_fields(
        DOM_CONDITIONAL,
        current_state_hash,
        &op_bytes,
        recipient_info,
        Some(&combined),
        None,
    ))
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
) -> Result<Vec<u8>, DsmError> {
    let op_bytes = operation.to_bytes();
    validate_inputs(&op_bytes, recipient_info)?;

    let mut extra = [0u8; 16];
    extra[0..8].copy_from_slice(&period_seconds.to_le_bytes());
    extra[8..16].copy_from_slice(&end_date.to_le_bytes());

    Ok(hash_fields(
        DOM_RECURRING,
        current_state_hash,
        &op_bytes,
        recipient_info,
        None,
        Some(&extra),
    ))
}

/// Verify a deterministic commitment (base variant).
///
/// Returns `false` on length mismatch, mismatched digest, or invalid input
/// to the underlying constructor (the constructor's `DsmError` is consumed
/// because at the verify boundary any invalid input is just a non-match).
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
    match create_deterministic_commitment(current_state_hash, operation, recipient_info, conditions)
    {
        Ok(calculated) => calculated.as_slice() == commitment,
        Err(_) => false,
    }
}

// ---------- Internal helpers (deterministic, canonical) ----------

fn validate_inputs(op_bytes: &[u8], recipient_info: &[u8]) -> Result<(), DsmError> {
    if op_bytes.is_empty() {
        return Err(DsmError::invalid_operation(
            "deterministic commitment: operation bytes empty",
        ));
    }
    if op_bytes.len() > MAX_OP_BYTES_LEN {
        return Err(DsmError::invalid_operation(format!(
            "deterministic commitment: operation bytes {} exceed cap {MAX_OP_BYTES_LEN}",
            op_bytes.len()
        )));
    }
    if recipient_info.is_empty() {
        return Err(DsmError::invalid_operation(
            "deterministic commitment: recipient_info empty",
        ));
    }
    if recipient_info.len() > MAX_RECIPIENT_INFO_LEN {
        return Err(DsmError::invalid_operation(format!(
            "deterministic commitment: recipient_info {} exceeds cap {MAX_RECIPIENT_INFO_LEN}",
            recipient_info.len()
        )));
    }
    Ok(())
}

/// Canonical text:
/// - trim
/// - ASCII only
/// - lowercase
/// - bounded length
fn canonical_text(s: &str) -> Result<String, DsmError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(DsmError::invalid_operation(
            "deterministic commitment: text field empty after trim",
        ));
    }
    if t.len() > MAX_TEXT_LEN {
        return Err(DsmError::invalid_operation(format!(
            "deterministic commitment: text length {} exceeds cap {MAX_TEXT_LEN}",
            t.len()
        )));
    }
    if !t.is_ascii() {
        return Err(DsmError::invalid_operation(
            "deterministic commitment: text contains non-ASCII characters",
        ));
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
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher(TAG_COMMITMENT_FIELDS);
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
            policy_commit: [0u8; 32],
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
            authority_policy: None,
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
        )
        .expect("commitment must construct");

        assert_eq!(commitment.len(), 32);

        let commitment2 = create_deterministic_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        )
        .expect("commitment must construct");
        assert_eq!(commitment, commitment2);

        let different_operation = mk_transfer(200);

        let different_commitment = create_deterministic_commitment(
            &current_state_hash,
            &different_operation,
            recipient_info,
            conditions,
        )
        .expect("commitment must construct");

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
        )
        .expect("commitment must construct");

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
        )
        .expect("time-locked commitment must construct");

        let commitment2 = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_slot,
        )
        .expect("time-locked commitment must construct");
        assert_eq!(commitment, commitment2);

        let different_commitment = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_slot + 1,
        )
        .expect("time-locked commitment must construct");
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
        )
        .expect("conditional commitment must construct");

        let commitment2 = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            condition,
            oracle_id,
        )
        .expect("conditional commitment must construct");
        assert_eq!(commitment, commitment2);

        let different_commitment = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            "btc_price_gt_60000",
            oracle_id,
        )
        .expect("conditional commitment must construct");
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
        )
        .expect("recurring commitment must construct");

        let commitment2 = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            period_slot,
            end_slot,
        )
        .expect("recurring commitment must construct");
        assert_eq!(commitment, commitment2);

        let different_commitment = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            period_slot + 1,
            end_slot,
        )
        .expect("recurring commitment must construct");
        assert_ne!(commitment, different_commitment);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Issue #180.D regression — invalid inputs must produce a typed error,
    // never the fail-silent Vec::new() sentinel.
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn constructors_reject_empty_recipient_info() {
        let h = [1u8; 32];
        let op = mk_transfer(100);
        assert!(create_deterministic_commitment(&h, &op, &[], None).is_err());
        assert!(create_time_locked_commitment(&h, &op, &[], 1).is_err());
        assert!(create_conditional_commitment(&h, &op, &[], "x", "y").is_err());
        assert!(create_recurring_commitment(&h, &op, &[], 1, 2).is_err());
    }

    #[test]
    fn constructors_reject_oversized_recipient_info() {
        let h = [1u8; 32];
        let op = mk_transfer(100);
        let big = vec![0u8; MAX_RECIPIENT_INFO_LEN + 1];
        assert!(create_deterministic_commitment(&h, &op, &big, None).is_err());
        assert!(create_time_locked_commitment(&h, &op, &big, 1).is_err());
        assert!(create_conditional_commitment(&h, &op, &big, "x", "y").is_err());
        assert!(create_recurring_commitment(&h, &op, &big, 1, 2).is_err());
    }

    #[test]
    fn conditional_rejects_non_ascii_text_fields() {
        let h = [1u8; 32];
        let op = mk_transfer(100);
        let r = b"recipient";
        // Non-ASCII condition.
        assert!(create_conditional_commitment(&h, &op, r, "café", "oracle").is_err());
        // Non-ASCII oracle id.
        assert!(create_conditional_commitment(&h, &op, r, "ok", "oráculo").is_err());
    }

    #[test]
    fn deterministic_rejects_empty_conditions_string() {
        let h = [1u8; 32];
        let op = mk_transfer(100);
        let r = b"recipient";
        // Empty-after-trim is rejected by canonical_text.
        assert!(create_deterministic_commitment(&h, &op, r, Some("   ")).is_err());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Issue #179 regression — strengthen deterministic commitment tests.
    // Each test below builds the expected digest via a raw `blake3::Hasher`
    // walk so the verifier and the expected value do not share construction
    // code. If `hash_fields` drifts (domain tag, framing, length-prefix
    // format), these tests fail.
    // ────────────────────────────────────────────────────────────────────────

    /// Independent length-prefix writer matching `canonical_lp::write_lp`:
    /// `u32 LE length || bytes`.
    fn write_lp_raw(h: &mut blake3::Hasher, bytes: &[u8]) {
        let len: u32 = bytes.len().try_into().unwrap_or(u32::MAX);
        h.update(&len.to_le_bytes());
        h.update(bytes);
    }

    /// Independent BLAKE3 evaluation of `hash_fields(domain, ...)`.
    /// Does NOT call into `crate::crypto::blake3` or `canonical_lp`.
    fn independent_hash_fields(
        domain_v2: &[u8],
        state_hash: &[u8],
        op_bytes: &[u8],
        recipient_info: &[u8],
        opt_text: Option<&str>,
        opt_extra: Option<&[u8]>,
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        // dsm_domain_hasher("DSM/commitment-fields") = BLAKE3 state primed with
        // the tag + NUL terminator.
        h.update(b"DSM/commitment-fields");
        h.update(&[0u8]);
        h.update(domain_v2);
        write_lp_raw(&mut h, state_hash);
        write_lp_raw(&mut h, op_bytes);
        write_lp_raw(&mut h, recipient_info);
        match opt_text {
            Some(s) => write_lp_raw(&mut h, s.as_bytes()),
            None => write_lp_raw(&mut h, &[]),
        }
        match opt_extra {
            Some(e) => write_lp_raw(&mut h, e),
            None => write_lp_raw(&mut h, &[]),
        }
        *h.finalize().as_bytes()
    }

    #[test]
    fn deterministic_commitment_matches_independent_construction() {
        let state_hash = [0x11u8; 32];
        let op = mk_transfer(100);
        let recipient = b"recipient-bytes";

        // No conditions.
        let from_api = create_deterministic_commitment(&state_hash, &op, recipient, None)
            .expect("commitment must construct");
        let expected = independent_hash_fields(
            b"DSM/commit/base/v2\0",
            &state_hash,
            &op.to_bytes(),
            recipient,
            None,
            None,
        );
        assert_eq!(
            from_api.as_slice(),
            expected.as_slice(),
            "deterministic commitment must equal independent BLAKE3 walk"
        );

        // With canonicalized conditions text.
        let from_api_cond = create_deterministic_commitment(
            &state_hash,
            &op,
            recipient,
            Some("Payment For Services"),
        )
        .expect("commitment must construct");
        let canonical_cond = "payment for services"; // trim + ASCII-lowercase
        let expected_cond = independent_hash_fields(
            b"DSM/commit/base/v2\0",
            &state_hash,
            &op.to_bytes(),
            recipient,
            Some(canonical_cond),
            None,
        );
        assert_eq!(
            from_api_cond.as_slice(),
            expected_cond.as_slice(),
            "deterministic commitment with conditions must equal independent walk"
        );
    }

    #[test]
    fn time_locked_commitment_matches_independent_construction() {
        let state_hash = [0x22u8; 32];
        let op = mk_transfer(100);
        let recipient = b"r";
        let unlock_slot = 0xDEAD_BEEFu64;

        let from_api = create_time_locked_commitment(&state_hash, &op, recipient, unlock_slot)
            .expect("commitment");
        let mut extra = [0u8; 8];
        extra.copy_from_slice(&unlock_slot.to_le_bytes());
        let expected = independent_hash_fields(
            b"DSM/commit/timelock/v2\0",
            &state_hash,
            &op.to_bytes(),
            recipient,
            None,
            Some(&extra),
        );
        assert_eq!(from_api.as_slice(), expected.as_slice());
    }

    #[test]
    fn conditional_commitment_matches_independent_construction() {
        let state_hash = [0x33u8; 32];
        let op = mk_transfer(100);
        let recipient = b"r";
        // Force canonicalization through trim + lowercase.
        let cond = "  BTC_Price_GT_50000  ";
        let oracle = "  Crypto_Price_Oracle  ";
        let from_api = create_conditional_commitment(&state_hash, &op, recipient, cond, oracle)
            .expect("commitment");

        let combined = format!(
            "cond={};oracle={}",
            "btc_price_gt_50000", "crypto_price_oracle"
        );
        let expected = independent_hash_fields(
            b"DSM/commit/conditional/v2\0",
            &state_hash,
            &op.to_bytes(),
            recipient,
            Some(&combined),
            None,
        );
        assert_eq!(
            from_api.as_slice(),
            expected.as_slice(),
            "canonicalized condition + oracle must reproduce the digest independently"
        );
    }

    #[test]
    fn recurring_commitment_matches_independent_construction() {
        let state_hash = [0x44u8; 32];
        let op = mk_transfer(100);
        let recipient = b"r";
        let period: u64 = 17;
        let end: u64 = 999;

        let from_api = create_recurring_commitment(&state_hash, &op, recipient, period, end)
            .expect("commitment");
        let mut extra = [0u8; 16];
        extra[0..8].copy_from_slice(&period.to_le_bytes());
        extra[8..16].copy_from_slice(&end.to_le_bytes());
        let expected = independent_hash_fields(
            b"DSM/commit/recurring/v2\0",
            &state_hash,
            &op.to_bytes(),
            recipient,
            None,
            Some(&extra),
        );
        assert_eq!(from_api.as_slice(), expected.as_slice());
    }

    #[test]
    fn deterministic_commitment_canonicalization_is_case_and_whitespace_invariant() {
        // The canonical_text helper trims and ASCII-lowercases. Inputs that
        // differ only in case or leading/trailing whitespace must produce
        // identical digests.
        let state_hash = [0x55u8; 32];
        let op = mk_transfer(100);
        let recipient = b"r";

        let a =
            create_deterministic_commitment(&state_hash, &op, recipient, Some("hello")).expect("a");
        let b =
            create_deterministic_commitment(&state_hash, &op, recipient, Some("HELLO")).expect("b");
        let c = create_deterministic_commitment(&state_hash, &op, recipient, Some("  HeLLo   "))
            .expect("c");
        assert_eq!(a, b, "case must be canonicalized");
        assert_eq!(a, c, "whitespace must be canonicalized");

        // Verify the canonical form is independent-recomputable.
        let independent = independent_hash_fields(
            b"DSM/commit/base/v2\0",
            &state_hash,
            &op.to_bytes(),
            recipient,
            Some("hello"),
            None,
        );
        assert_eq!(a.as_slice(), independent.as_slice());
    }

    #[test]
    fn deterministic_commitment_each_field_independently_affects_digest() {
        // For every input field, mutate it minimally and assert the digest
        // changes. Catches accidental field-omission bugs in `hash_fields`.
        let state_hash = [0x66u8; 32];
        let op = mk_transfer(100);
        let recipient = b"r";
        let baseline = create_deterministic_commitment(&state_hash, &op, recipient, Some("cond"))
            .expect("baseline");

        // Mutate state_hash.
        let mut sh = state_hash;
        sh[0] ^= 0x01;
        let mutated = create_deterministic_commitment(&sh, &op, recipient, Some("cond"))
            .expect("mutated state_hash");
        assert_ne!(baseline, mutated, "state_hash must affect digest");

        // Mutate operation (different amount).
        let op2 = mk_transfer(101);
        let mutated = create_deterministic_commitment(&state_hash, &op2, recipient, Some("cond"))
            .expect("mutated op");
        assert_ne!(baseline, mutated, "operation must affect digest");

        // Mutate recipient_info.
        let mutated =
            create_deterministic_commitment(&state_hash, &op, b"different-recipient", Some("cond"))
                .expect("mutated recipient");
        assert_ne!(baseline, mutated, "recipient_info must affect digest");

        // Mutate condition.
        let mutated = create_deterministic_commitment(&state_hash, &op, recipient, Some("cond2"))
            .expect("mutated cond");
        assert_ne!(baseline, mutated, "conditions must affect digest");

        // None vs Some — must differ.
        let no_cond =
            create_deterministic_commitment(&state_hash, &op, recipient, None).expect("no cond");
        assert_ne!(
            baseline, no_cond,
            "presence of conditions must affect digest"
        );
    }

    #[test]
    fn time_locked_commitment_domain_tag_differs_from_base_and_recurring() {
        // Two commitments built over identical fields but with different
        // domain tags must produce different digests. Catches a class of
        // refactor bugs where DOM_BASE / DOM_TIMELOCK / DOM_RECURRING are
        // swapped.
        let state_hash = [0x77u8; 32];
        let op = mk_transfer(100);
        let recipient = b"r";

        let base =
            create_deterministic_commitment(&state_hash, &op, recipient, None).expect("base");
        let timelock =
            create_time_locked_commitment(&state_hash, &op, recipient, 0).expect("timelock");
        let recurring =
            create_recurring_commitment(&state_hash, &op, recipient, 0, 0).expect("recurring");

        assert_ne!(base, timelock, "base != timelock");
        assert_ne!(base, recurring, "base != recurring");
        assert_ne!(timelock, recurring, "timelock != recurring");
    }

    #[test]
    fn verify_deterministic_commitment_rejects_single_byte_corruption() {
        let state_hash = [0x88u8; 32];
        let op = mk_transfer(100);
        let recipient = b"r";
        let cond = Some("payment");
        let commitment =
            create_deterministic_commitment(&state_hash, &op, recipient, cond).expect("c");
        assert_eq!(commitment.len(), OUT_LEN);

        for byte_idx in 0..commitment.len() {
            for bit in 0..8u8 {
                let mut corrupted = commitment.clone();
                corrupted[byte_idx] ^= 1 << bit;
                assert!(
                    !verify_deterministic_commitment(&corrupted, &state_hash, &op, recipient, cond,),
                    "verify must reject corruption at byte {byte_idx} bit {bit}"
                );
            }
        }
    }
}
