//! Bitcoin HTLC script construction for DSM vaults.
//!
//! Builds dual-hashlock HTLC scripts per the dBTC spec (main.tex, Definition 7.1):
//!
//! Two spend paths:
//!   (a) **Fulfill** — holder reveals preimage of h_f (derived from Burn proof sigma)
//!   (b) **Refund**  — depositor reveals preimage of h_r (derived from budget-exhaustion proof pi_beta)
//!
//! The DSM determines which path resolves the vault; Bitcoin merely checks which preimage
//! is presented. No clock synchronization is required between DSM and Bitcoin.

use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::Address;

use crate::types::error::DsmError;

use super::types::BitcoinNetwork;

/// Helper to push a variable-length pubkey slice into a script Builder.
/// bitcoin 0.32 requires `AsRef<PushBytes>` which is only impl'd for fixed arrays.
fn push_pubkey(builder: Builder, pubkey: &[u8]) -> Result<Builder, DsmError> {
    match <&[u8; 33]>::try_from(pubkey) {
        Ok(arr) => Ok(builder.push_slice(arr)),
        Err(_) => match <&[u8; 65]>::try_from(pubkey) {
            Ok(arr) => Ok(builder.push_slice(arr)),
            Err(_) => Err(DsmError::invalid_operation(format!(
                "Invalid pubkey length for script push: {}",
                pubkey.len()
            ))),
        },
    }
}

/// Build a dual-hashlock HTLC script for DSM vault settlement.
///
/// Per main.tex Definition 7.1, the script has two spend paths:
///
/// ```text
/// OP_IF
///   // Path (a): Fulfill — current holder reveals sk_V preimage
///   OP_SHA256 <fulfill_hash> OP_EQUALVERIFY
///   <claimer_pubkey> OP_CHECKSIG
/// OP_ELSE
///   // Path (b): Refund — depositor reveals rk_V preimage (iteration budget exhausted)
///   OP_SHA256 <refund_hash> OP_EQUALVERIFY
///   <refund_pubkey> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// # Parameters
/// - `fulfill_hash`: SHA256 hash of the fulfill preimage h_f (= SHA256(sk_V))
/// - `refund_hash`: SHA256 hash of the refund preimage h_r (= SHA256(rk_V))
/// - `claimer_pubkey`: Public key of the party who can claim via Burn proof
/// - `refund_pubkey`: Public key of the original depositor (refund path)
pub fn build_htlc_script(
    fulfill_hash: &[u8; 32],
    refund_hash: &[u8; 32],
    claimer_pubkey: &[u8],
    refund_pubkey: &[u8],
) -> Result<Vec<u8>, DsmError> {
    if claimer_pubkey.len() != 33 && claimer_pubkey.len() != 65 {
        return Err(DsmError::invalid_operation(format!(
            "Invalid claimer pubkey length: {} (expected 33 or 65)",
            claimer_pubkey.len()
        )));
    }
    if refund_pubkey.len() != 33 && refund_pubkey.len() != 65 {
        return Err(DsmError::invalid_operation(format!(
            "Invalid refund pubkey length: {} (expected 33 or 65)",
            refund_pubkey.len()
        )));
    }

    let builder = Builder::new()
        .push_opcode(opcodes::OP_IF)
        .push_opcode(opcodes::OP_SHA256)
        .push_slice(fulfill_hash)
        .push_opcode(opcodes::OP_EQUALVERIFY);
    let builder = push_pubkey(builder, claimer_pubkey)?;
    let builder = builder
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_ELSE)
        .push_opcode(opcodes::OP_SHA256)
        .push_slice(refund_hash)
        .push_opcode(opcodes::OP_EQUALVERIFY);
    let builder = push_pubkey(builder, refund_pubkey)?;
    let script = builder
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_ENDIF)
        .into_script();

    Ok(script.to_bytes())
}

/// Compute the P2WSH address for an HTLC script.
///
/// Returns the bech32-encoded SegWit address (bc1q... for mainnet).
pub fn htlc_p2wsh_address(htlc_script: &[u8], network: BitcoinNetwork) -> Result<String, DsmError> {
    let script_buf = ScriptBuf::from(htlc_script.to_vec());
    let address = Address::p2wsh(&script_buf, network.to_bitcoin_network());
    Ok(address.to_string())
}

/// Verify that a script matches the expected dual-hashlock HTLC structure.
///
/// Validates the complete script template against the canonical 2-path HTLC pattern
/// produced by `build_htlc_script`, including verification of both hash locks,
/// pubkeys, and all opcodes.
pub fn verify_htlc_script(
    script_bytes: &[u8],
    expected_fulfill_hash: &[u8; 32],
    expected_refund_hash: &[u8; 32],
    expected_claimer_pubkey: &[u8],
    expected_refund_pubkey: &[u8],
) -> bool {
    // Dual-hashlock 2-path layout:
    //   OP_IF (0x63)
    //     OP_SHA256 (0xa8) PUSH32 <fulfill_hash> OP_EQUALVERIFY (0x88)
    //     PUSH_PK <claimer_pk> OP_CHECKSIG (0xac)
    //   OP_ELSE (0x67)
    //     OP_SHA256 (0xa8) PUSH32 <refund_hash> OP_EQUALVERIFY (0x88)
    //     PUSH_PK <refund_pk> OP_CHECKSIG (0xac)
    //   OP_ENDIF (0x68)

    let s = script_bytes;
    let claimer_pk_len = expected_claimer_pubkey.len();
    let refund_pk_len = expected_refund_pubkey.len();

    if (claimer_pk_len != 33 && claimer_pk_len != 65)
        || (refund_pk_len != 33 && refund_pk_len != 65)
    {
        return false;
    }

    let mut pos = 0;

    if !check_opcode(s, &mut pos, 0x63) {
        return false;
    }
    if !check_opcode(s, &mut pos, 0xa8) {
        return false;
    }
    if !check_push32(s, &mut pos, expected_fulfill_hash) {
        return false;
    }
    if !check_opcode(s, &mut pos, 0x88) {
        return false;
    }
    if !check_pubkey(s, &mut pos, expected_claimer_pubkey) {
        return false;
    }
    if !check_opcode(s, &mut pos, 0xac) {
        return false;
    }

    if !check_opcode(s, &mut pos, 0x67) {
        return false;
    }
    if !check_opcode(s, &mut pos, 0xa8) {
        return false;
    }
    if !check_push32(s, &mut pos, expected_refund_hash) {
        return false;
    }
    if !check_opcode(s, &mut pos, 0x88) {
        return false;
    }
    if !check_pubkey(s, &mut pos, expected_refund_pubkey) {
        return false;
    }
    if !check_opcode(s, &mut pos, 0xac) {
        return false;
    }
    if !check_opcode(s, &mut pos, 0x68) {
        return false;
    }

    pos == s.len()
}

// ── Verification helpers ────────────────────────────────────────────────────

/// Check a single opcode at position, advance pos.
fn check_opcode(s: &[u8], pos: &mut usize, expected: u8) -> bool {
    if *pos >= s.len() || s[*pos] != expected {
        return false;
    }
    *pos += 1;
    true
}

/// Check a PUSH32 (0x20) followed by 32 bytes matching `expected`.
fn check_push32(s: &[u8], pos: &mut usize, expected: &[u8; 32]) -> bool {
    if *pos >= s.len() || s[*pos] != 0x20 {
        return false;
    }
    *pos += 1;
    if *pos + 32 > s.len() {
        return false;
    }
    if &s[*pos..*pos + 32] != expected {
        return false;
    }
    *pos += 32;
    true
}

/// Check a pubkey push (0x21 for 33 bytes, 0x41 for 65 bytes) and match content.
fn check_pubkey(s: &[u8], pos: &mut usize, expected_pk: &[u8]) -> bool {
    let pk_len = expected_pk.len();
    let push_op = if pk_len == 33 { 0x21u8 } else { 0x41u8 };
    if *pos >= s.len() || s[*pos] != push_op {
        return false;
    }
    *pos += 1;
    if *pos + pk_len > s.len() {
        return false;
    }
    if &s[*pos..*pos + pk_len] != expected_pk {
        return false;
    }
    *pos += pk_len;
    true
}

/// Compute SHA256 of a preimage (for creating hash locks compatible with Bitcoin OP_SHA256)
pub fn sha256_hash_lock(preimage: &[u8]) -> [u8; 32] {
    let hash = sha256::Hash::hash(preimage);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_byte_array());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dual_hashlock_htlc_valid() {
        let fulfill_hash = [0x42; 32];
        let refund_hash = [0x43; 32];
        let claimer_pk = [0x02; 33];
        let refund_pk = [0x03; 33];

        let script = build_htlc_script(&fulfill_hash, &refund_hash, &claimer_pk, &refund_pk)
            .expect("build should succeed");
        assert!(!script.is_empty());

        assert!(verify_htlc_script(
            &script,
            &fulfill_hash,
            &refund_hash,
            &claimer_pk,
            &refund_pk,
        ));
    }

    #[test]
    fn build_htlc_rejects_bad_pubkey() {
        let fulfill_hash = [0x42; 32];
        let refund_hash = [0x43; 32];
        let bad_pk = [0x02; 10];
        let good_pk = [0x03; 33];

        assert!(build_htlc_script(&fulfill_hash, &refund_hash, &bad_pk, &good_pk).is_err());
        assert!(build_htlc_script(&fulfill_hash, &refund_hash, &good_pk, &bad_pk).is_err());
    }

    #[test]
    fn sha256_hash_lock_deterministic() {
        let preimage = b"atomic swap secret";
        let h1 = sha256_hash_lock(preimage);
        let h2 = sha256_hash_lock(preimage);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn verify_htlc_rejects_wrong_fulfill_hash() {
        let fulfill_hash = [0x42; 32];
        let refund_hash = [0x43; 32];
        let wrong_hash = [0x44; 32];
        let claimer_pk = [0x02; 33];
        let refund_pk = [0x03; 33];

        let script =
            build_htlc_script(&fulfill_hash, &refund_hash, &claimer_pk, &refund_pk).expect("ok");
        assert!(!verify_htlc_script(
            &script,
            &wrong_hash,
            &refund_hash,
            &claimer_pk,
            &refund_pk
        ));
    }

    #[test]
    fn verify_htlc_rejects_wrong_refund_hash() {
        let fulfill_hash = [0x42; 32];
        let refund_hash = [0x43; 32];
        let wrong_hash = [0x44; 32];
        let claimer_pk = [0x02; 33];
        let refund_pk = [0x03; 33];

        let script =
            build_htlc_script(&fulfill_hash, &refund_hash, &claimer_pk, &refund_pk).expect("ok");
        assert!(!verify_htlc_script(
            &script,
            &fulfill_hash,
            &wrong_hash,
            &claimer_pk,
            &refund_pk
        ));
    }

    #[test]
    fn verify_htlc_rejects_wrong_claimer_pubkey() {
        let fulfill_hash = [0x42; 32];
        let refund_hash = [0x43; 32];
        let claimer_pk = [0x02; 33];
        let refund_pk = [0x03; 33];
        let wrong_pk = [0x04; 33];

        let script =
            build_htlc_script(&fulfill_hash, &refund_hash, &claimer_pk, &refund_pk).expect("ok");
        assert!(!verify_htlc_script(
            &script,
            &fulfill_hash,
            &refund_hash,
            &wrong_pk,
            &refund_pk
        ));
    }

    #[test]
    fn verify_htlc_rejects_wrong_refund_pubkey() {
        let fulfill_hash = [0x42; 32];
        let refund_hash = [0x43; 32];
        let claimer_pk = [0x02; 33];
        let refund_pk = [0x03; 33];
        let wrong_pk = [0x04; 33];

        let script =
            build_htlc_script(&fulfill_hash, &refund_hash, &claimer_pk, &refund_pk).expect("ok");
        assert!(!verify_htlc_script(
            &script,
            &fulfill_hash,
            &refund_hash,
            &claimer_pk,
            &wrong_pk
        ));
    }

    #[test]
    fn verify_htlc_rejects_swapped_pubkeys() {
        let fulfill_hash = [0x42; 32];
        let refund_hash = [0x43; 32];
        let claimer_pk = [0x02; 33];
        let refund_pk = [0x03; 33];

        let script =
            build_htlc_script(&fulfill_hash, &refund_hash, &claimer_pk, &refund_pk).expect("ok");
        assert!(!verify_htlc_script(
            &script,
            &fulfill_hash,
            &refund_hash,
            &refund_pk,
            &claimer_pk
        ));
    }

    #[test]
    fn two_paths_are_distinct() {
        let same_hash = [0x42; 32];
        let claimer_pk = [0x02; 33];
        let refund_pk = [0x03; 33];

        let script =
            build_htlc_script(&same_hash, &same_hash, &claimer_pk, &refund_pk).expect("ok");
        assert!(verify_htlc_script(
            &script,
            &same_hash,
            &same_hash,
            &claimer_pk,
            &refund_pk
        ));
    }
}
