// SPDX-License-Identifier: Apache-2.0

//! Vault state anchor primitive (Tier 2 Foundation).
//!
//! Owner-signed snapshot of a DLV's state at a specific sequence.
//! Published to storage at `defi/vault-state/{vault_id_b32}/latest`
//! for off-device traders to read at quote time.  The local
//! `DLVManager` is the authoritative truth source for the chunks #7
//! gate — anchors are an *advertisement*, not a consensus mechanism.
//!
//! All cryptographic operations are domain-separated BLAKE3.
//! Signatures are SPHINCS+.  No JSON, no hex, no wall-clock.

use blake3::Hasher;

const DOMAIN_RESERVES: &[u8] = b"DSM/amm-reserves\0";
const DOMAIN_ANCHOR: &[u8] = b"DSM/vault-state-anchor\0";

/// Compute the canonical reserves digest for an AMM constant-product
/// vault.  Stable across endianness because all integer fields are
/// big-endian encoded.
pub fn compute_reserves_digest(
    token_a: &[u8],
    token_b: &[u8],
    reserve_a: u128,
    reserve_b: u128,
    fee_bps: u32,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_RESERVES);
    h.update(token_a);
    h.update(token_b);
    h.update(&reserve_a.to_be_bytes());
    h.update(&reserve_b.to_be_bytes());
    h.update(&fee_bps.to_be_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_digest_is_deterministic() {
        let d1 = compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 30);
        let d2 = compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 30);
        assert_eq!(d1, d2);
    }

    #[test]
    fn reserves_digest_differs_on_any_field_change() {
        let base = compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 30);
        assert_ne!(base, compute_reserves_digest(b"AAB", b"BBB", 1000, 2000, 30));
        assert_ne!(base, compute_reserves_digest(b"AAA", b"BBC", 1000, 2000, 30));
        assert_ne!(base, compute_reserves_digest(b"AAA", b"BBB", 1001, 2000, 30));
        assert_ne!(base, compute_reserves_digest(b"AAA", b"BBB", 1000, 2001, 30));
        assert_ne!(base, compute_reserves_digest(b"AAA", b"BBB", 1000, 2000, 31));
    }
}
