// SPDX-License-Identifier: MIT OR Apache-2.0

//! ERA's canonical token policy (SoFi Amendment S11): the one network-anchored
//! policy, fixed here, held by every device by construction.
//!
//! ERA's identity is derived from these exact bytes and from nothing else:
//! [`era_policy_commit`] is `BLAKE3(DSM/policy ‖ 0x00 ‖ TokenPolicyV3 bytes)`,
//! the commitment every token has (§47). A different byte is a different
//! ERA — every ERA balance key and the reserve id move with it — so the value
//! is pinned by this module's tests and by the specification's check value.

use std::sync::LazyLock;

use crate::economic::token_policy::{parse_token_policy, TokenPolicy};
use crate::types::error::DsmError;

/// ERA's `TokenPolicyV3` bytes, field by field (SoFi §47, Amendment S11).
const ERA_POLICY_PROTO: [u8; 40] = [
    // TokenPolicyV3 { policy_bytes (field 1) }: the 38-byte blob.
    0x0A, 0x26, //
    // version 3, fungible, native.
    0x03, 0x00, 0x00, //
    // flags: burn | transferable; no recipient allowlist.
    0x03, //
    // release rule: the beta faucet. Network-anchored, so no creator and no
    // signer set follow (Amendment S11).
    0x01, //
    // ticker "ERA".
    0x03, b'E', b'R', b'A', //
    // alias "ERA".
    0x00, 0x03, b'E', b'R', b'A', //
    // decimals: whole ERA.
    0x00, //
    // genesis supply: 80,000,000,000 (u128, big-endian; owner, 2026-09-26).
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x12, 0xA0, 0x5F, 0x20, 0x00, //
    // description: none; icon: none.
    0x00, 0x00, 0x00, 0x00, //
    // recipient allowlist: none (kind NONE, count 0).
    0x00, 0x00, 0x00,
];

static ERA_POLICY_COMMIT: LazyLock<[u8; 32]> = LazyLock::new(|| {
    crate::core::token::policy::TokenPolicySystem::commitment_of(&ERA_POLICY_PROTO)
});

static ERA_POLICY: LazyLock<Result<TokenPolicy, String>> =
    LazyLock::new(|| parse_token_policy(&ERA_POLICY_PROTO));

/// ERA's policy bytes, exactly as committed.
pub fn era_policy_bytes() -> &'static [u8] {
    &ERA_POLICY_PROTO
}

/// ERA's policy commitment, derived from its bytes.
pub fn era_policy_commit() -> [u8; 32] {
    *ERA_POLICY_COMMIT
}

/// ERA's policy, read by the one parser. The compiled bytes parse — this
/// module's tests pin it — and Core does not panic on its own data, so a
/// failure reaches the caller as an error.
pub fn era_policy() -> Result<&'static TokenPolicy, DsmError> {
    ERA_POLICY.as_ref().map_err(|e| {
        DsmError::invalid_operation(format!("ERA's compiled policy does not parse: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::token::policy::TokenPolicySystem;
    use crate::economic::token_policy::Release;
    use prost::Message;

    /// SoFi Amendment S11: ERA's commitment is derived from its bytes, and it
    /// is the check value the specification states. Any byte changed is a
    /// different ERA, and it goes red here.
    #[test]
    fn eras_commitment_is_derived_from_its_bytes_and_is_the_specifications() {
        assert_eq!(
            era_policy_commit(),
            TokenPolicySystem::commitment_of(era_policy_bytes())
        );
        assert_eq!(
            crate::utils::text_id::encode_base32_crockford(&era_policy_commit()),
            "JXPMPGJH45HDTE0ARWE2CTB9E9BWTQZ3T78CE5RFF1RXMR9VKK80"
        );
    }

    /// One policy, one commitment: ERA's bytes are the canonical encoding of
    /// the blob they carry.
    #[test]
    fn eras_bytes_are_the_canonical_encoding_of_its_blob() {
        let decoded = crate::types::proto::TokenPolicyV3::decode(era_policy_bytes())
            .expect("ERA's wrapper decodes");
        assert_eq!(decoded.encode_to_vec(), era_policy_bytes());
    }

    /// Every field of ERA's policy, as SoFi Amendment S11 fixes it.
    #[test]
    fn eras_policy_states_what_the_specification_fixes() {
        assert_eq!(
            era_policy().expect("ERA's policy parses"),
            &TokenPolicy {
                ticker: "ERA".into(),
                alias: "ERA".into(),
                decimals: 0,
                genesis_supply: 80_000_000_000,
                release: Release::Faucet,
                description: None,
                icon_url: None,
                burn_enabled: true,
                transferable: true,
                allowlist_device_ids: Vec::new(),
            }
        );
    }
}
