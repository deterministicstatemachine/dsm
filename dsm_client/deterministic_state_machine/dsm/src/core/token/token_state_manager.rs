// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token policy commits and canonical balance keys.
//!
//! A token is named in hashing by its 32-byte `policy_commit`: ERA's is
//! derived from its committed policy ([`crate::core::token::era_policy`]),
//! dBTC's is fixed, and every other token resolves through a registered
//! policy. Balance keys are derived under that commit.

use std::collections::HashMap;

use parking_lot::RwLock;

use crate::types::error::DsmError;

/// ERA destroyed to create a token.
///
/// This lives in CORE, not in the SDK's mutable `fee_schedule` map, because the
/// conservation guard must be able to validate it. The guard is a pure function
/// over `(operation, deltas)`; a fee it cannot see is a fee it cannot enforce,
/// and a fee that a runtime map could change is not a protocol rule. The SDK's
/// schedule now READS this value, so there is exactly one authority.
pub const TOKEN_CREATION_FEE_ERA: u64 = 10;

/// Display-only ticker resolution for non-builtin (CPTA-anchored) tokens.
///
/// The canonical key for a balance is and remains the 32-byte `policy_commit`.
/// This map exists solely so the compatibility projection can render a
/// human-readable ticker: core cannot see the SDK's token registry, and
/// without it every created token surfaced under a placeholder key.
///
/// It is authoritative for NOTHING. A missing entry means "cannot name this
/// balance yet", which callers must treat as "omit the row", never as "show a
/// wrong one".
static POLICY_COMMIT_TICKERS: RwLock<Option<HashMap<[u8; 32], String>>> = RwLock::new(None);

/// Register a `policy_commit -> ticker` mapping for display. Called by the SDK
/// when it loads or creates a token; idempotent.
pub fn register_policy_commit_ticker(policy_commit: [u8; 32], ticker: &str) {
    let mut guard = POLICY_COMMIT_TICKERS.write();
    guard
        .get_or_insert_with(HashMap::new)
        .insert(policy_commit, ticker.to_string());
}

/// Resolve a ticker for display: builtins first (they are compiled in and
/// always resolvable), then the registered map.
pub fn resolve_ticker_for_policy_commit(policy_commit: &[u8; 32]) -> Option<String> {
    if let Some(builtin) = builtin_token_id_for_policy_commit(policy_commit) {
        return Some(builtin.to_string());
    }
    POLICY_COMMIT_TICKERS
        .read()
        .as_ref()
        .and_then(|m| m.get(policy_commit).cloned())
}

/// Canonical balance key for a position, or `None` when the token cannot be
/// named yet.
///
/// The SINGLE place the compatibility projection builds a balance key, so the
/// state-machine view and the SDK view cannot drift. Returning `None` — rather
/// than a placeholder key — is deliberate: an unnameable balance must be
/// ABSENT from the projection, because a row with the wrong token id is worse
/// than a missing row.
pub fn canonical_balance_key_for_commit(
    policy_commit: &[u8; 32],
    owner_pk: &[u8],
) -> Option<String> {
    let ticker = resolve_ticker_for_policy_commit(policy_commit)?;
    Some(derive_canonical_balance_key(
        policy_commit,
        owner_pk,
        &ticker,
    ))
}

/// Derive the stable canonical balance key for a token position.
///
/// `balance_key` is the identity of the canonical balance entry. Freshness and
/// versioning belong to projection rows, not to the balance identity itself.
pub fn derive_canonical_balance_key(
    policy_commit: &[u8; 32],
    owner_pk: &[u8],
    token_id: &str,
) -> String {
    let digest = crate::crypto::blake3::token_domain_hash(policy_commit, "balance-key", owner_pk);
    let bytes = digest.as_bytes();
    let mut le = [0u8; 16];
    le.copy_from_slice(&bytes[..16]);
    let prefix = u128::from_le_bytes(le);
    format!("{prefix}|{token_id}")
}

/// ERA's policy commitment, derived from ERA's committed policy bytes (SoFi
/// Amendment S11). Callers that mean ERA use this and carry no
/// string-keyed lookup.
pub use crate::core::token::era_policy::era_policy_commit;

/// Deterministic policy_commit lookup for builtin token types.
/// Used by state machine core to apply token operations deterministically.
pub fn builtin_policy_commit_for_token(token_id: &str) -> Option<[u8; 32]> {
    match token_id {
        "ERA" => Some(era_policy_commit()),
        "dBTC" => Some(DBTC_POLICY_COMMIT),
        _ => None,
    }
}

/// Reverse of [`builtin_policy_commit_for_token`]: given a 32-byte
/// `policy_commit`, return the builtin token_id ("ERA" or "dBTC") if it
/// matches one of the canonical constants. Returns `None` for non-builtin
/// (CPTA-anchored) tokens, whose ticker must be resolved via the token
/// registry / CPTA cache.
///
/// Used by the DeviceState → State compatibility projection to reconstruct
/// balance keys in the canonical `{prefix}|{token_id}` format produced by
/// [`derive_canonical_balance_key`].
pub fn builtin_token_id_for_policy_commit(policy_commit: &[u8; 32]) -> Option<&'static str> {
    if *policy_commit == era_policy_commit() {
        Some("ERA")
    } else if *policy_commit == DBTC_POLICY_COMMIT {
        Some("dBTC")
    } else {
        None
    }
}

const DBTC_POLICY_COMMIT: [u8; 32] = [
    0x03, 0xa4, 0x2b, 0x67, 0x19, 0x17, 0xaf, 0x84, 0x2f, 0x07, 0x3d, 0x87, 0xcf, 0xa4, 0x59, 0xd8,
    0x45, 0xb9, 0x68, 0xfd, 0xb1, 0xab, 0xcb, 0x03, 0x31, 0x2d, 0x91, 0x4e, 0x35, 0x01, 0x62, 0x22,
];

/// Resolve policy_commit for a token by ticker.
///
/// §9.1: all TokenOps MUST include `policy_commit`. Builtins resolve to
/// theirs: ERA's derived from its committed policy, dBTC's fixed. For every
/// other token the canonical policy_commit is
/// `BLAKE3(DSM/policy ‖ 0x00 ‖ TokenPolicyV3 bytes)` and can only be produced
/// by reading the registered policy — not derived from the ticker string.
///
/// This function therefore strict-fails for any non-builtin token.  Callers
/// that handle custom tokens MUST carry `policy_commit` explicitly on the
/// `BalanceDelta` (the `execute_on_relationship` path) so the transition
/// layer applies the authoritative value from the producing SDK.
pub fn resolve_policy_commit(token_id: &str) -> Result<[u8; 32], DsmError> {
    builtin_policy_commit_for_token(token_id).ok_or_else(|| {
        DsmError::invalid_operation(format!(
            "resolve_policy_commit: no registered policy for token_id {token_id}; custom tokens must carry policy_commit on the BalanceDelta (no fallback derivation)"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{derive_canonical_balance_key, resolve_policy_commit};

    #[test]
    fn resolve_policy_commit_succeeds_for_builtins() {
        let era = resolve_policy_commit("ERA").expect("ERA is a builtin");
        let dbtc = resolve_policy_commit("dBTC").expect("dBTC is a builtin");
        assert_ne!(era, [0u8; 32]);
        assert_ne!(dbtc, [0u8; 32]);
        assert_ne!(era, dbtc);
    }

    #[test]
    fn resolve_policy_commit_fails_for_unregistered_token() {
        // No BLAKE3-of-token-id fallback: custom tokens MUST carry policy_commit
        // on the BalanceDelta path.  Strict-fail closed here.
        let err = resolve_policy_commit("FOOBAR").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("FOOBAR"),
            "error must name the offending token_id, got: {msg}"
        );
        assert!(
            msg.contains("no registered policy"),
            "error must explain missing registration, got: {msg}"
        );
    }

    #[test]
    fn canonical_balance_key_is_stable_for_same_semantic_input() {
        let policy_commit = [0x11; 32];
        let owner_pk = [0x22; 32];

        let a = derive_canonical_balance_key(&policy_commit, &owner_pk, "dBTC");
        let b = derive_canonical_balance_key(&policy_commit, &owner_pk, "dBTC");

        assert_eq!(a, b);
    }

    #[test]
    fn canonical_balance_key_changes_when_policy_commit_changes() {
        let owner_pk = [0x22; 32];

        let a = derive_canonical_balance_key(&[0x11; 32], &owner_pk, "dBTC");
        let b = derive_canonical_balance_key(&[0x33; 32], &owner_pk, "dBTC");

        assert_ne!(a, b);
    }

    #[test]
    fn canonical_balance_key_changes_when_owner_binding_changes() {
        let policy_commit = [0x11; 32];

        let a = derive_canonical_balance_key(&policy_commit, &[0x22; 32], "dBTC");
        let b = derive_canonical_balance_key(&policy_commit, &[0x44; 32], "dBTC");

        assert_ne!(a, b);
    }
}
