// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Token Policy Module
//!
//! Built-in CPTA (Content-Addressed Token Policy Anchor) definitions.

pub mod builtins;

use dsm::types::{error::DsmError, policy_types::PolicyAnchor};

use crate::storage::client_db::token_registry;

/// The `policy_commit` of the token this device names `token_id` (§9.5),
/// from what is installed here and never from a peer: a built-in's, which
/// Core answers, or else the commitment of the registry row for that token
/// id — or, failing one, that ticker — whose stored policy bytes re-hash to
/// it.
///
/// Creation writes the row inside its advance, and adoption beside its own,
/// so a row whose policy bytes are not stored is an inconsistent store, not
/// a token to look for elsewhere. The refusals stay distinct: a token with
/// no row is not installed on this device; a registry or policy store that
/// cannot be read, bytes that do not re-hash, or a row without its bytes
/// is a storage error.
pub fn resolve_policy_commit_strict(token_id: &[u8]) -> Result<[u8; 32], DsmError> {
    let token_id = std::str::from_utf8(token_id)
        .map_err(|e| DsmError::invalid_operation(format!("a token id is not UTF-8: {e}")))?;
    if let Some(commit) = dsm::core::token::builtin_policy_commit_for_token(token_id) {
        return Ok(commit);
    }
    let registry = |e: anyhow::Error| {
        DsmError::storage(format!("token registry: {e}"), None::<std::io::Error>)
    };
    let row = match token_registry::get_token(token_id).map_err(registry)? {
        Some(row) => Some(row),
        None => token_registry::get_token_by_ticker(token_id).map_err(registry)?,
    };
    let Some(row) = row else {
        return Err(DsmError::not_found(
            "token",
            Some(format!(
                "{token_id} is not installed on this device: create it, or add it by its \
                 CPTA anchor"
            )),
        ));
    };
    match token_registry::load_policy_verified(&row.policy_commit).map_err(registry)? {
        Some(_) => Ok(row.policy_commit),
        None => Err(DsmError::storage(
            format!(
                "token registry: {token_id} is registered under a policy whose bytes are not \
                 stored"
            ),
            None::<std::io::Error>,
        )),
    }
}

pub fn parse_policy_anchor_uri(policy_anchor_uri: &str) -> Result<[u8; 32], DsmError> {
    let anchor_b32 = policy_anchor_uri
        .strip_prefix("dsm:policy:")
        .unwrap_or(policy_anchor_uri);
    let anchor = PolicyAnchor::from_base32(anchor_b32)?;
    Ok(*anchor.as_bytes())
}

pub fn strict_policy_commit_for_token(
    token_id: &str,
    policy_anchor_uri: Option<&str>,
) -> Result<[u8; 32], DsmError> {
    if let Some(commit) = dsm::core::token::builtin_policy_commit_for_token(token_id) {
        return Ok(commit);
    }

    let policy_anchor_uri = policy_anchor_uri.ok_or_else(|| {
        DsmError::invalid_operation(format!("Missing policy anchor for token {token_id}"))
    })?;

    parse_policy_anchor_uri(policy_anchor_uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy_commit_accepts_prefixed_anchor_uri() {
        let anchor = PolicyAnchor::from_bytes([0x11; 32]);
        let commit = strict_policy_commit_for_token(
            "USER",
            Some(&format!("dsm:policy:{}", anchor.to_base32())),
        )
        .expect("policy anchor should parse");
        assert_eq!(commit, [0x11; 32]);
    }

    #[test]
    fn strict_policy_commit_uses_builtin_for_dbtc() {
        let commit = strict_policy_commit_for_token("dBTC", None).expect("builtin dBTC commit");
        assert_eq!(commit, *builtins::DBTC_POLICY_COMMIT);
    }
}
