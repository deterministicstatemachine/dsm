//! # Token Policy Module
//!
//! Built-in CPTA (Content-Addressed Token Policy Anchor) definitions and
//! integrity assertions verified at library load time via `#[ctor]`.

pub mod builtins;

use dsm::types::{error::DsmError, policy_types::PolicyAnchor};

pub fn builtin_policy_commit(token_id: &str) -> Option<[u8; 32]> {
    match token_id {
        "ERA" => Some(*builtins::NATIVE_POLICY_COMMIT),
        "dBTC" => Some(*builtins::DBTC_POLICY_COMMIT),
        _ => None,
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
    if let Some(commit) = builtin_policy_commit(token_id) {
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
