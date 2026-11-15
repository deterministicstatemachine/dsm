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
/// schedule now READS this value, so there is exactly one authority. In base
/// units: 10.00 ERA at ERA's two decimals (SoFi Amendment S18).
pub const TOKEN_CREATION_FEE_ERA: u64 = 1_000;

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

/// The tickers of the tokens Core builds in. No token a device creates or
/// adopts may carry one, in any letter case, nor a ticker a person reads as
/// one (SA-104, SA-145).
pub const BUILTIN_TICKERS: [&str; 2] = ["ERA", "dBTC"];

/// The first character of `ticker` a person does not see: a format or
/// zero-width character, a variation selector, a combining mark or a tag.
/// A ticker is read by a person, so none belongs in one.
pub fn ticker_invisible_char(ticker: &str) -> Option<char> {
    ticker.chars().find(|c| {
        matches!(
            *c as u32,
            0x00AD
                | 0x034F
                | 0x061C
                | 0x115F..=0x1160
                | 0x17B4..=0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0x3164
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xFFF0..=0xFFF8
                | 0x0300..=0x036F
                | 0x1AB0..=0x1AFF
                | 0x1DC0..=0x1DFF
                | 0x20D0..=0x20FF
                | 0xFE20..=0xFE2F
                | 0x1D173..=0x1D17A
                | 0xE0000..=0xE0FFF
        ) || c.is_control()
            || c.is_whitespace()
    })
}

/// The ASCII letter or digit a person reads `c` as, when `c` is drawn like
/// one: full-width and mathematical forms, and the Cyrillic and Greek letters
/// that share a Latin letter's shape. Any other character reads as itself.
fn reads_as_ascii(c: char) -> char {
    let code = c as u32;
    let drawn_as = if (0xFF01..=0xFF5E).contains(&code) {
        // Full-width forms of the printable ASCII range.
        Some(code - 0xFEE0)
    } else if (0x1D400..=0x1D6A3).contains(&code) {
        // Mathematical alphanumeric letters: 52 letters a style, A to Z then
        // a to z.
        let at = (code - 0x1D400) % 52;
        Some(if at < 26 {
            u32::from(b'A') + at
        } else {
            u32::from(b'a') + at - 26
        })
    } else if (0x1D7CE..=0x1D7FF).contains(&code) {
        // Mathematical digits: 10 digits a style.
        Some(u32::from(b'0') + (code - 0x1D7CE) % 10)
    } else {
        None
    };
    if let Some(ascii) = drawn_as.and_then(char::from_u32) {
        return ascii;
    }
    match c {
        // Cyrillic capitals.
        '\u{0410}' => 'A',
        '\u{0412}' => 'B',
        '\u{0415}' => 'E',
        '\u{041A}' => 'K',
        '\u{041C}' => 'M',
        '\u{041D}' => 'H',
        '\u{041E}' => 'O',
        '\u{0420}' => 'P',
        '\u{0421}' => 'C',
        '\u{0422}' => 'T',
        '\u{0423}' => 'Y',
        '\u{0425}' => 'X',
        '\u{0405}' => 'S',
        '\u{0406}' => 'I',
        '\u{0408}' => 'J',
        '\u{04C0}' => 'I',
        '\u{051A}' => 'Q',
        '\u{051C}' => 'W',
        '\u{0417}' => '3',
        '\u{0400}' => 'E',
        '\u{0401}' => 'E',
        // Cyrillic small letters.
        '\u{0430}' => 'a',
        '\u{0435}' => 'e',
        '\u{043E}' => 'o',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0443}' => 'y',
        '\u{0445}' => 'x',
        '\u{0455}' => 's',
        '\u{0456}' => 'i',
        '\u{0458}' => 'j',
        '\u{04BB}' => 'h',
        '\u{0501}' => 'd',
        '\u{051B}' => 'q',
        '\u{051D}' => 'w',
        '\u{0432}' => 'b',
        '\u{043A}' => 'k',
        '\u{043C}' => 'm',
        '\u{043D}' => 'h',
        '\u{0442}' => 't',
        // Greek capitals.
        '\u{0391}' => 'A',
        '\u{0392}' => 'B',
        '\u{0395}' => 'E',
        '\u{0396}' => 'Z',
        '\u{0397}' => 'H',
        '\u{0399}' => 'I',
        '\u{039A}' => 'K',
        '\u{039C}' => 'M',
        '\u{039D}' => 'N',
        '\u{039F}' => 'O',
        '\u{03A1}' => 'P',
        '\u{03A4}' => 'T',
        '\u{03A5}' => 'Y',
        '\u{03A7}' => 'X',
        '\u{03F9}' => 'C',
        '\u{037F}' => 'J',
        // Greek small letters.
        '\u{03B1}' => 'a',
        '\u{03BF}' => 'o',
        '\u{03BD}' => 'v',
        '\u{03C1}' => 'p',
        '\u{03C5}' => 'u',
        '\u{03B9}' => 'i',
        '\u{03BA}' => 'k',
        '\u{03C7}' => 'x',
        '\u{03F2}' => 'c',
        '\u{03F3}' => 'j',
        // Latin letters drawn like others.
        '\u{0131}' => 'i',
        '\u{01C0}' => 'l',
        '\u{2160}' => 'I',
        '\u{2164}' => 'V',
        '\u{2169}' => 'X',
        '\u{216C}' => 'L',
        '\u{216D}' => 'C',
        '\u{216E}' => 'D',
        '\u{216F}' => 'M',
        '\u{212A}' => 'K',
        '\u{212B}' => 'A',
        '\u{2102}' => 'C',
        '\u{210D}' => 'H',
        '\u{2115}' => 'N',
        '\u{2119}' => 'P',
        '\u{211A}' => 'Q',
        '\u{211D}' => 'R',
        '\u{2124}' => 'Z',
        '\u{212C}' => 'B',
        '\u{2130}' => 'E',
        '\u{2131}' => 'F',
        '\u{210B}' => 'H',
        '\u{2110}' => 'I',
        '\u{2112}' => 'L',
        '\u{2133}' => 'M',
        '\u{211B}' => 'R',
        '\u{0BE6}' => '0',
        other => other,
    }
}

/// The built-in ticker a person reads `ticker` as, letter case aside: each
/// character as the ASCII letter or digit it is drawn like, the characters a
/// person does not see left out. `None` when it reads as none of them.
pub fn builtin_ticker_read_in(ticker: &str) -> Option<&'static str> {
    let read: String = ticker
        .chars()
        .filter(|c| ticker_invisible_char(&c.to_string()).is_none())
        .map(reads_as_ascii)
        .collect();
    BUILTIN_TICKERS
        .iter()
        .find(|builtin| builtin.eq_ignore_ascii_case(&read))
        .copied()
}

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
    use super::{
        builtin_ticker_read_in, derive_canonical_balance_key, resolve_policy_commit,
        ticker_invisible_char,
    };

    /// A ticker a person reads as a built-in one is read as it (SA-104,
    /// SA-145): look-alike Cyrillic, Greek, full-width and mathematical
    /// letters, in any case, with invisible characters left out. Tickers that
    /// only share letters with one, or differ by a letter a person sees, are
    /// not.
    #[test]
    fn a_ticker_drawn_like_a_builtin_reads_as_it() {
        for read_as_era in [
            "ERA",
            "era",
            "\u{0415}RA",
            "ER\u{0410}",
            "\u{0395}RA",
            "\u{0435}r\u{0430}",
            "\u{FF25}\u{FF32}\u{FF21}",
            "\u{1D404}\u{1D411}\u{1D400}",
            "ERA\u{200B}",
            "E\u{200D}RA",
        ] {
            assert_eq!(
                builtin_ticker_read_in(read_as_era),
                Some("ERA"),
                "{read_as_era:?} reads as ERA"
            );
        }
        assert_eq!(builtin_ticker_read_in("dBTC"), Some("dBTC"));
        assert_eq!(builtin_ticker_read_in("\u{0501}BTC"), Some("dBTC"));
        for other in ["ERAS", "ERB", "GOLD", "\u{0416}RA", "E R"] {
            assert_eq!(builtin_ticker_read_in(other), None, "{other:?} is no built-in");
        }
    }

    /// A character a person does not see is named; one they see is not.
    #[test]
    fn an_invisible_character_in_a_ticker_is_named() {
        assert_eq!(ticker_invisible_char("ERA\u{200B}"), Some('\u{200B}'));
        assert_eq!(ticker_invisible_char("E\u{FEFF}X"), Some('\u{FEFF}'));
        assert_eq!(ticker_invisible_char("E\u{0301}X"), Some('\u{0301}'));
        assert_eq!(ticker_invisible_char("GOLD"), None);
        assert_eq!(ticker_invisible_char("\u{0415}RA"), None);
    }

    /// The built-in commitments, pinned when the SDK's copy of this lookup was
    /// deleted (§6.118): ERA's, derived from its committed policy bytes, and
    /// dBTC's fixed one. A ticker is a built-in only as spelled here.
    #[test]
    fn the_builtin_policy_commits_are_pinned() {
        assert_eq!(
            super::builtin_policy_commit_for_token("ERA"),
            Some([
                173, 96, 19, 155, 31, 50, 153, 174, 49, 182, 197, 125, 30, 254, 98, 107, 62, 113,
                102, 202, 77, 205, 222, 67, 16, 186, 101, 9, 255, 218, 118, 96,
            ])
        );
        assert_eq!(
            super::builtin_policy_commit_for_token("dBTC"),
            Some([
                3, 164, 43, 103, 25, 23, 175, 132, 47, 7, 61, 135, 207, 164, 89, 216, 69, 185, 104,
                253, 177, 171, 203, 3, 49, 45, 145, 78, 53, 1, 98, 34,
            ])
        );
        assert_eq!(super::builtin_policy_commit_for_token("era"), None);
        assert_eq!(super::builtin_policy_commit_for_token("WILD"), None);
    }

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
