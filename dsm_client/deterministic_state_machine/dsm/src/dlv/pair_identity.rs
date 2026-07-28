// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical pair identity — a vault's two assets, named by what they ARE.
//!
//! WHY THIS EXISTS. A vault used to name its pair by the UTF-8 bytes of a typed
//! label. A ticker is not an identity: this repo has held two distinct tokens
//! both called `RIGB`, with different policy anchors and different supply. Under
//! label identity those two are the same asset — they collide in the routing
//! keyspace, they are indistinguishable inside a vault, and a reserve inclusion
//! proof for one matches a quote for the other while every signature on the path
//! verifies. Nothing looks wrong until value moves the wrong way.
//!
//! The 32-byte CPTA `policy_commit` is the identity. It is the thing the
//! creation commitment binds, the thing balances are keyed by, and the thing
//! reserve leaves are keyed by, so naming the pair with it makes the vault, the
//! advertisement, the quote and the proof all speak about the same asset.
//!
//! ONE PARSER, NO FALLBACK. Every boundary that accepts a pair goes through
//! [`CanonicalPair::parse`]. There is deliberately no "resolve this ticker to a
//! policy commit" path: a ticker can resolve to more than one commit, and a
//! lookup that picked one would reintroduce exactly the ambiguity this replaces
//! — silently, and only for users who happen to hold both. Ambiguity fails
//! closed.
//!
//! ORDERING IS OVER THE COMMITS. Lex order over 32-byte commits, not over
//! labels, so the canonical pair is a function of identity alone. Ordering by
//! label would make the same two assets sort differently depending on what their
//! holders had named them.

use crate::types::error::DsmError;

/// A vault's two assets in canonical order: `a` is lex-lower than `b`.
///
/// Construct only through [`Self::parse`], so the ordering and distinctness
/// invariants hold everywhere by construction rather than by each caller
/// remembering to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPair {
    a: [u8; 32],
    b: [u8; 32],
}

impl CanonicalPair {
    /// Parse two asset identifiers into a canonical pair, sorting them.
    ///
    /// Rejects anything that is not exactly 32 bytes — that is where a label
    /// dies, before any cryptographic work is done with it — and rejects a pair
    /// naming one asset twice, which is not a market.
    ///
    /// Order-insensitive: `parse(x, y)` and `parse(y, x)` produce the same pair,
    /// so the side a user happened to pick first cannot change the vault's
    /// identity or its routing key.
    pub fn parse(first: &[u8], second: &[u8]) -> Result<Self, DsmError> {
        let a = Self::commit(first, "first")?;
        let b = Self::commit(second, "second")?;
        if a == b {
            return Err(DsmError::invalid_operation(
                "pair identity: both sides name the same asset",
            ));
        }
        let (a, b) = if a < b { (a, b) } else { (b, a) };
        Ok(Self { a, b })
    }

    fn commit(v: &[u8], which: &str) -> Result<[u8; 32], DsmError> {
        <[u8; 32]>::try_from(v).map_err(|_| {
            DsmError::invalid_operation(format!(
                "pair identity: the {which} asset must be a 32-byte policy commit, got {} bytes — \
                 a ticker is not an identity and is never resolved to one",
                v.len()
            ))
        })
    }

    /// The lex-lower asset.
    pub fn a(&self) -> [u8; 32] {
        self.a
    }

    /// The lex-higher asset.
    pub fn b(&self) -> [u8; 32] {
        self.b
    }

    /// `true` when `policy_commit` is one of this pair's two assets.
    pub fn contains(&self, policy_commit: &[u8; 32]) -> bool {
        self.a == *policy_commit || self.b == *policy_commit
    }

    /// Given the asset going IN, the asset coming OUT — or `None` when the input
    /// is not part of this pair.
    ///
    /// `None` rather than a default side: a trade naming an asset the vault does
    /// not hold is a malformed trade, not a trade in the other direction.
    pub fn counterpart(&self, input: &[u8; 32]) -> Option<[u8; 32]> {
        if *input == self.a {
            Some(self.b)
        } else if *input == self.b {
            Some(self.a)
        } else {
            None
        }
    }

    /// `true` when `input` is the lex-lower side. Callers that keep reserves as
    /// an ordered `(a, b)` tuple use this to pick which side the input hits.
    pub fn input_is_a(&self, input: &[u8; 32]) -> Option<bool> {
        if *input == self.a {
            Some(true)
        } else if *input == self.b {
            Some(false)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// THE REPRODUCTION. Two tokens sharing a ticker are distinct assets, and
    /// the pair keeps them apart — under label identity they were the same.
    #[test]
    fn two_tokens_sharing_a_ticker_are_different_assets() {
        // Both would be typed "RIGB" by their holders.
        let rigb_one = pc(0x11);
        let rigb_two = pc(0x22);
        let era = pc(0x33);

        let p1 = CanonicalPair::parse(&era, &rigb_one).expect("pair");
        let p2 = CanonicalPair::parse(&era, &rigb_two).expect("pair");
        assert_ne!(p1, p2, "same ticker, different asset, different pair");

        // And a vault over one does not contain the other.
        assert!(p1.contains(&rigb_one));
        assert!(!p1.contains(&rigb_two));
        assert_eq!(p1.counterpart(&era), Some(rigb_one));
        assert_eq!(
            p2.counterpart(&era),
            Some(rigb_two),
            "the counterpart must be the asset actually funded, not whatever shares its ticker"
        );
    }

    /// Whichever side the user picked first, the canonical pair is the same. The
    /// UI's selection order must not change a vault's identity or its routing
    /// key.
    #[test]
    fn selection_order_does_not_change_the_canonical_pair() {
        let (x, y) = (pc(0xF0), pc(0x0F));
        let forward = CanonicalPair::parse(&x, &y).expect("pair");
        let reversed = CanonicalPair::parse(&y, &x).expect("pair");
        assert_eq!(forward, reversed);
        assert_eq!(forward.a(), pc(0x0F), "a is always the lex-lower commit");
        assert_eq!(forward.b(), pc(0xF0));
    }

    /// Ordering is over the COMMITS. Were it over labels, the same two assets
    /// would sort differently depending on what their holders had named them.
    #[test]
    fn ordering_is_over_commits_not_over_anything_else() {
        // 0x01… sorts below 0xFE… regardless of any name either might carry.
        let low = pc(0x01);
        let high = pc(0xFE);
        let p = CanonicalPair::parse(&high, &low).expect("pair");
        assert_eq!(p.a(), low);
        assert_eq!(p.b(), high);
        assert!(p.a() < p.b());
    }

    /// A label dies at the boundary, before any cryptographic work is done with
    /// it — and the error says why, so nobody adds a lookup to "fix" it.
    #[test]
    fn a_label_is_rejected_and_never_resolved() {
        let era = pc(0x33);
        for bad in [b"RIGB".as_slice(), b"".as_slice(), &[0u8; 31], &[0u8; 33]] {
            let err = CanonicalPair::parse(&era, bad)
                .expect_err("a non-commit must not be accepted as identity");
            let msg = format!("{err}");
            assert!(
                msg.contains("32-byte policy commit"),
                "must fail as an identity error, got: {msg}"
            );
        }
        // Both sides are checked, not only the second.
        assert!(CanonicalPair::parse(b"RIGB", &era).is_err());
    }

    #[test]
    fn a_pair_naming_one_asset_twice_is_not_a_market() {
        let era = pc(0x33);
        let err = CanonicalPair::parse(&era, &era).expect_err("self-pair rejected");
        assert!(format!("{err}").contains("same asset"));
    }

    /// An asset the vault does not hold yields no counterpart — a malformed
    /// trade, never silently the other direction.
    #[test]
    fn an_unheld_asset_has_no_counterpart_and_no_side() {
        let p = CanonicalPair::parse(&pc(0x11), &pc(0x22)).expect("pair");
        let stranger = pc(0x99);
        assert_eq!(p.counterpart(&stranger), None);
        assert_eq!(p.input_is_a(&stranger), None);
        assert_eq!(p.input_is_a(&pc(0x11)), Some(true));
        assert_eq!(p.input_is_a(&pc(0x22)), Some(false));
    }
}
