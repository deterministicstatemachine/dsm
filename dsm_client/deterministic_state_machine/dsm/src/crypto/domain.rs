// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated domain types for the three domain-separation constructions.
//!
//! See `docs/adr/0001-three-domain-separation-constructions.md`. The rule:
//!
//! > The same cryptographic construction must encode domains identically
//! > everywhere. Different constructions stay explicitly different and never
//! > share helpers or silently normalize each other.
//!
//! There is deliberately **no** generic `&[u8]` domain parameter shared across
//! constructions. A tagged-hash domain and a KDF context are different types, so
//! one cannot be passed where the other is expected.
//!
//! ## Why validation happens at construction
//!
//! An invalid domain is unrepresentable rather than rejected late. A static
//! protocol domain fails to **compile**; a runtime domain fails when it is
//! built. Hashing then accepts only a valid domain and always appends exactly
//! one delimiter.
//!
//! Validating at hash time instead would let a malformed domain travel through
//! the system and turn a source-level mistake into a runtime cryptographic
//! failure. With a private field and typed helper inputs there is nothing left
//! to re-check.
//!
//! ## What this replaced
//!
//! Seven implementations disagreeing on the encoding, including
//! `dsm_sdk::wire::domain_hash_bytes`, which called `trim_end_matches('\0')` and
//! so silently mapped `"X\0"` onto `"X"`'s domain — two declared domains sharing
//! one digest space. Trimming is gone: a NUL in a source domain is an error, not
//! something to normalize away.

use core::fmt;

/// A domain that could not be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    /// Empty, or contains a NUL byte. The NUL is the encoder's delimiter, so a
    /// source domain containing one would be ambiguous with a different domain
    /// plus payload — exactly the separation failure the delimiter exists to
    /// prevent.
    InvalidDomain,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::InvalidDomain => {
                write!(f, "domain must be non-empty and contain no NUL byte")
            }
        }
    }
}

impl std::error::Error for DomainError {}

/// A validated domain for the ordinary tagged-hash construction.
///
/// Encoded form is always `source_bytes() || 0x00`, produced in exactly one
/// place. **Callers never append their own delimiter** — a caller that spells
/// the NUL itself cannot construct this type.
///
/// ```
/// # use dsm::crypto::domain::TaggedHashDomain;
/// const TAG: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/example");
/// assert_eq!(TAG.source_bytes(), b"DSM/example");
/// ```
///
/// A NUL-bearing literal fails to compile:
///
/// ```compile_fail
/// # use dsm::crypto::domain::TaggedHashDomain;
/// const BAD: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/example\0");
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedHashDomain<'a>(&'a [u8]);

impl TaggedHashDomain<'static> {
    /// Build a static protocol domain, validated at compile time.
    ///
    /// Used in a `const` context, a violation is a compile error rather than a
    /// panic — which is the point: the four double-NUL sites this cut fixes
    /// become a compiler worklist, not a runtime surprise.
    pub const fn from_static(bytes: &'static [u8]) -> Self {
        if bytes.is_empty() {
            panic!("tagged-hash domain must not be empty");
        }

        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0 {
                panic!("tagged-hash domain must not contain NUL");
            }
            i += 1;
        }

        Self(bytes)
    }
}

impl<'a> TaggedHashDomain<'a> {
    /// Build a domain from runtime bytes.
    ///
    /// Prefer [`TaggedHashDomain::from_static`] for protocol domains, so the
    /// check happens at compile time.
    pub fn try_new(bytes: &'a [u8]) -> Result<Self, DomainError> {
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(DomainError::InvalidDomain);
        }
        Ok(Self(bytes))
    }

    /// The domain WITHOUT the delimiter. The encoder appends it.
    pub const fn source_bytes(self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_domain_round_trips() {
        let d = TaggedHashDomain::try_new(b"DSM/example").expect("valid");
        assert_eq!(d.source_bytes(), b"DSM/example");
    }

    #[test]
    fn a_trailing_nul_is_rejected() {
        assert_eq!(
            TaggedHashDomain::try_new(b"DSM/example\0"),
            Err(DomainError::InvalidDomain),
            "a trailing NUL must be an error, not trimmed — trimming is the \
             defect this type removes"
        );
    }

    #[test]
    fn an_embedded_nul_is_rejected() {
        assert_eq!(
            TaggedHashDomain::try_new(b"DSM/a\0b"),
            Err(DomainError::InvalidDomain)
        );
    }

    #[test]
    fn an_empty_domain_is_rejected() {
        assert_eq!(
            TaggedHashDomain::try_new(b""),
            Err(DomainError::InvalidDomain)
        );
    }

    /// The const constructor accepts what `try_new` accepts.
    #[test]
    fn the_static_and_runtime_constructors_agree() {
        const STATIC: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/example");
        let runtime = TaggedHashDomain::try_new(b"DSM/example").expect("valid");
        assert_eq!(STATIC, runtime);
    }
}
