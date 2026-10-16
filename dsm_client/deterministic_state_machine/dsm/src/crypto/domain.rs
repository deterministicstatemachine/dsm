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
//! That includes the family a domain belongs to. Every domain DSM hashes under
//! starts with `DSM/` or `DJTE.` (the join-triggered emissions family, which
//! goes with those emissions), and the type refuses any other. The hasher once
//! asserted the prefix instead, so a domain read off the wire — a storage
//! member's `x-namespace` answer — panicked the reader at hash time; now it is
//! refused where it is read, as any other malformed answer is.
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
    /// Starts with neither `DSM/` nor `DJTE.`, the domain families DSM hashes
    /// under.
    Unprefixed,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::InvalidDomain => {
                write!(f, "domain must be non-empty and contain no NUL byte")
            }
            DomainError::Unprefixed => {
                write!(f, "domain must start with \"DSM/\" or \"DJTE.\"")
            }
        }
    }
}

/// Whether `bytes` begins with `prefix`, usable in a `const` context.
const fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    let mut i = 0;
    while i < prefix.len() && i < bytes.len() && bytes[i] == prefix[i] {
        i += 1;
    }
    i == prefix.len()
}

/// Whether `bytes` is in a domain family DSM hashes under.
const fn has_protocol_prefix(bytes: &[u8]) -> bool {
    starts_with(bytes, b"DSM/") || starts_with(bytes, b"DJTE.")
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
///
/// So does one outside the `DSM/` and `DJTE.` families:
///
/// ```compile_fail
/// # use dsm::crypto::domain::TaggedHashDomain;
/// const BAD: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"example");
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedHashDomain<'a>(&'a [u8]);

impl TaggedHashDomain<'static> {
    /// Build a static protocol domain, validated at compile time.
    ///
    /// Used in a `const` context, a violation is a compile error rather than a
    /// panic — which is the point: the four double-NUL sites this cut fixes
    /// become a compiler worklist, not a runtime surprise.
    /// Prefer the [`tagged_domain!`] macro, which forces const evaluation so the
    /// panic below is a compile error and cannot be reached at runtime.
    ///
    /// The three `panic!`s are the COMPILE-TIME gate, not runtime error handling.
    ///
    /// `const fn` has no fallible return in a const context — a `Result` cannot
    /// halt compilation. Evaluated in a `const` position (which is how every
    /// protocol domain is declared) a violation becomes
    /// `error[E0080]: evaluation panicked`, verified against the real
    /// `"DSM/cert-restart/v1\0"` literal during the cut. That is the mechanism
    /// that turned a ~676-site migration into a compiler worklist.
    ///
    /// `clippy::panic` is allowed here deliberately and NOWHERE else in this
    /// module. Runtime construction must use [`TaggedHashDomain::try_new`],
    /// which returns [`DomainError`] instead.
    #[allow(clippy::panic)]
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

        if !has_protocol_prefix(bytes) {
            panic!("tagged-hash domain must start with \"DSM/\" or \"DJTE.\"");
        }

        Self(bytes)
    }
}

impl<'a> TaggedHashDomain<'a> {
    /// Build a domain from runtime bytes: non-empty, NUL-free, and starting
    /// with `DSM/` or `DJTE.`. Bytes another party chose — a member's
    /// namespace answer — are refused here, never at hash time.
    ///
    /// Prefer [`TaggedHashDomain::from_static`] for protocol domains, so the
    /// check happens at compile time.
    pub fn try_new(bytes: &'a [u8]) -> Result<Self, DomainError> {
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(DomainError::InvalidDomain);
        }
        if !has_protocol_prefix(bytes) {
            return Err(DomainError::Unprefixed);
        }
        Ok(Self(bytes))
    }

    /// The domain WITHOUT the delimiter. The encoder appends it.
    pub const fn source_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// Build a `TaggedHashDomain` from a literal, **forcing const evaluation**.
///
/// `TaggedHashDomain::from_static` is a `const fn`, and a `const fn` can also be
/// called at runtime — where its `panic!` would be an ordinary production panic
/// rather than the intended compile error. That weakened the "no production
/// panic" property the repo's safety gate enforces.
///
/// This macro closes it: the inline `const { … }` block makes the call a
/// constant expression, so a NUL-bearing or empty literal is
/// `error[E0080]: evaluation panicked` at BUILD time and the panic is
/// unreachable at run time.
///
/// ```
/// # use dsm::tagged_domain;
/// let d = tagged_domain!(b"DSM/example");
/// assert_eq!(d.source_bytes(), b"DSM/example");
/// ```
///
/// ```compile_fail
/// # use dsm::tagged_domain;
/// let d = tagged_domain!(b"DSM/example\0");
/// ```
///
/// Runtime bytes cannot use this macro by construction — use
/// [`TaggedHashDomain::try_new`], which returns [`DomainError`].
#[macro_export]
macro_rules! tagged_domain {
    ($bytes:expr) => {
        const { $crate::crypto::domain::TaggedHashDomain::from_static($bytes) }
    };
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

    /// A domain outside the families the hasher separates is refused when it
    /// is built, whoever chose the bytes: before, it was built and then
    /// panicked the hasher.
    #[test]
    fn an_unprefixed_domain_is_rejected() {
        for unprefixed in [&b"x"[..], b"dsm/lowercase", b"DSM", b"DJTE", b"/DSM/"] {
            assert_eq!(
                TaggedHashDomain::try_new(unprefixed),
                Err(DomainError::Unprefixed),
                "{:?}",
                String::from_utf8_lossy(unprefixed)
            );
        }
        for prefixed in [&b"DSM/"[..], b"DJTE.JAP"] {
            assert_eq!(
                TaggedHashDomain::try_new(prefixed).map(TaggedHashDomain::source_bytes),
                Ok(prefixed)
            );
        }
    }

    /// The const constructor accepts what `try_new` accepts.
    #[test]
    fn the_static_and_runtime_constructors_agree() {
        const STATIC: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/example");
        let runtime = TaggedHashDomain::try_new(b"DSM/example").expect("valid");
        assert_eq!(STATIC, runtime);
    }
}
