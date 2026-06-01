// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Canonical Encoding Module
//!
//! Centralized, audited canonical encoding for cryptographic commitments.
//! All structures that contribute to state hashes must implement the CanonicalEncode trait.
//!
//! This module provides:
//! - Consistent byte ordering and field inclusion
//! - Single source of truth for all canonical encodings

use crate::DsmError;

/// Trait for structures that can be canonically encoded for cryptographic commitments.
/// All implementations must ensure deterministic, unambiguous byte representation.
pub trait CanonicalEncode {
    /// Encode this structure to canonical bytes for hashing/commitment.
    /// Must be deterministic and unambiguous.
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, DsmError>;

    /// Return the domain tag for this type's canonical encoding.
    fn domain_tag(&self) -> &'static str;
}

// `pub mod cbor` REMOVED — Issue #182 Finding #1.
//
// Storagenodes spec §3 (normative) and whitepaper §2.1/§4.2.1 forbid CBOR
// in canonical encoding paths: "No JSON, no base64, no hex, no CBOR." The
// helpers were `pub` and reachable by any downstream caller, which would
// silently produce a commitment byte sequence incompatible with the
// canonical Envelope wire v3 protobuf-only path. Removed entirely. The
// only surviving export from this module is the `CanonicalEncode`
// trait.
//
// If a future protocol extension genuinely needs structured byte streams
// outside protobuf, define a new domain-tagged primitive — do not
// resurrect generic CBOR.
