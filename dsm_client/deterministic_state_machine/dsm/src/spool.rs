// SPDX-License-Identifier: MIT OR Apache-2.0

//! The b0x spool's limits (storage spec §8): one definition for the node that
//! enforces them and the device that reads within them.

/// The largest sealed payload a member takes into a spool, and so the largest
/// envelope a spool read answers with.
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024;

/// The largest write a member takes (DSM Amendment A34): an envelope of at
/// most [`MAX_ENVELOPE_BYTES`] with the inbox's key, the key's grant and the
/// writer's signature, each SPHINCS+ signature at most 65,535 bytes, and
/// their framing.
pub const MAX_SPOOL_WRITE_BYTES: usize = MAX_ENVELOPE_BYTES + 3 * 65_535;

/// The most envelopes one spool read answers with: a member pages a spool
/// from a position, this many at a time.
pub const MAX_BATCH_RETRIEVE: usize = 64;

/// The most envelope bytes one spool read answers with, and always the first
/// envelope from the position asked: a page ends before the envelope that
/// would take it past this. A member holds a page in memory to answer it, so
/// what one read can make it hold is this, whatever the spool holds.
pub const SPOOL_PAGE_BYTES: usize = 1024 * 1024;
