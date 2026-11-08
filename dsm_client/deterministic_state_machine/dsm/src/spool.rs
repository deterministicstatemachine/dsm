// SPDX-License-Identifier: MIT OR Apache-2.0

//! The b0x spool's limits (storage spec §8): one definition for the node that
//! enforces them and the device that reads within them.

/// The largest sealed payload a member takes into a spool, and so the largest
/// envelope a spool read answers with.
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024;

/// The most envelopes one spool read answers with: a member pages a spool
/// from a position, this many at a time.
pub const MAX_BATCH_RETRIEVE: usize = 64;
