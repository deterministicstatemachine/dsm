// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bytes of a match transcript's entries, as the application that
//! relays a staked match builds them for each player's wallet to sign.
//!
//! The entries are DSM's own objects (SoFi §19.10, class `0x0068
//! TranscriptEntry`), not this program's: Core decodes them, re-encodes them
//! and chains them, and the wallet refuses any entry that is not exactly
//! Core's encoding. This module writes those same bytes for an application
//! that cannot link Core (the game server, through WebAssembly), and the
//! SDK's tests hold it to Core's encoder byte for byte. Nothing here is
//! evidence: a wallet signs an entry only after Core and the program checked
//! it.

use crate::codec::{tagged_hash, DecodeError, Writer};
use crate::engine::Side;
use crate::MAX_OPENED_MOVE_BYTES;

/// Core's class of a transcript entry.
pub const TRANSCRIPT_ENTRY_CLASS: u16 = 0x0068;
/// `DSM/escrow/move-commit/v1`: the tag of a Commit's commitment.
pub const TAG_MOVE_COMMIT: &str = "DSM/escrow/move-commit/v1";

const KIND_COMMIT: u8 = 1;
const KIND_REVEAL: u8 = 2;
const KIND_RESIGN: u8 = 3;

fn side_byte(side: Side) -> u8 {
    match side {
        Side::A => 1,
        Side::B => 2,
    }
}

/// `H(DSM/escrow/move-commit/v1 ‖ salt ‖ u32be(|move|) ‖ move)`: what a
/// Commit commits to and its Reveal later opens.
pub fn move_commitment(salt: &[u8; 32], played: &[u8]) -> [u8; 32] {
    let len = (played.len().min(u32::MAX as usize) as u32).to_be_bytes();
    tagged_hash(TAG_MOVE_COMMIT, &[salt, &len, played])
}

fn entry(index: u32, side: Side, kind: u8) -> Result<Writer, DecodeError> {
    if index == 0 {
        return Err(DecodeError::UnknownValue {
            field: "entry.index",
            value: index,
        });
    }
    let mut w = Writer::object(TRANSCRIPT_ENTRY_CLASS);
    w.u32(index);
    w.u8(side_byte(side));
    w.u8(kind);
    Ok(w)
}

/// Entry `index`, `side`'s commitment to the move `played` under `salt`.
pub fn commit_entry(
    index: u32,
    side: Side,
    salt: &[u8; 32],
    played: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let mut w = entry(index, side, KIND_COMMIT)?;
    w.digest(&move_commitment(salt, played));
    Ok(w.finish())
}

/// Entry `index`, `side`'s opening of the move `played` it committed to
/// under `salt`: 1 to 64 bytes, as Core bounds a Reveal.
pub fn reveal_entry(
    index: u32,
    side: Side,
    salt: &[u8; 32],
    played: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    if played.is_empty() || played.len() > MAX_OPENED_MOVE_BYTES {
        return Err(DecodeError::Cardinality {
            field: "entry.move",
            min: 1,
            max: MAX_OPENED_MOVE_BYTES,
            got: played.len(),
        });
    }
    let mut w = entry(index, side, KIND_REVEAL)?;
    w.digest(salt);
    w.bytes(played);
    Ok(w.finish())
}

/// Entry `index`, `side` resigning the match.
pub fn resign_entry(index: u32, side: Side) -> Result<Vec<u8>, DecodeError> {
    Ok(entry(index, side, KIND_RESIGN)?.finish())
}
