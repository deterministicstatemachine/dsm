//! BLAKE3's compression function, which the VM's `BLAKE3` instruction applies, and its constants, which the Flock
//! circuit walk ([`crate::flock`]) encodes. Scratch research port: leanVM 68b4844b with the BLAKE3 instruction.

/// BLAKE3's IV (BLAKE2s's, the SHA-256 IV): the chaining value of an unkeyed hash's first block.
pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
pub const ROUNDS: usize = 7;
/// The message word each `G` input takes, per round: BLAKE3's permutation applied round by round.
pub const SIGMA: [[usize; 16]; ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];
/// `G(a, b, c, d)` lanes: four columns, then four diagonals.
pub const G_LANES: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

/// The chunk counter, block length and flags of a one-block 64-byte message: chunk 0, 64 bytes,
/// `CHUNK_START | CHUNK_END | ROOT`. Its compression's first 8 words are `blake3` of the 64 bytes.
pub const ONE_BLOCK: (u64, u32, u32) = (0, 64, 1 | 2 | 8);

/// BLAKE3's compression: the new chaining value, the low 8 words of its output.
pub fn compress(cv: &[u32; 8], block: &[u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 8] {
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(cv);
    v[8..12].copy_from_slice(&IV[..4]);
    v[12] = counter as u32;
    v[13] = (counter >> 32) as u32;
    v[14] = block_len;
    v[15] = flags;
    for sigma in &SIGMA {
        for (gate, &[a, b, c, d]) in G_LANES.iter().enumerate() {
            let (x, y) = (block[sigma[2 * gate]], block[sigma[2 * gate + 1]]);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }
    }
    std::array::from_fn(|i| v[i] ^ v[i + 8])
}

/// Two little-endian `u32` words as the 64-bit limb a memory cell holds.
pub const fn limb(lo: u32, hi: u32) -> u64 {
    lo as u64 | (hi as u64) << 32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(bytes: &[u8]) -> [u32; 16] {
        std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
    }

    /// The `blake3` crate's digests (1.8.7): one-block messages, and a two-block chunk chained.
    #[test]
    fn compression_is_blake3() {
        let (counter, len, flags) = ONE_BLOCK;
        let seq: Vec<u8> = (0u8..128).collect();
        assert_eq!(
            compress(&IV, &block(&seq[..64]), counter, len, flags),
            [
                0x4171ed4e, 0xd45c4aea, 0x6b6088b7, 0xe2463fd2, 0xac9caf12, 0x7ddcaceb, 0xc76d4c1f, 0x981b51f2
            ]
        );
        assert_eq!(
            compress(&IV, &[0; 16], counter, len, flags),
            [
                0x7669004d, 0x96866a63, 0x30a609d9, 0xad1a08a4, 0xf8507c4d, 0x04eefd1a, 0x50f00b02, 0x556aab86
            ]
        );
        let cv = compress(&IV, &block(&seq[..64]), 0, 64, 1);
        assert_eq!(
            compress(&cv, &block(&seq[64..]), 0, 64, 2 | 8),
            [
                0x05577ef1, 0x7865b264, 0xf4b73bc3, 0x39f54346, 0xdf054b62, 0x1fc8761a, 0x48d5ac30, 0xef454bc4
            ]
        );
    }
}
