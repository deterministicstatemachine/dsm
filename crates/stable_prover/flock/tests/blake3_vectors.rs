//! The patched compression is BLAKE3 compression: checked against the blake3 crate (1.8.7) digests.
use flock::hash::blake2s_compress as compress;

const IV: [u32; 8] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const ROOT: u32 = 8;

fn block(bytes: &[u8]) -> [u32; 16] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

#[test]
fn one_block_messages_are_blake3() {
    let seq: Vec<u8> = (0u8..64).collect();
    assert_eq!(
        compress(&IV, &block(&seq), 0, 64, CHUNK_START | CHUNK_END | ROOT),
        [0x4171ed4e, 0xd45c4aea, 0x6b6088b7, 0xe2463fd2, 0xac9caf12, 0x7ddcaceb, 0xc76d4c1f, 0x981b51f2]
    );
    assert_eq!(
        compress(&IV, &block(&[0u8; 64]), 0, 64, CHUNK_START | CHUNK_END | ROOT),
        [0x7669004d, 0x96866a63, 0x30a609d9, 0xad1a08a4, 0xf8507c4d, 0x04eefd1a, 0x50f00b02, 0x556aab86]
    );
}

#[test]
fn a_two_block_chunk_chains_as_blake3() {
    let seq: Vec<u8> = (0u8..128).collect();
    let cv = compress(&IV, &block(&seq[..64]), 0, 64, CHUNK_START);
    assert_eq!(
        compress(&cv, &block(&seq[64..]), 0, 64, CHUNK_END | ROOT),
        [0x05577ef1, 0x7865b264, 0xf4b73bc3, 0x39f54346, 0xdf054b62, 0x1fc8761a, 0x48d5ac30, 0xef454bc4]
    );
}
