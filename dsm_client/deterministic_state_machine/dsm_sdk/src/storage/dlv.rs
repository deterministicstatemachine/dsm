//! Client-side DLV helpers mirroring storage node derivations.
//! No network I/O, pure computations for routable addresses.

use blake3::Hasher;

const DOMAIN_OBJECT: &[u8] = b"DSM/object\0";

fn blake3_tagged(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts { h.update(p); }
    h.finalize().into()
}

/// Compute address for an object placed under a DLV slot.
/// - dlv_i: 32-byte slot id
/// - path: canonical path bytes (client-determined layout)
/// - content_hash: BLAKE3-256 of content bytes
pub fn object_address(dlv_i: &[u8], path: &[u8], content_hash: &[u8]) -> [u8;32] {
    blake3_tagged(DOMAIN_OBJECT, &[dlv_i, path, content_hash])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addr_nonzero() {
        let addr = object_address(&[1u8;32], b"/x", &[2u8;32]);
        assert_ne!(addr, [0u8;32]);
    }
}
