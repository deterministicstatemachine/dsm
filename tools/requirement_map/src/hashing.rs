// SPDX-License-Identifier: MIT OR Apache-2.0
//! The BLAKE3 domains of the map and the one framing every hash uses.

use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::domain::TaggedHashDomain;
use dsm::utils::text_id::encode_base32_crockford;

/// Every listed source file, in list order: what an index was built from.
pub const TREE: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/code-tree/v1");
/// One source file: its path and its bytes.
pub const FILE: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/code-file/v1");
/// One definition: its symbol and its token text.
pub const ITEM: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/code-item/v1");
/// A symbol the index references but does not define (std, a dependency).
pub const EXTERNAL: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/code-external/v1");
/// A workspace symbol the index has no definition of (prost output, a
/// macro's item): its symbol and the inputs that generate it.
pub const GENERATED: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/code-generated/v1");
/// What generates a package's code the index cannot define: its build
/// script, the module file its path names, every `.proto` file and every
/// macro definition.
pub const GENERATION: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/code-generation-inputs/v1");
/// A strongly connected component: its members' items and its callees' closures.
pub const COMPONENT: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/code-component/v1");
/// One definition and everything it reaches.
pub const CLOSURE: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/code-closure/v1");

pub type Digest = [u8; 32];

/// Each part is preceded by its length, so two different part lists never
/// share an encoding.
pub fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

pub fn hash(domain: TaggedHashDomain<'static>, parts: &[&[u8]]) -> Digest {
    domain_hash_bytes(domain, &framed(parts))
}

pub fn text(digest: &Digest) -> String {
    encode_base32_crockford(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_separates_part_boundaries() {
        assert_ne!(framed(&[b"ab", b"c"]), framed(&[b"a", b"bc"]));
        assert_ne!(hash(ITEM, &[b"ab", b"c"]), hash(ITEM, &[b"a", b"bc"]));
    }

    #[test]
    fn domains_separate_equal_payloads() {
        assert_ne!(hash(ITEM, &[b"x"]), hash(CLOSURE, &[b"x"]));
        assert_ne!(hash(EXTERNAL, &[b"x"]), hash(COMPONENT, &[b"x"]));
        assert_ne!(hash(FILE, &[b"x"]), hash(ITEM, &[b"x"]));
        assert_ne!(hash(GENERATED, &[b"x"]), hash(EXTERNAL, &[b"x"]));
        assert_ne!(hash(GENERATION, &[b"x"]), hash(GENERATED, &[b"x"]));
    }

    #[test]
    fn digests_display_as_crockford_base32() {
        let shown = text(&hash(CLOSURE, &[b"item"]));
        assert_eq!(shown.len(), 52);
        assert!(shown
            .chars()
            .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
    }
}
