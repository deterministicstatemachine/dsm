// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable content-addressed storage — the Area 4 address derivation.
//!
//! Rev 15 §15.3, for a payload `P` in namespace `N`, written with the
//! registry's pinned `H_dom(d, x) = BLAKE3(d ‖ 0x00 ‖ x)`:
//!
//! ```text
//! inner(N, P) = H_dom(N, P)
//! addr(N, P)  = H_dom(DSM/storage-object, N_bytes ‖ inner(N, P))
//! ```
//!
//! `N_bytes` is the namespace tag's ASCII spelling without a trailing NUL. It
//! is variable-length but followed by a fixed 32-byte digest, so the
//! concatenation is unambiguous — the only reason no length prefix is needed.
//!
//! **The address is a pure function of `(N, P)`.** No path, no partition id,
//! no writer identity, no clock. Two independent publishers of identical
//! bytes compute the identical address, which is what makes Req 15.2's
//! idempotence meaningful rather than accidental — and it is the property the
//! burned `addr := H(DSM/object ‖ dlv_id ‖ path ‖ …)` derivation lacked.
//!
//! **Specialization for registered CCB objects.** When `P = CCB(o)` and `N`
//! is the identity domain the registry declares for `o`'s class,
//! `inner(N, CCB(o))` **is** `id(o)` — for `V_n`, `inner` is exactly `c_n`.
//! Nothing is recomputed and no second identity exists; the substrate
//! addresses the digest the object already has, which is why a verifier
//! holding `c_n` computes the fetch address directly with no index and no
//! lookup: [`immutable_addr_from_inner`].
//!
//! The namespace check splits, and the split is forced: verifying that `N`
//! matches the class inside a CCB payload requires decoding it, which is the
//! one thing a storage node must never do. The node checks the *arithmetic*
//! (address correctness); the consumer checks the *agreement* (that the class
//! it decoded declares the namespace it queried under), after re-hash and
//! before use.

use crate::common::domain_tags::TAG_DSM_STORAGE_OBJECT;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;

/// `inner(N, P) = H_dom(N, P)`.
pub fn immutable_inner(namespace: TaggedHashDomain<'_>, payload: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(namespace);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// `addr(N, P) = H_dom(DSM/storage-object, N_bytes ‖ inner(N, P))`.
pub fn immutable_addr(namespace: TaggedHashDomain<'_>, payload: &[u8]) -> [u8; 32] {
    immutable_addr_from_inner(namespace, &immutable_inner(namespace, payload))
}

/// The address from a namespace and an already-known inner digest.
///
/// For a registered CCB object the inner digest is the object's identity —
/// `c_n` for `V_n` — so a verifier that holds the identity computes the
/// address without holding the bytes. This is what makes "resolve `c_n` to
/// exact bytes" a computation rather than a discovery step.
pub fn immutable_addr_from_inner(namespace: TaggedHashDomain<'_>, inner: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_STORAGE_OBJECT);
    h.update(namespace.source_bytes());
    h.update(inner);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::domain_tags::TAG_DSM_VAULT_STATE;

    /// The full construction matches an independent recomputation whose
    /// domain tags are typed from the SPEC, not read from the constants —
    /// the provenance rule from the `DSM/storage-set/v1` miss.
    #[test]
    fn the_address_matches_the_spec_construction() {
        let payload = b"arbitrary payload bytes";
        let addr = immutable_addr(TAG_DSM_VAULT_STATE, payload);

        // inner = BLAKE3("DSM/vault-state" ‖ 0x00 ‖ P)
        let mut inner_pre = b"DSM/vault-state".to_vec();
        inner_pre.push(0x00);
        inner_pre.extend_from_slice(payload);
        let inner: [u8; 32] = *blake3::hash(&inner_pre).as_bytes();

        // addr = BLAKE3("DSM/storage-object" ‖ 0x00 ‖ "DSM/vault-state" ‖ inner)
        let mut addr_pre = b"DSM/storage-object".to_vec();
        addr_pre.push(0x00);
        addr_pre.extend_from_slice(b"DSM/vault-state");
        addr_pre.extend_from_slice(&inner);
        let expected: [u8; 32] = *blake3::hash(&addr_pre).as_bytes();

        assert_eq!(addr, expected);
    }

    /// Obligation: the address is a pure function of `(N, P)`. Identical
    /// bytes always produce the identical address — there is no path or
    /// partition input for two publishers to disagree about, structurally.
    #[test]
    fn identical_bytes_produce_the_identical_address() {
        let a = immutable_addr(TAG_DSM_VAULT_STATE, b"same bytes");
        let b = immutable_addr(TAG_DSM_VAULT_STATE, b"same bytes");
        assert_eq!(a, b);
    }

    /// The namespace is load-bearing: the same payload under two namespaces
    /// has two addresses, so a publisher cannot smuggle bytes from one
    /// class's namespace into another's.
    #[test]
    fn the_namespace_separates_addresses() {
        use crate::common::domain_tags::TAG_DSM_GENESIS_V3;
        let p = b"same payload";
        assert_ne!(
            immutable_addr(TAG_DSM_VAULT_STATE, p),
            immutable_addr(TAG_DSM_GENESIS_V3, p),
        );
    }

    /// The identity-to-address shortcut agrees with the full derivation, and
    /// for `V_n` the inner digest IS `c_n`.
    #[test]
    fn the_inner_shortcut_agrees_and_is_c_n_for_vault_state() {
        let payload = b"stand-in for CCB(V_n)";
        let inner = immutable_inner(TAG_DSM_VAULT_STATE, payload);
        assert_eq!(
            immutable_addr(TAG_DSM_VAULT_STATE, payload),
            immutable_addr_from_inner(TAG_DSM_VAULT_STATE, &inner),
        );

        // inner over the vault-state namespace is the c_n construction.
        let mut c_n_pre = b"DSM/vault-state".to_vec();
        c_n_pre.push(0x00);
        c_n_pre.extend_from_slice(payload);
        let c_n: [u8; 32] = *blake3::hash(&c_n_pre).as_bytes();
        assert_eq!(inner, c_n);
    }
}
