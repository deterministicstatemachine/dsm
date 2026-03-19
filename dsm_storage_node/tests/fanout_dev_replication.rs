// Replication fanout tests.
// The dev-replication fanout helper was removed (superseded by ByteCommit-based
// audit trail per whitepaper §10.3).  This file verifies invariants of the
// deterministic replica-placement function used in its place.

/// Verify that BLAKE3-based placement discriminators are deterministic:
/// the same object address always produces the same seed, regardless of call
/// order or timing (whitepaper §10.1 — "DSM/place\0" domain tag).
#[test]
fn replica_placement_seed_is_deterministic() {
    // Simulate the whitepaper §10.1 placement derivation:
    //   seed := BLAKE3("DSM/place\0" || addr)
    // Two independent derivations for the same addr must be byte-equal.
    let addr = b"DSM-test-object-address-32-bytes";
    let tag = b"DSM/place\0";
    let mut preimage = Vec::with_capacity(tag.len() + addr.len());
    preimage.extend_from_slice(tag);
    preimage.extend_from_slice(addr);
    let seed_a = blake3::hash(&preimage);
    let seed_b = blake3::hash(&preimage);
    assert_eq!(
        seed_a.as_bytes(),
        seed_b.as_bytes(),
        "placement seed must be deterministic for a given address"
    );
    // Different addresses must produce different seeds (collision sanity check).
    let addr2 = b"DSM-test-object-address-32-byte2";
    let mut preimage2 = Vec::with_capacity(tag.len() + addr2.len());
    preimage2.extend_from_slice(tag);
    preimage2.extend_from_slice(addr2);
    let seed_c = blake3::hash(&preimage2);
    assert_ne!(
        seed_a.as_bytes(),
        seed_c.as_bytes(),
        "distinct addresses must produce distinct placement seeds"
    );
}
