fn test() {
    let tr_bytes = vec![1, 2, 3];
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/merkle-leaf");
    hasher.update(&tr_bytes);
    let leaf_hash = hasher.finalize().as_bytes().clone();

    // The state hash is the verification_state. We need a tree where root == verification_state?
}
