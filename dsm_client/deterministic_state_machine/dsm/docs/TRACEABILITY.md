# Stitched Receipts Traceability

This document maps whitepaper elements to concrete code and tests.

- Spec sections: DSM whitepaper (docs/WHITEPAPER.md), Stitched Receipts (v2)

Definitions and invariants -> Code
- Relationship key ki = H("DSM/rel" || IDi)
  - Code: src/bilateral/receipt.rs: derive_relationship_key()
- Receipt payload τA→B fields and deterministic encoding
  - Code: src/bilateral/receipt.rs: StitchedReceiptV2, to_bytes() via postcard
- Inclusion proofs VerifyIncl(r, ki -> hi, π)
  - Code: merkle/sparse_merkle_tree.rs: SparseMerkleTreeImpl::verify_proof
  - Used in: src/bilateral/receipt.rs: verify_stitched_receipt()
- Deterministic replay Update(r_prev, ki, h'i) == r_next
  - Code: src/bilateral/receipt.rs: recompute_root_with_value()
- Countersignatures Σ.Vrfy(pkA, mA, σA), Σ.Vrfy(pkB, mB, σB)
  - Code: src/bilateral/receipt.rs: verify_stitched_receipt() via crypto::sphincs

Acceptance rules -> Code
- Local predicate: t == t_local + 1
  - Code: src/bilateral/receipt.rs: verify_stitched_receipt()
- Duplicate guard on (r_prev, ki)
  - Code: src/bilateral/receipt.rs: ReceiptGuard

Tests
- Negative: t mismatch rejected
  - Test: tests/receipt_tests.rs::test_receipt_t_mismatch_rejected
- Negative: deterministic replay mismatch rejected
  - Test: tests/receipt_tests.rs::test_receipt_replay_mismatch_rejected
- Positive: happy path and duplicate guard
  - Test: src/bilateral/receipt.rs::tests::stitched_receipt_happy_path

Cryptographic primitives
- Hashing: blake3 with domain separation
  - Code: src/bilateral/receipt.rs: domain_hash(), replay hashing
- Signatures: SPHINCS+
  - Code: crypto/sphincs.rs: sphincs_sign/sphincs_verify

Notes
- Storage nodes are passive; all checks are purely cryptographic and local.
- SMT domain prefixes (0x00 leaf, 0x01 node) match tree implementation.
