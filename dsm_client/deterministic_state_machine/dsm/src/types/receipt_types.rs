//! Canonical Receipt Types
//!
//! This module implements the stitched receipt structures as specified in the
//! DSM whitepaper. Receipts are the fundamental cryptographic commitment objects
//! that bind state transitions, Merkle proofs, and signatures together.
//!
//! Key invariants:
//! - Canonical Protobuf encoding (deterministic, per whitepaper Sec. 4.2.1)
//! - Domain-separated BLAKE3 hashing
//! - Dual SPHINCS+ signatures (both parties)
//! - Inclusion proofs for old/new leaves and device binding

use crate::types::error::DsmError;
use std::collections::HashMap;

/// Canonical Stitched Receipt V2
///
/// This structure matches the whitepaper specification (Sec. "Receipt Construction").
/// It contains exactly 10 fields plus signatures, all encoded deterministically.
///
/// Fields correspond to the canonical commit form:
/// 1. genesis (32B)
/// 2. devid_a (32B)
/// 3. devid_b (32B)
/// 4. parent_tip (32B)
/// 5. child_tip (32B)
/// 6. parent_root (32B)
/// 7. child_root (32B)
/// 8. rel_proof_parent (variable bstr)
/// 9. rel_proof_child (variable bstr)
/// 10. dev_proof (variable bstr)
#[derive(Clone, Debug)]
pub struct StitchedReceiptV2 {
    /// Genesis hash (32 bytes)
    pub genesis: [u8; 32],

    /// Device ID of party A (32 bytes)
    pub devid_a: [u8; 32],

    /// Device ID of party B (32 bytes)
    pub devid_b: [u8; 32],

    /// Parent relationship tip hash (h_n, 32 bytes)
    pub parent_tip: [u8; 32],

    /// Child relationship tip hash (h_{n+1}, 32 bytes)
    pub child_tip: [u8; 32],

    /// Parent Per-Device SMT root (r_A, 32 bytes)
    pub parent_root: [u8; 32],

    /// Child Per-Device SMT root (r_A', 32 bytes)
    pub child_root: [u8; 32],

    /// Inclusion proof for parent_tip in parent_root (variable length)
    pub rel_proof_parent: Vec<u8>,

    /// Inclusion proof for child_tip in child_root (variable length)
    pub rel_proof_child: Vec<u8>,

    /// Inclusion proof for devid_a in Device Tree root R_G (variable length)
    pub dev_proof: Vec<u8>,

    /// Canonical SMT replace witness for relationship leaf update.
    ///
    /// This witness MUST allow a verifier to recompute `child_root` from `parent_root`
    /// by applying a single-leaf replace at the canonical relationship key.
    ///
    /// Encoding (deterministic, bytes-only):
    /// - `path` is an ordered list of sibling node hashes from leaf-level upward.
    /// - For each step i, `path[i].sibling` is 32 bytes.
    /// - `path[i].is_left` indicates whether the current hash is the left child (true)
    ///   or right child (false) when combining with sibling at that level.
    ///
    /// Domain separation for node hashing lives in the SMT verifier.
    pub rel_replace_witness: Vec<u8>,

    /// SPHINCS+ signature from party A over canonical commit bytes
    pub sig_a: Vec<u8>,

    /// SPHINCS+ signature from party B over canonical commit bytes
    pub sig_b: Vec<u8>,
}

impl StitchedReceiptV2 {
    /// Create a new receipt with all required fields
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis: [u8; 32],
        devid_a: [u8; 32],
        devid_b: [u8; 32],
        parent_tip: [u8; 32],
        child_tip: [u8; 32],
        parent_root: [u8; 32],
        child_root: [u8; 32],
        rel_proof_parent: Vec<u8>,
        rel_proof_child: Vec<u8>,
        dev_proof: Vec<u8>,
    ) -> Self {
        Self {
            genesis,
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            parent_root,
            child_root,
            rel_proof_parent,
            rel_proof_child,
            dev_proof,
            rel_replace_witness: Vec::new(),
            sig_a: Vec::new(),
            sig_b: Vec::new(),
        }
    }

    /// Set the relationship SMT replace witness bytes.
    pub fn set_rel_replace_witness(&mut self, w: Vec<u8>) {
        self.rel_replace_witness = w;
    }

    /// Convert to prost-generated `ReceiptCommit` (canonical form, no sigs).
    /// Proto3 omits empty bytes → encode_to_vec() produces fields 1-11 only.
    fn to_proto_canonical(&self) -> crate::types::proto::ReceiptCommit {
        crate::types::proto::ReceiptCommit {
            genesis: self.genesis.to_vec(),
            devid_a: self.devid_a.to_vec(),
            devid_b: self.devid_b.to_vec(),
            parent_tip: self.parent_tip.to_vec(),
            child_tip: self.child_tip.to_vec(),
            parent_root: self.parent_root.to_vec(),
            child_root: self.child_root.to_vec(),
            rel_proof_parent: self.rel_proof_parent.clone(),
            rel_proof_child: self.rel_proof_child.clone(),
            dev_proof: self.dev_proof.clone(),
            rel_replace_witness: self.rel_replace_witness.clone(),
            sig_a: vec![],
            sig_b: vec![],
        }
    }

    /// Convert to prost-generated `ReceiptCommit` (full form, with sigs).
    fn to_proto_full(&self) -> crate::types::proto::ReceiptCommit {
        let mut proto = self.to_proto_canonical();
        proto.sig_a.clone_from(&self.sig_a);
        proto.sig_b.clone_from(&self.sig_b);
        proto
    }

    /// Construct from prost-generated `ReceiptCommit`.
    fn from_proto(rc: crate::types::proto::ReceiptCommit) -> Result<Self, DsmError> {
        let copy32 = |src: &[u8], name: &str| -> Result<[u8; 32], DsmError> {
            if src.len() != 32 {
                return Err(DsmError::invalid_operation(format!(
                    "receipt field {name}: expected 32 bytes, got {}",
                    src.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(src);
            Ok(arr)
        };

        let mut receipt = Self::new(
            copy32(&rc.genesis, "genesis")?,
            copy32(&rc.devid_a, "devid_a")?,
            copy32(&rc.devid_b, "devid_b")?,
            copy32(&rc.parent_tip, "parent_tip")?,
            copy32(&rc.child_tip, "child_tip")?,
            copy32(&rc.parent_root, "parent_root")?,
            copy32(&rc.child_root, "child_root")?,
            rc.rel_proof_parent,
            rc.rel_proof_child,
            rc.dev_proof,
        );
        receipt.set_rel_replace_witness(rc.rel_replace_witness);
        if !rc.sig_a.is_empty() {
            receipt.add_sig_a(rc.sig_a);
        }
        if !rc.sig_b.is_empty() {
            receipt.add_sig_b(rc.sig_b);
        }
        Ok(receipt)
    }

    /// Decode a `StitchedReceiptV2` from protobuf bytes (canonical or full).
    ///
    /// Uses prost-generated `ReceiptCommit::decode()`. Accepts both canonical
    /// (fields 1-11) and full (fields 1-13 with sigs) encodings.
    pub fn from_canonical_protobuf(bytes: &[u8]) -> Result<Self, DsmError> {
        use prost::Message;
        let rc = crate::types::proto::ReceiptCommit::decode(bytes)
            .map_err(|e| DsmError::invalid_operation(format!("receipt decode: {e}")))?;
        Self::from_proto(rc)
    }

    /// Returns the canonical protobuf bytes for hashing/signing.
    ///
    /// Encodes fields 1-11 only (no signatures) via prost `ReceiptCommit`.
    /// Proto3 omits empty bytes fields, so sig_a/sig_b are excluded.
    /// Format: ReceiptCommit message as specified in whitepaper Sec. 4.2.1
    pub fn to_canonical_protobuf(&self) -> Result<Vec<u8>, DsmError> {
        use prost::Message;
        Ok(self.to_proto_canonical().encode_to_vec())
    }

    /// Returns the full wire protobuf bytes including signatures.
    ///
    /// Fields 1-11 are identical to `to_canonical_protobuf()` (the commitment
    /// preimage). Fields 12 (sig_a) and 13 (sig_b) are included when non-empty.
    /// Use this for transport; use `to_canonical_protobuf()` for commitment hashing.
    pub fn to_full_protobuf(&self) -> Result<Vec<u8>, DsmError> {
        use prost::Message;
        Ok(self.to_proto_full().encode_to_vec())
    }

    /// Compute the canonical commitment hash
    ///
    /// Per whitepaper: BLAKE3("DSM/receipt-commit\0" || canonical_protobuf_bytes)
    pub fn compute_commitment(&self) -> Result<[u8; 32], DsmError> {
        let protobuf_bytes = self.to_canonical_protobuf()?;

        // Domain-separated BLAKE3-256: BLAKE3("DSM/receipt-commit\0" || canonical_protobuf_bytes)
        let hash = crate::crypto::blake3::domain_hash("DSM/receipt-commit", &protobuf_bytes);
        Ok(*hash.as_bytes())
    }

    /// Add signature from party A
    pub fn add_sig_a(&mut self, sig: Vec<u8>) {
        self.sig_a = sig;
    }

    /// Add signature from party B
    pub fn add_sig_b(&mut self, sig: Vec<u8>) {
        self.sig_b = sig;
    }

    /// Check if both signatures are present
    pub fn is_fully_signed(&self) -> bool {
        !self.sig_a.is_empty() && !self.sig_b.is_empty()
    }

    /// Get total serialized size (canonical protobuf + signatures)
    pub fn serialized_size(&self) -> usize {
        let pb_size = self.to_canonical_protobuf().map(|b| b.len()).unwrap_or(0);
        pb_size + self.sig_a.len() + self.sig_b.len()
    }

    /// Validate size cap (≤128 KiB per whitepaper)
    pub fn validate_size_cap(&self) -> Result<(), DsmError> {
        const MAX_SIZE: usize = 128 * 1024; // 128 KiB
        let size = self.serialized_size();
        if size > MAX_SIZE {
            return Err(DsmError::InvalidOperation(format!(
                "Receipt exceeds size cap: {} > {} bytes",
                size, MAX_SIZE
            )));
        }
        Ok(())
    }

    /// Get canonical commitment (alias for compute_commitment)
    pub fn canonical_commit(&self) -> Result<[u8; 32], DsmError> {
        self.compute_commitment()
    }

    /// Get device ID A
    pub fn id_a(&self) -> &[u8; 32] {
        &self.devid_a
    }

    /// Get device ID B
    pub fn id_b(&self) -> &[u8; 32] {
        &self.devid_b
    }

    /// Extract sequence number from parent_tip hash
    /// In the canonical format, sequence is encoded in the tip hash chain
    pub fn t(&self) -> u64 {
        // The sequence number is implicitly in the tip hash chain
        // For compatibility, extract from last 8 bytes of parent_tip
        u64::from_le_bytes([
            self.parent_tip[24],
            self.parent_tip[25],
            self.parent_tip[26],
            self.parent_tip[27],
            self.parent_tip[28],
            self.parent_tip[29],
            self.parent_tip[30],
            self.parent_tip[31],
        ])
    }
}

/// Receipt verification context
///
/// Holds all data needed to verify a stitched receipt against acceptance predicates.
pub struct ReceiptVerificationContext {
    /// Device Tree root R_G
    pub device_tree_root: [u8; 32],

    /// Expected parent Per-Device SMT root
    pub expected_parent_root: [u8; 32],

    /// SPHINCS+ public key for party A
    pub pubkey_a: Vec<u8>,

    /// SPHINCS+ public key for party B
    pub pubkey_b: Vec<u8>,

    /// Set of previously consumed parent tips (for uniqueness check)
    pub consumed_parents: std::collections::HashSet<[u8; 32]>,
}

impl ReceiptVerificationContext {
    pub fn new(
        device_tree_root: [u8; 32],
        expected_parent_root: [u8; 32],
        pubkey_a: Vec<u8>,
        pubkey_b: Vec<u8>,
    ) -> Self {
        Self {
            device_tree_root,
            expected_parent_root,
            pubkey_a,
            pubkey_b,
            consumed_parents: std::collections::HashSet::new(),
        }
    }

    /// Mark a parent tip as consumed
    pub fn mark_consumed(&mut self, parent_tip: [u8; 32]) {
        self.consumed_parents.insert(parent_tip);
    }

    /// Check if parent has been consumed
    pub fn is_consumed(&self, parent_tip: &[u8; 32]) -> bool {
        self.consumed_parents.contains(parent_tip)
    }
}

/// Receipt acceptance result
#[derive(Debug, Clone)]
pub struct ReceiptAcceptance {
    /// Whether the receipt is valid
    pub valid: bool,

    /// Detailed reason if invalid
    pub reason: Option<String>,

    /// Computed commitment hash
    pub commitment: Option<[u8; 32]>,
}

impl ReceiptAcceptance {
    pub fn accept(commitment: [u8; 32]) -> Self {
        Self {
            valid: true,
            reason: None,
            commitment: Some(commitment),
        }
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: Some(reason.into()),
            commitment: None,
        }
    }
}

/// Parent consumption tracker
///
/// Tracks which parent tips have been consumed to enforce uniqueness
/// and detect fork attempts.
#[derive(Default)]
pub struct ParentConsumptionTracker {
    /// Map: parent_tip -> child_tip
    consumed: HashMap<[u8; 32], [u8; 32]>,
}

impl ParentConsumptionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn with_capacity(_capacity: usize) -> Self {
        // Capacity is ignored, kept for API compatibility
        Self::new()
    }

    /// Try to consume a parent tip
    ///
    /// Returns Ok(()) if parent is fresh, Err if already consumed.
    pub fn try_consume(
        &mut self,
        parent_tip: [u8; 32],
        child_tip: [u8; 32],
    ) -> Result<(), DsmError> {
        if let Some(existing_child) = self.consumed.get(&parent_tip) {
            if existing_child == &child_tip {
                // Idempotent: same transition attempted twice (replay)
                return Err(DsmError::InvalidOperation(
                    "Parent already consumed (replay detected)".to_string(),
                ));
            } else {
                // Fork: different children for same parent
                return Err(DsmError::InvalidOperation(format!(
                    "Fork detected: parent {:?} has conflicting children",
                    &parent_tip[..8]
                )));
            }
        }

        // Fresh parent: mark as consumed
        self.consumed.insert(parent_tip, child_tip);
        Ok(())
    }

    /// Check if parent is consumed (read-only)
    pub fn is_consumed(&self, parent_tip: &[u8; 32]) -> bool {
        self.consumed.contains_key(parent_tip)
    }

    /// Get the child for a consumed parent (if any)
    pub fn get_child(&self, parent_tip: &[u8; 32]) -> Option<&[u8; 32]> {
        self.consumed.get(parent_tip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_protobuf_includes_rel_replace_witness_field_11() {
        let mut receipt = StitchedReceiptV2::new(
            [0x00; 32],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            vec![1, 2, 3],
            vec![4, 5],
            vec![6],
        );
        receipt.set_rel_replace_witness(vec![9, 9, 9, 9]);
        let pb = receipt.to_canonical_protobuf().expect("protobuf");
        // Field 11 tag = (11 << 3) | 2 = 0x5a. Ensure it exists.
        assert!(pb.contains(&0x5a), "missing field 11 tag");
    }

    #[test]
    fn test_commitment_hash() {
        let receipt = StitchedReceiptV2::new(
            [0x00; 32],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            vec![],
            vec![],
            vec![],
        );

        let commitment = receipt.compute_commitment().unwrap();

        // Should produce a 32-byte hash
        assert_eq!(commitment.len(), 32);

        // Should be deterministic
        let commitment2 = receipt.compute_commitment().unwrap();
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_parent_consumption_tracker() {
        let mut tracker = ParentConsumptionTracker::new();

        let parent = [0xaa; 32];
        let child1 = [0xbb; 32];
        let child2 = [0xcc; 32];

        // First consumption should succeed
        assert!(tracker.try_consume(parent, child1).is_ok());

        // Second consumption with same child (replay) should fail
        assert!(tracker.try_consume(parent, child1).is_err());

        // Consumption with different child (fork) should fail
        assert!(tracker.try_consume(parent, child2).is_err());

        // Query
        assert!(tracker.is_consumed(&parent));
        assert_eq!(tracker.get_child(&parent), Some(&child1));
    }

    #[test]
    fn fork_rejects_duplicate_parent() {
        let mut tracker = ParentConsumptionTracker::new();

        let parent = [0x01; 32];
        let child_a = [0x02; 32];
        let child_b = [0x03; 32];

        // First consume establishes the canonical child for this parent tip
        tracker
            .try_consume(parent, child_a)
            .expect("first consumption must succeed");

        // A different child for the same parent must trip the fork exclusion gate
        let err = tracker
            .try_consume(parent, child_b)
            .expect_err("fork must be rejected deterministically");
        let msg = format!("{err}");
        assert!(
            msg.contains("Fork detected"),
            "error should explain fork tripwire; got: {msg}"
        );

        // Ensure original mapping is preserved and no overwrite occurred
        assert_eq!(tracker.get_child(&parent), Some(&child_a));
    }

    #[test]
    fn test_prost_canonical_roundtrip() {
        let mut receipt = StitchedReceiptV2::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            [7u8; 32],
            vec![8u8; 64],
            vec![9u8; 64],
            vec![10u8; 16],
        );
        receipt.set_rel_replace_witness(vec![0, 0, 0, 0]);

        let canonical = receipt.to_canonical_protobuf().unwrap();
        let decoded = StitchedReceiptV2::from_canonical_protobuf(&canonical).unwrap();
        assert_eq!(decoded.genesis, receipt.genesis);
        assert_eq!(decoded.devid_a, receipt.devid_a);
        assert_eq!(decoded.devid_b, receipt.devid_b);
        assert_eq!(decoded.parent_tip, receipt.parent_tip);
        assert_eq!(decoded.child_tip, receipt.child_tip);
        assert_eq!(decoded.parent_root, receipt.parent_root);
        assert_eq!(decoded.child_root, receipt.child_root);
        assert_eq!(decoded.rel_proof_parent, receipt.rel_proof_parent);
        assert_eq!(decoded.rel_proof_child, receipt.rel_proof_child);
        assert_eq!(decoded.dev_proof, receipt.dev_proof);
        assert_eq!(decoded.rel_replace_witness, receipt.rel_replace_witness);
        assert!(decoded.sig_a.is_empty());
        assert!(decoded.sig_b.is_empty());

        // Commitment stability: encode → decode → re-encode must match
        let commit1 = receipt.compute_commitment().unwrap();
        let commit2 = decoded.compute_commitment().unwrap();
        assert_eq!(commit1, commit2);
    }

    #[test]
    fn test_prost_full_roundtrip_with_sigs() {
        let mut receipt = StitchedReceiptV2::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            [7u8; 32],
            vec![8u8; 64],
            vec![9u8; 64],
            vec![10u8; 16],
        );
        receipt.set_rel_replace_witness(vec![0, 0, 0, 0]);
        receipt.add_sig_a(vec![0xAA; 128]);
        receipt.add_sig_b(vec![0xBB; 128]);

        let full = receipt.to_full_protobuf().unwrap();
        let decoded = StitchedReceiptV2::from_canonical_protobuf(&full).unwrap();
        assert_eq!(decoded.sig_a, vec![0xAA; 128]);
        assert_eq!(decoded.sig_b, vec![0xBB; 128]);

        // Canonical bytes should NOT include sigs
        let canonical = receipt.to_canonical_protobuf().unwrap();
        assert!(canonical.len() < full.len());

        // Canonical commitment must be the same regardless of sigs
        let commit_unsigned = StitchedReceiptV2::from_canonical_protobuf(&canonical)
            .unwrap()
            .compute_commitment()
            .unwrap();
        let commit_signed = decoded.compute_commitment().unwrap();
        assert_eq!(commit_unsigned, commit_signed);
    }

    #[test]
    fn test_prost_encoding_tag_format() {
        let mut receipt = StitchedReceiptV2::new(
            [0x42u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            [7u8; 32],
            vec![8u8; 4],
            vec![9u8; 4],
            vec![10u8; 4],
        );
        receipt.set_rel_replace_witness(vec![0, 0, 0, 0]);

        let bytes = receipt.to_canonical_protobuf().unwrap();
        // Tag 1, wire type 2 (length-delimited) = (1 << 3) | 2 = 0x0A
        assert_eq!(bytes[0], 0x0A);
        // Length 32 = 0x20
        assert_eq!(bytes[1], 0x20);
        // Content: genesis [0x42; 32]
        assert_eq!(&bytes[2..34], &[0x42u8; 32]);
    }

    #[test]
    fn test_size_cap_enforcement() {
        let mut receipt = StitchedReceiptV2::new(
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            vec![],
            vec![],
            vec![],
        );

        // Small receipt should pass
        assert!(receipt.validate_size_cap().is_ok());

        // Add huge proofs to exceed cap
        receipt.rel_proof_parent = vec![0u8; 64 * 1024]; // 64 KiB
        receipt.rel_proof_child = vec![0u8; 64 * 1024]; // 64 KiB

        // Should exceed 128 KiB cap
        assert!(receipt.validate_size_cap().is_err());
    }
}

#[cfg(test)]
#[test]
fn print_test_vector_hash_for_spec() {
    // Intentionally empty. We do not print hex or canonical bytes from core tests.
    // Canonical commit fixtures should live as byte-exact Protobuf files alongside
    // expected digests, not as debug-print output.
}
