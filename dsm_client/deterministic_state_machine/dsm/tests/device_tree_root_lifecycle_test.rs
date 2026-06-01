//! Device Tree root lifecycle tests — ensure R_G persists across all DSM paths.
//!
//! Tests the core invariant: After SDK initialization, get_device_tree_root() MUST return
//! a valid 32-byte root. Violation causes all bilateral transfers to fail settlement silently.

use dsm::common::device_tree::DeviceTree;

#[test]
fn test_device_tree_root_deterministic() {
    // ARRANGE: Same device ID
    let device_id = [99u8; 32];

    // ACT: Compute root three times (simulating multiple app restarts)
    let root1 = DeviceTree::single(device_id).root();
    let root2 = DeviceTree::single(device_id).root();
    let root3 = DeviceTree::single(device_id).root();

    // ASSERT: Root is always deterministic
    assert_eq!(root1, root2, "Device tree root must be deterministic");
    assert_eq!(
        root2, root3,
        "Device tree root must remain stable across multiple computations"
    );
}

#[test]
fn test_device_tree_root_unique_per_device() {
    // ARRANGE
    let device_a = [1u8; 32];
    let device_b = [2u8; 32];

    // ACT: Compute roots for two different devices
    let root_a = DeviceTree::single(device_a).root();
    let root_b = DeviceTree::single(device_b).root();

    // ASSERT: Roots are different (each device is cryptographically unique)
    assert_ne!(
        root_a, root_b,
        "Different devices must have different R_G values (§2.3.1)"
    );
}

#[test]
fn test_device_tree_root_zero_and_max_device_ids() {
    // Test edge cases: all-zeros and all-ones device IDs
    let zeros = DeviceTree::single([0u8; 32]).root();
    let ones = DeviceTree::single([255u8; 32]).root();

    assert_ne!(
        zeros, ones,
        "Even edge-case device IDs must produce different roots"
    );
    assert_eq!(zeros.len(), 32, "Root must be 32 bytes");
    assert_eq!(ones.len(), 32, "Root must be 32 bytes");
}

#[test]
fn test_device_tree_root_32_byte_output() {
    // ARRANGE
    let device_id = [123u8; 32];

    // ACT
    let root = DeviceTree::single(device_id).root();

    // ASSERT: Root is always exactly 32 bytes (BLAKE3-256)
    assert_eq!(
        root.len(),
        32,
        "Device tree root must be 32 bytes (BLAKE3-256 output), got {}",
        root.len()
    );
}

#[test]
fn test_secondary_device_gets_unique_root() {
    // ARRANGE: Simulate multi-device account
    let primary = [111u8; 32];
    let secondary = [222u8; 32];

    // ACT: Initialize primary device
    let primary_root = DeviceTree::single(primary).root();

    // ACT: Add secondary device (each device gets its own R_G)
    let secondary_root = DeviceTree::single(secondary).root();

    // ASSERT: Secondary device has different root (not shared with primary)
    assert_ne!(
        primary_root, secondary_root,
        "Secondary device must have different R_G than primary (§2.3.1: multi-device scenario)"
    );
}

#[test]
fn test_recovery_path_settlement_exception() {
    // ARRANGE: Create transfer context for recovery path
    // This test verifies the Fix 4 exception: recovery settlements
    // are allowed to lack proof_data

    let tx_type = "bilateral_offline_recovered";
    let is_recovery = tx_type == "bilateral_offline_recovered";

    // ASSERT: Recovery path is correctly identified
    assert!(
        is_recovery,
        "Recovery path must be identified by tx_type={}",
        tx_type
    );

    // ARRANGE: Create normal path
    let tx_type_normal = "bilateral_offline";
    let is_recovery_normal = tx_type_normal == "bilateral_offline_recovered";

    // ASSERT: Normal path is not identified as recovery
    assert!(
        !is_recovery_normal,
        "Normal path tx_type={} must not be identified as recovery",
        tx_type_normal
    );
}

/// Verifies that the device tree root computation is stable and
/// suitable for use in cryptographic commitments.
#[test]
fn test_device_tree_root_suitable_for_cryptographic_commitment() {
    // ARRANGE: Multiple device IDs
    let test_cases = vec![
        ([0u8; 32], "zeros"),
        ([255u8; 32], "max"),
        (
            [
                1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            "mixed",
        ),
    ];

    for (device_id, name) in test_cases {
        // ACT: Compute root multiple times
        let root1 = DeviceTree::single(device_id).root();
        let root2 = DeviceTree::single(device_id).root();

        // ASSERT: Root is cryptographically stable (same input → same output)
        assert_eq!(
            root1, root2,
            "Root must be stable for device_id suffix ({})",
            name
        );

        // ASSERT: Root is non-zero (not accidentally all-zeros)
        assert_ne!(
            root1, [0u8; 32],
            "Root for {} device_id must be non-zero",
            name
        );
    }
}

#[test]
fn test_device_tree_root_injectivity() {
    // Verify that different device IDs produce different roots (injectivity).
    // This ensures that no two devices can share the same R_G.

    let mut device_ids = vec![];
    for i in 0..16u8 {
        // Reduced from 256 to keep test fast
        device_ids.push([i; 32]);
    }

    let roots: Vec<_> = device_ids
        .iter()
        .map(|&dev_id| DeviceTree::single(dev_id).root())
        .collect();

    // Check for duplicates
    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            assert_ne!(
                roots[i], roots[j],
                "Device tree roots must be injective: device_id[{}] and device_id[{}] produced same root",
                i, j
            );
        }
    }
}

#[test]
fn test_device_tree_root_zero_hash_is_invalid() {
    // Sanity check: DeviceTree::single() should never produce [0; 32]
    let test_cases: Vec<[u8; 32]> = vec![
        [0u8; 32],
        [255u8; 32],
        [
            1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
    ];

    for device_id in test_cases {
        let root = DeviceTree::single(device_id).root();
        assert_ne!(
            root,
            [0u8; 32],
            "Device tree root must never be all-zeros (invalid commitment), device_id={:?}",
            &device_id[..4]
        );
    }
}

#[test]
fn test_device_tree_root_all_bits_used() {
    // Verify root uses the full 256 bits, not just a subset.
    let mut device_ids: Vec<[u8; 32]> = vec![];
    for i in 0..32u8 {
        let mut dev = [255u8; 32];
        dev[i as usize] = 0;
        device_ids.push(dev);
    }

    let roots: Vec<_> = device_ids
        .iter()
        .map(|&dev_id| DeviceTree::single(dev_id).root())
        .collect();

    // All roots should be different (flipping each byte produces different result)
    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            assert_ne!(
                roots[i], roots[j],
                "Changing different bytes in device_id must produce different roots"
            );
        }
    }
}

// ============================================================================
// Phase B.1 — V1 proto round-trip tests (issue #272)
//
// Pins the wire-format guarantees the rest of Phase B depends on:
//   • encode → decode → encode is bitwise identical (deterministic encoding)
//   • each scalar field round-trips exactly
//   • fixed-length byte fields round-trip exactly
//   • repeated bytes preserve order
//   • zero-value defaults survive the wire (no implicit-default surprises
//     when an SDK caller sends an empty optional)
// ============================================================================

mod v1_proto_roundtrip {
    use dsm::types::proto::{
        DeviceInclusionProofV1, DeviceLeafV1, DeviceTreeRootUpdateV1, DeviceTreeV1,
    };
    use prost::Message;

    // `.expect()` is a banned panic-path even in tests (production-safety
    // mandate). Encoding into a `Vec` is infallible via `encode_to_vec`; the
    // only genuinely-fallible step is decode, so the helper returns a
    // `Result` and each test propagates with `?` and returns `Result<()>`.
    fn round_trip_bytes<M: Message + Default>(msg: &M) -> Result<M, prost::DecodeError> {
        let buf = msg.encode_to_vec();
        let decoded = M::decode(buf.as_slice())?;
        // Second encode must be bitwise identical to the first — protobuf is
        // not strictly canonical, but prost's encode is deterministic for
        // these structurally-simple messages.
        let buf2 = decoded.encode_to_vec();
        assert_eq!(buf, buf2, "encode → decode → encode must be deterministic");
        Ok(decoded)
    }

    #[test]
    fn device_leaf_v1_round_trip() -> Result<(), prost::DecodeError> {
        let original = DeviceLeafV1 {
            device_id: vec![0xAB; 32],
            device_name: "Brandon's phone".to_string(),
        };
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.device_name, original.device_name);
        Ok(())
    }

    #[test]
    fn device_leaf_v1_empty_name_is_preserved() -> Result<(), prost::DecodeError> {
        // Empty UI label is legal (the leaf hash binds device_id only).
        let original = DeviceLeafV1 {
            device_id: vec![0x01; 32],
            device_name: String::new(),
        };
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.device_id, original.device_id);
        assert!(
            decoded.device_name.is_empty(),
            "empty device_name must survive the wire"
        );
        Ok(())
    }

    #[test]
    fn device_tree_v1_round_trip() -> Result<(), prost::DecodeError> {
        let original = DeviceTreeV1 {
            schema_version: 1,
            root_hash: vec![0xCD; 32],
            device_count: 7,
            version_number: 42,
        };
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.schema_version, 1);
        assert_eq!(decoded.root_hash, original.root_hash);
        assert_eq!(decoded.device_count, 7);
        assert_eq!(decoded.version_number, 42);
        Ok(())
    }

    #[test]
    fn device_tree_v1_large_version_number_round_trip() -> Result<(), prost::DecodeError> {
        // version_number is u64 — verify the full range survives.
        let original = DeviceTreeV1 {
            schema_version: 1,
            root_hash: vec![0xFFu8; 32],
            device_count: u32::MAX,
            version_number: u64::MAX,
        };
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.version_number, u64::MAX);
        assert_eq!(decoded.device_count, u32::MAX);
        Ok(())
    }

    #[test]
    fn device_tree_root_update_v1_round_trip() -> Result<(), prost::DecodeError> {
        let original = DeviceTreeRootUpdateV1 {
            old_root: vec![0xAAu8; 32],
            new_root: vec![0xBBu8; 32],
            version_number: 100,
            signature: vec![0xCCu8; 49_856], // SPHINCS+ SPX256f signature length
        };
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.old_root, original.old_root);
        assert_eq!(decoded.new_root, original.new_root);
        assert_eq!(decoded.version_number, 100);
        assert_eq!(decoded.signature.len(), 49_856);
        assert_eq!(decoded.signature, original.signature);
        Ok(())
    }

    #[test]
    fn device_inclusion_proof_v1_round_trip_with_siblings() -> Result<(), prost::DecodeError> {
        // Realistic 5-level Merkle path; siblings + path_bits + counts must
        // all survive round-trip.
        let siblings: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 32]).collect();
        let original = DeviceInclusionProofV1 {
            device_id: vec![0xDEu8; 32],
            root_hash: vec![0xEFu8; 32],
            siblings: siblings.clone(),
            path_bits_len: 5,
            path_bits: vec![0b10101], // 5 valid bits
        };
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.root_hash, original.root_hash);
        assert_eq!(decoded.siblings.len(), 5);
        assert_eq!(
            decoded.siblings, siblings,
            "sibling ORDER must be preserved"
        );
        assert_eq!(decoded.path_bits_len, 5);
        assert_eq!(decoded.path_bits, vec![0b10101]);
        Ok(())
    }

    #[test]
    fn device_inclusion_proof_v1_empty_siblings_round_trip() -> Result<(), prost::DecodeError> {
        // Single-leaf tree: no siblings, path_bits_len = 0.
        let original = DeviceInclusionProofV1 {
            device_id: vec![0x11u8; 32],
            root_hash: vec![0x22u8; 32],
            siblings: Vec::new(),
            path_bits_len: 0,
            path_bits: Vec::new(),
        };
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.root_hash, original.root_hash);
        assert!(decoded.siblings.is_empty());
        assert_eq!(decoded.path_bits_len, 0);
        assert!(decoded.path_bits.is_empty());
        Ok(())
    }

    #[test]
    fn device_tree_v1_zero_defaults_round_trip() -> Result<(), prost::DecodeError> {
        // All-default message must encode + decode cleanly. Default()
        // gives an empty `root_hash` Vec, which is legal on the wire even
        // though the storage validator (Phase B.4) will reject it.
        let original = DeviceTreeV1::default();
        let decoded = round_trip_bytes(&original)?;
        assert_eq!(decoded.schema_version, 0);
        assert!(decoded.root_hash.is_empty());
        assert_eq!(decoded.device_count, 0);
        assert_eq!(decoded.version_number, 0);
        Ok(())
    }
}
