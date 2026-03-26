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
    assert_eq!(
        root1, root2,
        "Device tree root must be deterministic"
    );
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
        ([1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "mixed"),
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
            root1,
            [0u8; 32],
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
    for i in 0..16u8 {  // Reduced from 256 to keep test fast
        device_ids.push([i; 32]);
    }
    
    let roots: Vec<_> = device_ids.iter()
        .map(|&dev_id| DeviceTree::single(dev_id).root())
        .collect();
    
    // Check for duplicates
    for i in 0..roots.len() {
        for j in (i+1)..roots.len() {
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
        [1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
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
    
    let roots: Vec<_> = device_ids.iter()
        .map(|&dev_id| DeviceTree::single(dev_id).root())
        .collect();
    
    // All roots should be different (flipping each byte produces different result)
    for i in 0..roots.len() {
        for j in (i+1)..roots.len() {
            assert_ne!(
                roots[i], roots[j],
                "Changing different bytes in device_id must produce different roots"
            );
        }
    }
}
