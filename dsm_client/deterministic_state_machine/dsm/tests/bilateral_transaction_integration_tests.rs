//! Integration Tests for DSM Bilateral Transaction Flow (clean refactor)
//! - Byte-first; no serde/JSON/base64 in logic
//! - Deterministic keys/IDs using blake3
//! - Separate contact managers for relationship vs tx managers to avoid Clone bounds

#![allow(clippy::disallowed_methods)] // unwrap/expect usage acceptable in deterministic integration tests

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::token_types::Balance;

/// Relationship chain tips over process memory, with the store trait's
/// compare-and-set: an update applies only on the expected parent of a
/// relationship its contact add recorded.
#[derive(Default)]
struct MemoryTips {
    tips: std::sync::Mutex<std::collections::HashMap<[u8; 32], [u8; 32]>>,
}

impl dsm::core::chain_tip_store::ChainTipStore for MemoryTips {
    fn get_contact_chain_tip(
        &self,
        device_id: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, dsm::types::error::DsmError> {
        Ok(self
            .tips
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(device_id)
            .copied())
    }

    fn set_contact_chain_tip(
        &self,
        device_id: &[u8; 32],
        expected_parent_tip: [u8; 32],
        new_tip: [u8; 32],
    ) -> Result<bool, dsm::types::error::DsmError> {
        let mut tips = self.tips.lock().unwrap_or_else(|p| p.into_inner());
        let current = tips.get(device_id).copied().ok_or_else(|| {
            dsm::types::error::DsmError::InvalidState(
                "no relationship with that device".to_string(),
            )
        })?;
        if current != expected_parent_tip {
            return Ok(false);
        }
        tips.insert(*device_id, new_tip);
        Ok(true)
    }
}

#[tokio::test]
async fn test_bilateral_transaction_manager_creation() {
    let keypair = SignatureKeyPair::generate_from_entropy(b"it/mgr").expect("keygen");

    let device_id_arr: [u8; 32] = {
        let h = blake3::hash(b"test_device_123");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let contact_manager = DsmContactManager::new(device_id_arr);

    let local_genesis_arr: [u8; 32] = {
        let h = blake3::hash(b"local_genesis");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };

    let manager = BilateralTransactionManager::new(
        contact_manager,
        keypair,
        device_id_arr,
        local_genesis_arr,
        std::sync::Arc::new(MemoryTips::default()),
    );

    assert_eq!(
        manager.list_relationships().len(),
        0,
        "New manager should have no relationships"
    );
}

#[tokio::test]
async fn test_bilateral_relationship_anchor_generation() {
    let dev_a: [u8; 32] = {
        let h = blake3::hash(b"device_a");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let gen_a: [u8; 32] = {
        let h = blake3::hash(b"genesis_a");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let dev_b: [u8; 32] = {
        let h = blake3::hash(b"device_b");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let gen_b: [u8; 32] = {
        let h = blake3::hash(b"genesis_b");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };

    let h0_seen_by_a = dsm::core::bilateral_transaction_manager::initial_relationship_chain_tip(
        &dev_a, &gen_a, &dev_b, &gen_b,
    );
    let h0_seen_by_b = dsm::core::bilateral_transaction_manager::initial_relationship_chain_tip(
        &dev_b, &gen_b, &dev_a, &gen_a,
    );
    assert_eq!(
        h0_seen_by_a, h0_seen_by_b,
        "both devices derive one h_0 for their relationship"
    );
    let other_genesis = dsm::core::bilateral_transaction_manager::initial_relationship_chain_tip(
        &dev_a, &gen_b, &dev_b, &gen_a,
    );
    assert_ne!(
        h0_seen_by_a, other_genesis,
        "h_0 binds each device to its own genesis"
    );
}

#[test]
fn test_operation_serialization() {
    let op = Operation::Transfer {
        policy_commit: [0u8; 32],
        to_device_id: b"recipient_123".to_vec(),
        amount: Balance::amount(100),
        token_id: b"DSM_TOKEN".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![1, 2, 3, 4],
        recipient: b"Bob".to_vec(),
        to: b"recipient_123".to_vec(),
        message: "Test transfer".to_string(),
        signature: vec![],
        authority_policy: None,
    };

    assert_eq!(op.get_operation_type(), "transfer");
    let bytes = op.to_bytes();
    assert!(
        !bytes.is_empty(),
        "Operation should serialize to non-empty bytes"
    );
}
