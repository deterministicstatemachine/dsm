//! Per-Device SMT singleton — shared between online and offline paths on the same device (§2.2, §4.3).
//!
//! Both online (`app_router_impl`) and offline (`bilateral_ble_handler`) transfer
//! paths update the **same** Per-Device SMT. This module provides a process-wide
//! singleton so that SMT roots and inclusion proofs are consistent regardless of
//! which transport delivered the state transition.
//!
//! Also provides the §5.4 Modal Synchronization Lock: a per-relationship flag
//! that prevents concurrent online and offline transfers for the same (A,B) pair.

use std::collections::HashSet;
use std::sync::Arc;
use once_cell::sync::OnceCell;
use tokio::sync::RwLock;

use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

/// Process-wide Per-Device SMT instance.
static SHARED_SMT: OnceCell<Arc<RwLock<SparseMerkleTree>>> = OnceCell::new();

/// §5.4 Modal lock: set of relationship SMT keys with pending online projections.
static PENDING_ONLINE: OnceCell<Arc<RwLock<HashSet<[u8; 32]>>>> = OnceCell::new();

// ---------------------------------------------------------------------------
// Per-Device SMT
// ---------------------------------------------------------------------------

/// Initialize the shared Per-Device SMT. Called once during SDK bootstrap.
/// Subsequent calls return the existing instance (idempotent).
pub fn init_shared_smt(max_leaves: usize) -> Arc<RwLock<SparseMerkleTree>> {
    SHARED_SMT
        .get_or_init(|| Arc::new(RwLock::new(SparseMerkleTree::new(max_leaves))))
        .clone()
}

/// Get the shared Per-Device SMT instance.  Returns `None` only if
/// `init_shared_smt()` has never been called.
pub fn get_shared_smt() -> Option<Arc<RwLock<SparseMerkleTree>>> {
    SHARED_SMT.get().cloned()
}

// ---------------------------------------------------------------------------
// §5.4 Modal Synchronization Lock
// ---------------------------------------------------------------------------

fn pending_online_set() -> Arc<RwLock<HashSet<[u8; 32]>>> {
    PENDING_ONLINE
        .get_or_init(|| Arc::new(RwLock::new(HashSet::new())))
        .clone()
}

/// Mark relationship `smt_key` as having a pending online projection.
/// Returns `false` if the relationship was already pending (no-op).
pub async fn set_pending_online(smt_key: &[u8; 32]) -> bool {
    let set = pending_online_set();
    let mut guard = set.write().await;
    guard.insert(*smt_key)
}

/// Clear pending-online for relationship `smt_key`.
pub async fn clear_pending_online(smt_key: &[u8; 32]) {
    let set = pending_online_set();
    let mut guard = set.write().await;
    guard.remove(smt_key);
}

/// Check if relationship `smt_key` has a pending online projection.
/// If `true`, offline (BLE) transfers for this (A,B) pair MUST be rejected
/// per §5.4 Theorem 1.
pub async fn is_pending_online(smt_key: &[u8; 32]) -> bool {
    let set = pending_online_set();
    let guard = set.read().await;
    guard.contains(smt_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_shared_smt_returns_instance() {
        let smt = init_shared_smt(1024);
        assert!(Arc::strong_count(&smt) >= 1);
    }

    #[test]
    fn init_shared_smt_is_idempotent() {
        let a = init_shared_smt(1024);
        let b = init_shared_smt(2048);
        assert!(Arc::ptr_eq(&a, &b), "repeated init must return same Arc");
    }

    #[test]
    fn get_shared_smt_after_init() {
        let _ = init_shared_smt(1024);
        let fetched = get_shared_smt();
        assert!(fetched.is_some());
    }

    #[tokio::test]
    async fn pending_online_set_insert_and_check() {
        let key = [0xAA; 32];
        clear_pending_online(&key).await;

        assert!(!is_pending_online(&key).await);
        let inserted = set_pending_online(&key).await;
        assert!(inserted, "first insert should return true");
        assert!(is_pending_online(&key).await);
    }

    #[tokio::test]
    async fn pending_online_duplicate_insert_returns_false() {
        let key = [0xBB; 32];
        clear_pending_online(&key).await;

        set_pending_online(&key).await;
        let second = set_pending_online(&key).await;
        assert!(!second, "duplicate insert should return false");
    }

    #[tokio::test]
    async fn pending_online_clear_removes_key() {
        let key = [0xCC; 32];
        set_pending_online(&key).await;
        assert!(is_pending_online(&key).await);

        clear_pending_online(&key).await;
        assert!(!is_pending_online(&key).await);
    }

    #[tokio::test]
    async fn pending_online_independent_keys() {
        let k1 = [0x01; 32];
        let k2 = [0x02; 32];
        clear_pending_online(&k1).await;
        clear_pending_online(&k2).await;

        set_pending_online(&k1).await;
        assert!(is_pending_online(&k1).await);
        assert!(!is_pending_online(&k2).await);
    }

    #[tokio::test]
    async fn pending_online_clear_nonexistent_is_noop() {
        let key = [0xDD; 32];
        clear_pending_online(&key).await;
        clear_pending_online(&key).await;
        assert!(!is_pending_online(&key).await);
    }
}
