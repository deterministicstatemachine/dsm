// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cryptographic Progress Anchors for DSM Core
//! Eliminates mutable logical clocks; derives deterministic values from SMT root progression.
//! No wall clocks. No mutable timing state. Cryptographic scarcity through state transitions.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::DsmError;

/// Cryptographic progress context - replaces mutable tick state
/// Values are derived from SMT root progression, not mutable counters
#[derive(Clone, Debug)]
pub struct ProgressContext {
    /// Current SMT root hash (source of cryptographic progress)
    smt_root: [u8; 32],
    /// Commit height (monotonically increases only on accepted state transitions)
    commit_height: u64,
}

impl ProgressContext {
    /// Create new progress context
    pub fn new(smt_root: [u8; 32], commit_height: u64) -> Self {
        Self {
            smt_root,
            commit_height,
        }
    }

    /// Derive deterministic hash from current progress state + context
    pub fn derive_hash(&self, context: &[u8]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/deterministic-time");
        hasher.update(&self.smt_root);
        hasher.update(&self.commit_height.to_le_bytes());
        hasher.update(context);
        *hasher.finalize().as_bytes()
    }

    /// Derive deterministic u64 value from current progress state + context
    pub fn derive_u64(&self, context: &[u8]) -> Result<u64, DsmError> {
        let hash = self.derive_hash(context);
        Ok(u64::from_le_bytes(hash[..8].try_into().map_err(|_| {
            DsmError::Internal {
                context: "Failed to convert 8 bytes to u64 in derive_u64".to_string(),
                source: None,
            }
        })?))
    }

    /// Get current commit height (cryptographic progress anchor)
    pub fn commit_height(&self) -> u64 {
        self.commit_height
    }

    /// Get current SMT root
    pub fn smt_root(&self) -> &[u8; 32] {
        &self.smt_root
    }
}

/// Global progress context - must be updated only on accepted state transitions
/// Using std::sync::RwLock for synchronous access (no Tokio runtime required)
static PROGRESS_CONTEXT: once_cell::sync::Lazy<std::sync::RwLock<Option<ProgressContext>>> =
    once_cell::sync::Lazy::new(|| std::sync::RwLock::new(None));

/// Drift detection threshold (maximum allowed difference in commit heights)
const DRIFT_THRESHOLD: u64 = 100;

/// Resync result
#[derive(Debug, Clone, PartialEq)]
pub enum ResyncResult {
    /// No drift detected, heights are synchronized
    Synchronized,
    /// Local height is behind, needs catch-up
    Behind(u64),
    /// Local height is ahead, peer may need catch-up
    Ahead(u64),
    /// Excessive drift detected, manual intervention required
    ExcessiveDrift,
}

/// Detect clock drift between local and remote commit heights
pub fn detect_drift(local_height: u64, remote_height: u64) -> ResyncResult {
    let diff = local_height.abs_diff(remote_height);

    if diff == 0 {
        ResyncResult::Synchronized
    } else if diff > DRIFT_THRESHOLD {
        ResyncResult::ExcessiveDrift
    } else if local_height < remote_height {
        ResyncResult::Behind(remote_height - local_height)
    } else {
        ResyncResult::Ahead(local_height - remote_height)
    }
}

/// Attempt to resync progress context from a trusted peer
/// Returns true if resync was successful, false if rejected
pub fn attempt_resync(peer_smt_root: [u8; 32], peer_commit_height: u64) -> Result<bool, DsmError> {
    let current = current_progress()?;

    match current {
        Some(local_ctx) => {
            match detect_drift(local_ctx.commit_height(), peer_commit_height) {
                ResyncResult::Synchronized => {
                    // Heights match, verify SMT root consistency
                    if local_ctx.smt_root() == &peer_smt_root {
                        Ok(true) // Already synchronized
                    } else {
                        // Height matches but roots differ - potential fork
                        Ok(false)
                    }
                }
                ResyncResult::Behind(_diff) => {
                    // Local is behind, accept peer's progress
                    update_progress_context(peer_smt_root, peer_commit_height)?;
                    Ok(true)
                }
                ResyncResult::Ahead(_) => {
                    // Local is ahead, reject resync (peer should catch up)
                    Ok(false)
                }
                ResyncResult::ExcessiveDrift => {
                    // Excessive drift, reject and log
                    Ok(false)
                }
            }
        }
        None => {
            // Not initialized, accept peer's progress
            update_progress_context(peer_smt_root, peer_commit_height)?;
            Ok(true)
        }
    }
}

/// Get drift status for monitoring/diagnostics
pub fn get_drift_status(peer_height: u64) -> Result<ResyncResult, DsmError> {
    // Get local height using blocking version since we're in sync context
    let local_height = current_commit_height_blocking();
    Ok(detect_drift(local_height, peer_height))
}

/// Initialize or update the global progress context
/// This should ONLY be called when accepting a valid SMT root transition
pub fn update_progress_context(smt_root: [u8; 32], commit_height: u64) -> Result<(), DsmError> {
    let mut ctx = PROGRESS_CONTEXT.write().map_err(|e| DsmError::Internal {
        context: format!("Failed to acquire write lock for progress context: {}", e),
        source: None,
    })?;
    *ctx = Some(ProgressContext::new(smt_root, commit_height));
    Ok(())
}

/// Get current progress context (returns None if not initialized)
pub fn current_progress() -> Result<Option<ProgressContext>, DsmError> {
    let ctx = PROGRESS_CONTEXT.read().map_err(|e| DsmError::Internal {
        context: format!("Failed to acquire read lock for progress context: {}", e),
        source: None,
    })?;
    Ok(ctx.clone())
}

/// Get current commit height (returns 0 if not initialized)
pub fn current_commit_height() -> u64 {
    match current_progress() {
        Ok(Some(ctx)) => ctx.commit_height(),
        _ => 0,
    }
}

/// Synchronous version for non-async contexts (blocking)
/// Uses try_read to avoid async overhead and nested runtime issues
pub fn current_commit_height_blocking() -> u64 {
    if let Ok(guard) = PROGRESS_CONTEXT.try_read() {
        if let Some(ref progress) = *guard {
            return progress.commit_height;
        }
    }
    // Uninitialized or lock contention
    0
}

/// Derive deterministic hash from current progress + context
/// Returns zero hash if progress not initialized
pub fn derive_progress_hash(context: &[u8]) -> [u8; 32] {
    if let Ok(guard) = PROGRESS_CONTEXT.try_read() {
        if let Some(ref progress) = *guard {
            return progress.derive_hash(context);
        }
    }

    // Default path for uninitialized state or lock contention
    let mut hasher = dsm_domain_hasher("DSM/deterministic-time");
    hasher.update(b"UNINITIALIZED");
    hasher.update(context);
    *hasher.finalize().as_bytes()
}

/// Derive deterministic u64 from current progress + context
/// Returns 0 if progress not initialized
pub fn derive_progress_u64(context: &[u8]) -> u64 {
    if let Ok(guard) = PROGRESS_CONTEXT.try_read() {
        if let Some(ref progress) = *guard {
            return progress.derive_u64(context).unwrap_or(0);
        }
    }

    // Default path for uninitialized state or lock contention
    let hash = derive_progress_hash(context);
    #[allow(clippy::unwrap_used)]
    u64::from_le_bytes(hash[..8].try_into().unwrap())
}

/// ---- BACKWARD COMPATIBILITY APIS ----
/// These provide the same interface but derive values from cryptographic progress
/// Advance and return (hash, index) - now derived from progress, not mutable ticks
#[inline]
pub fn tick_raw() -> ([u8; 32], u64) {
    let hash = derive_progress_hash(b"DSM-TICK");
    let index = derive_progress_u64(b"DSM-TICK-INDEX");
    (hash, index)
}

/// Convenience: advance and return just the deterministic counter
#[inline]
pub fn tick_index() -> u64 {
    derive_progress_u64(b"DSM-TICK-INDEX")
}

/// Get clean tick index - now just returns commit height
#[inline]
pub fn clean_tick_index() -> u64 {
    current_commit_height_blocking()
}

/// Peek at the current (hash, index) without advancing - same as tick since no mutation
#[inline]
pub fn peek_raw() -> ([u8; 32], u64) {
    tick_raw()
}

/// Convenience: peek current tip hash
#[inline]
pub fn tick_hash() -> [u8; 32] {
    derive_progress_hash(b"DSM-TICK")
}

/// ---- BACK-COMPAT ALIASES ----
#[inline]
pub fn tick() -> ([u8; 32], u64) {
    tick_raw()
}

#[inline]
pub fn peek() -> ([u8; 32], u64) {
    peek_raw()
}

/// Reset for tests (initialize progress context)
#[inline]
pub fn reset_for_tests() {
    // Initialize with test values
    if let Ok(mut ctx) = PROGRESS_CONTEXT.try_write() {
        *ctx = Some(ProgressContext::new([0x42u8; 32], 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_context_derives_deterministic_values() {
        let ctx = ProgressContext::new([1u8; 32], 42);

        let hash1 = ctx.derive_hash(b"test");
        let hash2 = ctx.derive_hash(b"test");
        assert_eq!(hash1, hash2); // Same context produces same hash

        let u64_1 = ctx.derive_u64(b"test").unwrap();
        let u64_2 = ctx.derive_u64(b"test").unwrap();
        assert_eq!(u64_1, u64_2); // Same context produces same u64

        let different_ctx = ProgressContext::new([2u8; 32], 42);
        let different_hash = different_ctx.derive_hash(b"test");
        assert_ne!(hash1, different_hash); // Different SMT root produces different hash
    }

    #[test]
    fn backward_compatibility_apis_work() {
        // Initialize progress context
        update_progress_context([42u8; 32], 123).unwrap();

        let (hash1, idx1) = tick();
        let (hash2, idx2) = peek();

        // Should return same values since no mutation
        assert_eq!(hash1, hash2);
        assert_eq!(idx1, idx2);

        // Should be deterministic
        let (hash3, idx3) = tick();
        assert_eq!(hash1, hash3);
        assert_eq!(idx1, idx3);
    }

    #[test]
    fn uninitialized_progress_returns_defaults() {
        // Clear progress context
        {
            if let Ok(mut ctx) = PROGRESS_CONTEXT.try_write() {
                *ctx = None;
            }
        }

        let hash = derive_progress_hash(b"test");
        let u64_val = derive_progress_u64(b"test");

        // Should still work with default path
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(u64_val, u64::from_le_bytes(hash[..8].try_into().unwrap()));
    }
}
