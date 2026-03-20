//! Bilateral state synchronization and drift detection.
//!
//! Manages state consistency between bilateral relationship pairs by detecting
//! drift (divergence between local and counterparty state numbers) and
//! orchestrating resynchronization when needed. Uses deterministic tick-based
//! staleness detection rather than wall-clock time.

use crate::core::state_machine::RelationshipStatePair;
use crate::types::error::DsmError;
use crate::types::operations::TransactionMode;
use crate::types::state_types::{PreCommitment, State as StateTypesState};
use crate::utils::deterministic_time::{attempt_resync, detect_drift, ResyncResult};

// No extension trait needed, we'll use the direct method

/// SyncManager handles modal synchronization and commitment continuity
pub struct SyncManager;

impl SyncManager {
    /// Get optimal transaction mode based on connectivity and clock drift
    pub fn determine_transaction_mode(
        relationship: &RelationshipStatePair,
        counterparty_online: bool,
        peer_commit_height: Option<u64>,
    ) -> TransactionMode {
        if counterparty_online && !relationship.has_pending_unilateral_transactions() {
            // Check for excessive clock drift before allowing bilateral
            if let Some(peer_height) = peer_commit_height {
                if detect_drift(
                    crate::utils::deterministic_time::current_commit_height_blocking(),
                    peer_height,
                ) == ResyncResult::ExcessiveDrift
                {
                    // Force unilateral mode to allow resync
                    return TransactionMode::Unilateral;
                }
            }
            TransactionMode::Bilateral
        } else {
            TransactionMode::Unilateral
        }
    }

    /// Verify modal synchronization precedence according to whitepaper Section 23.4
    pub fn verify_modal_sync_precedence(
        relationship: &RelationshipStatePair,
        new_state: &StateTypesState,
        mode: TransactionMode,
    ) -> Result<bool, DsmError> {
        match mode {
            TransactionMode::Bilateral => {
                // For bilateral mode, verify both parties are synchronized
                if let Some(last_synced_state) = relationship.get_last_synced_state() {
                    // Verify no pending unilateral transactions
                    if relationship.has_pending_unilateral_transactions() {
                        return Ok(false);
                    }

                    // Verify synchronization state numbers match
                    if last_synced_state.state_number != relationship.entity_state.state_number {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            TransactionMode::Unilateral => {
                // For unilateral mode, verify forward commitment continuity
                if let Some(commitment) = &relationship.entity_state.forward_commitment {
                    // Verify new state adheres to commitment parameters
                    Self::verify_commitment_continuity(commitment, new_state)?;
                }
                Ok(true)
            }
        }
    }

    /// Verify forward commitment continuity according to whitepaper Section 23.3
    /// Ensures: ∀Sn,Sn+1 : Parameters(Sn+1) ⊆ Cfuture(Sn)
    pub fn verify_commitment_continuity(
        previous_commitment: &PreCommitment,
        new_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        use crate::types::operations::Ops;

        // 1. Verify state number meets minimum requirement
        if new_state.state_number < previous_commitment.min_state_number {
            log::warn!(
                "verify_commitment_continuity: state_number {} < min_state_number {}",
                new_state.state_number,
                previous_commitment.min_state_number
            );
            return Ok(false);
        }

        // 2. Verify operation type matches commitment (if commitment specifies one)
        if !previous_commitment.operation_type.is_empty() {
            let op_type = new_state.operation.get_id();
            if op_type != previous_commitment.operation_type {
                log::warn!(
                    "verify_commitment_continuity: op type '{}' != committed '{}'",
                    op_type,
                    previous_commitment.operation_type
                );
                return Ok(false);
            }
        }

        // 3. Verify fixed parameters are honored:
        //    Each committed fixed parameter value must appear in the operation bytes.
        let op_bytes = new_state.operation.to_bytes();
        for (key, expected_value) in &previous_commitment.fixed_parameters {
            if expected_value.is_empty() {
                continue;
            }
            if !op_bytes
                .windows(expected_value.len())
                .any(|w| w == expected_value.as_slice())
            {
                log::warn!(
                    "verify_commitment_continuity: fixed parameter '{}' not found in operation bytes",
                    key
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Update synchronization state after successful transaction
    pub fn update_sync_state(
        relationship: &mut RelationshipStatePair,
        new_state: &StateTypesState,
        mode: TransactionMode,
    ) -> Result<(), DsmError> {
        match mode {
            TransactionMode::Bilateral => {
                // Update both counterparty states for bilateral transactions
                relationship.update_entity_state(new_state.clone())?;
                let _ = relationship.set_last_synced_state(Some(new_state.clone()));
            }
            TransactionMode::Unilateral => {
                // Only update entity state for unilateral transactions
                relationship.update_entity_state(new_state.clone())?;
                // Unilateral transactions are added to pending queue
                relationship.add_pending_transaction(new_state.clone())?;
            }
        }
        Ok(())
    }

    /// Process pending unilateral transactions during synchronization
    pub fn process_pending_transactions(
        relationship: &mut RelationshipStatePair,
    ) -> Result<(), DsmError> {
        // Get pending transactions in order
        let pending = relationship.get_pending_unilateral_transactions();

        for transaction in pending {
            // Verify and apply each pending transaction
            if Self::verify_modal_sync_precedence(
                relationship,
                &transaction,
                TransactionMode::Unilateral,
            )? {
                relationship.apply_transaction(transaction)?;
            }
        }

        // Clear processed transactions
        relationship.clear_pending_transactions();
        Ok(())
    }

    /// Attempt to resync logical clock with counterparty
    /// Should be called during bilateral handshake
    pub async fn attempt_clock_resync(
        peer_smt_root: [u8; 32],
        peer_commit_height: u64,
    ) -> Result<bool, DsmError> {
        let success = attempt_resync(peer_smt_root, peer_commit_height)?;
        if !success {
            // Log drift status for diagnostics
            let local_height = crate::utils::deterministic_time::current_commit_height();
            let drift = detect_drift(local_height, peer_commit_height);
            match drift {
                ResyncResult::ExcessiveDrift => {
                    return Err(DsmError::ClockDrift {
                        message: "Excessive logical clock drift detected".to_string(),
                        local_height,
                        remote_height: peer_commit_height,
                    });
                }
                ResyncResult::Ahead(_) => {
                    // Local is ahead, this is normal during catch-up
                }
                _ => {}
            }
        }
        Ok(success)
    }
}
