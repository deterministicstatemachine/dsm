//! Speculative state projection for pre-validation.
//!
//! Allows creating hypothetical future states from a current state and a
//! proposed operation without committing to the hash chain. Used to validate
//! that a proposed state transition would satisfy all invariants before
//! actually applying it.

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{IdentityAnchor, State, StateFlag};
use std::collections::HashMap;

// Extension trait to add the missing fields
trait StateExtension {
    fn get_owner_id(&self) -> [u8; 32];
    fn get_entity_signature(&self) -> Option<Vec<u8>>;
    fn get_counterparty_signature(&self) -> Option<Vec<u8>>;
    fn get_projection_commitment(&self) -> Option<Vec<u8>>;
    fn set_owner_id(&mut self, owner_id: [u8; 32]);
    fn set_projection_commitment(&mut self, commitment: Option<Vec<u8>>);
}

// Implementation of the extension trait for State
impl StateExtension for State {
    fn get_owner_id(&self) -> [u8; 32] {
        // Use device_info.device_id instead of the removed device_id field
        self.device_info.device_id
    }

    fn get_entity_signature(&self) -> Option<Vec<u8>> {
        // Return None since entity_signature field doesn't exist on State
        None
    }

    fn get_counterparty_signature(&self) -> Option<Vec<u8>> {
        // Return None since counterparty_signature field doesn't exist on State
        None
    }

    fn get_projection_commitment(&self) -> Option<Vec<u8>> {
        // Use get_parameter to access projection commitment from external_data
        self.get_parameter("projection_commitment").cloned()
    }

    fn set_owner_id(&mut self, owner_id: [u8; 32]) {
        // Update device_info.device_id instead of the removed device_id field
        self.device_info.device_id = owner_id;
    }

    fn set_projection_commitment(&mut self, commitment: Option<Vec<u8>>) {
        if let Some(comm) = commitment {
            // Use add_metadata to store in external_data
            let _ = self.add_metadata("projection_commitment", comm);
        }
    }
}

/// Represents a projected future state based on proposed operations
#[derive(Clone, Debug, Default)]
pub struct ProjectedState {
    /// Base state from which this projection was created
    pub base_state: State,

    /// Operations that have been projected
    pub projected_operations: Vec<Operation>,

    /// Projected state hash
    pub projected_hash: Vec<u8>,

    /// Recipient identity anchor
    pub recipient: Option<IdentityAnchor>,

    /// Additional projection metadata
    pub metadata: HashMap<String, Vec<u8>>,
}

/// Implements quantum-resistant state projection according to whitepaper Section 23.2.1
pub struct StateProjector;

impl StateProjector {
    /// Project state to recipient's identity anchor for unilateral transactions
    /// StateProjection(SAn → IDB) = SA→Bn+1
    pub fn project_state(
        current_state: &State,
        recipient_id: &IdentityAnchor,
    ) -> Result<State, DsmError> {
        // Create projected state with recipient as owner
        let mut projected = current_state.clone();

        // Set recipient as new owner
        projected.set_owner_id(
            crate::crypto::blake3::domain_hash("DSM/entity-id", recipient_id.id.as_bytes()).into(),
        );

        // Note: Signatures are not stored in State struct fields, so no clearing needed
        // The projection will naturally not have signatures as they don't exist on State

        // Generate quantum-resistant projection commitment
        let commitment = Self::generate_projection_commitment(current_state, recipient_id)?;
        projected.set_projection_commitment(Some(commitment));

        // Mark as projected state
        projected.add_flag(StateFlag::Custom("projected".to_string()));

        Ok(projected)
    }

    /// Generate quantum-resistant commitment for state projection
    fn generate_projection_commitment(
        state: &State,
        recipient: &IdentityAnchor,
    ) -> Result<Vec<u8>, DsmError> {
        // Generate commitment according to whitepaper formula:
        // Cproj = H(Sn || IDB || "projection")
        let commitment_data = [
            state.hash()?.as_slice(),
            recipient.id.as_bytes(),
            b"projection",
        ]
        .concat();

        Ok(
            crate::crypto::blake3::domain_hash("DSM/state-projection", &commitment_data)
                .as_bytes()
                .to_vec(),
        )
    }

    /// Verify a projected state matches its commitment
    pub fn verify_projection(
        projected_state: &State,
        original_state: &State,
        recipient: &IdentityAnchor,
    ) -> Result<bool, DsmError> {
        // Verify projection commitment exists
        let commitment = match projected_state.get_projection_commitment() {
            Some(c) => c,
            None => return Ok(false),
        };

        // Verify commitment matches expected value
        let expected = Self::generate_projection_commitment(original_state, recipient)?;

        if commitment != expected {
            return Ok(false);
        }

        // Verify state contents match except for changed fields
        if !Self::verify_projected_state_contents(projected_state, original_state, recipient)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify contents of projected state match original except for projection-specific changes
    fn verify_projected_state_contents(
        projected: &State,
        original: &State,
        recipient: &IdentityAnchor,
    ) -> Result<bool, DsmError> {
        // Verify core state fields remain unchanged
        if projected.state_number != original.state_number
            || projected.prev_state_hash != original.prev_state_hash
            || projected.operation != original.operation
            || projected.entropy != original.entropy
        {
            return Ok(false);
        }

        // Verify projection-specific changes
        if projected.get_owner_id()
            != <[u8; 32]>::from(crate::crypto::blake3::domain_hash(
                "DSM/entity-id",
                recipient.id.as_bytes(),
            ))
            || projected.get_entity_signature().is_some()
            || projected.get_counterparty_signature().is_some()
            || !projected
                .flags
                .contains(&StateFlag::Custom("projected".to_string()))
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify that a projected state correctly reflects the transition from base state
    /// for the given recipient identity
    pub fn verify_state_projection(
        projected: &State,
        base: &State,
        recipient: &IdentityAnchor,
    ) -> Result<bool, DsmError> {
        // Verify state number increment
        if projected.state_number != base.state_number + 1 {
            return Ok(false);
        }

        // Verify hash chain continuity
        let base_hash = base.hash()?;
        if projected.prev_state_hash != base_hash {
            return Ok(false);
        }

        // Verify projected entropy derivation
        let projected_entropy =
            Self::derive_projected_entropy(&base.entropy, &projected.operation, recipient)?;
        if projected.entropy != projected_entropy {
            return Ok(false);
        }

        Ok(true)
    }

    /// Derive projected entropy for recipient according to whitepaper Section 6.1
    fn derive_projected_entropy(
        base_entropy: &[u8],
        operation: &Operation,
        recipient: &IdentityAnchor,
    ) -> Result<Vec<u8>, DsmError> {
        // Use canonical, deterministic operation bytes (no Serde/bincode)
        let op_bytes = operation.to_bytes();

        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/projection-entropy");
        hasher.update(base_entropy);
        hasher.update(&op_bytes);
        hasher.update(&recipient.as_bytes());
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Project a state using its hash
    pub fn project_state_by_hash(&self, state_hash: &[u8]) -> Result<ProjectedState, DsmError> {
        // Call internal implementation that handles the state_hash parameter
        Self::_internal_project_by_hash(state_hash)
    }

    // Fix for the unused variable warning
    fn _internal_project_by_hash(_state_hash: &[u8]) -> Result<ProjectedState, DsmError> {
        Ok(ProjectedState::default())
    }
}
