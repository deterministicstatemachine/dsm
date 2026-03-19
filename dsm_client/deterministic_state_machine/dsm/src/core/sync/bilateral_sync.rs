use crate::types::error::DsmError;
use crate::types::state_types::State;
use crate::storage::StorageNode;
use std::collections::HashSet;

/// Implements bilateral state synchronization from whitepaper Section 25.2
pub struct BilateralSync;

impl BilateralSync {
    /// Verify bilateral consistency according to whitepaper equation (98)
    pub async fn verify_sync_consistency(
        node_a: &StorageNode,
        node_b: &StorageNode,
        alpha_threshold: f64,
    ) -> Result<bool, DsmError> {
        // Get state sets from both nodes
        let states_a = node_a.get_all_states().await?;
        let states_b = node_b.get_all_states().await?;

        // Calculate intersection and union sizes
        let intersection: HashSet<_> = states_a.intersection(&states_b).collect();
        let union: HashSet<_> = states_a.union(&states_b).collect();

        // Calculate consistency ratio
        let ratio = intersection.len() as f64 / union.len() as f64;

        // Compare against threshold (typically ≥ 0.95)
        Ok(ratio >= alpha_threshold)
    }

    /// Verify global consistency across network according to equation (99)
    pub async fn verify_global_consistency(
        nodes: &[StorageNode],
        alpha_threshold: f64,
    ) -> Result<bool, DsmError> {
        // Check all neighbor pairs
        for i in 0..nodes.len() {
            for j in (i+1)..nodes.len() {
                if !Self::verify_sync_consistency(
                    &nodes[i],
                    &nodes[j], 
                    alpha_threshold
                ).await? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Verify state sample according to equation (100)
    pub async fn verify_sample(
        node_a: &StorageNode,
        node_b: &StorageNode,
        beta: f64,
    ) -> Result<bool, DsmError> {
        // Get states from node A
        let states_a = node_a.get_all_states().await?;

        // Select random sample of size beta * |states_a|
        let sample_size = (states_a.len() as f64 * beta) as usize;
        let sample = Self::random_sample(&states_a, sample_size);

        // Verify each sampled state exists in node B
        for state in sample {
            if !node_b.has_state(&state).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Randomly sample states for verification
    fn random_sample(states: &HashSet<State>, size: usize) -> Vec<State> {
        use rand::seq::IteratorRandom;
        let mut rng = crate::crypto::rng::SecureRng;
        states.iter()
            .choose_multiple(&mut rng, size)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Execute bilateral sync between nodes
    pub async fn sync_nodes(
        node_a: &mut StorageNode,
        node_b: &mut StorageNode,
    ) -> Result<(), DsmError> {
        // Get state sets
        let states_a = node_a.get_all_states().await?;
        let states_b = node_b.get_all_states().await?;

        // Find states missing from each node
        let missing_in_a: Vec<_> = states_b.difference(&states_a).cloned().collect();
        let missing_in_b: Vec<_> = states_a.difference(&states_b).cloned().collect();

        // Sync missing states
        for state in missing_in_a {
            node_a.add_state(state).await?;
        }

        for state in missing_in_b {
            node_b.add_state(state).await?;
        }

        Ok(())
    }

    /// Get sync status between nodes
    pub async fn get_sync_status(
        node_a: &StorageNode,
        node_b: &StorageNode,
    ) -> Result<SyncStatus, DsmError> {
        let states_a = node_a.get_all_states().await?;
        let states_b = node_b.get_all_states().await?;

        let missing_count = states_b.difference(&states_a).count();
        
        Ok(SyncStatus {
            total_states: states_b.len(),
            missing_states: missing_count,
            sync_ratio: 1.0 - (missing_count as f64 / states_b.len() as f64)
        })
    }
}