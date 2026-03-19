// SPDX-License-Identifier: Apache-2.0
//! Storage Node Partitioning Module
//! Implements advanced data partitioning and sharding for DSM storage nodes.
//! Provides deterministic placement, load balancing, and fault tolerance.

use blake3::Hasher;
use std::collections::HashMap;

/// Partition configuration for storage nodes
#[derive(Debug, Clone)]
pub struct PartitionConfig {
    /// Number of partitions per node
    pub partitions_per_node: usize,
    /// Replication factor
    pub replication_factor: usize,
    /// Load balancing threshold
    pub load_threshold: f64,
    /// Maximum partitions per node
    pub max_partitions_per_node: usize,
}

/// Partition manager for coordinating data distribution
pub struct PartitionManager {
    config: PartitionConfig,
    node_partitions: HashMap<String, Vec<String>>, // node_id -> partition_ids
    partition_nodes: HashMap<String, Vec<String>>, // partition_id -> node_ids
}

impl PartitionManager {
    /// Create a new partition manager
    pub fn new(config: PartitionConfig) -> Self {
        Self {
            config,
            node_partitions: HashMap::new(),
            partition_nodes: HashMap::new(),
        }
    }

    /// Add a node to the partition system
    pub fn add_node(&mut self, node_id: String) {
        // For now, assign partitions round-robin to nodes
        // In a real implementation, this would use consistent hashing
        let node_index = self.node_partitions.len();
        let mut partitions = Vec::new();

        for i in 0..self.config.partitions_per_node {
            let global_partition_index = node_index * self.config.partitions_per_node + i;
            let partition_id = format!("partition_{}", global_partition_index);
            partitions.push(partition_id.clone());

            // Update reverse mapping
            self.partition_nodes
                .entry(partition_id)
                .or_default()
                .push(node_id.clone());
        }

        self.node_partitions.insert(node_id, partitions);
    }

    /// Remove a node from the partition system
    pub fn remove_node(&mut self, node_id: &str) {
        if let Some(partitions) = self.node_partitions.remove(node_id) {
            for partition_id in partitions {
                if let Some(nodes) = self.partition_nodes.get_mut(&partition_id) {
                    nodes.retain(|n| n != node_id);
                    if nodes.is_empty() {
                        self.partition_nodes.remove(&partition_id);
                    }
                }
            }
        }
    }

    /// Get nodes responsible for a partition
    pub fn get_partition_nodes(&self, partition_id: &str) -> Vec<String> {
        self.partition_nodes
            .get(partition_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get partitions assigned to a node
    pub fn get_node_partitions(&self, node_id: &str) -> Vec<String> {
        self.node_partitions
            .get(node_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Determine the partition for a given key using global partitioning
    pub fn get_partition_for_key(&self, key: &[u8]) -> String {
        let hash = self.hash_key(key);
        let total_partitions = self.node_partitions.len() * self.config.partitions_per_node;
        if total_partitions == 0 {
            return "partition_0".to_string();
        }
        let partition_index = hash % total_partitions;
        format!("partition_{}", partition_index)
    }

    /// Get all nodes that should store a given key
    pub fn get_nodes_for_key(&self, key: &[u8]) -> Vec<String> {
        let partition_id = self.get_partition_for_key(key);
        let mut nodes = self.get_partition_nodes(&partition_id);

        // Apply replication factor
        if nodes.len() > self.config.replication_factor {
            nodes.truncate(self.config.replication_factor);
        }

        nodes
    }

    /// Check if a node should store a given key
    pub fn should_node_store_key(&self, node_id: &str, key: &[u8]) -> bool {
        let required_nodes = self.get_nodes_for_key(key);
        required_nodes.contains(&node_id.to_string())
    }

    /// Get load distribution across nodes
    pub fn get_load_distribution(&self) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();
        for (node_id, partitions) in &self.node_partitions {
            distribution.insert(node_id.clone(), partitions.len());
        }
        distribution
    }

    /// Check if the system is balanced
    pub fn is_balanced(&self) -> bool {
        let distribution = self.get_load_distribution();
        if distribution.is_empty() {
            return true;
        }

        let total_partitions: usize = distribution.values().sum();
        let avg_load = total_partitions as f64 / distribution.len() as f64;

        for &load in distribution.values() {
            let deviation = (load as f64 - avg_load).abs() / avg_load;
            if deviation > self.config.load_threshold {
                return false;
            }
        }

        true
    }

    /// Rebalance partitions across nodes
    pub fn rebalance(&mut self) {
        let nodes: Vec<String> = self.node_partitions.keys().cloned().collect();
        let _total_partitions = nodes.len() * self.config.partitions_per_node;

        // Clear existing assignments
        self.node_partitions.clear();
        self.partition_nodes.clear();

        // Reassign partitions
        for node_id in nodes {
            self.add_node(node_id);
        }
    }

    /// Hash a key for partition assignment
    fn hash_key(&self, key: &[u8]) -> usize {
        let mut hasher = Hasher::new();
        hasher.update(b"DSM/key-hash");
        hasher.update(key);
        let hash_bytes = hasher.finalize();

        // Use first 8 bytes as usize
        let mut first8 = [0u8; 8];
        first8.copy_from_slice(&hash_bytes.as_bytes()[..8]);
        usize::from_le_bytes(first8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_assignment() {
        let config = PartitionConfig {
            partitions_per_node: 4,
            replication_factor: 2,
            load_threshold: 0.2,
            max_partitions_per_node: 10,
        };

        let mut manager = PartitionManager::new(config);

        // Add nodes
        manager.add_node("node1".to_string());
        manager.add_node("node2".to_string());
        manager.add_node("node3".to_string());

        // Check partition assignment
        let partitions = manager.get_node_partitions("node1");
        assert_eq!(partitions.len(), 4);

        // Check key distribution
        let key = b"test_key";
        let nodes = manager.get_nodes_for_key(key);
        assert!(!nodes.is_empty());

        // Check that node should store key
        let should_store = manager.should_node_store_key(&nodes[0], key);
        assert!(should_store);
    }

    #[test]
    fn test_load_balancing() {
        let config = PartitionConfig {
            partitions_per_node: 4,
            replication_factor: 2,
            load_threshold: 0.2,
            max_partitions_per_node: 10,
        };

        let mut manager = PartitionManager::new(config);

        manager.add_node("node1".to_string());
        manager.add_node("node2".to_string());

        assert!(manager.is_balanced());

        let distribution = manager.get_load_distribution();
        assert_eq!(distribution.len(), 2);
        for &load in distribution.values() {
            assert_eq!(load, 4);
        }
    }

    #[test]
    fn test_node_removal() {
        let config = PartitionConfig {
            partitions_per_node: 4,
            replication_factor: 2,
            load_threshold: 0.2,
            max_partitions_per_node: 10,
        };

        let mut manager = PartitionManager::new(config);

        manager.add_node("node1".to_string());
        manager.add_node("node2".to_string());

        assert_eq!(manager.get_node_partitions("node1").len(), 4);

        manager.remove_node("node1");

        assert_eq!(manager.get_node_partitions("node1").len(), 0);
    }
}
