//! Random walk verification for commitment proofs.
//!
//! Provides functionality for verifying the validity of commitments without
//! revealing the underlying data. Uses hashed commitment data as a seed for
//! a deterministic random walk that generates coordinates in 3D space.
//! The coordinates can then be verified against the hash of the data without
//! revealing the data itself (whitepaper Sections 13-14).
/// Provides functionality for generating random walk coordinates and verifying them.
///
/// # Example
/// ```text
/// use dsm::core::state_machine::random_walk::algorithms::{verify_state_transition, Position, generate_positions};
/// use dsm::core::state_machine::random_walk::Coordinate;
/// use dsm::types::state_types::State;
/// use dsm::types::operations::Operation;
/// use dsm::crypto::blake3::domain_hash;
///
/// // Create states with test data
/// let mut previous_state = State::default();
/// previous_state.entropy = vec![1, 2, 3];
/// previous_state.hash[0] as u64 = 0;
///
/// let mut new_state = State::default();
/// new_state.entropy = vec![4, 5, 6];
/// new_state.hash[0] as u64 = 1;
///
/// // Create a valid operation format: [op_type (1 byte), data...]
/// let op_bytes = [0u8; 32]; // Using zeroed bytes as test operation data
/// new_state.operation = Operation::from_bytes(&op_bytes).unwrap();
///
/// // Generate valid positions for the transition
/// let seed = domain_hash("DSM/walk-seed", b"test_seed");
/// let positions = generate_positions(&seed, None).unwrap();
///
/// let result = verify_state_transition(&previous_state, &new_state, &positions);
/// assert!(result.is_ok());
/// ```

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coordinate(pub Vec<i32>);

impl Default for Coordinate {
    fn default() -> Self {
        Self(vec![0; 3])
    }
}

// Implementation of random walk verification algorithms as described in the whitepaper
pub mod algorithms {
    use crate::types::error::DsmError;
    use blake3::Hash;
    use crate::crypto::blake3::dsm_domain_hasher;
    use std::convert::TryInto;

    // Default constants for random walk verification
    const DEFAULT_DIMENSIONS: usize = 3;
    const DEFAULT_STEP_COUNT: usize = 64;
    const DEFAULT_MAX_COORDINATE: u32 = 1_000_000;
    const HASH_SIZE: usize = 32; // Blake3 produces 32-byte hashes

    /// Configuration parameters for random walk generation
    pub struct RandomWalkConfig {
        /// Number of dimensions for the random walk space
        pub dimensions: usize,
        /// Number of positions to generate in the sequence
        pub step_count: usize,
        /// Maximum coordinate value in any dimension
        pub max_coordinate: u32,
        #[allow(dead_code)]
        pub(crate) position_count: usize,
    }

    impl Default for RandomWalkConfig {
        fn default() -> Self {
            RandomWalkConfig {
                dimensions: DEFAULT_DIMENSIONS,
                step_count: DEFAULT_STEP_COUNT,
                max_coordinate: DEFAULT_MAX_COORDINATE,
                position_count: DEFAULT_STEP_COUNT,
            }
        }
    }

    /// A position in the random walk sequence
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Position(pub Vec<i32>);

    impl Default for Position {
        fn default() -> Self {
            Self(vec![0; DEFAULT_DIMENSIONS])
        }
    }

    /// Generate a seed for the deterministic random walk
    ///
    /// As described in the whitepaper section 3.1, the seed is generated from input data
    /// using a cryptographic hash function: Seed = H(Sn || ExternalData || P)
    ///
    /// # Arguments
    ///
    /// * `state` - Current state hash
    /// * `external_data` - External data or parameters
    /// * `additional_params` - Optional additional parameters
    ///
    /// # Returns
    ///
    /// * `Hash` - The generated seed as a hash value
    pub fn generate_seed(
        state: &Hash,
        external_data: &[u8],
        additional_params: Option<&[u8]>,
    ) -> Hash {
        let mut hasher = dsm_domain_hasher("DSM/walk-seed");

        // Add state hash
        hasher.update(state.as_bytes());

        // Add external data
        hasher.update(external_data);

        // Add additional parameters if provided
        if let Some(params) = additional_params {
            hasher.update(params);
        }

        // Finalize and return the hash
        Hash::from(*hasher.finalize().as_bytes())
    }

    /// Generate a deterministic random walk position sequence from a seed
    ///
    /// As described in the whitepaper section 3.1, the positions are generated using
    /// a deterministic random walk algorithm: Positions = RW(Seed, n)
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed value derived from input data
    /// * `config` - Optional configuration parameters
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Position>, DsmError>` - The resulting position sequence or error
    pub fn generate_positions(
        seed: &Hash,
        config: Option<RandomWalkConfig>,
    ) -> Result<Vec<Position>, DsmError> {
        let config = config.unwrap_or_default();

        // Validate configuration parameters
        if config.dimensions == 0 {
            return Err(DsmError::invalid_parameter(
                "Dimensions must be greater than 0".to_string(),
            ));
        }
        if config.step_count == 0 {
            return Err(DsmError::invalid_parameter(
                "Step count must be greater than 0".to_string(),
            ));
        }

        // Initialize pseudorandom number generator from seed
        let mut positions = Vec::with_capacity(config.step_count);
        let seed_bytes = seed.as_bytes();

        // Generate positions using the seed to drive the PRNG
        let mut current_hash = *seed_bytes;

        for _ in 0..config.step_count {
            // Create a new position
            let mut position = Vec::with_capacity(config.dimensions);

            // Generate coordinates for this position
            for d in 0..config.dimensions {
                // Use 4 bytes of the hash for each coordinate to ensure uniform distribution
                let offset = (d % (HASH_SIZE / 4)) * 4;

                // Convert 4 bytes to u32 and then to signed i32 within max_coordinate range
                let bytes: [u8; 4] = current_hash[offset..offset + 4].try_into().map_err(|e| {
                    DsmError::internal("Failed to convert hash bytes to array".to_string(), Some(e))
                })?;

                let value = u32::from_le_bytes(bytes) % (2 * config.max_coordinate);
                let coordinate = (value as i32) - (config.max_coordinate as i32);

                position.push(coordinate);
            }

            // Add this position to our sequence
            positions.push(Position(position));

            // Update the hash for the next position
            let mut hasher = dsm_domain_hasher("DSM/walk-step");
            hasher.update(&current_hash);
            current_hash = *hasher.finalize().as_bytes();
        }

        Ok(positions)
    }

    /// Verify if two position sequences match exactly
    ///
    /// As described in the whitepaper section 3.1, verification occurs when multiple parties
    /// independently generate position sequences that match exactly: PositionsA = PositionsB ⇔ InputsA = InputsB
    ///
    /// # Arguments
    ///
    /// * `positions_a` - First position sequence
    /// * `positions_b` - Second position sequence
    ///
    /// # Returns
    ///
    /// * `bool` - True if positions match, false otherwise
    pub fn verify_positions(positions_a: &[Position], positions_b: &[Position]) -> bool {
        if positions_a.len() != positions_b.len() {
            return false;
        }

        for (pos_a, pos_b) in positions_a.iter().zip(positions_b.iter()) {
            if pos_a.0.len() != pos_b.0.len() {
                return false;
            }

            for (coord_a, coord_b) in pos_a.0.iter().zip(pos_b.0.iter()) {
                if coord_a != coord_b {
                    return false;
                }
            }
        }

        true
    }

    /// Generate random walk coordinates from a hash
    ///
    /// This is a convenience function that combines seed generation and position generation
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash to generate coordinates from
    /// * `external_data` - External data to include in the seed
    /// * `config` - Optional configuration parameters
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Position>, DsmError>` - The resulting position sequence or error
    pub fn generate_random_walk_coordinates(
        hash: &Hash,
        external_data: &[u8],
        config: Option<RandomWalkConfig>,
    ) -> Result<Vec<Position>, DsmError> {
        let seed = generate_seed(hash, external_data, None);
        generate_positions(&seed, config)
    }

    /// Verify random walk coordinates against a hash and external data
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash to verify against
    /// * `external_data` - External data used in seed generation
    /// * `positions` - Positions to verify
    /// * `config` - Optional configuration parameters
    ///
    /// # Returns
    ///
    /// * `Result<bool, DsmError>` - True if verification succeeds, false otherwise
    pub fn verify_random_walk_coordinates(
        hash: &Hash,
        external_data: &[u8],
        positions: &[Position],
        config: Option<RandomWalkConfig>,
    ) -> Result<bool, DsmError> {
        let seed = generate_seed(hash, external_data, None);
        let expected_positions = generate_positions(&seed, config)?;
        Ok(verify_positions(positions, &expected_positions))
    }

    /// Generate random walk verification for a forward commitment
    ///
    /// Implements the forward commitment verification described in the whitepaper section 7.3
    ///
    /// # Arguments
    ///
    /// * `commitment` - Commitment hash
    /// * `entropy` - Entropy value
    /// * `config` - Optional configuration parameters
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Position>, DsmError>` - Position sequence for the forward commitment
    pub fn generate_forward_commitment_verification(
        commitment: &Hash,
        entropy: &[u8],
        config: Option<RandomWalkConfig>,
    ) -> Result<Vec<Position>, DsmError> {
        let seed = generate_seed(commitment, entropy, None);
        generate_positions(&seed, config)
    }

    /// Generate a secure seed for multi-party verification
    ///
    /// # Arguments
    ///
    /// * `state` - Current state
    /// * `operation` - Operation data
    /// * `participants` - Participant identifiers
    ///
    /// # Returns
    ///
    /// * `Hash` - The generated secure seed
    pub fn generate_secure_multi_party_seed(
        state: &crate::types::state_types::State,
        operation: &[u8],
        participants: &[&[u8]],
    ) -> Result<Hash, DsmError> {
        let mut hasher = dsm_domain_hasher("DSM/walk-mpc-seed");

        // Add state hash
        hasher.update(&state.hash()?);

        // Add operation
        hasher.update(operation);

        // Add all participants
        for participant in participants {
            hasher.update(participant);
        }

        // Return the seed
        Ok(Hash::from(*hasher.finalize().as_bytes()))
    }

    pub fn verify_state_transition(
        previous_state: &crate::types::state_types::State,
        new_state: &crate::types::state_types::State,
        positions: &[Position],
    ) -> Result<bool, DsmError> {
        // Extract operation data from the new state
        let operation = new_state.operation.to_bytes();

        // Generate the expected seed based on previous state and operation.
        // Per §11 eq. 14 entropy is derived from adjacency inputs — prev
        // entropy, op, and the parent hash — not a counter.
        let previous_state_hash = previous_state.hash()?;
        let next_entropy = crate::core::state_machine::utils::calculate_next_entropy(
            &previous_state.entropy,
            &operation,
            &previous_state_hash,
        );
        let hash_array: [u8; 32] = previous_state_hash.as_slice().try_into().map_err(
            |e: std::array::TryFromSliceError| {
                DsmError::internal("Failed to convert hash to array".to_string(), Some(e))
            },
        )?;
        let expected_seed = generate_seed(&Hash::from(hash_array), &operation, Some(&next_entropy));

        // Generate expected positions
        let expected_positions = generate_positions(&expected_seed, None::<RandomWalkConfig>)?;

        // Verify positions match
        Ok(verify_positions(positions, &expected_positions))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::blake3::dsm_domain_hasher;
        use crate::core::state_machine::utils;

        struct TestCsprng {
            current: [u8; 32],
        }

        impl TestCsprng {
            fn new(seed: &[u8]) -> Self {
                // Use domain-separated hash so test CSPRNG is unambiguously distinct from
                // production random-walk hashing (tag = "DSM/test-csprng-seed").
                let mut hasher = dsm_domain_hasher("DSM/test-csprng-seed");
                hasher.update(seed);
                TestCsprng {
                    current: *hasher.finalize().as_bytes(),
                }
            }

            fn next_u32(&mut self) -> u32 {
                let mut hasher = dsm_domain_hasher("DSM/test-csprng-next");
                hasher.update(&self.current);
                self.current = *hasher.finalize().as_bytes();
                match self.current[0..4].try_into() {
                    Ok(bytes) => u32::from_le_bytes(bytes),
                    Err(_) => {
                        // Blake3 always produces 32 bytes, so this should never happen
                        // If it does, return a default value
                        0
                    }
                }
            }

            fn next_i32_range(&mut self, min: i32, max: i32) -> i32 {
                let range = (max - min) as u32;
                (self.next_u32() % range) as i32 + min
            }
        }

        #[test]
        fn test_csprng() {
            let seed = b"test_seed";
            let mut rng = TestCsprng::new(seed);
            let num1 = rng.next_u32();
            let num2 = rng.next_u32();
            assert_ne!(num1, num2);

            // Test next_i32_range
            let min = -100;
            let max = 100;
            let num = rng.next_i32_range(min, max);
            assert!(num >= min && num < max);
        }

        #[test]
        fn test_generate_seed() {
            let state = blake3::hash(b"test_state");
            let external_data = b"test_data";

            let seed1 = generate_seed(&state, external_data, None);
            let seed2 = generate_seed(&state, external_data, None);

            // Same inputs should produce the same seed
            assert_eq!(seed1, seed2);

            // Different inputs should produce different seeds
            let seed3 = generate_seed(&state, b"different_data", None);
            assert_ne!(seed1, seed3);
        }

        #[test]
        fn test_generate_positions() {
            let seed = blake3::hash(b"test_seed");

            // Default configuration
            let positions1 = generate_positions(&seed, None)
                .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
                .unwrap();
            assert_eq!(positions1.len(), DEFAULT_STEP_COUNT);
            assert_eq!(positions1[0].0.len(), DEFAULT_DIMENSIONS);

            // Same seed should produce the same positions
            let positions2 = generate_positions(&seed, None)
                .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
                .unwrap();
            assert_eq!(positions1, positions2);

            // Different seed should produce different positions
            let different_seed = blake3::hash(b"different_seed");
            let positions3 = generate_positions(&different_seed, None)
                .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
                .unwrap();
            assert_ne!(positions1, positions3);

            // Custom configuration
            let config = RandomWalkConfig {
                dimensions: 2,
                step_count: 10,
                max_coordinate: 100,
                position_count: 10,
            };

            let positions4 = generate_positions(&seed, Some(config))
                .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
                .unwrap();
            assert_eq!(positions4.len(), 10);
            assert_eq!(positions4[0].0.len(), 2);

            // Ensure coordinates are within range
            for position in &positions4 {
                for coordinate in &position.0 {
                    assert!(*coordinate >= -100 && *coordinate <= 100);
                }
            }
        }

        #[test]
        fn test_verify_positions() {
            let positions1 = vec![Position(vec![1, 2, 3]), Position(vec![4, 5, 6])];

            let positions2 = vec![Position(vec![1, 2, 3]), Position(vec![4, 5, 6])];

            let positions3 = vec![
                Position(vec![1, 2, 3]),
                Position(vec![4, 5, 7]), // Different
            ];

            assert!(verify_positions(&positions1, &positions2));
            assert!(!verify_positions(&positions1, &positions3));
        }

        #[test]
        fn test_generate_and_verify_random_walk() {
            let hash = blake3::hash(b"test_hash");
            let external_data = b"test_data";

            let positions = generate_random_walk_coordinates(&hash, external_data, None)
                .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
                .unwrap();
            let result = verify_random_walk_coordinates(&hash, external_data, &positions, None)
                .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
                .unwrap();

            assert!(result);

            // Different external data should fail verification
            let result2 =
                verify_random_walk_coordinates(&hash, b"different_data", &positions, None)
                    .map_err(|_| {
                        DsmError::internal(0.to_string(), None::<std::convert::Infallible>)
                    })
                    .unwrap();
            assert!(!result2);
        }

        #[test]
        fn test_calculate_next_entropy() {
            let current_entropy = b"current_entropy";
            let operation = b"operation";

            // Same inputs → same entropy (deterministic)
            let entropy1 = utils::calculate_next_entropy(current_entropy, operation, &[0u8; 32]);
            let entropy2 = utils::calculate_next_entropy(current_entropy, operation, &[0u8; 32]);
            assert_eq!(entropy1, entropy2);

            // Different parent hash → different entropy
            let entropy3 = utils::calculate_next_entropy(current_entropy, operation, &[0x01; 32]);
            assert_ne!(entropy1, entropy3);
        }
    }
}
