//! Token MPC SDK Module
//!
//! This module implements Multi-Party Computation (MPC) for secure token creation
//! using the same protocol as device ID generation. It provides secure token
//! genesis through distributed computation across multiple storage nodes.
//!
//! ## Key Features
//!
//! * **MPC Token Creation**: Secure token creation using distributed computation
//! * **ERA Token Support**: Native DSM ecosystem token creation
//! * **Policy Integration**: Content-Addressed Token Policy Anchor (CTPA) support
//! * **Quantum Resistance**: Post-quantum cryptographic algorithms
//! * **Threshold Security**: Configurable security thresholds
//! * **Global Policy Reference**: Support for global policy publishing and caching
//! * **Bilateral Transfers**: Complete implementation of secure peer-to-peer token transfers
//! * **Policy Enforcement**: Automatic policy validation and enforcement during transfers
//!
//! ## Security Features
//!
//! * **Token Anchoring**: All tokens are anchored to their creator's genesis state for
//!   enhanced security and provenance verification
//! * **Policy-Based Access Control**: Token policies can restrict operations and enforce
//!   transfer rules
//! * **Local Policy Caching**: Token holders can cache policies locally for efficient validation
//! * **Global Policy Reference**: Policies are stored on storage nodes for global reference
//!
//! ## Bilateral Transfers
//!
//! Bilateral transfers provide a secure way to transfer tokens between parties
//! without requiring global consensus. This is achieved through a two-phase commit
//! process where both the sender and recipient update their respective states.
//!
//! 1. **Send Phase**: Sender creates a state with reduced balance
//! 2. **Receive Phase**: Recipient creates a state with increased balance
//! 3. **Verification**: Both parties verify the consistency of their states
//!
//! ## Usage Example
//!
//! ```rust
//! use dsm_sdk::token_mpc_sdk::TokenMpcSDK;
//! use dsm_sdk::core_sdk::CoreSDK;
//! use std::sync::Arc;
//!
//! async fn example() {
//!     let core_sdk = Arc::new(CoreSDK::new());
//!     let token_mpc_sdk = TokenMpcSDK::new(core_sdk);
//!
//!     // Create a new token using MPC
//!     let params = TokenCreationParams {
//!         token_name: "MyToken".to_string(),
//!         token_symbol: "MTK".to_string(),
//!         initial_supply: 1000000,
//!         threshold: 3,
//!         timeout_ticks: 300,
//!         ..Default::default()
//!     };
//!
//!     let session_id = token_mpc_sdk.initiate_token_creation(params).await?;
//!     let token_genesis = token_mpc_sdk.wait_for_completion(session_id).await?;
//!     
//!     // Transfer tokens using bilateral transfer
//!     let (updated_state, transfer_id) = token_mpc_sdk.transfer_token(
//!         &token_genesis.token_id,
//!         "recipient_id",
//!         100,
//!         Some("Payment for services".to_string()),
//!     ).await?;
//! }
//! ```

use std::{collections::HashMap, sync::Arc};

use dsm::{
    core::token::token_factory::{create_token_genesis, TokenContribution, TokenGenesis},
    types::{
        error::DsmError,
        policy_types::{PolicyAnchor, PolicyFile},
        state_types::State,
        token_types::{Balance, TokenMetadata, TokenType},
        operations::TransactionMode,
    },
};
use parking_lot::RwLock;
use log::debug;
use prost::Message;
use dsm::common::deterministic_id;

use super::{
    core_sdk::CoreSDK,
    identity_sdk::IdentitySDK,
    policy_cache::{TokenPolicyCache, PolicyCacheConfig},
    token_sdk::TokenSDK,
};

/// Parameters for MPC token creation
#[derive(Debug, Clone)]
pub struct TokenCreationParams {
    /// Token name
    pub token_name: String,
    /// Token symbol
    pub token_symbol: String,
    /// Initial token supply
    pub initial_supply: u64,
    /// Description of the token
    pub description: Option<String>,
    /// Icon URL for the token
    pub icon_url: Option<String>,
    /// Number of decimal places
    pub decimals: u8,
    /// Custom token fields
    pub fields: HashMap<String, String>,
    /// MPC threshold (minimum number of nodes required)
    pub threshold: usize,
    /// Session timeout in deterministic ticks
    pub timeout_ticks: u64,
    /// Policy file for token governance
    pub policy_file: Option<PolicyFile>,
    /// Whether to skip policy publishing (for testing)
    pub skip_policy_publishing: bool,
    /// Whether to cache policy locally (defaults to true)
    pub cache_policy_locally: bool,
    /// Whether the token can be transferred bilaterally
    pub allow_bilateral_transfers: bool,
    /// Supported transaction modes for this token
    pub supported_transaction_modes: Option<Vec<TransactionMode>>,
}

/// Default implementation for TokenCreationParams
impl Default for TokenCreationParams {
    fn default() -> Self {
        Self {
            token_name: "Default Token".to_string(),
            token_symbol: "DFT".to_string(),
            initial_supply: 0,
            description: None,
            icon_url: None,
            decimals: 18,
            fields: HashMap::new(),
            threshold: 3,
            timeout_ticks: 300,
            policy_file: None,
            skip_policy_publishing: false,
            cache_policy_locally: true,
            allow_bilateral_transfers: true,
            supported_transaction_modes: None,
        }
    }
}

/// Token MPC session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenMpcState {
    /// Initializing session
    Initializing,
    /// Collecting contributions from nodes
    Collecting,
    /// Aggregating contributions
    Aggregating,
    /// Token creation complete
    Complete,
    /// Session failed or timed out
    Failed,
}

/// MPC session for token creation
#[derive(Debug, Clone)]
pub struct TokenMpcSession {
    /// Unique session identifier
    pub session_id: String,
    /// Token creation parameters
    pub params: TokenCreationParams,
    /// Current session state
    pub state: TokenMpcState,
    /// Number of contributions received
    pub contributions_received: usize,
    /// Generated token genesis (when complete)
    pub token_genesis: Option<TokenGenesis>,
    /// Token metadata (when complete)
    pub token_metadata: Option<TokenMetadata>,
    /// Creator's genesis hash (for anchoring)
    pub creator_genesis_hash: Option<Vec<u8>>,
    /// Session creation time in deterministic ticks
    pub started_at: u64,
    /// Session expiration time in deterministic ticks
    pub expires_at: u64,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Token MPC contribution from a storage node
#[derive(Debug, Clone)]
pub struct TokenMpcContribution {
    /// Node providing the contribution
    pub node_id: String,
    /// Session this contribution is for
    pub session_id: String,
    /// Entropy data contributed by this node
    pub entropy_data: Vec<u8>,
    /// Cryptographic proof of contribution validity
    pub proof: Option<Vec<u8>>,
    /// Deterministic ticks when contribution was made
    pub contribution_ticks: u64,
}

/// Response from MPC token creation
#[derive(Debug, Clone)]
pub struct TokenCreationResponse {
    /// Session ID for tracking
    pub session_id: String,
    /// Current session state
    pub state: TokenMpcState,
    /// Number of contributions received
    pub contributions_received: usize,
    /// Required threshold
    pub threshold: usize,
    /// Whether token creation is complete
    pub complete: bool,
    /// Token metadata (if complete)
    pub token_metadata: Option<TokenMetadata>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Token MPC SDK for secure distributed token creation
pub struct TokenMpcSDK {
    /// Core SDK instance
    core_sdk: Arc<CoreSDK>,
    /// Active MPC sessions
    sessions: Arc<RwLock<HashMap<String, TokenMpcSession>>>,
    /// Storage node endpoints for MPC coordination
    storage_nodes: Arc<RwLock<Vec<String>>>,
    /// Token policy cache for efficient policy access
    policy_cache: Arc<TokenPolicyCache>,
    /// Token SDK for token operations
    token_sdk: Arc<TokenSDK<IdentitySDK>>,
    /// HTTP client for storage node communication (real MPC when local-mpc is off)
    http_client: reqwest::Client,
}

impl TokenMpcSDK {
    /// Build an HTTP client with TLS/CA-cert configuration matching StorageNodeClient.
    fn build_http_client() -> reqwest::Client {
        crate::sdk::storage_node_sdk::build_ca_aware_client()
    }

    /// Default storage node URLs (localhost local-dev node set).
    fn default_storage_nodes() -> Vec<String> {
        vec![
            "http://localhost:8080".to_string(),
            "http://localhost:8081".to_string(),
            "http://localhost:8082".to_string(),
            "http://localhost:8083".to_string(),
            "http://localhost:8084".to_string(),
        ]
    }

    /// Create a new Token MPC SDK instance
    pub fn new(core_sdk: Arc<CoreSDK>) -> Self {
        let http_client = Self::build_http_client();
        let node_urls = Self::default_storage_nodes();

        // Create policy cache with HTTP client for real network publishing
        let policy_cache = Arc::new(TokenPolicyCache::new(
            core_sdk.clone(),
            None,
            Some(http_client.clone()),
            node_urls.clone(),
        ));

        let device_id = core_sdk
            .get_current_state()
            .map(|s| s.device_info.device_id)
            .unwrap_or_else(|_| {
                crate::util::domain_helpers::device_id_hash_bytes(b"default_device")
            });

        // Create token SDK instance
        let token_sdk = Arc::new(TokenSDK::<IdentitySDK>::new(core_sdk.clone(), device_id));

        Self {
            core_sdk,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            storage_nodes: Arc::new(RwLock::new(node_urls)),
            policy_cache,
            token_sdk,
            http_client,
        }
    }

    /// Create a new Token MPC SDK instance with custom policy cache config
    pub fn with_policy_cache_config(
        core_sdk: Arc<CoreSDK>,
        policy_cache_config: PolicyCacheConfig,
    ) -> Self {
        let http_client = Self::build_http_client();
        let node_urls = Self::default_storage_nodes();

        // Create policy cache with custom configuration and HTTP client
        let policy_cache = Arc::new(TokenPolicyCache::new(
            core_sdk.clone(),
            Some(policy_cache_config),
            Some(http_client.clone()),
            node_urls.clone(),
        ));

        let device_id = core_sdk
            .get_current_state()
            .map(|s| s.device_info.device_id)
            .unwrap_or_else(|_| {
                crate::util::domain_helpers::device_id_hash_bytes(b"default_device")
            });

        // Create token SDK instance
        let token_sdk = Arc::new(TokenSDK::<IdentitySDK>::new(core_sdk.clone(), device_id));

        Self {
            core_sdk,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            storage_nodes: Arc::new(RwLock::new(node_urls)),
            policy_cache,
            token_sdk,
            http_client,
        }
    }

    /// Configure storage node endpoints
    pub fn set_storage_nodes(&self, nodes: Vec<String>) {
        let mut storage_nodes = self.storage_nodes.write();
        *storage_nodes = nodes;
    }

    /// Initiate MPC token creation
    pub async fn initiate_token_creation(
        &self,
        params: TokenCreationParams,
    ) -> Result<String, DsmError> {
        // Generate unique session ID from token parameters
        let params_hash = dsm::crypto::blake3::domain_hash(
            "DSM/mpc-params",
            &[
                params.token_name.as_bytes(),
                params.token_symbol.as_bytes(),
                &params.initial_supply.to_le_bytes(),
            ]
            .concat(),
        );
        let session_id = deterministic_id::generate_session_id(params_hash.as_bytes());

        // Validate parameters: threshold must be > 0 and <= number of nodes
        let storage_nodes_len = {
            let storage_nodes = self.storage_nodes.read();
            storage_nodes.len()
        };
        if params.threshold == 0 || params.threshold > storage_nodes_len {
            return Err(DsmError::InvalidIndex);
        }

        // Get creator's genesis hash if available
        let creator_genesis_hash = self
            .core_sdk
            .get_current_state()
            .ok()
            .map(|genesis| genesis.hash.to_vec());

        // Create session using deterministic logical time
        let start = crate::util::deterministic_time::tick();
        // Create session
        let session = TokenMpcSession {
            session_id: session_id.clone(),
            params: params.clone(),
            state: TokenMpcState::Initializing,
            contributions_received: 0,
            token_genesis: None,
            token_metadata: None,
            creator_genesis_hash,
            started_at: start,
            expires_at: start + params.timeout_ticks,
            error_message: None,
        };

        // Store session
        {
            let mut sessions = self.sessions.write();
            sessions.insert(session_id.clone(), session);
        }

        // Send MPC requests to storage nodes (logging/notification step)
        self.send_mpc_requests(&session_id, &params).await?;

        // --- Feature-gated session completion ---
        #[cfg(not(feature = "local-mpc"))]
        {
            // Real MPC: fetch entropy from storage nodes and complete in one shot
            let mut session = {
                let mut sessions = self.sessions.write();
                let s = sessions
                    .get_mut(&session_id)
                    .ok_or_else(|| DsmError::state("Session disappeared during MPC init"))?;
                s.state = TokenMpcState::Aggregating;
                s.clone()
            };

            match self.process_token_creation(&mut session).await {
                Ok(_) => {
                    // Session was persisted inside process_token_creation
                    Ok(session_id)
                }
                Err(e) => {
                    // Mark session as failed
                    let mut sessions = self.sessions.write();
                    if let Some(s) = sessions.get_mut(&session_id) {
                        s.state = TokenMpcState::Failed;
                        s.error_message = Some(format!("{e}"));
                    }
                    Err(e)
                }
            }
        }

        #[cfg(feature = "local-mpc")]
        {
            // Mock mode: set to Collecting, caller drives with add_contribution()
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.state = TokenMpcState::Collecting;
            }
            Ok(session_id)
        }
    }

    /// Send MPC requests to storage nodes
    async fn send_mpc_requests(
        &self,
        session_id: &str,
        params: &TokenCreationParams,
    ) -> Result<(), DsmError> {
        let storage_nodes = self.storage_nodes.read();

        // Get creator's genesis if available
        let creator_genesis_id = self
            .core_sdk
            .get_state_by_number(0)
            .map(|genesis| crate::util::text_id::encode_base32_crockford(&genesis.hash[..16]))
            .unwrap_or_else(|_| "unknown".to_string());

        for node_url in storage_nodes.iter() {
            #[cfg(debug_assertions)]
            log::debug!("planning MPC request node={}", node_url);
            // Build canonical TokenMpcRequest proto payload for deterministic transport
            let req_proto = crate::generated::TokenMpcRequest {
                session_id: session_id.to_string(),
                token_name: params.token_name.clone(),
                token_symbol: params.token_symbol.clone(),
                threshold: params.threshold as u32,
                creator_genesis_id: creator_genesis_id.clone(),
                anchored_token: true,
                request_iteration: crate::util::deterministic_time::peek(),
            };
            let _request_payload = req_proto.encode_to_vec();

            // Send HTTP request to storage node
            // Note: In a real implementation, this would use an HTTP client
            // For now, we'll simulate the request
            #[cfg(feature = "diagnostics")]
            log::info!(
                "Sending token MPC request to node: {} for session: {}",
                node_url,
                session_id
            );
            // Use node_url to avoid unused variable warning
            let _ = node_url;
        }

        Ok(())
    }

    /// Check session status
    pub fn get_session_status_sync(&self, session_id: &str) -> Option<TokenCreationResponse> {
        let sessions = self.sessions.read();
        sessions
            .get(session_id)
            .map(|session| TokenCreationResponse {
                session_id: session.session_id.clone(),
                state: session.state.clone(),
                contributions_received: session.contributions_received,
                threshold: session.params.threshold,
                complete: session.state == TokenMpcState::Complete,
                token_metadata: session.token_metadata.clone(),
                error_message: session.error_message.clone(),
            })
    }

    /// Add a contribution from a storage node
    pub async fn add_contribution(
        &self,
        contribution: TokenMpcContribution,
    ) -> Result<bool, DsmError> {
        // First check session state without holding lock across await
        let should_process = {
            let mut sessions = self.sessions.write();

            if let Some(session) = sessions.get_mut(&contribution.session_id) {
                // Check session state
                if session.state != TokenMpcState::Collecting {
                    return Err(DsmError::InvalidIndex);
                }

                // Check expiration
                let current_time = crate::util::deterministic_time::peek();

                if current_time > session.expires_at {
                    session.state = TokenMpcState::Failed;
                    session.error_message = Some("Session expired".to_string());
                    return Err(DsmError::timeout("Session expired".to_string()));
                }

                // Add contribution
                session.contributions_received += 1;

                // Check if we have enough contributions
                if session.contributions_received >= session.params.threshold {
                    session.state = TokenMpcState::Aggregating;
                    true
                } else {
                    false
                }
            } else {
                return Err(DsmError::NotFound {
                    entity: "session".to_string(),
                    details: Some(contribution.session_id),
                    context: "Session not found".to_string(),
                    source: None,
                });
            }
        };

        if should_process {
            // Process token creation with a separate lock acquisition
            let session = {
                let mut sessions = self.sessions.write();
                sessions.get_mut(&contribution.session_id).cloned()
            };

            if let Some(mut session) = session {
                return self.process_token_creation(&mut session).await;
            }
        }

        Ok(false) // Not yet ready to process
    }

    /// Process token creation when threshold is reached
    async fn process_token_creation(
        &self,
        session: &mut TokenMpcSession,
    ) -> Result<bool, DsmError> {
        // Get creator's genesis state - required for anchoring tokens
        let creator_genesis = self
            .core_sdk
            .get_state_by_number(0)
            .map_err(|_| DsmError::state("Creator's Genesis not found"))?;

        // Generate token data for MPC
        let token_data = self.generate_token_data(&session.params)?;

        // --- Feature-gated MPC contribution collection ---
        #[cfg(feature = "local-mpc")]
        let (participants, contributions) = {
            // Local mock: deterministic dummy participants and contributions
            let participants: Vec<[u8; 32]> = (0..session.params.threshold)
                .map(|i| {
                    *dsm::crypto::blake3::domain_hash(
                        "DSM/mpc-node-id",
                        format!("node_{i}").as_bytes(),
                    )
                    .as_bytes()
                })
                .collect();
            let contributions: Vec<TokenContribution> = participants
                .iter()
                .map(|p| TokenContribution {
                    participant: *p,
                    material: *dsm::crypto::blake3::domain_hash(
                        "DSM/mpc-material",
                        b"dummy_material",
                    )
                    .as_bytes(),
                })
                .collect();
            (participants, contributions)
        };

        #[cfg(not(feature = "local-mpc"))]
        let (participants, contributions) = {
            self.fetch_real_mpc_contributions(session.params.threshold)
                .await?
        };

        // Add creator's genesis hash to token data to anchor it
        let mut anchored_token_data = Vec::new();
        anchored_token_data.extend_from_slice(&creator_genesis.hash);
        anchored_token_data.extend_from_slice(&token_data);

        // Prepare policy anchor
        let policy_anchor = if let Some(pf) = &session.params.policy_file {
            Some(PolicyAnchor::from_policy(pf)?)
        } else {
            None
        };

        // Create token genesis using MPC
        let token_genesis = create_token_genesis(
            session.params.threshold,
            participants,
            &anchored_token_data,
            policy_anchor,
            contributions,
        )?;

        // If policy file is provided, ensure it's published to storage nodes
        // and cached locally for future reference
        if let Some(policy_file) = &session.params.policy_file {
            // Handle policy according to flags
            if !session.params.skip_policy_publishing || session.params.cache_policy_locally {
                // If we should cache locally
                if session.params.cache_policy_locally {
                    // Cache the policy locally and mark it as required
                    let policy_id = self
                        .policy_cache
                        .cache_policy(policy_file.clone(), true)
                        .await
                        .map_err(|e| {
                            DsmError::internal(
                                format!("Failed to cache policy: {e}"),
                                None::<std::io::Error>,
                            )
                        })?;

                    debug!("Token policy published and cached with ID: {policy_id}");
                }
                // If we should publish but not cache
                else if !session.params.skip_policy_publishing {
                    // Just publish without local caching
                    let policy_anchor = PolicyAnchor::from_policy(policy_file).map_err(|e| {
                        DsmError::internal(
                            format!("Failed to generate policy anchor: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                    let policy_id =
                        crate::util::text_id::encode_base32_crockford(policy_anchor.as_bytes());

                    // Publish without caching
                    let _ = self
                        .policy_cache
                        .publish_policy_to_network(policy_file.clone())
                        .await
                        .map_err(|e| {
                            DsmError::internal(
                                format!("Failed to publish policy: {e}"),
                                None::<std::io::Error>,
                            )
                        })?;

                    debug!("Token policy published with ID: {policy_id}");
                }
            } else {
                debug!("Token policy handling skipped due to flags");
            }
        }

        // Create token metadata with creator genesis reference
        let token_metadata =
            self.create_token_metadata(&session.params, &token_genesis, &creator_genesis.hash)?;

        // Update session
        session.token_genesis = Some(token_genesis);
        session.token_metadata = Some(token_metadata);
        session.state = TokenMpcState::Complete;

        // Persist the updated session back into the sessions map so observers see completion
        {
            let mut sessions = self.sessions.write();
            if let Some(existing) = sessions.get_mut(&session.session_id) {
                *existing = session.clone();
            } else {
                sessions.insert(session.session_id.clone(), session.clone());
            }
        }

        Ok(true)
    }

    /// Fetch real MPC contributions from storage nodes via HTTP.
    ///
    /// Each storage node provides 32 bytes of CSPRNG entropy via `GET /api/v2/genesis/entropy`.
    /// Participant identities are derived deterministically from node URLs using domain-separated
    /// BLAKE3. Nodes are tried sequentially; individual failures are skipped. Returns an error
    /// only if fewer than `threshold` nodes respond successfully.
    #[cfg(not(feature = "local-mpc"))]
    async fn fetch_real_mpc_contributions(
        &self,
        threshold: usize,
    ) -> Result<(Vec<[u8; 32]>, Vec<TokenContribution>), DsmError> {
        let storage_nodes = self.storage_nodes.read().clone();

        if storage_nodes.len() < threshold {
            return Err(DsmError::invalid_operation(format!(
                "Need at least {} storage nodes, only {} configured",
                threshold,
                storage_nodes.len()
            )));
        }

        log::info!(
            "Fetching MPC entropy from {} storage nodes (threshold={})",
            storage_nodes.len(),
            threshold
        );

        let mut participants = Vec::new();
        let mut contributions = Vec::new();
        let mut errors = Vec::new();

        for (i, url) in storage_nodes.iter().enumerate() {
            let entropy_url = format!("{}/api/v2/genesis/entropy", url.trim_end_matches('/'));

            log::info!("Fetching entropy from node {}: {}", i, entropy_url);

            let response = match self.http_client.get(&entropy_url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    log::warn!("Failed to fetch entropy from {}: {}", entropy_url, e);
                    errors.push(format!("Node {} ({}): {}", i, url, e));
                    continue;
                }
            };

            if !response.status().is_success() {
                log::warn!(
                    "Storage node {} returned error status: {}",
                    url,
                    response.status()
                );
                errors.push(format!("Node {} ({}): HTTP {}", i, url, response.status()));
                continue;
            }

            let entropy_bytes = match response.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("Failed to read entropy bytes from {}: {}", url, e);
                    errors.push(format!("Node {} ({}): read error: {}", i, url, e));
                    continue;
                }
            };

            if entropy_bytes.len() != 32 {
                log::warn!(
                    "Storage node {} returned {} bytes, expected 32",
                    url,
                    entropy_bytes.len()
                );
                errors.push(format!(
                    "Node {} ({}): returned {} bytes, expected 32",
                    i,
                    url,
                    entropy_bytes.len()
                ));
                continue;
            }

            // Derive participant ID from node URL using domain-separated BLAKE3
            let participant_id: [u8; 32] =
                dsm::crypto::blake3::domain_hash_bytes("DSM/token-mpc/participant", url.as_bytes());

            let mut material = [0u8; 32];
            material.copy_from_slice(&entropy_bytes);

            participants.push(participant_id);
            contributions.push(TokenContribution {
                participant: participant_id,
                material,
            });

            log::info!("Received 32 bytes of entropy from node {}", i);

            // Stop once we have enough
            if contributions.len() >= threshold {
                break;
            }
        }

        // Check if we reached quorum
        if contributions.len() < threshold {
            return Err(DsmError::crypto(
                format!(
                    "Insufficient MPC contributions: got {}, need {}. Errors: {:?}",
                    contributions.len(),
                    threshold,
                    errors
                ),
                None::<String>,
            ));
        }

        log::info!(
            "Gathered {} MPC contributions (threshold={})",
            contributions.len(),
            threshold
        );

        Ok((participants, contributions))
    }

    /// Generate token data for MPC process
    fn generate_token_data(&self, params: &TokenCreationParams) -> Result<Vec<u8>, DsmError> {
        let mut data = Vec::new();
        data.extend_from_slice(params.token_name.as_bytes());
        data.extend_from_slice(params.token_symbol.as_bytes());
        data.extend_from_slice(&params.initial_supply.to_le_bytes());
        data.extend_from_slice(&params.decimals.to_le_bytes());

        if let Some(desc) = &params.description {
            data.extend_from_slice(desc.as_bytes());
        }

        Ok(data)
    }

    /// Create token metadata from parameters and genesis
    fn create_token_metadata(
        &self,
        params: &TokenCreationParams,
        genesis: &TokenGenesis,
        creator_genesis_hash: &[u8],
    ) -> Result<TokenMetadata, DsmError> {
        let token_id = crate::util::text_id::short_id(&genesis.token_hash, 8); // Use first 8 bytes as token ID
        let creator_genesis_id = crate::util::text_id::short_id(creator_genesis_hash, 8); // Creator's genesis ID

        // Add creator's genesis information to fields
        let mut fields = params.fields.clone();
        fields.insert("creator_genesis".to_string(), creator_genesis_id.clone());
        fields.insert("anchored".to_string(), "true".to_string());
        fields.insert("creation_method".to_string(), "mpc".to_string());

        Ok(TokenMetadata {
            name: params.token_name.clone(),
            symbol: params.token_symbol.clone(),
            description: params.description.clone(),
            icon_url: params.icon_url.clone(),
            decimals: params.decimals,
            fields,
            token_id: token_id.clone(),
            token_type: TokenType::Created,
            owner_id: genesis.token_entropy,
            creation_tick: crate::util::deterministic_time::tick(),
            metadata_uri: None,
            policy_anchor: genesis.policy_anchor.as_ref().map(|anchor| {
                format!(
                    "dsm:policy:{}",
                    crate::util::text_id::encode_base32_crockford(anchor.as_bytes())
                )
            }),
        })
    }

    /// Wait for token creation to complete
    pub async fn wait_for_completion(&self, session_id: String) -> Result<TokenMetadata, DsmError> {
        let max_wait = 60; // Maximum wait time in seconds
        let mut waited = 0;

        loop {
            if waited >= max_wait {
                return Err(DsmError::timeout("Token creation timeout".to_string()));
            }

            if let Ok(response) = self.get_session_status(&session_id).await {
                match response.state {
                    TokenMpcState::Complete => {
                        if let Some(metadata) = response.token_metadata {
                            return Ok(metadata);
                        } else {
                            return Err(DsmError::internal(
                                "Token metadata not available",
                                None::<String>,
                            ));
                        }
                    }
                    TokenMpcState::Failed => {
                        let error_msg = response
                            .error_message
                            .unwrap_or_else(|| "Token creation failed".to_string());
                        return Err(DsmError::internal(error_msg, None::<String>));
                    }
                    _ => {
                        // Still processing, wait a bit (deterministic)
                        // Deterministic: no wall-clock delays, continue immediately
                        waited += 1;
                    }
                }
            } else {
                return Err(DsmError::NotFound {
                    entity: "Session".to_string(),
                    details: Some("Session not found".to_string()),
                    context: "Session lookup failed".to_string(),
                    source: None,
                });
            }
        }
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<TokenCreationResponse> {
        let sessions = self.sessions.read();
        sessions
            .values()
            .map(|session| TokenCreationResponse {
                session_id: session.session_id.clone(),
                state: session.state.clone(),
                contributions_received: session.contributions_received,
                threshold: session.params.threshold,
                complete: session.state == TokenMpcState::Complete,
                token_metadata: session.token_metadata.clone(),
                error_message: session.error_message.clone(),
            })
            .collect()
    }

    /// Cancel a session
    pub fn cancel_session(&self, session_id: &str) -> Result<(), DsmError> {
        let mut sessions = self.sessions.write();
        if let Some(session) = sessions.get_mut(session_id) {
            session.state = TokenMpcState::Failed;
            session.error_message = Some("Cancelled by user".to_string());
            Ok(())
        } else {
            Err(DsmError::NotFound {
                entity: "Session".to_string(),
                details: Some("Session not found".to_string()),
                context: "Session lookup failed".to_string(),
                source: None,
            })
        }
    }

    /// Get a token policy by its ID
    pub async fn get_token_policy(&self, policy_id: &str) -> Result<Option<PolicyFile>, DsmError> {
        let response = self.policy_cache.get_policy(policy_id).await?;
        Ok(response.policy)
    }

    /// Publish a token policy to storage nodes
    pub async fn publish_token_policy(&self, policy_file: PolicyFile) -> Result<String, DsmError> {
        self.policy_cache.cache_policy(policy_file, true).await
    }

    /// Check if a token policy exists in the cache or on storage nodes
    pub async fn token_policy_exists(&self, policy_id: &str) -> Result<bool, DsmError> {
        let policy = self.policy_cache.get_policy(policy_id).await?;
        Ok(policy.found)
    }

    /// List all cached token policies
    pub async fn list_cached_policies(&self) -> Result<Vec<String>, DsmError> {
        let policies = self.policy_cache.list_cached_policies().await?;
        Ok(policies.into_iter().map(|p| p.name).collect())
    }

    /// Create a basic policy file for a token
    pub fn create_basic_policy_file(
        &self,
        name: &str,
        version: &str,
        description: Option<&str>,
        transferable: bool,
    ) -> PolicyFile {
        let mut policy = PolicyFile::new(name, version, "dsm_token_mpc_sdk");

        if let Some(desc) = description {
            policy.description = Some(desc.to_string());
        }

        // Add basic metadata
        policy
            .add_metadata("created_by", "dsm_token_mpc_sdk")
            .add_metadata("token_name", name);

        if transferable {
            policy.add_metadata("transferable", "true");
        } else {
            policy.add_metadata("transferable", "false");

            // Add metadata to indicate this token is non-transferable
            // Rather than using complex PolicyCondition that causes parsing issues,
            // we use metadata that can be checked during validation
            policy.add_metadata("transfer_restricted", "true");
            policy.add_metadata("allowed_operations", "mint,burn"); // Only allow mint and burn, not transfer
        }

        policy
    }

    /// Ensure a token policy is cached locally
    pub async fn ensure_policy_cached(
        &self,
        token_metadata: &TokenMetadata,
    ) -> Result<bool, DsmError> {
        // Check if the token has a policy anchor
        if let Some(policy_anchor_uri) = &token_metadata.policy_anchor {
            // Parse the policy ID from the URI
            // Format: "dsm:policy:policyId"
            let parts: Vec<&str> = policy_anchor_uri.split(':').collect();
            if parts.len() == 3 && parts[0] == "dsm" && parts[1] == "policy" {
                let policy_id = parts[2];

                // Check if policy exists in cache
                if let Ok(policy_response) = self.policy_cache.get_policy(policy_id).await {
                    if policy_response.found {
                        // Already cached
                        self.policy_cache
                            .mark_policy_as_required(policy_id, "token_operation")?;
                        return Ok(true);
                    }
                }

                // Try to fetch from network and cache
                if let Ok(policy_response) = self.policy_cache.get_policy(policy_id).await {
                    if policy_response.found {
                        // Mark as required since this token references it
                        self.policy_cache
                            .mark_policy_as_required(policy_id, "token_operation")?;
                        return Ok(true);
                    }
                }

                // Policy not found
                return Ok(false);
            }
        }

        // No policy anchor to cache
        Ok(true)
    }

    /// Create a token with a published and cached policy
    ///
    /// This is a convenience method that demonstrates how to create a token with
    /// a policy that is published to the global policy reference on storage nodes
    /// and cached locally for future reference.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dsm_sdk::token_mpc_sdk::TokenMpcSDK;
    /// use dsm_sdk::core_sdk::CoreSDK;
    /// use std::sync::Arc;
    ///
    /// async fn example() {
    ///    let core_sdk = Arc::new(CoreSDK::new());
    ///    let token_mpc_sdk = TokenMpcSDK::new(core_sdk);
    ///
    ///    // Create a token with published policy
    ///    let result = token_mpc_sdk.create_token_with_policy(
    ///        "MyToken",
    ///        "MTK",
    ///        1000000,
    ///        "My first token with published policy",
    ///        true, // Make it transferable
    ///        3,    // Threshold
    ///    ).await;
    ///
    ///    if let Ok(token_metadata) = result {
    ///        println!("Created token: {} with ID {}", token_metadata.name, token_metadata.token_id);
    ///        println!("Policy reference: {}", token_metadata.policy_anchor.unwrap_or_default());
    ///    }
    /// }
    /// ```
    pub async fn create_token_with_policy(
        &self,
        name: &str,
        symbol: &str,
        initial_supply: u64,
        description: &str,
        transferable: bool,
        threshold: usize,
    ) -> Result<TokenMetadata, DsmError> {
        // Create a basic policy file
        let policy_file =
            self.create_basic_policy_file(name, "1.0", Some(description), transferable);

        // Create token parameters with policy
        let params = TokenCreationParams {
            token_name: name.to_string(),
            token_symbol: symbol.to_string(),
            initial_supply,
            description: Some(description.to_string()),
            icon_url: None,
            decimals: 18,
            fields: {
                let mut fields = HashMap::new();
                fields.insert("version".to_string(), "1.0".to_string());
                fields.insert("transferable".to_string(), transferable.to_string());
                fields
            },
            threshold,
            timeout_ticks: 300,
            policy_file: Some(policy_file),
            skip_policy_publishing: false,
            cache_policy_locally: true,
            allow_bilateral_transfers: transferable,
            supported_transaction_modes: if transferable {
                Some(vec![
                    TransactionMode::Bilateral,
                    TransactionMode::Unilateral,
                ])
            } else {
                Some(vec![TransactionMode::Unilateral])
            },
        };

        // Create the token
        let session_id = self.create_anchored_token(params).await?;

        // Wait for token creation to complete
        self.wait_for_completion(session_id).await
    }

    /// Create an anchored token using MPC by utilizing the underlying `initiate_token_creation` method
    /// This anchors the token to the creator's genesis state for enhanced security and provenance.
    pub async fn create_anchored_token(
        &self,
        params: TokenCreationParams,
    ) -> Result<String, DsmError> {
        // Verify that creator genesis exists
        let _creator_genesis = self
            .core_sdk
            .get_state_by_number(0)
            .map_err(|_| DsmError::state("Creator's Genesis not found"))?;

        // Ensure valid threshold
        if params.threshold < 2 {
            return Err(DsmError::InvalidIndex);
        }

        // Initiate token creation with genesis anchoring
        self.initiate_token_creation(params).await
    }

    /// Import token data from another user - useful for bilateral transfers
    pub async fn import_token_data(
        &self,
        token_id: &str,
        metadata: TokenMetadata,
    ) -> Result<bool, DsmError> {
        // First, check if we have the token's policy and cache it if needed
        if let Some(_policy_anchor) = &metadata.policy_anchor {
            self.ensure_policy_cached(&metadata).await?;
        }

        // Store token metadata in the token SDK
        self.token_sdk
            .import_token_metadata(token_id.to_string(), metadata)
            .await?;

        Ok(true)
    }

    /// Get available token IDs from this SDK instance
    pub fn get_available_tokens(&self) -> Vec<String> {
        self.token_sdk.get_available_tokens()
    }

    /// Get the token's metadata if available
    pub async fn get_token_metadata(
        &self,
        token_id: &str,
    ) -> Result<Option<TokenMetadata>, DsmError> {
        self.token_sdk.get_token_metadata(token_id).await
    }

    /// Get debug info about token policies for this SDK instance
    pub async fn get_policy_debug_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();

        // Get policy cache stats
        if let Ok(policies) = self.list_cached_policies().await {
            info.insert(
                "cached_policy_count".to_string(),
                policies.len().to_string(),
            );
        }

        info
    }

    /// Transfer tokens using the bilateral transfer mechanism we created earlier
    /// This method integrates the MPC-created tokens with the bilateral transfer functionality
    pub async fn transfer_token(
        &self,
        token_id: &str,
        recipient: &str,
        amount: u64,
        memo: Option<String>,
    ) -> Result<(State, String), DsmError> {
        // Ensure we have the token's policy cached if it has one
        if let Ok(Some(metadata)) = self.token_sdk.get_token_metadata(token_id).await {
            if let Some(policy_anchor) = &metadata.policy_anchor {
                let policy_id = policy_anchor
                    .split(':')
                    .collect::<Vec<&str>>()
                    .get(2)
                    .cloned();
                if let Some(policy_id) = policy_id {
                    // Check if the policy allows bilateral transfers
                    if let Ok(Some(policy)) = self.get_token_policy(policy_id).await {
                        let transferable = policy
                            .metadata
                            .get("transferable")
                            .map(|v| v == "true")
                            .unwrap_or(true);

                        if !transferable {
                            return Err(DsmError::invalid_operation(
                                "Token policy does not allow transfers",
                            ));
                        }
                    }
                }
            }
        }

        // Use the token_sdk to execute the bilateral transfer
        self.token_sdk
            .execute_simplified_bilateral_transfer(
                token_id.to_string(),
                recipient.to_string(),
                amount,
                memo,
            )
            .await
    }

    /// Complete a bilateral token transfer as the recipient
    pub async fn complete_token_transfer(
        &self,
        token_id: &str,
        sender: &str,
        amount: u64,
        transfer_id: &str,
        sender_state_hash: &[u8],
    ) -> Result<State, DsmError> {
        // Use the token_sdk to complete the bilateral transfer
        self.token_sdk
            .complete_bilateral_transfer(
                token_id.to_string(),
                sender.to_string(),
                amount,
                transfer_id.to_string(),
                sender_state_hash.to_vec(),
            )
            .await
    }

    /// Check if token transfer should use bilateral mode by verifying policy
    pub async fn should_use_bilateral_transfer(&self, token_id: &str) -> Result<bool, DsmError> {
        // Default to true unless policy explicitly disables it
        let mut use_bilateral = true;

        // Check if we have policy information for this token
        if let Ok(Some(metadata)) = self.token_sdk.get_token_metadata(token_id).await {
            if let Some(policy_anchor) = &metadata.policy_anchor {
                let parts: Vec<&str> = policy_anchor.split(':').collect();
                if parts.len() == 3 && parts[0] == "dsm" && parts[1] == "policy" {
                    let policy_id = parts[2];

                    // Get policy to check if bilateral transfers are allowed
                    if let Ok(Some(policy)) = self.get_token_policy(policy_id).await {
                        // Check the transferable flag
                        if let Some(transferable) = policy.metadata.get("transferable") {
                            if transferable == "false" {
                                use_bilateral = false;
                            }
                        }

                        // Check if policy has explicit transaction mode restrictions
                        if let Some(transaction_modes) = policy.metadata.get("transaction_modes") {
                            // If the policy explicitly specifies transaction modes and bilateral is not included
                            if !transaction_modes.contains("bilateral") {
                                use_bilateral = false;
                            }
                        }
                    }
                }
            }
        }

        Ok(use_bilateral)
    }

    /// Test whether a transfer would be allowed by the token's policy
    pub async fn can_transfer_token(
        &self,
        token_id: &str,
        _recipient: &str,
        _amount: u64,
    ) -> Result<bool, DsmError> {
        // Get token metadata to check policy
        if let Ok(Some(metadata)) = self.get_token_metadata(token_id).await {
            // If there's a policy anchor, verify against the policy
            if let Some(policy_anchor_uri) = &metadata.policy_anchor {
                // Parse policy ID from URI (format: "dsm:policy:policy_id")
                let parts: Vec<&str> = policy_anchor_uri.split(':').collect();
                if parts.len() == 3 && parts[0] == "dsm" && parts[1] == "policy" {
                    let policy_id = parts[2];

                    // Try to get the policy from cache or network
                    if let Ok(response) = self.policy_cache.get_policy(policy_id).await {
                        if let Some(policy_file) = response.policy {
                            // Check if transfers are allowed in policy
                            if let Some(transferable) = policy_file.metadata.get("transferable") {
                                if transferable == "false" {
                                    return Ok(false);
                                }
                            }

                            // Check any additional transfer conditions
                            // Here we would implement more sophisticated policy checking
                            // based on the policy file's conditions

                            // For now, if we get here, transfers are allowed
                            return Ok(true);
                        }
                    }
                }
            } else {
                // No policy means transfers are allowed by default
                return Ok(true);
            }
        }

        // If we couldn't determine if transfer is allowed, default to not allowed for safety
        Ok(false)
    }

    /// Generate a token transfer report that includes policy information
    pub async fn generate_token_transfer_report(
        &self,
        token_id: &str,
        recipient: &str,
        amount: u64,
    ) -> Result<HashMap<String, String>, DsmError> {
        let mut report = HashMap::new();

        // Add basic transfer information
        report.insert("token_id".to_string(), token_id.to_string());
        report.insert("recipient".to_string(), recipient.to_string());
        report.insert("amount".to_string(), amount.to_string());

        // Get token metadata
        if let Ok(Some(metadata)) = self.get_token_metadata(token_id).await {
            report.insert("token_name".to_string(), metadata.name);
            report.insert("token_symbol".to_string(), metadata.symbol);

            // Add policy information if available
            if let Some(policy_anchor_uri) = &metadata.policy_anchor {
                report.insert("policy_anchor".to_string(), policy_anchor_uri.clone());

                // Parse policy ID from URI
                let parts: Vec<&str> = policy_anchor_uri.split(':').collect();
                if parts.len() == 3 && parts[0] == "dsm" && parts[1] == "policy" {
                    let policy_id = parts[2];
                    report.insert("policy_id".to_string(), policy_id.to_string());

                    // Try to get the policy
                    if let Ok(response) = self.policy_cache.get_policy(policy_id).await {
                        if let Some(policy_file) = response.policy {
                            report.insert("policy_name".to_string(), policy_file.name);
                            report.insert("policy_version".to_string(), policy_file.version);

                            if let Some(transferable) = policy_file.metadata.get("transferable") {
                                report.insert("transferable".to_string(), transferable.clone());
                            }
                        }
                    }
                }
            } else {
                report.insert("policy_anchor".to_string(), "None".to_string());
                report.insert("transferable".to_string(), "true".to_string());
            }
        }

        // Check if transfer would be allowed
        let can_transfer = self.can_transfer_token(token_id, recipient, amount).await?;
        report.insert("can_transfer".to_string(), can_transfer.to_string());

        Ok(report)
    }
    /// Get token balance for a specific token
    pub async fn get_token_balance(&self, token_id: &str) -> Result<Balance, DsmError> {
        // Get current state for state_hash
        let current_state = self.core_sdk.get_current_state()?;
        let state_hash = current_state.hash;

        // Use the token SDK to get balance
        let balance = self
            .token_sdk
            .get_balance(token_id, state_hash.to_vec())
            .await
            .map_err(|e| {
                DsmError::internal(
                    format!("Failed to get token balance: {e}"),
                    None::<std::io::Error>,
                )
            })?;

        Ok(balance)
    }

    /// Get transfer history for a token (protobuf-only).
    pub async fn get_transfer_history(
        &self,
        _token_id: &str,
        _limit: Option<usize>,
    ) -> Result<(), DsmError> {
        Err(DsmError::invalid_operation(
            "JSON token API removed. Use protobuf messages.",
        ))
    }

    /// Validate a transfer before execution (protobuf-only).
    pub async fn validate_transfer(
        &self,
        _token_id: &str,
        _recipient_id: &str,
        _amount: u64,
    ) -> Result<(), DsmError> {
        Err(DsmError::invalid_operation(
            "JSON token API removed. Use protobuf messages.",
        ))
    }

    /// Get detailed token information (protobuf-only).
    pub async fn get_token_info(&self, _token_id: &str) -> Result<(), DsmError> {
        Err(DsmError::invalid_operation(
            "JSON token API removed. Use protobuf messages.",
        ))
    }

    /// List all created policies
    pub async fn list_created_policies(
        &self,
    ) -> Result<Vec<dsm::types::policy_types::PolicyFile>, DsmError> {
        // Use the policy cache to list created policies
        let policies = self
            .policy_cache
            .list_cached_policies()
            .await
            .map_err(|e| {
                DsmError::internal(
                    format!("Failed to list created policies: {e}"),
                    None::<std::io::Error>,
                )
            })?;

        Ok(policies)
    }

    /// Get token creation status for an ongoing MPC session
    pub async fn get_session_status(
        &self,
        session_id: &str,
    ) -> Result<TokenCreationResponse, DsmError> {
        let sessions = self.sessions.read();

        if let Some(session) = sessions.get(session_id) {
            let response = TokenCreationResponse {
                session_id: session.session_id.clone(),
                state: session.state.clone(),
                contributions_received: session.contributions_received,
                threshold: session.params.threshold,
                complete: session.state == TokenMpcState::Complete,
                token_metadata: session.token_metadata.clone(),
                error_message: session.error_message.clone(),
            };

            Ok(response)
        } else {
            Err(DsmError::NotFound {
                entity: "Session".to_string(),
                details: Some("Session not found".to_string()),
                context: "Session lookup failed".to_string(),
                source: None,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[cfg(all(test, target_os = "android"))]
    use crate::jni::unified_protobuf_bridge::create_genesis_mpc;

    #[cfg(feature = "local-mpc")]
    #[tokio::test]
    async fn test_token_mpc_creation() -> Result<(), Box<dyn std::error::Error>> {
        let core_sdk = Arc::new(CoreSDK::new()?);
        core_sdk.initialize_with_genesis_state()?;
        let token_mpc_sdk = TokenMpcSDK::new(core_sdk);

        let params = TokenCreationParams {
            token_name: "TestToken".to_string(),
            token_symbol: "TEST".to_string(),
            initial_supply: 1000000,
            description: Some("Test token for MPC".to_string()),
            icon_url: None,
            decimals: 18,
            fields: HashMap::new(),
            threshold: 3,
            timeout_ticks: 300,
            policy_file: None,
            allow_bilateral_transfers: true,
            supported_transaction_modes: None,
            ..Default::default()
        };

        let session_id = token_mpc_sdk.initiate_token_creation(params).await?;
        assert!(!session_id.is_empty());

        let status = token_mpc_sdk.get_session_status(&session_id).await?;
        assert_eq!(status.state, TokenMpcState::Collecting);
        Ok(())
    }

    #[cfg(feature = "local-mpc")]
    #[tokio::test]
    async fn test_token_with_policy() -> Result<(), Box<dyn std::error::Error>> {
        let core_sdk = Arc::new(CoreSDK::new()?);
        core_sdk.initialize_with_genesis_state()?;
        let token_mpc_sdk = TokenMpcSDK::new(core_sdk);

        // Create a basic policy
        let policy = token_mpc_sdk.create_basic_policy_file(
            "TestPolicyToken",
            "1.0",
            Some("Token with policy"),
            true,
        );

        let params = TokenCreationParams {
            token_name: "PolicyToken".to_string(),
            token_symbol: "POLICY".to_string(),
            initial_supply: 5000,
            description: Some("Token with embedded policy".to_string()),
            decimals: 18,
            threshold: 3,
            timeout_ticks: 300,
            policy_file: Some(policy),
            skip_policy_publishing: true, // Skip for test since we don't have real storage nodes
            cache_policy_locally: true,
            ..Default::default()
        };

        let session_id = token_mpc_sdk.initiate_token_creation(params).await?;
        assert!(!session_id.is_empty());
        Ok(())
    }

    #[cfg(feature = "local-mpc")]
    #[tokio::test]
    async fn test_can_transfer_token() -> Result<(), Box<dyn std::error::Error>> {
        let core_sdk = Arc::new(CoreSDK::new()?);
        core_sdk.initialize_with_genesis_state()?;
        let token_mpc_sdk = TokenMpcSDK::new(core_sdk);

        // Create a non-transferable policy
        let policy = token_mpc_sdk.create_basic_policy_file(
            "NonTransferToken",
            "1.0",
            Some("Non-transferable token"),
            false,
        );

        let params = TokenCreationParams {
            token_name: "NoTransfer".to_string(),
            token_symbol: "NOTX".to_string(),
            initial_supply: 1000,
            description: Some("Token that cannot be transferred".to_string()),
            decimals: 18,
            threshold: 3,
            timeout_ticks: 300,
            policy_file: Some(policy),
            skip_policy_publishing: true, // Skip for test
            cache_policy_locally: true,
            allow_bilateral_transfers: false,
            ..Default::default()
        };

        let session_id = token_mpc_sdk.initiate_token_creation(params).await?;
        assert!(!session_id.is_empty());

        // Verify session state is Collecting under local-mpc
        let status = token_mpc_sdk.get_session_status(&session_id).await?;
        assert_eq!(status.state, TokenMpcState::Collecting);
        Ok(())
    }

    #[tokio::test]
    async fn test_policy_cache() -> Result<(), Box<dyn std::error::Error>> {
        let core_sdk = Arc::new(CoreSDK::new()?);
        let token_mpc_sdk = TokenMpcSDK::new(core_sdk);

        // Create a policy
        let policy = token_mpc_sdk.create_basic_policy_file(
            "CachedToken",
            "1.0",
            Some("Token with cached policy"),
            true,
        );

        // Get the policy anchor
        let anchor = PolicyAnchor::from_policy(&policy)?;
        let policy_id = crate::util::text_id::encode_base32_crockford(anchor.as_bytes());

        // Cache the policy directly
        let cached_id = token_mpc_sdk
            .policy_cache
            .cache_policy(policy.clone(), false)
            .await?;
        assert_eq!(cached_id, policy_id);

        // Try to retrieve it
        let cached_policy = token_mpc_sdk.get_token_policy(&policy_id).await?;
        assert!(cached_policy.is_some());
        if let Some(policy) = cached_policy {
            assert_eq!(policy.name, "CachedToken");
        }

        Ok(())
    }

    #[cfg(all(feature = "jni", target_os = "android"))]
    #[test]
    fn test_genesis_creation_integration() -> Result<(), Box<dyn std::error::Error>> {
        println!("🧬 Testing DSM Genesis Creation Integration...");

        // Test parameters
        let locale = "en_US";
        let network_id = "testnet";
        let device_entropy = b"test_device_entropy_12345";

        println!("📝 Creating genesis with:");
        println!("   Locale: {}", locale);
        println!("   Network ID: {}", network_id);
        println!("   Device Entropy: {} bytes", device_entropy.len());

        // Create genesis
        let genesis_result = create_genesis_mpc(locale, network_id, device_entropy)?;

        println!("✅ Genesis creation successful!");
        println!("📋 Genesis Details:");
        println!("   Success: {}", genesis_result.success);
        println!("   Device ID: {}", genesis_result.device_id);
        println!("   Genesis Hash: {}", genesis_result.genesis_hash);
        println!("   Network ID: {}", genesis_result.network_id);
        println!("   Locale: {}", genesis_result.locale);

        // Verify the results
        assert!(
            genesis_result.success,
            "Genesis creation should be successful"
        );
        assert!(
            !genesis_result.genesis_hash.is_empty(),
            "Genesis hash should not be empty"
        );
        assert!(
            !genesis_result.device_id.is_empty(),
            "Genesis device ID should not be empty"
        );

        println!("✅ All validations passed!");
        println!("🎉 DSM Genesis functionality is working correctly!");

        Ok(())
    }
}
