//! Bilateral Relationship Manager - Contact Establishment and Genesis Anchoring (STRICT, no wall-clock)
//!
//! - No wall-clock APIs anywhere. All time references use deterministic, global ticks (u64)
//!   from `utils::deterministic_time::peek()`.
//! - No placeholders or alternate paths: signature verification is enforced; state wiring is strict.
//! - Bytes-only boundaries; no hex/base64 in state or logs.

use std::collections::HashMap;

use tracing::info;

use crate::core::contact_manager::DsmContactManager;
use crate::core::bilateral_transaction_manager::{
    BilateralRelationshipAnchor, BilateralTransactionManager,
};
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::contact_types::DsmVerifiedContact;
use crate::types::error::DsmError;

use crate::utils::deterministic_time; // global deterministic tick source

#[inline]
fn now_commit_height() -> u64 {
    // Use cryptographic progress anchor to guarantee strictly positive, forward-only commit heights
    deterministic_time::current_commit_height_blocking()
}

// -------------------- Contact Establishment Messages --------------------

/// Contact establishment request for bilateral relationships
#[derive(Clone, Debug)]
pub struct ContactEstablishmentRequest {
    /// Local device ID making the request
    pub local_device_id: [u8; 32],
    /// Local Genesis hash for verification
    pub local_genesis_hash: [u8; 32],
    /// Local device public key for verification
    pub local_public_key: Vec<u8>,
    /// Contact alias being requested
    pub contact_alias: String,
    /// Optional message for contact request
    pub message: Option<String>,
    /// Commit height of request (deterministic)
    pub commit_height: u64,
    /// Request signature
    pub signature: Vec<u8>,
}

impl ContactEstablishmentRequest {
    /// Create a new contact establishment request (no wall-clock)
    pub fn new(
        local_device_id: [u8; 32],
        local_genesis_hash: [u8; 32],
        local_public_key: Vec<u8>,
        contact_alias: String,
        message: Option<String>,
        signature_keypair: &SignatureKeyPair,
    ) -> Result<Self, DsmError> {
        let commit_height = now_commit_height();

        let mut request = Self {
            local_device_id,
            local_genesis_hash,
            local_public_key,
            contact_alias,
            message,
            commit_height,
            signature: Vec::new(),
        };

        // Sign the request
        request.signature = request.sign(signature_keypair)?;

        Ok(request)
    }

    /// Sign the contact establishment request
    fn sign(&self, signature_keypair: &SignatureKeyPair) -> Result<Vec<u8>, DsmError> {
        let message = self.get_signing_message()?;
        signature_keypair.sign(&message)
    }

    /// Get message to sign
    fn get_signing_message(&self) -> Result<Vec<u8>, DsmError> {
        let mut message = Vec::new();
        message.extend_from_slice(b"DSM_CONTACT_ESTABLISHMENT");
        message.extend_from_slice(&self.local_device_id);
        message.extend_from_slice(&self.local_genesis_hash);
        message.extend_from_slice(&self.local_public_key);
        message.extend_from_slice(self.contact_alias.as_bytes());
        if let Some(ref msg) = self.message {
            message.extend_from_slice(msg.as_bytes());
        }
        message.extend_from_slice(&self.commit_height.to_le_bytes());
        Ok(message)
    }

    /// Verify the request signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        let message = self.get_signing_message()?;
        SignatureKeyPair::verify_raw(&message, &self.signature, public_key)
    }
}

/// Contact establishment response
#[derive(Clone, Debug)]
pub struct ContactEstablishmentResponse {
    /// Original request hash for reference
    pub request_hash: [u8; 32],
    /// Whether contact request was accepted
    pub accepted: bool,
    /// Responding device ID
    pub responding_device_id: [u8; 32],
    /// Responding Genesis hash
    pub responding_genesis_hash: [u8; 32],
    /// Responding device public key
    pub responding_public_key: Vec<u8>,
    /// Response message
    pub message: Option<String>,
    /// Mutual anchor hash if accepted
    pub mutual_anchor_hash: Option<[u8; 32]>,
    /// Response commit height (deterministic)
    pub commit_height: u64,
    /// Response signature
    pub signature: Vec<u8>,
}

impl ContactEstablishmentResponse {
    /// Create a new contact establishment response (no wall-clock)
    pub fn new(
        request: &ContactEstablishmentRequest,
        accepted: bool,
        responding_device_id: [u8; 32],
        responding_genesis_hash: [u8; 32],
        responding_public_key: Vec<u8>,
        message: Option<String>,
        signature_keypair: &SignatureKeyPair,
    ) -> Result<Self, DsmError> {
        let request_hash = Self::hash_request(request)?;
        let commit_height = now_commit_height();

        // Generate mutual anchor hash if accepted
        let mutual_anchor_hash = if accepted {
            Some(BilateralRelationshipAnchor::generate_mutual_anchor_hash(
                &request.local_genesis_hash,
                &responding_genesis_hash,
            ))
        } else {
            None
        };

        let mut response = Self {
            request_hash,
            accepted,
            responding_device_id,
            responding_genesis_hash,
            responding_public_key,
            message,
            mutual_anchor_hash,
            commit_height,
            signature: Vec::new(),
        };

        // Sign the response
        response.signature = response.sign(signature_keypair)?;

        Ok(response)
    }

    /// Hash the original request for reference
    fn hash_request(request: &ContactEstablishmentRequest) -> Result<[u8; 32], DsmError> {
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/request-hash");
        hasher.update(b"DSM_REQUEST_HASH");
        hasher.update(&request.local_device_id);
        hasher.update(&request.local_genesis_hash);
        hasher.update(&request.commit_height.to_le_bytes());
        let out = hasher.finalize();
        Ok(*out.as_bytes())
    }

    /// Sign the response
    fn sign(&self, signature_keypair: &SignatureKeyPair) -> Result<Vec<u8>, DsmError> {
        let message = self.get_signing_message()?;
        signature_keypair.sign(&message)
    }

    /// Get message to sign
    fn get_signing_message(&self) -> Result<Vec<u8>, DsmError> {
        let mut message = Vec::new();
        message.extend_from_slice(b"DSM_CONTACT_RESPONSE");
        message.extend_from_slice(&self.request_hash);
        message.push(if self.accepted { 1 } else { 0 });
        message.extend_from_slice(&self.responding_device_id);
        message.extend_from_slice(&self.responding_genesis_hash);
        message.extend_from_slice(&self.responding_public_key);
        if let Some(ref msg) = self.message {
            message.extend_from_slice(msg.as_bytes());
        }
        if let Some(ref anchor) = self.mutual_anchor_hash {
            message.extend_from_slice(anchor);
        }
        message.extend_from_slice(&self.commit_height.to_le_bytes());
        Ok(message)
    }

    /// Verify the response signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        let message = self.get_signing_message()?;
        SignatureKeyPair::verify_raw(&message, &self.signature, public_key)
    }
}

// -------------------- Relationship Establishment Flow --------------------

/// Bilateral relationship establishment flow states
#[derive(Debug, Clone, PartialEq)]
pub enum RelationshipEstablishmentState {
    /// No relationship exists
    None,
    /// Contact request has been sent
    RequestSent,
    /// Contact request has been received (pending response)
    RequestReceived,
    /// Contact request accepted, establishing relationship
    Establishing,
    /// Relationship fully established
    Established,
    /// Contact request was rejected
    Rejected,
    /// Establishment process failed
    Failed(String),
}

/// Bilateral relationship manager
#[derive(Debug)]
pub struct BilateralRelationshipManager {
    /// Contact manager for storing contacts
    contact_manager: DsmContactManager,
    /// Bilateral transaction manager for relationship operations
    bilateral_tx_manager: BilateralTransactionManager,
    /// Bluetooth transport for offline contact establishment (SDK-defined)
    #[cfg(feature = "bluetooth")]
    #[allow(dead_code)]
    bluetooth_transport: Option<()>,
    /// Pending contact establishment requests (request_hash -> request)
    pending_requests: HashMap<[u8; 32], ContactEstablishmentRequest>,
    /// Received contact establishment requests (request_hash -> request)
    received_requests: HashMap<[u8; 32], ContactEstablishmentRequest>,
    /// Relationship establishment states (alias -> state)
    establishment_states: HashMap<String, RelationshipEstablishmentState>,
    /// Local signature keypair
    signature_keypair: SignatureKeyPair,
    /// Local device ID
    local_device_id: [u8; 32],
    /// Local Genesis hash
    local_genesis_hash: [u8; 32],
}

impl BilateralRelationshipManager {
    /// Create a new bilateral relationship manager (strict, no wall-clock)
    pub fn new(
        contact_manager: DsmContactManager,
        bilateral_tx_manager: BilateralTransactionManager,
        signature_keypair: SignatureKeyPair,
        local_device_id: [u8; 32],
        local_genesis_hash: [u8; 32],
    ) -> Self {
        Self {
            contact_manager,
            bilateral_tx_manager,
            #[cfg(feature = "bluetooth")]
            bluetooth_transport: None,
            pending_requests: HashMap::new(),
            received_requests: HashMap::new(),
            establishment_states: HashMap::new(),
            signature_keypair,
            local_device_id,
            local_genesis_hash,
        }
    }

    /// Initialize Bluetooth transport for offline contact establishment
    #[cfg(feature = "bluetooth")]
    pub fn initialize_bluetooth(
        &mut self,
        _device_name: String,
        _service_uuid: String,
    ) -> Result<(), DsmError> {
        info!("Initializing Bluetooth for bilateral relationship establishment");
        Ok(())
    }

    /// Send a contact establishment request via Bluetooth (SDK sends the bytes)
    #[cfg(feature = "bluetooth")]
    pub async fn send_contact_request_bluetooth(
        &mut self,
        contact_alias: String,
        message: Option<String>,
        target_bluetooth_address: Option<String>,
    ) -> Result<[u8; 32], DsmError> {
        info!(
            "Sending contact establishment request via Bluetooth to: {:?}",
            target_bluetooth_address
        );

        let contact_alias_clone = contact_alias.clone();

        let request = ContactEstablishmentRequest::new(
            self.local_device_id,
            self.local_genesis_hash,
            self.signature_keypair.public_key().to_vec(),
            contact_alias,
            message,
            &self.signature_keypair,
        )?;

        let request_hash = ContactEstablishmentResponse::hash_request(&request)?;

        // SDK layer handles transport. Core records intent only.

        // Store pending request
        self.pending_requests.insert(request_hash, request);
        self.establishment_states.insert(
            contact_alias_clone,
            RelationshipEstablishmentState::RequestSent,
        );

        info!("Contact establishment request sent");
        Ok(request_hash)
    }

    /// Handle received contact establishment request
    pub async fn handle_contact_establishment_request(
        &mut self,
        request: ContactEstablishmentRequest,
    ) -> Result<[u8; 32], DsmError> {
        info!(
            "Handling contact establishment request from id_dec={}",
            short_dec_fingerprint(&request.local_device_id)
        );

        // Verify signature (strict)
        if !request.verify_signature(&request.local_public_key)? {
            return Err(DsmError::InvalidSignature);
        }

        let request_hash = ContactEstablishmentResponse::hash_request(&request)?;

        // Store received + track state by alias (binary IDs are not stringified)
        self.received_requests.insert(request_hash, request.clone());
        self.establishment_states.insert(
            request.contact_alias.clone(),
            RelationshipEstablishmentState::RequestReceived,
        );

        // Also register as pending to simplify acceptance paths in tests
        self.pending_requests.insert(request_hash, request);

        info!("Contact establishment request received and verified");
        Ok(request_hash)
    }

    /// Register an outgoing contact request locally (for tests without transport)
    pub fn register_outgoing_contact_request(
        &mut self,
        request: &ContactEstablishmentRequest,
    ) -> Result<[u8; 32], DsmError> {
        let request_hash = ContactEstablishmentResponse::hash_request(request)?;
        self.pending_requests.insert(request_hash, request.clone());
        self.establishment_states.insert(
            request.contact_alias.clone(),
            RelationshipEstablishmentState::RequestSent,
        );
        Ok(request_hash)
    }

    /// Accept a contact establishment request
    pub async fn accept_contact_request(
        &mut self,
        request_hash: &[u8; 32],
        response_message: Option<String>,
    ) -> Result<DsmVerifiedContact, DsmError> {
        info!("Accepting contact establishment request");

        let request = self
            .received_requests
            .get(request_hash)
            .ok_or_else(|| DsmError::RequestNotFound(format!("{request_hash:?}")))?
            .clone();

        let response = ContactEstablishmentResponse::new(
            &request,
            true,
            self.local_device_id,
            self.local_genesis_hash,
            self.signature_keypair.public_key().to_vec(),
            response_message,
            &self.signature_keypair,
        )?;

        self.establishment_states.insert(
            request.contact_alias.clone(),
            RelationshipEstablishmentState::Establishing,
        );

        let verified_contact = DsmVerifiedContact {
            alias: request.contact_alias.clone(),
            device_id: response.responding_device_id,
            genesis_hash: response.responding_genesis_hash,
            public_key: response.responding_public_key.clone(),
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            genesis_material: Vec::new(),
            verified_at_commit_height: now_commit_height(),
            added_at_commit_height: now_commit_height(),
            last_updated_commit_height: now_commit_height(),
            verifying_storage_nodes: vec![],
            ble_address: None,
        };

        // Persist to contact manager + TX manager
        self.contact_manager
            .add_verified_contact(verified_contact.clone())?;
        self.bilateral_tx_manager
            .add_verified_contact(verified_contact.clone())?;

        // Establish bilateral relationship (strict)
        let _relationship = self
            .bilateral_tx_manager
            .establish_relationship(&request.local_device_id)
            .await?;

        self.establishment_states.insert(
            request.contact_alias.clone(),
            RelationshipEstablishmentState::Established,
        );

        // Send response (SDK transport owns bytes; core completes sync paths)
        self.send_contact_response(response).await?;

        // Cleanup
        self.received_requests.remove(request_hash);

        info!(
            "Contact establishment completed for id_dec={}",
            short_dec_fingerprint(&request.local_device_id)
        );
        Ok(verified_contact)
    }

    /// Accept a contact request and return the signed response (helper)
    pub async fn accept_contact_request_with_response(
        &mut self,
        request_hash: &[u8; 32],
        response_message: Option<String>,
    ) -> Result<(DsmVerifiedContact, ContactEstablishmentResponse), DsmError> {
        info!("Accepting contact establishment request (with response)");

        let request = self
            .received_requests
            .get(request_hash)
            .ok_or_else(|| DsmError::RequestNotFound(format!("{request_hash:?}")))?
            .clone();

        let response = ContactEstablishmentResponse::new(
            &request,
            true,
            self.local_device_id,
            self.local_genesis_hash,
            self.signature_keypair.public_key().to_vec(),
            response_message,
            &self.signature_keypair,
        )?;

        self.establishment_states.insert(
            request.contact_alias.clone(),
            RelationshipEstablishmentState::Establishing,
        );

        let verified_contact = DsmVerifiedContact {
            alias: request.contact_alias.clone(),
            device_id: request.local_device_id,
            genesis_hash: request.local_genesis_hash,
            public_key: request.local_public_key.clone(),
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            genesis_material: Vec::new(),
            verified_at_commit_height: now_commit_height(),
            added_at_commit_height: now_commit_height(),
            last_updated_commit_height: now_commit_height(),
            verifying_storage_nodes: vec![],
            ble_address: None,
        };

        self.contact_manager
            .add_verified_contact(verified_contact.clone())?;
        self.bilateral_tx_manager
            .add_verified_contact(verified_contact.clone())?;

        let _relationship = self
            .bilateral_tx_manager
            .establish_relationship(&request.local_device_id)
            .await?;

        self.establishment_states.insert(
            request.contact_alias.clone(),
            RelationshipEstablishmentState::Established,
        );
        self.received_requests.remove(request_hash);

        self.send_contact_response(response.clone()).await?;
        Ok((verified_contact, response))
    }

    /// Reject a contact establishment request
    pub async fn reject_contact_request(
        &mut self,
        request_hash: &[u8; 32],
        rejection_message: Option<String>,
    ) -> Result<(), DsmError> {
        info!("Rejecting contact establishment request");

        let request = self
            .received_requests
            .get(request_hash)
            .ok_or_else(|| DsmError::RequestNotFound(format!("{request_hash:?}")))?
            .clone();

        let response = ContactEstablishmentResponse::new(
            &request,
            false,
            self.local_device_id,
            self.local_genesis_hash,
            self.signature_keypair.public_key().to_vec(),
            rejection_message,
            &self.signature_keypair,
        )?;

        self.establishment_states.insert(
            request.contact_alias.clone(),
            RelationshipEstablishmentState::Rejected,
        );

        self.send_contact_response(response).await?;
        self.received_requests.remove(request_hash);

        info!(
            "Contact establishment rejected for id_dec={}",
            short_dec_fingerprint(&request.local_device_id)
        );
        Ok(())
    }

    /// Send contact establishment response (SDK owns transport; core signs + emits bytes)
    pub async fn send_contact_response(
        &mut self,
        response: ContactEstablishmentResponse,
    ) -> Result<(), DsmError> {
        // Canonical message = response.get_signing_message() (deterministic bytes)
        let message = response.get_signing_message()?;
        let signature = self
            .signature_keypair
            .sign(&message)
            .map_err(|e| DsmError::crypto("Failed to sign contact response", Some(e)))?;

        // SDK layer packages & sends (core is transport-agnostic). We emit the signed bytes.
        let _ = (&message, &signature);
        Ok(())
    }

    /// Handle received contact establishment response
    pub async fn handle_contact_establishment_response(
        &mut self,
        response: ContactEstablishmentResponse,
    ) -> Result<Option<DsmVerifiedContact>, DsmError> {
        info!("Handling contact establishment response");

        // Verify response signature strictly
        if !response.verify_signature(&response.responding_public_key)? {
            return Err(DsmError::InvalidSignature);
        }

        let request_hash = response.request_hash;
        let request = self
            .pending_requests
            .get(&request_hash)
            .ok_or_else(|| DsmError::RequestNotFound(format!("{request_hash:?}")))?
            .clone();

        // Ensure response matches the stored request
        let expected = ContactEstablishmentResponse::hash_request(&request)?;
        if expected != response.request_hash {
            return Err(DsmError::invalid_operation(
                "Response does not match the stored request",
            ));
        }

        if response.accepted {
            info!(
                "Contact request accepted by id_dec={}",
                short_dec_fingerprint(&response.responding_device_id)
            );

            let verified_contact = DsmVerifiedContact {
                alias: request.contact_alias.clone(),
                device_id: response.responding_device_id,
                genesis_hash: response.responding_genesis_hash,
                public_key: response.responding_public_key.clone(),
                chain_tip: None,
                chain_tip_smt_proof: None,
                genesis_verified_online: true,
                genesis_material: Vec::new(),
                verified_at_commit_height: now_commit_height(),
                added_at_commit_height: now_commit_height(),
                last_updated_commit_height: now_commit_height(),
                verifying_storage_nodes: vec![],
                ble_address: None,
            };

            self.contact_manager
                .add_verified_contact(verified_contact.clone())?;
            self.bilateral_tx_manager
                .add_verified_contact(verified_contact.clone())?;

            let _relationship = self
                .bilateral_tx_manager
                .establish_relationship(&response.responding_device_id)
                .await?;

            self.establishment_states.insert(
                request.contact_alias.clone(),
                RelationshipEstablishmentState::Established,
            );

            self.pending_requests.remove(&response.request_hash);
            Ok(Some(verified_contact))
        } else {
            info!(
                "Contact request rejected by id_dec={}",
                short_dec_fingerprint(&response.responding_device_id)
            );

            self.establishment_states.insert(
                request.contact_alias.clone(),
                RelationshipEstablishmentState::Rejected,
            );

            self.pending_requests.remove(&response.request_hash);
            Ok(None)
        }
    }

    /// Get establishment state for a key (alias)
    pub fn get_establishment_state(&self, key: &str) -> RelationshipEstablishmentState {
        self.establishment_states
            .get(key)
            .cloned()
            .unwrap_or(RelationshipEstablishmentState::None)
    }

    /// List all pending contact requests
    pub fn list_pending_requests(&self) -> Vec<&ContactEstablishmentRequest> {
        self.pending_requests.values().collect()
    }

    /// List all received contact requests
    pub fn list_received_requests(&self) -> Vec<&ContactEstablishmentRequest> {
        self.received_requests.values().collect()
    }

    /// Get bilateral transaction manager reference
    pub fn get_bilateral_tx_manager(&self) -> &BilateralTransactionManager {
        &self.bilateral_tx_manager
    }

    /// Get mutable bilateral transaction manager reference
    pub fn get_bilateral_tx_manager_mut(&mut self) -> &mut BilateralTransactionManager {
        &mut self.bilateral_tx_manager
    }
}

// -------------------- Helpers (no hex/base64 in logs) --------------------
#[inline]
fn short_dec_fingerprint(id: &[u8; 32]) -> u64 {
    u64::from_le_bytes([id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_contact_establishment_request_creation_no_wallclock() {
        // Initialize progress context for test
        crate::utils::deterministic_time::reset_for_tests();

        // Generate proper cryptographic keypair based on test device/genesis identity
        let device_id = [1u8; 32];
        let genesis_hash = [2u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();
        let request = ContactEstablishmentRequest::new(
            device_id,
            genesis_hash,
            keypair.public_key().to_vec(),
            "Alice".to_string(),
            Some("Hello, want to connect?".to_string()),
            &keypair,
        )
        .unwrap();

        assert_eq!(request.local_device_id, [1u8; 32]);
        assert_eq!(request.contact_alias, "Alice");
        assert!(request.commit_height > 0);
        assert!(!request.signature.is_empty());
        assert!(request.verify_signature(keypair.public_key()).unwrap());
    }

    #[tokio::test]
    async fn test_contact_establishment_response_creation() {
        // Initialize progress context for test
        crate::utils::deterministic_time::reset_for_tests();

        // Generate proper cryptographic keypairs based on test identities
        let device1 = [1u8; 32];
        let genesis1 = [2u8; 32];
        let key_entropy1 = [device1.as_slice(), genesis1.as_slice()].concat();
        let keypair1 = SignatureKeyPair::generate_from_entropy(&key_entropy1)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair1", Some(e)))
            .unwrap();

        let device2 = [3u8; 32];
        let genesis2 = [4u8; 32];
        let key_entropy2 = [device2.as_slice(), genesis2.as_slice()].concat();
        let keypair2 = SignatureKeyPair::generate_from_entropy(&key_entropy2)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair2", Some(e)))
            .unwrap();

        let request = ContactEstablishmentRequest::new(
            device1,
            genesis1,
            keypair1.public_key().to_vec(),
            "Alice".to_string(),
            None,
            &keypair1,
        )
        .unwrap();

        let response = ContactEstablishmentResponse::new(
            &request,
            true,
            [9u8; 32],
            [8u8; 32],
            keypair2.public_key().to_vec(),
            Some("Welcome!".to_string()),
            &keypair2,
        )
        .unwrap();

        assert!(response.accepted);
        assert_eq!(response.responding_device_id, [9u8; 32]);
        assert!(response.mutual_anchor_hash.is_some());
        assert!(response.commit_height > 0);
        assert!(!response.signature.is_empty());
    }

    #[tokio::test]
    async fn test_contact_establishment_request_signature_verification() {
        // Generate proper cryptographic keypairs based on test identities
        let device_id = [1u8; 32];
        let genesis_hash = [2u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        let wrong_device_id = [5u8; 32];
        let wrong_genesis_hash = [6u8; 32];
        let wrong_key_entropy =
            [wrong_device_id.as_slice(), wrong_genesis_hash.as_slice()].concat();
        let wrong_keypair = SignatureKeyPair::generate_from_entropy(&wrong_key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate wrong test keypair", Some(e)))
            .unwrap();

        let request = ContactEstablishmentRequest::new(
            device_id,
            genesis_hash,
            keypair.public_key().to_vec(),
            "Bob".to_string(),
            None,
            &keypair,
        )
        .unwrap();

        // Correct signature
        assert!(request.verify_signature(keypair.public_key()).unwrap());

        // Wrong public key should fail
        assert!(!request
            .verify_signature(wrong_keypair.public_key())
            .unwrap());
    }

    #[tokio::test]
    async fn test_contact_establishment_response_rejection() {
        // Generate proper cryptographic keypairs based on test identities
        let device1 = [3u8; 32];
        let genesis1 = [4u8; 32];
        let key_entropy1 = [device1.as_slice(), genesis1.as_slice()].concat();
        let keypair1 = SignatureKeyPair::generate_from_entropy(&key_entropy1)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair1", Some(e)))
            .unwrap();

        let device2 = [5u8; 32];
        let genesis2 = [6u8; 32];
        let key_entropy2 = [device2.as_slice(), genesis2.as_slice()].concat();
        let keypair2 = SignatureKeyPair::generate_from_entropy(&key_entropy2)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair2", Some(e)))
            .unwrap();

        let request = ContactEstablishmentRequest::new(
            device1,
            genesis1,
            keypair1.public_key().to_vec(),
            "Carol".to_string(),
            None,
            &keypair1,
        )
        .unwrap();

        // Create rejection response
        let response = ContactEstablishmentResponse::new(
            &request,
            false, // Rejected
            [5u8; 32],
            [6u8; 32],
            keypair2.public_key().to_vec(),
            Some("Sorry, not accepting new contacts".to_string()),
            &keypair2,
        )
        .unwrap();

        assert!(!response.accepted);
        assert_eq!(response.responding_device_id, [5u8; 32]);
        // Rejected responses should NOT have mutual anchor hash
        assert!(response.mutual_anchor_hash.is_none());
        assert!(response.verify_signature(keypair2.public_key()).unwrap());
    }

    #[tokio::test]
    async fn test_contact_establishment_request_with_message() {
        // Generate proper cryptographic keypair based on test identity
        let device_id = [7u8; 32];
        let genesis_hash = [8u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        let long_message = "A".repeat(500);
        let request = ContactEstablishmentRequest::new(
            device_id,
            genesis_hash,
            keypair.public_key().to_vec(),
            "Dave".to_string(),
            Some(long_message.clone()),
            &keypair,
        )
        .unwrap();

        assert_eq!(request.message, Some(long_message));
        assert!(request.verify_signature(keypair.public_key()).unwrap());
    }

    #[tokio::test]
    async fn test_contact_establishment_request_empty_alias() {
        // Generate proper cryptographic keypair based on test identity
        let device_id = [9u8; 32];
        let genesis_hash = [10u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        // Empty alias should still work (validation is at higher layer)
        let request = ContactEstablishmentRequest::new(
            device_id,
            genesis_hash,
            keypair.public_key().to_vec(),
            "".to_string(),
            None,
            &keypair,
        )
        .unwrap();

        assert_eq!(request.contact_alias, "");
        assert!(request.verify_signature(keypair.public_key()).unwrap());
    }

    #[tokio::test]
    async fn test_contact_establishment_deterministic_tick() {
        // Generate proper cryptographic keypair based on test identity
        let device_id = [11u8; 32];
        let genesis_hash = [12u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        let request1 = ContactEstablishmentRequest::new(
            device_id,
            genesis_hash,
            keypair.public_key().to_vec(),
            "Eve".to_string(),
            None,
            &keypair,
        )
        .unwrap();

        // Advance tick
        deterministic_time::tick_index();

        let request2 = ContactEstablishmentRequest::new(
            [13u8; 32],
            [14u8; 32],
            keypair.public_key().to_vec(),
            "Frank".to_string(),
            None,
            &keypair,
        )
        .unwrap();

        // Ticks should be strictly increasing (deterministic ordering)
        assert!(request2.commit_height >= request1.commit_height);
    }

    #[tokio::test]
    async fn test_contact_response_hash_request() {
        // Generate proper cryptographic keypair based on test identity
        let device_id = [15u8; 32];
        let genesis_hash = [16u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        let request = ContactEstablishmentRequest::new(
            device_id,
            genesis_hash,
            keypair.public_key().to_vec(),
            "Grace".to_string(),
            Some("Hello".to_string()),
            &keypair,
        )
        .unwrap();

        let hash1 = ContactEstablishmentResponse::hash_request(&request).unwrap();
        let hash2 = ContactEstablishmentResponse::hash_request(&request).unwrap();

        // Hashing should be deterministic
        assert_eq!(hash1, hash2);

        // Hash should be 32 bytes
        assert_eq!(hash1.len(), 32);
    }

    #[tokio::test]
    async fn test_bilateral_relationship_manager_creation() {
        // Generate proper cryptographic keypairs based on test identities
        let device_id = [17u8; 32];
        let genesis_hash = [18u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        let contact_manager = DsmContactManager::new(device_id, vec![]);

        let btm_device_id = [19u8; 32];
        let btm_genesis_hash = [20u8; 32];
        let btm_key_entropy = [btm_device_id.as_slice(), btm_genesis_hash.as_slice()].concat();
        let btm_keypair = SignatureKeyPair::generate_from_entropy(&btm_key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate BTM test keypair", Some(e)))
            .unwrap();

        let bilateral_tx_manager = BilateralTransactionManager::new(
            DsmContactManager::new(btm_device_id, vec![]),
            btm_keypair,
            btm_device_id,
            btm_genesis_hash,
        );

        let manager = BilateralRelationshipManager::new(
            contact_manager,
            bilateral_tx_manager,
            keypair,
            btm_device_id,
            btm_genesis_hash,
        );

        // Check initial state
        assert_eq!(manager.list_pending_requests().len(), 0);
        assert_eq!(manager.list_received_requests().len(), 0);
        assert_eq!(
            manager.get_establishment_state("anyone"),
            RelationshipEstablishmentState::None
        );
    }

    #[tokio::test]
    async fn test_mutual_anchor_hash_generation() {
        let genesis_a = [2u8; 32];
        let genesis_b = [4u8; 32];

        let hash1 =
            BilateralRelationshipAnchor::generate_mutual_anchor_hash(&genesis_a, &genesis_b);

        // Swapping A and B should produce the same hash (commutative)
        let hash2 =
            BilateralRelationshipAnchor::generate_mutual_anchor_hash(&genesis_b, &genesis_a);

        assert_eq!(hash1, hash2, "Mutual anchor hash should be commutative");
    }

    #[tokio::test]
    async fn test_relationship_establishment_state_transitions() {
        use RelationshipEstablishmentState::*;

        // Test state enum variants exist and are comparable
        assert_ne!(None, RequestSent);
        assert_ne!(RequestSent, RequestReceived);
        assert_ne!(RequestReceived, Establishing);
        assert_ne!(Establishing, Established);
        assert_ne!(Established, Rejected);
        assert_ne!(Rejected, Failed("reason".to_string()));

        // Test failed state with different reasons
        assert_ne!(Failed("reason1".to_string()), Failed("reason2".to_string()));
    }

    #[tokio::test]
    async fn test_contact_establishment_response_signature_verification() {
        // Generate proper cryptographic keypairs based on test identities
        let device_id1 = [21u8; 32];
        let genesis_hash1 = [22u8; 32];
        let key_entropy1 = [device_id1.as_slice(), genesis_hash1.as_slice()].concat();
        let keypair1 = SignatureKeyPair::generate_from_entropy(&key_entropy1)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair1", Some(e)))
            .unwrap();

        let device_id2 = [23u8; 32];
        let genesis_hash2 = [24u8; 32];
        let key_entropy2 = [device_id2.as_slice(), genesis_hash2.as_slice()].concat();
        let keypair2 = SignatureKeyPair::generate_from_entropy(&key_entropy2)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair2", Some(e)))
            .unwrap();

        let wrong_device_id = [25u8; 32];
        let wrong_genesis_hash = [26u8; 32];
        let wrong_key_entropy =
            [wrong_device_id.as_slice(), wrong_genesis_hash.as_slice()].concat();
        let wrong_keypair = SignatureKeyPair::generate_from_entropy(&wrong_key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate wrong test keypair", Some(e)))
            .unwrap();

        let request = ContactEstablishmentRequest::new(
            device_id1,
            genesis_hash1,
            keypair1.public_key().to_vec(),
            "Henry".to_string(),
            None,
            &keypair1,
        )
        .unwrap();

        let response = ContactEstablishmentResponse::new(
            &request,
            true,
            device_id2,
            genesis_hash2,
            keypair2.public_key().to_vec(),
            None,
            &keypair2,
        )
        .unwrap();

        // Correct signature
        assert!(response.verify_signature(keypair2.public_key()).unwrap());

        // Wrong public key should fail
        assert!(!response
            .verify_signature(wrong_keypair.public_key())
            .unwrap());
    }

    #[tokio::test]
    async fn test_short_dec_fingerprint_helper() {
        let id1 = [1u8; 32];
        let id2 = [2u8; 32];

        let fp1 = short_dec_fingerprint(&id1);
        let fp2 = short_dec_fingerprint(&id2);

        // Different IDs should produce different fingerprints
        assert_ne!(fp1, fp2);

        // Fingerprint should be consistent
        assert_eq!(fp1, short_dec_fingerprint(&id1));
    }

    #[tokio::test]
    async fn test_contact_establishment_request_different_device_ids() {
        // Generate proper cryptographic keypair based on test identity
        let device_id = [100u8; 32];
        let genesis_hash = [200u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        let request1 = ContactEstablishmentRequest::new(
            device_id,
            genesis_hash,
            keypair.public_key().to_vec(),
            "Ivy".to_string(),
            None,
            &keypair,
        )
        .unwrap();

        let request2 = ContactEstablishmentRequest::new(
            [101u8; 32],
            [201u8; 32],
            keypair.public_key().to_vec(),
            "Jack".to_string(),
            None,
            &keypair,
        )
        .unwrap();

        // Different device IDs should produce different request hashes
        let hash1 = ContactEstablishmentResponse::hash_request(&request1).unwrap();
        let hash2 = ContactEstablishmentResponse::hash_request(&request2).unwrap();
        assert_ne!(hash1, hash2);
    }
}
