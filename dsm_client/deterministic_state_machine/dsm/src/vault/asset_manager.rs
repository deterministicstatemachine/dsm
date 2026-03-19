//! Asset management within Deterministic Limbo Vaults (DLVs).
//!
//! Provides functionality for tracking, locking, and unlocking digital assets
//! held within vaults. Assets are managed atomically alongside vault state
//! transitions to maintain the token conservation invariant.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::crypto::kyber::KyberKeyPair;
use crate::types::error::DsmError;

/// Type of asset that can be stored in a vault
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetType {
    /// Cryptographic key material
    KeyMaterial,
    /// Encrypted state data
    EncryptedState,
    /// Digital credential
    Credential,
    /// Raw binary data
    BinaryData,
    /// Structured JSON data
    JsonData,
    /// Token asset
    Token,
}

/// Represents a digital asset that can be stored in a vault
#[derive(Debug, Clone)]
pub struct DigitalAsset {
    /// Unique identifier for this asset
    pub id: String,
    /// Type of the asset
    pub asset_type: AssetType,
    /// The asset data
    pub data: Vec<u8>,
    /// Asset metadata (optional)
    pub metadata: HashMap<String, String>,
}

impl DigitalAsset {
    /// Create a new digital asset
    pub fn new(id: String, asset_type: AssetType, data: Vec<u8>) -> Self {
        Self {
            id,
            asset_type,
            data,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the asset
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Manages digital assets and their lifecycle
pub struct AssetManager {
    /// Map of asset ID to digital asset
    assets: Arc<RwLock<HashMap<String, DigitalAsset>>>,
}

impl AssetManager {
    /// Create a new asset manager
    pub fn new() -> Self {
        Self {
            assets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get read-only access to assets
    pub fn assets_read(
        &self,
    ) -> Result<RwLockReadGuard<'_, HashMap<String, DigitalAsset>>, DsmError> {
        self.assets.read().map_err(|_| DsmError::lock_error())
    }

    /// Get mutable access to assets
    pub fn assets_write(
        &self,
    ) -> Result<RwLockWriteGuard<'_, HashMap<String, DigitalAsset>>, DsmError> {
        self.assets.write().map_err(|_| DsmError::lock_error())
    }

    /// Add an asset to the manager
    pub fn add_asset(&self, asset: DigitalAsset) -> Result<(), DsmError> {
        let mut assets = self.assets_write()?;
        if assets.contains_key(&asset.id) {
            return Err(DsmError::invalid_operation(format!(
                "Asset with ID {} already exists",
                asset.id
            )));
        }

        assets.insert(asset.id.clone(), asset);
        Ok(())
    }

    /// Get an asset by ID (cloned to avoid borrowing across lock boundary)
    pub fn get_asset(&self, id: &str) -> Result<Option<DigitalAsset>, DsmError> {
        let assets = self.assets_read()?;
        Ok(assets.get(id).cloned())
    }

    /// Update an asset in place with the provided closure
    pub fn update_asset<F>(&self, id: &str, f: F) -> Result<bool, DsmError>
    where
        F: FnOnce(&mut DigitalAsset),
    {
        let mut assets = self.assets_write()?;
        if let Some(asset) = assets.get_mut(id) {
            f(asset);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove an asset by ID
    pub fn remove_asset(&self, id: &str) -> Result<Option<DigitalAsset>, DsmError> {
        let mut assets = self.assets_write()?;
        Ok(assets.remove(id))
    }

    /// Get all assets (cloned to avoid borrowing across lock boundary)
    pub fn get_all_assets(&self) -> Result<HashMap<String, DigitalAsset>, DsmError> {
        let assets = self.assets_read()?;
        Ok(assets.clone())
    }

    /// Get all assets of a specific type (cloned to avoid borrowing across lock boundary)
    pub fn get_assets_by_type(&self, asset_type: AssetType) -> Result<Vec<DigitalAsset>, DsmError> {
        let assets = self.assets_read()?;
        Ok(assets
            .values()
            .filter(|asset| asset.asset_type == asset_type)
            .cloned()
            .collect())
    }

    /// Update an asset's data
    pub fn update_asset_data(&self, id: &str, data: Vec<u8>) -> Result<(), DsmError> {
        let updated = self.update_asset(id, |asset| {
            asset.data = data;
        })?;

        if updated {
            Ok(())
        } else {
            Err(DsmError::not_found(
                "Asset",
                Some(format!("Asset with ID {id} not found")),
            ))
        }
    }

    /// Create a key material asset from a Kyber key pair
    pub fn create_key_asset(&self, id: &str, key_pair: &KyberKeyPair) -> Result<String, DsmError> {
        let key_bytes = key_pair.to_bytes();

        let asset = DigitalAsset::new(id.to_string(), AssetType::KeyMaterial, key_bytes);

        self.add_asset(asset)?;

        Ok(id.to_string())
    }

    /// Load a key material asset as a Kyber key pair
    pub fn load_key_asset(&self, id: &str) -> Result<KyberKeyPair, DsmError> {
        let asset = self.get_asset(id)?.ok_or_else(|| {
            DsmError::not_found(
                "Key asset",
                Some(format!("Key asset with ID {id} not found")),
            )
        })?;

        if asset.asset_type != AssetType::KeyMaterial {
            return Err(DsmError::invalid_operation(format!(
                "Asset with ID {id} is not a key material"
            )));
        }

        let key_pair = KyberKeyPair::from_bytes(&asset.data)?;

        Ok(key_pair)
    }

    /// Validate a token transfer
    pub fn validate_transfer(&self, token_id: &str, amount: u64) -> Result<(), DsmError> {
        // Get the token asset
        let token_asset = self
            .get_asset(token_id)?
            .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))?;

        // Check if it's a token type
        if token_asset.asset_type != AssetType::Token {
            return Err(DsmError::invalid_operation(format!(
                "Asset with ID {token_id} is not a token"
            )));
        }

        // For now, assume the asset data contains balance information as metadata
        // In a real implementation, you would have a proper token balance structure
        let available_balance = token_asset
            .metadata
            .get("balance")
            .and_then(|b| b.parse::<u64>().ok())
            .unwrap_or(0);

        // Check if balance is sufficient
        if available_balance < amount {
            return Err(DsmError::InsufficientBalance {
                token_id: token_id.to_string(),
                available: available_balance,
                requested: amount,
            });
        }

        Ok(())
    }
}

impl Default for AssetManager {
    fn default() -> Self {
        Self::new()
    }
}
