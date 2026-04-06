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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(id: &str, balance: u64) -> DigitalAsset {
        DigitalAsset::new(id.to_string(), AssetType::Token, vec![])
            .with_metadata("balance", &balance.to_string())
    }

    #[test]
    fn new_creates_empty_manager() {
        let mgr = AssetManager::new();
        let all = mgr.get_all_assets().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn add_asset_and_retrieve() {
        let mgr = AssetManager::new();
        let asset = DigitalAsset::new("a1".into(), AssetType::BinaryData, vec![1, 2, 3]);
        mgr.add_asset(asset).unwrap();

        let fetched = mgr.get_asset("a1").unwrap().unwrap();
        assert_eq!(fetched.id, "a1");
        assert_eq!(fetched.data, vec![1, 2, 3]);
        assert_eq!(fetched.asset_type, AssetType::BinaryData);
    }

    #[test]
    fn add_asset_duplicate_id_fails() {
        let mgr = AssetManager::new();
        let a1 = DigitalAsset::new("dup".into(), AssetType::BinaryData, vec![]);
        let a2 = DigitalAsset::new("dup".into(), AssetType::JsonData, vec![]);
        mgr.add_asset(a1).unwrap();
        let err = mgr.add_asset(a2).unwrap_err();
        assert!(format!("{err}").contains("dup"));
    }

    #[test]
    fn get_asset_returns_none_for_missing() {
        let mgr = AssetManager::new();
        assert!(mgr.get_asset("nonexistent").unwrap().is_none());
    }

    #[test]
    fn update_asset_returns_true_for_existing() {
        let mgr = AssetManager::new();
        mgr.add_asset(DigitalAsset::new(
            "u1".into(),
            AssetType::BinaryData,
            vec![0],
        ))
        .unwrap();

        let updated = mgr.update_asset("u1", |a| a.data = vec![9, 8, 7]).unwrap();
        assert!(updated);

        let fetched = mgr.get_asset("u1").unwrap().unwrap();
        assert_eq!(fetched.data, vec![9, 8, 7]);
    }

    #[test]
    fn update_asset_returns_false_for_missing() {
        let mgr = AssetManager::new();
        let updated = mgr.update_asset("ghost", |_| {}).unwrap();
        assert!(!updated);
    }

    #[test]
    fn remove_asset_returns_some() {
        let mgr = AssetManager::new();
        mgr.add_asset(DigitalAsset::new(
            "rm1".into(),
            AssetType::Credential,
            vec![],
        ))
        .unwrap();

        let removed = mgr.remove_asset("rm1").unwrap();
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, "rm1");
        assert!(mgr.get_asset("rm1").unwrap().is_none());
    }

    #[test]
    fn remove_asset_returns_none_for_missing() {
        let mgr = AssetManager::new();
        assert!(mgr.remove_asset("nope").unwrap().is_none());
    }

    #[test]
    fn get_all_assets_returns_all() {
        let mgr = AssetManager::new();
        mgr.add_asset(DigitalAsset::new("x".into(), AssetType::BinaryData, vec![]))
            .unwrap();
        mgr.add_asset(DigitalAsset::new("y".into(), AssetType::JsonData, vec![]))
            .unwrap();
        mgr.add_asset(DigitalAsset::new("z".into(), AssetType::Token, vec![]))
            .unwrap();

        let all = mgr.get_all_assets().unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.contains_key("x"));
        assert!(all.contains_key("y"));
        assert!(all.contains_key("z"));
    }

    #[test]
    fn get_assets_by_type_filters_correctly() {
        let mgr = AssetManager::new();
        mgr.add_asset(DigitalAsset::new("t1".into(), AssetType::Token, vec![]))
            .unwrap();
        mgr.add_asset(DigitalAsset::new("t2".into(), AssetType::Token, vec![]))
            .unwrap();
        mgr.add_asset(DigitalAsset::new(
            "b1".into(),
            AssetType::BinaryData,
            vec![],
        ))
        .unwrap();

        let tokens = mgr.get_assets_by_type(AssetType::Token).unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens.iter().all(|a| a.asset_type == AssetType::Token));

        let binary = mgr.get_assets_by_type(AssetType::BinaryData).unwrap();
        assert_eq!(binary.len(), 1);

        let creds = mgr.get_assets_by_type(AssetType::Credential).unwrap();
        assert!(creds.is_empty());
    }

    #[test]
    fn update_asset_data_updates_existing() {
        let mgr = AssetManager::new();
        mgr.add_asset(DigitalAsset::new(
            "d1".into(),
            AssetType::BinaryData,
            vec![0],
        ))
        .unwrap();

        mgr.update_asset_data("d1", vec![5, 6, 7]).unwrap();
        let fetched = mgr.get_asset("d1").unwrap().unwrap();
        assert_eq!(fetched.data, vec![5, 6, 7]);
    }

    #[test]
    fn update_asset_data_fails_for_missing() {
        let mgr = AssetManager::new();
        let err = mgr.update_asset_data("missing", vec![1]).unwrap_err();
        assert!(format!("{err}").contains("missing"));
    }

    #[test]
    fn validate_transfer_sufficient_balance_succeeds() {
        let mgr = AssetManager::new();
        mgr.add_asset(make_token("tok1", 1000)).unwrap();
        mgr.validate_transfer("tok1", 500).unwrap();
    }

    #[test]
    fn validate_transfer_insufficient_balance_fails() {
        let mgr = AssetManager::new();
        mgr.add_asset(make_token("tok2", 100)).unwrap();
        let err = mgr.validate_transfer("tok2", 200).unwrap_err();
        match err {
            DsmError::InsufficientBalance {
                token_id,
                available,
                requested,
            } => {
                assert_eq!(token_id, "tok2");
                assert_eq!(available, 100);
                assert_eq!(requested, 200);
            }
            other => panic!("Expected InsufficientBalance, got: {other}"),
        }
    }

    #[test]
    fn validate_transfer_non_token_asset_fails() {
        let mgr = AssetManager::new();
        mgr.add_asset(DigitalAsset::new(
            "notok".into(),
            AssetType::BinaryData,
            vec![],
        ))
        .unwrap();
        let err = mgr.validate_transfer("notok", 1).unwrap_err();
        assert!(format!("{err}").contains("not a token"));
    }

    #[test]
    fn validate_transfer_missing_asset_fails() {
        let mgr = AssetManager::new();
        let err = mgr.validate_transfer("ghost", 1).unwrap_err();
        match err {
            DsmError::NotFound { .. } => {}
            other => panic!("Expected NotFound, got: {other}"),
        }
    }

    #[test]
    fn digital_asset_new_sets_fields() {
        let asset = DigitalAsset::new("id1".into(), AssetType::KeyMaterial, vec![10, 20]);
        assert_eq!(asset.id, "id1");
        assert_eq!(asset.asset_type, AssetType::KeyMaterial);
        assert_eq!(asset.data, vec![10, 20]);
        assert!(asset.metadata.is_empty());
    }

    #[test]
    fn digital_asset_with_metadata_adds_metadata() {
        let asset = DigitalAsset::new("id2".into(), AssetType::JsonData, vec![])
            .with_metadata("key1", "val1")
            .with_metadata("key2", "val2");
        assert_eq!(asset.metadata.len(), 2);
        assert_eq!(asset.metadata.get("key1").unwrap(), "val1");
        assert_eq!(asset.metadata.get("key2").unwrap(), "val2");
    }

    #[test]
    fn default_asset_manager_is_empty() {
        let mgr = AssetManager::default();
        assert!(mgr.get_all_assets().unwrap().is_empty());
    }
}
