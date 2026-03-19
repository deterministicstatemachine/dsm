//! Token Registry (STRICT: view + name index, not a second source of truth)
//!
//! This module is intentionally *not* an authoritative token database.
//! In DSM, token truth must come from state transitions applied by TokenStateManager.
//!
//! TokenRegistry provides:
//! - friendly-name -> token_id mapping (UI convenience)
//! - optional in-memory cache for bootstrapping / offline UI
//! - deterministic lookup semantics (state manager first, cache second)
//!
//! It does NOT:
//! - revoke tokens
//! - update token metadata
//! - "refresh" from state manager via list APIs (unless such API exists elsewhere)
//!
//! Those actions must occur via state transitions handled by TokenStateManager.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use crate::{
    core::token::token_state_manager::TokenStateManager,
    types::{
        error::DsmError,
        token_types::{Balance, Token, TokenStatus},
    },
};

/// Token Registry for managing token metadata lookup and friendly names.
///
/// Authoritative source of token truth is TokenStateManager.
/// This registry is a lightweight view and UI helper.
pub struct TokenRegistry {
    /// Optional in-memory token cache (non-authoritative).
    /// Useful for bootstrapping UI or temporarily holding token descriptors
    /// before state manager has indexed them.
    token_cache: Arc<RwLock<HashMap<String, Token>>>,

    /// Mapping from friendly names to token IDs (UI-only).
    name_registry: Arc<RwLock<HashMap<String, String>>>,

    /// Authoritative state-integrated token manager.
    token_state_manager: Arc<TokenStateManager>,
}

impl TokenRegistry {
    /// Create a new token registry with a reference to the token state manager.
    pub fn new(token_state_manager: Arc<TokenStateManager>) -> Self {
        Self {
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            name_registry: Arc::new(RwLock::new(HashMap::new())),
            token_state_manager,
        }
    }

    /// Register a token for UI lookup / bootstrapping.
    ///
    /// This does *not* mutate DSM state. It only updates local cache + friendly name map.
    pub fn register_token(
        &self,
        token: Token,
        friendly_name: Option<String>,
    ) -> Result<(), DsmError> {
        let token_id = token.id().to_string();

        // Cache token locally (non-authoritative)
        {
            let mut cache = self.token_cache.write().map_err(|_| {
                DsmError::internal(
                    "Token cache lock poisoned".to_string(),
                    None::<std::io::Error>,
                )
            })?;
            cache.insert(token_id.clone(), token);
        }

        // Register friendly name if provided (UI-only)
        if let Some(name) = friendly_name {
            let mut names = self.name_registry.write().map_err(|_| {
                DsmError::internal(
                    "Name registry lock poisoned".to_string(),
                    None::<std::io::Error>,
                )
            })?;
            names.insert(name, token_id);
        }

        Ok(())
    }

    /// Get a token by ID (authoritative-first).
    ///
    /// Order:
    /// 1) TokenStateManager
    /// 2) local cache
    pub fn get_token(&self, token_id: &str) -> Result<Token, DsmError> {
        if let Ok(t) = self.token_state_manager.get_token(token_id) {
            return Ok(t);
        }

        let cache = self.token_cache.read().map_err(|_| {
            DsmError::internal(
                "Token cache lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        cache
            .get(token_id)
            .cloned()
            .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))
    }

    /// Get a token by its friendly name (UI-only).
    pub fn get_token_by_name(&self, name: &str) -> Result<Token, DsmError> {
        let names = self.name_registry.read().map_err(|_| {
            DsmError::internal(
                "Name registry lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        let token_id = names
            .get(name)
            .ok_or_else(|| DsmError::not_found("Token name", Some(name.to_string())))?
            .clone();

        self.get_token(&token_id)
    }

    /// Find tokens matching criteria, using local cache only.
    ///
    /// Why cache-only?
    /// TokenStateManager may not expose a stable "list tokens" API, and registry must not
    /// invent one. This stays deterministic and avoids calling non-existent methods.
    ///
    /// Deterministic output: sorted by token id.
    pub fn find_tokens(
        &self,
        owner_id: Option<&str>,
        status: Option<TokenStatus>,
        limit: usize,
    ) -> Result<Vec<Token>, DsmError> {
        let cache = self.token_cache.read().map_err(|_| {
            DsmError::internal(
                "Token cache lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        let mut out: Vec<Token> = cache
            .values()
            .filter(|token| {
                if let Some(owner) = owner_id {
                    if token.owner_id() != owner {
                        return false;
                    }
                }
                if let Some(s) = &status {
                    if token.status() != s {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        out.sort_by(|a, b| a.id().cmp(b.id()));
        if out.len() > limit {
            out.truncate(limit);
        }

        Ok(out)
    }

    /// Verify if a token exists and is valid.
    pub fn verify_token(&self, token_id: &str) -> Result<bool, DsmError> {
        match self.get_token(token_id) {
            Ok(t) => Ok(t.is_valid()),
            Err(DsmError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Update token friendly name (UI-only mapping change).
    pub fn update_token_name(&self, token_id: &str, new_name: &str) -> Result<(), DsmError> {
        // Ensure token exists somewhere
        self.get_token(token_id)?;

        let mut names = self.name_registry.write().map_err(|_| {
            DsmError::internal(
                "Name registry lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        // Remove any existing name pointing to token_id
        let mut to_remove: Option<String> = None;
        for (k, v) in names.iter() {
            if v == token_id {
                to_remove = Some(k.clone());
                break;
            }
        }
        if let Some(k) = to_remove {
            names.remove(&k);
        }

        // Ensure new_name is unique by overwriting (UI semantics)
        names.insert(new_name.to_string(), token_id.to_string());
        Ok(())
    }

    /// Get all cached token IDs (deterministic order).
    pub fn get_all_token_ids(&self) -> Result<Vec<String>, DsmError> {
        let cache = self.token_cache.read().map_err(|_| {
            DsmError::internal(
                "Token cache lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        let mut ids: Vec<String> = cache.keys().cloned().collect();
        ids.sort();
        Ok(ids)
    }

    /// Cached token count (non-authoritative).
    pub fn token_count(&self) -> usize {
        self.token_cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Get token balance for a specific owner (authoritative).
    ///
    /// This is state-integrated, so it must come from TokenStateManager.
    pub fn get_token_balance(&self, token_id: &str, owner_id: &str) -> Result<Balance, DsmError> {
        self.token_state_manager
            .get_token_balance_from_store(owner_id.as_bytes(), token_id)
    }

    /// Registry must not revoke tokens.
    ///
    /// Revocation is a state transition and must be applied via TokenStateManager / operations.
    pub fn revoke_token(&self, _token_id: &str) -> Result<(), DsmError> {
        Err(DsmError::invalid_operation(
            "TokenRegistry cannot revoke tokens. Apply a state transition via TokenStateManager/operations.",
        ))
    }

    /// Registry must not update token metadata.
    ///
    /// Metadata changes must be state transitions.
    pub fn update_token_metadata(
        &self,
        _token_id: &str,
        _metadata: Vec<u8>,
    ) -> Result<(), DsmError> {
        Err(DsmError::invalid_operation(
            "TokenRegistry cannot update token metadata. Apply a state transition via TokenStateManager/operations.",
        ))
    }

    /// No-op by design.
    ///
    /// If you later add a stable list/query API to TokenStateManager, implement a separate
    /// synchronizer module that can rebuild the cache deterministically from that snapshot.
    pub fn refresh_registry(&self) -> Result<(), DsmError> {
        Err(DsmError::invalid_operation(
            "TokenRegistry refresh is disabled (no stable TokenStateManager listing API).",
        ))
    }

    /// Optional: clear cached tokens (UI-only).
    pub fn clear_cache(&self) -> Result<(), DsmError> {
        let mut cache = self.token_cache.write().map_err(|_| {
            DsmError::internal(
                "Token cache lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;
        cache.clear();
        Ok(())
    }

    /// Optional: remove a cached token entry (UI-only).
    pub fn remove_from_cache(&self, token_id: &str) -> Result<(), DsmError> {
        let mut cache = self.token_cache.write().map_err(|_| {
            DsmError::internal(
                "Token cache lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;
        cache.remove(token_id);
        Ok(())
    }

    /// Optional: get all friendly names mapped to a token id (deterministic).
    pub fn names_for_token(&self, token_id: &str) -> Result<Vec<String>, DsmError> {
        let names = self.name_registry.read().map_err(|_| {
            DsmError::internal(
                "Name registry lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        let mut out: Vec<String> = names
            .iter()
            .filter_map(|(k, v)| if v == token_id { Some(k.clone()) } else { None })
            .collect();

        out.sort();
        Ok(out)
    }

    /// Optional: get all friendly names (deterministic).
    pub fn all_friendly_names(&self) -> Result<Vec<String>, DsmError> {
        let names = self.name_registry.read().map_err(|_| {
            DsmError::internal(
                "Name registry lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        let mut out: Vec<String> = names.keys().cloned().collect();
        out.sort();
        Ok(out)
    }

    /// Optional: validate name registry has no duplicate target ids under different names.
    /// (Different names pointing to same token is allowed; this just reports stats.)
    pub fn name_registry_stats(&self) -> Result<(usize, usize), DsmError> {
        let names = self.name_registry.read().map_err(|_| {
            DsmError::internal(
                "Name registry lock poisoned".to_string(),
                None::<std::io::Error>,
            )
        })?;

        let total = names.len();
        let mut unique_targets: HashSet<String> = HashSet::new();
        for v in names.values() {
            unique_targets.insert(v.clone());
        }
        Ok((total, unique_targets.len()))
    }
}
