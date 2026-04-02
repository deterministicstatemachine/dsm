//! Bilateral Storage SDK Interface
//!
//! This module provides a clean SDK interface for bilateral storage operations,
//! enabling offline capability and per-(sender,receiver) pair isolation.
//! This is the public API that applications should use for storage operations.

use dsm::types::unified_error::{UnifiedDsmError, DsmResult};
use dsm::types::identifiers::{VaultId, SessionId, TransactionId};
use prost::Message;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Bilateral chain tip information (matches wallet_sdk::ChainTipInfo)
#[derive(Debug, Clone)]
pub struct BilateralChainTip {
    pub counterparty_device_id: Vec<u8>,
    pub chain_tip_id: Vec<u8>,
    pub last_state_hash: Vec<u8>,
    pub state_number: u64,
    pub last_updated: u64,
    pub is_synchronized: bool,
}

/// Configuration for bilateral storage
#[derive(Debug, Clone)]
pub struct BilateralStorageConfig {
    /// Base directory for all storage
    pub base_path: String,
    /// Maximum cache size per partition (in bytes)
    pub max_cache_size: usize,
    /// Maximum number of partitions to keep in memory
    pub max_partitions: usize,
    /// Enable offline mode
    pub offline_mode: bool,
    /// Compression level (0-9, 0 = no compression)
    pub compression_level: i32,
}

impl Default for BilateralStorageConfig {
    fn default() -> Self {
        // Priority: env var → SDK storage base dir (Android-safe) → OS data dir → current dir
        let base_path = std::env::var("DSM_BILATERAL_BASE_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                crate::storage_utils::get_storage_base_dir()
                    .map(|p| p.join("bilateral_storage").to_string_lossy().to_string())
            })
            .unwrap_or_else(|| {
                let p = dirs::data_dir().unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
                });
                p.join("dsm_bilateral_storage")
                    .to_string_lossy()
                    .to_string()
            });
        Self {
            base_path,
            max_cache_size: 100 * 1024 * 1024, // 100MB
            max_partitions: 1000,
            offline_mode: false,
            compression_level: 6,
        }
    }
}

/// Bilateral partition key for per-pair isolation
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BilateralKey {
    pub sender: VaultId,
    pub receiver: VaultId,
}

/// SDK interface for bilateral storage operations
pub trait BilateralStorageInterface {
    /// Initialize bilateral storage with configuration
    fn init(config: BilateralStorageConfig) -> DsmResult<Self>
    where
        Self: Sized;

    /// Store a transaction for a specific bilateral pair
    fn store_transaction(
        &self,
        key: &BilateralKey,
        transaction_id: &TransactionId,
        data: &[u8],
    ) -> DsmResult<()>;

    /// Retrieve a transaction for a specific bilateral pair
    fn get_transaction(
        &self,
        key: &BilateralKey,
        transaction_id: &TransactionId,
    ) -> DsmResult<Option<Vec<u8>>>;

    /// Store session data for offline capability
    fn store_session(
        &self,
        key: &BilateralKey,
        session_id: &SessionId,
        data: &[u8],
    ) -> DsmResult<()>;

    /// Retrieve session data
    fn get_session(&self, key: &BilateralKey, session_id: &SessionId)
        -> DsmResult<Option<Vec<u8>>>;

    /// List all transactions for a bilateral pair
    fn list_transactions(&self, key: &BilateralKey) -> DsmResult<Vec<TransactionId>>;

    /// List all sessions for a bilateral pair
    fn list_sessions(&self, key: &BilateralKey) -> DsmResult<Vec<SessionId>>;

    /// Remove old data to free up space
    fn cleanup_partition(&self, key: &BilateralKey, max_age_days: u32) -> DsmResult<usize>;

    /// Get storage statistics
    fn get_stats(&self) -> DsmResult<BilateralStorageStats>;

    /// Save bilateral chain tip (for persistent state across restarts)
    fn save_chain_tip(&self, tip: &BilateralChainTip) -> DsmResult<()>;

    /// Load bilateral chain tip
    fn load_chain_tip(&self, counterparty_device_id: &[u8])
        -> DsmResult<Option<BilateralChainTip>>;

    /// List all stored chain tips
    fn list_chain_tips(&self) -> DsmResult<Vec<BilateralChainTip>>;
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct BilateralStorageStats {
    /// Total partitions
    pub total_partitions: usize,
    /// Total size in bytes
    pub total_size_bytes: u64,
    /// Number of transactions stored
    pub transaction_count: usize,
    /// Number of sessions stored
    pub session_count: usize,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
    /// Persistent backing (SQLite) available
    pub persistent_available: bool,
}

/// Default implementation that delegates to the core bilateral storage
pub struct BilateralStorageSDK {
    // In-memory storage for bilateral transactions and sessions
    transactions: Arc<Mutex<HashMap<String, HashMap<String, Vec<u8>>>>>,
    sessions: Arc<Mutex<HashMap<String, HashMap<String, Vec<u8>>>>>,
    // SQLite connection for persistent chain tips
    db: Arc<Mutex<Connection>>,
    config: BilateralStorageConfig,
}

impl BilateralStorageSDK {
    /// Build a BilateralState with strict canonical checks (build-time guard).
    ///
    /// Enforces:
    /// - relationship_key is 32 bytes
    /// - relationship_key == smt_proof.key
    /// - relationship_key == compute_smt_key(local_dev, remote_dev)
    #[allow(clippy::too_many_arguments)]
    pub fn build_bilateral_state_checked(
        remote_device_id: &[u8; 32],
        state_bytes: Vec<u8>,
        smt_proof: crate::generated::SmtProof,
        device_tree_proof: crate::generated::DeviceTreeProof,
        chain_tip: [u8; 32],
        state_number: u64,
        smt_root: [u8; 32],
        device_tree_root: [u8; 32],
        relationship_key: [u8; 32],
    ) -> DsmResult<crate::generated::BilateralState> {
        if smt_proof.key.as_slice() != relationship_key {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.relationship_key must match smt_proof.key".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }

        let local_dev = crate::get_sdk_context().device_id_array();
        let expected_key =
            dsm::verification::smt_replace_witness::compute_smt_key(&local_dev, remote_device_id);
        if relationship_key != expected_key {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.relationship_key must match canonical derivation"
                    .to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }

        Ok(crate::generated::BilateralState {
            state_bytes,
            smt_proof: Some(smt_proof),
            device_tree_proof: Some(device_tree_proof),
            chain_tip: chain_tip.to_vec(),
            state_number,
            smt_root: smt_root.to_vec(),
            device_tree_root: device_tree_root.to_vec(),
            relationship_key: relationship_key.to_vec(),
        })
    }
    fn make_key_string(key: &BilateralKey) -> String {
        format!(
            "{}:{}",
            String::from_utf8_lossy(key.sender.as_bytes()),
            String::from_utf8_lossy(key.receiver.as_bytes())
        )
    }

    fn init_db(db_path: &Path) -> DsmResult<Connection> {
        let conn = Connection::open(db_path).map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to open bilateral database: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        // Create bilateral_chain_tips table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS bilateral_chain_tips (
                counterparty_device_id BLOB PRIMARY KEY,
                chain_tip_id BLOB NOT NULL,
                last_state_hash BLOB NOT NULL,
                state_number INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                is_synchronized INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to create bilateral_chain_tips table: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        // Create bilateral_transactions table for persistent transaction storage
        conn.execute(
            "CREATE TABLE IF NOT EXISTS bilateral_transactions (
                tx_id BLOB PRIMARY KEY,
                counterparty_device_id BLOB NOT NULL,
                commitment_hash BLOB NOT NULL,
                operation_data BLOB NOT NULL,
                phase TEXT NOT NULL,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                local_signature BLOB,
                counterparty_signature BLOB,
                result_data BLOB
            )",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to create bilateral_transactions table: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        // Create index for fast lookups by counterparty
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_bilateral_tx_counterparty 
             ON bilateral_transactions(counterparty_device_id)",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to create bilateral_transactions index: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        // Create bilateral_receipts table for cryptographic receipts
        conn.execute(
            "CREATE TABLE IF NOT EXISTS bilateral_receipts (
                receipt_id BLOB PRIMARY KEY,
                tx_id BLOB NOT NULL,
                counterparty_device_id BLOB NOT NULL,
                receipt_data BLOB NOT NULL,
                sig_local BLOB NOT NULL,
                sig_counterparty BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (tx_id) REFERENCES bilateral_transactions(tx_id)
            )",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to create bilateral_receipts table: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS bilateral_state_history (
                counterparty_device_id BLOB NOT NULL,
                state_blob BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (counterparty_device_id, created_at)
            )",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to create bilateral_state_history table: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS bilateral_state_mirror (
                counterparty_device_id BLOB PRIMARY KEY,
                state_blob BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to create bilateral_state_mirror table: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS bilateral_state_mirror_history (
                counterparty_device_id BLOB NOT NULL,
                state_blob BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (counterparty_device_id, created_at)
            )",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!(
                "Failed to create bilateral_state_mirror_history table: {}",
                e
            ),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        // Create index for receipts by transaction ID
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_bilateral_receipts_tx 
             ON bilateral_receipts(tx_id)",
            [],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to create bilateral_receipts index: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        Ok(conn)
    }

    fn db_guard(&self) -> DsmResult<std::sync::MutexGuard<'_, Connection>> {
        self.db.lock().map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to lock database: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })
    }
}

impl BilateralStorageInterface for BilateralStorageSDK {
    fn init(config: BilateralStorageConfig) -> DsmResult<Self> {
        let base_dir = Path::new(&config.base_path);
        std::fs::create_dir_all(base_dir).map_err(|e| UnifiedDsmError::Storage {
            context: format!(
                "Failed to create bilateral storage directory '{}': {}",
                base_dir.display(),
                e
            ),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;
        let db_path = base_dir.join("bilateral_chains.db");
        let conn = Self::init_db(&db_path)?;

        Ok(Self {
            transactions: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            db: Arc::new(Mutex::new(conn)),
            config,
        })
    }

    fn store_transaction(
        &self,
        key: &BilateralKey,
        transaction_id: &TransactionId,
        data: &[u8],
    ) -> DsmResult<()> {
        let key_str = Self::make_key_string(key);
        let tx_id_str = String::from_utf8_lossy(transaction_id.as_bytes()).into_owned();

        let conn = self.db_guard()?;

        // Use a deterministic, process-local monotonic counter for created_at/updated_at
        // instead of wall-clock time. Absolute value has no semantic meaning; only
        // ordering matters for queries.
        static MONO_STORE_COUNTER: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
            std::sync::OnceLock::new();
        let counter = MONO_STORE_COUNTER.get_or_init(|| std::sync::atomic::AtomicI64::new(1));
        let now = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        conn.execute(
            "INSERT OR REPLACE INTO bilateral_transactions 
                     (tx_id, counterparty_device_id, commitment_hash, operation_data, 
                      phase, sender, receiver, created_at, updated_at, status) 
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                tx_id_str,
                &[] as &[u8], // counterparty_device_id - to be populated by caller
                &[] as &[u8], // commitment_hash - to be populated by caller
                data,         // operation_data - full envelope/operation bytes
                "unknown",    // phase - to be updated by phase handlers
                String::from_utf8_lossy(key.sender.as_bytes()).as_ref(),
                String::from_utf8_lossy(key.receiver.as_bytes()).as_ref(),
                now,
                now,
                "pending" // status - to be updated as flow progresses
            ],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral transaction: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: false,
        })?;

        drop(conn);

        let mut store = self
            .transactions
            .lock()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to lock transactions store: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        let partition = store.entry(key_str).or_insert_with(HashMap::new);
        partition.insert(tx_id_str, data.to_vec());

        Ok(())
    }

    fn get_transaction(
        &self,
        key: &BilateralKey,
        transaction_id: &TransactionId,
    ) -> DsmResult<Option<Vec<u8>>> {
        let key_str = Self::make_key_string(key);
        let tx_id_str = String::from_utf8_lossy(transaction_id.as_bytes()).into_owned();

        let store = self
            .transactions
            .lock()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to lock transactions store: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(store
            .get(&key_str)
            .and_then(|partition| partition.get(&tx_id_str).cloned()))
    }

    fn store_session(
        &self,
        key: &BilateralKey,
        session_id: &SessionId,
        data: &[u8],
    ) -> DsmResult<()> {
        let key_str = Self::make_key_string(key);
        let session_id_str = String::from_utf8_lossy(session_id.as_bytes()).into_owned();

        let mut store = self.sessions.lock().map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to lock sessions store: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        let partition = store.entry(key_str).or_insert_with(HashMap::new);
        partition.insert(session_id_str, data.to_vec());

        Ok(())
    }

    fn get_session(
        &self,
        key: &BilateralKey,
        session_id: &SessionId,
    ) -> DsmResult<Option<Vec<u8>>> {
        let key_str = Self::make_key_string(key);
        let session_id_str = String::from_utf8_lossy(session_id.as_bytes()).into_owned();

        let store = self.sessions.lock().map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to lock sessions store: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(store
            .get(&key_str)
            .and_then(|partition| partition.get(&session_id_str).cloned()))
    }

    fn list_transactions(&self, key: &BilateralKey) -> DsmResult<Vec<TransactionId>> {
        let key_str = Self::make_key_string(key);

        let store = self
            .transactions
            .lock()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to lock transactions store: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(store
            .get(&key_str)
            .map(|partition| {
                partition
                    .keys()
                    .map(|k| TransactionId::new(k.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn list_sessions(&self, key: &BilateralKey) -> DsmResult<Vec<SessionId>> {
        let key_str = Self::make_key_string(key);

        let store = self.sessions.lock().map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to lock sessions store: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(store
            .get(&key_str)
            .map(|partition| {
                partition
                    .keys()
                    .map(|k| SessionId::new(k.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn cleanup_partition(&self, key: &BilateralKey, _max_age_days: u32) -> DsmResult<usize> {
        let key_str = Self::make_key_string(key);

        let mut tx_store = self
            .transactions
            .lock()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to lock transactions store: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        let mut sess_store = self.sessions.lock().map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to lock sessions store: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        let tx_count = tx_store.get(&key_str).map(|p| p.len()).unwrap_or(0);
        let sess_count = sess_store.get(&key_str).map(|p| p.len()).unwrap_or(0);

        tx_store.remove(&key_str);
        sess_store.remove(&key_str);

        Ok(tx_count + sess_count)
    }

    fn get_stats(&self) -> DsmResult<BilateralStorageStats> {
        let tx_store = self
            .transactions
            .lock()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to lock transactions store: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;
        let sess_store = self.sessions.lock().map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to lock sessions store: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;
        let total_transactions: usize = tx_store.values().map(|p| p.len()).sum();
        let total_sessions: usize = sess_store.values().map(|p| p.len()).sum();
        let total_partitions = tx_store.len().max(sess_store.len());
        let total_size: usize = tx_store
            .values()
            .flat_map(|p| p.values())
            .map(|v| v.len())
            .sum::<usize>()
            + sess_store
                .values()
                .flat_map(|p| p.values())
                .map(|v| v.len())
                .sum::<usize>();
        Ok(BilateralStorageStats {
            total_partitions,
            total_size_bytes: total_size as u64,
            transaction_count: total_transactions,
            session_count: total_sessions,
            cache_hit_rate: 1.0,
            persistent_available: true,
        })
    }

    fn save_chain_tip(&self, tip: &BilateralChainTip) -> DsmResult<()> {
        let conn = self.db_guard()?;

        conn.execute(
            "INSERT OR REPLACE INTO bilateral_chain_tips
             (counterparty_device_id, chain_tip_id, last_state_hash, state_number, last_updated, is_synchronized)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &tip.counterparty_device_id,
                &tip.chain_tip_id,
                &tip.last_state_hash,
                tip.state_number as i64,
                tip.last_updated as i64,
                if tip.is_synchronized { 1 } else { 0 }
            ],
        ).map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to save chain tip: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(())
    }

    fn load_chain_tip(
        &self,
        counterparty_device_id: &[u8],
    ) -> DsmResult<Option<BilateralChainTip>> {
        let conn = self.db_guard()?;

        let result = conn.query_row(
            "SELECT counterparty_device_id, chain_tip_id, last_state_hash, state_number, last_updated, is_synchronized
             FROM bilateral_chain_tips WHERE counterparty_device_id = ?1",
            params![counterparty_device_id],
            |row| {
                let counterparty_bytes: Vec<u8> = row.get(0)?;
                let chain_tip_bytes: Vec<u8> = row.get(1)?;
                let state_hash_bytes: Vec<u8> = row.get(2)?;
                Ok(BilateralChainTip {
                    counterparty_device_id: counterparty_bytes,
                    chain_tip_id: chain_tip_bytes,
                    last_state_hash: state_hash_bytes,
                    state_number: row.get::<_, i64>(3)? as u64,
                    last_updated: row.get::<_, i64>(4)? as u64,
                    is_synchronized: row.get::<_, i32>(5)? != 0,
                })
            },
        ).optional().map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to load chain tip: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(result)
    }

    fn list_chain_tips(&self) -> DsmResult<Vec<BilateralChainTip>> {
        let conn = self.db_guard()?;

        let mut stmt = conn.prepare(
            "SELECT counterparty_device_id, chain_tip_id, last_state_hash, state_number, last_updated, is_synchronized
             FROM bilateral_chain_tips ORDER BY last_updated DESC"
        ).map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to prepare statement: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        let tips = stmt
            .query_map([], |row| {
                let counterparty_bytes: Vec<u8> = row.get(0)?;
                let chain_tip_bytes: Vec<u8> = row.get(1)?;
                let state_hash_bytes: Vec<u8> = row.get(2)?;
                Ok(BilateralChainTip {
                    counterparty_device_id: counterparty_bytes,
                    chain_tip_id: chain_tip_bytes,
                    last_state_hash: state_hash_bytes,
                    state_number: row.get::<_, i64>(3)? as u64,
                    last_updated: row.get::<_, i64>(4)? as u64,
                    is_synchronized: row.get::<_, i32>(5)? != 0,
                })
            })
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to query chain tips: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to collect chain tips: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(tips)
    }
}

impl BilateralStorageSDK {
    /// Persist bilateral transaction with full metadata (called by bilateral handlers)
    #[allow(clippy::too_many_arguments)]
    pub fn persist_bilateral_transaction(
        &self,
        tx_id: &[u8],
        counterparty_device_id: &[u8],
        commitment_hash: &[u8],
        operation_data: &[u8],
        phase: &str,
        status: &str,
        local_signature: Option<&[u8]>,
        counterparty_signature: Option<&[u8]>,
    ) -> DsmResult<()> {
        let conn = self.db_guard()?;

        // Deterministic, process-local counter for created_at/updated_at
        static MONO_PERSIST_COUNTER: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
            std::sync::OnceLock::new();
        let counter = MONO_PERSIST_COUNTER.get_or_init(|| std::sync::atomic::AtomicI64::new(1));
        let now = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        conn.execute(
            "INSERT OR REPLACE INTO bilateral_transactions 
             (tx_id, counterparty_device_id, commitment_hash, operation_data, 
              phase, sender, receiver, created_at, updated_at, status, 
              local_signature, counterparty_signature) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                tx_id,
                counterparty_device_id,
                commitment_hash,
                operation_data,
                phase,
                "", // sender - empty for now, can be populated if needed
                "", // receiver - empty for now
                now,
                now,
                status,
                local_signature.unwrap_or(&[]),
                counterparty_signature.unwrap_or(&[]),
            ],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral transaction: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(())
    }

    /// Retrieve all pending bilateral transactions (PENDING or IN_PROGRESS)
    pub fn get_pending_transactions(
        &self,
    ) -> DsmResult<Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, i64, String)>> {
        let conn = self.db_guard()?;

        let mut stmt = conn.prepare(
            "SELECT tx_id, counterparty_device_id, commitment_hash, operation_data, phase, created_at, status 
             FROM bilateral_transactions 
             WHERE status = 'PENDING' OR status = 'IN_PROGRESS'
             ORDER BY created_at DESC"
        ).map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to prepare statement: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to query pending txs: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to collect pending txs: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(rows)
    }

    /// Update bilateral transaction phase and status
    pub fn update_bilateral_transaction_phase(
        &self,
        tx_id: &[u8],
        phase: &str,
        status: &str,
    ) -> DsmResult<()> {
        let conn = self.db_guard()?;

        // Deterministic, process-local counter for created_at
        static MONO_RECEIPT_COUNTER: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
            std::sync::OnceLock::new();
        let counter = MONO_RECEIPT_COUNTER.get_or_init(|| std::sync::atomic::AtomicI64::new(1));
        let now = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        conn.execute(
            "UPDATE bilateral_transactions 
             SET phase = ?1, status = ?2, updated_at = ?3
             WHERE tx_id = ?4",
            params![phase, status, now, tx_id],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to update bilateral transaction: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(())
    }

    /// Persist a bilateral receipt after successful commit
    pub fn persist_receipt(
        &self,
        receipt_id: &[u8],
        tx_id: &[u8],
        counterparty_device_id: &[u8],
        receipt_data: &[u8],
        sig_local: &[u8],
        sig_counterparty: &[u8],
    ) -> DsmResult<()> {
        let conn = self.db_guard()?;

        // Deterministic, process-local counter for created_at
        static MONO_RECEIPT_COUNTER_V2: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
            std::sync::OnceLock::new();
        let counter = MONO_RECEIPT_COUNTER_V2.get_or_init(|| std::sync::atomic::AtomicI64::new(1));
        let now = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        conn.execute(
            "INSERT INTO bilateral_receipts 
             (receipt_id, tx_id, counterparty_device_id, receipt_data, sig_local, sig_counterparty, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![receipt_id, tx_id, counterparty_device_id, receipt_data, sig_local, sig_counterparty, now],
        ).map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral receipt: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(())
    }

    // ========== Bilateral Reconciliation Support Methods ==========
    // These methods support the BilateralReconciliationEngine (Task 2: beta readiness)

    /// Get the current chain tip for a relationship from local Per-Device SMT.
    ///
    /// Returns None if relationship has not been established yet.
    pub async fn get_relationship_tip(
        &self,
        remote_device_id: &[u8],
    ) -> DsmResult<Option<Vec<u8>>> {
        let conn = self.db_guard()?;

        let tip: Option<Vec<u8>> = conn
            .query_row(
                "SELECT last_state_hash FROM bilateral_chain_tips WHERE counterparty_device_id = ?1",
                params![remote_device_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to query relationship tip: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(tip)
    }

    /// Get the remote device's chain tip from mirrored bilateral storage.
    ///
    /// This is populated when the remote device sends us their current tip
    /// during BLE handshake/sync.
    pub async fn get_remote_tip_mirror(
        &self,
        remote_device_id: &[u8],
    ) -> DsmResult<Option<Vec<u8>>> {
        let conn = self.db_guard()?;

        let state_blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT state_blob FROM bilateral_state_mirror WHERE counterparty_device_id = ?1",
                params![remote_device_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to query bilateral_state_mirror: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        let Some(blob) = state_blob else {
            return Ok(None);
        };

        let state = crate::generated::BilateralState::decode(&*blob).map_err(|e| {
            UnifiedDsmError::Storage {
                context: format!("Failed to decode BilateralState from mirror: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            }
        })?;

        if state.chain_tip.len() != 32 {
            return Ok(None);
        }
        Ok(Some(state.chain_tip))
    }

    /// Get chain history for a relationship (for pulling remote states).
    pub async fn get_remote_chain_history(
        &self,
        _remote_device_id: &[u8],
    ) -> DsmResult<Vec<Vec<u8>>> {
        let conn = self.db_guard()?;

        let mut stmt = conn
            .prepare(
                "SELECT state_blob FROM bilateral_state_mirror_history 
                 WHERE counterparty_device_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to prepare mirror history query: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        let rows = stmt
            .query_map(params![_remote_device_id], |row| row.get(0))
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to query mirror history: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?
            .collect::<Result<Vec<Vec<u8>>, _>>()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to collect mirror history: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(rows)
    }

    /// Get local chain history to push to remote device.
    pub async fn get_local_chain_history(
        &self,
        _remote_device_id: &[u8],
    ) -> DsmResult<Vec<Vec<u8>>> {
        let conn = self.db_guard()?;

        let mut stmt = conn
            .prepare(
                "SELECT state_blob FROM bilateral_state_history 
                 WHERE counterparty_device_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to prepare history query: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        let rows = stmt
            .query_map(params![_remote_device_id], |row| row.get(0))
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to query history: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?
            .collect::<Result<Vec<Vec<u8>>, _>>()
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to collect history: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(rows)
    }

    /// Apply a remote state to local storage (SMT replace operation).
    pub async fn apply_remote_state(
        &self,
        remote_device_id: &[u8],
        state: &crate::generated::BilateralState,
    ) -> DsmResult<()> {
        if state.chain_tip.len() != 32 {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.chain_tip must be 32 bytes".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }
        if state.smt_proof.is_none() || state.device_tree_proof.is_none() {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState is missing required proofs".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }
        if state.smt_root.len() != 32 {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.smt_root must be 32 bytes".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }
        if state.device_tree_root.len() != 32 {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.device_tree_root must be 32 bytes".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }
        if state.relationship_key.len() != 32 {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.relationship_key must be 32 bytes".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }
        if let Some(ref smt) = state.smt_proof {
            if smt.key.as_slice() != state.relationship_key.as_slice() {
                return Err(UnifiedDsmError::Storage {
                    context: "BilateralState.relationship_key must match smt_proof.key".to_string(),
                    component: Some("bilateral_storage".to_string()),
                    source: None,
                    recoverable: true,
                });
            }
        }
        let local_dev = crate::get_sdk_context().device_id_array();
        let mut remote_dev = [0u8; 32];
        remote_dev.copy_from_slice(remote_device_id);
        let expected_key =
            dsm::verification::smt_replace_witness::compute_smt_key(&local_dev, &remote_dev);
        if state.relationship_key.as_slice() != expected_key {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.relationship_key must match canonical derivation"
                    .to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }

        let conn = self.db_guard()?;

        static MONO_APPLY_COUNTER: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
            std::sync::OnceLock::new();
        let counter = MONO_APPLY_COUNTER.get_or_init(|| std::sync::atomic::AtomicI64::new(1));
        let now = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut state_blob = Vec::new();
        state
            .encode(&mut state_blob)
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to encode BilateralState: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        conn.execute(
            "INSERT INTO bilateral_state_history 
             (counterparty_device_id, state_blob, created_at)
             VALUES (?1, ?2, ?3)",
            params![remote_device_id, &state_blob, now],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral_state_history: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        conn.execute(
            "INSERT OR REPLACE INTO bilateral_state_mirror 
             (counterparty_device_id, state_blob, updated_at)
             VALUES (?1, ?2, ?3)",
            params![remote_device_id, &state_blob, now],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral_state_mirror: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        conn.execute(
            "INSERT INTO bilateral_state_mirror_history 
             (counterparty_device_id, state_blob, created_at)
             VALUES (?1, ?2, ?3)",
            params![remote_device_id, &state_blob, now],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral_state_mirror_history: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        conn.execute(
            "INSERT OR REPLACE INTO bilateral_chain_tips
             (counterparty_device_id, chain_tip_id, last_state_hash, state_number, last_updated, is_synchronized)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                remote_device_id,
                &state.chain_tip,
                &state.chain_tip,
                state.state_number as i64,
                now,
                1,
            ],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to update bilateral_chain_tips: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(())
    }

    /// Update remote mirror with pushed state.
    pub async fn update_remote_mirror(
        &self,
        _remote_device_id: &[u8],
        _state_bytes: &[u8],
    ) -> DsmResult<()> {
        let conn = self.db_guard()?;

        let state = crate::generated::BilateralState::decode(_state_bytes).map_err(|e| {
            UnifiedDsmError::Storage {
                context: format!("Failed to decode BilateralState for mirror: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            }
        })?;

        if state.chain_tip.len() != 32 {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.chain_tip must be 32 bytes".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }
        if state.relationship_key.len() != 32 {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.relationship_key must be 32 bytes".to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }
        if let Some(ref smt) = state.smt_proof {
            if smt.key.as_slice() != state.relationship_key.as_slice() {
                return Err(UnifiedDsmError::Storage {
                    context: "BilateralState.relationship_key must match smt_proof.key".to_string(),
                    component: Some("bilateral_storage".to_string()),
                    source: None,
                    recoverable: true,
                });
            }
        }
        let local_dev = crate::get_sdk_context().device_id_array();
        let mut remote_dev = [0u8; 32];
        remote_dev.copy_from_slice(_remote_device_id);
        let expected_key =
            dsm::verification::smt_replace_witness::compute_smt_key(&local_dev, &remote_dev);
        if state.relationship_key.as_slice() != expected_key {
            return Err(UnifiedDsmError::Storage {
                context: "BilateralState.relationship_key must match canonical derivation"
                    .to_string(),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            });
        }

        static MONO_MIRROR_COUNTER: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
            std::sync::OnceLock::new();
        let counter = MONO_MIRROR_COUNTER.get_or_init(|| std::sync::atomic::AtomicI64::new(1));
        let now = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        conn.execute(
            "INSERT OR REPLACE INTO bilateral_state_mirror 
             (counterparty_device_id, state_blob, updated_at)
             VALUES (?1, ?2, ?3)",
            params![_remote_device_id, _state_bytes, now],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral_state_mirror: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        conn.execute(
            "INSERT INTO bilateral_state_mirror_history 
             (counterparty_device_id, state_blob, created_at)
             VALUES (?1, ?2, ?3)",
            params![_remote_device_id, _state_bytes, now],
        )
        .map_err(|e| UnifiedDsmError::Storage {
            context: format!("Failed to persist bilateral_state_mirror_history: {}", e),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        Ok(())
    }

    /// Get SMT inclusion proof for a specific state.
    pub async fn get_smt_proof_for_state(
        &self,
        _remote_device_id: &[u8],
        _state: &[u8],
    ) -> DsmResult<Vec<u8>> {
        let state = crate::generated::BilateralState::decode(_state).map_err(|e| {
            UnifiedDsmError::Storage {
                context: format!("Failed to decode BilateralState for SMT proof: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            }
        })?;

        let proof = state.smt_proof.ok_or_else(|| UnifiedDsmError::Storage {
            context: "BilateralState missing smt_proof".to_string(),
            component: Some("bilateral_storage".to_string()),
            source: None,
            recoverable: true,
        })?;

        let mut out = Vec::new();
        proof
            .encode(&mut out)
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to encode SMT proof: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;
        Ok(out)
    }

    /// Get Device Tree inclusion proof for this device.
    pub async fn get_device_tree_proof(&self) -> DsmResult<Vec<u8>> {
        let proof = crate::generated::DeviceTreeProof {
            siblings: Vec::new(),
            leaf_to_root: true,
            path_bits_len: 0,
            path_bits: Vec::new(),
        };

        let mut out = Vec::new();
        proof
            .encode(&mut out)
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to encode DeviceTreeProof: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;
        Ok(out)
    }

    /// Check if there are pending (uncommitted) states for a relationship.
    pub async fn has_pending_state(&self, remote_device_id: &[u8]) -> DsmResult<bool> {
        let conn = self.db_guard()?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM bilateral_transactions 
                 WHERE counterparty_device_id = ?1 AND status = 'PENDING'",
                params![remote_device_id],
                |row| row.get(0),
            )
            .map_err(|e| UnifiedDsmError::Storage {
                context: format!("Failed to query pending states: {}", e),
                component: Some("bilateral_storage".to_string()),
                source: None,
                recoverable: true,
            })?;

        Ok(count > 0)
    }
}

/// Convenience functions for common operations
pub mod bilateral {
    use super::*;

    /// Create a new bilateral storage instance with default configuration
    pub fn new() -> DsmResult<BilateralStorageSDK> {
        BilateralStorageSDK::init(BilateralStorageConfig::default())
    }

    /// Create a bilateral storage instance with custom configuration
    pub fn with_config(config: BilateralStorageConfig) -> DsmResult<BilateralStorageSDK> {
        BilateralStorageSDK::init(config)
    }

    /// Create a bilateral key from two vault IDs
    pub fn key(sender: VaultId, receiver: VaultId) -> BilateralKey {
        BilateralKey { sender, receiver }
    }
}

// Re-export the interface and types for easy access
pub use bilateral::*;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_config(dir: &TempDir) -> BilateralStorageConfig {
        BilateralStorageConfig {
            base_path: dir.path().to_string_lossy().to_string(),
            max_cache_size: 1024,
            max_partitions: 10,
            offline_mode: false,
            compression_level: 0,
        }
    }

    fn make_sdk(dir: &TempDir) -> BilateralStorageSDK {
        BilateralStorageSDK::init(tmp_config(dir)).expect("init must succeed")
    }

    fn sample_key() -> BilateralKey {
        BilateralKey {
            sender: VaultId::new("alice"),
            receiver: VaultId::new("bob"),
        }
    }

    // ── BilateralStorageConfig ─────────────────────────────────────

    #[test]
    fn config_default_fields() {
        let cfg = BilateralStorageConfig {
            base_path: "/tmp/test".into(),
            ..Default::default()
        };
        assert_eq!(cfg.max_cache_size, 100 * 1024 * 1024);
        assert_eq!(cfg.max_partitions, 1000);
        assert!(!cfg.offline_mode);
        assert_eq!(cfg.compression_level, 6);
    }

    #[test]
    fn config_default_respects_env() {
        let sentinel = "/tmp/dsm_bilateral_test_env_dir";
        std::env::set_var("DSM_BILATERAL_BASE_DIR", sentinel);
        let cfg = BilateralStorageConfig::default();
        std::env::remove_var("DSM_BILATERAL_BASE_DIR");
        assert_eq!(cfg.base_path, sentinel);
    }

    #[test]
    fn config_default_ignores_blank_env() {
        std::env::set_var("DSM_BILATERAL_BASE_DIR", "   ");
        let cfg = BilateralStorageConfig::default();
        std::env::remove_var("DSM_BILATERAL_BASE_DIR");
        assert_ne!(cfg.base_path, "   ");
    }

    // ── BilateralKey ───────────────────────────────────────────────

    #[test]
    fn bilateral_key_eq_and_hash() {
        let k1 = BilateralKey {
            sender: VaultId::new("a"),
            receiver: VaultId::new("b"),
        };
        let k2 = BilateralKey {
            sender: VaultId::new("a"),
            receiver: VaultId::new("b"),
        };
        assert_eq!(k1, k2);

        let mut m = std::collections::HashMap::new();
        m.insert(k1.clone(), 42);
        assert_eq!(m.get(&k2), Some(&42));
    }

    #[test]
    fn bilateral_key_ne_swapped() {
        let k1 = BilateralKey {
            sender: VaultId::new("a"),
            receiver: VaultId::new("b"),
        };
        let k2 = BilateralKey {
            sender: VaultId::new("b"),
            receiver: VaultId::new("a"),
        };
        assert_ne!(k1, k2);
    }

    // ── make_key_string ────────────────────────────────────────────

    #[test]
    fn make_key_string_format() {
        let k = sample_key();
        let s = BilateralStorageSDK::make_key_string(&k);
        assert_eq!(s, "alice:bob");
    }

    #[test]
    fn make_key_string_empty_ids() {
        let k = BilateralKey {
            sender: VaultId::new(""),
            receiver: VaultId::new(""),
        };
        assert_eq!(BilateralStorageSDK::make_key_string(&k), ":");
    }

    // ── convenience helpers ────────────────────────────────────────

    #[test]
    fn bilateral_key_helper() {
        let k = bilateral::key(VaultId::new("x"), VaultId::new("y"));
        assert_eq!(k.sender, VaultId::new("x"));
        assert_eq!(k.receiver, VaultId::new("y"));
    }

    // ── init & DB schema ───────────────────────────────────────────

    #[test]
    fn init_creates_db() {
        let dir = TempDir::new().unwrap();
        let _sdk = make_sdk(&dir);
        assert!(dir.path().join("bilateral_chains.db").exists());
    }

    #[test]
    fn init_idempotent() {
        let dir = TempDir::new().unwrap();
        let _sdk1 = make_sdk(&dir);
        let _sdk2 = make_sdk(&dir);
    }

    // ── transaction CRUD ───────────────────────────────────────────

    #[test]
    fn store_and_get_transaction() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();
        let txid = TransactionId::new("tx1");
        let data = b"hello world";

        sdk.store_transaction(&key, &txid, data).unwrap();
        let got = sdk.get_transaction(&key, &txid).unwrap();
        assert_eq!(got.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn get_transaction_missing() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();
        let txid = TransactionId::new("nonexistent");
        assert_eq!(sdk.get_transaction(&key, &txid).unwrap(), None);
    }

    #[test]
    fn store_transaction_overwrite() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();
        let txid = TransactionId::new("tx1");

        sdk.store_transaction(&key, &txid, b"v1").unwrap();
        sdk.store_transaction(&key, &txid, b"v2").unwrap();
        let got = sdk.get_transaction(&key, &txid).unwrap();
        assert_eq!(got.as_deref(), Some(b"v2".as_slice()));
    }

    #[test]
    fn list_transactions_empty() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert!(sdk.list_transactions(&sample_key()).unwrap().is_empty());
    }

    #[test]
    fn list_transactions_populated() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();

        sdk.store_transaction(&key, &TransactionId::new("t1"), b"a")
            .unwrap();
        sdk.store_transaction(&key, &TransactionId::new("t2"), b"b")
            .unwrap();

        let mut ids: Vec<String> = sdk
            .list_transactions(&key)
            .unwrap()
            .into_iter()
            .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["t1", "t2"]);
    }

    // ── session CRUD ───────────────────────────────────────────────

    #[test]
    fn store_and_get_session() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();
        let sid = SessionId::new("s1");
        let data = b"session-data";

        sdk.store_session(&key, &sid, data).unwrap();
        let got = sdk.get_session(&key, &sid).unwrap();
        assert_eq!(got.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn get_session_missing() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert_eq!(
            sdk.get_session(&sample_key(), &SessionId::new("x"))
                .unwrap(),
            None
        );
    }

    #[test]
    fn list_sessions_populated() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();

        sdk.store_session(&key, &SessionId::new("s1"), b"a")
            .unwrap();
        sdk.store_session(&key, &SessionId::new("s2"), b"b")
            .unwrap();

        let mut ids: Vec<String> = sdk
            .list_sessions(&key)
            .unwrap()
            .into_iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["s1", "s2"]);
    }

    // ── cleanup ────────────────────────────────────────────────────

    #[test]
    fn cleanup_partition_returns_count() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();

        sdk.store_transaction(&key, &TransactionId::new("t1"), b"a")
            .unwrap();
        sdk.store_session(&key, &SessionId::new("s1"), b"b")
            .unwrap();

        let removed = sdk.cleanup_partition(&key, 0).unwrap();
        assert_eq!(removed, 2);

        assert!(sdk.list_transactions(&key).unwrap().is_empty());
        assert!(sdk.list_sessions(&key).unwrap().is_empty());
    }

    #[test]
    fn cleanup_empty_partition() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert_eq!(sdk.cleanup_partition(&sample_key(), 0).unwrap(), 0);
    }

    // ── get_stats ──────────────────────────────────────────────────

    #[test]
    fn stats_empty() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let stats = sdk.get_stats().unwrap();
        assert_eq!(stats.total_partitions, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert_eq!(stats.transaction_count, 0);
        assert_eq!(stats.session_count, 0);
        assert!((stats.cache_hit_rate - 1.0).abs() < f64::EPSILON);
        assert!(stats.persistent_available);
    }

    #[test]
    fn stats_reflects_data() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();

        sdk.store_transaction(&key, &TransactionId::new("t1"), b"abc")
            .unwrap();
        sdk.store_session(&key, &SessionId::new("s1"), b"de")
            .unwrap();

        let stats = sdk.get_stats().unwrap();
        assert_eq!(stats.transaction_count, 1);
        assert_eq!(stats.session_count, 1);
        assert_eq!(stats.total_size_bytes, 5); // 3 + 2
    }

    // ── chain tips (SQLite) ────────────────────────────────────────

    #[test]
    fn save_and_load_chain_tip() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let tip = BilateralChainTip {
            counterparty_device_id: vec![1u8; 32],
            chain_tip_id: vec![2u8; 32],
            last_state_hash: vec![3u8; 32],
            state_number: 7,
            last_updated: 100,
            is_synchronized: true,
        };

        sdk.save_chain_tip(&tip).unwrap();
        let loaded = sdk.load_chain_tip(&tip.counterparty_device_id).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.counterparty_device_id, tip.counterparty_device_id);
        assert_eq!(loaded.chain_tip_id, tip.chain_tip_id);
        assert_eq!(loaded.last_state_hash, tip.last_state_hash);
        assert_eq!(loaded.state_number, tip.state_number);
        assert!(loaded.is_synchronized);
    }

    #[test]
    fn load_chain_tip_missing() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert!(sdk.load_chain_tip(&[0u8; 32]).unwrap().is_none());
    }

    #[test]
    fn save_chain_tip_upsert() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let device_id = vec![9u8; 32];

        let tip1 = BilateralChainTip {
            counterparty_device_id: device_id.clone(),
            chain_tip_id: vec![1; 32],
            last_state_hash: vec![1; 32],
            state_number: 1,
            last_updated: 10,
            is_synchronized: false,
        };
        sdk.save_chain_tip(&tip1).unwrap();

        let tip2 = BilateralChainTip {
            counterparty_device_id: device_id.clone(),
            chain_tip_id: vec![2; 32],
            last_state_hash: vec![2; 32],
            state_number: 2,
            last_updated: 20,
            is_synchronized: true,
        };
        sdk.save_chain_tip(&tip2).unwrap();

        let loaded = sdk.load_chain_tip(&device_id).unwrap().unwrap();
        assert_eq!(loaded.state_number, 2);
        assert!(loaded.is_synchronized);
    }

    #[test]
    fn list_chain_tips_order() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        for i in 0u8..3 {
            let tip = BilateralChainTip {
                counterparty_device_id: vec![i; 32],
                chain_tip_id: vec![i; 32],
                last_state_hash: vec![i; 32],
                state_number: i as u64,
                last_updated: (i as u64) * 10,
                is_synchronized: false,
            };
            sdk.save_chain_tip(&tip).unwrap();
        }

        let tips = sdk.list_chain_tips().unwrap();
        assert_eq!(tips.len(), 3);
        assert!(
            tips[0].last_updated >= tips[1].last_updated
                && tips[1].last_updated >= tips[2].last_updated,
            "tips should be ordered by last_updated DESC"
        );
    }

    // ── persist_bilateral_transaction ──────────────────────────────

    #[test]
    fn persist_bilateral_transaction_roundtrip() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"tx001",
            b"remote_device",
            b"commitment_hash",
            b"op_data",
            "PREPARE",
            "PENDING",
            Some(b"local_sig"),
            None,
        )
        .unwrap();

        let pending = sdk.get_pending_transactions().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, b"tx001"); // tx_id
        assert_eq!(pending[0].4, "PREPARE"); // phase
        assert_eq!(pending[0].6, "PENDING"); // status
    }

    #[test]
    fn update_bilateral_transaction_phase() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"tx002", b"remote", b"hash", b"data", "PREPARE", "PENDING", None, None,
        )
        .unwrap();

        sdk.update_bilateral_transaction_phase(b"tx002", "COMMIT", "COMPLETED")
            .unwrap();

        let pending = sdk.get_pending_transactions().unwrap();
        assert!(
            pending.is_empty(),
            "COMPLETED transactions should not appear in pending"
        );
    }

    // ── persist_receipt ────────────────────────────────────────────

    #[test]
    fn persist_receipt_succeeds() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"txR", b"remote", b"ch", b"od", "COMMIT", "PENDING", None, None,
        )
        .unwrap();

        sdk.persist_receipt(
            b"receipt_001",
            b"txR",
            b"remote",
            b"receipt-body",
            b"sig_local",
            b"sig_remote",
        )
        .unwrap();
    }

    // ── has_pending_state ──────────────────────────────────────────

    #[tokio::test]
    async fn has_pending_state_false_when_empty() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert!(!sdk.has_pending_state(b"device").await.unwrap());
    }

    #[tokio::test]
    async fn has_pending_state_true_after_insert() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"txP", b"device", b"ch", b"od", "PREPARE", "PENDING", None, None,
        )
        .unwrap();

        assert!(sdk.has_pending_state(b"device").await.unwrap());
    }

    // ── get_relationship_tip ───────────────────────────────────────

    #[tokio::test]
    async fn get_relationship_tip_none_when_empty() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert!(sdk.get_relationship_tip(b"remote").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_relationship_tip_after_save() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let tip = BilateralChainTip {
            counterparty_device_id: b"remote".to_vec(),
            chain_tip_id: vec![0xAA; 32],
            last_state_hash: vec![0xBB; 32],
            state_number: 5,
            last_updated: 42,
            is_synchronized: true,
        };
        sdk.save_chain_tip(&tip).unwrap();

        let hash = sdk.get_relationship_tip(b"remote").await.unwrap();
        assert_eq!(hash, Some(vec![0xBB; 32]));
    }

    // ── get_remote_tip_mirror ──────────────────────────────────────

    #[tokio::test]
    async fn get_remote_tip_mirror_none_when_empty() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert!(sdk
            .get_remote_tip_mirror(b"remote")
            .await
            .unwrap()
            .is_none());
    }

    // ── get_device_tree_proof ──────────────────────────────────────

    #[tokio::test]
    async fn get_device_tree_proof_is_decodable() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let bytes = sdk.get_device_tree_proof().await.unwrap();
        assert!(!bytes.is_empty());

        let proof =
            crate::generated::DeviceTreeProof::decode(bytes.as_slice()).expect("must decode");
        assert!(proof.leaf_to_root);
        assert_eq!(proof.path_bits_len, 0);
    }

    // ── get_local_chain_history & get_remote_chain_history ────────

    #[tokio::test]
    async fn chain_history_empty() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        assert!(sdk
            .get_local_chain_history(b"dev")
            .await
            .unwrap()
            .is_empty());
        assert!(sdk
            .get_remote_chain_history(b"dev")
            .await
            .unwrap()
            .is_empty());
    }

    // ── partition isolation ────────────────────────────────────────

    #[test]
    fn different_keys_are_isolated() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let k1 = BilateralKey {
            sender: VaultId::new("a"),
            receiver: VaultId::new("b"),
        };
        let k2 = BilateralKey {
            sender: VaultId::new("c"),
            receiver: VaultId::new("d"),
        };

        sdk.store_transaction(&k1, &TransactionId::new("t"), b"v1")
            .unwrap();
        sdk.store_transaction(&k2, &TransactionId::new("t"), b"v2")
            .unwrap();

        assert_eq!(
            sdk.get_transaction(&k1, &TransactionId::new("t"))
                .unwrap()
                .as_deref(),
            Some(b"v1".as_slice())
        );
        assert_eq!(
            sdk.get_transaction(&k2, &TransactionId::new("t"))
                .unwrap()
                .as_deref(),
            Some(b"v2".as_slice())
        );
    }

    // ── BilateralChainTip struct ───────────────────────────────────

    #[test]
    fn chain_tip_clone_and_debug() {
        let tip = BilateralChainTip {
            counterparty_device_id: vec![1],
            chain_tip_id: vec![2],
            last_state_hash: vec![3],
            state_number: 0,
            last_updated: 0,
            is_synchronized: false,
        };
        let tip2 = tip.clone();
        assert_eq!(tip.counterparty_device_id, tip2.counterparty_device_id);
        let dbg = format!("{tip:?}");
        assert!(dbg.contains("BilateralChainTip"));
    }

    // ── BilateralStorageStats ──────────────────────────────────────

    #[test]
    fn storage_stats_debug_and_clone() {
        let stats = BilateralStorageStats {
            total_partitions: 1,
            total_size_bytes: 100,
            transaction_count: 2,
            session_count: 3,
            cache_hit_rate: 0.5,
            persistent_available: true,
        };
        let stats2 = stats.clone();
        assert_eq!(stats.total_partitions, stats2.total_partitions);
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("BilateralStorageStats"));
    }

    // ── get_smt_proof_for_state ────────────────────────────────────

    #[tokio::test]
    async fn get_smt_proof_for_state_missing_proof() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let state = crate::generated::BilateralState {
            state_bytes: vec![],
            smt_proof: None,
            device_tree_proof: None,
            chain_tip: vec![0u8; 32],
            state_number: 0,
            smt_root: vec![0u8; 32],
            device_tree_root: vec![0u8; 32],
            relationship_key: vec![0u8; 32],
        };
        let mut buf = Vec::new();
        prost::Message::encode(&state, &mut buf).unwrap();

        let result = sdk.get_smt_proof_for_state(b"remote", &buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_smt_proof_for_state_roundtrip() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let proof = crate::generated::SmtProof {
            key: vec![0xAA; 32],
            v_path: None,
            siblings: vec![],
        };
        let state = crate::generated::BilateralState {
            state_bytes: vec![],
            smt_proof: Some(proof.clone()),
            device_tree_proof: None,
            chain_tip: vec![0u8; 32],
            state_number: 0,
            smt_root: vec![0u8; 32],
            device_tree_root: vec![0u8; 32],
            relationship_key: vec![0u8; 32],
        };
        let mut buf = Vec::new();
        prost::Message::encode(&state, &mut buf).unwrap();

        let proof_bytes = sdk.get_smt_proof_for_state(b"remote", &buf).await.unwrap();
        let decoded =
            crate::generated::SmtProof::decode(proof_bytes.as_slice()).expect("must decode");
        assert_eq!(decoded.key, vec![0xAA; 32]);
    }

    // ── bilateral::with_config ─────────────────────────────────────

    #[test]
    fn with_config_helper() {
        let dir = TempDir::new().unwrap();
        let sdk = bilateral::with_config(tmp_config(&dir)).unwrap();
        let stats = sdk.get_stats().unwrap();
        assert_eq!(stats.total_partitions, 0);
    }

    // ── multi-partition stats ──────────────────────────────────────

    #[test]
    fn stats_multiple_partitions() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let k1 = BilateralKey {
            sender: VaultId::new("a"),
            receiver: VaultId::new("b"),
        };
        let k2 = BilateralKey {
            sender: VaultId::new("c"),
            receiver: VaultId::new("d"),
        };

        sdk.store_transaction(&k1, &TransactionId::new("t1"), b"aaa")
            .unwrap();
        sdk.store_transaction(&k2, &TransactionId::new("t2"), b"bb")
            .unwrap();
        sdk.store_session(&k1, &SessionId::new("s1"), b"cccc")
            .unwrap();

        let stats = sdk.get_stats().unwrap();
        assert_eq!(stats.transaction_count, 2);
        assert_eq!(stats.session_count, 1);
        assert_eq!(stats.total_size_bytes, 9); // 3 + 2 + 4
        assert_eq!(stats.total_partitions, 2);
    }

    // ── stats after cleanup ────────────────────────────────────────

    #[test]
    fn stats_after_cleanup() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();

        sdk.store_transaction(&key, &TransactionId::new("t1"), b"data")
            .unwrap();
        sdk.store_session(&key, &SessionId::new("s1"), b"sess")
            .unwrap();

        sdk.cleanup_partition(&key, 0).unwrap();

        let stats = sdk.get_stats().unwrap();
        assert_eq!(stats.transaction_count, 0);
        assert_eq!(stats.session_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }

    // ── store_transaction with empty data ──────────────────────────

    #[test]
    fn store_transaction_empty_data() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();
        let txid = TransactionId::new("empty_tx");

        sdk.store_transaction(&key, &txid, b"").unwrap();
        let got = sdk.get_transaction(&key, &txid).unwrap();
        assert_eq!(got.as_deref(), Some(b"".as_slice()));
    }

    // ── store_session overwrites ───────────────────────────────────

    #[test]
    fn store_session_overwrite() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let key = sample_key();
        let sid = SessionId::new("s1");

        sdk.store_session(&key, &sid, b"v1").unwrap();
        sdk.store_session(&key, &sid, b"v2").unwrap();
        let got = sdk.get_session(&key, &sid).unwrap();
        assert_eq!(got.as_deref(), Some(b"v2".as_slice()));
    }

    // ── cleanup only affects target partition ──────────────────────

    #[test]
    fn cleanup_does_not_affect_other_partitions() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let k1 = BilateralKey {
            sender: VaultId::new("a"),
            receiver: VaultId::new("b"),
        };
        let k2 = BilateralKey {
            sender: VaultId::new("c"),
            receiver: VaultId::new("d"),
        };

        sdk.store_transaction(&k1, &TransactionId::new("t1"), b"a")
            .unwrap();
        sdk.store_transaction(&k2, &TransactionId::new("t2"), b"b")
            .unwrap();

        sdk.cleanup_partition(&k1, 0).unwrap();

        assert!(sdk.list_transactions(&k1).unwrap().is_empty());
        assert_eq!(sdk.list_transactions(&k2).unwrap().len(), 1);
    }

    // ── persist multiple transactions, query pending ───────────────

    #[test]
    fn get_pending_transactions_filters_by_status() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"tx_a", b"dev_a", b"ch", b"data", "PREPARE", "PENDING", None, None,
        )
        .unwrap();
        sdk.persist_bilateral_transaction(
            b"tx_b",
            b"dev_b",
            b"ch",
            b"data",
            "COMMIT",
            "COMPLETED",
            None,
            None,
        )
        .unwrap();
        sdk.persist_bilateral_transaction(
            b"tx_c",
            b"dev_c",
            b"ch",
            b"data",
            "COMMIT",
            "IN_PROGRESS",
            None,
            None,
        )
        .unwrap();

        let pending = sdk.get_pending_transactions().unwrap();
        assert_eq!(pending.len(), 2);
        let statuses: Vec<&str> = pending.iter().map(|t| t.6.as_str()).collect();
        assert!(statuses.contains(&"PENDING"));
        assert!(statuses.contains(&"IN_PROGRESS"));
    }

    // ── persist_receipt with signatures ─────────────────────────────

    #[test]
    fn persist_receipt_with_all_fields() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"tx_r2", b"remote", b"ch", b"od", "COMMIT", "PENDING", None, None,
        )
        .unwrap();

        sdk.persist_receipt(
            b"r_001",
            b"tx_r2",
            b"remote",
            b"receipt_body",
            b"sig_a",
            b"sig_b",
        )
        .unwrap();

        sdk.persist_receipt(
            b"r_002",
            b"tx_r2",
            b"remote",
            b"receipt_body_2",
            b"sig_c",
            b"sig_d",
        )
        .unwrap();
    }

    // ── make_key_string with special characters ────────────────────

    #[test]
    fn make_key_string_with_unicode() {
        let k = BilateralKey {
            sender: VaultId::new("älice"),
            receiver: VaultId::new("böb"),
        };
        let s = BilateralStorageSDK::make_key_string(&k);
        assert!(s.contains(':'));
        assert!(s.starts_with("älice"));
        assert!(s.ends_with("böb"));
    }

    // ── chain tips: is_synchronized false ───────────────────────────

    #[test]
    fn chain_tip_not_synchronized() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        let tip = BilateralChainTip {
            counterparty_device_id: vec![5u8; 32],
            chain_tip_id: vec![6u8; 32],
            last_state_hash: vec![7u8; 32],
            state_number: 0,
            last_updated: 0,
            is_synchronized: false,
        };
        sdk.save_chain_tip(&tip).unwrap();

        let loaded = sdk
            .load_chain_tip(&tip.counterparty_device_id)
            .unwrap()
            .unwrap();
        assert!(!loaded.is_synchronized);
    }

    // ── list_chain_tips empty ──────────────────────────────────────

    #[test]
    fn list_chain_tips_empty() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        assert!(sdk.list_chain_tips().unwrap().is_empty());
    }

    // ── get_smt_proof_for_state with invalid data ──────────────────

    #[tokio::test]
    async fn get_smt_proof_for_state_invalid_bytes() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);
        let result = sdk
            .get_smt_proof_for_state(b"remote", b"not-protobuf")
            .await;
        assert!(result.is_err());
    }

    // ── has_pending_state after completion ──────────────────────────

    #[tokio::test]
    async fn has_pending_state_false_after_phase_update() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"txQ", b"device2", b"ch", b"od", "PREPARE", "PENDING", None, None,
        )
        .unwrap();

        assert!(sdk.has_pending_state(b"device2").await.unwrap());

        sdk.update_bilateral_transaction_phase(b"txQ", "COMMIT", "COMPLETED")
            .unwrap();

        assert!(!sdk.has_pending_state(b"device2").await.unwrap());
    }

    // ── concurrent-like: Arc<BilateralStorageSDK> ──────────────────

    #[test]
    fn sdk_is_thread_safe() {
        let dir = TempDir::new().unwrap();
        let sdk = Arc::new(make_sdk(&dir));
        let sdk2 = Arc::clone(&sdk);

        let h = std::thread::spawn(move || {
            let key = BilateralKey {
                sender: VaultId::new("thread_a"),
                receiver: VaultId::new("thread_b"),
            };
            sdk2.store_transaction(&key, &TransactionId::new("t_thread"), b"data")
                .unwrap();
        });
        h.join().unwrap();

        let key = BilateralKey {
            sender: VaultId::new("thread_a"),
            receiver: VaultId::new("thread_b"),
        };
        let got = sdk
            .get_transaction(&key, &TransactionId::new("t_thread"))
            .unwrap();
        assert_eq!(got.as_deref(), Some(b"data".as_slice()));
    }

    // ── persist_bilateral_transaction with signatures ───────────────

    #[test]
    fn persist_bilateral_transaction_with_both_signatures() {
        let dir = TempDir::new().unwrap();
        let sdk = make_sdk(&dir);

        sdk.persist_bilateral_transaction(
            b"tx_sig",
            b"remote",
            b"commit_h",
            b"op",
            "COMMIT",
            "PENDING",
            Some(b"local_sig_bytes"),
            Some(b"remote_sig_bytes"),
        )
        .unwrap();

        let pending = sdk.get_pending_transactions().unwrap();
        assert_eq!(pending.len(), 1);
    }

    // ── config clone and debug ─────────────────────────────────────

    #[test]
    fn config_clone_and_debug() {
        let cfg = BilateralStorageConfig {
            base_path: "/test".into(),
            max_cache_size: 42,
            max_partitions: 5,
            offline_mode: true,
            compression_level: 3,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.max_cache_size, 42);
        assert!(cfg2.offline_mode);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("BilateralStorageConfig"));
    }
}
