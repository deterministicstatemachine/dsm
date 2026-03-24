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
