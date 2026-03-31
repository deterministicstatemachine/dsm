// SPDX-License-Identifier: MIT OR Apache-2.0
//! # WAL-Based Offline Transaction Queue
//!
//! Write-Ahead Logging for offline transaction queues to prevent corruption
//! and enable atomic operations with rollback capability.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::security::offline_security::{DeviceMasterKey, EncryptedTransaction};
use dsm::types::error::DsmError;
use crate::util::deterministic_time::tick;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use bincode;
use rand_core06::RngCore;

/// WAL operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalOperation {
    Insert = 1,
    Delete = 2,
    Clear = 3,
}

/// WAL entry header
#[derive(Debug)]
struct WalEntry {
    operation: WalOperation,
    tick_index: u64,
    data_length: u32,
}

/// WAL-based transaction queue with corruption recovery
pub struct WalTransactionQueue {
    /// In-memory queue state
    transactions: Mutex<HashMap<u64, EncryptedTransaction>>,
    /// Master key for encryption
    master_key: DeviceMasterKey,
    /// WAL file handle
    wal_file: Mutex<Option<BufWriter<File>>>,
    /// WAL file path for reopening
    wal_path: String,
    /// Next sequence number for WAL entries
    sequence: Mutex<u64>,
}

impl WalTransactionQueue {
    /// Create a new WAL-based queue
    pub fn new(master_key: DeviceMasterKey, wal_path: impl Into<String>) -> Result<Self, DsmError> {
        let wal_path = wal_path.into();
        let mut queue = Self {
            transactions: Mutex::new(HashMap::new()),
            master_key,
            wal_file: Mutex::new(None),
            wal_path,
            sequence: Mutex::new(0),
        };

        // Recover state from WAL if it exists
        queue.recover_from_wal()?;

        // Open WAL for writing
        queue.open_wal()?;

        Ok(queue)
    }

    /// Open WAL file for writing
    fn open_wal(&self) -> Result<(), DsmError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wal_path)
            .map_err(|e| DsmError::storage("Failed to open WAL file", Some(e)))?;

        let mut wal_guard = self
            .wal_file
            .lock()
            .map_err(|_| DsmError::storage("WAL file mutex poisoned", None::<std::io::Error>))?;
        *wal_guard = Some(BufWriter::new(file));
        Ok(())
    }

    /// Recover queue state from WAL file
    fn recover_from_wal(&mut self) -> Result<(), DsmError> {
        if !Path::new(&self.wal_path).exists() {
            return Ok(()); // No WAL to recover from
        }

        let file = File::open(&self.wal_path)
            .map_err(|e| DsmError::storage("Failed to open WAL for recovery", Some(e)))?;
        let mut reader = BufReader::new(file);

        let mut transactions = HashMap::new();
        let mut max_sequence = 0u64;

        loop {
            // Read entry header
            let mut header_buf = [0u8; 1 + 8 + 4]; // op(1) + tick(8) + len(4)
            match reader.read_exact(&mut header_buf) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // End of file
                Err(e) => return Err(DsmError::storage("Failed to read WAL header", Some(e))),
            }

            let operation = match header_buf[0] {
                1 => WalOperation::Insert,
                2 => WalOperation::Delete,
                3 => WalOperation::Clear,
                _ => {
                    return Err(DsmError::crypto(
                        "Invalid WAL operation",
                        None::<std::io::Error>,
                    ))
                }
            };

            let tick_index = u64::from_le_bytes(header_buf[1..9].try_into().map_err(|_| {
                DsmError::storage("Invalid WAL tick bytes", None::<std::io::Error>)
            })?);
            let data_length = u32::from_le_bytes(header_buf[9..13].try_into().map_err(|_| {
                DsmError::storage("Invalid WAL length bytes", None::<std::io::Error>)
            })?);

            // Read data
            let mut data_buf = vec![0u8; data_length as usize];
            reader
                .read_exact(&mut data_buf)
                .map_err(|e| DsmError::storage("Failed to read WAL data", Some(e)))?;

            // Apply operation
            match operation {
                WalOperation::Insert => {
                    let transaction: EncryptedTransaction = bincode::deserialize(&data_buf)
                        .map_err(|e| {
                            DsmError::crypto("Failed to deserialize WAL transaction", Some(e))
                        })?;
                    transactions.insert(tick_index, transaction);
                }
                WalOperation::Delete => {
                    transactions.remove(&tick_index);
                }
                WalOperation::Clear => {
                    transactions.clear();
                }
            }

            max_sequence = max_sequence.max(tick_index);
        }

        let transaction_count = transactions.len();

        let mut tx_guard = self.transactions.lock().map_err(|_| {
            DsmError::storage("Transactions mutex poisoned", None::<std::io::Error>)
        })?;
        *tx_guard = transactions;
        let mut seq_guard = self
            .sequence
            .lock()
            .map_err(|_| DsmError::storage("Sequence mutex poisoned", None::<std::io::Error>))?;
        *seq_guard = max_sequence + 1;

        log::info!("Recovered {} transactions from WAL", transaction_count);
        Ok(())
    }

    /// Write operation to WAL
    fn write_wal(
        &self,
        operation: WalOperation,
        tick_index: u64,
        data: &[u8],
    ) -> Result<(), DsmError> {
        let mut wal_file = self
            .wal_file
            .lock()
            .map_err(|_| DsmError::storage("WAL file mutex poisoned", None::<std::io::Error>))?;
        let wal_file = wal_file
            .as_mut()
            .ok_or_else(|| DsmError::storage("WAL file not open", None::<std::io::Error>))?;

        // Write header
        wal_file
            .write_all(&[operation as u8])
            .map_err(|e| DsmError::storage("Failed to write WAL header", Some(e)))?;
        wal_file
            .write_all(&tick_index.to_le_bytes())
            .map_err(|e| DsmError::storage("Failed to write WAL tick", Some(e)))?;
        wal_file
            .write_all(&(data.len() as u32).to_le_bytes())
            .map_err(|e| DsmError::storage("Failed to write WAL length", Some(e)))?;

        // Write data
        wal_file
            .write_all(data)
            .map_err(|e| DsmError::storage("Failed to write WAL data", Some(e)))?;

        // Flush to ensure durability
        wal_file
            .flush()
            .map_err(|e| DsmError::storage("Failed to flush WAL", Some(e)))?;

        Ok(())
    }

    /// Enqueue a transaction with WAL protection
    pub fn enqueue_transaction(&self, transaction: &[u8]) -> Result<(), DsmError> {
        let encrypted = self.encrypt_transaction(transaction)?;
        let tick_index = encrypted.tick_index;

        // Serialize transaction for WAL
        let serialized = bincode::serialize(&encrypted)
            .map_err(|e| DsmError::crypto("Failed to serialize transaction for WAL", Some(e)))?;

        // Write to WAL first (write-ahead)
        self.write_wal(WalOperation::Insert, tick_index, &serialized)?;

        // Then update in-memory state
        let mut tx_guard = self.transactions.lock().map_err(|_| {
            DsmError::storage("Transactions mutex poisoned", None::<std::io::Error>)
        })?;
        tx_guard.insert(tick_index, encrypted);

        Ok(())
    }

    /// Clear synced transactions with WAL protection
    pub fn clear_synced_transactions(&self, count: usize) {
        let mut transactions = match self.transactions.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!("clear_synced_transactions: transactions mutex poisoned");
                return;
            }
        };
        let mut to_remove = Vec::new();

        // Collect tick indices to remove (first N by tick order)
        let mut ticks: Vec<_> = transactions.keys().cloned().collect();
        ticks.sort();
        for &tick in ticks.iter().take(count) {
            to_remove.push(tick);
        }

        // Write deletions to WAL
        for tick in &to_remove {
            if let Err(e) = self.write_wal(WalOperation::Delete, *tick, &[]) {
                log::error!("Failed to write deletion to WAL: {:?}", e);
                // Continue anyway - corruption is better than losing data
            }
        }

        // Remove from memory
        for tick in to_remove {
            transactions.remove(&tick);
        }
    }

    /// Get pending transactions (read-only)
    pub fn get_pending_transactions(&self) -> Vec<EncryptedTransaction> {
        let transactions = match self.transactions.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!("get_pending_transactions: transactions mutex poisoned");
                return Vec::new();
            }
        };
        let mut result: Vec<_> = transactions.values().cloned().collect();
        // Sort by tick index for deterministic ordering
        result.sort_by_key(|t| t.tick_index);
        result
    }

    /// Force WAL checkpoint (for maintenance)
    pub fn checkpoint(&self) -> Result<(), DsmError> {
        // Close current WAL
        {
            let mut wal_file = self.wal_file.lock().map_err(|_| {
                DsmError::storage("WAL file mutex poisoned", None::<std::io::Error>)
            })?;
            *wal_file = None;
        }

        // Create new WAL file (old one becomes checkpoint)
        let backup_path = format!("{}.checkpoint.{}", self.wal_path, tick());
        std::fs::rename(&self.wal_path, &backup_path)
            .map_err(|e| DsmError::storage("Failed to create WAL checkpoint", Some(e)))?;

        // Open new WAL
        self.open_wal()?;

        log::info!("Created WAL checkpoint: {}", backup_path);
        Ok(())
    }

    /// Encrypt transaction (same as original)
    fn encrypt_transaction(&self, transaction: &[u8]) -> Result<EncryptedTransaction, DsmError> {
        let key_context = dsm::crypto::blake3::domain_hash("DSM/wal-key-ctx", transaction)
            .as_bytes()
            .to_vec();
        let enc_key = self
            .master_key
            .derive_storage_key("transaction", &key_context);
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| DsmError::crypto("Invalid AES key", Some(e)))?;

        let mut nonce = [0u8; 12];
        rand_core06::OsRng.fill_bytes(&mut nonce);

        let encrypted_data = cipher
            .encrypt(&nonce.into(), transaction)
            .map_err(|e| DsmError::crypto("Failed to encrypt transaction", Some(e)))?;

        // Use local sequence counter for unique tick indices
        let tick_index = {
            let mut seq = self.sequence.lock().map_err(|_| {
                DsmError::internal(
                    "Sequence mutex poisoned".to_string(),
                    None::<std::io::Error>,
                )
            })?;
            *seq += 1;
            *seq
        };

        Ok(EncryptedTransaction {
            encrypted_data,
            nonce,
            key_context,
            tick_index,
        })
    }

    /// Decrypt transaction (same as original)
    pub fn decrypt_transaction(
        &self,
        encrypted: &EncryptedTransaction,
    ) -> Result<Vec<u8>, DsmError> {
        let enc_key = self
            .master_key
            .derive_storage_key("transaction", &encrypted.key_context);
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| DsmError::crypto("Invalid AES key", Some(e)))?;

        cipher
            .decrypt(&encrypted.nonce.into(), encrypted.encrypted_data.as_ref())
            .map_err(|e| DsmError::crypto("Failed to decrypt transaction", Some(e)))
    }
}

impl Drop for WalTransactionQueue {
    fn drop(&mut self) {
        // Ensure WAL is flushed on drop
        if let Ok(mut wal_file) = self.wal_file.lock() {
            if let Some(ref mut writer) = *wal_file {
                let _ = writer.flush();
            }
        } else {
            log::warn!("WalTransactionQueue drop: WAL file mutex poisoned");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_wal_enqueue_and_clear() {
        let master_key = DeviceMasterKey::generate_from_hardware().unwrap();
        let temp_file = NamedTempFile::new().unwrap();
        let wal_path = temp_file.path().to_str().unwrap().to_string();

        let queue = WalTransactionQueue::new(master_key, wal_path).unwrap();

        // Enqueue transactions
        queue.enqueue_transaction(b"tx1").unwrap();
        queue.enqueue_transaction(b"tx2").unwrap();

        assert_eq!(queue.get_pending_transactions().len(), 2);

        // Clear first transaction
        queue.clear_synced_transactions(1);
        assert_eq!(queue.get_pending_transactions().len(), 1);
    }

    #[test]
    fn test_wal_recovery() {
        let master_key = DeviceMasterKey::generate_from_hardware().unwrap();
        let temp_file = NamedTempFile::new().unwrap();
        let wal_path = temp_file.path().to_str().unwrap().to_string();

        // Create queue and add transactions
        {
            let queue = WalTransactionQueue::new(master_key.clone(), wal_path.clone()).unwrap();
            queue.enqueue_transaction(b"persistent_tx").unwrap();
        }

        // Create new queue instance - should recover from WAL
        let recovered_queue = WalTransactionQueue::new(master_key, wal_path).unwrap();
        assert_eq!(recovered_queue.get_pending_transactions().len(), 1);
    }
}
