// SPDX-License-Identifier: MIT OR Apache-2.0
//! Contact record persistence and BLE status management.

use anyhow::{anyhow, Result};
use log::{info, warn};
use dsm::types::receipt_types::DeviceTreeAcceptanceCommitment;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use super::types::ContactRecord;
use crate::storage::codecs::{meta_from_blob, meta_to_blob};
use crate::util::deterministic_time::tick;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedRemoteTipSource {
    Unknown = 0,
    DeferredInbox = 1,
    LivePeerClaim = 2,
}

impl ObservedRemoteTipSource {
    pub(crate) fn from_db(value: Option<i64>) -> Self {
        match value {
            Some(1) => Self::DeferredInbox,
            Some(2) => Self::LivePeerClaim,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn db_value(self) -> i64 {
        self as i64
    }

    pub(crate) fn blocks_send_without_local_corroboration(self) -> bool {
        matches!(self, Self::LivePeerClaim)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedRemoteTipRecord {
    pub tip: [u8; 32],
    pub updated_at: u64,
    pub source: ObservedRemoteTipSource,
}

pub fn store_contact(contact: &ContactRecord) -> Result<()> {
    info!(
        "Storing contact: {} (device_id {} bytes, public_key {} bytes)",
        contact.alias,
        contact.device_id.len(),
        contact.public_key.len()
    );

    // TRUST BOUNDARY GUARD: Log warning if storing contact without public key.
    // Contacts without public keys CANNOT be used for bilateral verification.
    // For protocol-controlled actors (DLV, Faucet), use SystemPeerRecord instead.
    if contact.public_key.is_empty() {
        log::warn!(
            "TRUST BOUNDARY: Storing contact \"{}\" with EMPTY public_key.  \
                 This contact CANNOT be used for bilateral verification.  \
                 Consider using SystemPeerRecord for protocol-controlled actors.",
            contact.alias
        );
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "INSERT INTO contacts (
            contact_id, device_id, alias, genesis_hash, public_key, chain_tip,
            added_at, verified, verification_proof, metadata, ble_address,
            status, needs_online_reconcile, last_seen_online_counter, last_seen_ble_counter
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
        ON CONFLICT(device_id) DO UPDATE SET
            alias = excluded.alias,
            genesis_hash = excluded.genesis_hash,
            public_key = COALESCE(excluded.public_key, contacts.public_key),
            chain_tip = COALESCE(contacts.chain_tip, excluded.chain_tip),
            added_at = contacts.added_at,
            verified = CASE
                WHEN excluded.verified != 0 OR contacts.verified != 0 THEN 1
                ELSE 0
            END,
            verification_proof = COALESCE(excluded.verification_proof, contacts.verification_proof),
            metadata = excluded.metadata,
            ble_address = COALESCE(excluded.ble_address, contacts.ble_address),
            status = excluded.status,
            needs_online_reconcile = excluded.needs_online_reconcile,
            last_seen_online_counter = excluded.last_seen_online_counter,
            last_seen_ble_counter = excluded.last_seen_ble_counter",
        params![
            contact.contact_id,
            contact.device_id,
            contact.alias,
            contact.genesis_hash,
            if contact.public_key.is_empty() {
                None
            } else {
                Some(&contact.public_key)
            },
            contact.current_chain_tip.as_ref(),
            contact.added_at as i64,
            if contact.verified { 1i32 } else { 0i32 },
            contact.verification_proof.as_deref(),
            meta_to_blob(&contact.metadata),
            contact.ble_address.as_deref(),
            contact.status.clone(),
            if contact.needs_online_reconcile {
                1i32
            } else {
                0i32
            },
            contact.last_seen_online_counter as i64,
            contact.last_seen_ble_counter as i64,
        ],
    )?;

    // Persist the canonical single-device R_G alongside the contact record.
    if contact.device_id.len() == 32 {
        let mut devid = [0u8; 32];
        devid.copy_from_slice(&contact.device_id);
        let r_g = dsm::common::device_tree::DeviceTree::single(devid).root();
        conn.execute(
            "UPDATE contacts SET device_tree_root = ?1 WHERE contact_id = ?2 AND device_tree_root IS NULL",
            params![r_g.as_slice(), contact.contact_id],
        )?;
    }

    info!("Contact stored");
    Ok(())
}

pub fn get_all_contacts() -> Result<Vec<ContactRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let mut stmt = conn.prepare(
        "SELECT contact_id, device_id, alias, genesis_hash, public_key, chain_tip,
                added_at, verified, verification_proof, metadata, ble_address,
                status, needs_online_reconcile, last_seen_online_counter, last_seen_ble_counter,
                previous_chain_tip
           FROM contacts
       ORDER BY added_at DESC",
    )?;
    let iter = stmt.query_map([], |row| {
        let meta_blob: Vec<u8> = row.get(9)?;
        let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
        Ok(ContactRecord {
            contact_id: row.get(0)?,
            device_id: row.get(1)?,
            alias: row.get(2)?,
            genesis_hash: row.get(3)?,
            public_key: row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
            current_chain_tip: row.get(5)?,
            added_at: row.get::<_, i64>(6)? as u64,
            verified: row.get::<_, i32>(7)? != 0,
            verification_proof: row.get::<_, Option<Vec<u8>>>(8)?,
            metadata,
            ble_address: row.get(10)?,
            status: row
                .get::<_, String>(11)
                .unwrap_or_else(|_| "Created".to_string()),
            needs_online_reconcile: row.get::<_, i32>(12).unwrap_or(0) != 0,
            last_seen_online_counter: row.get::<_, i64>(13).unwrap_or(0) as u64,
            last_seen_ble_counter: row.get::<_, i64>(14).unwrap_or(0) as u64,
            previous_chain_tip: row.get(15).unwrap_or(None),
        })
    })?;

    let mut contacts = Vec::new();
    for c in iter {
        contacts.push(c?);
    }
    Ok(contacts)
}

/// Check if a contact exists for the given device_id (32 bytes).
/// Used by BLE layer to gate binding before attempting offline operations.
pub fn has_contact_for_device_id(device_id: &[u8]) -> Result<bool> {
    if device_id.len() != 32 {
        return Ok(false); // Invalid device_id length
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM contacts WHERE device_id = ?1",
        params![device_id],
        |row| row.get(0),
    )?;

    Ok(count > 0)
}

/// Check if a BLE address has a completed pairing (ble_address is stored for any contact).
/// Returns true if the address is paired, false otherwise.
pub fn is_ble_address_paired(address: &str) -> Result<bool> {
    if address.is_empty() {
        return Ok(false);
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM contacts WHERE ble_address = ?1",
        params![address],
        |row| row.get(0),
    )?;

    Ok(count > 0)
}

/// Get contact by device_id for chain tip validation.
/// Returns None if not found.
pub fn get_contact_by_device_id(device_id: &[u8]) -> Result<Option<ContactRecord>> {
    if device_id.len() != 32 {
        return Ok(None);
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result = conn
        .query_row(
            "SELECT contact_id, device_id, alias, genesis_hash, public_key, chain_tip,
                added_at, verified, verification_proof, metadata, ble_address,
                status, needs_online_reconcile, last_seen_online_counter, last_seen_ble_counter,
                previous_chain_tip
           FROM contacts
          WHERE device_id = ?1",
            params![device_id],
            |row| {
                let meta_blob: Vec<u8> = row.get(9)?;
                let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
                Ok(ContactRecord {
                    contact_id: row.get(0)?,
                    device_id: row.get(1)?,
                    alias: row.get(2)?,
                    genesis_hash: row.get(3)?,
                    public_key: row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
                    current_chain_tip: row.get(5)?,
                    added_at: row.get::<_, i64>(6)? as u64,
                    verified: row.get::<_, i32>(7)? != 0,
                    verification_proof: row.get::<_, Option<Vec<u8>>>(8)?,
                    metadata,
                    ble_address: row.get(10)?,
                    status: row
                        .get::<_, String>(11)
                        .unwrap_or_else(|_| "Created".to_string()),
                    needs_online_reconcile: row.get::<_, i32>(12).unwrap_or(0) != 0,
                    last_seen_online_counter: row.get::<_, i64>(13).unwrap_or(0) as u64,
                    last_seen_ble_counter: row.get::<_, i64>(14).unwrap_or(0) as u64,
                    previous_chain_tip: row.get(15).unwrap_or(None),
                })
            },
        )
        .optional()?;

    Ok(result)
}

/// Get contact by alias.
/// Returns None if not found.
pub fn get_contact_by_alias(alias: &str) -> Result<Option<ContactRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result = conn
        .query_row(
            "SELECT contact_id, device_id, alias, genesis_hash, public_key, chain_tip,
                added_at, verified, verification_proof, metadata, ble_address,
                status, needs_online_reconcile, last_seen_online_counter, last_seen_ble_counter,
                previous_chain_tip
           FROM contacts
          WHERE alias = ?1",
            params![alias],
            |row| {
                let meta_blob: Vec<u8> = row.get(9)?;
                let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
                Ok(ContactRecord {
                    contact_id: row.get(0)?,
                    device_id: row.get(1)?,
                    alias: row.get(2)?,
                    genesis_hash: row.get(3)?,
                    public_key: row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
                    current_chain_tip: row.get(5)?,
                    added_at: row.get::<_, i64>(6)? as u64,
                    verified: row.get::<_, i32>(7)? != 0,
                    verification_proof: row.get::<_, Option<Vec<u8>>>(8)?,
                    metadata,
                    ble_address: row.get(10)?,
                    status: row
                        .get::<_, String>(11)
                        .unwrap_or_else(|_| "Created".to_string()),
                    needs_online_reconcile: row.get::<_, i32>(12).unwrap_or(0) != 0,
                    last_seen_online_counter: row.get::<_, i64>(13).unwrap_or(0) as u64,
                    last_seen_ble_counter: row.get::<_, i64>(14).unwrap_or(0) as u64,
                    previous_chain_tip: row.get(15).unwrap_or(None),
                })
            },
        )
        .optional()?;

    Ok(result)
}

/// Get contact by normalized BLE address.
/// Returns None if not found.
pub fn get_contact_by_ble_address(ble_address: &str) -> Result<Option<ContactRecord>> {
    let normalized = ble_address.trim().to_uppercase();
    if normalized.is_empty() {
        return Ok(None);
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result = conn
        .query_row(
            "SELECT contact_id, device_id, alias, genesis_hash, public_key, chain_tip,
                added_at, verified, verification_proof, metadata, ble_address,
                status, needs_online_reconcile, last_seen_online_counter, last_seen_ble_counter,
                previous_chain_tip
           FROM contacts
          WHERE UPPER(ble_address) = ?1",
            params![normalized],
            |row| {
                let meta_blob: Vec<u8> = row.get(9)?;
                let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
                Ok(ContactRecord {
                    contact_id: row.get(0)?,
                    device_id: row.get(1)?,
                    alias: row.get(2)?,
                    genesis_hash: row.get(3)?,
                    public_key: row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
                    current_chain_tip: row.get(5)?,
                    added_at: row.get::<_, i64>(6)? as u64,
                    verified: row.get::<_, i32>(7)? != 0,
                    verification_proof: row.get::<_, Option<Vec<u8>>>(8)?,
                    metadata,
                    ble_address: row.get(10)?,
                    status: row
                        .get::<_, String>(11)
                        .unwrap_or_else(|_| "Created".to_string()),
                    needs_online_reconcile: row.get::<_, i32>(12).unwrap_or(0) != 0,
                    last_seen_online_counter: row.get::<_, i64>(13).unwrap_or(0) as u64,
                    last_seen_ble_counter: row.get::<_, i64>(14).unwrap_or(0) as u64,
                    previous_chain_tip: row.get(15).unwrap_or(None),
                })
            },
        )
        .optional()?;

    Ok(result)
}

/// Delete a contact by contact_id.
pub fn delete_contact_by_id(contact_id: &str) -> Result<()> {
    if contact_id.trim().is_empty() {
        return Err(anyhow!("Invalid contact_id"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let rows = conn.execute(
        "DELETE FROM contacts WHERE contact_id = ?1",
        params![contact_id],
    )?;

    if rows == 0 {
        log::warn!(
            "delete_contact_by_id: no rows deleted for contact_id={}",
            contact_id
        );
    } else {
        log::info!("delete_contact_by_id: removed contact_id={}", contact_id);
    }

    Ok(())
}

pub fn get_contact_public_key_by_device_id(device_id_str: &str) -> Option<Vec<u8>> {
    let device_id_bytes = crate::util::text_id::decode_base32_crockford(device_id_str)?;

    if device_id_bytes.len() != 32 {
        return None;
    }

    match get_contact_by_device_id(&device_id_bytes) {
        Ok(Some(contact)) if !contact.public_key.is_empty() => Some(contact.public_key),
        _ => None,
    }
}

/// Update contact status after BLE identity validation.
/// Sets status to BleCapable if chain tips match, or sets needs_online_reconcile if mismatch.
///
/// If the contact does not exist yet (common during BLE auto-pairing when the advertiser
/// receives the scanner's identity before a contact record is persisted), this function
/// returns Ok(()) with a warning instead of failing. The contact will be auto-created by
/// `processBleIdentityEnvelope` and updated on the next BLE interaction.
pub fn update_contact_ble_status(
    device_id: &[u8],
    observed_chain_tip: Option<&[u8]>,
    ble_address: Option<&str>,
) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }

    let contact = match get_contact_by_device_id(device_id)? {
        Some(c) => c,
        None => {
            log::warn!(
                "update_contact_ble_status: contact not found for device {:02x}{:02x}... — \
                 skipping (will be created by BLE auto-pairing)",
                device_id[0],
                device_id[1]
            );
            return Ok(());
        }
    };

    let now = tick();

    // Determine new status and reconciliation flag
    let (new_status, needs_reconcile) = if observed_chain_tip.is_some() {
        // Chain tip provided: validate it matches
        match (contact.current_chain_tip.as_deref(), observed_chain_tip) {
            (Some(stored_tip), Some(observed_tip))
                if stored_tip.len() == 32 && observed_tip.len() == 32 =>
            {
                if stored_tip == observed_tip {
                    // Tips match: BLE capable
                    ("BleCapable".to_string(), false)
                } else {
                    // Tips diverged: flag for online reconciliation
                    info!(
                        "Chain tip mismatch for device: stored={:?} observed={:?}",
                        &stored_tip[..8],
                        &observed_tip[..8]
                    );
                    (contact.status.clone(), true) // Keep existing status, flag reconcile
                }
            }
            (None, Some(_)) => {
                // First tip observation from BLE
                ("OnlineCapable".to_string(), false)
            }
            _ => {
                // Invalid data
                (contact.status.clone(), contact.needs_online_reconcile)
            }
        }
    } else {
        // No chain tip provided (BLE identity observation without chain tip)
        // Promote to BleCapable since we confirmed BLE connectivity and validated identity
        ("BleCapable".to_string(), false)
    };

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let updated_ble_address = ble_address.or(contact.ble_address.as_deref());
    let observed_tip_bytes = observed_chain_tip.filter(|tip| tip.len() == 32);
    let observed_tip_source = observed_tip_bytes
        .as_ref()
        .map(|_| ObservedRemoteTipSource::LivePeerClaim.db_value());

    conn.execute(
        "UPDATE contacts SET
            status = ?1,
            needs_online_reconcile = ?2,
            last_seen_ble_counter = ?3,
            ble_address = ?4,
            observed_remote_chain_tip = COALESCE(?5, observed_remote_chain_tip),
            observed_remote_tip_updated_at = CASE
                WHEN ?5 IS NULL THEN observed_remote_tip_updated_at
                ELSE ?3
            END,
            observed_remote_tip_source = CASE
                WHEN ?5 IS NULL THEN observed_remote_tip_source
                ELSE ?6
            END
         WHERE device_id = ?7",
        params![
            new_status,
            if needs_reconcile { 1i32 } else { 0i32 },
            now as i64,
            updated_ble_address,
            observed_tip_bytes,
            observed_tip_source,
            device_id,
        ],
    )?;

    info!(
        "Updated contact BLE status: {} (reconcile: {})",
        new_status, needs_reconcile
    );

    Ok(())
}

/// Persist an unverified remote chain-tip claim in an observed-only namespace.
///
/// This is advisory durability for BLE/session recovery. It MUST NOT be used as
/// the canonical bilateral relationship tip.
pub fn record_observed_remote_chain_tip(
    device_id: &[u8],
    observed_chain_tip: &[u8],
    source: ObservedRemoteTipSource,
) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    if observed_chain_tip.len() != 32 {
        return Err(anyhow!("Invalid observed_chain_tip length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let now = tick();
    let updated = conn.execute(
        "UPDATE contacts SET
            observed_remote_chain_tip = ?1,
            observed_remote_tip_updated_at = ?2,
            observed_remote_tip_source = ?3
         WHERE device_id = ?4",
        params![observed_chain_tip, now as i64, source.db_value(), device_id],
    )?;
    if updated == 0 {
        return Err(anyhow!(
            "Cannot persist observed remote chain tip for unknown contact"
        ));
    }

    info!(
        "Recorded observed remote chain tip without mutating canonical state: tip={:?}",
        &observed_chain_tip[..8]
    );
    Ok(())
}

/// Load the last observed unverified remote chain tip, if any.
pub fn get_observed_remote_tip_record(device_id: &[u8]) -> Result<Option<ObservedRemoteTipRecord>> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let value: Option<(Option<Vec<u8>>, Option<i64>, Option<i64>)> = conn
        .query_row(
            "SELECT observed_remote_chain_tip, observed_remote_tip_updated_at, observed_remote_tip_source
               FROM contacts WHERE device_id = ?1",
            params![device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;

    match value {
        Some((Some(tip), updated_at, source)) if tip.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&tip);
            Ok(Some(ObservedRemoteTipRecord {
                tip: arr,
                updated_at: updated_at.unwrap_or_default() as u64,
                source: ObservedRemoteTipSource::from_db(source),
            }))
        }
        Some((Some(tip), _, _)) => Err(anyhow!(
            "Observed remote chain tip has invalid length {}",
            tip.len()
        )),
        Some((None, _, _)) => Ok(None),
        None => Ok(None),
    }
}

pub fn get_observed_remote_chain_tip(device_id: &[u8]) -> Result<Option<[u8; 32]>> {
    Ok(get_observed_remote_tip_record(device_id)?.map(|record| record.tip))
}

/// Clear any observed-only remote chain-tip claim for a contact.
pub fn clear_observed_remote_chain_tip(device_id: &[u8]) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.execute(
        "UPDATE contacts
            SET observed_remote_chain_tip = NULL,
                observed_remote_tip_updated_at = NULL,
                observed_remote_tip_source = NULL
          WHERE device_id = ?1",
        params![device_id],
    )?;
    Ok(())
}

pub fn clear_observed_remote_chain_tip_if_matches(
    device_id: &[u8],
    observed_chain_tip: &[u8],
) -> Result<bool> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    if observed_chain_tip.len() != 32 {
        return Err(anyhow!("Invalid observed_chain_tip length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let rows = conn.execute(
        "UPDATE contacts
            SET observed_remote_chain_tip = NULL,
                observed_remote_tip_updated_at = NULL,
                observed_remote_tip_source = NULL
          WHERE device_id = ?1
            AND observed_remote_chain_tip = ?2",
        params![device_id, observed_chain_tip],
    )?;
    Ok(rows > 0)
}

/// Restore a finalized bilateral chain tip only when storage is empty, zero, or already equal.
///
/// This is the only valid non-CAS restore path. It never overwrites a different
/// canonical tip.
pub fn restore_finalized_bilateral_chain_tip(device_id: &[u8], restored_tip: &[u8]) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    if restored_tip.len() != 32 {
        return Err(anyhow!("Invalid restored_tip length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let current_tip: Option<Vec<u8>> = conn
        .query_row(
            "SELECT chain_tip FROM contacts WHERE device_id = ?1",
            params![device_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();

    match current_tip.as_deref() {
        Some(tip) if tip.len() != 32 => {
            return Err(anyhow!(
                "Stored finalized chain tip has invalid length {}",
                tip.len()
            ));
        }
        Some(tip) if tip != restored_tip && !tip.iter().all(|byte| *byte == 0) => {
            return Err(anyhow!(
                "Refusing to overwrite finalized bilateral chain tip with a different restored tip"
            ));
        }
        _ => {}
    }

    let now = tick();
    let zero_tip = [0u8; 32];
    let updated = conn.execute(
        "UPDATE contacts SET
            previous_chain_tip = CASE
                WHEN chain_tip IS NULL OR chain_tip = ?1 OR chain_tip = ?2 THEN previous_chain_tip
                ELSE chain_tip
            END,
            chain_tip = ?2,
            local_bilateral_chain_tip = ?2,
            observed_remote_chain_tip = NULL,
            observed_remote_tip_updated_at = NULL,
            observed_remote_tip_source = NULL,
            needs_online_reconcile = 0,
            last_seen_online_counter = ?3,
            status = CASE
                WHEN status = 'BleCapable' THEN 'BleCapable'
                ELSE 'OnlineCapable'
            END
         WHERE device_id = ?4
           AND (chain_tip IS NULL OR chain_tip = ?1 OR chain_tip = ?2)",
        params![&zero_tip, restored_tip, now as i64, device_id],
    )?;
    if updated == 0 {
        return Err(anyhow!(
            "Cannot restore finalized bilateral chain tip for unknown contact"
        ));
    }

    info!(
        "Restored finalized bilateral chain tip without overwrite: tip={:?}",
        &restored_tip[..8]
    );
    Ok(())
}

/// Check whether the persisted shared relationship tip still matches the
/// expected parent tip for the next transition.
///
/// `NULL` is treated as the zero tip for first-use relationships.
pub fn contact_chain_tip_matches_expected(
    device_id: &[u8],
    expected_parent_tip: &[u8],
) -> Result<bool> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    if expected_parent_tip.len() != 32 {
        return Err(anyhow!("Invalid expected_parent_tip length"));
    }

    let current_tip = get_contact_chain_tip_raw(device_id).unwrap_or([0u8; 32]);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(expected_parent_tip);
    Ok(current_tip == expected)
}

/// Atomically advance a finalized relationship tip only if the persisted parent
/// tip still matches `expected_parent_tip`.
///
/// Returns `Ok(true)` when the advance succeeds, `Ok(false)` when the parent no
/// longer matches (Tripwire / ParentConsumed), and `Err(_)` for actual storage
/// failures. `NULL` is treated as the zero tip for first-use relationships.
pub fn try_advance_finalized_bilateral_chain_tip(
    device_id: &[u8],
    expected_parent_tip: &[u8],
    new_chain_tip: &[u8],
) -> Result<bool> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    if expected_parent_tip.len() != 32 {
        return Err(anyhow!("Invalid expected_parent_tip length"));
    }
    if new_chain_tip.len() != 32 {
        return Err(anyhow!("Invalid chain_tip length"));
    }
    if expected_parent_tip == new_chain_tip {
        return Err(anyhow!(
            "Finalized bilateral chain tip advance requires child tip different from parent tip"
        ));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let now = tick();
    let expected_is_zero = expected_parent_tip.iter().all(|b| *b == 0);

    let rows_changed = if expected_is_zero {
        conn.execute(
            "UPDATE contacts SET
                previous_chain_tip = chain_tip,
                chain_tip = ?1,
                local_bilateral_chain_tip = ?1,
                observed_remote_chain_tip = NULL,
                observed_remote_tip_updated_at = NULL,
                observed_remote_tip_source = NULL,
                needs_online_reconcile = 0,
                last_seen_online_counter = ?2,
                status = CASE
                    WHEN status = 'BleCapable' THEN 'BleCapable'
                    ELSE 'OnlineCapable'
                END
             WHERE device_id = ?3
               AND (chain_tip IS NULL OR chain_tip = ?4)",
            params![new_chain_tip, now as i64, device_id, expected_parent_tip],
        )?
    } else {
        conn.execute(
            "UPDATE contacts SET
                previous_chain_tip = chain_tip,
                chain_tip = ?1,
                local_bilateral_chain_tip = ?1,
                observed_remote_chain_tip = NULL,
                observed_remote_tip_updated_at = NULL,
                observed_remote_tip_source = NULL,
                needs_online_reconcile = 0,
                last_seen_online_counter = ?2,
                status = CASE
                    WHEN status = 'BleCapable' THEN 'BleCapable'
                    ELSE 'OnlineCapable'
                END
             WHERE device_id = ?3
               AND chain_tip = ?4",
            params![new_chain_tip, now as i64, device_id, expected_parent_tip],
        )?
    };

    if rows_changed > 0 {
        info!(
            "Advanced finalized bilateral chain tip with parent match: parent={:?} tip={:?}",
            &expected_parent_tip[..8],
            &new_chain_tip[..8]
        );
        Ok(true)
    } else {
        warn!(
            "Rejected finalized bilateral chain tip advance: expected_parent={:?} new_tip={:?}",
            &expected_parent_tip[..8],
            &new_chain_tip[..8]
        );
        Ok(false)
    }
}

/// Clear the `needs_online_reconcile` flag for a contact WITHOUT touching the
/// chain tip. This is the only correct way to mark a reconcile as done —
/// the observed-tip namespace must NOT be written into canonical chain-tip
/// columns just to clear this flag, as doing so destroys the real chain tip and
/// causes every subsequent Prepare to be rejected with TipMismatch.
pub fn clear_contact_reconcile_flag(device_id: &[u8]) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.execute(
        "UPDATE contacts SET needs_online_reconcile = 0 WHERE device_id = ?1",
        params![device_id],
    )?;

    log::info!(
        "Cleared reconcile flag for contact {:02x}{:02x}..",
        device_id[0],
        device_id[1]
    );

    Ok(())
}

/// Flag a contact for online reconciliation without changing status.
pub fn mark_contact_needs_online_reconcile(device_id: &[u8]) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let updated = conn.execute(
        "UPDATE contacts SET needs_online_reconcile = 1 WHERE device_id = ?1",
        params![device_id],
    )?;

    if updated > 0 {
        info!(
            "Marked contact for online reconciliation: device_id={:02x}{:02x}...",
            device_id[0], device_id[1]
        );
    }

    Ok(())
}

/// §6 Tripwire Fork-Exclusion: Permanently brick a relationship after fork detection.
///
/// Sets the contact status to "Bricked" and records the reason in metadata.
/// Once bricked, no future transfers with this counterparty are accepted.
/// Only fires on post-commit fork: stored tip is non-zero, doesn't match
/// the claimed parent tip. Pre-commit forking (abandoned BLE sessions,
/// failed online attempts) does NOT trigger this because the stored tip
/// only advances after full finalization.
pub fn brick_contact(device_id: &[u8; 32], reason: &str) {
    let binding = match get_connection() {
        Ok(b) => b,
        Err(e) => {
            log::error!("[client_db] brick_contact: DB connection failed: {}", e);
            return;
        }
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let reason_bytes = reason.as_bytes();
    match conn.execute(
        "UPDATE contacts SET status = 'Bricked', metadata = ?1 WHERE device_id = ?2",
        params![reason_bytes, device_id.as_slice()],
    ) {
        Ok(n) if n > 0 => {
            log::error!(
                "[client_db] §6 TRIPWIRE: Contact BRICKED (device_id={:02x}{:02x}{:02x}{:02x}..): {}",
                device_id[0], device_id[1], device_id[2], device_id[3], reason
            );
        }
        Ok(_) => {
            log::warn!(
                "[client_db] brick_contact: no matching contact for device_id={:02x}{:02x}{:02x}{:02x}..",
                device_id[0], device_id[1], device_id[2], device_id[3]
            );
        }
        Err(e) => {
            log::error!("[client_db] brick_contact: SQL update failed: {}", e);
        }
    }
}

/// Check if a contact has been permanently bricked (Tripwire fork-exclusion).
pub fn is_contact_bricked(device_id: &[u8]) -> bool {
    if device_id.len() != 32 {
        return false;
    }

    let binding = match get_connection() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.query_row(
        "SELECT status FROM contacts WHERE device_id = ?1",
        params![device_id],
        |row| row.get::<_, String>(0),
    )
    .map(|status| status == "Bricked")
    .unwrap_or(false)
}

/// Get the Device Tree root R_G for a contact (§2.3).
///
/// Returns the stored value if present.
pub fn get_contact_device_tree_root(device_id: &[u8]) -> Option<[u8; 32]> {
    if device_id.len() != 32 {
        return None;
    }

    let binding = match get_connection() {
        Ok(b) => b,
        Err(_) => return None,
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT device_tree_root FROM contacts WHERE device_id = ?1",
            params![device_id],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    match result {
        Some(blob) if blob.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&blob);
            Some(arr)
        }
        _ => None,
    }
}

/// Get the authenticated persisted device-tree commitment for a contact.
///
/// Today this is the raw stored `R_G` wrapped for receipt acceptance paths
/// that verify `π_dev` relationship-locally.
pub fn get_contact_device_tree_commitment(
    device_id: &[u8],
) -> Option<DeviceTreeAcceptanceCommitment> {
    get_contact_device_tree_root(device_id).map(DeviceTreeAcceptanceCommitment::from_root)
}

/// Persist the Device Tree root R_G for a contact (§2.3).
///
/// Called during pairing or on receipt of a multi-device R_G from a counterparty.
/// Overwrites any previously stored root for this device_id.
pub fn store_contact_device_tree_root(
    device_id: &[u8],
    root: &[u8; 32],
) -> Result<(), dsm::types::error::DsmError> {
    if device_id.len() != 32 {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "store_contact_device_tree_root: device_id must be 32 bytes",
        ));
    }
    let binding = get_connection().map_err(|e| {
        dsm::types::error::DsmError::invalid_operation(format!("DB unavailable: {e}"))
    })?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "UPDATE contacts SET device_tree_root = ?1 WHERE device_id = ?2",
        rusqlite::params![root.as_slice(), device_id],
    )
    .map_err(|e| {
        dsm::types::error::DsmError::invalid_operation(format!(
            "store_contact_device_tree_root SQL error: {e}"
        ))
    })?;
    Ok(())
}

/// Get a contact's current chain tip from SQLite storage.
/// Strict mode: returns None if chain_tip is NULL or invalid.
pub fn get_contact_chain_tip(device_id: &[u8]) -> Option<[u8; 32]> {
    if device_id.len() != 32 {
        log::warn!(
            "[client_db] get_contact_chain_tip: invalid device_id length {}",
            device_id.len()
        );
        return None;
    }

    // Debug: log the device_id we're looking for
    log::info!(
        "[client_db] get_contact_chain_tip: looking for device_id={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...",
        device_id[0], device_id[1], device_id[2], device_id[3],
        device_id[4], device_id[5], device_id[6], device_id[7]
    );

    let binding = match get_connection() {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "[client_db] get_contact_chain_tip: failed to get connection: {}",
                e
            );
            return None;
        }
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    // Strict canonical lookup: chain_tip only.
    // NOTE: DB column is "chain_tip", struct field is "current_chain_tip"
    let result: Result<Option<Vec<u8>>, _> = conn.query_row(
        "SELECT chain_tip FROM contacts WHERE device_id = ?1",
        params![device_id],
        |row| row.get(0),
    );

    match result {
        Ok(Some(tip)) if tip.len() == 32 => {
            log::info!(
                "[client_db] get_contact_chain_tip: FOUND chain_tip in DB (first 8: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x})",
                tip[0], tip[1], tip[2], tip[3], tip[4], tip[5], tip[6], tip[7]
            );
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&tip);
            Some(arr)
        }
        Ok(tip) => {
            log::warn!(
                "[client_db] get_contact_chain_tip: contact found but invalid chain_tip len={:?}",
                tip.as_ref().map(|t| t.len())
            );
            None
        }
        Err(e) => {
            log::warn!(
                "[client_db] get_contact_chain_tip: query failed (contact not found?): {}",
                e
            );
            None
        }
    }
}

/// Get a contact's chain tip from SQLite storage.
/// Returns None if chain_tip is NULL or invalid length.
pub fn get_contact_chain_tip_raw(device_id: &[u8]) -> Option<[u8; 32]> {
    if device_id.len() != 32 {
        log::warn!(
            "[client_db] get_contact_chain_tip_raw: invalid device_id length {}",
            device_id.len()
        );
        return None;
    }

    let binding = match get_connection() {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "[client_db] get_contact_chain_tip_raw: failed to get connection: {}",
                e
            );
            return None;
        }
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result: Result<Option<Vec<u8>>, _> = conn.query_row(
        "SELECT chain_tip FROM contacts WHERE device_id = ?1",
        params![device_id],
        |row| row.get(0),
    );

    match result {
        Ok(Some(tip)) if tip.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&tip);
            Some(arr)
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("[client_db] get_contact_chain_tip_raw: query failed: {}", e);
            None
        }
    }
}

/// Persist the caller's own bilateral chain tip for a relationship with `device_id`.
/// Keyed by the counterparty's device_id — "my chain tip for my relationship with device X."
pub fn update_local_bilateral_chain_tip(device_id: &[u8], tip: &[u8]) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    if tip.len() != 32 {
        return Err(anyhow!("Invalid tip length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.execute(
        "UPDATE contacts SET local_bilateral_chain_tip = ?1 WHERE device_id = ?2",
        params![tip, device_id],
    )?;

    info!(
        "[client_db] Updated local bilateral chain tip: {:02x}{:02x}{:02x}{:02x}...",
        tip[0], tip[1], tip[2], tip[3]
    );

    Ok(())
}

/// Get the caller's own bilateral chain tip for a relationship with `device_id`.
/// Returns None if NULL or invalid length.
pub fn get_local_bilateral_chain_tip(device_id: &[u8]) -> Option<[u8; 32]> {
    if device_id.len() != 32 {
        log::warn!(
            "[client_db] get_local_bilateral_chain_tip: invalid device_id length {}",
            device_id.len()
        );
        return None;
    }

    let binding = match get_connection() {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "[client_db] get_local_bilateral_chain_tip: failed to get connection: {}",
                e
            );
            return None;
        }
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result: Result<Option<Vec<u8>>, _> = conn.query_row(
        "SELECT local_bilateral_chain_tip FROM contacts WHERE device_id = ?1",
        params![device_id],
        |row| row.get(0),
    );

    match result {
        Ok(Some(tip)) if tip.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&tip);
            Some(arr)
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!(
                "[client_db] get_local_bilateral_chain_tip: query failed: {}",
                e
            );
            None
        }
    }
}

/// Check if there are any contacts that are not yet BLE-capable (i.e., need BLE pairing)
pub fn has_unpaired_contacts() -> bool {
    let binding = match get_connection() {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "[client_db] has_unpaired_contacts: failed to get connection: {}",
                e
            );
            return false;
        }
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result: Result<i64, _> = conn.query_row(
        "SELECT COUNT(*) FROM contacts WHERE status != 'BleCapable' OR status IS NULL",
        [],
        |row| row.get(0),
    );

    match result {
        Ok(count) => count > 0,
        Err(e) => {
            log::warn!("[client_db] has_unpaired_contacts: query failed: {}", e);
            false
        }
    }
}

/// Update a contact's public key (e.g., after receiving signing key via BLE prepare)
pub fn update_contact_public_key(device_id: &[u8], public_key: &[u8]) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let rows_changed = conn.execute(
        "UPDATE contacts SET public_key = ?1 WHERE device_id = ?2",
        params![public_key, device_id],
    )?;

    if rows_changed == 0 {
        info!(
            "No contact found with device_id={:?} to update public_key",
            &device_id[..8]
        );
    } else {
        info!(
            "Updated contact public_key: device_id={:?} key_len={}",
            &device_id[..8],
            public_key.len()
        );
    }

    Ok(())
}

/// Remove a contact by its contact_id. Returns Ok(true) if a row was deleted, Ok(false) if not found.
pub fn remove_contact(contact_id: &str) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let affected = conn.execute(
        "DELETE FROM contacts WHERE contact_id = ?1",
        params![contact_id],
    )?;
    if affected > 0 {
        info!("Contact removed: {contact_id}");
        Ok(true)
    } else {
        info!("Contact not found: {contact_id}");
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::collections::HashMap;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_contact(device_id: [u8; 32], alias: &str) -> ContactRecord {
        ContactRecord {
            contact_id: format!("cid-{alias}"),
            device_id: device_id.to_vec(),
            alias: alias.to_string(),
            genesis_hash: [0xAAu8; 32].to_vec(),
            public_key: vec![0xBBu8; 64],
            current_chain_tip: None,
            added_at: 1,
            verified: false,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        }
    }

    #[test]
    fn has_contact_for_device_id_rejects_short_device_id() {
        let short = vec![0u8; 16];
        assert_eq!(has_contact_for_device_id(&short).unwrap(), false);
    }

    #[test]
    fn get_contact_by_device_id_returns_none_for_invalid_length() {
        assert!(get_contact_by_device_id(&[0u8; 31]).unwrap().is_none());
        assert!(get_contact_by_device_id(&[0u8; 33]).unwrap().is_none());
    }

    #[test]
    fn delete_contact_by_id_rejects_empty_id() {
        let err = delete_contact_by_id("").unwrap_err();
        assert!(err.to_string().contains("Invalid contact_id"));
        let err2 = delete_contact_by_id("   ").unwrap_err();
        assert!(err2.to_string().contains("Invalid contact_id"));
    }

    #[test]
    fn is_ble_address_paired_returns_false_for_empty_address() {
        assert_eq!(is_ble_address_paired("").unwrap(), false);
    }

    #[test]
    fn update_contact_ble_status_rejects_short_device_id() {
        let err = update_contact_ble_status(&[0u8; 16], None, None).unwrap_err();
        assert!(err.to_string().contains("Invalid device_id length"));
    }

    #[test]
    fn record_observed_remote_chain_tip_rejects_invalid_lengths() {
        let err = record_observed_remote_chain_tip(&[0u8; 16], &[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("Invalid device_id length"));
        let err2 = record_observed_remote_chain_tip(&[0u8; 32], &[0u8; 16]).unwrap_err();
        assert!(err2.to_string().contains("Invalid observed_chain_tip length"));
    }

    #[test]
    fn try_advance_rejects_same_parent_and_child_tip() {
        let tip = [0x11u8; 32];
        let err = try_advance_finalized_bilateral_chain_tip(&[0u8; 32], &tip, &tip).unwrap_err();
        assert!(err.to_string().contains("different from parent"));
    }

    #[test]
    fn is_contact_bricked_returns_false_for_invalid_device_id() {
        assert!(!is_contact_bricked(&[0u8; 10]));
    }

    #[test]
    fn get_contact_device_tree_root_returns_none_for_invalid_device_id() {
        assert!(get_contact_device_tree_root(&[0u8; 10]).is_none());
    }

    #[test]
    #[serial]
    fn store_and_retrieve_contact_round_trip() {
        init_test_db();
        let device_id = [0x01u8; 32];
        let contact = make_contact(device_id, "alice");
        store_contact(&contact).expect("store contact");

        let loaded = get_contact_by_device_id(&device_id)
            .expect("query")
            .expect("contact exists");
        assert_eq!(loaded.alias, "alice");
        assert_eq!(loaded.device_id, device_id.to_vec());
        assert_eq!(loaded.public_key, vec![0xBBu8; 64]);
    }

    #[test]
    #[serial]
    fn get_all_contacts_returns_stored_contacts() {
        init_test_db();
        let c1 = make_contact([0x02u8; 32], "bob");
        let c2 = make_contact([0x03u8; 32], "carol");
        store_contact(&c1).expect("store c1");
        store_contact(&c2).expect("store c2");

        let all = get_all_contacts().expect("get all");
        assert!(all.len() >= 2);
        assert!(all.iter().any(|c| c.alias == "bob"));
        assert!(all.iter().any(|c| c.alias == "carol"));
    }

    #[test]
    #[serial]
    fn get_contact_by_alias_finds_stored_contact() {
        init_test_db();
        let contact = make_contact([0x04u8; 32], "dave");
        store_contact(&contact).expect("store");

        let found = get_contact_by_alias("dave")
            .expect("query")
            .expect("contact exists");
        assert_eq!(found.device_id, [0x04u8; 32].to_vec());
    }

    #[test]
    #[serial]
    fn remove_contact_returns_false_for_nonexistent() {
        init_test_db();
        let removed = remove_contact("nonexistent-id").expect("remove");
        assert!(!removed);
    }

    #[test]
    #[serial]
    fn remove_contact_deletes_existing() {
        init_test_db();
        let contact = make_contact([0x05u8; 32], "eve");
        store_contact(&contact).expect("store");

        let removed = remove_contact("cid-eve").expect("remove");
        assert!(removed);
        assert!(get_contact_by_alias("eve").expect("query").is_none());
    }
}
