// SPDX-License-Identifier: MIT OR Apache-2.0
//! Contact record persistence and BLE status management.

use anyhow::{anyhow, Result};
use log::info;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use super::types::ContactRecord;
use crate::storage::codecs::{meta_from_blob, meta_to_blob};

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
    pub source: ObservedRemoteTipSource,
}

pub fn store_contact(contact: &ContactRecord) -> Result<()> {
    // A contact is added from its self-proving directory entry, which carries
    // its AK and its Kyber key, and starts at the relationship's h_0. A record
    // without any of them is not a contact.
    if contact.device_id.len() != 32 {
        return Err(anyhow!(
            "contact device_id is {} bytes, expected 32",
            contact.device_id.len()
        ));
    }
    if contact.public_key.is_empty() {
        return Err(anyhow!("contact {:?} has no signing key", contact.alias));
    }
    if contact.kyber_public_key.is_empty() {
        return Err(anyhow!("contact {:?} has no Kyber key", contact.alias));
    }
    if contact.current_chain_tip.as_ref().map(Vec::len) != Some(32) {
        return Err(anyhow!(
            "contact {:?} has no 32-byte relationship tip",
            contact.alias
        ));
    }
    info!("Storing contact: {}", contact.alias);

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    // Adding a contact again pins nothing new: its genesis, AK and Kyber key
    // are the ones first pinned, and its relationship state (tips, pairing
    // state, the online-reconcile hold) is not the add's to reset.
    let pinned: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT genesis_hash, public_key, kyber_public_key FROM contacts WHERE device_id = ?1",
            params![contact.device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((genesis_hash, public_key, kyber_public_key)) = pinned {
        if genesis_hash != contact.genesis_hash
            || public_key != contact.public_key
            || kyber_public_key != contact.kyber_public_key
        {
            return Err(anyhow!(
                "contact {:?} is pinned to another genesis or key; a contact's pinned identity is \
                 not replaced",
                contact.alias
            ));
        }
    }
    conn.execute(
        "INSERT INTO contacts (
            contact_id, device_id, alias, genesis_hash, public_key, kyber_public_key, chain_tip,
            local_bilateral_chain_tip, verified, verification_proof, metadata, ble_address,
            status, needs_online_reconcile
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?7,?8,?9,?10,?11,?12,?13)
        ON CONFLICT(device_id) DO UPDATE SET
            alias = excluded.alias,
            verified = CASE
                WHEN excluded.verified != 0 OR contacts.verified != 0 THEN 1
                ELSE 0
            END,
            verification_proof = COALESCE(excluded.verification_proof, contacts.verification_proof),
            metadata = excluded.metadata,
            ble_address = COALESCE(excluded.ble_address, contacts.ble_address)",
        params![
            contact.contact_id,
            contact.device_id,
            contact.alias,
            contact.genesis_hash,
            contact.public_key,
            contact.kyber_public_key,
            contact.current_chain_tip.as_ref(),
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
        ],
    )?;

    // Persist the canonical single-device R_G alongside the contact record.
    let mut devid = [0u8; 32];
    devid.copy_from_slice(&contact.device_id);
    let r_g = dsm::common::device_tree::DeviceTree::single(devid).root();
    conn.execute(
        "UPDATE contacts SET device_tree_root = ?1 WHERE contact_id = ?2 AND device_tree_root IS NULL",
        params![r_g.as_slice(), contact.contact_id],
    )?;

    info!("Contact stored");
    Ok(())
}

/// The columns [`contact_from_row`] reads, in its order.
const CONTACT_COLUMNS: &str = "contact_id, device_id, alias, genesis_hash, public_key, \
     kyber_public_key, chain_tip, verified, verification_proof, metadata, ble_address, status, \
     needs_online_reconcile, previous_chain_tip";

/// A contact row read as stored: every column its type, the keys present,
/// the metadata decoding. A row that does not read is an error, never a
/// record with defaults in its place.
fn contact_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContactRecord> {
    let meta_blob: Vec<u8> = row.get(9)?;
    let metadata = meta_from_blob(&meta_blob).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Blob, e.into())
    })?;
    Ok(ContactRecord {
        contact_id: row.get(0)?,
        device_id: row.get(1)?,
        alias: row.get(2)?,
        genesis_hash: row.get(3)?,
        public_key: row.get(4)?,
        kyber_public_key: row.get(5)?,
        current_chain_tip: row.get(6)?,
        verified: row.get::<_, i32>(7)? != 0,
        verification_proof: row.get(8)?,
        metadata,
        ble_address: row.get(10)?,
        status: row.get(11)?,
        needs_online_reconcile: row.get::<_, i32>(12)? != 0,
        previous_chain_tip: row.get(13)?,
    })
}

pub fn get_all_contacts() -> Result<Vec<ContactRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let mut stmt = conn.prepare(&format!(
        "SELECT {CONTACT_COLUMNS} FROM contacts ORDER BY rowid DESC"
    ))?;
    let iter = stmt.query_map([], contact_from_row)?;

    let mut contacts = Vec::new();
    for c in iter {
        contacts.push(c?);
    }
    Ok(contacts)
}

/// Check if a contact exists for the given device_id (32 bytes).
/// Used by BLE layer to gate binding before attempting offline operations.
pub fn has_contact_for_device_id(device_id: &[u8]) -> Result<bool> {
    require_device_id(device_id)?;

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
    require_device_id(device_id)?;

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result = conn
        .query_row(
            &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE device_id = ?1"),
            params![device_id],
            contact_from_row,
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
            &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE alias = ?1"),
            params![alias],
            contact_from_row,
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
            &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE UPPER(ble_address) = ?1"),
            params![normalized],
            contact_from_row,
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

/// The signing key of the contact whose device id is `device_id_str`
/// (Base32 Crockford), or `None` when no contact has that device id.
pub fn get_contact_public_key_by_device_id(device_id_str: &str) -> Result<Option<Vec<u8>>> {
    let device_id_bytes = crate::util::text_id::decode_base32_crockford(device_id_str)
        .ok_or_else(|| anyhow!("device id is not Base32 Crockford"))?;
    Ok(get_contact_by_device_id(&device_id_bytes)?.map(|contact| contact.public_key))
}

/// Record what a BLE identity observation says about a contact's transport:
/// its BLE address, the pairing state that drives scanning (`BleCapable`),
/// and a chain tip the peer reported, kept as an observed claim only.
///
/// Transport facts decide nothing about the relationship: this never touches
/// the relationship tips or the online-reconcile hold. A tip the peer reports
/// that differs from the stored one leaves the pairing state as it was; the
/// observed claim blocks sending until the relationship is reconciled.
pub fn update_contact_ble_status(
    device_id: &[u8],
    observed_chain_tip: Option<&[u8]>,
    ble_address: Option<&str>,
) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    let contact = get_contact_by_device_id(device_id)?
        .ok_or_else(|| anyhow!("no contact has that device id"))?;
    let observed_tip_bytes = match observed_chain_tip {
        Some(tip) if tip.len() == 32 => Some(tip),
        Some(tip) => {
            return Err(anyhow!(
                "an observed chain tip is {} bytes, expected 32",
                tip.len()
            ))
        }
        None => None,
    };
    let diverged = match (contact.current_chain_tip.as_deref(), observed_tip_bytes) {
        (Some(stored), Some(observed)) => stored != observed,
        _ => false,
    };
    let new_status = if diverged {
        contact.status.clone()
    } else {
        "BleCapable".to_string()
    };

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let updated_ble_address = ble_address.or(contact.ble_address.as_deref());
    let observed_tip_source = observed_tip_bytes
        .as_ref()
        .map(|_| ObservedRemoteTipSource::LivePeerClaim.db_value());

    conn.execute(
        "UPDATE contacts SET
            status = ?1,
            ble_address = ?2,
            observed_remote_chain_tip = COALESCE(?3, observed_remote_chain_tip),
            observed_remote_tip_source = CASE
                WHEN ?3 IS NULL THEN observed_remote_tip_source
                ELSE ?4
            END
         WHERE device_id = ?5",
        params![
            new_status,
            updated_ble_address,
            observed_tip_bytes,
            observed_tip_source,
            device_id,
        ],
    )?;

    info!(
        "Updated contact BLE status: {} (observed tip diverged: {})",
        new_status, diverged
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

    let updated = conn.execute(
        "UPDATE contacts SET
            observed_remote_chain_tip = ?1,
            observed_remote_tip_source = ?2
         WHERE device_id = ?3",
        params![observed_chain_tip, source.db_value(), device_id],
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

    let value: Option<(Option<Vec<u8>>, Option<i64>)> = conn
        .query_row(
            "SELECT observed_remote_chain_tip, observed_remote_tip_source
               FROM contacts WHERE device_id = ?1",
            params![device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    match value {
        Some((Some(tip), source)) if tip.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&tip);
            Ok(Some(ObservedRemoteTipRecord {
                tip: arr,
                source: ObservedRemoteTipSource::from_db(source),
            }))
        }
        Some((Some(tip), _)) => Err(anyhow!(
            "Observed remote chain tip has invalid length {}",
            tip.len()
        )),
        Some((None, _)) => Ok(None),
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

    let updated = conn.execute(
        "UPDATE contacts SET
            local_bilateral_chain_tip = ?1,
            observed_remote_chain_tip = NULL,
            observed_remote_tip_source = NULL,
            needs_online_reconcile = 0,
            status = CASE
                WHEN status = 'BleCapable' THEN 'BleCapable'
                ELSE 'OnlineCapable'
            END
         WHERE device_id = ?2 AND chain_tip = ?1",
        params![restored_tip, device_id],
    )?;
    if updated == 0 {
        return Err(anyhow!(
            "Refusing to restore a finalized bilateral chain tip: no contact holds that tip"
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

    let current_tip = get_contact_chain_tip(device_id)?
        .ok_or_else(|| anyhow!("no contact has this device id"))?;
    Ok(current_tip.as_slice() == expected_parent_tip)
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

/// The Device Tree root `R_G` kept for a contact (§2.3): `None` when the
/// device is not a contact or no root is kept for it. A malformed device id,
/// an unreadable database, or a stored root that is not 32 bytes is an error,
/// never an absent root.
pub fn get_contact_device_tree_root(
    device_id: &[u8],
) -> Result<Option<[u8; 32]>, dsm::types::error::DsmError> {
    use dsm::types::error::DsmError;
    if device_id.len() != 32 {
        return Err(DsmError::invalid_operation(
            "get_contact_device_tree_root: device_id must be 32 bytes",
        ));
    }
    let binding = get_connection()
        .map_err(|e| DsmError::storage(format!("DB unavailable: {e}"), None::<std::io::Error>))?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let stored: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT device_tree_root FROM contacts WHERE device_id = ?1",
            params![device_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            DsmError::storage(
                format!("contact device_tree_root read: {e}"),
                None::<std::io::Error>,
            )
        })?;
    match stored.flatten() {
        None => Ok(None),
        Some(blob) => <[u8; 32]>::try_from(blob.as_slice())
            .map(Some)
            .map_err(|_| {
                DsmError::storage(
                    format!(
                        "the contact's stored device_tree_root is {} bytes, not 32",
                        blob.len()
                    ),
                    None::<std::io::Error>,
                )
            }),
    }
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

fn require_device_id(device_id: &[u8]) -> Result<()> {
    if device_id.len() != 32 {
        return Err(anyhow!(
            "device id is {} bytes, expected 32",
            device_id.len()
        ));
    }
    Ok(())
}

/// Read one 32-byte tip column of the contact `device_id`: `None` when no
/// contact has that device id. Every contact starts at its relationship's
/// h_0, so a contact with no tip, or a tip that is not 32 bytes, is a
/// corrupt row and an error.
fn read_contact_tip(device_id: &[u8], column: &str) -> Result<Option<[u8; 32]>> {
    require_device_id(device_id)?;
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let tip: Option<Option<Vec<u8>>> = conn
        .query_row(
            &format!("SELECT {column} FROM contacts WHERE device_id = ?1"),
            params![device_id],
            |row| row.get(0),
        )
        .optional()?;
    match tip {
        None => Ok(None),
        Some(None) => Err(anyhow!("the contact has no {column}")),
        Some(Some(tip)) => tip
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| anyhow!("the contact's {column} is {} bytes, expected 32", tip.len())),
    }
}

/// The contact's finalized relationship tip (`chain_tip`), or `None` when no
/// contact has that device id.
pub fn get_contact_chain_tip(device_id: &[u8]) -> Result<Option<[u8; 32]>> {
    read_contact_tip(device_id, "chain_tip")
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

/// This device's own tip for its relationship with `device_id`
/// (`local_bilateral_chain_tip`), or `None` when no contact has that device id.
pub fn get_local_bilateral_chain_tip(device_id: &[u8]) -> Result<Option<[u8; 32]>> {
    read_contact_tip(device_id, "local_bilateral_chain_tip")
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

/// Store `contact` in the client database as the contact add path would: its
/// keys and its relationship tip, which the tests that build an in-memory
/// manager hold only in memory.
#[cfg(test)]
pub(crate) fn store_contact_for_tests(contact: &dsm::types::contact_types::DsmVerifiedContact) {
    let tip = contact
        .chain_tip
        .unwrap_or_else(|| panic!("a test contact starts at a relationship tip"));
    store_contact(&ContactRecord {
        contact_id: crate::util::text_id::encode_base32_crockford(&contact.device_id),
        device_id: contact.device_id.to_vec(),
        alias: contact.alias.clone(),
        genesis_hash: contact.genesis_hash.to_vec(),
        public_key: contact.public_key.clone(),
        kyber_public_key: vec![0x4B; 1184],
        current_chain_tip: Some(tip.to_vec()),
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: contact.ble_address.clone(),
        status: "OnlineCapable".to_string(),
        needs_online_reconcile: false,
        previous_chain_tip: None,
    })
    .unwrap_or_else(|e| panic!("store the test contact: {e}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::collections::HashMap;

    fn init_test_db() {
        crate::economic_fixtures::use_test_storage_dir();
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
            kyber_public_key: vec![0x4B; 1184],
            current_chain_tip: Some(vec![0x70; 32]),
            verified: false,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        }
    }

    /// A contact is its directory entry's keys and its relationship tip: a
    /// record missing any of them is refused, and nothing is stored.
    #[test]
    #[serial]
    fn a_contact_without_its_keys_or_its_tip_is_refused() {
        init_test_db();
        let device_id = [0x5Du8; 32];
        let refused = |contact: ContactRecord, why: &str| {
            let err = store_contact(&contact).expect_err(why).to_string();
            assert!(err.contains(why), "refused for another reason: {err}");
            assert!(get_contact_by_device_id(&device_id).unwrap().is_none());
        };
        let mut c = make_contact(device_id, "keyless");
        c.public_key = Vec::new();
        refused(c, "no signing key");
        let mut c = make_contact(device_id, "no-kyber");
        c.kyber_public_key = Vec::new();
        refused(c, "no Kyber key");
        let mut c = make_contact(device_id, "no-tip");
        c.current_chain_tip = None;
        refused(c, "no 32-byte relationship tip");
        let mut c = make_contact(device_id, "short-tip");
        c.current_chain_tip = Some(vec![0x70; 31]);
        refused(c, "no 32-byte relationship tip");

        store_contact(&make_contact(device_id, "whole")).expect("a whole contact is stored");
        assert_eq!(get_contact_chain_tip(&device_id).unwrap(), Some([0x70; 32]));
        assert_eq!(
            get_local_bilateral_chain_tip(&device_id).unwrap(),
            Some([0x70; 32]),
            "a new contact's local tip starts at its relationship tip"
        );
    }

    /// A stored tip that is missing or not 32 bytes is a corrupt row: reading
    /// it is an error, never "no tip".
    #[test]
    #[serial]
    fn a_corrupt_stored_tip_is_an_error_not_an_absent_tip() {
        init_test_db();
        let device_id = [0x5Eu8; 32];
        store_contact(&make_contact(device_id, "corrupt")).expect("store");
        let corrupt = |sql: &str| {
            let binding = get_connection().expect("db");
            let conn = binding.lock().expect("lock");
            conn.execute(sql, params![device_id])
                .expect("corrupt the row");
        };
        corrupt("UPDATE contacts SET chain_tip = x'0102' WHERE device_id = ?1");
        assert!(get_contact_chain_tip(&device_id).is_err());
        corrupt("UPDATE contacts SET chain_tip = NULL WHERE device_id = ?1");
        assert!(get_contact_chain_tip(&device_id).is_err());
        corrupt("UPDATE contacts SET local_bilateral_chain_tip = x'0102' WHERE device_id = ?1");
        assert!(get_local_bilateral_chain_tip(&device_id).is_err());
        assert_eq!(
            get_contact_chain_tip(&[0x5Fu8; 32]).unwrap(),
            None,
            "no such contact"
        );
    }

    #[test]
    fn a_device_id_that_is_not_32_bytes_is_an_error_not_an_absent_contact() {
        assert!(has_contact_for_device_id(&[0u8; 16]).is_err());
        assert!(get_contact_by_device_id(&[0u8; 31]).is_err());
        assert!(get_contact_by_device_id(&[0u8; 33]).is_err());
        assert!(get_contact_chain_tip(&[0u8; 31]).is_err());
        assert!(get_local_bilateral_chain_tip(&[0u8; 33]).is_err());
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
        assert!(!is_ble_address_paired("").unwrap());
    }

    #[test]
    fn update_contact_ble_status_rejects_short_device_id() {
        let err = update_contact_ble_status(&[0u8; 16], None, None).unwrap_err();
        assert!(err.to_string().contains("Invalid device_id length"));
    }

    #[test]
    fn record_observed_remote_chain_tip_rejects_invalid_lengths() {
        let err = record_observed_remote_chain_tip(
            &[0u8; 16],
            &[0u8; 32],
            ObservedRemoteTipSource::Unknown,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid device_id length"));
        let err2 = record_observed_remote_chain_tip(
            &[0u8; 32],
            &[0u8; 16],
            ObservedRemoteTipSource::Unknown,
        )
        .unwrap_err();
        assert!(err2
            .to_string()
            .contains("Invalid observed_chain_tip length"));
    }

    #[test]
    fn get_contact_device_tree_root_refuses_a_malformed_device_id() {
        assert!(get_contact_device_tree_root(&[0u8; 10]).is_err());
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

    /// A BLE identity observation records transport facts only. It never
    /// lifts the online-reconcile hold a failed step set — not on a plain
    /// address write, and not on a reported tip equal to the stored one — and
    /// a contact that does not exist is not "updated". MUTATION CONTROL:
    /// clearing the hold on a matching observation turns this red.
    #[test]
    #[serial]
    fn a_ble_observation_never_lifts_the_reconcile_hold() {
        init_test_db();
        let device_id = [0x0Bu8; 32];
        let mut contact = make_contact(device_id, "held");
        contact.needs_online_reconcile = true;
        store_contact(&contact).expect("store contact");

        update_contact_ble_status(&device_id, None, Some("AA:BB:CC:DD:EE:02"))
            .expect("record the address");
        update_contact_ble_status(&device_id, Some(&[0x70u8; 32]), None)
            .expect("record a matching observation");

        let stored = get_contact_by_device_id(&device_id)
            .expect("read")
            .expect("the contact");
        assert!(
            stored.needs_online_reconcile,
            "a BLE observation lifted the reconcile hold"
        );
        assert_eq!(stored.ble_address.as_deref(), Some("AA:BB:CC:DD:EE:02"));
        assert_eq!(stored.status, "BleCapable");
        assert!(
            update_contact_ble_status(&[0x0Cu8; 32], None, Some("AA:BB:CC:DD:EE:03")).is_err(),
            "an observation of a device that is not a contact updated nothing and says so"
        );
    }

    /// Cold-peer RPA rotation: after a paired peer's BLE address rotates, the canonical re-persist
    /// (`update_contact_ble_status(device_id, None, Some(new))`, driven by the probe's on-match
    /// `observeGattIdentityRead`) must re-point the contact so the FRESH address resolves and the
    /// STALE one no longer does — the storage half of the directed-probe fix.
    #[test]
    #[serial]
    fn update_contact_ble_status_repoints_rotated_address() {
        init_test_db();
        let device_id = [0x0Au8; 32];
        store_contact(&make_contact(device_id, "rotator")).expect("store contact");

        let old_addr = "AA:BB:CC:DD:EE:01";
        let new_addr = "11:22:33:44:55:66";

        // Initial BLE address, then confirm it resolves.
        update_contact_ble_status(&device_id, None, Some(old_addr)).expect("set old addr");
        assert!(get_contact_by_ble_address(old_addr).unwrap().is_some());

        // RPA rotates: re-point to the fresh address.
        update_contact_ble_status(&device_id, None, Some(new_addr)).expect("repoint addr");

        let hit = get_contact_by_ble_address(new_addr).expect("query new addr");
        assert!(hit.is_some(), "fresh rotated address must resolve");
        assert_eq!(hit.unwrap().device_id, device_id.to_vec());
        assert!(
            get_contact_by_ble_address(old_addr).unwrap().is_none(),
            "stale rotated address must no longer resolve",
        );
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
