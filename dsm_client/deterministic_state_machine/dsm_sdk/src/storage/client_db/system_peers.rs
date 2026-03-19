// SPDX-License-Identifier: MIT OR Apache-2.0
//! System peer persistence (DLV, Faucet, and other protocol-controlled actors).

use anyhow::{anyhow, Result};
use log::info;
use rusqlite::params;

use super::get_connection;
use super::types::{SystemPeerRecord, SystemPeerType};
use crate::storage::codecs::{meta_from_blob, meta_to_blob};
use crate::util::deterministic_time::tick;

/// Store or update a system peer record.
/// System peers are protocol-controlled actors (DLV, Faucet) that do NOT have public keys
/// and CANNOT be used for bilateral verification.
pub fn store_system_peer(peer: &SystemPeerRecord) -> Result<()> {
    info!(
        "Storing system peer: {} (type: {:?}, device_id {} bytes)",
        peer.display_name,
        peer.peer_type,
        peer.device_id.len()
    );

    if peer.device_id.len() != 32 {
        return Err(anyhow!("SystemPeerRecord requires 32-byte device_id"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let now = tick();

    conn.execute(
        "INSERT INTO system_peers (
            peer_key, device_id, display_name, peer_type, chain_tip,
            created_at, updated_at, metadata
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(peer_key) DO UPDATE SET
            display_name = excluded.display_name,
            chain_tip = excluded.chain_tip,
            updated_at = excluded.updated_at,
            metadata = excluded.metadata",
        params![
            peer.peer_key,
            peer.device_id,
            peer.display_name,
            peer.peer_type.as_str(),
            peer.current_chain_tip.as_ref(),
            peer.created_at as i64,
            now as i64,
            meta_to_blob(&peer.metadata),
        ],
    )?;
    info!("System peer stored: {}", peer.peer_key);
    Ok(())
}

/// Get a system peer by peer_key (e.g., "dlv", "faucet").
pub fn get_system_peer(peer_key: &str) -> Result<Option<SystemPeerRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result = conn.query_row(
        "SELECT peer_key, device_id, display_name, peer_type, chain_tip,
                created_at, updated_at, metadata
           FROM system_peers WHERE peer_key = ?1",
        params![peer_key],
        |row| {
            let meta_blob: Vec<u8> = row.get(7)?;
            let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
            Ok(SystemPeerRecord {
                peer_key: row.get(0)?,
                device_id: row.get(1)?,
                display_name: row.get(2)?,
                peer_type: row
                    .get::<_, String>(3)?
                    .parse::<SystemPeerType>()
                    .unwrap_or(SystemPeerType::Protocol),
                current_chain_tip: row.get(4)?,
                created_at: row.get::<_, i64>(5)? as u64,
                updated_at: row.get::<_, i64>(6)? as u64,
                metadata,
            })
        },
    );

    match result {
        Ok(rec) => Ok(Some(rec)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(anyhow!("Failed to get system peer: {}", e)),
    }
}

/// Get a system peer by device_id (32 bytes).
pub fn get_system_peer_by_device_id(device_id: &[u8]) -> Result<Option<SystemPeerRecord>> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length: {}", device_id.len()));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let result = conn.query_row(
        "SELECT peer_key, device_id, display_name, peer_type, chain_tip,
                created_at, updated_at, metadata
           FROM system_peers WHERE device_id = ?1",
        params![device_id],
        |row| {
            let meta_blob: Vec<u8> = row.get(7)?;
            let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
            Ok(SystemPeerRecord {
                peer_key: row.get(0)?,
                device_id: row.get(1)?,
                display_name: row.get(2)?,
                peer_type: row
                    .get::<_, String>(3)?
                    .parse::<SystemPeerType>()
                    .unwrap_or(SystemPeerType::Protocol),
                current_chain_tip: row.get(4)?,
                created_at: row.get::<_, i64>(5)? as u64,
                updated_at: row.get::<_, i64>(6)? as u64,
                metadata,
            })
        },
    );

    match result {
        Ok(rec) => Ok(Some(rec)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(anyhow!("Failed to get system peer by device_id: {}", e)),
    }
}

/// Update chain tip for a system peer.
pub fn update_system_peer_chain_tip(peer_key: &str, new_chain_tip: &[u8]) -> Result<()> {
    if new_chain_tip.len() != 32 {
        return Err(anyhow!("Invalid chain_tip length: {}", new_chain_tip.len()));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let now = tick();

    let rows = conn.execute(
        "UPDATE system_peers SET chain_tip = ?1, updated_at = ?2 WHERE peer_key = ?3",
        params![new_chain_tip, now as i64, peer_key],
    )?;

    if rows == 0 {
        return Err(anyhow!("System peer not found: {}", peer_key));
    }

    info!(
        "Updated system peer chain tip: {} -> {:?}",
        peer_key,
        &new_chain_tip[..8]
    );
    Ok(())
}

/// Get all system peers.
pub fn get_all_system_peers() -> Result<Vec<SystemPeerRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let mut stmt = conn.prepare(
        "SELECT peer_key, device_id, display_name, peer_type, chain_tip,
                created_at, updated_at, metadata
           FROM system_peers ORDER BY created_at ASC",
    )?;

    let iter = stmt.query_map([], |row| {
        let meta_blob: Vec<u8> = row.get(7)?;
        let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
        Ok(SystemPeerRecord {
            peer_key: row.get(0)?,
            device_id: row.get(1)?,
            display_name: row.get(2)?,
            peer_type: row
                .get::<_, String>(3)?
                .parse::<SystemPeerType>()
                .unwrap_or(SystemPeerType::Protocol),
            current_chain_tip: row.get(4)?,
            created_at: row.get::<_, i64>(5)? as u64,
            updated_at: row.get::<_, i64>(6)? as u64,
            metadata,
        })
    })?;

    let mut peers = Vec::new();
    for p in iter {
        peers.push(p?);
    }
    Ok(peers)
}
