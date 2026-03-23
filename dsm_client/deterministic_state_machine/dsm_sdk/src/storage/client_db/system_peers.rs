// SPDX-License-Identifier: MIT OR Apache-2.0
//! System peer persistence (DLV, Faucet, and other protocol-controlled actors).

use anyhow::{anyhow, Result};
use log::info;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use super::types::{SystemPeerEvent, SystemPeerRecord, SystemPeerType};
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
            device_id = excluded.device_id,
            display_name = excluded.display_name,
            peer_type = excluded.peer_type,
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

fn parse_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SystemPeerEvent> {
    Ok(SystemPeerEvent {
        peer_key: row.get(0)?,
        peer_type: row
            .get::<_, String>(1)?
            .parse::<SystemPeerType>()
            .unwrap_or(SystemPeerType::Protocol),
        parent_tip: row.get(2)?,
        child_tip: row.get(3)?,
        transition_digest: row.get(4)?,
        source_state_hash: row.get(5)?,
        source_state_number: row.get::<_, i64>(6)? as u64,
        payload_bytes: row.get(7)?,
        created_at: row.get::<_, i64>(8)? as u64,
    })
}

/// Advance a sovereign protocol peer tip without touching bilateral contact state.
///
/// The resulting child tip is namespaced away from canonical entity state:
/// `H("DSM/system-peer-tip" || peer_key || parent_tip || transition_digest)`.
pub fn advance_system_peer_tip(
    peer_key: &str,
    peer_type: SystemPeerType,
    payload_bytes: &[u8],
    source_state_hash: &[u8],
    source_state_number: u64,
) -> Result<SystemPeerEvent> {
    if payload_bytes.is_empty() {
        return Err(anyhow!("System peer transition payload must be non-empty"));
    }
    if source_state_hash.len() != 32 {
        return Err(anyhow!(
            "System peer source_state_hash must be 32 bytes (got {})",
            source_state_hash.len()
        ));
    }

    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let tx = conn.transaction()?;

    let row: Option<(String, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT peer_type, chain_tip FROM system_peers WHERE peer_key = ?1",
            params![peer_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (stored_peer_type, current_tip) =
        row.ok_or_else(|| anyhow!("System peer not found: {}", peer_key))?;
    let stored_peer_type = stored_peer_type
        .parse::<SystemPeerType>()
        .unwrap_or(SystemPeerType::Protocol);
    if stored_peer_type != peer_type {
        return Err(anyhow!(
            "System peer type mismatch for {}: stored={} requested={}",
            peer_key,
            stored_peer_type.as_str(),
            peer_type.as_str()
        ));
    }

    let had_current_tip = current_tip.is_some();
    let parent_tip = current_tip.unwrap_or_else(|| vec![0u8; 32]);
    let transition_digest = {
        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/system-peer-transition");
        hasher.update(peer_key.as_bytes());
        hasher.update(&(payload_bytes.len() as u32).to_le_bytes());
        hasher.update(payload_bytes);
        hasher.finalize().as_bytes().to_vec()
    };
    let child_tip = {
        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/system-peer-tip");
        hasher.update(peer_key.as_bytes());
        hasher.update(&parent_tip);
        hasher.update(&transition_digest);
        hasher.finalize().as_bytes().to_vec()
    };
    let now = tick();

    tx.execute(
        "INSERT INTO system_peer_events (
            peer_key, peer_type, parent_tip, child_tip, transition_digest,
            source_state_hash, source_state_number, payload_bytes, created_at
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            peer_key,
            peer_type.as_str(),
            &parent_tip,
            &child_tip,
            &transition_digest,
            source_state_hash,
            source_state_number as i64,
            payload_bytes,
            now as i64,
        ],
    )?;

    let updated_rows = if had_current_tip {
        tx.execute(
            "UPDATE system_peers
                SET chain_tip = ?1, updated_at = ?2
              WHERE peer_key = ?3 AND chain_tip = ?4",
            params![&child_tip, now as i64, peer_key, &parent_tip],
        )?
    } else {
        tx.execute(
            "UPDATE system_peers
                SET chain_tip = ?1, updated_at = ?2
              WHERE peer_key = ?3 AND chain_tip IS NULL",
            params![&child_tip, now as i64, peer_key],
        )?
    };

    if updated_rows != 1 {
        return Err(anyhow!(
            "Concurrent system peer tip update rejected for {}",
            peer_key
        ));
    }

    tx.commit()?;

    Ok(SystemPeerEvent {
        peer_key: peer_key.to_string(),
        peer_type,
        parent_tip,
        child_tip,
        transition_digest,
        source_state_hash: source_state_hash.to_vec(),
        source_state_number,
        payload_bytes: payload_bytes.to_vec(),
        created_at: now,
    })
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

/// Load the sovereign event history for a single system peer.
pub fn get_system_peer_events(peer_key: &str) -> Result<Vec<SystemPeerEvent>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let mut stmt = conn.prepare(
        "SELECT peer_key, peer_type, parent_tip, child_tip, transition_digest,
                source_state_hash, source_state_number, payload_bytes, created_at
           FROM system_peer_events
          WHERE peer_key = ?1
          ORDER BY created_at ASC, rowid ASC",
    )?;

    let iter = stmt.query_map(params![peer_key], parse_event_row)?;
    let mut events = Vec::new();
    for event in iter {
        events.push(event?);
    }
    Ok(events)
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
