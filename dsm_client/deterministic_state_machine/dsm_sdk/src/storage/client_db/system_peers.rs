// SPDX-License-Identifier: MIT OR Apache-2.0
//! System peer persistence (DLV, Faucet, and other protocol-controlled actors).

use anyhow::{anyhow, Result};
use log::info;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use super::types::{SystemPeerEvent, SystemPeerRecord, SystemPeerType};
use crate::storage::codecs::{meta_from_blob, meta_to_blob};
use crate::util::deterministic_time::tick;

/// Store a system peer record if it does not already exist.
///
/// This is intentionally insert-only for identity-bearing fields. Existing
/// protocol peers must advance only through `advance_system_chain_tip(...)`.
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

    if peer.peer_key.trim().is_empty() {
        return Err(anyhow!("SystemPeerRecord requires non-empty peer_key"));
    }
    if peer.current_chain_tip.is_some() {
        return Err(anyhow!(
            "SystemPeerRecord creation must not seed current_chain_tip; advance through advance_system_chain_tip"
        ));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let existing: Option<(Vec<u8>, String)> = conn
        .query_row(
            "SELECT device_id, peer_type FROM system_peers WHERE peer_key = ?1",
            params![peer.peer_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((device_id, peer_type)) = existing {
        let stored_peer_type = peer_type
            .parse::<SystemPeerType>()
            .unwrap_or(SystemPeerType::Protocol);
        return Err(anyhow!(
            "System peer {} already exists (device_id_match={}, stored_type={})",
            peer.peer_key,
            device_id == peer.device_id,
            stored_peer_type.as_str()
        ));
    }

    let now = tick();
    conn.execute(
        "INSERT INTO system_peers (
            peer_key, device_id, display_name, peer_type, chain_tip,
            created_at, updated_at, metadata
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
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
/// The caller must supply the exact expected parent tip; this path never infers
/// authority to advance from storage alone.
pub fn advance_system_chain_tip(
    peer_key: &str,
    peer_type: SystemPeerType,
    expected_parent_tip: &[u8],
    payload_bytes: &[u8],
    source_state_hash: &[u8],
    source_state_number: u64,
) -> Result<SystemPeerEvent> {
    if peer_key.trim().is_empty() {
        return Err(anyhow!(
            "System peer transition requires non-empty peer_key"
        ));
    }
    if payload_bytes.is_empty() {
        return Err(anyhow!("System peer transition payload must be non-empty"));
    }
    if expected_parent_tip.len() != 32 {
        return Err(anyhow!(
            "System peer expected_parent_tip must be 32 bytes (got {})",
            expected_parent_tip.len()
        ));
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

    let last_state_number: Option<u64> = tx
        .query_row(
            "SELECT source_state_number
               FROM system_peer_events
              WHERE peer_key = ?1
              ORDER BY created_at DESC, rowid DESC
              LIMIT 1",
            params![peer_key],
            |row| Ok(row.get::<_, i64>(0)? as u64),
        )
        .optional()?;
    if let Some(last_state_number) = last_state_number {
        if source_state_number <= last_state_number {
            return Err(anyhow!(
                "System peer {} must advance monotonically: {} <= {}",
                peer_key,
                source_state_number,
                last_state_number
            ));
        }
    }

    let last_child_tip: Option<Vec<u8>> = tx
        .query_row(
            "SELECT child_tip
               FROM system_peer_events
              WHERE peer_key = ?1
              ORDER BY created_at DESC, rowid DESC
              LIMIT 1",
            params![peer_key],
            |row| row.get(0),
        )
        .optional()?;

    let had_current_tip = current_tip.is_some();
    let parent_tip = match current_tip {
        Some(parent_tip) if parent_tip.len() == 32 => parent_tip,
        Some(parent_tip) => {
            return Err(anyhow!(
                "System peer {} has invalid stored chain_tip length {}",
                peer_key,
                parent_tip.len()
            ));
        }
        None => vec![0u8; 32],
    };
    if parent_tip != expected_parent_tip {
        return Err(anyhow!(
            "System peer {} expected parent tip does not match stored chain tip",
            peer_key
        ));
    }
    if let Some(last_child_tip) = last_child_tip {
        if last_child_tip != parent_tip {
            return Err(anyhow!(
                "System peer {} current tip does not match append-only event head",
                peer_key
            ));
        }
    } else if expected_parent_tip.iter().any(|byte| *byte != 0) {
        return Err(anyhow!(
            "System peer {} expected parent tip is non-zero but event history is empty",
            peer_key
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_peer(peer_key: &str, peer_type: SystemPeerType) -> SystemPeerRecord {
        SystemPeerRecord {
            peer_key: peer_key.to_string(),
            device_id: vec![0xABu8; 32],
            display_name: format!("Test {}", peer_key),
            peer_type,
            current_chain_tip: None,
            created_at: 0,
            updated_at: 0,
            metadata: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn store_system_peer_rejects_wrong_device_id_length() {
        let mut peer = make_peer("dlv", SystemPeerType::Dlv);
        peer.device_id = vec![0u8; 16];
        let err = store_system_peer(&peer).unwrap_err();
        assert!(err.to_string().contains("32-byte device_id"));
    }

    #[test]
    fn store_system_peer_rejects_empty_peer_key() {
        let mut peer = make_peer("dlv", SystemPeerType::Dlv);
        peer.peer_key = "  ".to_string();
        let err = store_system_peer(&peer).unwrap_err();
        assert!(err.to_string().contains("non-empty peer_key"));
    }

    #[test]
    fn store_system_peer_rejects_seeded_chain_tip() {
        let mut peer = make_peer("dlv", SystemPeerType::Dlv);
        peer.current_chain_tip = Some(vec![1u8; 32]);
        let err = store_system_peer(&peer).unwrap_err();
        assert!(err.to_string().contains("must not seed current_chain_tip"));
    }

    #[test]
    fn advance_system_chain_tip_rejects_empty_peer_key() {
        let err = advance_system_chain_tip(
            "  ",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"payload",
            &[0u8; 32],
            1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-empty peer_key"));
    }

    #[test]
    fn advance_system_chain_tip_rejects_empty_payload() {
        let err =
            advance_system_chain_tip("dlv", SystemPeerType::Dlv, &[0u8; 32], b"", &[0u8; 32], 1)
                .unwrap_err();
        assert!(err.to_string().contains("payload must be non-empty"));
    }

    #[test]
    fn advance_system_chain_tip_rejects_short_parent_tip() {
        let err = advance_system_chain_tip(
            "dlv",
            SystemPeerType::Dlv,
            &[0u8; 16],
            b"payload",
            &[0u8; 32],
            1,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("expected_parent_tip must be 32 bytes"));
    }

    #[test]
    fn advance_system_chain_tip_rejects_short_source_state_hash() {
        let err = advance_system_chain_tip(
            "dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"payload",
            &[0u8; 10],
            1,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("source_state_hash must be 32 bytes"));
    }

    #[test]
    fn get_system_peer_by_device_id_rejects_wrong_length() {
        let err = get_system_peer_by_device_id(&[0u8; 16]).unwrap_err();
        assert!(err.to_string().contains("Invalid device_id length"));
    }

    #[test]
    #[serial]
    fn store_and_get_system_peer_roundtrip() {
        init_test_db();
        let peer = make_peer("dlv", SystemPeerType::Dlv);
        store_system_peer(&peer).expect("store");

        let loaded = get_system_peer("dlv").expect("get").expect("should exist");
        assert_eq!(loaded.peer_key, "dlv");
        assert_eq!(loaded.display_name, "Test dlv");
        assert_eq!(loaded.peer_type, SystemPeerType::Dlv);
        assert_eq!(loaded.device_id, vec![0xABu8; 32]);
        assert!(loaded.current_chain_tip.is_none());
    }

    #[test]
    #[serial]
    fn store_system_peer_rejects_duplicate() {
        init_test_db();
        let peer = make_peer("faucet", SystemPeerType::Faucet);
        store_system_peer(&peer).expect("first store");
        let err = store_system_peer(&peer).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    #[serial]
    fn get_all_system_peers_returns_stored() {
        init_test_db();
        let p1 = make_peer("dlv", SystemPeerType::Dlv);
        let mut p2 = make_peer("faucet", SystemPeerType::Faucet);
        p2.device_id = vec![0xCDu8; 32];
        store_system_peer(&p1).unwrap();
        store_system_peer(&p2).unwrap();

        let all = get_all_system_peers().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    #[serial]
    fn get_system_peer_by_device_id_roundtrip() {
        init_test_db();
        let peer = make_peer("dlv", SystemPeerType::Dlv);
        store_system_peer(&peer).unwrap();

        let loaded = get_system_peer_by_device_id(&[0xABu8; 32])
            .unwrap()
            .expect("should find peer");
        assert_eq!(loaded.peer_key, "dlv");
    }

    #[test]
    #[serial]
    fn get_system_peer_not_found() {
        init_test_db();
        assert!(get_system_peer("nonexistent").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn advance_system_chain_tip_roundtrip() {
        init_test_db();
        let peer = make_peer("dlv", SystemPeerType::Dlv);
        store_system_peer(&peer).unwrap();

        let event = advance_system_chain_tip(
            "dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"payload-1",
            &[0xAA; 32],
            1,
        )
        .unwrap();

        assert_eq!(event.peer_key, "dlv");
        assert_eq!(event.peer_type, SystemPeerType::Dlv);
        assert_eq!(event.parent_tip, vec![0u8; 32]);
        assert_eq!(event.source_state_number, 1);
        assert_eq!(event.child_tip.len(), 32);
        assert_ne!(event.child_tip, vec![0u8; 32]);

        let loaded = get_system_peer("dlv").unwrap().unwrap();
        assert_eq!(loaded.current_chain_tip.as_ref().unwrap(), &event.child_tip);
    }

    #[test]
    #[serial]
    fn advance_system_chain_tip_two_steps() {
        init_test_db();
        let peer = make_peer("faucet", SystemPeerType::Faucet);
        store_system_peer(&peer).unwrap();

        let e1 = advance_system_chain_tip(
            "faucet",
            SystemPeerType::Faucet,
            &[0u8; 32],
            b"step-1",
            &[0xBB; 32],
            1,
        )
        .unwrap();

        let e2 = advance_system_chain_tip(
            "faucet",
            SystemPeerType::Faucet,
            &e1.child_tip.clone().try_into().unwrap_or([0u8; 32]),
            b"step-2",
            &[0xCC; 32],
            2,
        )
        .unwrap();

        assert_eq!(e2.parent_tip, e1.child_tip);
        assert_ne!(e2.child_tip, e1.child_tip);
    }

    #[test]
    #[serial]
    fn get_system_peer_events_returns_ordered() {
        init_test_db();
        let peer = make_peer("dlv", SystemPeerType::Dlv);
        store_system_peer(&peer).unwrap();

        let e1 = advance_system_chain_tip(
            "dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"ev-1",
            &[0x11; 32],
            1,
        )
        .unwrap();

        let parent: [u8; 32] = e1.child_tip.clone().try_into().unwrap();
        advance_system_chain_tip("dlv", SystemPeerType::Dlv, &parent, b"ev-2", &[0x22; 32], 2)
            .unwrap();

        let events = get_system_peer_events("dlv").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].source_state_number, 1);
        assert_eq!(events[1].source_state_number, 2);
        assert_eq!(events[1].parent_tip, events[0].child_tip);
    }

    #[test]
    #[serial]
    fn advance_rejects_non_monotonic_state_number() {
        init_test_db();
        let peer = make_peer("dlv", SystemPeerType::Dlv);
        store_system_peer(&peer).unwrap();

        let e1 = advance_system_chain_tip(
            "dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"first",
            &[0xAA; 32],
            5,
        )
        .unwrap();

        let parent: [u8; 32] = e1.child_tip.try_into().unwrap();
        let err = advance_system_chain_tip(
            "dlv",
            SystemPeerType::Dlv,
            &parent,
            b"second",
            &[0xBB; 32],
            3,
        )
        .unwrap_err();
        assert!(err.to_string().contains("monotonically"));
    }

    #[test]
    #[serial]
    fn advance_rejects_type_mismatch() {
        init_test_db();
        let peer = make_peer("dlv", SystemPeerType::Dlv);
        store_system_peer(&peer).unwrap();

        let err = advance_system_chain_tip(
            "dlv",
            SystemPeerType::Faucet,
            &[0u8; 32],
            b"payload",
            &[0xAA; 32],
            1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("type mismatch"));
    }

    #[test]
    #[serial]
    fn get_system_peer_events_empty_for_unknown() {
        init_test_db();
        let events = get_system_peer_events("nonexistent").unwrap();
        assert!(events.is_empty());
    }

    #[test]
    #[serial]
    fn store_system_peer_with_metadata() {
        init_test_db();
        let mut peer = make_peer("meta-peer", SystemPeerType::Protocol);
        peer.metadata.insert("key1".to_string(), b"value1".to_vec());
        peer.metadata.insert("key2".to_string(), b"value2".to_vec());
        store_system_peer(&peer).unwrap();

        let loaded = get_system_peer("meta-peer").unwrap().unwrap();
        assert_eq!(
            loaded.metadata.get("key1").map(|v| v.as_slice()),
            Some(b"value1".as_ref())
        );
        assert_eq!(
            loaded.metadata.get("key2").map(|v| v.as_slice()),
            Some(b"value2".as_ref())
        );
    }
}
