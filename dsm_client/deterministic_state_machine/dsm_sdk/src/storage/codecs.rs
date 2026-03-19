//! # Storage Codecs
//!
//! Binary-first encoding and decoding helpers for persisting DSM types
//! (operations, genesis records, contacts) to SQLite. No JSON, no Base64;
//! uses BLAKE3-tagged length-prefixed binary format.

// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::operations::Operation;
use crate::storage::client_db::GenesisRecord;

pub fn hash_blake3_bytes(data: &[u8]) -> [u8; 32] {
    *dsm::crypto::blake3::domain_hash("DSM/codec-hash", data).as_bytes()
}

pub fn smt_proof_bytes(root: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/smt-proof");
    hasher.update(root);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

pub fn generate_hash_chain_proof_bytes(data: &[u8]) -> [u8; 32] {
    hash_blake3_bytes(data)
}

/// Serialize Operation to bytes using a deterministic binary format
pub fn serialize_operation(op: &Operation) -> Vec<u8> {
    // Simple deterministic encoding: tag byte + payload
    let mut bytes = Vec::new();

    match op {
        Operation::Genesis => {
            bytes.push(0u8);
        }
        Operation::Transfer {
            to_device_id,
            amount,
            token_id,
            mode,
            nonce,
            verification,
            pre_commit,
            recipient,
            to,
            message,
            signature: _,
        } => {
            bytes.push(1u8); // Transfer tag

            // Encode each field with length prefix
            let to_device_bytes = to_device_id.as_slice();
            bytes.extend_from_slice(&(to_device_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(to_device_bytes);

            bytes.extend_from_slice(&amount.value().to_le_bytes());

            let token_bytes = token_id.as_slice();
            bytes.extend_from_slice(&(token_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(token_bytes);

            let mode_byte = match mode {
                dsm::types::operations::TransactionMode::Unilateral => 0u8,
                dsm::types::operations::TransactionMode::Bilateral => 1u8,
            };
            bytes.push(mode_byte);

            bytes.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
            bytes.extend_from_slice(nonce);

            let verification_byte = match verification {
                dsm::types::operations::VerificationType::Standard => 0u8,
                dsm::types::operations::VerificationType::Enhanced => 1u8,
                dsm::types::operations::VerificationType::Bilateral => 2u8,
                dsm::types::operations::VerificationType::Directory => 3u8,
                dsm::types::operations::VerificationType::StandardBilateral => 4u8,
                dsm::types::operations::VerificationType::PreCommitted => 5u8,
                dsm::types::operations::VerificationType::UnilateralIdentityAnchor => 6u8,
                dsm::types::operations::VerificationType::Custom(_) => 255u8,
            };
            bytes.push(verification_byte);

            // Serialize pre_commit if present
            bytes.push(if pre_commit.is_some() { 1 } else { 0 });

            let recipient_bytes = recipient.as_slice();
            bytes.extend_from_slice(&(recipient_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(recipient_bytes);

            let to_bytes = to.as_slice();
            bytes.extend_from_slice(&(to_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(to_bytes);

            let msg_bytes = message.as_bytes();
            bytes.extend_from_slice(&(msg_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(msg_bytes);
        }
        _ => {
            // For other operations, use a simplified encoding
            // In production, implement full serialization for all variants
            bytes.push(255u8); // Unknown tag
        }
    }

    bytes
}

/// Deserialize Operation from bytes
pub fn deserialize_operation(bytes: &[u8]) -> Result<Operation> {
    if bytes.is_empty() {
        return Err(anyhow!("Empty operation bytes"));
    }

    let tag = bytes[0];
    let mut cursor = &bytes[1..];

    fn read_u32(cursor: &mut &[u8]) -> Result<u32> {
        if cursor.len() < 4 {
            return Err(anyhow!("Insufficient bytes for u32"));
        }
        let val = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        *cursor = &cursor[4..];
        Ok(val)
    }

    fn read_u64(cursor: &mut &[u8]) -> Result<u64> {
        if cursor.len() < 8 {
            return Err(anyhow!("Insufficient bytes for u64"));
        }
        let val = u64::from_le_bytes([
            cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6], cursor[7],
        ]);
        *cursor = &cursor[8..];
        Ok(val)
    }

    fn read_bytes(cursor: &mut &[u8]) -> Result<Vec<u8>> {
        let len = read_u32(cursor)? as usize;
        const MAX_FIELD_SIZE: usize = 10 * 1024 * 1024; // 10MB
        if len > MAX_FIELD_SIZE {
            return Err(anyhow!("Field size {} exceeds maximum", len));
        }
        if cursor.len() < len {
            return Err(anyhow!("Insufficient bytes for data"));
        }
        let data = cursor[..len].to_vec();
        *cursor = &cursor[len..];
        Ok(data)
    }

    fn read_string(cursor: &mut &[u8]) -> Result<String> {
        let bytes = read_bytes(cursor)?;
        String::from_utf8(bytes).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }

    match tag {
        0 => Ok(Operation::Genesis),
        1 => {
            // Transfer
            let to_device_id = read_bytes(&mut cursor)?;
            let amount = read_u64(&mut cursor)?;
            let token_id = read_bytes(&mut cursor)?;

            if cursor.is_empty() {
                return Err(anyhow!("Incomplete Transfer data"));
            }
            let mode_byte = cursor[0];
            cursor = &cursor[1..];
            let mode = match mode_byte {
                0 => dsm::types::operations::TransactionMode::Unilateral,
                1 => dsm::types::operations::TransactionMode::Bilateral,
                _ => dsm::types::operations::TransactionMode::Unilateral,
            };

            let nonce = read_bytes(&mut cursor)?;

            if cursor.is_empty() {
                return Err(anyhow!("Incomplete Transfer verification"));
            }
            let verification_byte = cursor[0];
            cursor = &cursor[1..];
            let verification = match verification_byte {
                0 => dsm::types::operations::VerificationType::Standard,
                1 => dsm::types::operations::VerificationType::Enhanced,
                2 => dsm::types::operations::VerificationType::Bilateral,
                3 => dsm::types::operations::VerificationType::Directory,
                4 => dsm::types::operations::VerificationType::StandardBilateral,
                5 => dsm::types::operations::VerificationType::PreCommitted,
                6 => dsm::types::operations::VerificationType::UnilateralIdentityAnchor,
                _ => dsm::types::operations::VerificationType::Standard,
            };

            if cursor.is_empty() {
                return Err(anyhow!("Incomplete Transfer pre_commit flag"));
            }
            let has_precommit = cursor[0];
            cursor = &cursor[1..];
            let pre_commit = if has_precommit == 1 {
                Some(Default::default())
            } else {
                None
            };

            let recipient = read_bytes(&mut cursor)?;
            let to = read_bytes(&mut cursor)?;
            let message = read_string(&mut cursor)?;

            // Create Balance from raw u64 amount (empty state hash for deserialized sessions)
            let balance = dsm::types::token_types::Balance::from_state(amount, [0u8; 32], 0);

            Ok(Operation::Transfer {
                to_device_id,
                amount: balance,
                token_id,
                mode,
                nonce,
                verification,
                pre_commit,
                recipient,
                to,
                message,
                signature: Vec::new(),
            })
        }
        255 => Ok(Operation::Noop),
        _ => Err(anyhow!("Unknown operation tag: {}", tag)),
    }
}

pub fn meta_to_blob(map: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    let mut keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    for k in keys {
        let key_bytes = k.as_bytes();
        let val = &map[k];
        out.extend_from_slice(&(key_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(key_bytes);
        out.extend_from_slice(&(val.len() as u32).to_le_bytes());
        out.extend_from_slice(val);
    }
    out
}

pub fn meta_from_blob(mut bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    use std::io::{Error, ErrorKind};
    fn take<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], std::io::Error> {
        if r.len() < N {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "take",
            ));
        }
        let mut out = [0u8; N];
        // out.copy_from_slice(&r[..N]);
        // Correct way is:
        out.copy_from_slice(&r[..N]);
        *r = &r[N..];
        Ok(out)
    }
    fn read_len_u16(r: &mut &[u8]) -> Result<usize, std::io::Error> {
        Ok(u16::from_le_bytes(take::<2>(r)?) as usize)
    }
    fn read_len_u32(r: &mut &[u8]) -> Result<usize, std::io::Error> {
        Ok(u32::from_le_bytes(take::<4>(r)?) as usize)
    }
    fn read_vec(r: &mut &[u8], len: usize) -> Result<Vec<u8>, std::io::Error> {
        if r.len() < len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "vec",
            ));
        }
        let v = r[..len].to_vec();
        *r = &r[len..];
        Ok(v)
    }

    let count = read_len_u32(&mut bytes)?;
    // Bounds check: prevent unbounded allocation on corrupted data
    const MAX_META_ENTRIES: usize = 10_000;
    if count > MAX_META_ENTRIES {
        return Err(anyhow!(
            "meta_from_blob: entry count {} exceeds maximum {}",
            count,
            MAX_META_ENTRIES
        ));
    }
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let key_len = read_len_u16(&mut bytes)?;
        let key = read_vec(&mut bytes, key_len)?;
        let val_len = read_len_u32(&mut bytes)?;
        let val = read_vec(&mut bytes, val_len)?;
        let key_str = std::str::from_utf8(&key)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "key utf8"))?
            .to_string();
        map.insert(key_str, val);
    }
    Ok(map)
}

pub fn encode_genesis_record_bytes(r: &GenesisRecord) -> Vec<u8> {
    fn put_str(s: &str, out: &mut Vec<u8>) {
        let b = s.as_bytes();
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    let mut out = Vec::new();
    put_str(&r.genesis_id, &mut out);
    put_str(&r.device_id, &mut out);
    put_str(&r.mpc_proof, &mut out);
    put_str(&r.dbrw_binding, &mut out);
    put_str(&r.merkle_root, &mut out);
    out.extend_from_slice(&r.participant_count.to_le_bytes());
    put_str(&r.progress_marker, &mut out);
    put_str(&r.publication_hash, &mut out);
    put_str(&r.storage_nodes.join(","), &mut out);
    put_str(&r.entropy_hash, &mut out);
    put_str(&r.protocol_version, &mut out);
    out
}

pub fn take<const N: usize>(r: &mut &[u8]) -> std::io::Result<[u8; N]> {
    use std::io::ErrorKind;
    if r.len() < N {
        return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "take"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&r[..N]);
    *r = &r[N..];
    Ok(out)
}
pub fn read_len_u32(r: &mut &[u8]) -> std::io::Result<usize> {
    Ok(u32::from_le_bytes(take::<4>(r)?) as usize)
}
pub fn read_u8(r: &mut &[u8]) -> std::io::Result<u8> {
    Ok(take::<1>(r)?[0])
}
pub fn read_u64(r: &mut &[u8]) -> std::io::Result<u64> {
    Ok(u64::from_le_bytes(take::<8>(r)?))
}
pub fn read_vec(r: &mut &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::ErrorKind;
    let len = read_len_u32(r)?;
    if r.len() < len {
        return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "vec"));
    }
    let v = r[..len].to_vec();
    *r = &r[len..];
    Ok(v)
}
pub fn read_string(r: &mut &[u8]) -> std::io::Result<String> {
    use std::str;
    let v = read_vec(r)?;
    Ok(str::from_utf8(&v).unwrap_or("").to_string())
}
