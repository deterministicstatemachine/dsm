// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Storage Codecs
//!
//! Binary-first encoding and decoding helpers for persisting DSM types
//! (operations, genesis records, contacts) to SQLite. No JSON, no Base64;
//! uses BLAKE3-tagged length-prefixed binary format.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::operations::Operation;
use crate::storage::client_db::GenesisRecord;

pub fn hash_blake3_bytes(data: &[u8]) -> [u8; 32] {
    *dsm::crypto::blake3::domain_hash(dsm::common::domain_tags::TAG_DSM_CODEC_HASH, data).as_bytes()
}

pub fn smt_proof_bytes(root: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_SMT_PROOF);
    hasher.update(root);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

pub fn generate_hash_chain_proof_bytes(data: &[u8]) -> [u8; 32] {
    hash_blake3_bytes(data)
}

/// An operation as it is persisted: its canonical encoding, the bytes it is
/// signed and hashed over. One encoding, every variant.
pub fn serialize_operation(op: &Operation) -> Vec<u8> {
    op.to_bytes()
}

/// A persisted operation, decoded by the canonical decoder.
pub fn deserialize_operation(bytes: &[u8]) -> Result<Operation> {
    Operation::from_bytes(bytes).map_err(|e| anyhow!("stored operation does not decode: {e}"))
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
    put_str(&r.device_birth_binding, &mut out);
    put_str(&r.merkle_root, &mut out);
    put_str(&r.progress_marker, &mut out);
    put_str(&r.publication_hash, &mut out);
    put_str(&r.entropy_hash, &mut out);
    put_str(&r.protocol_version, &mut out);
    put_str(&r.genesis_nonce, &mut out);
    put_str(&r.genesis_profile, &mut out);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn hash_blake3_bytes_deterministic_and_nonzero() {
        let h1 = hash_blake3_bytes(b"hello");
        let h2 = hash_blake3_bytes(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn hash_blake3_bytes_different_inputs() {
        let h1 = hash_blake3_bytes(b"alpha");
        let h2 = hash_blake3_bytes(b"beta");
        assert_ne!(h1, h2);
    }

    #[test]
    fn smt_proof_bytes_varies_with_root() {
        let data = b"some-encoded-data";
        let p1 = smt_proof_bytes(b"root-a", data);
        let p2 = smt_proof_bytes(b"root-b", data);
        assert_ne!(p1, p2);
    }

    #[test]
    fn smt_proof_bytes_varies_with_data() {
        let root = b"merkle-root";
        let p1 = smt_proof_bytes(root, b"data-1");
        let p2 = smt_proof_bytes(root, b"data-2");
        assert_ne!(p1, p2);
    }

    #[test]
    fn generate_hash_chain_proof_equals_hash() {
        let data = b"chain-data";
        assert_eq!(
            generate_hash_chain_proof_bytes(data),
            hash_blake3_bytes(data)
        );
    }

    #[test]
    fn meta_round_trip_empty() {
        let m: HashMap<String, Vec<u8>> = HashMap::new();
        let blob = meta_to_blob(&m);
        let back = meta_from_blob(&blob).expect("deserialize empty");
        assert!(back.is_empty());
    }

    #[test]
    fn meta_round_trip_single_entry() {
        let mut m = HashMap::new();
        m.insert("key1".to_string(), b"value1".to_vec());
        let blob = meta_to_blob(&m);
        let back = meta_from_blob(&blob).expect("deserialize");
        assert_eq!(back.get("key1").unwrap(), b"value1");
    }

    #[test]
    fn meta_round_trip_multiple_entries_preserves_all() {
        let mut m = HashMap::new();
        m.insert("alpha".to_string(), vec![1, 2, 3]);
        m.insert("beta".to_string(), vec![4, 5]);
        m.insert("gamma".to_string(), vec![]);
        let blob = meta_to_blob(&m);
        let back = meta_from_blob(&blob).expect("deserialize");
        assert_eq!(back.len(), 3);
        assert_eq!(back.get("alpha").unwrap(), &vec![1, 2, 3]);
        assert_eq!(back.get("beta").unwrap(), &vec![4, 5]);
        assert_eq!(back.get("gamma").unwrap(), &Vec::<u8>::new());
    }

    #[test]
    fn meta_from_blob_rejects_truncated_data() {
        assert!(meta_from_blob(&[]).is_err());
        assert!(meta_from_blob(&[0x01, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn meta_from_blob_rejects_excessive_count() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(20_000u32).to_le_bytes());
        assert!(meta_from_blob(&blob).is_err());
    }

    #[test]
    fn serialize_deserialize_genesis_op() {
        let op = Operation::Genesis;
        let bytes = serialize_operation(&op);
        let back = deserialize_operation(&bytes).expect("deserialize genesis");
        assert!(matches!(back, Operation::Genesis));
    }

    #[test]
    fn deserialize_rejects_empty_bytes() {
        assert!(deserialize_operation(&[]).is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_tag() {
        assert!(deserialize_operation(&[200u8]).is_err());
    }

    /// Every variant round-trips: a stored operation is never read back as a
    /// different one.
    #[test]
    fn a_stored_operation_is_read_back_as_itself() {
        for op in [Operation::Noop, Operation::Genesis] {
            let back = deserialize_operation(&serialize_operation(&op)).expect("decodes");
            assert_eq!(back.to_bytes(), op.to_bytes());
        }
    }

    #[test]
    fn serialize_deserialize_transfer_round_trip() {
        let balance = dsm::types::token_types::Balance::amount(1000);
        let op = Operation::Transfer {
            policy_commit: [0u8; 32],
            to_device_id: vec![0xAAu8; 32],
            amount: balance,
            token_id: b"dBTC".to_vec(),
            mode: dsm::types::operations::TransactionMode::Bilateral,
            nonce: vec![0xBBu8; 16],
            recipient: vec![0xCCu8; 32],
            to: vec![0xDDu8; 32],
            message: "test transfer".to_string(),
            signature: vec![0xEEu8; 64],
            authority_policy: None,
        };
        let bytes = serialize_operation(&op);
        let back = deserialize_operation(&bytes).expect("deserialize transfer");
        match back {
            Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                mode,
                nonce,
                recipient,
                to,
                message,
                ..
            } => {
                assert_eq!(to_device_id, vec![0xAAu8; 32]);
                assert_eq!(amount.value(), 1000);
                assert_eq!(token_id, b"dBTC".to_vec());
                assert!(matches!(
                    mode,
                    dsm::types::operations::TransactionMode::Bilateral
                ));
                assert_eq!(nonce, vec![0xBBu8; 16]);
                assert_eq!(recipient, vec![0xCCu8; 32]);
                assert_eq!(to, vec![0xDDu8; 32]);
                assert_eq!(message, "test transfer");
            }
            _ => panic!("expected Transfer variant"),
        }
    }

    #[test]
    fn encode_genesis_record_bytes_is_nonempty_and_deterministic() {
        let rec = GenesisRecord {
            genesis_id: "gen-1".into(),
            device_id: "dev-1".into(),
            device_birth_binding: "bind".into(),
            merkle_root: "root".into(),
            progress_marker: "P".into(),
            publication_hash: "pub".into(),
            entropy_hash: "ent".into(),
            protocol_version: "1.0".into(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
            genesis_nonce: String::new(),
            genesis_profile: String::new(),
            network_id: "dsm-test".into(),
        };
        let enc1 = encode_genesis_record_bytes(&rec);
        let enc2 = encode_genesis_record_bytes(&rec);
        assert_eq!(enc1, enc2);
        assert!(!enc1.is_empty());
    }

    #[test]
    fn take_reads_exact_bytes() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut cursor: &[u8] = &data;
        let first4 = take::<4>(&mut cursor).expect("take 4");
        assert_eq!(first4, [1, 2, 3, 4]);
        assert_eq!(cursor, &[5, 6, 7, 8]);
    }

    #[test]
    fn take_fails_on_insufficient_data() {
        let data = [1u8, 2];
        let mut cursor: &[u8] = &data;
        assert!(take::<4>(&mut cursor).is_err());
    }

    #[test]
    fn read_len_u32_parses_little_endian() {
        let val = 42u32;
        let bytes = val.to_le_bytes();
        let mut cursor: &[u8] = &bytes;
        assert_eq!(read_len_u32(&mut cursor).unwrap(), 42);
    }

    #[test]
    fn read_u8_reads_single_byte() {
        let data = [0xABu8, 0xCD];
        let mut cursor: &[u8] = &data;
        assert_eq!(read_u8(&mut cursor).unwrap(), 0xAB);
        assert_eq!(cursor, &[0xCD]);
    }

    #[test]
    fn read_u64_parses_little_endian() {
        let val = 123456789u64;
        let bytes = val.to_le_bytes();
        let mut cursor: &[u8] = &bytes;
        assert_eq!(read_u64(&mut cursor).unwrap(), 123456789);
    }

    #[test]
    fn read_vec_reads_length_prefixed_data() {
        let payload = b"hello";
        let mut data = Vec::new();
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(payload);
        data.extend_from_slice(b"extra");

        let mut cursor: &[u8] = &data;
        let v = read_vec(&mut cursor).unwrap();
        assert_eq!(v, b"hello");
        assert_eq!(cursor, b"extra");
    }

    #[test]
    fn read_string_reads_length_prefixed_utf8() {
        let s = "world";
        let mut data = Vec::new();
        data.extend_from_slice(&(s.len() as u32).to_le_bytes());
        data.extend_from_slice(s.as_bytes());

        let mut cursor: &[u8] = &data;
        assert_eq!(read_string(&mut cursor).unwrap(), "world");
    }
}
