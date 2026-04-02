// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protobuf persistence helpers — binary, deterministic, JSON-free.
//!
//! Use these helpers to read and write binary prost-encoded messages to disk
//! instead of text JSON serialization. This keeps persistence deterministic
//! and cross-language compatible.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use prost::Message;
use dsm::types::error::DsmError;

#[inline]
pub fn write_proto_to_file<M: Message>(path: &Path, msg: &M) -> Result<(), DsmError> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).map_err(|e| {
        DsmError::serialization_error(
            "Failed to encode protobuf message",
            "ProstMessage",
            None::<String>,
            Some(e),
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(DsmError::Io)?;
    }
    let mut f = File::create(path).map_err(DsmError::Io)?;
    f.write_all(&buf).map_err(DsmError::Io)
}

#[inline]
pub fn read_proto_from_file<M: Message + Default>(path: &Path) -> Result<M, DsmError> {
    let mut f = File::open(path).map_err(DsmError::Io)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(DsmError::Io)?;
    M::decode(&*buf).map_err(|e| {
        DsmError::serialization_error(
            "Failed to decode protobuf message",
            "ProstMessage",
            None::<String>,
            Some(e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("dsm_proto_persist_tests");
        std::fs::create_dir_all(&dir).ok();
        dir.join(name)
    }

    fn sample_message() -> dsm::types::proto::Hash32 {
        dsm::types::proto::Hash32 {
            v: vec![0xAA; 32],
        }
    }

    #[test]
    fn roundtrip_write_read() {
        let path = temp_path("roundtrip.bin");
        let msg = sample_message();
        write_proto_to_file(&path, &msg).unwrap();
        let decoded: dsm::types::proto::Hash32 = read_proto_from_file(&path).unwrap();
        assert_eq!(decoded.v, msg.v);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_creates_parent_directories() {
        let path = temp_path("nested/deep/dir/msg.bin");
        let msg = sample_message();
        let result = write_proto_to_file(&path, &msg);
        assert!(result.is_ok());
        assert!(path.exists());
        std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap().parent().unwrap()).ok();
    }

    #[test]
    fn read_nonexistent_file_returns_error() {
        let path = temp_path("does_not_exist.bin");
        let result = read_proto_from_file::<dsm::types::proto::Hash32>(&path);
        assert!(result.is_err());
    }

    #[test]
    fn read_corrupt_data_returns_error() {
        let path = temp_path("corrupt.bin");
        std::fs::write(&path, b"not valid protobuf data!!!!").unwrap();
        let result = read_proto_from_file::<dsm::types::proto::Hash32>(&path);
        assert!(result.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn overwrite_existing_file() {
        let path = temp_path("overwrite.bin");
        let msg1 = dsm::types::proto::Hash32 { v: vec![1; 32] };
        let msg2 = dsm::types::proto::Hash32 { v: vec![2; 32] };
        write_proto_to_file(&path, &msg1).unwrap();
        write_proto_to_file(&path, &msg2).unwrap();
        let decoded: dsm::types::proto::Hash32 = read_proto_from_file(&path).unwrap();
        assert_eq!(decoded.v, vec![2; 32]);
        std::fs::remove_file(&path).ok();
    }
}
