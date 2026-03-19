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
