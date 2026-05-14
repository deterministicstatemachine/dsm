// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for storage-node integration tests.
//!
//! Cargo treats `tests/common/` specially: files inside it are NOT compiled
//! as standalone integration test binaries, so we can safely keep helpers
//! here without spawning a phantom test target.

#![allow(dead_code)]

pub fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err:?}"),
    }
}

pub fn some_or_panic<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{context}"),
    }
}
