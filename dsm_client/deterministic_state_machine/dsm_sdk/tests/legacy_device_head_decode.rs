// SPDX-License-Identifier: MIT OR Apache-2.0
//! Can the current build read the device heads that are actually on the phones?
//!
//! Phase 4 added `policy_commit` to `Operation::Mint`/`Burn` by inserting it in
//! the MIDDLE of a hand-rolled positional encoding that carries no field
//! identifiers. Every field after it shifts by one slot, so a blob written
//! before that change cannot be read after it. `Transfer.authority_policy` was
//! added the other way — appended, emitting nothing when absent, explicitly so
//! that prior encodings and state hashes stayed byte-identical.
//!
//! That difference decides whether the new build can be installed over existing
//! wallet state or whether that state has to be wiped first. Wiping is not
//! cleanly reversible on these devices (clearing app data can destroy the
//! Keystore material that makes a DB snapshot readable), so the question is
//! answered against the real bytes rather than reasoned about.
//!
//! Point `DSM_LEGACY_HEAD_DIR` at a directory of `*-head-*.bin` blobs pulled
//! from `bcr_device_heads.head_bytes` and run:
//!
//!   DSM_LEGACY_HEAD_DIR=/path/to/blobs \
//!     cargo test -p dsm_sdk --test legacy_device_head_decode -- --nocapture
//!
//! Without that variable the test skips: this is a diagnostic against captured
//! device state, not something CI can synthesise.

#![allow(clippy::disallowed_methods)]

use dsm_sdk::storage::client_db::decode_device_state;

#[test]
fn legacy_device_heads_decode_under_the_current_build() {
    let Ok(dir) = std::env::var("DSM_LEGACY_HEAD_DIR") else {
        eprintln!("DSM_LEGACY_HEAD_DIR unset — skipping (needs captured device blobs)");
        return;
    };

    let mut blobs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {dir}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    blobs.sort();
    assert!(!blobs.is_empty(), "no .bin blobs in {dir}");

    let mut failed = Vec::new();

    for path in &blobs {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let bytes = std::fs::read(path).expect("read blob");

        match decode_device_state(&bytes) {
            Ok((state, root)) => {
                // Report enough to tell a real decode from a lucky one.
                println!(
                    "  {name}: OK — {} bytes, {} relationship tip(s), root {}",
                    bytes.len(),
                    state.relationship_keys().len(),
                    bs58_ish(&root),
                );
            }
            Err(e) => {
                println!("  {name}: FAILED — {} bytes: {e}", bytes.len());
                failed.push((name, e.to_string()));
            }
        }
    }

    if !failed.is_empty() {
        panic!(
            "{}/{} captured device head(s) cannot be decoded by this build:\n{}\n\n\
             These are the live heads from the handsets. A device whose head does not \
             decode cannot construct its CoreSDK, so the wallet does not start. \
             Installing this build over that state would brick it; the state must be \
             wiped first (beta doctrine: clean cut, no migration path).",
            failed.len(),
            blobs.len(),
            failed
                .iter()
                .map(|(n, e)| format!("  - {n}: {e}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

/// Short, non-hex digest rendering — the repo bans hex in protocol paths and
/// there is no reason for a diagnostic to be the exception.
fn bs58_ish(root: &[u8; 32]) -> String {
    const A: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    root.iter()
        .take(6)
        .map(|b| A[(*b >> 3) as usize] as char)
        .collect()
}
