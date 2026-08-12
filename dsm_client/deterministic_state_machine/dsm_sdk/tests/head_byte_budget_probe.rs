// SPDX-License-Identifier: MIT OR Apache-2.0
//! DIAGNOSTIC PROBE — not a permanent test. Decodes a real `head_bytes` blob pulled
//! off a device and prints a field-by-field byte budget, so the 51,101 -> 1,202
//! contraction can be attributed to concrete fields rather than inferred.
//!
//! Run: DSM_HEAD_BIN=/path/to/head.bin cargo test -p dsm_sdk --test head_byte_budget_probe -- --nocapture --ignored

#![allow(clippy::disallowed_methods)]

use dsm_sdk::storage::client_db::decode_device_state;

#[test]
#[ignore = "diagnostic probe; requires DSM_HEAD_BIN"]
fn head_byte_budget() {
    let path = std::env::var("DSM_HEAD_BIN").expect("set DSM_HEAD_BIN");
    let bytes = std::fs::read(&path).expect("read head bin");
    println!("\n=== HEAD BYTE BUDGET: {path} ===");
    println!("total head_bytes: {}", bytes.len());

    let (head, stored_root) = match decode_device_state(&bytes) {
        Ok(v) => v,
        Err(e) => panic!("decode failed: {e}"),
    };

    println!("stored smt_root : {}", hex(&stored_root));
    println!("recomputed root : {}", hex(&head.root()));
    println!(
        "ROOT MATCH      : {}",
        if head.root() == stored_root {
            "YES"
        } else {
            "NO  <-- head is internally inconsistent"
        }
    );

    let mut accounted = 1usize + 32 + 32 + 32; // version + genesis + devid + root
    println!("\n-- fixed header --");
    println!("  version+genesis+devid+root : {accounted}");

    let pk = head.public_key();
    accounted += 4 + pk.len();
    println!("  public_key                 : {} (+4 len)", pk.len());

    accounted += 1 + if head.legacy_anchor().is_some() {
        32
    } else {
        0
    };
    println!(
        "  legacy_anchor              : {:?}",
        head.legacy_anchor().is_some()
    );

    let balances = head.balances_snapshot();
    accounted += 4 + balances.len() * 40;
    println!(
        "\n-- balances: {} entries ({} bytes) --",
        balances.len(),
        balances.len() * 40
    );
    for (pc, v) in balances {
        println!("    {} = {}", hex(&pc[..6]), v);
    }

    let rel_keys = head.relationship_keys();
    accounted += 4;
    println!("\n-- tips: {} relationship(s) --", rel_keys.len());
    let mut sig_bytes_total = 0usize;
    let mut op_bytes_total = 0usize;
    for rk in &rel_keys {
        let tip = head.rel_chain_tip(rk).expect("tip");
        // rel_key + chain_tip + counterparty + vc_tag + state_flag
        accounted += 32 + 32 + 32 + 1 + 1;
        println!("  rel {} vc={:?}", hex(&rk[..6]), tip.value_capability);
        // v0x06: a tip is a bounded accumulator entry — digest + entropy. The
        // operation and its ~50 KB signature live in the BCR archive, not here.
        if tip.tip_entropy.is_empty() {
            println!("    entropy: NONE  <-- digest-only tip (capsule restore)");
        } else {
            println!("    entropy: {} bytes", tip.tip_entropy.len());
        }
        accounted += 4 + tip.tip_entropy.len();
    }

    let extra = head.extra_leaves_snapshot();
    let allocs = head.offline_allocations_snapshot();
    let reserves = head.vault_reserves_snapshot();
    accounted += 4 + extra.len() * 64 + 4 + allocs.len() * 48 + 4 + reserves.len() * 48;
    println!("\n-- extra_leaves       : {} entries", extra.len());
    println!("-- offline_allocations: {} entries", allocs.len());
    println!("-- vault_reserves     : {} entries", reserves.len());
    for (k, r) in &reserves {
        println!(
            "     {} amount={} seq={}",
            hex(&k[..6]),
            r.amount,
            r.sequence
        );
    }

    println!("\n=== ATTRIBUTION ===");
    println!("  SIGNATURE bytes (entity+counterparty across all tips): {sig_bytes_total}");
    println!("  OPERATION bytes (across all tips)                    : {op_bytes_total}");
    println!(
        "  everything else (approx)                             : {}",
        bytes.len() as i64 - sig_bytes_total as i64 - op_bytes_total as i64
    );
    println!(
        "  head minus signatures                                : {}",
        bytes.len() - sig_bytes_total
    );
    println!(
        "  (rough accounted total: {accounted} vs actual {})",
        bytes.len()
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
