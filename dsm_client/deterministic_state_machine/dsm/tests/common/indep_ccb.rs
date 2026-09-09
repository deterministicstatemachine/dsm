// SPDX-License-Identifier: Apache-2.0

//! An INDEPENDENT CCB encoder, written from the registry text and never from
//! the production encoder. Shared by every conformance test so there is one
//! second implementation, not several that could drift from each other.
//!
//! Extracted verbatim from `ccb_conformance.rs`'s private `mod indep` so the
//! DLV successor vectors can use the same encoder; `#[path]`-included by each
//! test crate that needs it.
#![allow(dead_code)]
pub fn u16be(v: u16) -> Vec<u8> {
    vec![(v >> 8) as u8, (v & 0xff) as u8]
}

pub fn u32be(v: u32) -> Vec<u8> {
    (0..4).rev().map(|i| (v >> (i * 8)) as u8).collect()
}

pub fn u64be(v: u64) -> Vec<u8> {
    (0..8).rev().map(|i| (v >> (i * 8)) as u8).collect()
}

pub fn envelope(class: u16, version: u16) -> Vec<u8> {
    [u16be(class), u16be(version)].concat()
}

pub fn bytes_field(v: &[u8]) -> Vec<u8> {
    [u32be(v.len() as u32), v.to_vec()].concat()
}

/// Schema 3: envelope, count, then for each entry in ascending MEMBER-ID
/// order a length-prefixed member id followed by its 32-byte register
/// incarnation. Sorted by member id only — never by the pair.
pub fn storage_set(mut entries: Vec<(Vec<u8>, [u8; 32])>) -> Vec<u8> {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = [envelope(0x0002, 3), u32be(entries.len() as u32)].concat();
    for (id, incarnation) in entries {
        out.extend(bytes_field(&id));
        out.extend_from_slice(&incarnation);
    }
    out
}

pub fn market_policy(family: u16, version: u16, a: [u8; 32], b: [u8; 32]) -> Vec<u8> {
    [
        envelope(0x0007, 1),
        u16be(family),
        u16be(version),
        a.to_vec(),
        b.to_vec(),
    ]
    .concat()
}

pub fn release_policy(family: u16, version: u16) -> Vec<u8> {
    [envelope(0x0009, 1), u16be(family), u16be(version)].concat()
}

pub fn fee_policy(fee_bps: u32) -> Vec<u8> {
    [envelope(0x000A, 1), u32be(fee_bps)].concat()
}

pub fn encumbrance_claim(
    parent_binding: [u8; 32],
    claim_seq: u64,
    amount: u64,
    token: [u8; 32],
    purpose: u16,
) -> Vec<u8> {
    [
        envelope(0x0004, 2),
        parent_binding.to_vec(),
        u64be(claim_seq),
        u64be(amount),
        token.to_vec(),
        u16be(purpose),
    ]
    .concat()
}

pub fn encumbrance_set(mut claims: Vec<Vec<u8>>) -> Vec<u8> {
    claims.sort();
    let mut out = [envelope(0x0005, 2), u32be(claims.len() as u32)].concat();
    for c in claims {
        out.extend(c);
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub fn vault_state(
    g_o: [u8; 32],
    d_o: [u8; 32],
    vault_id: [u8; 32],
    generation: u64,
    r_a: u64,
    r_b: u64,
    p_m: Vec<u8>,
    p_r: Vec<u8>,
    phi: Vec<u8>,
    e: Vec<u8>,
    beta: Option<u64>,
    h_n: [u8; 32],
    r_o: [u8; 32],
    s: Vec<u8>,
    q: u32,
) -> Vec<u8> {
    let beta_bytes = match beta {
        None => vec![0x00],
        Some(v) => [vec![0x01], u64be(v)].concat(),
    };
    [
        envelope(0x0001, 4),
        g_o.to_vec(),
        d_o.to_vec(),
        vault_id.to_vec(),
        u64be(generation),
        u64be(r_a),
        u64be(r_b),
        p_m,
        p_r,
        phi,
        e,
        beta_bytes,
        h_n.to_vec(),
        r_o.to_vec(),
        s,
        u32be(q),
    ]
    .concat()
}
