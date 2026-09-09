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

// ── amendment 2c-A.1: the settlement bundle and what it nests ────────────────
//
// Written from registry §5.5, §5.10, §5.11, §5.13, §5.19–§5.23 and the 2c-B
// grammars, never from `dsm::ccb::settlement`.

/// `H_dom(tag, payload)` as §2 states it: BLAKE3 over `tag ‖ 0x00 ‖ payload`.
pub fn h_dom(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&[0u8]);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// `addr(N, P) = H_dom(DSM/storage-object, N ‖ H_dom(N, P))` (Def 6.19).
pub fn storage_addr(namespace: &[u8], inner: &[u8; 32]) -> [u8; 32] {
    h_dom(b"DSM/storage-object", &[namespace, inner].concat())
}

pub fn trade_intent(
    token_in: [u8; 32],
    amount_in: u64,
    token_out: [u8; 32],
    min_out: u64,
    max_fee: u64,
    max_hops: u32,
    max_fanout: u32,
    k: u32,
    nonce: [u8; 32],
) -> Vec<u8> {
    [
        envelope(0x000B, 1),
        token_in.to_vec(),
        u64be(amount_in),
        token_out.to_vec(),
        u64be(min_out),
        u64be(max_fee),
        u32be(max_hops),
        u32be(max_fanout),
        u32be(k),
        nonce.to_vec(),
    ]
    .concat()
}

/// Schema 2: `c_n`, the two deltas, the consumed claim, the fee policy inline.
pub fn allocation(
    parent_binding: [u8; 32],
    delta_in: u64,
    delta_out: u64,
    encumbrance_claim: [u8; 32],
    phi: Vec<u8>,
) -> Vec<u8> {
    [
        envelope(0x0015, 2),
        parent_binding.to_vec(),
        u64be(delta_in),
        u64be(delta_out),
        encumbrance_claim.to_vec(),
        phi,
    ]
    .concat()
}

/// Schema 2: a SET — ordered by complete element encoding.
pub fn allocation_bundle(mut allocations: Vec<Vec<u8>>) -> Vec<u8> {
    allocations.sort();
    let mut out = [envelope(0x0016, 2), u32be(allocations.len() as u32)].concat();
    for a in allocations {
        out.extend(a);
    }
    out
}

/// Schema 2: a SEQUENCE — legs in execution order, never sorted.
pub fn route(legs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = [envelope(0x000D, 2), u32be(legs.len() as u32)].concat();
    for leg in legs {
        out.extend(leg);
    }
    out
}

/// `0x0031` schema 1: three digests, `operation_bytes`, `entropy` as `bytes`
/// of 32, field 6 absent, `sigma_dsm` as `bytes`.
pub fn dsm_successor_evidence(
    rel_key: [u8; 32],
    embedded_parent: [u8; 32],
    counterparty_devid: [u8; 32],
    operation_bytes: &[u8],
    entropy: [u8; 32],
    sigma_dsm: &[u8],
) -> Vec<u8> {
    [
        envelope(0x0031, 1),
        rel_key.to_vec(),
        embedded_parent.to_vec(),
        counterparty_devid.to_vec(),
        bytes_field(operation_bytes),
        bytes_field(&entropy),
        vec![0x00],
        bytes_field(sigma_dsm),
    ]
    .concat()
}

pub fn market_terms(
    intent: Vec<u8>,
    route_set_commitment: [u8; 32],
    selected_route: Vec<u8>,
    trader_parent: [u8; 32],
    trader_successor: [u8; 32],
    recovery_material: Vec<u8>,
) -> Vec<u8> {
    [
        envelope(0x0033, 1),
        intent,
        route_set_commitment.to_vec(),
        selected_route,
        trader_parent.to_vec(),
        trader_successor.to_vec(),
        recovery_material,
    ]
    .concat()
}

/// `0x000F` schema 1: `parent_binding` as a bare digest, the complete nested
/// successor, field 3 absent, field 4 marker + `bytes` when present.
pub fn consumed_dlv_transition(
    parent_binding: [u8; 32],
    successor: Vec<u8>,
    close_authorization: Option<&[u8]>,
) -> Vec<u8> {
    let field4 = match close_authorization {
        None => vec![0x00],
        Some(sig) => [vec![0x01], bytes_field(sig)].concat(),
    };
    [
        envelope(0x000F, 1),
        parent_binding.to_vec(),
        successor,
        vec![0x00],
        field4,
    ]
    .concat()
}

/// `0x000E` schema 1: field 1 with its marker always emitted, then the
/// transition SET ordered by complete element encoding.
pub fn settlement_bundle(market_terms: Option<Vec<u8>>, mut transitions: Vec<Vec<u8>>) -> Vec<u8> {
    let field1 = match market_terms {
        None => vec![0x00],
        Some(t) => [vec![0x01], t].concat(),
    };
    transitions.sort();
    let mut out = [envelope(0x000E, 1), field1, u32be(transitions.len() as u32)].concat();
    for t in transitions {
        out.extend(t);
    }
    out
}
