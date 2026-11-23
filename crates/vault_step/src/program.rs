//! The vault-step program (`guests/vault_step.py`): its constants, and a step's hint streams and public input.

use crate::reference::*;
use isa::Program;
use primitives::field::{F128, g_pow};
use std::collections::BTreeMap;

pub const SOURCE: &str = include_str!("../../../guests/vault_step.py");

/// A 16-byte run as a cell: the low limb its first 8 bytes, little-endian.
pub fn cell(bytes: &[u8]) -> F128 {
    let limb = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    F128::new(limb(&bytes[..8]), limb(&bytes[8..16]))
}

pub fn cells(v: &D32) -> [F128; 2] {
    [cell(&v[..16]), cell(&v[16..])]
}

fn literal(c: F128) -> String {
    (u128::from(c.c0) | u128::from(c.c1) << 64).to_string()
}

fn byte_list(b: &[u8]) -> String {
    format!("[{}]", b.iter().map(u8::to_string).collect::<Vec<_>>().join(", "))
}

/// The first compression's four message cells of a 25-byte-prefix hash: the 24-byte tag, its NUL, zeros.
fn prefix_cells(tag: &[u8]) -> String {
    assert_eq!(tag.len(), 24);
    let mut block = [0u8; 64];
    block[..24].copy_from_slice(tag);
    let c: Vec<String> = block.chunks(16).map(|b| literal(cell(b))).collect();
    format!("[{}]", c.join(", "))
}

fn md(len: u64, flags: u64) -> String {
    ((u128::from(len) | u128::from(flags) << 32) << 64).to_string()
}

pub fn placeholders() -> BTreeMap<String, String> {
    let iv: Vec<u8> = verifier::blake3::IV.iter().flat_map(|w| w.to_le_bytes()).collect();
    [
        ("B3_IV0_PLACEHOLDER", literal(cell(&iv[..16]))),
        ("B3_IV1_PLACEHOLDER", literal(cell(&iv[16..]))),
        ("TAG_STATE_KEY_PLACEHOLDER", byte_list(TAG_VAULT_STATE_KEY)),
        ("TAG_LEAF_STATE_PLACEHOLDER", byte_list(TAG_VAULT_LEAF_STATE)),
        ("TAG_REL_KEY_PLACEHOLDER", byte_list(TAG_REL_KEY)),
        ("TAG_REL_LEAF_PLACEHOLDER", byte_list(TAG_REL_LEAF)),
        ("TAG_SUCC_CELL_PLACEHOLDER", byte_list(TAG_SUCC_CELL_V2)),
        ("TAG_MARKET_OBJ_PLACEHOLDER", byte_list(TAG_MARKET_POLICY_OBJECT)),
        ("TAG_FEE_OBJ_PLACEHOLDER", byte_list(TAG_FEE_POLICY_OBJECT)),
        ("TAG_STORAGE_OBJ_PLACEHOLDER", byte_list(TAG_STORAGE_OBJECT)),
        ("TAG_STATEMENT_PLACEHOLDER", byte_list(TAG_STATEMENT)),
        ("NODE_M_PLACEHOLDER", prefix_cells(TAG_SMT_NODE)),
        ("LEAF_M_PLACEHOLDER", prefix_cells(TAG_SMT_LEAF)),
        ("ATTEMPT_M_PLACEHOLDER", prefix_cells(TAG_SUCC_ATTEMPT)),
        ("MD_64_START_PLACEHOLDER", md(64, 1)),
        ("MD_25_END_PLACEHOLDER", md(25, 2 | 8)),
        ("MD_1_END_PLACEHOLDER", md(1, 2 | 8)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

pub fn program() -> Program {
    let ast = zkdsl_compiler::parse_with_replacements(SOURCE, &placeholders()).expect("the vault-step program parses");
    Program::from(zkdsl_compiler::compile(&ast))
}

fn gp(e: u64) -> F128 {
    F128::from(g_pow(e as usize))
}

/// The `n` base-16 digits of `v`, least significant first, as g-powers.
fn digits_u128(v: u128, n: usize) -> Vec<F128> {
    (0..n).map(|k| gp(((v >> (4 * k)) & 15) as u64)).collect()
}

/// The 64 digits of a 32-byte big-endian integer, least significant first.
fn digits_be256(b: &D32) -> Vec<F128> {
    (0..64)
        .map(|k| {
            let byte = b[31 - k / 2];
            gp(u64::from(if k % 2 == 0 { byte & 15 } else { byte >> 4 }))
        })
        .collect()
}

/// `b - a - 1` of two 32-byte big-endian integers, `a < b`.
fn gap_be(a: &D32, b: &D32) -> D32 {
    let mut out = [0u8; 32];
    let mut borrow = 1i32; // the extra 1
    for i in (0..32).rev() {
        let mut d = i32::from(b[i]) - i32::from(a[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = d as u8;
    }
    assert_eq!(borrow, 0, "a < b");
    out
}

pub type Witness = Vec<(String, Vec<Vec<F128>>)>;

/// The hint streams of a step and its public input, the statement's two cells.
pub fn hints(w: &StepWitness, r_prev: &D32, public: &StepPublic) -> (Witness, [F128; 2]) {
    let mut streams: BTreeMap<&str, Vec<Vec<F128>>> = BTreeMap::new();
    let mut put = |name: &'static str, v: Vec<F128>| streams.entry(name).or_default().push(v);
    for (name, value) in [
        ("vault_id", &w.vault_id),
        ("r_prev", r_prev),
        ("external_commitment", &w.external_commitment),
        ("trader_genesis", &w.trader_genesis),
        ("trader_device_id", &w.trader_device_id),
        ("relationship_base", &w.relationship_base),
        ("owner_genesis", &w.state.owner_genesis),
        ("owner_device_id", &w.state.owner_device_id),
        ("release_policy", &w.state.release_policy),
        ("storage_set_id", &w.state.storage_set_id),
        ("token_a", &w.token_a),
        ("token_b", &w.token_b),
    ] {
        let _ = name;
        put("value", cells(value).to_vec());
    }
    let s = &w.state;
    for (name, v) in [
        ("create_position", s.create_position),
        ("generation", s.generation),
        ("reserve_a", s.reserve_a),
        ("reserve_b", s.reserve_b),
        ("amount_in", w.hop.amount_in),
        ("amount_out", w.hop.amount_out),
        ("attempt", w.attempt),
    ] {
        let _ = name;
        put("digits", digits_u128(u128::from(v), 16));
    }
    put("digits", digits_u128(u128::from(w.fee_bps), 8));
    let bit = |b: bool| F128::from(u128::from(b));
    put("flags", vec![bit(w.hop.in_is_a), bit(w.relationship_present)]);
    put("digits", digits_be256(&gap_be(&w.token_a, &w.token_b)));
    let fee_c = BPS_DENOMINATOR - w.fee_bps;
    put("digits", digits_u128(u128::from(fee_c), 4));
    let (r_in, r_out) = if w.hop.in_is_a {
        (s.reserve_a, s.reserve_b)
    } else {
        (s.reserve_b, s.reserve_a)
    };
    let after_fee = u128::from(w.hop.amount_in) * u128::from(fee_c);
    let den = u128::from(r_in) * u128::from(BPS_DENOMINATOR) + after_fee;
    let num = u128::from(r_out) * after_fee;
    let rem = num % den;
    put("digits", digits_u128(rem, 21));
    put("digits", digits_u128(den - rem - 1, 21));
    put("digits", digits_u128(u128::from(r_out - w.hop.amount_out), 16));
    let path = |p: &[D32]| p.iter().flat_map(cells).collect::<Vec<_>>();
    put("state_path", path(&w.state_path));
    put("relationship_path", path(&w.relationship_path));
    let state_key = vault_state_key(&w.vault_id);
    let rel_key = relationship_key(&w.trader_genesis, &w.trader_device_id, &w.vault_id);
    let d = (0..HEIGHT)
        .find(|&b| get_bit(&state_key, b) != get_bit(&rel_key, b))
        .expect("distinct keys");
    put("divergence", vec![gp(d as u64)]);
    put("attempt_is_zero", vec![bit(w.attempt == 0)]);
    let witness = streams.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    (witness, cells(&public.digest()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::fixture;

    #[test]
    fn digits_spell_their_values() {
        let v = 0x0123_4567_89ab_cdefu128;
        let d = digits_u128(v, 16);
        assert_eq!(d[0], gp(0xf));
        assert_eq!(d[15], gp(0x0));
        let mut b = [0u8; 32];
        b[31] = 0xab;
        let d = digits_be256(&b);
        assert_eq!((d[0], d[1], d[2]), (gp(0xb), gp(0xa), gp(0)));
        let f = fixture(1, true, 2, 0);
        let _ = hints(&f.witness, &f.r_prev, &f.public);
    }
}
