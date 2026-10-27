// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every leader seed and register key, pinned against an independent hasher and
//! frozen digests (MR-DSM-0082, MR-SOFI-0078, MR-SOFI-0126).
//!
//! A seed is derived from committed state only: node ids, availability and the
//! caller's identity never enter it (storage spec §9 rule 2). The writer and the
//! verifier share each derivation, so a change to its tag, its inputs, their
//! order or their encoding would pass any test that compares the two. These
//! compare each derivation with `BLAKE3(tag ‖ 0x00 ‖ inputs)` computed here from
//! the specification's formula, and with digests computed outside this
//! repository (`b3sum` over the same bytes), so a seed that took one more input
//! — a node id, a reader — turns these red.

/// `BLAKE3(tag ‖ 0x00 ‖ parts…)`, the specification's `H(tag; parts)`.
fn h(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(&[0u8]);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn cf(bytes: &[u8; 32]) -> String {
    dsm::utils::text_id::encode_base32_crockford(bytes)
}

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const R_P: [u8; 32] = [0x33; 32];
const Q: u64 = 7;

/// SoFi §7.2: `s(q) = H(DSM/economic/position-seed/v1; G ∥ DevID ∥ u64be(q) ∥
/// R_p)`, from committed state alone.
#[test]
fn a_positions_seed_is_the_specifications_hash_of_committed_state() {
    let seed = dsm::economic::register::position_seed(&G, &DEV, Q, &R_P);
    assert_eq!(
        seed,
        h(
            "DSM/economic/position-seed/v1",
            &[&G, &DEV, &Q.to_be_bytes(), &R_P]
        )
    );
    assert_eq!(
        cf(&seed),
        "HVNGZ07A3YYBA45JFPN8RWEFEBHZWDAVPZN2X8D2074JK4BN4SA0"
    );
}

/// SoFi §17.4: `K_root(q) = H(DSM/trader-economic-root-register-key/v1; G ∥
/// DevID ∥ u64be(q))`.
#[test]
fn a_root_register_key_is_the_specifications_hash_of_the_position() {
    let key = dsm::economic::register::economic_root_register_key(&G, &DEV, Q);
    assert_eq!(
        key,
        h(
            "DSM/trader-economic-root-register-key/v1",
            &[&G, &DEV, &Q.to_be_bytes()]
        )
    );
    assert_eq!(
        cf(&key),
        "2XMS24WY4H6D4FDQB85PD7XY230R0CR6EPV64BCKD80FD2RD2ZX0"
    );
}

/// The reserve's successor cell seed: `H(DSM/native-reserve-seed/v1;
/// reserve_id ∥ R_n)`.
#[test]
fn a_reserve_cells_seed_is_the_hash_of_the_reserve_and_its_parent() {
    let (reserve_id, parent) = ([0x44; 32], [0x55; 32]);
    let seed = dsm::economic::native_reserve::reserve_seed(&reserve_id, &parent);
    assert_eq!(
        seed,
        h("DSM/native-reserve-seed/v1", &[&reserve_id, &parent])
    );
    assert_eq!(
        cf(&seed),
        "P82X5E4V074PT1A131NYY2Q6ZXZAVXVTQ8C0CSBMSRM7NSYFT4XG"
    );
}

/// SoFi Amendments S21 and S22: the verdict, match and start cells are seeded
/// by their keys alone.
#[test]
fn the_escrow_cells_seeds_are_the_hashes_of_their_keys() {
    let verdict = [0x66; 32];
    let seed = dsm::sofi::escrow::verdict_seed(&verdict);
    assert_eq!(seed, h("DSM/escrow/verdict-seed/v1", &[&verdict]));
    assert_eq!(
        cf(&seed),
        "DDN5PDQ0B97SAXPX8ZVY90QK9DGPGQ6TNG2VV4K86939SE0WTJVG"
    );

    let match_cell = [0x77; 32];
    let seed = dsm::sofi::computed::match_seed(&match_cell);
    assert_eq!(seed, h("DSM/escrow/computed-match-seed/v1", &[&match_cell]));
    assert_eq!(
        cf(&seed),
        "NCWRZQH2NFSFQ7MYKXRPV47XKGZ1AD8R9M651YH92ERF87R5QWKG"
    );

    let start_cell = [0x88; 32];
    let seed = dsm::sofi::computed::start_seed(&start_cell);
    assert_eq!(seed, h("DSM/escrow/computed-start-seed/v1", &[&start_cell]));
    assert_eq!(
        cf(&seed),
        "ZXPWMS2D5GBSSNC3G1X7A33WZJ9CVHZ5BC2NWZ1JDYFH4YF0F4FG"
    );
}
