// SPDX-License-Identifier: Apache-2.0

//! SoFi v8 wire registry — independent conformance.
//!
//! `indep` below is a SECOND implementation written from the field tables in
//! `dsm::sofi::wire` (module docs) and the derivation list in
//! `dsm::sofi::derive`, sharing no encoder, hasher or Base32 code with the
//! crate. Agreement between the two, plus the frozen Base32 golden digests, is
//! the evidence; a round trip through one implementation alone is not.

#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

use dsm::ccb::decode::DecodeError;
use dsm::sofi::arith::{resolve, CellObservation, CellResolution};
use dsm::sofi::conformance::{
    check_fulfillment_against_precommit, derive_policy_fulfillments, FulfillmentConformanceError,
    Validation,
};
use dsm::sofi::derive as d;
use dsm::sofi::fisher_yates;
use dsm::sofi::wire::*;

mod indep {
    //! Written from the tables, never from the production encoder.

    pub fn u16be(v: u16) -> Vec<u8> {
        vec![(v >> 8) as u8, v as u8]
    }
    pub fn u32be(v: u32) -> Vec<u8> {
        (0..4).rev().map(|i| (v >> (i * 8)) as u8).collect()
    }
    pub fn u64be(v: u64) -> Vec<u8> {
        (0..8).rev().map(|i| (v >> (i * 8)) as u8).collect()
    }
    pub fn env(class: u16) -> Vec<u8> {
        [u16be(class), u16be(1)].concat()
    }
    pub fn key(alg: u16, k: &[u8]) -> Vec<u8> {
        [u16be(alg), u32be(k.len() as u32), k.to_vec()].concat()
    }

    /// `BLAKE3(tag ‖ 0x00 ‖ parts…)`.
    pub fn h(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        hasher.update(&[0u8]);
        for p in parts {
            hasher.update(p);
        }
        *hasher.finalize().as_bytes()
    }

    pub fn crockford(bytes: &[u8]) -> String {
        const A: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let mut bits: Vec<u8> = Vec::new();
        for b in bytes {
            for i in (0..8).rev() {
                bits.push((b >> i) & 1);
            }
        }
        while !bits.len().is_multiple_of(5) {
            bits.push(0);
        }
        bits.chunks(5)
            .map(|c| A[c.iter().fold(0usize, |acc, b| (acc << 1) | *b as usize)] as char)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        g: &[u8; 32],
        dev: &[u8; 32],
        p: u64,
        v: &[u8; 32],
        cref: &[u8; 32],
        root: &[u8; 32],
        alg: u16,
        k: &[u8],
    ) -> Vec<u8> {
        [
            env(0x0036),
            g.to_vec(),
            dev.to_vec(),
            u64be(p),
            v.to_vec(),
            cref.to_vec(),
            root.to_vec(),
            key(alg, k),
        ]
        .concat()
    }

    pub fn parent_single(cref: &[u8; 32]) -> Vec<u8> {
        [env(0x003B), cref.to_vec()].concat()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn precommit(
        g: &[u8; 32],
        dev: &[u8; 32],
        p: u64,
        parent: Vec<u8>,
        e: &[u8; 32],
        legs: &[([u8; 32], [u8; 32], [u8; 32])],
        realize: &[u8; 32],
        void: &[u8; 32],
        set: &[u8; 32],
        alg: u16,
        k: &[u8],
    ) -> Vec<u8> {
        let mut out = [
            env(0x0037),
            g.to_vec(),
            dev.to_vec(),
            u64be(p),
            parent,
            e.to_vec(),
            u32be(legs.len() as u32),
        ]
        .concat();
        for (v, r, s) in legs {
            out.extend_from_slice(v);
            out.extend_from_slice(r);
            out.extend_from_slice(s);
        }
        [
            out,
            realize.to_vec(),
            void.to_vec(),
            set.to_vec(),
            key(alg, k),
        ]
        .concat()
    }

    pub fn policy_fulfillment(
        pid: &[u8; 32],
        e: &[u8; 32],
        v: &[u8; 32],
        r: &[u8; 32],
        shadow: &[u8; 32],
    ) -> Vec<u8> {
        [
            env(0x0038),
            pid.to_vec(),
            e.to_vec(),
            v.to_vec(),
            r.to_vec(),
            shadow.to_vec(),
        ]
        .concat()
    }

    pub fn fulfillment(
        pid: &[u8; 32],
        set: &[[u8; 32]],
        attempts: &[([u8; 32], u64)],
        q: u64,
        alg: u16,
        k: &[u8],
    ) -> Vec<u8> {
        let mut out = [env(0x0039), pid.to_vec(), u32be(set.len() as u32)].concat();
        for id in set {
            out.extend_from_slice(id);
        }
        out.extend(u32be(attempts.len() as u32));
        for (v, a) in attempts {
            out.extend_from_slice(v);
            out.extend(u64be(*a));
        }
        [out, u64be(q), key(alg, k)].concat()
    }

    pub fn resolution_claim(
        g: &[u8; 32],
        dev: &[u8; 32],
        q: u64,
        fid: &[u8; 32],
        realize: &[u8; 32],
        void: &[u8; 32],
    ) -> Vec<u8> {
        [
            env(0x003A),
            g.to_vec(),
            dev.to_vec(),
            u64be(q),
            fid.to_vec(),
            realize.to_vec(),
            void.to_vec(),
        ]
        .concat()
    }

    /// `(vault_id, parent_root, setup_ref, shadow_core)`.
    pub type RouteLeg = ([u8; 32], [u8; 32], [u8; 32], [u8; 32]);

    pub fn route_leg_set(legs: &[RouteLeg]) -> Vec<u8> {
        let mut out = [env(0x004A), u32be(legs.len() as u32)].concat();
        for (v, r, s, c) in legs {
            for x in [v, r, s, c] {
                out.extend_from_slice(x);
            }
        }
        out
    }

    /// The normative Fisher-Yates, from the text.
    pub fn fisher_yates(seed: &[u8; 32], view: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut perm = view.to_vec();
        perm.sort();
        for i in (1..perm.len()).rev() {
            let range = (i as u64) + 1;
            let threshold = ((1u128 << 64) % range as u128) as u64;
            let mut ctr: u32 = 0;
            let j = loop {
                let out = h(
                    "DSM/sofi/fy-prf/v1",
                    &[seed, &(i as u32).to_be_bytes(), &ctr.to_be_bytes()],
                );
                let w = u64::from_be_bytes(out[..8].try_into().expect("8"));
                if w >= threshold {
                    break (w % range) as usize;
                }
                ctr += 1;
            };
            perm.swap(i, j);
        }
        perm
    }
}

// ── fixtures ───────────────────────────────────────────────────────────────

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const V1: [u8; 32] = [0x33; 32];
const R1: [u8; 32] = [0x44; 32];
const V2: [u8; 32] = [0x66; 32];
const R2: [u8; 32] = [0x77; 32];
const KEY: [u8; 64] = [0x55; 64];
const ALG: u16 = dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F;

fn setup_body() -> SofiSetupBody {
    SofiSetupBody::new(G, DEV, 7, V1, [0x88; 32], [0x99; 32], ALG, &KEY).expect("setup")
}

fn precommit(legs: Vec<PrecommitLeg>) -> TraderPrecommitBody {
    TraderPrecommitBody::new(
        G,
        DEV,
        41,
        ParentClaimRef::SingleRoot {
            claim_ref: [0xAA; 32],
        },
        [0xEE; 32],
        legs,
        [0xC1; 32],
        [0xC2; 32],
        [0xC3; 32],
        ALG,
        &KEY,
    )
    .expect("precommit")
}

fn two_leg_precommit() -> TraderPrecommitBody {
    let rho = d::setup_ref(&setup_body());
    precommit(vec![
        PrecommitLeg {
            vault_id: V1,
            parent_root: R1,
            setup_ref: rho,
        },
        PrecommitLeg {
            vault_id: V2,
            parent_root: R2,
            setup_ref: [0xBB; 32],
        },
    ])
}

const SHADOWS: [[u8; 32]; 2] = [[5; 32], [6; 32]];

fn conforming_fulfillment(p: &TraderPrecommitBody) -> TraderFulfillmentBody {
    let mut set: Vec<[u8; 32]> = derive_policy_fulfillments(p, &SHADOWS)
        .expect("derive")
        .iter()
        .map(d::policy_fulfillment_id)
        .collect();
    set.sort();
    TraderFulfillmentBody::new(
        d::precommit_id(p),
        set,
        vec![
            AttemptEntry {
                vault_id: V1,
                attempt: 0,
            },
            AttemptEntry {
                vault_id: V2,
                attempt: 3,
            },
        ],
        42,
        ALG,
        &KEY,
    )
    .expect("fulfillment")
}

fn cf(b: &[u8; 32]) -> String {
    indep::crockford(b)
}

// ── positive vectors: two implementations agree, byte for byte ─────────────

#[test]
fn every_object_matches_the_independent_encoder_and_round_trips() {
    let s = setup_body();
    let s_bytes = indep::setup(&G, &DEV, 7, &V1, &[0x88; 32], &[0x99; 32], ALG, &KEY);
    assert_eq!(s.encode(), s_bytes);
    assert_eq!(SofiSetupBody::decode(&s_bytes).expect("decode"), s);

    let p = two_leg_precommit();
    let rho = d::setup_ref(&s);
    let p_bytes = indep::precommit(
        &G,
        &DEV,
        41,
        indep::parent_single(&[0xAA; 32]),
        &[0xEE; 32],
        &[(V1, R1, rho), (V2, R2, [0xBB; 32])],
        &[0xC1; 32],
        &[0xC2; 32],
        &[0xC3; 32],
        ALG,
        &KEY,
    );
    assert_eq!(p.encode(), p_bytes);
    assert_eq!(TraderPrecommitBody::decode(&p_bytes).expect("decode"), p);

    let pid = d::precommit_id(&p);
    let g0 = DlvPolicyFulfillmentBody {
        precommit_id: pid,
        external_commitment: [0xEE; 32],
        vault_id: V1,
        parent_root: R1,
        shadow_core: SHADOWS[0],
    };
    let g0_bytes = indep::policy_fulfillment(&pid, &[0xEE; 32], &V1, &R1, &SHADOWS[0]);
    assert_eq!(g0.encode(), g0_bytes);
    assert_eq!(
        DlvPolicyFulfillmentBody::decode(&g0_bytes).expect("decode"),
        g0
    );

    let f = conforming_fulfillment(&p);
    let f_bytes = indep::fulfillment(
        &pid,
        f.policy_fulfillment_set(),
        &[(V1, 0), (V2, 3)],
        42,
        ALG,
        &KEY,
    );
    assert_eq!(f.encode(), f_bytes);
    assert_eq!(TraderFulfillmentBody::decode(&f_bytes).expect("decode"), f);

    let c = d::resolution_claim(&p, &f);
    let fid = d::fulfillment_id(&f);
    assert_eq!(
        c.encode(),
        indep::resolution_claim(&G, &DEV, 42, &fid, &[0xC1; 32], &[0xC2; 32])
    );
    assert_eq!(SofiResolutionClaim::decode(&c.encode()).expect("decode"), c);

    let gamma = RouteLegSet::new(vec![
        RouteLegEntry {
            vault_id: V1,
            parent_root: R1,
            setup_ref: rho,
            shadow_core: SHADOWS[0],
        },
        RouteLegEntry {
            vault_id: V2,
            parent_root: R2,
            setup_ref: [0xBB; 32],
            shadow_core: SHADOWS[1],
        },
    ])
    .expect("gamma");
    assert_eq!(
        gamma.encode(),
        indep::route_leg_set(&[(V1, R1, rho, SHADOWS[0]), (V2, R2, [0xBB; 32], SHADOWS[1])])
    );
    assert_eq!(RouteLegSet::decode(&gamma.encode()).expect("decode"), gamma);
}

#[test]
fn every_union_variant_round_trips() {
    for r in [
        ParentClaimRef::SingleRoot { claim_ref: [1; 32] },
        ParentClaimRef::Conditional {
            fulfillment_id: [2; 32],
        },
    ] {
        assert_eq!(ParentClaimRef::decode(&r.encode()).expect("decode"), r);
    }
    let refs = [
        ValidationRef::ContentAddr {
            object_class: 0x001C,
            addr: [3; 32],
        },
        ValidationRef::SingleRootClaim { claim_ref: [4; 32] },
        ValidationRef::ConditionalClaim {
            genesis: G,
            device_id: DEV,
            position: 9,
            fulfillment_id: [5; 32],
        },
        ValidationRef::Setup { setup_ref: [6; 32] },
    ];
    for r in refs {
        assert_eq!(ValidationRef::decode(&r.encode()).expect("decode"), r);
    }
    let mut sorted = refs.to_vec();
    sorted.sort_by_key(|r| r.encode());
    let idx = PreEClosureIndex::new(sorted).expect("closure");
    assert_eq!(
        PreEClosureIndex::decode(&idx.encode()).expect("decode"),
        idx
    );
    let aux = PolicyFulfillmentAuxRef {
        policy_fulfillment_id: [14; 32],
        evidence_class: 0x0042,
        addr: [15; 32],
    };
    assert_eq!(
        PolicyFulfillmentAuxRef::decode(&aux.encode()).expect("decode"),
        aux
    );
}

#[test]
fn derivations_match_the_independent_hasher_and_the_frozen_golden_digests() {
    let s = setup_body();
    let rho = d::setup_ref(&s);
    let p = two_leg_precommit();
    let gamma = RouteLegSet::new(vec![
        RouteLegEntry {
            vault_id: V1,
            parent_root: R1,
            setup_ref: rho,
            shadow_core: SHADOWS[0],
        },
        RouteLegEntry {
            vault_id: V2,
            parent_root: R2,
            setup_ref: [0xBB; 32],
            shadow_core: SHADOWS[1],
        },
    ])
    .expect("gamma");

    let vault_id = d::vault_id(&G, &DEV, 3);
    assert_eq!(
        vault_id,
        indep::h("DSM/sofi/vault-id/v1", &[&G, &DEV, &3u64.to_be_bytes()])
    );
    assert_eq!(
        cf(&vault_id),
        "M3WG6KHDYZVS6A47EDWYJ46VW3THXDDK6SC0E9RQ6KJ43PXDF2N0"
    );

    let rel_key = d::relationship_key(&G, &DEV, &V1);
    assert_eq!(rel_key, indep::h("DSM/sofi/rel-key/v1", &[&G, &DEV, &V1]));
    assert_eq!(
        cf(&rel_key),
        "6ZP55P0686BPY6XSS9G78TSQZ3J5WM5D09FT2FG2J2ED9SM1GP4G"
    );

    let sigma = d::setup_id(&G, &DEV, 7, &V1);
    assert_eq!(
        sigma,
        indep::h(
            "DSM/sofi/setup-id/v1",
            &[&G, &DEV, &7u64.to_be_bytes(), &V1]
        )
    );
    assert_eq!(
        cf(&sigma),
        "K6EX7KQHPA6TSJQQSNZYJG88KNDP7MB2BVPCFPGHH1TMAZX9K72G"
    );

    let h0 = d::relationship_leaf_genesis(&sigma);
    assert_eq!(h0, indep::h("DSM/sofi/rel-genesis/v1", &[&sigma]));
    assert_eq!(
        cf(&h0),
        "4M35HDSA499X7MSVN4ZDJJET2APHCGQR4GK3GZSBAN3N85SBVT5G"
    );
    assert_eq!(
        d::relationship_leaf_next(&h0, &[0xEE; 32]),
        indep::h("DSM/sofi/rel-leaf/v1", &[&h0, &[0xEE; 32]])
    );
    assert_eq!(
        d::relationship_index_key(&G, &DEV, &V1),
        indep::h("DSM/sofi/rel-index/v1", &[&G, &DEV, &V1])
    );

    assert_eq!(rho, indep::h("DSM/sofi/setup-ref/v1", &[&s.encode()]));
    assert_eq!(
        cf(&rho),
        "4CBT38T1Y1PRB0XAM5K4SK80XZGVW0RN5WKNT1TRH2RP7MXXFK70"
    );
    assert_eq!(
        d::setup_signing_digest(&s),
        indep::h("DSM/sofi/setup-sign/v1", &[&s.encode()])
    );

    let pid = d::precommit_id(&p);
    assert_eq!(
        pid,
        indep::h("DSM/sofi/trader-precommit-id/v1", &[&p.encode()])
    );
    assert_eq!(
        cf(&pid),
        "Z4JXZM2DVSRH1048RAM3XHFDW020JN1SY1KMR6QJX1E37YAESHEG"
    );
    assert_eq!(
        d::precommit_signing_digest(&p),
        indep::h("DSM/sofi/trader-precommit-sign/v1", &[&p.encode()])
    );

    let f = conforming_fulfillment(&p);
    let fid = d::fulfillment_id(&f);
    assert_eq!(fid, indep::h("DSM/sofi/fulfillment-id/v1", &[&f.encode()]));
    assert_eq!(
        d::fulfillment_signing_digest(&f),
        indep::h("DSM/sofi/fulfillment-sign/v1", &[&f.encode()])
    );

    let kful = d::fulfillment_register_key(&G, &DEV, 42);
    assert_eq!(
        kful,
        indep::h("DSM/sofi/fulfillment/v1", &[&G, &DEV, &42u64.to_be_bytes()])
    );
    assert_eq!(
        cf(&kful),
        "GSGPNYKP0QQ358ATA397WQJ3FJQ667GD7VWTZW8RRV7JQJ9TG9NG"
    );

    let k0 = d::successor_attempt_key(&V1, &R1, 0);
    assert_eq!(k0, d::successor_base_key(&V1, &R1));
    assert_eq!(k0, indep::h("DSM/sofi/succ-cell/v2", &[&V1, &R1]));
    assert_eq!(
        cf(&k0),
        "3KD2BSTSD0P61CZZAR6112JSMR6TRTG3MKSPK73711MT5YQBM7RG"
    );
    let k5 = d::successor_attempt_key(&V1, &R1, 5);
    assert_eq!(
        k5,
        indep::h("DSM/sofi/succ-attempt/v1", &[&k0, &5u64.to_be_bytes()])
    );
    assert_eq!(
        cf(&k5),
        "6G398C3SJ5EMSCT6PQQ1C8W8P3TVBV2DX14PKB6B11D2HD0E4ZY0"
    );

    let seed = d::storage_seed(&V1, &R1);
    assert_eq!(seed, indep::h("DSM/sofi/storage-seed/v4", &[&V1, &R1]));
    assert_eq!(
        cf(&seed),
        "ZR62RFKH9TBX5PM9HNSQA9YTQ1FEJ0QFZHJD2EFVQ3BFK59H1W7G"
    );

    let e1 = d::external_commitment_single(&V1, &R1, &rho, &[1; 32], &[2; 32], &[3; 32], &[4; 32]);
    assert_eq!(
        e1,
        indep::h(
            "DSM/sofi/atomic-ext/v4",
            &[&V1, &R1, &rho, &[1; 32], &[2; 32], &[3; 32], &[4; 32]]
        )
    );
    assert_eq!(
        cf(&e1),
        "9SX91Y54Z2X1FMTVH1SG7730V350BDCFSCJK0ZSMXY6XPFQYV66G"
    );

    let gamma_digest = indep::h("DSM/sofi/route-leg-set/v1", &[&gamma.encode()]);
    assert_eq!(d::route_leg_set_digest(&gamma), gamma_digest);
    let e2 = d::external_commitment_route(&[1; 32], &[3; 32], &[4; 32], &gamma);
    assert_eq!(
        e2,
        indep::h(
            "DSM/sofi/atomic-ext/multivault/v5",
            &[&[1; 32], &[3; 32], &[4; 32], &gamma_digest]
        )
    );
    assert_eq!(
        cf(&e2),
        "2YKH5ZG0BXMBGZ00JQ3QB1VHFA2700ZMKBM2T86Q925CSW6FB96G"
    );

    assert_eq!(
        d::preimage_locator(&e2),
        indep::h("DSM/sofi/preimage-locator/v1", &[&e2])
    );
    assert_eq!(
        d::vault_genesis_locator(&vault_id),
        indep::h("DSM/sofi/vault-genesis-locator/v1", &[&vault_id])
    );
    assert_eq!(
        d::trader_core_digest(b"core"),
        indep::h("DSM/sofi/trader-core/v3", &[b"core"])
    );
    assert_eq!(
        d::dlv_core_digest(b"core"),
        indep::h("DSM/sofi/dlv-core/v3", &[b"core"])
    );
    assert_eq!(
        d::settlement_core_digest(b"core"),
        indep::h("DSM/sofi/settlement-core/v3", &[b"core"])
    );
    assert_eq!(
        d::claim_ref(b"envelope"),
        indep::h("DSM/economic-root-claim-envelope/v1", &[b"envelope"]),
        "ClaimRef is the existing exact-envelope digest, not a new identity"
    );
}

#[test]
fn fisher_yates_matches_the_independent_algorithm_and_the_frozen_order() {
    let seed = d::storage_seed(&V1, &R1);
    let view: Vec<Vec<u8>> = (1u8..=5).map(|k| vec![k; 8]).collect();
    let perm = fisher_yates::permute(&seed, &view).expect("permute");
    assert_eq!(perm, indep::fisher_yates(&seed, &view));
    let order: Vec<u8> = perm.iter().map(|m| m[0]).collect();
    assert_eq!(order, vec![1, 5, 3, 2, 4], "frozen routing order");
    for s in 0u8..16 {
        let sd = [s; 32];
        assert_eq!(
            fisher_yates::permute(&sd, &view).expect("permute"),
            indep::fisher_yates(&sd, &view)
        );
    }
}

#[test]
fn identities_are_over_bodies_so_signatures_never_fork_them() {
    // No identity function takes a signature: an alternate valid envelope over
    // the same body is the same object.
    let p = two_leg_precommit();
    assert_eq!(
        d::precommit_id(&p),
        d::precommit_id(&TraderPrecommitBody::decode(&p.encode()).expect("decode"))
    );
    let f = conforming_fulfillment(&p);
    assert_eq!(d::fulfillment_id(&f), d::fulfillment_id(&f.clone()));
    // Exactly one policy-fulfillment identity per leg.
    let a = derive_policy_fulfillments(&p, &SHADOWS).expect("derive");
    let b = derive_policy_fulfillments(&p, &SHADOWS).expect("derive");
    assert_eq!(a, b);
    assert_ne!(
        d::policy_fulfillment_id(&a[0]),
        d::policy_fulfillment_id(&a[1])
    );
}

#[test]
fn successor_attempt_keys_are_o1_and_distinct() {
    let base = d::successor_base_key(&V1, &R1);
    assert_ne!(d::successor_attempt_key(&V1, &R1, 1), base);
    assert_ne!(
        d::successor_attempt_key(&V1, &R1, 1),
        d::successor_attempt_key(&V1, &R1, 2)
    );
    // An attacker-chosen index costs one hash.
    let _ = d::successor_attempt_key(&V1, &R1, u64::MAX);
}

// ── negative vectors ───────────────────────────────────────────────────────

#[test]
fn fulfillment_conformance_refuses_every_malformed_exercise() {
    let p = two_leg_precommit();
    let good = conforming_fulfillment(&p);
    assert_eq!(
        check_fulfillment_against_precommit(&p, &good, &SHADOWS),
        Ok(())
    );

    // Missing a policy-fulfillment witness: one id for a two-leg P.
    let ids = good.policy_fulfillment_set().to_vec();
    let short = TraderFulfillmentBody::new(
        *good.precommit_id(),
        vec![ids[0]],
        good.attempts().to_vec(),
        42,
        ALG,
        &KEY,
    )
    .expect("structurally valid");
    assert_eq!(
        check_fulfillment_against_precommit(&p, &short, &SHADOWS),
        Err(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical)
    );

    // An extra witness is now CANONICAL BYTES — the codec bound is the byte
    // bound, not the beta route cap [R16-6] — and is refused one layer up,
    // where completeness is decided: the set is not the derived one.
    let mut three = ids.clone();
    three.push([0xFF; 32]);
    let extra = TraderFulfillmentBody::new(
        *good.precommit_id(),
        three,
        good.attempts().to_vec(),
        42,
        ALG,
        &KEY,
    )
    .expect("a third witness encodes; cardinality is not the codec's business");
    assert_eq!(
        check_fulfillment_against_precommit(&p, &extra, &SHADOWS),
        Err(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical)
    );

    // A witness bound to another shadow (another E / parent binding) is not derived.
    assert_eq!(
        check_fulfillment_against_precommit(&p, &good, &[[5; 32], [0x7F; 32]]),
        Err(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical)
    );

    // Another P.
    let other = precommit(vec![PrecommitLeg {
        vault_id: V1,
        parent_root: R1,
        setup_ref: [0xBB; 32],
    }]);
    assert_eq!(
        check_fulfillment_against_precommit(&other, &good, &SHADOWS[..1]),
        Err(FulfillmentConformanceError::PrecommitMismatch)
    );

    // Wrong successor position.
    let wrong_q = TraderFulfillmentBody::new(
        *good.precommit_id(),
        ids.clone(),
        good.attempts().to_vec(),
        43,
        ALG,
        &KEY,
    )
    .expect("structurally valid");
    assert_eq!(
        check_fulfillment_against_precommit(&p, &wrong_q, &SHADOWS),
        Err(FulfillmentConformanceError::PositionNotSuccessor {
            expected: 42,
            got: 43
        })
    );

    // Signed under another key.
    let wrong_key = TraderFulfillmentBody::new(
        *good.precommit_id(),
        ids.clone(),
        good.attempts().to_vec(),
        42,
        ALG,
        &[0x56; 64],
    )
    .expect("structurally valid");
    assert_eq!(
        check_fulfillment_against_precommit(&p, &wrong_key, &SHADOWS),
        Err(FulfillmentConformanceError::KeyMismatch)
    );

    // Attempts not covering P's legs.
    let wrong_attempts = TraderFulfillmentBody::new(
        *good.precommit_id(),
        ids,
        vec![
            AttemptEntry {
                vault_id: V1,
                attempt: 0,
            },
            AttemptEntry {
                vault_id: [0x68; 32],
                attempt: 0,
            },
        ],
        42,
        ALG,
        &KEY,
    )
    .expect("structurally valid");
    assert_eq!(
        check_fulfillment_against_precommit(&p, &wrong_attempts, &SHADOWS),
        Err(FulfillmentConformanceError::AttemptsDoNotCoverLegs)
    );
}

#[test]
fn decoders_refuse_wrong_envelopes_truncation_and_trailing_bytes() {
    let p = two_leg_precommit();
    let bytes = p.encode();

    let mut wrong_class = bytes.clone();
    wrong_class[1] = 0x38;
    assert!(matches!(
        TraderPrecommitBody::decode(&wrong_class),
        Err(DecodeError::WrongClass { .. })
    ));

    let mut wrong_schema = bytes.clone();
    wrong_schema[3] = 2;
    assert!(matches!(
        TraderPrecommitBody::decode(&wrong_schema),
        Err(DecodeError::UnknownSchema { got: 2 })
    ));

    // Little-endian class bytes read as a different class.
    let mut le = bytes.clone();
    le.swap(0, 1);
    assert!(matches!(
        TraderPrecommitBody::decode(&le),
        Err(DecodeError::WrongClass { .. })
    ));

    assert!(matches!(
        TraderPrecommitBody::decode(&bytes[..bytes.len() - 1]),
        Err(DecodeError::Truncated)
    ));

    // F restating a field, or G carrying a signature or attempt index: extra
    // bytes after the table are refused.
    let f = conforming_fulfillment(&p);
    let mut f_extra = f.encode();
    f_extra.extend_from_slice(&[0xC1; 32]);
    assert!(matches!(
        TraderFulfillmentBody::decode(&f_extra),
        Err(DecodeError::TrailingBytes { extra: 32 })
    ));
    let g = derive_policy_fulfillments(&p, &SHADOWS).expect("derive")[0];
    let mut g_extra = g.encode();
    g_extra.extend_from_slice(&0u64.to_be_bytes());
    assert!(matches!(
        DlvPolicyFulfillmentBody::decode(&g_extra),
        Err(DecodeError::TrailingBytes { extra: 8 })
    ));

    // A hostile sequence count is refused before any allocation.
    let pid = d::precommit_id(&p);
    let hostile = [indep::env(0x0039), pid.to_vec(), indep::u32be(u32::MAX)].concat();
    assert!(
        matches!(TraderFulfillmentBody::decode(&hostile), Err(DecodeError::Invalid(m)) if m.contains("policy fulfillment set"))
    );
}

#[test]
fn keys_and_algorithms_are_validated() {
    assert!(matches!(
        SofiSetupBody::new(G, DEV, 7, V1, [0; 32], [0; 32], 0x7777, &KEY),
        Err(SofiWireError::UnknownSignatureAlg { alg: 0x7777 })
    ));
    assert!(matches!(
        SofiSetupBody::new(G, DEV, 7, V1, [0; 32], [0; 32], ALG, &KEY[..63]),
        Err(SofiWireError::KeyLengthMismatch {
            expected: 64,
            got: 63
        })
    ));
    // An altered algorithm in the bytes changes the signed body and fails to decode.
    let mut b = setup_body().encode();
    let alg_at = 4 + 32 + 32 + 8 + 32 + 32 + 32;
    b[alg_at + 1] = 0x02;
    assert!(matches!(
        SofiSetupBody::decode(&b),
        Err(DecodeError::Invalid(_))
    ));
}

#[test]
fn precommit_legs_and_route_leg_sets_are_canonical() {
    let leg = |v: [u8; 32]| PrecommitLeg {
        vault_id: v,
        parent_root: R1,
        setup_ref: [0; 32],
    };
    assert!(matches!(
        TraderPrecommitBody::new(
            G,
            DEV,
            1,
            ParentClaimRef::SingleRoot { claim_ref: [0; 32] },
            [0; 32],
            vec![leg(V2), leg(V1)],
            [0; 32],
            [0; 32],
            [0; 32],
            ALG,
            &KEY
        ),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));
    assert!(matches!(
        TraderPrecommitBody::new(
            G,
            DEV,
            1,
            ParentClaimRef::SingleRoot { claim_ref: [0; 32] },
            [0; 32],
            vec![leg(V1), leg(V1)],
            [0; 32],
            [0; 32],
            [0; 32],
            ALG,
            &KEY
        ),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));
    assert!(matches!(
        TraderPrecommitBody::new(
            G,
            DEV,
            1,
            ParentClaimRef::SingleRoot { claim_ref: [0; 32] },
            [0; 32],
            vec![],
            [0; 32],
            [0; 32],
            [0; 32],
            ALG,
            &KEY
        ),
        Err(SofiWireError::Cardinality { .. })
    ));
    let entry = |v: [u8; 32]| RouteLegEntry {
        vault_id: v,
        parent_root: R1,
        setup_ref: [0; 32],
        shadow_core: [0; 32],
    };
    assert!(matches!(
        RouteLegSet::new(vec![entry(V1)]),
        Err(SofiWireError::Cardinality { min: 2, .. })
    ));
    assert!(matches!(
        RouteLegSet::new(vec![entry(V1), entry(V1)]),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));
}

#[test]
fn counters_are_checked_never_wrapped() {
    assert!(next_position(u64::MAX).is_err());
    assert!(next_attempt(u64::MAX).is_err());
    assert!(next_generation(u64::MAX).is_err());
    assert_eq!(next_position(41), Ok(42));
    assert!(matches!(
        TraderPrecommitBody::new(
            G,
            DEV,
            u64::MAX,
            ParentClaimRef::SingleRoot { claim_ref: [0; 32] },
            [0; 32],
            vec![PrecommitLeg {
                vault_id: V1,
                parent_root: R1,
                setup_ref: [0; 32]
            }],
            [0; 32],
            [0; 32],
            [0; 32],
            ALG,
            &KEY
        ),
        Err(SofiWireError::CounterOverflow { .. })
    ));
}

#[test]
fn closure_index_enforces_bounds_order_and_current_e_exclusion() {
    let addr = |n: u16| ValidationRef::ContentAddr {
        object_class: 0x001C,
        addr: [(n % 251) as u8; 32],
    };
    // Exactly 64 distinct refs is accepted; 65 is refused.
    let mut refs: Vec<ValidationRef> = (0u16..64)
        .map(|n| ValidationRef::SingleRootClaim {
            claim_ref: {
                let mut a = [0u8; 32];
                a[..2].copy_from_slice(&n.to_be_bytes());
                a
            },
        })
        .collect();
    refs.sort_by_key(|r| r.encode());
    assert!(PreEClosureIndex::new(refs.clone()).is_ok());
    let mut over = refs.clone();
    over.push(ValidationRef::Setup {
        setup_ref: [0xFF; 32],
    });
    over.sort_by_key(|r| r.encode());
    assert!(matches!(
        PreEClosureIndex::new(over),
        Err(SofiWireError::Cardinality {
            max: 64,
            got: 65,
            ..
        })
    ));

    // Duplicates and misorder are malformed.
    assert!(matches!(
        PreEClosureIndex::new(vec![addr(1), addr(1)]),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));
    assert!(matches!(
        PreEClosureIndex::new(vec![addr(2), addr(1)]),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));

    // P, G, F, C_q, aux evidence, records, outcome cells and the index itself
    // may never be content-bound; neither may bodies with their own ref variant.
    for class in CLOSURE_FORBIDDEN_CONTENT_CLASSES {
        assert!(
            matches!(
                PreEClosureIndex::new(vec![ValidationRef::ContentAddr {
                    object_class: *class,
                    addr: [1; 32]
                }]),
                Err(SofiWireError::ForbiddenClosureClass { .. })
            ),
            "{class:#06x} must be refused"
        );
    }
    // A prior conditional position (an earlier E) is admissible.
    assert!(PreEClosureIndex::new(vec![ValidationRef::ConditionalClaim {
        genesis: G,
        device_id: DEV,
        position: 3,
        fulfillment_id: [9; 32]
    }])
    .is_ok());
}

#[test]
fn successor_arithmetic_and_validation_composition() {
    use CellObservation::{Empty, Holds, Unknown};
    let a = [0xA; 32];
    let b = [0xB; 32];
    assert_eq!(
        resolve(&[Holds(a), Holds(a), Holds(a), Holds(b), Holds(b)]),
        CellResolution::Final(a)
    );
    assert_eq!(
        resolve(&[Holds(a), Holds(a), Holds(b), Holds(b), Holds([0xC; 32])]),
        CellResolution::Dead
    );
    assert_eq!(
        resolve(&[Holds(a), Holds(a), Holds(b), Holds(b), Unknown]),
        CellResolution::Unresolved
    );
    assert_eq!(
        resolve(&[Holds(a), Holds(a), Holds(b), Holds(b), Empty]),
        CellResolution::Unresolved
    );
    assert_eq!(
        Validation::Unavailable.and(Validation::Valid),
        Validation::Unavailable
    );
    assert_eq!(
        Validation::Unavailable.and(Validation::Invalid),
        Validation::Invalid
    );
}

#[test]
fn bounds_are_the_ruled_values() {
    assert_eq!(MAX_CLOSURE_REFS, 64);
    assert_eq!(MAX_CLOSURE_OBJECT_BYTES, 256 * 1024);
    assert_eq!(MAX_AUTH_ENVELOPES, 16);
    assert_eq!(MAX_VALIDATION_FETCH_BYTES, 4 * 1024 * 1024);
    assert_eq!(MAX_PROVENANCE_FANOUT, 16);
    assert_eq!(MAX_SETTLEMENT_PREIMAGE_BYTES, 256 * 1024);
    assert_eq!(
        (STORAGE_MEMBER_COUNT, STORAGE_FINALITY_COUNT, ROUTE_MAX_LEGS),
        (5, 3, 2)
    );
}

/// The signed transport envelope, byte for byte, from the field table.
///
/// `0x005C` carries a canonical SoFi body and the trader's signature over it.
/// The layout is fixed here independently of the production encoder:
/// envelope(class, schema) ‖ body_class ‖ len(body) ‖ body ‖ alg ‖ len(sig) ‖ sig.
///
/// The vector also pins the property the envelope exists to NOT have: the
/// object's identity is `precommit_id` over the BODY, so these envelope bytes
/// appear nowhere in it.
#[test]
fn the_signed_envelope_matches_the_independent_encoder() {
    use dsm::ccb::class;

    // A stand-in body and signature: this test fixes the ENVELOPE's layout,
    // and the inner body has its own vectors elsewhere.
    let body = dsm::sofi::wire::TraderPrecommitBody::new(
        G,
        DEV,
        5,
        dsm::sofi::wire::ParentClaimRef::SingleRoot {
            claim_ref: [0x66; 32],
        },
        [0x0E; 32],
        vec![dsm::sofi::wire::PrecommitLeg {
            vault_id: [0xC1; 32],
            parent_root: [0x62; 32],
            setup_ref: [0x55; 32],
        }],
        [0xA1; 32],
        [0x61; 32],
        [0x77; 32],
        dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F,
        &[0x33; 64],
    )
    .expect("a well-formed precommit body");
    let body_bytes = body.encode();
    let signature = vec![0x44u8; 49_856];

    let produced = dsm::sofi::wire::SignedSofiObject::new(
        class::SOFI_TRADER_PRECOMMIT_BODY,
        &body_bytes,
        dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F,
        &signature,
    )
    .expect("a well-formed envelope")
    .encode();

    let expected = [
        indep::env(class::SOFI_SIGNED_OBJECT),
        indep::u16be(class::SOFI_TRADER_PRECOMMIT_BODY),
        indep::u32be(body_bytes.len() as u32),
        body_bytes.clone(),
        indep::u16be(dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F),
        indep::u32be(signature.len() as u32),
        signature.clone(),
    ]
    .concat();
    assert_eq!(produced, expected, "the envelope layout is frozen here");

    // IDENTITY IS THE BODY. The envelope bytes are not in it.
    let id = dsm::sofi::derive::precommit_id(&body);
    assert_eq!(
        id,
        dsm::sofi::derive::precommit_id(
            &dsm::sofi::wire::TraderPrecommitBody::decode(&body_bytes).unwrap()
        )
    );
    assert!(
        !produced.windows(32).any(|w| w == id),
        "the identity is derived from the body, never carried in the envelope"
    );
}

/// Registry collision guard: every `class::` discriminant is unique, and a
/// number the registry burned is never live again. A class allocated on main
/// before this lands shows up here as a duplicate value; a burned number
/// reappearing as a live class shows up as a double allocation.
#[test]
fn class_discriminants_do_not_collide() {
    let src = include_str!("../src/ccb/mod.rs");
    fn consts(src: &str, module: &str) -> std::collections::BTreeMap<u16, String> {
        let start = src.find(module).expect("module");
        let body = &src[start..];
        let end = body.find("\n}\n").expect("module end");
        let mut seen = std::collections::BTreeMap::new();
        for line in body[..end].lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("pub const ") {
                let name = rest.split(':').next().expect("name").to_string();
                if let Some(hex) = rest.split("= 0x").nth(1) {
                    let v = u16::from_str_radix(hex.trim_end_matches(';'), 16).expect("hex class");
                    if let Some(prev) = seen.insert(v, name.clone()) {
                        panic!("class {v:#06x} allocated twice: {prev} and {name}");
                    }
                }
            }
        }
        seen
    }
    let live = consts(src, "pub mod class {");
    let burned = consts(src, "pub mod burned_class {");
    for (v, name) in &burned {
        assert!(
            !live.contains_key(v),
            "burned class {v:#06x} ({name}) is live again as {}",
            live[v]
        );
        assert!(
            dsm::ccb::burned_class::is_burned_class(*v),
            "{name} is declared under burned_class but is not in burned_class::ALL"
        );
    }
    // The SoFi v8 range is fully accounted for: every number is a live class
    // or a burned one, and the demolition's seven are burned.
    for v in 0x0036u16..=0x004A {
        assert!(
            live.contains_key(&v) || burned.contains_key(&v),
            "{v:#06x} is neither a live SoFi v8 class nor a burned one"
        );
    }
    for v in 0x0043u16..=0x0049 {
        assert!(
            burned.contains_key(&v) && !live.contains_key(&v),
            "{v:#06x} was the resolution-record / outcome-cell family and must stay burned"
        );
    }
}

/// E1c-2a's new bytes, against the independent hasher and a frozen golden.
///
/// Two objects are being frozen: the key the owner's creation record occupies
/// in `R_econ`, and the leaf value committed at it. Both are checked against
/// bytes written from the tables here — never against the production encoder,
/// which is the thing under test.
#[test]
fn the_creation_key_and_leaf_match_the_independent_hasher() {
    const VAULT: [u8; 32] = [0xC1; 32];

    // 1. `vault_creation_key = H(vault-creation-key/v1 ‖ G_o ‖ DevID_o ‖ v)`.
    let key = d::vault_creation_key(&G, &DEV, &VAULT);
    assert_eq!(
        key,
        indep::h("DSM/sofi/vault-creation-key/v1", &[&G, &DEV, &VAULT])
    );
    assert_eq!(
        cf(&key),
        "QGD7JDM2EVWH2V26RSB7XE26NBT11265N97C4TAJX7TH3H3YPZ3G"
    );

    // It is NOT the storage locator: an economic address and a storage
    // coordinate are different namespaces, and one derivation serving both is
    // how they collide.
    assert_ne!(key, d::vault_genesis_locator(&VAULT));

    // 2. The creation leaf's CCB bytes are the `0x005B` wire object's — one
    //    encoding, so the record in `R_econ` and the record the operation
    //    carries cannot drift.
    let record = VaultCreation {
        vault_id: VAULT,
        genesis_root: [0x0C; 32],
        amount_a: 1_000,
        amount_b: 2_000,
    };
    let expected_ccb = [
        indep::env(0x005B),
        VAULT.to_vec(),
        [0x0C; 32].to_vec(),
        indep::u64be(1_000),
        indep::u64be(2_000),
    ]
    .concat();
    assert_eq!(record.encode(), expected_ccb);

    // 3. And the economic leaf VALUE over those exact bytes.
    let state = dsm::economic::state::EconomicLeafState::VaultCreation(record);
    assert_eq!(state.encode().expect("encodable"), expected_ccb);
    let value = state.leaf_value().expect("a leaf value");
    assert_eq!(
        value,
        indep::h("DSM/economic-leaf-state/v1", &[&expected_ccb])
    );
    assert_eq!(
        cf(&value),
        "403GTT1AX78AHE9YA46SFXNPK0Y706N0P6TZDY161WKTSQ54M740"
    );

    // 4. The leaf derives its own key from the owner's coordinates.
    assert_eq!(state.leaf_key(&G, &DEV), key);
}
