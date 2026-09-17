// SPDX-License-Identifier: Apache-2.0

//! SoFi v8 — the DLV tree, the cores, `B°` and vault genesis (E1b-2).
//!
//! `indep` is a SECOND implementation written from the field tables in
//! `dsm::sofi::wire` and the derivation list in `dsm::sofi::derive`, sharing no
//! encoder, hasher or Base32 code with the crate. Agreement between the two,
//! plus the frozen golden digests, is the evidence; a round trip through one
//! implementation alone is not.

#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

use dsm::ccb::decode::DecodeError;
use dsm::sofi::derive as d;
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

    pub fn path(sibs: &[[u8; 32]]) -> Vec<u8> {
        let mut out = u32be(sibs.len() as u32);
        for s in sibs {
            out.extend_from_slice(s);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub fn vault_state(
        owner_genesis: &[u8; 32],
        owner_device: &[u8; 32],
        create_position: u64,
        market: &[u8; 32],
        fee: &[u8; 32],
        release: &[u8; 32],
        storage_set: &[u8; 32],
        generation: u64,
        reserve_a: u64,
        reserve_b: u64,
        status: u16,
    ) -> Vec<u8> {
        [
            env(0x004B),
            owner_genesis.to_vec(),
            owner_device.to_vec(),
            u64be(create_position),
            market.to_vec(),
            fee.to_vec(),
            release.to_vec(),
            storage_set.to_vec(),
            u64be(generation),
            u64be(reserve_a),
            u64be(reserve_b),
            u16be(status),
        ]
        .concat()
    }

    pub fn vault_relationship(g: &[u8; 32], dev: &[u8; 32], leaf: &[u8; 32]) -> Vec<u8> {
        [env(0x004C), g.to_vec(), dev.to_vec(), leaf.to_vec()].concat()
    }

    pub fn trader_relationship(v: &[u8; 32], leaf: &[u8; 32]) -> Vec<u8> {
        [env(0x004D), v.to_vec(), leaf.to_vec()].concat()
    }

    pub fn entry_mutation(
        key: &[u8; 32],
        pre: &[u8; 32],
        post: &[u8; 32],
        sibs: &[[u8; 32]],
    ) -> Vec<u8> {
        [
            env(0x004E),
            key.to_vec(),
            pre.to_vec(),
            post.to_vec(),
            path(sibs),
        ]
        .concat()
    }

    pub fn entry_read(key: &[u8; 32], value: &[u8; 32], sibs: &[[u8; 32]]) -> Vec<u8> {
        [env(0x004F), key.to_vec(), value.to_vec(), path(sibs)].concat()
    }

    pub fn entry_relationship(
        g: &[u8; 32],
        dev: &[u8; 32],
        v: &[u8; 32],
        base: &[u8; 32],
        sibs: &[[u8; 32]],
    ) -> Vec<u8> {
        [
            env(0x0050),
            g.to_vec(),
            dev.to_vec(),
            v.to_vec(),
            base.to_vec(),
            path(sibs),
        ]
        .concat()
    }

    pub fn trader_core(
        g: &[u8; 32],
        dev: &[u8; 32],
        position: u64,
        pre_root: &[u8; 32],
        entries: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut out = [
            env(0x0051),
            g.to_vec(),
            dev.to_vec(),
            u64be(position),
            pre_root.to_vec(),
            u32be(entries.len() as u32),
        ]
        .concat();
        for e in entries {
            out.extend_from_slice(e);
        }
        out
    }

    pub fn dlv_core(
        vault_id: &[u8; 32],
        pre_root: &[u8; 32],
        g: &[u8; 32],
        dev: &[u8; 32],
        base: &[u8; 32],
        entries: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut out = [
            env(0x0052),
            vault_id.to_vec(),
            pre_root.to_vec(),
            g.to_vec(),
            dev.to_vec(),
            base.to_vec(),
            u32be(entries.len() as u32),
        ]
        .concat();
        for e in entries {
            out.extend_from_slice(e);
        }
        out
    }

    /// One hop: vault, parent, setup, token_in, amount_in, token_out, amount_out.
    pub type Hop = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], u64, [u8; 32], u64);

    pub fn hops(hs: &[Hop]) -> Vec<u8> {
        let mut out = u32be(hs.len() as u32);
        for (v, pr, sr, ti, ai, to, ao) in hs {
            out.extend_from_slice(v);
            out.extend_from_slice(pr);
            out.extend_from_slice(sr);
            out.extend_from_slice(ti);
            out.extend_from_slice(&u64be(*ai));
            out.extend_from_slice(to);
            out.extend_from_slice(&u64be(*ao));
        }
        out
    }

    pub fn closure_empty() -> Vec<u8> {
        [env(0x0041), u32be(0)].concat()
    }

    pub fn owner_origin() -> Vec<u8> {
        env(0x0055)
    }

    pub fn owner_successor(class: u16, addr: &[u8; 32]) -> Vec<u8> {
        [env(0x0056), u16be(class), addr.to_vec()].concat()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn settlement_swap(
        token_in: &[u8; 32],
        amount_in: u64,
        token_out: &[u8; 32],
        exact_out: u64,
        hs: &[Hop],
        trader_core: &[u8; 32],
        dlv_cores: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut out = [
            env(0x0053),
            token_in.to_vec(),
            u64be(amount_in),
            token_out.to_vec(),
            u64be(exact_out),
            hops(hs),
            trader_core.to_vec(),
            u32be(dlv_cores.len() as u32),
        ]
        .concat();
        for c in dlv_cores {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&closure_empty());
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub fn settlement_close(
        vault_id: &[u8; 32],
        parent_root: &[u8; 32],
        setup_ref: &[u8; 32],
        authority: &[u8],
        reserve_a: u64,
        reserve_b: u64,
        trader_core: &[u8; 32],
        dlv_core: &[u8; 32],
    ) -> Vec<u8> {
        [
            env(0x0054),
            vault_id.to_vec(),
            parent_root.to_vec(),
            setup_ref.to_vec(),
            authority.to_vec(),
            u64be(reserve_a),
            u64be(reserve_b),
            trader_core.to_vec(),
            dlv_core.to_vec(),
            closure_empty(),
        ]
        .concat()
    }

    pub fn route_digest_swap(hs: &[Hop]) -> Vec<u8> {
        [env(0x0057), hops(hs)].concat()
    }

    pub fn route_digest_close(
        vault_id: &[u8; 32],
        parent_root: &[u8; 32],
        setup_ref: &[u8; 32],
        reserve_a: u64,
        reserve_b: u64,
    ) -> Vec<u8> {
        [
            env(0x0058),
            vault_id.to_vec(),
            parent_root.to_vec(),
            setup_ref.to_vec(),
            u64be(reserve_a),
            u64be(reserve_b),
        ]
        .concat()
    }

    pub fn settlement_preimage(body: &[u8], trader_core: &[u8], dlv_cores: &[Vec<u8>]) -> Vec<u8> {
        let mut out = [
            env(0x0059),
            body.to_vec(),
            trader_core.to_vec(),
            u32be(dlv_cores.len() as u32),
        ]
        .concat();
        for c in dlv_cores {
            out.extend_from_slice(c);
        }
        out
    }

    pub fn vault_genesis(
        owner_genesis: &[u8; 32],
        owner_device: &[u8; 32],
        create_position: u64,
        state: &[u8],
    ) -> Vec<u8> {
        [
            env(0x005A),
            owner_genesis.to_vec(),
            owner_device.to_vec(),
            u64be(create_position),
            state.to_vec(),
        ]
        .concat()
    }

    pub fn vault_creation(
        vault_id: &[u8; 32],
        genesis_root: &[u8; 32],
        amount_a: u64,
        amount_b: u64,
    ) -> Vec<u8> {
        [
            env(0x005B),
            vault_id.to_vec(),
            genesis_root.to_vec(),
            u64be(amount_a),
            u64be(amount_b),
        ]
        .concat()
    }
}

// ── fixtures ───────────────────────────────────────────────────────────────

fn b(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn sibs() -> Vec<[u8; 32]> {
    (0..256u32).map(|i| b((i % 251) as u8)).collect()
}

fn cf(x: &[u8; 32]) -> String {
    indep::crockford(x)
}

/// The codec bound is the byte bound, not the beta route cap [R16-6]. Checked
/// at compile time, so it cannot be true only for the values a test picked.
const _: () = assert!(CANONICAL_MAX_LEGS > ROUTE_MAX_LEGS);

const OWNER_G: [u8; 32] = [0x11; 32];
const OWNER_DEV: [u8; 32] = [0x22; 32];
const P_CREATE: u64 = 7;

fn state_leaf(status: u16, generation: u64, reserve_a: u64, reserve_b: u64) -> VaultStateLeaf {
    VaultStateLeaf {
        owner_genesis: OWNER_G,
        owner_device_id: OWNER_DEV,
        create_position: P_CREATE,
        market_policy: b(0x31),
        fee_policy: b(0x32),
        release_policy: b(0x33),
        storage_set_id: b(0x34),
        generation,
        reserve_a,
        reserve_b,
        status,
    }
}

fn mutation_entry(key: [u8; 32]) -> CoreEntry {
    CoreEntry::Mutation {
        key,
        pre: b(0x41),
        post: b(0x42),
        path: sibs(),
    }
}

fn hop(vault: u8, amount_in: u64, amount_out: u64) -> SwapHop {
    SwapHop {
        vault_id: b(vault),
        parent_root: b(vault ^ 0x0F),
        setup_ref: b(vault ^ 0xF0),
        token_in: b(0x51),
        amount_in,
        token_out: b(0x52),
        amount_out,
    }
}

fn indep_hop(h: &SwapHop) -> indep::Hop {
    (
        h.vault_id,
        h.parent_root,
        h.setup_ref,
        h.token_in,
        h.amount_in,
        h.token_out,
        h.amount_out,
    )
}

fn trader_core(keys: &[[u8; 32]]) -> TraderCore {
    let mut entries: Vec<CoreEntry> = keys.iter().map(|k| mutation_entry(*k)).collect();
    entries.sort_by_key(|e| e.key());
    TraderCore::new(OWNER_G, OWNER_DEV, 9, b(0x61), entries).unwrap()
}

fn dlv_core(vault: u8) -> DlvCore {
    DlvCore::new(
        b(vault),
        b(0x62),
        OWNER_G,
        OWNER_DEV,
        b(0x63),
        vec![mutation_entry(b(0x71))],
    )
    .unwrap()
}

// ── the objects, against the independent encoder ───────────────────────────

#[test]
fn every_new_object_matches_the_independent_encoder_and_round_trips() {
    let leaf = state_leaf(VAULT_STATUS_ACTIVE, 3, 1_000, 2_000);
    assert_eq!(
        leaf.encode().unwrap(),
        indep::vault_state(
            &OWNER_G,
            &OWNER_DEV,
            P_CREATE,
            &b(0x31),
            &b(0x32),
            &b(0x33),
            &b(0x34),
            3,
            1_000,
            2_000,
            VAULT_STATUS_ACTIVE
        )
    );
    assert_eq!(
        VaultStateLeaf::decode(&leaf.encode().unwrap()).unwrap(),
        leaf
    );

    let vrel = VaultRelationshipLeaf {
        trader_genesis: b(0x81),
        trader_device_id: b(0x82),
        leaf: b(0x83),
    };
    assert_eq!(
        vrel.encode(),
        indep::vault_relationship(&b(0x81), &b(0x82), &b(0x83))
    );
    assert_eq!(VaultRelationshipLeaf::decode(&vrel.encode()).unwrap(), vrel);

    let trel = TraderRelationshipLeaf {
        vault_id: b(0x84),
        leaf: b(0x85),
    };
    assert_eq!(
        trel.encode(),
        indep::trader_relationship(&b(0x84), &b(0x85))
    );
    assert_eq!(
        TraderRelationshipLeaf::decode(&trel.encode()).unwrap(),
        trel
    );

    let path = sibs();
    let mutation = mutation_entry(b(0x91));
    assert_eq!(
        mutation.encode().unwrap(),
        indep::entry_mutation(&b(0x91), &b(0x41), &b(0x42), &path)
    );
    let read = CoreEntry::Read {
        key: b(0x92),
        value: b(0x93),
        path: path.clone(),
    };
    assert_eq!(
        read.encode().unwrap(),
        indep::entry_read(&b(0x92), &b(0x93), &path)
    );
    let rel = CoreEntry::Relationship {
        genesis: OWNER_G,
        device_id: OWNER_DEV,
        vault_id: b(0x94),
        base: b(0x95),
        path: path.clone(),
    };
    assert_eq!(
        rel.encode().unwrap(),
        indep::entry_relationship(&OWNER_G, &OWNER_DEV, &b(0x94), &b(0x95), &path)
    );
    // A relationship entry derives its key from its key material.
    assert_eq!(
        rel.key(),
        d::relationship_key(&OWNER_G, &OWNER_DEV, &b(0x94))
    );
    for e in [&mutation, &read, &rel] {
        assert_eq!(&CoreEntry::decode(&e.encode().unwrap()).unwrap(), e);
    }

    let tc = trader_core(&[b(0x71)]);
    assert_eq!(
        tc.encode().unwrap(),
        indep::trader_core(
            &OWNER_G,
            &OWNER_DEV,
            9,
            &b(0x61),
            &[indep::entry_mutation(&b(0x71), &b(0x41), &b(0x42), &path)]
        )
    );
    assert_eq!(TraderCore::decode(&tc.encode().unwrap()).unwrap(), tc);

    let vc = dlv_core(0xA1);
    assert_eq!(
        vc.encode().unwrap(),
        indep::dlv_core(
            &b(0xA1),
            &b(0x62),
            &OWNER_G,
            &OWNER_DEV,
            &b(0x63),
            &[indep::entry_mutation(&b(0x71), &b(0x41), &b(0x42), &path)]
        )
    );
    assert_eq!(DlvCore::decode(&vc.encode().unwrap()).unwrap(), vc);

    let creation = VaultCreation {
        vault_id: b(0xB1),
        genesis_root: b(0xB2),
        amount_a: 10,
        amount_b: 20,
    };
    assert_eq!(
        creation.encode(),
        indep::vault_creation(&b(0xB1), &b(0xB2), 10, 20)
    );
    assert_eq!(VaultCreation::decode(&creation.encode()).unwrap(), creation);

    let genesis = VaultGenesisPreimage {
        owner_genesis: OWNER_G,
        owner_device_id: OWNER_DEV,
        create_position: P_CREATE,
        state: state_leaf(VAULT_STATUS_ACTIVE, 0, 500, 600),
    };
    assert_eq!(
        genesis.encode().unwrap(),
        indep::vault_genesis(
            &OWNER_G,
            &OWNER_DEV,
            P_CREATE,
            &genesis.state.encode().unwrap()
        )
    );
    assert_eq!(
        VaultGenesisPreimage::decode(&genesis.encode().unwrap()).unwrap(),
        genesis
    );
    // The vault id is recomputed from the preimage, never carried.
    assert_eq!(
        genesis.vault_id(),
        d::vault_id(&OWNER_G, &OWNER_DEV, P_CREATE)
    );
}

#[test]
fn both_settlement_branches_and_both_authorities_match_and_round_trip() {
    let hops = vec![hop(0xC1, 100, 90), hop(0xC2, 90, 80)];
    let ihops: Vec<indep::Hop> = hops.iter().map(indep_hop).collect();
    let swap = SettlementBody::Swap {
        token_in: b(0x51),
        amount_in: 100,
        token_out: b(0x52),
        exact_out: 80,
        hops: hops.clone(),
        trader_core: b(0xD1),
        dlv_cores: vec![b(0xC1), b(0xC2)],
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    assert_eq!(
        swap.encode().unwrap(),
        indep::settlement_swap(
            &b(0x51),
            100,
            &b(0x52),
            80,
            &ihops,
            &b(0xD1),
            &[b(0xC1), b(0xC2)]
        )
    );
    assert_eq!(
        SettlementBody::decode(&swap.encode().unwrap()).unwrap(),
        swap
    );

    for authority in [
        OwnerAuthority::Origin,
        OwnerAuthority::DsmSuccessor {
            authority_class: 0x1234,
            authority_addr: b(0xE1),
        },
    ] {
        let close = SettlementBody::Close {
            vault_id: b(0xC1),
            parent_root: b(0xC3),
            setup_ref: b(0xC4),
            owner_authority: authority,
            reserve_a: 111,
            reserve_b: 222,
            trader_core: b(0xD1),
            dlv_core: b(0xD2),
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        };
        let iauth = match authority {
            OwnerAuthority::Origin => indep::owner_origin(),
            OwnerAuthority::DsmSuccessor {
                authority_class,
                authority_addr,
            } => indep::owner_successor(authority_class, &authority_addr),
        };
        assert_eq!(
            close.encode().unwrap(),
            indep::settlement_close(
                &b(0xC1),
                &b(0xC3),
                &b(0xC4),
                &iauth,
                111,
                222,
                &b(0xD1),
                &b(0xD2)
            )
        );
        assert_eq!(
            SettlementBody::decode(&close.encode().unwrap()).unwrap(),
            close
        );
        assert_eq!(
            OwnerAuthority::decode(&authority.encode()).unwrap(),
            authority
        );
    }

    // R18-1: the reserved branch is canonical bytes and a live refusal.
    assert!(OwnerAuthority::Origin.is_activated());
    assert!(!OwnerAuthority::DsmSuccessor {
        authority_class: 0x1234,
        authority_addr: b(0xE1),
    }
    .is_activated());
}

#[test]
fn the_route_digest_variant_comes_from_the_settlement_branch() {
    let hops = vec![hop(0xC1, 100, 90), hop(0xC2, 90, 80)];
    let ihops: Vec<indep::Hop> = hops.iter().map(indep_hop).collect();
    let swap_pre = RouteDigestPreimage::Swap { hops: hops.clone() };
    assert_eq!(swap_pre.encode().unwrap(), indep::route_digest_swap(&ihops));
    assert_eq!(
        d::route_digest(&swap_pre).unwrap(),
        indep::h(
            "DSM/sofi/route-digest/v1",
            &[&indep::route_digest_swap(&ihops)]
        )
    );

    let close_pre = RouteDigestPreimage::Close {
        vault_id: b(0xC1),
        parent_root: b(0xC3),
        setup_ref: b(0xC4),
        reserve_a: 111,
        reserve_b: 222,
    };
    assert_eq!(
        close_pre.encode().unwrap(),
        indep::route_digest_close(&b(0xC1), &b(0xC3), &b(0xC4), 111, 222)
    );
    // The two variants never share bytes, so one can never be read as the other.
    assert_ne!(swap_pre.encode().unwrap(), close_pre.encode().unwrap());
    assert_ne!(
        d::route_digest(&swap_pre).unwrap(),
        d::route_digest(&close_pre).unwrap()
    );
    assert_eq!(
        RouteDigestPreimage::decode(&close_pre.encode().unwrap()).unwrap(),
        close_pre
    );

    // And the digest a settlement body commits is its OWN branch's.
    let close = SettlementBody::Close {
        vault_id: b(0xC1),
        parent_root: b(0xC3),
        setup_ref: b(0xC4),
        owner_authority: OwnerAuthority::Origin,
        reserve_a: 111,
        reserve_b: 222,
        trader_core: b(0xD1),
        dlv_core: b(0xD2),
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    assert_eq!(close.route_digest_preimage(), close_pre);
    let swap = SettlementBody::Swap {
        token_in: b(0x51),
        amount_in: 100,
        token_out: b(0x52),
        exact_out: 80,
        hops,
        trader_core: b(0xD1),
        dlv_cores: vec![b(0xC1), b(0xC2)],
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    assert_eq!(swap.route_digest_preimage(), swap_pre);
}

// ── the frozen golden digests ──────────────────────────────────────────────

#[test]
fn derivations_match_the_independent_hasher_and_the_frozen_goldens() {
    let v = d::vault_id(&OWNER_G, &OWNER_DEV, P_CREATE);
    assert_eq!(
        v,
        indep::h(
            "DSM/sofi/vault-id/v1",
            &[&OWNER_G, &OWNER_DEV, &indep::u64be(P_CREATE)]
        )
    );
    assert_eq!(
        cf(&v),
        "65CGCGCJQY73JMHXMF98AE0XYQGYXSYXHAHTZ0M0TBVZJD5789E0"
    );

    let key = d::vault_state_key(&v);
    assert_eq!(key, indep::h("DSM/sofi/vault-state-key/v1", &[&v]));
    assert_eq!(
        cf(&key),
        "D4KBGMYRG3CF51W1VVP35EJNDJT0Q8KG8403VV1A9X78AETX7GWG"
    );

    let leaf = state_leaf(VAULT_STATUS_ACTIVE, 3, 1_000, 2_000);
    let value = d::vault_state_leaf_value(&leaf).unwrap();
    assert_eq!(
        value,
        indep::h("DSM/sofi/vault-leaf-state/v1", &[&leaf.encode().unwrap()])
    );
    assert_eq!(
        cf(&value),
        "RQ3WF0SX43S0ZRR2D9P8J16FCKMKPSBJ26F4CCXR163DS2X6XCHG"
    );

    let rel = VaultRelationshipLeaf {
        trader_genesis: b(0x81),
        trader_device_id: b(0x82),
        leaf: b(0x83),
    };
    let rel_value = d::vault_relationship_leaf_value(&rel);
    assert_eq!(
        rel_value,
        indep::h("DSM/sofi/vault-leaf-state/v1", &[&rel.encode()])
    );
    assert_eq!(
        cf(&rel_value),
        "1T6GHT7857HYWJ57H7TWZBN3AF8ZDV4JRW65RNHJKJC4XK6YVHNG"
    );
    // One tag, two classes: the envelope inside the preimage separates them.
    assert_ne!(value, rel_value);

    let hops = vec![hop(0xC1, 100, 90), hop(0xC2, 90, 80)];
    let xswap = d::route_digest(&RouteDigestPreimage::Swap { hops }).unwrap();
    assert_eq!(
        cf(&xswap),
        "C7NW32DQGDPN5VYM0P3YRT5QMVER6GHSCY808A0V53SDQ7SPQQ5G"
    );
    let xclose = d::route_digest(&RouteDigestPreimage::Close {
        vault_id: b(0xC1),
        parent_root: b(0xC3),
        setup_ref: b(0xC4),
        reserve_a: 111,
        reserve_b: 222,
    })
    .unwrap();
    assert_eq!(
        cf(&xclose),
        "8PK083C413P6BTBMV30HWY97GM4EWYV5WHCN3H2W2G5WY1VHBDNG"
    );
}

/// R15-3 and R16-6: the form of E follows the leg count, and the canonical
/// codec goes past the beta cap. One leg — swap or close — is the single-vault
/// form; two or more is the multivault form.
#[test]
fn the_e_form_follows_the_leg_count_for_one_two_and_three_legs() {
    let goldens = [
        "8S241WX5PXN56ZAJ08XG72K00W2YN9HBGCXEQNYFDNZZT0CCE5H0",
        "EFB9KVE5N26C8D5B07F14ZX11HERY2PZ6RTS23XRV1DMX6T6PZR0",
        "HTPXR73P4PDRGKTACF7DBNJZ19N3FAKPD9B6PBH2WF6RP9RFNVYG",
    ];
    for (i, n) in [1usize, 2, 3].iter().enumerate() {
        let hops: Vec<SwapHop> = (0..*n).map(|j| hop(0xC1 + j as u8, 100, 90)).collect();
        let cores: Vec<DlvCore> = (0..*n).map(|j| dlv_core(0xC1 + j as u8)).collect();
        let swap = SettlementBody::Swap {
            token_in: b(0x51),
            amount_in: 100,
            token_out: b(0x52),
            exact_out: 90,
            hops,
            trader_core: b(0xD1),
            dlv_cores: cores.iter().map(|c| *c.vault_id()).collect(),
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        };
        let preimage = SettlementPreimage::new(swap, trader_core(&[b(0x71)]), cores).unwrap();
        let e = d::recompute_e(&preimage).unwrap();
        assert_eq!(cf(&e), goldens[i], "E for {n} legs");
        assert_eq!(
            preimage.encode().unwrap(),
            indep::settlement_preimage(
                &preimage.settlement().encode().unwrap(),
                &preimage.trader_core().encode().unwrap(),
                &preimage
                    .dlv_cores()
                    .iter()
                    .map(|c| c.encode().unwrap())
                    .collect::<Vec<_>>()
            ),
            "P(E) for {n} legs"
        );
        // Round trip at every cardinality, including past ROUTE_MAX_LEGS.
        assert_eq!(
            SettlementPreimage::decode(&preimage.encode().unwrap()).unwrap(),
            preimage
        );
    }
    assert_eq!(ROUTE_MAX_LEGS, 2, "the beta cap is unchanged");

    // A three-leg Γ also has canonical bytes.
    let legs: Vec<RouteLegEntry> = (0..3u8)
        .map(|j| RouteLegEntry {
            vault_id: b(0xC1 + j),
            parent_root: b((0xC1 + j) ^ 0x0F),
            setup_ref: b((0xC1 + j) ^ 0xF0),
            shadow_core: b((0xC1 + j) ^ 0x33),
        })
        .collect();
    let gamma = RouteLegSet::new(legs).unwrap();
    assert_eq!(RouteLegSet::decode(&gamma.encode()).unwrap(), gamma);
    assert_eq!(
        cf(&d::route_leg_set_digest(&gamma)),
        "A1HF7DEMV274E115E36RJ61SAQX4GGGH6WJMKHSTPYNW53BZ4660"
    );
}

/// A close is one leg, so it takes the single-vault form — and its E differs
/// from the swap over the same vault, because the branch is in the digest.
#[test]
fn a_close_takes_the_single_vault_form_and_never_collides_with_a_swap() {
    let core = dlv_core(0xC1);
    let close = SettlementBody::Close {
        vault_id: b(0xC1),
        parent_root: b(0xC1 ^ 0x0F),
        setup_ref: b(0xC1 ^ 0xF0),
        owner_authority: OwnerAuthority::Origin,
        reserve_a: 111,
        reserve_b: 222,
        trader_core: b(0xD1),
        dlv_core: b(0xD2),
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    let closing =
        SettlementPreimage::new(close, trader_core(&[b(0x71)]), vec![core.clone()]).unwrap();
    let e_close = d::recompute_e(&closing).unwrap();
    assert_eq!(
        cf(&e_close),
        "ARJ2HQAS6EK128TFTMVNR7FV8PGZKJ8QCRSMJY0ECH3RJTKJV55G"
    );

    let swap = SettlementBody::Swap {
        token_in: b(0x51),
        amount_in: 100,
        token_out: b(0x52),
        exact_out: 90,
        hops: vec![hop(0xC1, 100, 90)],
        trader_core: b(0xD1),
        dlv_cores: vec![b(0xC1)],
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    let swapping = SettlementPreimage::new(swap, trader_core(&[b(0x71)]), vec![core]).unwrap();
    assert_ne!(e_close, d::recompute_e(&swapping).unwrap());
}

// ── negatives: every constructor check ─────────────────────────────────────

#[test]
fn constructors_refuse_every_malformed_shape() {
    // A status that is neither Active nor Retired.
    assert!(matches!(
        state_leaf(0x0003, 0, 1, 1).encode(),
        Err(SofiWireError::UnknownVaultStatus { status: 0x0003 })
    ));
    let mut bad = state_leaf(VAULT_STATUS_ACTIVE, 0, 1, 1).encode().unwrap();
    let n = bad.len();
    bad[n - 2..].copy_from_slice(&[0x00, 0x09]);
    assert!(matches!(
        VaultStateLeaf::decode(&bad),
        Err(DecodeError::Invalid(_))
    ));

    // A path that is not exactly 256 deep, either way.
    for depth in [255usize, 257] {
        let entry = CoreEntry::Mutation {
            key: b(0x91),
            pre: b(0x41),
            post: b(0x42),
            path: sibs()[..depth.min(256)].to_vec(),
        };
        let entry = if depth == 257 {
            let mut p = sibs();
            p.push(b(0x01));
            CoreEntry::Mutation {
                key: b(0x91),
                pre: b(0x41),
                post: b(0x42),
                path: p,
            }
        } else {
            entry
        };
        assert!(
            matches!(entry.encode(), Err(SofiWireError::PathDepth { .. })),
            "path depth {depth} must be refused"
        );
    }

    // Core entries out of key order, and duplicates.
    let two = vec![mutation_entry(b(0x72)), mutation_entry(b(0x71))];
    assert!(matches!(
        TraderCore::new(OWNER_G, OWNER_DEV, 9, b(0x61), two),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));
    let dup = vec![mutation_entry(b(0x71)), mutation_entry(b(0x71))];
    assert!(matches!(
        TraderCore::new(OWNER_G, OWNER_DEV, 9, b(0x61), dup),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));
    assert!(matches!(
        TraderCore::new(OWNER_G, OWNER_DEV, 9, b(0x61), Vec::new()),
        Err(SofiWireError::Cardinality { .. })
    ));

    // R15-4: a route may not reference one DLV parent twice.
    let repeated = SettlementBody::Swap {
        token_in: b(0x51),
        amount_in: 100,
        token_out: b(0x52),
        exact_out: 80,
        hops: vec![hop(0xC1, 100, 90), hop(0xC1, 90, 80)],
        trader_core: b(0xD1),
        dlv_cores: vec![b(0xC1)],
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    assert!(matches!(
        repeated.encode(),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));

    // B°'s `dlv_cores` are DIGESTS, positional against P(E)'s vault-sorted
    // cores, so they carry no order of their own and this layer cannot bind
    // them — `sofi::validation` does, and refuses a body naming another core.
    // What the codec still refuses is a core sequence out of vault order in
    // P(E) itself, which IS an ordering this layer can see.
    let swap = SettlementBody::Swap {
        token_in: b(0x51),
        amount_in: 100,
        token_out: b(0x52),
        exact_out: 80,
        hops: vec![hop(0xC1, 100, 90), hop(0xC2, 90, 80)],
        trader_core: b(0xD1),
        dlv_cores: vec![b(0xC2), b(0xC1)],
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    assert!(
        swap.encode().is_ok(),
        "a digest sequence has no order of its own"
    );
    assert!(matches!(
        SettlementPreimage::new(
            swap,
            trader_core(&[b(0x71)]),
            vec![dlv_core(0xC2), dlv_core(0xC1)]
        ),
        Err(SofiWireError::NotStrictlyAscending { .. })
    ));
}

#[test]
fn decoders_refuse_wrong_classes_truncation_and_trailing_bytes() {
    let leaf = state_leaf(VAULT_STATUS_ACTIVE, 1, 2, 3).encode().unwrap();
    assert!(matches!(
        VaultRelationshipLeaf::decode(&leaf),
        Err(DecodeError::WrongClass { got: 0x004B })
    ));
    assert!(matches!(
        VaultStateLeaf::decode(&leaf[..leaf.len() - 1]),
        Err(DecodeError::Truncated)
    ));
    let mut long = leaf.clone();
    long.push(0);
    assert!(matches!(
        VaultStateLeaf::decode(&long),
        Err(DecodeError::TrailingBytes { extra: 1 })
    ));

    // A union member cannot be read as its sibling.
    let origin = OwnerAuthority::Origin.encode();
    assert!(matches!(
        RouteDigestPreimage::decode(&origin),
        Err(DecodeError::WrongClass { got: 0x0055 })
    ));
    let swap_digest = RouteDigestPreimage::Swap {
        hops: vec![hop(0xC1, 1, 1)],
    }
    .encode()
    .unwrap();
    assert!(matches!(
        OwnerAuthority::decode(&swap_digest),
        Err(DecodeError::WrongClass { got: 0x0057 })
    ));
}

#[test]
fn the_new_classes_are_allocated_exactly_once() {
    let src = include_str!("../src/ccb/mod.rs");
    let start = src.find("pub mod class {").expect("class module");
    let body = &src[start..];
    let end = body.find("\n}\n").expect("class module end");
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
    for v in 0x004Bu16..=0x005B {
        assert!(
            seen.contains_key(&v),
            "{v:#06x} must be allocated to a SoFi v8 class"
        );
    }
}
