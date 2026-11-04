// SPDX-License-Identifier: MIT OR Apache-2.0

//! The parsers production runs on objects it reads embedded in another one:
//! a settlement preimage carries its cores, entries, settlement body, owner
//! authority and closure index, an economic leaf carries a trader
//! relationship leaf. Each parses back exactly what was encoded, and a union
//! member's parser refuses its sibling's bytes. None of these objects has a
//! standalone decoder, because nothing in production decodes one alone
//! (Gate G1, SoFi §37).
use super::*;

fn b(byte: u8) -> D32 {
    [byte; 32]
}

fn path() -> Vec<D32> {
    (0..256u32).map(|i| b((i % 251) as u8)).collect()
}

/// `bytes` parsed whole by `at`.
fn parsed<T>(
    bytes: &[u8],
    at: fn(&mut Cursor<'_>) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    let value = at(&mut c)?;
    finish(&c, value)
}

/// `value`'s bytes, parsed back by `at`, are `value`.
fn round_trips<T: PartialEq + core::fmt::Debug>(
    value: &T,
    bytes: Vec<u8>,
    at: fn(&mut Cursor<'_>) -> Result<T, DecodeError>,
) {
    match parsed(&bytes, at) {
        Ok(back) => assert_eq!(&back, value),
        Err(e) => panic!("{value:?} does not parse back: {e:?}"),
    }
}

fn encoded(bytes: Result<Vec<u8>, SofiWireError>) -> Vec<u8> {
    match bytes {
        Ok(bytes) => bytes,
        Err(e) => panic!("a fixture that does not encode: {e:?}"),
    }
}

fn hop(vault: u8) -> SwapHop {
    SwapHop {
        vault_id: b(vault),
        parent_root: b(vault ^ 0x0F),
        setup_ref: b(vault ^ 0xF0),
        token_in: b(0x51),
        amount_in: 100,
        token_out: b(0x52),
        amount_out: 90,
    }
}

fn mutation() -> CoreEntry {
    CoreEntry::Mutation {
        key: b(0x71),
        pre: b(0x41),
        post: b(0x42),
        path: path(),
    }
}

#[test]
fn every_core_entry_kind_parses_back() {
    let read = CoreEntry::Read {
        key: b(0x92),
        value: b(0x93),
        path: path(),
    };
    let relationship = CoreEntry::Relationship {
        genesis: b(0x11),
        device_id: b(0x22),
        vault_id: b(0x94),
        base: b(0x95),
        path: path(),
    };
    for entry in [mutation(), read, relationship] {
        round_trips(&entry, encoded(entry.encode()), CoreEntry::at);
    }
}

#[test]
fn both_cores_parse_back() {
    let Ok(trader) = TraderCore::new(b(0x11), b(0x22), 9, b(0x61), vec![mutation()]) else {
        panic!("a trader core")
    };
    round_trips(&trader, encoded(trader.encode()), TraderCore::at);
    let Ok(vault) = DlvCore::new(
        b(0xA1),
        b(0x62),
        b(0x11),
        b(0x22),
        b(0x63),
        vec![mutation()],
    ) else {
        panic!("a vault core")
    };
    round_trips(&vault, encoded(vault.encode()), DlvCore::at);
}

#[test]
fn both_settlement_branches_and_both_authorities_parse_back() {
    let Ok(closure) = PreEClosureIndex::new(Vec::new()) else {
        panic!("an empty closure")
    };
    let swap = SettlementBody::Swap {
        token_in: b(0x51),
        amount_in: 100,
        token_out: b(0x52),
        exact_out: 80,
        hops: vec![hop(0xC1), hop(0xC2)],
        trader_core: b(0xD1),
        dlv_cores: vec![b(0xC1), b(0xC2)],
        closure: closure.clone(),
    };
    round_trips(&swap, encoded(swap.encode()), SettlementBody::at);
    for authority in [
        OwnerAuthority::Origin,
        OwnerAuthority::DsmSuccessor {
            authority_class: 0x1234,
            authority_addr: b(0xE1),
        },
    ] {
        round_trips(&authority, authority.encode(), OwnerAuthority::at);
        let close = SettlementBody::Close {
            vault_id: b(0xC1),
            parent_root: b(0xC3),
            setup_ref: b(0xC4),
            owner_authority: authority,
            reserve_a: 111,
            reserve_b: 222,
            trader_core: b(0xD1),
            dlv_core: b(0xD2),
            closure: closure.clone(),
        };
        round_trips(&close, encoded(close.encode()), SettlementBody::at);
    }
}

#[test]
fn an_owner_authority_is_never_read_from_a_route_digest_preimage() {
    let swap_digest = encoded(
        RouteDigestPreimage::Swap {
            hops: vec![hop(0xC1)],
        }
        .encode(),
    );
    assert!(matches!(
        parsed(&swap_digest, OwnerAuthority::at),
        Err(DecodeError::WrongClass { got: 0x0057 })
    ));
}

#[test]
fn every_validation_ref_and_a_closure_of_them_parse_back() {
    let mut refs = vec![
        ValidationRef::ContentAddr {
            object_class: 0x001C,
            addr: b(3),
        },
        ValidationRef::SingleRootClaim { claim_ref: b(4) },
        ValidationRef::ConditionalClaim {
            genesis: b(0x11),
            device_id: b(0x22),
            position: 9,
            fulfillment_id: b(5),
        },
        ValidationRef::Setup { setup_ref: b(6) },
    ];
    for r in &refs {
        round_trips(r, r.encode(), ValidationRef::at);
    }
    refs.sort_by_key(|r| r.encode());
    let Ok(closure) = PreEClosureIndex::new(refs) else {
        panic!("a closure of every reference kind")
    };
    round_trips(&closure, closure.encode(), PreEClosureIndex::at);
}

#[test]
fn a_trader_relationship_leaf_parses_back() {
    let leaf = TraderRelationshipLeaf {
        vault_id: b(0x84),
        leaf: b(0x85),
    };
    round_trips(&leaf, leaf.encode(), TraderRelationshipLeaf::at);
}
