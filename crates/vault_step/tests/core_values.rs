//! The reference against DSM Core's own derivations: Core main cc9e44b36's functions, run on these fixed inputs
//! (`scratchpad/core_export/.../dsm/tests/vault_xcheck.rs`), printed these digests.
use vault_step::reference::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn the_reference_computes_cores_values() {
    let d = |i: u8| [i; 32];
    let (vault_id, ta, tb, g, dev, base, e, rprev) = (d(1), d(2), d(3), d(4), d(5), d(6), d(7), d(8));
    let mp = market_policy_addr(&ta, &tb);
    let fp = fee_policy_addr(30);
    let state = VaultStateLeaf {
        owner_genesis: d(9),
        owner_device_id: d(10),
        create_position: 0x0102030405060708,
        market_policy: mp,
        fee_policy: fp,
        release_policy: d(11),
        storage_set_id: d(12),
        generation: 77,
        reserve_a: 1 << 50,
        reserve_b: 3 << 48,
        status: 1,
    };
    let core = [
        ("market_addr", "519cfc7bd890a2c0a760895cebacac61e78f13b97ba9047fa30522172820fd61", mp),
        ("fee_addr", "5704ff85a06d6302f708b77f8ce6b66430a349a2ca0300b79231e5a370652a85", fp),
        ("state_key", "89a6f527de84a5a2204789c187a10f5299569d6d544b70227955fb6c36c32a39", vault_state_key(&vault_id)),
        ("state_value", "67923b1b947405a51fb7d3f4f6390adcab80ce95be709724366c10cdd2ce22ea", vault_state_leaf_value(&state)),
        ("rel_key", "ab2db8a97bcbc9572dab0b4c62843d224bbcb6263088ec2aa3b304454a950d68", relationship_key(&g, &dev, &vault_id)),
        ("rel_next", "fa680b0733caf071124f2acb0986624d2cd6c15d49e15b5d1a220bf3e06f42f0", relationship_leaf_next(&base, &e)),
        ("rel_value", "c9fa768ea958375e4459a951d5af999590c3e1c1d11b5d15686c0633e34b1d98", vault_relationship_leaf_value(&g, &dev, &base)),
        ("attempt0", "f9bb00924942d168fc4e946909aabad3974225d7adf9b546a6bf07ced59645b4", successor_attempt_key(&vault_id, &rprev, 0)),
        ("attempt9", "2d0e2a1a7b095749e0148a8c20c2cf06b9d241f181b62a4eddbe713da4110c4e", successor_attempt_key(&vault_id, &rprev, 9)),
        ("node", "5f586b75a0521e28768659f89d2fcf48d97d74a192f5cb8bc75d2341737048da", econ_node(&d(13), &d(14))),
        ("leaf", "4d66e372b80e5db74c2b0d275c32ca5791404f34028f6d0bf75ad6e901d231c9", econ_leaf(&d(15), &d(16))),
        ("default256", "92499129ec363dcfce2e06aa4c64368dded243dc5615830994f0254d7a9608dd", default_node(256)),
    ];
    for (name, want, got) in core {
        assert_eq!(hex(&got), want, "{name}");
    }
    assert_eq!(constant_product_output(123_456_789, 1 << 50, 3 << 48, 30), Some(92314803));
}
