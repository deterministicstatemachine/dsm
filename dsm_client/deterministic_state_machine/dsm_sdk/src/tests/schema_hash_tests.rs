// Tests for generated schema hash helper
#[test]
fn contact_add_response_schema_hash_is_canonical() {
    // Include the build-time generated helper
    include!(concat!(env!("OUT_DIR"), "/dsm_contact_schema_hash.rs"));

    let hash = contact_add_response_schema_hash();
    let v = hash.v;
    // Must be exactly 32 bytes (BLAKE3-256)
    assert_eq!(v.len(), 32, "schema hash must be 32 bytes");
    // Must not be all zeros
    assert!(v.iter().any(|&b| b != 0), "schema hash must not be all zeros");
}

#[test]
fn resultpack_roundtrip_preserves_canonical_schema_hash() {
    // Include generated prost types and helper
    include!(concat!(env!("OUT_DIR"), "/dsm.rs"));
    include!(concat!(env!("OUT_DIR"), "/dsm_contact_schema_hash.rs"));

    // Build a minimal ContactAddResponse
    let contact = ContactAddResponse {
        alias: "alice".to_string(),
        device_id: vec![1u8; 32],
        genesis_hash: Some(Hash32 { v: vec![2u8; 32] }),
        chain_tip: None,
        chain_tip_smt_proof: None,
        alias_binding: None,
        genesis_verified_online: true,
        verify_counter: 0,
        added_counter: 0,
        verifying_storage_nodes: Vec::new(),
        ble_address: "".to_string(),
        signing_public_key: vec![3u8; 64],
    };

    let mut body = Vec::new();
    contact.encode(&mut body).expect("encode contact");

    let schema_vec = contact_add_response_schema_hash_vec();
    let rp = ResultPack {
        schema_hash: Some(generated::Hash32 { v: schema_vec.clone() }),
        codec: Codec::Proto as i32,
        body: body.clone(),
    };

    let mut rp_bytes = Vec::new();
    rp.encode(&mut rp_bytes).expect("encode resultpack");

    let decoded = ResultPack::decode(&*rp_bytes).expect("decode resultpack");
    assert_eq!(decoded.codec, Codec::Proto as i32);
    assert_eq!(decoded.schema_hash.unwrap().v, schema_vec);

    let decoded_contact = ContactAddResponse::decode(&decoded.body[..]).expect("decode contact");
    assert_eq!(decoded_contact.alias, "alice");
}

