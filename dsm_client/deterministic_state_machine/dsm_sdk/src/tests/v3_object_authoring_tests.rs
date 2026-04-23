// SPDX-License-Identifier: MIT OR Apache-2.0

use prost::Message;

use crate::vault::lifecycle::author_dlv_open;
use crate::wire::{author_contact_accept, author_contact_add, domain_hash_bytes, pb};

#[test]
fn contact_accept_add_digest_matches_domain_hash() {
    let author = [1u8; 32];
    let peer = [2u8; 32];
    let counterparty_tip = [3u8; 32];
    let local_tip = [4u8; 32];

    let add = author_contact_add(&author, &peer, &counterparty_tip);
    let accept = author_contact_accept(&author, &add, &local_tip);

    let add_bytes = add.encode_to_vec();
    let expected = domain_hash_bytes("DSM/contact/add\0", &add_bytes);
    assert_eq!(accept.add_digest, expected.to_vec());
}

#[test]
fn dlv_open_is_bytes_only() {
    let device_id = [9u8; 32];
    let vault_id = [8u8; 32];
    let reveal = b"abc\x00\xff";

    let open = author_dlv_open(&device_id, &vault_id, reveal);
    assert_eq!(open.device_id, device_id.to_vec());
    assert_eq!(open.vault_id, vault_id.to_vec());
    assert_eq!(open.reveal_material, reveal.to_vec());
}

#[test]
fn token_policy_and_anchor_types_exist() {
    // This test fails to compile if these types are not present in pb.
    let _p = pb::TokenPolicyV3 {
        policy_bytes: vec![1, 2, 3],
    };
    let _a = pb::PolicyAnchorV3 {
        policy_digest: vec![0u8; 32],
        author_device_id: vec![0u8; 32],
        parent_digest: vec![],
    };
}
