// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::vault::lifecycle::author_dlv_open;

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
