// SPDX-License-Identifier: MIT OR Apache-2.0

//! A rival writer for the node harness ([`super::nodes::RivalPut`]): one cell
//! entry put at a member through the SDK's own client, just before the member
//! takes the next put naming that entry's cell.

use std::sync::Arc;

use dsm::types::proto::CellPutsV1;
use prost::Message;

use crate::sdk::route_seats::CellPut;
use crate::sdk::storage_node_sdk::SetClient;
use crate::sdk::storage_set::StorageSet;
use crate::test_support::nodes::RivalPut;

/// `entry` put at `member_id` of `set` as another writer would put it, armed
/// to land just before the next put there naming `entry`'s cell.
pub fn rival_put(set: &StorageSet, member_id: &str, entry: CellPut) -> RivalPut {
    let client = Arc::new(SetClient::new(set).expect("a client of the set"));
    let key = entry.1;
    let member_id = member_id.to_string();
    RivalPut {
        names: Box::new(move |body: &[u8]| match CellPutsV1::decode(body) {
            Ok(batch) => batch.entries.iter().any(|put| put.key == key),
            Err(e) => panic!("an armed member was handed a cell put it cannot read: {e}"),
        }),
        put: Box::new(move || {
            Box::pin(async move {
                let Some(member) = client.member(member_id.as_bytes()) else {
                    panic!("the rival's member {member_id} is not in the set");
                };
                if let Err(e) = member.put_cells(core::slice::from_ref(&entry)).await {
                    panic!("the rival's put: {e}");
                }
            })
        }),
    }
}
