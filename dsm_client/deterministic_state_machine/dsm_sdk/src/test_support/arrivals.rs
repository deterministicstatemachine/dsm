// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a device's poll reads from the members for it, before anything is
//! processed: the transfer entries and the evidence halves exactly as its
//! dispatcher is handed them. Tests take these as the honest arrivals of a
//! real send, and derive hostile arrivals from them.

use crate::economic_fixtures::FleetGuard;
use crate::sdk::b0x_sdk::{B0xEntry, B0xSDK, CountersignDelta, RelationshipFinalizedMessage};
use crate::storage::client_db;
use crate::test_support::two_device::TestDevice;

/// Everything waiting for one device on the members.
pub struct Arrived {
    /// Transfer halves, each with the route it was read from (`inbox_key`)
    /// and its correlation key (`transaction_id`).
    pub transfers: Vec<B0xEntry>,
    /// Evidence halves, each with the route it was read from.
    pub evidence: Vec<(dsm::types::proto::ReceiptEvidenceA, String)>,
    /// Recipients' countersign deltas for this device's sends.
    pub deltas: Vec<CountersignDelta>,
    /// Senders' finality certificates for transitions this device accepted.
    pub certificates: Vec<RelationshipFinalizedMessage>,
}

/// Read `device`'s inbox on `fleet` the way its poll does — every rotated
/// route it holds for its contacts — and process nothing.
pub async fn arrivals_for(device: &TestDevice, fleet: &FleetGuard) -> Arrived {
    device.enter();
    let mut b0x = B0xSDK::new(
        crate::util::text_id::encode_base32_crockford(&device.device_id),
        device.router().core_sdk.clone(),
        fleet.endpoints(),
    )
    .expect("B0xSDK");
    let contacts = client_db::get_all_contacts().expect("contacts");
    let mut arrived = Arrived {
        transfers: Vec::new(),
        evidence: Vec::new(),
        deltas: Vec::new(),
        certificates: Vec::new(),
    };
    for tagged in crate::handlers::app_router_impl::collect_tagged_inbox_addresses(
        device.genesis,
        device.device_id,
        &contacts,
    ) {
        arrived.transfers.extend(
            b0x.retrieve_from_b0x_v2(&tagged.address)
                .await
                .expect("read the inbox"),
        );
        for evidence in b0x.take_evidence_artifacts() {
            arrived.evidence.push((evidence, tagged.address.clone()));
        }
        arrived.deltas.extend(b0x.take_countersign_deltas());
        arrived
            .certificates
            .extend(b0x.take_relationship_finalized());
    }
    arrived
}

/// The one transfer and its evidence waiting for `device`.
pub async fn the_one_transfer(device: &TestDevice, fleet: &FleetGuard) -> OneTransfer {
    let mut arrived = arrivals_for(device, fleet).await;
    assert_eq!(arrived.transfers.len(), 1, "one transfer is waiting");
    assert_eq!(arrived.evidence.len(), 1, "its evidence is waiting");
    let transfer = arrived.transfers.remove(0);
    let (evidence, evidence_route) = arrived.evidence.remove(0);
    assert_eq!(
        evidence.transfer_submission_id, transfer.transaction_id,
        "the evidence names the transfer"
    );
    OneTransfer {
        key: transfer.transaction_id.clone(),
        route: transfer.inbox_key.clone(),
        transfer_bytes: transfer.transfer_wire_bytes.clone(),
        evidence,
        evidence_route,
    }
}

/// One transfer's halves as they arrived.
pub struct OneTransfer {
    /// The correlation key the recipient stages under.
    pub key: String,
    /// The route the transfer half was read from.
    pub route: String,
    /// The `OnlineTransferRequest` wire bytes, exactly as the sender froze them.
    pub transfer_bytes: Vec<u8>,
    pub evidence: dsm::types::proto::ReceiptEvidenceA,
    /// The route the evidence half was read from.
    pub evidence_route: String,
}

impl OneTransfer {
    /// The evidence half with its receipt bytes replaced.
    pub fn evidence_with(
        &self,
        full_receipt_bytes: Vec<u8>,
    ) -> dsm::types::proto::ReceiptEvidenceA {
        dsm::types::proto::ReceiptEvidenceA {
            transfer_submission_id: self.evidence.transfer_submission_id.clone(),
            receipt_evidence_digest: self.evidence.receipt_evidence_digest.clone(),
            full_receipt_bytes,
        }
    }
}
