// SPDX-License-Identifier: MIT OR Apache-2.0

//! A payer's offline boundaries reach its contacts (DSM Amendment A30; the
//! owner's design of 2026-10-22: "it automatically alerts their contacts and
//! gives them a package to sync up with", "just part of the synchronization
//! process").
//!
//! A receiver takes an offline payment only from the account it validated
//! itself (`dsm::bilateral::offline::spend_starts_at_the_record`). So each load
//! and unload is told to the payer's contacts, sealed to each on the
//! relationship's route, naming the economic position it is admitted at. The
//! contact's sync validates that one step, one hop, by the check any other reads
//! with; only that check records an account.
//!
//! A notice is discovery, never authority. It is unsigned and proves nothing: one
//! naming a step that is no boundary records nothing, and one naming a boundary
//! that verifies as wrong is refused where it is read.

use dsm::economic::provenance::PeerLineageFailure;

use crate::sdk::b0x_sdk::{B0xSDK, OfflineBoundaryNotice};
use crate::storage::client_db::{self, offline_boundary_notices as notices, ContactRecord};

use super::app_router_impl::{contact_relationship_tip, AppRouterImpl};

/// How many contacts are told at once: a load costs its slowest window's
/// deliveries, not the sum of every contact's.
const CONTACTS_TOLD_AT_ONCE: usize = 16;

/// What the check a notice asks for came to.
#[derive(Debug)]
pub(crate) enum NoticeChecked {
    /// The step the notice names was checked. Whatever it recorded, the notice
    /// has done all it can.
    Done,
    /// Not established: the notice is left on its route and read again. A fact
    /// not established is never read as its negation (storage spec §4).
    NotEstablished(String),
    /// The notice never will be anything: its bytes name no position, its sender
    /// is no contact, or the boundary it names verifies as wrong.
    Refused(String),
}

fn device_of(contact: &ContactRecord) -> Result<[u8; 32], String> {
    contact
        .device_id
        .as_slice()
        .try_into()
        .map_err(|e| format!("contact {}'s device id: {e}", contact.alias))
}

/// Deliver to `contact` the notices it is owed, in order. Its mark moves after
/// each delivery, so a failure leaves owed exactly what was not delivered.
async fn tell_contact(
    contact: &ContactRecord,
    owed: Vec<u64>,
    mut b0x: B0xSDK,
) -> Result<(), String> {
    let device = device_of(contact)?;
    let genesis: [u8; 32] = contact
        .genesis_hash
        .as_slice()
        .try_into()
        .map_err(|e| format!("contact {}'s genesis: {e}", contact.alias))?;
    let tip = contact_relationship_tip(contact)?;
    for position in owed {
        b0x.submit_offline_boundary_notice(position, &genesis, &device, &tip)
            .await
            .map_err(|e| format!("telling {} of position {position}: {e}", contact.alias))?;
        notices::record_told(&device, position)
            .map_err(|e| format!("marking {} told of position {position}: {e}", contact.alias))?;
    }
    Ok(())
}

impl AppRouterImpl {
    /// Tell each contact of this device's offline boundaries it has not been
    /// told of. Runs when a boundary is admitted and on every sync, so a
    /// delivery that failed and a contact added since are both met. Answers what
    /// could not be done; what was not delivered stays owed. A device with no
    /// admitted boundary owes nothing and reads no further than that.
    pub(crate) async fn tell_contacts_of_offline_boundaries(
        &self,
        storage_endpoints: &[String],
    ) -> Vec<String> {
        let admitted = match client_db::economic_lineage::get_admitted() {
            Ok(Some(admitted)) => admitted.economic_position(),
            Ok(None) => return Vec::new(),
            Err(e) => return vec![format!("the admitted position: {e}")],
        };
        let contacts = match client_db::get_all_contacts() {
            Ok(contacts) => contacts,
            Err(e) => return vec![format!("the contacts to tell: {e}")],
        };
        let mut failures = Vec::new();
        let mut owed = Vec::new();
        for contact in contacts {
            let positions = device_of(&contact)
                .and_then(|device| notices::owed_to(&device, admitted).map_err(|e| e.to_string()));
            match positions {
                Ok(positions) if positions.is_empty() => {}
                Ok(positions) => owed.push((contact, positions)),
                Err(e) => failures.push(format!("what contact {} is owed: {e}", contact.alias)),
            }
        }
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        for window in owed.chunks(CONTACTS_TOLD_AT_ONCE) {
            let mut deliveries = Vec::with_capacity(window.len());
            for (contact, positions) in window {
                match B0xSDK::new(
                    device_id_b32.clone(),
                    self.core_sdk.clone(),
                    storage_endpoints.to_vec(),
                ) {
                    Ok(b0x) => deliveries.push(tell_contact(contact, positions.clone(), b0x)),
                    Err(e) => failures.push(format!("the inbox client: {e}")),
                }
            }
            for delivered in futures::future::join_all(deliveries).await {
                if let Err(e) = delivered {
                    failures.push(e);
                }
            }
        }
        failures
    }
}

/// Run the check `notice` asks for: its sender's step at the position it names,
/// one hop, recording what that step validated when it is a boundary.
pub(crate) async fn check_offline_boundary_notice(notice: &OfflineBoundaryNotice) -> NoticeChecked {
    let Ok(sender) = <[u8; 32]>::try_from(notice.sender.as_slice()) else {
        return NoticeChecked::Refused("it names no device".to_string());
    };
    let Ok(position) = <[u8; 8]>::try_from(notice.body.as_slice()).map(u64::from_be_bytes) else {
        return NoticeChecked::Refused("its body is no position".to_string());
    };
    let contact = match client_db::get_contact_by_device_id(&sender) {
        Ok(Some(contact)) => contact,
        Ok(None) => return NoticeChecked::Refused("its sender is no contact".to_string()),
        Err(e) => return NoticeChecked::NotEstablished(format!("the contacts: {e}")),
    };
    let Ok(genesis) = <[u8; 32]>::try_from(contact.genesis_hash.as_slice()) else {
        return NoticeChecked::Refused("its sender's contact holds no genesis".to_string());
    };
    match crate::sdk::economic_registers::record_peer_offline_boundary(genesis, sender, position)
        .await
    {
        Ok(scan) if scan.reached() == position => NoticeChecked::Done,
        Ok(scan) => NoticeChecked::NotEstablished(format!(
            "position {position} is not established: {:?}",
            scan.stop()
        )),
        Err(PeerLineageFailure::Invalid(why)) => {
            NoticeChecked::Refused(format!("position {position}: {why}"))
        }
        Err(other) => NoticeChecked::NotEstablished(format!("position {position}: {other}")),
    }
}
