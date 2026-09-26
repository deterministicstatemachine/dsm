// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local relationship send-status derivation.
//!
//! Rust is the sole authority for whether a relationship is send-ready.
//! Frontend and Android only display or transport these statuses.

use dsm::types::proto as generated;

use crate::storage::client_db::{self, ContactRecord};

fn block_reason_i32(reason: generated::RelationshipSendBlockReason) -> i32 {
    reason as i32
}

fn check_state_i32(state: generated::RelationshipSendCheckState) -> i32 {
    state as i32
}

pub(crate) fn ready_status() -> generated::RelationshipSendStatus {
    generated::RelationshipSendStatus {
        send_ready: true,
        send_check_state: check_state_i32(generated::RelationshipSendCheckState::Ready),
        send_block_reason: block_reason_i32(generated::RelationshipSendBlockReason::Unspecified),
        send_block_message: "Ready to send".to_string(),
    }
}

pub(crate) fn blocked_status(
    reason: generated::RelationshipSendBlockReason,
    message: impl Into<String>,
) -> generated::RelationshipSendStatus {
    generated::RelationshipSendStatus {
        send_ready: false,
        send_check_state: check_state_i32(generated::RelationshipSendCheckState::Blocked),
        send_block_reason: block_reason_i32(reason),
        send_block_message: message.into(),
    }
}

pub(crate) fn status_message(status: &generated::RelationshipSendStatus) -> String {
    if !status.send_block_message.trim().is_empty() {
        status.send_block_message.clone()
    } else if status.send_ready {
        "Ready to send".to_string()
    } else {
        "Relationship is blocked".to_string()
    }
}

/// Finality-barrier block on ORIGINATING toward `counterparty_device_id`, from
/// either role, and the ONE check every originate chokepoint consults
/// (`wallet.send`, the BLE prepare, the send-status authority below):
///
/// - our own prior send on the relationship has not reached its finality
///   checkpoint (the pending online gate is armed), or
/// - an inbound acceptance we journaled still awaits the peer's verified
///   `RelationshipFinalizedV1` (`peer_finalized = 0`, not rejected), or
/// - an inbound transfer from the peer is staged but not yet applied (crossing
///   mitigation).
///
/// Ordinary bilateral relationships allow ONE unresolved semantic predecessor
/// per originator; both conditions mean ours is unresolved. `Ok(None)` ⇔ free
/// to originate. Relationship-local, never wallet-global.
pub(crate) fn finality_barrier_block(
    counterparty_device_id: &[u8],
) -> Result<Option<generated::RelationshipSendStatus>, String> {
    let pending_outbox = client_db::get_pending_online_outbox(counterparty_device_id)
        .map_err(|e| format!("Failed to load pending online catch-up state: {e}"))?;
    if let Some(pending) = pending_outbox {
        if pending.parent_tip.len() != 32 || pending.next_tip.len() != 32 {
            return Err("Pending online catch-up gate is malformed".to_string());
        }
        return Ok(Some(blocked_status(
            generated::RelationshipSendBlockReason::PendingCatchup,
            "Waiting for prior transfer to settle",
        )));
    }
    if client_db::counterparty_awaits_peer_finalization(counterparty_device_id)
        .map_err(|e| format!("Failed to load acceptance finality state: {e}"))?
    {
        return Ok(Some(blocked_status(
            generated::RelationshipSendBlockReason::PendingCatchup,
            "Waiting for the peer to finalize a transfer you received",
        )));
    }
    // An inbound transfer from this peer is staged but not yet applied:
    // originating now would cross it. Narrows the crossing window; the
    // deterministic turn rule for a true simultaneous cross is a protocol
    // decision outside this barrier.
    if client_db::recipient_staging::counterparty_has_unconverged_inbound(counterparty_device_id)
        .map_err(|e| format!("Failed to load inbound staging state: {e}"))?
    {
        return Ok(Some(blocked_status(
            generated::RelationshipSendBlockReason::PendingCatchup,
            "Waiting for a transfer from this peer to finish applying",
        )));
    }
    Ok(None)
}

pub(crate) fn derive_local_send_status_for_device_id(
    device_id: &[u8],
) -> generated::RelationshipSendStatus {
    match client_db::get_contact_by_device_id(device_id) {
        Ok(Some(contact)) => derive_local_send_status_for_contact(&contact),
        Ok(None) => blocked_status(
            generated::RelationshipSendBlockReason::InternalError,
            "Relationship not found",
        ),
        Err(e) => blocked_status(
            generated::RelationshipSendBlockReason::InternalError,
            format!("Failed to load relationship state: {e}"),
        ),
    }
}

pub(crate) fn derive_local_send_status_for_contact(
    contact: &ContactRecord,
) -> generated::RelationshipSendStatus {
    if contact.public_key.is_empty() {
        return blocked_status(
            generated::RelationshipSendBlockReason::InternalError,
            "Relationship is missing a canonical public key",
        );
    }

    match finality_barrier_block(&contact.device_id) {
        Ok(Some(blocked)) => return blocked,
        Ok(None) => {}
        Err(e) => {
            return blocked_status(generated::RelationshipSendBlockReason::InternalError, e);
        }
    }

    // One step at a time on the relationship, whichever process: an offline
    // step in flight with the contact — this device's proposal, or the
    // contact's that it holds — holds every other origination until it
    // commits or ends.
    match client_db::bilateral_step_in_flight_with(&contact.device_id, None) {
        Ok(Some(_)) => {
            return blocked_status(
                generated::RelationshipSendBlockReason::PendingCatchup,
                "An offline step with this contact is in flight",
            );
        }
        Ok(None) => {}
        Err(e) => {
            return blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                format!("The relationship's offline step is unreadable: {e}"),
            );
        }
    }

    let tips = client_db::get_contact_chain_tip(&contact.device_id).and_then(|canonical| {
        Ok((
            canonical,
            client_db::get_local_bilateral_chain_tip(&contact.device_id)?,
        ))
    });
    let (canonical_tip, local_tip) = match tips {
        Ok((Some(canonical), Some(local))) => (canonical, local),
        Ok(_) => {
            return blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                "The contact disappeared while its tips were read",
            );
        }
        Err(e) => {
            return blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                format!("The relationship tips are unreadable: {e}"),
            );
        }
    };

    if contact.needs_online_reconcile {
        return blocked_status(
            generated::RelationshipSendBlockReason::StateDivergence,
            "Relationship state diverged and needs repair",
        );
    }

    if canonical_tip != local_tip {
        return blocked_status(
            generated::RelationshipSendBlockReason::StateDivergence,
            "Relationship tips diverged locally",
        );
    }
    match client_db::get_observed_remote_tip_record(&contact.device_id) {
        Ok(Some(observed_tip))
            if observed_tip
                .source
                .blocks_send_without_local_corroboration()
                && observed_tip.tip != canonical_tip =>
        {
            blocked_status(
                generated::RelationshipSendBlockReason::StateDivergence,
                format!(
                    "Live peer reported a different relationship tip ({})",
                    crate::util::text_id::encode_base32_crockford(&observed_tip.tip)
                        .get(..8)
                        .unwrap_or("?")
                ),
            )
        }
        Ok(Some(_)) | Ok(None) => ready_status(),
        Err(e) => blocked_status(
            generated::RelationshipSendBlockReason::InternalError,
            format!("Failed to load observed peer relationship tip: {e}"),
        ),
    }
}
