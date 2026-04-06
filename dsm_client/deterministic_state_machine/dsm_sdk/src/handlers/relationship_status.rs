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
    if contact.status == "Bricked" {
        return blocked_status(
            generated::RelationshipSendBlockReason::StateDivergence,
            "Relationship is bricked after a Tripwire fork detection",
        );
    }

    if contact.public_key.is_empty() {
        return blocked_status(
            generated::RelationshipSendBlockReason::InternalError,
            "Relationship is missing a canonical public key",
        );
    }

    let pending_outbox = match client_db::get_pending_online_outbox(&contact.device_id) {
        Ok(v) => v,
        Err(e) => {
            return blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                format!("Failed to load pending online catch-up state: {e}"),
            );
        }
    };

    let canonical_tip = client_db::get_contact_chain_tip_raw(&contact.device_id);
    let local_tip = client_db::get_local_bilateral_chain_tip(&contact.device_id);

    if let Some(pending) = pending_outbox {
        if pending.parent_tip.len() != 32 || pending.next_tip.len() != 32 {
            return blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                "Pending online catch-up gate is malformed",
            );
        }

        return blocked_status(
            generated::RelationshipSendBlockReason::PendingCatchup,
            "Waiting for prior transfer to settle",
        );
    }

    if contact.needs_online_reconcile {
        return blocked_status(
            generated::RelationshipSendBlockReason::StateDivergence,
            "Relationship state diverged and needs repair",
        );
    }

    match (canonical_tip, local_tip) {
        (Some(canonical), Some(local)) if canonical != local => blocked_status(
            generated::RelationshipSendBlockReason::StateDivergence,
            "Relationship tips diverged locally",
        ),
        (Some(_), None) | (None, Some(_)) => blocked_status(
            generated::RelationshipSendBlockReason::StateDivergence,
            "Relationship tip columns are inconsistent",
        ),
        _ => {
            let observed_remote_tip = client_db::get_observed_remote_tip_record(&contact.device_id);
            match observed_remote_tip {
                Ok(Some(observed_tip))
                    if observed_tip
                        .source
                        .blocks_send_without_local_corroboration() =>
                {
                    let reference_tip = canonical_tip.or(local_tip).unwrap_or([0u8; 32]);
                    if observed_tip.tip != reference_tip {
                        blocked_status(
                            generated::RelationshipSendBlockReason::StateDivergence,
                            format!(
                                "Live peer reported a different relationship tip ({})",
                                crate::util::text_id::encode_base32_crockford(&observed_tip.tip)
                                    .get(..8)
                                    .unwrap_or("?")
                            ),
                        )
                    } else {
                        ready_status()
                    }
                }
                Ok(Some(_)) | Ok(None) => ready_status(),
                Err(e) => blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Failed to load observed peer relationship tip: {e}"),
                ),
            }
        }
    }
}
