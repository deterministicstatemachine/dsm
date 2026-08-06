// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: bilateral transport

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_B0X: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/b0x");
pub const TAG_DSM_B0X_MSGID: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/b0x-msgid");
pub const TAG_DSM_B0X_UNILATERAL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/B0X/UNILATERAL");
pub const TAG_DSM_BILATERAL_COMMIT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/bilateral-commit");
pub const TAG_DSM_BILATERAL_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/bilateral-entropy");
pub const TAG_DSM_BILATERAL_OP_COMMIT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/bilateral-op-commit");
pub const TAG_DSM_BILATERAL_PARAMS_HASH: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/bilateral-params-hash");
pub const TAG_DSM_BILATERAL_STATE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/bilateral-state");
pub const TAG_DSM_BLE_FRAME: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/ble-frame");
pub const TAG_DSM_BLE_FRAME_CHECKSUM: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ble-frame-checksum");
pub const TAG_DSM_BLE_SESSION_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ble-session-key");
pub const TAG_DSM_CHAIN_TIP: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/CHAIN_TIP");
pub const TAG_DSM_CHAIN_TIP_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/chain-tip-id");
pub const TAG_DSM_ENVELOPE_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ENVELOPE_ID");
pub const TAG_DSM_ENVELOPE_MSGID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/envelope-msgid");
pub const TAG_DSM_ERROR_ENVELOPE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/error-envelope");
pub const TAG_DSM_ERROR_ENVELOPE_CHAIN: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/error-envelope/chain");
pub const TAG_DSM_JNI_CORE_ENVELOPE_MESSAGE_ID_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/jni-core-envelope-message-id/v1");
pub const TAG_DSM_JNI_ENVELOPE_MESSAGE_ID_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/jni-envelope-message-id/v1");
pub const TAG_DSM_OFFLINE_KEY_CTX: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/offline-key-ctx");
pub const TAG_DSM_OFFLINE_TX_CTX: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/offline-tx-ctx");
pub const TAG_DSM_ONLINETRANSFERREQUEST_NONCE_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/OnlineTransferRequest/nonce/v1");
pub const TAG_DSM_ONLINE_MESSAGE_NONCE_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/online-message/nonce/v3");
pub const TAG_DSM_ONLINE_MESSAGE_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/online-message/v3");
pub const TAG_DSM_RELATIONSHIP: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/relationship");
pub const TAG_DSM_RELATIONSHIP_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/relationship-key");
pub const TAG_DSM_SDK_BILATERAL_ENTRY_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sdk/bilateral-entry/v1");
pub const TAG_DSM_SYSTEM_PEER_TIP: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/system-peer-tip");
pub const TAG_DSM_SYSTEM_PEER_TRANSITION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/system-peer-transition");
pub const TAG_DSM_TRANSFER_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/transfer/v3");

#[cfg(test)]
pub(super) const TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_B0X,
    TAG_DSM_B0X_MSGID,
    TAG_DSM_B0X_UNILATERAL,
    TAG_DSM_BILATERAL_COMMIT,
    TAG_DSM_BILATERAL_ENTROPY,
    TAG_DSM_BILATERAL_OP_COMMIT,
    TAG_DSM_BILATERAL_PARAMS_HASH,
    TAG_DSM_BILATERAL_STATE,
    TAG_DSM_BLE_FRAME,
    TAG_DSM_BLE_FRAME_CHECKSUM,
    TAG_DSM_BLE_SESSION_KEY,
    TAG_DSM_CHAIN_TIP,
    TAG_DSM_CHAIN_TIP_ID,
    TAG_DSM_ENVELOPE_ID,
    TAG_DSM_ENVELOPE_MSGID,
    TAG_DSM_ERROR_ENVELOPE,
    TAG_DSM_ERROR_ENVELOPE_CHAIN,
    TAG_DSM_JNI_CORE_ENVELOPE_MESSAGE_ID_V1,
    TAG_DSM_JNI_ENVELOPE_MESSAGE_ID_V1,
    TAG_DSM_OFFLINE_KEY_CTX,
    TAG_DSM_OFFLINE_TX_CTX,
    TAG_DSM_ONLINETRANSFERREQUEST_NONCE_V1,
    TAG_DSM_ONLINE_MESSAGE_NONCE_V3,
    TAG_DSM_ONLINE_MESSAGE_V3,
    TAG_DSM_RELATIONSHIP,
    TAG_DSM_RELATIONSHIP_KEY,
    TAG_DSM_SDK_BILATERAL_ENTRY_V1,
    TAG_DSM_SYSTEM_PEER_TIP,
    TAG_DSM_SYSTEM_PEER_TRANSITION,
    TAG_DSM_TRANSFER_V3,
];
