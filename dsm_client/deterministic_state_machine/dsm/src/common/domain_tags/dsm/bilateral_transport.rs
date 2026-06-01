// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: bilateral transport

pub const TAG_DSM_B0X: &str = "DSM/b0x";
pub const TAG_DSM_B0X_MSGID: &str = "DSM/b0x-msgid";
pub const TAG_DSM_B0X_UNILATERAL: &str = "DSM/B0X/UNILATERAL";
pub const TAG_DSM_BILATERAL_COMMIT: &str = "DSM/bilateral-commit";
pub const TAG_DSM_BILATERAL_ENTROPY: &str = "DSM/bilateral-entropy";
pub const TAG_DSM_BILATERAL_OP_COMMIT: &str = "DSM/bilateral-op-commit";
pub const TAG_DSM_BILATERAL_PARAMS_HASH: &str = "DSM/bilateral-params-hash";
pub const TAG_DSM_BILATERAL_STATE: &str = "DSM/bilateral-state";
pub const TAG_DSM_BLE_FRAME: &str = "DSM/ble-frame";
pub const TAG_DSM_BLE_FRAME_CHECKSUM: &str = "DSM/ble-frame-checksum";
pub const TAG_DSM_BLE_SESSION_KEY: &str = "DSM/ble-session-key";
pub const TAG_DSM_CHAIN_TIP: &str = "DSM/CHAIN_TIP";
pub const TAG_DSM_CHAIN_TIP_ID: &str = "DSM/chain-tip-id";
pub const TAG_DSM_ENVELOPE_ID: &str = "DSM/ENVELOPE_ID";
pub const TAG_DSM_ENVELOPE_MSGID: &str = "DSM/envelope-msgid";
pub const TAG_DSM_ERROR_ENVELOPE: &str = "DSM/error-envelope";
pub const TAG_DSM_ERROR_ENVELOPE_CHAIN: &str = "DSM/error-envelope/chain";
pub const TAG_DSM_JNI_CORE_ENVELOPE_MESSAGE_ID_V1: &str = "DSM/jni-core-envelope-message-id/v1";
pub const TAG_DSM_JNI_ENVELOPE_MESSAGE_ID_V1: &str = "DSM/jni-envelope-message-id/v1";
pub const TAG_DSM_OFFLINE_KEY_CTX: &str = "DSM/offline-key-ctx";
pub const TAG_DSM_OFFLINE_TX_CTX: &str = "DSM/offline-tx-ctx";
pub const TAG_DSM_ONLINETRANSFERREQUEST_NONCE_V1: &str = "DSM/OnlineTransferRequest/nonce/v1";
pub const TAG_DSM_ONLINE_MESSAGE_NONCE_V3: &str = "DSM/online-message/nonce/v3";
pub const TAG_DSM_ONLINE_MESSAGE_V3: &str = "DSM/online-message/v3";
pub const TAG_DSM_RELATIONSHIP: &str = "DSM/relationship";
pub const TAG_DSM_RELATIONSHIP_KEY: &str = "DSM/relationship-key";
pub const TAG_DSM_SDK_BILATERAL_ENTRY_V1: &str = "DSM/sdk/bilateral-entry/v1";
pub const TAG_DSM_SYSTEM_PEER_TIP: &str = "DSM/system-peer-tip";
pub const TAG_DSM_SYSTEM_PEER_TRANSITION: &str = "DSM/system-peer-transition";
pub const TAG_DSM_TRANSFER_V3: &str = "DSM/transfer/v3";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
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
