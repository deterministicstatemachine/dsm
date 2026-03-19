package com.dsm.wallet.bridge.ble

/**
 * BLE session modes for coordinating scanning and advertising behavior.
 */
enum class BleSessionMode {
    IDLE,
    AWAITING_PEER_FOR_CONTACT,
    AWAITING_PEER_FOR_TRANSFER
}