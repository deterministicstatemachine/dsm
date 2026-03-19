package com.dsm.wallet.bridge.ble

import com.dsm.wallet.bridge.BleOutboxItem

/**
 * State maintained by BleCoordinator for each GATT client session.
 * This replaces direct access to GattClientSession atomic variables.
 *
 * Transport-level state only — all protocol decisions are made by Rust.
 */
data class BleSessionState(
    val deviceAddress: String,
    var isConnected: Boolean = false,
    var negotiatedMtu: Int = 23, // Default minimum MTU
    var serviceDiscoveryCompleted: Boolean = false,
    var lastError: BleSessionEvent.ErrorOccurred? = null,
    var currentTransaction: BleOutboxItem? = null, // Currently processing transaction
    var identityExchangeInProgress: Boolean = false, // Transport guard: prevents eviction during identity read/write (Phase 3)
    var pairingInProgress: Boolean = false // Transport guard: prevents GATT eviction during active pairing (Phase 4)
)
