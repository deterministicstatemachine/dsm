// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge.ble

import java.util.UUID

/**
 * BLE-related constants used across components.
 */
object BleConstants {
    // Service UUID - versioned to defeat Android GATT service caching. Version 3:
    // the service has no identity or pairing characteristics; a link's peer is
    // learned only by the link handshake on TX_REQUEST / TX_RESPONSE (DSM
    // Amendment A27).
    val DSM_SERVICE_UUID: UUID = UUID.fromString("8e7f1002-7c07-4f3f-9b32-7bf3ba6c2a01")

    // Characteristic UUIDs
    val TX_REQUEST_UUID: UUID = UUID.fromString("8e7f0002-7c07-4f3f-9b32-7bf3ba6c2a01")
    val TX_RESPONSE_UUID: UUID = UUID.fromString("8e7f0003-7c07-4f3f-9b32-7bf3ba6c2a01")

    // This device's side of a link, as Rust names it across the JNI boundary.
    const val LINK_ROLE_CLIENT = 1
    const val LINK_ROLE_SERVER = 2

    // Client Characteristic Configuration Descriptor
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    // Manufacturer-specific data for truncated-advertisement matching.
    // Company ID 0xFFFF = reserved for internal/experimental use (Bluetooth SIG).
    // 4-byte magic "DSM\x01" avoids false positives from other experimental advertisers.
    const val DSM_MANUFACTURER_ID = 0xFFFF
    val DSM_MANUFACTURER_MAGIC = byteArrayOf(0x44, 0x53, 0x4D, 0x01)

    // MTU settings — request Android max (517) to trigger DLE at the controller level.
    // Actual negotiated MTU may be lower; chunk size adapts dynamically.
    const val MTU_SIZE = 517
    // The MTU a link asks for: at 512 a notification carries 509 bytes, one
    // sealed record of 500 bytes behind its one-byte tag.
    const val LINK_MTU_REQUEST = 512

    // ── Reconnection backoff ──
    // Exponential backoff for BLE reconnection after unexpected disconnect.
    // Prevents battery drain and Android scan-rate-limit violations.
    const val RECONNECT_INITIAL_DELAY_MS = 1_000L
    const val RECONNECT_MAX_DELAY_MS = 30_000L
    const val RECONNECT_MAX_ATTEMPTS = 8

    // ── Scan duration cap ──
    // LOW_LATENCY (100% duty) transitions to BALANCED after this window.
    const val SCAN_LOW_LATENCY_DURATION_MS = 12_000L

    // ── GATT error 133 retry ──
    // Status 133 is transient on most OEMs. Close GATT, wait, retry fresh.
    const val GATT_ERROR_STATUS = 133
    const val GATT_RETRY_DELAY_MS = 300L
    const val GATT_RETRY_MAX_ATTEMPTS = 3

    // ── Connection priority management ──
    // Reset HIGH → BALANCED after transfer completion to save battery.
    const val CONNECTION_PRIORITY_RESET_DELAY_MS = 500L
}
