// SPDX-License-Identifier: MIT OR Apache-2.0

import CoreBluetooth
import Foundation

/// The radio contract both platforms speak (DSM Amendment A27; `BleConstants.kt`).
enum BleConstants {
    /// The DSM service. Version 3: no identity or pairing characteristics; a
    /// link's peer is learned only by the link handshake on TX_REQUEST /
    /// TX_RESPONSE.
    static let serviceUUID = CBUUID(string: "8e7f1002-7c07-4f3f-9b32-7bf3ba6c2a01")
    /// Written by the GATT client: handshake fragments, sealed records, chunk ACKs.
    static let txRequestUUID = CBUUID(string: "8e7f0002-7c07-4f3f-9b32-7bf3ba6c2a01")
    /// Notified by the GATT server: handshake fragments and sealed records.
    static let txResponseUUID = CBUUID(string: "8e7f0003-7c07-4f3f-9b32-7bf3ba6c2a01")

    /// This device's side of a link, as Rust names it across the boundary.
    static let linkRoleClient: Int32 = 1
    static let linkRoleServer: Int32 = 2

    /// Manufacturer-specific data Android advertises in its scan response for
    /// scanners whose stack truncated the service UUID: company id 0xFFFF
    /// (reserved for experimental use) and the magic "DSM\x01". iOS cannot
    /// advertise manufacturer data; it only matches it.
    static let manufacturerId: UInt16 = 0xFFFF
    static let manufacturerMagic = Data([0x44, 0x53, 0x4D, 0x01])

    /// One sealed record on the radio: `0x06 ‖ 500 bytes`
    /// (`dsm::crypto::ble_link::RECORD_LEN` behind its tag).
    static let recordOnRadio = 501
    /// The server's first notification of a transfer carries `0xFF ‖ nonce`
    /// before the chunk.
    static let transferHeader = 2
    /// A client link carries a record only if one write can hold it.
    static let minWriteValueLength = recordOnRadio
    /// A server link carries a record only if one notification can hold it
    /// behind the transfer header. Android asks for MTU 512 (509 bytes of
    /// value); iOS asks for nothing and measures what the link gave.
    static let minUpdateValueLength = recordOnRadio + transferHeader

    /// Transport-level chunk ACK the client writes to TX_REQUEST:
    /// `0xFF ‖ nonce ‖ b3 b2 b1 b0`, the transfer nonce it counts under and the
    /// count of notifications received under it.
    static let chunkAckMarker: UInt8 = 0xFF
    static let chunkAckLength = 6
    /// Notifications the server sends before it waits for an ACK.
    static let notificationWindow = 10
    /// A window's ACK is waited for this long before the transfer goes again
    /// from that window. It arrives once the window has drained over the air:
    /// 240 ms typically and 516 ms at most over 275 windows (Android,
    /// 2026-10-15), so a window not acknowledged in 2 s lost a notification.
    static let ackTimeout = DispatchTimeInterval.milliseconds(2000)
    /// Attempts of one transfer, each under a new nonce, each after the first
    /// resuming at the window whose ACK did not come.
    static let transferMaxAttempts = 3
    /// A write refused by the stack as busy is waited on this long.
    static let readyTimeout = DispatchTimeInterval.seconds(5)
    /// A link that is not ready within this long is dropped.
    static let connectionTimeout = DispatchTimeInterval.seconds(15)
}
