// SPDX-License-Identifier: MIT OR Apache-2.0

import CoreBluetooth
import Foundation

/// Transport state for one peer, by its address: the client link this device
/// opened to it, and the server link it opened to this device. Protocol
/// decisions are Rust's; this holds what the radio reported.
final class PeerSession {
    /// A link Rust has opened (its handshake and every sealed record travel on it).
    enum LinkState { case closed, opened }

    let address: String

    // Client side: this device connected to the peer.
    var peripheral: CBPeripheral?
    var txRequest: CBCharacteristic?
    var txResponse: CBCharacteristic?
    var clientLink = LinkState.closed
    /// The contact this link was connected for, named to the handshake as its target.
    var target: Data?
    /// Notifications received in the current transfer, for the ACK windows.
    var notificationCount = 0
    var currentTransferNonce: UInt8?
    /// Writes waiting for the stack to be ready to send without response.
    var pendingWrites: [Data] = []
    /// Signalled when the stack is ready to take a write without response.
    let writeReady = DispatchSemaphore(value: 0)
    /// The one in-flight `write` call's completion, for the caller blocked on it.
    var writeOutcome: ((Int32) -> Void)?

    // Server side: the peer connected to this device.
    var central: CBCentral?
    var subscribedToTxResponse = LinkState.closed
    var serverLink = LinkState.closed
    var serverTransferNonce: UInt8 = 0
    /// The latest chunk ACK the client wrote, for the window the server waits on.
    var lastAck: Int?
    let ackArrived = DispatchSemaphore(value: 0)
    let notifyReady = DispatchSemaphore(value: 0)
    /// Notifications the stack refused as busy, waiting for `notifyReady`.
    var pendingNotifications: [Data] = []

    /// Bytes from this peer are handed to Rust one after another, off the
    /// radio's queue, so the radio keeps taking writes while Rust works.
    let inbound: DispatchQueue

    init(address: String) {
        self.address = address
        inbound = DispatchQueue(label: "com.dsm.wallet.ble.inbound.\(address)")
    }

    /// Whether anything of this peer remains after a side cleared.
    var isEmpty: Bool {
        peripheral == nil && central == nil
    }

    func clearClientState() {
        peripheral = nil
        txRequest = nil
        txResponse = nil
        clientLink = .closed
        target = nil
        notificationCount = 0
        currentTransferNonce = nil
        pendingWrites.removeAll()
        writeOutcome?(BleCoordinator.writeNotNow)
        writeOutcome = nil
    }

    func clearServerState() {
        central = nil
        subscribedToTxResponse = .closed
        serverLink = .closed
        lastAck = nil
        pendingNotifications.removeAll()
        notifyReady.signal()
        ackArrived.signal()
    }
}
