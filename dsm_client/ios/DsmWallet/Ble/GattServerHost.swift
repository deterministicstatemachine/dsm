// SPDX-License-Identifier: MIT OR Apache-2.0

import CoreBluetooth
import Foundation

/// The GATT server: this device's DSM service, its advertising, and the
/// links peers open to it. The service holds no identity and no pairing
/// characteristics: a link's peer is learned only by the link handshake Rust
/// runs on it (DSM Amendment A27), whose every byte, like every later byte,
/// travels on TX_REQUEST and TX_RESPONSE.
///
/// iOS tells a peripheral nothing about a connection as such; a link is open
/// to Rust from the central's TX_RESPONSE subscription (which the client makes
/// before its first write) to its unsubscription or disconnect, and only when
/// one notification can carry a sealed record behind the transfer header.
final class GattServerHost: NSObject, CBPeripheralManagerDelegate {
    private unowned let coordinator: BleCoordinator
    private let queue: DispatchQueue
    private let tag = "GattServerHost"
    private(set) var manager: CBPeripheralManager?
    private var txResponse: CBMutableCharacteristic?
    private enum ServiceState { case absent, adding, added }
    private var service = ServiceState.absent
    private enum Wanted { case nothing, advertising }
    private var wanted = Wanted.nothing

    init(coordinator: BleCoordinator, queue: DispatchQueue) {
        self.coordinator = coordinator
        self.queue = queue
    }

    /// Creates the manager (which prompts for the Bluetooth permission the first time).
    func ensureManager() -> CBPeripheralManager {
        if let manager { return manager }
        let made = CBPeripheralManager(delegate: self, queue: queue)
        manager = made
        return made
    }

    var isAdvertising: Bool { manager?.isAdvertising ?? (manager != nil) }

    /// Advertise the service; it is added first when it is not yet. Answers 0
    /// when advertising is on or requested, else why not.
    func startAdvertising() -> Int32 {
        let manager = ensureManager()
        wanted = .advertising
        guard manager.state == .poweredOn else {
            DsmLog.warn(tag, "startAdvertising: the radio is not on (\(manager.state.rawValue)); it starts when it is")
            return 1
        }
        switch service {
        case .absent:
            addService(manager)
            return 0
        case .adding:
            return 0
        case .added:
            if manager.isAdvertising { return 0 }
            manager.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [BleConstants.serviceUUID]])
            return 0
        }
    }

    func stopAdvertising() {
        wanted = .nothing
        manager?.stopAdvertising()
    }

    private func addService(_ manager: CBPeripheralManager) {
        service = .adding
        let request = CBMutableCharacteristic(
            type: BleConstants.txRequestUUID,
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        let response = CBMutableCharacteristic(
            type: BleConstants.txResponseUUID,
            properties: [.notify],
            value: nil,
            permissions: [.readable]
        )
        txResponse = response
        let dsm = CBMutableService(type: BleConstants.serviceUUID, primary: true)
        dsm.characteristics = [request, response]
        manager.add(dsm)
    }

    // MARK: Notifying a central

    /// Write `records` to the central at `peer`, in order, as `GattServerHost
    /// .sendChunkedNotifications` does on Android: the first notification of
    /// the transfer carries `0xFF ‖ nonce` before its record, every window of
    /// ten waits for the client's chunk ACK, and a window whose ACK does not
    /// come has the whole transfer tried again under a new nonce, up to three
    /// times (the client's reassembly takes a repeated record once). Blocks
    /// the caller (Rust's thread) until every record is taken or the link is
    /// gone. Answers `BleCoordinator.writeSent` or `writeNotNow`.
    func notify(_ peer: PeerSession, records: [Data]) -> Int32 {
        guard let manager, let txResponse else { return BleCoordinator.writeNotNow }
        var central: CBCentral?
        var subscribed = PeerSession.LinkState.closed
        queue.sync {
            central = peer.central
            subscribed = peer.subscribedToTxResponse
        }
        guard let central, subscribed == .opened else {
            DsmLog.warn(tag, "notify: \(peer.address) is not subscribed to TX_RESPONSE; \(records.count) records refused")
            return BleCoordinator.writeNotNow
        }
        for attempt in 1...BleConstants.transferMaxAttempts {
            var nonce: UInt8 = 0
            queue.sync {
                peer.serverTransferNonce &+= 1
                nonce = peer.serverTransferNonce
                peer.lastAck = nil
            }
            DsmLog.info(tag, "notify: \(records.count) records to \(peer.address) (nonce \(nonce), attempt \(attempt))")
            // The window whose ACK did not come, when one did not.
            var timedOutAt: Int?
            for (index, record) in records.enumerated() {
                let data = index == 0 ? Data([BleConstants.chunkAckMarker, nonce]) + record : record
                guard send(manager, central, txResponse, data, peer) else {
                    return BleCoordinator.writeNotNow
                }
                // The client ACKs on window boundaries only, never a final partial window.
                let chunkNumber = index + 1
                if chunkNumber % BleConstants.notificationWindow == 0, !awaitAck(peer, atLeast: chunkNumber) {
                    DsmLog.error(tag, "notify: ACK timeout at \(chunkNumber)/\(records.count) (attempt \(attempt))")
                    timedOutAt = chunkNumber
                    break
                }
            }
            if timedOutAt == nil {
                return BleCoordinator.writeSent
            }
            // The link recovers for a moment, then the transfer goes again.
            let paused = peer.notifyReady.wait(timeout: .now() + .milliseconds(500))
            DsmLog.info(tag, "notify: retrying the transfer to \(peer.address) after a pause (\(paused))")
        }
        DsmLog.error(tag, "notify: the transfer to \(peer.address) failed after \(BleConstants.transferMaxAttempts) attempts")
        return BleCoordinator.writeNotNow
    }

    /// What one `updateValue` came to.
    private enum Attempt { case taken, busy, linkGone }

    private func attempt(_ manager: CBPeripheralManager, _ central: CBCentral, _ characteristic: CBMutableCharacteristic, _ data: Data, _ peer: PeerSession) -> Attempt {
        var outcome = Attempt.busy
        queue.sync {
            if peer.central == nil {
                outcome = .linkGone
            } else if manager.updateValue(data, for: characteristic, onSubscribedCentrals: [central]) {
                outcome = .taken
            }
        }
        return outcome
    }

    /// One notification; waits once for the stack when its queue is full.
    /// Answers whether the stack took it.
    private func send(_ manager: CBPeripheralManager, _ central: CBCentral, _ characteristic: CBMutableCharacteristic, _ data: Data, _ peer: PeerSession) -> Bool {
        var outcome = attempt(manager, central, characteristic, data, peer)
        if outcome == .busy {
            // The transmit queue is full: the stack says when it has room.
            if peer.notifyReady.wait(timeout: .now() + BleConstants.readyTimeout) == .timedOut {
                DsmLog.warn(tag, "send: the stack stayed busy for \(BleConstants.readyTimeout)")
            } else {
                outcome = attempt(manager, central, characteristic, data, peer)
            }
        }
        return outcome == .taken
    }

    private func latestAck(_ peer: PeerSession) -> Int {
        var acked = 0
        queue.sync { acked = peer.lastAck ?? 0 }
        return acked
    }

    /// Wait for the client's chunk ACK to reach `count`, within the ACK timeout.
    private func awaitAck(_ peer: PeerSession, atLeast count: Int) -> Bool {
        let deadline = DispatchTime.now() + BleConstants.ackTimeout
        var acked = latestAck(peer)
        while acked < count, peer.ackArrived.wait(timeout: deadline) != .timedOut {
            acked = latestAck(peer)
        }
        return latestAck(peer) >= count
    }

    // MARK: CBPeripheralManagerDelegate

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        DsmLog.info(tag, "peripheral manager state \(peripheral.state.rawValue)")
        switch peripheral.state {
        case .poweredOn:
            if wanted == .advertising {
                let code = startAdvertising()
                DsmLog.info(tag, "the radio is on; advertising requested (code \(code))")
            }
        case .poweredOff, .resetting, .unauthorized, .unsupported, .unknown:
            // Every link ended with the radio; the registration too.
            service = .absent
            coordinator.radioOff()
        @unknown default:
            service = .absent
        }
        coordinator.radioStateChanged()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error {
            DsmLog.error(tag, "the DSM service was not registered: \(error)")
            self.service = .absent
            return
        }
        self.service = .added
        DsmLog.info(tag, "the DSM service is registered")
        if wanted == .advertising {
            peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [BleConstants.serviceUUID]])
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error {
            DsmLog.error(tag, "the stack refused the advertising set: \(error)")
            coordinator.advertisingFailed()
            return
        }
        DsmLog.info(tag, "advertising started")
        coordinator.advertisingStarted()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        guard characteristic.uuid == BleConstants.txResponseUUID else { return }
        let address = central.identifier.uuidString
        let peer = coordinator.peer(address)
        peer.central = central
        // A notification must carry one sealed record behind the transfer
        // header; a link that cannot does not become a route (fail closed).
        let capacity = central.maximumUpdateValueLength
        guard capacity >= BleConstants.minUpdateValueLength else {
            DsmLog.warn(tag, "\(address): one notification carries \(capacity) bytes; a sealed record needs \(BleConstants.minUpdateValueLength); the link is not opened")
            // There is no disconnect for a peripheral to call; the central's
            // writes are refused until it goes away.
            return
        }
        peer.subscribedToTxResponse = .opened
        DsmLog.info(tag, "\(address): subscribed to TX_RESPONSE, notification capacity \(capacity) bytes")
        coordinator.openServerLink(peer)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard characteristic.uuid == BleConstants.txResponseUUID else { return }
        coordinator.closeServerLink(coordinator.peer(central.identifier.uuidString))
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard request.characteristic.uuid == BleConstants.txRequestUUID else {
                peripheral.respond(to: request, withResult: .writeNotPermitted)
                continue
            }
            // The response goes first: some stacks serialize the next ATT
            // operation behind it, and the data's processing may notify back.
            peripheral.respond(to: request, withResult: .success)
            guard let data = request.value, !data.isEmpty else { continue }
            let address = request.central.identifier.uuidString
            let peer = coordinator.peer(address)
            if peer.central == nil { peer.central = request.central }
            // The client's transport-level chunk ACK: `0xFF ‖ b3 b2 b1 b0`.
            if data.count == BleConstants.chunkAckLength, data[data.startIndex] == BleConstants.chunkAckMarker {
                let count = data.dropFirst().reduce(0) { ($0 << 8) | Int($1) }
                peer.lastAck = count
                peer.ackArrived.signal()
                continue
            }
            coordinator.inbound(peer, role: BleConstants.linkRoleServer, bytes: data)
        }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        coordinator.notifyReadyForAll()
    }
}
